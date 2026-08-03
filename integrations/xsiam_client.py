"""XSIAM Public API read-back client — the verify half of the detector test loop.

Every other integration in this repo is write-only (push events at a collector). This
module is the opposite: it reads the tenant back to answer two questions an autonomous
test loop has to be able to answer for itself:

    1. Did the event actually land?      -> xql_query() against microsoft_windows_raw
    2. Did the detector fire on it?      -> get_alerts() / wait_for_alert()

Auth is the XSIAM **Standard** API key scheme: the key is sent verbatim in
``Authorization`` alongside the numeric key id in ``x-xdr-auth-id``. (Advanced keys use
an HMAC-SHA256 nonce+timestamp signature instead — not implemented here; if the key is
ever upgraded to Advanced, every call starts returning 401 and _sign() is where to fix it.)

Env (see .env):
    XSIAM_API_BASE     https://api-<tenant>.xdr.us.paloaltonetworks.com
    XSIAM_API_KEY_ID   numeric ID column from Settings -> API Keys
    XSIAM_API_KEY      the key value

Standalone smoke test — verifies auth, XQL, and alert-read permissions separately, so a
role missing just one scope is obvious rather than looking like a broken key:

    python integrations/xsiam_client.py
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    raise SystemExit("The 'requests' package is required: pip install -r requirements.txt")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass


# XQL results are polled, not returned inline. These bound that wait.
_POLL_INTERVAL = 5.0     # seconds between get_query_results calls (API is rate-limited)
_QUERY_TIMEOUT = 180.0   # give up on a single XQL query after this long
_MAX_PAGE = 100          # get_alerts_multi_events enforces 0 < search_to-search_from <= 100
_TRANSPORT_RETRIES = 4   # transport-level retries (connection resets), not HTTP errors
_TRANSPORT_BACKOFF = 3.0 # seconds, multiplied by attempt number

# The only alert sources that can result from firing an event. Posture Policy and
# Vulnerability Policy are standing-configuration findings — they never correlate to a
# fired log, and Vulnerability Policy alone is ~90% of this tenant's alert volume.
ANALYTICS_SOURCES = ("XDR Analytics", "XDR Analytics BIOC", "Correlation")

# microsoft_windows_raw is SHARED with a live WEC feed from a real lab DC
# (DC1.lab.local / jumpbox, in lab.local). LogSim's synthetic events are in
# examplecorp.local. Every ingest check and alert attribution MUST scope to the LogSim
# domain, or real DC activity will be misread as a passing test.
LOGSIM_DOMAIN = "examplecorp.local"
FOREIGN_HOSTS = ("DC1.lab.local", "jumpbox")

# Alerts carry a `tags` list describing provenance, e.g. for a Windows identity detection:
#   ['R:Domain Controllers', 'DT:Identity Analytics', 'DS:Microsoft/Windows', 'DOM:Security']
# DS: = data source, DT: = detector type, R: = role, DOM: = domain.
#
# `DS:Microsoft/Windows` is the precise way to ask "did this alert come from the Windows
# feed" — far better than guessing at alert_source, which is a hand-enumerated allowlist
# that silently misses any source not already seen. It is NOT server-side filterable
# (get_alerts_multi_events rejects `tags`), so it is applied client-side as a matcher.
WINDOWS_DS_TAG = "DS:Microsoft/Windows"
IDENTITY_DT_TAG = "DT:Identity Analytics"


def has_tag(alert: Dict[str, Any], tag: str) -> bool:
    """Case-insensitive membership test over an alert's tags (and original_tags)."""
    want = tag.lower()
    for key in ("tags", "original_tags"):
        for t in (alert.get(key) or []):
            if str(t).lower() == want:
                return True
    return False


class XsiamError(RuntimeError):
    """Any non-2xx from the Public API, or a query that never completed."""


class XsiamAuthError(XsiamError):
    """401/403 — bad key, wrong key id, or a role missing the required scope."""


class XsiamClient:
    def __init__(self, base: Optional[str] = None, key_id: Optional[str] = None,
                 api_key: Optional[str] = None, timeout: float = 180.0):
        # 180s, not 60: get_alerts_multi_events over a wide window on this tenant
        # (~19k alerts/day) intermittently takes >60s to return the first page.
        self.base = (base or os.getenv("XSIAM_API_BASE", "")).rstrip("/")
        self.key_id = str(key_id or os.getenv("XSIAM_API_KEY_ID", "")).strip()
        self.api_key = (api_key or os.getenv("XSIAM_API_KEY", "")).strip()
        self.timeout = timeout
        missing = [n for n, v in (("XSIAM_API_BASE", self.base),
                                  ("XSIAM_API_KEY_ID", self.key_id),
                                  ("XSIAM_API_KEY", self.api_key)) if not v]
        if missing:
            raise XsiamError(f"Missing required env var(s): {', '.join(missing)}. See .env.")
        self._session = requests.Session()

    # ── transport ─────────────────────────────────────────────────────────────
    def _sign(self) -> Dict[str, str]:
        """Standard-key headers. Advanced keys would sign a nonce+timestamp here."""
        return {
            "x-xdr-auth-id": self.key_id,
            "Authorization": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _post(self, endpoint: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base}/public_api/v1/{endpoint.strip('/')}"
        # The tenant intermittently resets TLS connections mid-handshake (WinError 10054).
        # An unretried reset kills a 10-minute autonomous poll, so transport errors get a
        # few attempts with backoff. HTTP-level errors below are NOT retried — a 500 from a
        # bad filter is deterministic and retrying only hides it.
        last_exc: Optional[Exception] = None
        for attempt in range(_TRANSPORT_RETRIES):
            try:
                r = self._session.post(url, headers=self._sign(),
                                       json={"request_data": request_data},
                                       timeout=self.timeout)
                break
            except requests.RequestException as e:
                last_exc = e
                if attempt == _TRANSPORT_RETRIES - 1:
                    raise XsiamError(
                        f"Could not reach {url} after {_TRANSPORT_RETRIES} attempts: {e}")
                time.sleep(_TRANSPORT_BACKOFF * (attempt + 1))
                # A reset connection stays poisoned in the pool; rebuild it.
                self._session = requests.Session()
        else:  # pragma: no cover - loop always breaks or raises
            raise XsiamError(f"Could not reach {url}: {last_exc}")

        if r.status_code in (401, 403):
            raise XsiamAuthError(
                f"HTTP {r.status_code} on {endpoint}. Either the key/key-id pair is wrong, or "
                f"the key's role lacks permission for this endpoint. Body: {r.text[:400]}"
            )
        if r.status_code == 429:
            raise XsiamError(f"Rate limited (429) on {endpoint}. Back off and retry.")
        if not r.ok:
            raise XsiamError(f"HTTP {r.status_code} on {endpoint}: {r.text[:600]}")
        try:
            return r.json()
        except ValueError:
            raise XsiamError(f"Non-JSON response from {endpoint}: {r.text[:300]}")

    # ── XQL ───────────────────────────────────────────────────────────────────
    def xql_query(self, query: str, minutes_back: int = 30,
                  limit: int = 100, timeout: float = _QUERY_TIMEOUT) -> List[Dict[str, Any]]:
        """Run an XQL query and block until results are ready. Returns the data rows.

        `minutes_back` sets the search window relative to now.
        """
        started = self._post("xql/start_xql_query/", {
            "query": query,
            "tenants": [],
            "timeframe": {"relativeTime": int(minutes_back * 60 * 1000)},
        })
        execution_id = started.get("reply")
        if not execution_id:
            raise XsiamError(f"start_xql_query returned no execution id: {started}")

        deadline = time.time() + timeout
        while True:
            res = self._post("xql/get_query_results/", {
                "query_id": execution_id,
                "pending_flag": True,
                "limit": limit,
                "format": "json",
            })
            reply = res.get("reply", {}) or {}
            status = (reply.get("status") or "").upper()
            if status == "SUCCESS":
                results = reply.get("results", {}) or {}
                # Large result sets come back as a stream_id instead of inline data. The
                # verify loop only ever needs existence + a handful of rows, so a caller
                # hitting this should tighten its query rather than page a stream.
                if "data" not in results and results.get("stream_id"):
                    raise XsiamError(
                        "Result set too large for inline return (got a stream_id). "
                        "Narrow the query or lower the limit."
                    )
                return results.get("data", []) or []
            if status in ("FAIL", "FAILED", "ERROR"):
                raise XsiamError(f"XQL query failed: {reply}")
            if time.time() > deadline:
                raise XsiamError(f"XQL query {execution_id} still {status or 'PENDING'} "
                                 f"after {timeout:.0f}s")
            time.sleep(_POLL_INTERVAL)

    def count_events(self, dataset: str, where: str, minutes_back: int = 30) -> int:
        """Ingest check: how many rows in `dataset` match `where` in the window.

        `where` is raw XQL filter syntax. Note two XQL gotchas learned the hard way:
        `comp` is a reserved word and cannot be used as an `alter` alias, and regextract
        returns an *array* — compare with `arrayindex(x, 0)`, not `x`.
        """
        rows = self.xql_query(
            f"dataset = {dataset} | filter {where} | fields _time | limit 1000",
            minutes_back=minutes_back, limit=1000,
        )
        return len(rows)

    def count_windows_events(self, event_id: int, minutes_back: int = 15,
                             logsim_only: bool = True) -> int:
        """Ingest check for one Windows Event ID in microsoft_windows_raw.

        `logsim_only` scopes to the LogSim domain so the real lab-DC feed sharing this
        dataset can't be mistaken for LogSim output. Leave it True for tests.
        """
        q = (r'dataset = microsoft_windows_raw '
             r'| alter eid = arrayindex(regextract(_raw_log, "<EventID>(\d+)<"), 0) '
             r'| alter host_x = arrayindex(regextract(_raw_log, "<Computer>([^<]+)<"), 0) '
             f'| filter eid = "{event_id}" ')
        if logsim_only:
            q += f'| filter host_x contains "{LOGSIM_DOMAIN}" '
        q += '| fields _time | limit 1000'
        return len(self.xql_query(q, minutes_back=minutes_back, limit=1000))

    # ── Alerts ────────────────────────────────────────────────────────────────
    def get_alerts(self, minutes_back: int = 30, limit: int = 300,
                   sources: Optional[List[str]] = None,
                   name_contains: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch alerts created in the window, newest first.

        Two hard constraints of get_alerts_multi_events shape this signature:

        * Only these filter fields are accepted — alert_id_list, external_id_list,
          alert_source, creation_time, last_modified_ts, server_creation_time,
          severity — and `alert_source` accepts only the `in` operator. There is **no
          server-side name filter**, so `name_contains` is applied client-side.
        * `search_to - search_from` must be in (0, 100], so anything past the first
          100 rows has to be paged.

        Always pass `sources` when verifying a detector. This tenant produces ~19k
        alerts/day, the overwhelming majority Vulnerability Policy noise; without a
        source filter the detector you care about is buried tens of pages deep.
        """
        since_ms = int((time.time() - minutes_back * 60) * 1000)
        out: List[Dict[str, Any]] = []
        for offset in range(0, max(limit, 1), _MAX_PAGE):
            page = min(_MAX_PAGE, limit - offset)
            if page <= 0:
                break
            filters: List[Dict[str, Any]] = [
                {"field": "creation_time", "operator": "gte", "value": since_ms},
            ]
            if sources:
                filters.append({"field": "alert_source", "operator": "in", "value": sources})
            res = self._post("alerts/get_alerts_multi_events/", {
                "filters": filters,
                "search_from": offset,
                "search_to": offset + page,
                "sort": {"field": "creation_time", "keyword": "desc"},
            })
            reply = res.get("reply", {}) or {}
            batch = reply.get("alerts", []) or []
            out.extend(batch)
            if len(batch) < page:
                break
        if name_contains:
            needle = name_contains.lower()
            out = [a for a in out if needle in (a.get("name") or "").lower()]
        return out

    def wait_for_alert(self, predicate, minutes_back: int = 30,
                       timeout: float = 600.0, interval: float = 30.0,
                       sources: Optional[List[str]] = None):
        """Poll alerts until `predicate(alert)` is true, or `timeout` elapses.

        Returns the matching alert dict, or None on timeout. `timeout` defaults to the
        10-minute detector SLA the test loop assumes. `sources` defaults to the three
        event-driven sources — Posture Policy and Vulnerability Policy findings are
        never the result of a fired event, so including them only adds noise.
        """
        if sources is None:
            sources = list(ANALYTICS_SOURCES)
        deadline = time.time() + timeout
        while True:
            for alert in self.get_alerts(minutes_back=minutes_back, sources=sources):
                if predicate(alert):
                    return alert
            if time.time() >= deadline:
                return None
            time.sleep(interval)


# ── smoke test ────────────────────────────────────────────────────────────────
def _smoke() -> int:
    print("XSIAM read-back smoke test")
    try:
        c = XsiamClient()
    except XsiamError as e:
        print(f"  FAIL config: {e}")
        return 2
    print(f"  base    : {c.base}")
    print(f"  key id  : {c.key_id}")
    print(f"  key     : ...{c.api_key[-6:]} ({len(c.api_key)} chars)")

    rc = 0

    print("\n[1/3] alert read (alerts/get_alerts_multi_events)")
    try:
        alerts = c.get_alerts(minutes_back=240, limit=100,
                              sources=list(ANALYTICS_SOURCES))
        print(f"  OK - {len(alerts)} event-driven alert(s) in the last 4h")
        for a in alerts[:5]:
            print(f"       - [{a.get('source')}] {a.get('name')!r} "
                  f"sev={a.get('severity')} host={a.get('host_name')}")
    except XsiamError as e:
        print(f"  FAIL {e}")
        rc = 1

    print("\n[2/3] XQL permission + windows dataset reachable")
    try:
        rows = c.xql_query("dataset = microsoft_windows_raw | fields _time | limit 5",
                           minutes_back=1440, limit=5)
        print(f"  OK - XQL ran, {len(rows)} row(s) from microsoft_windows_raw in 24h")
        if not rows:
            print("       (dataset empty in window — expected if the module hasn't run today)")
    except XsiamError as e:
        print(f"  FAIL {e}")
        rc = 1

    print("\n[3/3] ingest-latency probe (most recent windows event)")
    try:
        rows = c.xql_query(
            "dataset = microsoft_windows_raw | fields _time | sort desc _time | limit 1",
            minutes_back=1440, limit=1)
        if rows:
            print(f"  OK - newest _time: {rows[0].get('_time')}")
        else:
            print("  OK - query ran; no rows in 24h")
    except XsiamError as e:
        print(f"  FAIL {e}")
        rc = 1

    print("\nresult:", "all checks passed" if rc == 0 else "one or more checks FAILED")
    return rc


if __name__ == "__main__":
    raise SystemExit(_smoke())
