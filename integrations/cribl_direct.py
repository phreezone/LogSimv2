"""Direct-to-XSIAM "Cribl receiver" transport — push synthetic events into the native
dataset + Fusion analytics pipeline WITHOUT a Cribl instance at runtime.

Reverse-engineered from a real Cribl Cortex XSIAM destination's outbound request
(2026-10-10). The integrated receiver (/logs/v1/integrated/cribl/data) only columns data
that arrives in the exact wire shape the Cribl destination emits:

  POST <CRIBL_COLLECTOR_URL>
  Authorization:          Bearer <CRIBL_TOKEN>      # the "Bearer " prefix is required
  Content-Type:           application/json
  Content-Encoding:       gzip
  Format:                 json
  Source-Identifier:      <dedicated catalog UUID>  # selects dataset + parser; must be exact
  Integration-Identifier: <any non-empty string>    # free-form; not validated
  body = gzip( NDJSON )  where each line = {"data": <vendor record>, "collector_ms": <ms>}

A bare record (no {"data":...} envelope), or a non-gzip body, or a bare (non-Bearer)
token, all return HTTP 200 but land in _raw_log and never parse — that cost us a month of
"lands raw" results. Only every piece above together yields parsed, analytics-eligible rows.

Portability: a user needs only the FREE XSIAM Cribl integration (Settings -> Data Sources
-> add Cribl -> generate token). No Entra account, no Cribl Stream instance.

Catalog Source-Identifier UUIDs are per data source; see DEDICATED_UUIDS below and the
XSIAM "Data source UUIDs" doc for the full list.
"""
import gzip
import json
import os
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:  # pragma: no cover
    raise SystemExit("The 'requests' package is required: pip install -r requirements.txt")

# Dedicated catalog UUIDs verified against the tenant (land + parse into the named dataset).
DEDICATED_UUIDS = {
    "o365_azure_ad":   "e1f109f886ea42fbb96be6ec0cc597a9",  # -> msft_o365_azure_ad_raw
    "azure_ad_signin": "f56dcfdf6bca43e793a4b6e9290e7b12",  # -> msft_azure_ad_raw
    "azure_event_hub": "fce13a1d51294f84bae4a37851503060",  # -> msft_azure_raw (Event Hub diagnostics)
}

# A record may name a different destination than the module that produced it, e.g. the
# Event Hub copy of a Graph sign-in (msft_azure_raw rather than msft_azure_ad_raw):
# record[ROUTE_KEY] = [source_identifier, integration_identifier]. split_routes() groups a
# batch by destination; the key never goes on the wire.
ROUTE_KEY = "__cribl_route__"


def split_routes(records: Sequence[Any], source_identifier: str,
                 integration_identifier: str) -> Dict[Tuple[str, str], List[Any]]:
    """{(source_identifier, integration_identifier): [records]} with ROUTE_KEY removed.
    Records without a route go to the given defaults; insertion order is kept."""
    groups: Dict[Tuple[str, str], List[Any]] = {}
    for r in records:
        dest = (source_identifier, integration_identifier)
        if isinstance(r, dict) and ROUTE_KEY in r:
            r = dict(r)
            route = r.pop(ROUTE_KEY) or ()
            dest = (route[0] if len(route) > 0 and route[0] else source_identifier,
                    route[1] if len(route) > 1 and route[1] else integration_identifier)
        groups.setdefault(dest, []).append(r)
    return groups


class CriblDirectSender:
    """POSTs synthetic events straight into XSIAM's integrated Cribl receiver."""

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None,
                 verify_tls: bool = False, timeout: float = 30.0):
        self.url = url or os.getenv("CRIBL_COLLECTOR_URL")
        self.token = token or os.getenv("CRIBL_TOKEN")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._session = requests.Session()
        if not self.url or not self.token:
            raise ValueError("CRIBL_COLLECTOR_URL and CRIBL_TOKEN must be set (env or args).")

    def send(self, records: Sequence[Dict[str, Any]], source_identifier: str,
             integration_identifier: str = "logsim:synthetic") -> Tuple[int, str, int]:
        """Send a batch of vendor records under one dedicated Source-Identifier.

        Returns (http_status, response_text, num_records_sent). All records in a call must
        belong to the same source (same Source-Identifier). Batches freely — the real
        destination sends many NDJSON lines per POST.
        """
        records = [{k: v for k, v in r.items() if k != ROUTE_KEY}
                   if isinstance(r, dict) and ROUTE_KEY in r else r for r in records]
        if not records:
            return 0, "no records", 0
        now_ms = int(time.time() * 1000)
        ndjson = "\n".join(
            json.dumps({"data": r, "collector_ms": now_ms}, default=str) for r in records
        ) + "\n"
        body = gzip.compress(ndjson.encode("utf-8"))
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Format": "json",
            "Source-Identifier": source_identifier,
            "Integration-Identifier": integration_identifier,
        }
        resp = self._session.post(self.url, headers=headers, data=body,
                                  verify=self.verify_tls, timeout=self.timeout)
        return resp.status_code, resp.text[:200], len(records)


def send_batch(records: Sequence[Dict[str, Any]], source_identifier: str,
               integration_identifier: str = "logsim:synthetic") -> Tuple[int, str, int]:
    """One-shot convenience wrapper around CriblDirectSender.send()."""
    return CriblDirectSender().send(records, source_identifier, integration_identifier)
