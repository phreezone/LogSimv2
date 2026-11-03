"""Transport routing: each module's native pipe when it is set up, else XSIAM's Cribl receiver.

Every module has a native pipe -- the way the real product reaches XSIAM:

  syslog  Broker VM Syslog Collector  (SYSLOG_HOST + the module's syslog_port)
  http    XSIAM HTTP Log Collector    (http_collectors[collector_id] URL + key env vars)
  s3      AWS S3 bucket               (S3_BUCKET_NAME + AWS credentials)
  pubsub  GCP Pub/Sub                 (GCP_PROJECT_ID + GCP_PUBSUB_TOPIC + credentials)
  wec     Broker VM WEC               (WEC_BROKER_URL + WEC_PFX_PATH)
  cribl   XSIAM's integrated Cribl receiver (CRIBL_COLLECTOR_URL + CRIBL_TOKEN)

The module's config section names it (``transport``; "auto" or no value means the
module's NATIVE_TRANSPORT, else syslog). When that pipe is not configured, or fails on a
send with an error that retrying will not fix (connection refused, unknown host, 401/403/
404, bad credentials, missing bucket or topic), the send goes to the Cribl receiver under
the module's catalog Source-Identifier instead. A pipe that failed is retried after
``transport_retry_s`` (default 300 s); until then its sends go to Cribl.

Fallback is on by default. ``"cribl_fallback": false`` turns it off globally (top level of
config.json) or for one module (its config section). It also needs CRIBL_COLLECTOR_URL and
CRIBL_TOKEN; without them a module stays on its native pipe and logs that pipe's errors as
before.

Cribl routes. A module with a dedicated catalog UUID sets SOURCE_IDENTIFIER to it (see
integrations.cribl_direct.CATALOG). A module with none sets SOURCE_IDENTIFIER to
cribl_direct.GENERIC_UUID and XSIAM_VENDOR/XSIAM_PRODUCT; a CEF line's own header vendor
and product take precedence, so each CEF product lands where the Syslog Collector would
put it. A module may define cribl_record(payload) to reshape one payload for Cribl (the
Windows module renders its event as the XML a Cribl WEF source carries).
"""
import gzip
import json
import os
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from integrations import cribl_direct

NATIVE_TRANSPORTS = ("syslog", "http", "s3", "pubsub", "wec")
CRIBL = "cribl"
_ALIASES = {"tcp": "syslog", "auto": None, "": None}
DEFAULT_RETRY_S = 300.0

_log: Callable[[str], None] = print


def set_logger(fn: Callable[[str], None]) -> None:
    """Route this module's messages through the caller's printer (log_simulator._tprint)."""
    global _log
    _log = fn


def _placeholder(v) -> str:
    v = (v or "").strip() if isinstance(v, str) else (v or "")
    return "" if not v or str(v).startswith("PLACEHOLDER") else str(v)


# ── Which pipe a module wants ────────────────────────────────────────────────

def module_conf(module, config) -> Dict[str, Any]:
    key = getattr(module, "CONFIG_KEY", None)
    return ((config or {}).get(key) or {}) if key else {}


def preferred(module, config) -> str:
    """The module's own pipe: its config ``transport``, else NATIVE_TRANSPORT, else syslog."""
    t = str(module_conf(module, config).get("transport") or "").strip().lower()
    t = _ALIASES.get(t, t)
    if not t:
        t = getattr(module, "NATIVE_TRANSPORT", None) or "syslog"
    return t if t in NATIVE_TRANSPORTS or t == CRIBL else "syslog"


def target(transport: str, module, config) -> str:
    """What a failure is scoped to: one Broker port, one HTTP collector, else the pipe."""
    conf = module_conf(module, config)
    if transport == "syslog":
        return str(conf.get("syslog_port", (config or {}).get("SYSLOG_PORT", "514")))
    if transport == "http":
        return str(conf.get("collector_id") or "")
    return ""


# ── Is the native pipe set up? ───────────────────────────────────────────────

def http_settings(module, config) -> Tuple[str, str, str, str]:
    """(collector_id, url, auth_type, api_key) as send_http_batch reads them."""
    cid = module_conf(module, config).get("collector_id") or ""
    cc = ((config or {}).get("http_collectors") or {}).get(cid) or {}
    uvar, kvar, avar = cc.get("url_env_var"), cc.get("api_key_env_var"), cc.get("auth_type_env_var")
    url = (os.getenv(uvar) if uvar else None) or os.getenv("HTTP_COLLECTOR_URL") or ""
    auth = ((os.getenv(avar) if avar else None) or "xsiam").lower().strip()
    key = (os.getenv(kvar) if kvar else None) or ""
    return cid, url, auth, key


def s3_settings(module, config) -> Tuple[str, bool]:
    """(bucket, has_credentials) as send_s3_message reads them."""
    conf = module_conf(module, config)
    bucket = _placeholder(os.getenv("S3_BUCKET_NAME") or conf.get("s3_bucket_name"))
    creds = bool((os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"))
                 or os.getenv("AWS_PROFILE"))
    return bucket, creds


def pubsub_settings(module, config) -> Tuple[str, str, bool]:
    """(project_id, topic_id, has_credentials) as send_pubsub_message reads them."""
    conf = module_conf(module, config)
    project = _placeholder(os.getenv("GCP_PROJECT_ID") or conf.get("gcp_project_id"))
    topic = _placeholder(os.getenv("GCP_PUBSUB_TOPIC") or conf.get("pubsub_topic"))
    creds = bool(os.getenv("GCP_SERVICE_ACCOUNT_KEY_JSON")
                 or os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))
    return project, topic, creds


def wec_settings(config) -> Tuple[str, str]:
    """(broker_url, pfx_path) as _get_wec_client reads them."""
    wc = (config or {}).get("windows_events_config") or {}
    return (_placeholder(os.getenv("WEC_BROKER_URL") or wc.get("wec_broker_url")),
            _placeholder(os.getenv("WEC_PFX_PATH") or wc.get("wec_pfx_path")))


def native_ready(transport: str, module, config) -> Tuple[bool, str]:
    """(True, "") when *transport* has every setting it needs, else (False, what is missing)."""
    if transport == "syslog":
        return (True, "") if os.getenv("SYSLOG_HOST") else (False, "SYSLOG_HOST not set")
    if transport == "http":
        cid, url, auth, key = http_settings(module, config)
        if not cid:
            return False, "no collector_id"
        if not url:
            return False, f"no URL for HTTP collector '{cid}'"
        if auth != "none" and not key:
            return False, f"no key for HTTP collector '{cid}'"
        return True, ""
    if transport == "s3":
        bucket, creds = s3_settings(module, config)
        if not bucket:
            return False, "S3_BUCKET_NAME not set"
        return (True, "") if creds else (False, "AWS credentials not set")
    if transport == "pubsub":
        project, topic, creds = pubsub_settings(module, config)
        if not (project and topic):
            return False, "GCP_PROJECT_ID / GCP_PUBSUB_TOPIC not set"
        if not creds:
            return False, "GCP credentials not set"
        try:
            from google.cloud import pubsub_v1  # noqa: F401
        except ImportError:
            return False, "google-cloud-pubsub not installed"
        return True, ""
    if transport == "wec":
        broker, pfx = wec_settings(config)
        return (True, "") if broker and pfx else (False, "WEC_BROKER_URL / WEC_PFX_PATH not set")
    if transport == CRIBL:
        return (True, "") if cribl_configured() else (False, "CRIBL_COLLECTOR_URL / CRIBL_TOKEN not set")
    return False, f"unknown transport '{transport}'"


def cribl_configured() -> bool:
    return bool(os.getenv("CRIBL_COLLECTOR_URL") and os.getenv("CRIBL_TOKEN"))


def has_cribl_route(module) -> bool:
    src = getattr(module, "SOURCE_IDENTIFIER", None)
    if not src:
        return False
    if src == cribl_direct.GENERIC_UUID:
        return bool(getattr(module, "XSIAM_VENDOR", None) and getattr(module, "XSIAM_PRODUCT", None))
    return True


def fallback_enabled(module, config) -> bool:
    conf = module_conf(module, config)
    if "cribl_fallback" in conf:
        return bool(conf["cribl_fallback"])
    return bool((config or {}).get("cribl_fallback", True))


def can_fall_back(module, config) -> bool:
    return fallback_enabled(module, config) and cribl_configured() and has_cribl_route(module)


# ── Pipes that failed this run ───────────────────────────────────────────────
_down: Dict[Tuple[str, str], Tuple[float, str]] = {}   # (transport, target) -> (until, reason)
_down_lock = threading.Lock()
_announced: Dict[Tuple[str, str], str] = {}           # module name, transport -> last reason


def retry_seconds(config) -> float:
    try:
        return float((config or {}).get("transport_retry_s", DEFAULT_RETRY_S))
    except (TypeError, ValueError):
        return DEFAULT_RETRY_S


def mark_down(transport: str, module, config, reason: str) -> None:
    """Send *module*'s *transport* sends (scoped by target()) to Cribl for transport_retry_s."""
    key = (transport, target(transport, module, config))
    until = time.time() + retry_seconds(config)
    with _down_lock:
        already = key in _down and _down[key][0] > time.time()
        _down[key] = (until, reason)
    if not already:
        where = f" {key[1]}" if key[1] else ""
        _log(f"WARNING: {transport}{where} failed for {getattr(module, 'NAME', '?')} ({reason}); "
             f"sending via the Cribl receiver, retrying {transport} in {retry_seconds(config):.0f}s")


def down_reason(transport: str, module, config) -> Optional[str]:
    key = (transport, target(transport, module, config))
    with _down_lock:
        entry = _down.get(key)
        if entry and entry[0] <= time.time():
            del _down[key]
            entry = None
    return entry[1] if entry else None


def reset() -> None:
    """Forget failed pipes (tests, or a config reload)."""
    with _down_lock:
        _down.clear()
        _announced.clear()


# ── The decision ─────────────────────────────────────────────────────────────

def resolve(module, config) -> str:
    """The transport this send uses: the module's pipe when it is set up and not failing,
    else "cribl" when fallback is possible, else the module's pipe (whose sender then
    reports why it cannot deliver)."""
    pref = preferred(module, config)
    if pref == CRIBL:
        return CRIBL
    ok, why = native_ready(pref, module, config)
    if ok:
        why = down_reason(pref, module, config)
        if why is None:
            return pref
    if not can_fall_back(module, config):
        return pref
    _announce(module, pref, why)
    return CRIBL


def _announce(module, pref, why):
    name = getattr(module, "NAME", "?")
    key = (name, pref)
    with _down_lock:
        if _announced.get(key) == why:
            return
        _announced[key] = why
    _log(f"{name}: {pref} unavailable ({why}) -> Cribl receiver ({cribl_label(module)})")


def describe(module, config) -> Dict[str, Any]:
    """Routing summary for health checks and the dashboard."""
    pref = preferred(module, config)
    ok, why = native_ready(pref, module, config)
    down = down_reason(pref, module, config) if ok else None
    return {
        "module": getattr(module, "NAME", "?"),
        "preferred": pref,
        "native_ready": ok and down is None,
        "reason": why or down or "",
        "effective": resolve(module, config),
        "fallback_enabled": fallback_enabled(module, config),
        "cribl_route": cribl_label(module) if has_cribl_route(module) else None,
    }


def cribl_label(module) -> str:
    src = getattr(module, "SOURCE_IDENTIFIER", None) or ""
    if src == cribl_direct.GENERIC_UUID:
        return (f"generic {getattr(module, 'XSIAM_VENDOR', '?')}/"
                f"{getattr(module, 'XSIAM_PRODUCT', '?')}")
    for name, (uuid, dataset) in cribl_direct.CATALOG.items():
        if uuid == src:
            return dataset or name
    return src[:8] or "no route"


# ── Payloads -> Cribl records ────────────────────────────────────────────────
# A Cribl group key: (source_identifier, integration_identifier, vendor, product).
GroupKey = Tuple[str, str, Optional[str], Optional[str]]

_CEF_RE = re.compile(r"CEF:\d+\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|")


def cef_vendor_product(line: str) -> Optional[Tuple[str, str]]:
    """(vendor, product) from a CEF header anywhere in a syslog line, else None."""
    m = _CEF_RE.search(line)
    if not m:
        return None
    return m.group(1).replace("\\|", "|"), m.group(2).replace("\\|", "|")


def _s3_records(blob: bytes) -> List[Any]:
    """The CloudTrail records inside one gzipped {"Records":[...]} blob."""
    try:
        obj = json.loads(gzip.decompress(blob).decode("utf-8"))
    except Exception:
        try:
            obj = json.loads(blob.decode("utf-8"))
        except Exception:
            return []
    if isinstance(obj, dict) and "Records" in obj:
        return list(obj["Records"])
    return list(obj) if isinstance(obj, list) else [obj]


def to_cribl_records(payloads, module) -> List[Any]:
    """Native payloads (syslog lines, HTTP JSON strings, S3 blobs, Pub/Sub JSON, Windows
    event JSON, dicts) as Cribl records: dicts for JSON sources, str for text lines."""
    if not isinstance(payloads, list):
        payloads = [payloads]
    hook = getattr(module, "cribl_record", None)
    out: List[Any] = []
    for p in payloads:
        if p is None or p == "" or p == b"":
            continue
        if isinstance(p, (bytes, bytearray)):
            out.extend(_s3_records(bytes(p)))
            continue
        if callable(hook):
            p = hook(p)
            if p is None:
                continue
        if isinstance(p, str):
            s = p.strip()
            if s[:1] in "{[":
                try:
                    obj = json.loads(s)
                    out.extend(obj if isinstance(obj, list) else [obj])
                    continue
                except json.JSONDecodeError:
                    pass
            out.append(p.rstrip("\n"))
        else:
            out.append(p)
    return out


def group_records(records, module) -> Dict[GroupKey, List[Any]]:
    """{(src, integ, vendor, product): records} for *module*'s Cribl route, keeping
    insertion order. Dict records may name their own route (cribl_direct.ROUTE_KEY)."""
    src = getattr(module, "SOURCE_IDENTIFIER", None) or ""
    integ = getattr(module, "INTEGRATION_IDENTIFIER", None) or \
        f"logsim:{getattr(module, 'CONFIG_KEY', 'synthetic') or 'synthetic'}"
    generic = src == cribl_direct.GENERIC_UUID
    vendor = getattr(module, "XSIAM_VENDOR", None) if generic else None
    product = getattr(module, "XSIAM_PRODUCT", None) if generic else None
    groups: Dict[GroupKey, List[Any]] = {}
    dicts = [r for r in records if isinstance(r, dict)]
    for (s, i), recs in cribl_direct.split_routes(dicts, src, integ).items():
        groups.setdefault((s, i, vendor, product), []).extend(recs)
    for r in records:
        if isinstance(r, dict):
            continue
        r = str(r)
        v, p = (cef_vendor_product(r) or (vendor, product)) if generic else (None, None)
        groups.setdefault((src, integ, v, p), []).append(r)
    return groups
