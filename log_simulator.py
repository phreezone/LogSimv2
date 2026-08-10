import socket
import time
import random
import json
import re
import importlib
import os
import requests
import urllib3
import uuid
import boto3  # Added for S3 transport
import gzip  # S3 batch: merge/compress a run's events into one CloudTrail object
import datetime # Added for S3 transport and timestamp fixes
import sys
import threading
import copy
import contextvars  # per-run emission capture (external API run-tracking)
from dotenv import load_dotenv

# Session context helper (imported after modules dir is on path)
# We do a lazy import inside main() so the modules/ directory is guaranteed loaded first.
# Suppress only the single InsecureRequestWarning from urllib3 needed for this script
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── HTTP Circuit Breaker ────────────────────────────────────────────────────
# Tracks per-collector failure state to suppress error spam when an endpoint
# is unreachable.  After HTTP_CB_THRESHOLD consecutive failures the circuit
# opens and errors are suppressed for HTTP_CB_COOLDOWN seconds.  A single
# success resets the counter and closes the circuit.
HTTP_CB_THRESHOLD = 3          # consecutive failures before suppressing
HTTP_CB_COOLDOWN  = 60         # seconds to stay quiet before retrying
HTTP_CB_POST_TIMEOUT = 15      # seconds for a single POST request

_http_cb_state = {}   # {collector_id: {"fails": int, "open_since": float|None}}
_http_cb_lock  = threading.Lock()   # protects _http_cb_state for parallel thread safety
_print_lock    = threading.Lock()   # ensures one complete line prints at a time

# Shared HTTP session with connection pooling: high-volume runs reuse keep-alive TLS
# connections instead of doing a fresh handshake per event (the dominant cost in bulk
# training runs). pool_maxsize covers the concurrent bulk sender threads.
_http_session = requests.Session()
_http_adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32, max_retries=0)
_http_session.mount('https://', _http_adapter)
_http_session.mount('http://', _http_adapter)

# When True, suppress the routine per-event "Sending ..." success prints. A bulk run emits
# 100k+ events and the per-event console I/O (under _print_lock) is itself a bottleneck.
# Errors are always printed regardless.
_quiet_sends = False


def _tprint(*args, **kwargs):
    """Thread-safe print — holds _print_lock so parallel threads don't interleave lines."""
    with _print_lock:
        print(*args, **kwargs)

def _prepare_event_context(shared_session=None):
    ctx = {
        'user_identity': None,
        'target_user': None,
        'ip_address': None,
        'aws_region': None
    }
    if isinstance(shared_session, dict):
        # overlay known session values (ip, user_identity, aws_region)
        for k in ('user_identity','target_user','ip_address','aws_region'):
            if k in shared_session and shared_session[k] is not None:
                ctx[k] = shared_session[k]
    return ctx


def fetch_tor_exit_nodes():
    """Fetches the current list of Tor exit node IP addresses."""
    url = "https://check.torproject.org/torbulkexitlist"
    print(f"\nAttempting to fetch live Tor exit node list from {url}...")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        
        ips = response.text.strip().splitlines()
        tor_nodes = [{"ip": ip, "country": "Unknown"} for ip in ips]
        
        print(f"Successfully fetched {len(tor_nodes)} live Tor exit nodes.")
        return tor_nodes
    except requests.exceptions.RequestException as e:
        # config.json no longer ships a static fallback list (it went stale — only 1 of
        # 25 entries was still a real exit node). An empty list makes every Tor generator
        # silently fall back to a random external IP while still labelling the event as
        # Tor, so XSIAM's Tor detections stop firing with no other symptom.
        print("=" * 78)
        print(f"ERROR: Could not fetch live Tor exit nodes: {e}")
        print("       There is NO static fallback in config.json — the Tor list is EMPTY.")
        print("       Tor generators will emit ordinary external IPs labelled as Tor;")
        print("       XSIAM Tor detections WILL NOT FIRE until this fetch succeeds.")
        print("=" * 78)
        return None

def load_modules():
    """Loads all Python files from the 'modules' directory."""
    modules = {}
    module_dir = 'modules'
    if not os.path.exists(module_dir):
        print("ERROR: 'modules' directory not found. Please create it and add module files.")
        return modules
        
    for filename in os.listdir(module_dir):
        if filename.endswith('.py') and not filename.startswith('__'):
            module_name = filename[:-3]
            try:
                importlib.invalidate_caches()
                full_module_name = f'{module_dir}.{module_name}'

                # --- START: CORRECTED RELOAD LOGIC ---
                # This correctly checks if the module is already in memory and forces a reload
                if full_module_name in sys.modules:
                    module = importlib.reload(sys.modules[full_module_name])
                else:
                    module = importlib.import_module(full_module_name)
                # --- END: CORRECTED RELOAD LOGIC ---
                              
                if not hasattr(module, 'NAME'):
                    continue  # utility/helper module — not a log generator
                modules[module.NAME] = module
                print(f"Successfully loaded module: {module.NAME}")
            except Exception as e:
                print(f"Error loading module {module_name}: {e}")
    return modules
# ── Persistent Syslog TCP Connection Pool ──────────────────────────────────
# Reuses a single TCP socket per (host, port) instead of opening a new
# connection for every log line.  Reconnects automatically on failure.
_syslog_connections: dict[tuple[str, int], socket.socket] = {}
_syslog_last_used: dict[tuple[str, int], float] = {}
_syslog_lock = threading.Lock()

# A cached TCP socket idle longer than this may have been silently dropped by the
# broker/firewall (TCP half-open). Recycle it proactively so the first sends of a
# run — which happen hours after the previous run — don't vanish into a dead socket.
_SYSLOG_IDLE_MAX = 60.0


def _get_syslog_sock(host: str, port: int) -> socket.socket:
    """Return a persistent TCP socket for (host, port), recycling stale/idle ones."""
    key = (host, port)
    sock = _syslog_connections.get(key)
    now = time.time()
    if sock is not None:
        if now - _syslog_last_used.get(key, 0.0) <= _SYSLOG_IDLE_MAX:
            return sock
        # Idle too long — assume half-open and rebuild.
        _close_syslog_sock(host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.connect((host, port))
    _syslog_connections[key] = sock
    _syslog_last_used[key] = now
    return sock


def _close_syslog_sock(host: str, port: int) -> None:
    """Close and discard the cached socket for (host, port)."""
    key = (host, port)
    _syslog_last_used.pop(key, None)
    sock = _syslog_connections.pop(key, None)
    if sock:
        try:
            sock.close()
        except OSError:
            pass


def send_syslog_message(message, host, port, app_name="LogSim"):
    """Send a message over a persistent TCP syslog connection.

    Retries once on a fresh socket so a stale/half-open cached connection does
    not silently drop the triggering message (the previous behaviour lost it).
    """
    payload = f"{message}\n".encode('utf-8')
    last_err = None
    for attempt in (1, 2):
        try:
            with _syslog_lock:
                sock = _get_syslog_sock(host, port)
                sock.sendall(payload)
                _syslog_last_used[(host, port)] = time.time()
            if not _quiet_sends:
                _tprint(f"Sending Syslog for {app_name}: {host}:{port}")
            return
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError) as e:
            last_err = e
            _close_syslog_sock(host, port)  # force a fresh connection, then retry once
        except Exception as e:
            last_err = e
            _close_syslog_sock(host, port)
            break
    if isinstance(last_err, ConnectionRefusedError):
        _tprint(f"ERROR: Connection refused for Syslog. Is the Broker VM at {host}:{port} listening?")
    else:
        _tprint(f"ERROR: syslog send to {host}:{port} failed after retry ({last_err})")

def send_http_message(message, module, config):
    """
    Sends a message to the HTTP endpoint for this module's collector.

    All runtime values (URLs, keys, auth types) are read exclusively from
    environment variables — never from config.json.  config.json holds only
    the *names* of the env vars to read, following the same pattern as the
    existing api_key_env_var field.

    ── URL resolution (first set env var wins) ──────────────────────────────
      1. os.getenv(collector_conf['url_env_var'])   e.g. OKTA_COLLECTOR_URL
      2. os.getenv('HTTP_COLLECTOR_URL')            global fallback

    ── Auth type resolution ─────────────────────────────────────────────────
      1. os.getenv(collector_conf['auth_type_env_var'])  e.g. OKTA_AUTH_TYPE
      2. 'xsiam'  (default — preserves original behaviour for all existing
                   collectors that have no auth_type_env_var set)

    ── Auth type values ─────────────────────────────────────────────────────
      xsiam       (default) Authorization: <raw_key>
                  + x-palo-alto-networks-vendor/product headers.
                  Used for direct XSIAM HTTP Log Collector ingestion.
                  NOTE: Also works for Cribl — Cribl accepts bare tokens and
                  simply ignores the extra PA vendor headers.

      splunk_hec  Authorization: Splunk <token>
                  For Cribl Splunk HEC Source (recommended Cribl inbound type).
                  Cribl also accepts a bare token here, but this is explicit.

      basic       Authorization: Basic <base64(user:pass)>
                  Set the corresponding *_KEY to "username:password".

      none        No Authorization header — open or IP-restricted endpoint.

    .env.example entries for the Okta→Cribl Splunk HEC use-case:
      OKTA_COLLECTOR_URL=https://your-cribl-host:8088/services/collector/event
      OKTA_AUTH_TYPE=splunk_hec
      OKTA_KEY=your-cribl-hec-token
    """
    conf_key = getattr(module, 'CONFIG_KEY', None)
    if not conf_key or conf_key not in config:
        return

    module_conf    = config.get(conf_key, {})
    collector_id   = module_conf.get('collector_id')
    collector_conf = config.get('http_collectors', {}).get(collector_id)
    if not collector_conf:
        return

    # ── URL ──────────────────────────────────────────────────────────────────
    url_env_var = collector_conf.get('url_env_var')
    url = (os.getenv(url_env_var) if url_env_var else None) or os.getenv('HTTP_COLLECTOR_URL')
    if not url:
        _tprint(f"Error: No destination URL for collector '{collector_id}'. "
               f"Set {url_env_var or 'HTTP_COLLECTOR_URL'} in your .env file.")
        return

    # ── Auth type ─────────────────────────────────────────────────────────────
    auth_type_env_var = collector_conf.get('auth_type_env_var')
    auth_type = (os.getenv(auth_type_env_var) if auth_type_env_var else None) or 'xsiam'
    auth_type = auth_type.lower().strip()

    # ── API key / token ───────────────────────────────────────────────────────
    api_key_env_var = collector_conf.get('api_key_env_var')
    api_key = os.getenv(api_key_env_var) if api_key_env_var else None

    # ── Build headers ─────────────────────────────────────────────────────────
    headers = {'Content-Type': collector_conf.get('content_type', 'application/json')}

    if auth_type == 'xsiam':
        # Direct XSIAM HTTP Log Collector — bare token + PA vendor headers.
        # Also works for Cribl: Cribl accepts bare tokens and ignores the extra headers.
        if not api_key:
            _tprint(f"Error: {module.NAME} key not found — set {api_key_env_var} in .env")
            return
        headers['Authorization'] = api_key
        headers['x-palo-alto-networks-vendor'] = getattr(module, 'XSIAM_VENDOR', 'Custom')
        headers['x-palo-alto-networks-product'] = getattr(module, 'XSIAM_PRODUCT', 'LogSim')

    elif auth_type == 'splunk_hec':
        # Cribl Splunk HEC Source (and real Splunk HEC).
        # HEC requires payload wrapped as {"event": <data>} -- we handle that below
        # before the POST so the caller never needs to know.
        if not api_key:
            _tprint(f"Error: {module.NAME} Splunk HEC token not found -- set {api_key_env_var} in .env")
            return
        headers['Authorization'] = f"Splunk {api_key}"
        # Wrap plain JSON string into HEC envelope {"event": <parsed_object>}
        try:
            message = json.dumps({"event": json.loads(message)})
        except (json.JSONDecodeError, TypeError):
            # If message isn't valid JSON, wrap it as a raw string value
            message = json.dumps({"event": message})

    elif auth_type == 'basic':
        import base64
        if not api_key:
            _tprint(f"Error: {module.NAME} basic-auth credentials not found — set {api_key_env_var} in .env")
            return
        headers['Authorization'] = f"Basic {base64.b64encode(api_key.encode()).decode()}"

    elif auth_type == 'none':
        pass  # open / IP-restricted endpoint

    else:
        _tprint(f"Warning: Unknown {auth_type_env_var}='{auth_type}' for '{collector_id}'. Skipping auth header.")

    # ── Circuit breaker check ────────────────────────────────────────────────
    cb = _http_cb_state.setdefault(collector_id, {"fails": 0, "open_since": None})
    now = time.time()
    if cb["open_since"] is not None:
        elapsed = now - cb["open_since"]
        if elapsed < HTTP_CB_COOLDOWN:
            return
        else:
            _tprint(f"[HTTP] Circuit re-closing for {module.NAME} after {int(elapsed)}s cooldown — retrying...")
            cb["fails"] = 0
            cb["open_since"] = None

    try:
        response = _http_session.post(url, headers=headers, data=message,
                                      verify=False, timeout=HTTP_CB_POST_TIMEOUT)
        if response.status_code not in [200, 202, 204]:
            _tprint(f"HTTP send error for {module.NAME}: status {response.status_code} — {response.text[:120]}")
            cb["fails"] += 1
        else:
            cb["fails"] = 0
            if not _quiet_sends:
                _tprint(f"Sending HTTP for {module.NAME}: {collector_id} -> {response.status_code}")

    except requests.exceptions.Timeout:
        cb["fails"] += 1
        if cb["fails"] <= HTTP_CB_THRESHOLD:
            _tprint(f"HTTP send error for {module.NAME}: timed out after {HTTP_CB_POST_TIMEOUT}s "
                    f"(failure {cb['fails']}/{HTTP_CB_THRESHOLD})")
    except requests.exceptions.ConnectionError as e:
        cb["fails"] += 1
        if cb["fails"] <= HTTP_CB_THRESHOLD:
            _tprint(f"HTTP send error for {module.NAME}: {str(e).replace(chr(10), ' ')} "
                    f"(failure {cb['fails']}/{HTTP_CB_THRESHOLD})")
    except requests.exceptions.RequestException as e:
        cb["fails"] += 1
        if cb["fails"] <= HTTP_CB_THRESHOLD:
            _tprint(f"HTTP send error for {module.NAME}: {e} "
                    f"(failure {cb['fails']}/{HTTP_CB_THRESHOLD})")

    if cb["fails"] >= HTTP_CB_THRESHOLD and cb["open_since"] is None:
        cb["open_since"] = now
        _tprint(f"[HTTP] Circuit OPEN for {module.NAME} after {HTTP_CB_THRESHOLD} failures. "
                f"Suppressing errors for {HTTP_CB_COOLDOWN}s.")

# ── Cached S3 client ────────────────────────────────────────────────────────
# Creating a new boto3 Session + S3 client on every PUT adds ~50-100ms of
# overhead.  Cache the client per (access_key, region) so subsequent uploads
# reuse the existing HTTPS connection pool.
_s3_client_cache: dict[tuple, "boto3.client"] = {}
_s3_client_lock = threading.Lock()


def _get_s3_client(region: str):
    """Return a cached boto3 S3 client for the given region."""
    key_id = os.getenv('AWS_ACCESS_KEY_ID', '')
    cache_key = (key_id, region)
    with _s3_client_lock:
        client = _s3_client_cache.get(cache_key)
        if client is not None:
            return client
        session = boto3.Session(
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=region,
        )
        client = session.client('s3')
        _s3_client_cache[cache_key] = client
        return client


# --- S3 batch buffer ---------------------------------------------------------
# Accumulate a scenario run's AWS events and write them as ONE CloudTrail-style
# object ({"Records":[...]}) at flush. Real CloudTrail batches many events per
# S3 object; doing the same here means one object per run for the collector to
# pull instead of ~8 tiny objects, which eliminates the per-object partial
# pickup we were seeing (steps landing intermittently).
# Batches are keyed PER MODULE so different AWS log types (CloudTrail vs GuardDuty)
# never merge into one object — they use different S3 prefixes AND different on-disk
# formats (CloudTrail = {"Records":[...]}.json.gz, GuardDuty = newline-delimited
# .jsonl.gz), which the collector parses with different log-type parsers.
_s3_batches = {}          # module.NAME -> {"blobs": [...], "module": mod, "config": cfg}
_s3_batch_lock = threading.Lock()


_s3_last_enqueue = [0.0]
_s3_oldest_enqueue = [0.0]   # when the current batch started filling; 0 = empty
_s3_flusher_started = [False]

# Flush triggers. Idle alone is NOT enough: a module running at an interval shorter
# than the idle threshold (the AWS module defaults to 1s) never goes quiet, so the
# batch grew in memory forever and nothing was ever uploaded. Size and age caps
# guarantee delivery under continuous load while keeping the batching behaviour that
# lets a whole scenario ride one collector pull.
_S3_FLUSH_IDLE_S = 4        # quiet period => end of a burst, flush what we have
_S3_FLUSH_MAX_AGE_S = 30    # never let an event sit buffered longer than this
_S3_FLUSH_MAX_EVENTS = 500  # cap batch size so one object stays reasonable


def _ensure_s3_flusher():
    """Start a background thread that auto-flushes the S3 batches a few seconds
    after events stop arriving. This makes batching work even if no explicit
    flush hook runs (e.g. an entry point that never calls flush_s3_batch) — so
    AWS events can never get stranded in the buffer."""
    with _s3_batch_lock:
        if _s3_flusher_started[0]:
            return
        _s3_flusher_started[0] = True

    def _loop():
        while True:
            time.sleep(1)
            with _s3_batch_lock:
                pending = sum(len(g["blobs"]) for g in _s3_batches.values())
                now = time.time()
                idle = now - _s3_last_enqueue[0]
                age = (now - _s3_oldest_enqueue[0]) if _s3_oldest_enqueue[0] else 0.0
            if pending and (idle >= _S3_FLUSH_IDLE_S
                            or age >= _S3_FLUSH_MAX_AGE_S
                            or pending >= _S3_FLUSH_MAX_EVENTS):
                try:
                    flush_s3_batch()
                except Exception as e:
                    # Never silent: a failure here means events were dropped, and
                    # the symptom (nothing in S3) looks identical to not generating.
                    _tprint(f"ERROR: S3 batch flush failed: {e}")

    threading.Thread(target=_loop, daemon=True, name="s3-batch-flusher").start()


def _enqueue_s3(content_bytes, module, config):
    """Buffer one gzipped single-event blob for the current run, grouped by module."""
    with _s3_batch_lock:
        key = getattr(module, 'NAME', 'unknown')
        grp = _s3_batches.setdefault(key, {"blobs": [], "module": module, "config": config})
        grp["blobs"].append(content_bytes)
        grp["module"] = module
        grp["config"] = config
        _s3_last_enqueue[0] = time.time()
        if not _s3_oldest_enqueue[0]:
            # First blob of a new batch — starts the max-age clock.
            _s3_oldest_enqueue[0] = _s3_last_enqueue[0]
    _ensure_s3_flusher()


def flush_s3_batch():
    """Merge each module's buffered blobs into ONE object and upload it, using that
    module's on-disk format. Called at the end of each scenario run."""
    with _s3_batch_lock:
        if not _s3_batches:
            return
        groups = list(_s3_batches.values())
        _s3_batches.clear()
        _s3_oldest_enqueue[0] = 0.0   # batch drained; restart the max-age clock

    for grp in groups:
        module = grp.get("module")
        config = grp.get("config")
        blobs = grp.get("blobs", [])
        # `not config` would treat a valid-but-empty config dict as "no config" and
        # drop the whole batch, which looks identical to the events never being
        # generated. Test for absence explicitly, and never drop in silence.
        if not module or config is None or not blobs:
            if blobs:
                _tprint(f"ERROR: dropping {len(blobs)} buffered S3 events for "
                        f"module={getattr(module, 'NAME', module)!r} - missing "
                        f"{'module' if not module else 'config'}")
            continue
        records = []
        for b in blobs:
            try:
                obj = json.loads(gzip.decompress(b).decode("utf-8"))
            except Exception:
                continue
            if isinstance(obj, dict) and "Records" in obj:
                records.extend(obj["Records"])
            elif isinstance(obj, list):
                records.extend(obj)
            else:
                records.append(obj)
        if not records:
            continue

        # Format the merged object per the module's declared S3 record format.
        fmt = getattr(module, 'S3_RECORD_FORMAT', 'cloudtrail_records')
        if fmt == 'jsonl':
            # GuardDuty findings export: newline-delimited JSON, one finding per line.
            body = "\n".join(json.dumps(r, default=str) for r in records)
        else:
            # CloudTrail: single {"Records":[...]} envelope.
            body = json.dumps({"Records": records}, default=str)
        merged = gzip.compress(body.encode("utf-8"))
        send_s3_message(merged, module, config, f"batch:{len(records)} events")


def send_s3_message(content_bytes, module, config, event_name):
    event_str = f" ({event_name})" if event_name else ""

    """Uploads a gzipped log file to S3."""
    conf_key = getattr(module, 'CONFIG_KEY', None)
    if not conf_key or conf_key not in config:
        return

    try:
        # Use timezone-aware datetime object
        now = datetime.datetime.now(datetime.UTC)

        # Get the 'aws_config' section from config.json for fallback values
        aws_conf = config.get(conf_key, {})

        # Retrieve variables: Prioritize .env (os.getenv) > config.json > Safe Default
        # AWS_ACCOUNT_ID
        account_id = os.getenv('AWS_ACCOUNT_ID', aws_conf.get('aws_account_id', '123456789012'))

        # AWS_REGION
        region = os.getenv('AWS_REGION', aws_conf.get('aws_region', 'us-east-1'))

        # S3 bucket. A module may declare its own bucket env var (S3_BUCKET_ENV) so a
        # separate log type (e.g. GuardDuty) can land in its own bucket; otherwise it
        # falls back to the shared S3_BUCKET_NAME (same bucket, different prefix).
        bucket_env = getattr(module, 'S3_BUCKET_ENV', None)
        bucket_name = (os.getenv(bucket_env) if bucket_env else None) \
                      or os.getenv('S3_BUCKET_NAME') or aws_conf.get('s3_bucket_name')

        if not bucket_name:
            print(f"ERROR: S3 bucket is not defined ({bucket_env or 'S3_BUCKET_NAME'} in .env / '{conf_key}' in config.json). Cannot upload log.")
            return

        # Build the object key from the module's declared log type. GuardDuty's native
        # export is <prefix>/<UUID>.jsonl.gz (flat, no date partition); CloudTrail is a
        # date-partitioned {"Records":[...]}.json.gz object.
        log_type = getattr(module, 'S3_LOG_TYPE', 'CloudTrail')
        if log_type == 'GuardDuty':
            file_name = f"{uuid.uuid4().hex}.jsonl.gz"
            s3_key = f"AWSLogs/{account_id}/GuardDuty/{region}/{file_name}"
        else:
            file_name = f"{account_id}_CloudTrail_{region}_{now.strftime('%Y%m%dT%H%MZ')}_{str(uuid.uuid4())[:6].upper()}.json.gz"
            s3_key = f"AWSLogs/{account_id}/CloudTrail/{region}/{now.strftime('%Y/%m/%d')}/{file_name}"

        _tprint(f"Sending S3 for {module.NAME}{event_str}: Uploading {file_name} to {bucket_name}/{s3_key}")

        # Retry with backoff so a transient S3 error doesn't silently drop the
        # event. Rebuild the client on each failed attempt in case it went stale.
        last_err = None
        for _attempt in range(3):
            try:
                _get_s3_client(region).put_object(
                    Bucket=bucket_name,
                    Key=s3_key,
                    Body=content_bytes,
                    ContentEncoding='gzip',
                    ContentType='application/json'
                )
                last_err = None
                break
            except Exception as e:
                last_err = e
                with _s3_client_lock:
                    _s3_client_cache.pop((os.getenv('AWS_ACCESS_KEY_ID', ''), region), None)
                time.sleep(0.5 * (_attempt + 1))
        if last_err is not None:
            _tprint(f"ERROR: S3 put failed after 3 attempts ({file_name}): {last_err}")

    except ImportError:
        _tprint("ERROR: 'boto3' library not found. Please install it with 'pip install boto3' to use S3 transport.")


def send_pubsub_message(message_data, module, config, event_name=None):
    """
    Publishes a single log entry (JSON string) to a Google Cloud Pub/Sub topic.

    Authentication uses one of two methods (checked in order):
      1. GCP_SERVICE_ACCOUNT_KEY_JSON env var — inline JSON key content
      2. GOOGLE_APPLICATION_CREDENTIALS env var — path to a service account
         JSON key file (standard ADC; also works with Workload Identity)

    Required env vars (or config.json fallback):
      GCP_PROJECT_ID   — GCP project that owns the Pub/Sub topic
      GCP_PUBSUB_TOPIC — topic name (not full resource path)
    """
    try:
        from google.cloud import pubsub_v1
    except ImportError:
        _tprint("ERROR: 'google-cloud-pubsub' not installed. "
               "Run: pip install google-cloud-pubsub")
        return

    conf_key = getattr(module, 'CONFIG_KEY', None)
    module_conf = config.get(conf_key, {}) if conf_key else {}

    project_id = os.getenv('GCP_PROJECT_ID', module_conf.get('gcp_project_id', ''))
    topic_id   = os.getenv('GCP_PUBSUB_TOPIC', module_conf.get('pubsub_topic', ''))

    if not project_id or not topic_id:
        _tprint("WARNING: Pub/Sub not configured — set GCP_PROJECT_ID and "
               "GCP_PUBSUB_TOPIC in .env or config.json gcp_config section.")
        return

    event_str = f" ({event_name})" if event_name else ""

    # Build publisher client with explicit credentials if inline key is supplied
    inline_key_json = os.getenv('GCP_SERVICE_ACCOUNT_KEY_JSON')
    try:
        if inline_key_json:
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_info(
                json.loads(inline_key_json),
                scopes=["https://www.googleapis.com/auth/pubsub"],
            )
            publisher = pubsub_v1.PublisherClient(credentials=creds)
        else:
            # Falls back to GOOGLE_APPLICATION_CREDENTIALS or ADC
            publisher = pubsub_v1.PublisherClient()

        topic_path = publisher.topic_path(project_id, topic_id)
        data = message_data.encode('utf-8') if isinstance(message_data, str) else message_data

        _tprint(f"Sending Pub/Sub for {module.NAME}{event_str}: "
               f"Publishing to {project_id}/{topic_id}")

        future = publisher.publish(topic_path, data)
        future.result(timeout=10)

    except Exception as e:
        _tprint(f"ERROR: Pub/Sub publish failed for {module.NAME}{event_str}: {e}")


# ── Throughput counter (shared across all calls to process_and_send) ─────────
_throughput_counter = {"count": 0, "last_report": time.time(), "last_count": 0}
_throughput_lock    = threading.Lock()   # protects _throughput_counter for parallel threads
THROUGHPUT_REPORT_INTERVAL = 10  # seconds


def _increment_throughput():
    """Thread-safe increment of the throughput counter."""
    with _throughput_lock:
        _throughput_counter["count"] += 1


def _maybe_report_throughput():
    """Prints a throughput summary every THROUGHPUT_REPORT_INTERVAL seconds."""
    with _throughput_lock:
        now = time.time()
        elapsed = now - _throughput_counter["last_report"]
        if elapsed < THROUGHPUT_REPORT_INTERVAL:
            return
        logs_in_window = _throughput_counter["count"] - _throughput_counter["last_count"]
        snapshot_count = _throughput_counter["count"]
        _throughput_counter["last_report"] = now
        _throughput_counter["last_count"]  = snapshot_count
    rate_sec = logs_in_window / elapsed if elapsed > 0 else 0
    rate_min = rate_sec * 60
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] Throughput: {logs_in_window} logs in {elapsed:.1f}s "
          f"= {rate_sec:.0f}/sec ({rate_min:.0f}/min)")


# ── WEC Transport (Direct WS-Management to Broker VM) ────────────────────
_wec_client = None
_wec_client_lock = threading.Lock()
_wec_batch = []
_wec_batch_lock = threading.Lock()
_wec_batch_timer = None
_wec_cb_state = {"fails": 0, "open_since": None}

def _get_wec_client(config):
    """Lazy-init the WecClient singleton. Returns None on failure."""
    global _wec_client
    if _wec_client is not None:
        return _wec_client
    with _wec_client_lock:
        if _wec_client is not None:
            return _wec_client
        try:
            from modules.wec_transport import WecClient, WecTransportError
            wec_cfg = config.get("windows_events_config", {})
            broker_url = os.getenv("WEC_BROKER_URL") or wec_cfg.get("wec_broker_url", "")
            pfx_path = os.getenv("WEC_PFX_PATH") or wec_cfg.get("wec_pfx_path", "")
            pfx_password = os.getenv("WEC_PFX_PASSWORD") or wec_cfg.get("wec_pfx_password", "")
            machine_id = wec_cfg.get("wec_machine_id", "logsim.examplecorp.local")
            if not broker_url or not pfx_path:
                _tprint("Error: WEC transport requires WEC_BROKER_URL and WEC_PFX_PATH. "
                        "Set them in .env or config.json.")
                return None
            client = WecClient(broker_url, pfx_path, pfx_password, machine_id)
            client.enumerate()
            hb_interval = wec_cfg.get("wec_heartbeat_interval_s", 900)
            client.start_heartbeat_thread(interval_s=hb_interval)
            _wec_client = client
            _tprint(f"WEC transport connected: subscription={client.subscription_id}")
            return client
        except Exception as exc:
            _tprint(f"Error: WEC transport init failed: {exc}")
            return None


def _flush_wec_batch(config):
    """Send accumulated WEC events in a single SOAP POST."""
    global _wec_batch_timer
    with _wec_batch_lock:
        batch = _wec_batch[:]
        _wec_batch.clear()
        _wec_batch_timer = None
    if not batch:
        return
    client = _get_wec_client(config)
    if not client:
        return
    try:
        client.deliver_events(batch)
        with _wec_batch_lock:
            _wec_cb_state["fails"] = 0
            _wec_cb_state["open_since"] = None
    except Exception as exc:
        with _wec_batch_lock:
            _wec_cb_state["fails"] += 1
            if _wec_cb_state["fails"] >= HTTP_CB_THRESHOLD:
                if _wec_cb_state["open_since"] is None:
                    _wec_cb_state["open_since"] = time.time()
                    _tprint(f"WEC circuit breaker OPEN after {HTTP_CB_THRESHOLD} failures: {exc}")


def send_wec_message(message, module, config):
    """Queue a Windows event for WEC transport (batched delivery)."""
    global _wec_batch_timer
    # Circuit breaker check
    with _wec_batch_lock:
        if _wec_cb_state["open_since"]:
            if time.time() - _wec_cb_state["open_since"] < HTTP_CB_COOLDOWN:
                return
            _wec_cb_state["open_since"] = None
            _wec_cb_state["fails"] = 0

    try:
        ev = json.loads(message) if isinstance(message, str) else message
    except (json.JSONDecodeError, TypeError):
        _tprint(f"Warning: {module.NAME} WEC transport received non-JSON content. Skipping.")
        return

    from modules.windows_events import _render_event_xml
    try:
        xml_str = _render_event_xml(ev)
    except Exception as exc:
        _tprint(f"Warning: WEC XML render failed: {exc}")
        return

    wec_cfg = config.get("windows_events_config", {})
    batch_size = wec_cfg.get("wec_batch_size", 20)
    batch_interval_ms = wec_cfg.get("wec_batch_interval_ms", 1000)

    with _wec_batch_lock:
        _wec_batch.append(xml_str)
        if len(_wec_batch) >= batch_size:
            threading.Thread(target=_flush_wec_batch, args=(config,),
                             daemon=True).start()
        elif _wec_batch_timer is None:
            _wec_batch_timer = threading.Timer(
                batch_interval_ms / 1000.0,
                _flush_wec_batch, args=(config,))
            _wec_batch_timer.daemon = True
            _wec_batch_timer.start()


# ── Capture / dry-run hook (used by the training-mode determinism verifier) ──
# When _capture_sink is a list, every payload passed to process_and_send is
# appended as (module_name, event_name, payload) BEFORE sending. When _dry_run
# is True, process_and_send records and returns without actually sending — so a
# pack can be replayed for a content-equality diff with no network I/O.
_capture_sink = None      # list | None
_dry_run = False
# When set (list), process_and_send COLLECTS (module, payload, event_name) and returns
# without sending. Training bulk generates under a frozen clock (freezegun serializes calls
# while active, so sends can't parallelize there) then replays the collected payloads through
# a parallel sender AFTER leaving the freeze. Unlike _capture_sink this keeps the module object
# so the payload can actually be sent, and unlike _dry_run it is training-only.
_bulk_collector = None

# ── Per-run emission capture (external API / MCP run-tracking) ────────────────
# A ContextVar (NOT a module global) so concurrent scenario runs stay isolated and
# baseline module traffic — which flows through the async _SEND_QUEUE on a different
# thread — is never miscounted into a run. The dashboard sets this around a scenario's
# thread via capture_run(); every process_and_send in THAT thread records into it.
# Scenarios are single-threaded and call process_and_send directly (verified), so the
# ContextVar set at the top of the scenario thread is visible to all of the run's sends.
_run_collector: "contextvars.ContextVar" = contextvars.ContextVar("logsim_run_collector", default=None)


class RunCapture:
    """Thread-safe tally of what a single scenario run emitted. `.record()` is called
    from process_and_send for every payload sent during the run. Reports EMISSION only
    (what LogSim sent) — NOT what fired/detected in XSIAM (that's the xql-builder side)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total = 0
        self.by_module = {}   # module_name -> count
        self.by_event = {}    # "module_name/event_name" -> count

    def record(self, module_name, event_name, payload):
        # For list payloads (HTTP/WEC multi-event), count each element; else one event.
        n = len(payload) if isinstance(payload, list) else 1
        key = f"{module_name}/{event_name}" if event_name else module_name
        with self._lock:
            self.total += n
            self.by_module[module_name] = self.by_module.get(module_name, 0) + n
            self.by_event[key] = self.by_event.get(key, 0) + n

    def manifest(self):
        with self._lock:
            return {
                "total_events": self.total,
                "by_module": dict(self.by_module),
                "by_event": dict(self.by_event),
            }


class capture_run:
    """Context manager: while active, every process_and_send call in the CURRENT thread
    records into *collector*. Usage:  with capture_run(collector): scenario_func(...)."""

    def __init__(self, collector):
        self._collector = collector
        self._token = None

    def __enter__(self):
        self._token = _run_collector.set(self._collector)
        return self._collector

    def __exit__(self, *exc):
        if self._token is not None:
            _run_collector.reset(self._token)
        return False


# Regexes for blanking volatile timestamps so two runs can be compared on content
# alone (event-time intentionally differs between bulk backfill and live stream).
_MON = r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
_TS_ISO_RE   = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?')
# Apache Common Log Format:  18/Jul/2026:14:38:51 +0000
_TS_CLF_RE   = re.compile(r'\d{1,2}/' + _MON + r'/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4}')
# BSD syslog header:  Jul 18 14:38:51  (day may be space-padded)
_TS_SYSLOG_RE = re.compile(_MON + r'\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')
# LDAP/AD GeneralizedTime (Windows whenChanged etc.):  20260719132733.0Z
# (no leading \b — it is often preceded by a word char like the 't' of a literal \t)
_TS_GENTIME_RE = re.compile(r'(?<!\d)\d{14}(?:\.\d+)?Z')
# US human-readable (AWS consoles etc.):  Jul 26, 2026, 01:30:01 PM
_TS_USDATE_RE = re.compile(_MON + r' \d{1,2}, \d{4}, \d{2}:\d{2}:\d{2} [AP]M')
# Epoch seconds (10), milliseconds (13), microseconds (16), or nanoseconds (19 digits;
# e.g. FortiGate FTNTFGTeventtime), optional fraction.
_TS_EPOCH_RE = re.compile(r'\b\d{10}(?:\d{3}){0,3}(?:\.\d+)?\b')


def _strip_volatile(payload):
    """Return a copy of *payload* with all timestamp formats blanked, so two runs can
    be diffed on content (users, IPs, hostnames, GUIDs, ordering) alone. Event-time is
    intentionally different between bulk backfill and live stream, so it must not count
    as a content difference. Covers ISO-8601, Apache CLF, BSD syslog, and epoch
    (s/ms/µs) timestamps."""
    if isinstance(payload, (bytes, bytearray)):
        # S3/CloudTrail events arrive gzipped; decompress so the JSON inside can be
        # compared on content (raw gzip bytes differ by embedded mtime + compressed
        # timestamps and are not meaningful to diff).
        if len(payload) >= 2 and payload[0] == 0x1f and payload[1] == 0x8b:
            try:
                payload = gzip.decompress(bytes(payload))
            except Exception:
                pass
        try:
            payload = payload.decode('utf-8', 'replace')
        except Exception:
            return payload
    if not isinstance(payload, str):
        payload = str(payload)
    payload = _TS_ISO_RE.sub('<TS>', payload)
    payload = _TS_CLF_RE.sub('<CLF>', payload)
    payload = _TS_SYSLOG_RE.sub('<SYSLOG>', payload)
    payload = _TS_USDATE_RE.sub('<USDATE>', payload)
    payload = _TS_GENTIME_RE.sub('<GENTIME>', payload)
    payload = _TS_EPOCH_RE.sub('<EPOCH>', payload)
    return payload


# ── Timestamp shifting (training capture-replay) ─────────────────────────────
# The same locators used to BLANK timestamps are reused to SHIFT them by a fixed
# delta: the training canonical is generated at a constant synthetic anchor time, then
# replayed with every timestamp moved to the target window (bulk: now-4h..now; stream:
# now..now+4h). Correctness invariant: _strip_volatile(shift(p, d)) == _strip_volatile(p)
# — shifting must touch ONLY timestamps, never structure.

def _shift_iso(s, delta):
    try:
        core = s
        tz = ''
        if core.endswith('Z'):
            core, tz = core[:-1], 'Z'
        elif len(core) >= 6 and core[-6] in '+-' and core[-3] == ':':
            core, tz = core[:-6], core[-6:]
        elif len(core) >= 5 and core[-5] in '+-':
            core, tz = core[:-5], core[-5:]
        has_ms = '.' in core
        fmt = '%Y-%m-%dT%H:%M:%S' if 'T' in core else '%Y-%m-%d %H:%M:%S'
        if has_ms:
            fmt += '.%f'
        dt = datetime.datetime.strptime(core, fmt) + datetime.timedelta(seconds=delta)
        out = dt.strftime('%Y-%m-%dT%H:%M:%S' if 'T' in core else '%Y-%m-%d %H:%M:%S')
        if has_ms:
            out += '.' + f"{dt.microsecond:06d}"[:len(core.split('.')[1])]
        return out + tz
    except Exception:
        return s


def _shift_clf(s, delta):
    try:
        dt = datetime.datetime.strptime(s, '%d/%b/%Y:%H:%M:%S %z') + datetime.timedelta(seconds=delta)
        return dt.strftime('%d/%b/%Y:%H:%M:%S %z')
    except Exception:
        return s


def _shift_syslog(s, delta):
    # BSD syslog has no year; anchor to a leap-safe reference year to compute the shift,
    # then re-emit month/day/time (day space-padded, as RFC 3164).
    try:
        parts = s.split()
        norm = f"{parts[0]} {int(parts[1]):02d} {parts[2]}"
        dt = datetime.datetime.strptime(f"2024 {norm}", '%Y %b %d %H:%M:%S') + datetime.timedelta(seconds=delta)
        return dt.strftime('%b %d %H:%M:%S')
    except Exception:
        return s


def _shift_usdate(s, delta):
    try:
        dt = datetime.datetime.strptime(s, '%b %d, %Y, %I:%M:%S %p') + datetime.timedelta(seconds=delta)
        return dt.strftime('%b %d, %Y, %I:%M:%S %p')
    except Exception:
        return s


def _shift_gentime(s, delta):
    try:
        frac = ''
        base = s[:-1]  # drop Z
        if '.' in base:
            base, frac = base.split('.', 1)
            frac = '.' + frac
        dt = datetime.datetime.strptime(base, '%Y%m%d%H%M%S') + datetime.timedelta(seconds=delta)
        return dt.strftime('%Y%m%d%H%M%S') + frac + 'Z'
    except Exception:
        return s


# Epoch shifts are the one ambiguous case: a bare 10-19 digit number could be a real epoch
# OR a non-timestamp ID (Zscaler externalId, session IDs, byte counts). Shifting the wrong
# one corrupts content. So epochs are shifted ONLY when they sit within EPOCH_SHIFT_MARGIN
# of the known anchor — real event-times do, arbitrary IDs almost never.
_EPOCH_SHIFT_MARGIN = 400 * 86400  # seconds


def _shift_epoch(s, delta, anchor_epoch=None):
    try:
        digits = s.split('.')[0]
        scale = {10: 1, 13: 1_000, 16: 1_000_000, 19: 1_000_000_000}.get(len(digits))
        if scale is None:
            return s
        val = float(s) if '.' in s else int(s)
        if anchor_epoch is not None and abs(val / scale - anchor_epoch) > _EPOCH_SHIFT_MARGIN:
            return s  # not a timestamp near the anchor — leave it alone
        shifted = val + delta * scale
        if '.' in s:
            return f"{shifted:.{len(s.split('.')[1])}f}"
        return str(int(round(shifted)))
    except Exception:
        return s


def shift_timestamps(payload, delta_seconds, anchor_epoch=None):
    """Return *payload* with every recognized timestamp moved by delta_seconds. Handles
    str and gzipped-bytes (S3) payloads; re-gzips bytes on the way out. `anchor_epoch`
    (the canonical's base time) guards epoch shifting against non-timestamp IDs."""
    if delta_seconds == 0:
        return payload
    was_bytes = isinstance(payload, (bytes, bytearray))
    gz = False
    if was_bytes:
        if len(payload) >= 2 and payload[0] == 0x1f and payload[1] == 0x8b:
            try:
                payload = gzip.decompress(bytes(payload)); gz = True
            except Exception:
                return payload
        try:
            s = payload.decode('utf-8')
        except Exception:
            return payload
    elif isinstance(payload, str):
        s = payload
    else:
        return payload

    s = _TS_ISO_RE.sub(lambda m: _shift_iso(m.group(0), delta_seconds), s)
    s = _TS_CLF_RE.sub(lambda m: _shift_clf(m.group(0), delta_seconds), s)
    s = _TS_SYSLOG_RE.sub(lambda m: _shift_syslog(m.group(0), delta_seconds), s)
    s = _TS_USDATE_RE.sub(lambda m: _shift_usdate(m.group(0), delta_seconds), s)
    s = _TS_GENTIME_RE.sub(lambda m: _shift_gentime(m.group(0), delta_seconds), s)
    s = _TS_EPOCH_RE.sub(lambda m: _shift_epoch(m.group(0), delta_seconds, anchor_epoch), s)

    if was_bytes:
        out = s.encode('utf-8')
        return gzip.compress(out) if gz else out
    return s


def process_and_send(log_content, module, config, event_name=None):
    """Determines how to send the log and sends it. Counts logs for throughput reporting."""
    transport = "syslog"
    if not log_content:
        return

    if _capture_sink is not None:
        _capture_sink.append((getattr(module, 'NAME', '?'), event_name, log_content))
    _rc = _run_collector.get()
    if _rc is not None:
        try:
            _rc.record(getattr(module, 'NAME', '?'), event_name, log_content)
        except Exception:
            pass
    if _dry_run:
        return
    if _bulk_collector is not None:
        _bulk_collector.append((module, log_content, event_name))
        return

    conf_key = getattr(module, 'CONFIG_KEY', None)
    module_config = {}
    if conf_key and conf_key in config:
        module_config = config.get(conf_key, {})
        transport = module_config.get("transport", "syslog")

    if transport == "s3":
        if isinstance(log_content, bytes):
            # Buffer for one batched upload per run (see flush_s3_batch).
            _enqueue_s3(log_content, module, config)
            _increment_throughput()
        else:
            event_str = f" ({event_name})" if event_name else ""
            _tprint(f"Warning: Module {module.NAME}{event_str} is configured for S3 but did not return bytes content. Skipping.")
    elif transport == "http":
        if isinstance(log_content, list):
            for msg in log_content:
                send_http_message(msg, module, config)
                _increment_throughput()
        elif isinstance(log_content, str):
            send_http_message(log_content, module, config)
            _increment_throughput()
        else:
            event_str = f" ({event_name})" if event_name else ""
            _tprint(f"Warning: Module {module.NAME}{event_str} wants HTTP transport but did not return a string or list of strings. Skipping.")
    elif transport == "wec":
        if isinstance(log_content, list):
            for msg in log_content:
                send_wec_message(msg, module, config)
                _increment_throughput()
        elif isinstance(log_content, str):
            send_wec_message(log_content, module, config)
            _increment_throughput()
        else:
            event_str = f" ({event_name})" if event_name else ""
            _tprint(f"Warning: Module {module.NAME}{event_str} wants WEC transport but did not return a string or list of strings. Skipping.")
    elif transport == "pubsub":
        if isinstance(log_content, list):
            for msg in log_content:
                send_pubsub_message(msg, module, config, event_name)
                _increment_throughput()
        elif isinstance(log_content, str):
            send_pubsub_message(log_content, module, config, event_name)
            _increment_throughput()
        else:
            event_str = f" ({event_name})" if event_name else ""
            _tprint(f"Warning: Module {module.NAME}{event_str} wants Pub/Sub transport but did not return a string or list of strings. Skipping.")
    else:  # Default to syslog
        syslog_host = os.getenv('SYSLOG_HOST')
        syslog_port = int(module_config.get("syslog_port", config.get('SYSLOG_PORT', '514')))
        if isinstance(log_content, list):
            for msg in log_content:
                send_syslog_message(msg, syslog_host, syslog_port, app_name=module.NAME)
                _increment_throughput()
        elif isinstance(log_content, str):
            send_syslog_message(log_content, syslog_host, syslog_port, app_name=module.NAME)
            _increment_throughput()
        else:
            event_str = f" ({event_name})" if event_name else ""
            _tprint(f"Warning: Module {module.NAME}{event_str} wants Syslog transport but did not return a string or list of strings. Skipping.")

    _maybe_report_throughput()
        
def select_product_log_mode(all_modules):
    """Handles the independent log generation mode."""
    print("\nAvailable Log Modules:")
    module_list = list(all_modules.values())
    for i, module in enumerate(module_list, 1):
        print(f"  {i}. {module.NAME} - {module.DESCRIPTION}")

    choices_str = input("Select modules to run (e.g., '1,3,4' or 'all'): ")
    
    selected_modules = []
    if choices_str.lower() == 'all':
        selected_modules = module_list
    else:
        try:
            choices = [int(c.strip()) for c in choices_str.split(',')]
            for choice in choices:
                if 1 <= choice <= len(module_list):
                    selected_modules.append(module_list[choice - 1])
        except ValueError:
            print("Invalid input. Please enter numbers separated by commas.")
            return

    if not selected_modules:
        print("No modules selected. Exiting.")
        return
    
    return selected_modules

def _dispatch_result(result, module, config):
    """Unpack and send whatever generate_log() returned."""
    if result is None:
        return
    if isinstance(result, tuple) and len(result) == 2:
        log_content, event_name = result
    else:
        log_content, event_name = result, None
    if isinstance(log_content, list):
        for msg in log_content:
            process_and_send(log_content=msg, module=module, event_name=event_name, config=config)
    elif log_content:
        process_and_send(log_content=log_content, module=module, config=config, event_name=event_name)


def run_module_loop(module, config, threat_level, benign_mode, context, interval, stop_event):
    """Runs a single module in its own continuous loop (used by parallel mode)."""
    while not stop_event.is_set():
        try:
            result = module.generate_log(config=config, threat_level=threat_level,
                                          benign_only=benign_mode, context=context)
            _dispatch_result(result, module, config)
        except Exception as e:
            print(f"[{module.NAME}] Error: {e}")
        stop_event.wait(timeout=interval)  # interruptible sleep


def run_sim(threat_level, selected_modules, config, session_context=None, parallel=False):
    benign_mode = (threat_level == "Benign Traffic Only")
    mode_label  = "Parallel" if parallel else "Serial"
    print(f"\nStarting log generation | Mode: {mode_label} | Threat level: '{threat_level}' | "
          f"Modules: {', '.join([m.NAME for m in selected_modules])}")
    print("Press Ctrl+C to stop.\n")

    with _throughput_lock:
        _throughput_counter["count"]       = 0
        _throughput_counter["last_count"]  = 0
        _throughput_counter["last_report"] = time.time()

    base_context = {'session_context': session_context} if session_context else {}
    interval     = config.get('base_event_interval_seconds', 1)

    if parallel:
        stop_event = threading.Event()
        threads = [
            threading.Thread(
                target=run_module_loop,
                args=(module, config, threat_level, benign_mode, base_context, interval, stop_event),
                daemon=True,
                name=f"logsim-{module.NAME}",
            )
            for module in selected_modules
        ]
        for t in threads:
            t.start()
        try:
            while not stop_event.is_set():
                stop_event.wait(timeout=1)
        except KeyboardInterrupt:
            print("\nStopping all threads...")
            stop_event.set()
        for t in threads:
            t.join(timeout=5)
        with _throughput_lock:
            total = _throughput_counter["count"]
        print(f"\nStopped. Total logs sent this session: {total}")
    else:
        # Original serial round-robin behaviour
        try:
            while True:
                for module in selected_modules:
                    result = module.generate_log(config=config, threat_level=threat_level,
                                                  benign_only=benign_mode, context=base_context)
                    _dispatch_result(result, module, config)
                    time.sleep(max(0, interval / len(selected_modules)))
        except KeyboardInterrupt:
            with _throughput_lock:
                total = _throughput_counter["count"]
            print(f"\nStopped. Total logs sent this session: {total}")
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")
            import traceback
            traceback.print_exc()


def select_specific_threat_mode(all_modules):
    """Lets the user pick a technology and then a specific named threat to generate."""
    selected_modules = select_product_log_mode(all_modules)
    if not selected_modules:
        return None, None, False

    # Collect (module, threat_name) pairs from modules that expose get_threat_names()
    threat_entries = []
    for module in selected_modules:
        threat_fn = getattr(module, 'get_threat_names', None)
        names = threat_fn() if callable(threat_fn) else None
        if names:
            for name in names:
                threat_entries.append((module, name))

    if not threat_entries:
        print("No named threats are available for the selected modules.")
        return None, None, False

    print("\nAvailable Threats:")
    current_module = None
    for i, (module, name) in enumerate(threat_entries, 1):
        if module is not current_module:
            print(f"\n  [{module.NAME}]")
            current_module = module
        print(f"    {i:>3}. {name}")

    try:
        choice = int(input(f"\nSelect threat number (1-{len(threat_entries)}): ").strip())
        if not (1 <= choice <= len(threat_entries)):
            print("Invalid selection.")
            return None, None, False
    except ValueError:
        print("Invalid input.")
        return None, None, False

    selected_module, threat_name = threat_entries[choice - 1]

    repeat_choice = input("Run once [1] or repeat until Ctrl+C [2]? ").strip()
    repeat = (repeat_choice == "2")

    return selected_module, threat_name, repeat


def run_specific_threat(module, threat_name, config, session_context, repeat):
    """Generates and sends a specific named threat from a module, once or repeatedly."""
    context  = {'session_context': session_context} if session_context else {}
    interval = config.get('base_event_interval_seconds', 1)

    with _throughput_lock:
        _throughput_counter["count"]       = 0
        _throughput_counter["last_count"]  = 0
        _throughput_counter["last_report"] = time.time()

    print(f"\nGenerating threat '{threat_name}' via {module.NAME}.")
    if repeat:
        print("Press Ctrl+C to stop.\n")

    def _generate():
        # Try scenario_event path first (AWS, GCP, Okta, Proofpoint, Zscaler)
        result = module.generate_log(config, scenario_event=threat_name, context=context,
                                      threat_level="Insane")
        if result is not None:
            return result
        # Fallback: config override for event_mix-based firewall modules
        module_key = getattr(module, 'CONFIG_KEY', None)
        if module_key:
            forced_config = copy.deepcopy(config)
            if module_key in forced_config:
                forced_config[module_key].setdefault("event_mix", {})["threat"] = [
                    {"event": threat_name, "weight": 1}
                ]
            return module.generate_log(forced_config, threat_level="Insane",
                                        benign_only=False, context=context)
        return None

    try:
        _dispatch_result(_generate(), module, config)
        if repeat:
            while True:
                time.sleep(interval)
                _dispatch_result(_generate(), module, config)
    except KeyboardInterrupt:
        with _throughput_lock:
            total = _throughput_counter["count"]
        print(f"\nStopped. Total logs sent: {total}")


def select_threat_level(config):
    """Prompts the user to select a threat generation level."""
    levels = config.get('threat_generation_levels', {})
    if not levels:
        print("Warning: 'threat_generation_levels' not found in config.json. Defaulting to Realistic.")
        return "Realistic"
        
    print("\nSelect Threat Generation Level:")
    level_keys = list(levels.keys())
    for i, level in enumerate(level_keys, 1):
        print(f"  {i}. {level}")

    try:
        choice = int(input(f"Enter choice (1-{len(level_keys)}): "))
        if 1 <= choice <= len(level_keys):
            return level_keys[choice - 1]
        else:
            print("Invalid choice. Defaulting to Realistic.")
            return "Realistic"
    except ValueError:
        print("Invalid input. Defaulting to Realistic.")
        return "Realistic"

def _fresh_attacker_ip():
    """Return a fresh, effectively-unique external attacker IP each call.

    Scenarios must NOT reuse a fixed Tor-node IP across runs: the XSIAM
    correlation rules suppress duplicate alerts keyed on xdm.source.ipv4
    (1h for step rules, up to 24h for composites). A repeated source IP gets
    deduped and the scenario looks like it "didn't fire". A fresh IP per run
    keeps every scenario testable at any time. Octets are drawn from common
    external/VPS ranges so the IP still reads as suspicious/off-corp.
    """
    return (f"{random.choice([45, 77, 91, 104, 141, 171, 185, 193, 209, 212])}."
            f"{random.randint(1, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}")


# Helper function to flesh out a user template from config
def _get_random_user_from_template(config, user_template):
    """Takes a user template from config and returns a fully-fleshed identity object."""
    account_id = os.getenv('AWS_ACCOUNT_ID')
    
    final_identity = user_template.copy()
    final_identity['accountId'] = account_id

    if 'arn' not in final_identity and 'arn_suffix' in final_identity:
        final_identity['arn'] = f"arn:aws:iam::{account_id}:{final_identity['arn_suffix']}"

    if 'principalId' not in final_identity:
        principal_id_prefix = ""
        principal_id_main = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=17))
        id_type = final_identity.get('type', 'IAMUser')

        if id_type == 'IAMUser':
            principal_id_prefix = "AIDA"
        elif id_type in ['AssumedRole', 'Role']:
            principal_id_prefix = "AROA"
        elif id_type == 'Root':
            final_identity['principalId'] = account_id
            return final_identity
        else:
            principal_id_prefix = "AIDAU" 

        if id_type in ['AssumedRole', 'Role']:
             role_id_part = f"{principal_id_prefix}{principal_id_main}"
             session_name_part = final_identity.get('name', 'DefaultSession').split('/')[-1]
             final_identity['principalId'] = f"{role_id_part}:{session_name_part}"
             final_identity['_baseRoleId'] = role_id_part
        else:
            final_identity['principalId'] = f"{principal_id_prefix}{principal_id_main}"
            
    return final_identity

def run_compromised_account_gdrive_exfil_scenario(modules, config):
    """Generates a sequence of logs simulating data exfiltration from Google Drive."""
    print("\n--- Running 'Compromised Account & G-Drive Exfil' Scenario ---")

    gworkspace_module = modules.get("google_workspace")
    okta_module = modules.get("okta")
    asa_module = modules.get("cisco_asa")

    if not gworkspace_module or not (okta_module or asa_module):
        print("ERROR: This scenario requires the 'google_workspace' module and at least one of 'okta' or 'cisco_asa'.")
        return
        
    attacker_ip = _fresh_attacker_ip()   # fresh per run — avoids source-IP alert suppression
    compromised_user_short = 'c.lewis' 
    compromised_user_email = f"{compromised_user_short}@{config.get('google_workspace_config', {}).get('domains', ['examplecorp.com'])[0]}"
    sensitive_file = next((f for f in config.get('google_workspace_config',{}).get('drive_files', []) if f.get('sensitive')), None)
    
    if not sensitive_file:
        print("ERROR: No sensitive files found in 'google_workspace_config' for this scenario.")
        return

    print(f"  - Attacker IP: {attacker_ip}")
    print(f"  - Compromised User: {compromised_user_email}")
    print(f"  - Target File: {sensitive_file['title']}")
    
    try:
        if okta_module and hasattr(okta_module, 'generate_log'):
            print("\n[STEP 1] Generating Okta login from suspicious IP...")
            context = {'ip': attacker_ip, 'user': compromised_user_short, 'outcome': 'SUCCESS'}
            okta_log = okta_module.generate_log(config, scenario_event="LOGIN", context=context)
            
            # UPDATED: Handle tuple return from Okta module
            if isinstance(okta_log, tuple): 
                log_content, event_name = okta_log
            else: 
                log_content, event_name = okta_log, None
            process_and_send(log_content, okta_module, config, event_name)
            time.sleep(1)

        print("[STEP 2] Generating Google Workspace login from same IP...")
        g_context = {'ip': attacker_ip, 'user_email': compromised_user_email}
        gdrive_log_1 = gworkspace_module.generate_log(config, scenario_event="LOGIN_SUCCESS", context=g_context)
        if isinstance(gdrive_log_1, tuple): 
            log_content, event_name = gdrive_log_1
        else: 
            log_content, event_name = gdrive_log_1, None
        process_and_send(log_content, gworkspace_module, config, event_name)
        time.sleep(2)

        print("[STEP 3] Generating Google Drive access to sensitive file...")
        g_context.update({'file': sensitive_file})
        gdrive_log_2 = gworkspace_module.generate_log(config, scenario_event="DRIVE_VIEW_SENSITIVE", context=g_context)
        if isinstance(gdrive_log_2, tuple): 
            log_content, event_name = gdrive_log_2
        else: 
            log_content, event_name = gdrive_log_2, None
        process_and_send(log_content, gworkspace_module, config, event_name)
        time.sleep(1)

        print("[STEP 4] Generating Google Drive public sharing event...")
        gdrive_log_3 = gworkspace_module.generate_log(config, scenario_event="DRIVE_PUBLIC_SHARE", context=g_context)
        if isinstance(gdrive_log_3, tuple): 
            log_content, event_name = gdrive_log_3
        else: 
            log_content, event_name = gdrive_log_3, None
        process_and_send(log_content, gworkspace_module, config, event_name)
        time.sleep(2)

        print("[STEP 5] Generating Google Drive download event...")
        gdrive_log_4 = gworkspace_module.generate_log(config, scenario_event="DRIVE_DOWNLOAD", context=g_context)
        if isinstance(gdrive_log_4, tuple): 
            log_content, event_name = gdrive_log_4
        else: 
            log_content, event_name = gdrive_log_4, None
        process_and_send(log_content, gworkspace_module, config, event_name)
        time.sleep(1)

        if asa_module and hasattr(asa_module, 'generate_log'):
            print("[STEP 6] Generating ASA log for large data egress...")
            asa_context = {'src_ip': attacker_ip, 'bytes': random.randint(20000000, 50000000)}
            asa_log = asa_module.generate_log(config, scenario_event="LARGE_EGRESS", context=asa_context)
            if isinstance(asa_log, tuple):
                log_content, event_name = asa_log
            else: 
                log_content, event_name = asa_log, None
            process_and_send(log_content, asa_module, config, event_name)

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Scenario Complete ---")

def _emit_guardduty(all_modules, config, context, finding_event):
    """Fire a corroborating Amazon GuardDuty finding on the SAME pivot/context as the
    CloudTrail step it backs up, if the 'AWS GuardDuty' module is loaded. Optional —
    silently skipped when the module isn't present, like other optional scenario modules.
    GuardDuty findings model to xdm.alert.* (an alert), so they raise the corroborating
    step from a raw event to a vendor-confirmed detection on the same account/principal/IP."""
    gd = all_modules.get("AWS GuardDuty")
    if not gd:
        return
    try:
        result = gd.generate_log(config, context=context, scenario_event=finding_event)
        if result:
            process_and_send(result, gd, config, finding_event)
            print(f"    -> GuardDuty finding: {finding_event}")
    except Exception as e:
        print(f"    (GuardDuty finding {finding_event} skipped: {e})")


def run_aws_pentest_scenario(modules, config):
    """Generates a sequence of logs simulating a pentest/attack scenario in AWS."""
    print("\n--- Running 'AWS Pentest & Defense Evasion' Scenario ---")

    aws_module = modules.get("aws") # Match the NAME from the module
    if not aws_module:
        print("ERROR: This scenario requires the 'AWS' module.")
        return

    # Get a consistent attacker IP (Tor) and a target user for the story
    attacker_ip = _fresh_attacker_ip()   # fresh per run — avoids source-IP alert suppression
    aws_conf = config.get('aws_config', {})
    pentest_user_pool = [u for u in aws_conf.get('users_and_roles', []) if u['type'] == 'IAMUser']
    if not pentest_user_pool:
        pentest_user_template = {
            "type": "IAMUser", 
            "name": "pentest-user", 
            "arn_suffix": "user/pentest-user"
        }
    else:
        pentest_user_template = random.choice(pentest_user_pool)

    pentest_user = _get_random_user_from_template(config, pentest_user_template)

    context = {
        'ip_address': attacker_ip,
        'user_identity': pentest_user,
        'target_user': pentest_user
    }

    print(f"  - Attacker IP: {attacker_ip}")
    print(f"  - Attacker User Identity: {pentest_user.get('name')}")
    
    try:
        print("\n[STEP 1] Generating Pentest Instance Launch (Kali)...")
        log_1, name_1 = aws_module.generate_log(config, scenario_event="PENTEST_LAUNCH", context=context)
        process_and_send(log_1, aws_module, config, name_1)
        time.sleep(2)

        print("[STEP 2] Simulating Console Login from multiple Tor exit nodes (impossible travel)...")
        all_users = aws_conf.get('users_and_roles', [])
        # tor_user must be an IAMUser so the ConsoleLogin detection (IAMUser + >=3 networks)
        # matches AND the TOR_LOGIN generator keeps the SAME identity across every login
        # (it randomizes the user for non-IAMUser identities).
        tor_user_pool = [u for u in all_users
                         if u.get('type') == 'IAMUser' and u.get('name') != pentest_user.get('name')]
        tor_user_template = random.choice(tor_user_pool) if tor_user_pool else pentest_user_template
        tor_user = _get_random_user_from_template(config, tor_user_template)

        # Emit >=3 console logins for the SAME user from distinct Tor exit nodes in
        # different /16 networks (Tor rotates exit nodes) so the multi-location
        # console-login detection (>=3 distinct networks) fires on the hijacked account.
        _tor_nodes = [n.get('ip') for n in config.get('tor_exit_nodes', []) if n.get('ip')]
        _seen16, tor_ips = set(), []
        # Seed with the shared attacker IP so STEP 2 overlaps the IP-grouped
        # defense-evasion steps (helps all six land in one case).
        for _ip in [attacker_ip] + _tor_nodes:
            _n16 = '.'.join(_ip.split('.')[:2])
            if _n16 not in _seen16:
                _seen16.add(_n16); tor_ips.append(_ip)
            if len(tor_ips) >= 4:
                break
        while len(tor_ips) < 3:
            tor_ips.append(f"{random.choice([45,91,104,171,185,193])}.{random.randint(1,254)}."
                           f"{random.randint(1,254)}.{random.randint(1,254)}")
        for _tip in tor_ips:
            tor_context = {'ip_address': _tip, 'user_identity': tor_user}
            log_2, name_2 = aws_module.generate_log(config, scenario_event="TOR_LOGIN", context=tor_context)
            process_and_send(log_2, aws_module, config, name_2)
            time.sleep(1)
        # GuardDuty corroboration: Tor-sourced API call on the hijacked identity.
        _emit_guardduty(modules, config,
                        {'ip_address': tor_ips[0], 'user_identity': tor_user}, "GD_TOR_LOGIN")

        print("[STEP 3] Simulating Privilege Escalation (Attach Admin Policy to pentest user)...")
        log_3, name_3 = aws_module.generate_log(config, scenario_event="ATTACH_ADMIN_POLICY", context=context)
        process_and_send(log_3, aws_module, config, name_3)
        _emit_guardduty(modules, config, context, "GD_ADMIN_PRIVESC")
        time.sleep(1)

        print("[STEP 4] Simulating Defense Evasion (Stop CloudTrail)...")
        log_4, name_4 = aws_module.generate_log(config, scenario_event="STOP_CLOUDTRAIL", context=context)
        process_and_send(log_4, aws_module, config, name_4)
        _emit_guardduty(modules, config, context, "GD_CLOUDTRAIL_DISABLED")
        time.sleep(1)

        print("[STEP 5] Simulating Defense Evasion (Disable GuardDuty)...")
        log_5, name_5 = aws_module.generate_log(config, scenario_event="DISABLE_GUARDDUTY", context=context)
        process_and_send(log_5, aws_module, config, name_5)
        time.sleep(2)

        print("[STEP 6] Simulating Persistence (Make S3 Bucket Public)...")
        log_6, name_6 = aws_module.generate_log(config, scenario_event="MAKE_S3_PUBLIC", context=context)
        process_and_send(log_6, aws_module, config, name_6)
        _emit_guardduty(modules, config, context, "GD_S3_PUBLIC")
        time.sleep(1)

    except Exception as e:
        print(f"\nAn error occurred during AWS scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- AWS Scenario Complete ---")


def run_phishing_kill_chain_scenario(modules, config):
    """
    Simulates a complete phishing kill chain:
      1. Proofpoint TAP: phishing email delivered to victim (slipped past filters)
      2. Proofpoint TAP: victim clicks the rewritten URL (click-permitted — TAP allowed it)
      3. Zscaler: victim's browser reaches malicious domain (Zscaler may block or allow)
      4. Cisco Firepower/ASA: C2 beacon appears from victim's workstation post-infection
      5. Okta: attacker uses harvested credentials to authenticate from external IP

    Storytelling fields that tie events together:
      - target_email / target_user / click_ip link Proofpoint → Zscaler → Firepower → Okta
      - shared sender_ip shows Proofpoint senderIP in correlation queries
      - shared_guid ties the click-permitted event to the message-delivered event
    """
    print("\n--- Running 'Phishing Kill Chain' Scenario ---")

    pp_module       = modules.get("Proofpoint Email Gateway")
    zs_module       = modules.get("Zscaler Web Gateway")
    fp_module       = modules.get("Cisco Firepower")
    asa_module      = modules.get("Cisco ASA Firewall")
    cp_module       = modules.get("Check Point Firewall")
    infoblox_module = modules.get("Infoblox NIOS")
    okta_module     = modules.get("Okta SSO")

    if not pp_module:
        print("ERROR: This scenario requires the 'Proofpoint Email Gateway' module.")
        return

    # Pick a victim user from session context (built in main) or fall back
    try:
        from modules.session_utils import build_session_context, get_random_user
        session_context = build_session_context(config)
        victim_info = get_random_user(session_context)
    except Exception:
        session_context = {}
        victim_info = None

    if victim_info:
        victim_email  = victim_info.get("email", "victim@examplecorp.com")
        victim_ip     = victim_info.get("ip", f"10.{random.randint(1,10)}.{random.randint(1,254)}.{random.randint(1,254)}")
        victim_user   = victim_info.get("username", "victim.user")
    else:
        victim_email  = "victim@examplecorp.com"
        victim_ip     = f"10.{random.randint(1,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
        victim_user   = "victim.user"

    # Attacker infrastructure — consistent across all steps
    attacker_ip   = _fresh_attacker_ip()   # fresh per run — avoids source-IP alert suppression
    shared_guid   = (f"{{{random.randint(0x10000000,0xFFFFFFFF):08X}-"
                     f"{random.randint(0x1000,0xFFFF):04X}-"
                     f"{random.randint(0x1000,0xFFFF):04X}-"
                     f"{random.randint(0x1000,0xFFFF):04X}-"
                     f"{random.randint(0x100000000000,0xFFFFFFFFFFFF):012X}}}")

    print(f"  Victim:      {victim_email} ({victim_ip})")
    print(f"  Attacker IP: {attacker_ip}")
    print(f"  Message GUID:{shared_guid}")

    base_ctx = {"session_context": session_context}

    try:
        # STEP 1 — Phishing email delivered (slipped past TAP)
        print("\n[STEP 1] Proofpoint: Phishing email delivered to victim mailbox...")
        pp_ctx = {**base_ctx, "target_email": victim_email,
                  "sender_ip": attacker_ip, "shared_guid": shared_guid}
        result = pp_module.generate_log(config, scenario_event="PHISHING_DELIVERED", context=pp_ctx)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "PHISHING_DELIVERED"
        process_and_send(log_content, pp_module, config, event_name)
        time.sleep(2)

        # STEP 2 — Victim clicks the link (click-permitted: TAP allowed it at click time)
        print("[STEP 2] Proofpoint: Victim clicks malicious URL (click-permitted)...")
        click_ctx = {**base_ctx, "target_email": victim_email,
                     "sender_ip": attacker_ip, "shared_guid": shared_guid}
        result = pp_module.generate_log(config, scenario_event="CLICK_PERMITTED", context=click_ctx)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "CLICK_PERMITTED"
        process_and_send(log_content, pp_module, config, event_name)
        time.sleep(1)

        # STEP 2b — Infoblox: victim browser resolves phishing/C2 domains via DNS.
        # Emit a small burst across multiple malicious domains so the aggregation
        # rule (>=3 queries, >=2 distinct domains in 30m) trips on a single run.
        # The leading domains contain rule keywords (malware-distro / credential-
        # stealer / phishing-login) so detection is guaranteed regardless of config.
        if infoblox_module and hasattr(infoblox_module, 'generate_dns_pair'):
            _malicious = ['malware-distro-site.ru', 'credential-stealer-portal.com',
                          'phishing-login-secure.net']
            cfg_domains = config.get('proofpoint_config', {}).get('phishing_domains', [])
            phishing_domains = list(dict.fromkeys(_malicious + cfg_domains))[:3]
            print(f"[STEP 2b] Infoblox: Victim browser resolves {len(phishing_domains)} phishing domains in DNS...")
            for pdom in phishing_domains:
                dns_logs, dns_name = infoblox_module.generate_dns_pair(
                    config, victim_ip, pdom, q_type="A"
                )
                process_and_send(dns_logs, infoblox_module, config, dns_name)
                time.sleep(0.3)

        # STEP 3 — Zscaler sees the victim's browser hit the phishing domain
        if zs_module and hasattr(zs_module, "generate_log"):
            print("[STEP 3] Zscaler: Victim browser reaches phishing domain...")
            zs_ctx = {**base_ctx, "src_ip": victim_ip, "user": victim_user}
            result = zs_module.generate_log(config, scenario_event="THREAT_BLOCK", context=zs_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "THREAT_BLOCK"
            if log_content:
                process_and_send(log_content, zs_module, config, event_name)
        elif cp_module and hasattr(cp_module, "generate_log"):
            print("[STEP 3] Check Point: Victim browser hits phishing domain (URL block)...")
            cp_ctx = {**base_ctx, "src_ip": victim_ip, "user": victim_user}
            result = cp_module.generate_log(config, scenario_event="THREAT_BLOCK", context=cp_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "THREAT_BLOCK"
            if log_content:
                process_and_send(log_content, cp_module, config, event_name)
        else:
            print("[STEP 3] No Zscaler/Check Point module loaded — skipping.")
        time.sleep(2)

        # STEP 4 — C2 callback / large outbound transfer from the victim workstation.
        # Deterministically use Cisco ASA (rule-aligned dataset with rich XDM). Bytes
        # are sized above the ASA C2 rule's 20MB threshold so a single 302014 teardown
        # trips detection. Firepower/Check Point are fallbacks only.
        if asa_module and hasattr(asa_module, "generate_log"):
            print("[STEP 4] Cisco ASA: Large outbound transfer from victim workstation...")
            asa_ctx = {**base_ctx, "src_ip": victim_ip,
                       "bytes": random.randint(22000000, 60000000)}
            result = asa_module.generate_log(config, scenario_event="LARGE_EGRESS", context=asa_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "LARGE_EGRESS"
            if log_content:
                process_and_send(log_content, asa_module, config, event_name)
        elif fp_module and hasattr(fp_module, "generate_log"):
            print("[STEP 4] Cisco Firepower: C2 beacon from victim workstation...")
            fp_ctx = {**base_ctx, "src_ip": victim_ip}
            result = fp_module.generate_log(config, scenario_event="LARGE_EGRESS", context=fp_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "C2_BEACON"
            if log_content:
                process_and_send(log_content, fp_module, config, event_name)
        elif cp_module and hasattr(cp_module, "generate_log"):
            print("[STEP 4] Check Point: Large outbound transfer from victim workstation...")
            cp_ctx = {**base_ctx, "src_ip": victim_ip}
            result = cp_module.generate_log(config, scenario_event="LARGE_EGRESS", context=cp_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "LARGE_EGRESS"
            if log_content:
                process_and_send(log_content, cp_module, config, event_name)
        else:
            print("[STEP 4] No Firepower/ASA/Check Point module loaded — skipping.")
        time.sleep(2)

        # STEP 5 — Okta: attacker authenticates with harvested credentials from external IP
        if okta_module and hasattr(okta_module, "generate_log"):
            print("[STEP 5] Okta: Attacker authenticates with stolen credentials from external IP...")
            okta_ctx = {**base_ctx, "ip": attacker_ip,
                        "user": victim_user, "outcome": "SUCCESS"}
            result = okta_module.generate_log(config, scenario_event="LOGIN", context=okta_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "LOGIN"
            if log_content:
                process_and_send(log_content, okta_module, config, event_name)
        else:
            print("[STEP 5] Okta module not loaded — skipping.")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Phishing Kill Chain Scenario Complete ---")
    print("\nHunt queries to run in XSIAM:")
    print(f"  1. dataset=proofpoint_tap_raw | filter GUID=\"{shared_guid}\"")
    print(f"  2. dataset=proofpoint_tap_raw | filter _log_type=\"click-permitted\" and clickIP=\"{victim_ip}\"")
    print(f"  3. Correlate clickIP={victim_ip} across Zscaler, Firepower, and Okta datasets")


def run_insider_threat_scenario(modules, config):
    """
    Insider Threat / Cloud Data Exfiltration Kill Chain.

    Steps:
      1. Okta:     Insider authenticates normally from office workstation
      2. AWS:      Insider accesses cloud credentials via SSM/Secrets Manager
      3. AWS:      Insider disables AWS Security Hub (defense evasion)
      4. AWS:      Insider stops AWS Config recorder (defense evasion)
      5. Zscaler:  Insider uploads large data to external cloud storage (DLP event)
      6. Firepower/ASA: Large outbound transfer detected from insider workstation

    Storytelling fields that tie events together:
      - insider_ip links Okta xdm.source.ipv4 → AWS sourceIPAddress → Zscaler src → Firepower src
      - insider username links Okta xdm.source.user.upn → AWS xdm.source.user.username → Zscaler suser
    """
    print("\n--- Running 'Insider Threat / Cloud Data Exfiltration' Scenario ---")

    okta_module     = modules.get("Okta SSO")
    aws_module      = modules.get("aws")
    zs_module       = modules.get("Zscaler Web Gateway")
    fp_module       = modules.get("Cisco Firepower")
    asa_module      = modules.get("Cisco ASA Firewall")
    cp_module       = modules.get("Check Point Firewall")
    infoblox_module = modules.get("Infoblox NIOS")

    if not aws_module:
        print("ERROR: This scenario requires the 'aws' module.")
        return

    # Build session context and pick an insider — prefer one with an AWS IAM user mapped
    try:
        from modules.session_utils import build_session_context, get_random_user
        session_context = build_session_context(config)
    except Exception:
        session_context = {}

    insider_info = None
    for profile in session_context.values():
        if profile.get("aws_iam_user"):
            insider_info = profile
            break
    if insider_info is None:
        try:
            insider_info = get_random_user(session_context)
        except Exception:
            insider_info = None

    if insider_info:
        insider_username = insider_info.get("username", "insider.user")
        insider_email    = insider_info.get("email", "insider@examplecorp.com")
        insider_ip       = insider_info.get("ip", f"10.{random.randint(1,10)}.{random.randint(1,254)}.{random.randint(1,254)}")
        insider_aws_name = insider_info.get("aws_iam_user") or insider_username
    else:
        insider_username = "insider.user"
        insider_email    = "insider@examplecorp.com"
        insider_ip       = f"10.{random.randint(1,10)}.{random.randint(1,254)}.{random.randint(1,254)}"
        insider_aws_name = insider_username

    print(f"  Insider:     {insider_email} ({insider_ip})")
    print(f"  AWS IAM:     {insider_aws_name}")

    # Build an AWS IAMUser identity for the insider, matching the config entry if possible
    aws_conf   = config.get("aws_config", {})
    account_id = aws_conf.get("aws_account_id", "123456789012")
    aws_identity = None
    for entry in aws_conf.get("users_and_roles", []):
        if entry.get("type") == "IAMUser" and entry.get("name") == insider_aws_name:
            aws_identity = dict(entry)
            aws_identity["accountId"] = account_id
            break
    if aws_identity is None:
        aws_identity = {
            "type":       "IAMUser",
            "name":       insider_aws_name,
            "arn_suffix": f"user/{insider_aws_name}",
            "accountId":  account_id,
        }

    base_ctx = {"session_context": session_context}

    try:
        # STEP 1 — Okta: normal login from office workstation
        if okta_module and hasattr(okta_module, "generate_log"):
            print("\n[STEP 1] Okta: Insider authenticates from office workstation...")
            okta_ctx = {**base_ctx, "ip": insider_ip, "user": insider_username, "outcome": "SUCCESS"}
            result = okta_module.generate_log(config, scenario_event="LOGIN", context=okta_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "LOGIN"
            if log_content:
                process_and_send(log_content, okta_module, config, event_name)
        else:
            print("[STEP 1] Okta module not loaded — skipping.")
        time.sleep(2)

        # STEP 2 — AWS: access cloud credentials
        print("[STEP 2] AWS: Insider accesses cloud credentials (Secrets Manager/SSM)...")
        aws_cred_ctx = {**base_ctx, "user_identity": aws_identity, "ip_address": insider_ip}
        result = aws_module.generate_log(config, scenario_event="CREDENTIAL_FILE_ACCESS", context=aws_cred_ctx)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "CREDENTIAL_FILE_ACCESS"
        if log_content:
            process_and_send(log_content, aws_module, config, event_name)
        time.sleep(2)

        # STEP 3 — AWS: disable Security Hub
        print("[STEP 3] AWS: Insider disables Security Hub (defense evasion)...")
        aws_evasion_ctx = {**base_ctx, "user_identity": aws_identity, "ip_address": insider_ip}
        result = aws_module.generate_log(config, scenario_event="DISABLE_SECURITY_HUB", context=aws_evasion_ctx)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "DISABLE_SECURITY_HUB"
        if log_content:
            process_and_send(log_content, aws_module, config, event_name)
        time.sleep(2)

        # STEP 4 — AWS: stop Config recorder
        print("[STEP 4] AWS: Insider stops AWS Config recorder (defense evasion)...")
        result = aws_module.generate_log(config, scenario_event="STOP_CONFIG_RECORDER", context=aws_evasion_ctx)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "STOP_CONFIG_RECORDER"
        if log_content:
            process_and_send(log_content, aws_module, config, event_name)
        time.sleep(2)

        # STEP 4b — Infoblox: insider's workstation resolves exfil destination via DNS
        if infoblox_module and hasattr(infoblox_module, 'generate_dns_pair'):
            exfil_domains = config.get('zscaler_config', {}).get('exfil_destinations',
                                       config.get('benign_domains', ['drive.google.com']))
            _exfil_choice = random.choice(exfil_domains)
            # exfil_destinations entries are {url, domain} dicts; benign_domains are
            # plain strings. generate_dns_pair needs the domain string, not the dict
            # (passing the dict throws "unhashable type: dict" and aborts steps 4b-6).
            exfil_domain  = _exfil_choice.get('domain') if isinstance(_exfil_choice, dict) else _exfil_choice
            print(f"[STEP 4b] Infoblox: Insider workstation resolves exfil destination ({exfil_domain})...")
            dns_logs, dns_name = infoblox_module.generate_dns_pair(
                config, insider_ip, exfil_domain, q_type="A"
            )
            process_and_send(dns_logs, infoblox_module, config, dns_name)
            time.sleep(0.5)

        # STEP 5 — Zscaler: DLP / data exfiltration upload
        if zs_module and hasattr(zs_module, "generate_log"):
            print("[STEP 5] Zscaler: Insider uploads data to external cloud storage (DLP)...")
            zs_ctx = {**base_ctx, "src_ip": insider_ip, "user": insider_username}
            result = zs_module.generate_log(config, scenario_event="DATA_EXFIL", context=zs_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "DATA_EXFIL"
            if log_content:
                process_and_send(log_content, zs_module, config, event_name)
        else:
            print("[STEP 5] Zscaler module not loaded — skipping.")
        time.sleep(2)

        # STEP 6 — large outbound transfer from the insider workstation.
        # Deterministically use Cisco ASA (rule-aligned dataset, rich XDM); bytes
        # exceed the ASA exfil rule's 50MB threshold. Firepower/Check Point fallback.
        if asa_module and hasattr(asa_module, "generate_log"):
            print("[STEP 6] Cisco ASA: Large outbound transfer from insider workstation...")
            asa_ctx = {**base_ctx, "src_ip": insider_ip, "bytes": random.randint(50000000, 200000000)}
            result = asa_module.generate_log(config, scenario_event="LARGE_EGRESS", context=asa_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "LARGE_EGRESS"
            if log_content:
                process_and_send(log_content, asa_module, config, event_name)
        elif fp_module and hasattr(fp_module, "generate_log"):
            print("[STEP 6] Cisco Firepower: Large outbound transfer from insider workstation...")
            fp_ctx = {**base_ctx, "src_ip": insider_ip}
            result = fp_module.generate_log(config, scenario_event="LARGE_EGRESS", context=fp_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "LARGE_EGRESS"
            if log_content:
                process_and_send(log_content, fp_module, config, event_name)
        elif cp_module and hasattr(cp_module, "generate_log"):
            print("[STEP 6] Check Point: Large outbound transfer from insider workstation...")
            cp_ctx = {**base_ctx, "src_ip": insider_ip, "bytes": random.randint(50000000, 200000000)}
            result = cp_module.generate_log(config, scenario_event="LARGE_EGRESS", context=cp_ctx)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "LARGE_EGRESS"
            if log_content:
                process_and_send(log_content, cp_module, config, event_name)
        else:
            print("[STEP 6] No Firepower/ASA/Check Point module loaded — skipping.")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Insider Threat Scenario Complete ---")
    print("\nHunt queries to run in XSIAM:")
    print(f"  1. datamodel dataset = okta_sso_raw | filter xdm.source.user.upn contains \"{insider_email}\" | fields xdm.source.ipv4, xdm.event.operation, _time")
    print(f"  2. dataset = amazon_aws_raw | filter xdm.source.user.username = \"{insider_aws_name}\" | fields xdm.event.operation, xdm.source.ipv4, _time")
    print(f"  3. dataset = zscaler_nssweblog_raw | filter src = \"{insider_ip}\" | fields suser, request, cn1, _time")
    print(f"  4. dataset = cisco_firepower_raw | filter src = \"{insider_ip}\" and app = \"SSL\" | fields src, dst, bytesOut, msg, _time")


def run_infoblox_single_threat(scenario_event_name, all_modules, config):
    """Runs a single Infoblox threat scenario and sends the result."""
    infoblox_module = all_modules.get("Infoblox NIOS")
    if not infoblox_module:
        print("Infoblox NIOS module is not loaded. Ensure infoblox_dns.py is in modules/.")
        return
    result = infoblox_module.generate_log(config, scenario_event=scenario_event_name)
    if result is None:
        print(f"No log generated for {scenario_event_name}.")
        return
    content, name = result if isinstance(result, tuple) else (result, scenario_event_name)
    process_and_send(content, infoblox_module, config, name)
    count = len(content) if isinstance(content, list) else 1
    print(f"  Sent {count} log(s) for {name}.")


# ---------------------------------------------------------------------------
# Scenario helpers
# ---------------------------------------------------------------------------

_FW_MODULE_NAMES = [
    "Cisco Firepower",
    "Cisco ASA Firewall",
    "Check Point Firewall",
    "Fortinet FortiGate",
    "Zscaler Web Gateway",
]


def _collect_fw_modules(all_modules):
    """Returns all loaded network firewall modules in priority order."""
    return [all_modules[n] for n in _FW_MODULE_NAMES if n in all_modules]


def _send_to_all_fw(fw_modules, scenario_event, config, context, step_label):
    """Sends a scenario event to every loaded firewall module.

    Dispatch order:
      1. scenario_event path — works for modules that handle it natively (Zscaler, Check Point LARGE_EGRESS, etc.)
      2. event_mix config override — forces the named threat via the module's internal dispatcher
         (works for cisco_asa, cisco_firepower, checkpoint, fortinet which use event_mix)
      3. Random Insane-level threat fallback — ensures the dataset is populated even if the
         threat name doesn't exist in that module's threat pool
    """
    if not fw_modules:
        print(f"{step_label} No network firewall modules loaded — skipping.")
        return
    for fw_module in fw_modules:
        result = fw_module.generate_log(config, scenario_event=scenario_event,
                                        context=context, threat_level="Insane")
        if result is None:
            # Fallback: override event_mix to force the named threat type
            module_key = getattr(fw_module, 'CONFIG_KEY', None)
            if module_key:
                forced_config = copy.deepcopy(config)
                forced_config.setdefault(module_key, {}).setdefault("event_mix", {})["threat"] = [
                    {"event": scenario_event, "weight": 1}
                ]
                result = fw_module.generate_log(forced_config, threat_level="Insane",
                                                benign_only=False, context=context)
        if result is None:
            result = fw_module.generate_log(config, threat_level="Insane", context=context)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, scenario_event
        if log_content:
            process_and_send(log_content, fw_module, config, event_name)


def run_dns_c2_killchain_scenario(all_modules, config):
    """
    DNS C2 Kill Chain — 7-step scenario across Infoblox DNS/DHCP + network firewall.

    Story: Implant on a compromised host attempts to beacon to C2.
    First two domain attempts blocked (DNS RPZ + firewall Security Intel).
    Third domain resolves (new C2 infra not yet on blocklists) — connection established.

    XSIAM datasets touched: infoblox_dhcp_raw, infoblox_dns_raw, plus one network firewall dataset.
    Hunt: JOIN on xdm.source.ip across DHCP (who is the device?) → DNS (what resolved?) → FW (what connected?).
    """
    print("\n--- Running 'DNS C2 Kill Chain' Scenario ---")

    infoblox_module = all_modules.get("Infoblox NIOS")
    fw_modules      = _collect_fw_modules(all_modules)

    if not infoblox_module:
        print("ERROR: This scenario requires the 'Infoblox NIOS' module.")
        return

    try:
        from modules.session_utils import build_session_context, get_random_user
        session_context = build_session_context(config)
        victim_info     = get_random_user(session_context, preferred_device_type='workstation')
    except Exception:
        session_context = {}
        victim_info     = None

    if victim_info:
        victim_ip   = victim_info.get("ip", "192.168.1.50")
        victim_host = victim_info.get("hostname", "CORP-WS-001")
        victim_mac  = f"00:50:56:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
    else:
        victim_ip   = f"192.168.1.{random.randint(10, 200)}"
        victim_host = "CORP-WS-001"
        victim_mac  = f"00:50:56:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"

    c2_domain_1 = random.choice(config.get('infoblox_threats', {}).get('malicious_domains', ['blocked-c2.ru']))
    c2_domain_3 = f"new-c2-{random.randint(1000,9999)}.com"  # new infra, not yet blocked

    base_ctx = {"session_context": session_context}
    fw_names = ", ".join(m.NAME for m in fw_modules) if fw_modules else "none"

    print(f"  Victim:      {victim_host} ({victim_ip} / {victim_mac})")
    print(f"  C2 domain 1 (blocked by RPZ): {c2_domain_1}")
    print(f"  C2 domain 3 (new infra, resolves): {c2_domain_3}")
    print(f"  Firewall modules: {fw_names}")

    try:
        # STEP 1 — DHCP: victim device joins the network
        print("\n[STEP 1] Infoblox DHCP: Victim device gets IP lease...")
        dhcp_log, dhcp_name = infoblox_module.generate_dhcp_ack(config, victim_ip, victim_mac, victim_host)
        process_and_send(dhcp_log, infoblox_module, config, dhcp_name)
        time.sleep(1)

        # STEP 2 — Benign DNS: device connectivity check (baseline)
        print("[STEP 2] Infoblox DNS: Normal connectivity check (baseline)...")
        benign_domain = random.choice(config.get('benign_domains', ['www.microsoft.com']))
        dns_logs, dns_name = infoblox_module.generate_dns_pair(config, victim_ip, benign_domain)
        process_and_send(dns_logs, infoblox_module, config, dns_name)
        time.sleep(1)

        # STEP 3 — RPZ block: first C2 domain attempt blocked at DNS.
        # Use RPZ_BLOCK (emits the RPZ-QNAME CEF the detection keys on); C2_BEACON
        # only produces a plain NXDOMAIN, which the RPZ rule can't match.
        print(f"[STEP 3] Infoblox DNS: C2 beacon blocked by RPZ — {c2_domain_1}...")
        result = infoblox_module.generate_log(config, scenario_event="RPZ_BLOCK",
                                              context={**base_ctx, "src_ip": victim_ip, "domain": c2_domain_1})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "RPZ_BLOCK"
        if log_content:
            process_and_send(log_content, infoblox_module, config, event_name)
        time.sleep(1)

        # STEP 4 — NXDOMAIN storm: DGA cycling (second domain set)
        print("[STEP 4] Infoblox DNS: DGA NXDOMAIN storm (implant cycling through C2 candidates)...")
        result = infoblox_module.generate_log(config, scenario_event="NXDOMAIN_STORM",
                                              context={**base_ctx, "src_ip": victim_ip})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "NXDOMAIN_STORM"
        if log_content:
            process_and_send(log_content, infoblox_module, config, event_name)
        time.sleep(1)

        # STEP 5 — ALL firewalls: Security Intel / URL block on second C2 domain
        print(f"[STEP 5] All firewall modules: Security Intel block on C2 domain...")
        _send_to_all_fw(fw_modules, "THREAT_BLOCK", config,
                        {**base_ctx, "src_ip": victim_ip}, "[STEP 5]")
        time.sleep(1)

        # STEP 6 — DNS resolves: third C2 domain succeeds (new infra)
        print(f"[STEP 6] Infoblox DNS: Third C2 domain resolves (NOERROR) — {c2_domain_3}...")
        dns_logs, dns_name = infoblox_module.generate_dns_pair(config, victim_ip, c2_domain_3)
        process_and_send(dns_logs, infoblox_module, config, dns_name)
        time.sleep(1)

        # STEP 7 — ALL firewalls: outbound connection to C2 IP allowed (not yet on blocklist)
        print(f"[STEP 7] All firewall modules: Outbound connection to C2 IP established...")
        _send_to_all_fw(fw_modules, "LARGE_EGRESS", config,
                        {**base_ctx, "src_ip": victim_ip}, "[STEP 7]")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- DNS C2 Kill Chain Scenario Complete ---")
    print("\nHunt queries to run in XSIAM:")
    print(f"  1. dataset=infoblox_dhcp_raw | filter xdm.source.ip=\"{victim_ip}\" — identify device")
    print(f"  2. dataset=infoblox_dns_raw  | filter xdm.source.ip=\"{victim_ip}\" and xdm.network.dns.dns_response_code=\"NXDOMAIN\" | stats count — DGA storm")
    print(f"  3. dataset=infoblox_dns_raw  | filter xdm.source.ip=\"{victim_ip}\" and xdm.network.dns.dns_response_code=\"NOERROR\" — resolving domain")
    print(f"  4. Join step 3 resolve with firewall allowed connection to confirm C2 establishment")


def run_device_compromise_scenario(all_modules, config):
    """
    Device Compromise (Full Lifecycle) — DHCP → DNS baseline → C2 attempts → detection.

    Story: Complete device compromise story from network join through C2 establishment.
    Spans 4 XSIAM datasets: infoblox_dhcp_raw, infoblox_dns_raw, infoblox_threat_raw,
    and one network firewall dataset.

    Hunt: Find device MAC in DHCP → find same IP in DNS NXDOMAIN storm → find same IP
    in threat-protect-log CEF within same day. Use threat-protect event to pivot backward.
    """
    print("\n--- Running 'Device Compromise (Full Lifecycle)' Scenario ---")

    infoblox_module = all_modules.get("Infoblox NIOS")
    fw_modules      = _collect_fw_modules(all_modules)

    if not infoblox_module:
        print("ERROR: This scenario requires the 'Infoblox NIOS' module.")
        return

    try:
        from modules.session_utils import build_session_context, get_random_user
        session_context = build_session_context(config)
        victim_info     = get_random_user(session_context, preferred_device_type='workstation')
    except Exception:
        session_context = {}
        victim_info     = None

    if victim_info:
        victim_ip   = victim_info.get("ip", "192.168.1.60")
        victim_host = victim_info.get("hostname", "CORP-WS-002")
        victim_mac  = f"00:50:56:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
    else:
        victim_ip   = f"192.168.1.{random.randint(10, 200)}"
        victim_host = "CORP-WS-002"
        victim_mac  = f"00:50:56:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"

    base_ctx = {"session_context": session_context}
    fw_names = ", ".join(m.NAME for m in fw_modules) if fw_modules else "none"
    print(f"  Device:           {victim_host} ({victim_ip} / {victim_mac})")
    print(f"  Firewall modules: {fw_names}")

    try:
        # STEP 1 — DHCP: device joins network
        print("\n[STEP 1] Infoblox DHCP: Device joins network (DHCP ACK)...")
        dhcp_log, dhcp_name = infoblox_module.generate_dhcp_ack(config, victim_ip, victim_mac, victim_host)
        process_and_send(dhcp_log, infoblox_module, config, dhcp_name)
        time.sleep(1)

        # STEP 2 — Benign DNS: normal activity baseline
        print("[STEP 2] Infoblox DNS: Normal web browsing DNS query (baseline)...")
        benign_domain = random.choice(config.get('benign_domains', ['www.office365.com']))
        dns_logs, dns_name = infoblox_module.generate_dns_pair(config, victim_ip, benign_domain)
        process_and_send(dns_logs, infoblox_module, config, dns_name)
        time.sleep(1)

        # STEP 3 — ALL firewalls: normal outbound web browsing (benign baseline)
        print(f"[STEP 3] All firewall modules: Normal outbound web browsing (benign baseline)...")
        fw_ctx = {**base_ctx, "src_ip": victim_ip}
        if fw_modules:
            for fw_module in fw_modules:
                result = fw_module.generate_log(config, benign_only=True, context=fw_ctx)
                if isinstance(result, tuple):
                    log_content, event_name = result
                else:
                    log_content, event_name = result, "BENIGN_TRAFFIC"
                if log_content:
                    process_and_send(log_content, fw_module, config, event_name)
        else:
            print("[STEP 3] No network firewall modules loaded — skipping.")
        time.sleep(1)

        # STEP 4 — RPZ NXDOMAIN: first C2 attempt blocked at DNS
        print("[STEP 4] Infoblox DNS: RPZ NXDOMAIN — first C2 attempt blocked at DNS...")
        result = infoblox_module.generate_log(config, scenario_event="RPZ_BLOCK",
                                              context={**base_ctx, "src_ip": victim_ip})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "RPZ_BLOCK"
        if log_content:
            process_and_send(log_content, infoblox_module, config, event_name)
        time.sleep(1)

        # STEP 5 — ALL firewalls: URL/Security Intel block on second C2 domain
        print(f"[STEP 5] All firewall modules: URL/Security Intel block — second C2 attempt...")
        _send_to_all_fw(fw_modules, "THREAT_BLOCK", config,
                        {**base_ctx, "src_ip": victim_ip}, "[STEP 5]")
        time.sleep(1)

        # STEP 6 — DNS NOERROR: third C2 domain resolves (not yet on any blocklist)
        print("[STEP 6] Infoblox DNS: Third C2 domain resolves (NOERROR — new infra)...")
        c2_domain = f"c2-infra-{random.randint(1000,9999)}.net"
        dns_logs, dns_name = infoblox_module.generate_dns_pair(config, victim_ip, c2_domain)
        process_and_send(dns_logs, infoblox_module, config, dns_name)
        time.sleep(1)

        # STEP 7 — Threat Protect: post-connection CEF DROP (BloxOne detects C2 category)
        print("[STEP 7] Infoblox Threat Protect: Post-connection C2 category detection (CEF DROP)...")
        result = infoblox_module.generate_log(config, scenario_event="THREAT_PROTECT",
                                              context={**base_ctx, "src_ip": victim_ip})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "THREAT_PROTECT"
        if log_content:
            process_and_send(log_content, infoblox_module, config, event_name)

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Device Compromise Scenario Complete ---")
    print("\nHunt queries to run in XSIAM (pivot from threat-protect alert backward):")
    print(f"  1. dataset=infoblox_threat_raw | filter xdm.source.ip=\"{victim_ip}\" — Threat Protect alert")
    print(f"  2. dataset=infoblox_dhcp_raw   | filter xdm.source.ip=\"{victim_ip}\" — who is this device?")
    print(f"  3. dataset=infoblox_dns_raw    | filter xdm.source.ip=\"{victim_ip}\" | sort _time — full DNS history")
    print(f"  4. Correlate MAC from step 2 with other devices — did this MAC appear on multiple IPs?")


def run_gcp_cloud_pentest_scenario(modules, config):
    """
    GCP Cloud Pentest — Privilege Escalation + Defense Evasion + Data Staging.

    Story: Attacker accesses GCP API from a Tor exit node, escalates privileges via IAM,
    creates a persistent service account key, disables audit logging and SCC, then makes
    a GCS bucket public and exfiltrates a disk snapshot for offline analysis.

    Datasets: google_cloud_logging_raw
    Hunt: Chain on protoPayload.authenticationInfo.principalEmail + callerIp (Tor) across
          SetIamPolicy → CreateServiceAccountKey → UpdateSink → UpdateNotificationConfig →
          SetBucketAcl → CreateSnapshot events within the same session window.
    """
    print("\n--- Running 'GCP Cloud Pentest' Scenario ---")

    gcp_module = modules.get("Google Cloud Compute")
    if not gcp_module:
        print("ERROR: This scenario requires the 'Google Cloud Compute (GCP)' module.")
        return

    attacker_ip = _fresh_attacker_ip()   # fresh per run — avoids source-IP alert suppression

    try:
        from modules.session_utils import build_session_context, get_random_user
        session_context = build_session_context(config)
        user_info = get_random_user(session_context)
    except Exception:
        session_context = {}
        user_info = None

    attacker_email = (user_info.get("email") if user_info else None) or "attacker@external.com"

    context = {
        "session_context": session_context,
        "ip_address":      attacker_ip,
        "principal_email": attacker_email,
    }

    print(f"  Attacker IP:    {attacker_ip} (Tor exit node)")
    print(f"  Attacker email: {attacker_email}")

    try:
        print("\n[STEP 1] GCP: API access from Tor exit node (reconnaissance)...")
        result = gcp_module.generate_log(config, scenario_event="TOR_API_ACCESS", context=context)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "TOR_API_ACCESS"
        if log_content:
            process_and_send(log_content, gcp_module, config, event_name)
        time.sleep(2)

        print("[STEP 2] GCP: IAM privilege escalation (SetIamPolicy → roles/owner)...")
        result = gcp_module.generate_log(config, scenario_event="IAM_PRIVILEGE_ESCALATION", context=context)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "IAM_PRIVILEGE_ESCALATION"
        if log_content:
            process_and_send(log_content, gcp_module, config, event_name)
        time.sleep(1)

        print("[STEP 3] GCP: Create service account key (persistence)...")
        result = gcp_module.generate_log(config, scenario_event="CREATE_SA_KEY", context=context)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "CREATE_SA_KEY"
        if log_content:
            process_and_send(log_content, gcp_module, config, event_name)
        time.sleep(1)

        print("[STEP 4] GCP: Disable Cloud Audit Logging (defense evasion)...")
        result = gcp_module.generate_log(config, scenario_event="DISABLE_AUDIT_LOGGING", context=context)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "DISABLE_AUDIT_LOGGING"
        if log_content:
            process_and_send(log_content, gcp_module, config, event_name)
        time.sleep(1)

        print("[STEP 5] GCP: Disable Security Command Center (defense evasion)...")
        result = gcp_module.generate_log(config, scenario_event="DISABLE_SCC", context=context)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "DISABLE_SCC"
        if log_content:
            process_and_send(log_content, gcp_module, config, event_name)
        time.sleep(1)

        print("[STEP 6] GCP: Make GCS bucket public (data staging)...")
        result = gcp_module.generate_log(config, scenario_event="MAKE_GCS_PUBLIC", context=context)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "MAKE_GCS_PUBLIC"
        if log_content:
            process_and_send(log_content, gcp_module, config, event_name)
        time.sleep(1)

        print("[STEP 7] GCP: Snapshot exfiltration (copy disk snapshot to attacker project)...")
        result = gcp_module.generate_log(config, scenario_event="SNAPSHOT_EXFIL", context=context)
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "SNAPSHOT_EXFIL"
        if log_content:
            process_and_send(log_content, gcp_module, config, event_name)

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- GCP Cloud Pentest Scenario Complete ---")
    print("\nHunt queries to run in XSIAM:")
    print(f"  1. dataset=google_cloud_logging_raw | filter protoPayload.requestMetadata.callerIp=\"{attacker_ip}\"")
    print(f"  2. Sequence: same principalEmail performs SetIamPolicy → CreateKey → UpdateSink → SetIamPolicy(GCS) within 15 min")
    print(f"  3. Filter protoPayload.methodName contains \"setIamPolicy\" and resource.type=\"gcs_bucket\" — public bucket pivots")


def run_web_app_compromise_scenario(modules, config):
    """
    Web Application Compromise → Server-Side C2.

    Story: Attacker scans the web application for vulnerabilities, exploits a web shell,
    executes malicious payloads, then the compromised server initiates anomalous outbound
    connections (post-exploit beacon) — visible across all loaded network firewalls.

    Datasets: apache_httpd_raw + all loaded firewall datasets
    Hunt: Find server IP appearing as *source* (not destination) in firewall outbound Allow
          events shortly after webshell_execution in apache_httpd_raw.
    """
    print("\n--- Running 'Web Application Compromise → Server C2' Scenario ---")

    httpd_module = modules.get("Apache httpd")
    fw_modules   = _collect_fw_modules(modules)

    if not httpd_module:
        print("ERROR: This scenario requires the 'Apache httpd' module.")
        return

    try:
        from modules.session_utils import build_session_context, get_random_user
        session_context = build_session_context(config)
    except Exception:
        session_context = {}

    # Pick a server IP from config (not a workstation — this is a server-side attack).
    # The Apache module's config key is 'apache_config' (server_ips list, or the
    # single server_ip); these match the web-server IPs the C2 rule keys on.
    apache_conf = config.get('apache_config', {})
    server_networks = apache_conf.get('server_ips') or (
        [apache_conf['server_ip']] if apache_conf.get('server_ip') else [])
    server_ip = (random.choice(server_networks) if server_networks
                 else f"10.0.10.{random.randint(50, 52)}")
    attacker_ip = f"{random.choice([45,52,91,104,185,193])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    base_ctx = {"session_context": session_context}
    fw_names = ", ".join(m.NAME for m in fw_modules) if fw_modules else "none"

    print(f"  Target server:  {server_ip}")
    print(f"  Attacker IP:    {attacker_ip}")
    print(f"  Firewall modules: {fw_names}")

    try:
        print("\n[STEP 1] Apache HTTPD: Attacker reconnaissance scan against web server...")
        result = httpd_module.generate_log(config, scenario_event="recon_scan",
                                           context={**base_ctx, "src_ip": attacker_ip})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "recon_scan"
        if log_content:
            process_and_send(log_content, httpd_module, config, event_name)
        time.sleep(2)

        print("[STEP 2] Apache HTTPD: Web shell execution detected (POST to upload path)...")
        result = httpd_module.generate_log(config, scenario_event="webshell_execution",
                                           context={**base_ctx, "src_ip": attacker_ip})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "webshell_execution"
        if log_content:
            process_and_send(log_content, httpd_module, config, event_name)
        time.sleep(2)

        print("[STEP 3] Apache HTTPD: Malicious payload delivery via web shell...")
        result = httpd_module.generate_log(config, scenario_event="malicious_payload",
                                           context={**base_ctx, "src_ip": attacker_ip})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "malicious_payload"
        if log_content:
            process_and_send(log_content, httpd_module, config, event_name)
        time.sleep(2)

        print(f"[STEP 4] All firewall modules: Anomalous outbound connection from server IP (post-exploit beacon)...")
        _send_to_all_fw(fw_modules, "server_outbound_http", config,
                        {**base_ctx, "src_ip": server_ip}, "[STEP 4]")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Web Application Compromise Scenario Complete ---")
    print("\nHunt queries to run in XSIAM:")
    print(f"  1. dataset=apache_httpd_raw | filter src_ip=\"{attacker_ip}\" | sort _time")
    print(f"  2. Pivot: find server IP \"{server_ip}\" as *source* in firewall outbound Allow events (anomalous — servers don't initiate)")
    print(f"  3. Sequence: apache webshell_execution → firewall server_outbound_http from same server IP within 5 min")


def run_vpn_compromise_scenario(modules, config):
    """
    VPN Credential Compromise → Lateral Movement.

    Story: Attacker brute-forces VPN credentials, then authenticates with impossible travel
    (same user VPN login from two geographically distant IPs). Once inside, attacker enumerates
    SMB shares and moves laterally to high-value targets. Okta logs impossible travel from the
    attacker's VPN-assigned IP authenticating to SSO.

    Datasets: cisco_asa_raw + all loaded firewall datasets + okta_raw
    Hunt: Find same username in ASA vpn_bruteforce AND Okta impossible_travel within 30 min.
          Join on VPN-assigned IP across ASA VPN session logs → firewall SMB lateral events.
    """
    print("\n--- Running 'VPN Compromise → Lateral Movement' Scenario ---")

    asa_module  = modules.get("Cisco ASA Firewall")
    okta_module = modules.get("Okta SSO")
    fw_modules  = _collect_fw_modules(modules)

    if not asa_module:
        print("ERROR: This scenario requires the 'Cisco ASA Firewall' module.")
        return

    try:
        from modules.session_utils import build_session_context, get_random_user
        session_context = build_session_context(config)
        victim_info = get_random_user(session_context)
    except Exception:
        session_context = {}
        victim_info = None

    if victim_info:
        victim_user = victim_info.get("username", "jsmith")
        victim_ip   = victim_info.get("ip", f"10.200.{random.randint(1,254)}.{random.randint(1,254)}")
    else:
        victim_user = "jsmith"
        victim_ip   = f"10.200.{random.randint(1,254)}.{random.randint(1,254)}"

    attacker_ip = f"{random.choice([45,52,91,104,185,193])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    # Internal IP the VPN gateway assigns to the attacker session. The ASA 722051
    # event binds victim_user to this IP; SMB lateral movement is sourced from it
    # so XSIAM stitches the lateral activity back to the VPN identity.
    vpn_inside_ip = f"10.250.{random.randint(1,254)}.{random.randint(1,254)}"
    base_ctx    = {"session_context": session_context}
    fw_names    = ", ".join(m.NAME for m in fw_modules) if fw_modules else "none"

    print(f"  Target user:      {victim_user} ({victim_ip})")
    print(f"  Attacker IP:      {attacker_ip}")
    print(f"  VPN-assigned IP:  {vpn_inside_ip}")
    print(f"  Firewall modules: {fw_names}")

    def _asa_threat(threat_name, ctx):
        """Force a named ASA threat via event_mix override."""
        asa_key = getattr(asa_module, 'CONFIG_KEY', 'cisco_asa_config')
        forced   = copy.deepcopy(config)
        forced.setdefault(asa_key, {}).setdefault("event_mix", {})["threat"] = [
            {"event": threat_name, "weight": 1}
        ]
        return asa_module.generate_log(forced, threat_level="Insane", benign_only=False, context=ctx)

    try:
        print("\n[STEP 1] Cisco ASA: VPN credential brute-force (many failed auth attempts)...")
        result = _asa_threat("vpn_bruteforce",
                             {**base_ctx, "src_ip": attacker_ip, "user": victim_user})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "vpn_bruteforce"
        if log_content:
            process_and_send(log_content, asa_module, config, event_name)
        time.sleep(2)

        print("[STEP 2] Cisco ASA: Impossible travel — VPN login from geographically distant IP...")
        result = _asa_threat("vpn_impossible_travel",
                             {**base_ctx, "src_ip": attacker_ip, "user": victim_user,
                              "vpn_inside_ip": vpn_inside_ip})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "vpn_impossible_travel"
        if log_content:
            process_and_send(log_content, asa_module, config, event_name)
        time.sleep(2)

        print(f"[STEP 3] All firewall modules: SMB share enumeration from VPN-assigned IP...")
        _send_to_all_fw(fw_modules, "smb_share_enumeration", config,
                        {**base_ctx, "src_ip": vpn_inside_ip}, "[STEP 3]")
        time.sleep(2)

        print(f"[STEP 4] All firewall modules: SMB lateral movement to new host...")
        _send_to_all_fw(fw_modules, "smb_new_host_lateral", config,
                        {**base_ctx, "src_ip": vpn_inside_ip}, "[STEP 4]")
        time.sleep(2)

        if okta_module:
            print("[STEP 5] Okta: Impossible travel — SSO login from attacker IP after VPN session...")
            result = okta_module.generate_log(config, scenario_event="impossible_travel",
                                              context={**base_ctx, "ip": attacker_ip, "user": victim_user})
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "impossible_travel"
            if log_content:
                process_and_send(log_content, okta_module, config, event_name)
        else:
            print("[STEP 5] Okta module not loaded — skipping impossible travel event.")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- VPN Compromise → Lateral Movement Scenario Complete ---")
    print("\nHunt queries to run in XSIAM:")
    print(f"  1. dataset=cisco_asa_raw | filter xdm.source.user.username=\"{victim_user}\" and event_type in (\"vpn_bruteforce\",\"vpn_impossible_travel\")")
    print(f"  2. Pivot: find IP \"{vpn_inside_ip}\" (VPN-assigned) in firewall SMB lateral events")
    print(f"  3. Correlate ASA VPN session for \"{victim_user}\" → Okta impossible_travel for same user within 30 min")


def run_aitm_session_hijack_scenario(modules, config):
    """
    AiTM Phishing → Session Hijack → Cloud Abuse.

    Story: Attacker delivers a QR-code phishing email that bypasses MFA. Victim authenticates
    through an attacker-controlled reverse proxy (AiTM), session cookie is stolen. Attacker
    replays the token (token_reuse) and the session appears from a new IP/device (session_roaming).
    Attacker then pivots to AWS using the hijacked cloud session to assume a cross-account role
    and disable Security Hub to evade detection.

    Datasets: proofpoint_tap_raw + okta_raw + amazon_aws_raw
    Hunt: Correlate Okta aitm_phishing event → token_reuse from new IP → AWS API calls from same
          access key within 10 min. Find Okta user matching AWS principalEmail within session window.
    OOB Detections: Proofpoint phishing delivered; Okta impossible travel may fire.
    """
    print("\n--- Running 'AiTM Session Hijack → Cloud Abuse' Scenario ---")

    pp_module   = modules.get("Proofpoint Email Gateway")
    okta_module = modules.get("Okta SSO")
    aws_module  = modules.get("aws")

    if not okta_module:
        print("ERROR: This scenario requires the 'Okta SSO' module.")
        return

    try:
        from modules.session_utils import build_session_context, get_random_user
        session_context = build_session_context(config)
        victim_info = get_random_user(session_context)
    except Exception:
        session_context = {}
        victim_info = None

    if victim_info:
        victim_email = victim_info.get("email", "victim@examplecorp.com")
        victim_user  = victim_info.get("username", "victim.user")
    else:
        victim_email = "victim@examplecorp.com"
        victim_user  = "victim.user"

    attacker_ip = _fresh_attacker_ip()   # fresh per run — avoids source-IP alert suppression
    base_ctx    = {"session_context": session_context}

    print(f"  Victim:      {victim_email} ({victim_user})")
    print(f"  Attacker IP: {attacker_ip}")

    try:
        if pp_module:
            print("\n[STEP 1] Proofpoint: QR-code phishing email delivered to victim (bypasses link scan)...")
            result = pp_module.generate_log(config, scenario_event="qr_code_phishing",
                                            context={**base_ctx, "target_email": victim_email,
                                                     "sender_ip": attacker_ip})
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "qr_code_phishing"
            if log_content:
                process_and_send(log_content, pp_module, config, event_name)
            time.sleep(2)
        else:
            print("\n[STEP 1] Proofpoint module not loaded — skipping QR-code phishing delivery.")

        print("[STEP 2] Okta: AiTM phishing — victim authenticates through attacker reverse proxy...")
        result = okta_module.generate_log(config, scenario_event="aitm_phishing",
                                          context={**base_ctx, "ip": attacker_ip, "user": victim_user})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "aitm_phishing"
        if log_content:
            process_and_send(log_content, okta_module, config, event_name)
        time.sleep(2)

        print("[STEP 3] Okta: Token reuse — stolen session cookie replayed from attacker IP...")
        result = okta_module.generate_log(config, scenario_event="token_reuse",
                                          context={**base_ctx, "ip": attacker_ip, "user": victim_user})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "token_reuse"
        if log_content:
            process_and_send(log_content, okta_module, config, event_name)
        time.sleep(1)

        print("[STEP 4] Okta: Session roaming — session active from new device/IP (hijacked)...")
        result = okta_module.generate_log(config, scenario_event="session_roaming",
                                          context={**base_ctx, "ip": attacker_ip, "user": victim_user})
        if isinstance(result, tuple):
            log_content, event_name = result
        else:
            log_content, event_name = result, "session_roaming"
        if log_content:
            process_and_send(log_content, okta_module, config, event_name)
        time.sleep(2)

        if aws_module:
            aws_conf = config.get('aws_config', {})
            account_id = aws_conf.get('aws_account_id', '123456789012')
            # AiTM: the hijacked Okta session federates into AWS via SAML SSO, so the
            # AWS identity IS the victim (userName=victim email). This lets the cloud-abuse
            # alerts stitch to the same identity as the upstream Okta/Proofpoint stages.
            victim_fed_identity = {
                "type":       "SAMLUser",
                "name":       victim_email,
                "userName":   victim_email,
                "accountId":  account_id,
                "arn_suffix": f"assumed-role/OktaSSO-AdminAccess/{victim_email}",
            }
            aws_context = {
                **base_ctx,
                "ip_address":         attacker_ip,
                "user_identity":      victim_fed_identity,
                "target_role":        "AdministratorAccess",
                "role_session_name":  victim_email,
            }

            print("[STEP 5] AWS: Cross-account role assumption using hijacked session credentials...")
            result = aws_module.generate_log(config, scenario_event="CROSS_ACCOUNT_ASSUME_ROLE",
                                             context=aws_context)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "CROSS_ACCOUNT_ASSUME_ROLE"
            if log_content:
                process_and_send(log_content, aws_module, config, event_name)
            time.sleep(1)

            print("[STEP 6] AWS: Disable Security Hub (defense evasion — suppress GuardDuty findings)...")
            result = aws_module.generate_log(config, scenario_event="DISABLE_SECURITY_HUB",
                                             context=aws_context)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "DISABLE_SECURITY_HUB"
            if log_content:
                process_and_send(log_content, aws_module, config, event_name)
        else:
            print("[STEP 5-6] AWS module not loaded — skipping cloud abuse steps.")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- AiTM Session Hijack → Cloud Abuse Scenario Complete ---")
    print("\nHunt queries to run in XSIAM:")
    print(f"  1. dataset=okta_raw | filter user=\"{victim_user}\" and event_type in (\"aitm_phishing\",\"token_reuse\",\"session_roaming\") | sort _time")
    print(f"  2. Correlate Okta session start IP → AWS API calls from same IP or access key within 10 min")
    print(f"  3. dataset=amazon_aws_raw | filter callerIp=\"{attacker_ip}\" and eventName in (\"AssumeRole\",\"DisableSecurityHub\")")
    print(f"  OOB: Okta aitm_phishing and impossible_travel may fire; all other steps need custom correlation rules.")


def run_ransomware_precursor_scenario(modules, config):
    """
    Ransomware Precursor Kill Chain.

    Story: Attacker delivers a malware attachment via email. Uses harvested credentials to
    authenticate to Okta (bypassing MFA). Once on network, enumerates SMB shares, moves
    laterally, and transfers suspicious files. Disables AWS security controls. Finally,
    large egress sessions are observed from multiple hosts — consistent with pre-encryption
    data staging.

    Datasets: proofpoint_tap_raw + okta_raw + all loaded firewall datasets + amazon_aws_raw
    Hunt: Timeline from Proofpoint delivery → Okta auth → firewall SMB enumeration → AWS
          defense evasion → LARGE_EGRESS across all firewall datasets on same day.
    OOB: Proofpoint malware_attachment delivered; Okta brute_force / mfa_bypass may fire.
    """
    print("\n--- Running 'Ransomware Precursor Kill Chain' Scenario ---")

    pp_module   = modules.get("Proofpoint Email Gateway")
    okta_module = modules.get("Okta SSO")
    aws_module  = modules.get("aws")
    fw_modules  = _collect_fw_modules(modules)

    try:
        from modules.session_utils import build_session_context, get_random_user
        session_context = build_session_context(config)
        victim_info = get_random_user(session_context)
    except Exception:
        session_context = {}
        victim_info = None

    if victim_info:
        victim_email = victim_info.get("email", "victim@examplecorp.com")
        victim_user  = victim_info.get("username", "victim.user")
        victim_ip    = victim_info.get("ip", f"10.{random.randint(1,10)}.{random.randint(1,254)}.{random.randint(2,254)}")
    else:
        victim_email = "victim@examplecorp.com"
        victim_user  = "victim.user"
        victim_ip    = f"10.{random.randint(1,10)}.{random.randint(1,254)}.{random.randint(2,254)}"

    attacker_ip = f"{random.choice([45,52,91,104,185,193])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    base_ctx    = {"session_context": session_context}
    fw_names    = ", ".join(m.NAME for m in fw_modules) if fw_modules else "none"

    print(f"  Victim:           {victim_email} / {victim_user} ({victim_ip})")
    print(f"  Attacker IP:      {attacker_ip}")
    print(f"  Firewall modules: {fw_names}")

    try:
        if pp_module:
            print("\n[STEP 1] Proofpoint: Malware attachment delivered to victim mailbox...")
            result = pp_module.generate_log(config, scenario_event="MALWARE_ATTACHMENT",
                                            context={**base_ctx, "target_email": victim_email,
                                                     "sender_ip": attacker_ip})
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "MALWARE_ATTACHMENT"
            if log_content:
                process_and_send(log_content, pp_module, config, event_name)
            time.sleep(2)
        else:
            print("\n[STEP 1] Proofpoint module not loaded — skipping email delivery step.")

        if okta_module:
            print("[STEP 2] Okta: Credential brute-force — attacker cycling passwords from harvested list...")
            result = okta_module.generate_log(config, scenario_event="brute_force",
                                              context={**base_ctx, "ip": attacker_ip, "user": victim_user})
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "brute_force"
            if log_content:
                process_and_send(log_content, okta_module, config, event_name)
            time.sleep(1)

            print("[STEP 3] Okta: MFA reset — attacker resets the victim's MFA factors to seize the account...")
            result = okta_module.generate_log(config, scenario_event="mfa_reset",
                                              context={**base_ctx, "ip": attacker_ip, "user": victim_user})
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "mfa_bypass"
            if log_content:
                process_and_send(log_content, okta_module, config, event_name)
            time.sleep(2)
        else:
            print("[STEP 2-3] Okta module not loaded — skipping credential compromise steps.")

        print(f"[STEP 4] All firewall modules: SMB share enumeration (discovering file shares)...")
        _send_to_all_fw(fw_modules, "smb_share_enumeration", config,
                        {**base_ctx, "src_ip": victim_ip}, "[STEP 4]")
        time.sleep(2)

        print(f"[STEP 5] All firewall modules: SMB lateral movement + rare file transfer (staging)...")
        _send_to_all_fw(fw_modules, "smb_rare_file_transfer", config,
                        {**base_ctx, "src_ip": victim_ip}, "[STEP 5]")
        time.sleep(2)

        if aws_module:
            aws_conf = config.get('aws_config', {})
            all_users = aws_conf.get('users_and_roles', [])
            user_template = next(
                (u for u in all_users if u.get('type') == 'IAMUser'), None
            ) or {"type": "IAMUser", "name": victim_user, "arn_suffix": f"user/{victim_user}"}
            aws_context = {
                **base_ctx,
                "ip_address":    attacker_ip,
                "user_identity": _get_random_user_from_template(config, user_template),
            }

            print("[STEP 6] AWS: Stop Config Recorder (prevent change tracking before encryption)...")
            result = aws_module.generate_log(config, scenario_event="STOP_CONFIG_RECORDER",
                                             context=aws_context)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "STOP_CONFIG_RECORDER"
            if log_content:
                process_and_send(log_content, aws_module, config, event_name)
            time.sleep(1)

            print("[STEP 7] AWS: Delete WAF rule (remove inbound protection before staging)...")
            result = aws_module.generate_log(config, scenario_event="DELETE_WAF_RULE",
                                             context=aws_context)
            if isinstance(result, tuple):
                log_content, event_name = result
            else:
                log_content, event_name = result, "DELETE_WAF_RULE"
            if log_content:
                process_and_send(log_content, aws_module, config, event_name)
            time.sleep(1)
        else:
            print("[STEP 6-7] AWS module not loaded — skipping defense evasion steps.")

        print(f"[STEP 8] All firewall modules: Large egress sessions (data staging before encryption)...")
        _send_to_all_fw(fw_modules, "LARGE_EGRESS", config,
                        {**base_ctx, "src_ip": victim_ip}, "[STEP 8]")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Ransomware Precursor Kill Chain Scenario Complete ---")
    print("\nHunt queries to run in XSIAM:")
    print(f"  1. dataset=proofpoint_tap_raw | filter recipient=\"{victim_email}\" and disposition=\"delivered\"")
    print(f"  2. dataset=okta_raw | filter user=\"{victim_user}\" and event_type in (\"brute_force\",\"mfa_bypass\") | sort _time")
    print(f"  3. Join victim IP \"{victim_ip}\" across firewall datasets: smb_share_enumeration → smb_rare_file_transfer → LARGE_EGRESS sequence")
    print(f"  4. dataset=amazon_aws_raw | filter eventName in (\"StopConfigurationRecorder\",\"DeleteWebACL\") | same time window")
    print(f"  OOB: Proofpoint malware delivered; Okta brute_force / mfa_bypass may fire. All other steps need custom correlation rules.")


def run_domain_dominance_scenario(all_modules, config):
    """Domain Dominance — on-prem Active Directory takeover from a phished workstation.

    A single victim (email + AD username + host IP + hostname) is threaded through every
    stage so XSIAM stitches them into one incident:
      0. Infoblox    — DHCP lease anchor (binds IP↔MAC↔host for identity-graph resolution)
      1. Proofpoint  — malware email delivered to the victim
      2. Infoblox    — PTR sweep + zone transfer from the beachhead (internal recon)
      3. Windows     — Kerberoasting (burst of RC4 service-ticket requests)
      4. Windows     — DCSync (directory replication rights abused)
      5. Cisco ASA   — SMB share enumeration to unseen internal hosts (lateral movement)
      6. Windows     — account delegation rights modified (persistence)

    Spine: the victim user (AD) + host IP. The Windows AD threats pick their user from
    session_context, so we hand them a SINGLE-victim context to pin them to one user.
    """
    print("\n--- Running 'Domain Dominance' Scenario ---")

    pp_module  = all_modules.get("Proofpoint Email Gateway")
    win_module = all_modules.get("Windows Event Log")
    ibx_module = all_modules.get("Infoblox NIOS")
    fw_modules = _collect_fw_modules(all_modules)

    if not win_module:
        print("ERROR: This scenario requires the 'Windows Event Log' module (AD attack stages).")
        return

    try:
        from modules.session_utils import build_session_context, get_user_by_name
        session_context = build_session_context(config)
    except Exception as e:
        print(f"ERROR: could not build session context: {e}")
        return

    # Pick a victim who is a Windows user WITH a host + IP (so the AD threats + DNS/SMB
    # stages all key off a real, consistent host).
    win_keys = [u for u, p in session_context.items()
                if (p.get("primary_os_type") or "").lower() == "windows"]
    victim_key = victim = None
    for u in random.sample(win_keys, len(win_keys)):
        info = get_user_by_name(session_context, u)
        if info and info.get("hostname") and info.get("ip"):
            victim_key, victim = u, info
            break
    if not victim_key:
        print("ERROR: no Windows user with a host + IP in session context — cannot run AD scenario.")
        return

    victim_user  = victim.get("username", victim_key)
    default_dom  = (config.get("google_workspace_config", {}).get("domains") or ["examplecorp.com"])[0]
    victim_email = victim.get("email") or f"{victim_user}@{default_dom}"
    victim_ip    = victim.get("ip")
    victim_host  = victim.get("hostname")
    victim_mac   = victim.get("mac") or (
        f"00:50:56:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}")
    attacker_ip  = _fresh_attacker_ip()

    # Single-victim session_context so EVERY Windows AD threat targets the SAME user+host
    # (the threat generators call _pick_windows_user, which picks randomly from the context).
    victim_sc = {victim_key: session_context[victim_key]}
    win_ctx   = {"session_context": victim_sc}
    base_ctx  = {"session_context": session_context}

    print(f"  Victim:      {victim_email} / {victim_user} on {victim_host} ({victim_ip})")
    print(f"  Attacker IP: {attacker_ip}")

    def _emit(result, module, default_name):
        if not result:
            return
        content, name = result if isinstance(result, tuple) else (result, default_name)
        if content:
            process_and_send(content, module, config, name)

    try:
        # ANCHOR — DHCP lease binds victim_ip ↔ victim_mac ↔ victim_host. This seeds
        # XSIAM's identity graph with the IP↔hostname mapping so the IP-keyed DNS/SMB
        # alerts can resolve to the same host/user as the AD alerts — the missing rung
        # that lets all stages fold into one incident.
        if ibx_module and victim_ip:
            print("\n[ANCHOR] Infoblox: DHCP lease — device on network (binds IP ↔ host)...")
            _emit(ibx_module.generate_log(config, scenario_event="DHCP_ACK",
                                          context={"src_ip": victim_ip, "client_mac": victim_mac,
                                                   "hostname": victim_host}),
                  ibx_module, "DHCP_ACK")
            time.sleep(1)

        # BINDING — victim authenticates from their workstation IP (Windows 4624 type-3).
        # This single IP↔user event is what the IP-keyed DNS/SMB detections join against
        # to resolve the user, so they fold into the AD user's incident.
        print("[BIND] Windows: victim network logon from workstation IP (IP ↔ user)...")
        _emit(win_module.generate_log(config, scenario_event="NETWORK_LOGON",
                                      context={"session_context": victim_sc, "user_identity": victim_key,
                                               "src_ip": victim_ip}),
              win_module, "network_logon")
        time.sleep(1)

        # STEP 1 — Initial access: malware email to the victim
        if pp_module:
            print("[STEP 1] Proofpoint: malware attachment delivered to victim mailbox...")
            _emit(pp_module.generate_log(config, scenario_event="MALWARE_ATTACHMENT",
                                         context={**base_ctx, "target_email": victim_email,
                                                  "sender_ip": attacker_ip}),
                  pp_module, "MALWARE_ATTACHMENT")
            time.sleep(2)
        else:
            print("\n[STEP 1] Proofpoint module not loaded — skipping malware delivery.")

        # STEP 2 — Internal recon: PTR sweep + zone transfer from the beachhead host
        if ibx_module and victim_ip:
            print("[STEP 2] Infoblox: reverse-DNS sweep + zone transfer from the compromised host...")
            _emit(ibx_module.generate_log(config, scenario_event="PTR_SWEEP",
                                          context={"src_ip": victim_ip, "hostname": victim_host}),
                  ibx_module, "PTR_SWEEP")
            time.sleep(1)
            _emit(ibx_module.generate_log(config, scenario_event="ZONE_TRANSFER",
                                          context={"src_ip": victim_ip, "hostname": victim_host}),
                  ibx_module, "ZONE_TRANSFER")
            time.sleep(2)
        else:
            print("[STEP 2] Infoblox module not loaded — skipping DNS recon.")

        # STEP 3 — Credential access: Kerberoasting (RC4 service-ticket burst)
        print("[STEP 3] Windows: Kerberoasting — burst of service-ticket requests from the victim...")
        _emit(win_module.generate_log(config, scenario_event="MULTIPLE_SERVICE_TICKETS", context=win_ctx),
              win_module, "multiple_service_tickets")
        time.sleep(2)

        # STEP 4 — Privilege escalation: DCSync
        print("[STEP 4] Windows: DCSync — directory replication rights abused...")
        _emit(win_module.generate_log(config, scenario_event="DCSYNC", context=win_ctx),
              win_module, "dcsync")
        time.sleep(2)

        # STEP 5 — Lateral movement: SMB share enumeration from the victim IP
        if fw_modules and victim_ip:
            print("[STEP 5] Cisco ASA: SMB share enumeration to unseen internal hosts...")
            _send_to_all_fw(fw_modules, "smb_share_enumeration", config,
                            {**base_ctx, "src_ip": victim_ip}, "[STEP 5]")
            time.sleep(2)
        else:
            print("[STEP 5] No firewall module loaded — skipping SMB lateral movement.")

        # STEP 6 — Persistence: delegation change on the victim account.
        # (priv_group_addition is intentionally not used here — it needs a separate
        # admin actor + target, which conflicts with pinning every stage to one victim.)
        print("[STEP 6] Windows: persistence — account delegation rights modified...")
        _emit(win_module.generate_log(config, scenario_event="DELEGATION_CHANGE", context=win_ctx),
              win_module, "delegation_change")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Domain Dominance Scenario Complete ---")
    print("\nHunt queries to run in XSIAM:")
    print(f"  1. Timeline the victim across sources: user \"{victim_user}\" / host \"{victim_host}\" / IP \"{victim_ip}\"")
    print(f"  2. dataset=microsoft_windows_raw | filter user \"{victim_user}\": Kerberoast(4769) → DCSync(4662) → delegation/priv-group")
    print(f"  3. Correlate Infoblox client \"{victim_ip}\" (PTR sweep + zone transfer) with the AD activity on the same host")
    print(f"  NOTE: Proofpoint↔AD linkage relies on the identity graph resolving {victim_email} ↔ AD user {victim_user}.")


def run_beaconing_implant_scenario(all_modules, config):
    """Beaconing Implant — one infected host runs an implant that beacons to C2 over
    DNS, web, and the firewall, then persists via a newly installed service.

    Spine: ONE infected host (hostname + IP). Every stage keys off that host/IP so the
    alerts fold into a single incident.
    """
    print("\n--- Running 'Beaconing Implant' Scenario ---")

    win_module = all_modules.get("Windows Event Log")
    ibx_module = all_modules.get("Infoblox NIOS")
    zs_module  = all_modules.get("Zscaler Web Gateway")
    fw_modules = _collect_fw_modules(all_modules)

    try:
        from modules.session_utils import build_session_context, get_user_by_name
        session_context = build_session_context(config)
    except Exception as e:
        print(f"ERROR: could not build session context: {e}")
        return

    win_keys = [u for u, p in session_context.items()
                if (p.get("primary_os_type") or "").lower() == "windows"]
    victim_key = victim = None
    for u in random.sample(win_keys, len(win_keys)):
        info = get_user_by_name(session_context, u)
        if info and info.get("hostname") and info.get("ip"):
            victim_key, victim = u, info
            break
    if not victim_key:
        print("ERROR: no Windows host with an IP in session context.")
        return

    host_ip   = victim.get("ip")
    host_name = victim.get("hostname")
    host_mac  = victim.get("mac") or (
        f"00:50:56:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}")
    c2_ip     = _fresh_attacker_ip()
    victim_sc = {victim_key: session_context[victim_key]}

    print(f"  Infected host: {host_name} ({host_ip})   C2: {c2_ip}")

    def _emit(result, module, default_name):
        if not result:
            return
        content, name = result if isinstance(result, tuple) else (result, default_name)
        if content:
            process_and_send(content, module, config, name)

    try:
        # ANCHOR — DHCP lease binds host IP ↔ host name (seeds the identity graph).
        if ibx_module:
            print("\n[ANCHOR] Infoblox: DHCP lease (binds IP ↔ host)...")
            _emit(ibx_module.generate_log(config, scenario_event="DHCP_ACK",
                                          context={"src_ip": host_ip, "client_mac": host_mac,
                                                   "hostname": host_name}),
                  ibx_module, "DHCP_ACK")
            time.sleep(1)

        # BINDING — host authenticates from its IP (4624 type-3): the IP↔user binding that
        # lets the IP-keyed DNS detections (C2 beacon, DNS tunnel) resolve the user, so every
        # implant alert carries both host IP and user (full enrichment).
        if win_module:
            print("[BIND] Windows: host network logon from its IP (IP ↔ user)...")
            _emit(win_module.generate_log(config, scenario_event="NETWORK_LOGON",
                                          context={"session_context": victim_sc, "user_identity": victim_key,
                                                   "src_ip": host_ip}),
                  win_module, "network_logon")
            time.sleep(1)

        # STEP 0 — Initial execution: phishing doc spawns a hidden-PowerShell process tree.
        if win_module:
            print("[STEP 0] Windows: initial execution — Office → PowerShell → LOLBin (4688 tree)...")
            _emit(win_module.generate_log(config, scenario_event="PROCESS_TREE",
                                          context={"session_context": victim_sc, "user_identity": victim_key,
                                                   "c2_ip": c2_ip}),
                  win_module, "process_tree")
            time.sleep(2)

        # STEP 1 — DNS C2 beacon: recurring queries to the C2 domain from the host.
        if ibx_module:
            print("[STEP 1] Infoblox: DNS C2 beacon (recurring domain queries)...")
            _emit(ibx_module.generate_log(config, scenario_event="C2_BEACON",
                                          context={"src_ip": host_ip}),
                  ibx_module, "C2_BEACON")
            time.sleep(2)

        # STEP 2 — DNS tunneling: TXT-record burst carrying encoded C2 traffic.
        if ibx_module:
            print("[STEP 2] Infoblox: DNS tunneling (TXT burst)...")
            _emit(ibx_module.generate_log(config, scenario_event="DNS_TUNNEL",
                                          context={"src_ip": host_ip}),
                  ibx_module, "DNS_TUNNEL")
            time.sleep(2)

        # STEP 2b — Web-layer C2 beacon: periodic HTTP callbacks (Zscaler web proxy / nssweblog).
        if zs_module:
            print("[STEP 2b] Zscaler: web-layer C2 beacon (periodic HTTP callbacks)...")
            _emit(zs_module.generate_log(config, scenario_event="web_c2_beacon",
                                         context={"session_context": victim_sc, "src_ip": host_ip}),
                  zs_module, "web_c2_beacon")
            time.sleep(2)

        # STEP 3 — Web-channel exfil over HTTPS from the host (Zscaler).
        if zs_module:
            print("[STEP 3] Zscaler: implant exfil over HTTPS...")
            _emit(zs_module.generate_log(config, scenario_event="DATA_EXFIL",
                                         context={"session_context": victim_sc, "src_ip": host_ip}),
                  zs_module, "data_exfil")
            time.sleep(2)

        # STEP 4 — Periodic outbound to the C2 IP across the perimeter firewalls.
        if fw_modules:
            print("[STEP 4] Firewalls: periodic outbound to C2...")
            _send_to_all_fw(fw_modules, "server_outbound_http", config,
                            {"src_ip": host_ip, "dst_ip": c2_ip}, "[STEP 4]")
            time.sleep(2)

        # STEP 5 — Persistence: implant installs an auto-start service on the host (4697).
        if win_module:
            print("[STEP 5] Windows: implant persistence — service installed (4697)...")
            _emit(win_module.generate_log(config, scenario_event="SERVICE_INSTALL",
                                          context={"session_context": victim_sc, "hostname": host_name}),
                  win_module, "service_install")
            time.sleep(2)

        # STEP 6 — Anti-forensics: clear the Security event log (1102).
        if win_module:
            print("[STEP 6] Windows: anti-forensics — Security audit log cleared (1102)...")
            _emit(win_module.generate_log(config, scenario_event="CLEAR_LOGS",
                                          context={"session_context": victim_sc, "user_identity": victim_key}),
                  win_module, "log_cleared")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Beaconing Implant Scenario Complete ---")
    print(f"  Spine: infected host {host_name} / {host_ip} beaconing to {c2_ip}")
    print(f"  Detects: Infoblox C2 beacon + DNS tunnel; native 4697 service-install; FW/Zscaler egress — all keyed to the host.")


def run_server_breach_cloud_scenario(all_modules, config):
    """Server Breach → Cloud Takeover — a public web server is exploited and used as a
    pivot for a reverse shell + DNS exfil, then its EC2 role is abused to exfil S3.

    Spine (on-prem): the web SERVER's IP. Apache attack → reverse shell → DNS exfil all
    key off it. The cloud stage links via the instance role (server↔role); the cross-tier
    merge lands once XSIAM identity unification ships.
    """
    print("\n--- Running 'Server Breach → Cloud Takeover' Scenario ---")

    httpd_module = all_modules.get("Apache httpd")
    ibx_module   = all_modules.get("Infoblox NIOS")
    aws_module   = all_modules.get("aws")
    fw_modules   = _collect_fw_modules(all_modules)

    if not httpd_module:
        print("ERROR: this scenario requires the 'Apache httpd' module.")
        return

    try:
        from modules.session_utils import build_session_context
        session_context = build_session_context(config)
    except Exception:
        session_context = None

    apache_conf = config.get("apache_config", {})
    server_ip   = (apache_conf.get("server_ips") or [apache_conf.get("server_ip")] or [None])[0] \
                  or f"10.0.{random.randint(1, 20)}.{random.randint(2, 254)}"
    attacker_ip = _fresh_attacker_ip()

    print(f"  Web server (pivot): {server_ip}   Attacker: {attacker_ip}")

    def _emit(result, module, default_name):
        if not result:
            return
        content, name = result if isinstance(result, tuple) else (result, default_name)
        if content:
            process_and_send(content, module, config, name)

    try:
        # STEP 1 — Recon: attacker sweeps the web server (404 burst).
        print("\n[STEP 1] Apache: attacker reconnaissance scan against the web server...")
        _emit(httpd_module.generate_log(config, scenario_event="recon_scan",
                                        context={"session_context": session_context, "src_ip": attacker_ip}),
              httpd_module, "recon_scan")
        time.sleep(2)

        # STEP 2 — Web-shell upload (POST to an upload handler).
        print("[STEP 2] Apache: web-shell upload (POST to upload handler)...")
        _emit(httpd_module.generate_log(config, scenario_event="webshell_execution",
                                        context={"session_context": session_context, "src_ip": attacker_ip}),
              httpd_module, "webshell_execution")
        time.sleep(2)

        # STEP 3 — Command execution via the web shell (SQL/cmd payloads).
        print("[STEP 3] Apache: command execution via web shell (malicious payloads)...")
        _emit(httpd_module.generate_log(config, scenario_event="malicious_payload",
                                        context={"session_context": session_context, "src_ip": attacker_ip}),
              httpd_module, "malicious_payload")
        time.sleep(2)

        # STEP 4 — Reverse shell: anomalous outbound from the server to the attacker.
        if fw_modules:
            print("[STEP 4] Firewalls: reverse shell / egress from the server IP...")
            _send_to_all_fw(fw_modules, "server_outbound_http", config,
                            {"src_ip": server_ip, "dst_ip": attacker_ip}, "[STEP 4]")
            time.sleep(2)

        # STEP 5 — DNS exfil (TXT tunnel) staged from the server.
        if ibx_module:
            print("[STEP 5] Infoblox: DNS tunneling exfil from the server...")
            _emit(ibx_module.generate_log(config, scenario_event="DNS_TUNNEL",
                                          context={"src_ip": server_ip}),
                  ibx_module, "DNS_TUNNEL")
            time.sleep(2)

        # STEP 6 — Cloud pivot: SSRF/IMDS steals the server's EC2-role credentials.
        if aws_module:
            print("[STEP 6] AWS: SSRF/IMDS credential theft — instance role used from the attacker IP...")
            _emit(aws_module.generate_log(config, scenario_event="IMDS_CREDENTIAL_THEFT",
                                          context={"session_context": session_context,
                                                   "ip_address": attacker_ip}),
                  aws_module, "IMDS_CREDENTIAL_THEFT")
            # GuardDuty corroboration: instance-role credentials used from outside AWS.
            _emit_guardduty(all_modules, config,
                            {"session_context": session_context, "ip_address": attacker_ip},
                            "GD_INSTANCE_CRED_EXFIL")
            time.sleep(2)

        # STEP 7 — Cloud exfil: the stolen EC2-role credentials bulk-read + exfil S3.
        if aws_module:
            print("[STEP 7] AWS: EC2-role S3 data exfiltration (ListBuckets → bulk GetObject)...")
            _emit(aws_module.generate_log(config, scenario_event="S3_READ_EXFIL_CHAIN",
                                          context={"session_context": session_context,
                                                   "ip_address": attacker_ip}),
                  aws_module, "S3_READ_EXFIL_CHAIN")
            _emit_guardduty(all_modules, config,
                            {"session_context": session_context, "ip_address": attacker_ip},
                            "GD_S3_EXFIL")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Server Breach → Cloud Takeover Scenario Complete ---")
    print(f"  Spine (on-prem): web server {server_ip} — Apache attack → reverse shell → DNS exfil group by server IP.")
    print(f"  Cloud stage (S3 exfil) links via the instance role; cross-tier merge awaits XSIAM identity unification.")


def run_cloud_ransomware_scenario(all_modules, config):
    """Cloud Ransomware — a compromised AWS principal encrypts and ransoms S3 data.

    Full kill chain: credential brute force → privilege escalation → defense evasion →
    data exfil (double extortion) → mass re-encryption with a foreign KMS key + version
    destruction + ransom note. Spine (cloud): the compromised principal + attacker IP
    threaded across the CloudTrail stages.
    """
    print("\n--- Running 'Cloud Ransomware' Scenario ---")

    aws_module = all_modules.get("aws")
    if not aws_module:
        print("ERROR: this scenario requires the 'aws' module.")
        return

    try:
        from modules.session_utils import build_session_context
        session_context = build_session_context(config)
    except Exception:
        session_context = None

    attacker_ip = _fresh_attacker_ip()
    aws_ctx = {"session_context": session_context, "ip_address": attacker_ip}

    print(f"  Attacker IP: {attacker_ip}  (CloudTrail sourceIPAddress across stages)")

    def _emit(result, module, default_name):
        if not result:
            return
        content, name = result if isinstance(result, tuple) else (result, default_name)
        if content:
            process_and_send(content, module, config, name)

    # (label, scenario_event) — a realistic cloud-ransomware kill chain from existing events.
    stages = [
        ("STEP 1", "Initial access: console-login credential brute force",       "CONSOLE_LOGIN_BRUTE_FORCE"),
        ("STEP 2", "Privilege escalation: attach AdministratorAccess policy",     "ATTACH_ADMIN_POLICY"),
        ("STEP 3", "Defense evasion: stop CloudTrail logging",                    "STOP_CLOUDTRAIL"),
        ("STEP 4", "Defense evasion: disable S3 bucket access logging",           "DISABLE_S3_LOGGING"),
        ("STEP 5", "Double extortion: bulk S3 read + exfil before encryption",    "S3_READ_EXFIL_CHAIN"),
        ("STEP 6", "Impact: mass re-encryption (foreign KMS) + delete + ransom note", "S3_RANSOMWARE_ENCRYPT"),
        ("STEP 7", "Impact: destroy KMS keys (DisableKey + ScheduleKeyDeletion)",  "KMS_KEY_DESTRUCTION"),
    ]

    # Corroborating GuardDuty finding per CloudTrail stage (same principal/IP pivot).
    _gd_for_stage = {
        "CONSOLE_LOGIN_BRUTE_FORCE": "GD_MALICIOUS_IP",
        "ATTACH_ADMIN_POLICY":       "GD_ADMIN_PRIVESC",
        "STOP_CLOUDTRAIL":           "GD_CLOUDTRAIL_DISABLED",
        "DISABLE_S3_LOGGING":        "GD_S3_LOGGING_DISABLED",
        "S3_READ_EXFIL_CHAIN":       "GD_S3_EXFIL",
        "S3_RANSOMWARE_ENCRYPT":     "GD_S3_IMPACT",
    }

    try:
        for label, desc, ev in stages:
            print(f"[{label}] AWS: {desc}...")
            _emit(aws_module.generate_log(config, scenario_event=ev, context=aws_ctx),
                  aws_module, ev)
            gd_ev = _gd_for_stage.get(ev)
            if gd_ev:
                _emit_guardduty(all_modules, config, aws_ctx, gd_ev)
            time.sleep(2)
    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Deliver the batched CloudTrail objects as one S3 upload per run.
        try:
            flush_s3_batch()
        except Exception:
            pass

    print("\n--- Cloud Ransomware Scenario Complete ---")
    print(f"  Chain: brute force → admin policy → stop CloudTrail → disable S3 logging → exfil → encrypt+ransom.")
    print(f"  Detects: AWS console brute force, defense-evasion (StopLogging), S3 exfil, 'Suspicious objects encryption in an AWS bucket'.")


def run_perimeter_intrusion_scenario(all_modules, config):
    """Perimeter Intrusion — one external attacker IP probes and breaches the edge.

    Chain: port scan across the perimeter firewalls → high-volume denied inbound →
    VPN credential brute force → web-server exploitation (Log4Shell / injection).
    Spine: the external attacker IP (pinned for the Apache stages; the firewall threat
    generators each use their own single external IP — see the generator-pinning
    enhancement).
    """
    print("\n--- Running 'Perimeter Intrusion' Scenario ---")

    httpd_module = all_modules.get("Apache httpd")
    fw_modules   = _collect_fw_modules(all_modules)

    if not fw_modules and not httpd_module:
        print("ERROR: this scenario requires firewall and/or Apache modules.")
        return

    try:
        from modules.session_utils import build_session_context
        session_context = build_session_context(config)
    except Exception:
        session_context = None

    attacker_ip = _fresh_attacker_ip()
    print(f"  External attacker IP: {attacker_ip}")

    def _emit(result, module, default_name):
        if not result:
            return
        content, name = result if isinstance(result, tuple) else (result, default_name)
        if content:
            process_and_send(content, module, config, name)

    try:
        # STEP 1 — Port scan across the perimeter firewalls.
        if fw_modules:
            print("\n[STEP 1] Firewalls: external port scan against the perimeter...")
            _send_to_all_fw(fw_modules, "port_scan", config,
                            {"src_ip": attacker_ip}, "[STEP 1]")
            time.sleep(2)

        # STEP 2 — High-volume denied inbound connections (scanner / brute probing).
        if fw_modules:
            print("[STEP 2] Firewalls: high-volume denied inbound connections...")
            _send_to_all_fw(fw_modules, "failed_connections_burst", config,
                            {"src_ip": attacker_ip}, "[STEP 2]")
            time.sleep(2)

        # STEP 3 — VPN credential brute force against the gateway.
        if fw_modules:
            print("[STEP 3] Firewalls: VPN credential brute force...")
            _send_to_all_fw(fw_modules, "vpn_bruteforce", config,
                            {"src_ip": attacker_ip}, "[STEP 3]")
            time.sleep(2)

        # STEP 4 — Web-server exploitation attempt (Log4Shell probe).
        if httpd_module:
            print("[STEP 4] Apache: Log4Shell exploitation probe against the web server...")
            _emit(httpd_module.generate_log(config, scenario_event="log4shell_probe",
                                            context={"session_context": session_context, "src_ip": attacker_ip}),
                  httpd_module, "log4shell_probe")
            time.sleep(2)

        # STEP 5 — Follow-on injection payloads from the same attacker.
        if httpd_module:
            print("[STEP 5] Apache: command/SQL injection payloads from the attacker...")
            _emit(httpd_module.generate_log(config, scenario_event="malicious_payload",
                                            context={"session_context": session_context, "src_ip": attacker_ip}),
                  httpd_module, "malicious_payload")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Perimeter Intrusion Scenario Complete ---")
    print(f"  Chain: port scan → denied inbound flood → VPN brute force → web exploit, from attacker {attacker_ip}.")
    print(f"  Detects: port scan, high-volume denied inbound, VPN brute force, Apache Log4Shell/injection.")


def run_identity_attack_cloud_scenario(all_modules, config):
    """Identity Attack → Cloud — an Okta account takeover federates into AWS.

    MFA-fatigue + Tor login compromise an Okta account; the same identity federates into
    AWS via AssumeRoleWithSAML (roleSessionName = the Okta user), then escalates and
    exfiltrates. Spine: the victim username, carried from Okta into the AWS SAML session —
    pre-staging the exact Okta↔AWS link the identity graph will resolve.
    """
    print("\n--- Running 'Identity Attack → Cloud' Scenario ---")

    okta_module = all_modules.get("Okta SSO")
    aws_module  = all_modules.get("aws")
    if not okta_module or not aws_module:
        print("ERROR: this scenario requires the 'Okta SSO' and 'aws' modules.")
        return

    try:
        from modules.session_utils import build_session_context, get_user_by_name
        session_context = build_session_context(config)
    except Exception as e:
        print(f"ERROR: could not build session context: {e}")
        return

    keys = list(session_context.keys())
    victim_key = random.choice(keys) if keys else None
    victim = get_user_by_name(session_context, victim_key) if victim_key else None
    victim_user = (victim or {}).get("username", victim_key or "j.doe")
    attacker_ip = _fresh_attacker_ip()

    okta_ctx = {"session_context": session_context, "user": victim_user, "ip": attacker_ip}
    # Pin the AWS actor to the victim so every cloud stage (SAML, admin-policy, exfil)
    # carries the same identity — full enrichment + links to the Okta side. target_user
    # and user_identity must be DICTs (some AWS events call .get() on them).
    _aws_acct = config.get("aws_config", {}).get("aws_account_id", "123456789012")
    victim_identity = {"type": "IAMUser", "name": victim_user, "userName": victim_user,
                       "accountId": _aws_acct}
    aws_ctx  = {"session_context": session_context, "ip_address": attacker_ip,
                "saml_user": victim_user, "user_identity": victim_identity,
                "target_user": {"name": victim_user, "userName": victim_user}}

    print(f"  Victim identity: {victim_user}   Attacker IP: {attacker_ip}")

    def _emit(result, module, default_name):
        if not result:
            return
        content, name = result if isinstance(result, tuple) else (result, default_name)
        if content:
            process_and_send(content, module, config, name)

    try:
        # STEP 1 — MFA fatigue: attacker spams push prompts at the victim.
        print("\n[STEP 1] Okta: MFA-fatigue push bombing against the victim...")
        _emit(okta_module.generate_log(config, scenario_event="mfa_bombing", context=okta_ctx),
              okta_module, "mfa_bombing")
        time.sleep(2)

        # STEP 2 — Account takeover: successful login from a Tor exit node.
        print("[STEP 2] Okta: account takeover — login from a Tor exit node...")
        _emit(okta_module.generate_log(config, scenario_event="tor_login", context=okta_ctx),
              okta_module, "tor_login")
        time.sleep(2)

        # STEP 3 — Federation: the compromised identity assumes an AWS role via SAML.
        print("[STEP 3] AWS: AssumeRoleWithSAML — Okta identity federates into AWS...")
        _emit(aws_module.generate_log(config, scenario_event="ASSUME_ROLE_WITH_SAML", context=aws_ctx),
              aws_module, "ASSUME_ROLE_WITH_SAML")
        time.sleep(2)

        # STEP 4 — Cloud privilege escalation.
        print("[STEP 4] AWS: privilege escalation — attach AdministratorAccess...")
        _emit(aws_module.generate_log(config, scenario_event="ATTACH_ADMIN_POLICY", context=aws_ctx),
              aws_module, "ATTACH_ADMIN_POLICY")
        _emit_guardduty(all_modules, config, aws_ctx, "GD_ADMIN_PRIVESC")
        time.sleep(2)

        # STEP 5 — Cloud data exfiltration as the federated session.
        print("[STEP 5] AWS: bulk S3 read + exfil as the federated identity...")
        _emit(aws_module.generate_log(config, scenario_event="S3_READ_EXFIL_CHAIN", context=aws_ctx),
              aws_module, "S3_READ_EXFIL_CHAIN")
        _emit_guardduty(all_modules, config, aws_ctx, "GD_S3_EXFIL")

    except Exception as e:
        print(f"\nAn error occurred during scenario execution: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            flush_s3_batch()
        except Exception:
            pass

    print("\n--- Identity Attack → Cloud Scenario Complete ---")
    print(f"  Spine: Okta user '{victim_user}' → AWS SAML roleSessionName '{victim_user}'.")
    print(f"  Detects: Okta MFA bombing / Tor login (ThreatInsight), AWS admin-policy grant, S3 exfil.")
    print(f"  Cross-identity (Okta↔AWS) shares the username now; full merge lands with XSIAM identity unification.")


def get_scenarios():
    """Return the id→{name, func} map of all attack scenarios.

    Module-level so both the CLI menu (select_scenario_mode) and the Web-UI
    training engine (modules/training_engine.py) resolve scenarios by the same id.
    """
    # NOTE: Scenario "Compromised Account & Data Exfiltration via Google Drive" is disabled
    # until the Google Workspace module is restored. The function remains in the codebase.
    scenarios = {
        # ── High-value multi-module scenarios (no Infoblox required) ──────────
        "1": {
            "name": "AWS Pentest & Defense Evasion",
            "func": run_aws_pentest_scenario
        },
        "2": {
            "name": "Phishing Kill Chain (Email → Click → DNS → C2 → Credential Theft)",
            "func": run_phishing_kill_chain_scenario
        },
        "3": {
            "name": "Insider Threat / Cloud Data Exfiltration (with DNS correlation)",
            "func": run_insider_threat_scenario
        },
        "4": {
            "name": "GCP Cloud Pentest (Privilege Escalation + Defense Evasion + Data Staging)",
            "func": run_gcp_cloud_pentest_scenario
        },
        "5": {
            "name": "Web App Compromise → Server C2 (HTTPD + All Network Firewalls)",
            "func": run_web_app_compromise_scenario
        },
        "6": {
            "name": "VPN Compromise → Lateral Movement (ASA + All Firewalls + Okta)",
            "func": run_vpn_compromise_scenario
        },
        "7": {
            "name": "AiTM Session Hijack → Cloud Abuse (Proofpoint + Okta + AWS)",
            "func": run_aitm_session_hijack_scenario
        },
        "8": {
            "name": "Ransomware Precursor Kill Chain (Proofpoint + Okta + All Firewalls + AWS)",
            "func": run_ransomware_precursor_scenario
        },
        # ── Infoblox kill chains (require Infoblox NIOS module) ───────────────
        "9": {
            "name": "DNS C2 Kill Chain (Infoblox DHCP/DNS + All Network Firewalls) [requires Infoblox]",
            "func": run_dns_c2_killchain_scenario
        },
        "10": {
            "name": "Device Compromise — Full Lifecycle: DHCP → DNS → C2 → Threat Protect [requires Infoblox]",
            "func": run_device_compromise_scenario
        },
        # ── Infoblox standalone validation tests ──────────────────────────────
        "11": {
            "name": "Infoblox — C2 Beacon (DNS query to C2 domain → NXDOMAIN) [Infoblox standalone]",
            "func": lambda m, c: run_infoblox_single_threat("C2_BEACON", m, c)
        },
        "12": {
            "name": "Infoblox — DNS Tunneling (TXT exfil subdomain → SERVFAIL) [Infoblox standalone]",
            "func": lambda m, c: run_infoblox_single_threat("DNS_TUNNEL", m, c)
        },
        "13": {
            "name": "Infoblox — RPZ Block (named RPZ CEF NXDOMAIN/PASSTHRU event) [Infoblox standalone]",
            "func": lambda m, c: run_infoblox_single_threat("RPZ_BLOCK", m, c)
        },
        "14": {
            "name": "Infoblox — Threat Protect Block (BloxOne CEF DROP event) [Infoblox standalone]",
            "func": lambda m, c: run_infoblox_single_threat("THREAT_PROTECT", m, c)
        },
        "15": {
            "name": "Infoblox — NXDOMAIN Storm / DGA (20-50 query+NXDOMAIN pairs) [Infoblox standalone]",
            "func": lambda m, c: run_infoblox_single_threat("NXDOMAIN_STORM", m, c)
        },
        "16": {
            "name": "Infoblox — DNS Flood (20-50 rapid queries, same source IP) [Infoblox standalone]",
            "func": lambda m, c: run_infoblox_single_threat("DNS_FLOOD", m, c)
        },
        "17": {
            "name": "Infoblox — DHCP Starvation (20-50 DISCOVERs from spoofed MACs) [Infoblox standalone]",
            "func": lambda m, c: run_infoblox_single_threat("DHCP_STARVATION", m, c)
        },
        "18": {
            "name": "Domain Dominance (Phish → AD Recon → Kerberoast → DCSync → Lateral → Persistence)",
            "func": run_domain_dominance_scenario
        },
        "19": {
            "name": "Beaconing Implant (DNS C2 → DNS tunnel → web exfil → FW egress → service persistence) [host-keyed]",
            "func": run_beaconing_implant_scenario
        },
        "20": {
            "name": "Server Breach → Cloud Takeover (Apache exploit → reverse shell → DNS exfil → S3 exfil) [server-keyed]",
            "func": run_server_breach_cloud_scenario
        },
        "21": {
            "name": "Cloud Ransomware (brute force → admin → stop logging → exfil → S3 encrypt + ransom) [AWS-keyed]",
            "func": run_cloud_ransomware_scenario
        },
        "22": {
            "name": "Perimeter Intrusion (port scan → denied inbound → VPN brute force → web exploit) [attacker-IP-keyed]",
            "func": run_perimeter_intrusion_scenario
        },
        "23": {
            "name": "Identity Attack → Cloud (Okta MFA-fatigue + Tor login → AWS SAML federation → privesc → exfil) [identity-keyed]",
            "func": run_identity_attack_cloud_scenario
        },
        # ── XDR attack orchestration (real Atomic on a Cortex-agent box + aligned synthetic net) ──
        "24": {
            "name": "XDR Orchestration — FULL kill-chain: recon sweep → C2 (DNS/tunnel/web) → persistence x2 [purple-team, requires target box]",
            "func": _run_xdr_reference_story
        },
        "25": {
            "name": "XDR Orchestration — QUICK: recon + aligned C2 beacon (fast, small run) [purple-team, requires target box]",
            "func": _run_xdr_quick_story
        },
    }
    return scenarios


def _run_xdr_reference_story(all_modules, config):
    """Thin adapter so get_scenarios stays import-light: the xdr_orchestration
    package (and pywinrm) is imported only when this scenario is actually run."""
    from modules.xdr_orchestration import run_reference_story
    return run_reference_story(all_modules, config)


def _run_xdr_quick_story(all_modules, config):
    """QUICK XDR story — short, small-footprint purple-team run."""
    from modules.xdr_orchestration import run_quick_story
    return run_quick_story(all_modules, config)


def select_scenario_mode(all_modules, config):
    """Handles the attack scenario generation mode (CLI)."""
    scenarios = get_scenarios()

    print("\nSelect an Attack Scenario to run:")
    for key, value in scenarios.items():
        print(f"  {key:>2}. {value['name']}")

    choice = input(f"Enter choice (1-{len(scenarios)}): ")

    if choice in scenarios:
        try:
            scenarios[choice]["func"](all_modules, config)
        finally:
            # Flush the run's buffered AWS events as one batched CloudTrail object.
            flush_s3_batch()
    else:
        print("Invalid choice.")

def main():
    """Main function to start the simulator."""
    print("--- XSIAM Log Simulator ---")
    # --- Main Configuration Loading ---
    load_dotenv()
    CONFIG_FILE_PATH = 'config.json'
    config = {}
    try:
        with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as f:
            config_str = f.read()

        # Substitute PLACEHOLDER_* values from environment variables so that
        # setting GCP_PROJECT_ID / GCP_PROJECT_NUMBER / AWS_ACCOUNT_ID in .env
        # propagates into ALL config values (log content, resource names, ARNs),
        # not just the transport-layer lookups that already read os.getenv().
        _placeholders = {
            'PLACEHOLDER_GCP_PROJECT_ID':     os.getenv('GCP_PROJECT_ID', ''),
            'PLACEHOLDER_GCP_PROJECT_NUMBER': os.getenv('GCP_PROJECT_NUMBER', ''),
            'PLACEHOLDER_AWS_ACCOUNT_ID':     os.getenv('AWS_ACCOUNT_ID', ''),
        }
        for _placeholder, _value in _placeholders.items():
            if _value:
                config_str = config_str.replace(_placeholder, _value)
            else:
                print(f"--- WARNING: {_placeholder} not set in .env — "
                      f"config.json values using this placeholder will be literal. ---")

        config = json.loads(config_str)
        print(f"--- Diagnostic: Successfully loaded '{CONFIG_FILE_PATH}'. ---")
    except FileNotFoundError:
        print(f"FATAL ERROR: The configuration file '{CONFIG_FILE_PATH}' was not found.")
        exit()
    except json.JSONDecodeError as e:
        print(f"FATAL ERROR: Could not parse '{CONFIG_FILE_PATH}'. Please check for JSON syntax errors: {e}")
        exit()

    # --- Expand service_accounts template into flat application/database lists ---
    sa = config.get('service_accounts', {})
    if sa.pop('_expand', False):
        app_names = sa.pop('app_names', [])
        db_names  = sa.pop('db_names', [])
        # First 3 app services get PROD + DEV variants; the rest get a plain _SVC suffix
        sa['application'] = (
            [f"{n}_SVC_PROD" for n in app_names[:3]] +
            [f"{n}_SVC_DEV"  for n in app_names[:3]] +
            [f"{n}_SVC"      for n in app_names[3:]]
        )
        sa['database'] = [f"DB_{d}_SVC" for d in db_names]

    # --- Overwrite static Tor list with dynamic list if available ---
    live_tor_nodes = fetch_tor_exit_nodes()
    if live_tor_nodes:
        config['tor_exit_nodes'] = live_tor_nodes

    all_modules = load_modules()

    if not all_modules:
        print("\nNo modules found. Exiting.")
        return

    _start_dashboard()

    # --- Build session context: stable user→device→IP mapping for this run ---
    # Import here so the modules/ directory is already loaded
    try:
        from modules.session_utils import build_session_context
        session_context = build_session_context(config)
        user_count = len(session_context)
        active_device_count = sum(len(p['active_devices']) for p in session_context.values())
        print(f"\n--- Session Context Built: {user_count} users, {active_device_count} active devices for this run ---\n")
    except Exception as e:
        print(f"WARNING: Could not build session context: {e}. Modules will use fallback user selection.")
        session_context = {}

    while True:
        print("\nSelect Simulation Mode:")
        print("  1. Generate Independent Product Logs (Continuous background noise)")
        print("  2. Generate Correlated Attack Scenarios (Specific story-based events)")
        print("  3. Generate Specific Threat (Targeted — pick technology + threat type)")
        print("  q. Quit")

        mode = input("\nEnter mode (1, 2, 3, or q): ").strip().lower()

        if mode == 'q':
            print("Exiting.")
            break
        elif mode == '1':
            threat_level     = select_threat_level(config)
            selected_modules = select_product_log_mode(all_modules)
            if not selected_modules:
                continue
            print("\nExecution mode:")
            print("  1. Serial   (round-robin — one module at a time, current behaviour)")
            print("  2. Parallel (each module runs in its own thread simultaneously)")
            exec_choice = input("Enter execution mode (1 or 2): ").strip()
            parallel = (exec_choice == "2")
            run_sim(threat_level, selected_modules, config, session_context=session_context,
                    parallel=parallel)
        elif mode == '2':
            select_scenario_mode(all_modules, config)
        elif mode == '3':
            module, threat_name, repeat = select_specific_threat_mode(all_modules)
            if module and threat_name:
                run_specific_threat(module, threat_name, config, session_context, repeat)
        else:
            print("Invalid selection.")

def _kill_port(port):
    """Kill any process currently listening on *port* (Windows taskkill)."""
    import subprocess as _sp
    try:
        r = _sp.run(['netstat', '-ano'], capture_output=True, text=True, timeout=5)
        seen = set()
        for line in r.stdout.splitlines():
            if f':{port}' in line and 'LISTENING' in line:
                parts = line.split()
                try:
                    pid = int(parts[-1])
                except (ValueError, IndexError):
                    continue
                if pid > 4 and pid not in seen:
                    seen.add(pid)
                    _sp.run(['taskkill', '/F', '/PID', str(pid)],
                            capture_output=True, timeout=3)
                    print(f"[dashboard] Killed stale process PID {pid} on port {port}")
    except Exception:
        pass


_dashboard_proc = None


def _cleanup_dashboard():
    global _dashboard_proc
    if _dashboard_proc and _dashboard_proc.poll() is None:
        _dashboard_proc.terminate()
        try:
            _dashboard_proc.wait(timeout=3)
        except Exception:
            _dashboard_proc.kill()


def _start_dashboard():
    """Launch the Flask dashboard as a child subprocess.

    Kills any stale process already on the port, starts a fresh subprocess,
    and registers an atexit handler so it is always cleaned up on exit.
    """
    import subprocess, atexit
    global _dashboard_proc

    dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'dashboard', 'app.py')
    if not os.path.exists(dashboard_path):
        print("Dashboard not found — skipping.")
        return

    port = int(os.getenv("DASHBOARD_PORT", "5000"))
    project_root = os.path.dirname(os.path.abspath(__file__))

    # Kill any leftover process from a previous run before binding the port.
    _kill_port(port)
    time.sleep(0.5)

    try:
        proc = subprocess.Popen(
            [sys.executable, dashboard_path],
            cwd=project_root,
            env={**os.environ, 'LOGSIM_PARENT_PID': str(os.getpid())},
        )
        _dashboard_proc = proc
        atexit.register(_cleanup_dashboard)

        time.sleep(2)  # Give Flask time to bind
        if proc.poll() is None:
            print(f"--- Dashboard started -> http://localhost:{port} ---\n")
        else:
            print(f"WARNING: Dashboard process exited early (code {proc.returncode})")
    except Exception as e:
        print(f"WARNING: Could not start dashboard: {e}")


if __name__ == "__main__":
    main()

