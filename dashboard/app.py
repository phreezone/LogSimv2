"""
LogSim Dashboard — Flask application for controlling and monitoring log generation modules.

Run from the project root:
    python dashboard/app.py

Or with Flask CLI:
    flask --app dashboard/app.py run --host 0.0.0.0 --port 5000
"""

import sys
import os
import threading
import queue as _queue
import time
import json
import copy
import ctypes
import uuid as _uuid
from collections import deque

# ── Path setup — must run from project root ──────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── Parent-process watchdog ───────────────────────────────────────────────────
# When log_simulator.py dies (normally, force-killed, or via IDE stop), this
# watchdog detects the gone parent and shuts Flask down within ~5 seconds.

def _parent_alive(pid: int) -> bool:
    """Return True if the process with *pid* is still running (Windows)."""
    try:
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        kernel32.CloseHandle(handle)
        return exit_code.value == STILL_ACTIVE
    except Exception:
        return False


def _start_watchdog():
    parent_pid = int(os.environ.get('LOGSIM_PARENT_PID', '0'))
    if not parent_pid:
        return  # Running standalone — no watchdog needed

    def _watch():
        while True:
            time.sleep(5)
            if not _parent_alive(parent_pid):
                print("[dashboard] Parent process gone — shutting down.", flush=True)
                os._exit(0)

    t = threading.Thread(target=_watch, daemon=True, name="dashboard-watchdog")
    t.start()


_start_watchdog()
os.chdir(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, render_template, request, make_response
import importlib

# ── Simulator helpers — imported lazily inside worker to avoid circular import
# when this file is exec'd from within a running log_simulator.py process.
def _get_process_and_send():
    from log_simulator import process_and_send
    return process_and_send

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.jinja_env.auto_reload = True          # always read template from disk
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ── Load config ───────────────────────────────────────────────────────────────
_CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.json")
with open(_CONFIG_PATH) as _f:
    _config_str = _f.read()

# Apply the same placeholder substitution as log_simulator.py so that
# GCP_PROJECT_ID / GCP_PROJECT_NUMBER / AWS_ACCOUNT_ID from .env propagate
# into all config values (resource paths, SA emails, bucket names, etc.)
_placeholders = {
    'PLACEHOLDER_GCP_PROJECT_ID':     os.getenv('GCP_PROJECT_ID', ''),
    'PLACEHOLDER_GCP_PROJECT_NUMBER': os.getenv('GCP_PROJECT_NUMBER', ''),
    'PLACEHOLDER_AWS_ACCOUNT_ID':     os.getenv('AWS_ACCOUNT_ID', ''),
}
for _ph, _val in _placeholders.items():
    if _val:
        _config_str = _config_str.replace(_ph, _val)
CONFIG = json.loads(_config_str)

# ── Live Tor exit node fetch ──────────────────────────────────────────────────
# Overwrites the static fallback list in config.json so that all Tor-themed
# threat generators (AWS BEDROCK_TOR_USAGE, GCP TOR_API_ACCESS, VERTEX_TOR_PREDICT,
# and any other module that reads config['tor_exit_nodes']) use IPs that are
# confirmed to be on the live Tor exit node list at startup time.
def _fetch_tor_exit_nodes() -> list[dict]:
    """Fetch the current Tor exit node list from the Tor Project bulk-exit URL.
    Returns a list of {ip, country} dicts on success, or empty list on failure."""
    _TOR_BULK_URL = "https://check.torproject.org/torbulkexitlist"
    try:
        import urllib.request
        with urllib.request.urlopen(_TOR_BULK_URL, timeout=10) as resp:
            ips = resp.read().decode("utf-8").strip().splitlines()
        nodes = [{"ip": ip.strip(), "country": "Unknown"} for ip in ips if ip.strip()]
        print(f"[dashboard] Fetched {len(nodes)} live Tor exit nodes from torproject.org")
        return nodes
    except Exception as exc:
        print(f"[dashboard] WARNING: Could not fetch live Tor exit nodes ({exc}). "
              "Using static fallback list from config.json.")
        return []

_live_tor = _fetch_tor_exit_nodes()
if _live_tor:
    CONFIG["tor_exit_nodes"] = _live_tor

THREAT_LEVELS = list(CONFIG.get("threat_generation_levels", {
    "Benign Traffic Only": 86400,
    "Realistic": 7200,
    "Elevated": 3600,
    "High": 1800,
    "Extreme": 600,
    "Insane": 0,
}).keys())


# ── Load simulator modules ────────────────────────────────────────────────────
def _load_modules():
    modules = {}
    module_dir = os.path.join(PROJECT_ROOT, "modules")
    for filename in sorted(os.listdir(module_dir)):
        if not filename.endswith(".py") or filename.startswith("__"):
            continue
        module_name = filename[:-3]
        full_name = f"modules.{module_name}"
        try:
            if full_name in sys.modules:
                mod = importlib.reload(sys.modules[full_name])
            else:
                mod = importlib.import_module(full_name)
            if not hasattr(mod, "NAME"):
                continue
            modules[mod.NAME] = mod
        except Exception as e:
            print(f"[dashboard] Could not load module {module_name}: {e}")
    return modules

MODULES = _load_modules()

# ── Build session context (stable user→IP map, same as parallel mode) ────────
try:
    from modules.session_utils import build_session_context as _build_session_context
    from modules.session_utils import get_users_by_department as _get_users_by_department
    SESSION_CONTEXT = _build_session_context(CONFIG)
except Exception as _e:
    print(f"[dashboard] Could not build session context: {_e}")
    SESSION_CONTEXT = {}


# ── Session timer ─────────────────────────────────────────────────────────────
_session_start: float | None = None

# ── Scheduler ─────────────────────────────────────────────────────────────────
_schedule: list = []          # list of job dicts
_schedule_lock = threading.Lock()


# ── Per-module state ──────────────────────────────────────────────────────────
class ModuleState:
    """Holds runtime state and metrics for a single log-generation module."""

    def __init__(self, module):
        self.module = module
        self.name = module.NAME
        self.description = getattr(module, "DESCRIPTION", "")

        # Control
        self.status = "stopped"       # stopped | running | error
        self.error_msg = ""
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Config
        self.threat_level = "Realistic"
        self.event_interval: float = CONFIG.get("base_event_interval_seconds", 1.0)

        # Metrics
        self.total_logs = 0
        self.total_threats = 0
        self.last_threat: str = ""
        self._timestamps: deque = deque(maxlen=600)        # all events
        self._benign_timestamps: deque = deque(maxlen=600) # non-threat events
        self._threat_timestamps: deque = deque(maxlen=600) # threat events
        self._threat_event_details: deque = deque(maxlen=600)  # (timestamp, event_name) pairs
        self._threat_counts: dict = {}                         # {event_name: int} this session

        # Build threat name set for classification
        self.threat_names: set = set()
        fn = getattr(module, "get_threat_names", None)
        if callable(fn):
            try:
                self.threat_names = set(fn())  # type: ignore[arg-type]
            except Exception:
                pass

    # ── Metric helpers ────────────────────────────────────────────────────────

    def record_log(self, event_name: str | None, log_count: int = 1):
        """Record one event. log_count is the number of individual log lines in
        the burst (e.g. 30 for a port-scan).  Threat counter increments by 1
        regardless of burst size — a brute-force is one event, not 30."""
        now = time.time()
        with self._lock:
            self.total_logs += log_count
            self._timestamps.append(now)          # one per event, not per log line
            if event_name and event_name in self.threat_names:
                self.total_threats += 1           # one threat per event, not per log line
                self._threat_timestamps.append(now)
                self._threat_event_details.append((now, event_name))
                self.last_threat = event_name
                self._threat_counts[event_name] = self._threat_counts.get(event_name, 0) + 1
            else:
                self._benign_timestamps.append(now)  # one per event, not per log line

    def get_rate(self, window: int = 10) -> float:
        cutoff = time.time() - window
        with self._lock:
            recent = sum(1 for t in self._timestamps if t > cutoff)
        return round(recent / window, 2)

    def reset_metrics(self):
        with self._lock:
            self.total_logs = 0
            self.total_threats = 0
            self.last_threat = ""
            self._timestamps.clear()
            self._benign_timestamps.clear()
            self._threat_timestamps.clear()
            self._threat_event_details.clear()
            self._threat_counts.clear()

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "error": self.error_msg,
            "threat_level": self.threat_level,
            "total_logs": self.total_logs,
            "total_threats": self.total_threats,
            "rate_per_sec": self.get_rate(),
            "last_threat": self.last_threat,
            "event_interval": self.event_interval,
            "threat_breakdown": dict(self._threat_counts),
        }


# Instantiate states for every loaded module
MODULE_STATES: dict[str, ModuleState] = {
    name: ModuleState(mod) for name, mod in MODULES.items()
}


# ── Bad User mode ─────────────────────────────────────────────────────────────
# Independent worker threads that focus ALL log generation on a single selected
# user, causing them to accumulate risk score in XSIAM UEBA.  Normal module
# workers keep running to provide baseline traffic from other users.

_baduser_lock = threading.Lock()
_baduser_state = {
    "active": False,
    "username": None,
    "display_name": None,
    "department": None,
    "started_at": None,
    "duration_seconds": 0,
    "threat_level": "Extreme",
    "event_interval": 0.5,
    "stop_event": threading.Event(),
    "threads": [],
    "metrics": {},       # {module_name: {"logs": int, "threats": int}}
    "selected_modules": [],  # module names chosen by user (empty = all)
}


def _build_baduser_context(username):
    """Deep-copy a single user's profile into a new session_context dict.

    Since every module (except AWS) calls get_random_user(session_context) and
    there's only one user in the dict, all events will attribute to that user.
    """
    if username not in SESSION_CONTEXT:
        return None
    return {"session_context": {username: copy.deepcopy(SESSION_CONTEXT[username])}}


def _build_baduser_aws_config(username, config):
    """Return a config with aws_config.users_and_roles filtered to the target user's IAM identity.

    Returns None if the user has no aws_iam_user mapping (skip AWS in that case).
    """
    profile = SESSION_CONTEXT.get(username, {})
    iam_name = profile.get('aws_iam_user')
    if not iam_name:
        return None
    cfg = copy.deepcopy(config)
    aws_conf = cfg.get('aws_config', {})
    pool = aws_conf.get('users_and_roles', [])
    # Keep only entries matching the user's IAM identity
    filtered = [u for u in pool if u.get('name') == iam_name]
    if not filtered:
        # Create an IAMUser entry for the target
        filtered = [{"type": "IAMUser", "name": iam_name, "arn_suffix": f"user/{iam_name}"}]
    aws_conf['users_and_roles'] = filtered
    cfg['aws_config'] = aws_conf
    return cfg


def _baduser_worker(module, config, context, stop_event, metrics_key,
                    threat_level, event_interval_func):
    """Worker loop for a single module in bad-user mode.

    Same pattern as _module_worker() but uses a filtered single-user context
    and records metrics into the bad-user state instead of MODULE_STATES.
    """
    _ensure_send_workers()

    while not stop_event.is_set():
        current_level = threat_level
        benign_only = (current_level == "Benign Traffic Only")
        cycle_start = time.time()
        try:
            result = module.generate_log(
                config=config,
                threat_level=current_level,
                benign_only=benign_only,
                context=context,
            )
            if result is not None:
                if isinstance(result, tuple) and len(result) == 2:
                    log_content, event_name = result
                else:
                    log_content, event_name = result, None

                logs = log_content if isinstance(log_content, list) else [log_content]
                valid = [m for m in logs if m]

                if valid:
                    # Record metrics immediately, send async
                    with _baduser_lock:
                        m = _baduser_state["metrics"].get(metrics_key, {"logs": 0, "threats": 0})
                        m["logs"] += len(valid)
                        # Check if this was a threat event
                        state = MODULE_STATES.get(module.NAME)
                        if state and event_name and event_name in state.threat_names:
                            m["threats"] += 1
                        _baduser_state["metrics"][metrics_key] = m
                    for msg in valid:
                        try:
                            _SEND_QUEUE.put_nowait((msg, module, config, event_name))
                        except _queue.Full:
                            pass

        except Exception as exc:
            print(f"[bad-user][{module.NAME}] worker error: {exc}")
            stop_event.wait(timeout=5)
            continue

        elapsed = time.time() - cycle_start
        remaining = max(0.0, event_interval_func() - elapsed)
        stop_event.wait(timeout=remaining)


def _baduser_watchdog(duration_seconds, stop_event):
    """Auto-stop bad-user mode after the configured duration."""
    elapsed = 0
    while elapsed < duration_seconds and not stop_event.is_set():
        stop_event.wait(timeout=1)
        elapsed += 1
    if not stop_event.is_set():
        print("[bad-user] Duration expired — stopping.")
        _stop_baduser()


def _start_baduser(username, duration_minutes, threat_level, event_interval,
                   selected_modules=None):
    """Spin up bad-user worker threads for selected (or all) modules."""
    with _baduser_lock:
        if _baduser_state["active"]:
            return False, "Bad user mode is already active"

    context = _build_baduser_context(username)
    if context is None:
        return False, f"User '{username}' not found in session context"

    profile = SESSION_CONTEXT[username]
    duration_seconds = int(duration_minutes * 60)
    stop_event = threading.Event()

    with _baduser_lock:
        _baduser_state["active"] = True
        _baduser_state["username"] = username
        _baduser_state["display_name"] = profile.get("display_name", username)
        _baduser_state["department"] = profile.get("department", "Unknown")
        _baduser_state["started_at"] = time.time()
        _baduser_state["duration_seconds"] = duration_seconds
        _baduser_state["threat_level"] = threat_level
        _baduser_state["event_interval"] = event_interval
        _baduser_state["stop_event"] = stop_event
        _baduser_state["threads"] = []
        _baduser_state["metrics"] = {}
        _baduser_state["selected_modules"] = selected_modules or []

    # Closure so workers always read current interval
    def _get_interval():
        with _baduser_lock:
            return _baduser_state["event_interval"]

    base_config = copy.deepcopy(CONFIG)

    _sel = set(selected_modules) if selected_modules else None
    for name, mod in MODULES.items():
        if _sel and name not in _sel:
            continue
        # AWS special handling — skip if no IAM mapping
        if name == "aws":
            aws_cfg = _build_baduser_aws_config(username, base_config)
            if aws_cfg is None:
                print(f"[bad-user] Skipping {name} — no aws_iam_user mapping for {username}")
                continue
            worker_config = aws_cfg
            worker_context = context  # AWS ignores session_context but we pass it anyway
        else:
            worker_config = copy.deepcopy(base_config)
            worker_context = context

        with _baduser_lock:
            _baduser_state["metrics"][name] = {"logs": 0, "threats": 0}

        t = threading.Thread(
            target=_baduser_worker,
            args=(mod, worker_config, worker_context, stop_event, name,
                  threat_level, _get_interval),
            daemon=True,
            name=f"baduser-{name}",
        )
        with _baduser_lock:
            _baduser_state["threads"].append(t)
        t.start()

    # Watchdog thread for auto-stop
    wd = threading.Thread(
        target=_baduser_watchdog,
        args=(duration_seconds, stop_event),
        daemon=True,
        name="baduser-watchdog",
    )
    with _baduser_lock:
        _baduser_state["threads"].append(wd)
    wd.start()

    n_threads = len(_baduser_state["threads"]) - 1  # exclude watchdog
    print(f"[bad-user] Started — {username} ({profile.get('display_name')}) | "
          f"{n_threads} modules | {duration_minutes}min | {threat_level} | "
          f"{1/event_interval:.1f}/sec")
    return True, None


def _stop_baduser():
    """Stop all bad-user worker threads."""
    with _baduser_lock:
        if not _baduser_state["active"]:
            return
        _baduser_state["stop_event"].set()
        threads = list(_baduser_state["threads"])

    for t in threads:
        t.join(timeout=5)

    with _baduser_lock:
        _baduser_state["active"] = False
        _baduser_state["threads"] = []
    print("[bad-user] Stopped.")


# ── Async send queue — decouples metrics from network I/O ─────────────────────
# Modules that produce large batches (e.g. Windows Events parallel mode draining
# 50 events at once) would block the worker loop for 10–30s if each message is
# sent synchronously via HTTP.  The send queue lets the worker record metrics
# instantly while a pool of sender threads handles the slow network I/O.

_SEND_QUEUE: _queue.Queue = _queue.Queue(maxsize=5000)
_SEND_WORKERS_STARTED = False
_SEND_WORKERS_LOCK = threading.Lock()


def _send_worker():
    """Background thread that pulls (msg, module, config, event_name) from the
    send queue and forwards via process_and_send."""
    process_and_send = _get_process_and_send()
    while True:
        try:
            msg, module, config, event_name = _SEND_QUEUE.get()
            try:
                process_and_send(msg, module, config, event_name)
            except Exception:
                pass
        except Exception:
            pass


def _ensure_send_workers(count=3):
    """Start sender pool once (idempotent)."""
    global _SEND_WORKERS_STARTED
    with _SEND_WORKERS_LOCK:
        if _SEND_WORKERS_STARTED:
            return
        _SEND_WORKERS_STARTED = True
    for i in range(count):
        t = threading.Thread(target=_send_worker, daemon=True, name=f"send-worker-{i}")
        t.start()


# ── Module worker thread ──────────────────────────────────────────────────────

def _module_worker(state: ModuleState, config: dict):
    """
    Runs continuously, calling module.generate_log() and forwarding results
    to the appropriate transport via process_and_send().  Stopped by setting
    state._stop_event.

    Both state.threat_level and state.event_interval are read each iteration
    so that live updates via PATCH /threat_level or PATCH /interval take effect
    without needing a stop/restart.
    """
    context: dict = {"session_context": SESSION_CONTEXT}
    _ensure_send_workers()

    # Every module initialises last_threat_event_time = 0 at import, which
    # makes the very first generate_log call always fire a threat (since
    # time.time() - 0 >> any interval).  Reset it to now so the module waits
    # the correct interval before the first threat, matching the selected level.
    if hasattr(state.module, "last_threat_event_time"):
        state.module.last_threat_event_time = time.time()

    while not state._stop_event.is_set():
        # Read both live values each iteration so PATCH updates apply immediately.
        current_level = state.threat_level
        benign_only   = (current_level == "Benign Traffic Only")
        cycle_start   = time.time()
        try:
            result = state.module.generate_log(
                config=config,
                threat_level=current_level,
                benign_only=benign_only,
                context=context,
            )
            if result is not None:
                if isinstance(result, tuple) and len(result) == 2:
                    log_content, event_name = result
                else:
                    log_content, event_name = result, None

                logs = log_content if isinstance(log_content, list) else [log_content]
                valid = [m for m in logs if m]
                # Record metrics immediately — sending happens async via send queue.
                if valid:
                    state.record_log(event_name, log_count=len(valid))
                    for msg in valid:
                        try:
                            _SEND_QUEUE.put_nowait((msg, state.module, config, event_name))
                        except _queue.Full:
                            pass  # drop if send queue is backed up

        except Exception as exc:
            state.status = "error"
            state.error_msg = str(exc)
            print(f"[{state.name}] worker error: {exc}")
            # Brief pause before retry
            state._stop_event.wait(timeout=5)
            if not state._stop_event.is_set():
                state.status = "running"
                state.error_msg = ""
            continue

        # Wait only the remaining portion of the interval so that generate_log +
        # process_and_send time (e.g. S3 upload latency for AWS) doesn't inflate
        # the effective cycle time beyond event_interval.
        elapsed = time.time() - cycle_start
        remaining = max(0.0, state.event_interval - elapsed)
        state._stop_event.wait(timeout=remaining)

    state.status = "stopped"


# ── REST API ──────────────────────────────────────────────────────────────────

# ── Module start/stop helpers (shared by API endpoints and scheduler) ─────────

def _start_module_state(state: ModuleState, threat_level: str,
                        event_interval: float | None = None) -> None:
    """Start *state* if not already running. Caller holds no locks."""
    global _session_start
    if state.status == "running":
        return
    if threat_level in THREAT_LEVELS:
        state.threat_level = threat_level
    if event_interval is not None and event_interval >= 0.01:
        state.event_interval = event_interval
    state._stop_event.clear()
    state.error_msg = ""
    if _session_start is None:
        _session_start = time.time()
    t = threading.Thread(
        target=_module_worker,
        args=(state, copy.deepcopy(CONFIG)),
        daemon=True,
        name=f"logsim-{state.name}",
    )
    state._thread = t
    state.status = "running"
    t.start()


def _stop_module_state(state: ModuleState) -> None:
    """Stop *state* and wait up to 5 s for the worker to exit."""
    state._stop_event.set()
    if state._thread and state._thread.is_alive():
        state._thread.join(timeout=5)
    state.status = "stopped"


@app.get("/api/modules")
def api_get_modules():
    return jsonify([s.to_dict() for s in MODULE_STATES.values()])


@app.get("/api/threat_levels")
def api_threat_levels():
    return jsonify(THREAT_LEVELS)


@app.post("/api/modules/<name>/start")
def api_start_module(name: str):
    state = MODULE_STATES.get(name)
    if not state:
        return jsonify({"error": f"Module '{name}' not found"}), 404
    if state.status == "running":
        return jsonify({"error": "Module is already running"}), 409
    body = request.get_json(silent=True) or {}
    level = body.get("threat_level", state.threat_level)
    if level not in THREAT_LEVELS:
        return jsonify({"error": f"Unknown threat level '{level}'"}), 400
    raw_iv = body.get("event_interval")
    iv = None
    if raw_iv is not None:
        try:
            iv = float(raw_iv)
        except (ValueError, TypeError):
            iv = None
    _start_module_state(state, level, iv)
    return jsonify(state.to_dict())


@app.post("/api/modules/<name>/stop")
def api_stop_module(name: str):
    state = MODULE_STATES.get(name)
    if not state:
        return jsonify({"error": f"Module '{name}' not found"}), 404
    _stop_module_state(state)
    return jsonify(state.to_dict())


@app.post("/api/modules/start_all")
def api_start_all():
    body = request.get_json(silent=True) or {}
    level = body.get("threat_level", "Realistic")
    raw_iv = body.get("event_interval")
    iv = None
    if raw_iv is not None:
        try:
            iv = float(raw_iv)
        except (ValueError, TypeError):
            iv = None
    for state in MODULE_STATES.values():
        _start_module_state(state, level, iv)
    return jsonify([s.to_dict() for s in MODULE_STATES.values()])


@app.post("/api/modules/stop_all")
def api_stop_all():
    for state in MODULE_STATES.values():
        _stop_module_state(state)
    return jsonify([s.to_dict() for s in MODULE_STATES.values()])


@app.post("/api/modules/<name>/reset")
def api_reset_metrics(name: str):
    state = MODULE_STATES.get(name)
    if not state:
        return jsonify({"error": f"Module '{name}' not found"}), 404
    state.reset_metrics()
    return jsonify(state.to_dict())


@app.post("/api/reset_all")
def api_reset_all():
    global _session_start
    _session_start = None
    for state in MODULE_STATES.values():
        state.reset_metrics()
    return jsonify([s.to_dict() for s in MODULE_STATES.values()])


@app.route("/api/modules/<name>/interval", methods=["PATCH"])
def api_set_interval(name: str):
    state = MODULE_STATES.get(name)
    if not state:
        return jsonify({"error": f"Module '{name}' not found"}), 404
    body = request.get_json(silent=True) or {}
    try:
        iv = float(body.get("event_interval", 0))
        if iv < 0.01:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "event_interval must be a number >= 0.01"}), 400
    state.event_interval = iv
    return jsonify(state.to_dict())


@app.route("/api/modules/<name>/threat_level", methods=["PATCH"])
def api_set_threat_level(name: str):
    """Update the threat level on a running or stopped module.
    Takes effect on the next generate_log iteration — no restart needed."""
    state = MODULE_STATES.get(name)
    if not state:
        return jsonify({"error": f"Module '{name}' not found"}), 404
    body = request.get_json(silent=True) or {}
    level = body.get("threat_level")
    if not level or level not in THREAT_LEVELS:
        return jsonify({"error": f"Unknown threat level '{level}'. Valid: {THREAT_LEVELS}"}), 400
    # Reset last_threat_event_time when switching to a timed level so the module
    # doesn't immediately fire a threat because the old timer had expired.
    if level not in ("Insane", "Benign Traffic Only"):
        if hasattr(state.module, "last_threat_event_time"):
            state.module.last_threat_event_time = time.time()
    state.threat_level = level
    return jsonify(state.to_dict())


@app.get("/api/modules/<name>/threats")
def api_get_threats(name: str):
    state = MODULE_STATES.get(name)
    if not state:
        return jsonify({"error": f"Module '{name}' not found"}), 404
    fn = getattr(state.module, "get_threat_names", None)
    threats = sorted(fn()) if callable(fn) else []  # type: ignore[arg-type]
    return jsonify({"module": name, "threats": threats})


@app.post("/api/modules/<name>/fire")
def api_fire_threat(name: str):
    state = MODULE_STATES.get(name)
    if not state:
        return jsonify({"error": f"Module '{name}' not found"}), 404
    body = request.get_json(silent=True) or {}
    event_name = body.get("event")
    if not event_name:
        return jsonify({"error": "event name required"}), 400
    process_and_send = _get_process_and_send()
    cfg = copy.deepcopy(CONFIG)
    context = {"session_context": SESSION_CONTEXT}
    try:
        result = state.module.generate_log(
            config=cfg,
            threat_level="Insane",
            benign_only=False,
            context=context,
            scenario_event=event_name,
        )
        if result is None:
            return jsonify({"fired": False, "reason": "generate_log returned None"}), 200
        log_content, ret_name = result if (isinstance(result, tuple) and len(result) == 2) else (result, event_name)
        logs = log_content if isinstance(log_content, list) else [log_content]
        valid = [m for m in logs if m]
        for msg in valid:
            process_and_send(msg, state.module, cfg, ret_name or event_name)
        if valid:
            state.record_log(ret_name or event_name, log_count=len(valid))
        return jsonify({"fired": True, "event": event_name, "log_count": len(valid)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Multi-module scenarios (imported lazily from log_simulator) ───────────────
_SCENARIOS = None

def _get_scenarios():
    global _SCENARIOS
    if _SCENARIOS is not None:
        return _SCENARIOS
    try:
        from log_simulator import (
            run_aws_pentest_scenario,
            run_phishing_kill_chain_scenario,
            run_insider_threat_scenario,
            run_gcp_cloud_pentest_scenario,
            run_web_app_compromise_scenario,
            run_vpn_compromise_scenario,
            run_aitm_session_hijack_scenario,
            run_ransomware_precursor_scenario,
            run_dns_c2_killchain_scenario,
            run_device_compromise_scenario,
            run_infoblox_single_threat,
        )
        _SCENARIOS = [
            {"id": "1",  "name": "AWS Pentest & Defense Evasion",                          "func": run_aws_pentest_scenario},
            {"id": "2",  "name": "Phishing Kill Chain (Email → DNS → C2 → Credential Theft)", "func": run_phishing_kill_chain_scenario},
            {"id": "3",  "name": "Insider Threat / Cloud Data Exfiltration",               "func": run_insider_threat_scenario},
            {"id": "4",  "name": "GCP Cloud Pentest (Privilege Escalation + Defense Evasion)", "func": run_gcp_cloud_pentest_scenario},
            {"id": "5",  "name": "Web App Compromise → Server C2",                         "func": run_web_app_compromise_scenario},
            {"id": "6",  "name": "VPN Compromise → Lateral Movement",                      "func": run_vpn_compromise_scenario},
            {"id": "7",  "name": "AiTM Session Hijack → Cloud Abuse",                      "func": run_aitm_session_hijack_scenario},
            {"id": "8",  "name": "Ransomware Precursor Kill Chain",                         "func": run_ransomware_precursor_scenario},
            {"id": "9",  "name": "DNS C2 Kill Chain [requires Infoblox]",                  "func": run_dns_c2_killchain_scenario},
            {"id": "10", "name": "Device Compromise Full Lifecycle [requires Infoblox]",   "func": run_device_compromise_scenario},
            {"id": "11", "name": "Infoblox — C2 Beacon",                                   "func": lambda m, c: run_infoblox_single_threat("C2_BEACON", m, c)},
            {"id": "12", "name": "Infoblox — DNS Tunneling",                               "func": lambda m, c: run_infoblox_single_threat("DNS_TUNNEL", m, c)},
            {"id": "13", "name": "Infoblox — RPZ Block",                                   "func": lambda m, c: run_infoblox_single_threat("RPZ_BLOCK", m, c)},
            {"id": "14", "name": "Infoblox — Threat Protect Block",                        "func": lambda m, c: run_infoblox_single_threat("THREAT_PROTECT", m, c)},
            {"id": "15", "name": "Infoblox — NXDOMAIN Storm",                              "func": lambda m, c: run_infoblox_single_threat("NXDOMAIN_STORM", m, c)},
            {"id": "16", "name": "Infoblox — DNS Flood",                                   "func": lambda m, c: run_infoblox_single_threat("DNS_FLOOD", m, c)},
            {"id": "17", "name": "Infoblox — DHCP Starvation",                             "func": lambda m, c: run_infoblox_single_threat("DHCP_STARVATION", m, c)},
        ]
    except Exception as e:
        print(f"[dashboard] Could not load scenarios from log_simulator: {e}")
        _SCENARIOS = []
    return _SCENARIOS


@app.get("/api/scenarios")
def api_get_scenarios():
    scenarios = _get_scenarios()
    return jsonify([{"id": s["id"], "name": s["name"]} for s in scenarios])


@app.post("/api/scenarios/<scenario_id>/run")
def api_run_scenario(scenario_id: str):
    scenarios = _get_scenarios()
    s = next((x for x in scenarios if x["id"] == scenario_id), None)
    if not s:
        return jsonify({"error": f"Scenario '{scenario_id}' not found"}), 404
    cfg = copy.deepcopy(CONFIG)
    modules = {name: state.module for name, state in MODULE_STATES.items()}
    t = threading.Thread(
        target=s["func"], args=(modules, cfg), daemon=True,
        name=f"scenario-{scenario_id}-{int(time.time())}",
    )
    t.start()
    return jsonify({"started": True, "scenario": s["name"]})


# ── Scheduler ─────────────────────────────────────────────────────────────────

def _execute_job(job: dict) -> None:
    with _schedule_lock:
        job["status"] = "running"
    try:
        t   = job["type"]
        p   = job["params"]
        if t == "module_start":
            state = MODULE_STATES.get(p["name"])
            if state:
                _start_module_state(state, p.get("threat_level", state.threat_level),
                                    p.get("event_interval"))
        elif t == "module_stop":
            state = MODULE_STATES.get(p["name"])
            if state:
                _stop_module_state(state)
        elif t == "global_start":
            for state in MODULE_STATES.values():
                _start_module_state(state, p.get("threat_level", "Realistic"),
                                    p.get("event_interval"))
        elif t == "global_stop":
            for state in MODULE_STATES.values():
                _stop_module_state(state)
        elif t == "scenario":
            scenarios = _get_scenarios()
            s = next((x for x in scenarios if x["id"] == p["scenario_id"]), None)
            if s:
                cfg = copy.deepcopy(CONFIG)
                mods = {n: st.module for n, st in MODULE_STATES.items()}
                threading.Thread(target=s["func"], args=(mods, cfg), daemon=True).start()
        elif t == "rate_change":
            targets = ([MODULE_STATES[p["name"]]] if p.get("name") and p["name"] in MODULE_STATES
                       else list(MODULE_STATES.values()))
            for state in targets:
                try:
                    state.event_interval = float(p["event_interval"])
                except (KeyError, TypeError, ValueError):
                    pass
        with _schedule_lock:
            job["status"] = "done"
            job["result"] = "executed"
    except Exception as exc:
        with _schedule_lock:
            job["status"] = "error"
            job["result"] = str(exc)


def _scheduler_tick() -> None:
    while True:
        time.sleep(1)
        now = time.time()
        with _schedule_lock:
            due = [j for j in _schedule if j["status"] == "pending" and j["run_at"] <= now]
        for job in due:
            _execute_job(job)
        # Trim completed jobs: keep only last 20 finished ones
        with _schedule_lock:
            done = [j for j in _schedule if j["status"] in ("done", "error")]
            pending = [j for j in _schedule if j["status"] in ("pending", "running")]
            _schedule[:] = pending + done[-20:]


threading.Thread(target=_scheduler_tick, daemon=True, name="scheduler").start()


@app.get("/api/schedule")
def api_schedule_list():
    with _schedule_lock:
        jobs = list(_schedule)
    return jsonify(jobs)


@app.post("/api/schedule")
def api_schedule_add():
    body = request.get_json(silent=True) or {}
    job_type = body.get("type", "")
    valid_types = {"module_start", "module_stop", "global_start", "global_stop",
                   "scenario", "rate_change"}
    if job_type not in valid_types:
        return jsonify({"error": f"Unknown job type '{job_type}'"}), 400

    # Resolve run_at
    if "run_at" in body:
        try:
            run_at = float(body["run_at"])
        except (ValueError, TypeError):
            return jsonify({"error": "run_at must be a unix timestamp float"}), 400
    elif "delay_seconds" in body:
        try:
            run_at = time.time() + float(body["delay_seconds"])
        except (ValueError, TypeError):
            return jsonify({"error": "delay_seconds must be numeric"}), 400
    else:
        return jsonify({"error": "provide run_at (epoch) or delay_seconds"}), 400

    job = {
        "id":     str(_uuid.uuid4()),
        "label":  body.get("label", job_type),
        "type":   job_type,
        "params": body.get("params", {}),
        "run_at": run_at,
        "status": "pending",
        "result": "",
    }
    with _schedule_lock:
        _schedule.append(job)
    return jsonify(job), 201


@app.delete("/api/schedule/<job_id>")
def api_schedule_cancel(job_id: str):
    with _schedule_lock:
        job = next((j for j in _schedule if j["id"] == job_id), None)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        if job["status"] != "pending":
            return jsonify({"error": f"Cannot cancel job with status '{job['status']}'"}), 409
        _schedule.remove(job)
    return jsonify({"cancelled": job_id})


@app.delete("/api/schedule")
def api_schedule_clear():
    with _schedule_lock:
        before = len(_schedule)
        _schedule[:] = [j for j in _schedule if j["status"] != "pending"]
        removed = before - len(_schedule)
    return jsonify({"cleared": removed})


# ── Health / preflight checks ─────────────────────────────────────────────────
_SKIP_COLLECTORS = {
    "google_login_collector", "google_drive_collector", "google_admin_collector",
    "google_user_accounts_collector", "google_token_collector",
}

# Health cache — populated by background monitor thread every 60 s
_health_cache: dict = {}
_health_ts: float = 0.0
_health_prev: dict = {}   # {f"{group}|{check}": status} from last run
_health_alerts: list = []
_health_lock = threading.Lock()


def _run_health_checks() -> dict:
    """Execute all health checks and return the result dict (no Flask response)."""
    import socket as _socket
    import requests as _requests

    results = []

    # ── 1. .env variable presence ─────────────────────────────────────────────
    ENV_VARS = {
        "SYSLOG_HOST":            "Syslog",
        "AWS_ACCESS_KEY_ID":      "AWS",
        "AWS_SECRET_ACCESS_KEY":  "AWS",
        "s3_bucket_name":         "AWS",
        "aws_account_id":         "AWS",
        "aws_region":             "AWS",
        "GCP_PROJECT_ID":         "GCP",
        "GCP_PUBSUB_TOPIC":       "GCP",
        "WEC_BROKER_URL":         "WEC",
        "WEC_PFX_PATH":           "WEC",
        "WEC_PFX_PASSWORD":       "WEC",
    }
    for var, group in ENV_VARS.items():
        val = os.getenv(var, "")
        results.append({
            "group": group,
            "check": f"{var} defined",
            "status": "ok" if val else "warn",
            "detail": "set" if val else "not set — transport will be skipped",
        })

    # Per-collector env vars (skip Google Workspace)
    global_http_url = os.getenv("HTTP_COLLECTOR_URL", "")
    for cid, ccfg in CONFIG.get("http_collectors", {}).items():
        if cid in _SKIP_COLLECTORS:
            continue
        uvar = ccfg.get("url_env_var", "")
        kvar = ccfg.get("api_key_env_var", "")
        label = cid.replace("_collector", "").replace("_", " ").title()
        group = f"HTTP — {label}"
        # URL: passes if either the per-collector var OR the global fallback is set
        if uvar:
            specific_url = os.getenv(uvar, "")
            if specific_url:
                url_status, url_detail = "ok", f"{uvar} set"
            elif global_http_url:
                url_status, url_detail = "ok", f"using HTTP_COLLECTOR_URL (global fallback)"
            else:
                url_status, url_detail = "warn", f"neither {uvar} nor HTTP_COLLECTOR_URL is set"
            results.append({
                "group": group,
                "check": "collector URL defined",
                "status": url_status,
                "detail": url_detail,
            })
        # Key: no global fallback exists — each collector needs its own
        if kvar:
            key_val = os.getenv(kvar, "")
            results.append({
                "group": group,
                "check": f"{kvar} defined",
                "status": "ok" if key_val else "warn",
                "detail": "set" if key_val else "not set — auth will fail",
            })

    # ── 2. Syslog TCP connectivity ────────────────────────────────────────────
    syslog_host = os.getenv("SYSLOG_HOST", "")
    syslog_port = CONFIG.get("syslog_port", 514)
    if syslog_host:
        try:
            with _socket.create_connection((syslog_host, syslog_port), timeout=3):
                pass
            results.append({
                "group": "Syslog",
                "check": f"TCP {syslog_host}:{syslog_port} reachable",
                "status": "ok", "detail": "connected",
            })
        except Exception as exc:
            results.append({
                "group": "Syslog",
                "check": f"TCP {syslog_host}:{syslog_port} reachable",
                "status": "error", "detail": str(exc),
            })
    else:
        results.append({
            "group": "Syslog", "check": "TCP connectivity",
            "status": "skip", "detail": "SYSLOG_HOST not set",
        })

    # ── 3. HTTP collector reachability ────────────────────────────────────────
    http_urls_checked: set = set()

    def _check_http_url(url, label, group):
        if not url or url in http_urls_checked:
            return
        http_urls_checked.add(url)
        try:
            r = _requests.head(url, timeout=3, verify=False,
                               headers={"User-Agent": "LogSim-healthcheck/1.0"})
            # Any HTTP response (even 401/403) means endpoint is reachable
            results.append({
                "group": group, "check": f"{label} reachable",
                "status": "ok", "detail": f"HTTP {r.status_code}",
            })
        except Exception as exc:
            results.append({
                "group": group, "check": f"{label} reachable",
                "status": "error", "detail": str(exc),
            })

    global_url = os.getenv("HTTP_COLLECTOR_URL", "")
    if global_url:
        _check_http_url(global_url, "HTTP_COLLECTOR_URL", "HTTP (global fallback)")

    for cid, ccfg in CONFIG.get("http_collectors", {}).items():
        if cid in _SKIP_COLLECTORS:
            continue
        uvar = ccfg.get("url_env_var", "")
        url = os.getenv(uvar, "") if uvar else ""
        label = cid.replace("_collector", "").replace("_", " ").title()
        if url:
            _check_http_url(url, label, f"HTTP — {label}")

    # ── 4. AWS S3 permissions ─────────────────────────────────────────────────
    aws_key    = os.getenv("AWS_ACCESS_KEY_ID", "")
    aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    # Accept upper or lower case — .env may use lowercase names
    aws_bucket = os.getenv("S3_BUCKET_NAME", "") or os.getenv("s3_bucket_name", "")
    aws_region = os.getenv("AWS_REGION", "") or os.getenv("aws_region", "us-east-1")
    if aws_key and aws_secret and aws_bucket:
        try:
            import boto3 as _boto3
            session = _boto3.Session(
                aws_access_key_id=aws_key,
                aws_secret_access_key=aws_secret,
                region_name=aws_region,
            )
            s3 = session.client("s3")
            # HeadBucket requires s3:ListBucket which may not be granted.
            # A 403 here does not mean PutObject will fail — check separately.
            try:
                s3.head_bucket(Bucket=aws_bucket)
                results.append({
                    "group": "AWS S3", "check": f"bucket '{aws_bucket}' accessible",
                    "status": "ok", "detail": "head_bucket succeeded",
                })
            except Exception as hb_exc:
                hb_msg = str(hb_exc)
                if "403" in hb_msg or "Forbidden" in hb_msg:
                    results.append({
                        "group": "AWS S3", "check": f"bucket '{aws_bucket}' accessible",
                        "status": "warn",
                        "detail": "403 on head_bucket — s3:ListBucket not granted. PutObject check will still run.",
                    })
                else:
                    results.append({
                        "group": "AWS S3", "check": f"bucket '{aws_bucket}' accessible",
                        "status": "error", "detail": hb_msg,
                    })
            test_key = f"logsim-healthcheck/{int(time.time())}.txt"
            s3.put_object(Bucket=aws_bucket, Key=test_key, Body=b"logsim-healthcheck")
            s3.delete_object(Bucket=aws_bucket, Key=test_key)
            results.append({
                "group": "AWS S3", "check": "s3:PutObject permission",
                "status": "ok", "detail": "write + delete succeeded",
            })
        except ImportError:
            results.append({
                "group": "AWS S3", "check": "boto3 installed",
                "status": "error", "detail": "not installed — run: pip install boto3",
            })
        except Exception as exc:
            results.append({
                "group": "AWS S3", "check": "S3 access",
                "status": "error", "detail": str(exc),
            })
    else:
        missing = [v for v in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET_NAME"]
                   if not (os.getenv(v, "") or os.getenv(v.lower(), ""))]
        results.append({
            "group": "AWS S3", "check": "credentials present",
            "status": "skip", "detail": f"not set: {', '.join(missing)}",
        })

    # ── 5. GCP Pub/Sub permissions ────────────────────────────────────────────
    gcp_project = os.getenv("GCP_PROJECT_ID", "")
    gcp_topic   = os.getenv("GCP_PUBSUB_TOPIC", "")
    inline_key  = os.getenv("GCP_SERVICE_ACCOUNT_KEY_JSON", "")
    adc_path    = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
    if gcp_project and gcp_topic and (inline_key or adc_path):
        try:
            from google.cloud import pubsub_v1 as _pubsub
            if inline_key:
                import json as _json
                from google.oauth2 import service_account as _sa
                creds = _sa.Credentials.from_service_account_info(
                    _json.loads(inline_key),
                    scopes=["https://www.googleapis.com/auth/pubsub"],
                )
                publisher = _pubsub.PublisherClient(credentials=creds)
            else:
                publisher = _pubsub.PublisherClient()
            topic_path = publisher.topic_path(gcp_project, gcp_topic)
            publisher.get_topic(request={"topic": topic_path})
            results.append({
                "group": "GCP Pub/Sub", "check": f"topic '{gcp_topic}' accessible",
                "status": "ok", "detail": "get_topic succeeded",
            })
        except ImportError:
            results.append({
                "group": "GCP Pub/Sub", "check": "google-cloud-pubsub installed",
                "status": "error", "detail": "not installed — run: pip install google-cloud-pubsub",
            })
        except Exception as exc:
            results.append({
                "group": "GCP Pub/Sub", "check": "Pub/Sub access",
                "status": "error", "detail": str(exc),
            })
    else:
        missing = []
        if not gcp_project: missing.append("GCP_PROJECT_ID")
        if not gcp_topic:   missing.append("GCP_PUBSUB_TOPIC")
        if not inline_key and not adc_path:
            missing.append("GCP_SERVICE_ACCOUNT_KEY_JSON or GOOGLE_APPLICATION_CREDENTIALS")
        results.append({
            "group": "GCP Pub/Sub", "check": "credentials present",
            "status": "skip", "detail": f"not set: {', '.join(missing)}" if missing else "skipped",
        })

    overall = ("error" if any(r["status"] == "error" for r in results)
               else "warn" if any(r["status"] == "warn" for r in results)
               else "ok")
    return {"overall": overall, "checks": results}


def _health_monitor_tick():
    """Background thread: run health checks every 60 s, detect state transitions."""
    global _health_cache, _health_ts, _health_prev, _health_alerts
    while True:
        time.sleep(60)
        try:
            result = _run_health_checks()
            new_map = {f"{r['group']}|{r['check']}": r["status"] for r in result["checks"]}
            with _health_lock:
                alerts = []
                for key, new_st in new_map.items():
                    old_st = _health_prev.get(key, "skip")
                    if new_st == "error" and old_st != "error":
                        group, check = key.split("|", 1)
                        detail = next((r["detail"] for r in result["checks"]
                                       if r["group"] == group and r["check"] == check), "")
                        alerts.append({"group": group, "check": check,
                                       "from": old_st, "to": "error", "detail": detail})
                    elif new_st == "warn" and old_st not in ("error", "warn"):
                        group, check = key.split("|", 1)
                        detail = next((r["detail"] for r in result["checks"]
                                       if r["group"] == group and r["check"] == check), "")
                        alerts.append({"group": group, "check": check,
                                       "from": old_st, "to": "warn", "detail": detail})
                _health_prev = new_map
                _health_alerts.extend(alerts)
                _health_cache = result
                _health_ts = time.time()
        except Exception:
            pass


# Start the background health monitor
threading.Thread(target=_health_monitor_tick, daemon=True, name="health-monitor").start()


@app.get("/api/health")
def api_health():
    force = request.args.get("refresh", "0") == "1"
    with _health_lock:
        cached = _health_cache if not force else None
    if cached:
        return jsonify(cached)
    # Fresh run (forced or cache empty)
    global _health_ts
    result = _run_health_checks()
    with _health_lock:
        _health_cache.clear()
        _health_cache.update(result)
        _health_ts = time.time()
    return jsonify(result)


@app.get("/api/health/alerts")
def api_health_alerts():
    """Return pending health alerts and clear them."""
    with _health_lock:
        alerts = list(_health_alerts)
        _health_alerts.clear()
    return jsonify({"alerts": alerts})


@app.get("/api/timeline")
def api_timeline():
    BUCKETS = 60
    BUCKET_SEC = 2
    window = BUCKETS * BUCKET_SEC   # 120 seconds
    now = time.time()

    result = {}
    for name, state in MODULE_STATES.items():
        benign       = [0] * BUCKETS
        threats      = [0] * BUCKETS
        threat_names = [[] for _ in range(BUCKETS)]
        with state._lock:
            for ts in state._benign_timestamps:
                age = now - ts
                if 0 <= age < window:
                    idx = BUCKETS - 1 - int(age / BUCKET_SEC)
                    benign[max(0, idx)] += 1
            for ts in state._threat_timestamps:
                age = now - ts
                if 0 <= age < window:
                    idx = BUCKETS - 1 - int(age / BUCKET_SEC)
                    threats[max(0, idx)] += 1
            for ts, ename in state._threat_event_details:
                age = now - ts
                if 0 <= age < window:
                    idx = BUCKETS - 1 - int(age / BUCKET_SEC)
                    bucket_names = threat_names[max(0, idx)]
                    if ename not in bucket_names:
                        bucket_names.append(ename)
        result[name] = {"benign": benign, "threats": threats, "threat_names": threat_names}

    labels = [f"-{(BUCKETS - i) * BUCKET_SEC}s" for i in range(BUCKETS)]
    sparse = [labels[i] if i % 10 == 0 or i == BUCKETS - 1 else "" for i in range(BUCKETS)]
    return jsonify({"labels": sparse, "modules": result})


@app.get("/api/metrics")
def api_metrics():
    states = list(MODULE_STATES.values())
    total_logs = sum(s.total_logs for s in states)
    total_threats = sum(s.total_threats for s in states)
    total_rate = round(sum(s.get_rate() for s in states), 2)
    running = sum(1 for s in states if s.status == "running")
    return jsonify({
        "total_logs": total_logs,
        "total_threats": total_threats,
        "total_rate_per_sec": total_rate,
        "modules_running": running,
        "modules_total": len(states),
        "session_start": _session_start,
        "per_module": [s.to_dict() for s in states],
    })


# ── Bad User API ─────────────────────────────────────────────────────────────

@app.get("/api/baduser/users")
def api_baduser_users():
    """User list grouped by department for the Bad User picker."""
    groups = _get_users_by_department(SESSION_CONTEXT)
    return jsonify(groups)


@app.post("/api/baduser/start")
def api_baduser_start():
    body = request.get_json(silent=True) or {}
    username = body.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400
    duration = float(body.get("duration_minutes", 15))
    if duration < 1 or duration > 480:
        return jsonify({"error": "duration_minutes must be 1-480"}), 400
    threat_level = body.get("threat_level", "Extreme")
    if threat_level not in THREAT_LEVELS:
        return jsonify({"error": f"Unknown threat level '{threat_level}'"}), 400
    event_interval = float(body.get("event_interval", 0.5))
    if event_interval < 0.01:
        return jsonify({"error": "event_interval must be >= 0.01"}), 400
    selected_modules = body.get("selected_modules")  # list of module names or None
    if selected_modules is not None and not isinstance(selected_modules, list):
        return jsonify({"error": "selected_modules must be a list"}), 400

    ok, err = _start_baduser(username, duration, threat_level, event_interval,
                             selected_modules=selected_modules)
    if not ok:
        return jsonify({"error": err}), 409
    return jsonify({"started": True, "username": username})


@app.post("/api/baduser/stop")
def api_baduser_stop():
    _stop_baduser()
    return jsonify({"stopped": True})


@app.get("/api/baduser/status")
def api_baduser_status():
    with _baduser_lock:
        active = _baduser_state["active"]
        if not active:
            return jsonify({"active": False})
        started_at = _baduser_state["started_at"]
        duration = _baduser_state["duration_seconds"]
        elapsed = time.time() - started_at if started_at else 0
        remaining = max(0, duration - elapsed)
        metrics = copy.deepcopy(_baduser_state["metrics"])
        total_logs = sum(m["logs"] for m in metrics.values())
        total_threats = sum(m["threats"] for m in metrics.values())
        return jsonify({
            "active": True,
            "username": _baduser_state["username"],
            "display_name": _baduser_state["display_name"],
            "department": _baduser_state["department"],
            "threat_level": _baduser_state["threat_level"],
            "event_interval": _baduser_state["event_interval"],
            "started_at": started_at,
            "duration_seconds": duration,
            "elapsed_seconds": round(elapsed),
            "remaining_seconds": round(remaining),
            "total_logs": total_logs,
            "total_threats": total_threats,
            "per_module": metrics,
            "selected_modules": list(_baduser_state["selected_modules"]),
        })


# ── Frontend ──────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    resp = make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    host = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    port = int(os.getenv("DASHBOARD_PORT", "5000"))
    print(f"\nLogSim Dashboard -> http://{host}:{port}")
    print(f"Loaded {len(MODULE_STATES)} modules: {', '.join(MODULE_STATES.keys())}\n")
    app.run(host=host, port=port, debug=False, threaded=True)
