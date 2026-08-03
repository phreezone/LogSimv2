"""LogSim MCP server — exposes the LogSimv2 control API as MCP tools over stdio.

Design: this drives an ALREADY-RUNNING dashboard over HTTP. It deliberately does NOT
import log_simulator. The simulator's live runtime state (async send queue, the cached
persistent syslog socket, per-module S3 batch buffers, module threads, the training
single-flight lock) is owned by the dashboard process; a second process importing
log_simulator would become a competing owner of those sockets/buffers. So every tool
here is a thin HTTP call to the running dashboard's versioned /api/v1 surface.

Run (dashboard must already be running):
    pip install -r integrations/requirements.txt
    LOGSIM_API_URL=http://127.0.0.1:5000 LOGSIM_API_KEY=<token> python integrations/mcp_server.py

Env:
    LOGSIM_API_URL   base URL of the running dashboard (default http://127.0.0.1:5000)
    LOGSIM_API_KEY   API token; required only if the dashboard has auth enabled. Sent as
                     X-API-Key. Leave unset when the dashboard is running zero-config (open).

Register with an MCP client (e.g. Claude Code) as a stdio server pointing at this file.
"""

import os
import time
from typing import Optional
from urllib.parse import quote

try:
    import requests
except ImportError:  # pragma: no cover
    raise SystemExit("The 'requests' package is required: pip install -r integrations/requirements.txt")

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    raise SystemExit(
        "The MCP SDK is not installed. Install it with:\n"
        "    pip install -r integrations/requirements.txt\n"
        "(or: pip install mcp)"
    )

API_URL = os.getenv("LOGSIM_API_URL", "http://127.0.0.1:5000").rstrip("/")
API_KEY = (os.getenv("LOGSIM_API_KEY") or "").strip()
BASE = f"{API_URL}/api/v1"

mcp = FastMCP("logsim")


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["X-API-Key"] = API_KEY
    return h


def _req(method: str, path: str, body: Optional[dict] = None):
    """Call the dashboard API. Raises RuntimeError with the server's message on non-2xx."""
    url = f"{BASE}{path}"
    try:
        r = requests.request(method, url, headers=_headers(), json=body, timeout=60)
    except requests.RequestException as e:
        raise RuntimeError(
            f"Could not reach the LogSim dashboard at {API_URL} ({e}). "
            "Is it running? Set LOGSIM_API_URL if it's elsewhere."
        )
    ct = r.headers.get("content-type", "")
    data = r.json() if ct.startswith("application/json") else {"raw": r.text}
    if r.status_code == 401:
        raise RuntimeError(
            "Unauthorized (401). The dashboard has auth enabled — set LOGSIM_API_KEY to its token."
        )
    if not r.ok:
        raise RuntimeError(f"{method} {path} -> HTTP {r.status_code}: {data}")
    return data


# ── Scenarios ─────────────────────────────────────────────────────────────────
@mcp.tool()
def list_scenarios() -> list:
    """List all available multi-step attack scenarios (each has an id and a human name)."""
    return _req("GET", "/scenarios")


@mcp.tool()
def run_scenario(scenario_id: str, wait: bool = False, timeout_s: int = 120) -> dict:
    """Trigger an attack scenario by id.

    Returns immediately with a run record containing a run_id. If wait=True, polls the run
    until it completes (status done/error) or timeout_s elapses, then returns the final
    record including `emitted` — the emission manifest (total_events, by_module, by_event).

    Note: `emitted` reports what LogSim SENT, not what was detected/fired in XSIAM.
    """
    started = _req("POST", f"/scenarios/{quote(scenario_id)}/run")
    run_id = started.get("run_id")
    if not wait or not run_id:
        return started
    deadline = time.time() + max(1, timeout_s)
    rec = started
    while time.time() < deadline:
        rec = _req("GET", f"/scenarios/runs/{run_id}")
        if rec.get("status") in ("done", "error"):
            return rec
        time.sleep(1.0)
    return rec  # timed out; return last-known status


@mcp.tool()
def get_run_status(run_id: str) -> dict:
    """Get the status and emission manifest of a scenario run by its run_id."""
    return _req("GET", f"/scenarios/runs/{quote(run_id)}")


@mcp.tool()
def list_runs() -> list:
    """List recent scenario runs (newest first) with their status and emission manifests."""
    return _req("GET", "/scenarios/runs")


# ── Modules ───────────────────────────────────────────────────────────────────
@mcp.tool()
def list_modules() -> list:
    """List log-generation modules and their current state (running/stopped, threat level, rates)."""
    return _req("GET", "/modules")


@mcp.tool()
def start_module(name: str, threat_level: Optional[str] = None,
                 event_interval: Optional[float] = None) -> dict:
    """Start continuous log generation for a module (e.g. "Cisco ASA", "AWS GuardDuty").

    threat_level: one of the configured levels (e.g. "Realistic", "Elevated", "High");
    omit to keep the module's current level. event_interval: seconds between events (optional).
    """
    body: dict = {}
    if threat_level:
        body["threat_level"] = threat_level
    if event_interval is not None:
        body["event_interval"] = event_interval
    return _req("POST", f"/modules/{quote(name)}/start", body=body)


@mcp.tool()
def stop_module(name: str) -> dict:
    """Stop a running log-generation module by name."""
    return _req("POST", f"/modules/{quote(name)}/stop")


@mcp.tool()
def list_module_threats(name: str) -> dict:
    """List the event names a module can fire one-shot.

    These are the only valid `event` values for fire_event on that module. Returns an empty
    list for modules that expose no named events.
    """
    return _req("GET", f"/modules/{quote(name)}/threats")


@mcp.tool()
def fire_event(name: str, event: str) -> dict:
    """Fire a single named threat/event from a module immediately (one-shot).

    Use list_modules to discover module names and list_module_threats to discover the
    valid `event` values for that module — do not guess event names.
    """
    return _req("POST", f"/modules/{quote(name)}/fire", body={"event": event})


@mcp.tool()
def set_module_interval(name: str, event_interval: float) -> dict:
    """Change a module's seconds-between-events. Applies live; no restart needed.

    Must be >= 0.01. Returns the updated module state.
    """
    return _req("PATCH", f"/modules/{quote(name)}/interval",
                body={"event_interval": event_interval})


@mcp.tool()
def set_module_threat_level(name: str, threat_level: str) -> dict:
    """Change a module's threat level. Works running or stopped; applies live.

    Use list_threat_levels for the valid values. Returns the updated module state.
    """
    return _req("PATCH", f"/modules/{quote(name)}/threat_level",
                body={"threat_level": threat_level})


@mcp.tool()
def reset_module_metrics(name: str) -> dict:
    """Reset one module's log/threat counters. Does not stop the module."""
    return _req("POST", f"/modules/{quote(name)}/reset")


@mcp.tool()
def reset_all_metrics() -> list:
    """Reset every module's counters and the session timer. Does not stop anything."""
    return _req("POST", "/modules/reset_all")


# ── Bad User (targeted insider-threat simulation) ─────────────────────────────
@mcp.tool()
def list_users() -> dict:
    """List simulated employee identities grouped by department.

    Source of valid `username` values for start_bad_user.
    """
    return _req("GET", "/baduser/users")


@mcp.tool()
def start_bad_user(username: str, duration_minutes: float = 15,
                   threat_level: str = "Extreme", event_interval: float = 0.5,
                   selected_modules: Optional[list] = None) -> dict:
    """Drive every selected module as one named malicious identity for a fixed duration.

    Unlike a scenario, this is a sustained run (duration_minutes 1-480) rather than a
    one-shot sequence, so it returns as soon as the run starts. Poll get_bad_user_status
    for progress. Only one Bad User run can be active — starting a second fails.

    username: from list_users. selected_modules: module names to drive, or omit for all.
    """
    body: dict = {"username": username, "duration_minutes": duration_minutes,
                  "threat_level": threat_level, "event_interval": event_interval}
    if selected_modules is not None:
        body["selected_modules"] = selected_modules
    return _req("POST", "/baduser/start", body=body)


@mcp.tool()
def stop_bad_user() -> dict:
    """Stop the active Bad User run. Safe to call when nothing is running."""
    return _req("POST", "/baduser/stop")


@mcp.tool()
def get_bad_user_status() -> dict:
    """Progress of the active Bad User run.

    Returns {"active": false} when idle; otherwise the user, remaining_seconds, and
    per-module log/threat tallies.
    """
    return _req("GET", "/baduser/status")


# ── Status ────────────────────────────────────────────────────────────────────
@mcp.tool()
def list_threat_levels() -> list:
    """List valid threat-level names, for start_module and set_module_threat_level."""
    return _req("GET", "/threat_levels")


@mcp.tool()
def get_status() -> dict:
    """Return a health + throughput-metrics snapshot of the running simulator."""
    return {"health": _req("GET", "/health"), "metrics": _req("GET", "/metrics")}


@mcp.tool()
def get_health_alerts() -> dict:
    """Drain queued health alerts (transport failures, stalled modules).

    DESTRUCTIVE READ: the server clears its alert queue on each call, so an alert goes to
    exactly one caller. If a dashboard UI is open it is polling this too and you will each
    see only part of the stream.
    """
    return _req("GET", "/health/alerts")


if __name__ == "__main__":
    mcp.run()
