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
def fire_event(name: str, event: str) -> dict:
    """Fire a single named threat/event from a module immediately (one-shot).

    `event` is the module's scenario_event name. Use list_modules to discover a module's name.
    """
    return _req("POST", f"/modules/{quote(name)}/fire", body={"event": event})


# ── Status ────────────────────────────────────────────────────────────────────
@mcp.tool()
def get_status() -> dict:
    """Return a health + throughput-metrics snapshot of the running simulator."""
    return {"health": _req("GET", "/health"), "metrics": _req("GET", "/metrics")}


if __name__ == "__main__":
    mcp.run()
