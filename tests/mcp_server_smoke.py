"""Live MCP smoke test — drives integrations/mcp_server.py over real stdio.

Run:  python tests/mcp_server_smoke.py
Needs the optional MCP SDK (pip install -r integrations/requirements.txt); without it the
test SKIPS with exit 0, since the MCP server is an optional integration. No XSIAM tenant is
needed and NO log traffic is emitted: only read-only tools are called (plus reset_all_metrics,
which merely zeroes counters). run_scenario, fire_event, start_module and start_bad_user are
deliberately never called — those would send events to the configured destinations.

Unlike tests/api_contract.py, which checks the contract in-process via Flask's test_client,
this exercises the whole external path an agent actually takes: a separate dashboard process,
an auth-gated HTTP API, and the MCP server as a stdio child speaking JSON-RPC.

What it proves:
  A. Handshake   — the server starts as a stdio child and completes MCP initialization.
  B. Tool list   — every tool the README documents is advertised.
  C. Round trip  — read-only tools return usable payloads THROUGH the auth-gated API,
                   so the server's token handling works end to end.
  D. Errors      — an API 4xx surfaces as a clean MCP tool error, not a crash or a hang.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, '.')

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("  SKIP: the MCP SDK is not installed (optional integration).\n"
          "        pip install -r integrations/requirements.txt")
    sys.exit(0)

API_KEY = "mcp-smoke-test-key"
MCP_SERVER = os.path.join('integrations', 'mcp_server.py')
DASHBOARD = os.path.join('dashboard', 'app.py')
BOOT_TIMEOUT_S = 90

# Tools the README documents; the smoke test asserts all of them are advertised.
EXPECTED_TOOLS = {
    "list_scenarios", "run_scenario", "get_run_status", "list_runs",
    "list_modules", "start_module", "stop_module", "list_module_threats", "fire_event",
    "set_module_interval", "set_module_threat_level", "reset_module_metrics",
    "reset_all_metrics",
    "list_users", "start_bad_user", "stop_bad_user", "get_bad_user_status",
    "list_threat_levels", "get_status", "get_health_alerts",
}

_results = []
_fails = []


def check(ok, label, detail=""):
    _results.append(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        _fails.append(f"{label}{('  ' + detail) if detail else ''}")


def free_port():
    """Bind :0 to get a port the OS says is free, so we never collide with a real dashboard."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return str(s.getsockname()[1])


def payload(result):
    """Decode a FastMCP tool result.

    Two shapes occur depending on SDK version and return annotation: either
    structuredContent is populated (a bare list arrives wrapped as {"result": [...]}), or it
    is None and the value lives in the content blocks — one TextContent PER ELEMENT for a
    list return, a single pretty-JSON block for a dict. Never join the blocks first: N
    concatenated JSON objects will not parse.
    """
    sc = result.structuredContent
    if isinstance(sc, dict) and set(sc) == {"result"}:
        return sc["result"]
    if sc is not None:
        return sc

    def one(text):
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text                      # plain scalar element, e.g. a bare string

    texts = [getattr(c, "text", "") for c in result.content]
    return one(texts[0]) if len(texts) == 1 else [one(t) for t in texts]


def error_text(result):
    return " ".join(getattr(c, "text", "") for c in result.content)


def start_dashboard(port):
    """Launch a throwaway auth-gated dashboard and wait for it to answer."""
    env = dict(os.environ)
    env.update({"DASHBOARD_HOST": "127.0.0.1", "DASHBOARD_PORT": port,
                "LOGSIM_API_KEY": API_KEY})
    proc = subprocess.Popen([sys.executable, DASHBOARD], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + BOOT_TIMEOUT_S
    while time.time() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"dashboard exited early (code {proc.returncode})")
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2)
            return proc
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    proc.kill()
    raise AssertionError(f"dashboard did not come up on :{port} within {BOOT_TIMEOUT_S}s")


def stop_dashboard(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


async def run_checks(session):
    await session.initialize()
    check(True, "MCP initialize handshake completed")

    tools = {t.name for t in (await session.list_tools()).tools}
    missing = sorted(EXPECTED_TOOLS - tools)
    check(not missing, f"all {len(EXPECTED_TOOLS)} documented tools advertised "
                       f"({len(tools)} total)", f"missing: {missing}")

    levels = payload(await session.call_tool("list_threat_levels", {}))
    check(isinstance(levels, list) and "Extreme" in levels,
          "list_threat_levels round trip", str(levels))

    mods = payload(await session.call_tool("list_modules", {}))
    check(isinstance(mods, list) and len(mods) > 1,
          f"list_modules round trip ({len(mods) if isinstance(mods, list) else '?'} modules)",
          str(mods)[:200])
    name = mods[0]["name"]

    threats = payload(await session.call_tool("list_module_threats", {"name": name}))
    check(isinstance(threats, dict) and isinstance(threats.get("threats"), list),
          f"list_module_threats('{name}') -> "
          f"{len(threats.get('threats', [])) if isinstance(threats, dict) else '?'} events",
          str(threats)[:200])

    users = payload(await session.call_tool("list_users", {}))
    check(isinstance(users, dict) and users,
          f"list_users ({len(users) if isinstance(users, dict) else '?'} departments)",
          str(users)[:200])

    status = payload(await session.call_tool("get_bad_user_status", {}))
    check(isinstance(status, dict) and status.get("active") is False,
          "get_bad_user_status reports idle", str(status))

    alerts = payload(await session.call_tool("get_health_alerts", {}))
    check(isinstance(alerts, dict) and "alerts" in alerts,
          "get_health_alerts round trip", str(alerts)[:200])

    snapshot = payload(await session.call_tool("get_status", {}))
    check(isinstance(snapshot, dict) and {"health", "metrics"} <= set(snapshot),
          "get_status returns health + metrics", str(snapshot)[:200])

    runs = payload(await session.call_tool("list_runs", {}))
    check(isinstance(runs, list), "list_runs round trip", str(runs)[:200])

    reset = payload(await session.call_tool("reset_all_metrics", {}))
    check(isinstance(reset, list) and all(m.get("total_logs") == 0 for m in reset),
          "reset_all_metrics zeroes every module", str(reset)[:200])

    # Errors must surface as MCP tool errors carrying the server's status code.
    bad = await session.call_tool("list_module_threats", {"name": "NoSuchModule"})
    check(bad.isError and "404" in error_text(bad),
          "unknown module surfaces a clean 404", error_text(bad)[:160])

    bad = await session.call_tool("start_bad_user", {"username": ""})
    check(bad.isError and "400" in error_text(bad),
          "invalid start_bad_user surfaces a clean 400", error_text(bad)[:160])

    return len(tools), name


async def main():
    port = free_port()
    dashboard = start_dashboard(port)
    print(f"dashboard up on 127.0.0.1:{port} (auth ENABLED)\n")
    try:
        env = dict(os.environ)               # merge, don't replace: the child needs PATH
        env["LOGSIM_API_URL"] = f"http://127.0.0.1:{port}"
        env["LOGSIM_API_KEY"] = API_KEY
        params = StdioServerParameters(command=sys.executable, args=[MCP_SERVER],
                                       env=env, cwd=os.getcwd())
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                n_tools, probed = await run_checks(session)
    finally:
        stop_dashboard(dashboard)

    print("\n".join(_results))
    total = len(_results)
    print(f"\n{total - len(_fails)}/{total} checks passed "
          f"({n_tools} tools advertised, probed module '{probed}')")
    if _fails:
        print("\nFAILURES:")
        for f in _fails:
            print(f"  - {f}")
        sys.exit(1)
    print("All MCP smoke checks PASSED.")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except AssertionError as e:
        print(f"\n  FAIL: {e}")
        sys.exit(1)
