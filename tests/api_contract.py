"""External API contract checks — /api/v1 vs openapi.yaml vs the MCP server.

Run:  python tests/api_contract.py
No XSIAM tenant and no network are required, and NO log traffic is emitted: every call goes
through Flask's test_client, and the routes that would generate events (module start,
scenario run, fire) are deliberately never called. The Tor-exit-node fetch that app.py does
at import is stubbed out so the run stays offline and fast.

What it proves:
  A. Inventory parity  — the /api/v1 routes Flask actually registered match openapi.yaml
                         exactly, in both directions, including HTTP methods.
  B. No silent drops   — every alias declared in _register_v1_aliases() really registered.
                         The alias table resolves view functions by NAME and only prints a
                         warning when one is missing, so renaming a view would otherwise
                         drop a v1 route with the tests still green.
  C. Legacy preserved  — each v1 alias still has its original /api/* route (the UI uses it).
  D. Read-only routes  — every GET in the contract answers 200 with the documented type.
  E. Mutations         — the PATCH/reset routes validate their input and take effect.
  F. Auth gating       — the new routes are gated when a key is set, via either header,
                         and /api/health stays exempt.
  G. MCP alignment     — every path mcp_server.py calls exists in the contract with that
                         method, so no tool can point at a route that was never registered.
"""

import importlib.util
import io
import contextlib
import os
import re
import sys

sys.path.insert(0, '.')

try:
    import yaml
except ImportError:
    print("  FAIL: PyYAML required to read openapi.yaml: pip install pyyaml")
    sys.exit(1)

APP_PATH = os.path.join('dashboard', 'app.py')
SPEC_PATH = os.path.join('integrations', 'openapi.yaml')
MCP_PATH = os.path.join('integrations', 'mcp_server.py')

_results = []
_fails = []


def check(ok, label, detail=""):
    _results.append(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        _fails.append(f"{label}{('  ' + detail) if detail else ''}")


def report(summary="", note=""):
    """Print everything accumulated so far, then exit nonzero if anything failed."""
    print("\n".join(_results))
    total = len(_results)
    print(f"\n{total - len(_fails)}/{total} checks passed" + (f" ({summary})" if summary else ""))
    if _fails:
        print("\nFAILURES:")
        for f in _fails:
            print(f"  - {f}")
        if note:
            print(f"\n{note}")
        sys.exit(1)


def _load_app():
    """Import dashboard/app.py as a module, offline.

    app.py fetches the live Tor exit list at import (10s timeout, graceful fallback). Stub
    urlopen so the fallback path is taken immediately — the contract does not depend on it.
    """
    import urllib.request
    real_urlopen = urllib.request.urlopen

    def _offline(*_a, **_kw):
        raise OSError("offline (stubbed by tests/api_contract.py)")

    urllib.request.urlopen = _offline
    spec = importlib.util.spec_from_file_location("dashboard_app_undertest", APP_PATH)
    mod = importlib.util.module_from_spec(spec)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            spec.loader.exec_module(mod)
    except Exception:
        print(buf.getvalue())
        raise
    finally:
        urllib.request.urlopen = real_urlopen
    return mod


def _app_v1_routes(app):
    """{path-without-/api/v1: {METHOD, ...}} for every registered v1 rule."""
    out = {}
    for rule in app.url_map.iter_rules():
        path = str(rule)
        if path.startswith("/api/v1"):
            out[path.replace("/api/v1", "", 1)] = rule.methods - {"HEAD", "OPTIONS"}
    return out


def _spec_v1_routes():
    with open(SPEC_PATH, encoding='utf-8') as f:
        spec = yaml.safe_load(f)
    out = {}
    for path, ops in spec["paths"].items():
        flask_path = re.sub(r"\{(\w+)\}", r"<\1>", path)   # OpenAPI {x} -> Flask <x>
        out[flask_path] = {m.upper() for m in ops
                           if m.lower() in ("get", "post", "put", "patch", "delete")}
    return out


def _declared_aliases():
    """The (path, view_name) pairs literally listed in _register_v1_aliases()."""
    src = open(APP_PATH, encoding='utf-8').read()
    block = src.split("def _register_v1_aliases():")[1].split("view_funcs =")[0]
    return re.findall(r'\("(/api/v1[^"]*)",\s*"(\w+)"', block)


def test_inventory(app):
    app_v1, spec_v1 = _app_v1_routes(app), _spec_v1_routes()
    check(set(app_v1) == set(spec_v1), f"inventory parity ({len(app_v1)} routes)",
          f"only in app: {sorted(set(app_v1) - set(spec_v1))} | "
          f"only in spec: {sorted(set(spec_v1) - set(app_v1))}")
    mismatched = {p: (sorted(app_v1[p]), sorted(spec_v1[p]))
                  for p in set(app_v1) & set(spec_v1) if app_v1[p] != spec_v1[p]}
    check(not mismatched, "methods agree on every shared path", str(mismatched))
    return app_v1


def test_aliases_registered(app, app_v1):
    declared = _declared_aliases()
    check(declared, "alias table parsed from source", "found none — did the block move?")
    check(len(declared) == len(app_v1),
          f"every declared alias registered ({len(declared)} declared)",
          f"declared={len(declared)} registered={len(app_v1)}")
    missing = [ep for _p, ep in declared if ep not in app.view_functions]
    check(not missing, "all alias view functions exist", str(missing))
    return declared


def test_legacy_preserved(app, declared):
    legacy = {str(r) for r in app.url_map.iter_rules()}
    # api_reset_all is intentionally relocated: legacy /api/reset_all -> v1
    # /api/v1/modules/reset_all (symmetry with start_all/stop_all), so skip it here.
    relocated = {"api_reset_all"}
    missing = [ep for path, ep in declared
               if ep not in relocated and path.replace("/api/v1", "/api", 1) not in legacy]
    check(not missing, f"legacy /api/* route kept for all {len(declared)} aliases", str(missing))
    check("/api/reset_all" in legacy, "relocated route still served at /api/reset_all")


def _json(response):
    """Body as a dict/list, or None for a non-JSON response (e.g. a 404 HTML page)."""
    return response.get_json(silent=True)


def test_read_only(client):
    mods = _json(client.get("/api/v1/modules"))
    mod = mods[0]["name"]
    expected = [
        ("/api/v1/scenarios", list), ("/api/v1/scenarios/runs", list),
        ("/api/v1/modules", list), ("/api/v1/threat_levels", list),
        ("/api/v1/timeline", dict), ("/api/v1/health", dict),
        ("/api/v1/health/alerts", dict), ("/api/v1/metrics", dict),
        ("/api/v1/baduser/users", dict), ("/api/v1/baduser/status", dict),
        (f"/api/v1/modules/{mod}/threats", dict),
    ]
    for path, want in expected:
        r = client.get(path)
        body = _json(r)
        check(r.status_code == 200 and isinstance(body, want), f"GET {path}",
              f"-> {r.status_code} {type(body).__name__}, wanted {want.__name__}")

    # Shapes the MCP tools and the spec's schemas promise.
    check("threats" in (_json(client.get(f"/api/v1/modules/{mod}/threats")) or {}),
          "threats payload has a 'threats' key")
    check((_json(client.get("/api/v1/baduser/status")) or {}).get("active") is False,
          "idle baduser status reports active:false")
    users = _json(client.get("/api/v1/baduser/users")) or {}
    check(users and all(isinstance(v, list) for v in users.values()),
          "baduser users grouped by department")
    sample = next(iter(users.values()))[0]
    check({"username", "display_name", "department"} <= set(sample),
          "user entry has username/display_name/department", str(sorted(sample)))
    check((_json(client.get("/api/v1/health/alerts")) or {}).get("alerts") is not None,
          "health/alerts payload has an 'alerts' key")
    levels = _json(client.get("/api/v1/threat_levels")) or []
    check(len(levels) > 1 and all(isinstance(x, str) for x in levels),
          "threat_levels is a list of names", str(levels))
    return mod, sample["username"], levels


def test_validation(client, mod, username):
    """Bad input must be rejected. None of these start anything."""
    cases = [
        ("PATCH", f"/api/v1/modules/{mod}/interval", {"event_interval": 0.001}, 400,
         "interval rejects < 0.01"),
        ("PATCH", f"/api/v1/modules/{mod}/threat_level", {"threat_level": "Bogus"}, 400,
         "threat_level rejects an unknown level"),
        ("PATCH", "/api/v1/modules/NoSuchModule/interval", {"event_interval": 5}, 404,
         "interval 404s an unknown module"),
        ("POST", "/api/v1/modules/NoSuchModule/reset", None, 404,
         "reset 404s an unknown module"),
        ("POST", "/api/v1/baduser/start", {}, 400, "baduser start requires a username"),
        ("POST", "/api/v1/baduser/start", {"username": username, "duration_minutes": 999},
         400, "baduser start rejects duration > 480"),
        ("POST", "/api/v1/baduser/start", {"username": username, "duration_minutes": 0},
         400, "baduser start rejects duration < 1"),
        ("POST", "/api/v1/baduser/start", {"username": username, "threat_level": "Bogus"},
         400, "baduser start rejects an unknown threat_level"),
        ("POST", "/api/v1/baduser/start", {"username": username, "event_interval": 0},
         400, "baduser start rejects event_interval < 0.01"),
        ("POST", "/api/v1/baduser/start", {"username": username,
                                           "selected_modules": "notalist"},
         400, "baduser start rejects non-list selected_modules"),
    ]
    for method, path, body, want, label in cases:
        r = client.open(path, method=method, json=body)
        check(r.status_code == want, label, f"-> {r.status_code}, wanted {want}")

    check(client.get(f"/api/v1/modules/{mod}/threats").status_code == 200
          and client.get("/api/v1/modules/NoSuchModule/threats").status_code == 404,
          "threats 404s an unknown module but 200s a real one")
    check((_json(client.post("/api/v1/baduser/stop")) or {}).get("stopped") is True,
          "baduser stop is idempotent when idle")


def test_mutations(client, mod, levels):
    """The PATCH/reset routes must actually change state (no events are emitted)."""
    level = levels[1]
    r = client.patch(f"/api/v1/modules/{mod}/threat_level", json={"threat_level": level})
    check(r.status_code == 200 and (_json(r) or {}).get("threat_level") == level,
          f"PATCH threat_level -> '{level}' takes effect",
          f"-> {r.status_code} {_json(r)}")
    r = client.patch(f"/api/v1/modules/{mod}/interval", json={"event_interval": 7})
    check(r.status_code == 200 and (_json(r) or {}).get("event_interval") == 7,
          "PATCH interval takes effect", f"-> {r.status_code} {_json(r)}")
    r = client.post(f"/api/v1/modules/{mod}/reset")
    check(r.status_code == 200 and (_json(r) or {}).get("total_logs") == 0,
          "POST reset zeroes one module's counters")
    r = client.post("/api/v1/modules/reset_all")
    body = _json(r)
    check(r.status_code == 200 and isinstance(body, list)
          and all(m["total_logs"] == 0 for m in body),
          f"POST reset_all zeroes all {len(body) if isinstance(body, list) else '?'} modules")


def test_auth(app_mod, client, mod):
    """Auth is opt-in; with a key set, the new routes must be gated."""
    key = "contract-test-key"
    previous = app_mod._API_KEY
    app_mod._API_KEY = key
    try:
        gated = ["/api/v1/baduser/status", "/api/v1/baduser/users", "/api/v1/threat_levels",
                 "/api/v1/timeline", "/api/v1/health/alerts",
                 f"/api/v1/modules/{mod}/threats"]
        blocked = [p for p in gated if client.get(p).status_code != 401]
        check(not blocked, f"all {len(gated)} new routes 401 without a token", str(blocked))
        check(client.get("/api/v1/baduser/status",
                         headers={"X-API-Key": key}).status_code == 200,
              "X-API-Key header is accepted")
        check(client.get("/api/v1/threat_levels",
                         headers={"Authorization": f"Bearer {key}"}).status_code == 200,
              "Authorization: Bearer is accepted")
        check(client.get("/api/v1/threat_levels",
                         headers={"X-API-Key": "wrong"}).status_code == 401,
              "a wrong token is rejected")
        check(client.get("/api/health").status_code == 200,
              "/api/health stays exempt (liveness probes)")
        check(client.patch(f"/api/v1/modules/{mod}/interval",
                           json={"event_interval": 5}).status_code == 401,
              "mutating routes are gated too")
    finally:
        app_mod._API_KEY = previous


def test_mcp_alignment(app_v1):
    """Every _req(...) path in mcp_server.py must be a real contract route."""
    src = open(MCP_PATH, encoding='utf-8').read()
    tools = re.findall(r"@mcp\.tool\(\)\s*\ndef (\w+)", src)
    calls = re.findall(r'_req\(\s*"(\w+)",\s*f?"([^"]+)"', src)
    check(len(tools) >= 20, f"mcp_server advertises {len(tools)} tools")
    check(calls, "mcp _req call sites parsed", "found none — did the call style change?")
    bad = []
    for method, raw in calls:
        # f-string interpolations, with or without quote(): {quote(x)} and {x} -> <x>
        norm = re.sub(r"\{(?:quote\()?(\w+)\)?\}", r"<\1>", raw)
        if norm not in app_v1 or method not in app_v1[norm]:
            bad.append(f"{method} {raw} (normalized {norm})")
    check(not bad, f"all {len(calls)} mcp call sites hit a registered v1 route", str(bad))
    return tools


def main():
    app_mod = _load_app()
    app = app_mod.app
    client = app.test_client()

    # Structural checks first. If the route inventory itself has drifted, probing individual
    # routes just produces a cascade of confusing 404s, so stop and report the real cause.
    app_v1 = test_inventory(app)
    declared = test_aliases_registered(app, app_v1)
    test_legacy_preserved(app, declared)
    if _fails:
        report(f"{len(app_v1)} v1 routes registered",
               "Route inventory drifted - runtime probes skipped. Fix the alias table in\n"
               "dashboard/app.py::_register_v1_aliases() or integrations/openapi.yaml so the\n"
               "two agree, then re-run. (Renaming a view silently drops its v1 alias.)")

    mod, username, levels = test_read_only(client)
    test_validation(client, mod, username)
    test_mutations(client, mod, levels)
    test_auth(app_mod, client, mod)
    tools = test_mcp_alignment(app_v1)

    report(f"{len(app_v1)} v1 routes, {len(tools)} MCP tools, probed module '{mod}'")
    print("All API contract checks PASSED.")


if __name__ == '__main__':
    main()
