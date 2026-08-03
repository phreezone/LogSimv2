"""Generate a Postman Collection (v2.1) from openapi.yaml — single source of truth.

The OpenAPI spec (openapi.yaml) is authoritative; this derives a ready-to-import Postman
collection so nothing drifts. Re-run after editing the spec:

    python integrations/gen_postman_collection.py

Produces: integrations/logsim.postman_collection.json
Postman can also import openapi.yaml directly — this file is the pre-wired convenience.
"""
import json
import os
import re

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML required: pip install pyyaml")

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "openapi.yaml")
OUT = os.path.join(HERE, "logsim.postman_collection.json")

# Sensible sample values for path parameters (used in the generated example requests).
PARAM_SAMPLES = {"scenario_id": "1", "run_id": "REPLACE_WITH_RUN_ID", "name": "Cisco ASA"}


def base_url_default(spec):
    """Expand the templated server URL with its variable defaults."""
    srv = spec["servers"][0]
    url = srv["url"]
    for var, meta in (srv.get("variables") or {}).items():
        url = url.replace("{" + var + "}", str(meta.get("default", "")))
    return url


def make_item(path, method, op):
    # Convert OpenAPI {param} → Postman :param and collect path variables.
    segments = [s for s in path.strip("/").split("/") if s]
    pm_segments, variables = [], []
    for seg in segments:
        m = re.fullmatch(r"\{(\w+)\}", seg)
        if m:
            pm_segments.append(":" + m.group(1))
            variables.append({"key": m.group(1), "value": PARAM_SAMPLES.get(m.group(1), "")})
        else:
            pm_segments.append(seg)

    req = {
        "method": method.upper(),
        "header": [],
        "url": {
            "raw": "{{baseUrl}}/" + "/".join(pm_segments),
            "host": ["{{baseUrl}}"],
            "path": pm_segments,
        },
        "description": op.get("summary", ""),
    }
    if variables:
        req["url"]["variable"] = variables

    body = op.get("requestBody", {})
    content = (body.get("content") or {}).get("application/json", {})
    example = content.get("example")
    if content:
        req["header"].append({"key": "Content-Type", "value": "application/json"})
        req["body"] = {
            "mode": "raw",
            "raw": json.dumps(example if example is not None else {}, indent=2),
            "options": {"raw": {"language": "json"}},
        }

    return {"name": op.get("summary") or f"{method.upper()} {path}", "request": req}


def main():
    with open(SPEC, encoding="utf-8") as f:
        spec = yaml.safe_load(f)

    # Group items into folders by first path segment (Scenarios / Modules / Bad User / Status).
    folder_for = {"scenarios": "Scenarios", "modules": "Modules", "baduser": "Bad User",
                  "health": "Status", "metrics": "Status", "threat_levels": "Status",
                  "timeline": "Status"}
    folders = {}
    for path, methods in spec["paths"].items():
        top = path.strip("/").split("/")[0]
        fname = folder_for.get(top, top.title())
        for method, op in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            folders.setdefault(fname, []).append(make_item(path, method, op))

    info = spec.get("info", {})
    collection = {
        "info": {
            "name": info.get("title", "LogSim Control API"),
            "description": (info.get("description", "") +
                           "\n\nSet the `baseUrl` and `apiKey` collection variables. "
                           "`apiKey` is only needed when the dashboard has auth enabled; "
                           "leave it blank when running open."),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        # X-API-Key on every request; harmless (ignored) when the dashboard runs open.
        "auth": {"type": "apikey", "apikey": [
            {"key": "key", "value": "X-API-Key"},
            {"key": "value", "value": "{{apiKey}}"},
            {"key": "in", "value": "header"},
        ]},
        "variable": [
            {"key": "baseUrl", "value": base_url_default(spec)},
            {"key": "apiKey", "value": ""},
        ],
        "item": [{"name": name, "item": items} for name, items in folders.items()],
    }

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(collection, f, indent=2)
    n = sum(len(v) for v in folders.values())
    print(f"Wrote {OUT} — {n} requests in {len(folders)} folders "
          f"({', '.join(folders)}), baseUrl default {base_url_default(spec)}")


if __name__ == "__main__":
    main()
