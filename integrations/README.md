# LogSim external control — REST API & MCP

Drive LogSim from outside the web UI: from scripts/CI over HTTP, or from an LLM/agent via
MCP. Both talk to the **already-running dashboard** — start it first
(`python log_simulator.py`, or `python dashboard/app.py`).

> **Why HTTP, not direct import?** The simulator's live runtime state (the async send queue,
> the cached persistent syslog socket, per-module S3 batch buffers, module threads, the
> training single-flight lock) is owned by the dashboard process. External callers must drive
> that one process over HTTP — never spin up a second process that imports `log_simulator`,
> or you get two competing owners of the same sockets/buffers.

## Authentication (opt-in, zero-config default)

- **No `LOGSIM_API_KEY` set** → the dashboard is fully open, exactly as before. Nothing to configure.
- **`LOGSIM_API_KEY` set** → every `/api/*` route requires the token. The browser UI still needs
  **no login**: the page receives the token at load time and attaches it automatically.
- External callers send the token as either header:
  - `X-API-Key: <token>`
  - `Authorization: Bearer <token>`
- Exempt (no token needed): `GET /` (the UI page), `GET /api/health` (liveness), `/static/*`.

> Tradeoff: this gates **automation**, not humans — anyone who can load `/` in a browser gets
> the token. Set a key whenever the dashboard is bound off-localhost.

## Versioned contract — `/api/v1`

External integrations should use `/api/v1/*` (the UI-shaped legacy `/api/*` routes may change).

| Method & path | Purpose |
|---|---|
| `GET  /api/v1/scenarios` | List scenarios (`[{id, name}]`) |
| `POST /api/v1/scenarios/{id}/run` | Trigger a scenario. Returns `202` + `{started, scenario, run_id}` |
| `GET  /api/v1/scenarios/runs` | List recent runs (newest first) |
| `GET  /api/v1/scenarios/runs/{run_id}` | Poll one run's status + emission manifest |
| `GET  /api/v1/modules` | List modules and their state |
| `POST /api/v1/modules/{name}/start` | Start a module. Body: `{threat_level?, event_interval?}` |
| `POST /api/v1/modules/{name}/stop` | Stop a module |
| `GET  /api/v1/modules/{name}/threats` | Event names this module can fire (the valid `fire` values) |
| `POST /api/v1/modules/{name}/fire` | Fire one event. Body: `{event}` |
| `PATCH /api/v1/modules/{name}/interval` | Change event interval. Body: `{event_interval}`. Applies live |
| `PATCH /api/v1/modules/{name}/threat_level` | Change threat level. Body: `{threat_level}`. Applies live |
| `POST /api/v1/modules/{name}/reset` | Reset one module's counters |
| `POST /api/v1/modules/start_all` / `stop_all` / `reset_all` | Bulk start / stop / reset counters |
| `GET  /api/v1/baduser/users` | Simulated identities grouped by department |
| `POST /api/v1/baduser/start` | Start a targeted insider-threat run. Body: `{username, duration_minutes?, threat_level?, event_interval?, selected_modules?}` |
| `POST /api/v1/baduser/stop` | Stop the active Bad User run (idempotent) |
| `GET  /api/v1/baduser/status` | Bad User progress: `remaining_seconds`, `per_module` tallies |
| `GET  /api/v1/threat_levels` | Valid threat-level names |
| `GET  /api/v1/health`, `GET /api/v1/metrics` | Status + throughput |
| `GET  /api/v1/health/alerts` | Drain queued health alerts — **destructive read**, see below |
| `GET  /api/v1/timeline` | 60×2s per-module sparkline buckets (sized for the UI chart) |

Two notes on the paths:

- **`/api/v1/modules/reset_all`** — the legacy route is `/api/reset_all` with no `/modules/`
  segment; v1 moves it under `/modules/` for symmetry with `start_all`/`stop_all`.
- **`GET /health/alerts` clears the queue it returns**, so each alert reaches exactly one
  caller. An open dashboard UI polls it too — the two of you will split the stream. Don't rely
  on it as a complete alert feed while someone has the UI open.

### Bad User vs. scenarios

A scenario is a one-shot sequence that ends on its own — `run_scenario` can wait for it and
hand back an emission manifest. Bad User is a *sustained* run: it drives the selected modules
as one named identity for 1–480 minutes, so `start` returns as soon as the run begins and
there is no wait-for-completion. Poll `GET /baduser/status` for `remaining_seconds` and the
per-module tallies. Only one Bad User run can be active at a time; a second `start` gets `409`.

### Run tracking

`POST /scenarios/{id}/run` is asynchronous (the scenario runs in a background thread) and
returns a `run_id`. Poll `GET /scenarios/runs/{run_id}`:

```json
{
  "run_id": "…", "scenario_id": "aws-pentest", "scenario_name": "AWS Pentest …",
  "status": "done",                     // queued | running | done | error
  "created_at": 1.7e9, "started_at": 1.7e9, "finished_at": 1.7e9, "error": null,
  "emitted": {                          // what LogSim SENT (populated when done)
    "total_events": 9,
    "by_module": { "Amazon AWS": 6, "Okta SSO": 1, "Cisco ASA": 2 },
    "by_event":  { "Amazon AWS/PENTEST_LAUNCH": 1, "…": 1 }
  }
}
```

> `emitted` is what LogSim **sent**, not what **fired/detected** in XSIAM. Detection outcome is
> the `logsim-xql-builder` side — bridge on the run's marker if you need closed-loop results.

### curl example

```bash
KEY=…   # omit the -H lines entirely if the dashboard is running open
run_id=$(curl -s -XPOST localhost:5000/api/v1/scenarios/aws-pentest/run \
           -H "X-API-Key: $KEY" | jq -r .run_id)
curl -s localhost:5000/api/v1/scenarios/runs/$run_id -H "X-API-Key: $KEY" | jq .status
```

## Postman & Swagger

The API is described by `openapi.yaml` (OpenAPI 3.0 — the successor to Swagger 2.0). Two ways
to get it into Postman:

- **Pre-built collection (easiest):** import `logsim.postman_collection.json`. It ships with
  `baseUrl` and `apiKey` collection variables and sends `X-API-Key: {{apiKey}}` on every request.
  Set `baseUrl` to your dashboard (default `http://127.0.0.1:5000/api/v1`) and, if auth is on,
  paste your token into `apiKey` — leave it blank when running open. Path params (e.g.
  `:scenario_id`) and example bodies are pre-filled.
- **From the spec:** in Postman, *Import → File →* `openapi.yaml`. Postman generates a collection
  and picks up the `{scheme}/{host}/{port}` server variables and the API-key security scheme.

The spec is the single source of truth; the collection is generated from it. After editing
`openapi.yaml`, regenerate:

```bash
python integrations/gen_postman_collection.py
```

You can also view it as interactive docs in any Swagger UI / Redoc (e.g. paste `openapi.yaml`
into https://editor.swagger.io).

## MCP server

`mcp_server.py` exposes the API as 20 MCP tools over stdio:

- **Scenarios** — `list_scenarios`, `run_scenario`, `get_run_status`, `list_runs`
- **Modules** — `list_modules`, `start_module`, `stop_module`, `list_module_threats`,
  `fire_event`, `set_module_interval`, `set_module_threat_level`, `reset_module_metrics`,
  `reset_all_metrics`
- **Bad User** — `list_users`, `start_bad_user`, `stop_bad_user`, `get_bad_user_status`
- **Status** — `list_threat_levels`, `get_status`, `get_health_alerts`

`/api/v1/timeline` has no tool: its 60-bucket × per-module payload is chart data, too bulky to
be useful in a tool result. Call it over HTTP if you need it.

```bash
pip install -r integrations/requirements.txt
LOGSIM_API_URL=http://127.0.0.1:5000 LOGSIM_API_KEY=<token> python integrations/mcp_server.py
```

`run_scenario(scenario_id, wait=True)` blocks until the run finishes and returns the emission
manifest — convenient for an agent that wants to generate traffic then act on the result.

Agents should discover values rather than guess them: `list_modules` for module names,
`list_module_threats` for a module's firable events, `list_threat_levels` for levels, and
`list_users` for Bad User targets.

### Tests

Two suites, neither of which needs an XSIAM tenant and neither of which emits log traffic
(`run_scenario`, `fire_event`, module start and `start_bad_user` are never called):

```bash
python tests/api_contract.py        # in-process, offline, ~seconds
python tests/mcp_server_smoke.py    # spawns a dashboard + the MCP server over real stdio
```

`api_contract.py` is the drift guard. `_register_v1_aliases()` resolves view functions **by
name** and only prints a warning when one is missing, so renaming a view would otherwise drop
a `/api/v1` route silently. The test diffs the registered routes against `openapi.yaml` in
both directions (paths *and* methods), confirms every declared alias registered, confirms each
alias still has its legacy `/api/*` twin, and confirms every path `mcp_server.py` calls really
exists. **Run it after touching the route table, the spec, or the MCP server.** If the
inventory has drifted it stops there and names the cause rather than emitting a cascade of 404s.

`mcp_server_smoke.py` covers the path an agent actually takes — separate dashboard process,
auth-gated HTTP, MCP server as a stdio child — and skips with exit 0 if the optional MCP SDK
isn't installed.

### Register with Claude Code

```json
{
  "mcpServers": {
    "logsim": {
      "command": "python",
      "args": ["integrations/mcp_server.py"],
      "env": {
        "LOGSIM_API_URL": "http://127.0.0.1:5000",
        "LOGSIM_API_KEY": "<token or empty>"
      }
    }
  }
}
```
