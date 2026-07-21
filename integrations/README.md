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
| `POST /api/v1/modules/{name}/fire` | Fire one event. Body: `{event}` |
| `POST /api/v1/modules/start_all` / `stop_all` | Bulk start/stop |
| `GET  /api/v1/health`, `GET /api/v1/metrics` | Status + throughput |

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

`mcp_server.py` exposes the API as MCP tools (`list_scenarios`, `run_scenario`,
`get_run_status`, `list_runs`, `list_modules`, `start_module`, `stop_module`, `fire_event`,
`get_status`) over stdio.

```bash
pip install -r integrations/requirements.txt
LOGSIM_API_URL=http://127.0.0.1:5000 LOGSIM_API_KEY=<token> python integrations/mcp_server.py
```

`run_scenario(scenario_id, wait=True)` blocks until the run finishes and returns the emission
manifest — convenient for an agent that wants to generate traffic then act on the result.

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
