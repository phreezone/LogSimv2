# XDR Attack Orchestration

**Type:** Coordinator / scenario (not a `generate_log` data-source module)
**Transport:** WinRM to the target box (pywinrm) + LogSim's existing network transports
**Status:** Phase 1 — foundation built and validated against a live box; executor / stories / orchestrator in progress

Unlike every other module, this one does **not** fake telemetry. It triggers *real* [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam) techniques on a *real* Windows workstation running the **Cortex XDR agent** — so XSIAM's agent-bound **endpoint** behavioral analytics genuinely fire — while LogSim emits **synthetic network logs pinned to that same box's real host/user/IP** and timed around the real activity. XSIAM then stitches endpoint + network into one coherent incident. An XSIAM management-API key can flip the agent between alerting and blocking.

This closes the one gap synthetic feeds can't: the Cortex agent's own data model can only be driven by real endpoint activity.

- **Package:** `modules/xdr_orchestration/` (a package, not a generator — the loader only scans top-level `modules/*.py`, so nothing here is startable as a data source)
- **Reached only through** `WorkstationConnection` (`connection.py`) — the single, fail-closed path to the box
- **Registered** (once complete) as a scenario in `get_scenarios()`, so it flows through the existing run-tracking + transports unchanged

---

## Configuration — everything lives in `.env`

**You never edit `config.json` to point at a box.** All deployment-specific values are read from `.env` under fixed variable names; `config.json` holds only structural defaults and a dev-only stub identity.

### `.env` (the only file you touch)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `XDR_TARGET_HOST` | live box | — | Box IP or hostname |
| `XDR_TARGET_WINRM_USER` | live box | — | Local-admin username (no `DOMAIN\` prefix for a workgroup box) |
| `XDR_TARGET_WINRM_PASSWORD` | live box | — | Local-admin password |
| `XDR_TARGET_WINRM_PORT` | no | `5985` | WinRM port |
| `XDR_TARGET_WINRM_SCHEME` | no | `http` | `http` (5985) or `https` (5986) |
| `XDR_TARGET_WINRM_AUTH` | no | `ntlm` | `ntlm` \| `basic` \| `kerberos` |
| `XDR_TARGET_TRANSPORT` | no | `winrm` | Set to `stub` for no-box development (uses `config.json` `stub_identity`) |
| `XDR_TARGET_EGRESS_IP` | no | — | Org NAT/public IP that external-facing logs (Zscaler, perimeter FW) should carry; discovery only knows the internal IP |
| `XDR_EMAIL_DOMAIN` | no | — | Derive user email when discovery can't |
| `XSIAM_API_BASE` / `XSIAM_API_KEY_ID` / `XSIAM_API_KEY` | policy control only | — | Cortex `/public_api` management key for agent alert↔block + read-back |

The variable *names* are defined once as `ENV_*` constants on `WorkstationConnection` in `connection.py`.

### `config.json` — structural only (no target values)

```json
"xdr_orchestration": {
  "connection": {
    "transport": "winrm",
    "stub_identity": {
      "username": "labuser", "hostname": "lab-wks01.corp.example",
      "ip": "192.168.0.60", "department": "Finance", "email": "labuser@corp.example"
    }
  },
  "xsiam": {
    "api_base_env_var": "XSIAM_API_BASE",
    "key_id_env_var": "XSIAM_API_KEY_ID",
    "key_env_var": "XSIAM_API_KEY"
  }
}
```

`transport` here is only a default — `XDR_TARGET_TRANSPORT` in `.env` overrides it. `stub_identity` is used only when transport is `stub`.

---

## Preflight (fail-closed health gate)

The orchestrator refuses to fire any technique unless `WorkstationConnection.preflight()` passes. Phase-1 checks:

| Check | What it verifies |
|---|---|
| **WinRM reachable + auth** | TCP to the port is open, then a `whoami` round-trips under the configured credentials |
| **Identity discovery** | The live box reports a logged-in user + hostname + primary IPv4 (the triad the synthetic logs will carry) |
| **Atomic present** | `Invoke-AtomicTest` is importable on the target |
| **Cortex agent healthy** | The `cyserver` service is installed and Running (else no endpoint telemetry) |
| **XSIAM API reachable** | Only when policy control is requested for the run |

### Run it

```bash
# Live box (reads .env):
python tests/xdr_preflight_check.py

# No-box dev (uses config.json stub_identity):
python tests/xdr_preflight_check.py --stub

# Machine-readable:
python tests/xdr_preflight_check.py --json
```

Exit code is `0` only when preflight is GREEN, so the harness doubles as a gate. Example live output:

```
Preflight: RED — orchestrator will refuse to fire
  ✓ WinRM reachable + auth: PASS — authenticated as windows10-works\eric
  ✓ Identity discovery: PASS — user=eric host=windows10-works ip=192.168.0.44
  ✗ Atomic present: FAIL — Invoke-AtomicTest not importable — install Invoke-AtomicRedTeam
  ✓ Cortex agent healthy: PASS — cyserver service Running
```

---

## Preparing a box

WinRM must be enabled and Atomic installed before preflight goes green. A console-generated **Kickstarter** will automate this (planned); until then:

1. **Enable WinRM** — copy `docs/enable-winrm-on-box.ps1` to the box and run it **elevated**. It turns on WinRM, scopes the firewall rule to the LogSim console IP (edit `$ConsoleIP` — for a VMware VM use the VMnet host adapter IP), and sets `LocalAccountTokenFilterPolicy=1` so a local admin gets a full token remotely (needed for admin-level Atomic tests). It ships with rollback notes.
2. **Install Atomic** — run `docs/install-atomic-on-box.ps1` (elevated on the box, or over WinRM from the console). It is **fully non-interactive**: it pre-installs the **NuGet provider**, **trusts PSGallery**, and pre-satisfies `powershell-yaml` so `Install-AtomicRedTeam` never stops on the "NuGet provider is required" / "Untrusted repository" approvals that otherwise block automation (and silently fail over WinRM). It then installs Invoke-AtomicRedTeam + the atomics and verifies `Invoke-AtomicTest` resolves. Idempotent.
   > **Cortex will quarantine the drops** unless you first allow-list the Atomic paths (or set the endpoint's prevention profiles to Report mode) — see [Cortex prevention & Atomic drops](#cortex-prevention--atomic-drops) below.
3. **Verify the Cortex agent** is installed and `cyserver` is Running.

### Cortex prevention & Atomic drops

Cortex XDR's malware/WildFire and Behavioral Threat Protection will flag or quarantine Atomic payloads as they land. To let the files drop **while preserving the endpoint alerts this module depends on**, prefer **Report (alert-only) mode over Disabled**:

- **Path allow-list** (surgical) — in **Endpoints → Policy Management → Prevention → Profiles**, add the Atomic locations to the Malware profile allow-list: `C:\AtomicRedTeam\`, `C:\Users\<user>\AppData\Local\Temp\`, and the `...\WindowsPowerShell\Modules\invoke-atomicredteam\` path. Everything outside those paths still protects/alerts.
- **Report-mode endpoint group** (for actual runs) — put the target in its own group with Malware / Exploit / BTP profiles set to **Report**, so techniques execute and real alerts still fire for XSIAM to correlate.
- If a specific payload is quarantined by hash even with the path allow-list, add a **hash allow-list** entry or drop that technique from the story.

> Fully disabling prevention removes the endpoint telemetry that is the whole point of this module. Automating this alert↔block flip via `/public_api` is the planned job of `xsiam_client.py` (verify the tenant's actual policy-API surface before coding against it).

> **Lab-only, security-sensitive tooling.** Use a dedicated, authorized demo box. Curate techniques to non-destructive, cleanup-capable Atomics.

---

## Identity discovery → synthetic-log seed

`connection.discover_identity()` queries the live box and returns the ground-truth triad (logged-in user, hostname/FQDN, primary IPv4) in the same shape `session_utils.get_user_by_name` yields. Those discovered facts seed **all** synthetic generation — bypassing `session_utils` randomization — so the project works on anyone's box with zero renaming. `.env` overrides (`XDR_TARGET_EGRESS_IP`, `XDR_EMAIL_DOMAIN`) win over discovery. Discovery yields the box's **internal** IP (correct for internal firewall/DNS logs); external-facing logs need the org's NAT/egress IP via `XDR_TARGET_EGRESS_IP`.

---

## Roadmap

- **Phase 1 (in progress):** `connection.py` ✅ → `executor.py` (WinRMAtomic + DryRun) → one reference story → `orchestrator.py`; `/api/v1/attack/*` routes.
- **Phase 2:** data-driven story files, closed-loop incident pull-back, tighter time alignment, MCP tools, the Kickstarter installer.
- **Phase 3:** more executors (Caldera, SSH/Kali), multi-host lateral-movement stories.
