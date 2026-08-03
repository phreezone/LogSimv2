# Windows Event Log Module

**Dataset:** `microsoft_windows_raw`
**Transport:** WEC (Windows Event Collector) — direct WS-Management over mutual TLS
**Format:** native Windows Security Event XML (`<Event>` … `<System>` / `<EventData>`)

Generates native Windows Security-channel Event XML targeting XSIAM's Identity Analytics (UEBA) engine and endpoint detections. Events are delivered to the Broker VM via the **WEC** transport (WS-Management / HTTPS 5986, mutual-TLS client certificate) — the same protocol as Windows Event Forwarding (WEF) source-initiated subscriptions. Because LogSim builds the SOAP/XML envelopes directly, it can simulate events from hundreds of distinct hostnames on a single machine (each event carries its own `<Computer>` field) — something native WEF cannot do.

- **Rendering:** `_render_event_xml()` uses `lxml` for correct namespace/prefix control and single-quoted attributes, matching real Windows XML byte-for-byte (lowercase GUIDs, nanosecond timestamps, `%%` message codes).
- **Event modeling:** every record is built through `_build_event(event_id, computer, event_data, …)` so `microsoft_windows_raw` modeling rules, correlation rules, and UEBA analytics process it identically to real WEC-collected events. `_raw_log` is the Windows Event **XML** (not JSON) — extract fields with `regextract(_raw_log, "Name='<Field>'>([^<]+)<")`.
- **Covered Event IDs:** 4624, 4625, 4634, 4647, 4648, 4656, 4662, 4663, 4672, 4688, 4689, 4697, 4720, 4722, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4741, 4742, 4756, 4757, 4767, 4768, 4769, 4771, 4776, 4886, 4887, 4888, 5136, 5137, 1102.

> **WEC subscription filter:** the Broker VM's WEC subscription must **forward the Event IDs** LogSim emits for them to reach XSIAM. If a newly added Event ID (e.g. 1102) doesn't appear in search, confirm it's in the subscription's query filter. See **WEC Transport Setup** in the [README](../../README.md) for broker configuration.

---

## Benign Events

20 benign generators establish the baseline that UEBA analytics train against. They cover:

| Category | Patterns |
|---|---|
| Authentication | interactive logon (4624 type 2), network logon (type 3), remote/RDP (type 10), service (type 5), cached (type 11), unlock (4624 type 7), logoff (4634/4647), failed logon (4625) |
| Kerberos / DC | TGT request (4768), service ticket (4769), pre-auth failure (4771), NTLM validation (4776), special-privilege logon (4672) |
| Directory service | LDAP bind, directory-service access (4662), directory-service changes (5136/5137 with proper `%%14674`/`%%14675` add/delete pairs) |
| Process / app | process creation (4688), SQL and web-app service access |

---

## AD / Identity Threat Scenarios

Named threat generators (via `scenario_event` = the key below, or fired individually). 13 trigger XSIAM Identity Analytics detections out of the box; 8 (`wip_` prefix) generate correct events but depend on an identity-graph baseline or are still under investigation.

**Confirmed detections:**

> **Names verified against live alerts on 2026-07-30** via
> `python tests/detector_loop.py --controls` (see [Detector Test Loop](../detector-test-loop.md)).
> Eight of the names previously in this table were wrong — the tenant's wording differs
> from the detector's description. Do not re-transcribe them by hand; re-run the sweep.

| Generator (`scenario_event`) | XSIAM Detection (as the tenant fires it) | Source | Verified |
|---|---|---|---|
| `DCSYNC` | Possible DCSync by an unusual user | Analytics BIOC | ✅ |
| `DELEGATION_CHANGE` | User account delegation to KRBTGT | Analytics BIOC | ✅ |
| `DNSHOSTNAME_SPOOFING` | Suspicious dNSHostName attribute change to DC name | Analytics BIOC | ✅ |
| `SAMACCOUNTNAME_SPOOFING` | Service ticket request with a spoofed sAMAccountName | Analytics BIOC | ✅ |
| `PRIV_GROUP_ADDITION` | User added to a Windows privileged group | Analytics BIOC | ✅ |
| `ACCOUNT_LOCKOUT` | Multiple user accounts failed login due to account lockouts | XDR Analytics | ✅ |
| `DEFAULT_ACCOUNT_ENABLED` | A user enabled the Windows DefaultAccount | Analytics BIOC | ✅ |
| `SUSPICIOUS_ACCOUNT_CREATION` | Suspicious hidden user created | Analytics BIOC | ✅ |
| `MASS_ACCOUNT_DELETION` | A user deleted multiple users for the first time | XDR Analytics | ✅ |
| `MULTIPLE_SERVICE_TICKETS` | *(re-test pending)* | — | ⏳ |
| `SUSPICIOUS_ACCOUNT_LOCKOUT` | *(re-test pending)* | — | ⏳ |
| `PRIV_GROUP_ADD_REMOVE` | **no alert** — events ingest, detector silent | — | ❌ |
| `SMS_ADMINS_ADDITION` | **no alert** — events ingest, detector silent | — | ❌ |

The last two were previously listed as confirmed detections. They are not: their events
ingest correctly and no alert is produced within a 10-minute window. Treat them as WIP.

**WIP** (events ingest correctly; detection pending baseline/investigation): `WIP_ADMINSDHOLDER_ACL_MODIFICATION`, `WIP_DMSA_PRIVESC`, `WIP_SENSITIVE_PASSWORD_RESET`, `WIP_PASSWORD_NEVER_EXPIRES`, `WIP_AS_REP_ROASTING`, `WIP_IRREGULAR_SERVICE_TGS`, `WIP_PRIV_CERT_REQUEST`, `WIP_SCCM_CONTAINER_RECON`.

---

## Endpoint Execution, Persistence & Anti-Forensics

Added for the advanced linked kill chains (Beaconing Implant, Domain Dominance). All are Security-channel events that ingest and parse in `microsoft_windows_raw`.

| `scenario_event` | Event | Description | Key Fields |
|---|---|---|---|
| `PROCESS_TREE` (`MALWARE_EXECUTION`) | 4688 ×4 | A linked process tree — `WINWORD.EXE` → hidden-PowerShell → `cmd.exe` → LOLBin (`certutil` download, or `vssadmin`/`wbadmin` shadow-delete). Each stage's `ParentProcessName` is the prior stage, with realistic command lines. Returns a list. | `NewProcessName`, `ParentProcessName`, `CommandLine` |
| `SERVICE_INSTALL` (`IMPLANT_SERVICE`) | 4697 | A service was installed (malware persistence). Subject defaults to SYSTEM (SCM-brokered); suspicious `ServiceFileName` paths (Temp/Public/encoded PowerShell); auto-start. | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType` |
| `CLEAR_LOGS` (`LOG_CLEARED`) | 1102 | The Security audit log was cleared (anti-forensics finale). | `SubjectUserName`, `SubjectDomainName` |
| `NETWORK_LOGON` (`WORKSTATION_LOGON`) | 4624 type 3 | A network logon carrying an explicit source IP — used as an **IP↔user binding** so IP-keyed detections (DNS/SMB) can join to resolve the user for full alert enrichment. | `IpAddress`, `TargetUserName`, `LogonType` |

---

## Scenario Events

The `scenario_event` parameter in `generate_log(config, scenario_event=…, context=…)` drives kill-chain integration. `context` accepts `session_context`, `user_identity` (resolve a specific user), `src_ip` (bind/network-logon source), and `hostname`.

| `scenario_event` | Purpose |
|---|---|
| `LOGIN` / `LOGIN_SUCCESS` | 4624 type-2 interactive logon |
| `LOGIN_FAILURE` / `LOGIN_FAILED` | 4625 failed logon |
| `NETWORK_LOGON` | 4624 type-3 network logon with a pinned source IP (IP↔user binding) |
| `LOGOFF` | 4634 logoff correlated to an open session |
| `LOCKOUT` | 4740 account lockout |
| `KERBEROS_TGT` | 4768 TGT request |
| `SERVICE_INSTALL` | 4697 service installed (persistence) |
| `PROCESS_TREE` | 4688 execution tree (initial access) |
| `CLEAR_LOGS` | 1102 log cleared (anti-forensics) |
| *any threat key* | e.g. `DCSYNC`, `MULTIPLE_SERVICE_TICKETS`, `DELEGATION_CHANGE` — see AD/Identity table above |

Multi-event generators (process trees, some threats) return a Python **list** of JSON records; `process_and_send()` renders each to XML and delivers it over WEC. Standalone runs that emit fewer than a full WEC batch should call `_flush_wec_batch(config)` on completion (the dashboard scenario wrapper does this automatically).

---

## Transport Setup

WEC broker configuration (certificate export, subscription URL, subscription filter) is documented in **WEC Transport Setup** in the [README](../../README.md#wec-transport-setup). In brief: the Broker VM's Windows Event Collector must be activated, and LogSim's `.env` must supply `WEC_BROKER_URL`, `WEC_PFX_PATH`, and `WEC_PFX_PASSWORD`.
