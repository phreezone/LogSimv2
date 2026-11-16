# Windows Event Log Module

**Dataset:** `microsoft_windows_raw`
**Transport:** WEC (Windows Event Collector) — direct WS-Management over mutual TLS
**Format:** native Windows Security Event XML (`<Event>` … `<System>` / `<EventData>`)

Generates native Windows Security-channel Event XML targeting XSIAM's Identity Analytics (UEBA) engine and endpoint detections. Events are delivered to the Broker VM via the **WEC** transport (WS-Management / HTTPS 5986, mutual-TLS client certificate) — the same protocol as Windows Event Forwarding (WEF) source-initiated subscriptions. Because LogSim builds the SOAP/XML envelopes directly, it can simulate events from hundreds of distinct hostnames on a single machine (each event carries its own `<Computer>` field) — something native WEF cannot do.

- **Rendering:** `_render_event_xml()` uses `lxml` for correct namespace/prefix control and single-quoted attributes, matching real Windows XML byte-for-byte (lowercase GUIDs, nanosecond timestamps, `%%` message codes).
- **Event modeling:** every record is built through `_build_event(event_id, computer, event_data, …)` so `microsoft_windows_raw` modeling rules, correlation rules, and UEBA analytics process it identically to real WEC-collected events. `_raw_log` is the Windows Event **XML** (not JSON) — extract fields with `regextract(_raw_log, "Name='<Field>'>([^<]+)<")`.
- **Covered Event IDs:** 4624, 4625, 4634, 4647, 4648, 4656, 4662, 4663, 4672, 4688, 4689, 4697, 4720, 4722, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4741, 4742, 4756, 4757, 4767, 4768, 4769, 4771, 4776, 4781, 4886, 4887, 4888, 5136, 5137, 1102.

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

Named threat generators (via `scenario_event` = the key below, or fired individually). The 19 in the table below target published analytics; 7 more, added on 2026-11-01, cover AD identity attacks; 5 (`wip_` prefix) generate correct events but depend on an identity-graph baseline or are still under investigation.

**Detections:**

> The names are XSIAM's alert wording, which can differ from a detector's description, so
> don't re-transcribe them by hand. `_local_validation/threat_harness.py` does fire → ingest
> → detect validation, with `win:` keys for on-prem threats.

| Generator (`scenario_event`) | XSIAM Detection | Source |
|---|---|---|
| `DCSYNC` | Possible DCSync by an unusual user | Analytics BIOC |
| `DELEGATION_CHANGE` | User account delegation to KRBTGT | Analytics BIOC |
| `DNSHOSTNAME_SPOOFING` | Suspicious dNSHostName attribute change to DC name | Analytics BIOC |
| `SAMACCOUNTNAME_SPOOFING` | Service ticket request with a spoofed sAMAccountName | Analytics BIOC |
| `PRIV_GROUP_ADDITION` | User added to a Windows privileged group | Analytics BIOC |
| `ACCOUNT_LOCKOUT` | Multiple user accounts failed login due to account lockouts | XDR Analytics |
| `DEFAULT_ACCOUNT_ENABLED` | A user enabled the Windows DefaultAccount | Analytics BIOC |
| `SUSPICIOUS_ACCOUNT_CREATION` | Suspicious hidden user created | Analytics BIOC |
| `MASS_ACCOUNT_DELETION` | A user deleted multiple users for the first time | XDR Analytics |
| `MULTIPLE_SERVICE_TICKETS` | Abnormal issuance of weakly encrypted service tickets to a user | XDR Analytics |
| `SUSPICIOUS_ACCOUNT_LOCKOUT` | Excessive account lockouts on suspicious users | XDR Analytics |
| `PRIV_GROUP_ADD_REMOVE` | Rare privileged group addition and removal | XDR Analytics |
| `SMS_ADMINS_ADDITION` | User added to the SMS Admins local group | XDR Analytics |
| `SMS_ADMINS_ADD_REMOVE` | User added to the SMS Admins group and removed | XDR Analytics |
| `IRREGULAR_TGT_BURST` | A user sent an excessive number of TGT requests to irregular services | XDR Analytics |
| `MACHINE_ACCOUNT_TO_DOMAIN_ADMINS` | Machine account was added to a domain admins group | Analytics BIOC |
| `AS_REP_ROASTING` | An excessive number of TGT requests were sent for users that do not require Kerberos pre-authentication | XDR Analytics |
| `DMSA_PRIVESC` | Possible Privilege Escalation using Delegated MSA account attempt | XDR Analytics |
| `SENSITIVE_PASSWORD_RESET` | Sensitive account password reset attempt for the first time | Analytics BIOC |

`AS_REP_ROASTING`, `DMSA_PRIVESC` and `SENSITIVE_PASSWORD_RESET` dropped their `WIP_`
prefix; the old `WIP_` names still dispatch.

**WIP** (events are correctly shaped; the detection depends on an identity-graph baseline or is still under investigation): `WIP_ADMINSDHOLDER_ACL_MODIFICATION`, `WIP_PASSWORD_NEVER_EXPIRES`, `WIP_PRIV_CERT_REQUEST`, `WIP_SCCM_CONTAINER_RECON`, and `WIP_IRREGULAR_SERVICE_TGS` — which only ever raises the weak-encryption alert owned by `MULTIPLE_SERVICE_TICKETS`, so it is background-only (`IRREGULAR_TGT_BURST` covers its intended detection).

`WIP_ADMINSDHOLDER_ACL_MODIFICATION` is now blocked on **object resolution**, not
event shape: the Identity Analytics engine only evaluates a 5136 attribute change
on a target it can resolve to an account, and AdminSDHolder is a `container`. See
"Target object must resolve to an entity" below. `WIP_SCCM_CONTAINER_RECON`
targets another `container` DN and is expected to share that blocker.

**On-demand firing** offers the threats in the module's `ANALYTIC_ALERTS` table: everything
above plus the four remaining `WIP_` detections, which target published analytics. Not
offered, background-only: `WIP_IRREGULAR_SERVICE_TGS`, `LSASS_HANDLE_ACCESS` (an XDR-agent
detection, not a Windows Event Collector analytic) and `ACCOUNT_ACCESS_REMOVAL` (no
matching published analytic).

### New AD Identity Generators (Added 2026-11-01)

Seven generators cover AD identity attacks that previously had no producer. The event
shapes follow Microsoft's documented field layout and the AD schema GUIDs were read from
Microsoft Learn on 2026-11-01.

Attribute-change detectors emit **both** the 5136 old→new pair and the 4662
write-property event (with the attribute's schema GUID), plus a state-carrying 4738/4742
where one exists. This is deliberate: repo notes disagree on whether 5136 reaches XSIAM's
WEC intake, so the 4662 corroboration keeps the signal alive either way.

| Generator (`scenario_event`) | Event sequence | Target analytic |
|---|---|---|
| `shadow_credentials` | 4624 ×2, 4672, 4688 (Whisker/Certipy), 5136 `msDS-KeyCredentialLink` added, 4662 write-property, 4768 PKINIT TGT, 4769, 4689 | Possible shadow credentials addition (Medium); Key credential attribute addition (Low) |
| `pkinit_auth` | 4768 with `PreAuthType: 15` (Microsoft's documented smart-card value; 16/17 are the other PKINIT codes), `PreAuthEncryptionType: 0x12`, and certificate issuer/serial/thumbprint fields, 4624 ×2, 4672, 4769 | Suspicious PKINIT TGT authentication request |
| `sid_history_injection` | 4624 ×2, 4672, 4688, 5136 `sIDHistory` added, 4662 write-property, 4738 carrying `SID History`, 4768, 4689 | Suspicious SID History Addition |
| `adfs_dkm_access` | 4624 ×2, 4672, 4688, 4662 read of `CN=DKM,CN=ADFS,CN=Microsoft,CN=Program Data` (`thumbnailPhoto` GUID, `AccessMask 0x10`), 4689 | ADFS DKM Key Access |
| `kerberos_relay` | 4768 for `<HOST>$` from the attacker IP, DC 4624, 4769, endpoint 4624 type 3 Kerberos from `127.0.0.1` as the **local** `Administrator` (`S-1-5-21-*-500`, non-zero `IpPort`, target never a DC), 4672, 4688, 4689 | Possible Kerberos relay attack |
| `spn_cleared` | 4624 ×2, 4672, 4688, 5136 ×2 (SPNs cleared on a machine account), 4662, 4742, 4689 | SPNs cleared from a machine account for the first time |
| `suspicious_sam_change` | 4624 ×2, 4672, 4688, 5136 ×2 (sAMAccountName → DC hostname), 4662, 4742, 4768, 4689 | Suspicious sAMAccountName change to DC hostname; related "TGT request with a spoofed sAMAccountName" |

Verified AD schema GUIDs used by the 4662 events: key credential
`5b47d60f-6090-40b2-9f37-2a4de88f3063`, sIDHistory
`17eb4278-d167-11d0-b002-0000f80367c1`, servicePrincipalName
`f3a64788-5306-11d1-a9c5-0000f80367c1`, sAMAccountName
`3e0abfd0-126a-11d0-a060-00aa006c33ed`, thumbnailPhoto
`8d3bca50-1d7e-11d0-a081-00aa006c33ed`.

Two shapes were inferred rather than documented. The ADFS DKM 4662
(`thumbnailPhoto` GUID with `AccessMask 0x10`) is inferred.
`kerberos_relay` is no longer inferred: the endpoint 4624 now follows the published
KrbRelayUp signature — EventID 4624, `LogonType 3`,
`AuthenticationPackageName Kerberos`, `IpAddress 127.0.0.1`, `TargetUserSid`
`S-1-5-21-*-500`, non-zero `IpPort`, and no domain-controller target — which is the
detection block of Sigma rule `749c9f5e-b353-4b90-a9c1-05243357ca4b`
("Potential Privilege Escalation via Local Kerberos Relay over LDAP") and Splunk
`8309c3a8-4d34-48ae-ad66-631658214653` ("Windows Kerberos Local Successful Logon").
The relayed ticket is modelled as the target's *machine-local* Administrator
(`S-1-5-21-<machine>-500`, `TargetDomainName` = the computer name), not the domain SID.

`samaccountname_spoofing` and `dnshostname_spoofing` also gained secondary claims for the
attribute-change analytics above, and `multiple_service_tickets` now lists
"A user requested multiple service tickets" alongside its weak-encryption primary.

### Live verification (2026-11-10)

Two of the seven AD identity generators were confirmed end-to-end against the
tenant. Three others (`pkinit_auth`, `spn_cleared`, `kerberos_relay`) and the
three mailbox generators emit correctly shaped events but produced **no** alert
after three or more isolated probe batches each, so they are **WIP**.
(`sid_history_injection` and `adfs_dkm_access` were not part of this probe.)

| Generator | Status | Evidence |
|---|---|---|
| `shadow_credentials` | **Confirmed** | Medium "Possible shadow credentials addition" fired 2026-11-08 and again 2026-11-10 04:46Z on `WEB43$`/`BACKUP31$` (actors `j.fedorov2`, `o.curtis`). A length sweep proved the Medium variation is selected by the 5136 `AttributeValue` DN-Binary length: only `B:828:` fires Medium; every other length fires the Low "Key credential attribute addition" variation. The generator therefore emits an 828-hex-character KEY_CREDENTIAL blob. |
| `suspicious_sam_change` | **Confirmed** | Low "Suspicious sAMAccountName change" fired 2026-11-08 18:59Z. The state-carrying **4781** rename record is what the analytic keys on, not the 4742 alone. The Medium "to DC hostname" variation is not selected by `NewTargetUserName=DC01` alone; its discriminator remains unknown. |
| `pkinit_auth` | **WIP** | 4 batches, 0 alerts. Tried the Microsoft-documented smart-card shape (4768 `PreAuthType=15`, `PreAuthEncryptionType=0x12`, cert issuer/serial/thumbprint), `PreAuthType` 14/16/17, rogue and enterprise issuers, short/full issuer DN, machine and user targets, missing cert, `4771` failure, `TicketOptions=0x60810010`, loopback `::1`, realm-qualified `ServiceName`, and a 4768 correlated with a preceding `msDS-KeyCredentialLink` write. All shapes ingested with the fields intact in both `microsoft_windows_raw` and `xdr_data`. |
| `spn_cleared` | **WIP** | 5 batches, 0 alerts. Tried 4742 `ServicePrincipalNames` empty / `-` / absent, 5136 `%%14675` delete pairs, 5136 `%%14674` add-with-empty-value, 4662 write-property, and a same-account state transition (4742 with real SPNs, then 4742 with `-`). Batches 4–5 added the missing realism: `UserAccountControl` `%%2080` / `0x1000` (instead of `-`), the "only SPN changed" 4742 shape (`SamAccountName`/`DnsHostName` left as `-`), a real tenant asset (`FS01$`) as well as a new machine, and deleted-value renderings `-` / empty / absent. All shapes ingested; none alerted. Batch 6 re-ran the module's full sequence after the CRLF fix (9 events, real CRLF) — still 0 alerts. |
| `kerberos_relay` | **WIP** | 7 batches, 0 alerts. Tried the published KrbRelayUp endpoint signature alone (4624 type 3, Kerberos, local Administrator RID 500, loopback) with `127.0.0.1` / `::1` / `::ffff:127.0.0.1` and `WorkstationName` `FS01` / `-`, then the full sequence 4768 → DC 4624 → 4769 → endpoint 4624 → 4672 → 4688 → 4689 against the real `FS01` asset. Batch 4 varied the target SID (machine-local vs synthetic-domain vs the tenant's real domain `S-1-5-21-2795392456-4107320412-3908095700` Administrator), the subject (machine account + `0x3e7` + `lsass.exe` vs anonymous `S-1-0-0`), and the target host (`FS01` vs `DC01`); all six events ingested with the fields intact and produced no alert. **Batches 5–7 ran after the CRLF fix below.** The stored `action_evtlog_message` now carries real CRLF (58–59 per 4624, 0 bare LF) and the published XQL hunt for this analytic returns the synthetic rows verbatim (`auth_package=Kerberos`, `logon_type=3`, `network=127.0.0.1`, `sid` ending `-500`). Batch 6 covered machine-local and real-domain Administrator SIDs; batch 7 fired the module's own full 7-event sequence against `SQL01`. Neither the Cribl receiver path nor attributing the WEC event to a real agent hostname (`Windows10-Workstation1`) changed anything — both still land as `EVENT_LOG_DOMAIN_CONTROLLER` with null `agent_ip_addresses`/`identity_enrichment`. That collector class is now the standing blocker: real agent 4624s are stamped `EVENT_LOG_AGENT_EVENT_LOG`, and no WEC/Cribl record can be. See "event_sub_type: WEC vs agent" below. |
| `adminsdholder_acl_modification` | **WIP** | 2 batches, 0 alerts. Batch 1 delivered the canonical shape — 5136 `nTSecurityDescriptor` pair on `CN=AdminSDHolder,CN=System,DC=examplecorp,DC=local` with `ObjectClass=container`, `OperationType` `%%14675`/`%%14674` under one `OpCorrelationID`, and a new ACE `(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<user SID>)` (Full control for a non-machine principal), plus the 4662 read `0x10`, WRITE_DAC `0x40000` and write-property `0x20` legs. This matches the published logic for the same detection (Splunk ESCU `00d877c3-7b7b-443d-9562-6b231e2abab9`: `EventCode=5136 ObjectClass=container ObjectDN="CN=AdminSDHolder,CN=System*"`, new ACE with Full control). Every field verified in `xdr_data`. Batch 2 was a differential probe; see "Target object must resolve to an entity" below. |
| `mailbox_export`, `mailbox_export_log_removal`, `mailbox_cas_change` | **WIP** | 3 batches, 0 alerts. Tried 4104 `ScriptBlockText` carrying `New-MailboxExportRequest` / `Remove-MailboxExportRequest` / `Set-CASMailbox`, 4688 process creation, and native `MSExchange Management` EventID 1 `CmdletName`/`CmdletParameters` (simple and full field sets: `ObjectModified`, `User`, `Organization`, `OriginatingServer`, `Succeeded`, `RunspaceId`, `Timestamp`). The `MSExchange Management` channel **does** ingest and normalize (`microsoft_windows_raw` → `xdr_data`, `action_evtlog_event_id=1`), so channel availability is not the blocker. |

What was ruled out as a common cause:

- **Ingestion/normalization** is not the blocker: WEC events reach both
  `microsoft_windows_raw` and the normalized `xdr_data` dataset with
  `event_sub_type=EVENT_LOG_DOMAIN_CONTROLLER`, and `action_evtlog_data_fields`
  carries the original EventData. The "excessive TGT requests without
  pre-authentication" analytic fires on the same WEC 4768 events
  (`PreAuthType=0`), so 4768 processing works.
- **Training period** is not the blocker: every one of these analytics, including
  the two that fire, lists Training Period 30 Days.
- **Activation state** could not be read: `analytics/*`, `detection_rules/*`,
  `correlation_rules/*` and `content/*` public-API endpoints return HTTP 500, the
  metadata datasets return HTTP 403, and the tenant UI requires SSO/CSP sign-in.
  The remaining explanation for the WIP set is therefore either an undiscovered
  discriminator or the analytics being disabled in the tenant.
- **Windows 4624 may not be a usable trigger source through this WEC collector.**
  Every event the collector delivers — including workstations such as
  `IT-WS-018`, `CS-LT-001` and `fs01` — is tagged
  `event_sub_type=EVENT_LOG_DOMAIN_CONTROLLER`, and the Splunk analogue of the
  relay rule explicitly excludes domain controllers. WEC 4624 records also carry
  **no** normalized logon fields: all `xdm.*` (including `xdm.logon.type`,
  `xdm.source.ipv4`) are null and only the raw `action_evtlog_data_fields` JSON is
  populated. Directory-service analytics (5136 `msDS-KeyCredentialLink`, 4781
  rename) and Kerberos-ticket analytics (4768/4769) do fire on this same
  collector, but **no** 4624-based analytic has ever fired in the tenant
  (274 BIOC alert groups, and across the 900 most recent analytics alerts the
  only referenced Windows events were 5136, 4781, 4720, 4728 and 4768 — never
  4624). That points at 4624 handling, not at the relay discriminator, as the
  hard blocker.

### Target object must resolve to an entity (2026-11-16)

`wip_adminsdholder_acl_modification` is the first case where the blocker is
**not** the event shape. The published page puts it in the **Identity Analytics**
module, the same module as two analytics that do fire here (`User added SID
History to an account`, `Key credential attribute modification`), so the module
itself is live.

Batch 2 was a differential probe: the two 5136 attributes that fire today were
retargeted at the AdminSDHolder container and everything else was left alone.

| Probe (all delivered, all verified in `xdr_data`) | Alerts |
|---|---|
| 5136 `sIDHistory` on `CN=AdminSDHolder,CN=System,...`, `ObjectClass=container` | 0 |
| 5136 `msDS-KeyCredentialLink` on the same DN, `ObjectClass=container` | 0 |
| 5136 `nTSecurityDescriptor` pair on the same DN (attempt 2 of the target) | 0 |
| **Positive control, same generator run 9 min later:** 5136 `sIDHistory` on `CN=c.ford,CN=Users,...`, `ObjectClass=user` | **"Suspicious SID History Addition" Medium** |

The control alert reads "The user examplecorp\j.castillo added SID history to the
account examplecorp\c.ford", i.e. the engine resolves the modified object to an
**account** before it evaluates the change. On a `container` DN it never
resolves, so no attribute-change analytic can fire against
`CN=AdminSDHolder,CN=System,...` from WEC-only data. That is an engine-side
requirement, not something the event can carry: the object would have to exist
in the tenant's identity inventory (an AD/Identity connector), which WEC
ingestion does not populate.

Caveat, deliberately not over-claimed: the probe changed the DN **and**
`ObjectClass` together, so which of the two the engine keys on is untested. Both
are `container` for a real AdminSDHolder, so the practical conclusion is the same.

This also predicts the same blocker for `wip_sccm_container_recon`
("Suspicious access of the System Management Container"), which targets another
`container` DN — **predicted, not yet tested**.

Also fixed in this pass: `_build_4768` / `_build_4769` / `_build_4771` used to
prepend `::ffff:` unconditionally, double-prefixing an already-mapped override to
`::ffff:::ffff:a.b.c.d`; they now use the shared `_win_ip()` helper and render
Windows' form exactly once.

### Renderer fix: CRLF in `action_evtlog_message` (2026-11-15)

Several Windows analytics parse the **rendered** event text, not the EventData
JSON. "Possible Kerberos relay attack" is one: its published XQL (LIVEcommunity
483034) extracts the fields with `\r\n`-anchored regexes from
`action_evtlog_message`:

```
Authentication Package:\s(\w+)
Source Network Address:\s(.*)\r\n
Logon Type:\s+(\d+)\r\n
Security ID:\s+(.*?-500)\r\n
```

A real XDR-agent 4624 message holds **58 CRLF / 0 bare LF**. Every WEC event in
the tenant held **0 CRLF / 58 bare LF**, so the regexes could never match and
every earlier relay batch was structurally unfireable regardless of field
values.

Two separate normalizations had to be solved:

1. **XML text normalization.** A literal CR in XML text is folded to LF by the
   parser, so it must be escaped as `&#13;`. `_render_event_xml` previously did
   `message.replace("\r\n", "\n")`; it now assigns the raw `\r\n` and lets lxml
   emit `&#13;`.
2. **XSIAM's parser collapses `\r\n` → `\n` in a single pass**, on both the WEC
   and the Cribl receiver paths. A marker event sent through each landed with 0
   CRLF while the stored `microsoft_windows_raw._raw_log` still held `&#13;`, so
   the fold happens when the message field is built, after XML decoding.
   `_render_event_xml` therefore **doubles the CR** (`"\r\n"` → `"\r\r\n"`, i.e.
   `&#13;&#13;\n`); the one-pass replacement turns that back into `\r\n`.

Verified end to end: a 4624 rendered with the doubling lands in the tenant with
58–59 CRLF / 0 bare LF, and all four relay regexes match. This applies to every
Windows event, not just the relay, so any message-parsing analytic now sees the
same line endings a real agent event carries.

The relay analytic still does not fire after that fix (batches 5–7). The data
now satisfies both the Sigma rule (`749c9f5e`, including `IpPort != 0`) and the
published hunt verbatim, so the remaining gap is not the event shape.

Other ingestion paths were checked and do not help:

- **Cribl receiver** (`windows_event_logs` UUID → `microsoft_windows_raw`):
  ingests and parses, normalizes CRLF identically, and produces the same
  `EVENT_LOG_DOMAIN_CONTROLLER` / null-enrichment record.
- **XDR Agent path**: the only path that preserves CRLF. The only
  WinRM-reachable agent host (`192.168.0.44`, `Windows10-Workstation1`) is a
  workgroup box, so it cannot produce a real Kerberos loopback logon, and it does
  not forward custom Application-log sources. Writing a genuine Security-channel
  4624 needs `AuthzReportSecurityEvent`, which requires `SeAuditPrivilege`; the
  WinRM token does not hold it (error 1300), so that path needs a SYSTEM context.

#### `event_sub_type`: WEC vs agent (2026-11-15)

The remaining structural difference is the collector class the parser stamps on
each record:

| Source | `_product` | `event_sub_type` |
|---|---|---|
| WEC / Cribl receiver | `Windows` | `EVENT_LOG_DOMAIN_CONTROLLER` |
| XDR agent | `XDR agent` | `EVENT_LOG_AGENT_EVENT_LOG` |

**Every** WEC record carries `EVENT_LOG_DOMAIN_CONTROLLER`, even when the event
is attributed to a workstation hostname (`FS01`, `SALES-LT-021`,
`Windows10-Workstation1`), and the tag follows the transport, not the payload:
the Cribl receiver path produces the same value. An analytic that excludes
domain controllers (the Sigma rule this one is derived from targets domain-joined
workstations) can therefore never match WEC data in this tenant. The analytic
catalog lists `windows-event-collector` as the data source, but its published
behaviour on this tenant is consistent only with agent-classed events.

Two related facts were established while chasing that path:

- **XSIAM does not build the message from EventData.** A 4624 sent with no
  `<RenderingInfo>` element lands with `action_evtlog_message = null`; the parser
  only decodes a message that the collector already rendered. Any agent-sourced
  event must therefore carry a locally rendered message.
- **`adtschema.dll` + `MsObjs.dll` renders a genuine 4624 text** (58 CRLF,
  `Logon Type: 3`, `Source Network Address: 127.0.0.1`, `Security ID: …-500`).
  This host's template uses the **older 27-string insertion order**
  (`TargetUserSid` is `%5`, `LogonType` is `%9`, `IpAddress` is `%21`), so the
  modern order renders shifted fields.

Producing an agent-sourced Security 4624 on `Windows10-Workstation1` is blocked:

| Step | Result |
|---|---|
| `AdjustTokenPrivileges(SeAuditPrivilege)` over WinRM | error 1300 (privilege not held) |
| same, in a `schtasks /ru SYSTEM` task | **succeeds** (err 0) |
| `RegisterEventSource` for a source under `…\EventLog\Security` | error 5 (access denied) |
| `AuthzRegisterSecurityEventSource` without install | error 2 (not installed) |
| `AuthzInstallSecurityEventSource` | **hangs** (process never returns) |

So the endpoint cannot emit an agent-classed 4624 without a real interactive
logon or a collector change on the tenant side.

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

## Delivery and Volume

One worker per workstation plus a DC worker and a threats worker generate events into
buffers that `generate_log()` drains. This is the only ambient mode: the old
single-threaded mode (`parallel_hosts: false`) was removed on 2026-10-20, and the key is
no longer read.

- **Events are released at their own timestamps.** Workers schedule each generated
  sequence into a time-ordered queue and a release thread hands every event out when its
  time arrives, assigning its `EventRecordID` at that moment. Per host and channel, ids
  therefore rise with time exactly as on a real machine (before, ~16% of consecutive ids
  ran backwards), and nothing is ever stamped in the future. A sequence that spans time
  arrives over that time: a process's 4689 exit is delivered when the process exits,
  minutes after its 4688. Scenario fires and other direct generator calls are not
  deferred; they return their events immediately.

- **Volume is set by pacing, not by a cap.** `wks_interval_multiplier` (default 10.0) sets
  how often each workstation emits; see [Delivery: buffers, not limits](../configuration.md).
- **Threats are delivered whole.** Each threat is queued as one unit on its own queue and
  drained before benign traffic, so a multi-event sequence is never cut short and its
  label is exact. They used to share the benign queue, where a full queue cut a threat off
  part-way and it was never retried.
- **No drops.** Workers wait when a buffer is full. A slow WEC broker pauses only the
  Windows module (`wec_max_pending`); WEC POSTs are pooled and retried, and anything still
  undeliverable is counted under "WEC delivery" in the health check.
- **Insane** fires a threat on every threats-worker tick (base interval x
  `threat_interval_multiplier`, 2 s by default). It previously fired none in parallel mode.

## Record Numbers

Each host's `EventRecordID` only ever increases, across restarts and across processes,
as on a real Windows host. Numbers are taken in reserved blocks of 10,000 from
`state/windows_record_numbers.json` (gitignored) under a lock shared between processes,
so the simulator and a sweep script running at once never hand out the same id. A host
seen for the first time starts at 1,000,000,000 or above.

They used to be reseeded at random (50,000-500,000) on every restart, so a restart could
put a host back into a range it had already used. Deleting the state file is safe: hosts
are reseeded above 1e9 again.

Deterministic Training Mode is unaffected: inside a training run numbering is seeded and
in-memory, so the same seed reproduces the same ids, and the live counters are untouched.

## Per-Host LSASS PID

The Security channel is written by LSASS, so its PID appears in `<Execution ProcessID>` on
every record. That PID was pinned globally at `584`, which is correct for **one host**
— LSASS does keep one PID for the life of a boot — but the simulator spans 500+
hostnames, and all of them reported 584 on every Security event.

It is now derived from the computer name: stable for that host across restarts, a multiple
of four as Windows allocates PIDs, within the realistic 500–1496 range. ~160 distinct
values across the estate.

The invariant the global pin existed for is preserved: when the logon-requesting process in
EventData *is* LSASS, its `ProcessId` matches the PID the record reports, and one PID never
names two executables.
