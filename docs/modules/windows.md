# Windows Event Log Module

**Dataset:** `microsoft_windows_raw`
**Transport:** WEC (Windows Event Collector) — direct WS-Management over mutual TLS
**Format:** native Windows Security Event XML (`<Event>` … `<System>` / `<EventData>`)

Generates native Windows Security-channel Event XML targeting XSIAM's Identity Analytics (UEBA) engine and endpoint detections. Events are delivered to the Broker VM via the **WEC** transport (WS-Management / HTTPS 5986, mutual-TLS client certificate) — the same protocol as Windows Event Forwarding (WEF) source-initiated subscriptions. Because LogSim builds the SOAP/XML envelopes directly, it can simulate events from hundreds of distinct hostnames on a single machine (each event carries its own `<Computer>` field) — something native WEF cannot do.

- **Rendering:** `_render_event_xml()` uses `lxml` for correct namespace/prefix control and single-quoted attributes, matching real Windows XML byte-for-byte (lowercase GUIDs, nanosecond timestamps, `%%` message codes).
- **Event modeling:** every record is built through `_build_event(event_id, computer, event_data, …)` so `microsoft_windows_raw` modeling rules, correlation rules, and UEBA analytics process it identically to real WEC-collected events. `_raw_log` is the Windows Event **XML** (not JSON) — extract fields with `regextract(_raw_log, "Name='<Field>'>([^<]+)<")`.
- **Covered Event IDs:** 1644, 4624, 4625, 4634, 4647, 4648, 4656, 4662, 4663, 4672, 4688, 4689, 4697, 4720, 4722, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4741, 4742, 4756, 4757, 4767, 4768, 4769, 4771, 4776, 4781, 4886, 4887, 4888, 4898, 4899, 4900, 5136, 5137, 1102.

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
| `PASSWORD_NEVER_EXPIRES` | A sensitive account was modified to password never expires (base variation: A user account was modified to password never expires, Informational) | Analytics BIOC |
| `PRIV_CERT_REQUEST` | Suspicious privileged certificate request via certificate template | Analytics BIOC |

`AS_REP_ROASTING`, `DMSA_PRIVESC`, `SENSITIVE_PASSWORD_RESET`,
`PASSWORD_NEVER_EXPIRES` and `PRIV_CERT_REQUEST` dropped their `WIP_` prefix; the
old `WIP_` names still dispatch.

**WIP** (events are correctly shaped; the detection depends on an identity-graph baseline or is still under investigation): `WIP_ADMINSDHOLDER_ACL_MODIFICATION`, `WIP_SCCM_CONTAINER_RECON`, `WIP_ESC4_TEMPLATE_MODIFICATION`, `WIP_NEW_MACHINE_DELEGATION`, and `WIP_IRREGULAR_SERVICE_TGS` — which only ever raises the weak-encryption alert owned by `MULTIPLE_SERVICE_TICKETS`, so it is background-only (`IRREGULAR_TGT_BURST` covers its intended detection).

`WIP_ADMINSDHOLDER_ACL_MODIFICATION` is **not** blocked on object resolution. A
differential probe fired "Possible shadow credentials addition" on the
AdminSDHolder `container` itself (alert 799066, description says "The account
type: container"), so the engine evaluates container targets. The ACL analytic
still raises nothing on the canonical shape; the remaining unknown is its
ACE/SDDL handling or its activation for WEC-only data. See "Container targets are
evaluated" below. `WIP_SCCM_CONTAINER_RECON` is therefore **not** presumed
blocked by object type either.

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
| `dnshostname_spoofing` | **Confirmed** | Medium "Suspicious dNSHostName attribute change to DC name" fired 2026-11-18 04:44:08Z (alert 803275) and again 05:06:32Z (803488), together with "Suspicious account attribute modification that matches that of a sensitive machine account" (803276 / 803489). The carrier is the **4742**, and the new value has to equal the FQDN of a DC the identity graph actually knows. See "dNSHostName spoofing: the 4742 carries it, and the value must be a real DC" below. |
| `priv_cert_request` | **Confirmed** | Low "Suspicious privileged certificate request via certificate template" fired 2026-11-16 17:22Z (alert 799505) on a request submitted **by** `Administrator` for an ordinary user. The reverse shape (ordinary requester, privileged requested subject/SAN) is silent, as is the same requester again within the 1-day dedup window. See "Privileged certificate request: the *requester* is the privileged identity" below. |
| `pkinit_auth` | **WIP** | 4 batches, 0 alerts. Tried the Microsoft-documented smart-card shape (4768 `PreAuthType=15`, `PreAuthEncryptionType=0x12`, cert issuer/serial/thumbprint), `PreAuthType` 14/16/17, rogue and enterprise issuers, short/full issuer DN, machine and user targets, missing cert, `4771` failure, `TicketOptions=0x60810010`, loopback `::1`, realm-qualified `ServiceName`, and a 4768 correlated with a preceding `msDS-KeyCredentialLink` write. All shapes ingested with the fields intact in both `microsoft_windows_raw` and `xdr_data`. |
| `spn_cleared` | **WIP** | 5 batches, 0 alerts. Tried 4742 `ServicePrincipalNames` empty / `-` / absent, 5136 `%%14675` delete pairs, 5136 `%%14674` add-with-empty-value, 4662 write-property, and a same-account state transition (4742 with real SPNs, then 4742 with `-`). Batches 4–5 added the missing realism: `UserAccountControl` `%%2080` / `0x1000` (instead of `-`), the "only SPN changed" 4742 shape (`SamAccountName`/`DnsHostName` left as `-`), a real tenant asset (`FS01$`) as well as a new machine, and deleted-value renderings `-` / empty / absent. All shapes ingested; none alerted. Batch 6 re-ran the module's full sequence after the CRLF fix (9 events, real CRLF) — still 0 alerts. |
| `kerberos_relay` | **WIP** | 7 batches, 0 alerts. Tried the published KrbRelayUp endpoint signature alone (4624 type 3, Kerberos, local Administrator RID 500, loopback) with `127.0.0.1` / `::1` / `::ffff:127.0.0.1` and `WorkstationName` `FS01` / `-`, then the full sequence 4768 → DC 4624 → 4769 → endpoint 4624 → 4672 → 4688 → 4689 against the real `FS01` asset. Batch 4 varied the target SID (machine-local vs synthetic-domain vs the tenant's real domain `S-1-5-21-2795392456-4107320412-3908095700` Administrator), the subject (machine account + `0x3e7` + `lsass.exe` vs anonymous `S-1-0-0`), and the target host (`FS01` vs `DC01`); all six events ingested with the fields intact and produced no alert. **Batches 5–7 ran after the CRLF fix below.** The stored `action_evtlog_message` now carries real CRLF (58–59 per 4624, 0 bare LF) and the published XQL hunt for this analytic returns the synthetic rows verbatim (`auth_package=Kerberos`, `logon_type=3`, `network=127.0.0.1`, `sid` ending `-500`). Batch 6 covered machine-local and real-domain Administrator SIDs; batch 7 fired the module's own full 7-event sequence against `SQL01`. Neither the Cribl receiver path nor attributing the WEC event to a real agent hostname (`Windows10-Workstation1`) changed anything — both still land as `EVENT_LOG_DOMAIN_CONTROLLER` with null `agent_ip_addresses`/`identity_enrichment`. That collector class is now the standing blocker: real agent 4624s are stamped `EVENT_LOG_AGENT_EVENT_LOG`, and no WEC/Cribl record can be. See "event_sub_type: WEC vs agent" below. |
| `adminsdholder_acl_modification` | **WIP** | 3 batches, 0 alerts. Batch 1 delivered the canonical shape — 5136 `nTSecurityDescriptor` pair on `CN=AdminSDHolder,CN=System,DC=examplecorp,DC=local` with `ObjectClass=container`, `OperationType` `%%14675`/`%%14674` under one `OpCorrelationID`, and a new ACE `(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<user SID>)` (Full control for a non-machine principal), plus the 4662 read `0x10`, WRITE_DAC `0x40000` and write-property `0x20` legs. This matches the published logic for the same detection (Splunk ESCU `00d877c3-7b7b-443d-9562-6b231e2abab9`: `EventCode=5136 ObjectClass=container ObjectDN="CN=AdminSDHolder,CN=System*"`, new ACE with Full control). Every field verified in `xdr_data`. Batch 2 was a differential probe: the same `msDS-KeyCredentialLink` change fired on the container (alert 799066, "The account type: container"), so the target type is not the blocker. Batch 3 added a second ACE for `WD` and named the `nTSecurityDescriptor` GUID in the WRITE_DAC `Properties`; still 0. See "Container targets are evaluated" below. |
| `wip_esc4_template_modification` | **WIP** | 3 batches, 0 alerts. Attempt 1 was `5136` only (`nTSecurityDescriptor` delete+add on the template granting Authenticated Users the write rights DA/SY hold, plus `msPKI-Certificate-Name-Flag=1`). Attempt 2 added the `4662` legs (`0x10` read, `0x40000` WRITE_DAC `%%1539`, `0x20` property write `%%7685`) with the documented schema GUIDs. Attempt 3 added `4899`/`4900` from the CA with old/new template content and old/new security descriptor. All events verified ingested. The detector's own event-collection reference names **4899, 4900 and 4662** (not 5136); the `4899`/`4900` EventData names remain unverifiable because Microsoft publishes no per-event page. See "AD CS detectors: what is reachable and what is not" below. |
| `wip_new_machine_delegation` | **WIP** | 3 batches, 0 alerts. Attempt 1: config-only `4741` + clean `4742(AllowedToDelegateTo)` + `5136`, a bare S4U2Self/S4U2Proxy pair, and a new machine TGT + TGS. Attempt 2: full RBCD chain on `FS01` (`5136` + `4662` with `3f78c3e5-…`), constrained delegation at creation (`4741` UAC `0x1001000`), unconstrained at creation (`4741` UAC `0x81000`). Attempt 3: the same three chains, each preceded by a DC-side machine `4624` and the machine's own TGT. All events verified ingested. A `4741` diagnostic showed a fresh machine creation by a first-time creator does **not** raise "Rare machine account creation", so `4741` is not what feeds machine-creation analytics here. See "New machine delegation: `4741` does not make a machine 'new'" below. |
| `mailbox_export`, `mailbox_export_log_removal`, `mailbox_cas_change` | **WIP** | 3 batches, 0 alerts. Tried 4104 `ScriptBlockText` carrying `New-MailboxExportRequest` / `Remove-MailboxExportRequest` / `Set-CASMailbox`, 4688 process creation, and native `MSExchange Management` EventID 1 `CmdletName`/`CmdletParameters` (simple and full field sets: `ObjectModified`, `User`, `Organization`, `OriginatingServer`, `Succeeded`, `RunspaceId`, `Timestamp`). The `MSExchange Management` channel **does** ingest and normalize (`microsoft_windows_raw` → `xdr_data`, `action_evtlog_event_id=1`), so channel availability is not the blocker. |

### dNSHostName spoofing: the 4742 carries it, and the value must be a real DC (2026-11-18)

`dnshostname_spoofing` had never produced an alert in 90 days and had no
verification note, so it was probed in three batches. The first two were silent
and the third fired **both** dNSHostName analytics within six seconds of
delivery.

| Attempt | Shape | Alert |
|---|---|---|
| 04:01Z | shipped generator: new `DESKTOP####` account, 5136 dNSHostName pair → `DC01.examplecorp.local`, SPN pairs, 4742, 4769 | none |
| 04:22Z | real `FS01$` asset, same shape plus 4662 legs (`0x10`, `0x8` Write Self, `0x20`) with the computer-class and dNSHostName schema GUIDs | none |
| 04:44Z | two accounts, 4742 reduced to a **dNSHostName-only change** (other attributes `-`): `FS01$` → `DC01.examplecorp.local` and `BACKUP01$` → `ExampleCorp-DC1.corp.examplecorp.com` | **803275 / 803276** for `backup01$` only |

Two bisects then separated the variables:

* **05:03Z** — a lone 5136 dNSHostName old→new pair on `FS02$` with the real DC
  FQDN produced no alert in 150 s. The 5136 pair is not what the analytic reads,
  consistent with the sAMAccountName finding that the state-carrying 4742 is the
  consumed event.
* **05:06Z** — a **single 4742** for a brand-new `WKSTMP7741$`, `DnsHostName` =
  `ExampleCorp-DC1.corp.examplecorp.com`, everything else `-`, fired both
  analytics six seconds later (803488 / 803489). No baseline, no 5136, no 4662,
  no 4768/4769 was needed.

The second discriminator is the value. `DC01.examplecorp.local` is a synthetic
host that only LogSim emits; the tenant's real DC is the computer account
`EXAMPLECORP-DC1$` in realm `CORP.EXAMPLECORP.COM` (read from real 4769s, whose
`ServiceName` is `EXAMPLECORP-DC1$` and `TargetDomainName` is
`CORP.EXAMPLECORP.COM`). The analytics compare the new dNSHostName against that
real asset, so a name that merely *looks* like a DC never matches. The generator
therefore takes its spoof target from `windows_events.spoof_dc_fqdn`
(default `ExampleCorp-DC1.corp.examplecorp.com`) instead of the synthetic
`domain_controller_hostname`, and emits the 4742 with
`SamAccountName`/`ServicePrincipalNames` as `-` exactly as the tenant's own real
4742 does for unchanged attributes.

Alert 803275 carries `DT:Identity Analytics`, `R:Domain Controllers` and
`DS:Microsoft/Windows`; 803276 additionally carries
`DT:Active Directory Certificate Services Analytics`. Dedup is per account:
the two accounts fired separately, and a repeat for a third account 22 minutes
later fired again.

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

### New machine delegation: `4741` does not make a machine "new" (2026-11-18)

`new_machine_delegation` had never alerted in 90 days, although the shipped
generator had been emitting a `4741` + `4742(AllowedToDelegateTo)` shape on a
background weight of 3. Three isolated batches were delivered; every event was
verified in `xdr_data` and none produced an alert.

| Attempt | Shape | Alert |
|---|---|---|
| 05:17Z | config-only: `4741` + clean `4742` (`AllowedToDelegateTo`, other attributes `-`) + `5136` pair; a bare S4U2Self + S4U2Proxy (`TransmittedServices` = the new machine); a new-machine TGT + TGS to `FS01` | none |
| 05:41Z | full RBCD chain on `FS01` (`5136` + `4662` with the `3f78c3e5-…` GUID); constrained delegation enabled at creation (`4741` UAC `0x1001000`); unconstrained at creation (`4741` UAC `0x81000`) | none |
| 06:14Z | the same three chains, each preceded by a DC-side machine `4624` (type 3, Kerberos, `TargetUserName` = `<machine>$`) and the machine's own TGT, so the identity graph has a machine node | none |

The third attempt targeted the obvious remaining gap: the new machine never
authenticated, so the graph had no machine node to attach a delegation to.
That did not change the outcome.

A separate diagnostic explains why. "Rare machine account creation" is a
single-event Identity Analytics detection ("a user was observed creating a
machine account for the first time") and has never fired in 90 days, although
the tenant holds 19 `4741`s created by ~15 distinct users — each one that
user's first. A fresh `4741` by `a.tucker`, who had never created a machine,
was ingested and still raised nothing. `4741` is therefore not what feeds
machine-creation analytics in this tenant, so this detector cannot establish
that the machine is "new" regardless of how the delegation half is shaped.

The vendor page also declares a **Test Period of 12 Hours**, so a delayed alert
cannot be ruled out completely. Re-probe only if a real `4741` ever drives a
machine-creation alert here.

### Container targets are evaluated; the AdminSDHolder ACL is analytic-specific (2026-11-16)

`wip_adminsdholder_acl_modification` is not shape-blocked. The published page
puts it in the **Identity Analytics** module, the same module as analytics that
do fire here, so the module itself is live.

Batch 2 was a differential probe: the 5136 attributes that fire today were
retargeted at the AdminSDHolder container and everything else was left alone.

| Probe (all delivered, all verified in `xdr_data`) | Alerts |
|---|---|
| 5136 `sIDHistory` on `CN=AdminSDHolder,CN=System,...`, `ObjectClass=container` | 0 |
| 5136 `msDS-KeyCredentialLink` on the same DN, `ObjectClass=container` | **"Possible shadow credentials addition" Medium (alert 799066)** |
| 5136 `nTSecurityDescriptor` pair on the same DN (attempt 2 of the target) | 0 |
| **Positive control, same generator run 9 min later:** 5136 `sIDHistory` on `CN=c.ford,CN=Users,...`, `ObjectClass=user` | **"Suspicious SID History Addition" Medium (alert 799072)** |

Alert 799066 is the decisive record. Its description is "The user
examplecorp\m.ramirez modified the msDS-KeyCredentialLink attribute for an
account. The account modified: CN=AdminSDHolder,CN=System,DC=examplecorp,DC=local.
... **The account type: container**." So the engine does evaluate a 5136
attribute change on a `container` DN and does not require the target to resolve
to an account. An earlier draft of this section claimed the opposite; that claim
was wrong and is retracted here.

What the probe does show is per-analytic target sensitivity: `sIDHistory` is
account-specific (silent on the container, fires on a user), while
`msDS-KeyCredentialLink` is object-agnostic. The AdminSDHolder ACL analytic is a
third case again — the canonical 5136 `nTSecurityDescriptor` pair plus all three
4662 legs on the correct DN and class still raise nothing.

Batch 3 changed the two things batch 2 left open: the added ACE trustee (now the
actor's SID **and** `WD`/Everyone, both Full control) and the 4662 WRITE_DAC
`Properties` (now naming the `nTSecurityDescriptor` attribute GUID as well as the
container class GUID). Delivered 10 events at 05:21:44Z; **0 alerts** in the
following 7 minutes. The poll matched by `description contains "AdminSDHolder"`,
which returns only the older 799066.

So this is three batches, zero alerts, and the item stays `WIP_`. Remaining
candidates, none verified: an ACE/SDDL parse this tenant does not perform, or the
analytic simply not being active for WEC-only data. Do not assume the container
target is the blocker; that hypothesis is disproven.

Process note: attempt 2 was initially read as 0 alerts because the poll filtered
on alert *names* containing "key credential". The tenant name is "Possible shadow
credentials addition", which matches neither that nor "adminsdholder". Poll by
`description contains "<object DN>"` (or by issue ID) instead of by a guessed
alert name.

`wip_sccm_container_recon` ("Suspicious access of the System Management
Container") is **not** blocked by object type for the same reason; it has since
been probed, and the probe is described in the next section.

### System Management container: the LDAP query was the missing event (2026-11-17)

The generator emitted the container read as `4662` only. That shape is silent, but
so is everything else about it until you look at what the tenant's own Directory
Service telemetry contains:

| Fact | Value |
|---|---|
| Real `1644` events (LDAP search diagnostics) in 90 days | **185,646**, all agent-collected on `ExampleCorp-DC1` |
| Distinct search bases those 1644s ever used | **2** — `CN=Schema,CN=Configuration,DC=corp,DC=examplecorp,DC=com` (the DC's own `pGMSA_…$` schema poll, `onelevel`, 2,694) and `DC=corp,DC=examplecorp,DC=com` (`Administrator`, `subtree`, 253) |
| `1644` events whose starting node is the System Management container | **0** |

`1644` is the only record that names the *search base*; `4662` says which object
was touched but not that an LDAP query enumerated it. The published investigative
action for this analytic is "look for the suspicious LDAP query that may trigger
this event", so the generator now emits one, using the field layout read off the
tenant's own rows:

| Field | Meaning | Synthetic value |
|---|---|---|
| `param1` | starting node | `CN=System Management,CN=System,DC=examplecorp,DC=local` |
| `param2` | filter | `( (objectClass=*) )` |
| `param3` / `param4` | visited / returned entries | object count of the burst (28–35) |
| `param5` | client | `[::ffff:<user ip>]:<port>` |
| `param6` | search scope | `subtree` |
| `param7` | attribute selection | `*` |
| `param9` | used indexes | `idx_objectClass:1:N;` |
| `param17` | user | `EXAMPLECORP\<user>` |

Provider (`Microsoft-Windows-ActiveDirectory_DomainService`), provider GUID
(`{0E8478C5-3605-4E8C-8497-1E730C959516}`) and channel (`Directory Service`) come
from the same rows, so `_build_event` now takes per-event provider/channel/keyword
overrides via `_EVENT_META`. Verified in the tenant: the synthetic 1644 lands with
every `param*` intact and real CRLF in `action_evtlog_message`.

Probe history for this detector, all with zero alerts:

| When | Shape |
|---|---|
| 11-09, 11-10, 11-15 (background) | `4662` read of the container + 27–34 child objects, before the 30-day training period completed |
| 11-17 13:31Z | same, plus a `List Contents` (`0x4`) read on the container itself (a real LDAP search emits both that and `Read Property`) |
| 11-17 13:43Z | same, plus the `1644` search naming the container |

The remaining candidate blocker is the **event class**, not the shape: every real
`1644` in this tenant is `EVENT_LOG_AGENT_EVENT_LOG` (XDR agent with XTH), while
WEC-delivered events land as `EVENT_LOG_DOMAIN_CONTROLLER` and nothing in the WEC
or Cribl paths changes that — the same wall documented for `kerberos_relay`. That
is consistent with the published Required Data listing the agent path separately.
The generator keeps the `1644` leg because it is the correct real-world shape.

### AD CS detectors: what is reachable and what is not (2026-11-17)

The AD CS module itself is live: alert 799505 carries
`DT:Active Directory Certificate Services Analytics`, so these analytics are
evaluating events in this tenant. Of its seven detectors, one is confirmed and
the rest are out of reach — each for a different, individually measured reason.

**"Vulnerable certificate template loaded" — WIP on an unverifiable field.**
Seven `4898` deliveries since 2026-10-29 (six of them on 2026-11-16/17) carried
an ESC1-shaped `TemplateContent` (`msPKI-Certificate-Name-Flag: 0x1`, Client Auth
EKU, `Authenticated Users` enroll in the SDDL) under five different template
names, including one literally named `ESC1-Vulnerable`. Zero alerts, and one of
those batches *did* fire a sibling AD CS analytic. The `TemplateContent` format
is hand-rolled and there is no way to check it against ground truth:

- the tenant holds only 7 `4898` events and all 7 are this generator's own
  output, so there is no captured real event to copy;
- Microsoft does not publish a per-event page for `4898`;
- the Cortex page explicitly declines to say which event ID or which fields the
  detector reads ("The detector page does not specify Windows event IDs or
  certificate-template parsing rules").

The `_build_4898` docstring already warned about this. Until a real `4898`
becomes available, further deliveries would be guessing at the same unknown, so
the detector is parked as WIP rather than probed again.

**"Discovery of misconfigured certificate templates using LDAP" — blocked by data
source, not shape.** Published Required Data is *XDR Agent with eXtended Threat
Hunting (XTH)* only, with Detector Tags `LDAP Analytics (Client)` and
`LDAP Analytics (Server)`. That is the agent's own LDAP parser, not a Windows
event, so WEC cannot feed it at all — the same agent-class wall as
`kerberos_relay` and the `1644` leg of SCCM recon. No generator is added for it.

**"A user certificate was issued with a mismatch" — WIP after three probes.** It
has WEC-or-agent data and keys on `4887` `Requester` vs `Subject`, both of which
the existing CA builders already emit. Every earlier `4887` came from
`priv_cert_request`, where the requester was the sensitive `Administrator`, so
all three probes used an ordinary requester:

| Attempt | Requester | Issued subject | Request SAN (`4886`) | Alert |
|---|---|---|---|---|
| 14:02Z | `i.fontaine` | `CN=v.brooks,CN=Users,DC=examplecorp,DC=local` | none | none |
| 14:11Z | `i.nielsen` | `CN=b.alvarez,CN=Users,DC=examplecorp,DC=local` | `b.alvarez@examplecorp.local` on both events | none |
| 14:20Z | `a.petit` | `CN=Administrator,CN=Users,DC=examplecorp,DC=local` | `Administrator@examplecorp.local` on both events | none |

All three ingested with `Requester`, `Subject` and `Attributes` intact (attempt 1
was re-read from `xdr_data` to confirm), and the detector has never fired in 30
days, so its 1-Day dedup cannot be responsible. Silence is also not a
missing-identity problem: ordinary LogSim users are well established in this
tenant (`v.brooks` 3,350 `4624`s, `i.fontaine` 3,454, `j.james` 3,505 over 90
days). The remaining unknown is what the analytic actually compares — the `4887`
`Requester` string, the SAN inside the `4886` `Attributes` blob, or something the
CA does not record at all — and it is not documented. WIP.

Two more AD CS detectors are out of reach for reasons unrelated to shape.
**"Deletion of AD CS certificate database entries"** needs the CA
database-deletion audit events (`4896`–`4902`), and Microsoft does not publish
field layouts for those either, so it would be a second unverifiable builder.
**"Unusual certificate management activity"** is a Cloud-module analytic fed by
AWS/Azure/GCP audit logs, not by Windows events at all.

**"Suspicious certificate template modification" (ESC4) — WIP after three
attempts.** This one produced the most useful negative result of the sweep,
because the vendor documentation names its inputs if you ask it directly. The
detector page does not describe its logic, but the XSIAM event-collection
reference lists **4899** ("A Certificate Services template was updated"),
**4900** ("Certificate Services template security was updated") and **4662** for
it. `5136` is *not* in that list — which is why the first two attempts, built
around the DC's directory-write record, could not have matched:

| Attempt | Shape | Alert |
|---|---|---|
| 14:28Z | `5136` only: `nTSecurityDescriptor` `%%14675`+`%%14674` on the template (AU gains the write rights DA/SY hold), plus `msPKI-Certificate-Name-Flag=1`, `ObjectClass=pKICertificateTemplate` | none |
| 14:40Z | the same, plus the established `4662` legs — `0x10` read, `0x40000` WRITE_DAC with `%%1539`, `0x20` property write with `%%7685` for `nTSecurityDescriptor` and the name flag | none |
| 14:49Z | the same, plus `4899` and `4900` from the CA with old/new template content and old/new security descriptor | none |

All three verified ingested: every `5136` carried the template DN, class,
attribute and SDDL; every `4662` carried the template class schema GUID
(`e5209ca2-3bba-11d2-90cc-00c04fd91ab1`, from MS-ADSC) and the attribute GUIDs
(`bf9679e3-…` for `nTSecurityDescriptor`, `ea1dddc4-…` for
`msPKI-Certificate-Name-Flag`, both from MS-ADA3); both `4899`/`4900` landed with
the Old/New pairs and real CRLF in the message.

What is left unverified is the `4899`/`4900` EventData naming. Microsoft
publishes no per-event page for either, so the builders follow the published
message template (`%1 v%2 (Schema V%3)`, template DN, Old/New Template Content,
Old/New Security Descriptor, Domain Controller) plus `4898`'s field names. That
is the same wall as `4898`, and it is why the generator is `WIP_`-prefixed rather
than tuned further. It is shipped as `WIP_ESC4_TEMPLATE_MODIFICATION` so the
full four-way shape stays available for a retry once a real `4899`/`4900` is
captured.

### Sensitive-account classification is inventory-driven (2026-11-16)

`PASSWORD_NEVER_EXPIRES` was WIP because the generator picked its target with
`random.choice()` from Administrator, krbtgt and four `svc_*` accounts. The Low
variation ("A sensitive account was modified to password never expires") needs
the target to be in a sensitive built-in group **in the tenant's identity
inventory**, and in this tenant only the built-in Administrator qualifies.

Evidence, all from `xdr_data` and `alerts`:

| 4738 target | Flag delta | Alert |
|---|---|---|
| `Administrator` (RID 500), 2026-10-30 | `0x10` → `0x210`, `%%2089` | "A sensitive account was modified to password never expires" **Low** (723849) |
| `svc_exchange`, 2026-10-29 | same | none |
| `svc_sql_prod`, 2026-11-03 | same | none |
| `Administrator` (RID 500), probe 2026-11-16 05:37:43Z | same | **Low** (799250) |
| `krbtgt` (RID 502), same probe, +60 s | same | none |

No 4728/4732/4756 event ever names those service accounts, so nothing puts them
in a privileged group in the identity graph. The generator now always targets
Administrator (`_PNE_TARGET_ACCOUNT`) rather than drawing from a list whose
other entries are silent here.

The base **Informational** variation ("A user account was modified to password
never expires") has never appeared in `dataset = alerts` in 30 days, even for the
Administrator 4738s that raised the Low variation — so the Low variation is the
observable outcome and is what the generator is measured against.

`PASSWORD_NEVER_EXPIRES` therefore dropped its `WIP_` prefix; `WIP_PASSWORD_NEVER_EXPIRES`
still dispatches through `_RENAMED_THREATS`.

### Privileged certificate request: the *requester* is the privileged identity (2026-11-16)

`PRIV_CERT_REQUEST` was WIP because the generator put the privileged account in
the **requested subject** and left the requester an ordinary user. That shape is
silent. The analytic fires on the opposite arrangement.

Attempt 1 (17:04Z) — normal user `a.petit` requests a cert with
`san:upn=Administrator@examplecorp.local`, `Subject=CN=Administrator,CN=Users,...`,
template `ESC1-Vulnerable`, 4886 + 4887 + PKINIT: **0 alerts**.

Attempt 2 (17:22Z) — two enrollments 120 s apart, distinct templates:

| Leg | Requester | Issued to | Template | Alert |
|---|---|---|---|---|
| A | `Administrator` | `j.james` (ordinary) | `UserAuth-Legacy` | **"Suspicious privileged certificate request via certificate template" Low (799505)** |
| B | `j.james` (ordinary) | `Administrator` | `VPN-Certificate` | none |

Alert 799505, verbatim: "A privileged certificate was requested by
EXAMPLECORP\Administrator via certificate template. This certificate was
requested via the template UserAuth. This certificate was issued for
CN=j.james,CN=Users,DC=examplecorp,DC=local. Certificate requests from this
account for this subject were never seen in the last 30 days. **This requester is
a sensitive user.** This may indicate abuse of the ESC8 ADCS attack". Its tags
include `R:Certificate Authority (CA) Servers` and `R:Privileged Accounts`, and
`user_name` is `EXAMPLECORP\Administrator` — the requester, not the subject.

So the analytic answers "did a sensitive account request a certificate", not "was
a certificate issued to a sensitive account". The generator now submits as
`Administrator` (`_PRIV_CERT_REQUESTER`) and requests the certificate for an
ordinary user drawn fresh each run, because the Low variation also requires the
`(requester, subject)` pair to be novel over 30 days.

Three secondary observations from the same batch:

- The Medium **denied** variation (4886 + 4888) was never probed. The generator
  no longer emits it, so `PRIV_CERT_REQUEST` always produces the verified issued
  path rather than gambling on an unverified variant.
- The `4768` PKINIT leg now carries `preauth_type=15` (PA-PK-AS-REP_OLD) and
  `preauth_encryption=0x12`. It previously used the default `2`
  (PA-ENC-TIMESTAMP), which renders a password pre-authentication record that
  also carries certificate fields.
- The `4887` `Subject` is a real distinguished name, so it carries no spaces
  after the commas (`CN=j.james,CN=Users,DC=examplecorp,DC=local`). The builders
  were emitting `CN=x, CN=Users, DC=...`; the analytic's own alert text reported
  the no-space form, and real AD DNs never contain those spaces. All three
  subject-DN constructions (`_build_4887`, `_build_4888`, `priv_cert_request`)
  now match.

**This analytic deduplicates for 1 Day** (published Deduplication Period), and the
key is the **requester**, not the subject — inferred from three post-fire batches
that used subjects never seen before and still stayed silent:

| Batch | Requester | Subject | Template | Alert |
|---|---|---|---|---|
| 11-16 17:36Z (shipped generator) | `Administrator` | `n.okafor` | `WebServerV2` | none |
| 11-16 17:47Z (shipped generator, template pinned) | `Administrator` | `e.wu` | `UserAuth-Legacy` | none |
| 11-17 13:24Z (shipped generator) | `Administrator` | `v.kato` | random | none |

All three ingested correctly (`4886` + `4887`, requester `EXAMPLECORP\Administrator`)
and stayed silent 14 minutes, 25 minutes and 20 hours after 799505. Repeating the
exact template that fired changed nothing, so the template is not the
discriminator and the generator can keep drawing from
`_CERT_TEMPLATES_VULNERABLE`. The 20-hour data point also rules out a
calendar-day reset: the window is a rolling period measured from the last alert,
so re-verify by waiting a full day after it rather than sending another batch.

**Confirmed on day 2.** The shipped generator was fired again at 2026-11-17
17:25:00Z — 24 h 3 min after 799505 — and raised alert **800683** at 17:24:52Z
(Low, `CA01.examplecorp.local`, `user_name=EXAMPLECORP\Administrator`, subject
`CN=d.kapoor,CN=Users,DC=examplecorp,DC=local`). So `PRIV_CERT_REQUEST` is
verified end to end from the shipped generator, not just from the probe, and the
dedup window is a rolling ~1 day from the last alert. The same batch also
delivered its `4898` leg, and "Vulnerable certificate template loaded" stayed
silent — independent confirmation of that detector's WIP status.

### CRLF reaches `action_evtlog_message`, not the EventData JSON (2026-11-16)

The 17:04Z CA batch was the first 4886/4887/4898 data with the renderer fix
applied. Measured on the stored rows:

| Field | CR | LF |
|---|---|---|
| `action_evtlog_message` | **yes** | yes |
| `action_evtlog_data_fields` → `Attributes` / `TemplateContent` | no | yes |

The rendered message carries real `\r\n` (`Requester:\tEXAMPLECORP\a.petit\r\n
Attributes:\tCertificateTemplate:...\r\nsan:upn=...`), while the EventData JSON is
stored LF-only. Analytics that parse the message see correct line endings; ones
that parse the JSON do not. The 2026-10-29 CA batch predates the fix and is
LF-only in both places, so it is not evidence about message parsing either way.

Also worth knowing when probing ADCS: `agent_hostname=CA01.examplecorp.local`
appears in exactly **nine** events in 90 days, all of them 4886/4887/4898. The
CA host has no other telemetry (no 4624, no 4688, no service events), unlike
DC01 and the user accounts the working identity analytics key on.

One unverified rendering detail, unchanged by this pass: `_msg_4898` renders the
template name inside the `Version:` line (`Version:\t<name> v100.2 (Schema V2)`)
and emits no `Template Internal Name:` line. No captured real 4898 exists here to
confirm whether that trailing line is part of the Windows message, so it was left
as is. The analytic that fired does not depend on the 4898 message.

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
