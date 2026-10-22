# Microsoft 365 workloads (Exchange, SharePoint/OneDrive, DLP, General)

Four feeds model the Office 365 Management Activity API workloads beyond Azure AD. They
share the Entra modules' identities, transport and threat model. See
[microsoft-entra.md](microsoft-entra.md) for **Cribl receiver setup** (`CRIBL_COLLECTOR_URL`,
`CRIBL_TOKEN`, content packs), the wire format and the episode-based threat rates.

| Module | Workload (record types) | XSIAM dataset | Source-Identifier |
|---|---|---|---|
| `o365_exchange` | Exchange: ExchangeAdmin (1), ExchangeItem (2), MailItemsAccessed (50) | `msft_o365_exchange_online_raw` | `dee8e85ce7db4573a8bc21b807e1d73a` |
| `o365_sharepoint` | SharePoint / OneDrive: file ops (6), sharing (14) | `msft_o365_sharepoint_online_raw` | `3a37f519e9094a3f8c4185fa572cd111` |
| `o365_dlp` | `Audit.DLP` DLPRuleMatch (11) | `msft_o365_dlp_raw` | `8f052782739d4b8389644cca23b994ac` |
| `o365_general` | Copilot (261), Power BI (20) | `msft_o365_general_raw` | `c7655e83805b4a058e66043a6715156c` |

As with Entra, these threats run in long-running sessions and through the validation
harness, but are not offered on the dashboard's Fire Individual Threat panel.

## `o365_exchange` — Exchange Online

Record shapes follow the Management Activity schema and real tenant rows:
- ExchangeAdmin cmdlet audit: `Parameters [{Name, Value}]`, an `ObjectId` path,
  `ResultStatus`.
- ExchangeItem mailbox actions: `LogonType` (0 owner, 2 delegated), `MailboxOwnerUPN`,
  `ClientInfoString`.
- MailItemsAccessed: `OperationProperties` with `MailAccessType`, plus `OperationCount`.

**Baseline:** routine mailbox activity (MailItemsAccessed dominates, then Send, Move,
benign inbox rules and logins), plus light admin.

**Threats (28):**
- **BEC mail rules:** inbox forwarding rule (plain, delegate and suspicious variants),
  email-hiding and catch-all hiding rules, email-hiding transport rule.
- **Forwarding and access:** mailbox SMTP forwarding (and delegate), transport forwarding
  rule (and delegate), mailbox delegation, SendAs grant, folder-permission change.
- **Access patterns:** mail accessed from multiple IPs in one subnet, scripted
  sent→deleted moves, one IP touching many mailboxes, mailbox enumeration, sensitive mail
  sent externally.
- **Defence evasion:** anti-phish policy disabled, mailbox audit bypass or audit log
  disabled, CAS mailbox change, compliance search created, DKIM disabled, malware filter
  removed, Safe Attachments / Safe Links disabled, DLP policy disabled.

## `o365_sharepoint` — SharePoint Online and OneDrive

The field set is verified against real tenant rows. `ObjectId` is the full file URL, with
`Site`/`SiteUrl`/`WebId`/`ListId`/`ListItemUniqueId`, `SourceFileName`/
`SourceRelativeUrl`, `ItemType`, `EventSource`, `ApplicationDisplayName`, browser,
device and platform, and `GeoLocation`. File paths come from a programmatic corpus with
hot and cold tiers, so files are stable entities while unique paths stay unbounded.

**Baseline:** routine document activity (access, modify, preview, upload, download, page
views, folder operations), weighted to business hours.

**Threats (19):**
- **Exfiltration:** mass download, full-sync download.
- **Sharing:** anonymous link created, and used externally; external sharing, including
  to an unusual domain.
- **Malware:** malware detected, suspicious malware file name.
- **Privilege:** site collection admin added.
- **Destructive:** mass deletion, mass editing, mass upload (ransomware-style).
- **Recon:** sensitive (AIP-labelled) file access, SharePoint enumeration, OneDrive
  enumeration.
- **Graph activity only** (Microsoft Graph request logs, no SharePoint audit record):
  OneDrive folder created through Graph, OneNote enumeration, Teams enumeration, an app
  reading site drives for the first time.

Downloads, uploads and the enumeration scenarios also emit the Graph request behind each
audit record (`MicrosoftGraphActivityLogs`, routed to `msft_azure_raw`). Inbox-rule and
mailbox-enumeration scenarios in `o365_exchange` do the same. See
[Event Hub copies](microsoft-entra.md#event-hub-copies-reaching-the-cloud-analytics).

## `o365_dlp` — Data Loss Prevention

Built from the Management Activity DLP schema: `PolicyDetails[{PolicyName, Rules[{RuleName,
Actions, Severity, ConditionsMatched.SensitiveInformation[...]}]}]`, plus workload metadata
(`ExchangeMetaData` for mail, `SharePointMetaData` for files). The source tenant has no DLP
policies, so this feed was built from the schema, not sampled from live rows.

**Baseline:** low-severity, notify-only matches (routine false positives).

**Threats (4):** high-severity PII/PCI match blocked on outbound mail, blocked SharePoint
file share, a burst of matches (mass sensitive-data movement), sensitive data shared
externally.

## `o365_general` — General feed (Copilot, Power BI)

The catch-all workloads. The Copilot field set (`CopilotEventData`, `CopilotLogVersion`,
`AppIdentity`) is verified against a real tenant row.

**Baseline:** Copilot interactions, plus Power BI report and dashboard views.

**Threats (2):** Power BI mass report export, Power BI bulk print.

## Validation

Same harness as the Entra feeds. The key prefixes are `ex:` for Exchange and `sp:` for
SharePoint:

```bash
python _local_validation/threat_harness.py fire ex:inbox_forwarding_rule
```
```bash
python _local_validation/threat_harness.py fire sp:mass_download
```
