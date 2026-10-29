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
- ExchangeAdmin cmdlet audit: `Parameters [{Name, Value}]`, `ModifiedObjectResolvedName`,
  `ObjectId` path, `ResultStatus`, `OriginatingServer`, `TokenObjectId` (schema-pinned —
  `AppPoolName`/`RequestId` were dropped as non-schema).
- `LogonType` verified enum: 0 Owner / 1 Admin / 2 Delegated / 3 Transport / 4 SystemService
  / 5 BestAccess / 6 DelegatedAdmin; `InternalLogonType` mirrors it.
- `ClientInfoString` uses documented real values (`Client=OWA;…`, `Client=WebServices;
  ExchangeWebServices`, `Client=REST;A3883EBA-FBE9-48BD-9ED3-DCA3E0E84250;;`,
  `Client=REST;Client=RESTSystem;;`, `Client=ActiveSync;…`).
- Store-folder ids use the real `AAMk…` base64 shape; `DestFolder {Id, Path, Name}`;
  aggregated-folder `Id` mandatory on MailItemsAccessed `Folders` entries.
- Mail sensitivity: top-level `SensitivityLabel` GUID + `recipientList` as the documented
  `Collection(EmailAddress)` shape.
- MailItemsAccessed: `OperationProperties` with `MailAccessType` (Bind/Sync), plus
  `OperationCount`; no undocumented `IsThrottled` pair; `AppId` = Graph GUID; `ClientAppId`
  is omitted (schema defines it as the original-caller identifier).

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
`SourceRelativeUrl`/`SourceFileExtension`, `ItemType`, `EventSource`,
`ApplicationDisplayName`, browser, device and platform, and `GeoLocation`. Copy/move
records also emit the `DestinationFileName`/`DestinationRelativeUrl`/
`DestinationFileExtension` set (per the schema rule that `ObjectId` on those ops is the
destination URL). Anonymous-download actors use the numeric `UserType: 10` (Guest) with the
`urn:spo:anon#…` UserId, not a string enum. Site-admin changes are RecordType 4 with
`SiteAdmin` in `ModifiedProperties`. Mass bursts keep one uniform `Operation` each so
volume analytics see a single coherent op.
**Baseline:** routine document activity (access, modify, preview, upload, download, page
views, folder operations), weighted to business hours.

Sharing ops and the sensitive-file shape are doc-verified: real sharing operations are
`SharingSet`, `SharingInvitationCreated/Accepted` (site-resource invitations),
`AnonymousLinkCreated`/`AnonymousLinkUsed`, `SecureLinkCreated`/`AddedToSecureLink`,
`SharedLinkCreated` (undocumented variants dropped); `TargetUserOrGroupType` carries the
documented string values (Member / Guest / SharePointGroup / SecurityGroup / Partner);
sensitivity labels ride the schema-pinned `SensitivityLabelId` +=
`SensitivityLabelOwnerEmail` fields.

**Threats (15):**
- **Exfiltration:** mass download, full-sync download.
- **Sharing:** anonymous link created, and used externally; external sharing, including
  to an unusual domain.
- **Malware:** malware detected, suspicious malware file name.
- **Privilege:** site collection admin added.
- **Destructive:** mass deletion, mass editing, mass upload (ransomware-style).
- **Recon:** sensitive (AIP-labelled) file access, SharePoint enumeration, OneDrive
  enumeration.

## `o365_dlp` — Data Loss Prevention

Built from the Management Activity DLP schema: `PolicyDetails[{PolicyName, Rules[{RuleName,
Actions, Severity, RuleMode, ConditionsMatched.SensitiveInformation[{Name, SensitiveType
(real SIT GUID), Count, Confidence}, ...]}]}]`, plus workload metadata (`ExchangeMetaData`
with `RecipientCount` for mail, `SharePointMetaData` with the full mandatory set —
`FileOwner`, `DocumentLastModifier`, `DocumentSharer`, `SiteCollectionGuid/Url`,
`UniqueId`, `IsViewableByExternalUsers`, `itemCreationTime`, `LastModifiedTime`,
`ItemSize`, …). RecordType is 13 for Exchange and 11 for SharePoint/OneDrive. String
property values are Microsoft-encoded. `UserKey` is `DlpAgent`. User-override records carry
top-level `ExceptionInfo {Reason, Justification}` (the mis-filed `OverrideInfo` was
removed). `DlpRuleUndo` is emitted only under the SharePoint workload. The source tenant
has no DLP policies, so this feed was built from the schema, not sampled from live rows. SIT pairs
and value semantics are doc-verified from the official entity-definition pages: credit
card `50842eb7-edc8-4019-85dd-5a5c1f2bb085`, U.S. SSN `a44669fe-0d48-453d-a9b1-2cc83f2cba77`,
U.S. bank account `a2ce32a8-f935-4bb6-8e96-2a5157672e2c`, ABA routing
`cb353f78-2b72-4c3c-8827-92ebe4f69fdf`, U.S. ITIN `e55e2a32-f92d-4985-a35d-a0b269eb687b`,
U.S./U.K. passport `178ec42a-18b4-47cc-85c7-d62c92fd67f8`; `SensitiveInformation` uses the
documented complex shape (`SensitiveType` GUID / `SensitiveInformationTypeName` /
`Count` / `UniqueCount` / `Confidence` with the documented High=85, Medium=75,
Low≤65 mapping), `RuleMode` = `Enforce` / `Audit with Notify` / `Audit only`, and
`ExceptionInfo` follows the documented complex type.
(RT40 `SecurityComplianceAlerts` — the aggregated DLP alert plane — is deliberately not
emulated yet.)

**Baseline:** low-severity, notify-only matches (routine false positives).

**Threats (4):** high-severity PII/PCI match blocked on outbound mail, blocked SharePoint
file share, a burst of matches (mass sensitive-data movement), sensitive data shared
externally.

## `o365_general` — General feed (Copilot, Power BI)

The catch-all workloads. Copilot records are aligned to the official Copilot audit schema:
top-level `ClientRegion` (ISO country) / `CopilotLogVersion`; `CopilotEventData` carries
`AppHost` from the documented host list (Teams/Word/Excel/PowerPoint/Outlook/M365App),
`Contexts[] = {Id, Type, ContainerId}` with real Type values (`docx`/`xlsx`/`pptx`/
`TeamsMeeting`/`TeamsChannel`/`TeamsChat`), `ThreadId`, `Messages[] = {Id, isPrompt}`,
`AccessedResources[] = {Id, SiteUrl, listItemUniqueId, Type, Name, SensitivityLabelId,
Action}` and `ModelTransparencyDetails[]` — every invented key (Graph-type accessed
resources, random MessageIds) was dropped. `AppIdentity` remains `"Copilot for Microsoft
365"` (not in the published schema; flagged unverified). Power BI records carry the
verified `WorkSpaceName`/`DashboardName`/`ReportName`/`DatasetName`/`CapacityID`/
`CapacityName`/`ReportSection` set; view/print/export op names verified against the Fabric
operation list. Success records are marked `ResultStatus: "Succeeded"`.

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
