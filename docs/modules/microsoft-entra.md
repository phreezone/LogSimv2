# Microsoft Entra ID (Azure AD)

Three feeds model a Microsoft Entra tenant, and a fourth module chains them into
multi-stage identity campaigns. Identities come from LogSim's own user model
(`config.json` `user_profiles` / the session context), so a user who signs in to Entra
is the same person who logs on to Windows, browses through Zscaler and authenticates to
Okta.

| Module | Feed (record shape) | XSIAM dataset | Source-Identifier |
|---|---|---|---|
| `azuread_signin` | Microsoft Graph `auditLogs/signIns` | `msft_azure_ad_raw` | `f56dcfdf6bca43e793a4b6e9290e7b12` |
| `azuread_audit` | Microsoft Graph `auditLogs/directoryAudits` | `msft_azure_ad_audit_raw` | `0e076d5abe864bf78e8145ea9e0d749e` |
| `o365_azuread` | O365 Management Activity, `Audit.AzureActiveDirectory` (RecordType 15 sign-ins, 8 directory ops) | `msft_o365_azure_ad_raw` | `e1f109f886ea42fbb96be6ec0cc597a9` |
| `azuread_identity_protection` | Entra diagnostics: ProvisioningLogs, UserRiskEvents/ServicePrincipalRiskEvents (risk-state categories dropped by ingestion) | `msft_azure_raw` | `fce13a1d51294f84bae4a37851503060` |
| `azuread_campaigns` | *(coordinator — sends through the feeds above, plus Windows over WEC)* | — | — |

The Microsoft 365 workloads (Exchange, SharePoint/OneDrive, DLP, General) are on
[microsoft-365.md](microsoft-365.md). The detection research behind both pages is in
[MICROSOFT_DETECTION_CATALOG.md](../../MICROSOFT_DETECTION_CATALOG.md).

## Transport: the Cribl receiver (no Cribl instance needed)

All seven Microsoft feeds use `"transport": "cribl"` (set in each module's
`*_config` block in `config.json`). LogSim posts straight into the tenant's **integrated
Cribl receiver** in the exact wire shape a Cribl Stream "Cortex XSIAM" destination
produces, so the records land in the native dataset, parsed into columns and eligible
for analytics. There is no Cribl Stream instance at runtime and no Microsoft tenant.

**Setup**

1. In XSIAM: **Settings → Data Sources → add "Cribl"**, generate a token, and copy the
   API URL. It ends in `/logs/v1/integrated/cribl/data`.
2. In `.env`:
   ```bash
   CRIBL_COLLECTOR_URL=https://api-<tenant>.xdr.<region>.paloaltonetworks.com/logs/v1/integrated/cribl/data
   CRIBL_TOKEN=<token>
   ```
   Enter the bare token; LogSim adds the `Bearer ` prefix itself.
3. Install the Microsoft content packs (Office 365, Azure AD / Entra ID) in the tenant.
   Without them the records land but are not modeled into XDM, and analytics never see
   them.

**Wire format** (`integrations/cribl_direct.py`). Every piece is required. Leave any one
out and the request still returns HTTP 200, but the record lands unparsed in `_raw_log`:

| Element | Value |
|---|---|
| Method / URL | `POST` `CRIBL_COLLECTOR_URL` |
| `Authorization` | `Bearer <CRIBL_TOKEN>` |
| `Content-Type` / `Content-Encoding` | `application/json` / `gzip` |
| `Format` | `json` |
| `Source-Identifier` | the feed's catalog UUID (table above): selects dataset and parser, and must be exact |
| `Integration-Identifier` | any non-empty string (LogSim sends `logsim:<feed>`) |
| Body | gzip of NDJSON, one line per record: `{"data": <vendor record>, "collector_ms": <epoch ms>}` |

## Event Hub copies: reaching the Cloud analytics

XSIAM's Cloud analytics (the *Azure Audit Log* detectors) read `cloud_audit_logs`, not the
native Graph datasets. A canary on 2026-10-22 showed what reaches it:

| Record, posted to `msft_azure_raw` (Azure Event Hubs Source-Identifier `fce13a1d51294f84bae4a37851503060`) | `cloud_audit_logs` `log_name` |
|---|---|
| Entra diagnostic category `SignInLogs` / `NonInteractiveUserSignInLogs` / `ServicePrincipalSignInLogs` / `ManagedIdentitySignInLogs` | `azure_ad_signin_logs` |
| `MicrosoftGraphActivityLogs` (one record per Graph API request) | `microsoft_graph_activity_logs` |
| `AuditLogs` | `azure_ad_audit_logs` (same log type as the Graph directoryAudits feed, but the Event Hub data source the Cloud detectors require) |

The Graph signIns feed (`msft_azure_ad_raw`) never reaches `cloud_audit_logs`, and most
Entra detectors in the *Azure Audit Log* list are tagged *Microsoft Graph Activity Logs*.
They key on the Graph request (`POST /users`, `POST .../addPassword`, `GET .../content`),
not the audit record. Thirty days of ~600 Add user / Add service principal / Add owner
audit records raised none of them.

The rest (*A Service Principal was created / removed in Azure*, *Azure application removed*,
*PIM privilege member removal*, *Azure permission delegation granted*, *Granting Access to an
Account*, *Removal of an Azure Owner*) list **Azure Audit Log** as required data and run in
the Cloud module. That is the Event Hub data source (`msft_azure_raw`), not the Graph feed.
The firing Entra detectors (*Azure AD PIM alert disabled*, federation, role assignment,
unverified domain) list **AzureAD Audit Log** and run in the Identity Threat Module. In
`cloud_audit_logs` both kinds of audit record land as `azure_ad_audit_logs`, but the Cloud
detectors read only what arrives through the Event Hub data source.

So the modules also emit Event Hub copies, routed per record to the Azure Event Hubs
Source-Identifier (`integrations.cribl_direct.ROUTE_KEY`; the cribl transport groups a
batch by destination and strips the key before sending):

- `azuread_signin`: every sign-in also goes out in the Event Hub sign-in envelope. Some
  successful sign-ins are followed by their client's routine Graph calls (Teams, Outlook,
  OneDrive, daemon apps).
- `azuread_audit`: every directory record also goes out in the Event Hub `AuditLogs`
  envelope. The exception is benign records whose operation a Cloud detector raises on by
  itself (`azure_audit_catalog.CLOUD_ALERTING_ACTIVITIES`: service principal/application
  create and delete, owners, role members, consent, users, groups, guests, Conditional
  Access, authentication methods). Scenarios are copied in full.
- `azuread_threat_sequences` (and so the campaigns): each sign-in gets its Event Hub copy;
  each directory change gets its AuditLogs copy, preceded by its Graph call where one is
  mapped.
- Scenarios aimed at a Graph-activity detector add the Graph requests behind them. These
  are `azuread_audit` user/group/app/CA/auth-method changes, Exchange inbox rules and
  mailbox enumeration, and SharePoint/OneDrive downloads, uploads and enumeration.
- The record builders live in `modules/graph_activity.py` (a helper, not a generator).

Benign traffic never contains a Graph request one of those detectors raises on by
itself, and benign directory/Exchange/SharePoint records carry no companion. To turn the
copies off for a module, set `"eventhub_copies": false` in its `config.json` block.

## Threat model

Microsoft feeds fire threats as **episodes** (one burst, sequence or session per episode)
from a wall-clock Poisson process (`azure_common.ThreatGate`). The rate doesn't depend on
how often the module is polled or how large a burst is. Each module first emits 500
benign records as a warmup so a baseline exists before any threat.

| Threat level | Episodes per hour, per module | Roughly, across all seven feeds |
|---|---|---|
| Benign Traffic Only | 0 | none |
| Realistic | 0.03 | ~5 a day |
| Elevated | 0.15 | ~25 a day |
| High | 0.6 | ~100 a day |
| Extreme | 2.0 | ~340 a day |
| Insane | 6.0 | ~1,000 a day |

These are the same six levels as every other module (`threat_generation_levels` in
`config.json`); only the pacing differs. Before 2026-10-20 this table also had two private
levels (Low, Medium) that nothing could select, and lacked Elevated and Extreme, which fell
back to the Realistic rate.

The Microsoft threats are not offered on the dashboard's **Fire Individual Threat** panel,
because no module maps them to a named analytic (`ANALYTIC_ALERTS`). They run in
long-running sessions and through the validation harness (below).

## `azuread_signin` — Graph sign-ins

**Baseline**, weighted like a real tenant. Mostly silent non-interactive token refreshes
(Outlook, Teams, OneDrive, mobile), then interactive sign-ins, then routine failures
(mistyped or expired password, MFA required). Each user keeps a stable corporate-egress
IP and home IP, so the ML analytics build coherent per-user profiles. Apps, resources
and error codes are drawn from what dominates a real Entra tenant.

**Egress is real-world consistent.** XSIAM geolocates IPs itself, so every block in
`azure_common` is announced by the ISP the record names and located by GeoLite in the
city it names. This covers the 10 office NAT pools, the home ISPs and mobile carriers in
each office's metro, the Azure daemon pool and the hosting networks attackers come from.
Each was checked against RIPEstat (origin ASN, MaxMind GeoLite) plus ipinfo on 2026-10-22.
A home day or a phone sign-in stays in the user's metro and country, so it never looks
like travel. Attacker egress comes from about 20M addresses across 13 hosting providers,
each prefix sitting in a single country. Re-verify any block you change.

**Threats (37):** brute force, password spray, account-lockout spray, impossible travel,
high-risk sign-in, TOR sign-in, SaaS API from TOR (desktop and mobile), multi-resource SSO,
multi-SSO through an anonymising proxy, AAD Connect sync from an unusual host, sign-in by
a disabled / dormant / honey user, suspicious-country and new-country sign-in, abnormal
user-agent / OS, machine-account SSO, SSO spray with IP rotation, pen-test tool activity,
first SSO to a resource / from a new ASN, unusual resource access by an app, app access
from an unknown tenant, service-principal and managed-identity token used remotely, device
code flow, service-account SSO, PowerShell sign-in, new-device sign-in. Graph-activity only:
directory enumeration through Graph, app and user throttling (HTTP 429), repeated denied
requests (HTTP 403), response-size spike, privileged app role used.

## `azuread_audit` — Graph directory audit

Graph `directoryAudit` records. The `id` format is per service, activity names come
verbatim from the Entra audit activity reference, `modifiedProperties` old/new values are
JSON-encoded strings, and `additionalDetails` is a key/value list.

**Baseline.** The directory activity a tenant produces on its own: user and group
maintenance, app consent, password resets, device registration. Admin actions are pinned
to IT/admin role pools and follow business hours, so "unusual admin" and "unusual time"
hold up.

**Threats (39):** admin role assignment and multiple role removals, risky app consent,
app credential added, app privilege escalation, application owner added/removed, app role
assignment, application URI change, service principal created/removed, MFA fraud
reported, security info disabled, authentication method added, temporary access pass
registered, BitLocker key retrieval, Conditional Access policy removed or unusual CA
operation, PIM elevation request / alert disabled / member removal / role settings
change, device registration policy change, unusual guest invitation, unlock plus password
reset, first PowerShell operation, on-prem sync collision, account created / deleted /
short-lived, federation change failed / federated-domain backdoor, unverified domain
added, security group created and deleted, and the cross-tenant set: trust abuse,
outbound sync, default weakened, delegated admin partner abuse, multi-tenant org join.

Confirmed firing in the tenant (fire → alert observed, 2026-10-30; promoted in
`ANALYTIC_ALERTS` with the exact observed names):

| Scenario | Observed XSIAM alert | Severity |
| --- | --- | --- |
| `admin_role_add` | A cloud identity escalated its permissions to a high privilege role/policy | Low |
| `consent_risky_app` | First seen Azure admin consent to an application | Low |
| `unverified_domain_added` | Rare unverified domain addition to Azure AD | Low |
| `federated_domain_backdoor` | A successful Azure domain federation settings modification | Medium |
| `ca_policy_removed` | Conditional Access policy removed | Low |
| `pim_alert_disabled` | Azure AD PIM alert disabled | Medium |
| `pim_role_settings_change` | Azure AD PIM role settings change | Low |
| `unusual_guest_invitation` | Rare successful guest invitation in the organization | Low |
| `tor_signin` (sign-ins) | A successful SSO sign-in from TOR | High |
| `first_sso_resource_org` (sign-ins) | Abnormal first access to a resource via SSO in the organization | Low |

Every directory/sign-in record shape in this module was diffed field-by-field against real
`*.onmicrosoft.com` tenant rows (2026-10-30) and matches. Scenarios whose records are
field-correct but do not raise a standalone alert from a synthetic one-shot are marked WIP
in-code with the reason: **Informational** severity (no standalone alert), **14-day activation
+ 30-day training**, **Identity Analytics + Cloud Identity Engine + baseline** (brute force /
spray / lockout / impossible travel, disabled / honey / service / machine / dormant accounts),
a **real tenant DLP policy** (DlpRuleMatch), or a **cross-tenant activation baseline**. This
tenant's live login brute-force coverage is Okta / Cisco-ASA correlation rules, and the
standalone spray/brute analytics are VPN/host-based rather than Azure AD SSO.

## `o365_azuread` — O365 Management Activity (Azure AD workload)

`Audit.AzureActiveDirectory` records in the `manage.office.com` shape. RecordType 15 is
StsLogon sign-ins and RecordType 8 is directory operations. This is a different feed and
dataset from the Graph sign-ins above, as in a real tenant that collects both.

**Baseline:** mostly successful interactive sign-ins, some routine failures, occasional
directory activity.

**Threats (14):** password spray, brute force, impossible travel, TOR sign-in, admin role
add and admin role removals, MFA disabled, privileged auth method added, atypical account
deletion, non-standard account creation, create-then-delete user, federation change, user
deletion, PIM role change.

## `azuread_identity_protection` — provisioning & Identity Protection

A standalone benign feed for the Entra diagnostic categories the `msft_azure_raw` modeling rule
maps but no other module produced: **ProvisioningLogs** (SCIM / HR-driven app provisioning sync
cycles) and the risk-detection categories **UserRiskEvents** / **ServicePrincipalRiskEvents**.
Records carry the Graph resource (`provisioningObjectSummary`, `riskDetection`) in `properties`,
in the event-hub envelope, sent under the Azure Event Hubs Source-Identifier. Every `properties`
path is one the modeling rule reads, and a 2026-10-23 canary confirmed ProvisioningLogs and
UserRiskEvents land in `msft_azure_raw` and map to XDM.

**Not emitted: the risk-*state* categories** `RiskyUsers` / `RiskyServicePrincipals`. The same
canary showed this ingestion path accepts them at the receiver but drops them before the dataset
(they never land, not even raw) — the source's parsing rule admits provisioning and risk-event
categories but not risk-state, so the modeling rule's `RiskyUsers` branch never receives a row.
Emitting them would only produce discarded sends.

Benign only: provisioning sync dominates, and risk detections stay low-level and
dismissed/remediated — the baseline the risk analytics learn. Genuinely risky sign-ins are the
needle the `azuread_signin` scenarios provide.

## Feed volumes

A real tenant is not an equal split across feeds, so each generator declares an `EVENT_INTERVAL`
(its default per-call interval) and the dashboard starts it at that rate. "Start all" with no
explicit interval keeps the relative shape: sign-ins highest (~0.15 s), then Exchange and
SharePoint, Activity and O365-AAD, then directory audit, with General, Identity Protection and
DLP the rarest. Set a per-module rate or pass an interval to "Start all" to scale the whole stack
up or down while keeping the proportions.

## `azuread_campaigns` — cross-feed identity campaigns

Multi-stage kill chains (`modules/azuread_threat_sequences.py`) that thread one victim or
attacker identity through events in several datasets, so XSIAM can fold them into one
incident. Steps go to the Graph sign-in, Graph audit and O365 feeds over Cribl, and to
Windows over WEC. The Windows steps are skipped cleanly when `WEC_BROKER_URL` /
`WEC_PFX_PATH` aren't set.

- **Dashboard:** each campaign is an entry under **Threats & Scenarios → Run Attack
  Scenario** ("Identity Campaign — …"); there is no module card. A run fails visibly if
  the Cribl receiver rejects a batch.
- **Random campaigns:** the **Random identity campaigns** toggle at the top of that panel
  launches one random campaign about every 12 hours (exponential waits, never less than
  2 hours apart). Change it with `random_mean_hours` / `random_min_gap_hours` in
  `azuread_campaigns_config`. It is off on every dashboard start. API:
  `GET/POST /api/v1/campaigns/random` with `{"enabled": true|false}`.
- **CLI:** still loadable as the opt-in coordinator module. It emits nothing in Benign
  Traffic Only and fires rarer than single-feed episodes: a campaign is one high-signal
  incident.
- **Campaigns (21):** BEC, ransomware, OAuth app abuse, illicit OAuth consent, stale
  account reactivation, insider threat, hybrid on-prem→cloud, refresh-token→PRT
  transition, AiTM token theft, spray→compromise→persist, golden SAML federation,
  service-principal credential abuse, privesc to Global Admin, MFA tamper takeover,
  impossible travel + risky sign-in, backdoor user, legacy-auth bypass, rogue-tenant
  cross-tenant sync, delegated-admin partner takeover, multi-tenant org join, outbound
  cross-tenant sync.

## Optional: Cloud Identity Engine identity map

By default, Entra users are not linked to directory identities, so ITDR enrichment
doesn't attach. To turn it on, point `LOGSIM_CIE_IDENTITY_MAP` (or `cie_identity_map_path`
in `config.json`) at an identity map exported from Cloud Identity Engine. The default
path, used when present, is `state/cie_identity_map.json`.

## Validation

`_local_validation/threat_harness.py` fires a threat through the real transport,
confirms ingestion by counting new rows in the target dataset, and polls analytics alerts
for a match.

```bash
python _local_validation/threat_harness.py list
```
```bash
python _local_validation/threat_harness.py fire admin_role_add
```
```bash
python _local_validation/threat_harness.py detect-all 180
```

Key prefixes: plain names are `azuread_audit`, `si:` sign-ins, `o365:` O365 Azure AD,
`seq:` campaigns. Run with LogSim stopped so the window holds only what the harness fired.
Behavioural analytics need the source's 14-day activation and 30-day training period
before they can fire. The correlation and BIOC rules fire without a baseline.
