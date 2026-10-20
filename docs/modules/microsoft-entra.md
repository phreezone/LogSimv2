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
| `azuread_campaigns` | *(coordinator — sends through the three feeds above, plus Windows over WEC)* | — | — |

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

## Threat model

Microsoft feeds fire threats as **episodes** (one burst, sequence or session per episode)
from a wall-clock Poisson process (`azure_common.ThreatGate`). The rate doesn't depend on
how often the module is polled or how large a burst is. Each module first emits 500
benign records as a warmup so a baseline exists before any threat.

| Threat level | Episodes per hour, per module | Roughly, across all seven feeds |
|---|---|---|
| Benign Traffic Only | 0 | none |
| Realistic | 0.03 | ~5 a day |
| High | 0.6 | ~100 a day |
| Insane | 6.0 | ~1,000 a day |

The dashboard's **Elevated** and **Extreme** levels are not in the episode table, and
currently fall back to the Realistic rate for these feeds.

The Microsoft threats are not offered on the dashboard's **Fire Individual Threat** panel,
because no module maps them to a named analytic (`ANALYTIC_ALERTS`). They run in
long-running sessions and through the validation harness (below).

## `azuread_signin` — Graph sign-ins

**Baseline**, weighted like a real tenant. Mostly silent non-interactive token refreshes
(Outlook, Teams, OneDrive, mobile), then interactive sign-ins, then routine failures
(mistyped or expired password, MFA required). Each user keeps a stable corporate-egress
IP and home IP, so the ML analytics build coherent per-user profiles. Apps, resources
and error codes are drawn from what dominates a real Entra tenant.

**Threats (31):** brute force, password spray, account-lockout spray, impossible travel,
high-risk sign-in, TOR sign-in, SaaS API from TOR (desktop and mobile), multi-resource SSO,
multi-SSO through an anonymising proxy, AAD Connect sync from an unusual host, sign-in by
a disabled / dormant / honey user, suspicious-country and new-country sign-in, abnormal
user-agent / OS, machine-account SSO, SSO spray with IP rotation, pen-test tool activity,
first SSO to a resource / from a new ASN, unusual resource access by an app, app access
from an unknown tenant, service-principal and managed-identity token used remotely, device
code flow, service-account SSO, PowerShell sign-in, new-device sign-in.

## `azuread_audit` — Graph directory audit

Graph `directoryAudit` records. The `id` format is per service, activity names come
verbatim from the Entra audit activity reference, `modifiedProperties` old/new values are
JSON-encoded strings, and `additionalDetails` is a key/value list.

**Baseline.** The directory activity a tenant produces on its own: user and group
maintenance, app consent, password resets, device registration. Admin actions are pinned
to IT/admin role pools and follow business hours, so "unusual admin" and "unusual time"
hold up.

**Threats (38):** admin role assignment and multiple role removals, risky app consent,
app credential added, app privilege escalation, application owner added/removed, app role
assignment, application URI change, service principal created/removed, MFA fraud
reported, security info disabled, authentication method added, temporary access pass
registered, BitLocker key retrieval, Conditional Access policy removed or unusual CA
operation, PIM elevation request / alert disabled / member removal / role settings
change, device registration policy change, unusual guest invitation, unlock plus password
reset, first PowerShell operation, on-prem sync collision, account created / deleted /
short-lived, federation change failed / federated-domain backdoor, unverified domain
added, and the cross-tenant set: trust abuse, outbound sync, default weakened, delegated
admin partner abuse, multi-tenant org join.

Confirmed firing in the tenant: `admin_role_add` raises *Suspicious Azure AD Administrator
Role assignment*. `federated_domain_backdoor` raises *Rare unverified domain addition to
Azure AD* and *A successful Azure domain federation settings modification*.

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

## `azuread_campaigns` — cross-feed identity campaigns

Multi-stage kill chains (`modules/azuread_threat_sequences.py`) that thread one victim or
attacker identity through events in several datasets, so XSIAM can fold them into one
incident. Steps go to the Graph sign-in, Graph audit and O365 feeds over Cribl, and to
Windows over WEC. The Windows steps are skipped cleanly when `WEC_BROKER_URL` /
`WEC_PFX_PATH` aren't set.

- **Opt-in:** it only runs when selected. It emits nothing in Benign Traffic Only, and
  fires rarer than single-feed episodes: a campaign is one high-signal incident.
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
