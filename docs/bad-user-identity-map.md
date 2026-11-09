# Bad User identity map — what to link in an XSIAM unified user profile

Every identifier a LogSim user appears under, which feeds and fields carry it, and the
rule that derives it from the AD account. Built 2026-11-05 from a full Bad User run
(39,038 records, every feed, most of the allowed threats) with
`_local_validation/baduser_identity_inventory.py`; example values are for `k.zhang`.

The anchor is the AD `sAMAccountName` — the key of `config.json` → `user_profiles`.
Everything below is either a fixed format of it, a value stored in that profile, or a
deterministic hash of it.

## 1. User identifiers

| # | Identifier | Example (`k.zhang`) | Derive from anchor | Feeds → fields |
|---|---|---|---|---|
| 1 | **sAMAccountName** (anchor) | `k.zhang` | — | Windows `TargetUserName`, `SubjectUserName`, `user.name` · ESXi `user` (`k.zhang@<src-ip>` in sshd/hostd lines) · ASA VPN username (bare) |
| 2 | **DOMAIN\user** | `EXAMPLECORP\k.zhang` | `EXAMPLECORP\` + anchor (NetBIOS from `windows_events_config.domain_name`) | Check Point / Firepower / FortiGate `suser` · PAN `source_user`, `srcuser`, `users` · ASA `(EXAMPLECORP\k.zhang)` identity-firewall suffix |
| 3 | **UPN / email** | `k.zhang@examplecorp.com` | anchor + `@examplecorp.com` (UPN suffix ≠ AD DNS domain `examplecorp.local`) | Entra sign-ins `userPrincipalName` · Entra audit `initiatedBy.user.userPrincipalName`, `targetResources[].userPrincipalName` · Azure Activity `caller`, `identity.claims.upn/name`, `identity.requester.upn` · O365 `UserId`, `MailboxOwnerUPN`, DLP `*MetaData.From/FileOwner` · Okta `actor.alternateId`, `target[].alternateId` · GCP `principalEmail` · Zscaler `suser` · Proofpoint `recipient` |
| 4 | **Display name** | `Karen Zhang` | profile `display_name` | Entra `userDisplayName`, `initiatedBy.user.displayName` · Azure Activity `identity.claims.name` · Okta `actor.displayName` · Zscaler `deviceOwner` · Exchange `ModifiedObjectResolvedName` |
| 5 | **Given / surname** | `Karen` / `Zhang` | split of display name | Azure Activity `claims/givenname`, `claims/surname` |
| 6 | **Entra object id** | `95a66757-e74b-ec26-aed3-d8acca308d6f` | `azure_common.user_oid()` — hash of the anchor, or the real objectId when the CIE identity map is loaded | Entra `userId`, `initiatedBy.user.id`, `targetResources[].id` · Graph activity `userId` · O365 `UserKey`, `Actor[].ID`, Exchange `TokenObjectId` · Azure Activity `claims/objectidentifier`, `principalId`, `requester.objectId` |
| 7 | **AD SID** | `S-1-5-21-3457937927-2839227994-823803824-5151` | domain SID + RID hashed from the anchor (`windows_events._stable_user_sid`) | Windows `SubjectUserSid`, `TargetUserSid`, `TargetSid`, `security_user_id` · Entra `onPremisesSecurityIdentifier` **only when the CIE identity map is loaded** |
| 8 | **Okta user id** | `00utPay0w4JLtAwUqxwh` | `okta_sso._stable_user_id()` — hash of the anchor | Okta `actor.id`, `target[].id` (Okta-only: join it through #3 `alternateId`) |
| 9 | **M365 PUID** | `10035C2DA9ED859B` | `azure_common.user_puid()` — hash of the anchor | Azure Activity `identity.claims.puid` · Exchange mailbox-row `UserKey` |
| 10 | **AWS IAM user** | `Karen.Zhang` | profile `aws_iam_user` (= display name with `.` for the space) — **not derivable from the anchor**, needs the mapping | AWS `userIdentity.userName`, `userIdentity.arn` = `arn:aws:iam::<acct>:user/Karen.Zhang`, `requestParameters.userName`, `resources[].ARN` |
| 11 | **OneDrive personal site** | `personal/k_zhang_examplecorp_com` | UPN with `.` and `@` → `_` | SharePoint `SiteUrl`, `ObjectId`, `SourceRelativeUrl` |

Optional aliases the attack scenarios create for the same person (link only if you want
exfiltration destinations on the profile):

| Identifier | Example | Where |
|---|---|---|
| Personal / forwarding mailbox | `kzhang@gmail.com`, `kzhang@outlook.com`, `kzhang@proton.me` | Exchange forwarding rules `Parameters[].Value`, `Recipients[]` (first initial + surname) |
| Guest UPN in another tenant | `kzhang@fabrikam.com`, `kzhang@contoso.com`, `kzhang@partnerco.com` | Entra sign-ins `userPrincipalName` in the cross-tenant campaigns |

## 2. Host and network identifiers (the user's computer)

| # | Identifier | Example | Feeds → fields |
|---|---|---|---|
| 12 | **Hostname** | `SALES-LT-009` (phone `KZHANG-GALAXYS24`) | Entra `deviceDetail.displayName` · SharePoint `DeviceDisplayName` · Entra audit device objects · Windows `WorkstationName` · Check Point / Firepower / FortiGate / Zscaler `shost` · Zscaler `devicehostname` · PAN `source_device_host`, `src_host` · Infoblox DHCP `(SALES-LT-009)` |
| 13 | **FQDN** | `SALES-LT-009.examplecorp.local` | Windows `computer_name`, `host_name` · Infoblox PTR / DDNS `sales-lt-009.examplecorp.local` |
| 14 | **MAC** | `18:db:f2:c0:93:a6` | FortiGate `srcmac` · PAN `source_device_mac`, `src_mac` · Infoblox DHCP ACK/EXPIRE |
| 15 | **Internal IP** | `192.168.10.26` | Windows `IpAddress` · all firewall `src` / ASA `inside:` · Zscaler `src` · Infoblox `client …#port`, threat `src` · ESXi `user@192.168.10.26` |
| 16 | **Egress (public) IP** | `51.171.78.11` | Entra `ipAddress`, `callerIpAddress` · O365 `ClientIP`, `ActorIpAddress` · Azure Activity `callerIpAddress`, `claims.ipaddr` · Okta `client.ipAddress` · AWS `sourceIPAddress` · GCP `callerIp` · Proofpoint `clickIP` · Zscaler `sourceTranslatedAddress` · PAN `nat_source` · ASA mapped address `(51.171.78.11/port)` |

#15 ↔ #16 is the firewall NAT pair (ASA mapped address, PAN `natsrc`, Zscaler
`sourceTranslatedAddress`): an XSIAM rule or profile can join on-prem activity (internal IP)
to cloud activity (egress) through it.

The egress (#16) is the office NAT, shared by everyone at the site and by the normal
(non-Bad User) traffic running at the same time. Bad User only sends a record that also
names the target (#1–#11) or carries their hostname or internal IP; the egress alone never
qualifies it. A correlation rule joining two feeds should therefore key on the user as well
as the IP. A join on the egress alone pairs the target with every other account behind it.

## 3. Linking rules to configure

1. `sAMAccountName` = UPN local part = email local part (`k.zhang` ↔ `k.zhang@examplecorp.com`).
2. `DOMAIN\user`: strip `EXAMPLECORP\` → `sAMAccountName`.
3. Entra object id ↔ UPN: from Entra itself (sign-in and audit records carry both).
4. AD SID ↔ sAMAccountName: from Windows events (4624 etc. carry both); ↔ Entra only via the CIE identity map.
5. Okta user id ↔ UPN: from Okta itself (`actor.id` + `actor.alternateId` in the same record).
6. AWS IAM user ↔ person: **needs an explicit mapping** (`user_profiles.<user>.aws_iam_user`) — the name has no fixed relation to the AD account.
7. GCP `principalEmail` = UPN (no `gcp_iam_user` is configured for anyone).
8. Display name ↔ UPN: from Entra / Okta records.
9. Host: hostname ↔ FQDN (append `.examplecorp.local`) ↔ MAC ↔ internal IP (Infoblox DHCP leases carry all of them).
10. Internal IP ↔ egress IP: firewall NAT fields (§2).

## 4. Linking gaps found and fixed (2026-11-05)

- **A. Cloud device names now match the computer.** Entra `deviceDetail.displayName`,
  SharePoint `DeviceDisplayName`, Entra audit device objects and the campaigns used
  `KZHANG-PC` / `K.ZHANG-PC` / `K-Phone`; they now carry the configured hostnames
  (`SALES-LT-009`, phone `KZHANG-GALAXYS24`) via `azure_common.device_name()` →
  `session_utils.user_device_name()`. The machine-account SSO scenario signs in as the
  real computer account (`SALES-LT-009$`).
- **B. One PUID per person.** `azure_common.user_puid()` (`1003` + 12 hex) is both the Azure
  Activity `puid` claim and the Exchange mailbox-row `UserKey` (Exchange used its own hash).
- **C. Stable AWS identity ids.** An IAM user has one `AIDA…` principalId and one long-lived
  `AKIA…` key (about a third of users hold a second, used ~1 call in 5); roles have one
  `AROA…` id. Temporary `ASIA…` STS keys and `AROA…:session` principals still vary per
  session, as in AWS. Role ids generated inside individual threat functions are still random.
- **D. Still open: no on-prem attributes on Entra records** unless the CIE identity map
  (`state/cie_identity_map.json`) is populated: `onPremisesSecurityIdentifier` /
  `onPremisesSamAccountName` are what tie the Entra object to the AD SID.

## 5. XSIAM Unified Human Identity correlation rules

XSIAM builds a Unified Human Identity from **identity assets** in the inventory (Settings →
Configurations → Identity Configuration → Correlation Rules). A rule compares one attribute
of a source provider's user asset with one attribute of a destination provider's user
asset; matches from all enabled rules combine transitively (A↔B and B↔C puts A, B and C in
one identity). Methods, per the Cortex docs:

- **Exact match** — values identical.
- **Partial match** — the source value appears inside the destination value (source ≥ 4 chars).
- **Regex** — RE2 pattern applied to the **destination** value; its first capture group must
  exactly equal the source value. Anchor with `^…$` and escape dots.

The **system rules** (enabled by default) already link every provider by **email**. The
custom rules below cover what email alone misses. Pick the human-user asset type for each
provider in the Asset Type dropdown.

| # | Source: Technology → Asset Type has Attribute | Method | Destination: Technology → Asset Type matches Attribute | Links (example) |
|---|---|---|---|---|
| S | any provider → user → **Email** | Exact (system rule) | any provider → user → **Email** | `k.zhang@examplecorp.com` everywhere it is populated |
| 1 | Active Directory → User → **Username** | Regex `^(.+)@examplecorp\.com$` | Azure Entra ID → User → **User Principal Name** | `k.zhang` ↔ `k.zhang@examplecorp.com` |
| 2 | Active Directory → User → **Username** | Regex `^(.+)@examplecorp\.com$` | Okta → User → **Username** (Okta login) | `k.zhang` ↔ `k.zhang@examplecorp.com` |
| 3 | Active Directory → User → **User Principal Name** | Exact | Azure Entra ID → User → **User Principal Name** | `k.zhang@examplecorp.com` ↔ same (hybrid-synced UPN) |
| 4 | Azure Entra ID → User → **User Principal Name** | Exact | Okta → User → **Username** | `k.zhang@examplecorp.com` ↔ same |
| 5 | Azure Entra ID → User → **User Principal Name** | Exact | GCP / Google Workspace → User → **Email** | `k.zhang@examplecorp.com` ↔ GCP `principalEmail` |
| — | AWS Identity Store → User → **Email** | Exact (system rule S — no custom rule) | any provider → user → **Email** | `k.zhang@examplecorp.com` ↔ the IAM Identity Center user's email |

Notes:

- **AD UPN suffix.** LogSim's UPN suffix is `examplecorp.com` while the AD DNS domain is
  `examplecorp.local`. If the real directory's UPNs end in `.local`, use
  `^(.+)@examplecorp\.local$` in rules 1–2 and an extra rule for `.local` ↔ `.com`.
- **AWS appears as AWS Identity Store (IAM Identity Center) with Email only.** The system
  email rule links those users to Entra/AD/Okta; no custom rule is needed. Classic IAM
  users are not Identity Store identities. LogSim's AWS activity, however, is generated as
  classic IAM users (`IAMUser Karen.Zhang`), so it never attaches to the Identity Store
  identity. To attach, human AWS activity must look like Identity Center sessions:
  `userIdentity.type = AssumedRole`, role `AWSReservedSSO_<PermissionSet>_<suffix>`, and
  session name = the user's Identity Store username, normally their email
  (`arn:aws:sts::<acct>:assumed-role/AWSReservedSSO_…/k.zhang@examplecorp.com`).
- **Okta user id, Entra object id, AD SID, PUID** are provider-internal ids; they link
  through the attributes above, not through rules of their own.
- **Log-only formats are not identity assets.** `EXAMPLECORP\k.zhang` (firewalls, PAN),
  `suser` (Zscaler), Proofpoint recipients, Windows `TargetUserName`, O365 `UserId` and the
  host identifiers in §2 are fields in logs, not provider users, so these rules never see
  them; they reach the person through XSIAM's normal user/host entity handling in issues
  and cases.
- **Prerequisite:** the rules only group identities that exist in the identity inventory.
  LogSim's `examplecorp` users are synthetic, so they have no AD/Entra/Okta/AWS identity
  assets to group unless the same accounts exist in a connected provider (see §6). The
  examples above use `examplecorp.com`; substitute your own UPN domain.

## 6. Portability: what works with and without an identity provider

LogSim is meant to be downloaded and run by anyone, and most people will have no Entra
tenant, no Cloud Identity Engine (CIE) and no identity license. The shipped setup is
therefore fully synthetic (`<user>@examplecorp.com`, `EXAMPLECORP\<user>`, hashed object
ids and SIDs), and nothing from a real tenant belongs in the repository.

### Works for everyone, out of the box

- **Bad User case linking.** Every event Bad User sends carries the same user, host,
  internal IP and office egress IP (§1–§2). XSIAM groups alerts into cases by the user,
  host and IP entities they share, so the target's activity across feeds builds into one
  case with no identity provider, connector or extra license.
- **Log-based detectors** that read only the ingested logs.

### Needs a connected identity provider (optional)

- **Unified Human Identities (§5).** Per the Cortex docs, this needs an XSIAM Premium, Cloud
  Posture Security or Cloud Runtime Security license and Cloud Identity Security, Cortex
  ITDR or Cortex SaaS Security. It groups identity accounts that XSIAM inventories from
  connected sources (on-prem directories, identity providers, cloud platforms, SaaS). The
  docs describe no way to create those identities from log events or to upload them, so
  LogSim cannot supply them; without a provider, the §5 rules have nothing to group.
- **Identity-analytics detectors** (Azure AD brute force, password spray, lockout,
  impossible travel) need CIE, Identity Analytics and a baseline period.

### Opting in with your own tenant

Anyone who does have connected providers can point LogSim at them with local files only.
`state/` is git-ignored, so nothing tenant-specific is committed or shared.

1. **Accounts in the providers.** The people you run Bad User against must exist in the
   connected providers with the same email everywhere (Entra UPN/mail = Okta login = AWS
   Identity Store email = Google email). The system email rules then group them; add the
   §5 custom rules with your UPN domain.
2. **CIE identity map.** `state/cie_identity_map.json` (template via
   `azure_common.write_identity_map_template`) holds each user's real Entra objectId,
   on-prem SID and sAMAccountName. The Microsoft feeds read it today.

Not built yet; only needed for this opt-in path:

- **Identity domain is hard-coded.** About 217 `examplecorp` literals across 25 modules
  (UPN/email domain `azure_common.UPN_DOMAIN`, Entra tenant id `HOME_TENANT_ID`, SharePoint
  host, …). Only `windows_events_config.domain_name` / `dns_domain`,
  `infoblox_config.ad_domain` and `proofpoint_config.internal_domain` are configurable.
- **Windows and Okta ignore the identity map.** `windows_events._stable_user_sid` and
  `okta_sso._stable_user_id` still hash the username.
- **AWS uses classic IAM users** (`IAMUser Karen.Zhang`), which never attach to an AWS
  Identity Store identity. Attaching needs human activity as IAM Identity Center sessions
  (§5 note) in the onboarded account.
- **GCP** already uses the email as `principalEmail`; the project must be the onboarded one
  (`GCP_PROJECT_ID`).
