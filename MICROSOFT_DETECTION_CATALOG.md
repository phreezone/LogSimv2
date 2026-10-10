# Microsoft Connector Detection Catalog (XSIAM)

Target detections for the synthetic Microsoft generators (`modules/o365_azuread.py`,
`modules/azuread_signin.py`), pushed via the `cribl_direct` transport into the native
datasets. Source of truth: Cortex **Analytics Alerts — alerts-by-name** reference and the
**Cortex Analytics Content release notes**.

## Datasets / dedicated UUIDs
| Feed | Dataset | Source-Identifier UUID | Record shape |
|------|---------|------------------------|--------------|
| O365 Management Activity (Azure AD) | `msft_o365_azure_ad_raw` | `e1f109f886ea42fbb96be6ec0cc597a9` | Audit.AzureActiveDirectory (RecordType 15 = StsLogon sign-ins; RecordType 8 = directory audit ops) |
| Azure AD sign-ins (Graph) | `msft_azure_ad_raw` | `f56dcfdf6bca43e793a4b6e9290e7b12` | Graph `auditLogs/signIns` object |
| Azure AD audit (Graph) | `msft_azure_ad_audit_raw` | *(catalog)* | Graph `auditLogs/directoryAudits` object |

## Activation note (important)
Most Azure AD / SSO detectors are **Analytics / Analytics BIOC** and carry **Activation
Prerequisites** — they stay *Pending Activation* until XSIAM has collected enough baseline
data (the "normal" profile). Brand-new datasets fire nothing until then. This is why the
generators emit a **continuous benign baseline** (default `generate_log` behavior) in
addition to the attack scenarios. Correlation rules and some value-keyed BIOCs
(e.g. specific audit Operations) can fire without a long baseline.

## Azure AD / Entra log types & content (research)

Microsoft Entra emits several distinct log streams; XSIAM ingests them into different
datasets. The generators model the two the tenant pulls natively:

**1. Sign-in logs** — Graph `auditLogs/signIns` → `msft_azure_ad_raw`. Sub-types (by volume):
- **Non-interactive user sign-ins** — *highest volume by far* (often 10–50× interactive):
  silent token refresh by Outlook/Teams/OneDrive sync/mobile/broker. `isInteractive=false`,
  `signInEventTypes=["nonInteractiveUser"]`, `authenticationDetails` method "Previously
  satisfied", `conditionalAccessStatus` success/notApplied, `status.errorCode=0`.
- **Interactive user sign-ins** — user hits a portal/app; MFA often satisfied via session.
  `signInEventTypes=["interactiveUser"]`, apps like Office365 Shell/OfficeHome/Teams.
- **Service-principal / managed-identity sign-ins** — app-only auth (e.g. the Cortex XDR
  collector itself). No UPN; `servicePrincipalName` instead.
- Key fields: `userPrincipalName`, `appDisplayName`, `resourceDisplayName`, `ipAddress`,
  `clientAppUsed` (Browser | Mobile Apps and Desktop clients), `conditionalAccessStatus`,
  `status.errorCode`, `riskState`/`riskLevelDuringSignIn`, `deviceDetail{}`, `location{}`
  (all nested objects stored as stringified JSON in the dataset).

**2. Directory audit logs** — Graph `auditLogs/directoryAudits` → `msft_azure_ad_audit_raw`
(and the same activity appears in O365 Management Activity RecordType 8). Categories:
UserManagement, GroupManagement, ApplicationManagement, RoleManagement, Policy, Device.
Common Operations: Add/Update/Delete user, Add/Remove member from group, Add member to
role, Change/Reset user password, Add service principal, Consent to application, Update
application credentials, Set federation settings on domain, Disable Strong Authentication.

**3. O365 Management Activity (Audit.AzureActiveDirectory)** → `msft_o365_azure_ad_raw`
(what this tenant pulls natively). `RecordType 15` = StsLogon sign-ins (Operation
UserLoggedIn / UserLoginFailed, `ExtendedProperties` ResultStatusDetail/UserAgent/RequestType
like `Login:login`/`Kmsi:kmsi`/`OAuth2:Authorize`, `DeviceProperties`, `ErrorNumber`,
`LogonError`); `RecordType 8` = AzureActiveDirectory directory audit (Operation +
ModifiedProperties). Shared fields: CreationTime, Id, OrganizationId, UserId (UPN),
ClientIP, Workload=AzureActiveDirectory, Actor[], Target[].

Common benign `status.errorCode` / `ErrorNumber`: `0` success; `50126` invalid password,
`50055` expired password, `50074`/`50072` MFA required, `50058` insufficient SSO session,
`50053` account locked, `53003` blocked by CA, `50128`/`50059` tenant/user not found.

## Baseline (benign) — implemented, keyed to LogSim's user model
Identities come from `config['user_profiles']` / `session_context` via
`modules/azure_common.py` (UPN = the profile email `@examplecorp.com`, same identity used by
every other module; device OS from the profile). Each user has a **stable public egress**:
mostly their department's shared office NAT IP, sometimes a deterministic home IP — so the
ML detectors build a coherent per-user IP/ASN/country baseline and anomalies read true.

Weighted mix emitted by `generate_benign` (reflects real tenant volume):
- **Sign-ins (`msft_azure_ad_raw`)**: ~70% non-interactive token refresh, ~22% interactive
  success (some MFA), ~8% benign failure (expired/mistyped password, MFA needed, SSO session).
- **O365 (`msft_o365_azure_ad_raw`)**: ~78% UserLoggedIn success, ~12% UserLoginFailed
  (benign codes), ~10% routine directory ops (update user, group add/remove, password change).

App mix: Office 365 Portal, Office365 Shell, OfficeHome, Teams, My Apps, Authentication
Broker, OneDrive SyncEngine, Outlook Mobile. Resources: Microsoft Graph, Exchange Online,
SharePoint Online, Windows Azure AD.

### Implemented sign-in variants (A) & directory-audit ops (B)
Field-faithful against Microsoft Graph `signIn` / `directoryAudit` /
`appliedConditionalAccessPolicy` resources, cross-checked with the Microsoft Sentinel
`SigninLogs` column schema and real tenant records (61-column sign-in; RT8 ops observed
natively: `Update user.`, `Reset user password.`, `Update PasswordProfile.`,
`Add service principal.` — Management-Activity trailing-period naming).

**A — sign-in variants in the benign mix (`msft_azure_ad_raw`):**
- non-interactive token refresh (incomingTokenType=primaryRefreshToken) — highest volume
- interactive success **evaluated by Conditional Access** (`appliedConditionalAccessPolicies`
  populated: id/displayName/enforcedGrantControls/result) + `authenticationRequirementPolicies`
- MFA-challenge sign-in (`authenticationDetails` with the MFA method, `authenticationMethodsUsed`)
- **service-principal** sign-in (`signInEventTypes=["servicePrincipal"]`, servicePrincipalName, clientCredentialType)
- **guest / B2B** sign-in (`userType=guest`, `crossTenantAccessType=b2bCollaboration`)
- **legacy-auth** attempt (clientAppUsed IMAP4/POP3/SMTP/… → CA-blocked, ResultType 53003)
- benign failures (50126/50055/50074/50072/50058)
Richer fields now emitted to match the real record: autonomousSystemNumber, tokenIssuerType,
incomingTokenType, authenticationProtocol, deviceDetail.trustType, networkLocationDetails,
authenticationProcessingDetails.

**B — directory-audit ops in the benign mix (`msft_o365_azure_ad_raw`, RecordType 8):**
categories from `azure_common.AUDIT_OPS` — UserManagement (Update user / Change|Reset password /
Update PasswordProfile), GroupManagement (add/remove/update group, with Group.DisplayName
ModifiedProperties), AuthMethod (register/delete security info), DeviceManagement (register
device/owner), ApplicationManagement (Consent to application with ConsentContext props).

TODO (further realism): business-hours/day-of-week weighting; occasional new-device /
new-app first-seen events; the Graph `directoryAudits` feed (`msft_azure_ad_audit_raw`) and
provisioning-log stream as separate sources.

## Threat sequences (multi-stage kill-chains) — `modules/azuread_threat_sequences.py`
Each sequence threads one identity through an ordered chain of events (across both
datasets) that each trip a detector, so XSIAM correlates them into a high-severity
**incident**. Fired on-demand via `fire(name)` / `fire_all()` (not continuous). All 10
verified landing parsed.

| Sequence | Chain (ATT&CK) | Key detectors tripped |
|----------|----------------|-----------------------|
| `aitm_token_theft` | TOR sign-in → register MFA → token reset | SSO sign-in from TOR (**High**), security-info reg |
| `spray_compromise_persist` | password spray → success → attacker MFA added | SSO Brute Force (Med) + persistence |
| `golden_saml_federation` | admin → Set federation settings → add domain | Federation modification (T1484), domain add |
| `illicit_oauth_consent` | user consents malicious app (Mail.Read/Files.RW) → SP reads data | Azure application consent, SP sign-in |
| `sp_credential_abuse` | admin → add SP credentials → SP sign-in from new IP | Azure application credentials added (Med) |
| `privesc_global_admin` | risky sign-in → granted Global Admin → PIM MFA removed | Identity assigned Azure AD Admin Role (Med), PIM change |
| `mfa_tamper_takeover` | disable MFA for target → reset password → sign in as target | MFA disabled, password reset, takeover |
| `impossible_travel_risky` | US success → foreign high-risk success minutes later | Impossible traveler, high-risk sign-in |
| `backdoor_user` | admin creates user → grants privileged role → it signs in | Account manipulation, privileged role add |
| `legacy_auth_bypass` | repeated legacy-protocol (IMAP/SMTP) sign-ins succeed (no MFA) | Legacy-auth MFA bypass to Exchange |

## New-device & Low-severity events (added to the baseline + scenarios)
- **New device seen**: `azure_common.device_for(user, new=True)` → sign-in from a brand-new
  unmanaged device; ~5% of the benign mix and the `new_device_signin` scenario. Users
  otherwise carry a stable per-user `deviceId` so first-seen reads as an anomaly.
- **Low scenarios**: `new_country_signin` (new-country/first-connection), `account_lockout_spray`
  (errorCode 50053 across users → "Multiple user accounts failed login due to account lockouts"),
  plus the earlier `powershell_signin`, `mfa_disabled`, `federation_change`, `user_deletion`,
  `pim_role_change`, `admin_role_removals`.

## Low-and-higher severity targets

| Detector | Severity | Type | Trigger (synthetic pattern) | Scenario |
|----------|----------|------|------------------------------|----------|
| A successful SSO sign-in from TOR | High | BIOC | successful sign-in whose source IP is a known TOR exit node | `risky_ip_signin` / `high_risk_signin` — **needs real TOR exit IPs** (wire to the Tor list) |
| SSO Brute Force | Medium | Analytics Alert | abnormally high SSO auth attempts in a short window (then a success) | `brute_force`, `password_spray` ✅ |
| Suspicious authentication with Azure Password Hash Sync user | Medium | BIOC | sign-in as the PHS/AAD-Connect sync account | TODO |
| Azure AD PIM alert disabled | Medium | BIOC | audit Operation disabling a PIM alert | TODO (RecordType 8) |
| Suspicious Azure AD interactive sign-in using PowerShell | Low | Analytics Alert | interactive sign-in, `appDisplayName` = Azure PowerShell, from unusual geo/ASN | TODO (signin: set app + risky ASN) |
| MFA was disabled for an Azure identity | Low | BIOC | audit Operation disabling strong auth / MFA for a user | TODO (RecordType 8) |
| Azure domain federation settings modification attempt | Low | BIOC | audit Operation "Set federation settings on domain" | TODO (RecordType 8) |
| Azure account deletion by a non-standard account | Low | BIOC | audit Operation "Delete user" by a non-admin actor | TODO (RecordType 8) |
| First Azure AD PowerShell operation for a user | Low | BIOC | first audit op via Azure AD PowerShell for a user | TODO |
| Azure AD PIM role settings change | Low | BIOC | audit Operation changing PIM role settings | TODO (RecordType 8) |
| Multiple Azure AD admin role removals | Low | Analytics Alert | several admin-role removals in a short window | TODO (RecordType 8 burst) |
| Multiple user accounts failed login due to account lockouts | Low | Analytics Alert | many distinct users hitting lockout (errorCode 50053) from one source | TODO (variant of spray) |
| Microsoft 365 storage services exfiltration activity | Low | Analytics Alert | high-volume download/share from M365 storage | TODO (SharePoint/OneDrive feed) |
| Identity assigned an Azure AD Administrator Role | Informational | BIOC | audit "Add member to role" → Global Administrator | `admin_role_add` ✅ (O365 Mgmt Activity) |

## Informational (baseline-relative) — covered, lower priority
Impossible traveler - SSO, SSO Password Spray, A possible risky login to Azure,
A user connected from a new country, SSO with abnormal user agent / new OS, Intense SSO
failures. Built scenarios: `impossible_travel`, `password_spray`, `high_risk_signin`.

## Next build order
1. Wire `risky_ip_signin` to real TOR exit IPs → **High** "SSO sign-in from TOR".
2. Add a RecordType-8 directory-audit record builder to `o365_azuread.py` and the
   audit-Operation scenarios (MFA disabled, federation mod, PIM change, user deletion,
   admin-role removals) → several **Low/Medium** BIOCs.
3. Add "Suspicious Azure AD interactive sign-in using PowerShell" (**Low**) to the signin module.
4. Broaden the benign baseline (home-IP/ASN stickiness, business hours, app mix) so the
   ML detectors activate and anomalies read true.
