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

## Baseline (benign) — build the "normal" profile
- Steady successful interactive sign-ins across a stable user pool from a few consistent
  corporate IPs/geos (`generate_benign` in both modules). This is what the ML detectors
  profile against; anomalies are judged relative to it.
- TODO: widen baseline realism — business-hours weighting, per-user home IP/ASN/geo
  stickiness, routine non-interactive token refreshes, common app mix (Office portal,
  Teams, Exchange), so "new country / new ASN / unusual time / unusual app" anomalies read true.

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
