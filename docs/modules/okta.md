# Okta SSO

**Dataset:** `okta_raw`
**Transport:** HTTP Collector
**Format:** Okta System Log REST API JSON (`/api/v1/logs` response format)

Simulates Okta Identity Engine (OIE) system log events for the XSIAM `okta_raw` dataset. The XSIAM built-in Okta parser maps the System Log event schema to XDM. Each event is a complete Okta `LogEvent` JSON object matching the `/api/v1/logs` API response format, including `actor`, `client`, `authenticationContext`, `securityContext`, `debugContext`, `target`, and `outcome` sub-objects.

- **XIF:** XSIAM built-in Okta parser
- **Key XDM fields:** `actor.displayName`, `actor.alternateId` (email), `client.ipAddress`, `client.geographicalContext`, `eventType`, `outcome.result`, `authenticationContext.authenticationProvider`, `securityContext.domain`
- **Transport config:** `okta_config.collector_id` references the `okta_collector` entry in `http_collectors`

---

## Okta SSO — Benign Events

Events are generated continuously as background noise. Core authentication events (session.start, SSO, MFA verify) are weighted 3× heavier than all others to produce a realistic enterprise baseline.

**User Session**

| EventType | Description |
|---|---|
| `user.session.start` | User login to Okta (password, FastPass, or MFA). Includes `debugContext`, `authenticationContext`, geo/IP context, and authenticator targets. |
| `user.session.end` | User logout from Okta. |
| `user.session.clear` | Admin clears all active sessions for a user. |
| `user.session.access_admin_app` | User accesses the Okta Admin Console from an active session. |
| `user.session.context.change` | Session context changes (network, device, or risk level shift). |
| `user.session.expire` | Session expires due to inactivity timeout. |

**User Authentication**

| EventType | Description |
|---|---|
| `user.authentication.sso` | User single sign on to app (SAML 2.0 or OIDC). |
| `user.authentication.auth_via_mfa` | MFA factor verification (Okta Verify Push, TOTP, SMS, Email, FastPass). |
| `user.authentication.verify` | Identity verification step (password accepted; MFA step now required). |
| `user.authentication.auth_via_webauthn` | WebAuthn/FIDO2 hardware key or passkey authentication (YubiKey, Touch ID, Windows Hello, Passkey). |
| `user.authentication.auth_via_kerberos` | Kerberos authentication via Okta Desktop SSO / AD-joined machine. |
| `user.authentication.auth_via_radius` | RADIUS authentication (corporate WiFi, VPN gateway, NAC). |
| `user.authentication.auth_via_IDP` | Authentication delegated to an external Identity Provider. |
| `user.authentication.auth_via_inbound_SAML` | Inbound SAML assertion from a federated IdP. |
| `user.authentication.auth_via_social` | Social login (Google, Apple, LinkedIn, GitHub, Microsoft, Facebook). |
| `user.authentication.slo` | Single logout — user session terminated across federated apps. |
| `user.authentication.universal_logout` | Universal Logout — all sessions terminated across all devices and apps. |

**User Account**

| EventType | Description |
|---|---|
| `user.account.update_password` | User self-service password change. |
| `user.account.reset_password` | Admin resets a user's password. |
| `user.account.expire_password` | Admin expires a user's password (forces reset on next login). |
| `user.account.lock` | Account locked after repeated authentication failures. |
| `user.account.lock.limit` | Account lock limit reached (elevated signal — may indicate brute force). |
| `user.account.unlock` | User self-unlocks via email/SMS recovery flow. |
| `user.account.unlock_by_admin` | Admin manually unlocks a locked account. |
| `user.account.unlock_token` | Account unlocked via one-time token. |
| `user.account.update_profile` | User or admin updates profile attributes (name, department, title). |
| `user.account.update_primary_email` | User changes their primary email address. |
| `user.account.update_secondary_email` | User changes their recovery/secondary email address. |
| `user.account.update_phone` | User changes their SMS/voice phone number. |
| `user.account.privilege.grant` | Admin role or privilege granted to a user. |
| `user.account.privilege.revoke` | Admin role or privilege revoked from a user. |
| `user.account.report_suspicious_activity_by_enduser` | User flags their own session as suspicious via end-user email alert. |

**User Lifecycle**

| EventType | Description |
|---|---|
| `user.lifecycle.create` | New user account created. |
| `user.lifecycle.activate` | User account activated (first login enabled). |
| `user.lifecycle.reactivate` | Previously deactivated account reactivated. |
| `user.lifecycle.suspend` | Account suspended (retains data; blocks login). |
| `user.lifecycle.unsuspend` | Suspended account restored. |
| `user.lifecycle.deactivate` | Account deactivated (soft delete). |
| `user.lifecycle.delete.initiated` | Account deletion initiated. |
| `user.lifecycle.delete.completed` | Account permanently deleted. |

**User MFA**

| EventType | Description |
|---|---|
| `user.mfa.factor.activate` | MFA factor enrolled and activated (Okta Verify, TOTP, SMS, Email, WebAuthn). |
| `user.mfa.factor.deactivate` | MFA factor removed from user's account. |
| `user.mfa.factor.suspend` | MFA factor temporarily suspended. |
| `user.mfa.factor.update` | MFA factor configuration updated. |
| `user.mfa.factor.reset_all` | Admin resets all MFA factors for a user. |
| `user.mfa.factor.challenge` | Okta presents MFA challenge (pre-verify step in OIE flow). |
| `user.mfa.okta_verify` | Okta Verify push notification sent. |
| `user.mfa.okta_verify.deny_push` | User explicitly denies an Okta Verify push notification. |
| `user.mfa.attempt_bypass` | Attempt to bypass MFA step detected. |

**User Risk**

| EventType | Description |
|---|---|
| `user.risk.detect` | Risk signal detected for a user (new country, anomalous behaviour, known threat IP). |
| `user.risk.change` | User's risk level changes (escalated or de-escalated). |

**User Registration**

| EventType | Description |
|---|---|
| `user.registration.create` | Self-service user registration submitted. |

**Group**

| EventType | Description |
|---|---|
| `group.lifecycle.create` | New group created. |
| `group.lifecycle.delete` | Group deleted. |
| `group.user_membership.add` | User added to a group. |
| `group.user_membership.remove` | User removed from a group. |
| `group.profile.update` | Group name or description updated. |
| `group.privilege.grant` | Admin privilege granted to a group. |
| `group.privilege.revoke` | Admin privilege revoked from a group. |
| `group.application_assignment.add` | Application assigned to a group. |
| `group.application_assignment.remove` | Application unassigned from a group. |

**Application Lifecycle & Membership**

| EventType | Description |
|---|---|
| `application.lifecycle.create` | New application integration created in Okta. |
| `application.lifecycle.activate` | Application activated. |
| `application.lifecycle.deactivate` | Application deactivated. |
| `application.lifecycle.delete` | Application deleted. |
| `application.lifecycle.update` | Application settings updated. |
| `application.user_membership.add` | User assigned to an application. |
| `application.user_membership.remove` | User unassigned from an application. |
| `application.user_membership.provision` | User provisioned in a downstream application (SCIM). |
| `application.user_membership.deprovision` | User deprovisioned in a downstream application (SCIM). |
| `application.policy.sign_on.deny_access` | Sign-on policy denied user access to an application. |
| `app.generic.provision.assign_user_to_app` | User assigned to app via provisioning. |
| `app.generic.import.started.incremental_import` | AD/LDAP incremental sync job started. |
| `app.generic.import.success` | AD/LDAP sync job completed successfully. |
| `app.generic.unauth_app_access_attempt` | Unauthorized attempt to access an application. |

**App User Management (SCIM / Provisioning)**

| EventType | Description |
|---|---|
| `app.user_management.push_new_user` | SCIM push creates a new user account in a downstream app. |
| `app.user_management.push_user_deactivation` | SCIM push deactivates a user account in a downstream app. |
| `app.user_management.push_password_update.success` | Password sync pushed successfully to downstream app. |
| `app.user_management.push_password_update.failure` | Password sync push failed (app unavailable, invalid credentials). |
| `app.user_management.push_profile_update.success` | Profile attribute sync pushed successfully to downstream app. |

**App Access Requests**

| EventType | Description |
|---|---|
| `app.access_request.request` | User requests access to an application. |
| `app.access_request.grant` | Access request approved. |
| `app.access_request.deny` | Access request denied. |

**App OAuth2 / OIDC**

| EventType | Description |
|---|---|
| `app.oauth2.as.authorize` | OAuth2 authorization request (SUCCESS or FAILURE). |
| `app.oauth2.as.authorize.scope_denied` | OAuth2 scope denied by policy. |
| `app.oauth2.as.token.grant.access_token` | Access token issued (authorization_code or client_credentials flow). |
| `app.oauth2.as.token.grant.refresh_token` | Refresh token issued. |
| `app.oauth2.as.token.grant.id_token` | OIDC id_token issued alongside access token. Fires on every OIDC login. |
| `app.oauth2.as.introspect` | Token introspection — API/service validates a bearer token. Common in microservice architectures. |
| `app.oauth2.as.token.revoke` | OAuth2 token revoked. |
| `app.oauth2.as.token.detect_reuse` | One-time refresh token reuse detected (potential session hijack). |
| `app.oauth2.as.consent.grant` | User grants OAuth2 consent to an app. |
| `app.oauth2.as.consent.revoke` | User revokes OAuth2 consent from an app. |
| `app.oauth2.signon` | OIDC SSO sign-on event. |
| `app.oauth2.client.lifecycle.create` | New OAuth2 client application registered. |
| `app.oauth2.client.lifecycle.delete` | OAuth2 client application deleted. |

**Policy**

| EventType | Description |
|---|---|
| `policy.evaluate_sign_on` | Sign-on policy evaluated for a user login attempt. |
| `policy.lifecycle.create` | New policy created. |
| `policy.lifecycle.update` | Policy updated. |
| `policy.lifecycle.delete` | Policy deleted. |
| `policy.lifecycle.activate` | Policy activated. |
| `policy.lifecycle.deactivate` | Policy deactivated. |
| `policy.rule.add` | Rule added to a policy. |
| `policy.rule.update` | Policy rule updated (e.g., MFA requirement changed). |
| `policy.rule.delete` | Policy rule deleted. |
| `policy.rule.activate` | Policy rule activated. |
| `policy.rule.deactivate` | Policy rule deactivated. |
| `policy.auth_reevaluate.fail` | Re-evaluation of auth policy failed for an active session. |
| `policy.entity_risk.evaluate` | Entity risk policy evaluated. |
| `policy.entity_risk.action` | Entity risk policy action taken (step-up MFA, session termination). |

**Security**

| EventType | Description |
|---|---|
| `security.threat.detected` | Okta ThreatInsight detected a threat (credential stuffing, brute force). |
| `security.attack.start` | Okta identifies the start of an attack pattern. |
| `security.attack.end` | Okta identifies the end of an attack pattern. |
| `security.breached_credential.detected` | Breached credential detected (dark web exposure, known breach). |
| `security.session.detect_client_roaming` | Session token used from a different IP than it was issued to. |
| `security.trusted_origin.create` | New trusted origin (CORS/redirect) added. |
| `security.trusted_origin.update` | Trusted origin updated. |
| `security.trusted_origin.delete` | Trusted origin deleted. |
| `security.events.provider.receive_event` | Third-party risk signal received (RISKY_USER from Zscaler, CrowdStrike, etc.). |
| `security.authenticator.lifecycle.activate` | Authenticator method activated org-wide. |
| `security.authenticator.lifecycle.deactivate` | Authenticator method deactivated org-wide. |

**Zone**

| EventType | Description |
|---|---|
| `zone.create` | New network zone created. |
| `zone.update` | Network zone updated. |
| `zone.delete` | Network zone deleted. |
| `zone.activate` | Network zone activated. |
| `zone.deactivate` | Network zone deactivated. |
| `zone.make_blacklist` | Zone added to blocklist. |
| `zone.remove_blacklist` | Zone removed from blocklist. |

**System**

| EventType | Description |
|---|---|
| `system.api_token.create` | API token created by an admin. |
| `system.api_token.revoke` | API token revoked. |
| `system.api_token.update` | API token updated. |
| `system.api_token.enable` | API token re-enabled. |
| `system.agent.ad.push_password_update` | AD agent syncs a password change from on-premises Active Directory. Actor is SystemPrincipal (not a human). Very high volume in hybrid deployments. |
| `system.email.send_factor_verify_message` | Email OTP verification message sent. |
| `system.email.password_reset.sent_message` | Password reset email sent. |
| `system.email.new_device_notification.sent_message` | New device notification email sent. |
| `system.sms.send_factor_verify_message` | SMS OTP verification message sent. |
| `system.sms.send_password_reset_message` | SMS password reset message sent. |
| `system.voice.send_mfa_challenge_call` | Voice call MFA challenge placed. |
| `system.voice.send_password_reset_call` | Voice call password reset placed. |
| `system.push.send_factor_verify_push` | Okta Verify push notification sent. |
| `system.idp.lifecycle.create` | External Identity Provider created. |
| `system.idp.lifecycle.update` | External Identity Provider updated. |
| `system.idp.lifecycle.delete` | External Identity Provider deleted. |
| `system.idp.lifecycle.activate` | External Identity Provider activated. |
| `system.idp.lifecycle.deactivate` | External Identity Provider deactivated. |
| `system.org.rate_limit.violation` | Org-level API rate limit violated. |
| `system.org.rate_limit.warning` | Org-level API rate limit warning threshold reached. |
| `system.org.rate_limit.burst` | Org-level API rate limit burst detected. |
| `system.log_stream.lifecycle.create` | Log streaming destination created (SIEM/Splunk/Datadog). |
| `system.log_stream.lifecycle.delete` | Log streaming destination deleted. |
| `system.mfa.factor.activate` | MFA factor type activated org-wide. |
| `system.mfa.factor.deactivate` | MFA factor type deactivated org-wide. |

**IAM (Custom Roles & Resource Sets)**

| EventType | Description |
|---|---|
| `iam.role.create` | Custom admin role created. |
| `iam.role.delete` | Custom admin role deleted. |
| `iam.role.update` | Custom admin role updated. |
| `iam.resourceset.bindings.add` | Admin role binding created (user assigned to custom role). |
| `iam.resourceset.bindings.delete` | Admin role binding removed. |

**Device**

| EventType | Description |
|---|---|
| `device.enrollment.create` | New device enrolled in Okta Device Trust. |
| `device.user.add` | Device assigned to a user. |
| `device.user.remove` | Device unassigned from a user. |
| `device.lifecycle.activate` | Device activated. |
| `device.lifecycle.deactivate` | Device deactivated. |
| `device.lifecycle.delete` | Device deleted from Okta. |
| `device.lifecycle.suspend` | Device suspended. |
| `device.lifecycle.unsuspend` | Device unsuspended. |
| `device.assurance.policy.evaluate` | Device assurance policy evaluated (COMPLIANT or NON_COMPLIANT). |

**Hooks**

| EventType | Description |
|---|---|
| `hook.outbound.request.sent` | Outbound event hook request sent to an external endpoint (Slack, SIEM, ServiceNow). Actor is SystemPrincipal. |

---

## Okta SSO — Threat Scenarios (88 Total)

All 88 threat scenarios are available from the Specific Threat menu. The module uses the `_make_threat_dict` pattern — adding a new entry automatically surfaces it in the menu without other changes.

**Authentication Attacks**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `brute_force` | Credential stuffing burst then account lock | `user.session.start` FAILURE ×N → `user.account.lock` |
| `mfa_bombing` | MFA push fatigue attack | `user.authentication.auth_via_mfa` FAILURE ×N (user denies pushes) |
| `mfa_bypass` | Attempt to step over MFA | `user.mfa.attempt_bypass` FAILURE |
| `password_spray` | Low-and-slow spray across many users | `user.session.start` FAILURE ×N (many users, same IP) |
| `sms_otp_bombing` | SMS OTP fatigue (20–40 messages) | `system.sms.send_factor_verify_message` ×20–40 burst to same user |
| `sso_brute_force` | SSO endpoint brute force | `user.authentication.sso` FAILURE ×N (same user) |
| `intense_sso_failures` | Mass SSO failure burst (50–200 events) | `user.authentication.sso` FAILURE ×50–200 (many users) |
| `sso_password_spray` | SSO spray across users | `user.authentication.sso` FAILURE ×N (different users, same IP) |
| `ip_rotation_sso` | Spray with rotating source IPs | `user.authentication.sso` FAILURE ×N (different IPs) |
| `radius_brute_force` | VPN/WiFi RADIUS brute force | `user.authentication.auth_via_radius` FAILURE ×20–50 |
| `tor_login` | Login from Tor exit node | `user.session.start` SUCCESS (Tor IP) |
| `sso_tor` | SSO from Tor exit node | `user.authentication.sso` SUCCESS (Tor IP) |
| `fastpass_phishing` | FastPass declined phishing attempt | `user.authentication.auth_via_mfa` FAILURE (reason = FastPass declined phishing) |
| `mfa_reset` | Admin bulk-resets all MFA for a user | `user.mfa.factor.reset_all` |
| `bulk_mfa_reset` | Admin resets MFA for 10–20 users | `user.mfa.factor.reset_all` ×10–20 |

**Impossible Travel & Geolocation**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `impossible_travel` | Geographically impossible login sequence | `user.session.start` (location A) → `user.session.start` (impossible location B, same user) |
| `sso_impossible_travel` | Impossible travel via SSO | `user.authentication.sso` (location A) → `user.authentication.sso` (impossible location B) |
| `sso_possible_imp_travel` | Suspicious but possible travel | `user.authentication.sso` × 2 (possible but very fast travel) |
| `sso_rejected_country` | Policy blocks login from restricted country | `user.authentication.sso` FAILURE + policy deny (high-risk country) |
| `sso_suspicious_country` | SSO from high-risk country (success) | `user.authentication.sso` SUCCESS (CN/RU/IR/KP/BY IP) |

**Anomalous Behaviour (UEBA)**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `sso_abnormal_ua` | Unusual user agent string | `user.authentication.sso` SUCCESS (uncommon browser/OS) |
| `sso_suspicious_auth` | Multiple simultaneous risk factors | `user.authentication.sso` SUCCESS (new country + new ASN + unusual time) |
| `sso_multi_unusual` | SSO failures to unusual apps | `user.authentication.sso` FAILURE ×5–10 (uncommon/sensitive apps) |
| `sso_unusual_time` | SSO at unusual hour | `user.authentication.sso` SUCCESS (outside business hours) |
| `service_account_login_abuse` | Service account used interactively | `user.session.start` + `user.authentication.sso` burst (non-interactive account behaves like a human) |
| `honey_auth` | Honeypot user account accessed | `user.session.start` SUCCESS (honeypot username — should never be used) |
| `honey_sso` | Honeypot user SSO accessed | `user.authentication.sso` SUCCESS (honeypot username) |
| `lateral_sso_attempts` | SSO failures across multiple apps | `user.authentication.sso` FAILURE ×5–10 (same user, different apps) |
| `benign_retry` | Normal user typo retry | `user.session.start` FAIL ×1–2 → SUCCESS (same user/IP, benign) |

**Session Attacks**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `aitm_phishing` | AiTM phishing proxy steals session token | `user.session.start` (phishing proxy IP) → `user.authentication.sso` ×3–5 (sensitive apps) → `security.session.detect_client_roaming` |
| `impersonation` | Admin impersonation of another user | `user.session.impersonation.grant` → `.initiate` → `.extend` → `.revoke` |
| `session_roaming` | Session token used from different IP | `security.session.detect_client_roaming` |
| `session_clear_bypass` | Sessions cleared then re-authenticated | `user.session.clear` → `user.session.start` SUCCESS (suspicious IP) |
| `universal_logout_bypass` | Universal logout then immediate re-login | `user.authentication.universal_logout` → `user.session.start` SUCCESS (same IP) |
| `admin_app_pivot` | Admin console accessed immediately after compromise | `user.authentication.sso` → `user.session.access_admin_app` (immediate pivot) |

**Privilege Escalation & Admin Abuse**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `rogue_admin_creation` | Admin creates a backdoor user with admin privileges | `user.lifecycle.create` → `user.account.privilege.grant` |
| `iam_privilege_escalation` | Custom role escalation to admin | `iam.role.create` → `iam.resourceset.bindings.add` → `user.account.privilege.grant` |
| `group_privilege_escalation` | Privilege granted to a group affecting many users | `group.privilege.grant` → `user.authentication.sso` |
| `admin_role_enumeration` | Attacker enumerates and expands admin roles | `user.session.access_admin_app` → `iam.role.update` ×4–6 → `iam.resourceset.bindings.add` ×3–5 → `user.account.privilege.grant` |
| `admin_privilege_revoke` | Admin privilege stripped from a user (insider leaving) | `user.account.privilege.revoke` |
| `iam_binding_add` | Resource set binding added (unexpected admin role assignment) | `iam.resourceset.bindings.add` |

**Defense Evasion**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `defense_evasion` | Log stream deleted + policy deactivated to blind SIEM | `system.log_stream.lifecycle.delete` → `policy.lifecycle.deactivate` → `user.authentication.sso` |
| `log_stream_evasion` | Admin console accessed then log stream deleted | `user.session.access_admin_app` → `system.log_stream.lifecycle.delete` |
| `event_hook_deletion` | Outbound event hooks deleted to silence external alerts | `system.event_hook.lifecycle.delete` → `user.authentication.sso` (activity continues unlogged externally) |
| `sign_on_policy_downgrade` | Sign-on policy weakened (MFA removed), then used immediately | `policy.rule.update` → `user.session.start` (no MFA) → `user.authentication.sso` |
| `mfa_downgrade_access` | User's MFA deactivated then login from new IP | `user.mfa.factor.deactivate` → `user.session.start` SUCCESS (new IP) |
| `authenticator_downgrade` | Org-wide authenticator deactivated | `system.mfa.factor.deactivate` → `user.authentication.auth_via_mfa` → `user.authentication.sso` |
| `zone_bypass_access` | Network zone deleted then SSO from removed zone's IP | `zone.delete` → `user.authentication.sso` SUCCESS (IP from deleted zone) |

**Identity Provider Attacks**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `shadow_idp_attack` | Rogue IdP registered and used to authenticate | `system.idp.lifecycle.create` → `user.authentication.auth_via_IDP` (new IdP) |
| `cross_idp_hijack` | Attacker registers, activates, and uses a rogue IdP | `system.idp.lifecycle.create` → `system.idp.lifecycle.activate` → `user.authentication.auth_via_IDP` ×N |
| `idp_delete` | Legitimate IdP deleted (disruption or sabotage) | `system.idp.lifecycle.delete` |

**OAuth2 & Token Attacks**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `malicious_oauth_app` | Rogue OAuth app registered with okta.* admin scopes | `app.oauth2.client.lifecycle.create` (okta.* scopes) → `app.oauth2.as.consent.grant` → `app.oauth2.as.token.grant.access_token` ×3–6 |
| `oauth_consent_abuse` | Broad OAuth scope consent then token harvest | `app.oauth2.as.consent.grant` (excessive scopes) → `app.oauth2.as.token.grant.access_token` burst |
| `oauth2_token_farm` | Token farming for persistent API access | `user.session.start` → `app.oauth2.as.token.grant.access_token` → `app.oauth2.as.token.grant.refresh_token` burst |
| `rogue_oauth_client_spray` | Rogue client registered then used for mass token grants | `app.oauth2.client.lifecycle.create` → `app.oauth2.as.token.grant.access_token` burst |
| `refresh_token_persistence` | Refresh tokens used for persistent long-term access | `user.session.start` → `app.oauth2.as.token.grant.access_token` → `app.oauth2.as.token.grant.refresh_token` ×N |
| `token_reuse` | Refresh token replayed (stolen token) | `app.oauth2.as.token.detect_reuse` |
| `oauth2_scope_denied` | Scope request denied by policy | `app.oauth2.as.authorize.scope_denied` |
| `api_token_abuse` | API token created then triggers rate limiting | `system.api_token.create` → `system.org.rate_limit.violation` |

**Risk-Based & Policy Signals**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `risk_detect` | Risk signal fires for a user | `user.risk.detect` |
| `risk_change` | User risk level escalated | `user.risk.change` |
| `risk_policy_bypass` | Risk detected but user bypasses step-up MFA | `user.risk.detect` → `policy.auth_reevaluate.fail` → `user.authentication.sso` SUCCESS |
| `policy_risk_action` | Entity risk policy takes automated action | `policy.entity_risk.action` |
| `policy_reeval_fail` | Policy re-evaluation fails for active session | `policy.auth_reevaluate.fail` |
| `policy_deny` | Sign-on policy denies access | `policy.evaluate_sign_on` DENY |
| `app_sign_on_deny` | Application sign-on policy denies access | `application.policy.sign_on.deny_access` |
| `breached_credential` | Breached credential detected | `security.breached_credential.detected` |
| `breached_credential_login` | Breached credential then successful login | `security.breached_credential.detected` → `user.session.start` SUCCESS |
| `third_party_signal_access` | Third-party risk signal (RISKY_USER) then SSO | `security.events.provider.receive_event` → `user.authentication.sso` |
| `threat_detected` | Okta ThreatInsight fires | `security.threat.detected` |
| `attack_start` | Okta marks start of attack pattern | `security.attack.start` |
| `reported_suspicious` | User self-reports suspicious activity | `user.account.report_suspicious_activity_by_enduser` |
| `account_lock_limit` | Account lock limit reached | `user.account.lock.limit` |
| `security_events_provider` | Third-party RISKY_USER signal received | `security.events.provider.receive_event` |

**Device Attacks**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `device_swap_enrollment` | Device deleted and replaced with attacker device | `device.lifecycle.delete` → `device.enrollment.create` → `user.authentication.sso` |
| `device_assurance_bypass` | Device assurance fails, then attacker uses different app | `device.assurance.policy.evaluate` NON_COMPLIANT → `user.authentication.sso` → `app.oauth2.as.authorize` (different app without assurance) |
| `mfa_enroll_attack` | Attacker enrolls new MFA factor to maintain persistence | `user.session.access_admin_app` → `user.mfa.factor.activate` → `user.authentication.auth_via_mfa` |
| `new_device_enrolled` | New device enrolled (may be attacker device) | `device.enrollment.create` → `user.mfa.factor.activate` |

**Lifecycle Attacks**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `ephemeral_account` | Account created and deleted within 60 seconds | `user.lifecycle.create` → `.activate` → `.deactivate` → `.delete.initiated` → `.delete.completed` |
| `scim_bulk_create` | SCIM agent bulk-creates backdoor accounts | `user.lifecycle.create` ×3–8 (SystemPrincipal actor, sequential) |
| `dormant_account_reactivation` | Dormant account reactivated then immediately accesses sensitive apps | `user.lifecycle.reactivate` → `user.authentication.sso` ×N (sensitive apps) |
| `registration_abuse` | Rapid self-registration burst | `user.registration.create` ×10–20 (rapid sequential) |

**Zone & Network Attacks**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `zone_blacklist` | Zone added to blocklist | `zone.make_blacklist` |
| `zone_update` | Zone config modified | `zone.update` |
| `sso_rejected_country` | Login blocked from restricted country zone | `user.authentication.sso` FAILURE + policy deny |

**Misc / Audit-Analytics Detections**

| Threat Key | Signal | EventType Chain |
|---|---|---|
| `mfa_factor_update` | MFA factor config changed | `user.mfa.factor.update` |
| `policy_rule_update` | Policy rule modified | `policy.rule.update` |
| `device_assigned` | Device assigned to a user | `device.user.add` |
| `unauth_app_access` | Unauthorized app access attempt | `app.generic.unauth_app_access_attempt` |
| `zone_blacklist` | Zone blacklisted | `zone.make_blacklist` |

## Attack Source Infrastructure (Tor is reserved)

Until 2026-10-02, 37 of the 82 threats sourced every event from a Tor exit, and the
three bulk sprays (`intense_sso_failures`, `sso_password_spray`, `password_spray`) sent
Tor-sourced SSO, ending in a success, to all ~500 users on every run. Every user's
Okta profile accumulated Tor activity, and the profile-scored Analytics BIOC
"A successful SSO sign-in from TOR" stopped firing after 2026-08-30. A tenant A/B showed
the August event shape no longer fires either, so the cause was the profile, not the
event format (`_local_validation/okta_tor_ab.py`).

- **Tor is used only by the threats where it is the signal:** `tor_login`, `sso_tor`,
  `tor_zone_bypass_access`, `tor_admin_app_pivot`, and `mfa_bombing` (left unchanged
  because its analytic fires today).
- **Every other threat** comes from attacker infrastructure: cloud/VPS hosting (55%,
  real provider ranges and ASNs), a commercial VPN (30%, still flagged as anonymized),
  or a residential-proxy exit (15%).
- **Tor is rare per user:** a Tor threat targets a user with no Tor activity yet in the
  current run, unless a scenario names its victim.

Measured locally: Tor fell to ~1.6% of threat events. Profiles already carrying Tor
history in the tenant decay on Cortex's schedule, so the Tor BIOC may take time to
return.

## User-Agent Fidelity

Okta previously picked a user-agent **at random per event** from a 33-entry pool, so one
person appeared to own 33 browsers — exactly backwards for "new device for this user".

Each event now reports the acting user's own sticky device agent, composed by
`modules/user_agents.py` and stable across restarts (a device fingerprint that changed on
every restart would make the whole estate look like new hardware). ~110 distinct agents
across the corpus, up from 33.

Threat generators that *need* an anomalous agent — `abnormal_user_agent`, `new_os`,
`abnormal_os` — still override it deliberately, so those detections continue to work.

Related: `Windows NT 11.0` was removed from the agent pools. It does not exist —
Windows 11 reports `Windows NT 10.0`, and Microsoft deliberately did not bump it.
