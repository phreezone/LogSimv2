"""Azure AD / Entra multi-stage threat SEQUENCES (identity kill-chains).

Each sequence threads one victim/attacker identity through an ordered chain of events that
each trip a real XSIAM identity detector, so XSIAM correlates them into a high-severity
incident. Events span BOTH native datasets:
  - Graph sign-ins       -> msft_azure_ad_raw      (azuread_signin builders)
  - O365 Management Act.  -> msft_o365_azure_ad_raw (o365_azuread _signin RT15 / _audit RT8)

A sequence returns a list of (source_identifier, integration_identifier, record) tuples in
chronological order. No NAME attribute -> not auto-loaded as a continuous module; fired
on-demand via fire()/fire_all() (the way named threats run).

Mapped to the highest-severity identity detectors / ATT&CK techniques on the Analytics
pages (TOR sign-in High; federation/consent/credential/role persistence; account takeover).
"""
import random
import time

from modules import azure_common as ac
from modules import o365_azuread as o365
from modules import azuread_signin as aad

O365_SRC, O365_INT = o365.SOURCE_IDENTIFIER, o365.INTEGRATION_IDENTIFIER
AAD_SRC, AAD_INT = aad.SOURCE_IDENTIFIER, aad.INTEGRATION_IDENTIFIER

RISKY_IPS = ["185.220.101.34", "45.148.10.92", "193.218.118.158", "171.25.193.78"]
FOREIGN = {"ip": "103.21.244.12", "city": "Singapore", "state": "", "countryOrRegion": "SG",
           "geoCoordinates": {"latitude": 1.29, "longitude": 103.85}}
HOME_US = {"ip": "108.245.61.200", "city": "Columbus", "state": "Ohio", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 39.96, "longitude": -82.99}}


def _tor(config):
    nodes = (config or {}).get("tor_exit_nodes") if isinstance(config, dict) else None
    if nodes:
        n = random.choice(nodes)
        return n.get("ip") if isinstance(n, dict) else n
    return random.choice(RISKY_IPS)


def _loc(ip, city="Unknown", country="US", lat=0, lon=0):
    return {"ip": ip, "city": city, "state": "", "countryOrRegion": country,
            "geoCoordinates": {"latitude": lat, "longitude": lon}}


def _aad(rec):
    return (AAD_SRC, AAD_INT, rec)


def _o365(rec):
    return (O365_SRC, O365_INT, rec)


# ── sequences ─────────────────────────────────────────────────────────────────────────

def seq_aitm_token_theft(config):
    """AiTM/token-theft takeover: TOR sign-in (High) -> attacker registers MFA -> token reset."""
    u = ac.pick_user(config); ip = _tor(config); loc = _loc(ip)
    s = aad._signin(u, loc, interactive=True, risk_level="high", risk_state="atRisk", offset_s=-600)
    s["riskEventTypes_v2"] = ["anonymizedIPAddress", "unfamiliarFeatures"]
    return [_aad(s),
            _o365(o365._audit("User registered security info.", u, ip,
                              modified=[{"Name": "SecurityInfo.Method", "NewValue": "Mobile app notification", "OldValue": ""}])),
            _o365(o365._audit("Update StsRefreshTokenValidFrom Timestamp.", u, ip))]


def seq_spray_compromise_persist(config):
    """Password spray (Medium) -> success -> attacker adds MFA method (persistence)."""
    ip = random.choice(RISKY_IPS); out = []
    for i in range(10):
        v = ac.pick_user(config)
        out.append(_aad(aad._signin(v, _loc(ip), interactive=True, success=False, error_code=50126,
                                    failure="Invalid username or password.", conditional="notApplied",
                                    offset_s=-(300 - i * 10))))
    victim = ac.pick_user(config)
    out.append(_aad(aad._signin(victim, _loc(ip), interactive=True, offset_s=-30)))
    out.append(_o365(o365._audit("User registered security info.", victim, ip,
                                 modified=[{"Name": "SecurityInfo.Method", "NewValue": "Mobile app notification", "OldValue": ""}])))
    return out


def seq_golden_saml_federation(config):
    """Federation backdoor (T1484 Domain/Tenant Policy Modification): admin -> set federation -> add domain."""
    admin = ac.pick_user(config); ip = HOME_US["ip"]
    return [_aad(aad._signin(admin, HOME_US, interactive=True, ca_result="success", offset_s=-400)),
            _o365(o365._audit("Set federation settings on domain.", admin, ip, target_name=ac.UPN_DOMAIN,
                              modified=[{"Name": "IssuerUri", "NewValue": "http://attacker.sts/adfs/services/trust", "OldValue": ""},
                                        {"Name": "TokenSigningCertificate", "NewValue": "<attacker-cert-thumbprint>", "OldValue": "<orig>"}])),
            _o365(o365._audit("Add unverified domain.", admin, ip, target_name="attacker-backdoor.com"))]


def seq_illicit_oauth_consent(config):
    """Consent-phishing: user consents a malicious app risky scopes -> the app (SP) reads mail/files."""
    u = ac.pick_user(config); ip = ac.egress(u)["ip"]
    app_loc = _loc(random.choice(RISKY_IPS))
    return [_aad(aad._signin(u, ac.egress(u), interactive=True, app="My Apps", offset_s=-300)),
            _o365(o365._audit("Consent to application.", u, ip, target_name="O365 Mail Reader (malicious)",
                              modified=[{"Name": "ConsentContext.IsAdminConsent", "NewValue": "False", "OldValue": ""},
                                        {"Name": "ConsentAction.Permissions", "NewValue": "Mail.Read Files.ReadWrite.All offline_access", "OldValue": ""}])),
            _aad(aad._sp_signin(app_loc))]


def seq_sp_credential_abuse(config):
    """Service-principal credential add (Medium persistence) -> SP signs in from new IP."""
    admin = ac.pick_user(config); ip = ac.egress(admin)["ip"]
    return [_aad(aad._signin(admin, ac.egress(admin), interactive=True, ca_result="success", offset_s=-300)),
            _o365(o365._audit("Add service principal credentials.", admin, ip, target_name="LogSim Reporting App",
                              modified=[{"Name": "KeyDescription", "NewValue": "[KeyType=AsymmetricX509Cert]", "OldValue": ""}])),
            _aad(aad._sp_signin(_loc(random.choice(RISKY_IPS))))]


def seq_privesc_global_admin(config):
    """Privilege escalation: compromised user -> granted Global Admin -> PIM MFA requirement removed."""
    u = ac.pick_user(config); ip = _loc(random.choice(RISKY_IPS))["ip"]
    return [_aad(aad._signin(ac.pick_user(config), _loc(random.choice(RISKY_IPS)), interactive=True,
                             risk_level="medium", risk_state="atRisk", offset_s=-400)),
            _o365(o365._audit("Add member to role.", ac.pick_user(config), ip, target_name=u["upn"],
                              modified=[{"Name": "Role.DisplayName", "NewValue": "Global Administrator", "OldValue": ""}])),
            _o365(o365._audit("Update role setting in PIM.", u, ip, target_name="Global Administrator",
                              modified=[{"Name": "RequireMfaOnActivation", "NewValue": "False", "OldValue": "True"}]))]


def seq_mfa_tamper_takeover(config):
    """Defense evasion + takeover: attacker disables MFA for target, resets password, signs in as them."""
    attacker = ac.pick_user(config); target = ac.pick_user(config); ip = _loc(random.choice(RISKY_IPS))["ip"]
    return [_aad(aad._signin(attacker, _loc(ip), interactive=True, offset_s=-300)),
            _o365(o365._audit("Disable Strong Authentication.", attacker, ip, target_name=target["upn"],
                              modified=[{"Name": "StrongAuthenticationRequirement", "NewValue": "[]", "OldValue": "[{\"State\":\"Enforced\"}]"}])),
            _o365(o365._audit("Reset user password.", attacker, ip, target_name=target["upn"])),
            _aad(aad._signin(target, _loc(ip), interactive=True, offset_s=-30))]


def seq_impossible_travel_risky(config):
    """Impossible traveler: success in US then minutes later a high-risk success abroad."""
    u = ac.pick_user(config)
    s2 = aad._signin(u, FOREIGN, interactive=True, risk_level="high", risk_state="atRisk", offset_s=-60)
    s2["riskEventTypes_v2"] = ["unlikelyTravel"]
    return [_aad(aad._signin(u, HOME_US, interactive=True, offset_s=-600)), _aad(s2)]


def seq_backdoor_user(config):
    """Persistence via new account: admin creates a user and grants it a privileged role; it signs in."""
    admin = ac.pick_user(config); ip = ac.egress(admin)["ip"]
    backdoor = f"svc-helpdesk@{ac.UPN_DOMAIN}"
    bd = {"username": "svc-helpdesk", "upn": backdoor, "display_name": "Service Helpdesk",
          "department": "IT", "os_type": "Windows", "os_version": "10"}
    return [_aad(aad._signin(admin, ac.egress(admin), interactive=True, ca_result="success", offset_s=-500)),
            _o365(o365._audit("Add user.", admin, ip, target_name=backdoor)),
            _o365(o365._audit("Add member to role.", admin, ip, target_name=backdoor,
                              modified=[{"Name": "Role.DisplayName", "NewValue": "Privileged Role Administrator", "OldValue": ""}])),
            _aad(aad._signin(bd, _loc(random.choice(RISKY_IPS)), interactive=True, offset_s=-30))]


def seq_legacy_auth_bypass(config):
    """Legacy-auth MFA bypass: repeated legacy-protocol sign-ins (no MFA) succeed to Exchange."""
    u = ac.pick_user(config); ip = random.choice(RISKY_IPS); out = []
    for i in range(6):
        out.append(_aad(aad._signin(u, _loc(ip), interactive=True, client_app=random.choice(["IMAP4", "SMTP", "POP3"]),
                                    resource="Office 365 Exchange Online", success=(i >= 4),
                                    error_code=(0 if i >= 4 else 50126),
                                    failure="Invalid username or password.",
                                    conditional="notApplied", offset_s=-(240 - i * 20))))
    return out


SEQUENCES = {
    "aitm_token_theft": seq_aitm_token_theft,
    "spray_compromise_persist": seq_spray_compromise_persist,
    "golden_saml_federation": seq_golden_saml_federation,
    "illicit_oauth_consent": seq_illicit_oauth_consent,
    "sp_credential_abuse": seq_sp_credential_abuse,
    "privesc_global_admin": seq_privesc_global_admin,
    "mfa_tamper_takeover": seq_mfa_tamper_takeover,
    "impossible_travel_risky": seq_impossible_travel_risky,
    "backdoor_user": seq_backdoor_user,
    "legacy_auth_bypass": seq_legacy_auth_bypass,
}


def get_sequence_names():
    return list(SEQUENCES.keys())


def build(name, config=None):
    """Return the ordered (source_id, integration_id, record) tuples for a sequence."""
    return SEQUENCES[name](config or {})


def fire(name, config=None, sender=None):
    """Send one sequence via the cribl_direct transport, grouping records per source."""
    from integrations.cribl_direct import CriblDirectSender
    sender = sender or CriblDirectSender()
    groups = {}
    for src, integ, rec in build(name, config):
        groups.setdefault((src, integ), []).append(rec)
    results = []
    for (src, integ), recs in groups.items():
        results.append((name, sender.send(recs, src, integ)))
    return results


def fire_all(config=None):
    """Fire every sequence; returns [(name, [(src,(code,text,n)),...]), ...]."""
    sender = None
    from integrations.cribl_direct import CriblDirectSender
    sender = CriblDirectSender()
    out = []
    for name in SEQUENCES:
        out.append((name, fire(name, config, sender)))
        time.sleep(0.3)
    return out
