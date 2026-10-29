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
import inspect
import random
import time

from modules import azure_common as ac
from modules import o365_azuread as o365
from modules import azuread_signin as aad
from modules import azuread_audit as aaud
from modules import o365_sharepoint as spo
from modules import o365_exchange as exch
from modules import o365_dlp as dlp
from modules import windows_events as winev

O365_SRC, O365_INT = o365.SOURCE_IDENTIFIER, o365.INTEGRATION_IDENTIFIER
AAD_SRC, AAD_INT = aad.SOURCE_IDENTIFIER, aad.INTEGRATION_IDENTIFIER
AUD_SRC, AUD_INT = aaud.SOURCE_IDENTIFIER, aaud.INTEGRATION_IDENTIFIER
SP_SRC, SP_INT = spo.SOURCE_IDENTIFIER, spo.INTEGRATION_IDENTIFIER
EX_SRC, EX_INT = exch.SOURCE_IDENTIFIER, exch.INTEGRATION_IDENTIFIER
DLP_SRC, DLP_INT = dlp.SOURCE_IDENTIFIER, dlp.INTEGRATION_IDENTIFIER
# Sentinel source for on-prem Windows events: these ride the WEC transport (not Cribl), so fire()
# and the harness route a WIN_SRC tuple's record (a windows event dict) through the WEC path.
WIN_SRC, WIN_INT = "__wec__", "logsim:windows"

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


def _aaud(rec):
    return (AUD_SRC, AUD_INT, rec)


def _spo(rec):
    return (SP_SRC, SP_INT, rec)


def _exch(rec):
    return (EX_SRC, EX_INT, rec)


def _dlp_(rec):
    return (DLP_SRC, DLP_INT, rec)


def _win(rec):
    """Wrap an on-prem Windows event DICT for the WEC transport (rendered to XML at fire time)."""
    return (WIN_SRC, WIN_INT, rec)


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
                              modified=[{"Name": "IssuerUri", "NewValue": "http://any.sts/adfs/services/trust", "OldValue": ""},
                                        {"Name": "TokenSigningCertificate", "NewValue": "<attacker-cert-thumbprint>", "OldValue": "<orig>"}])),
            _o365(o365._audit("Add unverified domain.", admin, ip,
                              target_name=ac.rare_domain(kind="federation")))]


def seq_illicit_oauth_consent(config):
    """Consent-phishing: user consents a malicious app risky scopes -> the app (SP) reads mail/files."""
    u = ac.pick_user(config); ip = ac.egress(u)["ip"]
    app_loc = _loc(random.choice(RISKY_IPS))
    return [_aad(aad._signin(u, ac.egress(u), interactive=True, app="My Apps", offset_s=-300)),
            _o365(o365._audit("Consent to application.", u, ip, target_name=ac.rare_app_name(),
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


def seq_rogue_tenant_cross_tenant_sync(config):
    """Rogue-tenant trust (cloud 'rogue forest join', T1484.002 Trust Modification): a compromised
    admin trusts an attacker-controlled external tenant via cross-tenant access + cross-tenant sync,
    inbound B2B users are provisioned from it, one is granted a privileged role, then signs in from
    the rogue tenant. Spans sign-ins, O365 directory audit, and the Graph directory-audit feed."""
    admin = ac.pick_by_role(config, aaud.ADMIN_ROLES, ("IT", "Security"))
    ip = _tor(config)
    rogue = ac.rare_tenant()            # one never-seen rogue tenant threaded through every step
    guest_upn = f"intern_{rogue['domain'].split('.')[0]}#EXT#@{ac.UPN_DOMAIN}"
    out = []
    # 1) admin account takeover from an anonymized/foreign IP (High)
    s = aad._signin(admin, _loc(ip), interactive=True, risk_level="high", risk_state="atRisk",
                    offset_s=-900)
    s["riskEventTypes_v2"] = ["anonymizedIPAddress", "unfamiliarFeatures"]
    out.append(_aad(s))
    # 2) trust the rogue external tenant: cross-tenant access + cross-tenant sync (3 audit records)
    # (between the -900 s takeover and the guest steps below; the invite lands <= -240 s)
    for rec in aaud.scenario_cross_tenant_trust_abuse(config, rogue=rogue, start=time.time() - 840):
        out.append(_aaud(rec))
    # 3) inbound B2B guest provisioned from the rogue tenant
    out.append(_o365(o365._audit("Add user.", admin, ip, target_name=guest_upn,
                                 modified=[{"Name": "UserType", "NewValue": "Guest", "OldValue": ""},
                                           {"Name": "Source", "NewValue": rogue["domain"], "OldValue": ""}],
                                 offset_s=-180)))
    # 4) privileged role granted to the provisioned guest (privilege path through the trust)
    out.append(_o365(o365._audit("Add member to role.", admin, ip, target_name=guest_upn,
                                 modified=[{"Name": "Role.DisplayName", "NewValue": "Privileged Role Administrator", "OldValue": ""}],
                                 offset_s=-120)))
    # 5) the rogue-tenant guest signs in cross-tenant and uses the access
    g = dict(admin); g["upn"] = guest_upn; g["username"] = "intern_rogue"; g["display_name"] = "intern (external)"
    out.append(_aad(aad._signin(g, _loc(ip), interactive=True, user_type="guest",
                                cross_tenant="b2bCollaboration", app="My Apps", offset_s=-30)))
    return out


def seq_delegated_admin_partner_takeover(config):
    """GDAP/DAP partner takeover: admin takeover -> an external partner is added and promoted with
    Global Admin over the tenant -> the partner acts (adds a role) -> partner signs in cross-tenant."""
    admin = ac.pick_by_role(config, aaud.ADMIN_ROLES, ("IT",)); ip = _tor(config)
    rogue = ac.rare_tenant()
    out = [_aad(aad._signin(admin, _loc(ip), interactive=True, risk_level="high",
                            risk_state="atRisk", offset_s=-700))]
    for rec in aaud.scenario_delegated_admin_partner_abuse(config, rogue=rogue,
                                                           start=time.time() - 660):
        out.append(_aaud(rec))
    # partner-controlled admin grants itself a directory role, then signs in from the partner tenant
    partner_upn = f"partner-admin_{rogue['domain'].split('.')[0]}#EXT#@" + ac.UPN_DOMAIN
    out.append(_o365(o365._audit("Add member to role.", admin, ip, target_name=partner_upn,
                                 modified=[{"Name": "Role.DisplayName", "NewValue": "Global Administrator", "OldValue": ""}],
                                 offset_s=-60)))
    g = dict(admin); g["upn"] = partner_upn; g["username"] = "partner_admin"
    out.append(_aad(aad._signin(g, _loc(ip), interactive=True, user_type="guest",
                                cross_tenant="b2bCollaboration", app="Azure Portal", offset_s=-20)))
    return out


def seq_multitenant_org_join(config):
    """Tenant folded into an attacker-run multi-tenant org with inbound identity sync -> members
    provisioned from the attacker tenant (cloud 'rogue forest' persistence)."""
    admin = ac.pick_by_role(config, aaud.ADMIN_ROLES, ("IT", "Security")); ip = _tor(config)
    rogue = ac.rare_tenant()
    out = [_aad(aad._signin(admin, _loc(ip), interactive=True, risk_level="high",
                            risk_state="atRisk", offset_s=-1200))]
    for rec in aaud.scenario_multitenant_org_join(config, rogue=rogue, start=time.time() - 1140):
        out.append(_aaud(rec))
    out.append(_o365(o365._audit("Add user.", admin, ip,
                                 target_name=f"mto_member_{rogue['domain'].split('.')[0]}#EXT#@" + ac.UPN_DOMAIN,
                                 modified=[{"Name": "UserType", "NewValue": "Member", "OldValue": ""},
                                           {"Name": "Source", "NewValue": rogue["domain"] + " (MTO sync)", "OldValue": ""}],
                                 offset_s=-60)))
    return out


def seq_cross_tenant_sync_outbound(config):
    """Outbound cross-tenant sync: admin takeover -> outbound B2B + user sync to the rogue tenant ->
    our users are provisioned OUT (user/data exfiltration via the identity fabric)."""
    admin = ac.pick_by_role(config, aaud.ADMIN_ROLES, ("IT", "Security")); ip = _tor(config)
    rogue = ac.rare_tenant()
    out = [_aad(aad._signin(admin, _loc(ip), interactive=True, risk_level="high",
                            risk_state="atRisk", offset_s=-1200))]
    for rec in aaud.scenario_cross_tenant_sync_outbound(config, rogue=rogue, start=time.time() - 1140):
        out.append(_aaud(rec))
    # a couple of our users get provisioned outbound (modeled as directory reads of the sync job)
    for i in range(2):
        v = ac.pick_user(config)
        out.append(_o365(o365._audit("Add user.", admin, ip, target_name=v["upn"],
                                     modified=[{"Name": "Source", "NewValue": rogue["domain"] + " (outbound sync)", "OldValue": ""}],
                                     offset_s=-60 + i * 10)))
    return out


def seq_insider_threat(config):
    """Possible insider threat: a legitimate (non-compromised) employee performs anomalous bulk
    data collection and sets up exfiltration channels — mass SharePoint/OneDrive downloads, an
    external sharing invite on sensitive files, an inbox rule forwarding mail to a personal
    address, and heavy mailbox access. One identity, spanning SharePoint + Exchange feeds."""
    u = ac.pick_user(config)
    ext = f"{u['username'].replace('.', '')}@gmail.com"
    out = []
    # 1) bulk SharePoint download (mass collection)
    for i in range(30):
        out.append(_spo(spo._sp("FileDownloaded", u, site=random.choice(spo._SITES),
                                offset_s=-(1800 - i * 30))))
    # 2) OneDrive full-library sync (stage everything locally)
    out.append(_spo(spo._sp("FileSyncDownloadedFull", u, workload="OneDrive", offset_s=-300)))
    # 3) external sharing invite on a sensitive file
    out.append(_spo(spo._sp("SharingInvitationCreated", u, record_type=14,
                            doc=random.choice(spo._SENSITIVE_DOCS),
                            extra={"TargetUserOrGroupName": ext, "TargetUserOrGroupType": "Guest",
                                   "EventData": "<Edit>"}, offset_s=-180)))
    # 4) inbox rule forwarding mail to a personal address
    out.append(_exch(exch.admin_cmdlet("New-InboxRule", u,
                                       exch._param(Name="Personal Archive", ForwardTo=ext,
                                                   StopProcessingRules="True"),
                                       target_user=u, offset_s=-120)))
    # 5) heavy mailbox access
    out.append(_exch(exch.mail_items_accessed(u, count=12, offset_s=-60)))
    return out


# ── correlated cross-feed campaigns ────────────────────────────────────────────────────
# Each threads ONE victim identity through several feeds so XSIAM stitches the events into a single
# incident. Rare entities (apps/domains/IPs) come from the reserved pools, so each campaign uses
# never-seen indicators. Compromised identities are ACTIVE accounts (pick_user) except where a stale
# account is the point (stale-reactivation uses the departed cohort).

def seq_bec_campaign(config):
    """Business Email Compromise: TOR account takeover -> MFA method added (persistence) -> hiding
    inbox rule + external auto-forward -> wire-fraud mail to an external party -> heavy mailbox read.
    Spans sign-ins, O365 directory audit, and Exchange."""
    u = ac.pick_user(config); ip = _tor(config)
    ext = ac.rare_ext_email()
    s = aad._signin(u, _loc(ip), interactive=True, risk_level="high", risk_state="atRisk", offset_s=-900)
    s["riskEventTypes_v2"] = ["anonymizedIPAddress", "unfamiliarFeatures"]
    return [
        _aad(s),
        _o365(o365._audit("User registered security info.", u, ip,
                          modified=[{"Name": "SecurityInfo.Method", "NewValue": "Phone (SMS)", "OldValue": ""}])),
        _exch(exch.admin_cmdlet("New-InboxRule", u, exch._param(
            Name=".", SubjectOrBodyContainsWords="invoice;wire;payment;bank;routing",
            ForwardTo=ext, DeleteMessage="True", StopProcessingRules="True"),
            target_user=u, external=True, offset_s=-600)),
        _exch(exch.admin_cmdlet("New-TransportRule", u, exch._param(
            Name="External Archive", BlindCopyTo=ext, Enabled="True"), external=True, offset_s=-500)),
        _exch(exch.mailbox_action("Send", u, client="OWA",
              item={"Subject": "UPDATED WIRE INSTRUCTIONS - action required",
                    "ParentFolder": {"Path": "\\Sent Items"}},
              extra={"Recipients": [ext], "ExternalAccess": True})),
        _exch(exch.mail_items_accessed(u, count=14, offset_s=-120)),
    ]


def seq_ransomware_campaign(config):
    """Cloud ransomware / destruction: compromised sign-in -> mass download (staging) -> mass
    encrypt-in-place (modify) -> mass delete, with DLP matches firing on the bulk movement. Spans
    sign-ins, SharePoint/OneDrive, and DLP."""
    u = ac.pick_user(config); ip = _tor(config)
    out = []
    s = aad._signin(u, _loc(ip), interactive=True, risk_level="high", risk_state="atRisk", offset_s=-1200)
    s["riskEventTypes_v2"] = ["anonymizedIPAddress"]
    out.append(_aad(s))
    site = random.choice(spo._SITES)
    for i in range(20):
        out.append(_spo(spo._sp("FileDownloaded", u, site=site, offset_s=-(1000 - i * 8))))
    for i in range(30):
        out.append(_spo(spo._sp("FileModified", u, site=site, offset_s=-(700 - i * 8))))
    for i in range(30):
        out.append(_spo(spo._sp(random.choice(["FileDeleted", "FileRecycled"]), u, site=site,
                                offset_s=-(300 - i * 6))))
    out.append(_dlp_(dlp._dlp(u, "SharePoint", "PCI DSS", "Cardholder Data - High",
                              random.sample(dlp._SIT, 2), "High",
                              ["BlockAccess", "GenerateIncidentReport"], random.randint(50, 400))))
    return out


def seq_oauth_app_abuse(config):
    """Illicit-consent OAuth abuse, end to end: a user consents a never-seen app high-privilege Graph
    scopes -> a credential is added to the app -> the app's service principal signs in from a hosting
    ASN -> it enumerates mailboxes and exfiltrates sensitive mail. Spans O365 audit, Graph directory
    audit, sign-ins, and Exchange."""
    u = ac.pick_user(config); ip = ac.egress(u)["ip"]
    app = ac.rare_app_name()
    out = [
        _o365(o365._audit("Consent to application.", u, ip, target_name=app,
                          modified=[{"Name": "ConsentContext.IsAdminConsent", "NewValue": "False", "OldValue": ""},
                                    {"Name": "ConsentAction.Permissions",
                                     "NewValue": "Mail.Read Mail.ReadWrite Files.ReadWrite.All offline_access",
                                     "OldValue": ""}])),
        _aaud(aaud.audit("Add service principal credentials", "ApplicationManagement", "Core Directory",
                         "Add", aaud.by_user(u),
                         [aaud.t_obj("ServicePrincipal", app,
                          [aaud.mp("KeyDescription", None, "[KeyType=AsymmetricX509Cert, KeyUsage=Verify]")])],
                         [aaud._ua(u)])),
    ]
    sp = aad._sp_signin(ac.rare_asn_loc())
    sp["appDisplayName"] = app; sp["appId"] = ac.app_id(app)
    sp["riskState"] = "atRisk"; sp["riskLevelDuringSignIn"] = "high"
    out.append(_aad(sp))
    # app reads many mailboxes, then exfiltrates sensitive mail externally
    for i in range(8):
        v = ac.pick_user(config)
        out.append(_exch(exch.mail_items_accessed(v, count=1, offset_s=-(200 - i * 10))))
    ext = ac.rare_ext_email()
    out.append(_exch(exch.mailbox_action("Send", u, client="REST",
               item={"Subject": "Export - confidential", "ParentFolder": {"Path": "\\Sent Items"}},
               extra={"Recipients": [ext], "ExternalAccess": True})))
    return out


def seq_stale_account_reactivation(config):
    """Stale-account reuse: a DEPARTED account (never active in the baseline) is targeted — disabled
    sign-in attempts, then a successful sign-in from a hosting ASN once re-enabled, a privileged role
    granted to it, and data access. Uses the identity lifecycle: attackers favor forgotten accounts.
    Spans sign-ins, O365 directory audit, and SharePoint."""
    dead = ac.pick_departed_user(config); ip = _tor(config)
    out = []
    for i in range(3):   # the account is still disabled -> 50057 failures
        out.append(_aad(aad._signin(dead, _loc(ip), interactive=True, success=False, error_code=50057,
                                    failure="The user account is disabled.", conditional="notApplied",
                                    offset_s=-(900 - i * 30))))
    # admin (compromised) re-enables + a successful takeover sign-in from a hosting ASN
    admin = ac.pick_by_role(config, aaud.ADMIN_ROLES, ("IT",))
    out.append(_o365(o365._audit("Update user.", admin, ac.egress(admin)["ip"], target_name=dead["upn"],
                                 modified=[{"Name": "AccountEnabled", "NewValue": "True", "OldValue": "False"}])))
    rec = aad._signin(dead, ac.rare_asn_loc(), interactive=True, ca_result="success",
                      conditional="success", risk_level="high", risk_state="atRisk", offset_s=-200)
    rec["riskEventTypes_v2"] = ["anonymizedIPAddress", "unfamiliarFeatures"]
    out.append(_aad(rec))
    out.append(_o365(o365._audit("Add member to role.", admin, ac.egress(admin)["ip"], target_name=dead["upn"],
                                 modified=[{"Name": "Role.DisplayName", "NewValue": "Privileged Role Administrator", "OldValue": ""}])))
    site = random.choice(spo._SITES)
    for i in range(12):
        out.append(_spo(spo._sp("FileDownloaded", dead, site=site, offset_s=-(120 - i * 6))))
    return out


def seq_hybrid_onprem_cloud(config, context=None):
    """Hybrid on-prem -> cloud kill chain for ONE identity: the user logs on at their workstation
    (on-prem AD Kerberos), an attacker harvests creds there and moves laterally, then the SAME
    identity's token surfaces in the cloud from a hosting ASN (AiTM/token theft), registers MFA
    persistence, and exfiltrates mail. Spans the WEC Windows feed AND the cloud feeds, joined by the
    shared identity (EXAMPLECORP\\user on-prem == user@domain in cloud) -- the correlation ITDR needs
    the CIE identity map populated to fully asset-join, but the events line up by identity + time.

    Returns WIN_SRC tuples (routed via WEC) interleaved with cloud tuples (routed via Cribl)."""
    sc = (context or {}).get("session_context") if isinstance(context, dict) else None
    wu = winev._pick_windows_user(sc) if sc else None
    if not wu:
        # No on-prem user available (no session_context) -> degrade to the cloud half only.
        return seq_aitm_token_theft(config)

    # cloud identity for the SAME person (username -> UPN)
    uname = wu["username"]
    cu = {"username": uname, "upn": wu.get("email") or f"{uname}@{ac.UPN_DOMAIN}",
          "display_name": wu.get("display_name", uname), "department": wu.get("department", "Unknown"),
          "os_type": wu.get("os_type", "Windows"), "os_version": wu.get("os_version", "10")}
    t0 = time.time()
    lid1 = winev._new_logon_id()
    out = []

    # 1) ON-PREM: legitimate morning workstation logon (TGT -> DC logon -> endpoint logon). The
    #    Kerberos artifact here is a TGT request (4768) -- ticket METADATA (enc type, options, SIDs),
    #    not the ticket bytes, exactly as a DC logs it.
    out.append(_win(winev._build_4768(wu, config, ts=t0 - 1800)))
    out.append(_win(winev._dc_logon_event(wu, config, ip_override=wu.get("ip"), logon_id=lid1, ts=t0 - 1799)))
    out.append(_win(winev._build_4624(wu, config, logon_type=2, auth_pkg=winev._NEG_PACKAGE,
                                      target_logon_id=lid1, ts=t0 - 1798)))
    # 2) ON-PREM: Kerberoast -- attacker requests a WEAKLY-ENCRYPTED (RC4, 0x17) service ticket for a
    #    USER service-account SPN. Use the module's roastable SPN inventory so ServiceName resolves to
    #    a user account (svc_*), NOT a computer account ($) -- XSIAM's Kerberoasting rule discards
    #    ServiceName values ending in "$", so a machine-account target would never fire.
    roast_spn = random.choice(winev._KERBEROAST_SPNS)
    svc_host = roast_spn.split("/")[1].split(":")[0]
    out.append(_win(winev._build_4769(wu, config, service_spn=roast_spn, encryption="0x17", ts=t0 - 900)))
    # attacker then uses cracked creds to reach the service host (lateral, Kerberos logon type 3)
    lid2 = winev._new_logon_id()
    out.append(_win(winev._build_4624(wu, config, logon_type=3, auth_pkg=winev._KRB_PACKAGE,
                                      target_logon_id=lid2, workstation_override=svc_host.split(".")[0].upper(),
                                      ts=t0 - 880)))

    # 3) CLOUD: a DIFFERENT token system. The attacker replays a stolen Primary Refresh Token (PRT)
    #    from a hosting ASN -> a NON-interactive sign-in whose incomingTokenType is primaryRefreshToken
    #    (how Entra records a token replay), high risk + anonymized IP. This is OAuth/PRT, not the
    #    on-prem Kerberos ticket; the two planes link by IDENTITY, not by one token crossing over.
    s = aad._signin(cu, ac.rare_asn_loc(), interactive=False, risk_level="high", risk_state="atRisk",
                    offset_s=-600)
    s["riskEventTypes_v2"] = ["anonymizedIPAddress", "unfamiliarFeatures"]
    out.append(_aad(s))
    # 4) CLOUD: attacker registers an MFA method on the account (persistence)
    out.append(_o365(o365._audit("User registered security info.", cu, s["ipAddress"],
                                 modified=[{"Name": "SecurityInfo.Method", "NewValue": "Phone (SMS)", "OldValue": ""}])))
    # 5) CLOUD: mail exfiltration to a never-seen external address
    ext = ac.rare_ext_email()
    out.append(_exch(exch.mailbox_action("Send", cu, client="REST",
               item={"Subject": "Financials - export", "ParentFolder": {"Path": "\\Sent Items"}},
               extra={"Recipients": [ext], "ExternalAccess": True})))
    out.append(_exch(exch.mail_items_accessed(cu, count=10, offset_s=-120)))
    return out


_MAB_APP_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e"   # Microsoft Authentication Broker


def seq_rt_to_prt_transition(config):
    """OAuth token-abuse bridge: RT -> PRT transition (Elastic: 'Entra ID RT to PRT Transition from
    Same User and Device'). An attacker with a stolen refresh token uses the Microsoft Authentication
    Broker to mint a Primary Refresh Token, then signs in with that PRT from an UNMANAGED device --
    both events for the SAME user + device within an hour. This is the genuine cloud-side token
    transition (OAuth RT->PRT), distinct from the on-prem Kerberos chain.

    Matches the rule's field conditions: step 1 appId = Microsoft Authentication Broker,
    incomingTokenType=refreshToken, AAD-joined device, session 'unbound'; step 2
    incomingTokenType=primaryRefreshToken, same deviceId, isManaged not true, resource !=
    Device Registration Service."""
    u = ac.pick_user(config)
    dev_id = ac._stable_guid("dev:" + u["username"])
    loc = ac.egress(u)

    # Step 1 — refresh-token sign-in via the Microsoft Authentication Broker on the AAD-joined device
    rt = aad._signin(u, loc, interactive=False, app="Microsoft Authentication Broker",
                     resource="Microsoft Graph", success=True, offset_s=-1800)
    rt["appId"] = _MAB_APP_ID
    rt["incomingTokenType"] = "refreshToken"
    rt["deviceDetail"] = {"deviceId": dev_id, "displayName": f'{u["username"].upper().replace(".", "")}-PC',
                          "operatingSystem": "Windows 10", "browser": "", "isCompliant": True,
                          "isManaged": True, "trustType": "Azure AD joined"}
    rt["tokenProtectionStatusDetails"] = {"signInSessionStatus": "unbound",
                                          "signInSessionStatusCode": 0}
    rt["userType"] = "member"

    # Step 2 — PRT sign-in from the SAME device, now UNMANAGED (the abuse the rule flags)
    prt = aad._signin(u, loc, interactive=False, app="Microsoft Office",
                      resource=random.choice(["Office 365 Exchange Online", "Microsoft Graph",
                                              "Office 365 SharePoint Online"]),
                      success=True, risk_level="high", risk_state="atRisk", offset_s=-120)
    prt["incomingTokenType"] = "primaryRefreshToken"
    prt["deviceDetail"] = {"deviceId": dev_id, "displayName": f'{u["username"].upper().replace(".", "")}-PC',
                           "operatingSystem": "Windows 10", "browser": "", "isCompliant": False,
                           "isManaged": False, "trustType": "Azure AD joined"}
    prt["riskEventTypes_v2"] = ["anonymizedIPAddress", "unfamiliarFeatures"]
    return [_aad(rt), _aad(prt)]


SEQUENCES = {
    "hybrid_onprem_cloud": seq_hybrid_onprem_cloud,
    "rt_to_prt_transition": seq_rt_to_prt_transition,
    "bec_campaign": seq_bec_campaign,
    "ransomware_campaign": seq_ransomware_campaign,
    "oauth_app_abuse": seq_oauth_app_abuse,
    "stale_account_reactivation": seq_stale_account_reactivation,
    "insider_threat": seq_insider_threat,
    "rogue_tenant_cross_tenant_sync": seq_rogue_tenant_cross_tenant_sync,
    "delegated_admin_partner_takeover": seq_delegated_admin_partner_takeover,
    "multitenant_org_join": seq_multitenant_org_join,
    "cross_tenant_sync_outbound": seq_cross_tenant_sync_outbound,
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


def build(name, config=None, context=None):
    """Return the ordered (source_id, integration_id, record) tuples for a sequence.

    Sequences that correlate on-prem + cloud (e.g. hybrid_onprem_cloud) take a second `context`
    argument carrying session_context; single-plane sequences take only config."""
    fn = SEQUENCES[name]
    if len(inspect.signature(fn).parameters) >= 2:
        return fn(config or {}, context)
    return fn(config or {})


def _send_windows(win_events, source_host="logsim.examplecorp.local"):
    """Deliver on-prem Windows event dicts via the WEC transport (mirrors the harness on-prem path).
    No-op (returns a skip marker) when WEC env/credentials aren't configured."""
    import os
    broker = os.getenv("WEC_BROKER_URL"); pfx = os.getenv("WEC_PFX_PATH"); pw = os.getenv("WEC_PFX_PASSWORD")
    if not (broker and pfx):
        return ("__wec__", "skipped: WEC_BROKER_URL/WEC_PFX_PATH not set", 0)
    from modules.wec_transport import WecClient
    client = WecClient(broker, pfx, pw, source_host)
    client.enumerate()
    xmls = [winev._render_event_xml(e) for e in win_events]
    client.deliver_events(xmls)
    return ("__wec__", "delivered", len(xmls))


def fire(name, config=None, sender=None, context=None):
    """Send one sequence: cloud records via cribl_direct (grouped per source), on-prem Windows
    records via the WEC transport."""
    from integrations.cribl_direct import CriblDirectSender
    groups = {}
    win_events = []
    for src, integ, rec in build(name, config, context):
        if src == WIN_SRC:
            win_events.append(rec)
        else:
            groups.setdefault((src, integ), []).append(rec)
    results = []
    if groups:
        sender = sender or CriblDirectSender()
        for (src, integ), recs in groups.items():
            results.append((name, sender.send(recs, src, integ)))
    if win_events:
        results.append((name, _send_windows(win_events)))
    return results


def fire_all(config=None, context=None):
    """Fire every sequence; returns [(name, [(src,(code,text,n)),...]), ...]."""
    sender = None
    from integrations.cribl_direct import CriblDirectSender
    sender = CriblDirectSender()
    out = []
    for name in SEQUENCES:
        out.append((name, fire(name, config, sender, context)))
        time.sleep(0.3)
    return out
