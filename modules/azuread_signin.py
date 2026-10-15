"""Azure AD / Entra sign-ins (Microsoft Graph auditLogs/signIns) -> msft_azure_ad_raw.

Emits individual signIn resource objects in the shape XSIAM's Graph collector stores.
Identities come from LogSim's user model (config['user_profiles'] / session_context) via
azure_common, so Azure AD activity ties to the same people as every other module.

Benign baseline reflects real tenant volume: mostly silent non-interactive token
refreshes, then interactive sign-ins, then routine benign failures (mistyped/expired
password, MFA needed). Attack scenarios carry Microsoft's own risk signals.
"""
import random
import time
import uuid

from modules import azure_common as ac

NAME = "Azure AD Sign-ins"
DESCRIPTION = "Simulates Microsoft Graph auditLogs/signIns events for msft_azure_ad_raw via the cribl_direct transport."
CONFIG_KEY = "azure_ad_signin_config"
SOURCE_IDENTIFIER = "f56dcfdf6bca43e793a4b6e9290e7b12"
INTEGRATION_IDENTIFIER = "logsim:azure_ad_signin"
DATASET = "msft_azure_ad_raw"

RISKY_IPS = ["185.220.101.34", "45.148.10.92", "193.218.118.158", "171.25.193.78"]

# Threat rate is governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (wall-clock
# episode rate, with a benign warmup) — see _GATE below.


def _g():
    return str(uuid.uuid4())


def _ts(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset_s))


def _tor_ip(config):
    nodes = (config or {}).get("tor_exit_nodes") if isinstance(config, dict) else None
    if nodes:
        n = random.choice(nodes)
        return n.get("ip") if isinstance(n, dict) else n
    return random.choice(RISKY_IPS)


def _signin(user, loc, *, interactive=True, success=True, error_code=0,
            failure="Other.", risk_level="none", risk_state="none", risk_detail="none",
            risk_events=None, offset_s=0,
            app=None, resource=None, conditional="success", client_app="Browser",
            mfa=False, ca_result=None, auth_method=None, user_type="member",
            cross_tenant="none", device=None):
    """Build one Graph signIn object from a user identity + egress location.

    Field set mirrors the real msft_azure_ad_raw record (Graph beta signIn) and the
    Sentinel SigninLogs schema. ca_result populates appliedConditionalAccessPolicies;
    auth_method populates authenticationDetails (MFA step); device overrides deviceDetail
    (pass ac.device_for(user, new=True) for a first-seen/new device)."""
    ts = _ts(offset_s)
    if auth_method:
        auth_dets = ac.auth_details(auth_method, succeeded=success, step_ts=ts)
        methods_used = [auth_method] if success else []
    else:
        auth_dets = [{"authenticationStepDateTime": ts,
                      "authenticationMethod": "Previously satisfied" if not interactive else "Password",
                      "authenticationMethodDetail": "", "succeeded": success,
                      "authenticationStepResultDetail": "", "authenticationStepRequirement": ""}]
        methods_used = ["Password"] if success and interactive else []
    app_name = app or random.choice(ac.APPS_INTERACTIVE)
    res_name = resource or random.choice(ac.RESOURCES)
    return {
        "id": _g(), "createdDateTime": ts,
        "userDisplayName": user["display_name"], "userPrincipalName": user["upn"],
        "userId": ac.user_oid(user["username"]),
        "appId": ac.app_id(app_name), "appDisplayName": app_name,
        "ipAddress": loc["ip"], "clientAppUsed": client_app, "correlationId": _g(),
        "conditionalAccessStatus": conditional, "isInteractive": interactive,
        "riskDetail": risk_detail, "riskLevelAggregated": risk_level,
        "riskLevelDuringSignIn": risk_level, "riskState": risk_state,
        "riskEventTypes": risk_events or [], "riskEventTypes_v2": risk_events or [],
        "resourceDisplayName": res_name, "resourceId": ac.resource_id(res_name),
        "homeTenantId": ac.HOME_TENANT_ID, "userType": user_type, "crossTenantAccessType": cross_tenant,
        "incomingTokenType": "primaryRefreshToken" if not interactive else "none",
        "tokenIssuerType": "AzureAD", "clientCredentialType": "none",
        "autonomousSystemNumber": loc.get("asn", ac._h(loc["ip"]) % 60000),
        "signInEventTypes": ["interactiveUser"] if interactive else ["nonInteractiveUser"],
        "authenticationRequirement": "multiFactorAuthentication" if (mfa or auth_method) else "singleFactorAuthentication",
        "authenticationProtocol": "oAuth2" if interactive else "none",
        "status": {"errorCode": error_code,
                   "failureReason": failure if not success else "Other.",
                   "additionalDetails": ("MFA requirement satisfied by claim in the token"
                                         if success else None)},
        "authenticationDetails": auth_dets,
        "authenticationMethodsUsed": methods_used,
        "authenticationRequirementPolicies": ([{"detail": "Security Defaults",
                                                 "requirementProvider": "securityDefaults"}] if (mfa or auth_method) else []),
        "authenticationProcessingDetails": [{"key": "Is CAE Token", "value": "False"}],
        "networkLocationDetails": [],
        "deviceDetail": device or ac.device_for(user),
        "location": {"city": loc["city"], "state": loc["state"],
                     "countryOrRegion": loc["countryOrRegion"], "geoCoordinates": loc["geoCoordinates"]},
        "ipAddressFromResourceProvider": None, "networkNames": [],
        "autonomousSystemOrganization": loc.get("isp"),
        "appliedConditionalAccessPolicies": (ac.applied_ca(ca_result, n=random.randint(1, 2))
                                             if ca_result else []),
    }


def _sp_signin(loc, offset_s=0):
    """Service-principal (app-only) sign-in — no user, servicePrincipal identity."""
    name = random.choice(["Microsoft Graph", "Office 365 Exchange Online", "LogSim Reporting App",
                          "Microsoft Intune", "Azure Resource Manager"])
    _res = random.choice(ac.RESOURCES)
    return {
        "id": _g(), "createdDateTime": _ts(offset_s), "appId": ac.app_id(name), "appDisplayName": name,
        "servicePrincipalId": ac.user_oid("sp:" + name), "servicePrincipalName": name,
        "ipAddress": loc["ip"], "correlationId": _g(), "conditionalAccessStatus": "notApplied",
        "isInteractive": False, "riskState": "none", "riskLevelDuringSignIn": "none",
        "resourceDisplayName": _res, "resourceId": ac.resource_id(_res),
        "signInEventTypes": ["servicePrincipal"], "clientCredentialType": "clientAssertion",
        "tokenIssuerType": "AzureAD", "authenticationProtocol": "oAuth2",
        "status": {"errorCode": 0, "failureReason": "Other.", "additionalDetails": None},
        "location": {"city": loc["city"], "state": loc["state"],
                     "countryOrRegion": loc["countryOrRegion"], "geoCoordinates": loc["geoCoordinates"]},
        "appliedConditionalAccessPolicies": [],
    }


# ── benign baseline (realistic weighted mix) ─────────────────────────────────────────

def _mi_signin(loc, offset_s=0):
    """Managed-identity sign-in (Azure resource identity) — signInEventTypes managedIdentity."""
    name = random.choice(["logsim-vm-prod", "logsim-func-app", "logsim-aks-cluster",
                          "logsim-logicapp", "logsim-datafactory"])
    msi = random.choice(["userAssigned", "systemAssigned"])
    return {
        "id": _g(), "createdDateTime": _ts(offset_s), "appId": ac.app_id(name),
        "appDisplayName": name, "servicePrincipalId": ac.user_oid("mi:" + name),
        "servicePrincipalName": name, "ipAddress": loc["ip"], "correlationId": _g(),
        "conditionalAccessStatus": "notApplied", "isInteractive": False,
        "riskState": "none", "riskLevelDuringSignIn": "none",
        "resourceDisplayName": random.choice(["Azure Resource Manager", "Azure Key Vault",
                                              "Azure Storage", "Microsoft Graph"]),
        "resourceId": ac.resource_id("Azure Resource Manager"),
        "signInEventTypes": ["managedIdentity"], "tokenIssuerType": "AzureAD",
        "authenticationProtocol": "none", "clientCredentialType": "managedIdentity",
        "managedServiceIdentity": {"msiType": msi, "associatedResourceId":
            f"/subscriptions/{ac._stable_guid('sub')}/resourceGroups/rg-prod/providers/"
            f"Microsoft.Compute/virtualMachines/{name}", "federatedTokenId": "", "federatedTokenIssuer": ""},
        "status": {"errorCode": 0, "failureReason": "Other.", "additionalDetails": None},
        "location": {"city": loc["city"], "state": loc["state"],
                     "countryOrRegion": loc["countryOrRegion"], "geoCoordinates": loc["geoCoordinates"]},
        "appliedConditionalAccessPolicies": [],
    }


_LEGACY_CLIENTS = ["IMAP4", "POP3", "SMTP", "Exchange ActiveSync", "Other clients"]
_GUEST_DOMAINS = ["partnerco.com", "contoso.com", "fabrikam.com", "vendor.io"]


# Azure AD Connect directory-sync service account. In a real tenant this account authenticates
# ONLY from the on-prem AAD Connect server; a sign-in from anywhere else means its credentials
# (which carry directory-write / password-hash-sync rights) were stolen.
_SYNC_ACCOUNT = {"username": "sync_aadconnect01",
                 "upn": "Sync_AADCONNECT01_7f3c2b9e@examplecorp.com",
                 "display_name": "On-Premises Directory Synchronization Service Account",
                 "department": "IT", "os_type": "Windows"}
_AADCONNECT_HOST_LOC = {"ip": "52.14.33.10", "city": "Columbus", "state": "Ohio",
                        "countryOrRegion": "US", "geoCoordinates": {"latitude": 39.96, "longitude": -82.99},
                        "asn": 7922, "isp": "Comcast Business"}


def _sync_signin(loc, *, risky=False, offset_s=0):
    rec = _signin(_SYNC_ACCOUNT, loc, interactive=False, app="Microsoft Azure AD Connect",
                  resource="Windows Azure Active Directory",
                  client_app="Mobile Apps and Desktop clients", offset_s=offset_s,
                  risk_level="high" if risky else "none",
                  risk_state="atRisk" if risky else "none")
    if risky:
        rec["riskEventTypes_v2"] = ["anonymizedIPAddress", "unfamiliarFeatures"]
    return rec


def scenario_aad_connect_sync_unusual_host(config=None, user=None):
    """The AAD Connect directory-sync service account authenticates from an UNUSUAL host/IP (it
    normally signs in only from the on-prem Connect server) -> 'Unusual Azure AD sync account
    sign-in from a new host' (sync-account credential theft)."""
    bad = {"ip": _tor_ip(config), "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    return [_sync_signin(bad, risky=True)]


def generate_benign(config=None, context=None):
    """One routine sign-in from the real-world weighted mix a live tenant produces."""
    user = ac.pick_user(config, context)
    loc = ac.egress(user)
    r = random.random()
    if r < 0.004:  # AAD Connect sync account's periodic auth FROM ITS NORMAL HOST (baseline for the
        return [_sync_signin(_AADCONNECT_HOST_LOC)]   # 'unusual host' anomaly to measure against)
    if r < 0.50:   # non-interactive token refresh — highest volume
        return [_signin(user, loc, interactive=False, app=random.choice(ac.APPS_NONINTERACTIVE),
                        conditional=random.choice(["success", "notApplied"]))]
    if r < 0.68:   # interactive success evaluated by Conditional Access
        return [_signin(user, loc, interactive=True, app=random.choice(ac.APPS_INTERACTIVE),
                        ca_result="success", conditional="success")]
    if r < 0.76:   # interactive sign-in that completed an MFA challenge
        return [_signin(user, loc, interactive=True, app=random.choice(ac.APPS_INTERACTIVE),
                        ca_result="success", conditional="success", mfa=True,
                        auth_method=random.choice(ac.MFA_METHODS[:3]))]
    if r < 0.78:   # mobile sign-in from a phone (cellular egress + registered mobile device)
        mloc = ac.egress(user, remote_prob=0.0, mobile_prob=1.0)
        return [_signin(user, mloc, interactive=(random.random() < 0.4),
                        app=random.choice(["Microsoft Teams", "Outlook Mobile", "OneDrive SyncEngine"]),
                        client_app="Mobile Apps and Desktop clients", ca_result="success",
                        conditional="success", device=ac.device_for(user, mobile=True))]
    if r < 0.84:   # app-only background auth: service principal, or managed identity (Azure resources)
        return [_mi_signin(loc) if random.random() < 0.3 else _sp_signin(loc)]
    if r < 0.87:   # guest / B2B sign-in
        guest = dict(user)
        guest["upn"] = f'{user["username"].replace(".", "")}@{random.choice(_GUEST_DOMAINS)}'
        return [_signin(guest, loc, interactive=True, app="My Apps", user_type="guest",
                        cross_tenant="b2bCollaboration", ca_result="success")]
    if r < 0.90:   # legacy-auth attempt (usually blocked by CA 'Block Legacy Authentication')
        return [_signin(user, loc, interactive=True, client_app=random.choice(_LEGACY_CLIENTS),
                        resource="Office 365 Exchange Online", success=False, error_code=53003,
                        failure="Access has been blocked by Conditional Access policies.",
                        conditional="failure", ca_result="failure")]
    if r < 0.925:  # report-only CA evaluation (policy in report-only mode — sign-in still succeeds)
        return [_signin(user, loc, interactive=True, app=random.choice(ac.APPS_INTERACTIVE),
                        conditional="success",
                        ca_result=random.choice(["reportOnlySuccess", "reportOnlyFailure"]))]
    if r < 0.95:   # first-seen / new device for this user (benign — new laptop, reinstall)
        return [_signin(user, loc, interactive=True, app=random.choice(ac.APPS_INTERACTIVE),
                        ca_result="success", conditional="success", device=ac.device_for(user, new=True))]
    if r < 0.97:   # low/medium sign-in risk that Identity Protection auto-remediated/dismissed (benign noise)
        lvl = random.choice(["low", "medium"])
        return [_signin(user, loc, interactive=True, app=random.choice(ac.APPS_INTERACTIVE),
                        ca_result="success", conditional="success", mfa=True,
                        auth_method=random.choice(ac.MFA_METHODS[:3]),
                        risk_level=lvl, risk_state=random.choice(["dismissed", "remediated"]),
                        risk_detail=random.choice(["aiConfirmedSigninSafe", "adminConfirmedSigninSafe"]),
                        risk_events=[random.choice(["unfamiliarFeatures", "unlikelyTravel"])])]
    # routine benign failure / MFA interrupt (mistyped or expired password, MFA needed, SSO session)
    code, reason = random.choice(ac.BENIGN_FAIL)
    return [_signin(user, loc, interactive=True, success=False, error_code=code, failure=reason,
                    conditional="notApplied")]


# ── attack scenarios ─────────────────────────────────────────────────────────────────

def scenario_brute_force(config=None, user=None, attempts=10, src_ip=None):
    u = ac.pick_user(config)
    loc = ac.egress(u)
    ip = src_ip or random.choice(RISKY_IPS)
    bad = {"ip": ip, "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    out = [_signin(u, bad, interactive=True, success=False, error_code=50126,
                   failure="Invalid username or password.", conditional="notApplied",
                   offset_s=-(120 - i * 8)) for i in range(attempts)]
    out.append(_signin(u, bad, interactive=True, offset_s=0))
    return out


def scenario_password_spray(config=None, victims=12, src_ip=None):
    ip = src_ip or random.choice(RISKY_IPS)
    bad = {"ip": ip, "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    out = []
    for i in range(victims):
        u = ac.pick_user(config)
        out.append(_signin(u, bad, interactive=True, success=False, error_code=50126,
                           failure="Invalid username or password.", conditional="notApplied",
                           offset_s=-(60 - i)))
    out.append(_signin(ac.pick_user(config), bad, interactive=True, offset_s=0))
    return out


def scenario_impossible_travel(config=None, user=None):
    u = ac.pick_user(config)
    us = {"ip": "108.245.61.200", "city": "Columbus", "state": "Ohio", "countryOrRegion": "US",
          "geoCoordinates": {"latitude": 39.96, "longitude": -82.99}}
    sg = {"ip": "103.21.244.12", "city": "Singapore", "state": "", "countryOrRegion": "SG",
          "geoCoordinates": {"latitude": 1.29, "longitude": 103.85}}
    return [_signin(u, us, offset_s=-300), _signin(u, sg, offset_s=-60)]


def scenario_high_risk_signin(config=None, user=None):
    u = ac.pick_user(config)
    bad = {"ip": random.choice(RISKY_IPS), "city": "Frankfurt", "state": "Hesse",
           "countryOrRegion": "DE", "geoCoordinates": {"latitude": 50.11, "longitude": 8.68}}
    rec = _signin(u, bad, interactive=True, risk_level="high", risk_state="atRisk")
    rec["riskDetail"] = "aiConfirmedSigninSafe"
    rec["riskEventTypes_v2"] = ["unfamiliarFeatures", "anonymizedIPAddress"]
    return [rec]


def scenario_tor_signin(config=None, user=None):
    u = ac.pick_user(config)
    bad = {"ip": _tor_ip(config), "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    rec = _signin(u, bad, interactive=True, risk_level="high", risk_state="atRisk")
    rec["riskEventTypes_v2"] = ["anonymizedIPAddress"]
    return [rec]


def scenario_powershell_signin(config=None, user=None):
    u = ac.pick_user(config)
    de = {"ip": "185.220.101.34", "city": "Frankfurt", "state": "Hesse", "countryOrRegion": "DE",
          "geoCoordinates": {"latitude": 50.11, "longitude": 8.68}}
    rec = _signin(u, de, interactive=True, app="Microsoft Azure PowerShell",
                  client_app="Mobile Apps and Desktop clients")
    rec["appId"] = "1950a258-227b-4e31-a9cf-717495945fc2"  # well-known Azure PowerShell app id
    return [rec]


def scenario_new_device_signin(config=None, user=None):
    """Successful sign-in from a brand-new, unmanaged device -> 'new device' anomaly (Low)."""
    u = ac.pick_user(config)
    return [_signin(u, ac.egress(u), interactive=True, ca_result="success",
                    device=ac.device_for(u, new=True))]


def scenario_new_country_signin(config=None, user=None):
    """Successful sign-in from a country the user doesn't normally use ->
    'A user connected from a new country' / 'First connection from a country' (Low/Info)."""
    u = ac.pick_user(config)
    far = {"ip": "102.89.44.9", "city": "Lagos", "state": "", "countryOrRegion": "NG",
           "geoCoordinates": {"latitude": 6.52, "longitude": 3.37}}
    return [_signin(u, far, interactive=True, ca_result="success")]


def scenario_account_lockout_spray(config=None, victims=10, src_ip=None):
    """Many distinct users hit account lockout (errorCode 50053) from one source ->
    'Multiple user accounts failed login due to account lockouts' (Low)."""
    ip = src_ip or random.choice(RISKY_IPS)
    bad = {"ip": ip, "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    out = []
    for i in range(victims):
        u = ac.pick_user(config)
        out.append(_signin(u, bad, interactive=True, success=False, error_code=50053,
                           failure="Account is locked because the user tried to sign in too many times with an incorrect user ID or password.",
                           conditional="notApplied", offset_s=-(120 - i * 8)))
    return out


def scenario_saas_api_from_tor(config=None, user=None):
    """A non-interactive SaaS/API token call to a Microsoft API from a TOR exit node ->
    'SaaS API called from TOR node'. (tor_signin is an interactive login; this is the API/token
    use of a SaaS resource over TOR.)"""
    u = ac.pick_user(config)
    bad = {"ip": _tor_ip(config), "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    rec = _signin(u, bad, interactive=False,
                  resource=random.choice(["Microsoft Graph", "Office 365 Exchange Online",
                                          "Office 365 SharePoint Online"]),
                  app=random.choice(ac.APPS_NONINTERACTIVE),
                  client_app="Mobile Apps and Desktop clients",
                  risk_level="high", risk_state="atRisk")
    rec["riskEventTypes_v2"] = ["anonymizedIPAddress"]
    return [rec]


def scenario_saas_api_from_tor_mobile(config=None, user=None):
    """SaaS/API token call from a TOR exit node on a MOBILE device -> 'SaaS API call from TOR via
    mobile device'."""
    u = ac.pick_user(config)
    bad = {"ip": _tor_ip(config), "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    rec = _signin(u, bad, interactive=False, resource=random.choice(["Microsoft Graph", "Office 365 Exchange Online"]),
                  app=random.choice(["Outlook Mobile", "Microsoft Teams", "OneDrive SyncEngine"]),
                  client_app="Mobile Apps and Desktop clients",
                  device=ac.device_for(u, mobile=True), risk_level="high", risk_state="atRisk")
    rec["riskEventTypes_v2"] = ["anonymizedIPAddress"]
    return [rec]


def scenario_multi_resource_sso(config=None, user=None):
    """One user accesses many apps/resources via SSO in a short window -> 'Suspicious user accessed
    multiple items via SSO'."""
    u = ac.pick_user(config); loc = ac.egress(u); out = []
    for i, r in enumerate(random.sample(ac.RESOURCES, min(6, len(ac.RESOURCES)))):
        out.append(_signin(u, loc, interactive=False, resource=r,
                           app=random.choice(ac.APPS_NONINTERACTIVE), offset_s=-(i * 20)))
    return out


def scenario_multi_sso_anon_proxy(config=None, user=None):
    """Many SSO resource accesses from an anonymized proxy / TOR -> 'User accessed multiple items
    via SSO using an anonymized proxy'."""
    u = ac.pick_user(config)
    bad = {"ip": _tor_ip(config), "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    out = []
    for i, r in enumerate(random.sample(ac.RESOURCES, min(6, len(ac.RESOURCES)))):
        rec = _signin(u, bad, interactive=True, resource=r, risk_level="high", risk_state="atRisk",
                      offset_s=-(i * 15))
        rec["riskEventTypes_v2"] = ["anonymizedIPAddress"]
        out.append(rec)
    return out


# A designated honey/decoy account that should never authenticate (requires the matching
# honey-user designation in XSIAM ITDR for the detector to fire).
_HONEY_ACCOUNT = {"username": "svc_backup_da", "upn": "svc_backup_da@examplecorp.com",
                  "display_name": "Backup Domain Admin (service)", "department": "IT", "os_type": "Windows"}
_SUSPICIOUS_COUNTRIES = [
    {"ip": "5.188.206.10", "city": "Moscow", "state": "", "countryOrRegion": "RU",
     "geoCoordinates": {"latitude": 55.75, "longitude": 37.62}},
    {"ip": "175.45.176.12", "city": "Pyongyang", "state": "", "countryOrRegion": "KP",
     "geoCoordinates": {"latitude": 39.03, "longitude": 125.75}},
    {"ip": "45.129.33.8", "city": "Tehran", "state": "", "countryOrRegion": "IR",
     "geoCoordinates": {"latitude": 35.69, "longitude": 51.39}}]


def scenario_disabled_user_signin(config=None, user=None):
    """A disabled account attempts SSO -> 'A disabled user attempted to authenticate via SSO'
    (errorCode 50057)."""
    u = ac.pick_user(config)
    return [_signin(u, ac.egress(u), interactive=True, success=False, error_code=50057,
                    failure="The user account is disabled.", conditional="notApplied")]


def scenario_honey_user_signin(config=None, user=None):
    """An authentication attempt against a honey/decoy account -> 'Authentication attempt by a
    honey user' (any sign-in to this account is suspicious)."""
    return [_signin(_HONEY_ACCOUNT, {"ip": _tor_ip(config), "city": "Unknown", "state": "",
                    "countryOrRegion": "US", "geoCoordinates": {"latitude": 0, "longitude": 0}},
                    interactive=True, risk_level="high", risk_state="atRisk")]


def scenario_suspicious_country_signin(config=None, user=None):
    """Sign-in from a high-risk country -> 'User attempted to connect from a suspicious country'."""
    u = ac.pick_user(config)
    return [_signin(u, random.choice(_SUSPICIOUS_COUNTRIES), interactive=True,
                    risk_level="high", risk_state="atRisk")]


def scenario_sso_abnormal_user_agent(config=None, user=None):
    """Sign-in with a user-agent abnormal for this user (automation/LOLBin agent) -> 'SSO with
    abnormal user agent'."""
    u = ac.pick_user(config)
    dev = dict(ac.device_for(u), browser=random.choice(
        ["python-requests/2.31.0", "curl/8.4.0", "axios/1.6.2", "Go-http-client/2.0"]))
    return [_signin(u, ac.egress(u), interactive=False, device=dev, risk_level="low", risk_state="atRisk")]


def scenario_sso_abnormal_os(config=None, user=None):
    """Sign-in from an operating system abnormal/new for this user -> 'SSO with abnormal/new
    operating system'."""
    u = ac.pick_user(config)
    odd = "Linux" if u.get("os_type") != "Linux" else "Windows"
    dev = dict(ac.device_for(u), operatingSystem=odd, isCompliant=False, isManaged=False, trustType="")
    return [_signin(u, ac.egress(u), interactive=True, device=dev, risk_level="low", risk_state="atRisk")]


def scenario_machine_account_sso(config=None, user=None):
    """A machine (computer) account authenticates via SSO -> 'SSO authentication by a machine
    account' (computer accounts should not interactively sign in to SaaS)."""
    u = ac.pick_user(config)
    mach = {"username": f'{u["username"].upper().replace(".", "")}-PC$',
            "upn": f'{u["username"].upper().replace(".", "")}-PC$@examplecorp.com',
            "display_name": f'{u["username"].upper()}-PC', "department": u.get("department", "IT"),
            "os_type": "Windows"}
    return [_signin(mach, ac.egress(u), interactive=True, user_type="member",
                    risk_level="low", risk_state="atRisk")]


def scenario_sso_spray_ip_rotation(config=None, victims=12):
    """Password spray with ROTATING source IPs across a subnet -> 'IP Rotation Pattern in SSO
    Spray' (evades per-IP lockout)."""
    net = random.choice(["45.148", "193.218", "185.220"])
    out = []
    for i in range(victims):
        v = ac.pick_user(config)
        ip = f"{net}.{random.randint(0, 255)}.{random.randint(2, 250)}"
        out.append(_signin(v, {"ip": ip, "city": "Unknown", "state": "", "countryOrRegion": "US",
                    "geoCoordinates": {"latitude": 0, "longitude": 0}}, interactive=True,
                    success=False, error_code=50126, failure="Invalid username or password.",
                    conditional="notApplied", offset_s=-(180 - i * 12)))
    return out


def scenario_first_sso_resource_org(config=None, user=None):
    """A sign-in accessing an app/resource never before seen in the org -> 'First SSO Resource
    Access in the Organization' (Informational baseline)."""
    u = ac.pick_user(config)
    novel = f"Custom LOB App {random.randint(1000, 9999)}"
    return [_signin(u, ac.egress(u), interactive=True, app=novel, resource=novel, ca_result="success")]


def scenario_first_sso_new_asn(config=None, user=None):
    """A sign-in from an ASN this user has never used (a hosting/VPS ASN, same country) -> 'First
    SSO access from ASN for user' (Informational baseline / 'Suspicious SSO access from ASN')."""
    u = ac.pick_user(config)
    loc = {"ip": f"165.1.{random.randint(0,255)}.{random.randint(2,250)}", "city": "Ashburn",
           "state": "Virginia", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 39.04, "longitude": -77.49},
           "asn": 14061, "isp": "DigitalOcean LLC"}
    return [_signin(u, loc, interactive=True, ca_result="success")]


_PENTEST_AGENTS = ["MSOLSpray/1.0", "AADInternals", "ROADtools", "o365-attack-toolkit",
                   "TeamFiltration/3.5", "python-requests/2.31 (MFASweep)", "Mantis"]


def scenario_pentest_tool_activity(config=None, user=None, attempts=8):
    """Sign-ins bearing known offensive-tool signatures in the user-agent -> 'Penetration testing
    tool activity attempt' (MSOLSpray / AADInternals / ROADtools / TeamFiltration etc.)."""
    agent = random.choice(_PENTEST_AGENTS)
    bad = {"ip": _tor_ip(config), "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    out = []
    for i in range(attempts):
        u = ac.pick_user(config)
        dev = dict(ac.device_for(u), browser=agent, isCompliant=False, isManaged=False, trustType="")
        out.append(_signin(u, bad, interactive=True, success=(i == attempts - 1),
                           error_code=(0 if i == attempts - 1 else 50126),
                           failure="Invalid username or password.", device=dev,
                           risk_level="high", risk_state="atRisk", conditional="notApplied",
                           offset_s=-(120 - i * 12)))
    return out


SCENARIOS = {
    "brute_force": scenario_brute_force,
    "password_spray": scenario_password_spray,
    "impossible_travel": scenario_impossible_travel,
    "high_risk_signin": scenario_high_risk_signin,
    "tor_signin": scenario_tor_signin,
    "saas_api_from_tor": scenario_saas_api_from_tor,
    "saas_api_from_tor_mobile": scenario_saas_api_from_tor_mobile,
    "multi_resource_sso": scenario_multi_resource_sso,
    "multi_sso_anon_proxy": scenario_multi_sso_anon_proxy,
    "aad_connect_sync_unusual_host": scenario_aad_connect_sync_unusual_host,
    "disabled_user_signin": scenario_disabled_user_signin,
    "honey_user_signin": scenario_honey_user_signin,
    "suspicious_country_signin": scenario_suspicious_country_signin,
    "sso_abnormal_user_agent": scenario_sso_abnormal_user_agent,
    "sso_abnormal_os": scenario_sso_abnormal_os,
    "machine_account_sso": scenario_machine_account_sso,
    "sso_spray_ip_rotation": scenario_sso_spray_ip_rotation,
    "pentest_tool_activity": scenario_pentest_tool_activity,
    "first_sso_resource_org": scenario_first_sso_resource_org,
    "first_sso_new_asn": scenario_first_sso_new_asn,
    "powershell_signin": scenario_powershell_signin,
    "new_device_signin": scenario_new_device_signin,
    "new_country_signin": scenario_new_country_signin,
    "account_lockout_spray": scenario_account_lockout_spray,
}


# ── LogSim module interface ──────────────────────────────────────────────────────────

_GATE = ac.ThreatGate(SCENARIOS)


def get_threat_names():
    return list(SCENARIOS.keys())


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    if scenario_event:
        key = scenario_event if scenario_event in SCENARIOS else scenario_event.lower()
        if key in SCENARIOS:
            return (SCENARIOS[key](config), key)
        return None
    if benign_only or threat_level == "Benign Traffic Only":
        return generate_benign(config, context)
    if _GATE.fire(threat_level, config):
        key = random.choice(list(SCENARIOS))
        return (SCENARIOS[key](config), key)
    return generate_benign(config, context)
