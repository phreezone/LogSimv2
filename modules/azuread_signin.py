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
from modules import graph_activity as ga

NAME = "Azure AD Sign-ins"
DESCRIPTION = "Simulates Microsoft Graph auditLogs/signIns events for msft_azure_ad_raw via the cribl_direct transport."
CONFIG_KEY = "azure_ad_signin_config"
SOURCE_IDENTIFIER = "f56dcfdf6bca43e793a4b6e9290e7b12"
INTEGRATION_IDENTIFIER = "logsim:azure_ad_signin"
DATASET = "msft_azure_ad_raw"
EVENT_INTERVAL = 0.15   # default relative benign volume: sign-ins are by far the highest-volume Entra feed (silent token refresh dominates)

RISKY_IPS = ["185.220.101.34", "45.148.10.92", "193.218.118.158", "171.25.193.78"]

# Threat rate is governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (wall-clock
# episode rate, with a benign warmup) — see _GATE below.


def _g():
    return str(uuid.uuid4())


def _ts(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset_s))


def _burst_offsets(n, spacing=3, end=-3):
    """n per-event offsets (seconds), earliest first, every one <= `end` (so <= now whatever n is)
    and `spacing` apart. spacing is an integer >= 1 so each lands on a distinct whole second (the
    sign-in feed stamps at second resolution), which keeps XSIAM from deduping them."""
    return [end - spacing * (n - 1 - i) for i in range(n)]


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
    rec = {
        "id": _g(), "uniqueTokenIdentifier": _g(), "createdDateTime": ts,
        "userDisplayName": user["display_name"], "userPrincipalName": user["upn"],
        "userId": ac.user_oid(user["username"]),
        "appId": ac.app_id(app_name), "appDisplayName": app_name,
        "ipAddress": loc["ip"], "clientAppUsed": client_app, "correlationId": _g(),
        "conditionalAccessStatus": conditional, "isInteractive": interactive,
        "riskDetail": risk_detail, "riskLevelAggregated": risk_level,
        "riskLevelDuringSignIn": risk_level, "riskState": risk_state,
        "riskEventTypes": risk_events or [], "riskEventTypes_v2": risk_events or [],
        "resourceDisplayName": res_name, "resourceId": ac.resource_id(res_name),
        "resourceTenantId": ac.HOME_TENANT_ID,
        "servicePrincipalId": ac._stable_guid("sp:" + res_name),
        "userAgent": ac.user_agent(user),
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
    # When the CIE identity map covers this user, attach the real on-prem SID / sAMAccountName so
    # ITDR identity-asset enrichment joins (no-op until the map is provided).
    rec.update(ac.cie_identity_overrides(user))
    return rec


def _sp_signin(loc, offset_s=0):
    """Service-principal (app-only) sign-in — no user, servicePrincipal identity."""
    name = random.choice(["Microsoft Graph", "Office 365 Exchange Online", "LogSim Reporting App",
                          "Microsoft Intune", "Azure Resource Manager"])
    # Each SP has a stable, narrow set of resources it normally calls (its baseline); drawing from
    # it keeps the per-app resource baseline tight so 'unusual resource access by app' can fire.
    _res = ac.pick_baseline_resource("sp:" + name)
    return {
        "id": _g(), "uniqueTokenIdentifier": _g(), "createdDateTime": _ts(offset_s), "appId": ac.app_id(name), "appDisplayName": name,
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
        "id": _g(), "uniqueTokenIdentifier": _g(), "createdDateTime": _ts(offset_s), "appId": ac.app_id(name),
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
_HQ = ac.OFFICES[0]   # the AAD Connect server sits behind the Columbus office NAT
_AADCONNECT_HOST_LOC = {"ip": _HQ["ips"][0], "city": _HQ["city"], "state": _HQ["state"],
                        "countryOrRegion": _HQ["countryOrRegion"],
                        "geoCoordinates": {"latitude": _HQ["lat"], "longitude": _HQ["lon"]},
                        "asn": _HQ["asn"], "isp": _HQ["isp"]}


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
    """One routine sign-in from the real-world weighted mix a live tenant produces, plus (when Event
    Hub copies are on) the Graph requests its client makes once it holds the token."""
    user = ac.pick_user(config, context)
    loc = ac.egress(user)
    recs = _benign_mix(config, user, loc)
    if not ac.eventhub_enabled(config, CONFIG_KEY):
        return recs
    first = recs[0] if recs else {}
    ok = (first.get("status") or {}).get("errorCode", 1) == 0
    if ok and first.get("userPrincipalName") == user["upn"] and random.random() < 0.35:
        recs = recs + ga.benign_user_calls(user, loc,
                                            sign_in_activity_id=first.get("uniqueTokenIdentifier"))
    elif ok and "servicePrincipal" in (first.get("signInEventTypes") or []) and random.random() < 0.5:
        recs = recs + ga.benign_app_calls(user=ac.pick_user(config, context),
                                           sign_in_activity_id=first.get("uniqueTokenIdentifier"))
    return recs


def _benign_mix(config, user, loc):
    r = random.random()
    if r < 0.004:  # AAD Connect sync account's periodic auth FROM ITS NORMAL HOST (baseline for the
        return [_sync_signin(_AADCONNECT_HOST_LOC)]   # 'unusual host' anomaly to measure against)
    if r < 0.50:   # non-interactive token refresh — highest volume
        return [_signin(user, loc, interactive=False, app=ac.pick_baseline_app(user, interactive=False),
                        resource=ac.pick_baseline_resource(user),
                        conditional=random.choice(["success", "notApplied"]))]
    if r < 0.68:   # interactive success evaluated by Conditional Access
        ac.publish_signin(user, loc)   # session start -> on-prem/network follow-on correlates
        return [_signin(user, loc, interactive=True, app=ac.pick_baseline_app(user),
                        resource=ac.pick_baseline_resource(user),
                        ca_result="success", conditional="success")]
    if r < 0.76:   # interactive sign-in that completed an MFA challenge
        ac.publish_signin(user, loc)
        return [_signin(user, loc, interactive=True, app=ac.pick_baseline_app(user),
                        resource=ac.pick_baseline_resource(user),
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
        return [_signin(user, loc, interactive=True, app=ac.pick_baseline_app(user),
                        resource=ac.pick_baseline_resource(user),
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

def scenario_brute_force(config=None, user=None, attempts=60, src_ip=None):
    u = ac.pick_user(config)
    loc = ac.egress(u)
    ip = src_ip or random.choice(RISKY_IPS)
    bad = {"ip": ip, "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    offs = _burst_offsets(attempts)
    out = [_signin(u, bad, interactive=True, success=False, error_code=50126,
                   failure="Invalid username or password.", conditional="notApplied",
                   offset_s=offs[i]) for i in range(attempts)]
    out.append(_signin(u, bad, interactive=True, offset_s=0))
    return out


def _distinct_victims(config, n):
    """n DISTINCT victim identities for a spray. Password spray is defined by ONE source hitting
    MANY different accounts, so uniqueness is essential. Prefer the run's user roster; if it is
    absent or too small (e.g. pick_user keeps returning the same stub), top up with synthetic
    employee-style victims so the 'many users from one IP' signal always holds."""
    seen, out = set(), []
    for _ in range(n * 4):
        if len(out) >= n:
            break
        u = ac.pick_user(config)
        if u["username"] not in seen:
            seen.add(u["username"]); out.append(u)
    i = 0
    while len(out) < n:
        i += 1
        uname = f"jdoe{i:04d}"
        if uname in seen:
            continue
        seen.add(uname)
        out.append({"username": uname, "upn": f"{uname}@{ac.UPN_DOMAIN}",
                    "display_name": f"J Doe {i:04d}", "department": "Unknown",
                    "os_type": "Windows", "os_version": "10"})
    return out


def scenario_password_spray(config=None, victims=50, src_ip=None):
    ip = src_ip or random.choice(RISKY_IPS)
    bad = {"ip": ip, "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    sprayed = _distinct_victims(config, victims)
    offs = _burst_offsets(victims)
    out = [_signin(u, bad, interactive=True, success=False, error_code=50126,
                   failure="Invalid username or password.", conditional="notApplied",
                   offset_s=offs[i]) for i, u in enumerate(sprayed)]
    # The compromise lands on one of the sprayed accounts, so the "many failures then a success
    # from one IP" story resolves on a victim the spray actually touched (not a fresh identity).
    out.append(_signin(random.choice(sprayed), bad, interactive=True, offset_s=0))
    return out


def scenario_impossible_travel(config=None, user=None):
    u = ac.pick_user(config)
    us = {"ip": "108.245.61.200", "city": "Columbus", "state": "Ohio", "countryOrRegion": "US",
          "geoCoordinates": {"latitude": 39.96, "longitude": -82.99}}
    sg = {"ip": "128.199.116.12", "city": "Singapore", "state": "", "countryOrRegion": "SG",
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


def scenario_account_lockout_spray(config=None, victims=40, src_ip=None):
    """Many distinct users hit account lockout (errorCode 50053) from one source ->
    'Multiple user accounts failed login due to account lockouts' (Low)."""
    ip = src_ip or random.choice(RISKY_IPS)
    bad = {"ip": ip, "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    out = []
    offs = _burst_offsets(victims)
    for i in range(victims):
        u = ac.pick_user(config)
        out.append(_signin(u, bad, interactive=True, success=False, error_code=50053,
                           failure="Account is locked because the user tried to sign in too many times with an incorrect user ID or password.",
                           conditional="notApplied", offset_s=offs[i]))
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
    (errorCode 50057). Draws a DEPARTED-cohort identity (a decommissioned/former account the benign
    baseline never signs in), so the attempt is coherent with a genuinely disabled account."""
    u = ac.pick_departed_user(config)
    return [_signin(u, ac.egress(u), interactive=True, success=False, error_code=50057,
                    failure="The user account is disabled.", conditional="notApplied")]


def scenario_dormant_account_signin(config=None, user=None):
    """A long-dormant account successfully signs in after being unused for a long period (a stale
    account reactivated by an attacker). Draws a DORMANT-cohort identity the benign baseline never
    signs in, so from the analytics' view it has no recent activity -> dormant-account reuse. Feeds
    ITDR / Identity Analytics (the named dormant detectors also require XDR Agent / firewall data)."""
    u = ac.pick_dormant_user(config)
    rec = _signin(u, ac.egress(u), interactive=True, ca_result="success", conditional="success",
                  risk_level="low", risk_state="atRisk")
    rec["riskEventTypes_v2"] = ["unfamiliarFeatures"]
    return [rec]


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


def scenario_sso_spray_ip_rotation(config=None, victims=50):
    """Password spray with ROTATING source IPs across a subnet -> 'IP Rotation Pattern in SSO
    Spray' (evades per-IP lockout)."""
    net = random.choice(["45.148", "193.218", "185.220"])
    out = []
    offs = _burst_offsets(victims)
    for i in range(victims):
        v = ac.pick_user(config)
        ip = f"{net}.{random.randint(0, 255)}.{random.randint(2, 250)}"
        out.append(_signin(v, {"ip": ip, "city": "Unknown", "state": "", "countryOrRegion": "US",
                    "geoCoordinates": {"latitude": 0, "longitude": 0}}, interactive=True,
                    success=False, error_code=50126, failure="Invalid username or password.",
                    conditional="notApplied", offset_s=offs[i]))
    return out


def scenario_first_sso_resource_org(config=None, user=None):
    """A sign-in accessing an app/resource never before seen in the org -> 'First SSO Resource
    Access in the Organization' (Informational baseline)."""
    u = ac.pick_user(config)
    novel = ac.rare_app_name()     # a never-before-seen app/resource for the whole org (unbounded)
    return [_signin(u, ac.egress(u), interactive=True, app=novel, resource=novel, ca_result="success")]


def scenario_first_sso_new_asn(config=None, user=None):
    """A sign-in from an ASN this user has never used (a hosting/VPS ASN, same country) -> 'First
    SSO access from ASN for user' (Informational baseline / 'Suspicious SSO access from ASN')."""
    u = ac.pick_user(config)
    loc = ac.rare_asn_loc()        # a hosting ASN this user/org has never signed in from (unbounded)
    return [_signin(u, loc, interactive=True, ca_result="success")]


_PENTEST_AGENTS = ["MSOLSpray/1.0", "AADInternals", "ROADtools", "o365-attack-toolkit",
                   "TeamFiltration/3.5", "python-requests/2.31 (MFASweep)", "Mantis"]


def scenario_pentest_tool_activity(config=None, user=None, attempts=30):
    """Sign-ins bearing known offensive-tool signatures in the user-agent -> 'Penetration testing
    tool activity attempt' (MSOLSpray / AADInternals / ROADtools / TeamFiltration etc.)."""
    agent = random.choice(_PENTEST_AGENTS)
    bad = {"ip": _tor_ip(config), "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    out = []
    offs = _burst_offsets(attempts)
    for i in range(attempts):
        u = ac.pick_user(config)
        dev = dict(ac.device_for(u), browser=agent, isCompliant=False, isManaged=False, trustType="")
        out.append(_signin(u, bad, interactive=True, success=(i == attempts - 1),
                           error_code=(0 if i == attempts - 1 else 50126),
                           failure="Invalid username or password.", device=dev,
                           risk_level="high", risk_state="atRisk", conditional="notApplied",
                           offset_s=offs[i]))
    return out


def scenario_unusual_resource_access_by_app(config=None, user=None):
    """A service principal reaches a resource outside its learned access pattern ->
    'Unusual resource access by Azure application'. The app itself is a stable entity (pinned
    appId) so UEBA learns its normal resource set; here it touches a sensitive resource
    (Key Vault / ARM / Directory) it does not normally call."""
    loc = ac.rare_asn_loc()
    rec = _sp_signin(loc)
    # Resource OUTSIDE this SP's learned baseline set -> genuinely unusual for this application.
    res = ac.rare_resource_for("sp:" + rec["appDisplayName"])
    rec["resourceDisplayName"] = res
    rec["resourceId"] = ac.resource_id(res)
    rec["riskState"] = "atRisk"
    rec["riskLevelDuringSignIn"] = "medium"
    return [rec]


def scenario_app_access_unknown_tenant(config=None, user=None):
    """An app sign-in originating from a foreign/unknown tenant via cross-tenant access ->
    'Attempted Azure application access from unknown tenant'. Carries a homeTenantId that is NOT
    this tenant and crossTenantAccessType=b2bCollaboration, from an anonymized IP."""
    loc = ac.rare_asn_loc()
    rec = _sp_signin(loc)
    tenant = ac.rare_tenant()                        # a never-seen external tenant (unbounded)
    rec["homeTenantId"] = tenant["tenant_id"]
    rec["resourceTenantId"] = ac.HOME_TENANT_ID
    rec["crossTenantAccessType"] = "b2bCollaboration"
    rec["riskState"] = "atRisk"
    rec["riskLevelDuringSignIn"] = "high"
    rec["riskEventTypes_v2"] = ["anonymizedIPAddress"]
    # ...and the Graph calls that app then attempts with its foreign-tenant token, refused (403):
    # the request log is what the Graph-activity variant of the detector reads.
    app = ga.app_identity(ac.rare_app_name(), tenant_id=tenant["tenant_id"])
    calls = [("GET", "/v1.0/users?$top=999", 403, 312), ("GET", "/v1.0/groups", 403, 312),
             ("GET", "/v1.0/organization", 403, 312)]
    return [rec] + ga.burst(app, calls, ip=loc["ip"], roles="Directory.Read.All", span_s=40)


def scenario_device_code_auth_flow(config=None, user=None):
    """A sign-in completed via the OAuth device-code flow from an anomalous location -> 'Suspicious
    Entra ID Device Code Authentication Flow'. Device-code phishing tricks a user into entering a
    code the attacker generated, so the token is minted for the attacker's device."""
    u = ac.pick_user(config)
    bad = {"ip": _tor_ip(config), "city": "Unknown", "state": "", "countryOrRegion": "US",
           "geoCoordinates": {"latitude": 0, "longitude": 0}}
    rec = _signin(u, bad, interactive=True, resource="Microsoft Graph",
                  app=random.choice(["Microsoft Authentication Broker", "Microsoft Office",
                                     "Visual Studio Code"]),
                  client_app="Mobile Apps and Desktop clients",
                  risk_level="high", risk_state="atRisk")
    rec["authenticationProtocol"] = "deviceCode"
    rec["riskEventTypes_v2"] = ["anonymizedIPAddress", "unfamiliarFeatures"]
    return [rec]


def scenario_service_account_sso(config=None, user=None):
    """A non-interactive service account authenticates interactively via SSO -> 'SSO authentication
    by a service account'. Service accounts (svc_*) should only use app/token flows; an interactive
    SSO by one signals credential theft."""
    u = ac.pick_user(config)
    svc = {"username": f'svc_{u["department"].lower().replace(" ", "")}' if u.get("department") else "svc_app",
           "upn": f'svc_{random.choice(["sql","backup","iis","batch","integration"])}@examplecorp.com',
           "display_name": "Service Account", "department": u.get("department", "IT"), "os_type": "Windows"}
    return [_signin(svc, ac.egress(u), interactive=True, user_type="member",
                    app=random.choice(ac.APPS_INTERACTIVE), risk_level="medium", risk_state="atRisk")]


def scenario_mi_token_remote_usage(config=None, user=None):
    """An Azure Managed Identity token used from OUTSIDE Azure (non-Azure egress) -> 'Remote usage
    of an Azure Managed Identity token'. MI tokens are bound to an Azure resource; external use
    means the token (e.g. from IMDS) was exfiltrated and replayed."""
    loc = ac.rare_asn_loc()                            # hosting/VPS egress, never in the baseline
    rec = _mi_signin(loc)
    rec["riskState"] = "atRisk"
    rec["riskLevelDuringSignIn"] = "high"
    rec["riskEventTypes_v2"] = ["anonymizedIPAddress"]
    return [rec]


def scenario_sp_token_remote_usage(config=None, user=None):
    """A service-principal token used from OUTSIDE the cloud environment (non-Azure egress) ->
    'Remote usage of an Azure Service Principal token'. The SP is a stable entity whose tokens
    normally originate from Azure/Microsoft ranges; here the app-only token is replayed from an
    external datacenter/residential IP."""
    loc = ac.rare_asn_loc()                            # hosting/VPS egress, never in the baseline
    rec = _sp_signin(loc)
    rec["clientCredentialType"] = "clientAssertion"
    rec["riskState"] = "atRisk"
    rec["riskLevelDuringSignIn"] = "high"
    rec["riskEventTypes_v2"] = ["anonymizedIPAddress", "unfamiliarFeatures"]
    return [rec]


# ── Graph API activity scenarios (MicrosoftGraphActivityLogs only) ───────────────────
# These detectors read Graph request logs, so the scenarios are the requests themselves; each
# also carries the sign-in that minted the token.

_ENUM_CALLS = ["/v1.0/users?$top=999", "/v1.0/groups?$top=999", "/v1.0/servicePrincipals?$top=999",
               "/v1.0/applications", "/v1.0/directoryRoles", "/v1.0/devices?$top=999",
               "/v1.0/organization", "/v1.0/domains", "/v1.0/identity/conditionalAccess/policies",
               "/v1.0/roleManagement/directory/roleAssignments", "/beta/policies/authorizationPolicy",
               "/v1.0/groups?$filter=securityEnabled eq true", "/v1.0/users?$select=id,onPremisesSamAccountName"]


def scenario_graph_enumeration(config=None, user=None):
    """A user token from an unfamiliar host walks the directory through Graph (users, groups, apps,
    roles, CA policies, devices) in a few minutes, ROADtools/AzureHound style -> 'Azure
    enumeration activity using Microsoft Graph API' (large responses also feed 'Uncommon
    increase in Azure Microsoft Graph API request sizes')."""
    u = user or ac.pick_user(config)
    loc = ac.rare_asn_loc()
    si = _signin(u, loc, interactive=True, app="Microsoft Graph Command Line Tools",
                 resource="Microsoft Graph", client_app="Mobile Apps and Desktop clients", offset_s=-260)
    calls = [("GET", c, 200, random.randint(60000, 900000)) for c in random.sample(_ENUM_CALLS, 11)]
    return [si] + ga.burst(u, calls, ip=loc["ip"], scopes="Directory.Read.All User.Read.All",
                           span_s=200, end_offset_s=-5)


def scenario_graph_throttling_app(config=None, user=None):
    """A daemon app hammers Graph until it is throttled (HTTP 429) -> 'An Azure application
    reached a throttling API rate'."""
    app = ga.app_identity(random.choice(list(ga.DAEMON_APPS)))
    calls = ([("GET", "/v1.0/users/" + ac.user_oid(ac.pick_user(config)["username"]) + "/messages?$top=50", 200, 41000)
              for _ in range(14)] +
             [("GET", "/v1.0/users/" + ac.user_oid(ac.pick_user(config)["username"]) + "/messages?$top=50", 429, 180)
              for _ in range(16)])
    return ga.burst(app, calls, roles=ga.DAEMON_APPS[app["name"]]["roles"] + " Mail.Read", span_s=90)


def scenario_graph_throttling_user(config=None, user=None):
    """A user identity's script exceeds Graph's per-user limits (HTTP 429) -> 'Cloud identity reached
    a throttling API rate'."""
    u = user or ac.pick_user(config)
    loc = ac.egress(u)
    calls = ([("GET", "/v1.0/me/drive/root/children", 200, 9000) for _ in range(12)] +
             [("GET", "/v1.0/me/drive/root/children", 429, 180) for _ in range(14)])
    return ga.burst(u, calls, ip=loc["ip"], scopes="Files.Read.All User.Read", span_s=60)


def scenario_graph_denied_burst(config=None, user=None):
    """An app token is pointed at directory endpoints it holds no permission for and is refused again
    and again (HTTP 403) -> 'An Azure identity performed multiple actions that were denied' (the
    application variation)."""
    app = ga.app_identity(random.choice(list(ga.DAEMON_APPS)))
    targets = ["/v1.0/roleManagement/directory/roleAssignments", "/v1.0/applications",
               "/v1.0/identity/conditionalAccess/policies", "/v1.0/policies/authorizationPolicy",
               "/v1.0/directoryRoles", "/v1.0/servicePrincipals", "/v1.0/auditLogs/signIns",
               "/v1.0/security/alerts_v2", "/v1.0/users?$select=signInActivity"]
    calls = [("GET", random.choice(targets), 403, 312) for _ in range(14)]
    return ga.burst(app, calls, ip=ac.rare_asn_loc()["ip"],
                    roles=ga.DAEMON_APPS[app["name"]]["roles"], span_s=420)


def scenario_graph_large_responses(config=None, user=None):
    """A daemon app that normally pulls small pages suddenly downloads huge responses (full
    directory / mailbox dumps) -> 'Uncommon increase in Azure Microsoft Graph API request sizes'."""
    name = random.choice(list(ga.DAEMON_APPS))
    app = ga.app_identity(name)
    calls = [("GET", random.choice(["/v1.0/users?$top=999&$select=*", "/beta/users?$expand=memberOf",
                                    "/v1.0/groups?$expand=members"]), 200,
              random.randint(18_000_000, 60_000_000)) for _ in range(6)]
    return ga.burst(app, calls, roles=ga.DAEMON_APPS[name]["roles"], span_s=300)


def scenario_graph_privileged_app_call(config=None, user=None):
    """An app holding a tenant-takeover app role (RoleManagement.ReadWrite.Directory) uses it to add
    a member to a directory role -> 'Privileged role used by Azure application'."""
    app = ga.app_identity(ac.rare_app_name())
    loc = ac.rare_asn_loc()
    calls = [("GET", "/v1.0/directoryRoles", 200, 7400),
             ("POST", f"/v1.0/directoryRoles/{ac._stable_guid('role:ga')}/members/$ref", 204, 0)]
    return ga.burst(app, calls, ip=loc["ip"], span_s=20,
                    roles="RoleManagement.ReadWrite.Directory Directory.ReadWrite.All")


def scenario_mailbox_enumeration(config=None, user=None):
    """App-only Graph requests enumerate users' mailbox surfaces and folders."""
    app = ga.app_identity(random.choice(list(ga.DAEMON_APPS)))
    users = [ac.user_oid(ac.pick_user(config)["username"]) for _ in range(5)]
    calls = [("GET", f"/v1.0/users/{oid}/mailFolders?$top=100", 200, random.randint(9000, 42000))
             for oid in users]
    calls += [("GET", f"/v1.0/users/{oid}/mailboxSettings", 200, random.randint(3000, 9000))
              for oid in users]
    return ga.burst(app, calls, roles="Mail.ReadBasic.All User.Read.All", span_s=180)


def scenario_mailbox_rule_create(config=None, user=None):
    """A delegated identity creates an inbox rule through the Graph API."""
    u = user or ac.pick_user(config)
    oid = ac.user_oid(u["username"])
    rule = {"displayName": "LogSim triage rule", "sequence": 1, "isEnabled": True,
            "conditions": {"subjectContains": ["LogSim test"]},
            "actions": {"moveToFolder": "Archive", "stopProcessingRules": True}}
    return ga.burst(u, [("POST", f"/v1.0/users/{oid}/mailFolders/inbox/messageRules", 201, 1200)],
                    scopes="MailboxSettings.ReadWrite", span_s=1)


def scenario_email_service_abuse(config=None, user=None):
    """Short, correlated Graph sendMail burst from a single app identity."""
    app = ga.app_identity(random.choice(list(ga.DAEMON_APPS)))
    calls = [("POST", f"/v1.0/users/{ac.user_oid(ac.pick_user(config)['username'])}/sendMail", 202, 900)
             for _ in range(12)]
    return ga.burst(app, calls, roles="Mail.Send User.Read.All", span_s=150)


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
    "dormant_account_signin": scenario_dormant_account_signin,
    "honey_user_signin": scenario_honey_user_signin,
    "suspicious_country_signin": scenario_suspicious_country_signin,
    "sso_abnormal_user_agent": scenario_sso_abnormal_user_agent,
    "sso_abnormal_os": scenario_sso_abnormal_os,
    "machine_account_sso": scenario_machine_account_sso,
    "sso_spray_ip_rotation": scenario_sso_spray_ip_rotation,
    "pentest_tool_activity": scenario_pentest_tool_activity,
    "first_sso_resource_org": scenario_first_sso_resource_org,
    "first_sso_new_asn": scenario_first_sso_new_asn,
    "unusual_resource_access_by_app": scenario_unusual_resource_access_by_app,
    "app_access_unknown_tenant": scenario_app_access_unknown_tenant,
    "sp_token_remote_usage": scenario_sp_token_remote_usage,
    "mi_token_remote_usage": scenario_mi_token_remote_usage,
    "device_code_auth_flow": scenario_device_code_auth_flow,
    "service_account_sso": scenario_service_account_sso,
    "powershell_signin": scenario_powershell_signin,
    "new_device_signin": scenario_new_device_signin,
    "new_country_signin": scenario_new_country_signin,
    "account_lockout_spray": scenario_account_lockout_spray,
    "graph_enumeration": scenario_graph_enumeration,
    "graph_throttling_app": scenario_graph_throttling_app,
    "graph_throttling_user": scenario_graph_throttling_user,
    "graph_denied_burst": scenario_graph_denied_burst,
    "graph_large_responses": scenario_graph_large_responses,
    "graph_privileged_app_call": scenario_graph_privileged_app_call,
}

SCENARIOS.update({
    "wip_unusual_country_api": scenario_new_country_signin,
    "wip_high_risk_ip_activity": scenario_high_risk_signin,
    "wip_api_call_from_tor": scenario_saas_api_from_tor,
    "wip_multiple_failed_logins": scenario_brute_force,
    "wip_impossible_travel_cloud": scenario_impossible_travel,
    "wip_suspicious_device_code": scenario_device_code_auth_flow,
    "wip_unknown_tenant_app_access": scenario_app_access_unknown_tenant,
    "wip_remote_service_principal_token": scenario_sp_token_remote_usage,
    "wip_remote_managed_identity_token": scenario_mi_token_remote_usage,
    "wip_graph_enumeration_activity": scenario_graph_enumeration,
    "wip_graph_throttling_app": scenario_graph_throttling_app,
    "wip_graph_denied_burst": scenario_graph_denied_burst,
    "wip_graph_response_size_spike": scenario_graph_large_responses,
    "wip_graph_privileged_app": scenario_graph_privileged_app_call,
    "wip_unusual_resource_by_app": scenario_unusual_resource_access_by_app,
    "wip_cloud_identity_unusual_country": scenario_suspicious_country_signin,
    "wip_graph_enumeration_exact": scenario_graph_enumeration,
    "wip_graph_throttling_exact": scenario_graph_throttling_app,
    "wip_mailbox_enumeration": scenario_mailbox_enumeration,
    "wip_mailbox_rule_create": scenario_mailbox_rule_create,
    "wip_cloud_email_infrastructure_enum": scenario_mailbox_enumeration,
    "wip_cloud_email_service_abuse": scenario_email_service_abuse,
    "wip_cloud_email_service_activity": scenario_email_service_abuse,
    "wip_unusual_cloud_identity_user_agent": scenario_sso_abnormal_user_agent,
    "wip_cloud_pentest_activity": scenario_pentest_tool_activity,
    "wip_multiple_risk_indicators": scenario_high_risk_signin,
    # CIE / ITDR-dependent: these detectors infer the account's directory classification
    # (disabled / honey / machine / service / dormant) from the Cloud Identity Engine identity map,
    # not from the sign-in log alone, so they cannot fire without a CIE directory export loaded in
    # the tenant. They stay WIP until a fire -> alert is observed with that map in place.
    # (disabled_user_signin was tested 2026-10-30 with a dedicated former-employee UPN + errorCode
    # 50057 and did not alert without CIE.)
    "wip_disabled_user_sso": scenario_disabled_user_signin,
    "wip_honey_user_sso": scenario_honey_user_signin,
    "wip_service_account_sso": scenario_service_account_sso,
    "wip_machine_account_sso": scenario_machine_account_sso,
    "wip_dormant_account_sso": scenario_dormant_account_signin,
})

ANALYTIC_ALERTS = {
    # Confirmed firing 2026-10-30 (fire -> alert observed on this feed's synthetic data).
    "tor_signin": "A successful SSO sign-in from TOR",
    "first_sso_resource_org": "Abnormal first access to a resource via SSO in the organization",
    "wip_unusual_country_api": "A cloud identity executed an API call from an unusual country",
    "wip_high_risk_ip_activity": "Cloud activity from a high-risk IP address",
    "wip_api_call_from_tor": "Suspicious API call from a Tor exit node",
    "wip_multiple_failed_logins": "Multiple failed logins from a single IP",
    "wip_impossible_travel_cloud": "Impossible travel by a cloud identity",
    "wip_suspicious_device_code": "Suspicious Entra ID Device Code Authentication Flow",
    "wip_unknown_tenant_app_access": "Attempted Azure application access from unknown tenant",
    "wip_remote_service_principal_token": "Remote usage of an Azure Service Principal token",
    "wip_remote_managed_identity_token": "Remote usage of an Azure Managed Identity token",
    "wip_graph_enumeration_activity": "Azure enumeration activity using Microsoft Graph API",
    "wip_graph_throttling_app": "An Azure application reached a throttling API rate",
    "wip_graph_denied_burst": "An Azure identity performed multiple actions that were denied",
    "wip_graph_response_size_spike": "Uncommon increase in Azure Microsoft Graph API request sizes",
    "wip_graph_privileged_app": "Privileged role used by Azure application",
    "wip_unusual_resource_by_app": "Unusual resource access by Azure application",
    "wip_cloud_identity_unusual_country": "A cloud identity executed an API call from an unusual country",
    "wip_graph_enumeration_exact": "Suspicious Azure enumeration activity",
    "wip_graph_throttling_exact": "Cloud identity reached a throttling API rate",
    "wip_mailbox_enumeration": "Mailbox enumeration activity by Azure application",
    "wip_mailbox_rule_create": "Azure mailbox rule creation",
    "wip_cloud_email_infrastructure_enum": "Cloud email infrastructure enumeration activity",
    "wip_cloud_email_service_abuse": "Suspicious activity indicating a potential abuse of a cloud-native email service",
    "wip_cloud_email_service_activity": "Cloud email service activity",
    "wip_unusual_cloud_identity_user_agent": "Unusual user-agent for a cloud identity",
    "wip_cloud_pentest_activity": "Cloud penetration testing tool activity",
    "wip_multiple_risk_indicators": "Multiple risk indicators for a cloud identity",
    # CIE / ITDR-dependent (unvalidated until a Cloud Identity Engine directory map is loaded that
    # marks the account disabled/honey/machine/service/dormant). Names for disabled/honey/service are
    # the published Cortex alerts; machine/dormant are provisional pending a confirmed fire.
    "wip_disabled_user_sso": "A disabled user attempted to authenticate via SSO",
    "wip_honey_user_sso": "SSO authentication attempt by a honey user",
    "wip_service_account_sso": "SSO authentication by a service account",
    "wip_machine_account_sso": "SSO authentication by a machine account",
    "wip_dormant_account_sso": "Dormant account authenticated via SSO",
}


# ── LogSim module interface ──────────────────────────────────────────────────────────

_GATE = ac.ThreatGate(SCENARIOS)


def get_threat_names():
    return list(SCENARIOS.keys())


def _copies(config, records):
    """Every signIn plus its Event Hub copy (msft_azure_raw, which the Cloud analytics read)."""
    return ac.with_eventhub_signins(records) if ac.eventhub_enabled(config, CONFIG_KEY) else records


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    if scenario_event:
        key = scenario_event if scenario_event in SCENARIOS else scenario_event.lower()
        if key in SCENARIOS:
            return (_copies(config, SCENARIOS[key](config)), key)
        return None
    if benign_only or threat_level == "Benign Traffic Only":
        return _copies(config, generate_benign(config, context))
    if _GATE.fire(threat_level, config):
        key = random.choice(list(SCENARIOS))
        return (_copies(config, SCENARIOS[key](config)), key)
    return _copies(config, generate_benign(config, context))
