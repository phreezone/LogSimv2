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

_THREAT_PROB = {
    "Benign Traffic Only": 0.0, "Low": 0.02, "Realistic": 0.05,
    "Medium": 0.08, "High": 0.12, "Insane": 0.30,
}


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
            failure="Other.", risk_level="none", risk_state="none", offset_s=0,
            app=None, resource=None, conditional="success", client_app="Browser",
            mfa=False):
    """Build one Graph signIn object from a user identity + egress location."""
    browser = f"Chrome 154.0.0" if user.get("os_type") != "macOS" else "Safari 17.3"
    return {
        "id": _g(), "createdDateTime": _ts(offset_s),
        "userDisplayName": user["display_name"], "userPrincipalName": user["upn"], "userId": _g(),
        "appId": _g(), "appDisplayName": app or random.choice(ac.APPS_INTERACTIVE),
        "ipAddress": loc["ip"], "clientAppUsed": client_app, "correlationId": _g(),
        "conditionalAccessStatus": conditional, "isInteractive": interactive,
        "riskDetail": "none", "riskLevelAggregated": risk_level,
        "riskLevelDuringSignIn": risk_level, "riskState": risk_state,
        "riskEventTypes": [], "riskEventTypes_v2": [],
        "resourceDisplayName": resource or random.choice(ac.RESOURCES), "resourceId": _g(),
        "homeTenantId": ac.HOME_TENANT_ID, "userType": "member",
        "signInEventTypes": ["interactiveUser"] if interactive else ["nonInteractiveUser"],
        "authenticationRequirement": "multiFactorAuthentication" if mfa else "singleFactorAuthentication",
        "status": {"errorCode": error_code,
                   "failureReason": failure if not success else "Other.",
                   "additionalDetails": ("MFA requirement satisfied by claim in the token"
                                         if success else None)},
        "authenticationDetails": [{"authenticationMethod": "Previously satisfied" if not interactive else "Password",
                                   "succeeded": success}],
        "authenticationMethodsUsed": (["Password"] if success and interactive else []),
        "deviceDetail": {"browser": browser, "deviceId": "", "displayName": "",
                         "operatingSystem": f'{user.get("os_type","Windows")}{user.get("os_version","")}'.strip(),
                         "isCompliant": True, "isManaged": True},
        "location": {"city": loc["city"], "state": loc["state"],
                     "countryOrRegion": loc["countryOrRegion"], "geoCoordinates": loc["geoCoordinates"]},
        "appliedConditionalAccessPolicies": [],
    }


# ── benign baseline (realistic weighted mix) ─────────────────────────────────────────

def generate_benign(config=None, context=None):
    """One routine sign-in, weighted toward silent token refreshes like a real tenant."""
    user = ac.pick_user(config, context)
    loc = ac.egress(user)
    r = random.random()
    if r < 0.70:   # non-interactive token refresh — highest volume
        return [_signin(user, loc, interactive=False, app=random.choice(ac.APPS_NONINTERACTIVE),
                        conditional=random.choice(["success", "notApplied"]), client_app="Browser")]
    if r < 0.92:   # interactive success (MFA satisfied via session)
        return [_signin(user, loc, interactive=True, app=random.choice(ac.APPS_INTERACTIVE),
                        mfa=random.random() < 0.3)]
    # routine benign failure (mistyped/expired password, MFA needed)
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


SCENARIOS = {
    "brute_force": scenario_brute_force,
    "password_spray": scenario_password_spray,
    "impossible_travel": scenario_impossible_travel,
    "high_risk_signin": scenario_high_risk_signin,
    "tor_signin": scenario_tor_signin,
    "powershell_signin": scenario_powershell_signin,
}


# ── LogSim module interface ──────────────────────────────────────────────────────────

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
    if random.random() < _THREAT_PROB.get(threat_level, 0.05):
        key = random.choice(list(SCENARIOS))
        return (SCENARIOS[key](config), key)
    return generate_benign(config, context)
