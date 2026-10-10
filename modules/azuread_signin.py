"""Azure AD / Entra sign-ins (Microsoft Graph auditLogs/signIns) -> msft_azure_ad_raw.

Emits individual signIn resource objects in the shape XSIAM's Graph collector stores
(captured from the live tenant's real sign-ins). One event = one unwrapped signIn object
(the Graph $metadata collection envelope is pagination metadata, stripped by the collector).
Pushed via cribl_direct using the dedicated Azure AD sign-ins UUID.

These carry Microsoft's own risk signals (riskState / riskLevelDuringSignIn) and a nested
status{errorCode}, which detections can evaluate directly.
"""
import random
import time
import uuid

NAME = "Azure AD Sign-ins"
DESCRIPTION = "Simulates Microsoft Graph auditLogs/signIns events for msft_azure_ad_raw via the cribl_direct transport."
CONFIG_KEY = "azure_ad_signin_config"
SOURCE_IDENTIFIER = "f56dcfdf6bca43e793a4b6e9290e7b12"
INTEGRATION_IDENTIFIER = "logsim:azure_ad_signin"
DATASET = "msft_azure_ad_raw"

_THREAT_PROB = {
    "Benign Traffic Only": 0.0, "Low": 0.02, "Realistic": 0.05,
    "Medium": 0.08, "High": 0.12, "Insane": 0.30,
}

TENANT_DOMAIN = "8p68rd.onmicrosoft.com"
HOME_TENANT = "09febfec-25f3-48fa-bd8c-9b4a44f896ec"

USERS = [("aturing", "Alan Turing"), ("ghopper", "Grace Hopper"),
         ("klovelace", "Ada Lovelace"), ("mcurie", "Marie Curie"),
         ("rfranklin", "Rosalind Franklin"), ("nbohr", "Niels Bohr")]
BENIGN_IPS = ["108.245.61.200", "73.202.14.6", "98.45.112.9"]
RISKY_IPS = ["185.220.101.34", "45.148.10.92", "193.218.118.158", "171.25.193.78"]
LOCS = {
    "108.245.61.200": {"city": "Columbus", "state": "Ohio", "countryOrRegion": "US",
                       "geoCoordinates": {"latitude": 39.96, "longitude": -82.99}},
    "103.21.244.12":  {"city": "Singapore", "state": "", "countryOrRegion": "SG",
                       "geoCoordinates": {"latitude": 1.29, "longitude": 103.85}},
    "185.220.101.34": {"city": "Frankfurt", "state": "Hesse", "countryOrRegion": "DE",
                       "geoCoordinates": {"latitude": 50.11, "longitude": 8.68}},
}


def _g():
    return str(uuid.uuid4())


def _ts(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset_s))


def _signin(user, full_name, ip, *, success=True, error_code=0, failure="Other.",
            risk_level="none", risk_state="none", interactive=True, offset_s=0,
            conditional="success"):
    upn = f"{user}@{TENANT_DOMAIN}"
    loc = LOCS.get(ip, {"city": "Unknown", "state": "", "countryOrRegion": "US",
                        "geoCoordinates": {"latitude": 0, "longitude": 0}})
    return {
        "id": _g(), "createdDateTime": _ts(offset_s),
        "userDisplayName": full_name, "userPrincipalName": upn, "userId": _g(),
        "appId": _g(), "appDisplayName": "Microsoft Azure PowerShell",
        "ipAddress": ip, "clientAppUsed": "Browser", "correlationId": _g(),
        "conditionalAccessStatus": conditional, "isInteractive": interactive,
        "riskDetail": "none", "riskLevelAggregated": risk_level,
        "riskLevelDuringSignIn": risk_level, "riskState": risk_state,
        "riskEventTypes": [], "riskEventTypes_v2": [],
        "resourceDisplayName": "Windows Azure Service Management API", "resourceId": _g(),
        "homeTenantId": HOME_TENANT, "userType": "member",
        "signInEventTypes": ["interactiveUser"] if interactive else ["nonInteractiveUser"],
        "authenticationRequirement": "singleFactorAuthentication",
        "status": {"errorCode": error_code,
                   "failureReason": failure if not success else "Other.",
                   "additionalDetails": "MFA requirement satisfied by claim in the token"},
        "authenticationDetails": [{"authenticationMethod": "Password", "succeeded": success}],
        "authenticationMethodsUsed": ["Password"] if success else [],
        "deviceDetail": {"browser": "Chrome 154.0.0", "deviceId": "", "displayName": "",
                         "operatingSystem": "Windows10", "isCompliant": False, "isManaged": False},
        "location": loc,
        "appliedConditionalAccessPolicies": [],
    }


def generate_benign(config=None):
    u, fn = random.choice(USERS)
    return [_signin(u, fn, random.choice(BENIGN_IPS))]


def scenario_brute_force(config=None, user=None, attempts=10, src_ip=None):
    """Repeated failed sign-ins (errorCode 50126) then a success for one user."""
    u, fn = next((x for x in USERS if x[0] == user), random.choice(USERS))
    ip = src_ip or random.choice(RISKY_IPS)
    out = [_signin(u, fn, ip, success=False, error_code=50126,
                   failure="Invalid username or password.", conditional="notApplied",
                   offset_s=-(120 - i * 8)) for i in range(attempts)]
    out.append(_signin(u, fn, ip, offset_s=0))
    return out


def scenario_password_spray(config=None, victims=12, src_ip=None):
    """One IP, failed sign-ins across many users, then one success."""
    ip = src_ip or random.choice(RISKY_IPS)
    pool = USERS if victims <= len(USERS) else [random.choice(USERS) for _ in range(victims)]
    picks = random.sample(USERS, min(victims, len(USERS))) if victims <= len(USERS) else pool
    out = []
    for i, (u, fn) in enumerate(picks):
        out.append(_signin(u, fn, ip, success=False, error_code=50126,
                           failure="Invalid username or password.", conditional="notApplied",
                           offset_s=-(60 - i)))
    u0, fn0 = picks[0]
    out.append(_signin(u0, fn0, ip, offset_s=0))
    return out


def scenario_impossible_travel(config=None, user=None):
    """Same user, two successful sign-ins from distant countries minutes apart."""
    u, fn = next((x for x in USERS if x[0] == user), random.choice(USERS))
    return [_signin(u, fn, "108.245.61.200", offset_s=-300),
            _signin(u, fn, "103.21.244.12", offset_s=-60)]


def scenario_high_risk_signin(config=None, user=None):
    """Successful sign-in flagged high risk from an anonymizer IP (Microsoft risk signal)."""
    u, fn = next((x for x in USERS if x[0] == user), random.choice(USERS))
    rec = _signin(u, fn, random.choice(RISKY_IPS), risk_level="high", risk_state="atRisk")
    rec["riskDetail"] = "aiConfirmedSigninSafe"
    rec["riskEventTypes_v2"] = ["unfamiliarFeatures", "anonymizedIPAddress"]
    return [rec]


SCENARIOS = {
    "brute_force": scenario_brute_force,
    "password_spray": scenario_password_spray,
    "impossible_travel": scenario_impossible_travel,
    "high_risk_signin": scenario_high_risk_signin,
}


# ── LogSim module interface ──────────────────────────────────────────────────────────

def get_threat_names():
    return list(SCENARIOS.keys())


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    """Return a LIST of Graph signIn records (dicts) for the cribl transport."""
    if scenario_event:
        key = scenario_event if scenario_event in SCENARIOS else scenario_event.lower()
        if key in SCENARIOS:
            return (SCENARIOS[key](config), key)
        return None
    if benign_only or threat_level == "Benign Traffic Only":
        return generate_benign(config)
    if random.random() < _THREAT_PROB.get(threat_level, 0.05):
        key = random.choice(list(SCENARIOS))
        return (SCENARIOS[key](config), key)
    return generate_benign(config)
