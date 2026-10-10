"""Shared helpers for the Azure AD / O365 generators.

Sources identities from LogSim's canonical user model (config['user_profiles'] /
session_context, same as every other module) and models realistic sign-in content:
stable corporate-egress and home public IPs per user (so the ML analytics build a
coherent per-user baseline), plus catalogs of the apps, resources and status codes that
dominate a real Microsoft Entra tenant.

Research basis (Microsoft Entra sign-in / audit schema + typical tenant volume):
- Non-interactive sign-ins (silent token refresh by Outlook/Teams/OneDrive/mobile) are by
  far the highest volume, then interactive user sign-ins, then benign failures, then
  directory-audit activity. generate-side weighting reflects that.
"""
import hashlib
import random

try:
    from modules.session_utils import get_random_user
except Exception:  # pragma: no cover
    get_random_user = None

UPN_DOMAIN = "examplecorp.com"   # match LogSim's identity model (user emails are @examplecorp.com)
HOME_TENANT_ID = "09febfec-25f3-48fa-bd8c-9b4a44f896ec"

# A few shared corporate NAT egress IPs (realistic "many users behind one office IP").
OFFICE_EGRESS = [
    {"ip": "52.14.33.10",  "city": "Columbus", "state": "Ohio",       "countryOrRegion": "US", "lat": 39.96, "lon": -82.99},
    {"ip": "20.44.12.88",  "city": "Austin",   "state": "Texas",      "countryOrRegion": "US", "lat": 30.27, "lon": -97.74},
    {"ip": "40.112.55.3",  "city": "Seattle",  "state": "Washington", "countryOrRegion": "US", "lat": 47.60, "lon": -122.33},
]
_HOME_PREFIXES = ["71.84.", "98.112.", "24.17.", "73.202.", "68.44.", "99.7."]
_HOME_CITIES = [
    {"city": "Dublin",    "state": "Ohio",       "countryOrRegion": "US", "lat": 40.09, "lon": -83.11},
    {"city": "Round Rock","state": "Texas",      "countryOrRegion": "US", "lat": 30.50, "lon": -97.67},
    {"city": "Redmond",   "state": "Washington", "countryOrRegion": "US", "lat": 47.67, "lon": -122.12},
    {"city": "Naperville","state": "Illinois",   "countryOrRegion": "US", "lat": 41.75, "lon": -88.15},
]

# Apps/resources that dominate real Entra sign-in telemetry.
APPS_INTERACTIVE = ["Microsoft Office 365 Portal", "Office365 Shell WCSS-Client", "OfficeHome",
                    "Microsoft Teams", "My Apps", "Microsoft Office", "Outlook Web App",
                    "Microsoft 365 Security and Compliance Center"]
APPS_NONINTERACTIVE = ["Microsoft Authentication Broker", "Microsoft Office", "OneDrive SyncEngine",
                       "Microsoft Teams", "Outlook Mobile", "Windows Sign In",
                       "Office365 Shell WCSS-Client", "Microsoft Account Controls V2"]
RESOURCES = ["Microsoft Graph", "Office 365 Exchange Online", "Office 365 SharePoint Online",
             "Windows Azure Active Directory", "Microsoft.Azure.SyncFabric"]
# Benign sign-in failures that happen routinely (mistyped password, expired password, MFA needed).
BENIGN_FAIL = [
    (50126, "Error validating credentials due to invalid username or password."),
    (50055, "The password is expired."),
    (50074, "Strong Authentication is required."),
    (50058, "Session information is not sufficient for single-sign-on."),
    (50072, "User needs to enroll for second factor authentication."),
]


# Conditional Access policies a tenant typically has (displayName -> grant controls).
CA_POLICIES = [
    ("Require MFA for All Users", ["Mfa"]),
    ("Block Legacy Authentication", ["Block"]),
    ("Require Compliant or Hybrid Joined Device", ["CompliantDevice", "DomainJoinedDevice"]),
    ("Require MFA for Admins", ["Mfa"]),
    ("Require Approved Client App", ["ApprovedApplication"]),
]
# MFA / authentication methods (Entra authenticationMethod values).
MFA_METHODS = ["Mobile app notification", "Mobile app verification code", "Text message",
               "Windows Hello for Business", "FIDO2 security key", "Password"]
# Benign directory-audit Operations by category (O365 Management Activity naming — trailing period).
AUDIT_OPS = {
    "UserManagement": ["Update user.", "Change user password.", "Reset user password.",
                       "Update PasswordProfile.", "Add user.", "Update StsRefreshTokenValidFrom Timestamp."],
    "GroupManagement": ["Add member to group.", "Remove member from group.", "Update group."],
    "AuthMethod": ["User registered security info.", "User started security info registration.",
                   "User deleted security info.", "Admin registered security info."],
    "DeviceManagement": ["Add registered device.", "Add registered owner to device.", "Update device."],
    "ApplicationManagement": ["Consent to application.", "Add app role assignment grant to user."],
}


def _h(s):
    return int(hashlib.sha256(str(s).encode()).hexdigest(), 16)


def applied_ca(result="success", n=1):
    """Return an appliedConditionalAccessPolicies list (Graph appliedConditionalAccessPolicy)."""
    picks = random.sample(CA_POLICIES, min(n, len(CA_POLICIES)))
    out = []
    for name, grants in picks:
        out.append({"id": str(_h(name) % 10**32).zfill(8)[:8] + "-ca",  # stable-ish id
                    "displayName": name, "enforcedGrantControls": grants,
                    "enforcedSessionControls": [], "result": result})
    return out


def auth_details(method="Password", succeeded=True, step_ts=None):
    """Return an authenticationDetails list entry (Graph signIn authenticationDetail)."""
    return [{"authenticationStepDateTime": step_ts,
             "authenticationMethod": method,
             "authenticationMethodDetail": "",
             "succeeded": succeeded,
             "authenticationStepResultDetail": ("MFA completed in Azure AD" if method != "Password"
                                                else "Correct password"),
             "authenticationStepRequirement": ""}]


def pick_user(config=None, context=None):
    """Return a normalized identity from LogSim's user model.

    Prefers the run's session_context; falls back to config['user_profiles']; last resort a
    stub. Keys: username, upn, display_name, department, os_type, os_version.
    """
    sc = (context or {}).get("session_context") if isinstance(context, dict) else None
    if sc and get_random_user:
        u = get_random_user(sc)
        if u:
            uname = u["username"]
            return {"username": uname,
                    "upn": u.get("email") or f"{uname}@{UPN_DOMAIN}",
                    "display_name": u.get("display_name", uname),
                    "department": u.get("department", "Unknown"),
                    "os_type": u.get("os_type", "Windows"),
                    "os_version": u.get("os_version", "10")}
    profiles = (config or {}).get("user_profiles") or {}
    if profiles:
        uname = random.choice(list(profiles))
        p = profiles[uname]
        dev = (p.get("devices") or [{}])[0]
        return {"username": uname,
                "upn": p.get("email") or f"{uname}@{UPN_DOMAIN}",
                "display_name": p.get("display_name", uname),
                "department": p.get("department", "Unknown"),
                "os_type": dev.get("os_type", "Windows"),
                "os_version": dev.get("os_version", "10")}
    return {"username": "a.user", "upn": f"a.user@{UPN_DOMAIN}", "display_name": "A User",
            "department": "Unknown", "os_type": "Windows", "os_version": "10"}


def _norm(uname, p):
    dev = (p.get("devices") or [{}])[0]
    return {"username": uname, "upn": p.get("email") or f"{uname}@{UPN_DOMAIN}",
            "display_name": p.get("display_name", uname),
            "department": p.get("department", "Unknown"), "role": p.get("role", ""),
            "os_type": dev.get("os_type", "Windows"), "os_version": dev.get("os_version", "10")}


_ROLE_POOLS = {}


def pick_by_role(config, roles, departments=None):
    """Pick an actor whose profile role is in `roles` (e.g. Help Desk, IT Administrator).

    Admin actions in a real tenant come from a small, stable set of admins — the analytics
    baseline 'who normally does this', so a non-admin doing it reads as anomalous. Falls back
    to IT-department users, then to pick_user()."""
    profiles = (config or {}).get("user_profiles") or {}
    key = (tuple(roles), tuple(departments or ()))
    if key not in _ROLE_POOLS:
        pool = [u for u, p in profiles.items() if p.get("role") in roles]
        if not pool and departments:
            pool = [u for u, p in profiles.items() if p.get("department") in departments]
        _ROLE_POOLS[key] = sorted(pool)
    pool = _ROLE_POOLS[key]
    if not pool:
        return pick_user(config)
    u = random.choice(pool)
    return _norm(u, profiles[u])


# Business-hours activity profile (US Eastern, fixed offset). Interactive/admin activity
# follows the workday; token refreshes continue overnight. Gives 'unusual time' detectors a
# real diurnal baseline to judge against.
TZ_OFFSET_HOURS = -5


def activity_weight(now_ts=None):
    """0..1 likelihood that a human-driven event happens right now."""
    import time as _t
    t = _t.gmtime((now_ts or _t.time()) + TZ_OFFSET_HOURS * 3600)
    h, weekday = t.tm_hour, t.tm_wday < 5
    if weekday:
        if 8 <= h < 18:
            return 1.0
        if h == 7 or 18 <= h < 21:
            return 0.35
        return 0.06
    return 0.15 if 9 <= h < 17 else 0.04


def _stable_guid(seed):
    h = hashlib.sha256(str(seed).encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _browser(os_type):
    return "Safari 17.3" if os_type == "macOS" else "Chrome 154.0.0"


# ── stable-per-entity identifiers (cardinality) ──────────────────────────────────────
# These MUST be stable per entity, not random per event, or the analytics see every
# sign-in as a brand-new user/app (infinite cardinality) and the baseline never forms and
# "first seen"/"new app" detectors misfire. IDs that MUST stay unique per event
# (id/Id, correlationId, InterSystemsId, IntraSystemId, sessionId) are left random.

def user_oid(username):
    """Stable directory object id for a user (Graph userId / O365 UserKey)."""
    return _stable_guid("oid:" + str(username))


def app_id(name):
    """Stable application id for an app display name (Graph appId / O365 ApplicationId)."""
    return _stable_guid("app:" + str(name))


def resource_id(name):
    """Stable resource id for a resource display name (Graph resourceId)."""
    return _stable_guid("res:" + str(name))


def device_for(user, new=False):
    """deviceDetail for a sign-in. Stable (registered/compliant) per user by default; a
    brand-new unmanaged device when new=True -> feeds 'new device seen' anomaly detectors."""
    os_type = user.get("os_type", "Windows")
    os_str = f'{os_type} {user.get("os_version", "")}'.strip()
    if new:
        return {"deviceId": "", "displayName": "", "browser": _browser(os_type),
                "operatingSystem": os_str, "isCompliant": False, "isManaged": False, "trustType": ""}
    return {"deviceId": _stable_guid("dev:" + user["username"]),
            "displayName": f'{user["username"].upper().replace(".", "")}-PC',
            "browser": _browser(os_type), "operatingSystem": os_str,
            "isCompliant": True, "isManaged": True, "trustType": "Azure AD joined"}


def egress(user, remote_prob=0.25):
    """Stable public egress for a user: mostly their dept office NAT, sometimes a home IP.

    Returns {ip, city, state, countryOrRegion, geoCoordinates}. Deterministic per user so a
    user keeps a coherent IP/ASN/country baseline (anomaly detectors judge against it).
    """
    if random.random() < remote_prob:
        n = _h("home:" + user["username"])
        pfx = _HOME_PREFIXES[n % len(_HOME_PREFIXES)]
        ip = f"{pfx}{(n >> 8) % 254 + 1}.{(n >> 16) % 254 + 1}"
        loc = _HOME_CITIES[n % len(_HOME_CITIES)]
    else:
        loc = OFFICE_EGRESS[_h(user["department"]) % len(OFFICE_EGRESS)]
        ip = loc["ip"]
    return {"ip": ip, "city": loc["city"], "state": loc["state"],
            "countryOrRegion": loc["countryOrRegion"],
            "geoCoordinates": {"latitude": loc["lat"], "longitude": loc["lon"]}}
