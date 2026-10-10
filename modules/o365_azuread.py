"""Office 365 Azure AD (Management Activity API) generator -> msft_o365_azure_ad_raw.

Emits Audit.AzureActiveDirectory records in the exact shape the manage.office.com
Management Activity feed produces (captured from the live tenant). Pushed via the
cribl_direct transport using the dedicated O365 Azure AD UUID, so events land parsed in
the native dataset and are Fusion/analytics-eligible WITHOUT a Cribl instance.

Scenario functions return a LIST of records (an attack is usually several events).
"""
import random
import time
import uuid

NAME = "Office 365 Azure AD"
DESCRIPTION = "Simulates Office 365 Management Activity (Azure AD) audit records for msft_o365_azure_ad_raw via the cribl_direct transport."
CONFIG_KEY = "o365_azure_ad_config"
SOURCE_IDENTIFIER = "e1f109f886ea42fbb96be6ec0cc597a9"
INTEGRATION_IDENTIFIER = "logsim:o365_azure_ad"
DATASET = "msft_o365_azure_ad_raw"

# Fraction of generation ticks that emit a threat scenario instead of benign baseline.
# Baseline dominates so the dataset builds a "normal" profile for the ML analytics.
_THREAT_PROB = {
    "Benign Traffic Only": 0.0, "Low": 0.02, "Realistic": 0.05,
    "Medium": 0.08, "High": 0.12, "Insane": 0.30,
}

# Tenant-shaped defaults (override via config if desired).
TENANT_DOMAIN = "8p68rd.onmicrosoft.com"
ORG_ID = "09febfec-25f3-48fa-bd8c-9b4a44f896ec"

USERS = ["aturing", "ghopper", "klovelace", "mcurie", "rfranklin", "nbohr"]
BENIGN_IPS = ["108.245.61.200", "73.202.14.6", "98.45.112.9"]
# anonymizer / hosting / Tor-ish egress (risky source IPs)
RISKY_IPS = ["185.220.101.34", "45.148.10.92", "193.218.118.158", "171.25.193.78"]
# geographically distant pair for impossible-travel
GEO_PAIR = [("108.245.61.200", "US", "Columbus"), ("103.21.244.12", "SG", "Singapore")]

UA_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")


def _g():
    return str(uuid.uuid4())


def _now(offset_s: int = 0):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + offset_s))


def _upn(user):
    return f"{user}@{TENANT_DOMAIN}"


def _base(operation, user, ip, result_status="Success", error_number="0",
          extended=None, offset_s=0):
    """One Audit.AzureActiveDirectory record (RecordType 15 = AzureActiveDirectoryStsLogon)."""
    upn = _upn(user)
    rid = _g()
    ext = [{"Name": "UserAgent", "Value": UA_CHROME},
           {"Name": "RequestType", "Value": "Login:login"}]
    if extended:
        ext = extended + ext
    return {
        "CreationTime": _now(offset_s), "Id": rid, "Operation": operation,
        "OrganizationId": ORG_ID, "RecordType": 15, "ResultStatus": result_status,
        "UserKey": _g(), "UserType": 0, "Version": 1, "Workload": "AzureActiveDirectory",
        "ClientIP": ip, "ObjectId": _g(), "UserId": upn, "AzureActiveDirectoryEventType": 1,
        "ExtendedProperties": ext, "ModifiedProperties": [],
        "Actor": [{"ID": _g(), "Type": 0}, {"ID": upn, "Type": 5}],
        "ActorContextId": ORG_ID, "ActorIpAddress": ip, "InterSystemsId": _g(),
        "IntraSystemId": rid, "SupportTicketId": "",
        "Target": [{"ID": _g(), "Type": 0}], "TargetContextId": ORG_ID, "ApplicationId": _g(),
        "DeviceProperties": [{"Name": "OS", "Value": "Windows10"},
                             {"Name": "BrowserType", "Value": "Chrome"},
                             {"Name": "IsCompliant", "Value": "False"}],
        "ErrorNumber": error_number,
    }


def _tor_ip(config):
    """A real Tor exit IP from the live list LogSim loads at startup, else a fallback."""
    nodes = (config or {}).get("tor_exit_nodes") if isinstance(config, dict) else None
    if nodes:
        n = random.choice(nodes)
        return n.get("ip") if isinstance(n, dict) else n
    return random.choice(RISKY_IPS)


def _home_ip(user):
    """Stable 'home' IP per user so new-country/new-ASN anomalies read true against baseline."""
    return BENIGN_IPS[hash(user) % len(BENIGN_IPS)]


def _audit(operation, actor_user, ip, target_name=None, modified=None, result_status="Success"):
    """Audit.AzureActiveDirectory directory-change record (RecordType 8 = AzureActiveDirectory)."""
    upn = _upn(actor_user)
    rid = _g()
    return {
        "CreationTime": _now(), "Id": rid, "Operation": operation, "OrganizationId": ORG_ID,
        "RecordType": 8, "ResultStatus": result_status, "UserKey": _g(), "UserType": 0,
        "Version": 1, "Workload": "AzureActiveDirectory", "ObjectId": target_name or _g(),
        "UserId": upn, "AzureActiveDirectoryEventType": 0,
        "ExtendedProperties": [{"Name": "additionalDetails", "Value": "{}"}],
        "ModifiedProperties": modified or [],
        "Actor": [{"ID": _g(), "Type": 0}, {"ID": upn, "Type": 5}],
        "ActorContextId": ORG_ID, "ActorIpAddress": ip, "InterSystemsId": _g(),
        "IntraSystemId": rid, "SupportTicketId": "",
        "Target": [{"ID": target_name or _g(), "Type": 1}], "TargetContextId": ORG_ID,
    }


_APPS = ["Microsoft Office 365 Portal", "Office365 Shell WCSS-Client",
         "Microsoft Teams", "OfficeHome", "Microsoft 365 Security and Compliance Center"]


def generate_benign(config=None):
    """A routine successful interactive sign-in from the user's stable home IP + common app."""
    user = random.choice(USERS)
    rec = _base("UserLoggedIn", user, _home_ip(user))
    rec["ExtendedProperties"] = [{"Name": "UserAgent", "Value": UA_CHROME},
                                 {"Name": "RequestType", "Value": "Login:login"}]
    rec["Target"] = [{"ID": random.choice(_APPS), "Type": 1}]
    return [rec]


# ── analytics-triggering scenarios ───────────────────────────────────────────────────

def scenario_password_spray(config=None, victims=12, src_ip=None):
    """One source IP fails sign-in against many users (spray), then one success.
    Targets brute-force / password-spray detections."""
    ip = src_ip or random.choice(RISKY_IPS)
    out = []
    targets = random.sample(USERS, min(victims, len(USERS))) if victims <= len(USERS) \
        else [random.choice(USERS) for _ in range(victims)]
    for i, u in enumerate(targets):
        out.append(_base("UserLoginFailed", u, ip, result_status="Failed",
                         error_number="50126",
                         extended=[{"Name": "ResultStatusDetail",
                                    "Value": "InvalidUserNameOrPassword"}],
                         offset_s=-(60 - i)))
    # the spray lands one account
    out.append(_base("UserLoggedIn", targets[0], ip, offset_s=0))
    return out


def scenario_brute_force(config=None, user=None, attempts=10, src_ip=None):
    """Many failures against ONE user then a success — classic brute force."""
    u = user or random.choice(USERS)
    ip = src_ip or random.choice(RISKY_IPS)
    out = [_base("UserLoginFailed", u, ip, result_status="Failed", error_number="50126",
                 extended=[{"Name": "ResultStatusDetail", "Value": "InvalidUserNameOrPassword"}],
                 offset_s=-(120 - i * 8)) for i in range(attempts)]
    out.append(_base("UserLoggedIn", u, ip, offset_s=0))
    return out


def scenario_impossible_travel(config=None, user=None):
    """Same user signs in successfully from two distant countries minutes apart."""
    u = user or random.choice(USERS)
    (ip1, _, _), (ip2, _, _) = GEO_PAIR[0], GEO_PAIR[1]
    return [_base("UserLoggedIn", u, ip1, offset_s=-300),
            _base("UserLoggedIn", u, ip2, offset_s=-60)]


def scenario_tor_signin(config=None, user=None):
    """Successful sign-in from a real Tor exit node -> 'A successful SSO sign-in from TOR' (High)."""
    u = user or random.choice(USERS)
    return [_base("UserLoggedIn", u, _tor_ip(config))]


def scenario_admin_role_add(config=None, user=None):
    """Privilege escalation: add member to a privileged directory role."""
    u = user or random.choice(USERS)
    rec = _audit("Add member to role.", u, _home_ip(u), target_name=_upn(random.choice(USERS)),
                 modified=[{"Name": "Role.DisplayName", "NewValue": "Global Administrator", "OldValue": ""},
                           {"Name": "Role.TemplateId",
                            "NewValue": "62e90394-69f5-4237-9190-012177145e10", "OldValue": ""}])
    return [rec]


def scenario_mfa_disabled(config=None, user=None):
    """Disable strong auth (MFA) for an identity -> 'MFA was disabled for an Azure identity' (Low)."""
    u = user or random.choice(USERS)
    return [_audit("Disable Strong Authentication.", u, _home_ip(u),
                   target_name=_upn(random.choice(USERS)),
                   modified=[{"Name": "StrongAuthenticationRequirement",
                              "NewValue": "[]", "OldValue": "[{\"State\":\"Enforced\"}]"}])]


def scenario_federation_change(config=None, user=None):
    """Set federation settings on a domain -> 'Azure domain federation settings modification' (Low)."""
    u = user or random.choice(USERS)
    return [_audit("Set federation settings on domain.", u, _home_ip(u),
                   target_name=TENANT_DOMAIN,
                   modified=[{"Name": "IssuerUri", "NewValue": "http://any.sts/malicious",
                              "OldValue": ""}])]


def scenario_user_deletion(config=None, user=None):
    """Delete a user by a non-standard account -> 'Azure account deletion by a non-standard account' (Low)."""
    u = user or random.choice(USERS)
    return [_audit("Delete user.", u, _home_ip(u), target_name=_upn(random.choice(USERS)))]


def scenario_pim_role_change(config=None, user=None):
    """Change PIM role settings -> 'Azure AD PIM role settings change' (Low)."""
    u = user or random.choice(USERS)
    return [_audit("Update role setting in PIM.", u, _home_ip(u), target_name="Global Administrator",
                   modified=[{"Name": "RequireMfaOnActivation", "NewValue": "False", "OldValue": "True"}])]


def scenario_admin_role_removals(config=None):
    """Several admin-role removals in a short window -> 'Multiple Azure AD admin role removals' (Low)."""
    actor = random.choice(USERS)
    return [_audit("Remove member from role.", actor, _home_ip(actor),
                   target_name=_upn(v),
                   modified=[{"Name": "Role.DisplayName", "NewValue": "", "OldValue": "Global Administrator"}])
            for v in random.sample(USERS, min(4, len(USERS)))]


SCENARIOS = {
    "password_spray": scenario_password_spray,
    "brute_force": scenario_brute_force,
    "impossible_travel": scenario_impossible_travel,
    "tor_signin": scenario_tor_signin,
    "admin_role_add": scenario_admin_role_add,
    "mfa_disabled": scenario_mfa_disabled,
    "federation_change": scenario_federation_change,
    "user_deletion": scenario_user_deletion,
    "pim_role_change": scenario_pim_role_change,
    "admin_role_removals": scenario_admin_role_removals,
}


# ── LogSim module interface ──────────────────────────────────────────────────────────

def get_threat_names():
    """Named threats this module can fire on demand (dashboard / specific-threat menu)."""
    return list(SCENARIOS.keys())


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    """Return a LIST of Audit.AzureActiveDirectory records (dicts) for the cribl transport.

    - scenario_event names a specific threat -> that scenario's records (or None if unknown,
      so the caller's fallback can try).
    - otherwise emit benign baseline, with a threat_level-weighted chance of a threat.
    """
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
