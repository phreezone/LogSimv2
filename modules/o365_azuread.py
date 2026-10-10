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
SOURCE_IDENTIFIER = "e1f109f886ea42fbb96be6ec0cc597a9"
INTEGRATION_IDENTIFIER = "logsim:o365_azure_ad"
DATASET = "msft_o365_azure_ad_raw"

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


def generate_benign(config=None):
    """A single routine successful interactive sign-in."""
    return [_base("UserLoggedIn", random.choice(USERS), random.choice(BENIGN_IPS))]


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


def scenario_risky_ip_signin(config=None, user=None):
    """Successful sign-in from a known anonymizer/Tor egress IP."""
    u = user or random.choice(USERS)
    return [_base("UserLoggedIn", u, random.choice(RISKY_IPS))]


def scenario_admin_role_add(config=None, user=None):
    """Privilege escalation: add member to a privileged directory role."""
    u = user or random.choice(USERS)
    rec = _base("Add member to role.", u, random.choice(BENIGN_IPS))
    rec["ModifiedProperties"] = [
        {"Name": "Role.DisplayName", "NewValue": "Global Administrator", "OldValue": ""},
        {"Name": "Role.TemplateId", "NewValue": "62e90394-69f5-4237-9190-012177145e10", "OldValue": ""},
    ]
    return [rec]


SCENARIOS = {
    "password_spray": scenario_password_spray,
    "brute_force": scenario_brute_force,
    "impossible_travel": scenario_impossible_travel,
    "risky_ip_signin": scenario_risky_ip_signin,
    "admin_role_add": scenario_admin_role_add,
}
