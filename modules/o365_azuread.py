"""Office 365 Azure AD (Management Activity API) generator -> msft_o365_azure_ad_raw.

Emits Audit.AzureActiveDirectory records in the manage.office.com Management Activity
shape (captured from the live tenant): RecordType 15 = StsLogon sign-ins, RecordType 8 =
directory audit operations. Identities come from LogSim's user model via azure_common, so
O365 activity ties to the same people as every other module. Pushed via cribl_direct under
the dedicated O365 Azure AD UUID (lands parsed in the native dataset, Fusion-eligible).

Benign baseline reflects real tenant mix: mostly successful interactive sign-ins, some
routine benign failures (mistyped/expired password), occasional directory activity.
"""
import random
import time
import uuid

from modules import azure_common as ac
from modules import azure_audit_catalog as _auditcat

# O365 Management Activity directory operations (RecordType 8), derived from the Entra audit
# catalog's Core Directory activities in O365-MA naming (trailing period). Gives the O365
# Azure AD feed the same broad directory-operation coverage as the Graph audit feed.
_O365_MA_OPS = [((a if a.endswith(".") else a + "."), c)
                for a, c, s, op, t in _auditcat.AUDIT_ACTIVITIES
                if s == "Core Directory" and c in ("UserManagement", "GroupManagement",
                "ApplicationManagement", "RoleManagement", "DirectoryManagement", "Device")]

NAME = "Office 365 Azure AD"
DESCRIPTION = "Simulates Office 365 Management Activity (Azure AD) audit records for msft_o365_azure_ad_raw via the cribl_direct transport."
CONFIG_KEY = "o365_azure_ad_config"
SOURCE_IDENTIFIER = "e1f109f886ea42fbb96be6ec0cc597a9"
INTEGRATION_IDENTIFIER = "logsim:o365_azure_ad"
DATASET = "msft_o365_azure_ad_raw"
ORG_ID = "09febfec-25f3-48fa-bd8c-9b4a44f896ec"

RISKY_IPS = ["185.220.101.34", "45.148.10.92", "193.218.118.158", "171.25.193.78"]
_APPS = ["Microsoft Office 365 Portal", "Office365 Shell WCSS-Client", "Microsoft Teams",
         "OfficeHome", "Microsoft 365 Security and Compliance Center"]

# Threat rate is governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (wall-clock
# episode rate, with a benign warmup) — see _GATE below.


def _g():
    return str(uuid.uuid4())


def _now(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + offset_s))


def _tor_ip(config):
    nodes = (config or {}).get("tor_exit_nodes") if isinstance(config, dict) else None
    if nodes:
        n = random.choice(nodes)
        return n.get("ip") if isinstance(n, dict) else n
    return random.choice(RISKY_IPS)


def _signin(operation, user, ip, *, result_status="Success", error_number="0",
            extended=None, offset_s=0, request_type="Login:login"):
    """Audit.AzureActiveDirectory sign-in record (RecordType 15 = AzureActiveDirectoryStsLogon)."""
    upn = user["upn"]
    rid = _g()
    ua = ac.user_agent(user)
    ext = [{"Name": "ResultStatusDetail", "Value": result_status},
           {"Name": "UserAgent", "Value": ua},
           {"Name": "RequestType", "Value": request_type}]
    if extended:
        ext = extended + ext
    app_name = random.choice(_APPS)
    app_guid = ac.app_id(app_name)   # stable per app; sign-in ObjectId==ApplicationId==Target.ID
    return {
        "CreationTime": _now(offset_s), "Id": rid, "Operation": operation,
        "OrganizationId": ORG_ID, "RecordType": 15, "ResultStatus": result_status,
        "UserKey": ac.user_oid(user["username"]), "UserType": 0, "Version": 1,
        "Workload": "AzureActiveDirectory",
        "ClientIP": ip, "ObjectId": app_guid, "UserId": upn, "AzureActiveDirectoryEventType": 1,
        "ExtendedProperties": ext, "ModifiedProperties": [],
        "Actor": [{"ID": ac.user_oid(user["username"]), "Type": 0}, {"ID": upn, "Type": 5}],
        "ActorContextId": ORG_ID, "ActorIpAddress": ip, "InterSystemsId": _g(),
        "IntraSystemId": rid, "SupportTicketId": "",
        "Target": [{"ID": app_guid, "Type": 1}], "TargetContextId": ORG_ID,
        "ApplicationId": app_guid,
        "DeviceProperties": [{"Name": "OS", "Value": user.get("os_type", "Windows")},
                             {"Name": "BrowserType", "Value": "Chrome"},
                             {"Name": "IsCompliant", "Value": "True"}],
        "ErrorNumber": error_number,
    }


def _audit(operation, actor, ip, target_name=None, modified=None, result_status="Success"):
    """Audit.AzureActiveDirectory directory-change record (RecordType 8 = AzureActiveDirectory)."""
    upn = actor["upn"]
    rid = _g()
    return {
        "CreationTime": _now(), "Id": rid, "Operation": operation, "OrganizationId": ORG_ID,
        "RecordType": 8, "ResultStatus": result_status,
        "UserKey": ac.user_oid(actor["username"]), "UserType": 0,
        "Version": 1, "Workload": "AzureActiveDirectory", "ObjectId": target_name or _g(),
        "UserId": upn, "AzureActiveDirectoryEventType": 0,
        "ExtendedProperties": [{"Name": "additionalDetails", "Value": "{}"}],
        "ModifiedProperties": modified or [],
        "Actor": [{"ID": ac.user_oid(actor["username"]), "Type": 0}, {"ID": upn, "Type": 5}],
        "ActorContextId": ORG_ID, "ActorIpAddress": ip, "InterSystemsId": _g(),
        "IntraSystemId": rid, "SupportTicketId": "",
        "Target": [{"ID": target_name or _g(), "Type": 1}], "TargetContextId": ORG_ID,
    }


def _benign_audit(actor, ip, config):
    """A routine directory-change record drawn from the full Core Directory operation set
    (O365 Management Activity shape), with Operation-appropriate ModifiedProperties for the
    common ones and sensible targets otherwise."""
    op, category = random.choice(_O365_MA_OPS)
    target = ac.pick_user(config)["upn"]
    modified = []
    if op == "Update user.":
        modified = [{"Name": "Included Updated Properties", "NewValue": "JobTitle, Department", "OldValue": ""}]
    elif op in ("Add member to group.", "Remove member from group."):
        target = ac.group_name()
        modified = [{"Name": "Group.DisplayName", "NewValue": target, "OldValue": ""},
                    {"Name": "Group.ObjectID", "NewValue": ac._stable_guid("Group:" + target), "OldValue": ""}]
    elif op == "User registered security info.":
        modified = [{"Name": "SecurityInfo.Method", "NewValue": random.choice(ac.MFA_METHODS), "OldValue": ""}]
    elif op == "Consent to application.":
        modified = [{"Name": "ConsentContext.IsAdminConsent", "NewValue": "False", "OldValue": ""},
                    {"Name": "ConsentAction.Permissions", "NewValue": "User.Read openid profile", "OldValue": ""}]
    elif op in ("Add registered device.", "Add registered owner to device.", "Update device."):
        target = f'{actor["username"].upper()}-LT'
    elif category == "GroupManagement":
        target = ac.group_name()
    elif category == "RoleManagement":
        target = random.choice(["Helpdesk Administrator", "User Administrator", "Security Reader",
                                "Exchange Administrator", "Application Administrator"])
    elif category == "ApplicationManagement":
        target = random.choice(["Salesforce", "ServiceNow", "Workday", "GitHub Enterprise"])
    elif category == "DirectoryManagement":
        target = ac.UPN_DOMAIN
    return _audit(op, actor, ip, target_name=target, modified=modified)


# ── benign baseline (realistic weighted mix) ─────────────────────────────────────────

def generate_benign(config=None, context=None):
    user = ac.pick_user(config, context)
    loc = ac.egress(user)
    r = random.random()
    if r < 0.78:   # successful interactive sign-in
        return [_signin("UserLoggedIn", user, loc["ip"],
                        request_type=random.choice(["Login:login", "Kmsi:kmsi", "OAuth2:Authorize"]))]
    if r < 0.90:   # routine benign failure
        code, _ = random.choice(ac.BENIGN_FAIL)
        return [_signin("UserLoginFailed", user, loc["ip"], result_status="Failed",
                        error_number=str(code),
                        extended=[{"Name": "ResultStatusDetail", "Value": "Failed"}])]
    # occasional routine directory activity (self-service / admin housekeeping)
    return [_benign_audit(user, loc["ip"], config)]


# ── attack scenarios ─────────────────────────────────────────────────────────────────

def scenario_password_spray(config=None, victims=12, src_ip=None):
    ip = src_ip or random.choice(RISKY_IPS)
    out = []
    for i in range(victims):
        u = ac.pick_user(config)
        out.append(_signin("UserLoginFailed", u, ip, result_status="Failed", error_number="50126",
                           extended=[{"Name": "ResultStatusDetail", "Value": "InvalidUserNameOrPassword"}],
                           offset_s=-(60 - i)))
    out.append(_signin("UserLoggedIn", ac.pick_user(config), ip, offset_s=0))
    return out


def scenario_brute_force(config=None, user=None, attempts=10, src_ip=None):
    u = ac.pick_user(config)
    ip = src_ip or random.choice(RISKY_IPS)
    out = [_signin("UserLoginFailed", u, ip, result_status="Failed", error_number="50126",
                   extended=[{"Name": "ResultStatusDetail", "Value": "InvalidUserNameOrPassword"}],
                   offset_s=-(120 - i * 8)) for i in range(attempts)]
    out.append(_signin("UserLoggedIn", u, ip, offset_s=0))
    return out


def scenario_impossible_travel(config=None, user=None):
    u = ac.pick_user(config)
    return [_signin("UserLoggedIn", u, "108.245.61.200", offset_s=-300),
            _signin("UserLoggedIn", u, "103.21.244.12", offset_s=-60)]


def scenario_tor_signin(config=None, user=None):
    u = ac.pick_user(config)
    return [_signin("UserLoggedIn", u, _tor_ip(config))]


def scenario_admin_role_add(config=None, user=None):
    actor = ac.pick_user(config)
    return [_audit("Add member to role.", actor, ac.egress(actor)["ip"],
                   target_name=ac.pick_user(config)["upn"],
                   modified=[{"Name": "Role.DisplayName", "NewValue": "Global Administrator", "OldValue": ""},
                             {"Name": "Role.TemplateId",
                              "NewValue": "62e90394-69f5-4237-9190-012177145e10", "OldValue": ""}])]


def scenario_mfa_disabled(config=None, user=None):
    actor = ac.pick_user(config)
    return [_audit("Disable Strong Authentication.", actor, ac.egress(actor)["ip"],
                   target_name=ac.pick_user(config)["upn"],
                   modified=[{"Name": "StrongAuthenticationRequirement", "NewValue": "[]",
                              "OldValue": "[{\"State\":\"Enforced\"}]"}])]


def scenario_federation_change(config=None, user=None):
    actor = ac.pick_user(config)
    return [_audit("Set federation settings on domain.", actor, ac.egress(actor)["ip"],
                   target_name=ac.UPN_DOMAIN,
                   modified=[{"Name": "IssuerUri", "NewValue": "http://any.sts/malicious", "OldValue": ""}])]


def scenario_user_deletion(config=None, user=None):
    actor = ac.pick_user(config)
    return [_audit("Delete user.", actor, ac.egress(actor)["ip"], target_name=ac.pick_user(config)["upn"])]


_PRIV_ROLES = ("IT Administrator", "IT Director", "Systems Engineer")


def scenario_priv_auth_method_added(config=None, user=None):
    """A new strong-auth method is registered ON a privileged account -> 'Suspicious authentication
    method added to an Azure Privileged account'. Target is an admin (the privilege is the signal);
    an attacker who took over an admin registers their own MFA method for persistence."""
    admin = ac.pick_by_role(config, _PRIV_ROLES, ("IT", "Security"))
    return [_audit("User registered security info.", admin, ac.egress(admin)["ip"],
                   target_name=admin["upn"],
                   modified=[{"Name": "SecurityInfo.Method", "NewValue": "Phone (SMS)", "OldValue": ""},
                             {"Name": "SecurityInfo.Action", "NewValue": "Register", "OldValue": ""}])]


def scenario_atypical_account_deletion(config=None, user=None):
    """Deletions by an identity with HIGH administrative activity that does NOT typically delete
    users -> 'Azure account deletion by a non-standard account'. Per the detector, the actor is an
    admin (high admin-op baseline) whose anomaly is the deletion itself, not a random user."""
    actor = ac.pick_by_role(config, ("IT Administrator", "IT Director", "Systems Engineer"),
                            ("IT", "Security"))
    ip = ac.egress(actor)["ip"]
    return [_audit("Delete user.", actor, ip, target_name=ac.pick_user(config)["upn"])
            for _ in range(random.randint(3, 6))]


def scenario_account_created_nonstandard(config=None, user=None):
    """A new Azure AD account is created BY an actor who does not normally create accounts (a
    regular non-admin user) -> 'Azure account created by non-standard account'."""
    actor = ac.pick_user(config)   # non-admin / non-standard creator
    new = f"svc_temp_{random.randint(1000, 9999)}@{ac.UPN_DOMAIN}"
    return [_audit("Add user.", actor, ac.egress(actor)["ip"], target_name=new,
                   modified=[{"Name": "AccountEnabled", "NewValue": "True", "OldValue": ""}])]


def scenario_user_create_delete_short(config=None, user=None):
    """An Azure AD account is created and then deleted within a short window (burner account) ->
    'Azure AD user created and deleted in a short time period'."""
    actor = ac.pick_user(config); ip = ac.egress(actor)["ip"]
    burner = f"temp_{random.randint(1000, 9999)}@{ac.UPN_DOMAIN}"
    return [_audit("Add user.", actor, ip, target_name=burner,
                   modified=[{"Name": "AccountEnabled", "NewValue": "True", "OldValue": ""}]),
            _audit("Delete user.", actor, ip, target_name=burner)]


def scenario_pim_role_change(config=None, user=None):
    actor = ac.pick_user(config)
    return [_audit("Update role setting in PIM.", actor, ac.egress(actor)["ip"],
                   target_name="Global Administrator",
                   modified=[{"Name": "RequireMfaOnActivation", "NewValue": "False", "OldValue": "True"}])]


def scenario_admin_role_removals(config=None):
    actor = ac.pick_user(config)
    ip = ac.egress(actor)["ip"]
    return [_audit("Remove member from role.", actor, ip, target_name=ac.pick_user(config)["upn"],
                   modified=[{"Name": "Role.DisplayName", "NewValue": "", "OldValue": "Global Administrator"}])
            for _ in range(4)]


SCENARIOS = {
    "password_spray": scenario_password_spray,
    "brute_force": scenario_brute_force,
    "impossible_travel": scenario_impossible_travel,
    "tor_signin": scenario_tor_signin,
    "admin_role_add": scenario_admin_role_add,
    "mfa_disabled": scenario_mfa_disabled,
    "priv_auth_method_added": scenario_priv_auth_method_added,
    "atypical_account_deletion": scenario_atypical_account_deletion,
    "account_created_nonstandard": scenario_account_created_nonstandard,
    "user_create_delete_short": scenario_user_create_delete_short,
    "federation_change": scenario_federation_change,
    "user_deletion": scenario_user_deletion,
    "pim_role_change": scenario_pim_role_change,
    "admin_role_removals": scenario_admin_role_removals,
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
