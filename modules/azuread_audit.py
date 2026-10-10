"""Microsoft Entra directory audit logs (Graph auditLogs/directoryAudits)
-> msft_azure_ad_audit_raw, via the cribl_direct transport (dedicated UUID).

Record shape verified against the Microsoft Graph resource docs (directoryAudit,
auditActivityInitiator, targetResource, modifiedProperty) AND real rows from the tenant:
  - id = "<ServicePrefix>_<correlationId>_<CODE>_<bignum>" (prefix per loggedByService)
  - activityDisplayName: Graph style, NO trailing period (differs from the O365 feed)
  - activityDateTime: 7-digit fractional seconds, Z
  - initiatedBy {user|app} (either or both; app may carry a null appId)
  - targetResources[].modifiedProperties[].oldValue/newValue are JSON-ENCODED strings
  - additionalDetails: key/value list; resultReason populated even on success

Activity names/categories/services are taken verbatim from the Microsoft Entra audit
activity reference. Benign baseline spans the directory activity a real tenant produces on
its own; admin actions are pinned to IT/admin role pools and follow business hours so
"unusual admin / unusual time" reads true. This is the widest new source of event types for
the Azure AD side.
"""
import datetime
import json
import random
import string
import uuid

from modules import azure_common as ac
from modules import azure_audit_catalog as cat

NAME = "Azure AD Audit"
DESCRIPTION = "Simulates Microsoft Graph directoryAudits events for msft_azure_ad_audit_raw via the cribl_direct transport."
CONFIG_KEY = "azure_ad_audit_config"
SOURCE_IDENTIFIER = "0e076d5abe864bf78e8145ea9e0d749e"
INTEGRATION_IDENTIFIER = "logsim:azure_ad_audit"
DATASET = "msft_azure_ad_audit_raw"

_THREAT_PROB = {"Benign Traffic Only": 0.0, "Low": 0.02, "Realistic": 0.05,
                "Medium": 0.08, "High": 0.12, "Insane": 0.30}

ADMIN_ROLES = ("IT Administrator", "IT Director", "Systems Engineer")
HELPDESK_ROLES = ("Help Desk", "IT Administrator")
_ID_PREFIX = {"Core Directory": "Directory", "Self-service Password Management": "SSPR",
              "Authentication Methods": "Authentication Methods", "Account Provisioning": "Sync"}
_GROUPS = ["All Employees", "Sales Team", "Engineering", "VPN Users", "Finance", "Marketing",
           "DevOps Admins", "M365 E5 Licensed Users", "Contractors"]
_SAAS_APPS = ["Salesforce", "ServiceNow", "Zoom", "Slack", "Workday", "DocuSign",
              "Atlassian Cloud", "GitHub Enterprise", "Adobe Acrobat Sign"]
_CA_POLICIES = [n for n, _ in ac.CA_POLICIES]


def _ts():
    d = datetime.datetime.now(datetime.timezone.utc)
    return f"{d:%Y-%m-%dT%H:%M:%S}.{d.microsecond:06d}{random.randint(0, 9)}Z"


def _code():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=5))


def _enc(v):
    return None if v is None else json.dumps(v)


def mp(name, old, new):
    return {"displayName": name, "oldValue": _enc(old), "newValue": _enc(new)}


def by_user(u, ip=None):
    ip = ip or ac.egress(u)["ip"]
    return {"user": {"id": ac.user_oid(u["username"]), "displayName": None,
                     "userPrincipalName": u["upn"], "ipAddress": ip, "userType": "Member",
                     "agentType": "notAgentic", "homeTenantId": None, "homeTenantName": None},
            "app": None}


def by_app(name, app_id=None):
    return {"user": None, "app": {"appId": app_id, "displayName": name,
                                  "servicePrincipalId": None, "servicePrincipalName": None}}


def t_user(u, mods=None):
    return {"id": ac.user_oid(u["username"]), "displayName": u.get("display_name"), "type": "User",
            "userPrincipalName": u["upn"], "groupType": None, "modifiedProperties": mods or []}


def t_obj(kind, name, mods=None, group_type=None):
    return {"id": ac._stable_guid(f"{kind}:{name}"), "displayName": name, "type": kind,
            "userPrincipalName": None, "groupType": group_type, "modifiedProperties": mods or []}


def audit(activity, category, service, op_type, initiator, targets,
          details=None, result="success", reason=""):
    corr = str(uuid.uuid4())
    pfx = _ID_PREFIX.get(service, "Directory")
    return {"id": f"{pfx}_{corr}_{_code()}_{random.randint(1000000, 999999999)}",
            "category": category, "correlationId": corr, "result": result,
            "resultReason": reason or activity, "activityDisplayName": activity,
            "activityDateTime": _ts(), "loggedByService": service, "operationType": op_type,
            "initiatedBy": initiator, "targetResources": targets, "additionalDetails": details or []}


def _ua(u):
    return {"key": "User-Agent",
            "value": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36" if u.get("os_type") == "macOS"
                      else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")}


# ── benign activity builders (weight, fn) ───────────────────────────────────────────

def _b_update_user(cfg):
    admin = ac.pick_by_role(cfg, HELPDESK_ROLES, ("IT",)); tgt = ac.pick_user(cfg)
    attr = random.choice([("JobTitle", "Account Executive", "Senior Account Executive"),
                          ("Department", "Sales", "Customer Success"),
                          ("OfficeLocation", "Columbus", "Austin")])
    mods = [mp(attr[0], attr[1], attr[2]),
            mp("Included Updated Properties", None, attr[0])]
    return audit("Update user", "UserManagement", "Core Directory", "Update",
                 by_user(admin), [t_user(tgt, mods)], [_ua(admin), {"key": "UserType", "value": "Member"}])


def _b_self_password(cfg):
    u = ac.pick_user(cfg)
    return audit("Change password (self-service)", "UserManagement",
                 "Self-service Password Management", "Update", by_user(u), [t_user(u)],
                 reason="Successfully completed change.")


def _b_admin_reset(cfg):
    admin = ac.pick_by_role(cfg, HELPDESK_ROLES, ("IT",)); tgt = ac.pick_user(cfg)
    return audit("Reset password (by admin)", "UserManagement",
                 "Self-service Password Management", "Update", by_user(admin), [t_user(tgt)],
                 [{"key": "OnPremisesAgent", "value": "None"}], reason="Successfully completed reset.")


def _b_secinfo_register(cfg):
    u = ac.pick_user(cfg)
    act = random.choice(["User registered security info", "User started security info registration",
                         "User registered all required security info", "User changed default security info"])
    return audit(act, "UserManagement", "Authentication Methods",
                 "Add" if "register" in act else "Update", by_user(u), [t_user(u)],
                 [{"key": "InitiatedFrom", "value": "Microsoft App Access Panel (0000000c-0000-0000-c000-000000000000)"}],
                 reason=act)


def _b_group_member(cfg):
    admin = ac.pick_by_role(cfg, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(cfg)
    g = random.choice(_GROUPS)
    add = random.random() < 0.6
    mods = [mp("Group.DisplayName", None, g),
            mp("Group.ObjectID", None, ac._stable_guid("Group:" + g))]
    return audit("Add member to group" if add else "Remove member from group", "GroupManagement",
                 "Core Directory", "Add" if add else "Remove", by_user(admin),
                 [t_obj("Group", g, mods, group_type="unifiedGroups"), t_user(tgt)], [_ua(admin)])


def _b_app_role_assign(cfg):
    u = ac.pick_user(cfg); app = random.choice(_SAAS_APPS)
    return audit("Add app role assignment grant to user", "UserManagement", "Core Directory",
                 "Assign", by_user(u), [t_obj("ServicePrincipal", app,
                 [mp("AppRole.Value", None, "User")])], [{"key": "User-Agent", "value": "EvoSTS"}])


def _b_consent(cfg):
    u = ac.pick_user(cfg); app = random.choice(_SAAS_APPS)
    mods = [mp("ConsentContext.IsAdminConsent", None, "False"),
            mp("ConsentAction.Permissions", None, "openid profile User.Read offline_access")]
    return audit("Consent to application", "ApplicationManagement", "Core Directory", "Assign",
                 by_user(u), [t_obj("ServicePrincipal", app, mods)],
                 [{"key": "User-Agent", "value": "EvoSTS"},
                  {"key": "ServicePrincipalProvisioningType", "value": "Other"}])


def _b_register_device(cfg):
    u = ac.pick_user(cfg); dev = f'{u["username"].upper().replace(".", "")}-PC'
    return audit("Register device", "Device", "Device Registration Service", "Add",
                 by_user(u), [t_obj("Device", dev, [mp("DeviceOSType", None, u.get("os_type", "Windows")),
                 mp("DeviceTrustType", None, "Azure AD joined")])])


def _b_token_timestamp(cfg):
    admin = ac.pick_by_role(cfg, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(cfg)
    return audit("Update StsRefreshTokenValidFrom Timestamp", "UserManagement", "Core Directory",
                 "Update", by_user(admin), [t_user(tgt, [mp("StsRefreshTokensValidFrom",
                 "2026-01-01T00:00:00Z", _ts()[:-1])])])


def _b_provisioning(cfg):
    act = random.choice(["Import", "Execution", "Export"])
    return audit(act, "ProvisioningManagement", "Account Provisioning", "Read",
                 by_app("Azure AD Cloud Sync"), [t_obj("ServicePrincipal", "Directory",
                 [mp("dirSyncEnabled", None, "True"), mp("countryLetterCode", None, "US")])],
                 [{"key": "EventName", "value": "EntryImport"}, {"key": "JoiningProperty", "value": "MSFT"}],
                 reason="Retrieved TenantDetail 'MSFT' from Microsoft Entra ID")


# High-fidelity builders for the common activities (bespoke modifiedProperties/details).
_B_HUMAN = [_b_update_user, _b_secinfo_register, _b_group_member, _b_self_password,
            _b_app_role_assign, _b_consent, _b_register_device, _b_admin_reset, _b_token_timestamp]

_GROUPS_T = ["All Employees", "Sales Team", "Engineering", "VPN Users", "Finance",
             "Marketing", "DevOps Admins", "Contractors"]
_ROLES_T = ["Helpdesk Administrator", "User Administrator", "Security Reader",
            "Exchange Administrator", "Global Reader", "Application Administrator"]


def _generic_mods(category, op_type):
    if op_type not in ("Add", "Update"):
        return []
    return {"GroupManagement": [mp("Group.DisplayName", None, random.choice(_GROUPS_T))],
            "RoleManagement": [mp("Role.DisplayName", None, random.choice(_ROLES_T))],
            "UserManagement": [mp("Included Updated Properties", None,
                                  random.choice(["AccountEnabled", "Department", "JobTitle", "UsageLocation"]))],
            "ApplicationManagement": [mp("AppRole.Value", None, "User")],
            "Policy": [mp("ConditionalAccessPolicy", None, "[conditions updated]")],
            "PolicyManagement": [mp("ConditionalAccessPolicy", None, "[conditions updated]")],
            }.get(category, [])


def _target_for(ttype, cfg, actor):
    if ttype == "User":
        return t_user(ac.pick_user(cfg))
    if ttype == "Group":
        return t_obj("Group", random.choice(_GROUPS_T), group_type="unifiedGroups")
    if ttype == "Role":
        return t_obj("Role", random.choice(_ROLES_T))
    if ttype in ("ServicePrincipal", "Application"):
        return t_obj(ttype, random.choice(_SAAS_APPS))
    if ttype == "Device":
        return t_obj("Device", f'{actor["username"].upper().replace(".", "")}-PC')
    if ttype == "Directory":
        return t_obj("Directory", ac.UPN_DOMAIN)
    if ttype == "Policy":
        return t_obj("Policy", random.choice(_CA_POLICIES))
    return t_obj("Other", "resource")


def _catalog_record(config, entry):
    """Build a faithful directoryAudit record for any catalogued activity."""
    activity, category, service, op_type, ttype = entry
    is_self = service == "Self-service Password Management" or activity.startswith(("User ", "user "))
    if service == "Account Provisioning":
        return _b_provisioning(config)
    if is_self:
        u = ac.pick_user(config)
        return audit(activity, category, service, op_type, by_user(u), [t_user(u)],
                     [_ua(u)], reason=activity)
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    tgt = _target_for(ttype, config, admin)
    tgt["modifiedProperties"] = _generic_mods(category, op_type)
    return audit(activity, category, service, op_type, by_user(admin), [tgt],
                 [_ua(admin)], reason=activity)


def generate_benign(config=None, context=None):
    # Off-hours: automated directory sync still runs; little human admin activity.
    if random.random() > ac.activity_weight():
        return [_b_provisioning(config)]
    # Business hours: mostly full-catalog coverage, with high-fidelity common activities mixed in.
    if random.random() < 0.25:
        return [random.choice(_B_HUMAN)(config)]
    return [_catalog_record(config, random.choice(cat.AUDIT_ACTIVITIES))]


# ── detection-relevant scenarios (named, on-demand) ─────────────────────────────────

def scenario_admin_role_add(config=None):
    """Grant of a privileged directory role -> 'Identity assigned an Azure AD Administrator Role'."""
    admin = ac.pick_by_role(config, ("IT Director",), ("IT",)); tgt = ac.pick_user(config)
    return [audit("Add member to role", "RoleManagement", "Core Directory", "Add", by_user(admin),
                  [t_obj("Role", "Global Administrator", [mp("Role.DisplayName", None, "Global Administrator"),
                   mp("Role.TemplateId", None, "62e90394-69f5-4237-9190-012177145e10")]), t_user(tgt)])]


def scenario_consent_risky_app(config=None):
    """Consent granting high-privilege Graph scopes -> 'Azure application consent'."""
    u = ac.pick_user(config)
    mods = [mp("ConsentContext.IsAdminConsent", None, "True"),
            mp("ConsentAction.Permissions", None, "Mail.Read Files.ReadWrite.All Directory.Read.All offline_access")]
    return [audit("Consent to application", "ApplicationManagement", "Core Directory", "Assign",
                  by_user(u), [t_obj("ServicePrincipal", "External Reporting Connector", mods)],
                  [{"key": "User-Agent", "value": "EvoSTS"}])]


def scenario_app_credential_added(config=None):
    """Certificate/secret added to an app -> 'Azure application credentials added'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [audit("Update application - Certificates and secrets management", "ApplicationManagement",
                  "Core Directory", "Update", by_user(admin),
                  [t_obj("Application", "Internal Automation App",
                   [mp("KeyDescription", None, "[KeyType=AsymmetricX509Cert, KeyUsage=Verify]")])])]


def scenario_security_info_disabled(config=None):
    """Strong auth disabled for a user -> 'MFA was disabled for an Azure identity'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [audit("Disable Strong Authentication", "UserManagement", "Core Directory", "Update",
                  by_user(admin), [t_user(tgt, [mp("StrongAuthenticationRequirement",
                  '[{"State":"Enforced"}]', "[]")])])]


SCENARIOS = {
    "admin_role_add": scenario_admin_role_add,
    "consent_risky_app": scenario_consent_risky_app,
    "app_credential_added": scenario_app_credential_added,
    "security_info_disabled": scenario_security_info_disabled,
}


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
