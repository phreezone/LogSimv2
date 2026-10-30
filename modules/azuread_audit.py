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
from modules import graph_activity as ga

NAME = "Azure AD Audit"
DESCRIPTION = "Simulates Microsoft Graph directoryAudits events for msft_azure_ad_audit_raw via the cribl_direct transport."
CONFIG_KEY = "azure_ad_audit_config"
SOURCE_IDENTIFIER = "0e076d5abe864bf78e8145ea9e0d749e"
INTEGRATION_IDENTIFIER = "logsim:azure_ad_audit"
DATASET = "msft_azure_ad_audit_raw"
EVENT_INTERVAL = 1.2   # default relative benign volume: directory-audit changes are lower volume than sign-ins

# Threat rate governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (see _GATE below).

ADMIN_ROLES = ("IT Administrator", "IT Director", "Systems Engineer")
HELPDESK_ROLES = ("Help Desk", "IT Administrator")
_ID_PREFIX = {"Core Directory": "Directory", "Self-service Password Management": "SSPR",
              "Authentication Methods": "Authentication Methods", "Account Provisioning": "Sync"}
# Directory-lifecycle operators: the only admins who create/delete users in the baseline. Other
# admins (IT Director, Systems Engineer) carry heavy admin activity but never delete accounts, so
# a deletion by one of them reads as 'deletion by a non-standard account'.
LIFECYCLE_ROLES = ("Help Desk", "IT Administrator")
_LIFECYCLE_ACTIVITIES = {"Add user", "Delete user", "Hard Delete user", "Restore user"}

# SaaS app catalogs live in azure_common (shared with the O365 directory feed). Benign events draw
# only from the baseline (recurring core + apps admitted by the wall-clock onboarding schedule);
# threat scenarios that need a never-seen app draw from ac.rare_app_name().
_SAAS_CORE = ac.SAAS_CORE
_SAAS_APPS = _SAAS_CORE   # back-compat alias (the recurring core)
_ADMIN_CONSENT_APPS = ac.ADMIN_CONSENT_APPS
_APP_VENDORS = ac.APP_VENDORS
_APP_PRODUCTS = ac.APP_PRODUCTS


def _saas_app():
    """Baseline app pick (benign): recurring core, plus apps already onboarded by the schedule."""
    return ac.baseline_saas_app()


_CA_POLICIES = [n for n, _ in ac.CA_POLICIES]


def _ts(offset_s=0.0):
    d = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=min(0.0, offset_s))
    return f"{d:%Y-%m-%dT%H:%M:%S}.{d.microsecond:06d}{random.randint(0, 9)}Z"


def _code():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=5))


def _enc(v):
    return None if v is None else json.dumps(v)


def mp(name, old, new):
    return {"displayName": name, "oldValue": _enc(old), "newValue": _enc(new)}


def by_user(u, ip=None):
    ip = ip or ac.egress(u)["ip"]
    # Real directoryAudits rows carry initiatedBy.user.userType = null (the "Member"/"Guest"
    # distinction lives on the target, not the initiator). Verified against live tenant rows.
    return {"user": {"id": ac.user_oid(u["username"]), "displayName": None,
                     "userPrincipalName": u["upn"], "ipAddress": ip, "userType": None,
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


def _add_user_mods(upn, name):
    # Real "Add user" rows carry array-form attribute values. Verified against live tenant rows.
    return [mp("AccountEnabled", [], [True]), mp("DisplayName", [], [name]),
            mp("UserPrincipalName", [], [upn])]


def audit(activity, category, service, op_type, initiator, targets,
          details=None, result="success", reason="", offset_s=0.0):
    corr = str(uuid.uuid4())
    pfx = _ID_PREFIX.get(service, "Directory")
    # Real rows set resultReason only when there is a genuine reason (e.g. "Successfully completed
    # reset."); for lifecycle ops (Delete/Update/Enable/Disable user) the field is null, not an echo
    # of the activity name. Verified against live tenant rows.
    return {"id": f"{pfx}_{corr}_{_code()}_{random.randint(1000000, 999999999)}",
            "category": category, "correlationId": corr, "result": result,
            "resultReason": reason or None, "activityDisplayName": activity,
            "activityDateTime": _ts(offset_s), "loggedByService": service, "operationType": op_type,
            "initiatedBy": initiator, "targetResources": targets, "additionalDetails": details or []}


def _ua(u):
    # Per-user, stable, varied (5 desktop + mobile profiles) and consistent with the user's
    # sign-in device browser — not one of two hardcoded strings.
    return {"key": "User-Agent", "value": ac.user_agent(u)}


def _app_details(u, app_id, sp=True, owner_org=None):
    """additionalDetails for ApplicationManagement rows: real rows carry AppId (and, for SP-targeted
    events, ServicePrincipalProvisioningType; Add service principal also AppOwnerOrganizationId)
    alongside the User-Agent. Verified against live tenant rows."""
    d = [_ua(u), {"key": "AppId", "value": app_id}]
    if owner_org:
        d.append({"key": "AppOwnerOrganizationId", "value": owner_org})
    if sp:
        d.append({"key": "ServicePrincipalProvisioningType", "value": "Other"})
    return d


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
    g = ac.group_name()
    add = random.random() < 0.6
    # Real rows: operationType Assign/Unassign, the Group.ObjectID/DisplayName mods ride on the User
    # target (member), and the Group object follows with empty mods. Verified against live tenant rows.
    gmods = [mp("Group.ObjectID", None, ac._stable_guid("Group:" + g)),
             mp("Group.DisplayName", None, g)]
    return audit("Add member to group" if add else "Remove member from group", "GroupManagement",
                 "Core Directory", "Assign" if add else "Unassign", by_user(admin),
                 [t_user(tgt, gmods), t_obj("Group", g, group_type="unknownFutureValue")], [_ua(admin)])


def _b_app_role_assign(cfg):
    u = ac.pick_user(cfg); app = _saas_app()
    return audit("Add app role assignment grant to user", "UserManagement", "Core Directory",
                 "Assign", by_user(u), [t_obj("ServicePrincipal", app,
                 [mp("AppRole.Value", None, "User")])], [{"key": "User-Agent", "value": "EvoSTS"}])


def _b_consent(cfg):
    u = ac.pick_user(cfg); app = _saas_app()
    mods = [mp("ConsentContext.IsAdminConsent", None, "False"),
            mp("ConsentAction.Permissions", None, "openid profile User.Read offline_access")]
    return audit("Consent to application", "ApplicationManagement", "Core Directory", "Assign",
                 by_user(u), [t_obj("ServicePrincipal", app, mods)],
                 [{"key": "User-Agent", "value": "EvoSTS"},
                  {"key": "AppId", "value": ac.app_id(app)},
                  {"key": "ServicePrincipalProvisioningType", "value": "Other"}])


def _b_admin_consent(cfg, app=None):
    # Tenant-wide admin consent by a privileged admin -> baselines XSIAM's
    # "First seen Azure admin consent to an application" first-seen detector.
    # The target app is pinned: a stable appId + SP objectId per app name, drawn from a
    # varied roster, so repeated consents reference a consistent application identity.
    admin = ac.pick_by_role(cfg, ADMIN_ROLES, ("IT",))
    app = app or ac.admin_consent_app()   # onboarded estate (grows on a wall-clock schedule)
    app_id = ac.app_id(app)
    mods = [mp("ConsentContext.IsAdminConsent", None, "True"),
            mp("ConsentContext.OnBehalfOfAll", None, "True"),
            mp("ConsentContext.Tags", None, "[]"),
            mp("TargetId.ServicePrincipalNames", None, app_id),
            mp("ServicePrincipal.AppId", None, app_id),
            mp("ConsentAction.Permissions", None,
               random.choice(["User.Read.All Group.Read.All openid profile offline_access",
                              "User.Read.All Directory.Read.All openid profile",
                              "User.Read openid profile email offline_access"]))]
    return audit("Consent to application", "ApplicationManagement", "Core Directory", "Assign",
                 by_user(admin), [t_obj("ServicePrincipal", app, mods)],
                 [{"key": "User-Agent", "value": "EvoSTS"},
                  {"key": "AppId", "value": app_id},
                  {"key": "ServicePrincipalProvisioningType", "value": "Other"}])


def _b_register_device(cfg):
    u = ac.pick_user(cfg); dev = f'{u["username"].upper().replace(".", "")}-PC'
    return audit("Register device", "Device", "Device Registration Service", "Add",
                 by_user(u), [t_obj("Device", dev, [mp("DeviceOSType", None, u.get("os_type", "Windows")),
                 mp("DeviceTrustType", None, "Azure AD joined")])])


def _b_token_timestamp(cfg):
    admin = ac.pick_by_role(cfg, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(cfg)
    # Real rows use array-form ISO-Z values and add the "Included Updated Properties" marker.
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return audit("Update StsRefreshTokenValidFrom Timestamp", "UserManagement", "Core Directory",
                 "Update", by_user(admin), [t_user(tgt, [
                     mp("StsRefreshTokensValidFrom", ["2026-01-01T00:00:00Z"], [now_iso]),
                     mp("Included Updated Properties", None, "StsRefreshTokensValidFrom")])])


def _b_provisioning(cfg):
    act = random.choice(["Import", "Execution", "Export"])
    return audit(act, "ProvisioningManagement", "Account Provisioning", "Read",
                 by_app("Azure AD Cloud Sync"), [t_obj("ServicePrincipal", "Directory",
                 [mp("dirSyncEnabled", None, "True"), mp("countryLetterCode", None, "US")])],
                 [{"key": "EventName", "value": "EntryImport"}, {"key": "JoiningProperty", "value": "MSFT"}],
                 reason="Retrieved TenantDetail 'MSFT' from Microsoft Entra ID")


def _b_enable_disable_account(cfg):
    # Routine lifecycle: an admin enables or disables a user account. Real rows carry array-form
    # AccountEnabled plus the Included Updated Properties marker. Verified against live tenant rows.
    admin = ac.pick_by_role(cfg, HELPDESK_ROLES, ("IT",)); tgt = ac.pick_user(cfg)
    enable = random.random() < 0.5
    old, new = ([False], [True]) if enable else ([True], [False])
    return audit("Enable account" if enable else "Disable account", "UserManagement",
                 "Core Directory", "Update", by_user(admin),
                 [t_user(tgt, [mp("AccountEnabled", old, new),
                               mp("Included Updated Properties", None, "AccountEnabled")])], [_ua(admin)])


def _b_update_sp(cfg):
    # Routine service-principal property update (ApplicationManagement). Real mods carry just the
    # Included Updated Properties marker; additionalDetails carry AppId + owner org + SP type.
    admin = ac.pick_by_role(cfg, ADMIN_ROLES, ("IT",)); app = _saas_app(); app_id = ac.app_id(app)
    return audit("Update service principal", "ApplicationManagement", "Core Directory", "Update",
                 by_user(admin), [t_obj("ServicePrincipal", app,
                 [mp("Included Updated Properties", None, "")])],
                 _app_details(admin, app_id, owner_org=ac.HOME_TENANT_ID))


def _b_update_password_profile(cfg):
    # Directory-side record of an admin password reset (distinct from the SSPR "Reset password (by
    # admin)" row): ForceChangePassword flips and Password is a null/null mod. Verified against real rows.
    admin = ac.pick_by_role(cfg, HELPDESK_ROLES, ("IT",)); tgt = ac.pick_user(cfg)
    return audit("Update PasswordProfile", "UserManagement", "Core Directory", "Update",
                 by_user(admin), [t_user(tgt, [mp("ForceChangePassword", "False", "True"),
                 mp("Password", None, None)])], [_ua(admin)])


def _b_delegated_grant(cfg):
    # A delegated OAuth2 permission grant to Microsoft Graph (admin, AllPrincipals). Verified shape.
    admin = ac.pick_by_role(cfg, ADMIN_ROLES, ("IT",))
    scope = random.choice(["User.Read", "User.Read openid profile", "offline_access User.Read",
                           "Directory.Read.All", "Group.Read.All User.Read"])
    tgt = t_obj("ServicePrincipal", "Microsoft Graph",
                [mp("DelegatedPermissionGrant.Scope", None, scope),
                 mp("DelegatedPermissionGrant.ConsentType", None, "AllPrincipals"),
                 mp("ServicePrincipal.ObjectID", None, ac._stable_guid("sp:" + _saas_app()))])
    tgt["id"] = ac._stable_guid("sp:Microsoft Graph")
    return audit("Add delegated permission grant", "ApplicationManagement", "Core Directory",
                 "Assign", by_user(admin), [tgt],
                 _app_details(admin, "00000003-0000-0000-c000-000000000000"))


# High-fidelity builders for the common activities (bespoke modifiedProperties/details).
_B_HUMAN = [_b_update_user, _b_secinfo_register, _b_group_member, _b_self_password,
            _b_app_role_assign, _b_consent, _b_register_device, _b_admin_reset, _b_token_timestamp,
            _b_enable_disable_account, _b_update_sp, _b_delegated_grant, _b_update_password_profile]

_ROLES_T = ["Helpdesk Administrator", "User Administrator", "Security Reader",
            "Exchange Administrator", "Global Reader", "Application Administrator"]


def _generic_mods(category, op_type):
    if op_type not in ("Add", "Update"):
        return []
    return {"GroupManagement": [mp("Group.DisplayName", None, ac.group_name())],
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
        return t_obj("Group", ac.group_name(), group_type="unifiedGroups")
    if ttype == "Role":
        return t_obj("Role", random.choice(_ROLES_T))
    if ttype in ("ServicePrincipal", "Application"):
        return t_obj(ttype, _saas_app())
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


# Authentic Entra directory-audit failure reasons (result="failure"), keyed by category. Real
# tenants carry a steady minority of failed admin operations: permission denials, misconfigurations,
# conflicting objects, and policy/consent blocks. Keeping these in the baseline makes the feed look
# real and gives detectors the success/failure distribution they expect.
_FAIL_GENERIC = [
    "Insufficient privileges to complete the operation.",
    "Authorization_RequestDenied",
    "Request_BadRequest",
    "A conflicting object with one or more of the specified property values is present in the directory.",
]
_FAIL_BY_CATEGORY = {
    "RoleManagement": ["Insufficient privileges to complete the operation.",
                       "The role assignment already exists."],
    "ApplicationManagement": ["Insufficient privileges to complete the operation.",
                              "Permissions were not granted; the application requires admin consent.",
                              "Request_BadRequest"],
    "UserManagement": ["Insufficient privileges to complete the operation.",
                       "The specified password does not comply with password complexity requirements.",
                       "A conflicting object with one or more of the specified property values is present in the directory."],
    "GroupManagement": ["Insufficient privileges to complete the operation.",
                        "A conflicting object with one or more of the specified property values is present in the directory.",
                        "Request_ResourceNotFound"],
    "Device": ["The device object was not found.",
               "Insufficient privileges to complete the operation."],
    "Policy": ["Insufficient privileges to complete the operation.", "Request_BadRequest"],
    "PolicyManagement": ["Insufficient privileges to complete the operation.", "Request_BadRequest"],
    "Self-service Password Management": ["The user's password could not be reset.",
                                         "Mobile phone verification failed."],
}
_AUDIT_FAIL_RATE = 0.10   # ~10% of human-driven benign admin ops fail (permission/config/policy)


def _maybe_fail(rec):
    """Flip a benign audit record to result='failure' with a category-appropriate reason."""
    if random.random() >= _AUDIT_FAIL_RATE:
        return rec
    category = rec.get("category", "")
    reason = random.choice(_FAIL_BY_CATEGORY.get(category, _FAIL_GENERIC))
    rec["result"] = "failure"
    rec["resultReason"] = reason
    return rec


def generate_benign(config=None, context=None):
    # Off-hours: automated directory sync still runs; little human admin activity. (Left as success;
    # automated provisioning sync rarely errors in the baseline.)
    if random.random() > ac.activity_weight():
        return [_b_provisioning(config)]
    # Tenant-wide admin consent is a legitimate but rare IT operation; keep it infrequent so it
    # behaves like the real "first seen" event (baselines, then only occasional recurrence).
    if random.random() < 0.015:
        return [_b_admin_consent(config)]
    # Business hours: mostly full-catalog coverage, with high-fidelity common activities mixed in.
    # A realistic minority of human-driven admin operations fail (permissions/config/policy).
    if random.random() < 0.25:
        return [_maybe_fail(random.choice(_B_HUMAN)(config))]
    return [_maybe_fail(_catalog_record(config, random.choice(cat.BENIGN_ACTIVITIES)))]


# ── detection-relevant scenarios (named, on-demand) ─────────────────────────────────

def scenario_admin_role_add(config=None):
    """Grant of a privileged directory role -> 'Identity assigned an Azure AD Administrator Role'."""
    admin = ac.pick_by_role(config, ("IT Director",), ("IT",)); tgt = ac.pick_user(config)
    # Real rows: operationType Assign; the Role.* mods ride on the User (member) target, the Role
    # object follows. Verified against live tenant rows.
    tmpl = "62e90394-69f5-4237-9190-012177145e10"   # Global Administrator template id
    role_mods = [mp("Role.ObjectID", None, tmpl), mp("Role.DisplayName", None, "Global Administrator"),
                 mp("Role.TemplateId", None, tmpl), mp("Role.WellKnownObjectName", None, "CompanyAdministrator")]
    return [audit("Add member to role", "RoleManagement", "Core Directory", "Assign", by_user(admin),
                  [t_user(tgt, role_mods), t_obj("Role", "Global Administrator")], [_ua(admin)])]


def scenario_consent_risky_app(config=None):
    """Admin consent granting high-privilege Graph scopes -> 'Azure application consent' (the
    detector is 'an ADMINISTRATIVE identity consented permissions to an application', so the
    initiator is an admin and ConsentContext.IsAdminConsent is True)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    app = ac.rare_app_name()   # a never-before-seen app -> genuine first-seen high-privilege consent
    mods = [mp("ConsentContext.IsAdminConsent", None, "True"),
            mp("ConsentContext.OnBehalfOfAll", None, "True"),
            mp("ConsentAction.Permissions", None, "Mail.Read Files.ReadWrite.All Directory.Read.All offline_access")]
    return [audit("Consent to application", "ApplicationManagement", "Core Directory", "Assign",
                  by_user(admin), [t_obj("ServicePrincipal", app, mods)],
                  [{"key": "User-Agent", "value": "EvoSTS"},
                   {"key": "AppId", "value": ac.app_id(app)},
                   {"key": "ServicePrincipalProvisioningType", "value": "Other"}])]


# The real Entra portal writes this activity with an EN DASH and a trailing space, not a hyphen;
# matching it exactly keeps any activityDisplayName string match aligned. Verified against live rows.
_CERT_MGMT_ACTIVITY = "Update application – Certificates and secrets management "


def scenario_app_credential_added(config=None):
    """Certificate/secret added to an app -> 'Azure application credentials added'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    app = "Internal Automation App"
    return [audit(_CERT_MGMT_ACTIVITY, "ApplicationManagement",
                  "Core Directory", "Update", by_user(admin),
                  [t_obj("Application", app,
                   [mp("KeyDescription", None, "[KeyType=AsymmetricX509Cert, KeyUsage=Verify]")])],
                  [_ua(admin), {"key": "AppId", "value": ac.app_id(app)}])]


def scenario_security_info_disabled(config=None):
    """Strong auth disabled for a user -> 'MFA was disabled for an Azure identity'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [audit("Disable Strong Authentication", "UserManagement", "Core Directory", "Update",
                  by_user(admin), [t_user(tgt, [mp("StrongAuthenticationRequirement",
                  '[{"State":"Enforced"}]', "[]")])])]


# A rogue external Entra tenant an attacker attaches via cross-tenant access + cross-tenant sync —
# the cloud equivalent of standing up a rogue forest and establishing a trust. Each fire uses a
# fresh, never-seen external tenant (ac.rare_tenant(), unbounded); multi-step sequences generate one
# rogue tenant and thread it through every step via the `rogue=` parameter so the chain stays
# coherent. A module-level default is kept only as a last-resort fallback.
def _rogue():
    return ac.rare_tenant()


def scenario_cross_tenant_trust_abuse(config=None, rogue=None):
    """Attacker trusts a rogue external tenant and opens inbound B2B + cross-tenant sync
    (the cloud 'rogue forest trust'): CrossTenantAccessSettings + CrossTenantIdentitySyncSettings
    changes granting inbound collaboration/direct-connect, MFA trust, auto-redemption and inbound
    user provisioning from the attacker tenant -> anomalous directory/trust change + privilege path."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    rogue = rogue or _rogue(); dom, tid = rogue["domain"], rogue["tenant_id"]
    # Real cross-tenant access rows target a Policy object ("CrossTenantAccessPolicy for <ownTenant>"),
    # not the partner domain: the Add carries only the partner tenantId, and the inbound B2B / trust /
    # auto-consent changes arrive on the subsequent Update. Verified against live tenant rows.
    def _xtap(mods):
        t = t_obj("Policy", f"CrossTenantAccessPolicy for {ac.HOME_TENANT_ID}", mods)
        t["id"] = ac._stable_guid("xtap:" + dom)
        return t
    return [
        audit("Add a partner to cross-tenant access setting", "CrossTenantAccessSettings",
              "Core Directory", "Add", by_user(admin),
              [_xtap([mp("tenantId", None, tid)])], [_ua(admin)]),
        audit("Update a partner cross-tenant access setting", "CrossTenantAccessSettings",
              "Core Directory", "Update", by_user(admin),
              [_xtap([
                  mp("b2bCollaborationInbound.usersAndGroups", '{"accessType":"blocked"}',
                     '{"accessType":"allowed"}'),
                  mp("b2bDirectConnectInbound.usersAndGroups", '{"accessType":"blocked"}',
                     '{"accessType":"allowed"}'),
                  mp("inboundTrust.isMfaAccepted", "false", "true"),
                  mp("inboundTrust.isCompliantDeviceAccepted", "false", "true"),
                  mp("automaticUserConsentSettings.inboundAllowed", "false", "true")])],
              [_ua(admin)]),
        audit("Create a partner cross-tenant identity sync setting", "CrossTenantIdentitySyncSettings",
              "Core Directory", "Add", by_user(admin),
              [t_obj("Other", dom,
                     [mp("tenantId", None, tid),
                      mp("userSyncInbound.isSyncAllowed", "false", "true")])],
              [_ua(admin)])]


def scenario_cross_tenant_sync_outbound(config=None, rogue=None):
    """Outbound cross-tenant sync: OUR users are provisioned OUT to the rogue tenant (user/data
    exfiltration via the identity fabric, T1537)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    rogue = rogue or _rogue(); dom, tid = rogue["domain"], rogue["tenant_id"]
    return [
        audit("Update a partner cross-tenant access setting", "CrossTenantAccessSettings",
              "Core Directory", "Update", by_user(admin),
              [t_obj("Other", dom,
                     [mp("tenantId", None, tid),
                      mp("b2bCollaborationOutbound.usersAndGroups",
                         '{"accessType":"blocked"}', '{"accessType":"allowed"}')])], [_ua(admin)]),
        audit("Create a partner cross-tenant identity sync setting", "CrossTenantIdentitySyncSettings",
              "Core Directory", "Add", by_user(admin),
              [t_obj("Other", dom,
                     [mp("tenantId", None, tid),
                      mp("userSyncOutbound.isSyncAllowed", "false", "true")])], [_ua(admin)])]


def scenario_delegated_admin_partner_abuse(config=None, rogue=None):
    """External delegated-admin (GDAP/DAP) partner promoted with Global Admin over the tenant —
    partner-tenant takeover (T1098 Account Manipulation / abuse of delegated administration)."""
    admin = ac.pick_by_role(config, ("IT Director",), ("IT",))
    partner = (rogue or _rogue())["domain"]
    pid = ac._stable_guid("gdap:" + partner)
    return [
        audit("Add partner to company", "DirectoryManagement", "Core Directory", "Add",
              by_user(admin), [t_obj("Directory", partner, [mp("PartnerTenantId", None, pid)])], [_ua(admin)]),
        audit("Promote company to partner", "DirectoryManagement", "Core Directory", "Add",
              by_user(admin), [t_obj("Directory", partner,
                     [mp("DelegatedAdminRelationship", None, "Global Administrator"),
                      mp("AccessAssignment", None, "Microsoft Entra Global Administrator")])], [_ua(admin)])]


def scenario_multitenant_org_join(config=None, rogue=None):
    """Tenant joined into an attacker-run multi-tenant org with identity sync — cloud cross-tenant
    fabric persistence (the cloud analog of joining a rogue forest)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    rogue = rogue or _rogue()
    mto = rogue["domain"].split(".")[0].replace("-", " ").title() + " MTO"
    return [
        audit("Create a MultiTenantOrg", "MultiTenantOrg", "Core Directory", "Add", by_user(admin),
              [t_obj("Other", mto, [mp("tenantId", None, rogue["tenant_id"]),
                                    mp("role", None, "owner"), mp("state", None, "active")])], [_ua(admin)]),
        audit("Update a multi tenant org identity sync policy template",
              "MultiTenantOrgIdentitySyncPolicyUpdate", "Core Directory", "Update", by_user(admin),
              [t_obj("Other", mto, [mp("templateApplicationLevel", None, "MemberAndOwnerTenants"),
                                    mp("userSyncInbound.isSyncAllowed", "false", "true")])], [_ua(admin)])]


def scenario_cross_tenant_default_weakened(config=None):
    """Company-DEFAULT cross-tenant access opened to ALL external tenants inbound (not one partner)
    with MFA trust + auto-redemption — a broad trust downgrade."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    return [audit("Update the company default cross-tenant access setting", "CrossTenantAccessSettings",
                  "Core Directory", "Update", by_user(admin),
                  [t_obj("Other", "Default Settings",
                         [mp("b2bCollaborationInbound.usersAndGroups",
                             '{"accessType":"blocked"}', '{"accessType":"allowed"}'),
                          mp("inboundTrust.isMfaAccepted", "false", "true"),
                          mp("automaticUserConsentSettings.inboundAllowed", "false", "true")])], [_ua(admin)])]


def scenario_federated_domain_backdoor(config=None, dom=None):
    """A new domain is added and federated to an attacker IdP — persistent Golden SAML backdoor
    (T1484.002 Trust Modification). The IssuerUri is the Mandiant-known-bad 'http://any.sts/...'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    dom = dom or ac.rare_domain(kind="federation")   # never-seen backdoor domain (unbounded)
    return [
        audit("Add unverified domain", "DirectoryManagement", "Core Directory", "Add",
              by_user(admin), [t_obj("Directory", dom)], [_ua(admin)]),
        audit("Set federation settings on domain", "DirectoryManagement", "Core Directory", "Update",
              by_user(admin), [t_obj("Directory", dom,
                     [mp("IssuerUri", None, "http://any.sts/adfs/services/trust"),
                      mp("PassiveSignInUri", None, f"https://{ac.rare_domain(kind='federation')}/adfs/ls/"),
                      mp("SigningCertificate", None, "<attacker-cert-thumbprint>")])], [_ua(admin)])]


def scenario_failed_federation_change(config=None, dom=None):
    """A FAILED attempt to modify domain federation settings (permission denied) -> the 'failed'
    half of 'Azure domain federation settings modification (successful/failed)'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    dom = dom or ac.rare_domain(kind="federation")
    return [audit("Set federation settings on domain", "DirectoryManagement", "Core Directory",
                  "Update", by_user(admin),
                  [t_obj("Directory", dom,
                         [mp("IssuerUri", None, "http://any.sts/adfs/services/trust")])],
                  [_ua(admin)], result="failure",
                  reason="Insufficient privileges to complete the operation.")]


def scenario_app_privilege_escalation(config=None):
    """An APPLICATION (service principal) assigns an Azure administrator role to a user ->
    'Azure Privilege Escalation Using an Application'. Per the detector the APP is the initiator
    (initiatedBy.app), the target is a user, and the role is a privileged directory role."""
    sp_name = "Internal Automation App"
    tgt = ac.pick_user(config)
    return [audit("Add member to role", "RoleManagement", "Core Directory", "Add",
                  by_app(sp_name, ac.app_id(sp_name)),
                  [t_obj("Role", "Global Administrator",
                         [mp("Role.DisplayName", None, "Global Administrator"),
                          mp("Role.TemplateId", None, "62e90394-69f5-4237-9190-012177145e10")]),
                   t_user(tgt)])]


def scenario_ca_policy_removed(config=None):
    """A Conditional Access policy is deleted -> 'Conditional Access policy removed' (guardrail
    removal)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    pol = random.choice(_CA_POLICIES)
    return [audit("Delete conditional access policy", "Policy", "Conditional Access", "Delete",
                  by_user(admin), [t_obj("Policy", pol, [mp("ConditionalAccessPolicy", pol, None)])],
                  [_ua(admin)])]


def scenario_ca_operation_unusual(config=None):
    """A Conditional Access policy is weakened by an identity that doesn't normally touch CA ->
    'Unusual Conditional Access operation for an identity'."""
    actor = ac.pick_nonstandard_actor(config)   # not a typical CA admin
    pol = random.choice(_CA_POLICIES)
    return [audit("Update conditional access policy", "Policy", "Conditional Access", "Update",
                  by_user(actor), [t_obj("Policy", pol,
                  [mp("ConditionalAccessPolicy", "[state=enabled]", "[state=disabled]")])], [_ua(actor)])]


# Real admin security-info rows (Authentication Methods service) carry an app component in
# initiatedBy (the Entra portal auth-methods blade, ADIbizaUX) and populate the initiator's
# displayName/userType; additionalDetails is InitiatedFrom, not User-Agent. Verified against live rows.
_AUTHMETHODS_APP = ("ADIbizaUX", "74658136-14ec-4630-ad9b-26e160ff0fc6")


def _admin_secinfo(admin, tgt, method, op, mods):
    init = by_user(admin)
    init["user"]["displayName"] = admin.get("display_name")
    init["user"]["userType"] = "Member"
    init["app"] = {"appId": _AUTHMETHODS_APP[1], "displayName": _AUTHMETHODS_APP[0],
                   "servicePrincipalId": None, "servicePrincipalName": None}
    activity = "Admin registered security info" if op == "Create" else "Admin deleted security info"
    verb = "registered" if op == "Create" else "deleted"
    return audit(activity, "UserManagement", "Authentication Methods", op, init,
                 [t_user(tgt, mods)],
                 [{"key": "InitiatedFrom", "value": f"{_AUTHMETHODS_APP[0]} ({_AUTHMETHODS_APP[1]})"}],
                 reason=f"Admin {verb} {method} authentication method for user")


def scenario_tap_registered(config=None):
    """A Temporary Access Pass is registered on an account (MFA-bypass persistence) -> 'Azure
    Temporary Access Pass (TAP) registered to an account'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [_admin_secinfo(admin, tgt, "Temporary Access Pass", "Create",
                           [mp("StrongAuthenticationMethod", None, "TemporaryAccessPass"),
                            mp("SecurityInfo.Action", None, "Register")])]


def scenario_bitlocker_key_retrieval(config=None):
    """A user reads a BitLocker recovery key -> 'BitLocker key retrieval'."""
    u = ac.pick_user(config)
    return [audit("Read BitLocker key", "KeyManagement", "Core Directory", "Read", by_user(u),
                  [t_obj("Device", f'{u["username"].upper().replace(".", "")}-PC',
                   [mp("KeyId", None, ac._stable_guid("blk:" + u["username"]))])], [_ua(u)])]


def scenario_owner_added_to_application(config=None):
    """An owner is added to an Azure application (app takeover / persistence) -> 'Owner added to
    Azure application'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    app = "Internal Automation App"; app_oid = ac._stable_guid("App:" + app); app_id = ac.app_id(app)
    owner_mods = [mp("Application.ObjectID", None, app_oid),
                  mp("Application.DisplayName", None, app),
                  mp("Application.AppId", None, app_id)]
    return [audit("Add owner to application", "ApplicationManagement", "Core Directory", "Assign",
                  by_user(admin), [t_user(tgt, owner_mods), t_obj("Application", app)],
                  [_ua(admin)])]


def scenario_sp_app_role_assigned(config=None):
    """A high-privilege app role (Graph app permission) is granted to a service principal ->
    'Azure service principal assigned app role'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    sp = "External Reporting Connector"
    return [audit("Add app role assignment to service principal", "ApplicationManagement",
                  "Core Directory", "Assign", by_user(admin),
                  [t_obj("ServicePrincipal", sp,
                   [mp("AppRole.Id", None, "e2a3a72e-5f79-4c64-b1b1-878b674786c9"),
                    mp("AppRole.Value", None, "Mail.ReadWrite.All"),
                    mp("AppRole.DisplayName", None, "Read and write mail in all mailboxes")])],
                  _app_details(admin, ac.app_id(sp)))]


def scenario_application_uri_modification(config=None):
    """An application's reply/redirect URI is modified to an attacker-controlled URL (token
    redirect hijack) -> 'Azure application URI modification'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    app = "Internal Automation App"
    return [audit("Update application", "ApplicationManagement", "Core Directory", "Update",
                  by_user(admin), [t_obj("Application", app,
                  [mp("AppAddress.ReplyUrl", "https://app.examplecorp.com/auth",
                      "https://attacker-collect.example/oauth/callback")])],
                  [_ua(admin), {"key": "AppId", "value": ac.app_id(app)}])]


def scenario_pim_elevation_request(config=None):
    """A PIM activation elevates an identity into a privileged role -> 'Azure AD PIM elevation
    request'."""
    u = ac.pick_user(config)
    return [audit("Add member to role completed (PIM activation)", "RoleManagement", "Core Directory",
                  "Add", by_user(u), [t_obj("Role", "Global Administrator",
                  [mp("Role.DisplayName", None, "Global Administrator")]), t_user(u)], [_ua(u)])]


def scenario_pim_alert_disabled(config=None):
    """A PIM security alert is disabled -> 'Azure AD PIM alert disabled' (defense evasion)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    return [audit("Disable PIM alert", "RoleManagement", "PIM", "Update", by_user(admin),
                  [t_obj("Other", "Roles are being assigned outside of Privileged Identity Management",
                   [mp("AlertEnabled", "True", "False")])], [_ua(admin)])]


def scenario_device_registration_policy_mod(config=None):
    """The device registration policy is weakened (e.g. MFA no longer required to join) -> 'Device
    Registration Policy modification'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [audit("Set device registration policy", "Policy", "Core Directory", "Update",
                  by_user(admin), [t_obj("Policy", "Device Registration Policy",
                  [mp("RequireMfaSetting", "True", "False"),
                   mp("AzureADJoinPolicy", "Selected", "All")])], [_ua(admin)])]


def scenario_unusual_guest_invitation(config=None):
    """An external guest is invited by an identity that doesn't normally invite guests ->
    'Successful unusual guest user invitation'."""
    inviter = ac.pick_nonstandard_actor(config)
    ext = ac.rare_ext_email()                        # never-seen external invitee (unbounded)
    guest = f"{ext.split('@')[0]}#EXT#@examplecorp.com"
    return [audit("Invite external user", "UserManagement", "Core Directory", "Add", by_user(inviter),
                  [t_user({"username": "guest", "upn": guest, "display_name": "external guest"},
                   [mp("Invitation.InvitedUserEmailAddress", None, ext)])], [_ua(inviter)])]


def scenario_account_unlock_password_reset(config=None):
    """An admin resets/unlocks a user's password (potential account takeover prep) -> 'Azure AD
    account unlock/password reset attempt'."""
    admin = ac.pick_by_role(config, HELPDESK_ROLES, ("IT",)); tgt = ac.pick_user(config)
    act = random.choice(["Reset user password", "Unlock user account", "Change user password"])
    return [audit(act, "UserManagement", "Self-service Password Management", "Update",
                  by_user(admin), [t_user(tgt)], [_ua(admin)], reason=act)]


def scenario_first_powershell_op(config=None):
    """A user performs an Azure AD directory operation via the Azure AD PowerShell module for the
    first time -> 'First Azure AD PowerShell operation for a user' (Informational baseline)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [audit("Update user", "UserManagement", "Core Directory", "Update", by_user(admin),
                  [t_user(tgt, [mp("Included Updated Properties", None, "Department")])],
                  [{"key": "User-Agent", "value": "Microsoft Azure Active Directory PowerShell"}])]


def scenario_owner_removed_from_application(config=None):
    """An owner is removed from an application / service principal (seize control, hide tracks) ->
    'Removal of an Azure Owner from an Application or Service Principal'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [audit("Remove owner from application", "ApplicationManagement", "Core Directory", "Remove",
                  by_user(admin), [t_obj("Application", "Internal Automation App"), t_user(tgt)], [_ua(admin)])]


def scenario_mfa_fraud_reported(config=None):
    """A user reported an MFA prompt as fraud -> 'Suspicious MFA request reported by user in Entra
    ID' (a sign of MFA-fatigue / push-bombing against the account)."""
    u = ac.pick_user(config)
    return [audit("Fraud reported - user is blocked for MFA", "UserManagement",
                  "Multi-Factor Authentication", "Update", by_user(u),
                  [t_user(u, [mp("FraudReported", None, "True")])], [_ua(u)])]


def scenario_onprem_sync_collision(config=None):
    """The directory-sync service binds an on-prem object to an EXISTING cloud account for the first
    time (soft-match hijack) -> 'First-time directory sync of an on-premises domain user to an
    existing cloud account'."""
    tgt = ac.pick_user(config)
    return [audit("Update user", "UserManagement", "Core Directory", "Update",
                  by_app("Microsoft Azure AD Connect"),
                  [t_user(tgt, [mp("SourceAnchor", None, ac._stable_guid("anchor:" + tgt["username"])),
                                mp("DirSyncEnabled", "False", "True"),
                                mp("Included Updated Properties", None, "SourceAnchor, DirSyncEnabled")])])]


def scenario_user_account_created(config=None):
    """A new directory user is created by an identity that does not normally provision accounts ->
    'Azure account creation by a non-standard account' (rogue account persistence)."""
    actor = ac.pick_nonstandard_actor(config)
    newu = f"svc_{random.randint(1000,9999)}"
    upn = f"{newu}@examplecorp.com"
    return [audit("Add user", "UserManagement", "Core Directory", "Add", by_user(actor),
                  [t_user({"username": newu, "upn": upn, "display_name": "Service Account"},
                          _add_user_mods(upn, "Service Account"))], [_ua(actor)])]


def scenario_user_account_deleted(config=None):
    """A directory user is deleted by an identity that does not normally delete accounts ->
    'Azure account deletion by a non-standard account' (destruction / covering tracks)."""
    actor = ac.pick_nonstandard_actor(config); tgt = ac.pick_user(config)
    return [audit("Delete user", "UserManagement", "Core Directory", "Delete", by_user(actor),
                  [t_user(tgt, [mp("Is Hard Deleted", None, "False")])], [_ua(actor)])]


def scenario_short_lived_account(config=None):
    """An account is created and then deleted within a short window (burner account used for an
    operation, then cleaned up) -> 'Short-lived Azure AD user account'."""
    actor = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    burner = f"tmp_{random.randint(1000,9999)}"
    u = {"username": burner, "upn": f"{burner}@examplecorp.com", "display_name": "Temp Account"}
    add = audit("Add user", "UserManagement", "Core Directory", "Add", by_user(actor),
                [t_user(u, _add_user_mods(u["upn"], u["display_name"]))], [_ua(actor)])
    rem = audit("Delete user", "UserManagement", "Core Directory", "Delete", by_user(actor),
                [t_user(u, [mp("Is Hard Deleted", None, "False")])], [_ua(actor)])
    return [add, rem]


def scenario_multiple_admin_role_removals(config=None):
    """An identity removes several members from privileged roles in a short window (mass privilege
    teardown / sabotage) -> 'Multiple Azure AD admin role removals'."""
    actor = ac.pick_by_role(config, ("IT Director",), ("IT",))
    roles = ["Global Administrator", "Privileged Role Administrator", "Security Administrator",
             "Exchange Administrator", "User Administrator"]
    out = []
    for r in random.sample(roles, 4):
        tgt = ac.pick_user(config)
        out.append(audit("Remove member from role", "RoleManagement", "Core Directory", "Remove",
                         by_user(actor), [t_obj("Role", r, [mp("Role.DisplayName", None, r)]),
                                          t_user(tgt)], [_ua(actor)]))
    return out


def scenario_pim_member_removal(config=None):
    """A privileged member is removed from a role via PIM (removing a rival admin / hiding an
    assignment) -> 'PIM privilege member removal'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security")); tgt = ac.pick_user(config)
    return [audit("Remove member from role (PIM activation)", "RoleManagement", "PIM", "Remove",
                  by_user(admin), [t_obj("Role", "Privileged Role Administrator",
                   [mp("Role.DisplayName", None, "Privileged Role Administrator")]), t_user(tgt)],
                  [_ua(admin)])]


def scenario_pim_role_settings_change(config=None):
    """PIM role settings are weakened (e.g. MFA/approval/justification no longer required for
    activation) -> 'Azure AD PIM role settings change'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    return [audit("Update role setting in PIM", "RoleManagement", "PIM", "Update", by_user(admin),
                  [t_obj("Role", "Global Administrator",
                   [mp("Setting.MfaOnActivation", "True", "False"),
                    mp("Setting.RequireApproval", "True", "False"),
                    mp("Setting.MaximumActivationDuration", "PT1H", "PT12H")])], [_ua(admin)])]


def scenario_sp_created(config=None):
    """A new service principal / application is registered (persistence via an app identity) ->
    'Azure Service principal/Application creation'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    app = ac.rare_app_name()     # a brand-new application identity (unbounded)
    app_id = ac.app_id(app)
    # Real "Add service principal" mods are array-form (AccountEnabled [true], AppPrincipalId
    # ["<appId>"], DisplayName ["<name>"]); additionalDetails carry AppId + AppOwnerOrganizationId
    # (our tenant) + ServicePrincipalProvisioningType. Verified against live tenant rows.
    return [audit("Add service principal", "ApplicationManagement", "Core Directory", "Add",
                  by_user(admin), [t_obj("ServicePrincipal", app,
                   [mp("AccountEnabled", [], [True]),
                    mp("AppPrincipalId", [], [app_id]),
                    mp("DisplayName", [], [app])])],
                  _app_details(admin, app_id, owner_org=ac.HOME_TENANT_ID))]


def scenario_sp_removed(config=None):
    """A service principal / application is deleted (removing an app identity to cover tracks) ->
    'Azure application removed'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    app = _saas_app()
    return [audit("Delete service principal", "ApplicationManagement", "Core Directory", "Delete",
                  by_user(admin), [t_obj("ServicePrincipal", app)], [_ua(admin)])]


def scenario_auth_method_added(config=None):
    """A new authentication method (phone/authenticator) is registered onto a privileged account by
    an admin -> 'Authentication method added to an Azure account' (MFA method backdoor on a
    high-value identity)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    tgt = ac.pick_by_role(config, ("IT Director",), ("IT",))
    method = random.choice(["Phone", "Microsoft Authenticator", "Email", "FIDO2 Security Key"])
    return [_admin_secinfo(admin, tgt, method, "Create",
                           [mp("AuthenticationMethod", None, method)])]


def scenario_auth_method_removed(config=None):
    """An admin removes an authentication (MFA) method from an account -> MFA teardown / defense
    evasion ('Authentication method removed from an Azure account'). Real 'Admin deleted security
    info' rows carry empty target modifiedProperties."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    tgt = ac.pick_by_role(config, ("IT Director",), ("IT",))
    method = random.choice(["Phone", "Microsoft Authenticator", "Email", "FIDO2 Security Key"])
    return [_admin_secinfo(admin, tgt, method, "Delete", [])]


def scenario_unverified_domain_added(config=None):
    """An unverified custom domain is added to the tenant (precursor to federation backdoor /
    domain takeover) -> 'Unverified domain added to Azure AD'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    dom = ac.rare_domain(kind="generic")             # never-seen custom domain (unbounded)
    return [audit("Add unverified domain", "DirectoryManagement", "Core Directory", "Add",
                  by_user(admin), [t_obj("Domain", dom,
                   [mp("Capability", None, "Email"), mp("IsVerified", None, "False")])], [_ua(admin)])]


def scenario_group_created_deleted(config=None):
    """A security group is created and, minutes later, deleted by an identity that does not normally
    manage groups -> 'Azure group creation/deletion' (persistence via a throwaway group)."""
    actor = ac.pick_nonstandard_actor(config)
    g = f"SG-{random.choice(['Ops','Data','Finance','Admins'])}-{random.randint(100, 999)}"
    add = audit("Add group", "GroupManagement", "Core Directory", "Add", by_user(actor),
                [t_obj("Group", g, [mp("DisplayName", None, g), mp("SecurityEnabled", None, "True")])],
                [_ua(actor)])
    rem = audit("Delete group", "GroupManagement", "Core Directory", "Delete", by_user(actor),
                [t_obj("Group", g)], [_ua(actor)])
    return [add, rem]


SCENARIOS = {
    "admin_role_add": scenario_admin_role_add,
    "consent_risky_app": scenario_consent_risky_app,
    "mfa_fraud_reported": scenario_mfa_fraud_reported,
    "owner_removed_from_application": scenario_owner_removed_from_application,
    "first_powershell_op": scenario_first_powershell_op,
    "onprem_sync_collision": scenario_onprem_sync_collision,
    "ca_policy_removed": scenario_ca_policy_removed,
    "ca_operation_unusual": scenario_ca_operation_unusual,
    "tap_registered": scenario_tap_registered,
    "bitlocker_key_retrieval": scenario_bitlocker_key_retrieval,
    "owner_added_to_application": scenario_owner_added_to_application,
    "sp_app_role_assigned": scenario_sp_app_role_assigned,
    "application_uri_modification": scenario_application_uri_modification,
    "pim_elevation_request": scenario_pim_elevation_request,
    "pim_alert_disabled": scenario_pim_alert_disabled,
    "device_registration_policy_mod": scenario_device_registration_policy_mod,
    "unusual_guest_invitation": scenario_unusual_guest_invitation,
    "account_unlock_password_reset": scenario_account_unlock_password_reset,
    "failed_federation_change": scenario_failed_federation_change,
    "app_privilege_escalation": scenario_app_privilege_escalation,
    "app_credential_added": scenario_app_credential_added,
    "security_info_disabled": scenario_security_info_disabled,
    "cross_tenant_trust_abuse": scenario_cross_tenant_trust_abuse,
    "cross_tenant_sync_outbound": scenario_cross_tenant_sync_outbound,
    "delegated_admin_partner_abuse": scenario_delegated_admin_partner_abuse,
    "multitenant_org_join": scenario_multitenant_org_join,
    "cross_tenant_default_weakened": scenario_cross_tenant_default_weakened,
    "federated_domain_backdoor": scenario_federated_domain_backdoor,
    "user_account_created": scenario_user_account_created,
    "user_account_deleted": scenario_user_account_deleted,
    "short_lived_account": scenario_short_lived_account,
    "multiple_admin_role_removals": scenario_multiple_admin_role_removals,
    "pim_member_removal": scenario_pim_member_removal,
    "pim_role_settings_change": scenario_pim_role_settings_change,
    "sp_created": scenario_sp_created,
    "sp_removed": scenario_sp_removed,
    "auth_method_added": scenario_auth_method_added,
    "unverified_domain_added": scenario_unverified_domain_added,
    "group_created_deleted": scenario_group_created_deleted,
    "wip_cloud_group_change": scenario_group_created_deleted,
}

# Additional Azure Audit Log targets use the same Graph directory-audit records and Event Hub
# copies as their original generator. They are explicitly WIP until the Cortex alert is observed.
SCENARIOS.update({
    "wip_azure_group_create_delete": scenario_group_created_deleted,
    "wip_app_credential_added": scenario_app_credential_added,
    "wip_app_owner_added": scenario_owner_added_to_application,
    "wip_app_owner_removed": scenario_owner_removed_from_application,
    "wip_service_principal_created": scenario_sp_created,
    "wip_service_principal_removed": scenario_sp_removed,
    "wip_auth_method_added": scenario_auth_method_added,
    "wip_auth_method_removed": scenario_auth_method_removed,
    "wip_conditional_access_change": scenario_ca_operation_unusual,
    "wip_user_created": scenario_user_account_created,
    "wip_user_deleted": scenario_user_account_deleted,
    "wip_user_password_reset": scenario_account_unlock_password_reset,
    "wip_external_guest_invitation": scenario_unusual_guest_invitation,
    "wip_pim_member_removal": scenario_pim_member_removal,
    "wip_application_removed": scenario_sp_removed,
    "wip_service_principal_application_created": scenario_sp_created,
    "wip_azure_domain_verification": scenario_unverified_domain_added,
})

# On-demand threats (threat_catalog): only scenarios whose analytic has been SEEN firing
# in the tenant on this feed's synthetic data -- alerts attributed to examplecorp
# identities on the exact operation the scenario emits (alerts dataset, 2026-09-30 ..
# 2026-10-21; admin_role_add and federated_domain_backdoor also confirmed fire->alert by
# _local_validation/threat_harness.py on 2026-10-12). Every other scenario stays
# background-only until an alert is observed for it. account_unlock_password_reset is
# held back: one alert in three weeks, not attributable to the scenario over the
# catalog's own password-reset records.
ANALYTIC_ALERTS = {
    "admin_role_add":           "Suspicious Azure AD Administrator Role assignment",
    "ca_policy_removed":        "Conditional Access policy removed",
    "pim_alert_disabled":       "Azure AD PIM alert disabled",
    "pim_role_settings_change": "Azure AD PIM role settings change",
    "unverified_domain_added":  "Rare unverified domain addition to Azure AD",
    "federated_domain_backdoor": "A successful Azure domain federation settings modification",
    "failed_federation_change": "Azure domain federation settings modification attempt",
    "wip_cloud_group_change": "A cloud identity created or modified a security group",
    "wip_azure_group_create_delete": "Azure group creation/deletion",
    "wip_app_credential_added": "Credentials were added to Azure application",
    "wip_app_owner_added": "Owner was added to Azure application",
    "wip_app_owner_removed": "Removal of an Azure Owner from an Application or Service Principal",
    "wip_service_principal_created": "A Service Principal was created in Azure",
    "wip_service_principal_removed": "A Service Principal was removed from Azure",
    "wip_auth_method_added": "Authentication method was added to Azure account",
    "wip_auth_method_removed": "Authentication method was removed from Azure account",
    "wip_conditional_access_change": "Azure conditional access policy creation or modification",
    "wip_user_created": "Azure user creation/deletion",
    "wip_user_deleted": "Azure user creation/deletion",
    "wip_user_password_reset": "Azure user password reset",
    "wip_external_guest_invitation": "External user invitation to Azure tenant",
    "wip_pim_member_removal": "PIM privilege member removal",
    "wip_application_removed": "Azure application removed",
    "wip_service_principal_application_created": "Azure Service principal/Application creation",
    "wip_azure_domain_verification": "A new Azure email domain verification was requested",
}


# ── Graph activity companions ────────────────────────────────────────────────────────
# The "Microsoft Graph Activity Logs" detectors read the API request behind a directory change,
# not the audit record, so each scenario below also emits the Graph call its initiator made
# (MicrosoftGraphActivityLogs, routed to msft_azure_raw). Built from the audit record itself:
# same admin, IP and target ids, two seconds before the change is recorded. Benign audit
# traffic carries no companion, so routine directory work never raises these detectors.
_PWD_METHOD = "28c10230-6103-485e-b985-444c60001490"   # the well-known password authentication method id
# activityDisplayName -> (method, uri template, status, wids)
_GRAPH_CALLS = {
    "Add user": ("POST", "/v1.0/users", 201, ga.WID_USER_ADMIN),
    "Delete user": ("DELETE", "/v1.0/users/{t}", 204, ga.WID_USER_ADMIN),
    "Reset user password": ("POST", "/v1.0/users/{t}/authentication/methods/" + _PWD_METHOD + "/resetPassword", 202, ga.WID_USER_ADMIN),
    "Unlock user account": ("PATCH", "/v1.0/users/{t}", 204, ga.WID_USER_ADMIN),
    "Change user password": ("POST", "/v1.0/users/{t}/authentication/methods/" + _PWD_METHOD + "/resetPassword", 202, ga.WID_USER_ADMIN),
    "Invite external user": ("POST", "/v1.0/invitations", 201, ga.WID_MEMBER),
    "Update conditional access policy": ("PATCH", "/v1.0/identity/conditionalAccess/policies/{t}", 204, ga.WID_SECURITY_ADMIN),
    "Delete conditional access policy": ("DELETE", "/v1.0/identity/conditionalAccess/policies/{t}", 204, ga.WID_SECURITY_ADMIN),
    _CERT_MGMT_ACTIVITY: ("POST", "/v1.0/applications/{t}/addPassword", 200, ga.WID_APP_ADMIN),
    "Add owner to application": ("POST", "/v1.0/applications/{t}/owners/$ref", 204, ga.WID_APP_ADMIN),
    "Remove owner from application": ("DELETE", "/v1.0/applications/{t}/owners/{t2}/$ref", 204, ga.WID_APP_ADMIN),
    "Admin registered security info": ("POST", "/v1.0/users/{t}/authentication/phoneMethods", 201, ga.WID_USER_ADMIN),
    "Add service principal": ("POST", "/v1.0/servicePrincipals", 201, ga.WID_APP_ADMIN),
    "Delete service principal": ("DELETE", "/v1.0/servicePrincipals/{t}", 204, ga.WID_APP_ADMIN),
    "Add member to role": ("POST", "/v1.0/roleManagement/directory/roleAssignments", 201, ga.WID_GLOBAL_ADMIN),
    "Add group": ("POST", "/v1.0/groups", 201, ga.WID_MEMBER),
    "Delete group": ("DELETE", "/v1.0/groups/{t}", 204, ga.WID_MEMBER),
}
# Scenarios whose Graph-activity detector is a target; the rest stay audit-only.
_GRAPH_SCENARIOS = {"user_account_created", "user_account_deleted", "short_lived_account",
                    "account_unlock_password_reset", "unusual_guest_invitation", "ca_operation_unusual",
                    "ca_policy_removed", "app_credential_added", "owner_added_to_application",
                    "owner_removed_from_application", "auth_method_added", "tap_registered", "sp_created",
                    "sp_removed", "admin_role_add", "group_created_deleted", "wip_cloud_group_change",
                    "wip_app_credential_added", "wip_app_owner_added", "wip_app_owner_removed",
                    "wip_service_principal_created", "wip_service_principal_removed", "wip_auth_method_added",
                    "wip_conditional_access_change", "wip_user_created", "wip_user_deleted",
                    "wip_user_password_reset", "wip_external_guest_invitation", "wip_pim_member_removal",
                    "wip_application_removed", "wip_service_principal_application_created",
                    "wip_azure_domain_verification"}


def _graph_companions(records):
    out = []
    for rec in records:
        spec = _GRAPH_CALLS.get(rec.get("activityDisplayName"))
        u = ((rec.get("initiatedBy") or {}).get("user") or {})
        if not spec or not u.get("userPrincipalName"):
            continue
        method, uri, status, wids = spec
        tgts = rec.get("targetResources") or [{}]
        uri = uri.replace("{t}", tgts[0].get("id") or "").replace(
            "{t2}", (tgts[1] if len(tgts) > 1 else {}).get("id") or "")
        if "TemporaryAccessPass" in json.dumps(tgts[0].get("modifiedProperties") or []):
            uri = uri.replace("/phoneMethods", "/temporaryAccessPassMethods")
        admin = {"username": u["userPrincipalName"].split("@")[0], "upn": u["userPrincipalName"]}
        if rec.get("activityDisplayName") == "Add service principal":   # app registration first
            out += ga.admin_change(admin, "POST", "/v1.0/applications", 201, wids=wids,
                                   ip=u.get("ipAddress"), offset_s=-4.0)
        out += ga.admin_change(admin, method, uri, status, wids=wids, ip=u.get("ipAddress"))
    return out


def _with_eventhub(records, benign):
    """records + the Entra AuditLogs event-hub copy of each (msft_azure_raw), which is what the
    Cloud-module "Azure Audit Log" analytics read. Benign records whose operation one of those
    analytics raises on by itself get no copy (azure_audit_catalog.CLOUD_ALERTING_ACTIVITIES)."""
    out = []
    for r in records:
        out.append(r)
        if (isinstance(r, dict) and "activityDisplayName" in r and not ac.is_eventhub_copy(r)
                and not (benign and cat.is_cloud_alerting(r["activityDisplayName"]))):
            out.append(ac.eventhub_audit(r))
    return out


def _with_graph(config, key, records):
    if not ac.eventhub_enabled(config, CONFIG_KEY):
        return records
    companions = _graph_companions(records) if key in _GRAPH_SCENARIOS else []
    return companions + _with_eventhub(records, benign=False)


def _benign(config, context):
    recs = generate_benign(config, context)
    return _with_eventhub(recs, benign=True) if ac.eventhub_enabled(config, CONFIG_KEY) else recs


_GATE = ac.ThreatGate(SCENARIOS)


def get_threat_names():
    return list(SCENARIOS.keys())


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    if scenario_event:
        key = scenario_event if scenario_event in SCENARIOS else scenario_event.lower()
        if key in SCENARIOS:
            return (_with_graph(config, key, SCENARIOS[key](config)), key)
        return None
    if benign_only or threat_level == "Benign Traffic Only":
        return _benign(config, context)
    if _GATE.fire(threat_level, config):
        key = random.choice(list(SCENARIOS))
        return (_with_graph(config, key, SCENARIOS[key](config)), key)
    return _benign(config, context)
