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

# Threat rate governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (see _GATE below).

ADMIN_ROLES = ("IT Administrator", "IT Director", "Systems Engineer")
HELPDESK_ROLES = ("Help Desk", "IT Administrator")
_ID_PREFIX = {"Core Directory": "Directory", "Self-service Password Management": "SSPR",
              "Authentication Methods": "Authentication Methods", "Account Provisioning": "Sync"}
# Common apps that recur in everyday delegated consent / app-role events — the hot core that
# forms the baseline (familiar, always-present apps).
_SAAS_CORE = ["Salesforce", "ServiceNow", "Zoom", "Slack", "Workday", "DocuSign", "Atlassian Cloud",
              "GitHub Enterprise", "Adobe Acrobat Sign", "Box", "Tableau Online", "Power BI",
              "Microsoft Graph Command Line Tools"]
# Enterprise integrations that realistically receive tenant-wide admin consent. A large, varied
# roster (200+): each app is a stable entity (deterministic appId + SP objectId), so the same app
# always appears with the same identity across events -- what a real tenant's consented-app estate
# looks like. The roster is intentionally broad so a never-before-seen app keeps appearing even after
# months of runtime, letting XSIAM's "first seen" admin-consent detector keep firing organically.
_ADMIN_CONSENT_APPS = [
    # Collaboration / productivity
    "Slack", "Zoom", "Webex", "Google Workspace", "Dropbox Business", "Box", "Egnyte",
    "Citrix ShareFile", "Notion", "Confluence", "Atlassian Cloud", "Asana", "Monday.com", "Trello",
    "Smartsheet", "Miro", "Mural", "Lucidchart", "Figma", "Airtable", "ClickUp", "Basecamp", "Wrike",
    "Coda", "Evernote Business", "Calendly", "Loom", "Grammarly Business", "Zapier", "Workato",
    "Tray.io", "Make", "Doodle",
    # E-signature / documents / content
    "DocuSign", "Adobe Acrobat Sign", "PandaDoc", "Dropbox Sign", "Adobe Creative Cloud", "Canva",
    "Contentful", "Webflow", "Wistia", "Vimeo", "Brightcove", "DocuWare", "M-Files", "Nintex",
    # CRM / sales / marketing
    "Salesforce", "HubSpot", "Zoho CRM", "Pipedrive", "Microsoft Dynamics 365", "Marketo",
    "Salesforce Pardot", "Outreach", "Salesloft", "Gong", "ZoomInfo", "Clearbit", "Drift",
    "Intercom", "Mailchimp", "SendGrid", "Constant Contact", "Braze", "Iterable", "Segment",
    "Amplitude", "Mixpanel", "Pendo", "Heap", "Marqeta", "Apollo.io", "6sense", "Demandbase",
    # Support / ITSM / customer success
    "ServiceNow", "Jira Service Management", "Freshservice", "Freshdesk", "Zendesk", "Help Scout",
    "Front", "Gainsight", "Totango", "ChurnZero", "Vitally", "ServiceTitan",
    # Observability / IT ops
    "PagerDuty", "Opsgenie", "Splunk Cloud", "Datadog", "New Relic", "Dynatrace", "AppDynamics",
    "Grafana Cloud", "Sumo Logic", "Elastic Cloud", "LogicMonitor", "SolarWinds", "ManageEngine",
    "NinjaOne", "Automox", "ConnectWise", "Jamf Pro", "Kandji", "Rippling", "JumpCloud",
    # Security / identity
    "Okta", "Ping Identity", "OneLogin", "Duo Security", "CyberArk", "SailPoint IdentityNow",
    "BeyondTrust", "CrowdStrike Falcon", "SentinelOne", "Proofpoint", "Mimecast", "Abnormal Security",
    "KnowBe4", "Netskope", "Zscaler", "Cloudflare", "Palo Alto Prisma Access", "Tenable.io", "Qualys",
    "Rapid7 InsightVM", "Wiz", "Lacework", "Snyk", "Veracode", "Checkmarx", "1Password Business",
    "LastPass", "Dashlane", "Keeper Security", "HashiCorp Vault", "Twingate", "Tailscale",
    "Vanta", "Drata", "Secureframe", "OneTrust", "LogicGate", "AuditBoard",
    # HR / recruiting / people
    "Workday", "BambooHR", "Gusto", "ADP Workforce Now", "UKG Pro", "Paylocity", "Paycom", "Namely",
    "Greenhouse", "Lever", "SmartRecruiters", "Workable", "Culture Amp", "Lattice", "15Five", "Deel",
    "Remote", "Cornerstone OnDemand", "Docebo", "LinkedIn Learning", "Udemy Business", "Pluralsight",
    "Coursera for Business", "Degreed", "WalkMe",
    # Finance / ERP / procurement
    "SAP Concur", "Coupa", "Bill.com", "Ramp", "Brex", "NetSuite", "Sage Intacct", "QuickBooks Online",
    "Xero", "Stripe", "Avalara", "Navan", "Airbase", "Tipalti", "Expensify", "Divvy", "Anaplan",
    "Workiva", "BlackLine",
    # Dev / engineering / CI-CD
    "GitHub Enterprise", "GitLab", "Bitbucket", "CircleCI", "Jenkins", "Harness", "Octopus Deploy",
    "JFrog Artifactory", "SonarCloud", "Sentry", "Rollbar", "Bugsnag", "LaunchDarkly", "Split.io",
    "Postman", "SwaggerHub", "Terraform Cloud", "Pulumi", "Docker Hub", "Databricks",
    # Data / analytics / BI
    "Snowflake", "dbt Cloud", "Fivetran", "Airbyte", "Looker", "Tableau Online", "Power BI",
    "Qlik Sense", "Mode Analytics", "Sisense", "ThoughtSpot", "Metabase", "Hex", "Alteryx",
    "Celonis", "Collibra", "Monte Carlo",
    # Automation / RPA / misc platform
    "UiPath", "Automation Anywhere", "Blue Prism", "MuleSoft", "Boomi", "BetterCloud", "Torii",
    "Productiv", "Zluri",
    # Storage / backup / DR
    "Druva", "Rubrik", "Cohesity", "Veeam", "Backblaze",
    # Comms / telephony
    "Twilio", "RingCentral", "Dialpad", "Aircall", "8x8", "Five9", "Talkdesk", "Genesys Cloud",
    "Vonage",
    # Microsoft first-party admin tooling
    "Microsoft Graph Command Line Tools", "Microsoft Graph PowerShell", "Azure CLI",
    # Design / construction / vertical
    "Autodesk Construction Cloud", "Procore", "Bluebeam", "Qualtrics", "SurveyMonkey", "Typeform",
]

# A long tail of less-common apps so new/first-seen apps keep appearing for a long time and the
# baseline does NOT saturate quickly. Built from the admin-consent roster plus generated vendor
# app registrations — deterministic and bounded (~800), so apps remain stable entities (each a
# fixed appId via ac.app_id), not an infinite stream. Everyday app events draw heavy-tailed:
# ~80% from the small hot core (recurs -> baseline), ~20% from this tail (rare -> first-seen fuel).
_APP_VENDORS = [
    "Asana", "Monday", "Notion", "Airtable", "Smartsheet", "Miro", "Figma", "Lucidchart", "Calendly",
    "Dropbox", "Egnyte", "Mural", "Coda", "ClickUp", "Wrike", "Basecamp", "Trello", "Jira",
    "Confluence", "Bitbucket", "GitLab", "CircleCI", "Datadog", "Grafana", "Splunk", "PagerDuty",
    "Opsgenie", "New Relic", "Sumo Logic", "Okta", "Ping Identity", "OneLogin", "Duo", "CyberArk",
    "SailPoint", "CrowdStrike", "SentinelOne", "Proofpoint", "Mimecast", "Netskope", "Zscaler",
    "Cloudflare", "Snyk", "Veracode", "1Password", "LastPass", "HashiCorp", "Twilio", "SendGrid",
    "Mailchimp", "HubSpot", "Marketo", "Segment", "Amplitude", "Mixpanel", "Pendo", "Intercom",
    "Drift", "Gong", "Outreach", "Salesloft", "Gainsight", "Totango", "Greenhouse", "Lever",
    "BambooHR", "Gusto", "Rippling", "Deel", "Expensify", "Coupa", "Ramp", "Brex", "Bill.com",
    "NetSuite", "Xero", "Stripe", "Snowflake", "Databricks", "Fivetran", "Looker", "Qlik",
    "ThoughtSpot", "Metabase", "Alteryx", "UiPath", "Workato", "Zapier", "Boomi", "MuleSoft",
    "Celonis", "Vanta", "Drata", "OneTrust", "AuditBoard", "Procore", "Qualtrics", "SurveyMonkey",
    "Typeform", "Loom", "Grammarly", "Webex", "RingCentral", "Twingate", "Tailscale", "JumpCloud"]
_APP_PRODUCTS = [
    "Connector", "for Microsoft 365", "SSO", "Integration", "Sync", "Cloud", "Enterprise",
    "Analytics", "API", "Automation", "Add-in", "Teams App", "Reporting", "Gateway", "Provisioning",
    "SCIM", "for Outlook", "for Teams", "for SharePoint", "Insights", "Workspace", "Platform",
    "Admin", "Service", "Bot"]


def _build_app_tail():
    rnd = random.Random("logsim-saas-tail-v1")   # seeded -> identical across runs/machines
    tail = set(_ADMIN_CONSENT_APPS)
    while len(tail) < 800:
        tail.add(f"{rnd.choice(_APP_VENDORS)} {rnd.choice(_APP_PRODUCTS)}")
    return sorted(tail)


_SAAS_TAIL = _build_app_tail()
_SAAS_APPS = _SAAS_CORE   # back-compat alias (the recurring core)
_TAIL_PROB = 0.20         # share of everyday app events drawn from the long tail


def _saas_app():
    """Heavy-tailed app pick: mostly the recurring core (baseline), sometimes a long-tail app
    (so first-seen / new-app detectors keep firing for a long time instead of saturating)."""
    if random.random() < _TAIL_PROB:
        return random.choice(_SAAS_TAIL)
    return random.choice(_SAAS_CORE)


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
    # Per-user, stable, varied (5 desktop + mobile profiles) and consistent with the user's
    # sign-in device browser — not one of two hardcoded strings.
    return {"key": "User-Agent", "value": ac.user_agent(u)}


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
    mods = [mp("Group.DisplayName", None, g),
            mp("Group.ObjectID", None, ac._stable_guid("Group:" + g))]
    return audit("Add member to group" if add else "Remove member from group", "GroupManagement",
                 "Core Directory", "Add" if add else "Remove", by_user(admin),
                 [t_obj("Group", g, mods, group_type="unifiedGroups"), t_user(tgt)], [_ua(admin)])


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
                  {"key": "ServicePrincipalProvisioningType", "value": "Other"}])


def _b_admin_consent(cfg, app=None):
    # Tenant-wide admin consent by a privileged admin -> baselines XSIAM's
    # "First seen Azure admin consent to an application" first-seen detector.
    # The target app is pinned: a stable appId + SP objectId per app name, drawn from a
    # varied roster, so repeated consents reference a consistent application identity.
    admin = ac.pick_by_role(cfg, ADMIN_ROLES, ("IT",))
    app = app or random.choice(_ADMIN_CONSENT_APPS)
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
    return [_maybe_fail(_catalog_record(config, random.choice(cat.AUDIT_ACTIVITIES)))]


# ── detection-relevant scenarios (named, on-demand) ─────────────────────────────────

def scenario_admin_role_add(config=None):
    """Grant of a privileged directory role -> 'Identity assigned an Azure AD Administrator Role'."""
    admin = ac.pick_by_role(config, ("IT Director",), ("IT",)); tgt = ac.pick_user(config)
    return [audit("Add member to role", "RoleManagement", "Core Directory", "Add", by_user(admin),
                  [t_obj("Role", "Global Administrator", [mp("Role.DisplayName", None, "Global Administrator"),
                   mp("Role.TemplateId", None, "62e90394-69f5-4237-9190-012177145e10")]), t_user(tgt)])]


def scenario_consent_risky_app(config=None):
    """Admin consent granting high-privilege Graph scopes -> 'Azure application consent' (the
    detector is 'an ADMINISTRATIVE identity consented permissions to an application', so the
    initiator is an admin and ConsentContext.IsAdminConsent is True)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    mods = [mp("ConsentContext.IsAdminConsent", None, "True"),
            mp("ConsentContext.OnBehalfOfAll", None, "True"),
            mp("ConsentAction.Permissions", None, "Mail.Read Files.ReadWrite.All Directory.Read.All offline_access")]
    return [audit("Consent to application", "ApplicationManagement", "Core Directory", "Assign",
                  by_user(admin), [t_obj("ServicePrincipal", "External Reporting Connector", mods)],
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


# A rogue external Entra tenant an attacker attaches via cross-tenant access + cross-tenant sync —
# the cloud equivalent of standing up a rogue forest and establishing a trust. Stable fake tenant.
_ROGUE_TENANT_ID = ac._stable_guid("rogue-tenant:evilcorp.onmicrosoft.com")
_ROGUE_TENANT_DOMAIN = "evilcorp.onmicrosoft.com"


def scenario_cross_tenant_trust_abuse(config=None):
    """Attacker trusts a rogue external tenant and opens inbound B2B + cross-tenant sync
    (the cloud 'rogue forest trust'): CrossTenantAccessSettings + CrossTenantIdentitySyncSettings
    changes granting inbound collaboration/direct-connect, MFA trust, auto-redemption and inbound
    user provisioning from the attacker tenant -> anomalous directory/trust change + privilege path."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    tgt = t_obj("Other", _ROGUE_TENANT_DOMAIN)
    tgt["modifiedProperties"] = [
        mp("tenantId", None, _ROGUE_TENANT_ID),
        mp("b2bCollaborationInbound.usersAndGroups", '{"accessType":"blocked"}',
           '{"accessType":"allowed"}'),
        mp("b2bDirectConnectInbound.usersAndGroups", '{"accessType":"blocked"}',
           '{"accessType":"allowed"}'),
        mp("inboundTrust.isMfaAccepted", "false", "true"),
        mp("inboundTrust.isCompliantDeviceAccepted", "false", "true"),
        mp("automaticUserConsentSettings.inboundAllowed", "false", "true")]
    return [
        audit("Add a partner to cross-tenant access setting", "CrossTenantAccessSettings",
              "Core Directory", "Add", by_user(admin), [tgt], [_ua(admin)]),
        audit("Update a partner cross-tenant access setting", "CrossTenantAccessSettings",
              "Core Directory", "Update", by_user(admin),
              [t_obj("Other", _ROGUE_TENANT_DOMAIN,
                     [mp("inboundTrust.isMfaAccepted", "false", "true"),
                      mp("automaticUserConsentSettings.inboundAllowed", "false", "true")])],
              [_ua(admin)]),
        audit("Create a partner cross-tenant identity sync setting", "CrossTenantIdentitySyncSettings",
              "Core Directory", "Add", by_user(admin),
              [t_obj("Other", _ROGUE_TENANT_DOMAIN,
                     [mp("tenantId", None, _ROGUE_TENANT_ID),
                      mp("userSyncInbound.isSyncAllowed", "false", "true")])],
              [_ua(admin)])]


def scenario_cross_tenant_sync_outbound(config=None):
    """Outbound cross-tenant sync: OUR users are provisioned OUT to the rogue tenant (user/data
    exfiltration via the identity fabric, T1537)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    return [
        audit("Update a partner cross-tenant access setting", "CrossTenantAccessSettings",
              "Core Directory", "Update", by_user(admin),
              [t_obj("Other", _ROGUE_TENANT_DOMAIN,
                     [mp("tenantId", None, _ROGUE_TENANT_ID),
                      mp("b2bCollaborationOutbound.usersAndGroups",
                         '{"accessType":"blocked"}', '{"accessType":"allowed"}')])], [_ua(admin)]),
        audit("Create a partner cross-tenant identity sync setting", "CrossTenantIdentitySyncSettings",
              "Core Directory", "Add", by_user(admin),
              [t_obj("Other", _ROGUE_TENANT_DOMAIN,
                     [mp("tenantId", None, _ROGUE_TENANT_ID),
                      mp("userSyncOutbound.isSyncAllowed", "false", "true")])], [_ua(admin)])]


def scenario_delegated_admin_partner_abuse(config=None):
    """External delegated-admin (GDAP/DAP) partner promoted with Global Admin over the tenant —
    partner-tenant takeover (T1098 Account Manipulation / abuse of delegated administration)."""
    admin = ac.pick_by_role(config, ("IT Director",), ("IT",))
    partner = "msp-partner-eval.onmicrosoft.com"
    pid = ac._stable_guid("gdap:" + partner)
    return [
        audit("Add partner to company", "DirectoryManagement", "Core Directory", "Add",
              by_user(admin), [t_obj("Directory", partner, [mp("PartnerTenantId", None, pid)])], [_ua(admin)]),
        audit("Promote company to partner", "DirectoryManagement", "Core Directory", "Add",
              by_user(admin), [t_obj("Directory", partner,
                     [mp("DelegatedAdminRelationship", None, "Global Administrator"),
                      mp("AccessAssignment", None, "Microsoft Entra Global Administrator")])], [_ua(admin)])]


def scenario_multitenant_org_join(config=None):
    """Tenant joined into an attacker-run multi-tenant org with identity sync — cloud cross-tenant
    fabric persistence (the cloud analog of joining a rogue forest)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    mto = "Contoso Global MTO"
    return [
        audit("Create a MultiTenantOrg", "MultiTenantOrg", "Core Directory", "Add", by_user(admin),
              [t_obj("Other", mto, [mp("tenantId", None, _ROGUE_TENANT_ID),
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


def scenario_federated_domain_backdoor(config=None):
    """A new domain is added and federated to an attacker IdP — persistent Golden SAML backdoor
    (T1484.002 Trust Modification)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    dom = "login-security-update.com"
    return [
        audit("Add unverified domain", "DirectoryManagement", "Core Directory", "Add",
              by_user(admin), [t_obj("Directory", dom)], [_ua(admin)]),
        audit("Set federation settings on domain", "DirectoryManagement", "Core Directory", "Update",
              by_user(admin), [t_obj("Directory", dom,
                     [mp("IssuerUri", None, "http://any.sts/adfs/services/trust"),
                      mp("PassiveSignInUri", None, "https://attacker-idp.example/adfs/ls/"),
                      mp("SigningCertificate", None, "<attacker-cert-thumbprint>")])], [_ua(admin)])]


def scenario_failed_federation_change(config=None):
    """A FAILED attempt to modify domain federation settings (permission denied) -> the 'failed'
    half of 'Azure domain federation settings modification (successful/failed)'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    return [audit("Set federation settings on domain", "DirectoryManagement", "Core Directory",
                  "Update", by_user(admin),
                  [t_obj("Directory", "login-security-update.com",
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
    actor = ac.pick_user(config)   # not a typical CA admin
    pol = random.choice(_CA_POLICIES)
    return [audit("Update conditional access policy", "Policy", "Conditional Access", "Update",
                  by_user(actor), [t_obj("Policy", pol,
                  [mp("ConditionalAccessPolicy", "[state=enabled]", "[state=disabled]")])], [_ua(actor)])]


def scenario_tap_registered(config=None):
    """A Temporary Access Pass is registered on an account (MFA-bypass persistence) -> 'Azure
    Temporary Access Pass (TAP) registered to an account'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [audit("Admin registered security info", "UserManagement", "Core Directory", "Update",
                  by_user(admin), [t_user(tgt, [mp("StrongAuthenticationMethod", None,
                  "TemporaryAccessPass"), mp("SecurityInfo.Action", None, "Register")])], [_ua(admin)])]


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
    return [audit("Add owner to application", "ApplicationManagement", "Core Directory", "Add",
                  by_user(admin), [t_obj("Application", "Internal Automation App"), t_user(tgt)],
                  [_ua(admin)])]


def scenario_sp_app_role_assigned(config=None):
    """A high-privilege app role (Graph app permission) is granted to a service principal ->
    'Azure service principal assigned app role'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    return [audit("Add app role assignment to service principal", "ApplicationManagement",
                  "Core Directory", "Assign", by_user(admin),
                  [t_obj("ServicePrincipal", "External Reporting Connector",
                   [mp("AppRole.Value", None, "Mail.ReadWrite.All"),
                    mp("AppRole.Id", None, "e2a3a72e-5f79-4c64-b1b1-878b674786c9")])], [_ua(admin)])]


def scenario_application_uri_modification(config=None):
    """An application's reply/redirect URI is modified to an attacker-controlled URL (token
    redirect hijack) -> 'Azure application URI modification'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [audit("Update application", "ApplicationManagement", "Core Directory", "Update",
                  by_user(admin), [t_obj("Application", "Internal Automation App",
                  [mp("AppAddress.ReplyUrl", "https://app.examplecorp.com/auth",
                      "https://attacker-collect.example/oauth/callback")])], [_ua(admin)])]


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
    inviter = ac.pick_user(config)
    guest = f"contractor_{random.randint(100,999)}#EXT#@examplecorp.com"
    return [audit("Invite external user", "UserManagement", "Core Directory", "Add", by_user(inviter),
                  [t_user({"username": "guest", "upn": guest, "display_name": "external guest"},
                   [mp("Invitation.InvitedUserEmailAddress", None,
                       f"contractor{random.randint(100,999)}@proton.me")])], [_ua(inviter)])]


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


SCENARIOS = {
    "admin_role_add": scenario_admin_role_add,
    "consent_risky_app": scenario_consent_risky_app,
    "mfa_fraud_reported": scenario_mfa_fraud_reported,
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
}


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
