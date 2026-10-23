"""Microsoft Entra ID Protection and provisioning diagnostic logs, streamed to an event hub ->
msft_azure_raw, via the cribl_direct transport under the Azure Event Hubs Source-Identifier.

Three Entra diagnostic categories the msft_azure_raw modeling rule maps but no other module emits:

  - ProvisioningLogs          -- SCIM / HR-driven app provisioning sync cycles.
  - RiskyUsers / RiskyServicePrincipals   -- Identity Protection risk-state of an identity.
  - UserRiskEvents / ServicePrincipalRiskEvents  -- individual risk detections.

Record shapes follow the Graph resources those categories carry (provisioningObjectSummary,
riskyUser, riskDetection) placed in `properties`, inside the event-hub resource-log envelope. Every
`properties` path here is one the modeling rule reads (verified against MicrosoftEntraID.xif):
provisioning reads initiatedBy/sourceSystem/targetSystem/targetIdentity/provisioningSteps/jobId;
risky-user reads userPrincipalName/riskState/riskDetail/riskLevel/accountEnabled/displayName; risk
events read activity/ipAddress/riskEventType/riskLevel/riskDetail/source/location/userType.

Benign only. Identity Protection in a healthy tenant is dominated by provisioning sync and by
low/dismissed/remediated risk (sign-ins Identity Protection looked at and cleared); genuinely risky
detections are the needle the azuread_signin threat scenarios already provide. So risk here stays
low/none and dismissed/remediated/confirmedSafe, which is the baseline the risk analytics learn.
"""
import datetime
import random
import time
import uuid

from modules import azure_common as ac

NAME = "Azure AD Identity Protection"
DESCRIPTION = ("Simulates Microsoft Entra ProvisioningLogs, RiskyUsers and UserRiskEvents diagnostic "
               "logs for msft_azure_raw via the cribl_direct transport.")
CONFIG_KEY = "azuread_identity_protection_config"
SOURCE_IDENTIFIER = ac.EVENTHUB_SOURCE          # Azure Event Hubs -> msft_azure_raw
INTEGRATION_IDENTIFIER = "logsim:entra_identity_protection"
DATASET = "msft_azure_raw"
EVENT_INTERVAL = 2.0   # default relative benign volume: provisioning sync steady; risk events rare

_RESOURCE = ac.EVENTHUB_RESOURCE                # /tenants/<tid>/providers/Microsoft.aadiam
TENANT_ID = ac.HOME_TENANT_ID


def _ts(offset_s=0.0):
    d = datetime.datetime.fromtimestamp(time.time() + min(0.0, offset_s), datetime.timezone.utc)
    return f"{d:%Y-%m-%dT%H:%M:%S}.{d.microsecond:06d}{random.randint(0, 9)}Z"


def _envelope(category, operation_name, properties, *, caller_ip="", result="Success", level=4,
              offset_s=0.0):
    return {"time": _ts(offset_s), "resourceId": _RESOURCE, "operationName": operation_name,
            "operationVersion": "1.0", "category": category, "tenantId": TENANT_ID,
            "resultType": result, "resultSignature": "None", "resultDescription": "",
            "durationMs": 0, "callerIpAddress": caller_ip, "correlationId": str(uuid.uuid4()),
            "Level": level, "properties": properties}


# ── ProvisioningLogs ────────────────────────────────────────────────────────────────
# Cloud-sync / SCIM provisioning agents keep user accounts in sync with SaaS apps. A healthy
# tenant produces a steady stream of per-user export/update cycles, almost all Success.
_PROV_CONNECTORS = ["Salesforce", "ServiceNow", "Workday", "Zoom", "Slack", "Google Workspace",
                    "Box", "Atlassian Cloud", "Adobe Acrobat Sign", "Workplace by Facebook"]
_PROV_ACTION = [("create", "Create"), ("update", "Update"), ("update", "Update"), ("update", "Update"),
                ("disable", "Disable"), ("other", "Other")]
_PROV_STEP_NAMES = ["Import", "Determine if in scope", "Match", "Determine actions", "Export"]


def _provisioning(config, context=None):
    u = ac.pick_user(config, context)
    connector = ac.baseline_saas_app()
    action, op = random.choice(_PROV_ACTION)
    job_id = ac._stable_guid("provjob:" + connector)   # stable per connector (a sync job entity)
    steps = [{"name": n, "provisioningStepType": "import" if n == "Import" else
              "scoping" if "scope" in n.lower() else "matching" if n == "Match" else "export",
              "status": "success",
              "description": f"{n} completed for {u['upn']}"} for n in _PROV_STEP_NAMES]
    props = {
        "id": uuid.uuid4().hex, "jobId": job_id, "cycleId": uuid.uuid4().hex,
        "changeId": uuid.uuid4().hex, "provisioningAction": action,
        "durationInMilliseconds": random.randint(80, 4000),
        "provisioningStatusInfo": {"status": "success", "errorInformation": None},
        "provisioningSteps": steps,
        "modifiedProperties": [{"displayName": "IsSoftDeleted", "oldValue": "True", "newValue": "False"}]
        if action == "create" else [],
        "servicePrincipal": {"id": ac.user_oid("sp:" + connector), "displayName": connector},
        "sourceSystem": {"Name": "Azure Active Directory", "details": {}},
        "targetSystem": {"Name": connector, "details": {"ApplicationId": ac.app_id(connector)}},
        "initiatedBy": {"Type": "application", "Name": "Microsoft Entra Provisioning Service",
                        "Id": ac.app_id("Entra Provisioning")},
        "sourceIdentity": {"Id": ac.user_oid(u["username"]), "Name": u.get("display_name"),
                           "identityType": "User", "details": {"UserPrincipalName": u["upn"]}},
        "targetIdentity": {"Id": ac._stable_guid(f"scim:{connector}:{u['username']}"),
                           "Name": u.get("display_name"), "identityType": "User",
                           "details": {"UserPrincipalName": u["upn"]}},
        "statusInfo": {"status": "success"}}
    rec = _envelope("ProvisioningLogs", op, props, result="Success")
    rec["properties"]["durationMs"] = props["durationInMilliseconds"]
    rec["durationMs"] = props["durationInMilliseconds"]
    return [rec]


# ── RiskyUsers / RiskyServicePrincipals ───────────────────────────────────────────────
# The current risk state of an identity. Benign tenant: risk cleared (confirmedSafe / remediated /
# dismissed) or none, at low/none level, account still enabled.
_RU_STATE = [("none", "none", "none"), ("remediated", "userPerformedSecuredPasswordChange", "low"),
             ("dismissed", "adminDismissedAllRiskForUser", "low"),
             ("confirmedSafe", "adminConfirmedUserSafe", "low"), ("none", "none", "none")]


def _risky_user(config, context=None):
    u = ac.pick_user(config, context)
    state, detail, level = random.choice(_RU_STATE)
    props = {"id": ac.user_oid(u["username"]), "userPrincipalName": u["upn"],
             "userDisplayName": u.get("display_name"), "displayName": u.get("display_name"),
             "riskState": state, "riskDetail": detail, "riskLevel": level,
             "riskLastUpdatedDateTime": _ts(-random.randint(60, 86400)), "accountEnabled": True,
             "isDeleted": False, "isProcessing": False}
    return [_envelope("RiskyUsers", "UserRiskUpdated", props, result="Success")]


def _risky_sp(config, context=None):
    name = ac.baseline_saas_app()
    props = {"id": ac.user_oid("sp:" + name), "displayName": name,
             "appId": ac.app_id(name), "servicePrincipalType": "Application",
             "riskState": random.choice(["dismissed", "none", "confirmedSafe"]),
             "riskDetail": "adminDismissedAllRiskForServicePrincipal", "riskLevel": "low",
             "riskLastUpdatedDateTime": _ts(-random.randint(60, 86400)),
             "accountEnabled": True, "isEnabled": True, "isProcessing": False}
    return [_envelope("RiskyServicePrincipals", "ServicePrincipalRiskUpdated", props)]


# ── UserRiskEvents / ServicePrincipalRiskEvents ───────────────────────────────────────
# Individual Identity Protection detections. Benign baseline: low-risk sign-in signals that were
# auto-dismissed or remediated (the bulk of real detections in a tenant with MFA/CA).
_URE_TYPE = [("unfamiliarFeatures", "aiConfirmedSigninSafe"), ("unlikelyTravel", "aiConfirmedSigninSafe"),
             ("unfamiliarFeatures", "adminConfirmedSigninSafe"), ("newCountry", "aiConfirmedSigninSafe"),
             ("anonymizedIPAddress", "aiConfirmedSigninSafe")]


def _user_risk_event(config, context=None):
    u = ac.pick_user(config, context)
    loc = ac.egress(u)
    etype, detail = random.choice(_URE_TYPE)
    props = {"id": uuid.uuid4().hex, "correlationId": str(uuid.uuid4()),
             "requestId": str(uuid.uuid4()), "activity": "signin",
             "activityDateTime": _ts(-random.randint(10, 600)),
             "detectedDateTime": _ts(-random.randint(5, 300)),
             "ipAddress": loc["ip"], "riskEventType": etype,
             "riskState": random.choice(["dismissed", "remediated"]), "riskLevel": "low",
             "riskDetail": detail, "source": "IdentityProtection", "detectionTimingType": "realtime",
             "userId": ac.user_oid(u["username"]), "userPrincipalName": u["upn"],
             "userDisplayName": u.get("display_name"), "userType": "member",
             "location": {"city": loc.get("city", ""), "state": loc.get("state", ""),
                          "countryOrRegion": loc.get("countryOrRegion", ""),
                          "geoCoordinates": loc.get("geoCoordinates", {})},
             "additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"" + ac.user_agent(u) + "\"}]"}
    return [_envelope("UserRiskEvents", "UserRiskDetection", props, caller_ip=loc["ip"])]


def _sp_risk_event(config, context=None):
    name = ac.baseline_saas_app()
    loc = ac.rare_asn_loc() if random.random() < 0.0 else {"ip": "", "countryOrRegion": ""}
    props = {"id": uuid.uuid4().hex, "correlationId": str(uuid.uuid4()),
             "activity": "servicePrincipal", "riskEventType": "investigationsThreatIntelligence",
             "riskState": "dismissed", "riskLevel": "low",
             "riskDetail": "adminDismissedAllRiskForServicePrincipal", "source": "IdentityProtection",
             "servicePrincipalId": ac.user_oid("sp:" + name), "servicePrincipalDisplayName": name,
             "appId": ac.app_id(name), "detectedDateTime": _ts(-random.randint(60, 3600))}
    return [_envelope("ServicePrincipalRiskEvents", "ServicePrincipalRiskDetection", props)]


# Provisioning sync is high-volume; risk state/detections are far rarer in a healthy tenant.
_BENIGN = [(70, _provisioning), (10, _risky_user), (3, _risky_sp), (14, _user_risk_event),
           (3, _sp_risk_event)]
_BENIGN_FNS = [f for w, f in _BENIGN for _ in range(w)]


def generate_benign(config=None, context=None):
    return random.choice(_BENIGN_FNS)(config, context)


SCENARIOS = {}
ANALYTIC_ALERTS = {}


def get_threat_names():
    return list(SCENARIOS)


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    if scenario_event:
        key = scenario_event if scenario_event in SCENARIOS else str(scenario_event).lower()
        return (SCENARIOS[key](config), key) if key in SCENARIOS else None
    return generate_benign(config, context)
