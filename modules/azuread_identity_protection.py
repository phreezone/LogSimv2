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


# NOTE: the RiskyUsers / RiskyServicePrincipals categories (an identity's current risk STATE) are
# not emitted. This ingestion path accepts them at the receiver but
# drops them before msft_azure_raw (they never land, not even raw) -- the source's parsing rule
# admits ProvisioningLogs and the risk-EVENT categories but not the risk-state ones, so the
# modeling rule's RiskyUsers branch never sees a row. Risk state would just be discarded sends.
# The risk-detection categories below (UserRiskEvents / ServicePrincipalRiskEvents) DO land.


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


# Provisioning sync is high-volume; risk detections are far rarer in a healthy tenant. (Risk-state
# categories are omitted — this ingestion path drops them; see the note above.)
_BENIGN = [(80, _provisioning), (17, _user_risk_event), (3, _sp_risk_event)]
_BENIGN_FNS = [f for w, f in _BENIGN for _ in range(w)]


def generate_benign(config=None, context=None):
    return random.choice(_BENIGN_FNS)(config, context)


# ── threat scenarios: genuine Identity Protection risk detections ─────────────────────
# High/medium-risk UserRiskEvents left in the atRisk state (not auto-dismissed) — the needle the
# risk analytics look for. Record shape is identical to the benign risk event above; only
# riskEventType / riskLevel / riskState / riskDetail and the source IP differ. UNCONFIRMED: these
# target the Entra Identity Protection risk detectors; the alert names below are provisional until a
# fire -> alert is observed in the tenant (same promote workflow used for the other Microsoft feeds).
_ANON_IPS = ["185.220.101.34", "45.148.10.92", "193.218.118.158", "171.25.193.78"]  # TOR / anonymizer exits


def _risk_threat(config, etype, level, *, loc=None, activity="signin", detail="none",
                 source="IdentityProtection", timing="realtime"):
    u = ac.pick_user(config)
    loc = loc or ac.egress(u)
    props = {"id": uuid.uuid4().hex, "correlationId": str(uuid.uuid4()),
             "requestId": str(uuid.uuid4()), "activity": activity,
             "activityDateTime": _ts(-random.randint(30, 300)),
             "detectedDateTime": _ts(-random.randint(5, 60)),
             "ipAddress": loc.get("ip", ""), "riskEventType": etype,
             "riskState": "atRisk", "riskLevel": level, "riskDetail": detail,
             "source": source, "detectionTimingType": timing,
             "userId": ac.user_oid(u["username"]), "userPrincipalName": u["upn"],
             "userDisplayName": u.get("display_name"), "userType": "member",
             "location": {"city": loc.get("city", ""), "state": loc.get("state", ""),
                          "countryOrRegion": loc.get("countryOrRegion", ""),
                          "geoCoordinates": loc.get("geoCoordinates", {})},
             "additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"" + ac.user_agent(u) + "\"}]"}
    return [_envelope("UserRiskEvents", "UserRiskDetection", props, caller_ip=loc.get("ip", ""))]


def _anon_loc():
    return {"ip": random.choice(_ANON_IPS), "city": "", "state": "",
            "countryOrRegion": "US", "geoCoordinates": {}}


def scenario_leaked_credentials(config=None):
    """Identity Protection flagged the user's credentials as leaked (found in a breach/paste dump) ->
    high-risk leakedCredentials detection left unremediated."""
    return _risk_threat(config, "leakedCredentials", "high", detail="none")


def scenario_malicious_ip_signin(config=None):
    """Sign-in from an IP Microsoft threat intelligence flags as malicious -> maliciousIPAddress."""
    return _risk_threat(config, "maliciousIPAddress", "high", loc=ac.rare_asn_loc())


def scenario_anonymous_ip_signin(config=None):
    """Sign-in from an anonymizer / TOR exit -> anonymizedIPAddress risk detection."""
    return _risk_threat(config, "anonymizedIPAddress", "medium", loc=_anon_loc())


def scenario_impossible_travel_risk(config=None):
    """Identity Protection unlikely-travel (impossible travel) risk detection from a foreign network."""
    return _risk_threat(config, "unlikelyTravel", "medium", loc=ac.rare_asn_loc())


def scenario_password_spray_risk(config=None):
    """Identity Protection password-spray risk detection on the account."""
    return _risk_threat(config, "passwordSpray", "medium", loc=ac.rare_asn_loc())


def scenario_new_country_risk(config=None):
    """Sign-in from a country the user (and often the tenant) has not signed in from -> newCountry."""
    return _risk_threat(config, "newCountry", "medium", loc=ac.rare_asn_loc())


def scenario_malware_ip_risk(config=None):
    """Sign-in from an IP in a known malware/botnet network -> malwareInfectedIPAddress."""
    return _risk_threat(config, "malwareInfectedIPAddress", "medium", loc=ac.rare_asn_loc())


def scenario_token_issuer_anomaly_risk(config=None):
    """SAML token issuer anomaly (forged / Golden-SAML-style token) -> tokenIssuerAnomaly (high)."""
    return _risk_threat(config, "tokenIssuerAnomaly", "high", loc=ac.rare_asn_loc())


def scenario_suspicious_browser_risk(config=None):
    """Anomalous browser fingerprint across sign-ins from one session -> suspiciousBrowser."""
    return _risk_threat(config, "suspiciousBrowser", "medium", loc=ac.rare_asn_loc())


def scenario_inbox_manipulation_risk(config=None):
    """Defender for Cloud Apps flagged suspicious inbox-manipulation rules on the mailbox ->
    mcasSuspiciousInboxManipulationRules (source MicrosoftCloudAppSecurity, offline detection)."""
    return _risk_threat(config, "mcasSuspiciousInboxManipulationRules", "medium",
                        activity="user", source="MicrosoftCloudAppSecurity", timing="offline")


def scenario_threat_intel_risk(config=None):
    """Microsoft Threat Intelligence correlated the account/IP with known malicious activity ->
    investigationsThreatIntelligence (high)."""
    return _risk_threat(config, "investigationsThreatIntelligence", "high", loc=ac.rare_asn_loc())


def scenario_anomalous_token_risk(config=None):
    """Token with abnormal lifetime / characteristics (replayed or forged access token) ->
    anomalousToken (high)."""
    return _risk_threat(config, "anomalousToken", "high", loc=ac.rare_asn_loc())


def scenario_unfamiliar_features_risk(config=None):
    """Sign-in with properties unfamiliar for the user (new device/location/ASN pattern) ->
    unfamiliarFeatures."""
    return _risk_threat(config, "unfamiliarFeatures", "medium", loc=ac.rare_asn_loc())


def scenario_admin_confirmed_compromised_risk(config=None):
    """Admin manually confirmed the account compromised in Identity Protection ->
    adminConfirmedUserCompromised (high, offline)."""
    return _risk_threat(config, "adminConfirmedUserCompromised", "high",
                        detail="adminConfirmedUserCompromised", timing="offline")


def scenario_mcas_impossible_travel_risk(config=None):
    """Defender for Cloud Apps impossible-travel detection across two distant sign-ins ->
    mcasImpossibleTravel (source MicrosoftCloudAppSecurity, offline)."""
    return _risk_threat(config, "mcasImpossibleTravel", "medium", loc=ac.rare_asn_loc(),
                        source="MicrosoftCloudAppSecurity", timing="offline")


def scenario_anomalous_user_activity_risk(config=None):
    """Identity Protection correlated abnormal account activity across signals ->
    anomalousUserActivity (high, offline)."""
    return _risk_threat(config, "anomalousUserActivity", "high", activity="user", timing="offline")


def scenario_aitm_token_theft_risk(config=None):
    """Adversary-in-the-middle session/token theft detected on the account ->
    attackerinTheMiddle (high, offline)."""
    return _risk_threat(config, "attackerinTheMiddle", "high", loc=ac.rare_asn_loc(),
                        timing="offline")


def scenario_suspicious_inbox_forwarding_risk(config=None):
    """Defender for Cloud Apps flagged suspicious inbox forwarding on the mailbox ->
    suspiciousInboxForwarding (source MicrosoftCloudAppSecurity, offline)."""
    return _risk_threat(config, "suspiciousInboxForwarding", "medium", activity="user",
                        source="MicrosoftCloudAppSecurity", timing="offline")


def scenario_risky_ip_risk(config=None):
    """Sign-in from an IP with a high volume of failed sign-ins across tenants -> riskyIPAddress."""
    return _risk_threat(config, "riskyIPAddress", "medium", loc=ac.rare_asn_loc())


def scenario_user_reported_suspicious_risk(config=None):
    """User reported a sign-in / MFA prompt as suspicious (fraud report) ->
    userReportedSuspiciousActivity (high, offline)."""
    return _risk_threat(config, "userReportedSuspiciousActivity", "high", activity="user",
                        timing="offline")


def scenario_suspicious_api_traffic_risk(config=None):
    """Anomalous Graph / API traffic from the account (post-compromise automation) ->
    suspiciousAPITraffic (offline)."""
    return _risk_threat(config, "suspiciousAPITraffic", "medium", activity="user",
                        timing="offline")


def scenario_suspicious_sending_patterns_risk(config=None):
    """Defender for Cloud Apps flagged abnormal outbound mail volume/pattern (spam/exfil) ->
    suspiciousSendingPatterns (source MicrosoftCloudAppSecurity, offline)."""
    return _risk_threat(config, "suspiciousSendingPatterns", "medium", activity="user",
                        source="MicrosoftCloudAppSecurity", timing="offline")


def scenario_inbox_manipulation_rules_risk(config=None):
    """Suspicious inbox-manipulation rules (legacy non-MCAS-prefixed variant) ->
    suspiciousInboxManipulationRules (source MicrosoftCloudAppSecurity, offline)."""
    return _risk_threat(config, "suspiciousInboxManipulationRules", "medium", activity="user",
                        source="MicrosoftCloudAppSecurity", timing="offline")


def scenario_generic_risk(config=None):
    """Generic Identity Protection risk detection (unclassified risky activity) -> generic (offline)."""
    return _risk_threat(config, "generic", "low", timing="offline")


# ── ServicePrincipalRiskEvents (workload-identity risk) ───────────────────────────────
# Identity Protection also flags service principals / app registrations, not just users. These land
# as category=ServicePrincipalRiskEvents / Cloud Audit Log (verified 2026-11-23). The record is the
# servicePrincipalRiskDetection resource: servicePrincipalId/servicePrincipalDisplayName/appId in
# place of the user fields, activity "servicePrincipal", no userPrincipalName.
_SP_APPS = ["Reporting Connector", "Mail Archive Utility", "Directory Sync Helper",
            "Invoice Automation App", "Teams Notifier Bot", "SharePoint Backup Agent",
            "Analytics Ingest Worker", "Expense Approval Bot"]


def _sp_identity():
    name = random.choice(_SP_APPS)
    return {"display": name, "spid": ac._stable_guid("sprisk-sp:" + name), "appid": ac.app_id(name)}


def _sp_risk_threat(config, etype, level, *, detail="none", source="IdentityProtection",
                    timing="offline", loc=None):
    sp = _sp_identity()
    loc = loc or ac.rare_asn_loc()
    props = {"id": uuid.uuid4().hex, "requestId": str(uuid.uuid4()),
             "correlationId": str(uuid.uuid4()), "activity": "servicePrincipal",
             "activityDateTime": _ts(-random.randint(30, 300)),
             "detectedDateTime": _ts(-random.randint(5, 60)),
             "ipAddress": loc.get("ip", ""), "riskEventType": etype,
             "riskState": "atRisk", "riskLevel": level, "riskDetail": detail,
             "source": source, "detectionTimingType": timing,
             "servicePrincipalId": sp["spid"], "servicePrincipalDisplayName": sp["display"],
             "appId": sp["appid"], "keyIds": [],
             "location": {"city": loc.get("city", ""), "state": loc.get("state", ""),
                          "countryOrRegion": loc.get("countryOrRegion", ""),
                          "geoCoordinates": loc.get("geoCoordinates", {})},
             "additionalInfo": "[]"}
    return [_envelope("ServicePrincipalRiskEvents", "ServicePrincipalRiskDetection",
                      props, caller_ip=loc.get("ip", ""))]


def scenario_sp_leaked_credentials(config=None):
    """Workload-identity credential (client secret/cert) found leaked -> leakedCredentials (high)."""
    return _sp_risk_threat(config, "leakedCredentials", "high")


def scenario_sp_malicious_application(config=None):
    """App flagged malicious by Microsoft (disabled) -> maliciousApplication (high)."""
    return _sp_risk_threat(config, "maliciousApplication", "high")


def scenario_sp_suspicious_signins(config=None):
    """Anomalous service-principal sign-in pattern -> suspiciousSignins (medium)."""
    return _sp_risk_threat(config, "suspiciousSignins", "medium")


def scenario_sp_anomalous_activity(config=None):
    """Abnormal service-principal behaviour across signals -> anomalousServicePrincipalActivity."""
    return _sp_risk_threat(config, "anomalousServicePrincipalActivity", "high")


def scenario_sp_admin_confirmed_compromised(config=None):
    """Admin confirmed the workload identity compromised ->
    adminConfirmedServicePrincipalCompromised (high)."""
    return _sp_risk_threat(config, "adminConfirmedServicePrincipalCompromised", "high",
                           detail="adminConfirmedServicePrincipalCompromised")


def scenario_sp_threat_intel(config=None):
    """Microsoft threat intelligence correlated the workload identity with malicious activity ->
    investigationsThreatIntelligence (high)."""
    return _sp_risk_threat(config, "investigationsThreatIntelligence", "high")


# Every scenario in this module is WIP and is exposed ONLY under its wip_ key: the Entra Identity
# Protection risk detectors are prerequisite-gated (see the ANALYTIC_ALERTS note below), so none has
# a confirmed fire -> alert yet. A scenario graduates to a plain (non-wip_) key here only once a
# working, verified analytics rule OR a correlation rule has fired on it in the tenant.
SCENARIOS = {
    "wip_leaked_credentials": scenario_leaked_credentials,
    "wip_malicious_ip_signin": scenario_malicious_ip_signin,
    "wip_anonymous_ip_signin": scenario_anonymous_ip_signin,
    "wip_impossible_travel_risk": scenario_impossible_travel_risk,
    "wip_password_spray_risk": scenario_password_spray_risk,
    "wip_new_country_risk": scenario_new_country_risk,
    "wip_malware_ip_risk": scenario_malware_ip_risk,
    "wip_token_issuer_anomaly_risk": scenario_token_issuer_anomaly_risk,
    "wip_suspicious_browser_risk": scenario_suspicious_browser_risk,
    "wip_inbox_manipulation_risk": scenario_inbox_manipulation_risk,
    "wip_threat_intel_risk": scenario_threat_intel_risk,
    "wip_anomalous_token_risk": scenario_anomalous_token_risk,
    "wip_unfamiliar_features_risk": scenario_unfamiliar_features_risk,
    "wip_admin_confirmed_compromised_risk": scenario_admin_confirmed_compromised_risk,
    "wip_mcas_impossible_travel_risk": scenario_mcas_impossible_travel_risk,
    "wip_anomalous_user_activity_risk": scenario_anomalous_user_activity_risk,
    "wip_aitm_token_theft_risk": scenario_aitm_token_theft_risk,
    "wip_suspicious_inbox_forwarding_risk": scenario_suspicious_inbox_forwarding_risk,
    "wip_risky_ip_risk": scenario_risky_ip_risk,
    "wip_user_reported_suspicious_risk": scenario_user_reported_suspicious_risk,
    "wip_suspicious_api_traffic_risk": scenario_suspicious_api_traffic_risk,
    "wip_suspicious_sending_patterns_risk": scenario_suspicious_sending_patterns_risk,
    "wip_inbox_manipulation_rules_risk": scenario_inbox_manipulation_rules_risk,
    "wip_generic_risk": scenario_generic_risk,
    # ServicePrincipalRiskEvents (workload-identity risk).
    "wip_sp_leaked_credentials": scenario_sp_leaked_credentials,
    "wip_sp_malicious_application": scenario_sp_malicious_application,
    "wip_sp_suspicious_signins": scenario_sp_suspicious_signins,
    "wip_sp_anomalous_activity": scenario_sp_anomalous_activity,
    "wip_sp_admin_confirmed_compromised": scenario_sp_admin_confirmed_compromised,
    "wip_sp_threat_intel": scenario_sp_threat_intel,
}

# WIP / prerequisite-gated. The records are field-correct and ingest into msft_azure_raw as
# category=UserRiskEvents / Cloud Audit Log with riskEventType/riskLevel/riskState parsed (verified
# 2026-11-19), but Entra Identity Protection risk detectors are Cortex Identity Analytics detections
# that need Identity Analytics enabled + the Cloud Identity Engine + a multi-day baseline, so a
# synthetic one-shot raises no standalone alert (confirmed no-fire 2026-11-19, same class as the
# sign-in cred-attack family). Names are provisional until a fire -> alert is observed. See
# [[azure-cred-attack-identity-analytics]].
ANALYTIC_ALERTS = {
    "wip_leaked_credentials": "Azure AD leaked credentials risk detection",
    "wip_malicious_ip_signin": "Azure AD sign-in from a malicious IP address",
    "wip_anonymous_ip_signin": "Azure AD sign-in from an anonymized IP address",
    "wip_impossible_travel_risk": "Azure AD impossible travel risk detection",
    "wip_password_spray_risk": "Azure AD password spray risk detection",
    "wip_new_country_risk": "Azure AD sign-in from a new country",
    "wip_malware_ip_risk": "Azure AD sign-in from a malware-linked IP address",
    "wip_token_issuer_anomaly_risk": "Azure AD token issuer anomaly",
    "wip_suspicious_browser_risk": "Azure AD suspicious browser risk detection",
    "wip_inbox_manipulation_risk": "Azure AD suspicious inbox manipulation rules",
    "wip_threat_intel_risk": "Azure AD threat intelligence risk detection",
    "wip_anomalous_token_risk": "Azure AD anomalous token risk detection",
    "wip_unfamiliar_features_risk": "Azure AD unfamiliar sign-in properties",
    "wip_admin_confirmed_compromised_risk": "Azure AD admin confirmed user compromised",
    "wip_mcas_impossible_travel_risk": "Azure AD impossible travel (Defender for Cloud Apps)",
    "wip_anomalous_user_activity_risk": "Azure AD anomalous user activity",
    "wip_aitm_token_theft_risk": "Azure AD adversary-in-the-middle token theft",
    "wip_suspicious_inbox_forwarding_risk": "Azure AD suspicious inbox forwarding",
    "wip_risky_ip_risk": "Azure AD sign-in from a risky IP address",
    "wip_user_reported_suspicious_risk": "Azure AD user-reported suspicious activity",
    "wip_suspicious_api_traffic_risk": "Azure AD suspicious API traffic",
    "wip_suspicious_sending_patterns_risk": "Azure AD suspicious sending patterns",
    "wip_inbox_manipulation_rules_risk": "Azure AD suspicious inbox manipulation rules (legacy)",
    "wip_generic_risk": "Azure AD generic risk detection",
    "wip_sp_leaked_credentials": "Azure AD workload identity leaked credentials",
    "wip_sp_malicious_application": "Azure AD malicious application detected",
    "wip_sp_suspicious_signins": "Azure AD workload identity suspicious sign-ins",
    "wip_sp_anomalous_activity": "Azure AD anomalous service principal activity",
    "wip_sp_admin_confirmed_compromised": "Azure AD admin confirmed service principal compromised",
    "wip_sp_threat_intel": "Azure AD workload identity threat intelligence risk",
}


def get_threat_names():
    return list(SCENARIOS)


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    if scenario_event:
        key = scenario_event if scenario_event in SCENARIOS else str(scenario_event).lower()
        return (SCENARIOS[key](config), key) if key in SCENARIOS else None
    return generate_benign(config, context)
