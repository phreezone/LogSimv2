"""Office 365 DLP audit (O365 Management Activity, Audit.DLP RecordType 11)
-> msft_o365_dlp_raw, via the cribl_direct transport (dedicated UUID).

Built from the Management Activity DLP schema (the tenant has no DLP policies, so no live
rows to sample): DLPRuleMatch records carry PolicyDetails[{PolicyName, Rules[{RuleName,
Actions, Severity, ConditionsMatched.SensitiveInformation[{SensitiveInformationTypeName,
Count, Confidence}]}]}] plus workload metadata (ExchangeMetaData for mail, SharePointMetaData
for files).

Benign baseline = low-severity notify-only matches (routine false positives). Scenarios target
DLP exfiltration: high-severity PII/PCI matches with BlockAccess on outbound mail/files, and
bursts of matches (mass sensitive-data movement).
"""
import random
import time
import uuid

from modules import azure_common as ac

NAME = "Office 365 DLP"
DESCRIPTION = "Simulates Office 365 DLP rule-match records for msft_o365_dlp_raw via the cribl_direct transport."
CONFIG_KEY = "o365_dlp_config"
SOURCE_IDENTIFIER = "8f052782739d4b8389644cca23b994ac"
INTEGRATION_IDENTIFIER = "logsim:o365_dlp"
DATASET = "msft_o365_dlp_raw"
ORG_ID = "09febfec-25f3-48fa-bd8c-9b4a44f896ec"
SP_HOST = "examplecorp.sharepoint.com"

_EXT_DOMAINS = ["gmail.com", "proton.me", "partner-co.com", "outlook.com"]
_SIT = ["Credit Card Number", "U.S. Social Security Number (SSN)", "U.S. Bank Account Number",
        "ABA Routing Number", "U.S. / U.K. Passport Number", "U.S. Individual Taxpayer Identification Number (ITIN)"]
_POLICIES = {"U.S. PII": ["U.S. SSN", "U.S. ITIN"], "PCI DSS": ["Credit Card"],
             "Financial Data": ["Bank Account", "ABA Routing"], "GDPR": ["EU Passport"]}
_DOCS = ["Customer List.xlsx", "Payroll.xlsx", "Cardholder Data.csv", "Patient Records.xlsx"]
_THREAT_PROB = {"Benign Traffic Only": 0.0, "Low": 0.02, "Realistic": 0.05,
                "Medium": 0.08, "High": 0.12, "Insane": 0.30}


def _g():
    return str(uuid.uuid4())


def _now(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + offset_s))


def _policy_details(policy, rule, sits, severity, actions, count):
    return [{"PolicyId": ac._stable_guid("dlppol:" + policy), "PolicyName": policy,
             "Rules": [{"RuleId": ac._stable_guid("dlprule:" + rule), "RuleName": rule,
                        "Severity": severity, "Actions": actions,
                        "ConditionsMatched": {"SensitiveInformation": [
                            {"SensitiveInformationTypeName": s, "Count": count,
                             "Confidence": random.choice([75, 85, 95])} for s in sits]}}]}]


def _dlp(user, workload, policy, rule, sits, severity, actions, count, offset_s=0):
    r = {"CreationTime": _now(offset_s), "Id": _g(), "Operation": "DLPRuleMatch",
         "OrganizationId": ORG_ID, "RecordType": 11, "UserType": 0, "Version": 1,
         "Workload": workload, "UserId": user["upn"], "UserKey": ac.user_oid(user["username"]),
         "ClientIP": ac.egress(user)["ip"], "SensitiveInfoDetectionIsIncluded": True,
         "PolicyDetails": _policy_details(policy, rule, sits, severity, actions, count)}
    if workload == "Exchange":
        r["ExchangeMetaData"] = {"MessageID": f"<{_g()}@{ac.UPN_DOMAIN}>", "From": user["upn"],
                                 "To": [f"ext@{random.choice(_EXT_DOMAINS)}"],
                                 "Subject": random.choice(["Report", "Files", "FYI", "Data export"]),
                                 "Sent": _now(offset_s)}
    else:
        doc = random.choice(_DOCS)
        r["SharePointMetaData"] = {"From": user["upn"], "FileName": doc, "DocumentId": _g(),
                                   "FilePathUrl": f"https://{SP_HOST}/sites/Finance/Shared Documents/{doc}"}
    return r


def generate_benign(config=None, context=None):
    """Routine low-severity notify-only match (false positive / policy tip)."""
    u = ac.pick_user(config, context)
    pol = random.choice(list(_POLICIES))
    wl = "Exchange" if random.random() < 0.6 else "SharePoint"
    return [_dlp(u, wl, pol, f"{pol} - Low", random.sample(_SIT, 1), "Low",
                 ["GenerateIncidentReport", "NotifyUser"], random.randint(1, 2))]


def scenario_dlp_exfil_block(config=None):
    """High-severity PII/PCI match with BlockAccess on outbound mail -> data exfiltration blocked by DLP."""
    u = ac.pick_user(config)
    pol = random.choice(["U.S. PII", "PCI DSS", "Financial Data"])
    return [_dlp(u, "Exchange", pol, f"{pol} - High volume", random.sample(_SIT, 2), "High",
                 ["BlockAccess", "GenerateIncidentReport", "NotifyUser"], random.randint(25, 200))]


def scenario_dlp_sharepoint_block(config=None):
    """High-severity sensitive-data match on a shared file -> DLP block on SharePoint/OneDrive."""
    u = ac.pick_user(config)
    return [_dlp(u, "SharePoint", "PCI DSS", "Cardholder Data - High", random.sample(_SIT, 2),
                 "High", ["BlockAccess", "GenerateIncidentReport"], random.randint(50, 500))]


def scenario_dlp_match_burst(config=None, count=15):
    """Many DLP matches in a short window for one user -> mass sensitive-data movement."""
    u = ac.pick_user(config)
    return [_dlp(u, random.choice(["Exchange", "SharePoint"]), "U.S. PII", "U.S. PII - Medium",
                 random.sample(_SIT, 1), "Medium", ["GenerateIncidentReport", "NotifyUser"],
                 random.randint(5, 30), offset_s=-(count - i) * 4) for i in range(count)]


SCENARIOS = {
    "dlp_exfil_block": scenario_dlp_exfil_block,
    "dlp_sharepoint_block": scenario_dlp_sharepoint_block,
    "dlp_match_burst": scenario_dlp_match_burst,
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
