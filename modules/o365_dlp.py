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
from modules import o365_sharepoint as spo

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
# Programmatic sensitive-filename generator (unbounded, realistic) — e.g. "Payroll Register 2026 Q3.xlsx".
_SENS_SUBJECT = ["Customer List", "Payroll", "Payroll Register", "Cardholder Data", "Patient Records",
                 "Employee SSNs", "Bank Details", "Tax Forms W2", "Credit Applications", "Insurance Claims",
                 "Vendor Banking", "HR Compensation", "Member PII", "Passport Scans", "Loan Applications",
                 "Benefits Enrollment", "Account Numbers", "Wire Instructions", "Salary Data", "Medical Records",
                 "Background Checks", "Direct Deposit", "Credit Card Export", "Donor List", "Student Records",
                 "Claimant Data", "Beneficiary List", "KYC Documents", "Investor Statements", "Tax Returns"]
_SENS_QUAL = ["", "", " Export", " Backup", " Master", " 2024", " 2025", " 2026", " Q1", " Q2", " Q3", " Q4",
              " Full", " Confidential", " - DO NOT SHARE", " copy", " (1)", " final"]
_SENS_EXT = ["xlsx", "xlsx", "csv", "csv", "pdf", "xls", "txt", "zip"]


def _sensitive_name(rnd=None):
    r = rnd or random
    return f"{r.choice(_SENS_SUBJECT)}{r.choice(_SENS_QUAL)}.{r.choice(_SENS_EXT)}"


_SIT = ["Credit Card Number", "U.S. Social Security Number (SSN)", "U.S. Bank Account Number",
        "ABA Routing Number", "U.S. / U.K. Passport Number", "U.S. Individual Taxpayer Identification Number (ITIN)"]
_POLICIES = {"U.S. PII": ["U.S. SSN", "U.S. ITIN"], "PCI DSS": ["Credit Card"],
             "Financial Data": ["Bank Account", "ABA Routing"], "GDPR": ["EU Passport"]}
# Threat rate governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (see _GATE below).


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


def _dlp(user, workload, policy, rule, sits, severity, actions, count, offset_s=0,
         operation="DLPRuleMatch", override=None):
    r = {"CreationTime": _now(offset_s), "Id": _g(), "Operation": operation,
         "OrganizationId": ORG_ID, "RecordType": 11, "UserType": 0, "Version": 1,
         "Workload": workload, "UserId": user["upn"], "UserKey": ac.user_oid(user["username"]),
         "ClientIP": ac.egress(user)["ip"], "SensitiveInfoDetectionIsIncluded": True,
         "PolicyDetails": _policy_details(policy, rule, sits, severity, actions, count)}
    if override:
        # User overrode a block or reported a false positive (OverrideInfo in the DLP schema).
        r["PolicyDetails"][0]["Rules"][0]["OverrideInfo"] = {
            "Reason": override, "Justification": {
                "FalsePositive": "This file does not contain sensitive data.",
                "Override": "I have business approval to send this.",
                "ReportFalsePositiveAndOverride": "Reported and overridden with manager approval.",
            }[override]}
    if workload == "Exchange":
        n_to = random.choices([1, 1, 2, 3], weights=[60, 20, 15, 5])[0]
        r["ExchangeMetaData"] = {"MessageID": f"<{_g()}@{ac.UPN_DOMAIN}>", "From": user["upn"],
                                 "To": [ac.external_email() for _ in range(n_to)],
                                 "Subject": ac.email_subject(external=True), "Sent": _now(offset_s)}
    else:
        f = spo.path_for_filename(random, _sensitive_name())
        r["SharePointMetaData"] = {"From": user["upn"], "FileName": f["filename"],
                                   "DocumentId": ac._stable_guid("item:" + f["host"] + f["rel"]),
                                   "FilePathUrl": f'https://{f["host"]}{f["rel"]}'}
    return r


def generate_benign(config=None, context=None):
    """Routine DLP outcomes: low-severity notify-only matches, policy tips, user overrides with
    justification, false-positive reports, and undo events — the everyday DLP outcome spread."""
    u = ac.pick_user(config, context)
    pol = random.choice(list(_POLICIES))
    wl = "Exchange" if random.random() < 0.6 else "SharePoint"
    r = random.random()
    if r < 0.55:   # low-severity notify-only match (policy tip / routine false positive)
        return [_dlp(u, wl, pol, f"{pol} - Low", random.sample(_SIT, 1), "Low",
                     ["GenerateIncidentReport", "NotifyUser"], random.randint(1, 2))]
    if r < 0.72:   # DLPInfo — policy tip shown to the user, no enforcement
        return [_dlp(u, wl, pol, f"{pol} - Notify", random.sample(_SIT, 1), "Low",
                     ["NotifyUser"], random.randint(1, 2), operation="DLPInfo")]
    if r < 0.86:   # user overrode a block with a business justification
        return [_dlp(u, wl, pol, f"{pol} - Medium", random.sample(_SIT, 1), "Medium",
                     ["BlockAccess", "NotifyUser"], random.randint(1, 4),
                     override=random.choice(["Override", "ReportFalsePositiveAndOverride"]))]
    if r < 0.94:   # user reported a false positive
        return [_dlp(u, wl, pol, f"{pol} - Low", random.sample(_SIT, 1), "Low",
                     ["NotifyUser"], 1, override="FalsePositive")]
    # DLPRuleUndo — a previously enforced action was undone (e.g., policy retuned, item released)
    return [_dlp(u, wl, pol, f"{pol} - Low", random.sample(_SIT, 1), "Low",
                 ["GenerateIncidentReport"], random.randint(1, 2), operation="DLPRuleUndo")]


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
