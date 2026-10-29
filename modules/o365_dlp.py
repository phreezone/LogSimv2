"""Office 365 DLP audit (O365 Management Activity, Audit.DLP; RecordType 13 = ComplianceDLPExchange
for mail, RecordType 11 = DLPSharePoint for files)
-> msft_o365_dlp_raw, via the cribl_direct transport (dedicated UUID).

Schema verified against https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
(the "DLP schema" section): DLPRuleMatch records carry PolicyDetails[{PolicyId, PolicyName,
Rules[{RuleId, RuleName, RuleMode (Enforce / Audit with Notify / Audit only), Actions, Severity,
ConditionsMatched.SensitiveInformation[{SensitiveType: <GUID>, SensitiveInformationTypeName,
Count, UniqueCount, Confidence: int 0-100}]}]}] plus workload metadata (ExchangeMetaData for
mail, SharePointMetaData for files) and a top-level ExceptionInfo (override/false-positive).
The SensitiveType GUIDs and SensitiveInformationTypeName names are the REAL published pairs
from each SIT's entity definition page (see _SIT_GUID below). Confidence levels map
High=85, Medium=75, Low<=65 per the SIT entity-definitions overview.

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

# Official Microsoft Sensitive Information Type entity GUIDs, extracted from the <Entity id="...">
# rule XML in each SIT's entity definition page on learn.microsoft.com (verified 2026-10):
# - sit-defn-credit-card-number                       -> 50842eb7-edc8-4019-85dd-5a5c1f2bb085
# - sit-defn-us-social-security-number                -> a44669fe-0d48-453d-a9b1-2cc83f2cba77
# - sit-defn-us-bank-account-number                   -> a2ce32a8-f935-4bb6-8e96-2a5157672e2c
# - sit-defn-aba-routing                              -> cb353f78-2b72-4c3c-8827-92ebe4f69fdf
# - sit-defn-us-individual-taxpayer-identification-number -> e55e2a32-f92d-4985-a35d-a0b269eb687b
# - sit-defn-us-uk-passport-number                    -> 178ec42a-18b4-47cc-85c7-d62c92fd67f8
# Names use the official entity-definition titles.
_SIT = ["Credit card number", "U.S. social security number (SSN)", "U.S. bank account number",
        "ABA Routing Number", "U.S. individual taxpayer identification number (ITIN)",
        "U.S./U.K. passport number"]
_SIT_GUID = {"Credit card number": "50842eb7-edc8-4019-85dd-5a5c1f2bb085",
             "U.S. social security number (SSN)": "a44669fe-0d48-453d-a9b1-2cc83f2cba77",
             "U.S. bank account number": "a2ce32a8-f935-4bb6-8e96-2a5157672e2c",
             "ABA Routing Number": "cb353f78-2b72-4c3c-8827-92ebe4f69fdf",
             "U.S. individual taxpayer identification number (ITIN)": "e55e2a32-f92d-4985-a35d-a0b269eb687b",
             "U.S./U.K. passport number": "178ec42a-18b4-47cc-85c7-d62c92fd67f8"}
# Documented built-in DLP policy template names could not be re-verified against a live docs page
# (the template-reference page no longer exists); these are kept as plausibly custom tenant
# policies whose names mirror the classic built-in template family.
_POLICIES = {"U.S. PII Data": ["U.S. social security number (SSN)",
                               "U.S. individual taxpayer identification number (ITIN)"],
             "U.S. Financial Data": ["U.S. bank account number", "ABA Routing Number"],
             "PCI DSS": ["Credit card number"],
             "U.S. State Breach Notification Laws": ["U.S. social security number (SSN)",
                                                     "U.S./U.K. passport number"]}
# Documented confidence levels map High=85, Medium=75, Low<=65
# (https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-entity-definitions).
_CONF_BY_SEVERITY = {"High": 85, "Medium": 75, "Low": 65}
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


# Threat rate governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (see _GATE below).


# Real-form Microsoft Sensitive Information Type GUIDs are defined in _SIT_GUID above.


def _g():
    return str(uuid.uuid4())


def _now(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + offset_s))


def _policy_details(policy, rules_meta, count):
    """PolicyDetails per the Rules / ConditionsMatched / SensitiveInformation complex types of
    https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema :
    SensitiveInformation entries carry SensitiveType (GUID), SensitiveInformationTypeName (string),
    Count, UniqueCount and Confidence (int 0-100; High=85, Medium=75, Low=65 per the docs)."""
    rm = rules_meta
    conf = _CONF_BY_SEVERITY.get(rm["severity"], 75)
    return [{"PolicyId": ac._stable_guid("dlppol:" + policy), "PolicyName": policy,
             "Rules": [{"RuleId": ac._stable_guid("dlprule:" + rm["rule"]), "RuleName": rm["rule"],
                        "RuleMode": rm["mode"], "Severity": rm["severity"],
                        "Actions": rm["actions"],
                        "ConditionsMatched": {"SensitiveInformation": [
                            {"SensitiveType": _SIT_GUID[s], "Count": count, "UniqueCount": max(1, count // 3),
                             "Confidence": conf, "SensitiveInformationTypeName": s}
                            for s in rm["sits"]]}}]}]


_EXCEPTION_JUST = {
    "Override": "I have business approval to send this.",
    "ReportFalsePositiveAndOverride": "Reported and overridden with manager approval.",
    "FalsePositive": "This file does not contain sensitive data.",
}


def _exception_info(reason, justification=None, rules=None, false_positive=False):
    """ExceptionInfo complex type: Reason (Override | Document Change | Policy Change),
    FalsePositive flag, Justification text, Rules (collection of rule GUIDs)."""
    return {"Reason": reason, "FalsePositive": false_positive,
            "Justification": justification if justification is not None else _EXCEPTION_JUST.get(reason, ""),
            "Rules": rules if rules is not None else []}


def _dlp(user, workload, policy, rule, sits, severity, actions, count, offset_s=0,
         operation="DlpRuleMatch", exception=None, rule_mode="Enforce", exposed=False):
    """Build one DLP audit record. RecordType 13 = ComplianceDLPExchange for mail,
    RecordType 11 = ComplianceDLPSharePoint (DLPSharePoint) for SharePoint/OneDrive records.
    RuleMode documented values: Enforce, Audit with Notify, Audit only."""
    r = {"CreationTime": _now(offset_s), "Id": _g(), "Operation": operation,
         "OrganizationId": ORG_ID,
         "RecordType": 13 if workload == "Exchange" else 11,
         "UserType": 0, "Version": 1, "Workload": workload,
         "UserId": user["upn"], "UserKey": "DlpAgent",      # DLP records: actor is the DLP agent
         "ClientIP": ac.egress(user)["ip"], "SensitiveInfoDetectionIsIncluded": True,
         "PolicyDetails": _policy_details(policy, {"rule": rule, "mode": rule_mode,
                                                   "severity": severity, "actions": actions,
                                                   "sits": sits}, count)}
    if exception:
        # User overrode a block or reported a false positive — ExceptionInfo (complex type:
        # Reason / FalsePositive / Justification / Rules) is a TOP-LEVEL property in the DLP
        # schema (not nested under the rule).
        fp = exception == "FalsePositive"
        info = _exception_info("Override", false_positive=fp,
                               justification=_EXCEPTION_JUST[exception])
        if fp:
            # For a false-positive designation Reason is not "Override"; drop it (the schema
            # marks Reason optional; it's documented for override / DLPRuleUndo cases).
            del info["Reason"]
        r["ExceptionInfo"] = info
    if workload == "Exchange":
        n_to = random.choices([1, 1, 2, 3], weights=[60, 20, 15, 5])[0]
        to = [ac.external_email() for _ in range(n_to)]
        r["ExchangeMetaData"] = {"MessageID": f"<{_g()}@{ac.UPN_DOMAIN}>", "From": user["upn"],
                                 "To": to, "Subject": ac.email_subject(external=True),
                                 "Sent": _now(offset_s), "RecipientCount": len(to) + 1}
    else:
        f = spo.path_for_filename(random, _sensitive_name())
        ts = _now(-86400 * 30)
        r["SharePointMetaData"] = {
            "From": user["upn"],
            "FileOwner": user["upn"],
            "DocumentLastModifier": user["upn"],
            "DocumentSharer": user["upn"],
            "FileName": f["filename"],
            "FileExtension": (f["filename"].rsplit(".", 1)[-1] if "." in f["filename"] else ""),
            "FilePathUrl": f'https://{f["host"]}{f["rel"]}',
            "FullPath": f'https://{f["host"]}{f["dir"]}/{f["filename"]}',
            "SiteCollectionGuid": ac._stable_guid("site:" + f["sitepath"]),
            "SiteCollectionUrl": f'https://{f["host"]}{f["sitepath"]}/',
            "UniqueId": ac._stable_guid("item:" + f["host"] + f["rel"]),
            "ItemId": ac._stable_guid("item:" + f["host"] + f["rel"]),
            "IsViewableByExternalUsers": exposed,
            "itemCreationTime": ts,
            "LastModifiedTime": ts,
            "ItemSize": random.randint(20_000, 4_000_000)}
    return r


def generate_benign(config=None, context=None):
    """Routine DLP outcomes: low-severity notify-only matches, policy tips, user overrides with
    justification, false-positive reports, and undo events — the everyday DLP outcome spread.
    Note: DlpRuleUndo is SharePoint-only, and InfoMode/Alert records carry RuleMode."""
    u = ac.pick_user(config, context)
    pol = random.choice(list(_POLICIES))
    wl = "Exchange" if random.random() < 0.6 else "SharePoint"
    r = random.random()
    if r < 0.55:   # low-severity notify-only match (policy tip / routine false positive)
        return [_dlp(u, wl, pol, f"{pol} - Low", random.sample(_SIT, 1), "Low",
                     ["GenerateIncidentReport", "NotifyUser"], random.randint(1, 2))]
    if r < 0.72:   # DlpInfo — policy tip shown to the user, no enforcement (audit-only rule)
        return [_dlp(u, wl, pol, f"{pol} - Notify", random.sample(_SIT, 1), "Low",
                     ["NotifyUser"], random.randint(1, 2), operation="DlpInfo",
                     rule_mode="Audit with Notify")]
    if r < 0.86:   # user overrode a block with a business justification
        return [_dlp(u, wl, pol, f"{pol} - Medium", random.sample(_SIT, 1), "Medium",
                     ["BlockAccess", "NotifyUser"], random.randint(1, 4),
                     exception=random.choice(["Override", "ReportFalsePositiveAndOverride"]))]
    if r < 0.94:   # user reported a false positive
        return [_dlp(u, wl, pol, f"{pol} - Low", random.sample(_SIT, 1), "Low",
                     ["NotifyUser"], 1, exception="FalsePositive")]
    # DlpRuleUndo — a previously enforced action was undone (SharePoint workload only)
    return [_dlp(u, "SharePoint", pol, f"{pol} - Low", random.sample(_SIT, 1), "Low",
                 ["GenerateIncidentReport"], random.randint(1, 2), operation="DlpRuleUndo")]


def scenario_dlp_exfil_block(config=None):
    """High-severity PII/PCI match with BlockAccess on outbound mail (Exchange: RecordType 13)
    -> data exfiltration blocked by DLP."""
    u = ac.pick_user(config)
    pol = random.choice(["U.S. PII Data", "PCI DSS", "U.S. Financial Data"])
    return [_dlp(u, "Exchange", pol, f"{pol} - High volume", random.sample(_SIT, 2), "High",
                 ["BlockAccess", "GenerateIncidentReport", "NotifyUser"], random.randint(25, 200),
                 rule_mode="Enforce")]


def scenario_dlp_sharepoint_block(config=None):
    """High-severity sensitive-data match on a file (SharePoint: RecordType 11) -> DLP block."""
    u = ac.pick_user(config)
    return [_dlp(u, "SharePoint", "PCI DSS", "Cardholder Data - High", random.sample(_SIT, 2),
                 "High", ["BlockAccess", "GenerateIncidentReport"], random.randint(50, 500),
                 rule_mode="Enforce")]


def scenario_dlp_sensitive_external(config=None):
    """Sensitive data (DLP match) shared/sent to EXTERNAL recipients -> 'DLP sensitive data exposed
    to external users'. SharePoint file shared externally, high severity, viewable externally."""
    u = ac.pick_user(config)
    return [_dlp(u, "SharePoint", random.choice(["U.S. PII Data", "PCI DSS", "U.S. Financial Data"]),
                 "Sensitive data shared externally", random.sample(_SIT, 2), "High",
                 ["GenerateIncidentReport", "NotifyUser"], random.randint(10, 60),
                 exposed=True)]


def scenario_dlp_match_burst(config=None, count=15):
    """Many DLP matches in a short window for one user -> mass sensitive-data movement."""
    u = ac.pick_user(config)
    return [_dlp(u, random.choice(["Exchange", "SharePoint"]), "U.S. PII Data", "U.S. PII Data - Medium",
                 random.sample(_SIT, 1), "Medium", ["GenerateIncidentReport", "NotifyUser"],
                 random.randint(5, 30), offset_s=-(count - i) * 4) for i in range(count)]


def scenario_dlp_undo_after_block(config=None):
    """A high-severity BlockAccess match on a SharePoint file is then UNDONE
    (DlpRuleUndo — a previously enforced action was undone; documented in the
    Management Activity schema, DLP schema section:
    https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema —
    the only DLP operations are DlpInfo / DlpRuleMatch / DlpRuleUndo; candidates like
    'DlpSensitiveContentExchanged' are not documented and are NOT emitted)
    -> suspicious enforcement rollback (potential DLP evasion)."""
    u = ac.pick_user(config)
    block = _dlp(u, "SharePoint", "U.S. PII Data", "U.S. PII Data - High", random.sample(_SIT, 2),
                 "High", ["BlockAccess", "GenerateIncidentReport"], random.randint(40, 300),
                 rule_mode="Enforce", offset_s=-120)
    undo = _dlp(u, "SharePoint", "U.S. PII Data", "U.S. PII Data - High", random.sample(_SIT, 2),
                "High", ["BlockAccess"], random.randint(40, 300), operation="DlpRuleUndo",
                rule_mode="Enforce", offset_s=0)
    return [block, undo]


SCENARIOS = {
    "dlp_exfil_block": scenario_dlp_exfil_block,
    "dlp_sharepoint_block": scenario_dlp_sharepoint_block,
    "dlp_match_burst": scenario_dlp_match_burst,
    "dlp_sensitive_external": scenario_dlp_sensitive_external,
    "dlp_undo_after_block": scenario_dlp_undo_after_block,
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
