"""Office 365 General audit (O365 Management Activity catch-all workloads)
-> msft_o365_general_raw, via the cribl_direct transport (dedicated UUID).

Covers the miscellaneous M365 workloads that land in the General feed. Field set verified
against a real tenant row for Copilot (RecordType 261, Workload "Copilot", CopilotEventData /
CopilotLogVersion / AppIdentity). Also emits Power BI (RecordType 20) view/export activity.

Benign baseline = Copilot interactions and Power BI report/dashboard views. Detection scenario:
Power BI mass report export (data exfiltration via BI export).
"""
import random
import time
import uuid

from modules import azure_common as ac

NAME = "Office 365 General"
DESCRIPTION = "Simulates Office 365 General workload audit records (Copilot, Power BI) for msft_o365_general_raw via the cribl_direct transport."
CONFIG_KEY = "o365_general_config"
SOURCE_IDENTIFIER = "c7655e83805b4a058e66043a6715156c"
INTEGRATION_IDENTIFIER = "logsim:o365_general"
DATASET = "msft_o365_general_raw"
ORG_ID = "09febfec-25f3-48fa-bd8c-9b4a44f896ec"

_COPILOT_HOSTS = ["Microsoft Teams", "Word", "Outlook", "Excel", "PowerPoint", "Microsoft365Chat"]
_PBI_REPORTS = ["Sales Pipeline", "Revenue Dashboard", "Customer 360", "Exec KPIs",
                "Support Metrics", "Finance Actuals", "Churn Analysis"]
_WORKSPACES = ["Sales Analytics", "Finance", "Exec", "Customer Success"]
_THREAT_PROB = {"Benign Traffic Only": 0.0, "Low": 0.02, "Realistic": 0.05,
                "Medium": 0.08, "High": 0.12, "Insane": 0.30}


def _g():
    return str(uuid.uuid4())


def _now(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + offset_s))


def _base(operation, user, record_type, workload, offset_s=0):
    return {"CreationTime": _now(offset_s), "Id": _g(), "Operation": operation,
            "OrganizationId": ORG_ID, "RecordType": record_type, "UserType": 0, "Version": 1,
            "Workload": workload, "UserId": user["upn"], "UserKey": ac.user_oid(user["username"]),
            "ClientIP": ac.egress(user)["ip"]}


def _copilot(user, offset_s=0):
    host = random.choice(_COPILOT_HOSTS)
    r = _base("CopilotInteraction", user, 261, "Copilot", offset_s)
    r.update({"CopilotLogVersion": "1.0", "AppIdentity": host,
              "CopilotEventData": {"AppHost": host, "ThreadId": _g(),
                                   "Contexts": [{"Id": _g(), "Type": random.choice(
                                       ["TeamsMeeting", "File", "Email", "Chat"])}],
                                   "MessageIds": [_g()], "AISystemPlugin": []}})
    return r


def _powerbi(user, operation, report=None, offset_s=0):
    report = report or random.choice(_PBI_REPORTS)
    r = _base(operation, user, 20, "PowerBI", offset_s)
    r.update({"ObjectId": report, "ArtifactName": report, "ArtifactId": ac._stable_guid("pbi:" + report),
              "WorkSpaceName": random.choice(_WORKSPACES),
              "WorkspaceId": ac._stable_guid("pbiws"), "DatasetName": report + " Dataset",
              "IsSuccess": True})
    return r


def generate_benign(config=None, context=None):
    u = ac.pick_user(config, context)
    if random.random() > ac.activity_weight():
        return [_copilot(u)]   # Copilot/BI usage is human-driven; keep light off-hours
    if random.random() < 0.55:
        return [_copilot(u)]
    return [_powerbi(u, random.choice(["ViewReport", "ViewDashboard", "ViewTile"]))]


def scenario_powerbi_mass_export(config=None, count=25):
    """Many Power BI report exports in a short window -> data exfiltration via BI export."""
    u = ac.pick_user(config)
    return [_powerbi(u, random.choice(["ExportReport", "ExportTile", "ExportArtifact"]),
                     report=random.choice(_PBI_REPORTS), offset_s=-(count - i) * 3)
            for i in range(count)]


def scenario_powerbi_print_bulk(config=None, count=12):
    """Bulk Power BI print/export of exec/finance reports -> sensitive report harvesting."""
    u = ac.pick_user(config)
    return [_powerbi(u, "PrintReport", report=random.choice(["Exec KPIs", "Finance Actuals"]),
                     offset_s=-(count - i) * 4) for i in range(count)]


SCENARIOS = {
    "powerbi_mass_export": scenario_powerbi_mass_export,
    "powerbi_print_bulk": scenario_powerbi_print_bulk,
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
