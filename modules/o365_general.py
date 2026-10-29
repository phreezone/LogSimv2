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

# AppHost value list per the official Copilot audit schema docs (learn.microsoft.com/
# en-us/office/office-365-management-api/copilot-schema): "Bing, Teams, Outlook, Office, DevUI,
# BashTool, Word, Excel, PowerPoint, OneNote, SharePoint, Loop, Whiteboard, M365App, ..." —
# "Microsoft Teams"/"Microsoft Copilot" are NOT valid AppHost values; use "Teams"/"M365App".
_COPILOT_HOSTS = ["Teams", "Word", "Outlook", "Excel", "PowerPoint", "M365App"]
_COPILOT_DOC_CONTEXT = ["Board Deck.docx", "Q3 Forecast.xlsx", "Product Roadmap.pptx",
                        "Meeting Minutes.docx", "Customer Contract.docx", "KPI Report.xlsx"]
# Threat rate governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (see _GATE below).


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
    """CopilotInteraction (RecordType 261). Field set per the official Copilot audit schema:
    https://learn.microsoft.com/en-us/office/office-365-management-api/copilot-schema
      - top-level repo props: ClientRegion, CopilotLogVersion (EntityType CopilotInteractionAuditRecord)
      - CopilotEventData: AppHost, Contexts[] {Id, Type, ContainerId}, ThreadId, MessageIds[],
        Messages[] {Id, Size, isPrompt}, AccessedResources[] {Id, SiteUrl, listItemUniqueId, Type,
        Name, SensitivityLabelId, Action}, ModelTransparencyDetails[], AISystemPlugin[]
        [{Name, Id, Version}]
      - Contexts[].Type follows the artifact (file extension "docx"/"xlsx"/"pptx", TeamsMeeting...)
      - AppHost values are the doc-published list (see _COPILOT_HOSTS)
    AppIdentity and CopilotLogVersion were additionally present in a real tenant Copilot row
    (AppIdentity value "Copilot for Microsoft 365"); AppIdentity is not in the published schema —
    kept because it appears in real harvested rows.
    """
    host = random.choice(_COPILOT_HOSTS)
    r = _base("CopilotInteraction", user, 261, "Copilot", offset_s)
    if random.random() < 0.6:
        # Document interaction: Contexts[].Id is the artifact URL; AccessedResources lists the
        # file(s) surfaced to the model (SensitivityLabelIdData, keys per schema).
        fn = random.choice(_COPILOT_DOC_CONTEXT)
        doc_site = random.choice(["Marketing", "Finance", "Sales", "Engineering"])
        ext = fn.rsplit(".", 1)[-1]                      # "docx" / "xlsx" / "pptx"
        site_url = f'https://examplecorp.sharepoint.com/sites/{doc_site}/Shared Documents/{fn}'
        ctx_id = site_url
        resources = [{"Type": ext, "Id": f'AAAA{random.getrandbits(96):024X}{random.getrandbits(96):024X}',
                      "SiteUrl": site_url, "listItemUniqueId": ac._stable_guid("copilot:" + fn),
                      "Name": fn, "SensitivityLabelId": ac._stable_guid("label:" + doc_site),
                      "Action": "Read"}]
        contexts = [{"Id": ctx_id, "Type": ext}]
    else:
        # Teams meeting interaction: Type "TeamsMeeting" (documented context type); accessed files
        # are meeting artifacts, so AccessedResources stays empty (matches doc example 1).
        meeting = "Meeting " + random.choice(["Weekly Review", "Standup", "Planning", "1:1"])
        ctx_id = f'https://teams.microsoft.com/l/meetup-join/19:meeting_{_g()[:8]}@thread.v2/0'
        resources = []
        contexts = [{"Id": ctx_id, "Type": "TeamsMeeting"}]
    thread = f"19:{_g().replace('-', '')}@thread.v2"
    # Messages: Id of the prompt and response messages + isPrompt (MessageData per schema).
    msgs = [{"Id": f"{int(time.time() * 1000) + random.randint(0, 900) // j * 350}",
             "isPrompt": j == 1} for j in (1, 2)]
    r.update({"CopilotLogVersion": "1.0", "AppIdentity": "Copilot for Microsoft 365",
              "ClientRegion": random.choice(["US", "US", "CA", "GB", "DE", "IN"]),
              "CopilotEventData": {"AppHost": host, "ThreadId": thread,
                                   "Contexts": contexts,
                                   "MessageIds": [], "Messages": msgs, "AISystemPlugin": [],
                                   "ModelTransparencyDetails": [],
                                   "AccessedResources": resources}})
    return r


def _powerbi(user, operation, report=None, offset_s=0):
    """PowerBIAudit (RecordType 20). Real op names verified against the Fabric operation list
    (learn.microsoft.com/en-us/fabric/admin/operation-list: ViewDashboard / ViewReport / ViewTile
    / PrintReport / ExportReport). Schema key names per the Power BI schema section of
    learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema:
    WorkSpaceName (note the 'WS' capitalization), DashboardName, ReportName, DatasetName,
    DataClassification, AppName. DashboardId/ReportId/DatasetId/WorkspaceId are NOT in the
    published schema table but appear in real tenant records — kept, marked unverified-in-docs.
    CapacityID/CapacityName appear on view ops (operation-list notes they can return null when
    viewed from a Power BI app); ReportSection is set per page during report interaction.
    """
    report = report or ac.report_name()
    ws = ac.workspace_name()
    r = _base(operation, user, 20, "PowerBI", offset_s)
    r.update({"WorkSpaceName": ws, "WorkspaceId": ac._stable_guid("pbiws:" + ws),
              "ResultStatus": "Succeeded", "IsSuccess": True,
              "CapacityID": ac._stable_guid("capacity:examplecorp"),
              "CapacityName": "CF-Main Capacity"})
    if operation in ("ViewDashboard", "CreateDashboard"):
        dname = report + " Dashboard"
        r.update({"DashboardName": dname, "DashboardId": ac._stable_guid("pbidash:" + dname),
                  "ObjectId": dname})
    else:
        ds = report + " Dataset"
        r.update({"ReportName": report, "ReportId": ac._stable_guid("pbi:" + report),
                  "DatasetName": ds, "DatasetId": ac._stable_guid("pbids:" + ds),
                  "ObjectId": report})
        if operation == "ViewReport":
            r["ReportSection"] = "ReportSection" + _g().replace("-", "")[:16]
    return r


# A realistic minority of Power BI operations fail (IsSuccess False): report render/refresh errors,
# datasets the user can't reach, export failures.
_FAIL_RATE = 0.07


def _maybe_fail(rec):
    if rec.get("Workload") == "PowerBI" and random.random() < _FAIL_RATE:
        rec["IsSuccess"] = False
        rec["ResultStatus"] = "Failed"
    return rec


def generate_benign(config=None, context=None):
    u = ac.pick_user(config, context)
    if random.random() > ac.activity_weight():
        return [_copilot(u)]   # Copilot/BI usage is human-driven; keep light off-hours
    if random.random() < 0.55:
        return [_copilot(u)]
    return [_maybe_fail(_powerbi(u, random.choice(
        ["ViewReport", "ViewDashboard", "ViewTile", "ViewUsageMetrics",
         "CreateReport", "CreateDashboard", "DownloadReport"])))]

# Benign authoring/view ops beyond the view set, verified in the Fabric operation list:
# ViewUsageMetrics ('Viewed Power BI usage metrics'), CreateDashboard ('Created Power BI
# dashboard'), CreateReport ('Created Power BI report'), DownloadReport ('Downloaded Power
# BI report').


def scenario_powerbi_mass_export(config=None, count=25):
    """Many Power BI report exports in a short window -> data exfiltration via BI export.
    One real export op consistently across the whole burst (ExportReport), with the real
    key set ReportId/ReportName/DatasetId/DatasetName so a volume analytic fires."""
    u = ac.pick_user(config)
    report = ac.report_name()
    return [_powerbi(u, "ExportReport", report=report, offset_s=-(count - i) * 3)
            for i in range(count)]


def scenario_powerbi_print_bulk(config=None, count=12):
    """Bulk Power BI print/export of exec/finance reports -> sensitive report harvesting."""
    u = ac.pick_user(config)
    return [_powerbi(u, "PrintReport", report=random.choice(["Exec KPIs", "Finance Actuals"]),
                     offset_s=-(count - i) * 4) for i in range(count)]


def scenario_powerbi_publish_to_web(config=None, count=3):
    """Power BI report published to the public web (PublishToWebReport) -> 'published Power
    BI report to web'; anyone with the embed link can read tenant data (external exposure).
    Verified op: 'Published Power BI report to web | PublishToWebReport' in the Fabric
    operation list."""
    u = ac.pick_user(config)
    return [_powerbi(u, "PublishToWebReport", report=ac.report_name(),
                     offset_s=-(count - i) * 30) for i in range(count)]


def scenario_powerbi_bulk_download(config=None, count=20):
    """Bulk Power BI report downloads over a short window -> 'downloaded Power BI report'
    (DownloadReport) burst; offline copy harvesting alongside the mass-export scenario.
    Verified op: 'Downloaded Power BI report | DownloadReport' in the Fabric operation list."""
    u = ac.pick_user(config)
    report = ac.report_name()
    return [_powerbi(u, "DownloadReport", report=report, offset_s=-(count - i) * 4)
            for i in range(count)]


SCENARIOS = {
    "powerbi_mass_export": scenario_powerbi_mass_export,
    "powerbi_print_bulk": scenario_powerbi_print_bulk,
    "powerbi_publish_to_web": scenario_powerbi_publish_to_web,
    "powerbi_bulk_download": scenario_powerbi_bulk_download,
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
