"""Office 365 SharePoint Online / OneDrive audit (O365 Management Activity)
-> msft_o365_sharepoint_online_raw, via the cribl_direct transport (dedicated UUID).

Field set verified against real tenant rows: RecordType 6 (SharePoint file/folder operations)
and 14 (SharePoint sharing operations), Workload "SharePoint"/"OneDrive", with ObjectId as the
full file URL, Site/SiteUrl/WebId/ListId/ListItemUniqueId, SourceFileName/SourceRelativeUrl,
ItemType, EventSource, ApplicationDisplayName, Browser/Device/Platform, GeoLocation.

Benign baseline = routine document activity (access/modify/preview/upload/download, page views,
folder ops), weighted to business hours. Detection scenarios target the M365 storage
exfiltration / external-sharing analytics: mass download, full sync download, anonymous link
creation, and external sharing invitations.
"""
import random
import time
import uuid

from modules import azure_common as ac

NAME = "Office 365 SharePoint Online"
DESCRIPTION = "Simulates Office 365 SharePoint/OneDrive audit records for msft_o365_sharepoint_online_raw via the cribl_direct transport."
CONFIG_KEY = "o365_sharepoint_config"
SOURCE_IDENTIFIER = "3a37f519e9094a3f8c4185fa572cd111"
INTEGRATION_IDENTIFIER = "logsim:o365_sharepoint"
DATASET = "msft_o365_sharepoint_online_raw"
ORG_ID = "09febfec-25f3-48fa-bd8c-9b4a44f896ec"
SP_HOST = "examplecorp.sharepoint.com"

ADMIN_ROLES = ("IT Administrator", "IT Director", "Systems Engineer")
_SITES = ["Sales", "Engineering", "Finance", "HR", "Marketing", "Operations", "Legal", "IT"]
_DOCS = ["Q3 Forecast.xlsx", "Roadmap.pptx", "Customer List.xlsx", "Contract Draft.docx",
         "Budget 2026.xlsx", "Architecture.vsdx", "Onboarding.pdf", "Pricing.xlsx",
         "Board Deck.pptx", "Salary Bands.xlsx", "Security Review.docx", "NDA.pdf"]
_EXT_DOMAINS = ["gmail.com", "proton.me", "partner-co.com", "outlook.com"]
_THREAT_PROB = {"Benign Traffic Only": 0.0, "Low": 0.02, "Realistic": 0.05,
                "Medium": 0.08, "High": 0.12, "Insane": 0.30}


def _g():
    return str(uuid.uuid4())


def _now(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + offset_s))


def _sp(operation, user, record_type=6, workload="SharePoint", site=None, doc=None,
        extra=None, offset_s=0):
    site = site or random.choice(_SITES)
    doc = doc or random.choice(_DOCS)
    rel = f"/sites/{site}/Shared Documents/{doc}"
    loc = ac.egress(user)
    r = {"CreationTime": _now(offset_s), "Id": _g(), "Operation": operation,
         "OrganizationId": ORG_ID, "RecordType": record_type, "UserType": 0, "Version": 1,
         "Workload": workload, "UserId": user["upn"], "UserKey": ac.user_oid(user["username"]),
         "ClientIP": loc["ip"], "CorrelationId": _g(), "EventSource": "SharePoint",
         "ItemType": "File", "ListId": ac._stable_guid("list:" + site),
         "ListItemUniqueId": _g(), "Site": ac._stable_guid("site:" + site),
         "WebId": ac._stable_guid("web:" + site),
         "SiteUrl": f"https://{SP_HOST}/sites/{site}/",
         "ObjectId": f"https://{SP_HOST}{rel}", "SourceFileName": doc,
         "SourceRelativeUrl": f"sites/{site}/Shared Documents",
         "ApplicationDisplayName": "OneDrive SyncEngine" if workload == "OneDrive" else "SharePoint",
         "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/154.0.0.0 Safari/537.36",
         "BrowserName": "Chrome", "BrowserVersion": "154.0.0.0", "Platform": "Windows10",
         "IsManagedDevice": True, "DeviceDisplayName": f'{user["username"].upper().replace(".", "")}-PC',
         "GeoLocation": loc["countryOrRegion"], "AuthenticationType": "OAuth"}
    if extra:
        r.update(extra)
    return r


# ── benign baseline ─────────────────────────────────────────────────────────────────

_BENIGN_OPS = ["FileAccessed", "FileModified", "FilePreviewed", "FileUploaded",
               "FileDownloaded", "FileCheckedOut", "FileCheckedIn", "FileRenamed",
               "PageViewed", "FolderCreated", "FileCopied", "FileMoved"]


def generate_benign(config=None, context=None):
    u = ac.pick_user(config, context)
    if random.random() > ac.activity_weight():
        # off-hours: background OneDrive sync still runs
        return [_sp("FileSyncUploadedFull", u, workload="OneDrive")]
    wl = "OneDrive" if random.random() < 0.4 else "SharePoint"
    return [_sp(random.choice(_BENIGN_OPS), u, workload=wl)]


# ── detection scenarios ─────────────────────────────────────────────────────────────

def scenario_mass_download(config=None, count=40):
    """Many file downloads in a short window by one user -> M365 storage exfiltration / mass download."""
    u = ac.pick_user(config); site = random.choice(_SITES)
    return [_sp("FileDownloaded", u, site=site, doc=random.choice(_DOCS), offset_s=-(count - i))
            for i in range(count)]


def scenario_full_sync_download(config=None):
    """OneDrive full-library sync download -> bulk data staging/exfil."""
    u = ac.pick_user(config)
    return [_sp("FileSyncDownloadedFull", u, workload="OneDrive")]


def scenario_anonymous_link(config=None):
    """Anonymous ('Anyone') link created on a sensitive file -> risky external sharing."""
    u = ac.pick_user(config); doc = random.choice(_DOCS)
    return [_sp("AnonymousLinkCreated", u, record_type=14, doc=doc,
                extra={"EventData": "<Anyone link, Edit>"})]


def scenario_external_sharing(config=None):
    """Sharing invitation to an external recipient -> data shared outside the org."""
    u = ac.pick_user(config); ext = f"recipient@{random.choice(_EXT_DOMAINS)}"
    return [_sp("SharingInvitationCreated", u, record_type=14, doc=random.choice(_DOCS),
                extra={"TargetUserOrGroupName": ext, "TargetUserOrGroupType": "Guest",
                       "EventData": "<Edit>"})]


def scenario_malware_detected(config=None):
    """Malware detected in an uploaded document -> SharePoint/OneDrive malware."""
    u = ac.pick_user(config)
    return [_sp("FileMalwareDetected", u, doc="Invoice_scan.pdf",
                extra={"ItemType": "File"})]


SCENARIOS = {
    "mass_download": scenario_mass_download,
    "full_sync_download": scenario_full_sync_download,
    "anonymous_link": scenario_anonymous_link,
    "external_sharing": scenario_external_sharing,
    "malware_detected": scenario_malware_detected,
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
