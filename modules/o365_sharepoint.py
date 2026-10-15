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
OD_HOST = "examplecorp-my.sharepoint.com"       # OneDrive personal host

ADMIN_ROLES = ("IT Administrator", "IT Director", "Systems Engineer")
_SITES = ["Sales", "Engineering", "Finance", "HR", "Marketing", "Operations", "Legal", "IT"]
_EXT_DOMAINS = ["gmail.com", "proton.me", "partner-co.com", "outlook.com"]
# Threat rate governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (see _GATE below).

# ── document corpus (deep, realistic, STABLE) ────────────────────────────────────────
# Per-site document libraries (SharePoint lists). Each site has several, not just "Shared Documents".
_LIBRARIES = {
    "Sales":       ["Shared Documents", "Proposals", "Pipeline", "Contracts", "Account Plans"],
    "Engineering": ["Shared Documents", "Design Docs", "Specs", "Runbooks", "Architecture", "Postmortems"],
    "Finance":     ["Shared Documents", "Budgets", "Invoices", "Audits", "Forecasts"],
    "HR":          ["Shared Documents", "Policies", "Onboarding", "Compensation", "Reviews"],
    "Marketing":   ["Shared Documents", "Campaigns", "Brand Assets", "Events", "Content"],
    "Operations":  ["Shared Documents", "Vendors", "Logistics", "SOPs", "Facilities"],
    "Legal":       ["Shared Documents", "Contracts", "NDAs", "Compliance", "IP"],
    "IT":          ["Shared Documents", "Runbooks", "Security", "Asset Inventory", "Change Management"],
}
# ── programmatic path vocabulary ─────────────────────────────────────────────────────
# Paths are generated combinatorially, not from a static name list. The dimensions below multiply
# to an effectively unbounded space (>10^12 distinct paths — see _space_size()), so there is no
# practical ceiling on unique paths while every segment stays a realistic business token.
_FOLDERS = ["Archive", "Drafts", "Templates", "Working", "Final", "Review", "Shared", "Backup",
            "Exports", "Imports", "Inbound", "Outbound", "Public", "Confidential", "Internal",
            "Reports", "Meeting Notes", "Presentations", "Spreadsheets", "Reference", "Old",
            "Q1", "Q2", "Q3", "Q4", "H1", "H2", "EMEA", "AMER", "APAC", "LATAM",
            "Team Alpha", "Team Bravo", "Team Charlie", "Team Delta", "Team Echo",
            "Project Apollo", "Project Zephyr", "Project Helios", "Project Orion", "Project Atlas",
            "Project Titan", "Project Nova", "Project Mercury", "Project Pegasus", "Project Phoenix",
            "Acme", "Globex", "Initech", "Umbrella Corp", "Soylent", "Hooli", "Stark Industries",
            "Wayne Enterprises", "Northwind", "Contoso", "Fabrikam", "Tailspin", "Adventure Works"]
_YEARS = [str(y) for y in range(2019, 2028)]
_FY = ["FY22", "FY23", "FY24", "FY25", "FY26", "FY27"]
# Filename stems (business documents). {q}->quarter is filled at generation time.
_STEMS = ["Q{q} Forecast", "Revenue Dashboard", "Customer List", "Master Services Agreement",
          "Annual Budget", "System Architecture", "New Hire Onboarding", "Price Book",
          "Board Deck", "Salary Bands", "Security Review", "Mutual NDA", "Incident Report",
          "Product Roadmap", "Sprint Plan", "Vendor SOW", "Expense Report", "Org Chart",
          "Meeting Minutes", "Deployment Runbook", "Threat Model", "Data Processing Addendum",
          "Campaign Brief", "Competitive Analysis", "Churn Analysis", "Capacity Plan",
          "Release Notes", "Design Spec", "Audit Findings", "Payroll Register", "Benefits Guide",
          "Travel Policy", "Access Review", "Network Diagram", "Disaster Recovery Plan",
          "KPI Report", "Customer Contract", "Partnership MOU", "Patent Filing", "Risk Register",
          "Status Update", "Weekly Report", "Monthly Summary", "Project Charter", "Statement of Work",
          "Change Request", "Test Plan", "Runbook", "Playbook", "Postmortem", "Retrospective",
          "Roadmap", "Backlog", "Requirements", "User Guide", "Data Model", "API Spec",
          "Marketing Plan", "Sales Deck", "Pricing Proposal", "Renewal Quote", "Purchase Order",
          "Invoice", "Receipt", "Reconciliation", "Forecast Model", "Headcount Plan",
          "Performance Review", "Offer Letter", "Policy Memo", "Compliance Report", "SOC2 Evidence"]
# Filename discriminators (realistic natural variety that also explodes the path space).
_VERS = ["", "", "", " v1", " v2", " v3", " v4", " v5", " Draft", " Final", " FINAL",
         " (1)", " (2)", " copy", " - reviewed", " - approved", " rev A", " rev B", " latest"]
_EXTS = [("docx", "File"), ("docx", "File"), ("xlsx", "File"), ("xlsx", "File"), ("pptx", "File"),
         ("pdf", "File"), ("pdf", "File"), ("vsdx", "File"), ("csv", "File"), ("one", "File"),
         ("txt", "File"), ("zip", "File"), ("mp4", "File"), ("png", "File"), ("msg", "File"),
         ("xlsm", "File"), ("json", "File"), ("pbix", "File")]
_OD_FOLDERS = ["", "Desktop", "Documents", "Downloads", "Pictures", "Attachments",
               "Microsoft Teams Chat Files", "Notebooks", "Recordings", "Work", "Personal",
               "Projects", "Screenshots", "Shared with Everyone"]


def _space_size():
    """Rough count of distinct paths the generator can produce (documentation/sanity)."""
    sites = len(_SITES)
    libs = sum(len(v) for v in _LIBRARIES.values())
    seg = len(_FOLDERS) + len(_YEARS) + len(_FY)          # ~73 folder segments
    chains = sum(seg ** d for d in range(0, 5))           # depth 0..4
    names = len(_STEMS) * 4 * len(_VERS) * len(_EXTS)     # stem × quarter × version × ext
    return sites * (libs // sites if sites else 1) * chains * names


def _rand_name(rnd):
    stem = rnd.choice(_STEMS).replace("{q}", str(rnd.randint(1, 4)))
    ext, itype = rnd.choice(_EXTS)
    # Some names carry a date or year token — common in real filenames, multiplies the space.
    tok = ""
    roll = rnd.random()
    if roll < 0.18:
        tok = " " + rnd.choice(_YEARS)
    elif roll < 0.30:
        tok = f" {rnd.choice(_YEARS)}-{rnd.randint(1,12):02d}-{rnd.randint(1,28):02d}"
    elif roll < 0.38:
        tok = " " + rnd.choice(_FY)
    return f"{stem}{tok}{rnd.choice(_VERS)}.{ext}", itype


def _seg_chain(rnd):
    depth = rnd.choices([0, 1, 2, 3, 4], weights=[12, 34, 30, 16, 8])[0]
    pool = _FOLDERS + _YEARS + _FY
    return [rnd.choice(pool) for _ in range(depth)]


def _sp_path(rnd, site=None):
    """Build one deterministic SharePoint file entity from an RNG (realistic, unbounded space)."""
    site = site or rnd.choice(_SITES)
    lib = rnd.choice(_LIBRARIES[site])
    folders = _seg_chain(rnd)
    fn, itype = _rand_name(rnd)
    d = f"/sites/{site}/" + "/".join([lib] + folders)
    return {"host": SP_HOST, "sitepath": f"/sites/{site}", "site_name": site, "library": lib,
            "rel": f"{d}/{fn}", "dir": d, "filename": fn, "itemtype": itype}


def path_for_filename(rnd, filename, site=None):
    """Build a realistic nested SharePoint path for a caller-supplied filename (used by DLP so
    its sensitive-file paths share the same deep folder/library structure)."""
    site = site or rnd.choice(_SITES)
    lib = rnd.choice(_LIBRARIES[site])
    folders = _seg_chain(rnd)
    d = f"/sites/{site}/" + "/".join([lib] + folders)
    return {"host": SP_HOST, "sitepath": f"/sites/{site}", "site_name": site, "library": lib,
            "rel": f"{d}/{filename}", "dir": d, "filename": filename, "itemtype": "File"}


def _od_path(rnd, user):
    acct = f'{user["username"].replace(".", "_")}_{ac.UPN_DOMAIN.replace(".", "_")}'
    base = f"/personal/{acct}"
    folders = [rnd.choice(_OD_FOLDERS)] + _seg_chain(rnd)
    folders = [s for s in folders if s]
    fn, itype = _rand_name(rnd)
    d = f"{base}/Documents" + ("/" + "/".join(folders) if folders else "")
    return {"host": OD_HOST, "sitepath": base, "site_name": "OneDrive", "library": "Documents",
            "rel": f"{d}/{fn}", "dir": d, "filename": fn, "itemtype": itype}


def _g():
    return str(uuid.uuid4())


def _now(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + offset_s))


# ── heavy-tailed working sets ────────────────────────────────────────────────────────
# A real tenant has a huge estate but day-to-day activity concentrates on a recurring "working
# set" (hot files). We model: a shared global hot set (collaboration docs many users touch), a
# bounded per-user hot slice (their own working set, forms the baseline), and an unbounded cold
# tail (fresh combinatorial paths -> effectively unlimited unique files over time). Every path's
# identity is hash-derived, so a file is the same stable entity whichever tier it comes from.
_HOT_PROB = 0.82          # share of activity that hits the recurring working set
_GLOBAL_HOT_N = 6000      # shared SharePoint working set across the tenant
_USER_HOT_N = (120, 300)  # per-user working-set slice size range

_GLOBAL_HOT = []
def _build_global_hot():
    rnd = random.Random("logsim-spo-hot-v2")   # seeded -> identical across runs/machines
    for _ in range(_GLOBAL_HOT_N):
        _GLOBAL_HOT.append(_sp_path(rnd))
_build_global_hot()

_USER_HOT = {}
def _user_hot(user):
    un = user["username"]
    hot = _USER_HOT.get(un)
    if hot is None:
        rnd = random.Random("spwork:" + un)
        n = rnd.randint(*_USER_HOT_N)
        # Mostly a slice of the shared estate (shared files are shared entities) + some own docs.
        hot = [_GLOBAL_HOT[rnd.randrange(_GLOBAL_HOT_N)] for _ in range(int(n * 0.7))]
        hot += [_sp_path(rnd) for _ in range(n - len(hot))]
        _USER_HOT[un] = hot
    return hot

_OD_HOT = {}
def _user_od_hot(user):
    un = user["username"]
    hot = _OD_HOT.get(un)
    if hot is None:
        rnd = random.Random("odwork:" + un)
        hot = [_od_path(rnd, user) for _ in range(rnd.randint(30, 90))]
        _OD_HOT[un] = hot
    return hot


def _onedrive_file(user):
    if random.random() < _HOT_PROB:
        return random.choice(_user_od_hot(user))     # recurring personal file
    return _od_path(random, user)                     # fresh long-tail personal file


def _file_for(user=None, workload="SharePoint", site=None, doc=None):
    """Resolve a file entity: explicit site/doc (scenarios), OneDrive personal, or a working-set/
    long-tail SharePoint pick. Hot picks recur (baseline); cold picks are fresh (unbounded)."""
    if doc is not None:
        s = site or random.choice(_SITES)
        return {"host": SP_HOST, "sitepath": f"/sites/{s}", "site_name": s, "library": "Shared Documents",
                "rel": f"/sites/{s}/Shared Documents/{doc}", "dir": f"/sites/{s}/Shared Documents",
                "filename": doc, "itemtype": "File"}
    if workload == "OneDrive" and user is not None:
        return _onedrive_file(user)
    if user is not None and random.random() < _HOT_PROB:
        pool = _user_hot(user)
        if site:
            s = [f for f in pool if f["site_name"] == site]
            if s:
                return random.choice(s)
        else:
            return random.choice(pool)
    return _sp_path(random, site)                     # fresh long-tail SharePoint file


def _sp(operation, user, record_type=6, workload="SharePoint", site=None, doc=None,
        extra=None, offset_s=0, fileobj=None):
    f = fileobj or _file_for(user, workload, site, doc)
    loc = ac.egress(user)
    _prof = ac._profile(user)
    rel = f["rel"]
    r = {"CreationTime": _now(offset_s), "Id": _g(), "Operation": operation,
         "OrganizationId": ORG_ID, "RecordType": record_type, "UserType": 0, "Version": 1,
         "Workload": workload, "UserId": user["upn"], "UserKey": ac.user_oid(user["username"]),
         "ClientIP": loc["ip"], "CorrelationId": _g(), "EventSource": "SharePoint",
         "ItemType": f["itemtype"],
         # ListId stable per library; ListItemUniqueId stable per file path (a file is one entity).
         "ListId": ac._stable_guid("list:" + f["sitepath"] + "/" + f["library"]),
         "ListItemUniqueId": ac._stable_guid("item:" + f["host"] + rel),
         "Site": ac._stable_guid("site:" + f["sitepath"]),
         "WebId": ac._stable_guid("web:" + f["sitepath"]),
         "SiteUrl": f'https://{f["host"]}{f["sitepath"]}/',
         "ObjectId": f'https://{f["host"]}{rel}', "SourceFileName": f["filename"],
         "SourceRelativeUrl": f["dir"].lstrip("/"),
         "ApplicationDisplayName": "OneDrive SyncEngine" if workload == "OneDrive" else "SharePoint",
         "UserAgent": _prof[4], "BrowserName": _prof[1], "BrowserVersion": _prof[2], "Platform": _prof[3],
         "IsManagedDevice": True, "DeviceDisplayName": f'{user["username"].upper().replace(".", "")}-PC',
         "GeoLocation": loc["countryOrRegion"], "AuthenticationType": "OAuth",
         "ResultStatus": "Succeeded"}
    if extra:
        r.update(extra)
    return r


# ── benign baseline ─────────────────────────────────────────────────────────────────

_BENIGN_OPS = ["FileAccessed", "FileModified", "FilePreviewed", "FileUploaded",
               "FileDownloaded", "FileCheckedOut", "FileCheckedIn", "FileRenamed",
               "PageViewed", "FolderCreated", "FileCopied", "FileMoved"]
# Benign RT14 sharing / access-request outcomes (internal, routine — the normal collaboration mix).
_SHARING_OPS = ["SharingSet", "SharingInvitationCreated", "SharingInvitationAccepted",
                "AddedToSecureLink", "SecureLinkCreated", "CompanyLinkCreated",
                "AccessRequestCreated", "AccessRequestApproved", "AccessRequestRejected",
                "AccessRequestWithdrawn", "SharingRevoked"]
# Sensitive-looking files for the risky-sharing scenarios.
_SENSITIVE_DOCS = ["Salary Bands.xlsx", "Customer List.xlsx", "Board Deck.pptx", "Cardholder Data.csv",
                   "Patient Records.xlsx", "Master Services Agreement.pdf", "Source Code.zip",
                   "Acquisition Terms.docx", "Employee SSNs.xlsx", "Patent Filing.pdf"]


def _b_sharing(cfg):
    """A routine internal sharing or access-request outcome (RecordType 14)."""
    u = ac.pick_user(cfg)
    op = random.choice(_SHARING_OPS)
    tgt = ac.pick_user(cfg)   # internal colleague
    status = "Failed" if (op == "AccessRequestRejected" and random.random() < 0.5) else "Succeeded"
    return _sp(op, u, record_type=14,
               extra={"TargetUserOrGroupName": tgt["upn"], "TargetUserOrGroupType": "Member",
                      "EventData": "<Edit>", "ResultStatus": status})


# A realistic minority of file operations fail (ResultStatus "Failed"): sync conflicts, checkout
# locks, permission denials, upload/download errors. Read/view ops are left as success.
_FAIL_RATE = 0.06
_FAILABLE = {"FileUploaded", "FileDownloaded", "FileCheckedOut", "FileCheckedIn", "FileRenamed",
             "FileCopied", "FileMoved", "FileSyncUploadedFull", "FileSyncDownloadedFull"}


def _maybe_fail(rec):
    if rec.get("Operation") in _FAILABLE and random.random() < _FAIL_RATE:
        rec["ResultStatus"] = "Failed"
    return rec


def generate_benign(config=None, context=None):
    u = ac.pick_user(config, context)
    if random.random() > ac.activity_weight():
        # off-hours: background OneDrive sync still runs
        return [_maybe_fail(_sp("FileSyncUploadedFull", u, workload="OneDrive"))]
    if random.random() < 0.15:   # routine internal sharing / access-request outcome
        return [_b_sharing(config)]
    wl = "OneDrive" if random.random() < 0.4 else "SharePoint"
    return [_maybe_fail(_sp(random.choice(_BENIGN_OPS), u, workload=wl))]


# ── detection scenarios ─────────────────────────────────────────────────────────────

def scenario_mass_download(config=None, count=40):
    """Many file downloads in a short window by one user -> M365 storage exfiltration / mass download."""
    u = ac.pick_user(config); site = random.choice(_SITES)
    return [_sp("FileDownloaded", u, site=site, offset_s=-(count - i))
            for i in range(count)]


def scenario_mass_file_deletion(config=None, count=50):
    """Many files deleted/recycled in a short window by one user -> 'Massive files deletion in
    Microsoft SharePoint or OneDrive' (ransomware/destruction or anti-forensics)."""
    u = ac.pick_user(config); site = random.choice(_SITES)
    return [_sp(random.choice(["FileDeleted", "FileRecycled"]), u, site=site, offset_s=-(count - i))
            for i in range(count)]


def scenario_mass_file_editing(config=None, count=40):
    """Many files modified in a short window by one user -> 'Massive files editing in Microsoft
    SharePoint or OneDrive' (ransomware encryption-in-place)."""
    u = ac.pick_user(config); site = random.choice(_SITES)
    return [_sp("FileModified", u, site=site, offset_s=-(count - i)) for i in range(count)]


def scenario_mass_file_upload(config=None, count=40):
    """Many files uploaded in a short window -> 'Massive upload to SaaS service' (staging/implants
    or re-upload of encrypted files)."""
    u = ac.pick_user(config); site = random.choice(_SITES)
    return [_sp(random.choice(["FileUploaded", "FileSyncUploadedFull"]), u, site=site,
                offset_s=-(count - i)) for i in range(count)]


def scenario_full_sync_download(config=None):
    """OneDrive full-library sync download -> bulk data staging/exfil."""
    u = ac.pick_user(config)
    return [_sp("FileSyncDownloadedFull", u, workload="OneDrive")]


def scenario_anonymous_link(config=None):
    """Anonymous ('Anyone') link created on a sensitive file -> risky external sharing."""
    u = ac.pick_user(config); doc = random.choice(_SENSITIVE_DOCS)
    return [_sp("AnonymousLinkCreated", u, record_type=14, doc=doc,
                extra={"EventData": "<Anyone link, Edit>"})]


def scenario_external_sharing(config=None):
    """Sharing invitation to an external recipient -> data shared outside the org."""
    u = ac.pick_user(config); ext = f"recipient@{random.choice(_EXT_DOMAINS)}"
    return [_sp("SharingInvitationCreated", u, record_type=14, doc=random.choice(_SENSITIVE_DOCS),
                extra={"TargetUserOrGroupName": ext, "TargetUserOrGroupType": "Guest",
                       "EventData": "<Edit>"})]


_SUS_FILENAMES = ["Invoice_2026.pdf.exe", "payroll.xlsx.lnk", "resume.doc.js", "statement.pdf.scr",
                  "photo.jpg.exe", "report‮slx.exe", "contract.pdf‮exe.scr",
                  "scan_001.one.vbs", "AnnualReview.docx.hta", "benefits.pdf‮kpa.exe"]


def scenario_malware_suspicious_filename(config=None):
    """File uploaded with a suspicious/obfuscated name (double extension, RTLO unicode, script/LOLBin
    extension) -> 'Suspicious characters in uploaded file name'."""
    u = ac.pick_user(config)
    return [_sp("FileUploaded", u, doc=random.choice(_SUS_FILENAMES), extra={"ItemType": "File"})]


_UNUSUAL_SHARE_DOMAINS = ["mail.ru", "protonmail.ch", "tutanota.com", "cock.li",
                          "guerrillamail.com", "temp-mail.org", "yandex.com", "mailfence.com"]


def scenario_site_collection_admin_added(config=None):
    """A user is granted Site Collection Administrator on a sensitive site -> 'Abnormal SharePoint
    site collection admin addition' (full control over the whole site collection)."""
    u = ac.pick_user(config); tgt = ac.pick_user(config)
    return [_sp("SiteCollectionAdminAdded", u, record_type=14, doc=random.choice(_SENSITIVE_DOCS),
                extra={"TargetUserOrGroupName": tgt["upn"], "TargetUserOrGroupType": "Member",
                       "EventData": "<SiteCollectionAdmin added>"})]


def scenario_anon_link_used_external(config=None):
    """An external/anonymous user accesses a sensitive file via an 'Anyone' link -> 'External user
    accessed a sensitive file via anonymous link'."""
    u = ac.pick_user(config)
    ext = f"external@{random.choice(_EXT_DOMAINS)}"
    return [_sp("AnonymousLinkUsed", u, record_type=14, doc=random.choice(_SENSITIVE_DOCS),
                extra={"UserId": "urn:spo:anon#" + _g(), "UserType": "Anonymous",
                       "TargetUserOrGroupName": ext, "EventData": "<Anyone link, View>"})]


def scenario_external_sharing_unusual_domain(config=None):
    """External sharing invitation to an UNUSUAL/rare recipient domain -> 'SaaS external file
    sharing to an unusual domain'."""
    u = ac.pick_user(config)
    ext = f"recipient@{random.choice(_UNUSUAL_SHARE_DOMAINS)}"
    return [_sp("SharingInvitationCreated", u, record_type=14, doc=random.choice(_SENSITIVE_DOCS),
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
    "malware_suspicious_filename": scenario_malware_suspicious_filename,
    "site_collection_admin_added": scenario_site_collection_admin_added,
    "anon_link_used_external": scenario_anon_link_used_external,
    "external_sharing_unusual_domain": scenario_external_sharing_unusual_domain,
    "mass_file_deletion": scenario_mass_file_deletion,
    "mass_file_editing": scenario_mass_file_editing,
    "mass_file_upload": scenario_mass_file_upload,
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
