"""Generated file names: business-plausible, unlimited variation, types coherent.

Same cardinality problem as the domain pools, one level down. Today:

    zscaler._UPLOAD_FILES        20 fixed names, no placeholders at all, so every
                                 upload in a month-long run is one of twenty, and
                                 "Q3_Financial_Report.xlsx" leaves DLP nothing to
                                 distinguish one exfil from the next
    proofpoint templates         8 malicious + 8 benign, varying only by {num}

A file-name or file-hash cardinality detector keys on exactly what a fixed pool
destroys. So names are composed here instead: a topic, an optional qualifier, an
optional period or number, and an extension whose content type matches.

What must NOT drift, because rules read it:

  * CONTENT TYPES. "Proofpoint - Image-Based (QR) Phishing" matches
    messageParts contains "image/png" / "image/jpeg", so the MIME string has to be
    the real one for the extension, not a plausible-looking guess. _CONTENT_TYPE
    below is the single source of truth and is keyed by extension.
  * THE MALICIOUS EXTENSION SET. "Proofpoint - Malware Attachment Delivered"
    matches an OR chain of .docm/.exe/.iso/.js/.lnk/.xlsm/.zip. The shipped
    templates covered .xlsm/.exe/.zip and never produced .lnk, .iso, .docm or .js,
    so four branches of that rule had never been exercised. They are in the mix
    now, which is also simply more current: once Office blocked macros by default,
    .lnk and .iso/.img container delivery became the dominant pattern, and a corpus
    stuck on macro documents is modelling 2021.

Malware families are tied to the extension class rather than picked at random --
IcedID really did ship .iso/.lnk, QakBot .xlsm -- because an analyst reading the
alert should not see "Emotet delivered via .lnk" and lose trust in the data.
"""

import random
import string

# Extension -> MIME. Rules match these strings, so they are the real ones.
_CONTENT_TYPE = {
    "pdf":   "application/pdf",
    "doc":   "application/msword",
    "docx":  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "docm":  "application/vnd.ms-word.document.macroEnabled.12",
    "xls":   "application/vnd.ms-excel",
    "xlsx":  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "xlsm":  "application/vnd.ms-excel.sheet.macroEnabled.12",
    "xlsb":  "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    "pptx":  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "csv":   "text/csv",
    "txt":   "text/plain",
    "zip":   "application/zip",
    "7z":    "application/x-7z-compressed",
    "rar":   "application/vnd.rar",
    "gz":    "application/gzip",
    "iso":   "application/x-iso9660-image",
    "img":   "application/octet-stream",
    "lnk":   "application/x-ms-shortcut",
    "exe":   "application/octet-stream",
    "dll":   "application/octet-stream",
    "js":    "text/javascript",
    "wsf":   "application/xml",
    "hta":   "application/hta",
    "one":   "application/onenote",
    "html":  "text/html",
    "apk":   "application/vnd.android.package-archive",
    "png":   "image/png",
    "jpg":   "image/jpeg",
    "svg":   "image/svg+xml",
    "py":    "text/x-python",
    "java":  "text/x-java-source",
    "sql":   "application/sql",
    "pst":   "application/vnd.ms-outlook",
}


def content_type(ext):
    """MIME type for an extension, defaulting to octet-stream."""
    return _CONTENT_TYPE.get(ext.lstrip(".").lower(), "application/octet-stream")


# --- business document names ------------------------------------------------

_TOPICS = {
    "document": ("Financial_Report", "Board_Deck", "Contract_Amendment",
                 "Budget_Forecast", "Strategy_Review", "Vendor_SOW",
                 "Audit_Findings", "Roadmap", "Pricing_Model", "Org_Chart",
                 "Incident_Postmortem", "Vendor_Assessment", "Capacity_Plan",
                 "Meeting_Minutes", "Statement_of_Work", "Renewal_Proposal",
                 "Compliance_Attestation", "Headcount_Plan", "Margin_Analysis",
                 "Territory_Review", "Partner_Agreement", "Service_Credit_Memo"),
    "pii":      ("Customer_Records", "Employee_Roster", "Account_Export",
                 "Payroll_Run", "Benefits_Enrollment", "Candidate_Pipeline",
                 "Patient_List", "Cardholder_Extract", "Salary_Bands",
                 "Emergency_Contacts", "Background_Check_Results"),
    "archive":  ("project_backup", "export_bundle", "photos_archive",
                 "case_files", "mailbox_export", "site_snapshot",
                 "ticket_attachments", "legal_hold"),
    "source":   ("app_source", "build_pipeline", "api_service", "repo_snapshot",
                 "deploy_scripts", "schema_migrations", "infra_modules",
                 "auth_service", "billing_worker"),
    "image":    ("scan", "photo", "receipt_scan", "whiteboard", "screenshot",
                 "badge_photo", "signed_page"),
}
_EXTS = {
    "document": ("xlsx", "docx", "pdf", "pptx", "doc", "xls"),
    "pii":      ("csv", "xlsx", "csv", "txt"),
    "archive":  ("zip", "7z", "gz", "rar"),
    "source":   ("tar.gz", "zip", "py", "java", "sql"),
    "image":    ("png", "jpg", "pdf"),
}
# Qualifiers and periods are what actually create the cardinality: a real share
# drive has Q3_Financial_Report_v4_FINAL.xlsx, not one canonical file name.
_QUALIFIERS = ("", "", "draft", "final", "FINAL", "v2", "v3", "v4", "rev1", "rev2",
               "reviewed", "approved", "internal", "confidential", "clean",
               "updated", "signed", "redlined", "consolidated")
_PERIODS = ("", "", "Q1", "Q2", "Q3", "Q4", "H1", "H2", "FY26", "FY27",
            "2026", "2027", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", "week12", "week33")


def document_name(kind="document"):
    """(filename, ext) for a plausible business file of the given kind.

    kind: document | pii | archive | source | image
    """
    topics = _TOPICS.get(kind, _TOPICS["document"])
    exts = _EXTS.get(kind, _EXTS["document"])
    parts = [random.choice(topics)]
    period = random.choice(_PERIODS)
    if period:
        # Periods lead on finance-style names and trail on everything else.
        if random.random() < 0.6:
            parts.insert(0, period)
        else:
            parts.append(period)
    qualifier = random.choice(_QUALIFIERS)
    if qualifier:
        parts.append(qualifier)
    ext = random.choice(exts)
    sep = "_" if "_" in parts[0] or len(parts) > 1 else ""
    name = sep.join(parts) if sep else parts[0]
    return f"{name}.{ext}", ext.split(".")[-1]


def document_file(kind="document"):
    """(filename, ext, content_type) for a plausible business file."""
    name, ext = document_name(kind)
    return name, ext, content_type(ext)


# --- malicious attachments --------------------------------------------------
#
# Delivery classes, weighted the way email-borne malware actually arrives after
# default macro blocking. Families are the ones really associated with each class.
_DELIVERY = (
    # (weight, extensions, families, name style)
    (26, ("lnk",),              ("IcedID", "QakBot", "Emotet", "Latrodectus"), "lure"),
    (18, ("iso", "img"),        ("IcedID", "BumbleBee", "Latrodectus"),        "lure"),
    (16, ("zip", "7z", "rar"),  ("IcedID", "AgentTesla", "FormBook"),          "lure"),
    (12, ("xlsm", "docm", "xlsb"), ("QakBot", "Emotet", "Dridex"),             "lure"),
    (10, ("js", "wsf", "hta"),  ("AsyncRAT", "NetSupport", "Nemucod"),         "lure"),
    (8,  ("pdf",),              ("PDFExploit", "MaliciousPDF"),                "lure"),
    (6,  ("one", "html"),       ("QakBot", "AsyncRAT"),                        "lure"),
    (4,  ("exe", "dll"),        ("AsyncRAT", "RemcosRAT", "FormBook"),         "lure"),
)
_DELIVERY_WEIGHTS = tuple(d[0] for d in _DELIVERY)

# Social-engineering lures: what the sender wants the name to say.
_LURES = ("Invoice", "Remittance", "Shipment", "Purchase_Order", "PO",
          "Statement", "Receipt", "Payment_Advice", "Report", "Document",
          "Scan", "Voicemail", "Fax", "Contract", "Proposal", "Resume",
          "CV", "Quotation", "Delivery_Note", "Credit_Note", "Tax_Notice",
          "Payroll_Notice", "Account_Statement", "Signed_Agreement",
          "Missed_Call", "Secure_Message", "Encrypted_Document")

# Image lures for QR-code phishing, where the payload is the image itself.
_QR_LURES = ("MFA_Setup", "Authenticator_QR", "Secure_Message", "Voicemail_QR",
             "Payroll_Portal", "Password_Expiry", "Benefits_Enrollment",
             "DocuSign_Scan", "Mailbox_Quota")
_QR_EXTS = ("png", "jpg")


def _ref():
    """A reference number, the way a real lure carries one."""
    style = random.random()
    if style < 0.45:
        return str(random.randint(100000, 999999))
    if style < 0.75:
        return f"{random.randint(2026, 2027)}-{random.randint(1000, 9999)}"
    return "".join(random.choice(string.ascii_uppercase) for _ in range(2)) + \
        str(random.randint(10000, 99999))


def malicious_attachment():
    """(filename, ext, content_type, malware_family) for a malware-bearing file.

    The extension set spans the whole OR chain the Proofpoint malware rule matches,
    so every branch of it gets exercised over a run rather than only the three the
    old fixed templates happened to cover.
    """
    _, exts, families, _style = random.choices(_DELIVERY, weights=_DELIVERY_WEIGHTS, k=1)[0]
    ext = random.choice(exts)
    name = f"{random.choice(_LURES)}_{_ref()}"
    # A container usually holds the real payload, and the name says so.
    if ext in ("iso", "img", "zip", "7z", "rar") and random.random() < 0.4:
        name = f"{name}_documents"
    return f"{name}.{ext}", ext, content_type(ext), random.choice(families)


def qr_phishing_attachment():
    """(filename, ext, content_type) for an image carrying a phishing QR code.

    Kept separate from malicious_attachment because the QR rule matches image MIME
    types, and an image must never leak into the malware-extension mix.
    """
    ext = random.choice(_QR_EXTS)
    name = f"{random.choice(_QR_LURES)}_{random.randint(1000, 9999)}"
    return f"{name}.{ext}", ext, content_type(ext)


# AV signature names are not free-form: the prefix encodes what the engine parsed,
# which is why real detections read JS.Trojan.Nemucod, W97M.Downloader.gen or
# Android.Agent.G. A name whose prefix disagrees with the file type is the kind of
# detail that tells an analyst the data is synthetic.
_AV_PREFIX = {
    "js": "JS", "wsf": "JS", "hta": "HTML", "html": "HTML",
    "doc": "W97M", "docm": "W97M", "docx": "W97M",
    "xls": "X97M", "xlsm": "X97M", "xlsb": "X97M", "xlsx": "X97M",
    "pdf": "PDF", "apk": "Android", "lnk": "LNK", "iso": "Win32",
    "img": "Win32", "exe": "Win32", "dll": "Win32",
    "zip": "Win32", "7z": "Win32", "rar": "Win32", "one": "OneNote",
}
_AV_KIND = ("Trojan", "Downloader", "Dropper", "Agent", "Phishing", "Ransom")
_AV_SUFFIX = ("gen", "A", "B", "G", "QY", "AZ", "dam", "mg")


def av_detection_name(ext, family=None):
    """A vendor-style detection name whose prefix matches the file type.

    e.g. ("js", "Nemucod") -> "JS.Trojan.Nemucod"
    """
    prefix = _AV_PREFIX.get(ext.lstrip(".").lower(), "Win32")
    if family and random.random() < 0.7:
        return f"{prefix}.{random.choice(_AV_KIND)}.{family}"
    return f"{prefix}.{random.choice(_AV_KIND)}.{random.choice(_AV_SUFFIX)}"


def malicious_file_info():
    """{fname, fileType, threatname} -- the shape Cisco Firepower's AMP events want.

    Replaces firepower_config.malicious_files, six fixed dicts whose file names
    (setup.exe, loader.js, update.apk ...) repeated on every malware event in a run,
    so the file-name and file-hash cardinality an AMP detector keys on was six.
    """
    name, ext, _ctype, family = malicious_attachment()
    return {"fname": name,
            "fileType": ext.upper(),
            "threatname": av_detection_name(ext, family)}


def benign_attachment():
    """(filename, ext, content_type) for an ordinary business attachment."""
    kind = random.choices(("document", "image", "archive", "pii"),
                          weights=(70, 15, 10, 5), k=1)[0]
    return document_file(kind)
