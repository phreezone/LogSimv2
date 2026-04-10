# modules/proofpoint_email.py
# Simulates Proofpoint TAP (Targeted Attack Protection) email security events.
# Dataset: proofpoint_tap_raw
# XIF: ProofpointTAPModelingRules_1_3.xif
# Transport: http (XSIAM HTTP Log Collector)
#
# Supported _log_type values (match XSIAM alert rules exactly):
#   message-delivered  – email delivered to mailbox (benign or slipped-through threat)
#   message-blocked    – email quarantined by TAP
#   click-blocked      – user clicked rewritten URL; TAP blocked destination
#   click-permitted    – user clicked URL; TAP allowed (retroactive threat signal)
#
# XDM field mapping (ProofpointTAPModelingRules_1_3.xif):
#   fromAddress        → xdm.email.sender
#   recipient          → xdm.email.recipients
#   ccAddresses        → xdm.email.cc
#   subject            → xdm.email.subject
#   messageID          → xdm.email.message_id
#   GUID               → xdm.event.id / xdm.alert.original_alert_id
#   sender             → xdm.email.return_path
#   messageParts       → xdm.email.attachment.filename/md5/sha256
#   threatsInfoMap     → xdm.alert.description / threatType / threatID
#   senderIP           → xdm.intermediate.host.ipv4_addresses
#   clickIP            → xdm.source.host.ipv4_addresses
#   userAgent          → xdm.source.user_agent
#   url                → xdm.target.url
#   messageTime        → xdm.email.delivery_timestamp
#
# Threat hunt fields (top-level in raw JSON, not in XIF but searchable in dataset):
#   classification, threatID, threatURL, threatStatus, clickTime, clickIP,
#   impostorScore, phishScore, malwareScore, spamScore, campaignId,
#   headerFrom, replyToAddress, modulesRun, completelyRewritten

import random
import time
import json
import hashlib
from datetime import datetime, timezone, timedelta

try:
    from modules.session_utils import get_random_user, get_all_emails
except ImportError:
    from session_utils import get_random_user, get_all_emails

NAME = "Proofpoint Email Gateway"
DESCRIPTION = "Simulates Proofpoint TAP email security events (message and click events)."
XSIAM_VENDOR = "Proofpoint"
XSIAM_PRODUCT = "Tap"
CONFIG_KEY = "proofpoint_config"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FIRST_OCTETS = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 194, 212, 213]

_BROWSER_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.2038.82",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0; Pro)",
]

_BENIGN_XMAILERS = [
    "Microsoft Outlook 16.0", "Microsoft Outlook 15.0", "Apple Mail",
    "Gmail", "Thunderbird 102.0", "Evolution 3.28.5",
    "HubSpot Email 9.0", "Mailchimp", "SendGrid",
]


# policyRoutes — realistic PPS routing policy names
# "default_inbound" is always present; threat emails targeting specific groups get an extra route.
_POLICY_ROUTES_EXTRA = [
    "executives", "finance", "hr", "it_staff", "legal", "anti-spam",
    "quarantine_inbound", "privileged_users",
]

# Sandbox status values per official SIEM API
_SANDBOX_CLEAN    = "CLEAN"
_SANDBOX_MALICIOUS= "MALICIOUS"
_SANDBOX_UNKNOWN  = "UNKNOWN"

_DEFAULT_BENIGN_SENDER_DOMAINS = [
    "microsoft.com", "google.com", "salesforce.com", "docusign.net",
    "linkedin.com", "adobe.com", "dropbox.com", "zoom.us",
    "hubspot.com", "mailchimp.com", "atlassian.com", "github.com",
    "slack.com", "servicenow.com", "workday.com", "concur.com",
]

_DEFAULT_THREAT_SENDER_DOMAINS = [
    "micros0ft-support.com", "docusign-notify.net", "secure-login-portal.xyz",
    "invoice-delivery.info", "hr-notification.co", "payroll-update.net",
    "account-security-alert.com", "verify-identity.click", "shared-document.link",
    "sharepoint-online.net", "onedrive-share.xyz", "zoom-meeting-invite.com",
    "microsoft365-security.info", "office-update-required.com", "it-helpdesk-support.net",
]

_DEFAULT_MALICIOUS_URL_DOMAINS = [
    "malicious-redirect.xyz", "phish-kit-host.ru", "credential-harvest.com",
    "fake-sharepoint.club", "office365-phish.pw", "login-verify.info",
    "doc-view-portal.xyz", "account-reactivate.net", "secure-file-share.to",
    "click-redirect.co", "track-email-open.ru", "download-invoice.link",
    "paypal-secure-verify.net", "microsoft-login-portal.info",
]

_BENIGN_SUBJECTS = [
    "Q4 Financial Report - Action Required",
    "Team Meeting Agenda - {date}",
    "Your invoice #{num} is ready",
    "Welcome to {service}",
    "Reminder: Annual Performance Review",
    "Project Update: {project} - Week {week}",
    "Please review and sign: {doc}",
    "Your order has shipped",
    "Upcoming webinar: Cybersecurity Best Practices",
    "Board Meeting Minutes - {date}",
    "IT Maintenance Window Notification",
    "HR Update: Open Enrollment for Benefits",
    "Re: Contract Renewal Discussion",
    "New Shared Document: {doc}",
    "Quarterly Business Review - Save the Date",
    "Payroll Update: Please Review",
    "Security Awareness Training Reminder",
    "NDA Required: New Vendor Onboarding",
]

_PHISHING_SUBJECTS = [
    "Your Microsoft 365 account requires verification",
    "URGENT: Your account will be suspended in 24 hours",
    "Important security notice for your account",
    "Your DocuSign document is waiting",
    "Action Required: Confirm your email address",
    "You have (1) pending message in your mailbox",
    "HR: Important payroll update required",
    "IT Support: Password Expiration Notice",
    "Voicemail from unknown caller (+1-{num})",
    "Your shared file is ready to view",
    "Re: Wire Transfer Approval Needed - Urgent",
    "Secure File Share: Invoice-{num}.pdf",
    "Zoom: Meeting Recording Available",
    "SharePoint: {name} shared a document with you",
    "Alert: Unusual sign-in activity detected on your account",
    "Your OneDrive storage is full - action required",
]

_BEC_SUBJECTS = [
    "Urgent Wire Transfer Request",
    "Confidential: Request for W-2 Information",
    "Quick Question",
    "IMPORTANT: Change of Bank Details",
    "Board approval needed urgently",
    "Confidential - Executive Action Required",
    "Please process payment - time sensitive",
    "Gift Card Purchase Request",
    "Vendor Payment Update",
    "Payroll Direct Deposit Change Request",
    "Re: Acquisition - Strictly Confidential",
]

_SPAM_SUBJECTS = [
    "You have WON a $1000 Amazon gift card!",
    "Limited Time Offer - 90% OFF All Products",
    "FINAL NOTICE: Claim your reward now",
    "Congratulations! You've been selected",
    "Make $5000/week working from home",
    "Refinance your mortgage - lowest rates ever",
    "Grow your business with our proven method",
    "EXCLUSIVE: Investment opportunity - 300% returns",
    "Your prescription is ready for pickup",
]

# Malicious attachment templates (classification and threat_type inform threatsInfoMap)
_MALICIOUS_ATTACHMENT_TEMPLATES = [
    {"filename": "Invoice_{num}.doc",   "contentType": "application/msword",                                                                   "classification": "MALWARE", "malware_family": "Emotet"},
    {"filename": "Shipment_{num}.xlsm", "contentType": "application/vnd.ms-excel.sheet.macroEnabled.12",                                       "classification": "MALWARE", "malware_family": "QakBot"},
    {"filename": "Report_{num}.exe",    "contentType": "application/octet-stream",                                                              "classification": "MALWARE", "malware_family": "AsyncRAT"},
    {"filename": "Document_{num}.pdf",  "contentType": "application/pdf",                                                                       "classification": "MALWARE", "malware_family": "PDFExploit"},
    {"filename": "Setup_{num}.zip",     "contentType": "application/zip",                                                                       "classification": "MALWARE", "malware_family": "IcedID"},
    {"filename": "Proposal_{num}.docx", "contentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",               "classification": "MALWARE", "malware_family": "AgentTesla"},
    {"filename": "PO_{num}.xlsb",       "contentType": "application/vnd.ms-excel.sheet.binary.macroEnabled.12",                                "classification": "MALWARE", "malware_family": "Dridex"},
    {"filename": "Resume_{num}.pdf",    "contentType": "application/pdf",                                                                       "classification": "MALWARE", "malware_family": "MaliciousPDF"},
]

_BENIGN_ATTACHMENT_TEMPLATES = [
    {"filename": "Q4_Report.pdf",          "contentType": "application/pdf"},
    {"filename": "Meeting_Agenda.docx",    "contentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"filename": "Invoice_{num}.pdf",      "contentType": "application/pdf"},
    {"filename": "Presentation.pptx",     "contentType": "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"filename": "Contract_Draft.docx",    "contentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"filename": "Budget_{year}.xlsx",     "contentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"filename": "photo.jpg",              "contentType": "image/jpeg"},
    {"filename": "project-update.png",     "contentType": "image/png"},
]

# Threat scenario selection weights
_THREAT_WEIGHTS = {
    "phishing_url":         20,
    "malware_attachment":   18,
    "credential_phishing":  15,
    "bec_impostor":         12,
    "spam_campaign":        10,   # multi-event: returns list
    "malicious_macro":       8,
    "click_blocked":        10,
    "click_permitted":       5,
    "qr_code_phishing":      3,
    "callback_phishing":     2,
    "phishing_campaign":     7,   # multi-event: burst to many recipients, returns list
}

# Module-level state for threat pacing
last_threat_event_time = 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_threat_interval(threat_level, config):
    if threat_level == "Benign Traffic Only":
        return 86400 * 365
    levels = config.get("threat_generation_levels", {})
    return levels.get(threat_level, 7200)


def _generate_hashes():
    random_data = str(random.random()).encode()
    sha256 = hashlib.sha256(random_data).hexdigest()
    md5    = hashlib.md5(random_data).hexdigest()
    return sha256, md5


def _random_external_ip():
    o1 = random.choice(_FIRST_OCTETS)
    return f"{o1}.{random.randint(0, 255)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _make_guid():
    return (f"{{{random.randint(0x10000000, 0xFFFFFFFF):08X}-"
            f"{random.randint(0x1000, 0xFFFF):04X}-"
            f"{random.randint(0x1000, 0xFFFF):04X}-"
            f"{random.randint(0x1000, 0xFFFF):04X}-"
            f"{random.randint(0x100000000000, 0xFFFFFFFFFFFF):012X}}}")


def _make_message_id(local_part="user", domain="mail.examplecorp.com"):
    rand = random.randint(100000000, 999999999)
    return f"<{rand}.JavaMail.{local_part}@{domain}>"


def _now_iso():
    """Return ISO-8601 timestamp with millisecond precision matching real TAP SIEM API format."""
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _offset_iso(seconds_ago):
    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _format_subject(template):
    return (template
            .replace("{date}", datetime.now(timezone.utc).strftime("%B %d, %Y"))
            .replace("{num}", str(random.randint(10000, 99999)))
            .replace("{week}", str(random.randint(1, 52)))
            .replace("{year}", str(datetime.now(timezone.utc).year))
            .replace("{project}", random.choice(["Alpha", "Phoenix", "Titan", "Aurora", "Helios"]))
            .replace("{doc}", random.choice(["NDA_Agreement", "Contract_2024", "Proposal_Final", "MSA_Draft"]))
            .replace("{service}", random.choice(["Microsoft 365", "Salesforce", "Workday", "ServiceNow"]))
            .replace("{name}", random.choice(["John Smith", "Sarah Connor", "Alex Johnson", "Mike Davis"])))


def _get_all_emails(config, session_context):
    """Return list of all user email addresses, preferring session_context."""
    if session_context:
        emails = get_all_emails(session_context)
        if emails:
            return emails
    fallback_users = list(config.get("zscaler_config", {}).get("users", {}).keys())
    if fallback_users:
        return [f"{u}@examplecorp.com" for u in fallback_users]
    return ["user.one@examplecorp.com", "user.two@examplecorp.com", "user.three@examplecorp.com"]


def _pick_recipients(all_emails, count=None):
    if not all_emails:
        return ["default.user@examplecorp.com"]
    n = count or random.randint(1, 3)
    return random.sample(all_emails, min(n, len(all_emails)))


def _cf(config):
    """Shorthand: get proofpoint_config sub-dict."""
    return config.get("proofpoint_config", {})


def _internal_domain(config):
    return _cf(config).get("internal_domain", "examplecorp.com")


def _cluster_id(config):
    return _cf(config).get("cluster_id", "pharmtech_hosted")


def _campaign_id(config):
    campaigns = _cf(config).get("campaign_ids", [])
    return random.choice(campaigns) if campaigns else f"CMP-{random.randint(1000, 9999)}"



def _benign_sender(config):
    senders = _cf(config).get("benign_senders", [])
    if senders:
        return random.choice(senders)
    domain = random.choice(_DEFAULT_BENIGN_SENDER_DOMAINS)
    local  = random.choice(["noreply", "info", "support", "notifications", "updates", "news", "billing"])
    return f"{local}@{domain}"


def _threat_sender(config):
    senders = _cf(config).get("threat_senders", [])
    if senders:
        return random.choice(senders)
    domain = random.choice(_DEFAULT_THREAT_SENDER_DOMAINS)
    local  = random.choice(["no-reply", "security", "support", "billing", "helpdesk", "notification", "service"])
    return f"{local}@{domain}"


def _malicious_url(config):
    domains = _cf(config).get("malicious_url_domains", _DEFAULT_MALICIOUS_URL_DOMAINS)
    domain  = random.choice(domains)
    token   = hashlib.md5(str(random.random()).encode()).hexdigest()[:16]
    path    = random.choice([
        f"/secure/verify?token={token}",
        f"/download/{random.randint(100000, 999999)}/document.html",
        f"/login?redirect={token[:8]}&next=%2Fhome",
        f"/view/invoice/{random.randint(10000, 99999)}",
        f"/auth/reset?key={token}",
    ])
    return f"https://{domain}{path}"


def _tap_threat_insight_url(guid):
    return f"https://threatinsight.proofpoint.com/#/threat/email/{guid.strip('{}')}"


def _make_body_part():
    """Inline body part — real TAP SIEM API uses text/plain, sandboxStatus=null for body parts."""
    sha256, md5 = _generate_hashes()
    return {
        "contentType": "text/plain", "disposition": "inline",
        "filename": "text.txt", "md5": md5,
        "oContentType": "text/plain", "sandboxStatus": None,
        "sha256": sha256,
    }


def _fill_attachment(template, malicious=False):
    """Return a copy of an attachment template with fresh hashes and resolved placeholders.

    sandboxStatus values per official Proofpoint TAP SIEM API:
      None        – not submitted to sandbox (e.g. images, plain text)
      "CLEAN"     – sandboxed and found clean
      "MALICIOUS" – sandboxed and found malicious
      "UNKNOWN"   – sandboxed but verdict inconclusive
    """
    att = {k: v for k, v in template.items()}
    sha256, md5 = _generate_hashes()
    att["sha256"]       = sha256
    att["md5"]          = md5
    att["oContentType"] = att["contentType"]
    att["disposition"]  = att.get("disposition", "attachment")
    att["filename"]     = att["filename"].replace("{num}",  str(random.randint(10000, 99999)))
    att["filename"]     = att["filename"].replace("{year}", str(datetime.now(timezone.utc).year))
    # Sandbox status depends on content type and whether it's a threat
    ct = att["contentType"]
    if malicious:
        att["sandboxStatus"] = _SANDBOX_MALICIOUS
    elif ct.startswith("image/"):
        att["sandboxStatus"] = None   # Images not submitted to sandbox
    elif "pdf" in ct or "word" in ct or "excel" in ct or "powerpoint" in ct or "msword" in ct or "octet" in ct or "zip" in ct:
        att["sandboxStatus"] = _SANDBOX_CLEAN
    else:
        att["sandboxStatus"] = None
    return att


def _make_threats_info_map(classification, threat_id, threat_type, guid, campaign_id, url=None):
    """Build threatsInfoMap per official Proofpoint TAP SIEM API schema.

    Note: 'actors' is NOT a SIEM API field — it belongs to the TAP Campaign API.
    Fields here match exactly what Proofpoint pushes to SIEM integrations.
    """
    entry = {
        "classification": classification,
        "threat":         url if url else threat_id,
        "threatId":       threat_id,
        "threatStatus":   "active",
        "threatType":     threat_type,
        "campaignId":     campaign_id,
        "threatTime":     _now_iso(),
        "threatUrl":      _tap_threat_insight_url(guid),
    }
    return [entry]


def _base_message(config, recipients, guid, sender, sender_ip, subject):
    """Construct base fields matching real Proofpoint TAP SIEM API message event schema.

    Key schema facts from official docs:
      - fromAddress  : array ["sender@domain.com"]
      - replyToAddress: array [] or ["reply@domain.com"]
      - xmailer      : lowercase field name
      - cluster      : present alongside clusterId
      - policyRoutes : always starts with "default_inbound"; threat targets may add a second route
    """
    if not isinstance(recipients, list):
        recipients = [recipients]
    local = sender.split("@")[0] if "@" in sender else sender
    cid   = _cluster_id(config)
    return {
        "_log_type":          "message-delivered",  # caller overrides
        "GUID":               guid,
        "QID":                f"r{random.choice('abcdefghijklmnopqrstuvwxyz')}{random.randint(1,9)}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{random.randint(10000,99999)}",
        "messageID":          _make_message_id(local),
        "messageTime":        _now_iso(),
        "recipient":          recipients,
        "toAddresses":        recipients,
        "headerTo":           "; ".join([f'"{r.split("@")[0]}" <{r}>' for r in recipients]),
        "ccAddresses":        [],
        "fromAddress":        [sender],          # ARRAY per official SIEM API
        "sender":             sender,
        "senderIP":           sender_ip,
        "headerFrom":         f'"{local.replace(".", " ").replace("-", " ").title()}" <{sender}>',
        "subject":            subject,
        "messageSize":        random.randint(5000, 500000),
        "policyRoutes":       ["default_inbound"],
        "phishScore":         0,
        "malwareScore":       0,
        "spamScore":          0,
        "impostorScore":      0,
        "quarantineFolder":   None,
        "quarantineRule":     None,
        "completelyRewritten":False,
        "clusterId":          cid,
        "cluster":            cid,               # real API includes both
        "modulesRun":         ["spam", "urldefense"],
        "messageParts":       [_make_body_part()],
        "threatsInfoMap":     [],
        "replyToAddress":     [],                # ARRAY per official SIEM API (empty = no reply-to)
        "headerReplyTo":      None,
        "xmailer":            random.choice(_BENIGN_XMAILERS),  # lowercase per official API
        # Hunt-relevant top-level fields (not in XIF but searchable in raw dataset)
        "classification":     None,
        "threatID":           None,
        "threatURL":          None,
        "threatStatus":       None,
        "url":                None,
    }


# ---------------------------------------------------------------------------
# Benign generators
# ---------------------------------------------------------------------------

def _generate_benign_delivered(config, session_context=None):
    """Standard business email delivered to mailbox."""
    all_emails = _get_all_emails(config, session_context)
    recipients  = _pick_recipients(all_emails)
    guid        = _make_guid()
    sender      = _benign_sender(config)
    sender_ip   = _random_external_ip()
    subject     = _format_subject(random.choice(_BENIGN_SUBJECTS))

    msg = _base_message(config, recipients, guid, sender, sender_ip, subject)
    msg["_log_type"]   = "message-delivered"
    msg["phishScore"]  = random.randint(0, 15)
    msg["spamScore"]   = random.randint(0, 25)
    msg["modulesRun"]  = ["spam", "urldefense"]

    # 50% chance of a benign attachment
    if random.random() > 0.5:
        tmpl = random.choice(_BENIGN_ATTACHMENT_TEMPLATES)
        att  = _fill_attachment(tmpl)
        if "pdf" in att["contentType"]:
            msg["modulesRun"].append("pdr")
        msg["messageParts"].append(att)

    # 30% chance of CC
    if random.random() > 0.70 and len(all_emails) > 1:
        cc_pool = [e for e in all_emails if e not in recipients]
        if cc_pool:
            cc = random.sample(cc_pool, min(random.randint(1, 2), len(cc_pool)))
            msg["ccAddresses"] = cc
            msg["headerCC"]    = "; ".join([f'"{c.split("@")[0]}" <{c}>' for c in cc])

    # Clean None fields before serialisation
    _strip_none_threat_fields(msg)
    return json.dumps(msg, default=str)


# ---------------------------------------------------------------------------
# Threat generators
# ---------------------------------------------------------------------------

def _strip_none_threat_fields(msg):
    """Remove hunt fields that are None — keeps raw data clean for non-threat events."""
    for f in ("classification", "threatID", "threatURL", "threatStatus", "url"):
        if msg.get(f) is None:
            msg.pop(f, None)


def _generate_phishing_url(config, session_context=None):
    """URL-based phishing — message-blocked, URL rewrote, high phishScore."""
    all_emails  = _get_all_emails(config, session_context)
    recipients  = _pick_recipients(all_emails, count=random.randint(1, 2))
    guid        = _make_guid()
    sender      = _threat_sender(config)
    sender_ip   = _random_external_ip()
    subject     = _format_subject(random.choice(_PHISHING_SUBJECTS))
    camp_id     = _campaign_id(config)

    url          = _malicious_url(config)
    threat_sha, _= _generate_hashes()

    msg = _base_message(config, recipients, guid, sender, sender_ip, subject)
    msg["_log_type"]          = "message-blocked"
    msg["phishScore"]         = random.randint(80, 100)
    msg["spamScore"]          = random.randint(40, 80)
    msg["malwareScore"]       = random.randint(0, 30)
    msg["completelyRewritten"]= True
    msg["quarantineFolder"]   = "Phish"
    msg["quarantineRule"]     = "module.urldefense.phish"
    msg["modulesRun"]         = ["spam", "urldefense", "pdr"]
    msg["policyRoutes"]       = ["default_inbound", random.choice(_POLICY_ROUTES_EXTRA)]
    msg["classification"]     = "PHISHING"
    msg["threatID"]           = threat_sha
    msg["threatURL"]          = _tap_threat_insight_url(guid)
    msg["threatStatus"]       = "active"
    msg["url"]                = url

    # Suspicious reply-to — common phishing signal; replyToAddress is array per SIEM API
    reply_domain = random.choice(_DEFAULT_THREAT_SENDER_DOMAINS)
    reply_to     = f"reply-{random.randint(1000, 9999)}@{reply_domain}"
    msg["replyToAddress"]  = [reply_to]
    msg["headerReplyTo"]   = f'"Reply Handler" <{reply_to}>'

    msg["threatsInfoMap"] = _make_threats_info_map(
        "PHISHING", threat_sha, "URL", guid, camp_id, url=url)

    return json.dumps(msg, default=str)


def _generate_malware_attachment(config, session_context=None):
    """Malicious attachment — message-blocked, sandbox detonated, malwareScore high."""
    all_emails  = _get_all_emails(config, session_context)
    recipients  = _pick_recipients(all_emails, count=random.randint(1, 3))
    guid        = _make_guid()
    sender      = _threat_sender(config)
    sender_ip   = _random_external_ip()
    subject     = _format_subject(random.choice(_PHISHING_SUBJECTS))
    camp_id     = _campaign_id(config)

    tmpl = random.choice(_MALICIOUS_ATTACHMENT_TEMPLATES)
    att  = _fill_attachment(tmpl, malicious=True)

    msg = _base_message(config, recipients, guid, sender, sender_ip, subject)
    msg["_log_type"]          = "message-blocked"
    msg["malwareScore"]       = random.randint(90, 100)
    msg["phishScore"]         = random.randint(20, 60)
    msg["spamScore"]          = random.randint(30, 70)
    msg["completelyRewritten"]= True
    msg["quarantineFolder"]   = "Malware"
    msg["quarantineRule"]     = "module.sandbox.threat"
    msg["modulesRun"]         = ["spam", "urldefense", "pdr", "sandbox"]
    msg["messageParts"].append(att)

    threat_sha             = att["sha256"]
    msg["classification"]  = tmpl.get("classification", "MALWARE")
    msg["threatID"]        = threat_sha
    msg["threatURL"]       = _tap_threat_insight_url(guid)
    msg["threatStatus"]    = "active"
    msg["threatsInfoMap"]  = _make_threats_info_map(
        tmpl.get("classification", "MALWARE"), threat_sha,
        "ATTACHMENT", guid, camp_id)

    return json.dumps(msg, default=str)


def _generate_credential_phishing(config, session_context=None):
    """Credential harvesting phishing — high phishScore, fake login page URL."""
    all_emails  = _get_all_emails(config, session_context)
    recipients  = _pick_recipients(all_emails, count=random.randint(1, 5))
    guid        = _make_guid()
    sender      = _threat_sender(config)
    sender_ip   = _random_external_ip()
    subject     = _format_subject(random.choice([
        "Action Required: Verify your Microsoft 365 credentials",
        "URGENT: Your account will be suspended - verify now",
        "IT Security: Reset your password immediately",
        "VPN Access: Re-authentication required",
        "Unusual sign-in detected - verify your identity",
        "Your account has been locked - click to unlock",
    ]))
    camp_id = _campaign_id(config)

    url         = _malicious_url(config)
    threat_sha, _ = _generate_hashes()

    msg = _base_message(config, recipients, guid, sender, sender_ip, subject)
    msg["_log_type"]          = "message-blocked"
    msg["phishScore"]         = random.randint(90, 100)
    msg["spamScore"]          = random.randint(50, 85)
    msg["completelyRewritten"]= True
    msg["quarantineFolder"]   = "Phish"
    msg["quarantineRule"]     = "module.urldefense.phish"
    msg["modulesRun"]         = ["spam", "urldefense", "pdr"]
    msg["policyRoutes"]       = ["default_inbound", random.choice(_POLICY_ROUTES_EXTRA)]
    msg["classification"]     = "PHISHING"
    msg["threatID"]           = threat_sha
    msg["threatURL"]          = _tap_threat_insight_url(guid)
    msg["threatStatus"]       = "active"
    msg["url"]                = url

    msg["threatsInfoMap"] = _make_threats_info_map(
        "PHISHING", threat_sha, "URL", guid, camp_id, url=url)

    return json.dumps(msg, default=str)


def _generate_bec_impostor(config, session_context=None):
    """Business Email Compromise — delivered (low attachment/URL score), high impostorScore.

    BEC emails typically slip through because they carry no malicious payload.
    The signal is a high impostorScore and a mismatched reply-to address.
    Hunt: filter message-delivered where impostorScore > 75 AND replyToAddress differs from fromAddress.
    """
    all_emails = _get_all_emails(config, session_context)
    recipients  = _pick_recipients(all_emails, count=1)
    guid        = _make_guid()

    # Attacker uses a lookalike of the internal domain
    internal = _internal_domain(config)
    tld_map  = {".com": ".net", ".net": ".org", ".org": ".co", ".co": ".io"}
    lookalike = internal
    for orig, fake in tld_map.items():
        if internal.endswith(orig):
            lookalike = internal.replace(orig, fake)
            break
    else:
        lookalike = f"secure-{internal}"

    exec_names = ["ceo", "cfo", "president", "exec.director", "vp.finance", "board.secretary"]
    sender     = f"{random.choice(exec_names)}@{lookalike}"
    sender_ip  = _random_external_ip()
    subject    = random.choice(_BEC_SUBJECTS)

    msg = _base_message(config, recipients, guid, sender, sender_ip, subject)
    msg["_log_type"]    = "message-delivered"   # BEC usually delivered
    msg["impostorScore"]= random.randint(75, 100)
    msg["phishScore"]   = random.randint(20, 55)
    msg["spamScore"]    = random.randint(5, 30)
    msg["malwareScore"] = 0
    msg["modulesRun"]   = ["spam", "urldefense", "impostor"]

    # Reply-to misdirection — the defining BEC signal
    reply_to           = f"ceo-{random.randint(100, 999)}@gmail.com"
    msg["replyToAddress"] = [reply_to]           # ARRAY per official SIEM API
    msg["headerReplyTo"]  = f'"CEO" <{reply_to}>'

    msg["classification"] = "IMPOSTOR"
    msg["threatStatus"]   = "active"
    _strip_none_threat_fields(msg)  # BEC has no URL/threatID
    return json.dumps(msg, default=str)


def _generate_malicious_macro(config, session_context=None):
    """Macro-enabled Office document — sandbox detects on open, message-blocked."""
    all_emails = _get_all_emails(config, session_context)
    recipients  = _pick_recipients(all_emails, count=random.randint(1, 3))
    guid        = _make_guid()
    sender      = _threat_sender(config)
    sender_ip   = _random_external_ip()
    subject     = _format_subject(random.choice([
        "Invoice_{num} - Please review and approve",
        "Updated Purchase Order attached",
        "Payment Confirmation - Document Attached",
        "Tax Document {year} - Action Required",
        "Budget Approval Needed: See Attached",
    ]))
    camp_id = _campaign_id(config)

    macro_templates = [
        {"filename": "Invoice_{num}.xlsm",  "contentType": "application/vnd.ms-excel.sheet.macroEnabled.12"},
        {"filename": "PO_{num}.doc",         "contentType": "application/msword"},
        {"filename": "Report_{num}.xlsb",    "contentType": "application/vnd.ms-excel.sheet.binary.macroEnabled.12"},
        {"filename": "Statement_{num}.docm", "contentType": "application/vnd.ms-word.document.macroEnabled.12"},
    ]
    att = _fill_attachment(random.choice(macro_templates), malicious=True)

    msg = _base_message(config, recipients, guid, sender, sender_ip, subject)
    msg["_log_type"]          = "message-blocked"
    msg["malwareScore"]       = random.randint(85, 100)
    msg["phishScore"]         = random.randint(20, 50)
    msg["spamScore"]          = random.randint(30, 60)
    msg["completelyRewritten"]= True
    msg["quarantineFolder"]   = "Malware"
    msg["quarantineRule"]     = "module.sandbox.threat"
    msg["modulesRun"]         = ["spam", "urldefense", "pdr", "sandbox"]
    msg["messageParts"].append(att)

    threat_sha            = att["sha256"]
    msg["classification"] = "MALWARE"
    msg["threatID"]       = threat_sha
    msg["threatURL"]      = _tap_threat_insight_url(guid)
    msg["threatStatus"]   = "active"
    msg["threatsInfoMap"] = _make_threats_info_map(
        "MALWARE", threat_sha, "ATTACHMENT", guid, camp_id)

    return json.dumps(msg, default=str)


def _generate_qr_code_phishing(config, session_context=None):
    """QR code phishing — image attachment contains URL opaque to URL scanners.

    Hunt: message-blocked where modulesRun contains 'qr-scanner' AND classification='PHISH'.
    Attackers use this to bypass URL rewriting since the URL lives inside a PNG.
    """
    all_emails = _get_all_emails(config, session_context)
    recipients  = _pick_recipients(all_emails, count=random.randint(1, 4))
    guid        = _make_guid()
    sender      = _threat_sender(config)
    sender_ip   = _random_external_ip()
    subject     = _format_subject(random.choice([
        "Multi-Factor Authentication Required - Scan QR Code",
        "Secure Document Sharing - Scan to Access",
        "HR Benefits Update - Scan QR Code to Enroll",
        "IT: Mandatory VPN Certificate Renewal - Scan Here",
        "Action Required: Approve Pending Request via Mobile",
    ]))
    camp_id = _campaign_id(config)

    qr_att  = _fill_attachment({"filename": "AuthCode.png", "contentType": "image/png"})
    url         = _malicious_url(config)
    threat_sha, _ = _generate_hashes()

    msg = _base_message(config, recipients, guid, sender, sender_ip, subject)
    msg["_log_type"]          = "message-blocked"
    msg["phishScore"]         = random.randint(70, 95)
    msg["spamScore"]          = random.randint(30, 60)
    msg["completelyRewritten"]= False     # URL is inside image — can't be rewritten
    msg["quarantineFolder"]   = "Phish"
    msg["quarantineRule"]     = "module.qr.phish"
    msg["modulesRun"]         = ["spam", "urldefense", "pdr", "qr-scanner"]
    msg["messageParts"].append(qr_att)
    msg["url"]                = url
    msg["classification"]     = "PHISHING"
    msg["threatID"]           = threat_sha
    msg["threatURL"]          = _tap_threat_insight_url(guid)
    msg["threatStatus"]       = "active"
    msg["threatsInfoMap"]     = _make_threats_info_map(
        "PHISHING", threat_sha, "URL", guid, camp_id, url=url)

    return json.dumps(msg, default=str)


def _generate_callback_phishing(config, session_context=None):
    """Callback/TOAD phishing — no URL/attachment payload; threat is a phone number.

    Hunt: message-blocked where spamScore > 70 AND phishScore > 50 AND threatsInfoMap is empty.
    """
    all_emails = _get_all_emails(config, session_context)
    recipients  = _pick_recipients(all_emails, count=random.randint(1, 3))
    guid        = _make_guid()
    sender      = _threat_sender(config)
    sender_ip   = _random_external_ip()
    subject     = random.choice([
        "Your Norton subscription has been renewed - Call to cancel",
        "McAfee Security Alert: Unauthorized access detected",
        f"Amazon: Suspicious purchase $499 - Call +1-888-{random.randint(100,999)}-{random.randint(1000,9999)}",
        "Microsoft Support: Your computer is at risk",
        "IRS Notice: Overdue tax payment - Call immediately",
        f"Geek Squad: Auto-renewal of $399 - Call +1-855-{random.randint(100,999)}-{random.randint(1000,9999)}",
    ])

    msg = _base_message(config, recipients, guid, sender, sender_ip, subject)
    msg["_log_type"]          = "message-blocked"
    msg["phishScore"]         = random.randint(50, 80)
    msg["spamScore"]          = random.randint(75, 100)
    msg["malwareScore"]       = 0
    msg["completelyRewritten"]= False
    msg["quarantineFolder"]   = "Spam"
    msg["quarantineRule"]     = "module.spam.callback"
    msg["modulesRun"]         = ["spam", "urldefense"]
    msg["classification"]     = "PHISHING"
    msg["threatStatus"]       = "active"
    _strip_none_threat_fields(msg)
    return json.dumps(msg, default=str)


def _generate_click_blocked(config, session_context=None, guid_override=None,
                             sender_override=None, sender_ip_override=None,
                             subject_override=None, target_email=None):
    """User clicked a rewritten URL; TAP URL Defense blocked the destination.

    This is a high-confidence indicator — XSIAM alert: 'Proofpoint - User Clicked Malicious Link'
    Hunt: click-blocked where clickIP = internal workstation IP → join with Zscaler/Firepower.
    """
    all_emails     = _get_all_emails(config, session_context)
    recipient_email= target_email or (random.choice(all_emails) if all_emails else "user@examplecorp.com")
    guid           = guid_override or _make_guid()

    # Use the target user's IP when known; fall back to a random user otherwise
    click_ip = None
    if session_context:
        if target_email:
            for _profile in session_context.values():
                if _profile.get('email') == target_email:
                    click_ip = _profile.get('primary_ip')
                    break
        if not click_ip:
            user_info = get_random_user(session_context)
            if user_info:
                click_ip = user_info.get("ip")
                if not target_email:
                    recipient_email = user_info.get("email", recipient_email)
    click_ip = click_ip or f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    url         = _malicious_url(config)
    threat_sha, _ = _generate_hashes()

    _sender   = sender_override or _threat_sender(config)
    _camp_id  = _campaign_id(config)
    _threat_t = _now_iso()
    event = {
        "_log_type":      "click-blocked",
        "GUID":           guid,
        "messageID":      _make_message_id(recipient_email.split("@")[0]),
        "clickTime":      _now_iso(),
        "clickIP":        click_ip,
        "userAgent":      random.choice(_BROWSER_UA),
        "url":            url,
        "recipient":      recipient_email,        # string per official click event schema
        "classification": "PHISHING",
        "campaignId":     _camp_id,               # top-level per official click event schema
        "threatID":       threat_sha,
        "threatTime":     _threat_t,              # top-level per official click event schema
        "threatURL":      _tap_threat_insight_url(guid),
        "threatStatus":   "active",
        "clusterId":      _cluster_id(config),
        "cluster":        _cluster_id(config),
        "sender":         _sender,
        "senderIP":       sender_ip_override or _random_external_ip(),
        "fromAddress":    [_sender],              # ARRAY per official SIEM API
        "subject":        subject_override or _format_subject(random.choice(_PHISHING_SUBJECTS)),
        "phishScore":     random.randint(80, 100),
        "malwareScore":   random.randint(0, 30),
        "spamScore":      random.randint(40, 80),
        "impostorScore":  0,
        "policyRoutes":   ["default_inbound"],
        "modulesRun":     ["urldefense"],
        "messageTime":    _offset_iso(random.randint(60, 900)),  # Message arrived earlier
    }
    return json.dumps(event, default=str)


def _generate_click_permitted(config, session_context=None, guid_override=None,
                               sender_override=None, sender_ip_override=None,
                               subject_override=None, target_email=None):
    """User clicked URL; TAP allowed it at time of click — later retroactively flagged.

    This is a critical signal: the user SUCCESSFULLY reached a phishing page.
    Hunt: click-permitted events → correlate clickIP with Zscaler proxy logs
    (same src IP visiting same URL shortly after) → then Okta failed/succeeded logins.
    threatStatus='active' means still considered a threat.
    """
    all_emails     = _get_all_emails(config, session_context)
    recipient_email= target_email or (random.choice(all_emails) if all_emails else "user@examplecorp.com")
    guid           = guid_override or _make_guid()

    # Use the target user's IP when known; fall back to a random user otherwise
    click_ip = None
    if session_context:
        if target_email:
            for _profile in session_context.values():
                if _profile.get('email') == target_email:
                    click_ip = _profile.get('primary_ip')
                    break
        if not click_ip:
            user_info = get_random_user(session_context)
            if user_info:
                click_ip = user_info.get("ip")
                if not target_email:
                    recipient_email = user_info.get("email", recipient_email)
    click_ip = click_ip or f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    url         = _malicious_url(config)
    threat_sha, _ = _generate_hashes()

    _sender   = sender_override or _threat_sender(config)
    _camp_id  = _campaign_id(config)
    _click_t  = _offset_iso(random.randint(30, 3600))   # Clicked a while back
    _threat_t = _offset_iso(random.randint(0, 30))       # TAP identified threat just before/after click
    event = {
        "_log_type":      "click-permitted",
        "GUID":           guid,
        "messageID":      _make_message_id(recipient_email.split("@")[0]),
        "clickTime":      _click_t,
        "clickIP":        click_ip,
        "userAgent":      random.choice(_BROWSER_UA),
        "url":            url,
        "recipient":      recipient_email,        # string per official click event schema
        "classification": "PHISHING",
        "campaignId":     _camp_id,               # top-level per official click event schema
        "threatID":       threat_sha,
        "threatTime":     _threat_t,              # top-level per official click event schema
        "threatURL":      _tap_threat_insight_url(guid),
        "threatStatus":   "active",
        "clusterId":      _cluster_id(config),
        "cluster":        _cluster_id(config),
        "sender":         _sender,
        "senderIP":       sender_ip_override or _random_external_ip(),
        "fromAddress":    [_sender],              # ARRAY per official SIEM API
        "subject":        subject_override or _format_subject(random.choice(_PHISHING_SUBJECTS)),
        "phishScore":     random.randint(60, 90),
        "malwareScore":   random.randint(0, 20),
        "spamScore":      random.randint(30, 70),
        "impostorScore":  0,
        "policyRoutes":   ["default_inbound"],
        "modulesRun":     ["urldefense"],
        "messageTime":    _offset_iso(random.randint(900, 7200)),  # Original message was older
    }
    return json.dumps(event, default=str)


def _generate_spam_campaign(config, session_context=None):
    """High-volume spam campaign — burst of messages from same sender IP.

    Returns a list of JSON strings.
    Hunt: message-blocked from same senderIP count >= 5 in 1 hour (XSIAM built-in alert).
    """
    all_emails = _get_all_emails(config, session_context)
    sender     = _threat_sender(config)
    sender_ip  = _random_external_ip()
    subject    = random.choice(_SPAM_SUBJECTS)
    count      = random.randint(5, 18)

    logs = []
    for _ in range(count):
        recipients = _pick_recipients(all_emails, count=random.randint(1, 3))
        guid       = _make_guid()
        msg        = _base_message(config, recipients, guid, sender, sender_ip, subject)
        msg["_log_type"]       = "message-blocked"
        msg["spamScore"]       = random.randint(85, 100)
        msg["phishScore"]      = random.randint(10, 40)
        msg["quarantineFolder"]= "Spam"
        msg["quarantineRule"]  = "module.spam.bulk"
        msg["modulesRun"]      = ["spam", "urldefense"]
        msg["classification"]  = "SPAM"
        msg["threatStatus"]    = "active"
        _strip_none_threat_fields(msg)
        logs.append(json.dumps(msg, default=str))
    return logs


def _generate_phishing_campaign(config, session_context=None):
    """Targeted phishing campaign — same attacker sends to many internal recipients.

    Returns a list of JSON strings (one per recipient pair).
    Hunt: same senderIP + same subject → many different recipients in short window.
    Useful to correlate with click-blocked events that share the same GUID.
    """
    all_emails = _get_all_emails(config, session_context)
    sender     = _threat_sender(config)
    sender_ip  = _random_external_ip()
    camp_id    = _campaign_id(config)
    subject    = _format_subject(random.choice(_PHISHING_SUBJECTS))
    count      = random.randint(4, 10)

    url         = _malicious_url(config)
    threat_sha, _ = _generate_hashes()

    logs = []
    for _ in range(count):
        recipients = _pick_recipients(all_emails, count=random.randint(1, 2))
        guid       = _make_guid()
        msg        = _base_message(config, recipients, guid, sender, sender_ip, subject)
        msg["_log_type"]          = "message-blocked"
        msg["phishScore"]         = random.randint(80, 100)
        msg["spamScore"]          = random.randint(40, 75)
        msg["completelyRewritten"]= True
        msg["quarantineFolder"]   = "Phish"
        msg["quarantineRule"]     = "module.urldefense.phish"
        msg["modulesRun"]         = ["spam", "urldefense", "pdr"]
        msg["classification"]     = "PHISHING"
        msg["threatID"]           = threat_sha         # Same threat across campaign
        msg["threatURL"]          = _tap_threat_insight_url(guid)
        msg["threatStatus"]       = "active"
        msg["url"]                = url
        msg["threatsInfoMap"]     = _make_threats_info_map(
            "PHISHING", threat_sha, "URL", guid, camp_id, url=url)
        logs.append(json.dumps(msg, default=str))
    return logs


# ---------------------------------------------------------------------------
# Scenario event handlers (storytelling / kill-chain mode)
# ---------------------------------------------------------------------------

def _generate_scenario_event(scenario_event, config, context):
    """Handle explicit scenario_event calls from log_simulator.py.

    Supported scenario_event values:
      PHISHING_DELIVERED  – email slips through TAP (low score), user receives it
      PHISHING_BLOCKED    – TAP catches and quarantines phishing email
      CLICK_BLOCKED       – user clicked URL; TAP URL Defense blocked it
      CLICK_PERMITTED     – user clicked URL; TAP allowed it (retroactive threat)
      MALWARE_ATTACHMENT  – malicious file attachment blocked
      BEC_EMAIL           – Business Email Compromise impostor email delivered

    Context keys used:
      session_context  – stable user/IP mapping
      target_email     – specific recipient email address
      sender_ip        – force a specific sender IP (for campaign correlation)
      shared_guid      – tie a click event to a specific message GUID
    """
    session_context = (context or {}).get("session_context")
    target_email    = (context or {}).get("target_email")
    sender_ip_ctx   = (context or {}).get("sender_ip")
    shared_guid     = (context or {}).get("shared_guid")

    if scenario_event == "PHISHING_DELIVERED":
        # Email slipped past TAP — low-enough scores, novel threat
        all_emails  = _get_all_emails(config, session_context)
        recipients  = [target_email] if target_email else _pick_recipients(all_emails, count=1)
        guid        = shared_guid or _make_guid()
        sender      = _threat_sender(config)
        sender_ip   = sender_ip_ctx or _random_external_ip()
        subject     = _format_subject(random.choice(_PHISHING_SUBJECTS))

        msg = _base_message(config, recipients, guid, sender, sender_ip, subject)
        msg["_log_type"]          = "message-delivered"     # Key: delivered, not blocked
        msg["phishScore"]         = random.randint(25, 60)  # Low enough to slip through
        msg["spamScore"]          = random.randint(15, 45)
        msg["completelyRewritten"]= True    # URLs rewritten for TAP tracking
        msg["modulesRun"]         = ["spam", "urldefense"]

        url         = _malicious_url(config)
        threat_sha, _ = _generate_hashes()
        msg["url"]            = url
        msg["classification"] = "PHISHING"
        msg["threatID"]       = threat_sha
        msg["threatURL"]      = _tap_threat_insight_url(guid)
        msg["threatStatus"]   = "active"
        return json.dumps(msg, default=str), "PHISHING_DELIVERED"

    elif scenario_event == "PHISHING_BLOCKED":
        log = _generate_phishing_url(config, session_context)
        return log, "PHISHING_BLOCKED"

    elif scenario_event == "CLICK_BLOCKED":
        log = _generate_click_blocked(
            config, session_context,
            guid_override=shared_guid,
            sender_ip_override=sender_ip_ctx,
            target_email=target_email,
        )
        return log, "CLICK_BLOCKED"

    elif scenario_event == "CLICK_PERMITTED":
        log = _generate_click_permitted(
            config, session_context,
            guid_override=shared_guid,
            sender_ip_override=sender_ip_ctx,
            target_email=target_email,
        )
        return log, "CLICK_PERMITTED"

    elif scenario_event == "MALWARE_ATTACHMENT":
        log = _generate_malware_attachment(config, session_context)
        return log, "MALWARE_ATTACHMENT"

    elif scenario_event == "BEC_EMAIL":
        log = _generate_bec_impostor(config, session_context)
        return log, "BEC_EMAIL"

    elif scenario_event in _THREAT_GENERATORS:
        return _THREAT_GENERATORS[scenario_event](config, session_context)

    return None, None


# ---------------------------------------------------------------------------
# Threat dispatcher
# ---------------------------------------------------------------------------

_THREAT_GENERATORS = {
    "phishing_url":        _generate_phishing_url,
    "malware_attachment":  _generate_malware_attachment,
    "credential_phishing": _generate_credential_phishing,
    "bec_impostor":        _generate_bec_impostor,
    "spam_campaign":       _generate_spam_campaign,
    "malicious_macro":     _generate_malicious_macro,
    "click_blocked":       _generate_click_blocked,
    "click_permitted":     _generate_click_permitted,
    "qr_code_phishing":    _generate_qr_code_phishing,
    "callback_phishing":   _generate_callback_phishing,
    "phishing_campaign":   _generate_phishing_campaign,
}


def get_threat_names():
    """Return available threat names dynamically from _THREAT_GENERATORS.
    Adding a new entry to _THREAT_GENERATORS automatically surfaces it here."""
    return list(_THREAT_GENERATORS.keys())


def _select_threat(config, session_context):
    """Pick and run a threat generator according to config weights."""
    cfg_mix = _cf(config).get("event_mix", {}).get("threat", {})
    weights_cfg = {k: cfg_mix.get(k, v) for k, v in _THREAT_WEIGHTS.items()}

    choices = list(weights_cfg.keys())
    weights = list(weights_cfg.values())
    threat_type = random.choices(choices, weights=weights, k=1)[0]

    fn = _THREAT_GENERATORS.get(threat_type, _generate_phishing_url)
    return (fn(config, session_context), threat_type)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_log(config, scenario=None, scenario_event=None, threat_level="Realistic",
                 benign_only=False, context=None):
    """
    Generate a Proofpoint TAP log event.

    Returns:
        str          – single JSON log string (most events)
        list[str]    – multiple JSON strings (spam_campaign, phishing_campaign)
        tuple(str,str) – (log_string, event_name) when called via scenario_event
    """
    global last_threat_event_time
    session_context = (context or {}).get("session_context")

    # --- Storytelling / scenario mode ---
    if scenario_event:
        return _generate_scenario_event(scenario_event, config, context)

    if scenario:
        return None

    # --- Benign-only mode ---
    if benign_only:
        return _generate_benign_delivered(config, session_context)

    # --- Insane mode: 40% threat ---
    if threat_level == "Insane":
        if random.random() < 0.40:
            return _select_threat(config, session_context)
        return _generate_benign_delivered(config, session_context)

    # --- Normal paced mode ---
    interval     = _get_threat_interval(threat_level, config)
    current_time = time.time()
    if (current_time - last_threat_event_time) > interval:
        last_threat_event_time = current_time
        return _select_threat(config, session_context)

    return _generate_benign_delivered(config, session_context)
