# modules/windows_events.py
# Simulates Windows Security Event Log entries in the WEC/WEF-rendered JSON
# shape produced by NXLog im_msvistalog / Winlogbeat / XDR Collector.
#
# Dataset (XSIAM):  microsoft_windows_raw
# XSIAM content pack reference:
#   https://cortex.marketplace.pan.dev/marketplace/details/MicrosoftWindowsEvents/
#   (demisto/content Packs/MicrosoftWindowsEvents – Security channel / Provider
#    "Microsoft-Windows-Security-Auditing")
# Transport:        http (XSIAM HTTP Log Collector)
#
# ── Scope (v1) ─────────────────────────────────────────────────────────────
# Only users in config.json whose primary device os_type == "Windows" are
# used.  macOS / Ubuntu / Android users are ignored by this module.  The
# user's Windows `hostname` and `ip` from the session_context is used as the
# event Computer and IpAddress respectively.
#
# ── Event IDs generated ────────────────────────────────────────────────────
# Endpoint (Security channel, Computer = user's workstation):
#   4624  An account was successfully logged on
#   4625  An account failed to log on
#   4634  An account was logged off
#   4647  User initiated logoff
#   4648  A logon was attempted using explicit credentials
#
# Synthetic Domain Controller (Security channel, Computer = "DC01.examplecorp.local"):
#   4740  A user account was locked out
#   4768  A Kerberos authentication ticket (TGT) was requested
#   4769  A Kerberos service ticket was requested
#   4771  Kerberos pre-authentication failed
#   4776  The computer attempted to validate the credentials for an account
#
# ── State awareness ────────────────────────────────────────────────────────
# The module keeps in-memory state per user for the life of the process:
#   • open logon sessions (logon_id → workstation, ip, logon_type, start_time)
#   • password-failure streaks (for lockout pacing)
# Logoff events (4634 / 4647) are ONLY emitted for a TargetLogonId that was
# produced by a prior 4624 in this same process.  Logoff time is always
# minutes-to-hours after the corresponding logon.  Workstation logons are
# paired with a DC 4768 (domain) or 4776 (NTLM) a fraction of a second
# earlier so the cross-host correlation line up in XSIAM UEBA.
#
# ── JSON shape ─────────────────────────────────────────────────────────────
# Every event is a single JSON object whose top-level fields mirror the
# NXLog im_msvistalog flat layout that the XSIAM content pack parses.  The
# EventData fields are merged into the top level (this is what NXLog emits
# by default and what the demisto Security parser expects).  The same
# payload is also repeated inside a nested "EventData" object so modeling
# rules that look at either shape find their fields.
#
# This module only generates synthetic events for log-ingestion and
# detection-rule testing. It never touches a real Windows machine.

import random
import re
import time
import json
import uuid
import hashlib
import threading
import queue as _queue_mod
from datetime import datetime, timezone, timedelta

try:
    from lxml import etree as _etree
    _HAS_LXML = True
except ImportError:
    _HAS_LXML = False

try:
    from modules.session_utils import get_random_user, get_user_by_name, get_random_anon_ip_ctx
except ImportError:
    from session_utils import get_random_user, get_user_by_name, get_random_anon_ip_ctx


# ---------------------------------------------------------------------------
# Required module-level attributes (the auto-loader uses these)
# ---------------------------------------------------------------------------

NAME        = "Windows Event Log"
DESCRIPTION = "Simulates Windows Security channel events (4624/4625/4634/4647/4648/4740/4768/4769/4771/4776) in NXLog-style JSON."
XSIAM_VENDOR  = "Microsoft"
XSIAM_PRODUCT = "Windows"
CONFIG_KEY    = "windows_events_config"

# Module-level pacing state
last_threat_event_time = 0

# Set from config at generate_log() time so _build_event can use it
_BUILD_EVENT_OS_SUBTYPE = "Windows 10"


# ---------------------------------------------------------------------------
# Static Windows reference data
# ---------------------------------------------------------------------------

_PROVIDER_NAME = "Microsoft-Windows-Security-Auditing"
_PROVIDER_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
_CHANNEL       = "Security"

# Logon types per Microsoft docs for event 4624
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
_LOGON_TYPE_LABELS = {
    2:  "Interactive",
    3:  "Network",
    4:  "Batch",
    5:  "Service",
    7:  "Unlock",
    8:  "NetworkCleartext",
    9:  "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}

# Keywords bitmask values Windows emits in the record header.
# 0x8020000000000000 = Audit Success
# 0x8010000000000000 = Audit Failure
_KW_AUDIT_SUCCESS = "0x8020000000000000"
_KW_AUDIT_FAILURE = "0x8010000000000000"

# (EventID → (Task category number, Task name, Version, default-success-or-failure))
# Task numbers pulled from the Security provider manifest on Windows 10/11.
_EVENT_META = {
    4624: {"task": 12544, "category": "Logon",                 "version": 2, "outcome": "success"},
    4625: {"task": 12546, "category": "Logon",                 "version": 0, "outcome": "failure"},
    4634: {"task": 12545, "category": "Logoff",                "version": 0, "outcome": "success"},
    4647: {"task": 12545, "category": "Logoff",                "version": 0, "outcome": "success"},
    4648: {"task": 12544, "category": "Logon",                 "version": 0, "outcome": "success"},
    4740: {"task": 13824, "category": "User Account Management","version": 0, "outcome": "success"},
    4768: {"task": 14339, "category": "Kerberos Authentication Service", "version": 2, "outcome": "success"},
    4769: {"task": 14337, "category": "Kerberos Service Ticket Operations", "version": 0, "outcome": "success"},
    4771: {"task": 14339, "category": "Kerberos Authentication Service", "version": 0, "outcome": "failure"},
    4776: {"task": 14336, "category": "Credential Validation", "version": 0, "outcome": "success"},
    4672: {"task": 12548, "category": "Special Logon",          "version": 0, "outcome": "success"},
    4688: {"task": 13312, "category": "Process Creation",       "version": 2, "outcome": "success"},
    4689: {"task": 13313, "category": "Process Termination",    "version": 0, "outcome": "success"},
    4767: {"task": 13824, "category": "User Account Management","version": 0, "outcome": "success"},
    4662: {"task": 14080, "category": "Directory Service Access","version": 0, "outcome": "success"},
    4656: {"task": 12800, "category": "File System",            "version": 1, "outcome": "success"},
    4663: {"task": 12800, "category": "File System",            "version": 1, "outcome": "success"},
    4741: {"task": 13825, "category": "Computer Account Management","version": 0, "outcome": "success"},
    4742: {"task": 13825, "category": "Computer Account Management","version": 0, "outcome": "success"},
    4728: {"task": 13826, "category": "Security Group Management",   "version": 0, "outcome": "success"},
    4732: {"task": 13826, "category": "Security Group Management",   "version": 0, "outcome": "success"},
    4756: {"task": 13826, "category": "Security Group Management",   "version": 0, "outcome": "success"},
    4729: {"task": 13826, "category": "Security Group Management",   "version": 0, "outcome": "success"},
    4733: {"task": 13826, "category": "Security Group Management",   "version": 0, "outcome": "success"},
    4757: {"task": 13826, "category": "Security Group Management",   "version": 0, "outcome": "success"},
    5136: {"task": 14081, "category": "Directory Service Changes",  "version": 0, "outcome": "success"},
    5137: {"task": 14081, "category": "Directory Service Changes",  "version": 0, "outcome": "success"},
    4886: {"task": 12290, "category": "Certification Services",    "version": 0, "outcome": "success"},
    4887: {"task": 12290, "category": "Certification Services",    "version": 0, "outcome": "success"},
    4888: {"task": 12290, "category": "Certification Services",    "version": 0, "outcome": "failure"},
    4720: {"task": 13824, "category": "User Account Management",   "version": 0, "outcome": "success"},
    4722: {"task": 13824, "category": "User Account Management",   "version": 0, "outcome": "success"},
    4724: {"task": 13824, "category": "User Account Management",   "version": 0, "outcome": "success"},
    4725: {"task": 13824, "category": "User Account Management",   "version": 0, "outcome": "success"},
    4726: {"task": 13824, "category": "User Account Management",   "version": 0, "outcome": "success"},
    4738: {"task": 13824, "category": "User Account Management",   "version": 0, "outcome": "success"},
}

def _format_message(event_id: int, ed: dict) -> str:
    """Build the full Windows-style message text for a given event ID."""
    d = ed
    _b = _MSG_BUILDERS.get(event_id)
    if _b:
        return _b(d)
    return f"Event ID {event_id}"


def _msg_4624(d):
    return (
        "An account was successfully logged on.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Logon Information:\r\n"
        f"\tLogon Type:\t\t{d.get('LogonType','')}\r\n"
        f"\tRestricted Admin Mode:\t{d.get('RestrictedAdminMode','-')}\r\n"
        f"\tVirtual Account:\t\t{d.get('VirtualAccount','')}\r\n"
        f"\tElevated Token:\t\t{d.get('ElevatedToken','')}\r\n\r\n"
        f"Impersonation Level:\t\t{d.get('ImpersonationLevel','')}\r\n\r\n"
        "New Logon:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('TargetLogonId','')}\r\n"
        f"\tLinked Logon ID:\t\t{d.get('TargetLinkedLogonId','0x0')}\r\n"
        f"\tNetwork Account Name:\t{d.get('TargetOutboundUserName','-')}\r\n"
        f"\tNetwork Account Domain:\t{d.get('TargetOutboundDomainName','-')}\r\n"
        f"\tLogon GUID:\t\t{d.get('LogonGuid','')}\r\n\r\n"
        "Process Information:\r\n"
        f"\tProcess ID:\t\t{d.get('ProcessId','')}\r\n"
        f"\tProcess Name:\t\t{d.get('ProcessName','')}\r\n\r\n"
        "Network Information:\r\n"
        f"\tWorkstation Name:\t{d.get('WorkstationName','')}\r\n"
        f"\tSource Network Address:\t{d.get('IpAddress','')}\r\n"
        f"\tSource Port:\t\t{d.get('IpPort','')}\r\n\r\n"
        "Detailed Authentication Information:\r\n"
        f"\tLogon Process:\t\t{d.get('LogonProcessName','')}\r\n"
        f"\tAuthentication Package:\t{d.get('AuthenticationPackageName','')}\r\n"
        f"\tTransited Services:\t{d.get('TransmittedServices','')}\r\n"
        f"\tPackage Name (NTLM only):\t{d.get('LmPackageName','')}\r\n"
        f"\tKey Length:\t\t{d.get('KeyLength','')}\r\n\r\n"
        "This event is generated when a logon session is created. It is generated on "
        "the computer that was accessed.\r\n\r\n"
        "The subject fields indicate the account on the local system which requested "
        "the logon. This is most commonly a service such as the Server service, or a "
        "local process such as Winlogon.exe or Services.exe.\r\n\r\n"
        "The logon type field indicates the kind of logon that occurred. The most common "
        "types are 2 (interactive) and 3 (network).\r\n\r\n"
        "The New Logon fields indicate the account for whom the new logon was created, "
        "i.e. the account that was logged on.\r\n\r\n"
        "The network fields indicate where a remote logon request originated. Workstation "
        "name is not always available and may be left blank in some cases.\r\n\r\n"
        "The impersonation level field indicates the extent to which a process in the "
        "logon session can impersonate.\r\n\r\n"
        "The authentication information fields provide detailed information about this "
        "specific logon request.\r\n"
        "\t- Logon GUID is a unique identifier that can be used to correlate this event "
        "with a KDC event.\r\n"
        "\t- Transited services indicate which intermediate services have participated in "
        "this logon request.\r\n"
        "\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n"
        "\t- Key length indicates the length of the generated session key. This will be 0 "
        "if no session key was requested."
    )


def _msg_4625(d):
    return (
        "An account failed to log on.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Logon Type:\t\t\t{}\r\n\r\n".format(d.get('LogonType','')) +
        "Account For Which Logon Failed:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Failure Information:\r\n"
        f"\tFailure Reason:\t\t{d.get('FailureReason','')}\r\n"
        f"\tStatus:\t\t\t{d.get('Status','')}\r\n"
        f"\tSub Status:\t\t{d.get('SubStatus','')}\r\n\r\n"
        "Process Information:\r\n"
        f"\tCaller Process ID:\t{d.get('ProcessId','')}\r\n"
        f"\tCaller Process Name:\t{d.get('ProcessName','')}\r\n\r\n"
        "Network Information:\r\n"
        f"\tWorkstation Name:\t{d.get('WorkstationName','')}\r\n"
        f"\tSource Network Address:\t{d.get('IpAddress','')}\r\n"
        f"\tSource Port:\t\t{d.get('IpPort','')}\r\n\r\n"
        "Detailed Authentication Information:\r\n"
        f"\tLogon Process:\t\t{d.get('LogonProcessName','')}\r\n"
        f"\tAuthentication Package:\t{d.get('AuthenticationPackageName','')}\r\n"
        f"\tTransited Services:\t{d.get('TransmittedServices','')}\r\n"
        f"\tPackage Name (NTLM only):\t{d.get('LmPackageName','')}\r\n"
        f"\tKey Length:\t\t{d.get('KeyLength','')}\r\n\r\n"
        "The subject fields indicate the account on the local system which requested "
        "the logon. This is most commonly a service such as the Server service, or a "
        "local process such as Winlogon.exe or Services.exe.\r\n\r\n"
        "The Logon Type field indicates the kind of logon that was requested. The most "
        "common types are 2 (interactive) and 3 (network).\r\n\r\n"
        "The Process Information fields indicate which account and process on the system "
        "requested the logon.\r\n\r\n"
        "The Network Information fields indicate where a remote logon request originated. "
        "Workstation name is not always available and may be left blank in some cases.\r\n\r\n"
        "The authentication information fields provide detailed information about this "
        "specific logon request.\r\n"
        "\t- Transited services indicate which intermediate services have participated in "
        "this logon request.\r\n"
        "\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n"
        "\t- Key length indicates the length of the generated session key. This will be 0 "
        "if no session key was requested."
    )


def _msg_4634(d):
    return (
        "An account was logged off.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('TargetLogonId','')}\r\n\r\n"
        f"Logon Type:\t\t\t{d.get('LogonType','')}\r\n\r\n"
        "This event is generated when a logon session is destroyed. It may be positively "
        "correlated with a logon event using the Logon ID value. Logon IDs are only unique "
        "between reboots on the same computer."
    )


def _msg_4647(d):
    return (
        "User initiated logoff:\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('TargetLogonId','')}"
    )


def _msg_4648(d):
    return (
        "A logon was attempted using explicit credentials.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n"
        f"\tLogon GUID:\t\t{d.get('LogonGuid','')}\r\n\r\n"
        "Account Whose Credentials Were Used:\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n"
        f"\tLogon GUID:\t\t{d.get('TargetLogonGuid','')}\r\n\r\n"
        "Target Server:\r\n"
        f"\tTarget Server Name:\t{d.get('TargetServerName','')}\r\n"
        f"\tAdditional Information:\t{d.get('TargetInfo','')}\r\n\r\n"
        "Process Information:\r\n"
        f"\tProcess ID:\t\t{d.get('ProcessId','')}\r\n"
        f"\tProcess Name:\t\t{d.get('ProcessName','')}\r\n\r\n"
        "Network Information:\r\n"
        f"\tNetwork Address:\t{d.get('IpAddress','')}\r\n"
        f"\tPort:\t\t\t{d.get('IpPort','')}\r\n\r\n"
        "This event is generated when a process attempts to log on an account by "
        "explicitly specifying that account's credentials.  This most commonly occurs "
        "in batch-type configurations such as scheduled tasks, or when using the "
        "RUNAS command."
    )


def _msg_4740(d):
    return (
        "A user account was locked out.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Account That Was Locked Out:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tCaller Computer Name:\t{d.get('TargetDomainName','')}"
    )


def _msg_4768(d):
    domain_dns = d.get('TargetDomainName', '')
    domain_nb = domain_dns.split('.')[0].upper() if '.' in domain_dns else domain_dns
    acct = d.get('TargetUserName', '').split('@')[0]
    user_id = f"{domain_nb}\\{acct}" if domain_nb else d.get('TargetSid', '')
    svc_name = d.get('ServiceName', '')
    svc_id = f"{domain_nb}\\{svc_name}" if domain_nb else d.get('ServiceSid', '')
    return (
        "A Kerberos authentication ticket (TGT) was requested.\r\n\r\n"
        "Account Information:\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tSupplied Realm Name:\t{domain_dns}\r\n"
        f"\tUser ID:\t\t\t{user_id}\r\n\r\n"
        "Service Information:\r\n"
        f"\tService Name:\t\t{svc_name}\r\n"
        f"\tService ID:\t\t{svc_id}\r\n\r\n"
        "Network Information:\r\n"
        f"\tClient Address:\t\t{d.get('IpAddress','')}\r\n"
        f"\tClient Port:\t\t{d.get('IpPort','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tTicket Options:\t\t{d.get('TicketOptions','')}\r\n"
        f"\tResult Code:\t\t{d.get('Status','')}\r\n"
        f"\tTicket Encryption Type:\t{d.get('TicketEncryptionType','')}\r\n"
        f"\tPre-Authentication Type:\t{d.get('PreAuthType','')}\r\n\r\n"
        "Certificate Information:\r\n"
        f"\tCertificate Issuer Name:\t\t{d.get('CertIssuerName','')}\r\n"
        f"\tCertificate Serial Number:\t{d.get('CertSerialNumber','')}\r\n"
        f"\tCertificate Thumbprint:\t\t{d.get('CertThumbprint','')}\r\n\r\n"
        "Certificate information is only provided if a certificate was used for "
        "pre-authentication.\r\n\r\n"
        "Pre-authentication types, ticket options, encryption types and result codes "
        "are defined in RFC 4120."
    )


def _msg_4769(d):
    return (
        "A Kerberos service ticket was requested.\r\n\r\n"
        "Account Information:\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n"
        f"\tLogon GUID:\t\t{d.get('LogonGuid','')}\r\n\r\n"
        "Service Information:\r\n"
        f"\tService Name:\t\t{d.get('ServiceName','')}\r\n"
        f"\tService ID:\t\t{d.get('ServiceSid','')}\r\n\r\n"
        "Network Information:\r\n"
        f"\tClient Address:\t\t{d.get('IpAddress','')}\r\n"
        f"\tClient Port:\t\t{d.get('IpPort','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tTicket Options:\t\t{d.get('TicketOptions','')}\r\n"
        f"\tTicket Encryption Type:\t{d.get('TicketEncryptionType','')}\r\n"
        f"\tFailure Code:\t\t{d.get('Status','')}\r\n"
        f"\tTransited Services:\t{d.get('TransmittedServices','')}\r\n\r\n"
        "This event is generated every time access is requested to a resource such as a "
        "computer or a Windows service.  The service name indicates the resource to which "
        "access was requested.\r\n\r\n"
        "This event can be correlated with Windows logon events by comparing the Logon GUID "
        "fields in each event.  The logon event occurs on the machine that was accessed, "
        "which is often a different machine than the domain controller which issued the "
        "service ticket.\r\n\r\n"
        "Ticket options, encryption types, and failure codes are defined in RFC 4120."
    )


def _msg_4771(d):
    return (
        "Kerberos pre-authentication failed.\r\n\r\n"
        "Account Information:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n\r\n"
        "Service Information:\r\n"
        f"\tService Name:\t\t{d.get('ServiceName','')}\r\n\r\n"
        "Network Information:\r\n"
        f"\tClient Address:\t\t{d.get('IpAddress','')}\r\n"
        f"\tClient Port:\t\t{d.get('IpPort','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tTicket Options:\t\t{d.get('TicketOptions','')}\r\n"
        f"\tFailure Code:\t\t{d.get('Status','')}\r\n"
        f"\tPre-Authentication Type:\t{d.get('PreAuthType','')}\r\n\r\n"
        "Certificate Information:\r\n"
        f"\tCertificate Issuer Name:\t\t{d.get('CertIssuerName','')}\r\n"
        f"\tCertificate Serial Number:\t{d.get('CertSerialNumber','')}\r\n"
        f"\tCertificate Thumbprint:\t\t{d.get('CertThumbprint','')}"
    )


def _msg_4776(d):
    return (
        "The computer attempted to validate the credentials for an account.\r\n\r\n"
        f"Authentication Package:\t{d.get('PackageName','MICROSOFT_AUTHENTICATION_PACKAGE_V1_0')}\r\n"
        f"Logon Account:\t\t{d.get('TargetUserName','')}\r\n"
        f"Source Workstation:\t{d.get('Workstation','')}\r\n"
        f"Error Code:\t\t{d.get('Status','')}"
    )


def _msg_4672(d):
    raw = d.get('PrivilegeList', '')
    privs_fmt = "\r\n\t\t\t".join(raw.split()) if raw else raw
    return (
        "Special privileges assigned to new logon.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        f"Privileges:\t\t{privs_fmt}"
    )


def _msg_4688(d):
    return (
        "A new process has been created.\r\n\r\n"
        "Creator Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Target Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('TargetLogonId','')}\r\n\r\n"
        "Process Information:\r\n"
        f"\tNew Process ID:\t\t{d.get('NewProcessId','')}\r\n"
        f"\tNew Process Name:\t{d.get('NewProcessName','')}\r\n"
        f"\tToken Elevation Type:\t{d.get('TokenElevationType','')}\r\n"
        f"\tMandatory Label:\t\t{d.get('MandatoryLabel','')}\r\n"
        f"\tCreator Process ID:\t{d.get('ProcessId','')}\r\n"
        f"\tCreator Process Name:\t{d.get('ParentProcessName','')}\r\n"
        f"\tProcess Command Line:\t{d.get('CommandLine','')}"
    )


def _msg_4689(d):
    return (
        "A process has exited.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Process Information:\r\n"
        f"\tProcess ID:\t{d.get('ProcessId','')}\r\n"
        f"\tProcess Name:\t{d.get('ProcessName','')}\r\n"
        f"\tExit Status:\t{d.get('Status','0x0')}"
    )


def _msg_4767(d):
    return (
        "A user account was unlocked.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Target Account:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}"
    )


_ACCESS_MASK_TO_NAME = {
    "0x100":   "Control Access",
    "0x10":    "Read Property",
    "0x20":    "Write Property",
    "0x1":     "Create Child",
    "0x2":     "Delete Child",
    "0x4":     "List Children",
    "0x40000": "WRITE_DAC",
    "0x10000": "DELETE",
}


_PROP_CODE_TO_NAME = {
    "%%1537": "Read Property",
    "%%1538": "Write Property",
    "%%1539": "WRITE_DAC",
    "%%1540": "Delete Child",
    "%%1541": "List Children",
    "%%7688": "Control Access",
    "%%5649": "Query secret value",
}


def _msg_4662(d):
    accesses = _ACCESS_MASK_TO_NAME.get(d.get('AccessMask', ''), 'Control Access')
    props_raw = d.get('Properties', '')
    props_rendered = props_raw
    for code, name in _PROP_CODE_TO_NAME.items():
        props_rendered = props_rendered.replace(code, name)
    return (
        "An operation was performed on an object.\r\n\r\n"
        "Subject :\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Object:\r\n"
        f"\tObject Server:\t\tDS\r\n"
        f"\tObject Type:\t\t{d.get('ObjectType','')}\r\n"
        f"\tObject Name:\t\t{d.get('ObjectName','')}\r\n"
        f"\tHandle ID:\t\t{d.get('HandleId','0x0')}\r\n\r\n"
        "Operation:\r\n"
        f"\tOperation Type:\t\t{d.get('OperationType','Object Access')}\r\n"
        f"\tAccesses:\t\t{accesses}\r\n"
        f"\t\t\t\t\r\n"
        f"\tAccess Mask:\t\t{d.get('AccessMask','')}\r\n"
        f"\tProperties:\t\t{props_rendered}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tParameter 1:\t\t{d.get('AdditionalInfo','-')}\r\n"
        f"\tParameter 2:\t\t"
    )


def _msg_4656(d):
    return (
        "A handle to an object was requested.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Object:\r\n"
        f"\tObject Server:\t\tSecurity\r\n"
        f"\tObject Type:\t\t{d.get('ObjectType','')}\r\n"
        f"\tObject Name:\t\t{d.get('ObjectName','')}\r\n"
        f"\tHandle ID:\t\t{d.get('HandleId','')}\r\n"
        f"\tResource Attributes:\t{d.get('ResourceAttributes','')}\r\n\r\n"
        "Process Information:\r\n"
        f"\tProcess ID:\t\t{d.get('ProcessId','')}\r\n"
        f"\tProcess Name:\t\t{d.get('ProcessName','')}\r\n\r\n"
        "Access Request Information:\r\n"
        f"\tTransaction ID:\t\t{d.get('TransactionId','')}\r\n"
        f"\tAccesses:\t\t{d.get('AccessList','')}\r\n"
        f"\tAccess Mask:\t\t{d.get('AccessMask','')}\r\n"
        f"\tPrivileges Used for Access Check:\t{d.get('PrivilegeList','')}\r\n"
        f"\tRestricted SID Count:\t{d.get('RestrictedSidCount','0')}"
    )


def _msg_4663(d):
    return (
        "An attempt was made to access an object.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Object:\r\n"
        f"\tObject Server:\t\tSecurity\r\n"
        f"\tObject Type:\t\t{d.get('ObjectType','')}\r\n"
        f"\tObject Name:\t\t{d.get('ObjectName','')}\r\n"
        f"\tHandle ID:\t\t{d.get('HandleId','')}\r\n"
        f"\tResource Attributes:\t{d.get('ResourceAttributes','')}\r\n\r\n"
        "Process Information:\r\n"
        f"\tProcess ID:\t\t{d.get('ProcessId','')}\r\n"
        f"\tProcess Name:\t\t{d.get('ProcessName','')}\r\n\r\n"
        "Access Request Information:\r\n"
        f"\tAccesses:\t\t{d.get('AccessList','')}\r\n"
        f"\tAccess Mask:\t\t{d.get('AccessMask','')}"
    )


def _msg_4741(d):
    uac_flags = d.get('UserAccountControl', '%%2080')
    return (
        "A computer account was created.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "New Computer Account:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Attributes:\r\n"
        f"\tSAM Account Name:\t{d.get('SamAccountName','')}\r\n"
        f"\tDisplay Name:\t\t{d.get('DisplayName','-')}\r\n"
        f"\tUser Principal Name:\t{d.get('UserPrincipalName','-')}\r\n"
        f"\tHome Directory:\t\t{d.get('HomeDirectory','-')}\r\n"
        f"\tHome Drive:\t\t{d.get('HomePath','-')}\r\n"
        f"\tScript Path:\t\t{d.get('ScriptPath','-')}\r\n"
        f"\tProfile Path:\t\t{d.get('ProfilePath','-')}\r\n"
        f"\tUser Workstations:\t{d.get('UserWorkstations','-')}\r\n"
        f"\tPassword Last Set:\t{d.get('PasswordLastSet','')}\r\n"
        f"\tAccount Expires:\t\t{d.get('AccountExpires','%%1794')}\r\n"
        f"\tPrimary Group ID:\t{d.get('PrimaryGroupId','515')}\r\n"
        f"\tAllowedToDelegateTo:\t{d.get('AllowedToDelegateTo','-')}\r\n"
        f"\tOld UAC Value:\t\t{d.get('OldUacValue','0x0')}\r\n"
        f"\tNew UAC Value:\t\t{d.get('NewUacValue','')}\r\n"
        f"\tUser Account Control:\t{uac_flags}\r\n"
        f"\tUser Parameters:\t{d.get('UserParameters','-')}\r\n"
        f"\tSID History:\t\t{d.get('SidHistory','-')}\r\n"
        f"\tLogon Hours:\t\t{d.get('LogonHours','%%1793')}\r\n"
        f"\tDNS Host Name:\t\t{d.get('DnsHostName','')}\r\n"
        f"\tService Principal Names:\t{d.get('ServicePrincipalNames','-')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tPrivileges:\t\t{d.get('PrivilegeList','-')}"
    )


def _msg_4742(d):
    return (
        "A computer account was changed.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Computer Account That Was Changed:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Changed Attributes:\r\n"
        f"\tSAM Account Name:\t{d.get('SamAccountName','')}\r\n"
        f"\tDisplay Name:\t\t{d.get('DisplayName','-')}\r\n"
        f"\tUser Principal Name:\t{d.get('UserPrincipalName','-')}\r\n"
        f"\tHome Directory:\t\t{d.get('HomeDirectory','-')}\r\n"
        f"\tHome Drive:\t\t{d.get('HomePath','-')}\r\n"
        f"\tScript Path:\t\t{d.get('ScriptPath','-')}\r\n"
        f"\tProfile Path:\t\t{d.get('ProfilePath','-')}\r\n"
        f"\tUser Workstations:\t{d.get('UserWorkstations','-')}\r\n"
        f"\tPassword Last Set:\t{d.get('PasswordLastSet','-')}\r\n"
        f"\tAccount Expires:\t\t{d.get('AccountExpires','-')}\r\n"
        f"\tPrimary Group ID:\t{d.get('PrimaryGroupId','-')}\r\n"
        f"\tAllowedToDelegateTo:\t{d.get('AllowedToDelegateTo','-')}\r\n"
        f"\tOld UAC Value:\t\t{d.get('OldUacValue','')}\r\n"
        f"\tNew UAC Value:\t\t{d.get('NewUacValue','')}\r\n"
        f"\tUser Account Control:\t{d.get('UserAccountControl','-')}\r\n"
        f"\tUser Parameters:\t{d.get('UserParameters','-')}\r\n"
        f"\tSID History:\t\t{d.get('SidHistory','-')}\r\n"
        f"\tLogon Hours:\t\t{d.get('LogonHours','-')}\r\n"
        f"\tDNS Host Name:\t\t{d.get('DnsHostName','')}\r\n"
        f"\tService Principal Names:\t{d.get('ServicePrincipalNames','-')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tPrivileges:\t\t{d.get('PrivilegeList','-')}"
    )


def _msg_5136(d):
    return (
        "A directory service object was modified.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Directory Service:\r\n"
        f"\tName:\t\t{d.get('DSName','')}\r\n"
        f"\tType:\t\t{d.get('DSType','%%14676')}\r\n\r\n"
        "Object:\r\n"
        f"\tDN:\t\t{d.get('ObjectDN','')}\r\n"
        f"\tGUID:\t\t{d.get('ObjectGUID','')}\r\n"
        f"\tClass:\t\t{d.get('ObjectClass','')}\r\n\r\n"
        "Attribute:\r\n"
        f"\tLDAP Display Name:\t{d.get('AttributeLDAPDisplayName','')}\r\n"
        f"\tSyntax (OID):\t\t{d.get('AttributeSyntaxOID','')}\r\n"
        f"\tValue:\t\t{d.get('AttributeValue','')}\r\n\r\n"
        "Operation:\r\n"
        f"\tType:\t\t{d.get('OperationType','')}\r\n"
        f"\tCorrelation ID:\t\t{d.get('OpCorrelationID','')}\r\n"
        f"\tApplication Correlation ID:\t{d.get('AppCorrelationID','-')}"
    )


def _msg_5137(d):
    return (
        "A directory service object was created.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Directory Service:\r\n"
        f"\tName:\t\t{d.get('DSName','')}\r\n"
        f"\tType:\t\t{d.get('DSType','%%14676')}\r\n\r\n"
        "Object:\r\n"
        f"\tDN:\t\t{d.get('ObjectDN','')}\r\n"
        f"\tGUID:\t\t{d.get('ObjectGUID','')}\r\n"
        f"\tClass:\t\t{d.get('ObjectClass','')}\r\n\r\n"
        "Operation:\r\n"
        f"\tCorrelation ID:\t\t{d.get('OpCorrelationID','')}\r\n"
        f"\tApplication Correlation ID:\t{d.get('AppCorrelationID','-')}"
    )


def _msg_4728(d):
    return (
        "A member was added to a security-enabled global group.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Member:\r\n"
        f"\tSecurity ID:\t\t{d.get('MemberSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('MemberName','')}\r\n\r\n"
        "Group:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tGroup Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tGroup Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tPrivileges:\t\t{d.get('PrivilegeList','-')}"
    )


def _msg_4732(d):
    return (
        "A member was added to a security-enabled local group.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Member:\r\n"
        f"\tSecurity ID:\t\t{d.get('MemberSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('MemberName','')}\r\n\r\n"
        "Group:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tGroup Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tGroup Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tPrivileges:\t\t{d.get('PrivilegeList','-')}"
    )


def _msg_4756(d):
    return (
        "A member was added to a security-enabled universal group.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Member:\r\n"
        f"\tSecurity ID:\t\t{d.get('MemberSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('MemberName','')}\r\n\r\n"
        "Group:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tGroup Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tGroup Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tPrivileges:\t\t{d.get('PrivilegeList','-')}"
    )


def _msg_4729(d):
    return (
        "A member was removed from a security-enabled global group.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Member:\r\n"
        f"\tSecurity ID:\t\t{d.get('MemberSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('MemberName','')}\r\n\r\n"
        "Group:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tGroup Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tGroup Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tPrivileges:\t\t{d.get('PrivilegeList','-')}"
    )


def _msg_4733(d):
    return (
        "A member was removed from a security-enabled local group.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Member:\r\n"
        f"\tSecurity ID:\t\t{d.get('MemberSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('MemberName','')}\r\n\r\n"
        "Group:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tGroup Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tGroup Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tPrivileges:\t\t{d.get('PrivilegeList','-')}"
    )


def _msg_4757(d):
    return (
        "A member was removed from a security-enabled universal group.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Member:\r\n"
        f"\tSecurity ID:\t\t{d.get('MemberSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('MemberName','')}\r\n\r\n"
        "Group:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tGroup Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tGroup Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tPrivileges:\t\t{d.get('PrivilegeList','-')}"
    )


def _msg_4886(d):
    return (
        "Certificate Services received a certificate request.\r\n\r\n"
        f"Request ID:\t{d.get('RequestId','')}\r\n"
        f"Requester:\t{d.get('Requester','')}\r\n"
        f"Attributes:\t{d.get('Attributes','')}"
    )


def _msg_4887(d):
    return (
        "Certificate Services approved a certificate request and issued a certificate.\r\n\r\n"
        f"Request ID:\t{d.get('RequestId','')}\r\n"
        f"Requester:\t{d.get('Requester','')}\r\n"
        f"Attributes:\t{d.get('Attributes','')}\r\n"
        f"Disposition:\t{d.get('Disposition','')}\r\n"
        f"SKI:\t\t{d.get('SubjectKeyIdentifier','')}\r\n"
        f"Subject:\t{d.get('Subject','')}"
    )


def _msg_4888(d):
    return (
        "Certificate Services denied a certificate request.\r\n\r\n"
        f"Request ID:\t{d.get('RequestId','')}\r\n"
        f"Requester:\t{d.get('Requester','')}\r\n"
        f"Attributes:\t{d.get('Attributes','')}\r\n"
        f"Disposition:\t{d.get('Disposition','')}\r\n"
        f"SKI:\t\t{d.get('SubjectKeyIdentifier','')}\r\n"
        f"Subject:\t{d.get('Subject','')}"
    )


def _msg_4720(d):
    return (
        "A user account was created.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "New Account:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Attributes:\r\n"
        f"\tSAM Account Name:\t{d.get('SamAccountName','')}\r\n"
        f"\tDisplay Name:\t\t{d.get('DisplayName','')}\r\n"
        f"\tUser Principal Name:\t{d.get('UserPrincipalName','')}\r\n"
        f"\tHome Directory:\t\t{d.get('HomeDirectory','')}\r\n"
        f"\tHome Drive:\t\t{d.get('HomePath','')}\r\n"
        f"\tScript Path:\t\t{d.get('ScriptPath','')}\r\n"
        f"\tProfile Path:\t\t{d.get('ProfilePath','')}\r\n"
        f"\tUser Workstations:\t{d.get('UserWorkstations','')}\r\n"
        f"\tPassword Last Set:\t{d.get('PasswordLastSet','')}\r\n"
        f"\tAccount Expires:\t\t{d.get('AccountExpires','')}\r\n"
        f"\tPrimary Group ID:\t{d.get('PrimaryGroupId','')}\r\n"
        f"\tAllowed To Delegate To:\t{d.get('AllowedToDelegateTo','')}\r\n"
        f"\tOld UAC Value:\t\t{d.get('OldUacValue','')}\r\n"
        f"\tNew UAC Value:\t\t{d.get('NewUacValue','')}\r\n"
        f"\tUser Account Control:\t{d.get('UserAccountControl','')}\r\n"
        f"\tUser Parameters:\t{d.get('UserParameters','')}\r\n"
        f"\tSID History:\t\t{d.get('SidHistory','')}\r\n"
        f"\tLogon Hours:\t\t{d.get('LogonHours','')}\r\n\r\n"
        "Additional Information:\r\n"
        f"\tPrivileges:\t\t{d.get('PrivilegeList','')}"
    )


def _msg_4722(d):
    return (
        "A user account was enabled.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Target Account:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}"
    )


def _msg_4724(d):
    return (
        "An attempt was made to reset an account's password.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Target Account:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}"
    )


def _msg_4725(d):
    return (
        "A user account was disabled.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Target Account:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}"
    )


def _msg_4726(d):
    return (
        "A user account was deleted.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Target Account:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}"
    )


def _msg_4738(d):
    return (
        "A user account was changed.\r\n\r\n"
        "Subject:\r\n"
        f"\tSecurity ID:\t\t{d.get('SubjectUserSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('SubjectUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('SubjectDomainName','')}\r\n"
        f"\tLogon ID:\t\t{d.get('SubjectLogonId','')}\r\n\r\n"
        "Target Account:\r\n"
        f"\tSecurity ID:\t\t{d.get('TargetSid','')}\r\n"
        f"\tAccount Name:\t\t{d.get('TargetUserName','')}\r\n"
        f"\tAccount Domain:\t\t{d.get('TargetDomainName','')}\r\n\r\n"
        "Changed Attributes:\r\n"
        f"\tSAM Account Name:\t{d.get('SamAccountName','')}\r\n"
        f"\tDisplay Name:\t\t{d.get('DisplayName','')}\r\n"
        f"\tUser Principal Name:\t{d.get('UserPrincipalName','')}\r\n"
        f"\tHome Directory:\t\t{d.get('HomeDirectory','')}\r\n"
        f"\tHome Drive:\t\t{d.get('HomePath','')}\r\n"
        f"\tScript Path:\t\t{d.get('ScriptPath','')}\r\n"
        f"\tProfile Path:\t\t{d.get('ProfilePath','')}\r\n"
        f"\tUser Workstations:\t{d.get('UserWorkstations','')}\r\n"
        f"\tPassword Last Set:\t{d.get('PasswordLastSet','')}\r\n"
        f"\tAccount Expires:\t\t{d.get('AccountExpires','')}\r\n"
        f"\tPrimary Group ID:\t{d.get('PrimaryGroupId','')}\r\n"
        f"\tAllowed To Delegate To:\t{d.get('AllowedToDelegateTo','')}\r\n"
        f"\tOld UAC Value:\t\t{d.get('OldUacValue','')}\r\n"
        f"\tNew UAC Value:\t\t{d.get('NewUacValue','')}\r\n"
        f"\tUser Account Control:\r\n"
        f"\t\t{d.get('UserAccountControl','')}\r\n"
        f"\tUser Parameters:\t{d.get('UserParameters','')}\r\n"
        f"\tSID History:\t\t{d.get('SidHistory','')}\r\n"
        f"\tLogon Hours:\t\t{d.get('LogonHours','')}"
    )


_MSG_BUILDERS = {
    4624: _msg_4624,
    4625: _msg_4625,
    4634: _msg_4634,
    4647: _msg_4647,
    4648: _msg_4648,
    4672: _msg_4672,
    4688: _msg_4688,
    4689: _msg_4689,
    4740: _msg_4740,
    4767: _msg_4767,
    4768: _msg_4768,
    4769: _msg_4769,
    4771: _msg_4771,
    4776: _msg_4776,
    4662: _msg_4662,
    4656: _msg_4656,
    4663: _msg_4663,
    4728: _msg_4728,
    4732: _msg_4732,
    4741: _msg_4741,
    4742: _msg_4742,
    4756: _msg_4756,
    4729: _msg_4729,
    4733: _msg_4733,
    4757: _msg_4757,
    5136: _msg_5136,
    5137: _msg_5137,
    4886: _msg_4886,
    4887: _msg_4887,
    4888: _msg_4888,
    4720: _msg_4720,
    4722: _msg_4722,
    4724: _msg_4724,
    4725: _msg_4725,
    4726: _msg_4726,
    4738: _msg_4738,
}

# 4625 Status/SubStatus → FailureReason mapping.  Status is the primary
# failure code; SubStatus provides additional detail.  The %%xxxx codes are
# Windows parameter insertion strings rendered by Event Viewer.
# (status, sub_status, failure_reason_%%_code)
_FAILURE_REASONS = [
    ("0xC000006D", "0xC000006A", "%%2313"),  # Unknown user name or bad password (bad pw)
    ("0xC000006D", "0xC0000064", "%%2313"),  # Unknown user name or bad password (no user)
    ("0xC000006E", "0xC000006F", "%%2311"),  # Account logon time restriction violation
    ("0xC000006E", "0xC0000070", "%%2312"),  # User not allowed to logon at this computer
    ("0xC000006E", "0xC0000071", "%%2309"),  # Password has expired
    ("0xC000006E", "0xC0000072", "%%2310"),  # Account currently disabled
    ("0xC0000193", "0x0",        "%%2305"),  # Account has expired
    ("0xC0000224", "0x0",        "%%2308"),  # User must change password at next logon
    ("0xC0000234", "0x0",        "%%2307"),  # Account locked out
    ("0xC0000413", "0xC0000413", "%%2304"),  # Authentication firewall refused connection
]

# Kerberos 4771/4768 failure codes (RFC 4120 error numbers, Windows formats
# them as hex).
_KRB_FAILURE_CODES = [
    ("0x6",  "Client not found in Kerberos database"),
    ("0x12", "Client's credentials have been revoked"),
    ("0x17", "Password has expired"),
    ("0x18", "Pre-authentication information was invalid"),
    ("0x25", "Clock skew too great"),
]

# Kerberos TicketEncryptionType values
# 0x01 DES-CBC-CRC     (deprecated/weak)
# 0x03 DES-CBC-MD5     (deprecated/weak)
# 0x11 AES128-CTS-HMAC-SHA1-96
# 0x12 AES256-CTS-HMAC-SHA1-96
# 0x17 RC4-HMAC        (used in Kerberoasting)
# 0x18 RC4-HMAC-EXP    (weak)
_TICKET_ENC_NORMAL = ["0x12", "0x12", "0x12", "0x11", "0x12"]   # almost always AES
_TICKET_ENC_WEAK   = ["0x17", "0x18", "0x01", "0x03"]          # RC4 / DES

# NTLM auth package — Windows always emits this literal string for 4776
_NTLM_PACKAGE = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"

# Kerberos authentication package names used in 4624
_KRB_PACKAGE  = "Kerberos"
_NEG_PACKAGE  = "Negotiate"
_NTLM_PACKAGE_SHORT = "NTLM"

# Common local/system SIDs
_SID_SYSTEM       = "S-1-5-18"
_SID_LOCAL_SERVICE= "S-1-5-19"
_SID_NETWORK_SVC  = "S-1-5-20"
_SID_ANON         = "S-1-0-0"

# Domain RID counter base – synthetic but realistic-looking domain SID prefix
_SYNTH_DOMAIN_SID = "S-1-5-21-3457937927-2839227994-823803824"

# Process names/paths keyed by logon type category.
# Windows uses specific processes for each logon scenario.
_LOGON_PROCESSES_BY_TYPE = {
    "interactive": [("0x1d4", "C:\\Windows\\System32\\winlogon.exe"),
                    ("0xb44", "C:\\Windows\\System32\\svchost.exe")],
    "service":     [("0x248", "C:\\Windows\\System32\\svchost.exe"),
                    ("0x5f4", "C:\\Windows\\System32\\services.exe")],
    "network":     [("0x34c", "C:\\Windows\\System32\\lsass.exe")],
    "unlock":      [("0x1d4", "C:\\Windows\\System32\\winlogon.exe")],
    "remote":      [("0x1d4", "C:\\Windows\\System32\\winlogon.exe")],
    "cached":      [("0x1d4", "C:\\Windows\\System32\\winlogon.exe")],
}
_LOGON_PROCESSES_DEFAULT = [("0x34c", "C:\\Windows\\System32\\lsass.exe")]

# LogonProcessName values Windows emits for various scenarios
_LOGON_PROCESS_NAMES = {
    "interactive":        ["User32 ", "Advapi  "],
    "network":            ["NtLmSsp ", "Kerberos"],
    "remote":             ["User32 ", "Advapi  "],
    "cached":             ["Advapi  "],
    "service":            ["Advapi  "],
    "unlock":             ["User32 "],
}

# Known service account and computer account name patterns
_SERVICE_ACCOUNT_SPNS = [
    "MSSQLSvc/sql01.examplecorp.local:1433",
    "MSSQLSvc/sql02.examplecorp.local:1433",
    "MSSQLSvc/sql03.examplecorp.local:1433",
    "MSSQLSvc/reportserver.examplecorp.local",
    "MSSQLSvc/crmdb.examplecorp.local:1433",
    "MSSQLSvc/datawarehouse.examplecorp.local:1433",
    "HTTP/intranet.examplecorp.local",
    "HTTP/sharepoint.examplecorp.local",
    "HTTP/jenkins.examplecorp.local",
    "HTTP/confluence.examplecorp.local",
    "HTTP/jira.examplecorp.local",
    "HTTP/gitlab.examplecorp.local",
    "HTTP/exchange.examplecorp.local",
    "LDAP/dc01.examplecorp.local",
    "LDAP/dc02.examplecorp.local",
    "cifs/fs01.examplecorp.local",
    "cifs/fs02.examplecorp.local",
    "cifs/backup01.examplecorp.local",
    "TERMSRV/rdp-gw01.examplecorp.local",
    "TERMSRV/rdp-gw02.examplecorp.local",
    "WSMAN/mgmt01.examplecorp.local",
    "exchangeMDB/exchange01.examplecorp.local",
    "SAPService/sap01.examplecorp.local",
]

_SERVICE_ACCOUNT_SAMS = [
    "svc_sql_prod",   "svc_sql_dev",   "svc_iis",   "svc_sharepoint",
    "svc_backup",     "svc_monitoring","svc_jenkins","svc_reporting",
    "svc_crm",        "svc_etl",
]

_SPN_TO_SERVICE_ACCOUNT = {
    "MSSQLSvc/sql01.examplecorp.local:1433":      "svc_sql_prod",
    "MSSQLSvc/sql02.examplecorp.local:1433":      "svc_sql_dev",
    "MSSQLSvc/sql03.examplecorp.local:1433":      "svc_sql_prod",
    "MSSQLSvc/reportserver.examplecorp.local":     "svc_reporting",
    "MSSQLSvc/crmdb.examplecorp.local:1433":       "svc_crm",
    "MSSQLSvc/datawarehouse.examplecorp.local:1433":"svc_etl",
    "HTTP/intranet.examplecorp.local":             "svc_iis",
    "HTTP/sharepoint.examplecorp.local":           "svc_sharepoint",
    "HTTP/jenkins.examplecorp.local":              "svc_jenkins",
    "HTTP/confluence.examplecorp.local":           "svc_iis",
    "HTTP/jira.examplecorp.local":                 "svc_iis",
    "HTTP/gitlab.examplecorp.local":               "svc_iis",
    "HTTP/exchange.examplecorp.local":             "svc_iis",
    "exchangeMDB/exchange01.examplecorp.local":    "svc_iis",
    "SAPService/sap01.examplecorp.local":          "svc_crm",
    "WSMAN/mgmt01.examplecorp.local":              "svc_monitoring",
}


# ---------------------------------------------------------------------------
# Per-process mutable state
# ---------------------------------------------------------------------------

# _OPEN_SESSIONS:  hostname → list of open session dicts
#   { "logon_id":"0x...", "target_user_sid":"...", "target_user_name":"...",
#     "target_domain":"...", "logon_type":2, "ip":"10.0.0.5",
#     "workstation":"WKSX", "start":<epoch seconds>,
#     "auth_package":"Kerberos" }
_OPEN_SESSIONS: dict[str, list] = {}

# _FAIL_COUNTS:  username → count of consecutive 4625/4771 failures since
# the last success.  Used to time lockouts.
_FAIL_COUNTS: dict[str, int] = {}

# Monotonically increasing RecordNumber counters, per source host.
_RECORD_NUMBERS: dict[str, int] = {}

# Stable user SIDs derived from the username so the same user always gets the
# same SID across events/restarts (mirrors how real AD assigns RIDs).
_USER_SIDS: dict[str, str] = {}

# Thread safety: the simulator runs modules in parallel threads.
_STATE_LOCK = threading.Lock()

# --- Parallel host mode infrastructure ---
_output_queue: _queue_mod.Queue = _queue_mod.Queue(maxsize=1000)
_status_queue: _queue_mod.Queue = _queue_mod.Queue(maxsize=200)
_worker_stats: dict = {}
_orchestrator_started = False
_orchestrator_lock = threading.Lock()
_workers_stop = threading.Event()


def _stable_user_sid(username: str) -> str:
    """Deterministic domain SID for a username (last-RID from hash)."""
    with _STATE_LOCK:
        sid = _USER_SIDS.get(username)
        if sid:
            return sid
        h = hashlib.sha1(username.encode()).digest()
        rid = 1100 + (int.from_bytes(h[:4], "big") % 8_900)
        sid = f"{_SYNTH_DOMAIN_SID}-{rid}"
        _USER_SIDS[username] = sid
        return sid


def _next_record_number(host: str) -> int:
    """Monotonic RecordNumber per host.  Seeded to a realistic multi-thousand value."""
    with _STATE_LOCK:
        cur = _RECORD_NUMBERS.get(host)
        if cur is None:
            cur = random.randint(50_000, 500_000)
        cur += 1
        _RECORD_NUMBERS[host] = cur
        return cur


def _new_logon_id() -> str:
    """Produce a hex logon-id string like '0x3e7' / '0xa35fa'."""
    return "0x" + format(random.randint(0x10000, 0xFFFFFF), "x")


def _new_logon_guid() -> str:
    """UUID in the braced form Windows uses."""
    return "{" + str(uuid.uuid4()) + "}"


def _format_logon_ip(ip, logon_type):
    """Format IpAddress the way real Windows 4624/4625 events do."""
    if logon_type not in (3, 10):
        if logon_type in (2, 7):
            return random.choice(["127.0.0.1", "::1"])
        return "-"
    if not ip or ip == "-":
        return "-"
    if ":" in str(ip):
        return ip
    return ip


def _iso_ts(t: float = None) -> str:
    """Windows-native ISO8601 timestamp with sub-microsecond precision."""
    if t is None:
        t = time.time()
    dt = datetime.fromtimestamp(t, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}000Z"


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _cf(config):
    """Shorthand — read this module's block from config.json with safe defaults."""
    return config.get(CONFIG_KEY, {}) or {}


def _get_domain(config):
    return _cf(config).get("domain_name", "EXAMPLECORP")


def _get_dns_domain(config):
    return _cf(config).get("dns_domain", "examplecorp.local")


def _get_dc_hostname(config):
    """Synthetic DC hostname used for DC-originated events (4740/4768/4769/4771/4776)."""
    return _cf(config).get("domain_controller_hostname", "DC01.examplecorp.local")


def _get_dc_short(config):
    return _get_dc_hostname(config).split(".")[0].upper()


def _fqdn(hostname, config):
    """Ensure a hostname is fully qualified — real Windows events always use FQDNs."""
    if "." in hostname:
        return hostname
    return f"{hostname}.{_get_dns_domain(config)}"


def _get_os_subtype(config):
    return _cf(config).get("os_subtype", "Windows 10")


def _get_windows_users(session_context):
    """Filter session_context down to users whose primary device is Windows.

    Returns a list of user_info dicts (from get_user_by_name) whose os_type is
    "Windows".  This is the authoritative population this module operates on.
    """
    if not session_context:
        return []
    windows_users = []
    for uname, prof in session_context.items():
        if (prof.get("primary_os_type") or "").lower() == "windows":
            info = get_user_by_name(session_context, uname)
            if info and info.get("hostname"):
                windows_users.append(info)
    return windows_users


def _pick_windows_user(session_context):
    """Return a random user_info for a user with a Windows primary device."""
    users = _get_windows_users(session_context)
    return random.choice(users) if users else None


def _get_threat_interval(threat_level, config):
    if threat_level == "Benign Traffic Only":
        return 86400 * 365
    levels = config.get("threat_generation_levels", {})
    return levels.get(threat_level, 7200)


# ---------------------------------------------------------------------------
# Core event-record builder
# ---------------------------------------------------------------------------

def _build_event(event_id: int, computer: str, event_data: dict,
                 success: bool = True,
                 ts: float = None) -> dict:
    """Construct a record matching the microsoft_windows_raw dataset schema.

    Outputs all fields present in the dataset schema so that XSIAM modeling
    rules, correlation rules, and UEBA analytics can process the events the
    same way they process real XDR-agent or WEC-collected events.

    The _collector_* and _insert_time fields are populated by the HTTP
    collector infrastructure automatically — we don't need to supply those.
    """
    meta = _EVENT_META[event_id]
    if ts is None:
        ts = time.time()

    kw = _KW_AUDIT_SUCCESS if success else _KW_AUDIT_FAILURE

    ts_str = _iso_ts(ts)

    message = _format_message(event_id, event_data)

    ed_clean = {k: v for k, v in event_data.items() if v is not None}

    proc_pid = str(random.randint(400, 9000))
    proc_tid = str(random.randint(500, 15000))

    # The process that generates Security Auditing events is lsass.exe
    lsass_path = "C:\\Windows\\System32\\lsass.exe"
    lsass_name = "lsass.exe"

    record = {
        # --- Fields matching the microsoft_windows_raw dataset schema ---
        "event_id":          str(event_id),
        "provider_name":     _PROVIDER_NAME,
        "provider_guid":     _PROVIDER_GUID,
        "channel":           _CHANNEL,
        "computer_name":     computer,
        "host_name":         computer,
        "time_created":      ts_str,
        "message":           message,
        "keywords":          kw,
        "log_level":         "Information",
        "event_result":      "success" if success else "failure",
        "event_action":      meta["category"],
        "task":              meta["task"],
        "opcode":            "Info",
        "op_code":           "0",
        "version":           str(meta["version"]),
        "os_subtype":        _BUILD_EVENT_OS_SUBTYPE,
        "record_id":         str(_next_record_number(computer)),
        "activity_id":       "",
        "process_pid":       proc_pid,
        "process_thread_id": proc_tid,
        "process_name":      lsass_name,
        "process_path":      lsass_path,
        "process_cmd":       "",
        "process_md5":       "",
        "process_sha256":    "",
        "event_data":        ed_clean,
        "user": {
            "name":       ed_clean.get("SubjectUserName", ""),
            "domain":     ed_clean.get("SubjectDomainName", ""),
            "identifier": ed_clean.get("SubjectUserSid", ""),
            "type":       _user_type(ed_clean.get("SubjectUserSid", ""),
                                     ed_clean.get("SubjectUserName", "")),
        },
        "user_data": {
            "SubjectDomainName": ed_clean.get("SubjectDomainName", ""),
            "SubjectUserName":   ed_clean.get("SubjectUserName", ""),
        },
    }

    return record


def _user_type(sid: str, username: str = "") -> str:
    """Derive user type from SID/username for the top-level 'user' object."""
    if username.endswith("$"):
        return "Computer"
    if sid in (_SID_SYSTEM, "S-1-5-18", "S-1-5-19", "S-1-5-20"):
        return "Service"
    return "User"


# ---------------------------------------------------------------------------
# Windows Event XML renderer (for WEC transport)
# ---------------------------------------------------------------------------

_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _render_event_xml(event: dict) -> str:
    """Render a _build_event() dict as native Windows Event XML.

    Produces the <Event> XML that WEC/WEF natively transports and that
    XSIAM's microsoft_windows_raw parser ingests.  Requires lxml for
    proper namespace prefix control.
    """
    if not _HAS_LXML:
        raise RuntimeError(
            "lxml is required for WEC transport. Install with: pip install lxml"
        )

    E = _etree.Element
    SE = _etree.SubElement

    root = E("Event", xmlns=_EVENT_NS)

    # -- <System> --
    system = SE(root, "System")

    provider = SE(system, "Provider")
    provider.set("Name", event.get("provider_name", ""))
    provider.set("Guid", event.get("provider_guid", ""))

    SE(system, "EventID").text = str(event.get("event_id", "0"))
    SE(system, "Version").text = str(event.get("version", "0"))

    # Level: 0 for audit events (both success and failure)
    SE(system, "Level").text = "0"

    SE(system, "Task").text = str(event.get("task", "0"))
    SE(system, "Opcode").text = str(event.get("op_code", "0"))

    kw = event.get("keywords", _KW_AUDIT_SUCCESS)
    SE(system, "Keywords").text = kw

    tc = SE(system, "TimeCreated")
    tc.set("SystemTime", event.get("time_created", ""))

    SE(system, "EventRecordID").text = str(event.get("record_id", "0"))

    corr = SE(system, "Correlation")
    activity = event.get("activity_id", "")
    if activity:
        corr.set("ActivityID", activity)

    exe = SE(system, "Execution")
    exe.set("ProcessID", str(event.get("process_pid", "0")))
    exe.set("ThreadID", str(event.get("process_thread_id", "0")))

    SE(system, "Channel").text = event.get("channel", "Security")
    SE(system, "Computer").text = event.get("computer_name", "")
    SE(system, "Security")

    # -- <EventData> --
    ed = event.get("event_data", {})
    if ed:
        event_data_el = SE(root, "EventData")
        for name, value in ed.items():
            data_el = SE(event_data_el, "Data")
            data_el.set("Name", name)
            data_el.text = str(value) if value is not None else ""

    # -- <RenderingInfo> --
    msg = event.get("message", "").replace("\r\n", "\n")
    if msg:
        ri = SE(root, "RenderingInfo")
        ri.set("Culture", "en-US")
        SE(ri, "Message").text = msg
        SE(ri, "Level").text = "Information"
        SE(ri, "Task").text = event.get("event_action", "")
        SE(ri, "Opcode").text = event.get("opcode", "Info")
        SE(ri, "Channel").text = event.get("channel", "Security")
        SE(ri, "Provider").text = "Microsoft Windows security auditing."
        kw_el = SE(ri, "Keywords")
        kw_text = "Audit Success" if event.get("event_result") == "success" else "Audit Failure"
        SE(kw_el, "Keyword").text = kw_text

    xml_str = _etree.tostring(root, encoding="unicode", xml_declaration=False)
    xml_str = re.sub(r'="([^"]*)"', lambda m: "='" + m.group(1) + "'", xml_str)
    return xml_str


# ---------------------------------------------------------------------------
# Per-EventID constructors
# ---------------------------------------------------------------------------

def _build_4624(user_info, config, *, logon_type=2, auth_pkg=None,
                workstation_override=None, ip_override=None,
                target_logon_id=None, logon_guid=None, ts=None,
                elevated=False) -> dict:
    """4624 – An account was successfully logged on (emitted by the endpoint)."""
    domain = _get_domain(config)
    computer = _fqdn(workstation_override or user_info["hostname"], config)
    ip = ip_override if ip_override is not None else user_info.get("ip") or "-"
    port = str(random.randint(49152, 65535))

    if auth_pkg is None:
        # LogonType 2/7/11/12/13 → Negotiate (Kerberos or NTLM fallback)
        # LogonType 3/10 → mostly Kerberos, occasionally NTLM
        if logon_type in (2, 7, 11, 13):
            auth_pkg = _NEG_PACKAGE
        elif logon_type in (3, 10):
            auth_pkg = random.choice([_KRB_PACKAGE, _KRB_PACKAGE, _KRB_PACKAGE, _NTLM_PACKAGE_SHORT])
        else:
            auth_pkg = _NEG_PACKAGE

    if auth_pkg == _NTLM_PACKAGE_SHORT:
        lm_pkg = random.choice(["NTLM V2", "NTLM V1"])
        key_len = random.choice(["128", "0"])
    else:
        lm_pkg = "-"
        key_len = "0"

    _lt_cat = {2: "interactive", 3: "network", 4: "service", 5: "service",
               7: "unlock", 10: "remote", 11: "cached",
               12: "remote", 13: "cached"}.get(logon_type, "interactive")

    if auth_pkg == _KRB_PACKAGE:
        lp_name = "Kerberos"
    elif auth_pkg == _NTLM_PACKAGE_SHORT:
        lp_name = "NtLmSsp "
    elif auth_pkg == _NEG_PACKAGE:
        lp_name = random.choice(["User32 ", "Advapi  ", "Negotiate"])
    else:
        lp_name = random.choice(_LOGON_PROCESS_NAMES.get(_lt_cat, ["User32"]))
    proc_id, proc_name = random.choice(
        _LOGON_PROCESSES_BY_TYPE.get(_lt_cat, _LOGON_PROCESSES_DEFAULT))

    target_logon_id = target_logon_id or _new_logon_id()
    logon_guid = logon_guid or _new_logon_guid()

    # Subject context depends on logon type:
    #   Type 3/10 (network/remote): NULL SID, empty name — auth hasn't bound a
    #     local identity yet, the Subject fields reflect the anonymous listener.
    #   All others (interactive/service/unlock/batch): SYSTEM / machine$ — the
    #     local system brokered the logon on behalf of the arriving user.
    if logon_type in (3, 10):
        subj_sid = _SID_ANON
        subj_name = "-"
        subj_domain = "-"
    else:
        subj_sid = _SID_SYSTEM
        subj_name = computer.split(".")[0].upper() + "$"
        subj_domain = domain

    if logon_type in (3, 10) and auth_pkg == _KRB_PACKAGE:
        _wks_name = "-"
    elif logon_type in (2, 3, 7, 10, 11):
        _wks_name = computer.split(".")[0].upper()
    else:
        _wks_name = "-"

    event_data = {
        "SubjectUserSid":            subj_sid,
        "SubjectUserName":           subj_name,
        "SubjectDomainName":         subj_domain,
        "SubjectLogonId":            "0x0" if logon_type in (3, 10) else "0x3e7",
        "TargetUserSid":             _stable_user_sid(user_info["username"]),
        "TargetUserName":            user_info["username"],
        "TargetDomainName":          domain,
        "TargetLogonId":             target_logon_id,
        "LogonType":                 str(logon_type),
        "LogonProcessName":          lp_name,
        "AuthenticationPackageName": auth_pkg,
        "WorkstationName":           _wks_name,
        "LogonGuid":                 logon_guid if auth_pkg == _KRB_PACKAGE else "{00000000-0000-0000-0000-000000000000}",
        "TransmittedServices":       "-",
        "LmPackageName":             lm_pkg,
        "KeyLength":                 key_len,
        "ProcessId":                 proc_id,
        "ProcessName":               proc_name,
        "IpAddress":                 _format_logon_ip(ip, logon_type),
        "IpPort":                    port if logon_type in (3, 10) else ("0" if logon_type in (2, 7, 11) else "-"),
        "ImpersonationLevel":        "%%1833",
        "RestrictedAdminMode":       ("Yes" if random.random() < 0.1 else "-") if logon_type == 10 else "-",
        "TargetOutboundUserName":    "-",
        "TargetOutboundDomainName":  "-",
        "VirtualAccount":            "%%1843",   # "No"
        "TargetLinkedLogonId":       _new_logon_id() if elevated else "0x0",
        "ElevatedToken":             "%%1842" if elevated else "%%1843",  # Yes / No
    }

    # Remember open session so logoff emitters can correlate
    with _STATE_LOCK:
        _OPEN_SESSIONS.setdefault(computer, []).append({
            "logon_id":       target_logon_id,
            "target_user_sid": event_data["TargetUserSid"],
            "target_user_name": event_data["TargetUserName"],
            "target_domain": domain,
            "logon_type":    logon_type,
            "ip":            ip,
            "computer":      computer,
            "workstation":   event_data["WorkstationName"],
            "start":         ts or time.time(),
            "auth_package":  auth_pkg,
            "logon_guid":    logon_guid,
        })
        # a success clears the failure streak
        _FAIL_COUNTS[user_info["username"]] = 0

    return _build_event(
        4624, computer, event_data, success=True, ts=ts,
    )


def _build_4625(user_info, config, *, logon_type=3, auth_pkg=None,
                sub_status=None, status=None, failure_reason=None,
                workstation_override=None, ip_override=None,
                source_workstation=None, ts=None) -> dict:
    """4625 – An account failed to log on.

    workstation_override — host that *logs* the event (computer_name).
    source_workstation   — host that *sent* the logon request (WorkstationName
                           inside event_data).  Defaults to computer_name.
    """
    domain = _get_domain(config)
    computer = _fqdn(workstation_override or user_info["hostname"], config)
    ip = ip_override if ip_override is not None else user_info.get("ip") or "-"
    port = str(random.randint(49152, 65535))

    if auth_pkg is None:
        auth_pkg = _NTLM_PACKAGE_SHORT if logon_type == 3 else _NEG_PACKAGE

    # Pick failure reason if not specified — most common is bad password.
    # _FAILURE_REASONS tuples: (status, sub_status, failure_reason_%%_code)
    if status is None and sub_status is None:
        status, sub_status, failure_reason = random.choice(_FAILURE_REASONS)
    elif status is not None and sub_status is None:
        match = next((t for t in _FAILURE_REASONS if t[0].lower() == status.lower()), None)
        sub_status = match[1] if match else "0x0"
        failure_reason = failure_reason or (match[2] if match else "%%2304")
    elif sub_status is not None and status is None:
        match = next((t for t in _FAILURE_REASONS if t[1].lower() == sub_status.lower()), None)
        status = match[0] if match else "0xC000006D"
        failure_reason = failure_reason or (match[2] if match else "%%2304")
    else:
        match = next((t for t in _FAILURE_REASONS if t[0].lower() == status.lower()), None)
        failure_reason = failure_reason or (match[2] if match else "%%2304")

    lp_category = {2: "interactive", 3: "network", 4: "service", 5: "service",
                   7: "unlock", 10: "remote", 11: "cached"}.get(logon_type, "network")
    proc_id, proc_name = random.choice(
        _LOGON_PROCESSES_BY_TYPE.get(lp_category, _LOGON_PROCESSES_DEFAULT))
    if auth_pkg == _KRB_PACKAGE:
        lp_name = "Kerberos"
    elif auth_pkg == _NTLM_PACKAGE_SHORT:
        lp_name = "NtLmSsp "
    elif auth_pkg == _NEG_PACKAGE:
        lp_name = random.choice(["User32 ", "Advapi  ", "Negotiate"])
    else:
        lp_name = random.choice(_LOGON_PROCESS_NAMES.get(lp_category, ["NtLmSsp "]))

    # For network/remote failures the Subject is NULL (auth hasn't completed).
    # For interactive/service failures the Subject is SYSTEM/machine account.
    if logon_type in (3, 10):
        subj_sid = _SID_ANON
        subj_name = "-"
        subj_domain = "-"
        subj_logon_id = "0x0"
        fail_proc_id = "0x0"
        fail_proc_name = "-"
    else:
        subj_sid = _SID_SYSTEM
        subj_name = computer.split(".")[0].upper() + "$"
        subj_domain = domain
        subj_logon_id = "0x3e7"
        fail_proc_id = proc_id
        fail_proc_name = proc_name

    target_domain = domain

    event_data = {
        "SubjectUserSid":            subj_sid,
        "SubjectUserName":           subj_name,
        "SubjectDomainName":         subj_domain,
        "SubjectLogonId":            subj_logon_id,
        "TargetUserSid":             _SID_ANON,
        "TargetUserName":            user_info["username"],
        "TargetDomainName":          target_domain,
        "Status":                    status,
        "FailureReason":             failure_reason,
        "SubStatus":                 sub_status,
        "LogonType":                 str(logon_type),
        "LogonProcessName":          lp_name,
        "AuthenticationPackageName": auth_pkg,
        "WorkstationName":           (source_workstation or computer).split(".")[0].upper(),
        "TransmittedServices":       "-",
        "LmPackageName":             "-",
        "KeyLength":                 "0",
        "ProcessId":                 fail_proc_id,
        "ProcessName":               fail_proc_name,
        "IpAddress":                 _format_logon_ip(ip, logon_type),
        "IpPort":                    str(random.randint(49152, 65535)) if logon_type in (3, 10) else "0",
    }

    with _STATE_LOCK:
        _FAIL_COUNTS[user_info["username"]] = _FAIL_COUNTS.get(user_info["username"], 0) + 1

    return _build_event(
        4625, computer, event_data, success=False, ts=ts,
    )


def _pop_open_session(hostname, username=None):
    """Pop (and return) an open logon session for a hostname, optionally filtered by user.

    Returns None if no matching session exists.  Runs under the state lock.
    """
    with _STATE_LOCK:
        sessions = _OPEN_SESSIONS.get(hostname, [])
        for i, s in enumerate(sessions):
            if username is None or s["target_user_name"] == username:
                return sessions.pop(i)
    return None


def _build_4634(session_row, config, ts=None) -> dict:
    """4634 – An account was logged off (system-generated)."""
    computer = session_row.get("computer") or session_row["workstation"]
    if "." not in computer:
        computer = f"{computer}.{_get_dns_domain(config)}"
    event_data = {
        "TargetUserSid":    session_row["target_user_sid"],
        "TargetUserName":   session_row["target_user_name"],
        "TargetDomainName": session_row["target_domain"],
        "TargetLogonId":    session_row["logon_id"],
        "LogonType":        str(session_row["logon_type"]),
    }
    return _build_event(4634, computer, event_data, success=True, ts=ts,
)


def _build_4647(session_row, config, ts=None) -> dict:
    """4647 – User initiated logoff (emitted only for interactive logon types)."""
    computer = session_row.get("computer") or session_row["workstation"]
    if "." not in computer:
        computer = f"{computer}.{_get_dns_domain(config)}"
    event_data = {
        "TargetUserSid":    session_row["target_user_sid"],
        "TargetUserName":   session_row["target_user_name"],
        "TargetDomainName": session_row["target_domain"],
        "TargetLogonId":    session_row["logon_id"],
    }
    return _build_event(4647, computer, event_data, success=True, ts=ts,
)


def _build_4648(user_info, config, *, target_user, target_server,
                process_name="C:\\Windows\\System32\\runas.exe",
                ip_override=None, ts=None) -> dict:
    """4648 – A logon was attempted using explicit credentials (runas/scheduled task)."""
    domain = _get_domain(config)
    computer = _fqdn(user_info["hostname"], config)
    ip = ip_override if ip_override is not None else user_info.get("ip") or "::1"
    is_local = target_server in ("localhost", "127.0.0.1", "::1",
                                  computer.split(".")[0].lower(),
                                  computer.lower())
    if is_local:
        ip_field = "::1"
    elif ip and "." in str(ip):
        ip_field = f"::ffff:{ip}"
    else:
        ip_field = ip or "-"
    event_data = {
        "SubjectUserSid":       _stable_user_sid(user_info["username"]),
        "SubjectUserName":      user_info["username"],
        "SubjectDomainName":    domain,
        "SubjectLogonId":       _new_logon_id(),
        "LogonGuid":            "{00000000-0000-0000-0000-000000000000}",
        "TargetUserName":       target_user,
        "TargetDomainName":     domain,
        "TargetLogonGuid":      "{00000000-0000-0000-0000-000000000000}",
        "TargetServerName":     target_server,
        "TargetInfo":           target_server,
        "ProcessId":            "0x%x" % random.randint(0x4, 0x9fff),
        "ProcessName":          process_name,
        "IpAddress":            ip_field,
        "IpPort":               "0",
    }
    return _build_event(4648, computer, event_data, success=True, ts=ts,
)


def _build_4740(user_info, config, *, source_workstation=None, ts=None) -> dict:
    """4740 – A user account was locked out (emitted by a DC).

    NOTE: TargetDomainName in 4740 is a schema quirk — it holds the
    **caller computer name** (source of the bad logon attempts), NOT
    the domain.  XSIAM reads this field as the lockout source host.
    """
    domain = _get_domain(config)
    dc_host = _get_dc_hostname(config)
    caller = source_workstation or user_info.get("hostname") or "UNKNOWN"
    caller_short = caller.split(".")[0].upper()
    event_data = {
        "TargetUserName":     user_info["username"],
        "TargetDomainName":   caller_short,
        "TargetSid":          _stable_user_sid(user_info["username"]),
        "SubjectUserSid":     _SID_SYSTEM,
        "SubjectUserName":    _get_dc_short(config) + "$",
        "SubjectDomainName":  domain,
        "SubjectLogonId":     "0x3e7",
    }
    return _build_event(4740, dc_host, event_data, success=True, ts=ts)


# Privileges assigned during admin/elevated logons
_ADMIN_PRIVILEGES = [
    "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege", "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege", "SeBackupPrivilege",
    "SeRestorePrivilege", "SeDebugPrivilege", "SeAuditPrivilege",
    "SeSystemEnvironmentPrivilege", "SeImpersonatePrivilege",
    "SeDelegateSessionUserImpersonatePrivilege",
]
_SERVICE_PRIVILEGES = [
    "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege", "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege", "SeBackupPrivilege",
    "SeRestorePrivilege", "SeDebugPrivilege", "SeAuditPrivilege",
    "SeSystemEnvironmentPrivilege", "SeImpersonatePrivilege",
    "SeDelegateSessionUserImpersonatePrivilege",
]
_NORMAL_USER_PRIVILEGES = [
    "SeSecurityPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
    "SeDebugPrivilege", "SeImpersonatePrivilege",
]


def _build_4672(user_info, config, *, logon_id=None, is_admin=False,
                is_service=False, ts=None) -> dict:
    """4672 – Special privileges assigned to new logon."""
    domain = _get_domain(config)
    computer = _fqdn(user_info["hostname"], config)
    if is_service:
        privs = _SERVICE_PRIVILEGES
    elif is_admin:
        privs = _ADMIN_PRIVILEGES
    else:
        privs = random.sample(_NORMAL_USER_PRIVILEGES,
                              k=random.randint(2, len(_NORMAL_USER_PRIVILEGES)))
    event_data = {
        "SubjectUserSid":    _stable_user_sid(user_info["username"]),
        "SubjectUserName":   user_info["username"],
        "SubjectDomainName": domain,
        "SubjectLogonId":    logon_id or _new_logon_id(),
        "PrivilegeList":     " ".join(privs),
    }
    return _build_event(4672, computer, event_data, success=True, ts=ts)


def _build_4688(user_info, config, *, process_name, command_line="",
                parent_process="C:\\Windows\\explorer.exe",
                logon_id=None, ts=None) -> dict:
    """4688 – A new process has been created."""
    domain = _get_domain(config)
    computer = _fqdn(user_info["hostname"], config)
    new_pid = "0x%x" % random.randint(0x200, 0xffff)
    parent_pid = "0x%x" % random.randint(0x100, 0x9fff)
    event_data = {
        "SubjectUserSid":    _SID_SYSTEM,
        "SubjectUserName":   computer.split(".")[0].upper() + "$",
        "SubjectDomainName": domain,
        "SubjectLogonId":    "0x3e7",
        "NewProcessId":      new_pid,
        "NewProcessName":    process_name,
        "TokenElevationType":"%%1936",
        "ProcessId":         parent_pid,
        "CommandLine":       command_line,
        "TargetUserSid":     _stable_user_sid(user_info["username"]),
        "TargetUserName":    user_info["username"],
        "TargetDomainName":  domain,
        "TargetLogonId":     logon_id or _new_logon_id(),
        "ParentProcessName": parent_process,
        "MandatoryLabel":    "S-1-16-12288",
    }
    return _build_event(4688, computer, event_data, success=True, ts=ts)


def _build_4689(user_info, config, *, process_name, process_id=None,
                logon_id=None, ts=None) -> dict:
    """4689 – A process has exited."""
    domain = _get_domain(config)
    computer = _fqdn(user_info["hostname"], config)
    event_data = {
        "SubjectUserSid":    _stable_user_sid(user_info["username"]),
        "SubjectUserName":   user_info["username"],
        "SubjectDomainName": domain,
        "SubjectLogonId":    logon_id or _new_logon_id(),
        "Status":            "0x0",
        "ProcessId":         process_id or ("0x%x" % random.randint(0x200, 0xffff)),
        "ProcessName":       process_name,
    }
    return _build_event(4689, computer, event_data, success=True, ts=ts)


def _build_4767(user_info, config, *, unlocked_by="Administrator", ts=None) -> dict:
    """4767 – A user account was unlocked (emitted by a DC)."""
    domain = _get_domain(config)
    dc_host = _get_dc_hostname(config)
    event_data = {
        "TargetUserName":    user_info["username"],
        "TargetDomainName":  domain,
        "TargetSid":         _stable_user_sid(user_info["username"]),
        "SubjectUserSid":    _stable_user_sid(unlocked_by),
        "SubjectUserName":   unlocked_by,
        "SubjectDomainName": domain,
        "SubjectLogonId":    _new_logon_id(),
    }
    return _build_event(4767, dc_host, event_data, success=True, ts=ts)


_ACCESS_MASK_TO_LIST = {
    "0x100":    "%%7688",
    "0x10":     "%%1537",
    "0x20":     "%%1538",
    "0x1":      "%%1539",
    "0x2":      "%%1540",
    "0x4":      "%%1541",
    "0x10000":  "%%1537",
    "0x40000":  "%%1539",
}


def _build_4662(user_info, config, *, object_type, object_name,
                access_mask="0x100", properties="", operation_type="Object Access",
                logon_id=None, ts=None) -> dict:
    """4662 – An operation was performed on an object (Directory Service Access).

    Used for DCSync detection: replication GUIDs in properties indicate
    DS-Replication-Get-Changes / DS-Replication-Get-Changes-All.
    """
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    access_list = _ACCESS_MASK_TO_LIST.get(access_mask, "%%7688") + "\n                "
    event_data = {
        "SubjectUserSid":    _stable_user_sid(user_info["username"]),
        "SubjectUserName":   user_info["username"],
        "SubjectDomainName": domain,
        "SubjectLogonId":    logon_id or _new_logon_id(),
        "ObjectServer":      "DS",
        "ObjectType":        object_type,
        "ObjectName":        object_name,
        "OperationType":     operation_type,
        "HandleId":          "0x0",
        "AccessList":        access_list,
        "AccessMask":        access_mask,
        "Properties":        properties,
        "AdditionalInfo":    "-",
        "AdditionalInfo2":   "",
    }
    return _build_event(4662, dc_host, event_data, success=True, ts=ts)


def _build_4656(user_info, config, *, object_type, object_name,
                process_name, access_mask="0x1F0FFF",
                handle_id=None, process_id=None,
                logon_id=None, ts=None) -> dict:
    """4656 – A handle to an object was requested.

    Used for LSASS credential dumping detection: a non-system process
    requesting a handle to lsass.exe with high-privilege access mask.
    """
    domain = _get_domain(config)
    computer = _fqdn(user_info["hostname"], config)
    event_data = {
        "SubjectUserSid":    _stable_user_sid(user_info["username"]),
        "SubjectUserName":   user_info["username"],
        "SubjectDomainName": domain,
        "SubjectLogonId":    logon_id or _new_logon_id(),
        "ObjectServer":      "Security",
        "ObjectType":        object_type,
        "ObjectName":        object_name,
        "HandleId":          handle_id or ("0x%x" % random.randint(0x100, 0xffff)),
        "TransactionId":     "{00000000-0000-0000-0000-000000000000}",
        "AccessList":        "%%4484\r\n\t\t\t\t%%4416",
        "AccessReason":      "-",
        "AccessMask":        access_mask,
        "PrivilegeList":     "-",
        "RestrictedSidCount": "0",
        "ProcessId":         process_id or ("0x%x" % random.randint(0x200, 0xffff)),
        "ProcessName":       process_name,
        "ResourceAttributes": "-",
    }
    return _build_event(4656, computer, event_data, success=True, ts=ts)


def _build_4663(user_info, config, *, object_type, object_name,
                process_name, access_mask="0x10", handle_id=None,
                process_id=None, logon_id=None, ts=None) -> dict:
    """4663 – An attempt was made to access an object.

    Follows 4656; indicates the actual read/write on the object handle.
    """
    domain = _get_domain(config)
    computer = _fqdn(user_info["hostname"], config)
    event_data = {
        "SubjectUserSid":    _stable_user_sid(user_info["username"]),
        "SubjectUserName":   user_info["username"],
        "SubjectDomainName": domain,
        "SubjectLogonId":    logon_id or _new_logon_id(),
        "ObjectServer":      "Security",
        "ObjectType":        object_type,
        "ObjectName":        object_name,
        "HandleId":          handle_id or ("0x%x" % random.randint(0x100, 0xffff)),
        "AccessList":        "%%4416",
        "AccessMask":        access_mask,
        "ProcessId":         process_id or ("0x%x" % random.randint(0x200, 0xffff)),
        "ProcessName":       process_name,
        "ResourceAttributes": "-",
    }
    return _build_event(4663, computer, event_data, success=True, ts=ts)


def _build_4741(user_info, config, *, target_computer_name, target_sid,
                sam_account_name, dns_host_name, spns="-",
                new_uac_value="0x80", logon_id=None, ts=None) -> dict:
    """4741 – A computer account was created (DC event).

    Generated when a new computer object is created in AD — including dMSA
    objects, which are of class msDS-DelegatedManagedServiceAccount but
    registered as computer accounts.
    """
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "TargetUserName":      target_computer_name,
        "TargetDomainName":    domain,
        "TargetSid":           target_sid,
        "SubjectUserSid":      _stable_user_sid(user_info["username"]),
        "SubjectUserName":     user_info["username"],
        "SubjectDomainName":   domain,
        "SubjectLogonId":      logon_id or _new_logon_id(),
        "PrivilegeList":       "-",
        "SamAccountName":      sam_account_name,
        "DisplayName":         "-",
        "UserPrincipalName":   "-",
        "HomeDirectory":       "-",
        "HomePath":            "-",
        "ScriptPath":          "-",
        "ProfilePath":         "-",
        "UserWorkstations":    "-",
        "PasswordLastSet":     _iso_ts(ts),
        "AccountExpires":      "%%1794",
        "PrimaryGroupId":      "515",
        "AllowedToDelegateTo": "-",
        "OldUacValue":         "0x0",
        "NewUacValue":         new_uac_value,
        "UserAccountControl":  "%%2087",
        "UserParameters":      "-",
        "SidHistory":          "-",
        "LogonHours":          "%%1793",
        "DnsHostName":         dns_host_name,
        "ServicePrincipalNames": spns,
    }
    return _build_event(4741, dc_host, event_data, success=True, ts=ts)


def _build_4742(user_info, config, *, target_computer_name, target_sid,
                sam_account_name, dns_host_name="-", spns="-",
                old_uac_value="-", new_uac_value="-", uac_control="-",
                allowed_to_delegate="-", logon_id=None, ts=None) -> dict:
    """4742 – A computer account was changed (DC event).

    Generated alongside 5136 events when computer account attributes change.
    Unlike 5136, this shows the final-state values (not old→new pairs).
    Only changed attributes have non-"-" values.
    """
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "TargetUserName":      target_computer_name,
        "TargetDomainName":    domain,
        "TargetSid":           target_sid,
        "SubjectUserSid":      _stable_user_sid(user_info["username"]),
        "SubjectUserName":     user_info["username"],
        "SubjectDomainName":   domain,
        "SubjectLogonId":      logon_id or _new_logon_id(),
        "PrivilegeList":       "-",
        "SamAccountName":      sam_account_name,
        "DisplayName":         "-",
        "UserPrincipalName":   "-",
        "HomeDirectory":       "-",
        "HomePath":            "-",
        "ScriptPath":          "-",
        "ProfilePath":         "-",
        "UserWorkstations":    "-",
        "PasswordLastSet":     "-",
        "AccountExpires":      "-",
        "PrimaryGroupId":      "-",
        "AllowedToDelegateTo": allowed_to_delegate,
        "OldUacValue":         old_uac_value,
        "NewUacValue":         new_uac_value,
        "UserAccountControl":  uac_control,
        "UserParameters":      "-",
        "SidHistory":          "-",
        "LogonHours":          "-",
        "DnsHostName":         dns_host_name,
        "ServicePrincipalNames": spns,
    }
    return _build_event(4742, dc_host, event_data, success=True, ts=ts)


# Well-known SIDs for privileged AD groups
_SID_DOMAIN_ADMINS     = f"{_SYNTH_DOMAIN_SID}-512"
_SID_ENTERPRISE_ADMINS = f"{_SYNTH_DOMAIN_SID}-519"
_SID_BUILTIN_ADMINS    = "S-1-5-32-544"

_PRIVILEGED_GROUPS = {
    "Domain Admins":     {"sid": _SID_DOMAIN_ADMINS,     "event_id": 4728, "remove_id": 4729, "scope": "global"},
    "Enterprise Admins": {"sid": _SID_ENTERPRISE_ADMINS, "event_id": 4756, "remove_id": 4757, "scope": "universal"},
    "Administrators":    {"sid": _SID_BUILTIN_ADMINS,    "event_id": 4732, "remove_id": 4733, "scope": "local"},
}

def _build_4728(user_info, config, *, member_name, member_sid,
                target_group="Domain Admins", target_sid=None,
                logon_id=None, ts=None) -> dict:
    """4728 – A member was added to a security-enabled global group (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "MemberName":         member_name,
        "MemberSid":          member_sid,
        "TargetUserName":     target_group,
        "TargetDomainName":   domain,
        "TargetSid":          target_sid or _SID_DOMAIN_ADMINS,
        "SubjectUserSid":     _stable_user_sid(user_info["username"]),
        "SubjectUserName":    user_info["username"],
        "SubjectDomainName":  domain,
        "SubjectLogonId":     logon_id or _new_logon_id(),
        "PrivilegeList":      "-",
    }
    return _build_event(4728, dc_host, event_data, success=True, ts=ts)


def _build_4732(user_info, config, *, member_name, member_sid,
                target_group="Administrators", target_sid=None,
                target_domain=None,
                logon_id=None, ts=None) -> dict:
    """4732 – A member was added to a security-enabled local group (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "MemberName":         member_name,
        "MemberSid":          member_sid,
        "TargetUserName":     target_group,
        "TargetDomainName":   target_domain or "Builtin",
        "TargetSid":          target_sid or _SID_BUILTIN_ADMINS,
        "SubjectUserSid":     _stable_user_sid(user_info["username"]),
        "SubjectUserName":    user_info["username"],
        "SubjectDomainName":  domain,
        "SubjectLogonId":     logon_id or _new_logon_id(),
        "PrivilegeList":      "-",
    }
    return _build_event(4732, dc_host, event_data, success=True, ts=ts)


def _build_4756(user_info, config, *, member_name, member_sid,
                target_group="Enterprise Admins", target_sid=None,
                logon_id=None, ts=None) -> dict:
    """4756 – A member was added to a security-enabled universal group (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "MemberName":         member_name,
        "MemberSid":          member_sid,
        "TargetUserName":     target_group,
        "TargetDomainName":   domain,
        "TargetSid":          target_sid or _SID_ENTERPRISE_ADMINS,
        "SubjectUserSid":     _stable_user_sid(user_info["username"]),
        "SubjectUserName":    user_info["username"],
        "SubjectDomainName":  domain,
        "SubjectLogonId":     logon_id or _new_logon_id(),
        "PrivilegeList":      "-",
    }
    return _build_event(4756, dc_host, event_data, success=True, ts=ts)


def _build_4729(user_info, config, *, member_name, member_sid,
                target_group="Domain Admins", target_sid=None,
                logon_id=None, ts=None) -> dict:
    """4729 – A member was removed from a security-enabled global group (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "MemberName":         member_name,
        "MemberSid":          member_sid,
        "TargetUserName":     target_group,
        "TargetDomainName":   domain,
        "TargetSid":          target_sid or _SID_DOMAIN_ADMINS,
        "SubjectUserSid":     _stable_user_sid(user_info["username"]),
        "SubjectUserName":    user_info["username"],
        "SubjectDomainName":  domain,
        "SubjectLogonId":     logon_id or _new_logon_id(),
        "PrivilegeList":      "-",
    }
    return _build_event(4729, dc_host, event_data, success=True, ts=ts)


def _build_4733(user_info, config, *, member_name, member_sid,
                target_group="Administrators", target_sid=None,
                target_domain=None,
                logon_id=None, ts=None) -> dict:
    """4733 – A member was removed from a security-enabled local group (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "MemberName":         member_name,
        "MemberSid":          member_sid,
        "TargetUserName":     target_group,
        "TargetDomainName":   target_domain or domain,
        "TargetSid":          target_sid or _SID_BUILTIN_ADMINS,
        "SubjectUserSid":     _stable_user_sid(user_info["username"]),
        "SubjectUserName":    user_info["username"],
        "SubjectDomainName":  domain,
        "SubjectLogonId":     logon_id or _new_logon_id(),
        "PrivilegeList":      "-",
    }
    return _build_event(4733, dc_host, event_data, success=True, ts=ts)


def _build_4757(user_info, config, *, member_name, member_sid,
                target_group="Enterprise Admins", target_sid=None,
                logon_id=None, ts=None) -> dict:
    """4757 – A member was removed from a security-enabled universal group (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "MemberName":         member_name,
        "MemberSid":          member_sid,
        "TargetUserName":     target_group,
        "TargetDomainName":   domain,
        "TargetSid":          target_sid or _SID_ENTERPRISE_ADMINS,
        "SubjectUserSid":     _stable_user_sid(user_info["username"]),
        "SubjectUserName":    user_info["username"],
        "SubjectDomainName":  domain,
        "SubjectLogonId":     logon_id or _new_logon_id(),
        "PrivilegeList":      "-",
    }
    return _build_event(4757, dc_host, event_data, success=True, ts=ts)


_REMOVE_BUILDERS = {4729: _build_4729, 4733: _build_4733, 4757: _build_4757}
_ADD_BUILDERS    = {4728: _build_4728, 4732: _build_4732, 4756: _build_4756}


def _build_5136(user_info, config, *, object_dn, object_class, object_guid,
                attribute_name, attribute_value, attribute_syntax_oid="2.5.5.1",
                operation_type="%%14674", op_correlation_id=None,
                logon_id=None, ts=None) -> dict:
    """5136 – A directory service object was modified (DC event).

    Generated when an AD object attribute is changed.  Each attribute change
    produces a separate 5136; correlated modifications share the same
    OpCorrelationID.  For value changes, two events fire: %%14675 (Value
    Deleted) then %%14674 (Value Added).

    Key detection signal for dMSA/BadSuccessor: AttributeLDAPDisplayName =
    "msDS-ManagedAccountPrecededByLink" with a privileged account DN as value.
    """
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    dns_domain = _get_dns_domain(config)
    event_data = {
        "OpCorrelationID":          op_correlation_id or _new_logon_guid(),
        "AppCorrelationID":         "-",
        "SubjectUserSid":           _stable_user_sid(user_info["username"]),
        "SubjectUserName":          user_info["username"],
        "SubjectDomainName":        domain,
        "SubjectLogonId":           logon_id or _new_logon_id(),
        "DSName":                   dns_domain,
        "DSType":                   "%%14676",
        "ObjectDN":                 object_dn,
        "ObjectGUID":               object_guid,
        "ObjectClass":              object_class,
        "AttributeLDAPDisplayName": attribute_name,
        "AttributeSyntaxOID":       attribute_syntax_oid,
        "AttributeValue":           attribute_value,
        "OperationType":            operation_type,
    }
    return _build_event(5136, dc_host, event_data, success=True, ts=ts)


def _build_5137(user_info, config, *, object_dn, object_class, object_guid,
                op_correlation_id=None, logon_id=None, ts=None) -> dict:
    """5137 – A directory service object was created (DC event).

    Generated when a new AD object is created.  For dMSA/BadSuccessor this
    fires when the attacker creates the msDS-DelegatedManagedServiceAccount
    object in an OU they have CreateChild permissions on.
    """
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    dns_domain = _get_dns_domain(config)
    event_data = {
        "OpCorrelationID":    op_correlation_id or _new_logon_guid(),
        "AppCorrelationID":   "-",
        "SubjectUserSid":     _stable_user_sid(user_info["username"]),
        "SubjectUserName":    user_info["username"],
        "SubjectDomainName":  domain,
        "SubjectLogonId":     logon_id or _new_logon_id(),
        "DSName":             dns_domain,
        "DSType":             "%%14676",
        "ObjectDN":           object_dn,
        "ObjectGUID":         object_guid,
        "ObjectClass":        object_class,
    }
    return _build_event(5137, dc_host, event_data, success=True, ts=ts)


def _get_ca_hostname(config):
    """Return the FQDN of the Certificate Authority server."""
    cfg = _cf(config)
    ca = cfg.get("ca_hostname", "CA01")
    dns = _get_dns_domain(config)
    if "." in ca:
        return ca
    return f"{ca}.{dns}"


_CERT_TEMPLATES_NORMAL = [
    "User", "Machine", "WebServer", "DomainController",
    "SmartcardLogon", "EFS", "CodeSigning",
]

_CERT_TEMPLATES_VULNERABLE = [
    "ESC1-Vulnerable", "WebServerV2", "UserAuth-Legacy",
    "VPN-Certificate", "Workstation-Auth",
]


def _random_ski():
    """Generate a random Subject Key Identifier (20-byte hex)."""
    return " ".join(f"{random.randint(0,255):02x}" for _ in range(20))


def _build_4886(user_info, config, *, template_name, request_id=None,
                san_override=None, ts=None) -> dict:
    """4886 – Certificate Services received a certificate request (CA event)."""
    ca_host = _get_ca_hostname(config)
    domain = _get_domain(config)
    dns_domain = _get_dns_domain(config)
    req_id = request_id or str(random.randint(100, 99999))
    requester = f"{domain}\\{user_info['username']}"
    attrs_parts = [f"CertificateTemplate:{template_name}"]
    if san_override:
        attrs_parts.append(f"san:upn={san_override}")
    hostname = user_info.get("hostname", "WKS-TEMP")
    if "." not in hostname:
        hostname = f"{hostname}.{dns_domain}"
    attrs_parts.append(f"ccm:{hostname}")
    attrs = "\r\n".join(attrs_parts)
    event_data = {
        "RequestId":  req_id,
        "Requester":  requester,
        "Attributes": attrs,
    }
    return _build_event(4886, ca_host, event_data, success=True, ts=ts)


def _build_4887(user_info, config, *, template_name, request_id=None,
                san_override=None, subject_dn=None, ts=None) -> dict:
    """4887 – Certificate Services approved and issued a certificate (CA event)."""
    ca_host = _get_ca_hostname(config)
    domain = _get_domain(config)
    dns_domain = _get_dns_domain(config)
    req_id = request_id or str(random.randint(100, 99999))
    requester = f"{domain}\\{user_info['username']}"
    attrs_parts = [f"CertificateTemplate:{template_name}"]
    if san_override:
        attrs_parts.append(f"san:upn={san_override}")
    hostname = user_info.get("hostname", "WKS-TEMP")
    if "." not in hostname:
        hostname = f"{hostname}.{dns_domain}"
    attrs_parts.append(f"ccm:{hostname}")
    attrs = "\r\n".join(attrs_parts)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)
    subj = subject_dn or f"CN={user_info['username']}, CN=Users, {base_dn}"
    event_data = {
        "RequestId":              req_id,
        "Requester":              requester,
        "Attributes":             attrs,
        "Disposition":            "3",
        "SubjectKeyIdentifier":   _random_ski(),
        "Subject":                subj,
    }
    return _build_event(4887, ca_host, event_data, success=True, ts=ts)


def _build_4888(user_info, config, *, template_name, request_id=None,
                san_override=None, subject_dn=None, ts=None) -> dict:
    """4888 – Certificate Services denied a certificate request (CA event)."""
    ca_host = _get_ca_hostname(config)
    domain = _get_domain(config)
    dns_domain = _get_dns_domain(config)
    req_id = request_id or str(random.randint(100, 99999))
    requester = f"{domain}\\{user_info['username']}"
    attrs_parts = [f"CertificateTemplate:{template_name}"]
    if san_override:
        attrs_parts.append(f"san:upn={san_override}")
    hostname = user_info.get("hostname", "WKS-TEMP")
    if "." not in hostname:
        hostname = f"{hostname}.{dns_domain}"
    attrs_parts.append(f"ccm:{hostname}")
    attrs = "\r\n".join(attrs_parts)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)
    subj = subject_dn or f"CN={user_info['username']}, CN=Users, {base_dn}"
    event_data = {
        "RequestId":              req_id,
        "Requester":              requester,
        "Attributes":             attrs,
        "Disposition":            "2",
        "SubjectKeyIdentifier":   "",
        "Subject":                subj,
    }
    return _build_event(4888, ca_host, event_data, success=False, ts=ts)


def _dc_logon_event(user_info, config, *, logon_type=3, auth_pkg=_KRB_PACKAGE,
                    ip_override=None, logon_id=None, ts=None) -> dict:
    """Emit a 4624 on the DC matching the Kerberos/NTLM auth that just succeeded.

    Real DCs log their own 4624 (type 3) whenever they process a successful
    authentication.  SIEM correlation rules join this DC-side 4624 to the
    endpoint-side 4624 via timestamp proximity and matching TargetUserName.
    """
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    ip = ip_override if ip_override is not None else user_info.get("ip") or "-"
    logon_id = logon_id or _new_logon_id()
    dc_short = _get_dc_short(config)
    event_data = {
        "SubjectUserSid":            _SID_SYSTEM,
        "SubjectUserName":           dc_short + "$",
        "SubjectDomainName":         domain,
        "SubjectLogonId":            "0x3e7",
        "TargetUserSid":             _stable_user_sid(user_info["username"]),
        "TargetUserName":            user_info["username"],
        "TargetDomainName":          domain,
        "TargetLogonId":             logon_id,
        "LogonType":                 str(logon_type),
        "LogonProcessName":          "Kerberos" if auth_pkg == _KRB_PACKAGE else "NtLmSsp ",
        "AuthenticationPackageName": auth_pkg,
        "WorkstationName":           "-" if auth_pkg == _KRB_PACKAGE else dc_short,
        "LogonGuid":                 _new_logon_guid(),
        "TransmittedServices":       "-",
        "LmPackageName":             "-",
        "KeyLength":                 "0",
        "ProcessId":                 "0x248",
        "ProcessName":               "C:\\Windows\\System32\\lsass.exe",
        "IpAddress":                 ip if ip and ip != "-" else "-",
        "IpPort":                    str(random.randint(49152, 65535)),
        "ImpersonationLevel":        "%%1833",
        "RestrictedAdminMode":       "-",
        "TargetOutboundUserName":    "-",
        "TargetOutboundDomainName":  "-",
        "VirtualAccount":            "%%1843",
        "TargetLinkedLogonId":       "0x0",
        "ElevatedToken":             "%%1843",
    }
    return _build_event(4624, dc_host, event_data, success=True, ts=ts)


def _build_4768(user_info, config, *, ip_override=None, encryption=None,
                status="0x0", cert_issuer="", cert_serial="", cert_thumbprint="",
                ts=None) -> dict:
    """4768 – Kerberos TGT request (DC event, success=Status 0x0)."""
    domain = _get_domain(config)
    dc_host = _get_dc_hostname(config)
    ip = ip_override if ip_override is not None else user_info.get("ip") or "-"
    enc = encryption or random.choice(_TICKET_ENC_NORMAL)
    success = (status == "0x0")
    dns_domain_upper = _get_dns_domain(config).upper()
    svc_name = "krbtgt" if success else f"krbtgt/{dns_domain_upper}"
    enc_desc = {"0x12": "AES256-CTS-HMAC-SHA1-96", "0x11": "AES128-CTS-HMAC-SHA1-96",
                "0x17": "RC4-HMAC", "0x3": "DES-CBC-MD5"}.get(enc, enc)
    dc_supported = "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)"
    client_enc_types = ("\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tAES128-CTS-HMAC-SHA1-96"
                        "\n\t\tRC4-HMAC-NT\n\t\tRC4-HMAC-NT-EXP\n\t\tRC4-HMAC-OLD-EXP")
    event_data = {
        "TargetUserName":                   user_info["username"],
        "TargetDomainName":                 dns_domain_upper,
        "TargetSid":                        _stable_user_sid(user_info["username"]) if success else _SID_ANON,
        "ServiceName":                      svc_name,
        "ServiceSid":                       f"{_SYNTH_DOMAIN_SID}-502" if success else _SID_ANON,
        "TicketOptions":                    "0x40810010",
        "Status":                           status,
        "TicketEncryptionType":             enc,
        "PreAuthType":                      "2",
        "IpAddress":                        f"::ffff:{ip}" if ip and "." in str(ip) else ip,
        "IpPort":                           str(random.randint(49152, 65535)) if ip and ip != "-" else "0",
        "CertIssuerName":                   cert_issuer,
        "CertSerialNumber":                 cert_serial,
        "CertThumbprint":                   cert_thumbprint,
        "ResponseTicket":                   "N/A",
        "AccountSupportedEncryptionTypes":  "N/A",
        "AccountAvailableKeys":             "N/A",
        "ServiceSupportedEncryptionTypes":  dc_supported,
        "ServiceAvailableKeys":             "AES-SHA1, RC4",
        "DCSupportedEncryptionTypes":       dc_supported,
        "DCAvailableKeys":                  "AES-SHA1, RC4",
        "ClientAdvertizedEncryptionTypes":  client_enc_types,
        "SessionKeyEncryptionType":         enc,
        "PreAuthEncryptionType":            "N/A",
    }
    return _build_event(4768, dc_host, event_data, success=success, ts=ts,
)


def _build_4769(user_info, config, *, service_spn=None, encryption=None,
                status="0x0", ip_override=None, ts=None) -> dict:
    """4769 – Kerberos service-ticket request (DC event)."""
    domain = _get_domain(config)
    dc_host = _get_dc_hostname(config)
    ip = ip_override if ip_override is not None else user_info.get("ip") or "-"
    spn = service_spn or random.choice(_SERVICE_ACCOUNT_SPNS)
    enc = encryption or random.choice(_TICKET_ENC_NORMAL)
    success = (status == "0x0")
    svc_acct = _SPN_TO_SERVICE_ACCOUNT.get(spn)
    if svc_acct:
        svc_name = svc_acct
    elif spn.lower().startswith("krbtgt"):
        svc_name = "krbtgt"
    elif "/" in spn:
        svc_name = spn.split("/")[1].split(":")[0].split(".")[0].upper() + "$"
    else:
        svc_name = spn
    event_data = {
        "TargetUserName":        f"{user_info['username']}@{_get_dns_domain(config).upper()}",
        "TargetDomainName":      _get_dns_domain(config).upper(),
        "ServiceName":           svc_name,
        "ServiceSid":            _stable_user_sid(spn) if success else _SID_ANON,
        "TicketOptions":         "0x40810000",
        "TicketEncryptionType":  enc if success else "0xFFFFFFFF",
        "IpAddress":             f"::ffff:{ip}" if ip and "." in str(ip) else ip,
        "IpPort":                str(random.randint(49152, 65535)) if ip and ip != "-" else "0",
        "Status":                status,
        "LogonGuid":             _new_logon_guid(),
        "TransmittedServices":   "-",
    }
    # 4769 on newer DCs may also include encryption detail fields
    # but they are less consistently present than in 4768
    return _build_event(4769, dc_host, event_data, success=success, ts=ts,
)


def _build_4771(user_info, config, *, status="0x18", ip_override=None, ts=None) -> dict:
    """4771 – Kerberos pre-authentication failed (DC event, failure only)."""
    dc_host = _get_dc_hostname(config)
    ip = ip_override if ip_override is not None else user_info.get("ip") or "-"
    event_data = {
        "TargetUserName":        user_info["username"],
        "TargetSid":             _stable_user_sid(user_info["username"]),
        "ServiceName":           f"krbtgt/{_get_dns_domain(config).upper()}",
        "TicketOptions":         "0x40810010",
        "Status":                status,
        "PreAuthType":           "2",
        "IpAddress":             f"::ffff:{ip}" if ip and "." in str(ip) else ip,
        "IpPort":                str(random.randint(49152, 65535)),
        "CertIssuerName":        "",
        "CertSerialNumber":      "",
        "CertThumbprint":        "",
    }
    with _STATE_LOCK:
        _FAIL_COUNTS[user_info["username"]] = _FAIL_COUNTS.get(user_info["username"], 0) + 1
    return _build_event(4771, dc_host, event_data, success=False, ts=ts,
)


def _build_4776(user_info, config, *, status="0x0", workstation=None, ts=None) -> dict:
    """4776 – NTLM credential validation (DC event)."""
    dc_host = _get_dc_hostname(config)
    ws = (workstation or user_info.get("hostname") or "UNKNOWN").split(".")[0].upper()
    success = (status == "0x0")
    event_data = {
        "PackageName":     _NTLM_PACKAGE,
        "TargetUserName":  user_info["username"],
        "Workstation":     ws,
        "Status":          status,
    }
    return _build_event(4776, dc_host, event_data, success=success, ts=ts,
)


# UAC value constants for 4720/4722/4738
_UAC_NORMAL_ACCOUNT        = "0x200"     # 512: normal user account
_UAC_ACCOUNTDISABLE        = "0x202"     # 514: disabled + normal
_UAC_DONT_EXPIRE_PASSWD    = "0x10200"   # 66048: normal + DONT_EXPIRE_PASSWORD
_UAC_PASSWD_NOTREQD        = "0x220"     # 544: PASSWD_NOTREQD + normal

_DEFAULT_LOCAL_ACCOUNTS = ["Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount"]


def _build_4720(user_info, config, *, target_username, target_sid,
                sam_account_name=None, display_name="-", upn="-",
                new_uac_value=_UAC_ACCOUNTDISABLE, logon_id=None,
                ts=None) -> dict:
    """4720 – A user account was created (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "TargetUserName":      target_username,
        "TargetDomainName":    domain,
        "TargetSid":           target_sid,
        "SubjectUserSid":      _stable_user_sid(user_info["username"]),
        "SubjectUserName":     user_info["username"],
        "SubjectDomainName":   domain,
        "SubjectLogonId":      logon_id or _new_logon_id(),
        "PrivilegeList":       "-",
        "SamAccountName":      sam_account_name or target_username,
        "DisplayName":         display_name,
        "UserPrincipalName":   upn,
        "HomeDirectory":       "-",
        "HomePath":            "-",
        "ScriptPath":          "-",
        "ProfilePath":         "-",
        "UserWorkstations":    "-",
        "PasswordLastSet":     _iso_ts(ts),
        "AccountExpires":      "%%1794",
        "PrimaryGroupId":      "513",
        "AllowedToDelegateTo": "-",
        "OldUacValue":         "0x0",
        "NewUacValue":         new_uac_value,
        "UserAccountControl":  "%%2080\r\n\t\t%%2082" if new_uac_value == _UAC_ACCOUNTDISABLE else "%%2080",
        "UserParameters":      "-",
        "SidHistory":          "-",
        "LogonHours":          "%%1793",
    }
    return _build_event(4720, dc_host, event_data, success=True, ts=ts)


def _build_4722(user_info, config, *, target_username, target_sid,
                logon_id=None, ts=None) -> dict:
    """4722 – A user account was enabled (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "TargetUserName":    target_username,
        "TargetDomainName":  domain,
        "TargetSid":         target_sid,
        "SubjectUserSid":    _stable_user_sid(user_info["username"]),
        "SubjectUserName":   user_info["username"],
        "SubjectDomainName": domain,
        "SubjectLogonId":    logon_id or _new_logon_id(),
    }
    return _build_event(4722, dc_host, event_data, success=True, ts=ts)


def _build_4725(user_info, config, *, target_username, target_sid,
                logon_id=None, ts=None) -> dict:
    """4725 – A user account was disabled (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "TargetUserName":    target_username,
        "TargetDomainName":  domain,
        "TargetSid":         target_sid,
        "SubjectUserSid":    _stable_user_sid(user_info["username"]),
        "SubjectUserName":   user_info["username"],
        "SubjectDomainName": domain,
        "SubjectLogonId":    logon_id or _new_logon_id(),
    }
    return _build_event(4725, dc_host, event_data, success=True, ts=ts)


def _build_4724(user_info, config, *, target_username, target_sid,
                logon_id=None, ts=None) -> dict:
    """4724 – An attempt was made to reset an account's password (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "TargetUserName":    target_username,
        "TargetDomainName":  domain,
        "TargetSid":         target_sid,
        "SubjectUserSid":    _stable_user_sid(user_info["username"]),
        "SubjectUserName":   user_info["username"],
        "SubjectDomainName": domain,
        "SubjectLogonId":    logon_id or _new_logon_id(),
    }
    return _build_event(4724, dc_host, event_data, success=True, ts=ts)


def _build_4726(user_info, config, *, target_username, target_sid,
                logon_id=None, ts=None) -> dict:
    """4726 – A user account was deleted (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "TargetUserName":    target_username,
        "TargetDomainName":  domain,
        "TargetSid":         target_sid,
        "SubjectUserSid":    _stable_user_sid(user_info["username"]),
        "SubjectUserName":   user_info["username"],
        "SubjectDomainName": domain,
        "SubjectLogonId":    logon_id or _new_logon_id(),
        "PrivilegeList":     "-",
    }
    return _build_event(4726, dc_host, event_data, success=True, ts=ts)


def _build_4738(user_info, config, *, target_username, target_sid,
                sam_account_name=None, old_uac_value=_UAC_NORMAL_ACCOUNT,
                new_uac_value=_UAC_NORMAL_ACCOUNT, uac_control="-",
                allowed_to_delegate="-",
                logon_id=None, ts=None) -> dict:
    """4738 – A user account was changed (DC event)."""
    dc_host = _get_dc_hostname(config)
    domain = _get_domain(config)
    event_data = {
        "Dummy":               "-",
        "TargetUserName":      target_username,
        "TargetDomainName":    domain,
        "TargetSid":           target_sid,
        "SubjectUserSid":      _stable_user_sid(user_info["username"]),
        "SubjectUserName":     user_info["username"],
        "SubjectDomainName":   domain,
        "SubjectLogonId":      logon_id or _new_logon_id(),
        "PrivilegeList":       "-",
        "SamAccountName":      sam_account_name or target_username,
        "DisplayName":         "-",
        "UserPrincipalName":   "-",
        "HomeDirectory":       "-",
        "HomePath":            "-",
        "ScriptPath":          "-",
        "ProfilePath":         "-",
        "UserWorkstations":    "-",
        "PasswordLastSet":     "-",
        "AccountExpires":      "-",
        "PrimaryGroupId":      "-",
        "AllowedToDelegateTo": allowed_to_delegate,
        "OldUacValue":         old_uac_value,
        "NewUacValue":         new_uac_value,
        "UserAccountControl":  uac_control,
        "UserParameters":      "-",
        "SidHistory":          "-",
        "LogonHours":          "-",
    }
    return _build_event(4738, dc_host, event_data, success=True, ts=ts)


# ---------------------------------------------------------------------------
# Benign event generators
# ---------------------------------------------------------------------------

def _benign_interactive_logon(config, session_context):
    """User logs on interactively at their workstation (LogonType 2).
    Produces: DC 4768 + DC 4624 + endpoint 4624 + optional 4672.
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    t0 = time.time()
    logon_id = _new_logon_id()
    is_admin = random.random() < 0.15
    result = []
    result.append(json.dumps(_build_4768(u, config, ts=t0 - random.uniform(2.0, 4.0))))
    result.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t0 - random.uniform(0.8, 1.5))))
    result.append(json.dumps(_build_4624(u, config, logon_type=2, auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id, elevated=is_admin, ts=t0)))
    if is_admin:
        result.append(json.dumps(_build_4672(u, config, logon_id=logon_id, ts=t0 + 0.05)))
    return result


def _benign_network_share_logon(config, session_context):
    """User's workstation accesses a file share (LogonType 3, Kerberos).
    Produces: DC 4769 TGS + DC 4624 + server-side 4624.
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    server_spns = [s for s in _SERVICE_ACCOUNT_SPNS if s.startswith("cifs/")]
    spn = random.choice(server_spns or _SERVICE_ACCOUNT_SPNS)
    server_fqdn = spn.split("/")[1].split(":")[0]
    if "." not in server_fqdn:
        server_fqdn = f"{server_fqdn}.{_get_dns_domain(config)}"

    t0 = time.time()
    logon_id = _new_logon_id()
    result = []
    result.append(json.dumps(_build_4769(u, config, service_spn=spn, ts=t0 - random.uniform(2.0, 3.5))))
    result.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t0 - random.uniform(0.8, 1.5))))
    result.append(json.dumps(_build_4624(u, config, logon_type=3, auth_pkg=_KRB_PACKAGE,
                                         workstation_override=server_fqdn,
                                         target_logon_id=logon_id, ts=t0)))
    return result


def _benign_workstation_unlock(config, session_context):
    """User unlocks their screen (LogonType 7)."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    return json.dumps(_build_4624(u, config, logon_type=7, auth_pkg=_NEG_PACKAGE))


def _benign_logoff(config, session_context):
    """Close an existing open session with a 4634 or 4647.
    This is the only generator that mutates _OPEN_SESSIONS.
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    # Find an open session for the user's hostname — only emit logoff if
    # one exists AND it has been open long enough (5+ minutes) to be realistic.
    session = _pop_open_session(u["hostname"], u["username"])
    if not session:
        # No open session for this user — fall back to any other open session
        # on the same host (matches real behaviour: system-initiated logoffs).
        session = _pop_open_session(u["hostname"])
    if not session:
        # Nothing open → skip; logoff without matching logon is forbidden.
        return None

    age = time.time() - session["start"]
    if age < 300:  # < 5 min
        # Put the session back; it's too fresh to be logged off realistically.
        with _STATE_LOCK:
            _OPEN_SESSIONS.setdefault(u["hostname"], []).append(session)
        return None

    # Interactive logons → 4647 (user-initiated) + a trailing 4634
    # Non-interactive → just 4634
    if session["logon_type"] in (2, 10, 11):
        t0 = time.time()
        e1 = _build_4647(session, config, ts=t0)
        e2 = _build_4634(session, config, ts=t0 + 0.2)
        return [json.dumps(e1), json.dumps(e2)]
    else:
        return json.dumps(_build_4634(session, config))


def _benign_service_logon(config, session_context):
    """A service account logon (LogonType 5) — always gets 4672 privileges."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    svc_name = random.choice(_SERVICE_ACCOUNT_SAMS)
    fake_user = {**u, "username": svc_name}
    logon_id = _new_logon_id()
    t = time.time()
    logon = _build_4624(fake_user, config, logon_type=5, auth_pkg=_NEG_PACKAGE,
                        target_logon_id=logon_id, ts=t)
    priv = _build_4672(fake_user, config, logon_id=logon_id, is_service=True,
                       ts=t + 0.01)
    return [json.dumps(logon), json.dumps(priv)]


def _benign_dc_self_logon(config, session_context):
    """DC self-authentication — the background noise DCs constantly generate.

    Produces a mix of:
      - Type 5 service logon (svchost.exe starting a service as SYSTEM/machine acct)
      - Type 7 unlock (admin unlocking DC console)
      - Self-TGT request (DC's machine account requesting its own krbtgt)
    """
    dc_host = _get_dc_hostname(config)
    dc_short = _get_dc_short(config)
    domain = _get_domain(config)
    dc_machine_acct = dc_short + "$"
    dc_user = {
        "username": dc_machine_acct,
        "hostname": dc_host,
        "ip": "127.0.0.1",
    }
    events = []
    t = time.time()

    scenario = random.choices(
        ["service", "unlock", "tgt"],
        weights=[50, 20, 30], k=1)[0]

    if scenario == "service":
        svc = random.choice(_SERVICE_ACCOUNT_SAMS + [dc_machine_acct, "SYSTEM"])
        svc_user = {**dc_user, "username": svc}
        events.append(json.dumps(
            _build_4624(svc_user, config, logon_type=5,
                        auth_pkg=_NEG_PACKAGE,
                        workstation_override=dc_host,
                        ip_override="-", ts=t)))
    elif scenario == "unlock":
        admin_user = {**dc_user, "username": "Administrator"}
        events.append(json.dumps(
            _build_4624(admin_user, config, logon_type=7,
                        auth_pkg=_NEG_PACKAGE,
                        workstation_override=dc_host,
                        ip_override="127.0.0.1", ts=t)))
    else:
        events.append(json.dumps(
            _build_4768(dc_user, config,
                        ip_override="::1", ts=t)))

    return events


def _benign_scheduled_task_logon(config, session_context):
    """Scheduled task fires (LogonType 4 – Batch)."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    return json.dumps(_build_4624(u, config, logon_type=4, auth_pkg=_NEG_PACKAGE))


def _benign_cached_logon(config, session_context):
    """Laptop offline, uses cached creds (LogonType 11)."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    return json.dumps(_build_4624(u, config, logon_type=11, auth_pkg=_NEG_PACKAGE))


def _benign_rdp_logon(config, session_context):
    """Benign RDP into user's machine from another internal host (LogonType 10).
    Produces: DC 4769 TGS + DC 4624 + endpoint 4624 + optional 4672.
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    src = _pick_windows_user(session_context)
    src_ip = src["ip"] if src and src["ip"] != u["ip"] else "10.10.10.200"

    t0 = time.time()
    logon_id = _new_logon_id()
    is_admin = random.random() < 0.3
    result = []
    result.append(json.dumps(_build_4769(u, config, service_spn=f"TERMSRV/{u['hostname']}", ts=t0 - random.uniform(2.0, 3.5))))
    result.append(json.dumps(_dc_logon_event(u, config, ip_override=src_ip,
                                             logon_id=logon_id, ts=t0 - random.uniform(0.8, 1.5))))
    result.append(json.dumps(_build_4624(u, config, logon_type=10, auth_pkg=_KRB_PACKAGE,
                                         ip_override=src_ip, target_logon_id=logon_id,
                                         elevated=is_admin, ts=t0)))
    if is_admin:
        result.append(json.dumps(_build_4672(u, config, logon_id=logon_id, ts=t0 + 0.05)))
    return result


def _benign_sql_access(config, session_context):
    """User connects to SQL Server — 4769 TGS for MSSQLSvc SPN with AES."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    sql_spns = [s for s in _SERVICE_ACCOUNT_SPNS if s.startswith("MSSQLSvc/")]
    spn = random.choice(sql_spns)
    return json.dumps(_build_4769(u, config, service_spn=spn, encryption="0x12"))


def _benign_web_app_access(config, session_context):
    """User accesses intranet web app — 4769 TGS for HTTP SPN with AES."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    http_spns = [s for s in _SERVICE_ACCOUNT_SPNS if s.startswith("HTTP/")]
    spn = random.choice(http_spns)
    return json.dumps(_build_4769(u, config, service_spn=spn, encryption="0x12"))


def _benign_ldap_query(config, session_context):
    """Workstation queries AD — 4769 TGS for LDAP SPN with AES."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    ldap_spns = [s for s in _SERVICE_ACCOUNT_SPNS if s.startswith("LDAP/")]
    spn = random.choice(ldap_spns)
    return json.dumps(_build_4769(u, config, service_spn=spn, encryption="0x12"))


def _benign_ntlm_validation(config, session_context):
    """DC validates an NTLM credential request (LogonType 3-ish but from 4776 side)."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    return json.dumps(_build_4776(u, config, status="0x0"))


def _benign_explicit_cred_runas(config, session_context):
    """User uses runas to launch a process as another local account."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    target_user = u["username"] + "_admin"
    target_server = "localhost"
    return json.dumps(_build_4648(u, config, target_user=target_user,
                                  target_server=target_server))


def _benign_password_typo(config, session_context):
    """A single 4625 — user mistypes their password once, no lockout."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    return json.dumps(_build_4625(u, config, logon_type=2,
                                  sub_status="0xC000006A"))


# ---------------------------------------------------------------------------
# Benign process creation (4688) — realistic user workstation activity
# ---------------------------------------------------------------------------
# Each entry: (process_path, parent_process, command_line_template, weight)
# command_line_template may contain {doc} placeholder filled at runtime.

_BENIGN_DOCS = [
    "Q4-Budget.xlsx", "Presentation-Draft.pptx", "Meeting-Notes.docx",
    "Project-Plan.xlsx", "Status-Report.docx", "Invoice-2026.xlsx",
    "Employee-Handbook.docx", "Sales-Forecast.xlsx", "RFP-Response.docx",
    "Design-Review.pptx", "Onboarding-Checklist.docx", "Expense-Report.xlsx",
]

_BENIGN_URLS = [
    "https://intranet.examplecorp.local/dashboard",
    "https://sharepoint.examplecorp.local/sites/team",
    "https://outlook.office365.com/mail",
    "https://teams.microsoft.com",
    "https://confluence.examplecorp.local/wiki",
    "https://jira.examplecorp.local/browse/PROJ-1234",
]

_BENIGN_PROCESS_TABLE = [
    # ── Office apps (35%) ──
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"{doc}\"",
     12),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE\" \"{doc}\"",
     10),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"",
     8),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE\" /S \"{doc}\"",
     5),

    # ── Browsers (25%) ──
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --profile-directory=\"Default\"",
     12),
    ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --single-argument {url}",
     8),
    ("C:\\Program Files\\Mozilla Firefox\\firefox.exe",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -url {url}",
     5),

    # ── System utilities (20%) ──
    ("C:\\Windows\\System32\\svchost.exe",
     "C:\\Windows\\System32\\services.exe",
     "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule",
     4),
    ("C:\\Windows\\System32\\svchost.exe",
     "C:\\Windows\\System32\\services.exe",
     "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s Dnscache",
     3),
    ("C:\\Windows\\System32\\taskhostw.exe",
     "C:\\Windows\\System32\\svchost.exe",
     "taskhostw.exe",
     3),
    ("C:\\Windows\\System32\\conhost.exe",
     "C:\\Windows\\System32\\cmd.exe",
     "\\??\\C:\\Windows\\System32\\conhost.exe 0xffffffff -ForceV1",
     2),
    ("C:\\Windows\\System32\\dllhost.exe",
     "C:\\Windows\\System32\\svchost.exe",
     "C:\\Windows\\System32\\dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
     2),
    ("C:\\Windows\\System32\\RuntimeBroker.exe",
     "C:\\Windows\\System32\\svchost.exe",
     "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
     2),
    ("C:\\Windows\\System32\\SearchProtocolHost.exe",
     "C:\\Windows\\System32\\SearchIndexer.exe",
     "\"C:\\Windows\\System32\\SearchProtocolHost.exe\" Global\\UsGthrFltPipeMssGthrPipe",
     2),
    ("C:\\Windows\\explorer.exe",
     "C:\\Windows\\System32\\userinit.exe",
     "C:\\Windows\\explorer.exe",
     1),

    # ── Legitimate admin / dev tools (10%) ──
    ("C:\\Windows\\System32\\cmd.exe",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Windows\\System32\\cmd.exe\" /c dir \\\\fs01\\shared",
     2),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "C:\\Windows\\System32\\svchost.exe",
     "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\Scripts\\BackupCleanup.ps1",
     2),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
     1),
    ("C:\\Windows\\System32\\mstsc.exe",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Windows\\System32\\mstsc.exe\" /v:rdp-gw01.examplecorp.local",
     1),
    ("C:\\Windows\\System32\\mmc.exe",
     "C:\\Windows\\explorer.exe",
     "\"C:\\Windows\\System32\\mmc.exe\" \"C:\\Windows\\System32\\compmgmt.msc\" /s",
     1),

    # ── AV / monitoring / agents (5%) ──
    ("C:\\Program Files\\Windows Defender\\MsMpEng.exe",
     "C:\\Windows\\System32\\services.exe",
     "\"C:\\Program Files\\Windows Defender\\MsMpEng.exe\"",
     2),
    ("C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
     "C:\\Windows\\System32\\svchost.exe",
     "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate",
     1),
    ("C:\\Windows\\System32\\MpSigStub.exe",
     "C:\\Windows\\System32\\svchost.exe",
     "MpSigStub.exe /stub 1.1.2606.1 /payload 4.18.2606.1",
     1),

    # ── Scheduled / maintenance (5%) ──
    ("C:\\Windows\\System32\\gpupdate.exe",
     "C:\\Windows\\System32\\svchost.exe",
     "gpupdate.exe /force",
     1),
    ("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
     "C:\\Windows\\System32\\svchost.exe",
     "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe -secured -Embedding",
     1),
    ("C:\\Windows\\System32\\wsqmcons.exe",
     "C:\\Windows\\System32\\svchost.exe",
     "C:\\Windows\\System32\\wsqmcons.exe",
     1),
]


def _benign_process_creation(config, session_context):
    """Emit 1-3 benign 4688 (process creation) + 4689 (exit) events for
    normal user workstation activity — Office, browsers, system utilities.

    This is the highest-volume event in real Windows environments and
    establishes the UEBA baseline that makes attack tool 4688 events
    (mimikatz, Rubeus, procdump) detectable as anomalous.
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    count = random.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
    entries = random.choices(
        _BENIGN_PROCESS_TABLE,
        weights=[e[3] for e in _BENIGN_PROCESS_TABLE],
        k=count,
    )

    events = []
    t = time.time()
    for proc_path, parent, cmd_template, _w in entries:
        cmd = cmd_template
        if "{doc}" in cmd:
            cmd = cmd.replace("{doc}", random.choice(_BENIGN_DOCS))
        if "{url}" in cmd:
            cmd = cmd.replace("{url}", random.choice(_BENIGN_URLS))

        events.append(json.dumps(_build_4688(
            u, config,
            process_name=proc_path,
            command_line=cmd,
            parent_process=parent,
            ts=t)))
        t += random.uniform(0.01, 0.05)

        if random.random() < 0.3:
            events.append(json.dumps(_build_4689(
                u, config,
                process_name=proc_path,
                ts=t + random.uniform(5, 600))))

    return events


# ---------------------------------------------------------------------------
# DC-specific benign generators (baseline for UEBA)
# ---------------------------------------------------------------------------

_DC_SERVICE_ACCOUNTS = [
    ("SYSTEM",          _SID_SYSTEM,       5),
    ("LOCAL SERVICE",   _SID_LOCAL_SERVICE, 5),
    ("NETWORK SERVICE", _SID_NETWORK_SVC,  5),
]

_DC_GP_ATTRIBUTES = [
    ("gPLink",               "2.5.5.12", "LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System"),
    ("gPOptions",            "2.5.5.9",  "0"),
    ("whenChanged",          "2.5.5.11", ""),
    ("uSNChanged",           "2.5.5.16", ""),
    ("dSCorePropagationData","2.5.5.11", ""),
    ("msDS-RevealedUsers",   "2.5.5.7",  ""),
    ("msDS-NcType",          "2.5.5.9",  "0"),
]

_DC_GP_OBJECT_CLASSES = [
    "domainDNS", "organizationalUnit", "groupPolicyContainer",
    "container", "builtinDomain",
]


def _benign_dc_kerberos_traffic(config, session_context):
    """Steady-state Kerberos auth on the DC — TGT renewals, TGS for services.

    A real DC sees hundreds of 4768+4769 pairs per minute from normal user
    activity.  This generator produces 2-5 pairs per call, mimicking routine
    auth cycles from random users.
    """
    users = [_pick_windows_user(session_context) for _ in range(random.randint(2, 5))]
    users = [u for u in users if u]
    if not users:
        return None

    events = []
    t = time.time() - len(users) * 0.5

    for u in users:
        events.append(json.dumps(
            _build_4768(u, config, ip_override=u.get("ip"), ts=t)))
        t += random.uniform(0.01, 0.05)

        spn = random.choice(_SERVICE_ACCOUNT_SPNS)
        events.append(json.dumps(
            _build_4769(u, config, service_spn=spn, encryption="0x12", ts=t)))
        t += random.uniform(0.2, 1.5)

        if random.random() < 0.3:
            spn2 = random.choice(_SERVICE_ACCOUNT_SPNS)
            events.append(json.dumps(
                _build_4769(u, config, service_spn=spn2, encryption="0x12", ts=t)))
            t += random.uniform(0.1, 0.4)

    return events


def _benign_dc_directory_service(config, session_context):
    """Normal directory service modifications on the DC — GPO refreshes,
    replication metadata updates, attribute housekeeping.

    These are the routine 5136 events that build the UEBA baseline, so
    the dMSA attack's msDS-ManagedAccountPrecededByLink stands out as
    anomalous.  Real DCs emit dozens of these per minute.
    """
    dc_host = _get_dc_hostname(config)
    dc_short = _get_dc_short(config)
    domain = _get_domain(config)
    dns_domain = _get_dns_domain(config)
    base_dn = ",".join(f"DC={p}" for p in dns_domain.split("."))
    dc_user = {
        "username": dc_short + "$",
        "hostname": dc_host,
        "ip": "127.0.0.1",
    }

    events = []
    t = time.time() - random.uniform(0, 2)
    op_correlation_id = _new_logon_guid()
    logon_id = _new_logon_id()
    n_mods = random.randint(1, 4)

    for _ in range(n_mods):
        attr_name, syntax_oid, default_val = random.choice(_DC_GP_ATTRIBUTES)
        obj_class = random.choice(_DC_GP_OBJECT_CLASSES)

        if attr_name in ("whenChanged", "dSCorePropagationData"):
            from datetime import datetime, timezone
            attr_value = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S.0Z")
        elif attr_name == "uSNChanged":
            attr_value = str(random.randint(100000, 9999999))
        elif default_val:
            attr_value = default_val
        else:
            attr_value = "-"

        ou_names = ["Domain Controllers", "Users", "Computers", "Servers"]
        obj_dn = f"OU={random.choice(ou_names)},{base_dn}"
        if obj_class == "groupPolicyContainer":
            gpo_guid = str(uuid.uuid4())
            obj_dn = f"CN={{{gpo_guid}}},CN=Policies,CN=System,{base_dn}"

        events.append(json.dumps(
            _build_5136(dc_user, config,
                        object_dn=obj_dn,
                        object_class=obj_class,
                        object_guid=_new_logon_guid(),
                        attribute_name=attr_name,
                        attribute_value=attr_value,
                        attribute_syntax_oid=syntax_oid,
                        op_correlation_id=op_correlation_id,
                        logon_id=logon_id,
                        ts=t)))
        t += random.uniform(0.001, 0.01)

    return events


def _benign_dc_service_activity(config, session_context):
    """Built-in service account logons on the DC — SYSTEM, DNS, DFSR, health
    mailbox, etc.  These fire constantly as Windows services start, renew
    credentials, or perform internal operations.

    Produces a type-5 (service) 4624 + 4672 pair from a DC built-in account.
    """
    dc_host = _get_dc_hostname(config)
    dc_short = _get_dc_short(config)
    domain = _get_domain(config)

    svc_acct, svc_sid, logon_type = random.choice(_DC_SERVICE_ACCOUNTS)
    dc_svc_user = {
        "username": svc_acct,
        "hostname": dc_host,
        "ip": "127.0.0.1",
    }

    events = []
    t = time.time()
    logon_id = _new_logon_id()

    events.append(json.dumps(
        _build_4624(dc_svc_user, config,
                    logon_type=logon_type,
                    auth_pkg=_NEG_PACKAGE,
                    workstation_override=dc_host,
                    ip_override="-",
                    target_logon_id=logon_id,
                    ts=t)))
    t += 0.01

    events.append(json.dumps(
        _build_4672(dc_svc_user, config,
                    logon_id=logon_id,
                    is_service=True,
                    ts=t)))

    if random.random() < 0.4:
        t += random.uniform(0.01, 0.05)
        machine_user = {**dc_svc_user, "username": dc_short + "$"}
        events.append(json.dumps(
            _build_4768(machine_user, config,
                        ip_override="::1", ts=t)))

    return events


_BENIGN_WEIGHTS = {
    # Higher weights → more realistic day-in-the-life (Windows auth volume
    # is dominated by unlocks, network-share access, and routine interactive
    # logons).  SQL/web/LDAP access generates steady 4769 AES baseline that
    # UEBA uses to contrast against RC4 Kerberoasting bursts.
    "interactive_logon":     18,
    "network_share_logon":   22,
    "workstation_unlock":    18,
    "logoff":                10,
    "service_logon":          6,
    "scheduled_task_logon":   4,
    "cached_logon":           2,
    "rdp_logon":              3,
    "sql_access":            10,
    "web_app_access":         8,
    "ldap_query":             6,
    "ntlm_validation":        4,
    "explicit_cred_runas":    1,
    "password_typo":          2,
    "dc_self_logon":          8,
    "dc_kerberos_traffic":   15,
    "dc_directory_service":   8,
    "dc_service_activity":   10,
    "process_creation":      30,
}

_BENIGN_GENERATORS = {
    "interactive_logon":    _benign_interactive_logon,
    "network_share_logon":  _benign_network_share_logon,
    "workstation_unlock":   _benign_workstation_unlock,
    "logoff":               _benign_logoff,
    "service_logon":        _benign_service_logon,
    "scheduled_task_logon": _benign_scheduled_task_logon,
    "cached_logon":         _benign_cached_logon,
    "rdp_logon":            _benign_rdp_logon,
    "sql_access":           _benign_sql_access,
    "web_app_access":       _benign_web_app_access,
    "ldap_query":           _benign_ldap_query,
    "ntlm_validation":      _benign_ntlm_validation,
    "explicit_cred_runas":  _benign_explicit_cred_runas,
    "password_typo":        _benign_password_typo,
    "dc_self_logon":        _benign_dc_self_logon,
    "dc_kerberos_traffic":  _benign_dc_kerberos_traffic,
    "dc_directory_service": _benign_dc_directory_service,
    "dc_service_activity":  _benign_dc_service_activity,
    "process_creation":     _benign_process_creation,
}


def _select_benign(config, session_context):
    """Pick a weighted benign generator and run it."""
    cfg_mix = _cf(config).get("event_mix", {}).get("benign", {})
    weights = {k: cfg_mix.get(k, v) for k, v in _BENIGN_WEIGHTS.items()}
    choice = random.choices(list(weights.keys()), weights=list(weights.values()), k=1)[0]
    fn = _BENIGN_GENERATORS[choice]
    result = fn(config, session_context)
    # Some generators (logoff) return None if no state allows them — retry once
    if result is None:
        fn2 = _BENIGN_GENERATORS["interactive_logon"]
        result = fn2(config, session_context)
    return result


# ---------------------------------------------------------------------------
# Threat generators
# ---------------------------------------------------------------------------
#
# Every threat generator returns a list of JSON strings so the transport
# layer emits them all in one call.  Detection-completeness patterns follow
# the same convention as the other LogSim modules: brute-force sequences
# always end with a successful authentication so XSIAM UEBA triggers on the
# failure→success transition.


_ASREP_EXTRA_TARGETS = [
    "svc_legacy", "svc_oldapp", "svc_ftp_legacy", "svc_ndes",
    "svc_print_legacy", "svc_kiosk", "app_readonly", "app_batch",
    "test_user01", "test_user02", "test_svc", "dev_deploy",
    "scan_agent", "report_svc", "monitor_legacy", "backup_old",
    "migration_svc", "staging_app", "qa_automation", "build_agent",
    "ldap_browser", "sync_svc", "repl_monitor", "audit_legacy",
    "helpdesk_svc", "inventory_svc", "patch_agent", "asset_scan",
    "nessus_svc", "splunk_fwd",
]


def _threat_as_rep_roasting(config, session_context):
    """AS-REP Roasting: attacker enumerates accounts with pre-auth disabled.

    Sequence:
      1. Attacker authenticates from their own machine → 4768 TGT (normal)
      2. Attacker's session starts → 4624 + 4672 (elevated)
      3. 4688 attack tool process (Rubeus/GetNPUsers)
      4. Burst of 30-50 4768 TGT requests for many different users with
         PreAuthType=0 (no pre-auth) and weak encryption — all from the
         same source IP.
      5. 4689 process exit + 4634 logoff

    Detection keys:
      - Many 4768 events for distinct TargetUserNames from a single IP
      - PreAuthType = 0 (Kerberos pre-auth disabled / not required)
      - Weak encryption types (RC4/DES) on the ticket responses
      - All requests hit the DC in rapid succession
    """
    users = _get_windows_users(session_context)
    if len(users) < 3:
        return None
    attacker = random.choice(users)
    src_ip = attacker.get("ip") or "10.0.0.1"

    target_usernames = [u["username"] for u in users if u["username"] != attacker["username"]]
    target_usernames += _ASREP_EXTRA_TARGETS[:]
    random.shuffle(target_usernames)
    target_usernames = target_usernames[:random.randint(40, 55)]

    events = []
    t = time.time() - len(target_usernames)

    logon_id = _new_logon_id()

    events.append(json.dumps(_build_4768(attacker, config, ip_override=src_ip, ts=t)))
    t += 1.0
    events.append(json.dumps(_dc_logon_event(attacker, config, ip_override=src_ip,
                                             logon_id=logon_id, ts=t)))
    t += 1.2
    events.append(json.dumps(_build_4624(attacker, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         ip_override=src_ip, elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(attacker, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    tool = ("C:\\Users\\Public\\Rubeus.exe",
            "C:\\Users\\Public\\Rubeus.exe asreproast /format:hashcat /nowrap")
    events.append(json.dumps(_build_4688(attacker, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    vuln_count = random.randint(3, 6)
    vuln_users = set(random.sample(target_usernames, k=min(vuln_count, len(target_usernames))))

    for uname in target_usernames:
        fake_user = {"username": uname, "ip": src_ip, "hostname": attacker.get("hostname", "WKS001")}
        if uname in vuln_users:
            ev = _build_4768(fake_user, config, ip_override=src_ip,
                             encryption="0x17", ts=t)
            ev["event_data"]["PreAuthType"] = "0"
            ev["event_data"]["TicketOptions"] = "0x40800010"
            events.append(json.dumps(ev))
        else:
            events.append(json.dumps(_build_4771(fake_user, config,
                                                  status="0x18",
                                                  ip_override=src_ip, ts=t)))
        t += random.uniform(0.1, 0.4)

    events.append(json.dumps(_build_4689(attacker, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(60, 300)
    session = _pop_open_session(attacker["hostname"], attacker["username"])
    if session:
        events.append(json.dumps(_build_4634(session, config, ts=t)))

    return events


def _threat_account_lockout(config, session_context):
    """Multiple users locked out from a single source host — password spray
    that triggers account lockout for each targeted user.

    XSIAM detection: "Excessive User Lockouts" — a high number of 4740
    events sharing the same source host (TargetDomainName) in a short window.

    All DC-side events (4771, 4776, 4625, 4740) use:
      - computer_name = DC hostname (DC logs them)
      - IpAddress     = attacker's IP  (single source)
      - Workstation   = attacker's hostname
    """
    users = _get_windows_users(session_context)
    if len(users) < 4:
        return None
    num_victims = random.randint(4, 8)
    victims = random.sample(users, k=min(len(users), num_victims))

    attacker = random.choice(users)
    attacker_ip = attacker.get("ip") or "10.0.1.200"
    attacker_hostname = attacker.get("hostname", "WKS-ATTACK01").split(".")[0].upper()
    dc_host = _get_dc_hostname(config)

    events = []
    t = time.time() - num_victims * 60

    for victim in victims:
        attempts = random.randint(8, 12)
        for _ in range(attempts):
            events.append(json.dumps(_build_4771(victim, config, status="0x18",
                                                 ip_override=attacker_ip, ts=t)))
            events.append(json.dumps(_build_4776(victim, config, status="0xC000006A",
                                                 workstation=attacker_hostname, ts=t + 0.8)))
            events.append(json.dumps(_build_4625(victim, config, logon_type=3,
                                                 sub_status="0xC000006A",
                                                 workstation_override=dc_host,
                                                 source_workstation=attacker_hostname,
                                                 ip_override=attacker_ip, ts=t + 1.5)))
            t += random.uniform(3, 8)
        events.append(json.dumps(_build_4740(victim, config,
                                             source_workstation=attacker_hostname, ts=t)))
        events.append(json.dumps(_build_4625(victim, config, logon_type=3,
                                             status="0xC0000234", sub_status="0x0",
                                             workstation_override=dc_host,
                                             source_workstation=attacker_hostname,
                                             ip_override=attacker_ip, ts=t + 2.0)))
        t += random.uniform(2, 5)
    return events


_SUSPICIOUS_LOCKOUT_ACCOUNTS = [
    "svc_sql_prod", "svc_sql_dev", "svc_iis", "svc_sharepoint",
    "svc_backup", "svc_monitoring", "svc_jenkins", "svc_reporting",
    "svc_crm", "svc_etl",
    "admin.backup", "admin.helpdesk", "admin.network",
    "Administrator", "da_admin", "tier0_admin",
]


def _threat_suspicious_account_lockout(config, session_context):
    """Service / admin / privileged accounts locked out from a single source
    host — significantly more suspicious than regular user lockouts.

    XSIAM detection: "Excessive account lockouts on suspicious users" —
    same trigger as regular lockout (multiple 4740 from one source) but
    elevated to Medium severity because the locked accounts are service
    accounts, admin accounts, or users with existing UEBA risk scores.

    All DC-side events (4771, 4776, 4625, 4740) use:
      - computer_name = DC hostname (DC logs them)
      - IpAddress     = attacker's IP  (single source)
      - Workstation   = attacker's hostname
    """
    all_users = _get_windows_users(session_context)
    if not all_users:
        return None

    dc_host = _get_dc_hostname(config)

    num_victims = random.randint(4, 7)
    svc_accounts = random.sample(
        _SUSPICIOUS_LOCKOUT_ACCOUNTS,
        k=min(len(_SUSPICIOUS_LOCKOUT_ACCOUNTS), num_victims))

    attacker = random.choice(all_users)
    attacker_ip = attacker.get("ip") or "10.0.1.200"
    attacker_hostname = attacker.get("hostname", "WKS-ATTACK01").split(".")[0].upper()

    events = []
    t = time.time() - num_victims * 60

    for acct_name in svc_accounts:
        svc_user = {
            "username": acct_name,
            "hostname": dc_host,
            "ip": attacker_ip,
        }
        attempts = random.randint(6, 10)
        for _ in range(attempts):
            events.append(json.dumps(_build_4771(svc_user, config, status="0x18",
                                                 ip_override=attacker_ip, ts=t)))
            events.append(json.dumps(_build_4776(svc_user, config, status="0xC000006A",
                                                 workstation=attacker_hostname, ts=t + 0.8)))
            events.append(json.dumps(_build_4625(svc_user, config, logon_type=3,
                                                 sub_status="0xC000006A",
                                                 workstation_override=dc_host,
                                                 source_workstation=attacker_hostname,
                                                 ip_override=attacker_ip, ts=t + 1.5)))
            t += random.uniform(3, 8)
        events.append(json.dumps(_build_4740(svc_user, config,
                                             source_workstation=attacker_hostname, ts=t)))
        events.append(json.dumps(_build_4625(svc_user, config, logon_type=3,
                                             status="0xC0000234", sub_status="0x0",
                                             workstation_override=dc_host,
                                             source_workstation=attacker_hostname,
                                             ip_override=attacker_ip, ts=t + 2.0)))
        t += random.uniform(2, 5)
    return events


# DCSync replication GUIDs (DS-Replication-Get-Changes family)
_GUID_REPL_GET_CHANGES     = "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
_GUID_REPL_GET_CHANGES_ALL = "{1131f6ae-9c07-11d1-f79f-00c04fc2dcd2}"
_GUID_REPL_IN_FILTERED_SET = "{89e95b76-444d-4c62-991a-0facbeda640c}"


def _threat_dcsync(config, session_context):
    """DCSync: attacker uses DS-Replication-Get-Changes to extract password
    hashes directly from a domain controller, mimicking DC replication.

    Sequence:
      1. Attacker authenticates → 4624 + 4672
      2. 4688 Mimikatz process creation (lsadump::dcsync)
      3. DC logs 4662 (Directory Service Access) with replication GUIDs —
         this is THE detection signal. Normal users never request replication.
      4. Multiple 4662 events for different target objects (krbtgt, admin accts)
      5. 4689 process exit

    Detection keys:
      - 4662 with Properties containing Replication-Get-Changes GUID from
        a non-DC machine account
      - SubjectUserName is a regular user/admin, NOT a DC$ machine account
      - ObjectName targets sensitive AD objects (CN=krbtgt, Domain Admins)
      - Sigma/Sentinel/Splunk all have dedicated DCSync rules for this
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)
    events = []
    t = time.time()

    logon_id = _new_logon_id()
    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    events.append(json.dumps(_build_4688(u, config,
                                         process_name="C:\\Users\\Public\\mimikatz.exe",
                                         command_line='mimikatz.exe "lsadump::dcsync /user:krbtgt"',
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(1.0, 3.0)

    targets = [
        f"CN=krbtgt,CN=Users,{base_dn}",
        f"CN=Administrator,CN=Users,{base_dn}",
        f"CN=Domain Admins,CN=Users,{base_dn}",
        f"{base_dn}",
    ]
    for obj in targets:
        props = (f"{_GUID_REPL_GET_CHANGES}\n    "
                 f"{_GUID_REPL_GET_CHANGES_ALL}\n    "
                 f"{_GUID_REPL_IN_FILTERED_SET}\n")
        events.append(json.dumps(_build_4662(
            u, config,
            object_type="%{bf967aba-0de6-11d0-a285-00aa003049e2}",
            object_name=obj,
            access_mask="0x100",
            properties=props,
            operation_type="Object Access",
            logon_id=logon_id, ts=t)))
        t += random.uniform(0.2, 0.5)

    events.append(json.dumps(_build_4689(u, config,
                                         process_name="C:\\Users\\Public\\mimikatz.exe",
                                         logon_id=logon_id, ts=t)))
    return events


def _threat_lateral_movement_chain(config, session_context):
    """Multi-hop lateral movement: attacker chains through 3+ hosts using
    a mix of PTH, RDP, and service ticket requests.

    Sequence (A→B→C→D):
      1. Attacker on Host-A uses PtH (4648+4776+4624 type 3) to reach Host-B
      2. From Host-B, requests TGS for Host-C (4769) + 4624 type 3 on Host-C
      3. From Host-C, requests TGS for Host-D (4769) + 4624 type 3 on Host-D
      4. Each hop leaves a DC-side 4624 + 4672 trail

    Detection keys:
      - Same TargetUserName appearing in 4624 type 3 across 3+ different
        ComputerNames in a short window (lateral spread)
      - IP address of each prior host appearing as source of next 4624
      - Rapid sequence of 4769 TGS requests for different host SPNs
      - KeyLength=0 + NTLM on the initial PTH hop
    """
    users = _get_windows_users(session_context)
    if len(users) < 4:
        return None

    attacker = random.choice(users)
    hops = random.sample([u for u in users if u["hostname"] != attacker["hostname"]],
                         k=min(3, len(users) - 1))
    events = []
    t = time.time()

    logon_id_0 = _new_logon_id()
    events.append(json.dumps(_build_4768(attacker, config, ts=t)))
    t += 1.0
    events.append(json.dumps(_dc_logon_event(attacker, config,
                                             ip_override=attacker.get("ip"),
                                             logon_id=logon_id_0, ts=t)))
    t += 1.2
    events.append(json.dumps(_build_4624(attacker, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id_0,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(attacker, config, logon_id=logon_id_0,
                                         is_admin=True, ts=t)))
    t += random.uniform(3, 8)

    current_ip = attacker.get("ip") or "10.0.0.1"

    for hop_target in hops:
        hop_logon_id = _new_logon_id()

        events.append(json.dumps(_build_4648(
            attacker, config,
            target_user=attacker["username"],
            target_server=hop_target["hostname"].split(".")[0],
            process_name="C:\\Windows\\System32\\cmd.exe",
            ip_override=current_ip, ts=t)))
        t += 1.0

        events.append(json.dumps(_build_4776(attacker, config, status="0x0",
                                             workstation=hop_target["hostname"],
                                             ts=t)))
        t += 0.8

        events.append(json.dumps(_dc_logon_event(attacker, config,
                                                 auth_pkg=_NTLM_PACKAGE_SHORT,
                                                 ip_override=current_ip,
                                                 logon_id=hop_logon_id, ts=t)))
        t += 0.5

        events.append(json.dumps(_build_4769(attacker, config,
                                             service_spn=f"cifs/{hop_target['hostname']}",
                                             ts=t)))
        t += 1.2

        ev = _build_4624(attacker, config, logon_type=3,
                         auth_pkg=_NTLM_PACKAGE_SHORT,
                         workstation_override=hop_target["hostname"],
                         ip_override=current_ip,
                         target_logon_id=hop_logon_id,
                         elevated=True, ts=t)
        ev["event_data"]["LogonProcessName"] = "NtLmSsp "
        ev["event_data"]["LmPackageName"] = "NTLM V2"
        ev["event_data"]["KeyLength"] = "0"
        events.append(json.dumps(ev))
        t += 0.05

        events.append(json.dumps(_build_4672(attacker, config,
                                             logon_id=hop_logon_id, ts=t)))
        t += random.uniform(3, 15)

        # Next hop source IP is the current target
        current_ip = hop_target.get("ip") or current_ip

    return events

_BENIGN_WEIGHTS["lateral_movement"] = 3
_BENIGN_GENERATORS["lateral_movement"] = _threat_lateral_movement_chain


# ---------------------------------------------------------------------------
# dMSA privilege escalation targets — privileged accounts whose privileges
# the attacker inherits via msDS-ManagedAccountPrecededByLink
# ---------------------------------------------------------------------------
_DMSA_TARGETS = [
    ("Administrator",  "CN=Administrator,CN=Users,{base_dn}"),
    ("krbtgt",         "CN=krbtgt,CN=Users,{base_dn}"),
    ("Domain Admins",  "CN=Domain Admins,CN=Users,{base_dn}"),
    ("Enterprise Admins", "CN=Enterprise Admins,CN=Users,{base_dn}"),
]

_DMSA_NAMES = [
    "svc-backup-dmsa", "svc-monitor-dmsa", "svc-deploy-dmsa",
    "svc-replication-dmsa", "svc-scanner-dmsa", "svc-audit-dmsa",
]

_DMSA_ATTACK_TOOLS = [
    ("C:\\Users\\Public\\SharpSuccessor.exe",
     'SharpSuccessor.exe add /impersonate:{target} /path:"{ou}" /name:{dmsa_name}'),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     'powershell.exe -ep bypass -c "Import-Module .\\BadSuccessor.ps1; '
     'Invoke-BadSuccessor -TargetAccount {target} -dMSAName {dmsa_name} -OUPath \'{ou}\'"'),
]


def _threat_dmsa_privesc(config, session_context):
    """dMSA (BadSuccessor) privilege escalation: attacker creates a delegated
    Managed Service Account and sets msDS-ManagedAccountPrecededByLink to
    point at a privileged account, inheriting its privileges.

    CVE-2025-21293 — requires CreateChild on target OU, works in default
    Windows Server 2025 AD configurations.

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4688 SharpSuccessor/PowerShell process creation
      3. 4741 Computer account created (dMSA is a computer-class object)
      4. 5137 Directory service object created (the dMSA)
      5. 5136 ×5 Directory service modifications (correlated by OpCorrelationID):
         a. msDS-DelegatedMSAState = 0 (initial)
         b. msDS-ManagedAccountPrecededByLink = {target DN} ← DETECTION TRIGGER
         c. msDS-ManagedPasswordInterval = 30
         d. msDS-DelegatedMSAState: 0 deleted → 2 added (migration complete)
         e. msDS-SupersededManagedAccountLink = {dMSA DN}
      6. 4688 Rubeus for TGT delegation + dMSA impersonation
      7. 4769 Kerberos TGS request (dMSA service ticket)
      8. 4689 ×2 Process exits

    Detection keys:
      - 5136 with AttributeLDAPDisplayName=msDS-ManagedAccountPrecededByLink
        from a non-service/non-admin account → XSIAM "Possible Privilege
        Escalation using Delegated MSA account"
      - 4741 creating msDS-DelegatedManagedServiceAccount computer object
      - OpCorrelationID ties all 5136 events into one atomic operation
      - Non-DC machine account performing dMSA succession
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)

    target_label, target_dn_template = random.choice(_DMSA_TARGETS)
    target_dn = target_dn_template.format(base_dn=base_dn)
    dmsa_name = random.choice(_DMSA_NAMES)
    dmsa_sam = f"{dmsa_name}$"
    dmsa_dns = f"{dmsa_name}.{dns_domain}"
    dmsa_dn = f"CN={dmsa_name},OU=Servers,{base_dn}"
    dmsa_guid = _new_logon_guid()
    dmsa_sid = _stable_user_sid(dmsa_name)
    ou_path = f"OU=Servers,{base_dn}"

    tool_path, cmd_template = random.choice(_DMSA_ATTACK_TOOLS)
    cmd_line = cmd_template.format(target=target_label, dmsa_name=dmsa_name, ou=ou_path)

    events = []
    t = time.time()

    logon_id = _new_logon_id()
    op_corr_id = _new_logon_guid()

    # 1. DC-side logon for Kerberos auth
    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0

    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05

    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 8.0)

    events.append(json.dumps(_build_4688(u, config,
                                         process_name=tool_path,
                                         command_line=cmd_line,
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(1.0, 3.0)

    # 5. Computer account created (dMSA object)
    events.append(json.dumps(_build_4741(u, config,
                                         target_computer_name=dmsa_sam,
                                         target_sid=dmsa_sid,
                                         sam_account_name=dmsa_sam,
                                         dns_host_name=dmsa_dns,
                                         spns=f"HOST/{dmsa_dns} RestrictedKrbHost/{dmsa_dns} HOST/{dmsa_name.upper()} RestrictedKrbHost/{dmsa_name.upper()}",
                                         new_uac_value="0x1000",
                                         logon_id=logon_id, ts=t)))
    t += 0.02

    # 6. Directory service object created (dMSA)
    events.append(json.dumps(_build_5137(u, config,
                                         object_dn=dmsa_dn,
                                         object_class="msDS-DelegatedManagedServiceAccount",
                                         object_guid=dmsa_guid,
                                         op_correlation_id=op_corr_id,
                                         logon_id=logon_id, ts=t)))
    t += 0.01

    # 7a. 5136: msDS-DelegatedMSAState = 0 (initial state)
    events.append(json.dumps(_build_5136(u, config,
                                         object_dn=dmsa_dn,
                                         object_class="msDS-DelegatedManagedServiceAccount",
                                         object_guid=dmsa_guid,
                                         attribute_name="msDS-DelegatedMSAState",
                                         attribute_value="0",
                                         attribute_syntax_oid="2.5.5.9",
                                         operation_type="%%14674",
                                         op_correlation_id=op_corr_id,
                                         logon_id=logon_id, ts=t)))
    t += 0.01

    # 7b. 5136: msDS-ManagedAccountPrecededByLink = target DN ← KEY DETECTION TRIGGER
    events.append(json.dumps(_build_5136(u, config,
                                         object_dn=dmsa_dn,
                                         object_class="msDS-DelegatedManagedServiceAccount",
                                         object_guid=dmsa_guid,
                                         attribute_name="msDS-ManagedAccountPrecededByLink",
                                         attribute_value=target_dn,
                                         attribute_syntax_oid="2.5.5.1",
                                         operation_type="%%14674",
                                         op_correlation_id=op_corr_id,
                                         logon_id=logon_id, ts=t)))
    t += 0.01

    # 7c. 5136: msDS-ManagedPasswordInterval = 30
    events.append(json.dumps(_build_5136(u, config,
                                         object_dn=dmsa_dn,
                                         object_class="msDS-DelegatedManagedServiceAccount",
                                         object_guid=dmsa_guid,
                                         attribute_name="msDS-ManagedPasswordInterval",
                                         attribute_value="30",
                                         attribute_syntax_oid="2.5.5.9",
                                         operation_type="%%14674",
                                         op_correlation_id=op_corr_id,
                                         logon_id=logon_id, ts=t)))
    t += 0.01

    # 7d. 5136: msDS-DelegatedMSAState: delete 0, add 2 (migration complete)
    events.append(json.dumps(_build_5136(u, config,
                                         object_dn=dmsa_dn,
                                         object_class="msDS-DelegatedManagedServiceAccount",
                                         object_guid=dmsa_guid,
                                         attribute_name="msDS-DelegatedMSAState",
                                         attribute_value="0",
                                         attribute_syntax_oid="2.5.5.9",
                                         operation_type="%%14675",
                                         op_correlation_id=op_corr_id,
                                         logon_id=logon_id, ts=t)))
    t += 0.005
    events.append(json.dumps(_build_5136(u, config,
                                         object_dn=dmsa_dn,
                                         object_class="msDS-DelegatedManagedServiceAccount",
                                         object_guid=dmsa_guid,
                                         attribute_name="msDS-DelegatedMSAState",
                                         attribute_value="2",
                                         attribute_syntax_oid="2.5.5.9",
                                         operation_type="%%14674",
                                         op_correlation_id=op_corr_id,
                                         logon_id=logon_id, ts=t)))
    t += 0.01

    # 7e. 5136: msDS-SupersededManagedAccountLink on the target (points back to dMSA)
    events.append(json.dumps(_build_5136(u, config,
                                         object_dn=target_dn,
                                         object_class="user",
                                         object_guid=_new_logon_guid(),
                                         attribute_name="msDS-SupersededManagedAccountLink",
                                         attribute_value=dmsa_dn,
                                         attribute_syntax_oid="2.5.5.1",
                                         operation_type="%%14674",
                                         op_correlation_id=op_corr_id,
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 2.0)

    # 8. Rubeus TGT delegation + dMSA impersonation
    events.append(json.dumps(_build_4688(u, config,
                                         process_name="C:\\Users\\Public\\Rubeus.exe",
                                         command_line="Rubeus.exe tgtdeleg /nowrap",
                                         parent_process=tool_path,
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.3, 1.0)

    # 9. Kerberos TGS request — dMSA requesting service ticket (impersonation)
    events.append(json.dumps(_build_4769(u, config,
                                         service_spn=f"krbtgt/{dns_domain.upper()}",
                                         encryption="0x12",
                                         ip_override=u.get("ip"),
                                         ts=t)))
    t += random.uniform(0.5, 1.5)

    # 10. Process exits
    events.append(json.dumps(_build_4689(u, config,
                                         process_name="C:\\Users\\Public\\Rubeus.exe",
                                         logon_id=logon_id, ts=t)))
    t += 0.01
    events.append(json.dumps(_build_4689(u, config,
                                         process_name=tool_path,
                                         logon_id=logon_id, ts=t)))

    return events


def _threat_priv_group_addition(config, session_context):
    """Machine or user account added to a privileged AD group (Domain Admins,
    Enterprise Admins, or Builtin Administrators).

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4688 net.exe / PowerShell process creation (group manipulation)
      3. 4728/4732/4756 member added to privileged group (DC event)
         — event ID depends on group scope (global/local/universal)
      4. 4689 process exit

    Detection keys:
      - 4728 with TargetUserName="Domain Admins" and MemberName containing
        a machine account ($) or non-admin user → immediate alert
      - SubjectUserName performing the add is a regular user, not a DC$ account
      - XSIAM rule: "Machine account was added to a domain admins group"
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)

    group_name, group_info = random.choice(list(_PRIVILEGED_GROUPS.items()))

    is_machine = random.random() < 0.6
    if is_machine:
        victim_name = random.choice([
            "YOURPC01$", "YOURPC02$", "WKS-TEMP$", "YOURPC03$",
            u["hostname"].split(".")[0].upper() + "$",
        ])
        victim_dn = f"CN={victim_name.rstrip('$')},CN=Computers,{base_dn}"
    else:
        victim = _pick_windows_user(session_context)
        if not victim or victim["username"] == u["username"]:
            victim = _pick_windows_user(session_context)
        if not victim or victim["username"] == u["username"]:
            return None
        victim_name = victim["username"]
        victim_dn = f"CN={victim_name},CN=Users,{base_dn}"
    victim_sid = _stable_user_sid(victim_name)

    events = []
    t = time.time()

    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\net.exe",
         f'net group "{group_name}" {victim_name} /add /domain'),
        ("C:\\Windows\\System32\\net.exe",
         f'net localgroup "{group_name}" {victim_name} /add /domain'),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -c "Add-ADGroupMember -Identity \'{group_name}\' '
         f'-Members \'{victim_name}\'"'),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    eid = group_info["event_id"]
    if eid == 4728:
        events.append(json.dumps(_build_4728(u, config,
                                             member_name=victim_dn,
                                             member_sid=victim_sid,
                                             target_group=group_name,
                                             target_sid=group_info["sid"],
                                             logon_id=logon_id, ts=t)))
    elif eid == 4732:
        events.append(json.dumps(_build_4732(u, config,
                                             member_name=victim_dn,
                                             member_sid=victim_sid,
                                             target_group=group_name,
                                             target_sid=group_info["sid"],
                                             logon_id=logon_id, ts=t)))
    elif eid == 4756:
        events.append(json.dumps(_build_4756(u, config,
                                             member_name=victim_dn,
                                             member_sid=victim_sid,
                                             target_group=group_name,
                                             target_sid=group_info["sid"],
                                             logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.0)

    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


def _threat_adminsdholder_acl_modification(config, session_context):
    """AdminSDHolder ACL modification: attacker writes a new ACE to the
    AdminSDHolder object's nTSecurityDescriptor, granting themselves (or a
    controlled account) full-control rights that SDProp will propagate to
    every protected group (Domain Admins, Enterprise Admins, etc.) within
    60 minutes.

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4688 PowerShell / dsacls.exe process creation (ACL manipulation)
      3. 4662 Directory Service Access on AdminSDHolder with WRITE_DACL
      4. 5136 nTSecurityDescriptor modified on AdminSDHolder (the detection trigger)
      5. 4689 process exit

    Detection keys:
      - 5136 with ObjectDN containing CN=AdminSDHolder,CN=System and
        AttributeLDAPDisplayName=nTSecurityDescriptor from a non-service account
      - 4662 with ObjectName=CN=AdminSDHolder,CN=System and
        AccessMask=0x40000 (WRITE_DACL) from a regular user
      - SubjectUserName is NOT a DC$ machine account or SYSTEM
      - XSIAM rule: "Suspicious modification of the AdminSDHolder's ACL"
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)
    adminsdholder_dn = f"CN=AdminSDHolder,CN=System,{base_dn}"
    adminsdholder_guid = "{" + str(uuid.uuid4()) + "}"

    events = []
    t = time.time()

    logon_id = _new_logon_id()
    op_corr_id = _new_logon_guid()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    attacker_sid = _stable_user_sid(u["username"])

    # Default AdminSDHolder SDDL (before attacker modifies it)
    base_sddl = (
        "O:DAG:DAD:PAI"
        "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
        "(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;BA)"
        "(A;;RPLCLORC;;;AU)"
        "(A;;LCRPLORC;;;ED)"
    )
    # New SDDL with attacker's full-control ACE appended
    new_sddl = base_sddl + f"(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;{attacker_sid})"

    tool = random.choice([
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -ep bypass -c "'
         f"$acl = Get-Acl 'AD:\\{adminsdholder_dn}'; "
         f"$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("
         f"[System.Security.Principal.SecurityIdentifier]'{attacker_sid}',"
         f"'GenericAll','Allow'); "
         f"$acl.AddAccessRule($ace); "
         f"Set-Acl 'AD:\\{adminsdholder_dn}' $acl\""),
        ("C:\\Windows\\System32\\dsacls.exe",
         f'dsacls.exe "{adminsdholder_dn}" /G {domain}\\{u["username"]}:GA'),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -ep bypass -c "Import-Module ActiveDirectory; '
         f"$path = 'AD:\\{adminsdholder_dn}'; "
         f"$acl = Get-Acl $path; "
         f"$user = '{domain}\\{u['username']}'; "
         f"$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("
         f"(New-Object System.Security.Principal.NTAccount($user)),"
         f"'GenericAll','Allow'); "
         f'$acl.AddAccessRule($ace); Set-Acl $path $acl"'),
    ])

    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    # 4662 — WRITE_DACL on AdminSDHolder container
    # Real events use %{GUID} for ObjectName, not the DN
    write_dacl_props = "%%1539\n    {bf967a8b-0de6-11d0-a285-00aa003049e2}\n"
    events.append(json.dumps(_build_4662(
        u, config,
        object_type="%{bf967a8b-0de6-11d0-a285-00aa003049e2}",
        object_name=f"%{adminsdholder_guid}",
        access_mask="0x40000",
        properties=write_dacl_props,
        operation_type="Object Access",
        logon_id=logon_id, ts=t)))
    t += 0.05

    # 5136 pair: %%14675 (old SDDL deleted) then %%14674 (new SDDL added)
    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=adminsdholder_dn,
        object_class="container",
        object_guid=adminsdholder_guid,
        attribute_name="nTSecurityDescriptor",
        attribute_value=base_sddl,
        attribute_syntax_oid="2.5.5.15",
        operation_type="%%14675",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += 0.001
    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=adminsdholder_dn,
        object_class="container",
        object_guid=adminsdholder_guid,
        attribute_name="nTSecurityDescriptor",
        attribute_value=new_sddl,
        attribute_syntax_oid="2.5.5.15",
        operation_type="%%14674",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.0)

    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


_IRREGULAR_SERVICE_SPNS = [
    "HOST/{dc_host}",
    "RPCSS/{dc_host}",
    "LDAP/{dc_host}",
    "LDAP/{dc_host}/{dns_domain}",
    "DNS/{dc_host}",
    "GC/{dc_host}/{dns_domain}",
    "cifs/{dc_host}",
    "E3514235-4B06-11D1-AB04-00C04FC2DCD2/{dc_host}/{dns_domain}",
    "HOST/fs01.{dns_domain}",
    "HOST/fs02.{dns_domain}",
    "WSMAN/mgmt01.{dns_domain}",
    "WSMAN/mgmt02.{dns_domain}",
    "cifs/backup01.{dns_domain}",
    "cifs/backup02.{dns_domain}",
    "HTTP/adfs.{dns_domain}",
    "HTTP/sccm01.{dns_domain}",
    "MSSQLSvc/sql01.{dns_domain}:1433",
    "MSSQLSvc/sql02.{dns_domain}:1433",
    "exchangeRFR/exchange01.{dns_domain}",
    "exchangeAB/exchange01.{dns_domain}",
    "SAPService/sap01.{dns_domain}",
    "TERMSRV/rdp-gw01.{dns_domain}",
    "FTP/ftp01.{dns_domain}",
    "HTTP/printing.{dns_domain}",
    "SMTP/mail01.{dns_domain}",
    "HOST/citrix01.{dns_domain}",
    "RestrictedKrbHost/{dc_host}",
]


def _threat_irregular_service_tgs(config, session_context):
    """A user sends TGS requests to many services they don't normally access,
    including non-standard SPNs like HOST/, RPCSS/, DNS/, GC/, and other
    admin-tier services.

    Unlike our Kerberoasting generator (which targets RC4 encryption),
    this attack uses NORMAL encryption — the anomaly is the breadth and
    novelty of services being probed, not the cipher.

    XSIAM fires three variants based on volume:
      - "A user sent a TGT request to irregular service" (single unusual target)
      - "A user sent multiple TGT requests to irregular services" (3-10 targets)
      - "A user sent an excessive number of TGT requests to irregular services" (10+)

    Sequence:
      1. Attacker authenticates normally → 4768 TGT
      2. 4624 interactive logon + 4672 elevated privileges
      3. 4688 PowerShell / LDAP recon tool process creation
      4. Burst of 4769 TGS requests to many unusual services — all from
         the same TargetUserName, all with normal AES encryption
      5. 4689 process exit + eventual 4634 logoff

    Detection keys:
      - Single TargetUserName across many 4769 events in a short window
      - ServiceName values are NOT krbtgt or kadmin (those are normal)
      - Services are outside the user's baseline access pattern
      - High distinct-service count in a short time window
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dc_host = _get_dc_hostname(config)
    dns_domain = _get_dns_domain(config)

    resolved_spns = [
        spn.format(dc_host=dc_host, dns_domain=dns_domain)
        for spn in _IRREGULAR_SERVICE_SPNS
    ]

    num_targets = random.randint(15, 25)
    targets = random.sample(resolved_spns, k=min(len(resolved_spns), num_targets))

    events = []
    t = time.time() - len(targets) * 2

    logon_id = _new_logon_id()
    logon_guid = _new_logon_guid()

    events.append(json.dumps(_build_4768(u, config, ts=t)))
    t += 1.0
    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.2
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         logon_guid=logon_guid,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -ep bypass -c \"[adsisearcher]'(&(servicePrincipalName=*))'"
         ".FindAll() | ForEach { $_.Properties.serviceprincipalname }\""),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -ep bypass -c \"Get-ADObject -Filter {servicePrincipalName -like '*'}"
         " -Properties servicePrincipalName\""),
        ("C:\\Users\\Public\\Rubeus.exe",
         "C:\\Users\\Public\\Rubeus.exe kerberoast /stats"),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    for spn in targets:
        ev = _build_4769(u, config, service_spn=spn,
                         encryption=random.choice(_TICKET_ENC_NORMAL), ts=t)
        ev["event_data"]["LogonGuid"] = logon_guid
        events.append(json.dumps(ev))
        t += random.uniform(0.3, 1.0)

    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(60, 300)
    session = _pop_open_session(u["hostname"], u["username"])
    if session:
        events.append(json.dumps(_build_4634(session, config, ts=t)))

    return events


# ---------------------------------------------------------------------------
# Well-known SID for SMS Admins local group (static in SCCM deployments)
# ---------------------------------------------------------------------------
_SID_SMS_ADMINS = "S-1-5-21-3457937927-2839227994-823803824-1200"


def _threat_sms_admins_addition(config, session_context):
    """User added to the SMS Admins local group — targets SCCM infrastructure.

    SMS Admins is the local group on SCCM site servers that grants full
    administrative control over Microsoft Configuration Manager.  Adding an
    account to this group allows lateral movement via SCCM client-push
    installation, application deployment, or script execution across all
    managed endpoints.

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4688 net.exe / PowerShell process creation (group manipulation)
      3. 4732 member added to SMS Admins (security-enabled local group)
      4. 4689 process exit

    XSIAM also detects the add-then-remove variant (attacker adds themselves,
    performs actions, then removes to cover tracks).

    Detection keys:
      - 4732 with TargetUserName="SMS Admins" from a non-service account
      - SubjectUserName is NOT the SCCM service account or SYSTEM
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    victim = _pick_windows_user(session_context)
    if not victim or victim["username"] == u["username"]:
        victim = _pick_windows_user(session_context)
    if not victim or victim["username"] == u["username"]:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)

    victim_name = victim["username"]
    victim_dn = f"CN={victim_name},CN=Users,{base_dn}"
    victim_sid = _stable_user_sid(victim_name)

    sccm_server = f"SCCM01.{dns_domain}"

    events = []
    t = time.time()

    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\net.exe",
         f'net localgroup "SMS Admins" {domain}\\{victim_name} /add'),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -c "Add-LocalGroupMember -Group \'SMS Admins\' '
         f'-Member \'{domain}\\{victim_name}\'"'),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -c "Invoke-Command -ComputerName {sccm_server} '
         f'-ScriptBlock {{ net localgroup \'SMS Admins\' {domain}\\{victim_name} /add }}"'),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    events.append(json.dumps(_build_4732(u, config,
                                         member_name=victim_dn,
                                         member_sid=victim_sid,
                                         target_group="SMS Admins",
                                         target_sid=_SID_SMS_ADMINS,
                                         target_domain=domain,
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.0)

    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


# bf967a86 = "container" schema class GUID
_SCCM_CONTAINER_OBJECT_TYPE = "{bf967a86-0de6-11d0-a285-00aa003049e2}"

_SCCM_READ_PROPERTY = "0x10"
_SCCM_LIST_CHILDREN = "0x4"


def _threat_sccm_container_recon(config, session_context):
    """Suspicious access of the System Management container — SCCM site
    server reconnaissance.

    The System Management container in AD (CN=System Management,CN=System)
    stores SCCM site server registration objects.  Enumerating this container
    reveals all SCCM site servers in the domain, their roles, and boundaries.
    Normal users have no reason to read this container — access indicates
    an attacker mapping the SCCM infrastructure for lateral movement.

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4688 PowerShell / ldapsearch / ADFind process creation (LDAP recon)
      3. 4662 Directory Service Access on CN=System Management,CN=System
         with READ_PROPERTY access from a non-service account
      4. 4662 second read on child objects (site server objects)
      5. 4689 process exit

    Detection keys:
      - 4662 with ObjectName containing CN=System Management,CN=System
        from a regular user account (not SCCM service account or SYSTEM)
      - AccessMask indicating read/list operations (0x10, 0x4)
      - Non-standard process performing LDAP queries
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)
    sysm_container_dn = f"CN=System Management,CN=System,{base_dn}"

    sccm_site_objects = [
        f"CN=SMS-Site-XS1,CN=System Management,CN=System,{base_dn}",
        f"CN=SMS-MP-SCCM01.{dns_domain},CN=System Management,CN=System,{base_dn}",
        f"CN=SMS-SLP-SCCM01.{dns_domain},CN=System Management,CN=System,{base_dn}",
    ]

    events = []
    t = time.time()

    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -ep bypass -c "Get-ADObject -SearchBase '
         f"'CN=System Management,CN=System,{base_dn}' "
         f'-Filter * -Properties *"'),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -ep bypass -c "[adsi]\'LDAP://{sysm_container_dn}\' | '
         f'ForEach {{ $_.psbase.Children }}"'),
        ("C:\\Users\\Public\\ADFind.exe",
         f'adfind.exe -b "CN=System Management,CN=System,{base_dn}" -f "(objectClass=*)"'),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    read_props = (
        "%%1537\n    "
        "{bf967a86-0de6-11d0-a285-00aa003049e2}\n"
    )
    list_props = (
        "%%1541\n    "
        "{bf967a86-0de6-11d0-a285-00aa003049e2}\n"
    )
    events.append(json.dumps(_build_4662(
        u, config,
        object_type=_SCCM_CONTAINER_OBJECT_TYPE,
        object_name=sysm_container_dn,
        access_mask=_SCCM_READ_PROPERTY,
        properties=read_props,
        operation_type="Object Access",
        logon_id=logon_id, ts=t)))
    t += random.uniform(0.2, 0.5)

    for site_obj in sccm_site_objects:
        events.append(json.dumps(_build_4662(
            u, config,
            object_type=_SCCM_CONTAINER_OBJECT_TYPE,
            object_name=site_obj,
            access_mask=_SCCM_LIST_CHILDREN,
            properties=list_props,
            operation_type="Object Access",
            logon_id=logon_id, ts=t)))
        t += random.uniform(0.1, 0.3)

    t += random.uniform(0.5, 1.0)
    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


def _threat_dnshostname_spoofing(config, session_context):
    """Suspicious dNSHostName attribute change to a DC name — CVE-2022-26923
    (Certifried) and related privilege escalation attacks.

    The attacker modifies the dNSHostName attribute of a machine account they
    control to match a domain controller's name.  When AD CS processes a
    certificate request from this machine, it issues a cert with the DC's
    identity, allowing the attacker to authenticate as the DC and perform
    DCSync.

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4741 or pre-existing machine account (attacker may create a new one)
      3. 4688 PowerShell / Certify process creation
      4. 5136 dNSHostName modified to DC hostname (detection trigger)
      5. 5136 servicePrincipalName updated to match DC SPNs
      6. 4769 TGS request using the spoofed identity
      7. 4689 process exit

    Detection keys:
      - 5136 with AttributeLDAPDisplayName=dNSHostName and AttributeValue
        matching a DC hostname from a non-DC machine account
      - Followed by certificate enrollment or TGS requests for DC services
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_host = _get_dc_hostname(config)
    dc_short = _get_dc_short(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)

    machine_suffix = random.randint(100, 9999)
    machine_name = random.choice(["YOURPC", "WKSTMP", "DESKTOP", "CLIENT"]) + str(machine_suffix)
    machine_sam = f"{machine_name}$"
    machine_dn = f"CN={machine_name},CN=Computers,{base_dn}"
    machine_guid = "{" + str(uuid.uuid4()) + "}"
    machine_sid = _stable_user_sid(machine_name)

    events = []
    t = time.time()

    logon_id = _new_logon_id()
    op_corr_id = _new_logon_guid()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    create_machine = random.random() < 0.5
    if create_machine:
        events.append(json.dumps(_build_4741(u, config,
                                             target_computer_name=machine_sam,
                                             target_sid=machine_sid,
                                             sam_account_name=machine_sam,
                                             dns_host_name=f"{machine_name.lower()}.{dns_domain}",
                                             spns=f"HOST/{machine_name.lower()}.{dns_domain} "
                                                  f"RestrictedKrbHost/{machine_name.lower()}.{dns_domain}",
                                             new_uac_value="0x1000",
                                             logon_id=logon_id, ts=t)))
        t += random.uniform(0.5, 1.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -ep bypass -c "Set-ADComputer {machine_name} '
         f"-DnsHostName '{dc_host}'\""),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -ep bypass -c "Get-ADComputer {machine_name} | '
         f"Set-ADComputer -DnsHostName '{dc_host}'\""),
        ("C:\\Users\\Public\\Certipy.exe",
         f"Certipy.exe account update -u {u['username']}@{dns_domain} "
         f"-p <password> -user {machine_name}$ -dns {dc_host}"),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    old_dns = f"{machine_name.lower()}.{dns_domain}"
    old_spn_host = f"HOST/{old_dns}"
    old_spn_rkrb = f"RestrictedKrbHost/{old_dns}"
    new_spn_host = f"HOST/{dc_host}"
    new_spn_rkrb = f"RestrictedKrbHost/{dc_host}"

    # 5136 pair: dNSHostName Value Deleted (old) then Value Added (new)
    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=machine_dn,
        object_class="computer",
        object_guid=machine_guid,
        attribute_name="dNSHostName",
        attribute_value=old_dns,
        attribute_syntax_oid="2.5.5.12",
        operation_type="%%14675",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += 0.001
    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=machine_dn,
        object_class="computer",
        object_guid=machine_guid,
        attribute_name="dNSHostName",
        attribute_value=dc_host,
        attribute_syntax_oid="2.5.5.12",
        operation_type="%%14674",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += 0.001

    # 5136 pairs: servicePrincipalName delete old, add new (per SPN)
    for old_spn, new_spn in [(old_spn_host, new_spn_host),
                              (old_spn_rkrb, new_spn_rkrb)]:
        events.append(json.dumps(_build_5136(
            u, config,
            object_dn=machine_dn,
            object_class="computer",
            object_guid=machine_guid,
            attribute_name="servicePrincipalName",
            attribute_value=old_spn,
            attribute_syntax_oid="2.5.5.12",
            operation_type="%%14675",
            op_correlation_id=op_corr_id,
            logon_id=logon_id, ts=t)))
        t += 0.001
        events.append(json.dumps(_build_5136(
            u, config,
            object_dn=machine_dn,
            object_class="computer",
            object_guid=machine_guid,
            attribute_name="servicePrincipalName",
            attribute_value=new_spn,
            attribute_syntax_oid="2.5.5.12",
            operation_type="%%14674",
            op_correlation_id=op_corr_id,
            logon_id=logon_id, ts=t)))
        t += 0.001
    t += 0.01

    # 4742: computer account changed — final-state values
    all_new_spns = f"{new_spn_host}\r\n\t{new_spn_rkrb}\r\n\tHOST/{dc_short}"
    events.append(json.dumps(_build_4742(
        u, config,
        target_computer_name=machine_sam,
        target_sid=machine_sid,
        sam_account_name=machine_sam,
        dns_host_name=dc_host,
        spns=all_new_spns,
        logon_id=logon_id, ts=t)))
    t += random.uniform(1.0, 3.0)

    fake_machine_user = {**u, "username": machine_sam, "hostname": dc_host}
    events.append(json.dumps(_build_4769(fake_machine_user, config,
                                         service_spn=f"ldap/{dc_host}",
                                         encryption="0x12",
                                         ip_override=u.get("ip"),
                                         ts=t)))
    t += random.uniform(0.5, 1.0)

    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


def _threat_samaccountname_spoofing(config, session_context):
    """TGT request with a spoofed sAMAccountName — CVE-2021-42278/42287 (noPac).

    The attacker creates a machine account, renames its sAMAccountName to match
    a domain controller (without the trailing $), requests a TGT under that
    spoofed name, renames back to avoid collision, then exchanges the TGT for
    a TGS — the KDC resolves the TGT's principal to the real DC account and
    issues a DC-level service ticket.

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4741 machine account created (attacker-controlled)
      3. 4688 PowerShell / noPac tool process creation
      4. 5136 sAMAccountName changed to DC name (e.g., "DC01") — KEY TRIGGER
      5. 4768 TGT request under the spoofed sAMAccountName
      6. 5136 sAMAccountName changed back to original
      7. 4769 TGS request using the spoofed TGT → DC service ticket
      8. 4689 process exit

    Detection keys:
      - 5136 with AttributeLDAPDisplayName=sAMAccountName and value matching
        a domain controller name (without trailing $)
      - 5136 servicePrincipalName cleared (triggers "SPNs cleared from a machine account")
      - 4768 for a principal that matches a DC name
      - sAMAccountName rename events (5136) bracketing a 4768
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_host = _get_dc_hostname(config)
    dc_short = _get_dc_short(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)

    machine_suffix = random.randint(100, 9999)
    machine_name = random.choice(["YOURPC", "WKSTMP", "DESKTOP", "CLIENT"]) + str(machine_suffix)
    machine_sam = f"{machine_name}$"
    machine_dn = f"CN={machine_name},CN=Computers,{base_dn}"
    machine_guid = "{" + str(uuid.uuid4()) + "}"
    machine_sid = _stable_user_sid(machine_name)

    events = []
    t = time.time()

    logon_id = _new_logon_id()
    op_corr_id = _new_logon_guid()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    original_spns = [
        f"HOST/{machine_name.lower()}.{dns_domain}",
        f"RestrictedKrbHost/{machine_name.lower()}.{dns_domain}",
    ]
    events.append(json.dumps(_build_4741(u, config,
                                         target_computer_name=machine_sam,
                                         target_sid=machine_sid,
                                         sam_account_name=machine_sam,
                                         dns_host_name=f"{machine_name.lower()}.{dns_domain}",
                                         spns=" ".join(original_spns),
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -ep bypass -c "Set-ADComputer {machine_name} '
         f"-ServicePrincipalName @{{}} ; Set-ADComputer {machine_name} "
         f"-SamAccountName '{dc_short}'\""),
        ("C:\\Users\\Public\\noPac.exe",
         f"noPac.exe -domain {dns_domain} -user {u['username']} -pass <password> "
         f"-dc-ip {dc_host} -impersonate Administrator"),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    for spn in original_spns:
        events.append(json.dumps(_build_5136(
            u, config,
            object_dn=machine_dn,
            object_class="computer",
            object_guid=machine_guid,
            attribute_name="servicePrincipalName",
            attribute_value=spn,
            attribute_syntax_oid="2.5.5.12",
            operation_type="%%14675",
            op_correlation_id=op_corr_id,
            logon_id=logon_id, ts=t)))
        t += 0.001

    t += random.uniform(0.3, 0.8)

    events.append(json.dumps(_build_4742(
        u, config,
        target_computer_name=machine_sam,
        target_sid=machine_sid,
        sam_account_name=machine_sam,
        dns_host_name=f"{machine_name.lower()}.{dns_domain}",
        spns="-",
        logon_id=logon_id, ts=t)))
    t += random.uniform(0.2, 0.5)

    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=machine_dn,
        object_class="computer",
        object_guid=machine_guid,
        attribute_name="sAMAccountName",
        attribute_value=machine_sam,
        attribute_syntax_oid="2.5.5.12",
        operation_type="%%14675",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += 0.001
    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=machine_dn,
        object_class="computer",
        object_guid=machine_guid,
        attribute_name="sAMAccountName",
        attribute_value=dc_short,
        attribute_syntax_oid="2.5.5.12",
        operation_type="%%14674",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += random.uniform(0.3, 0.8)

    spoofed_user = {**u, "username": dc_short, "hostname": dc_host}
    events.append(json.dumps(_build_4768(spoofed_user, config,
                                         ip_override=u.get("ip"), ts=t)))
    t += random.uniform(0.2, 0.5)

    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=machine_dn,
        object_class="computer",
        object_guid=machine_guid,
        attribute_name="sAMAccountName",
        attribute_value=dc_short,
        attribute_syntax_oid="2.5.5.12",
        operation_type="%%14675",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += 0.001
    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=machine_dn,
        object_class="computer",
        object_guid=machine_guid,
        attribute_name="sAMAccountName",
        attribute_value=machine_sam,
        attribute_syntax_oid="2.5.5.12",
        operation_type="%%14674",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.0)

    events.append(json.dumps(_build_4769(spoofed_user, config,
                                         service_spn=f"cifs/{dc_host}",
                                         encryption="0x12",
                                         ip_override=u.get("ip"),
                                         ts=t)))
    t += random.uniform(0.5, 1.0)

    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


# Delegation SPNs organized by severity for the three XSIAM variants:
#   - Generic service delegation (base severity)
#   - Delegation to a DC service (higher severity)
#   - Delegation to KRBTGT (highest severity — enables golden ticket forgery)
_DELEGATION_TARGETS_GENERIC = [
    "cifs/fs01.{dns_domain}",
    "HTTP/intranet.{dns_domain}",
    "MSSQLSvc/sql01.{dns_domain}:1433",
    "WSMAN/mgmt01.{dns_domain}",
    "HTTP/sharepoint.{dns_domain}",
]

_DELEGATION_TARGETS_DC = [
    "ldap/{dc_host}",
    "cifs/{dc_host}",
    "HOST/{dc_host}",
    "GC/{dc_host}/{dns_domain}",
]

_DELEGATION_TARGETS_KRBTGT = [
    "krbtgt/{dns_domain_upper}",
    "krbtgt",
]


def _threat_delegation_change(config, session_context):
    """User account delegation change — attacker modifies msDS-AllowedToDelegateTo
    to enable constrained delegation to a target service.

    Three severity variants (weighted randomly):
      - Generic service delegation: allows impersonation to file/web/SQL services
      - DC service delegation: allows impersonation to DC (ldap/cifs/HOST)
      - KRBTGT delegation: allows forging any ticket (golden ticket equivalent)

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4688 PowerShell / AD module process creation
      3. 5136 msDS-AllowedToDelegateTo delete/add pair (old="-", new=SPN)
      4. 5136 userAccountControl delete/add pair (old=512, new=16777728)
      5. 4738 user account changed (UAC + delegation)
      6. 4769 TGS request using the delegated service ticket
      7. 4689 process exit

    Detection keys:
      - 5136 with AttributeLDAPDisplayName=msDS-AllowedToDelegateTo
      - Higher severity when delegation target is a DC service or KRBTGT
      - userAccountControl change to include TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000)
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_host = _get_dc_hostname(config)
    dns_domain_upper = dns_domain.upper()
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)

    variant = random.choices(
        ["dc", "krbtgt"],
        weights=[55, 45], k=1)[0]

    if variant == "krbtgt":
        target_spn_template = random.choice(_DELEGATION_TARGETS_KRBTGT)
        target_spn = target_spn_template.format(
            dns_domain_upper=dns_domain_upper, dns_domain=dns_domain)
    else:
        target_spn_template = random.choice(_DELEGATION_TARGETS_DC)
        target_spn = target_spn_template.format(
            dc_host=dc_host, dns_domain=dns_domain)

    victim_acct = random.choice(_SERVICE_ACCOUNT_SAMS)
    victim_dn = f"CN={victim_acct},CN=Users,{base_dn}"
    victim_guid = "{" + str(uuid.uuid4()) + "}"

    events = []
    t = time.time()

    logon_id = _new_logon_id()
    op_corr_id = _new_logon_guid()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -ep bypass -c "Set-ADUser {victim_acct} '
         f"-Add @{{'msDS-AllowedToDelegateTo'='{target_spn}'}} "
         f'-TrustedToAuthForDelegation $true"'),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -ep bypass -c "Set-ADAccountControl -Identity {victim_acct} '
         f'-TrustedToAuthForDelegation $true; '
         f"Set-ADUser {victim_acct} -Add @{{'msDS-AllowedToDelegateTo'='{target_spn}'}}\""),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    # 5136: msDS-AllowedToDelegateTo — add only (no prior value to delete)
    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=victim_dn,
        object_class="user",
        object_guid=victim_guid,
        attribute_name="msDS-AllowedToDelegateTo",
        attribute_value=target_spn,
        attribute_syntax_oid="2.5.5.12",
        operation_type="%%14674",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += 0.02

    # 5136: userAccountControl delete/add pair (512 → 16777728)
    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=victim_dn,
        object_class="user",
        object_guid=victim_guid,
        attribute_name="userAccountControl",
        attribute_value="512",
        attribute_syntax_oid="2.5.5.9",
        operation_type="%%14675",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += 0.001
    events.append(json.dumps(_build_5136(
        u, config,
        object_dn=victim_dn,
        object_class="user",
        object_guid=victim_guid,
        attribute_name="userAccountControl",
        attribute_value="16777728",
        attribute_syntax_oid="2.5.5.9",
        operation_type="%%14674",
        op_correlation_id=op_corr_id,
        logon_id=logon_id, ts=t)))
    t += 0.05

    victim_sid = f"{_SYNTH_DOMAIN_SID}-{random.randint(1100, 9999)}"
    events.append(json.dumps(_build_4738(
        u, config,
        target_username=victim_acct,
        target_sid=victim_sid,
        sam_account_name=victim_acct,
        old_uac_value="0x200",
        new_uac_value="0x1000200",
        uac_control="%%2098",
        allowed_to_delegate=target_spn,
        logon_id=logon_id, ts=t)))
    t += random.uniform(1.0, 3.0)

    fake_svc_user = {**u, "username": victim_acct}
    events.append(json.dumps(_build_4769(fake_svc_user, config,
                                         service_spn=target_spn,
                                         encryption="0x12",
                                         ip_override=u.get("ip"),
                                         ts=t)))
    t += random.uniform(0.5, 1.0)

    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


def _threat_multiple_service_tickets(config, session_context):
    """A user requested multiple service tickets — volume-based Kerberoasting.

    This variant requests TGS tickets with RC4 encryption to many distinct
    service accounts in a short window.  XSIAM detects this on breadth: a single
    user requesting 10+ distinct service tickets within minutes.

    Also covers "Abnormal issuance of service tickets to a user" which fires on
    the same volume pattern regardless of encryption type.

    Sequence:
      1. Attacker authenticates → 4768 TGT (normal AES)
      2. DC-side 4624 + endpoint 4624 + 4672
      3. 4688 PowerShell / LDAP query tool
      4. Burst of 15-30 4769 TGS requests with AES256 encryption
         to many distinct SPNs — KEY TRIGGER (volume + breadth)
      5. 4689 process exit
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    num_tickets = random.randint(15, 30)
    targets = random.sample(_SERVICE_ACCOUNT_SPNS,
                            k=min(len(_SERVICE_ACCOUNT_SPNS), num_tickets))
    events = []
    t = time.time() - len(targets) * 2

    logon_id = _new_logon_id()
    logon_guid = _new_logon_guid()

    events.append(json.dumps(_build_4768(u, config, ts=t)))
    t += 1.0
    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.2
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         logon_guid=logon_guid,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -ep bypass -c \"Get-ADUser -Filter {ServicePrincipalName -ne '$null'} "
         "-Properties ServicePrincipalName | ForEach { Add-Type -AssemblyName System.IdentityModel; "
         "New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken "
         "-ArgumentList $_.ServicePrincipalName[0] }\""),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -ep bypass -c \"Import-Module .\\GetUserSPNs.ps1; "
         "Invoke-Kerberoast -OutputFormat Hashcat\""),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    for spn in targets:
        ev = _build_4769(u, config, service_spn=spn, encryption="0x17", ts=t)
        ev["event_data"]["LogonGuid"] = logon_guid
        events.append(json.dumps(ev))
        t += random.uniform(0.3, 0.8)

    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


def _threat_priv_group_add_remove(config, session_context):
    """User added to a privileged group and removed shortly after.

    Three XSIAM variants (all triggered by the same event pattern):
      - "User added to a privileged group and removed" (Low)
      - "Rare privileged group addition and removal" (Medium)
      - "User added to a group and removed the added user" (Low)

    The detection fires when a user is added to a privileged group (4728/4732/4756)
    and then removed (4729/4733/4757) within a short window — typically minutes.

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4688 PowerShell / net.exe process creation
      3. 4728/4732/4756 member added to privileged group — KEY TRIGGER
      4. Short dwell time (30s-5min) — attacker uses elevated access
      5. 4729/4733/4757 member removed from privileged group — KEY TRIGGER
      6. 4689 process exit
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    victim = _pick_windows_user(session_context)
    if not victim or victim["username"] == u["username"]:
        victim = _pick_windows_user(session_context)
    if not victim or victim["username"] == u["username"]:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)

    group_name = random.choice(list(_PRIVILEGED_GROUPS.keys()))
    grp = _PRIVILEGED_GROUPS[group_name]
    add_eid = grp["event_id"]
    remove_eid = grp["remove_id"]

    is_machine = random.random() < 0.3
    if is_machine:
        member_name = f"CN={victim['hostname']},CN=Computers,{base_dn}"
        member_sid = _stable_user_sid(victim["hostname"])
    else:
        member_name = f"CN={victim['username']},CN=Users,{base_dn}"
        member_sid = _stable_user_sid(victim["username"])

    events = []
    t = time.time()

    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    if group_name == "Administrators":
        cmd = f'net localgroup Administrators {victim["username"]} /add'
    else:
        cmd = (f'powershell.exe -ep bypass -c "Add-ADGroupMember '
               f"-Identity '{group_name}' -Members '{victim['username']}'\"")
    tool = ("C:\\Windows\\System32\\net.exe" if "net " in cmd
            else "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    events.append(json.dumps(_build_4688(u, config, process_name=tool,
                                         command_line=cmd,
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.0)

    add_builder = _ADD_BUILDERS[add_eid]
    events.append(json.dumps(add_builder(
        u, config,
        member_name=member_name,
        member_sid=member_sid,
        target_group=group_name,
        target_sid=grp["sid"],
        logon_id=logon_id, ts=t)))

    # ── Attacker dwell time: use the elevated access before removing tracks ──
    dwell = random.uniform(900, 2700)
    t += random.uniform(30.0, 120.0)

    # Attacker logs into other machines with the elevated account
    victim_u = {**victim, "ip": u.get("ip")}
    _lateral_pool = [p for p in session_context.values()
                     if isinstance(p, dict) and p.get("hostname")
                     and p["username"] != u["username"]]
    lateral_targets = random.sample(
        _lateral_pool,
        k=min(random.randint(1, 3), len(_lateral_pool))) if _lateral_pool else []
    for tgt in lateral_targets:
        tgt_host = tgt.get("hostname", "WKS-TEMP")
        events.append(json.dumps(_build_4624(victim_u, config, logon_type=3,
                                             auth_pkg=_KRB_PACKAGE,
                                             ip_override=u.get("ip"),
                                             ts=t)))
        t += random.uniform(5.0, 15.0)
        events.append(json.dumps(_build_4672(victim_u, config,
                                             logon_id=_new_logon_id(),
                                             is_admin=True, ts=t)))
        t += random.uniform(60.0, 180.0)

    # Attacker runs recon or data access under the elevated session
    recon_cmds = [
        ("C:\\Windows\\System32\\net.exe",
         "net group \"Domain Admins\" /domain"),
        ("C:\\Windows\\System32\\net.exe",
         "net group \"Enterprise Admins\" /domain"),
        ("C:\\Windows\\System32\\nltest.exe",
         "nltest /dclist:examplecorp.local"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -c \"Get-ADUser -Filter * -Properties AdminCount "
         "| Where-Object {$_.AdminCount -eq 1}\""),
        ("C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c dir \\\\fs01\\finance$ /s"),
    ]
    for recon_tool, recon_cmd in random.sample(recon_cmds, k=random.randint(2, 3)):
        events.append(json.dumps(_build_4688(u, config, process_name=recon_tool,
                                             command_line=recon_cmd,
                                             logon_id=logon_id, ts=t)))
        t += random.uniform(10.0, 30.0)
        events.append(json.dumps(_build_4689(u, config, process_name=recon_tool,
                                             logon_id=logon_id, ts=t)))
        t += random.uniform(60.0, 180.0)

    # TGS request using the elevated privileges
    events.append(json.dumps(_build_4769(victim_u, config,
                                         service_spn=f"cifs/{_get_dc_hostname(config)}",
                                         encryption="0x12",
                                         ip_override=u.get("ip"),
                                         ts=t)))
    t += random.uniform(2.0, 5.0)

    # Pad remaining dwell time
    remaining = dwell - (t - (time.time() + 60))
    if remaining > 0:
        t += remaining

    # ── Remove from group to cover tracks ──
    remove_builder = _REMOVE_BUILDERS[remove_eid]
    events.append(json.dumps(remove_builder(
        u, config,
        member_name=member_name,
        member_sid=member_sid,
        target_group=group_name,
        target_sid=grp["sid"],
        logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.0)

    events.append(json.dumps(_build_4689(u, config, process_name=tool,
                                         logon_id=logon_id, ts=t)))
    return events


# Privileged accounts and templates used for ADCS attack simulation
_PRIV_CERT_TARGETS = ["Administrator", "krbtgt", "DC01$", "svc_sql_prod"]

def _threat_priv_cert_request(config, session_context):
    """Privileged certificate request via certificate template (ADCS ESC attacks).

    Three XSIAM detection variants:
      - "Privileged certificate request via certificate template" (Low) —
        4886 + 4887 with a vulnerable template and SAN for a privileged account
      - "Suspicious privileged certificate request via certificate template" (Low) —
        same pattern but using a template that is more obviously suspicious
      - "Suspicious privileged certificate request denied via certificate template" (Medium) —
        4886 + 4888 where the CA denied the request

    Sequence:
      1. Attacker authenticates → DC-side 4624 + endpoint 4624 + 4672
      2. 4688 Certify.exe / certreq.exe / PowerShell process creation
      3. 4886 certificate request received on CA (KEY TRIGGER)
      4. 4887 certificate issued (success variants) OR 4888 request denied
      5. Optional: 4768 PKINIT TGT request using the issued certificate
      6. 4689 process exit

    Detection keys:
      - 4886/4887/4888 with CertificateTemplate pointing to a vulnerable template
      - SAN (san:upn=) in Attributes specifying a different identity than the Requester
      - Certificate used for PKINIT auth shortly after issuance
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)

    variant = random.choices(
        ["suspicious_issued", "denied"],
        weights=[55, 45], k=1)[0]

    priv_target = random.choice(_PRIV_CERT_TARGETS)
    san_upn = f"{priv_target}@{dns_domain}" if "$" not in priv_target else None
    san_dns = f"{priv_target.rstrip('$').lower()}.{dns_domain}" if "$" in priv_target else None
    san_value = san_upn or san_dns

    template = random.choice(_CERT_TEMPLATES_VULNERABLE)

    events = []
    t = time.time()

    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))
    t += random.uniform(2.0, 5.0)

    tool = random.choice([
        ("C:\\Users\\Public\\Certify.exe",
         f"Certify.exe request /ca:{_get_ca_hostname(config)} "
         f"/template:{template} /altname:{priv_target}"),
        ("C:\\Windows\\System32\\certreq.exe",
         f"certreq.exe -submit -attrib \"CertificateTemplate:{template}"
         f"\\nsan:upn={san_value}\" request.req"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f"powershell.exe -ep bypass -c \"Get-Certificate -Template {template} "
         f"-DnsName {priv_target.rstrip('$').lower()}.{dns_domain} "
         f"-CertStoreLocation Cert:\\CurrentUser\\My\""),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 1.5)

    request_id = str(random.randint(100, 99999))

    # 4886 always fires first — CA received the request
    events.append(json.dumps(_build_4886(u, config,
                                         template_name=template,
                                         request_id=request_id,
                                         san_override=san_value,
                                         ts=t)))
    t += random.uniform(0.1, 0.5)

    if variant == "denied":
        events.append(json.dumps(_build_4888(u, config,
                                             template_name=template,
                                             request_id=request_id,
                                             san_override=san_value,
                                             ts=t)))
    else:
        events.append(json.dumps(_build_4887(u, config,
                                             template_name=template,
                                             request_id=request_id,
                                             san_override=san_value,
                                             ts=t)))
        t += random.uniform(2.0, 5.0)

        # Attacker uses the cert for PKINIT TGT request
        priv_user = {**u, "username": priv_target.rstrip("$")}
        events.append(json.dumps(_build_4768(priv_user, config,
                                             ip_override=u.get("ip"),
                                             cert_issuer=f"{_get_domain(config)}-CA01-CA",
                                             cert_serial="6100000005a4b31a47c8b1ae9f000000000005",
                                             cert_thumbprint=_random_ski().replace(" ", ""),
                                             ts=t)))
    t += random.uniform(0.5, 1.0)

    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


# ---------------------------------------------------------------------------
# Tier 1 threat generators: account lifecycle detections
# ---------------------------------------------------------------------------

_SUSPICIOUS_ACCOUNT_PREFIXES = [
    "svc_", "tmp_", "test_", "backup_", "admin_", "sys_", "sql_",
    "dev_", "staging_", "deploy_", "audit_", "helpdesk_",
]

_HIDDEN_USER_SUFFIXES = ["$", ""]


def _threat_suspicious_account_creation(config, session_context):
    """Rapid creation of multiple user accounts from a single session.

    Detection targets:
      - "Multiple suspicious user accounts created" (5+ in short window)
      - "Suspicious domain user account creation" (unusual creator)
      - "Short-lived user account" (created then deleted within minutes)
      - "Local user account creation" / "Local user account creation by machine account"
      - "Suspicious hidden user created" (trailing $ in SAM name)

    Sequence:
      1. Attacker authenticates → DC 4624 + endpoint 4624 + 4672
      2. 4688 net.exe/PowerShell (account creation tool)
      3. Rapid-fire 4720 (user created) × 5–10 accounts
      4. 4722 (account enabled) for each
      5. Optionally 4726 (account deleted) for 1-2 accounts (short-lived)
      6. 4689 process exit
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    dns_domain = _get_dns_domain(config)
    domain = _get_domain(config)
    events = []
    t = time.time()
    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))

    t += random.uniform(3.0, 8.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\net.exe",
         "net user /add /domain"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         'powershell.exe -c "New-ADUser"'),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(0.5, 1.5)

    num_accounts = random.randint(5, 10)
    created_accounts = []

    for i in range(num_accounts):
        prefix = random.choice(_SUSPICIOUS_ACCOUNT_PREFIXES)
        suffix = random.choice(_HIDDEN_USER_SUFFIXES)
        acct_num = random.randint(100, 9999)
        acct_name = f"{prefix}{acct_num}{suffix}"
        acct_rid = random.randint(2001, 9999)
        acct_sid = f"{_SYNTH_DOMAIN_SID}-{acct_rid}"

        events.append(json.dumps(_build_4720(u, config,
                                             target_username=acct_name,
                                             target_sid=acct_sid,
                                             upn=f"{acct_name.rstrip('$')}@{dns_domain}",
                                             logon_id=logon_id, ts=t)))
        t += random.uniform(0.3, 1.0)

        events.append(json.dumps(_build_4722(u, config,
                                             target_username=acct_name,
                                             target_sid=acct_sid,
                                             logon_id=logon_id, ts=t)))
        t += random.uniform(0.2, 0.8)

        created_accounts.append((acct_name, acct_sid))

    short_lived_count = random.randint(1, min(3, num_accounts))
    short_lived = random.sample(created_accounts, short_lived_count)
    t += random.uniform(30.0, 120.0)
    for acct_name, acct_sid in short_lived:
        events.append(json.dumps(_build_4726(u, config,
                                             target_username=acct_name,
                                             target_sid=acct_sid,
                                             logon_id=logon_id, ts=t)))
        t += random.uniform(0.3, 0.8)

    t += random.uniform(1.0, 3.0)
    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


def _threat_mass_account_deletion(config, session_context):
    """Bulk deletion of user accounts.

    Detection targets:
      - "Multiple user accounts deleted" (5+ in short window)

    Sequence:
      1. Attacker authenticates → DC 4624 + endpoint 4624 + 4672
      2. 4688 process creation
      3. Rapid-fire 4726 (account deleted) × 5–8 accounts
      4. 4689 process exit
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    events = []
    t = time.time()
    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))

    t += random.uniform(2.0, 5.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\net.exe",
         "net user /delete /domain"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         'powershell.exe -c "Remove-ADUser"'),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(0.5, 1.5)

    num_deletions = random.randint(5, 8)
    for i in range(num_deletions):
        prefix = random.choice(_SUSPICIOUS_ACCOUNT_PREFIXES)
        acct_num = random.randint(100, 9999)
        acct_name = f"{prefix}{acct_num}"
        acct_rid = random.randint(2001, 9999)
        acct_sid = f"{_SYNTH_DOMAIN_SID}-{acct_rid}"

        events.append(json.dumps(_build_4726(u, config,
                                             target_username=acct_name,
                                             target_sid=acct_sid,
                                             logon_id=logon_id, ts=t)))
        t += random.uniform(0.3, 1.0)

    t += random.uniform(1.0, 3.0)
    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


_SENSITIVE_ACCOUNTS_FOR_RESET = [
    "Administrator", "krbtgt", "DSRM_Admin",
]


def _threat_sensitive_password_reset(config, session_context):
    """Non-admin user resets password of a sensitive account (Administrator, krbtgt).

    Detection targets:
      - "Sensitive account password reset attempt"

    Sequence:
      1. Attacker authenticates → DC 4624 + endpoint 4624
      2. 4688 process creation (net.exe or powershell)
      3. 4724 password reset for sensitive account
      4. 4738 account changed (PasswordLastSet updated)
      5. 4689 process exit
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    target_acct = random.choice(_SENSITIVE_ACCOUNTS_FOR_RESET)
    if target_acct == "krbtgt":
        target_sid = f"{_SYNTH_DOMAIN_SID}-502"
    elif target_acct == "Administrator":
        target_sid = f"{_SYNTH_DOMAIN_SID}-500"
    else:
        target_sid = _stable_user_sid(target_acct)

    events = []
    t = time.time()
    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))

    t += random.uniform(3.0, 8.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\net.exe",
         f'net user {target_acct} * /domain'),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -c "Set-ADAccountPassword -Identity \'{target_acct}\' -Reset"'),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(0.5, 2.0)
    events.append(json.dumps(_build_4724(u, config,
                                         target_username=target_acct,
                                         target_sid=target_sid,
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(0.1, 0.5)
    events.append(json.dumps(_build_4738(u, config,
                                         target_username=target_acct,
                                         target_sid=target_sid,
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(1.0, 3.0)
    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


_SENSITIVE_GROUP_ACCOUNTS = [
    "Administrator", "krbtgt", "svc_sql_prod", "svc_backup",
    "svc_exchange", "svc_sccm",
]


def _threat_password_never_expires(config, session_context):
    """Sensitive account modified to set password-never-expires flag.

    Detection targets:
      - "A sensitive account was modified to password never expires"
      - Target must be a member of a sensitive built-in AD group

    Sequence:
      1. Attacker authenticates → DC 4624 + endpoint 4624 + 4672
      2. 4688 process creation
      3. 4728 member added to Domain Admins (establishes sensitive context)
      4. 4738 account changed — OldUacValue=0x200, NewUacValue=0x10200
         (DONT_EXPIRE_PASSWORD flag added)
      5. 4689 process exit
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    target_acct = random.choice(_SENSITIVE_GROUP_ACCOUNTS)
    if target_acct == "Administrator":
        target_sid = f"{_SYNTH_DOMAIN_SID}-500"
    elif target_acct == "krbtgt":
        target_sid = f"{_SYNTH_DOMAIN_SID}-502"
    else:
        target_sid = _stable_user_sid(target_acct)

    events = []
    t = time.time()
    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))

    t += random.uniform(3.0, 8.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\net.exe",
         f'net user {target_acct} /expires:never /domain'),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -c "Set-ADUser -Identity \'{target_acct}\' '
         f'-PasswordNeverExpires $true"'),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(0.5, 1.0)

    dns_domain = _get_dns_domain(config)
    dc_parts = dns_domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in dc_parts)
    member_dn = f"CN={target_acct},CN=Users,{base_dn}"

    group_name, grp = random.choice(list(_PRIVILEGED_GROUPS.items()))
    events.append(json.dumps(_ADD_BUILDERS[grp["event_id"]](
        u, config,
        member_name=member_dn,
        member_sid=target_sid,
        target_group=group_name,
        target_sid=grp["sid"],
        logon_id=logon_id, ts=t)))
    t += random.uniform(0.5, 2.0)

    events.append(json.dumps(_build_4738(u, config,
                                         target_username=target_acct,
                                         target_sid=target_sid,
                                         old_uac_value=_UAC_NORMAL_ACCOUNT,
                                         new_uac_value=_UAC_DONT_EXPIRE_PASSWD,
                                         uac_control="%%2089",
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(1.0, 3.0)
    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


def _threat_default_account_enabled(config, session_context):
    """Default local account (Administrator, Guest, DefaultAccount) is enabled.

    Detection targets:
      - "User enabled a default local account"

    Sequence:
      1. Attacker authenticates → DC 4624 + endpoint 4624 + 4672
      2. 4688 process creation
      3. 4722 account enabled — for a default account name
      4. 4738 account changed — UAC cleared ACCOUNTDISABLE bit
      5. 4689 process exit
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    target_acct = random.choice(["Guest", "DefaultAccount", "WDAGUtilityAccount"])
    if target_acct == "Guest":
        target_sid = f"{_SYNTH_DOMAIN_SID}-501"
    elif target_acct == "DefaultAccount":
        target_sid = f"{_SYNTH_DOMAIN_SID}-503"
    else:
        target_sid = _stable_user_sid(target_acct)

    events = []
    t = time.time()
    logon_id = _new_logon_id()

    events.append(json.dumps(_dc_logon_event(u, config, ip_override=u.get("ip"),
                                             logon_id=logon_id, ts=t)))
    t += 1.0
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         target_logon_id=logon_id,
                                         elevated=True, ts=t)))
    t += 0.05
    events.append(json.dumps(_build_4672(u, config, logon_id=logon_id,
                                         is_admin=True, ts=t)))

    t += random.uniform(3.0, 8.0)

    tool = random.choice([
        ("C:\\Windows\\System32\\net.exe",
         f'net user {target_acct} /active:yes'),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         f'powershell.exe -c "Enable-ADAccount -Identity \'{target_acct}\'"'),
    ])
    events.append(json.dumps(_build_4688(u, config, process_name=tool[0],
                                         command_line=tool[1],
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(0.5, 2.0)
    events.append(json.dumps(_build_4722(u, config,
                                         target_username=target_acct,
                                         target_sid=target_sid,
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(0.1, 0.5)
    events.append(json.dumps(_build_4738(u, config,
                                         target_username=target_acct,
                                         target_sid=target_sid,
                                         old_uac_value=_UAC_ACCOUNTDISABLE,
                                         new_uac_value=_UAC_NORMAL_ACCOUNT,
                                         uac_control="%%2080",
                                         logon_id=logon_id, ts=t)))

    t += random.uniform(1.0, 3.0)
    events.append(json.dumps(_build_4689(u, config, process_name=tool[0],
                                         logon_id=logon_id, ts=t)))
    return events


_THREAT_WEIGHTS = {
    "wip_as_rep_roasting":         8,
    "account_lockout":             5,
    "suspicious_account_lockout":  4,
    "dcsync":                      4,
    "wip_dmsa_privesc":            3,
    "priv_group_addition":         5,
    "wip_adminsdholder_acl_modification": 3,
    "wip_irregular_service_tgs":   6,
    "sms_admins_addition":         3,
    "wip_sccm_container_recon":    3,
    "dnshostname_spoofing":        3,
    "samaccountname_spoofing":     3,
    "delegation_change":           3,
    "multiple_service_tickets":    5,
    "priv_group_add_remove":       4,
    "wip_priv_cert_request":       3,
    "suspicious_account_creation": 5,
    "mass_account_deletion":       4,
    "wip_sensitive_password_reset": 4,
    "wip_password_never_expires":  3,
    "default_account_enabled":     3,
}

_THREAT_GENERATORS = {
    "wip_as_rep_roasting":             _threat_as_rep_roasting,
    "account_lockout":                  _threat_account_lockout,
    "suspicious_account_lockout":       _threat_suspicious_account_lockout,
    "dcsync":                           _threat_dcsync,
    "wip_dmsa_privesc":                 _threat_dmsa_privesc,
    "priv_group_addition":              _threat_priv_group_addition,
    "wip_adminsdholder_acl_modification": _threat_adminsdholder_acl_modification,
    "wip_irregular_service_tgs":        _threat_irregular_service_tgs,
    "sms_admins_addition":              _threat_sms_admins_addition,
    "wip_sccm_container_recon":         _threat_sccm_container_recon,
    "dnshostname_spoofing":             _threat_dnshostname_spoofing,
    "samaccountname_spoofing":          _threat_samaccountname_spoofing,
    "delegation_change":                _threat_delegation_change,
    "multiple_service_tickets":         _threat_multiple_service_tickets,
    "priv_group_add_remove":            _threat_priv_group_add_remove,
    "wip_priv_cert_request":            _threat_priv_cert_request,
    "suspicious_account_creation":      _threat_suspicious_account_creation,
    "mass_account_deletion":            _threat_mass_account_deletion,
    "wip_sensitive_password_reset":     _threat_sensitive_password_reset,
    "wip_password_never_expires":       _threat_password_never_expires,
    "default_account_enabled":          _threat_default_account_enabled,
}


def get_threat_names():
    """Expose named threats to the dashboard / CLI 'fire threat' mode."""
    return list(_THREAT_GENERATORS.keys())


def _select_threat(config, session_context):
    """Pick and run a threat generator according to config weights."""
    cfg_mix = _cf(config).get("event_mix", {}).get("threat", {})
    weights = {k: cfg_mix.get(k, v) for k, v in _THREAT_WEIGHTS.items()}
    choice = random.choices(list(weights.keys()), weights=list(weights.values()), k=1)[0]
    fn = _THREAT_GENERATORS[choice]
    result = fn(config, session_context)
    if result is None:
        result = _threat_account_lockout(config, session_context)
    return (result, choice) if result is not None else (None, None)


# ---------------------------------------------------------------------------
# Scenario-event dispatch (used by log_simulator.py attack scenarios)
# ---------------------------------------------------------------------------

def _generate_scenario_event(scenario_event, config, context):
    """Scenario events let the top-level orchestrator request a specific
    event shape from this module (e.g. "LOGIN_SUCCESS", "LOGIN_FAILURE").
    """
    session_context = (context or {}).get("session_context")
    user = None
    if context and context.get("user_identity"):
        user = get_user_by_name(session_context, context["user_identity"])
    if user is None:
        user = _pick_windows_user(session_context)
    if user is None:
        return None

    ev = scenario_event.upper()
    if ev in ("LOGIN", "LOGIN_SUCCESS"):
        return json.dumps(_build_4624(user, config, logon_type=2, auth_pkg=_NEG_PACKAGE)), "login_success"
    if ev in ("LOGIN_FAILURE", "LOGIN_FAILED"):
        return json.dumps(_build_4625(user, config, logon_type=2,
                                      status="0xC000006D", sub_status="0xC000006A")), "login_failure"
    if ev == "LOGOFF":
        session = _pop_open_session(user["hostname"], user["username"])
        if not session:
            return None
        return json.dumps(_build_4634(session, config)), "logoff"
    if ev == "LOCKOUT":
        return json.dumps(_build_4740(user, config, source_workstation=user["hostname"])), "lockout"
    if ev == "KERBEROS_TGT":
        return json.dumps(_build_4768(user, config)), "kerberos_tgt"
    # Dispatch to named threat generators
    _threat_dispatch = {
        "WIP_AS_REP_ROASTING":             _threat_as_rep_roasting,
        "ACCOUNT_LOCKOUT":                  _threat_account_lockout,
        "SUSPICIOUS_ACCOUNT_LOCKOUT":       _threat_suspicious_account_lockout,
        "DCSYNC":                           _threat_dcsync,
        "WIP_DMSA_PRIVESC":                 _threat_dmsa_privesc,
        "PRIV_GROUP_ADDITION":              _threat_priv_group_addition,
        "WIP_ADMINSDHOLDER_ACL_MODIFICATION": _threat_adminsdholder_acl_modification,
        "WIP_IRREGULAR_SERVICE_TGS":        _threat_irregular_service_tgs,
        "SMS_ADMINS_ADDITION":              _threat_sms_admins_addition,
        "WIP_SCCM_CONTAINER_RECON":         _threat_sccm_container_recon,
        "DNSHOSTNAME_SPOOFING":             _threat_dnshostname_spoofing,
        "SAMACCOUNTNAME_SPOOFING":          _threat_samaccountname_spoofing,
        "DELEGATION_CHANGE":                _threat_delegation_change,
        "MULTIPLE_SERVICE_TICKETS":         _threat_multiple_service_tickets,
        "PRIV_GROUP_ADD_REMOVE":            _threat_priv_group_add_remove,
        "WIP_PRIV_CERT_REQUEST":            _threat_priv_cert_request,
        "SUSPICIOUS_ACCOUNT_CREATION":      _threat_suspicious_account_creation,
        "MASS_ACCOUNT_DELETION":            _threat_mass_account_deletion,
        "WIP_SENSITIVE_PASSWORD_RESET":     _threat_sensitive_password_reset,
        "WIP_PASSWORD_NEVER_EXPIRES":       _threat_password_never_expires,
        "DEFAULT_ACCOUNT_ENABLED":          _threat_default_account_enabled,
    }
    if ev in _threat_dispatch:
        result = _threat_dispatch[ev](config, session_context)
        return (result, ev.lower()) if result else None
    return None


# ---------------------------------------------------------------------------
# Entry point (called by log_simulator.py on every tick)
# ---------------------------------------------------------------------------

def generate_log(config, scenario=None, scenario_event=None,
                 threat_level="Realistic", benign_only=False, context=None):
    """Generate one Windows event record (or batch of records).

    Returns:
      • str            — one JSON record
      • list[str]      — several JSON records (one per event)
      • (obj, name)    — scenario dispatch returns (result, event_name)
      • None           — no eligible Windows users in session_context
    """
    global last_threat_event_time, _BUILD_EVENT_OS_SUBTYPE
    session_context = (context or {}).get("session_context")

    # --- Scenario / story mode (always synchronous) ---
    if scenario_event:
        _BUILD_EVENT_OS_SUBTYPE = _get_os_subtype(config)
        return _generate_scenario_event(scenario_event, config, context)

    if scenario:
        return None

    # --- Nothing to do if there are no Windows users configured ---
    if not _get_windows_users(session_context):
        return None

    # --- Parallel host mode ---
    if _cf(config).get("parallel_hosts", False):
        _ensure_orchestrator(config, session_context, threat_level, benign_only)
        batch = []
        try:
            while len(batch) < 50:
                batch.append(_output_queue.get_nowait())
        except _queue_mod.Empty:
            pass
        if not batch:
            return None
        # Check if a threat fired during this drain cycle
        threat_name = None
        try:
            while True:
                status_evt = _status_queue.get_nowait()
                if status_evt.get("type") == "threat_fired":
                    threat_name = status_evt["name"]
        except _queue_mod.Empty:
            pass
        content = batch if len(batch) > 1 else batch[0]
        if threat_name:
            return (content, threat_name)
        return content

    # --- Original single-threaded behavior ---
    _BUILD_EVENT_OS_SUBTYPE = _get_os_subtype(config)

    if benign_only:
        return _select_benign(config, session_context)

    # --- Insane mode: 50% threat, 50% benign ---
    if threat_level == "Insane":
        if random.random() < 0.50:
            result, threat_name = _select_threat(config, session_context)
            if result is not None:
                return (result, threat_name)
        return _select_benign(config, session_context)

    # --- Normal paced mode: threats released on the configured interval ---
    interval     = _get_threat_interval(threat_level, config)
    current_time = time.time()
    with _STATE_LOCK:
        if interval > 0 and (current_time - last_threat_event_time) > interval:
            last_threat_event_time = current_time
            should_fire = True
        else:
            should_fire = False
    if should_fire:
        result, threat_name = _select_threat(config, session_context)
        if result is not None:
            return (result, threat_name)

    return _select_benign(config, session_context)


# ---------------------------------------------------------------------------
# Per-host parallel generation (multi-threaded mode)
# ---------------------------------------------------------------------------

_DC_BENIGN_GENS = {
    "dc_kerberos_traffic":  15,
    "dc_directory_service":  8,
    "dc_service_activity":  10,
    "dc_self_logon":         8,
}

_WKS_BENIGN_GENS = {
    "interactive_logon":    18,
    "network_share_logon":  22,
    "workstation_unlock":   18,
    "logoff":               10,
    "service_logon":         6,
    "scheduled_task_logon":  4,
    "cached_logon":          2,
    "rdp_logon":             3,
    "sql_access":           10,
    "web_app_access":        8,
    "ldap_query":            6,
    "ntlm_validation":       4,
    "explicit_cred_runas":   1,
    "password_typo":         2,
    "process_creation":     30,
    "lateral_movement":      3,
}


def _dc_worker(config, session_context, interval, stop_event):
    """Background thread generating DC-specific benign events."""
    stats = _worker_stats["dc"]
    gens = list(_DC_BENIGN_GENS.keys())
    weights = list(_DC_BENIGN_GENS.values())
    while not stop_event.is_set():
        try:
            choice = random.choices(gens, weights=weights, k=1)[0]
            fn = _BENIGN_GENERATORS[choice]
            result = fn(config, session_context)
            if result:
                items = result if isinstance(result, list) else [result]
                for item in items:
                    _output_queue.put(item, timeout=5)
                    stats["events_generated"] += 1
                stats["last_event_time"] = time.time()
        except _queue_mod.Full:
            pass
        except Exception:
            pass
        stop_event.wait(timeout=interval)


def _wks_worker(config, scoped_ctx, hostname, interval, stop_event):
    """Background thread generating workstation-specific benign events."""
    stats = _worker_stats[hostname]
    gens = list(_WKS_BENIGN_GENS.keys())
    weights = list(_WKS_BENIGN_GENS.values())
    while not stop_event.is_set():
        try:
            choice = random.choices(gens, weights=weights, k=1)[0]
            fn = _BENIGN_GENERATORS[choice]
            result = fn(config, scoped_ctx)
            if result is None:
                stop_event.wait(timeout=interval)
                continue
            items = result if isinstance(result, list) else [result]
            for item in items:
                _output_queue.put(item, timeout=5)
                stats["events_generated"] += 1
            stats["last_event_time"] = time.time()
        except _queue_mod.Full:
            pass
        except Exception:
            pass
        stop_event.wait(timeout=interval)


def _threat_worker(config, session_context, threat_level, interval, stop_event):
    """Background thread that fires threats on a cadence."""
    global last_threat_event_time
    stats = _worker_stats["threats"]
    threat_interval = _get_threat_interval(threat_level, config)

    while not stop_event.is_set():
        try:
            current_time = time.time()
            should_fire = False
            with _STATE_LOCK:
                if threat_interval > 0 and (current_time - last_threat_event_time) > threat_interval:
                    last_threat_event_time = current_time
                    should_fire = True

            if should_fire:
                result, threat_name = _select_threat(config, session_context)
                if result:
                    items = result if isinstance(result, list) else [result]
                    for item in items:
                        _output_queue.put(item, timeout=5)
                        stats["events_generated"] += 1
                    stats["last_event_time"] = time.time()
                    stats["last_fired"] = threat_name
                    try:
                        _status_queue.put_nowait({
                            "type": "threat_fired",
                            "name": threat_name,
                            "event_count": len(items),
                            "timestamp": current_time,
                        })
                    except _queue_mod.Full:
                        pass
        except Exception:
            pass
        stop_event.wait(timeout=interval)


def _ensure_orchestrator(config, session_context, threat_level, benign_only):
    """Start worker threads on first call. Subsequent calls are no-ops."""
    global _orchestrator_started, _BUILD_EVENT_OS_SUBTYPE
    with _orchestrator_lock:
        if _orchestrator_started:
            return
        _orchestrator_started = True

    _BUILD_EVENT_OS_SUBTYPE = _get_os_subtype(config)

    base_interval = config.get("base_event_interval_seconds", 1.0)
    wcfg = _cf(config)

    # Group users by hostname
    hosts: dict[str, list[str]] = {}
    for uname, prof in (session_context or {}).items():
        if (prof.get("primary_os_type") or "").lower() == "windows":
            hostname = prof.get("primary_hostname", "")
            if hostname:
                hosts.setdefault(hostname, []).append(uname)

    # Initialize per-worker stats
    _worker_stats["dc"] = {"events_generated": 0, "last_event_time": 0}
    _worker_stats["threats"] = {"events_generated": 0, "last_event_time": 0, "last_fired": None}
    for hostname in hosts:
        _worker_stats[hostname] = {"events_generated": 0, "last_event_time": 0}

    # DC worker
    dc_interval = base_interval * wcfg.get("dc_interval_multiplier", 0.5)
    threading.Thread(
        target=_dc_worker,
        args=(config, session_context, dc_interval, _workers_stop),
        daemon=True, name="logsim-win-dc",
    ).start()

    # Per-workstation workers
    wks_interval = base_interval * wcfg.get("wks_interval_multiplier", 1.0)
    for hostname, user_list in hosts.items():
        scoped_ctx = {u: session_context[u] for u in user_list}
        threading.Thread(
            target=_wks_worker,
            args=(config, scoped_ctx, hostname, wks_interval, _workers_stop),
            daemon=True,
            name=f"logsim-win-{hostname.split('.')[0]}",
        ).start()

    # Threat worker (skipped in benign-only mode)
    if not benign_only:
        threat_interval = base_interval * wcfg.get("threat_interval_multiplier", 2.0)
        threading.Thread(
            target=_threat_worker,
            args=(config, session_context, threat_level, threat_interval, _workers_stop),
            daemon=True, name="logsim-win-threats",
        ).start()


# ---------------------------------------------------------------------------
# Public API for Flask UI status
# ---------------------------------------------------------------------------

def get_worker_stats() -> dict:
    """Returns current parallel-mode worker stats for the Flask dashboard."""
    return {
        **_worker_stats,
        "queue_depth": _output_queue.qsize(),
        "parallel_active": _orchestrator_started,
    }


def get_status_events(max_items: int = 20) -> list:
    """Drain status queue for Flask UI (threat-fired notifications, etc.)."""
    events = []
    try:
        while len(events) < max_items:
            events.append(_status_queue.get_nowait())
    except _queue_mod.Empty:
        pass
    return events
