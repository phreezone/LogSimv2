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
import time
import json
import uuid
import hashlib
import threading
from datetime import datetime, timezone, timedelta

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
_PROVIDER_GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"  # real provider GUID
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
    4768: {"task": 14339, "category": "Kerberos Authentication Service", "version": 0, "outcome": "success"},
    4769: {"task": 14337, "category": "Kerberos Service Ticket Operations", "version": 0, "outcome": "success"},
    4771: {"task": 14339, "category": "Kerberos Authentication Service", "version": 0, "outcome": "failure"},
    4776: {"task": 14336, "category": "Credential Validation", "version": 0, "outcome": "success"},
}

# Per-event human-readable message templates (abbreviated; Windows renders
# the full multi-line description from the provider manifest — we emit the
# first line + a compact key=value tail so XSIAM correlation on Message still
# works).  Full EventData is always present as individual fields.
_EVENT_MSG_TITLE = {
    4624: "An account was successfully logged on.",
    4625: "An account failed to log on.",
    4634: "An account was logged off.",
    4647: "User initiated logoff:",
    4648: "A logon was attempted using explicit credentials.",
    4740: "A user account was locked out.",
    4768: "A Kerberos authentication ticket (TGT) was requested.",
    4769: "A Kerberos service ticket was requested.",
    4771: "Kerberos pre-authentication failed.",
    4776: "The computer attempted to validate the credentials for an account.",
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
    "interactive": [("0x1d4", "C:\\Windows\\System32\\winlogon.exe")],
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
    "HTTP/intranet.examplecorp.local",
    "HTTP/sharepoint.examplecorp.local",
    "LDAP/dc01.examplecorp.local",
    "MSSQLSvc/reportserver.examplecorp.local",
    "cifs/fs01.examplecorp.local",
    "TERMSRV/rdp-gw01.examplecorp.local",
    "MSSQLSvc/crmdb.examplecorp.local:1433",
    "HTTP/jenkins.examplecorp.local",
]

_SERVICE_ACCOUNT_SAMS = [
    "svc_sql_prod",   "svc_sql_dev",   "svc_iis",   "svc_sharepoint",
    "svc_backup",     "svc_monitoring","svc_jenkins","svc_reporting",
    "svc_crm",        "svc_etl",
]


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


def _stable_user_sid(username: str) -> str:
    """Deterministic domain SID for a username (last-RID from hash)."""
    sid = _USER_SIDS.get(username)
    if sid:
        return sid
    # RID is 32-bit unsigned; clamp away from well-known RIDs (0-999)
    h = hashlib.sha1(username.encode()).digest()
    rid = 1000 + (int.from_bytes(h[:4], "big") % 9_000_000)
    sid = f"{_SYNTH_DOMAIN_SID}-{rid}"
    _USER_SIDS[username] = sid
    return sid


def _next_record_number(host: str) -> int:
    """Monotonic RecordNumber per host.  Seeded to a realistic multi-thousand value."""
    cur = _RECORD_NUMBERS.get(host)
    if cur is None:
        cur = random.randint(50_000, 500_000)
    cur += 1
    _RECORD_NUMBERS[host] = cur
    return cur


def _new_logon_id() -> str:
    """Produce a hex logon-id string like '0x3e7' / '0x1b3a972'."""
    # Real Windows uses 64-bit hex values; most are < 2^28 on typical systems
    return "0x" + format(random.randint(0x10000, 0x7FFFFFFF), "x")


def _new_logon_guid() -> str:
    """UUID in the braced form Windows uses."""
    return "{" + str(uuid.uuid4()).upper() + "}"


def _iso_ts(t: float = None) -> str:
    """Windows/NXLog-style ISO8601 timestamp with milliseconds and UTC offset."""
    if t is None:
        t = time.time()
    dt = datetime.fromtimestamp(t, tz=timezone.utc)
    # e.g. 2026-04-17T14:02:33.581000+00:00 → trim to 3 decimals
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+00:00"


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
                 success: bool = True, message_tail: str = "",
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

    msg_lines = [_EVENT_MSG_TITLE[event_id]]
    if message_tail:
        msg_lines.append(message_tail)
    for k, v in event_data.items():
        if v is None or v == "":
            continue
        msg_lines.append(f"\t{k}:\t\t{v}")
    message = "\r\n".join(msg_lines)

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
        "log_level":         "information",
        "event_result":      "success" if success else "failure",
        "event_action":      meta["category"],
        "task":              meta["task"],
        "opcode":            "Info",
        "op_code":           "0",
        "version":           str(meta["version"]),
        "os_subtype":        _BUILD_EVENT_OS_SUBTYPE,
        "record_id":         str(_next_record_number(computer)),
        "activity_id":       "{" + str(uuid.uuid4()).upper() + "}",
        "process_pid":       proc_pid,
        "process_thread_id": proc_tid,
        "process_name":      lsass_name,
        "process_path":      lsass_path,
        "process_cmd":       "",
        "process_md5":       "",
        "process_sha256":    "",
        "event_data":        ed_clean,
    }

    return record


# ---------------------------------------------------------------------------
# Per-EventID constructors
# ---------------------------------------------------------------------------

def _build_4624(user_info, config, *, logon_type=2, auth_pkg=None,
                workstation_override=None, ip_override=None,
                target_logon_id=None, logon_guid=None, ts=None,
                elevated=False) -> dict:
    """4624 – An account was successfully logged on (emitted by the endpoint)."""
    domain = _get_domain(config)
    computer = workstation_override or user_info["hostname"]
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

    lp_name = random.choice(_LOGON_PROCESS_NAMES.get(_lt_cat, ["User32"]))
    proc_id, proc_name = random.choice(
        _LOGON_PROCESSES_BY_TYPE.get(_lt_cat, _LOGON_PROCESSES_DEFAULT))

    target_logon_id = target_logon_id or _new_logon_id()
    logon_guid = logon_guid or _new_logon_guid()

    # Subject is SYSTEM for interactive/service/unlock; for network/remote
    # it's the machine account (COMPUTER$) on the authenticating host.
    if logon_type in (3, 10):
        subj_sid = _SID_SYSTEM
        subj_name = computer.split(".")[0].upper() + "$"
        subj_domain = domain
    else:
        subj_sid = _SID_SYSTEM
        subj_name = computer.split(".")[0].upper() + "$"
        subj_domain = domain

    event_data = {
        "SubjectUserSid":            subj_sid,
        "SubjectUserName":           subj_name,
        "SubjectDomainName":         subj_domain,
        "SubjectLogonId":            "0x3e7",   # SYSTEM
        "TargetUserSid":             _stable_user_sid(user_info["username"]),
        "TargetUserName":            user_info["username"],
        "TargetDomainName":          domain,
        "TargetLogonId":             target_logon_id,
        "LogonType":                 logon_type,
        "LogonProcessName":          lp_name,
        "AuthenticationPackageName": auth_pkg,
        "WorkstationName":           computer.split(".")[0].upper(),
        "LogonGuid":                 logon_guid if auth_pkg == _KRB_PACKAGE else "{00000000-0000-0000-0000-000000000000}",
        "TransmittedServices":       "-",
        "LmPackageName":             lm_pkg,
        "KeyLength":                 key_len,
        "ProcessId":                 proc_id,
        "ProcessName":               proc_name,
        "IpAddress":                 ip if logon_type in (3, 10) else ("127.0.0.1" if logon_type == 2 else "-"),
        "IpPort":                    port if logon_type in (3, 10) else "0",
        "ImpersonationLevel":        random.choice(["%%1833", "%%1834", "%%1834", "%%1834"]),
        "RestrictedAdminMode":       ("Yes" if random.random() < 0.1 else "-") if logon_type == 10 else "-",
        "TargetOutboundUserName":    "-",
        "TargetOutboundDomainName":  "-",
        "VirtualAccount":            "%%1843",   # "No"
        "TargetLinkedLogonId":       "0x0",
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
            "workstation":   event_data["WorkstationName"],
            "start":         ts or time.time(),
            "auth_package":  auth_pkg,
            "logon_guid":    logon_guid,
        })
        # a success clears the failure streak
        _FAIL_COUNTS[user_info["username"]] = 0

    return _build_event(
        4624, computer, event_data, success=True, ts=ts,
        message_tail=f"Logon Type:{logon_type}  {auth_pkg}  {event_data['TargetUserName']}",
    )


def _build_4625(user_info, config, *, logon_type=3, auth_pkg=None,
                sub_status=None, status=None, failure_reason=None,
                workstation_override=None, ip_override=None, ts=None) -> dict:
    """4625 – An account failed to log on."""
    domain = _get_domain(config)
    computer = workstation_override or user_info["hostname"]
    ip = ip_override if ip_override is not None else user_info.get("ip") or "-"
    port = str(random.randint(49152, 65535))

    if auth_pkg is None:
        auth_pkg = _NTLM_PACKAGE_SHORT if logon_type in (3, 10) else _NEG_PACKAGE

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
    lp_name = random.choice(_LOGON_PROCESS_NAMES.get(lp_category, ["NtLmSsp "]))

    event_data = {
        "SubjectUserSid":            _SID_SYSTEM,
        "SubjectUserName":           computer.split(".")[0].upper() + "$",
        "SubjectDomainName":         domain,
        "SubjectLogonId":            "0x3e7",
        "TargetUserSid":             _SID_ANON,
        "TargetUserName":            user_info["username"],
        "TargetDomainName":          domain,
        "Status":                    status,
        "FailureReason":             failure_reason,
        "SubStatus":                 sub_status,
        "LogonType":                 logon_type,
        "LogonProcessName":          lp_name,
        "AuthenticationPackageName": auth_pkg,
        "WorkstationName":           computer.split(".")[0].upper(),
        "TransmittedServices":       "-",
        "LmPackageName":             "-",
        "KeyLength":                 "0",
        "ProcessId":                 proc_id,
        "ProcessName":               proc_name,
        "IpAddress":                 ip,
        "IpPort":                    port,
    }

    with _STATE_LOCK:
        _FAIL_COUNTS[user_info["username"]] = _FAIL_COUNTS.get(user_info["username"], 0) + 1

    return _build_event(
        4625, computer, event_data, success=False, ts=ts,
        message_tail=f"{failure_reason} User={user_info['username']} LogonType={logon_type}",
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
    computer = session_row["workstation"]
    # Add the dns suffix back if the computer is a simple name and the
    # config declares an all-FQDN mode
    if "." not in computer and _cf(config).get("use_fqdn_hostnames", False):
        computer = f"{computer}.{_get_dns_domain(config)}"
    event_data = {
        "TargetUserSid":    session_row["target_user_sid"],
        "TargetUserName":   session_row["target_user_name"],
        "TargetDomainName": session_row["target_domain"],
        "TargetLogonId":    session_row["logon_id"],
        "LogonType":        session_row["logon_type"],
    }
    return _build_event(4634, computer, event_data, success=True, ts=ts,
                        message_tail=f"User={session_row['target_user_name']} LogonId={session_row['logon_id']}")


def _build_4647(session_row, config, ts=None) -> dict:
    """4647 – User initiated logoff (emitted only for interactive logon types)."""
    computer = session_row["workstation"]
    event_data = {
        "TargetUserSid":    session_row["target_user_sid"],
        "TargetUserName":   session_row["target_user_name"],
        "TargetDomainName": session_row["target_domain"],
        "TargetLogonId":    session_row["logon_id"],
    }
    return _build_event(4647, computer, event_data, success=True, ts=ts,
                        message_tail=f"User={session_row['target_user_name']} LogonId={session_row['logon_id']}")


def _build_4648(user_info, config, *, target_user, target_server,
                process_name="C:\\Windows\\System32\\runas.exe",
                ip_override=None, ts=None) -> dict:
    """4648 – A logon was attempted using explicit credentials (runas/scheduled task)."""
    domain = _get_domain(config)
    computer = user_info["hostname"]
    ip = ip_override if ip_override is not None else user_info.get("ip") or "::1"
    is_local = target_server in ("localhost", "127.0.0.1", "::1")
    ip_field = "::1" if is_local else (f"::ffff:{ip}" if "." in str(ip) and ":" not in str(ip) else ip)
    event_data = {
        "SubjectUserSid":       _stable_user_sid(user_info["username"]),
        "SubjectUserName":      user_info["username"],
        "SubjectDomainName":    domain,
        "SubjectLogonId":       _new_logon_id(),
        "LogonGuid":            _new_logon_guid(),
        "TargetUserName":       target_user,
        "TargetDomainName":     domain,
        "TargetLogonGuid":      "{00000000-0000-0000-0000-000000000000}",
        "TargetServerName":     target_server,
        "TargetInfo":           target_server,
        "ProcessId":            "0x%x" % random.randint(0x200, 0x9fff),
        "ProcessName":          process_name,
        "IpAddress":            ip_field,
        "IpPort":               "0" if is_local else str(random.randint(49152, 65535)),
    }
    return _build_event(4648, computer, event_data, success=True, ts=ts,
                        message_tail=f"Subject={user_info['username']} Target={target_user}@{target_server}")


def _build_4740(user_info, config, *, source_workstation=None, ts=None) -> dict:
    """4740 – A user account was locked out (emitted by a DC)."""
    domain = _get_domain(config)
    dc_host = _get_dc_hostname(config)
    caller = source_workstation or user_info.get("hostname") or "UNKNOWN"
    event_data = {
        "TargetUserName":     user_info["username"],
        "TargetDomainName":   caller.split(".")[0].upper(),
        "TargetSid":          _stable_user_sid(user_info["username"]),
        "SubjectUserSid":     _SID_SYSTEM,
        "SubjectUserName":    _get_dc_short(config) + "$",
        "SubjectDomainName":  domain,
        "SubjectLogonId":     "0x3e7",
    }
    return _build_event(4740, dc_host, event_data, success=True, ts=ts,
                        message_tail=f"User={user_info['username']} From={caller}")


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
    event_data = {
        "TargetUserName":         user_info["username"],
        "TargetDomainName":       dns_domain_upper,
        "TargetSid":              _stable_user_sid(user_info["username"]) if success else _SID_ANON,
        "ServiceName":            svc_name,
        "ServiceSid":             f"{_SYNTH_DOMAIN_SID}-502" if success else _SID_ANON,
        "TicketOptions":          "0x40810010",
        "Status":                 status,
        "TicketEncryptionType":   enc,
        "PreAuthType":            "2",
        "IpAddress":              f"::ffff:{ip}" if ip and "." in str(ip) else ip,
        "IpPort":                 str(random.randint(49152, 65535)),
        "CertIssuerName":         cert_issuer,
        "CertSerialNumber":       cert_serial,
        "CertThumbprint":         cert_thumbprint,
    }
    return _build_event(4768, dc_host, event_data, success=success, ts=ts,
                        message_tail=f"User={user_info['username']} Enc={enc} Status={status}")


def _build_4769(user_info, config, *, service_spn=None, encryption=None,
                status="0x0", ip_override=None, ts=None) -> dict:
    """4769 – Kerberos service-ticket request (DC event)."""
    domain = _get_domain(config)
    dc_host = _get_dc_hostname(config)
    ip = ip_override if ip_override is not None else user_info.get("ip") or "-"
    spn = service_spn or random.choice(_SERVICE_ACCOUNT_SPNS)
    enc = encryption or random.choice(_TICKET_ENC_NORMAL)
    success = (status == "0x0")
    svc_host = spn.split("/")[1].split(":")[0].split(".")[0].upper() + "$" if "/" in spn else spn
    event_data = {
        "TargetUserName":        f"{user_info['username']}@{_get_dns_domain(config).upper()}",
        "TargetDomainName":      _get_dns_domain(config).upper(),
        "ServiceName":           svc_host,
        "ServiceSid":            _stable_user_sid(spn) if success else _SID_ANON,
        "TicketOptions":         "0x40810000",
        "TicketEncryptionType":  enc if success else "0xFFFFFFFF",
        "IpAddress":             f"::ffff:{ip}" if ip and "." in str(ip) else ip,
        "IpPort":                str(random.randint(49152, 65535)),
        "Status":                status,
        "LogonGuid":             _new_logon_guid(),
        "TransmittedServices":   "-",
    }
    return _build_event(4769, dc_host, event_data, success=success, ts=ts,
                        message_tail=f"User={user_info['username']} Service={spn} Enc={enc}")


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
                        message_tail=f"User={user_info['username']} Status={status}")


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
                        message_tail=f"User={user_info['username']} Workstation={ws} Status={status}")


# ---------------------------------------------------------------------------
# Benign event generators
# ---------------------------------------------------------------------------

def _benign_interactive_logon(config, session_context):
    """User logs on interactively at their workstation (LogonType 2).
    Produces a DC 4768 (Kerberos TGT) + a workstation 4624 a moment later.
    Returns a list of JSON strings.
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None

    t0 = time.time()
    tgt    = _build_4768(u, config, ts=t0 - random.uniform(0.08, 0.35))
    logon  = _build_4624(u, config, logon_type=2, auth_pkg=_NEG_PACKAGE, ts=t0)
    return [json.dumps(tgt), json.dumps(logon)]


def _benign_network_share_logon(config, session_context):
    """User's workstation accesses a file share (LogonType 3, Kerberos).
    Produces a 4769 service-ticket event + 4624 on the server side.
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    # Pick a target "server" from the file-share SPN list
    server_spns = [s for s in _SERVICE_ACCOUNT_SPNS if s.startswith("cifs/")]
    spn = random.choice(server_spns or _SERVICE_ACCOUNT_SPNS)
    server_short = spn.split("/")[1].split(":")[0].split(".")[0].upper()

    t0 = time.time()
    tgs    = _build_4769(u, config, service_spn=spn, ts=t0 - 0.15)
    # Build a 4624 "from u's workstation to the share server" — we reuse the
    # user's hostname as WorkstationName and the server as Computer.
    logon  = _build_4624(u, config, logon_type=3, auth_pkg=_KRB_PACKAGE,
                         workstation_override=server_short, ts=t0)
    return [json.dumps(tgs), json.dumps(logon)]


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
    """A service account logon (LogonType 5)."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    svc_name = random.choice(_SERVICE_ACCOUNT_SAMS)
    fake_user = {**u, "username": svc_name}
    return json.dumps(_build_4624(fake_user, config, logon_type=5,
                                  auth_pkg=_NEG_PACKAGE))


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
    """Benign RDP into user's machine from another internal host (LogonType 10)."""
    u = _pick_windows_user(session_context)
    if not u:
        return None
    internal_nets = config.get("internal_networks", ["10.0.0.0/8"])
    # Pick another Windows user's IP as the source to match real lateral-admin flow
    src = _pick_windows_user(session_context)
    src_ip = src["ip"] if src and src["ip"] != u["ip"] else "10.10.10.200"

    t0 = time.time()
    tgs   = _build_4769(u, config, service_spn=f"TERMSRV/{u['hostname']}", ts=t0 - 0.2)
    logon = _build_4624(u, config, logon_type=10, auth_pkg=_KRB_PACKAGE,
                        ip_override=src_ip, ts=t0)
    return [json.dumps(tgs), json.dumps(logon)]


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


_BENIGN_WEIGHTS = {
    # Higher weights → more realistic day-in-the-life (Windows auth volume
    # is dominated by unlocks, network-share access, and routine interactive
    # logons).
    "interactive_logon":     18,
    "network_share_logon":   28,
    "workstation_unlock":    22,
    "logoff":                10,
    "service_logon":          6,
    "scheduled_task_logon":   4,
    "cached_logon":           2,
    "rdp_logon":              3,
    "ntlm_validation":        4,
    "explicit_cred_runas":    1,
    "password_typo":          2,
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
    "ntlm_validation":      _benign_ntlm_validation,
    "explicit_cred_runas":  _benign_explicit_cred_runas,
    "password_typo":        _benign_password_typo,
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


def _threat_brute_force(config, session_context):
    """N failed attempts followed by one success — full cross-host correlation.

    Each failure produces:
      DC:  4771 (Kerberos pre-auth failed) + 4776 (NTLM validation failed)
      WKS: 4625 (logon failed)
    Final success produces:
      DC:  4768 (TGT granted) + 4769 (TGS for target host)
      WKS: 4624 (logon succeeded)
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    attempts = random.randint(8, 22)
    anon = get_random_anon_ip_ctx(config)
    src_ip = anon["ip"]
    events = []
    t = time.time() - attempts * 2
    for i in range(attempts):
        events.append(json.dumps(_build_4771(u, config, status="0x18",
                                             ip_override=src_ip, ts=t)))
        events.append(json.dumps(_build_4776(u, config, status="0xC000006A",
                                             workstation=u["hostname"], ts=t + 0.05)))
        events.append(json.dumps(_build_4625(u, config, logon_type=3,
                                             sub_status="0xC000006A",
                                             ip_override=src_ip, ts=t + 0.1)))
        t += random.uniform(1.5, 3.5)
    events.append(json.dumps(_build_4768(u, config, ip_override=src_ip, ts=t)))
    events.append(json.dumps(_build_4769(u, config,
                                         service_spn=f"cifs/{u['hostname']}",
                                         ts=t + 0.05)))
    events.append(json.dumps(_build_4776(u, config, status="0x0",
                                         workstation=u["hostname"], ts=t + 0.08)))
    events.append(json.dumps(_build_4624(u, config, logon_type=3, auth_pkg=_KRB_PACKAGE,
                                         ip_override=src_ip, ts=t + 0.12)))
    return events


def _threat_password_spray(config, session_context):
    """One password tried against many users from a single source IP.

    Each failure produces:
      DC:  4771 (Kerberos pre-auth failed) + 4776 (NTLM validation failed)
      WKS: 4625 (logon failed)
    Final user succeeds:
      DC:  4768 (TGT) + 4776 (NTLM success)
      WKS: 4624 (logon success)
    """
    users = _get_windows_users(session_context)
    if len(users) < 4:
        return None
    targets = random.sample(users, k=min(len(users), random.randint(12, 25)))
    anon = get_random_anon_ip_ctx(config)
    src_ip = anon["ip"]
    events = []
    t = time.time() - len(targets) * 1.5
    for u in targets[:-1]:
        events.append(json.dumps(_build_4771(u, config, status="0x18",
                                             ip_override=src_ip, ts=t)))
        events.append(json.dumps(_build_4776(u, config, status="0xC000006A",
                                             workstation=u["hostname"], ts=t + 0.05)))
        events.append(json.dumps(_build_4625(u, config, logon_type=3,
                                             sub_status="0xC000006A",
                                             ip_override=src_ip, ts=t + 0.1)))
        t += random.uniform(1.0, 2.2)
    winner = targets[-1]
    events.append(json.dumps(_build_4768(winner, config, ip_override=src_ip, ts=t)))
    events.append(json.dumps(_build_4776(winner, config, status="0x0",
                                         workstation=winner["hostname"], ts=t + 0.05)))
    events.append(json.dumps(_build_4624(winner, config, logon_type=3,
                                         auth_pkg=_NTLM_PACKAGE_SHORT,
                                         ip_override=src_ip, ts=t + 0.1)))
    return events


def _threat_kerberoasting(config, session_context):
    """Full Kerberoasting attack chain from a single compromised user.

    Sequence:
      1. Attacker authenticates normally → 4768 TGT (AES, looks benign)
      2. Attacker's session starts on the workstation → 4624 (interactive)
      3. Burst of 4769 TGS requests for many service accounts with RC4
         encryption (0x17) — this is the detection signal.

    Detection keys:
      - Single TargetUserName across many 4769 events in a short window
      - TicketEncryptionType = 0x17 (RC4-HMAC) instead of normal 0x12 (AES256)
      - High volume of distinct ServiceName values
      - Benign baseline uses AES (0x12); this shift to RC4 is anomalous
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    targets = random.sample(_SERVICE_ACCOUNT_SPNS,
                            k=min(len(_SERVICE_ACCOUNT_SPNS), random.randint(6, 10)))
    events = []
    t = time.time() - len(targets) * 0.6

    events.append(json.dumps(_build_4768(u, config, ts=t)))
    t += random.uniform(0.1, 0.3)
    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE, ts=t)))
    t += random.uniform(0.5, 2.0)

    for spn in targets:
        events.append(json.dumps(_build_4769(u, config, service_spn=spn,
                                             encryption="0x17", ts=t)))
        t += random.uniform(0.2, 0.7)

    return events


def _threat_as_rep_roasting(config, session_context):
    """AS-REP Roasting: attacker enumerates accounts with pre-auth disabled.

    Sequence:
      1. Attacker authenticates from their own machine → 4768 TGT (normal)
      2. Attacker's session starts → 4624
      3. Burst of 4768 TGT requests for many different users with
         PreAuthType=0 (no pre-auth) and weak encryption — all from the
         same source IP.

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
    targets = random.sample(users, k=min(len(users), random.randint(6, 12)))
    anon = get_random_anon_ip_ctx(config)
    src_ip = anon["ip"]
    events = []
    t = time.time() - len(targets) - 2

    events.append(json.dumps(_build_4768(attacker, config, ip_override=src_ip, ts=t)))
    t += 0.15
    events.append(json.dumps(_build_4624(attacker, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE,
                                         ip_override=src_ip, ts=t)))
    t += random.uniform(1.0, 3.0)

    for u in targets:
        ev = _build_4768(u, config, ip_override=src_ip,
                         encryption=random.choice(_TICKET_ENC_WEAK), ts=t)
        ev["event_data"]["PreAuthType"] = "0"
        events.append(json.dumps(ev))
        t += random.uniform(0.3, 0.8)
    return events


def _threat_pass_the_hash(config, session_context):
    """Pass-the-Hash lateral movement using stolen NTLM credentials.

    Sequence:
      1. Attacker uses explicit credentials (4648) on compromised host
      2. DC validates NTLM credential (4776) — workstation unknown/mismatched
      3. Network logon (4624 type 3) on target host with PtH fingerprint:
         AuthenticationPackageName=NTLM, LogonProcessName=NtLmSsp,
         KeyLength=0, LmPackageName=NTLM V2
      4. Attacker accesses resources on target (4769 TGS for target service)

    Detection keys:
      - LogonType=3 + NTLM auth + KeyLength=0 (no session key negotiated)
      - LogonProcessName=NtLmSsp (not Kerberos or Negotiate)
      - Source IP doesn't match the user's known workstation
      - 4776 Workstation field doesn't match known hostnames
      - 4648 followed by 4624 on a different host
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    others = _get_windows_users(session_context)
    target_host = None
    for o in others:
        if o["hostname"] != u["hostname"]:
            target_host = o
            break
    if not target_host:
        target_host = u

    anon = get_random_anon_ip_ctx(config)
    src_ip = anon["ip"]
    events = []
    t = time.time()

    events.append(json.dumps(_build_4648(
        u, config, target_user=u["username"],
        target_server=target_host["hostname"].split(".")[0],
        process_name="C:\\Windows\\System32\\sekurlsa.exe",
        ip_override=src_ip, ts=t)))
    t += 0.1

    events.append(json.dumps(_build_4776(u, config, status="0x0",
                                         workstation="UNKNOWN-WKS", ts=t)))
    t += 0.08

    ev = _build_4624(u, config, logon_type=3, auth_pkg=_NTLM_PACKAGE_SHORT,
                     workstation_override=target_host["hostname"],
                     ip_override=src_ip, ts=t)
    ev["event_data"]["LogonProcessName"] = "NtLmSsp "
    ev["event_data"]["LmPackageName"] = "NTLM V2"
    ev["event_data"]["KeyLength"] = "0"
    events.append(json.dumps(ev))
    t += 0.15

    events.append(json.dumps(_build_4769(
        u, config,
        service_spn=f"cifs/{target_host['hostname']}",
        ts=t)))

    return events


def _threat_rdp_bruteforce(config, session_context):
    """RDP brute force from a single external IP, ending with success.

    Each failure produces:
      DC:  4776 (NTLM validation failed)
      WKS: 4625 (logon type 10 — RemoteInteractive)
    Final success produces:
      DC:  4768 (TGT) + 4769 (TGS for TERMSRV/<host>)
      WKS: 4624 (logon type 10)

    Detection keys:
      - Many 4625 LogonType=10 from a single external IP
      - Followed by a successful 4624 LogonType=10 from the same IP
      - 4769 requesting TERMSRV SPN correlates with the RDP session
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    anon = get_random_anon_ip_ctx(config)
    src_ip = anon["ip"]
    events = []
    attempts = random.randint(6, 15)
    t = time.time() - attempts * 2
    for _ in range(attempts):
        events.append(json.dumps(_build_4776(u, config, status="0xC000006A",
                                             workstation=u["hostname"], ts=t)))
        events.append(json.dumps(_build_4625(u, config, logon_type=10,
                                             sub_status="0xC000006A",
                                             ip_override=src_ip, ts=t + 0.08)))
        t += random.uniform(1.5, 3.0)
    events.append(json.dumps(_build_4768(u, config, ip_override=src_ip, ts=t)))
    events.append(json.dumps(_build_4769(u, config,
                                         service_spn=f"TERMSRV/{u['hostname']}",
                                         ts=t + 0.05)))
    events.append(json.dumps(_build_4624(u, config, logon_type=10,
                                         auth_pkg=_NEG_PACKAGE,
                                         ip_override=src_ip, ts=t + 0.12)))
    return events


def _threat_account_lockout(config, session_context):
    """N × 4625 bad-password attempts → 4740 lockout → 4625 locked-out reject.
    Does NOT end with a success (tests lockout-specific detections via 4740).
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    attempts = random.randint(10, 15)
    anon = get_random_anon_ip_ctx(config)
    src_ip = anon["ip"]
    events = []
    t = time.time() - attempts
    for _ in range(attempts):
        events.append(json.dumps(_build_4625(u, config, logon_type=3,
                                             sub_status="0xC000006A",
                                             ip_override=src_ip, ts=t)))
        t += random.uniform(0.8, 1.8)
    events.append(json.dumps(_build_4740(u, config, source_workstation=u["hostname"], ts=t)))
    events.append(json.dumps(_build_4625(u, config, logon_type=3,
                                         status="0xC0000234", sub_status="0x0",
                                         ip_override=src_ip, ts=t + 0.4)))
    return events


def _threat_account_lockout_then_success(config, session_context):
    """N × 4625 → 4740 lockout → lockout expires → successful 4624.
    Triggers both lockout detections (4740) AND failure→success UEBA patterns.
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    attempts = random.randint(10, 15)
    anon = get_random_anon_ip_ctx(config)
    src_ip = anon["ip"]
    events = []
    t = time.time() - attempts - random.uniform(1800, 3600)
    for _ in range(attempts):
        events.append(json.dumps(_build_4625(u, config, logon_type=3,
                                             sub_status="0xC000006A",
                                             ip_override=src_ip, ts=t)))
        t += random.uniform(0.8, 1.8)
    events.append(json.dumps(_build_4740(u, config, source_workstation=u["hostname"], ts=t)))
    events.append(json.dumps(_build_4625(u, config, logon_type=3,
                                         status="0xC0000234", sub_status="0x0",
                                         ip_override=src_ip, ts=t + 0.4)))
    t += random.uniform(1800, 3600)
    events.append(json.dumps(_build_4768(u, config, ip_override=src_ip, ts=t)))
    events.append(json.dumps(_build_4624(u, config, logon_type=3,
                                         auth_pkg=_KRB_PACKAGE,
                                         ip_override=src_ip, ts=t + 0.15)))
    return events


def _threat_explicit_credential_abuse(config, session_context):
    """Post-exploitation credential enumeration via runas / service account abuse.

    Sequence:
      1. Attacker's initial session exists → 4624 (interactive)
      2. Burst of 4648 (explicit credential) events trying many service accounts
      3. Each successful credential test produces a 4624 type 9 (NewCredentials)
         showing the attacker pivoting under a new identity
      4. DC sees corresponding 4769 TGS requests for service SPNs

    Detection keys:
      - Many 4648 events from a single SubjectUserName in a short window
      - Distinct TargetUserNames across the 4648 events (enumeration)
      - ProcessName = cmd.exe / powershell.exe (not normal for runas)
      - 4624 LogonType=9 (NewCredentials) following each 4648
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    targets = random.sample(_SERVICE_ACCOUNT_SAMS,
                            k=min(len(_SERVICE_ACCOUNT_SAMS), random.randint(5, 8)))
    servers = ["sql01", "fs01", "dc01", "app01", "web01"]
    events = []
    t = time.time() - len(targets) * 2

    events.append(json.dumps(_build_4624(u, config, logon_type=2,
                                         auth_pkg=_NEG_PACKAGE, ts=t)))
    t += random.uniform(1.0, 3.0)

    proc = random.choice(["C:\\Windows\\System32\\cmd.exe",
                           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"])
    for svc in targets:
        target_server = random.choice(servers)
        events.append(json.dumps(_build_4648(
            u, config, target_user=svc, target_server=target_server,
            process_name=proc, ts=t)))
        t += 0.2

        fake_svc_user = {**u, "username": svc}
        events.append(json.dumps(_build_4624(fake_svc_user, config, logon_type=9,
                                             auth_pkg=_NEG_PACKAGE, ts=t)))
        t += 0.15

        svc_spn = next((s for s in _SERVICE_ACCOUNT_SPNS
                        if target_server in s), _SERVICE_ACCOUNT_SPNS[0])
        events.append(json.dumps(_build_4769(u, config, service_spn=svc_spn,
                                             ts=t)))
        t += random.uniform(0.3, 0.8)

    return events



def _threat_anomalous_workstation_logon(config, session_context):
    """User logs in from a workstation they've never used — UEBA anomaly.

    Sequence:
      1. DC issues TGT for the user from an unusual source IP → 4768
      2. DC issues TGS for TERMSRV/<unusual_host> → 4769
      3. User logs on interactively at the unusual workstation → 4624 type 10
      4. User accesses a file share from the new host → 4769 (cifs)

    Detection keys:
      - 4624 WorkstationName ≠ user's established baseline host
      - Source IP in 4768/4769 doesn't match user's known IP
      - UEBA flags the user→host pairing as novel
    """
    u = _pick_windows_user(session_context)
    if not u:
        return None
    others = [o for o in _get_windows_users(session_context) if o["hostname"] != u["hostname"]]
    if not others:
        return None
    target_ws = random.choice(others)
    anon = get_random_anon_ip_ctx(config)
    src_ip = anon["ip"]
    events = []
    t = time.time()

    events.append(json.dumps(_build_4768(u, config, ip_override=src_ip, ts=t)))
    t += 0.1
    events.append(json.dumps(_build_4769(u, config,
                                         service_spn=f"TERMSRV/{target_ws['hostname']}",
                                         ts=t)))
    t += 0.12
    events.append(json.dumps(_build_4624(u, config, logon_type=10,
                                         auth_pkg=_KRB_PACKAGE,
                                         workstation_override=target_ws["hostname"],
                                         ip_override=src_ip, ts=t)))
    t += random.uniform(30, 120)
    events.append(json.dumps(_build_4769(u, config,
                                         service_spn=f"cifs/{random.choice(_SERVICE_ACCOUNT_SPNS).split('/')[1].split(':')[0]}",
                                         ts=t)))

    return events


_THREAT_WEIGHTS = {
    "brute_force":                18,
    "password_spray":             14,
    "kerberoasting":              10,
    "as_rep_roasting":             8,
    "pass_the_hash":               9,
    "rdp_bruteforce":             14,
    "account_lockout":             5,
    "account_lockout_then_success":5,
    "explicit_credential_abuse":   6,
    "anomalous_workstation_logon": 5,
}

_THREAT_GENERATORS = {
    "brute_force":                 _threat_brute_force,
    "password_spray":              _threat_password_spray,
    "kerberoasting":               _threat_kerberoasting,
    "as_rep_roasting":             _threat_as_rep_roasting,
    "pass_the_hash":               _threat_pass_the_hash,
    "rdp_bruteforce":              _threat_rdp_bruteforce,
    "account_lockout":              _threat_account_lockout,
    "account_lockout_then_success": _threat_account_lockout_then_success,
    "explicit_credential_abuse":    _threat_explicit_credential_abuse,
    "anomalous_workstation_logon": _threat_anomalous_workstation_logon,
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
        # Fall back to something that almost always works
        result = _threat_brute_force(config, session_context)
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
    if ev == "BRUTE_FORCE":
        result = _threat_brute_force(config, session_context)
        return (result, "brute_force") if result else None
    if ev == "KERBEROASTING":
        result = _threat_kerberoasting(config, session_context)
        return (result, "kerberoasting") if result else None
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
    _BUILD_EVENT_OS_SUBTYPE = _get_os_subtype(config)
    session_context = (context or {}).get("session_context")

    # --- Scenario / story mode ---
    if scenario_event:
        return _generate_scenario_event(scenario_event, config, context)

    if scenario:
        # Free-form scenario mode not supported in v1 — fall through.
        return None

    # --- Nothing to do if there are no Windows users configured ---
    if not _get_windows_users(session_context):
        return None

    # --- Benign-only mode ---
    if benign_only:
        return _select_benign(config, session_context)

    # --- Insane mode: 50% threat, 50% benign ---
    if threat_level == "Insane":
        if random.random() < 0.50:
            result, _name = _select_threat(config, session_context)
            return result
        return _select_benign(config, session_context)

    # --- Normal paced mode: threats released on the configured interval ---
    interval     = _get_threat_interval(threat_level, config)
    current_time = time.time()
    if interval > 0 and (current_time - last_threat_event_time) > interval:
        last_threat_event_time = current_time
        result, _name = _select_threat(config, session_context)
        if result is not None:
            return result

    return _select_benign(config, session_context)
