# modules/cisco_firepower.py
# Simulates Cisco Firepower (FTD/FMC) logs in CEF format for the XSIAM cisco_firepower_raw dataset.
#
# Architecture:
#   Generates native Cisco FTD/FMC CEF syslog messages.
#   XSIAM's built-in Cisco Firepower parsing rule creates cisco_firepower_raw records.
#   CiscoFirepower_1_3.xif models the CEF extensions to XDM fields.
#
# XDM fields populated per event type (CiscoFirepower_1_3.xif):
#   All events:   xdm.observer.name (dvchost), xdm.observer.unique_identifier (deviceExternalId),
#                 xdm.observer.action (act), xdm.event.outcome (outcome),
#                 xdm.event.outcome_reason (reason), xdm.event.id (externalId),
#                 xdm.observer.vendor / xdm.observer.product (from CEF header, auto-parsed)
#   Network:      xdm.source.ipv4 (src), xdm.source.port (spt),
#                 xdm.target.ipv4 (dst), xdm.target.port (dpt),
#                 xdm.network.application_protocol (app), xdm.network.rule (cs2),
#                 xdm.source.zone (cs3), xdm.target.zone (cs4),
#                 xdm.source.interface (deviceOutboundInterface),
#                 xdm.target.interface (deviceInboundInterface),
#                 xdm.source.sent_bytes (bytesOut), xdm.target.sent_bytes (bytesIn)
#   User:         xdm.source.user.username (suser), xdm.target.user.username (duser)
#   Alert:        xdm.alert.category (cs5), xdm.alert.severity (cefSeverity)
#   URL/App:      xdm.network.http.url (request),
#                 xdm.source.application.name (requestClientApplication)
#   File/Malware: xdm.target.file.filename (fname), xdm.target.file.md5 (fileHash),
#                 xdm.target.file.file_type (fileType)
#   Process:      xdm.source.process.pid (dvcpid, malware events only)
#
# Additional hunt-relevant fields (not in XIF model, preserved in raw dataset):
#   msg             - Human-readable event description; key field for threat hunting searches
#   cs1/cs1Label    - Access Control Policy name (connection/IPS: cs1Label="fwPolicy")
#                     AMP policy name (malware events: cs1Label="policy")
#   cs6/cs6Label    - IPS Snort rule ID (IPS events only: cs6Label="ruleId")
#   start/end       - Connection start and end times in epoch milliseconds
#   deviceDirection - Traffic direction: 1=outbound (LAN->WAN), 0=inbound (WAN->LAN for IPS)
#   cnt             - Event aggregation count; 1 for individual events
#   requestMethod   - HTTP method (GET/POST/PUT) on HTTP/HTTPS events
#   shost           - Source hostname when available from session context
#   dhost           - Destination hostname (malware domain, blocked URL, C2 domain)
#   sproc           - Source process name (malware events — process that triggered download)
#   filePath        - Full file path on the endpoint (malware events)
#   fileSize        - File size in bytes (malware events)
#
# Interface naming (Cisco FTD convention — packet-flow perspective):
#   deviceInboundInterface  = interface where ingress packet arrived  (inside for LAN→WAN)
#   deviceOutboundInterface = interface where egress packet departed  (outside for LAN→WAN)
#   XIF maps: xdm.source.interface = deviceOutboundInterface
#             xdm.target.interface = deviceInboundInterface

import random
import hashlib
import time
from datetime import datetime, timezone
from ipaddress import ip_network, AddressValueError

try:
    from modules.session_utils import (get_random_user, rand_ip_from_network,
        stable_vpn_ip, stable_mail_servers, weighted_destination)
except ImportError:
    from session_utils import (get_random_user, rand_ip_from_network,
        stable_vpn_ip, stable_mail_servers, weighted_destination)

NAME        = "Cisco Firepower"
DESCRIPTION = "Simulates Cisco FTD/FMC CEF syslog events for the XSIAM cisco_firepower_raw dataset."
XSIAM_PARSER = "cisco_firepower_raw"
CONFIG_KEY   = "firepower_config"

# Single source of truth for threat event names and their default weights.
# Used as the fallback in _generate_threat_log and by get_threat_names().
# Add new entries here when adding a new dispatch case in _generate_threat_log.
#
# analytic: True  -> event is expected to trigger an XSIAM Third-Party FW analytic
# analytic: False -> event is realistic but won't fire a dedicated XSIAM alert
# xsiam_alert:    -> name of the matching XSIAM analytics alert (or None)
_NON_ANALYTIC_PREFIX = "[Non-Analytic] "
_DEFAULT_THREAT_EVENTS = [
    {"event": "ips",                   "weight": 18, "analytic": False,
     "xsiam_alert": None},
    {"event": "malware",               "weight": 15, "analytic": False,
     "xsiam_alert": None},
    {"event": "url_filtering",         "weight": 10, "analytic": False,
     "xsiam_alert": None},
    {"event": "security_intel",        "weight": 8,  "analytic": False,
     "xsiam_alert": None},
    {"event": "port_scan",             "weight": 10, "analytic": True,
     "xsiam_alert": "Port Scan"},
    {"event": "brute_force",           "weight": 8,  "analytic": False,
     "xsiam_alert": None},
    {"event": "large_file_upload",     "weight": 6,  "analytic": True,
     "xsiam_alert": "Large Upload (HTTPS)"},
    {"event": "ssh_over_https",        "weight": 5,  "analytic": False,
     "xsiam_alert": None},
    {"event": "workstation_smb",       "weight": 4,  "analytic": True,
     "xsiam_alert": "Failed Connections"},
    {"event": "rdp_lateral",           "weight": 3,  "analytic": True,
     "xsiam_alert": "Failed Connections"},
    {"event": "tor",                   "weight": 3,  "analytic": True,
     "xsiam_alert": "Recurring access to rare IP"},
    {"event": "dns_c2_beacon",         "weight": 3,  "analytic": True,
     "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain"},
    {"event": "server_outbound_http",  "weight": 2,  "analytic": True,
     "xsiam_alert": "New Administrative Behavior"},
    {"event": "internal_smb",          "weight": 1,  "analytic": False,
     "xsiam_alert": None},
    {"event": "smb_new_host_lateral",  "weight": 4,  "analytic": True,
     "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "smb_rare_file_transfer","weight": 3,  "analytic": True,
     "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "smb_share_enumeration", "weight": 5,  "analytic": True,
     "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "vpn_brute_force",       "weight": 6,  "analytic": False,
     "xsiam_alert": None},
    {"event": "vpn_impossible_travel", "weight": 3,  "analytic": False,
     "xsiam_alert": None},
    {"event": "vpn_tor_login",         "weight": 3,  "analytic": True,
     "xsiam_alert": "Recurring access to rare IP"},
    {"event": "rare_external_rdp",     "weight": 3,  "analytic": True,
     "xsiam_alert": "Rare RDP session to a remote host"},
    {"event": "rare_ssh",              "weight": 3,  "analytic": True,
     "xsiam_alert": "Uncommon SSH session was established"},
    {"event": "smtp_spray",            "weight": 3,  "analytic": True,
     "xsiam_alert": "Spam Bot Traffic"},
    {"event": "smtp_large_exfil",      "weight": 2,  "analytic": True,
     "xsiam_alert": "Large Upload (SMTP)"},
    {"event": "ftp_large_exfil",       "weight": 2,  "analytic": True,
     "xsiam_alert": "New FTP Server"},
    {"event": "ddns_connection",       "weight": 3,  "analytic": True,
     "xsiam_alert": "Recurring rare domain access to dynamic DNS domain"},
    {"event": "app_control",           "weight": 4,  "analytic": False,
     "xsiam_alert": None},
    {"event": "network_anomaly",       "weight": 4,  "analytic": False,
     "xsiam_alert": None},
]

# --- Display-name mapping (same pattern as checkpoint_firewall.py) ---
_EVENT_DISPLAY_NAMES = {}   # event_key -> display_name
_DISPLAY_TO_EVENT    = {}   # display_name -> event_key  (reverse lookup)
for _e in _DEFAULT_THREAT_EVENTS:
    _key  = _e["event"]
    _name = _key if _e.get("analytic", True) else _NON_ANALYTIC_PREFIX + _key
    _EVENT_DISPLAY_NAMES[_key]  = _name
    _DISPLAY_TO_EVENT[_name]    = _key
    _DISPLAY_TO_EVENT[_key]     = _key      # also accept raw key for back-compat


def get_threat_names():
    """Return available threat names dynamically from _DEFAULT_THREAT_EVENTS.

    Non-analytic events (those that won't trigger an XSIAM Third-Party Firewall
    analytics detection) are prefixed with '[Non-Analytic] ' so operators can
    focus on events that will produce alerts.
    """
    return [_EVENT_DISPLAY_NAMES[e["event"]] for e in _DEFAULT_THREAT_EVENTS]


def get_threat_info():
    """Return full metadata for each threat event (name, analytic flag, XSIAM alert).

    Returns a list of dicts with keys: event, display_name, analytic, xsiam_alert, weight.
    """
    result = []
    for e in _DEFAULT_THREAT_EVENTS:
        result.append({
            "event":        e["event"],
            "display_name": _EVENT_DISPLAY_NAMES[e["event"]],
            "analytic":     e.get("analytic", True),
            "xsiam_alert":  e.get("xsiam_alert"),
            "weight":       e["weight"],
        })
    return result


# Cisco eStreamer sig_id patterns (appear as deviceEventClassId in CEF header position 4)
# Source: Cisco's official estreamer/adapters/cef.py
SIG_IDS = {
    "CONNECTION":  "RNA:1003:1",        # Connection statistics (allow / block)
    "IPS":         "INTRUSION:400:1",   # Intrusion event (generator:rendered appended)
    "MALWARE":     "FireAMP:125:1",     # AMP malware event (Record 125)
    "FILE":        "File:500:1",        # File event (non-malware)
    "URL":         "RNA:1003:1",        # URL Filtering (still a connection event in eStreamer)
    "SECINTEL":    "RNA:1003:1",        # Security Intelligence (connection event with SI fields)
}
# Keep legacy alias for any remaining references
SYSLOG_IDS = SIG_IDS

last_threat_event_time = 0

# Source process names seen in malware download and execution events
_BROWSER_PROCESSES = [
    "chrome.exe", "iexplore.exe", "firefox.exe", "msedge.exe",
    "outlook.exe", "winword.exe", "excel.exe",
]
_SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "svchost.exe",
]

# Cisco FTD built-in Intrusion Policy names (shown in cs6 on IPS events)
_IPS_POLICIES = [
    "Balanced Security and Connectivity",
    "Security Over Connectivity",
    "Connectivity Over Security",
    "Maximum Detection",
]

# URL Reputation labels used by Cisco FTD (shown in cs6 on connection/URL events)
_URL_REP_BENIGN  = ["Trustworthy", "Low Risk", "Moderate Risk"]
_URL_REP_SUSPECT = ["Suspicious", "High Risk"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_config(config):
    return config.get(CONFIG_KEY, {})


def _get_threat_interval(threat_level, config):
    """Gets the threat interval from the main config."""
    if threat_level == "Benign Traffic Only":
        return 86400 * 365
    return config.get('threat_generation_levels', {}).get(threat_level, 7200)


def _cef_escape(v):
    """Escapes a CEF extension value per ArcSight CEF spec.
    Backslash must be escaped first, then '=' and newlines."""
    s = str(v)
    s = s.replace("\\", "\\\\")
    s = s.replace("=",  "\\=")
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    return s


def _random_external_ip():
    """Realistic public (non-RFC-1918) IP for simulated external threats/attackers."""
    first_octets = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 194, 212, 213]
    return (f"{random.choice(first_octets)}."
            f"{random.randint(1, 254)}."
            f"{random.randint(1, 254)}."
            f"{random.randint(1, 254)}")


def _get_user_and_ip(config, session_context=None):
    """Returns (username, ip, hostname) for a random internal user.

    Prefers session_context via get_random_user() (same pattern as other modules);
    falls back to user_ip_map in the firepower_config block.
    """
    if session_context:
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        if user_info:
            return user_info['username'], user_info['ip'], user_info.get('hostname', user_info['ip'])

    firepower_conf = _get_config(config)
    user_ip_map = (firepower_conf.get('user_ip_map')
                   or config.get('shared_user_ip_map', {}))
    if user_ip_map:
        user, ip = random.choice(list(user_ip_map.items()))
        return user, ip, ip

    return "unknown.user", f"192.168.1.{random.randint(100, 200)}", None


def _ac_policy(config):
    """Returns the Access Control Policy name for cs1 on non-malware events."""
    return _get_config(config).get('access_control_policy', 'Default_Access_Control_Policy')


def _conn_timing(duration_ms=None):
    """Returns (start_ms, end_ms) epoch-millisecond connection timing fields.

    start/end are standard CEF fields preserved in the raw dataset.
    Duration defaults to a random short interval; callers override for long transfers.
    """
    start_ms = int(time.time() * 1000)
    if duration_ms is None:
        duration_ms = random.randint(50, 3_000)
    return start_ms, start_ms + duration_ms


def _dns_precursor_log(config, src_ip, user, dest_hostname, shost=None):
    """Generate a DNS resolution CONNECTION STATISTICS event that precedes a connection.

    Real FTD logs show a UDP/53 DNS query to an external resolver immediately
    before the TCP connection it enables.  This helper builds and formats that
    precursor so every 'conversation-complete' generator can prepend one.

    Returns a single formatted CEF string.
    """
    dns_start, dns_end = _conn_timing(random.randint(10, 200))
    fields = _base_fields(config, src_ip, user, shost)
    fields['proto'] = "17"  # UDP
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "DNS",
        "dst": random.choice(["8.8.8.8", "8.8.4.4", "1.1.1.1"]),
        "dpt": 53,
        "dhost": dest_hostname,
        "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_DNS", "cs2Label": "fwRule",
        "cs5": "Uncategorized",      "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(60, 120),
        "bytesIn":  random.randint(80, 300),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": f"DNS resolution for {dest_hostname} from {src_ip}",
        "start": dns_start, "end": dns_end,
    })
    return _format_firepower_cef(config, fields, "CONNECTION STATISTICS")


# ---------------------------------------------------------------------------
# UEBA behaviour-consistency helpers
# ---------------------------------------------------------------------------
# XSIAM UEBA builds per-user profiles by observing repeated patterns.
# These helpers ensure simulated users behave consistently across events
# so that detections like "rare login location" or "unusual destination"
# have a meaningful baseline to compare against.
# Shared helpers (stable_vpn_ip, weighted_destination) imported from session_utils.


def _format_firepower_cef(config, fields, cef_name):
    """Format a fields dict into a Cisco FTD CEF syslog string.

    CEF header: CEF:0|Cisco|Firepower|6.0|<sigId>|<cefName>|<cefSeverity>|
    Syslog PRI <13> = facility user (1<<3=8) + notice (5) = 13.
    (Cisco eStreamer default: SYSLOG_FACILITY_USER=1, SYSLOG_PRIORITY_NOTICE=5)

    XSIAM auto-parses cefDeviceVendor ("Cisco") and cefDeviceProduct ("Firepower")
    from the CEF header.  All XIF-mapped fields come from the extension string.

    The internal key '_sig_id' is popped before building the extension string
    so it appears only in the CEF header (position 4), not in extensions.
    """
    firepower_conf = _get_config(config)
    fields = dict(fields)  # work on a copy

    fields['dvchost']          = firepower_conf.get('hostname',   'Cisco-FTD')
    fields['deviceExternalId'] = firepower_conf.get('device_id', 'ftd-01')
    fields.setdefault('externalId', random.randint(100_000_000, 999_999_999))

    sig_id  = fields.pop('_sig_id', 'RNA:1003:1')
    cef_sev = str(fields.get('cefSeverity', '3'))

    # AD domain-qualify bare usernames so XSIAM Identity can stitch
    # firewall users (EXAMPLECORP\user) with cloud/SaaS users (user@examplecorp.com)
    for _ufield in ("suser", "duser"):
        _uval = fields.get(_ufield)
        if _uval and "\\" not in _uval and "@" not in _uval:
            fields[_ufield] = f"EXAMPLECORP\\{_uval}"

    timestamp  = datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')
    cef_header = f"CEF:0|Cisco|Firepower|6.0|{sig_id}|{cef_name}|{cef_sev}|"
    extension  = " ".join(f"{k}={_cef_escape(v)}" for k, v in fields.items() if v is not None)

    return f"<13>{timestamp} {fields['dvchost']} {cef_header}{extension}"


def _base_fields(config, src_ip, user, shost=None):
    """Common fields present on every Firepower event.

    XIF-mapped fields set here:
      src, spt, proto, suser, deviceInboundInterface, deviceOutboundInterface,
      cs3/cs3Label, cs4/cs4Label

    Hunt-relevant fields also set here (not in XIF, available in raw dataset):
      cnt             - Always 1 for individual (non-aggregated) events
      deviceDirection - 1=outbound (LAN→WAN); IPS events override to 0 (inbound)
      shost           - Source hostname when available from session context

    For standard outbound traffic (LAN → WAN):
      deviceInboundInterface  = inside   (packet arrives FROM LAN)
      deviceOutboundInterface = outside  (packet departs  TO  WAN)

    For inbound IPS events (WAN → LAN) callers override these two fields.
    """
    firepower_conf = _get_config(config)
    fields = {
        "src":   src_ip,
        "spt":   random.randint(49152, 65535),
        "proto": "6",
        "suser": user,
        "deviceInboundInterface":  firepower_conf.get('inbound_interface',  'inside'),
        "deviceOutboundInterface": firepower_conf.get('outbound_interface', 'outside'),
        "cs3": "User-Zone",     "cs3Label": "ingressZone",
        "cs4": "Internet-Zone", "cs4Label": "egressZone",
        # Hunt-relevant: not in XIF model but present in every real FTD CEF event
        "cnt":             1,
        "deviceDirection": 1,   # 1=outbound; override to 0 for inbound/IPS
    }
    if shost:
        fields["shost"] = shost
    return fields


# ---------------------------------------------------------------------------
# Benign event generators
# ---------------------------------------------------------------------------

def _generate_connection_event(config, src_ip, user, shost=None):
    """Standard outbound connection — web browsing (85%) or blocked suspicious port (15%).

    bytesOut = client request (small); bytesIn = server response (large for web).
    Uses _weighted_destination() so each user tends to visit the same sites,
    giving XSIAM UEBA a learnable per-user destination profile.
    """
    fields = _base_fields(config, src_ip, user, shost)
    destinations = config.get('benign_egress_destinations', [{}])
    destination = weighted_destination(user, destinations)
    try:
        dest_ip = rand_ip_from_network(ip_network(destination.get("ip_range", "8.8.8.0/24"), strict=False))
    except (AddressValueError, ValueError, IndexError):
        dest_ip = "8.8.8.8"

    start_ms, end_ms = _conn_timing(random.randint(100, 8_000))

    if random.random() > 0.15:  # 85% — outbound web browsing allowed
        dest_port  = random.choice([80, 443])
        app        = "HTTPS" if dest_port == 443 else "HTTP"
        act        = "Allow"
        rule       = "Allow_Outbound_Web"
        reason     = "Traffic Allowed"
        outcome    = "SUCCESS"
        bytes_out  = random.randint(500, 15_000)
        bytes_in   = random.randint(20_000, 500_000)
        cef_sev    = "3"
        url_rep    = random.choice(_URL_REP_BENIGN)
        msg        = f"Connection allowed by access control rule '{rule}'"
        req_method = "GET"
        user_agent = random.choice(config.get('user_agents', ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]))
    else:  # 15% — non-standard port blocked
        dest_port  = random.choice([23, 137, 138, 666, 4444, 31337])
        app        = "UNKNOWN"
        act        = "Block"
        rule       = "Block_Suspicious_Ports"
        reason     = "Access Control Rule"
        outcome    = "FAILURE"
        bytes_out  = random.randint(40, 200)
        bytes_in   = 0
        cef_sev    = "7"  # Cisco: Block → severity 7
        url_rep    = random.choice(_URL_REP_SUSPECT)
        msg        = f"Connection blocked by access control rule '{rule}'"
        req_method = None
        user_agent = None

    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": act, "app": app, "dst": dest_ip, "dpt": dest_port,
        "cs1": _ac_policy(config), "cs1Label": "fwPolicy",
        "cs2": rule,               "cs2Label": "fwRule",
        "cs6": url_rep,            "cs6Label": "URLReputation",
        "cefSeverity": cef_sev,
        "bytesOut": bytes_out, "bytesIn": bytes_in,
        "outcome": outcome, "reason": reason,
        "msg":   msg,
        "start": start_ms, "end": end_ms,
    })
    if req_method:
        fields["requestMethod"]          = req_method
        fields["requestClientApplication"] = user_agent
    return fields, "CONNECTION STATISTICS"


def _generate_internal_smb_event(config, src_ip, user, shost=None):
    """Internal file share (SMB/445) access — user to a LAN file server.

    Zone and interfaces reflect internal (LAN) traffic — no internet egress.
    """
    fields = _base_fields(config, src_ip, user, shost)
    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    # Both inbound and outbound interfaces are the inside segment
    fields['deviceInboundInterface']  = internal_iface
    fields['deviceOutboundInterface'] = internal_iface
    fields['cs3'] = "User-Zone"
    fields['cs4'] = "Server-Zone"

    server_nets = config.get('internal_networks', ['10.0.10.0/24'])
    try:
        dest_ip = rand_ip_from_network(ip_network(random.choice(server_nets)))
    except (ValueError, IndexError):
        dest_ip = "10.0.10.10"

    start_ms, end_ms = _conn_timing(random.randint(500, 30_000))

    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SMB", "dst": dest_ip, "dpt": 445,
        "duser": "FILE_SERVER_SVC",
        "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
        "cs2": "Allow_Internal_SMB", "cs2Label": "fwRule",
        "cs6": "Trustworthy",        "cs6Label": "URLReputation",
        "cefSeverity": "3",
        "bytesOut": random.randint(1_000, 500_000),
        "bytesIn":  random.randint(10_000, 5_000_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":   "Internal SMB file share access allowed",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_user_to_app_server_event(config, src_ip, user, shost=None):
    """Internal user → application server HTTPS session."""
    app_servers = config.get('internal_servers', [])
    if not app_servers:
        return None, None

    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    fields = _base_fields(config, src_ip, user, shost)
    fields['deviceInboundInterface']  = internal_iface
    fields['deviceOutboundInterface'] = internal_iface
    fields['cs3'] = "User-Zone"
    fields['cs4'] = "App-Server-Zone"

    dest_ip = random.choice(app_servers)
    start_ms, end_ms = _conn_timing(random.randint(200, 5_000))

    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "HTTPS", "dst": dest_ip, "dpt": 443,
        "duser": random.choice(config.get('service_accounts', {}).get('application', ['APP_SVC'])),
        "cs1": _ac_policy(config),    "cs1Label": "fwPolicy",
        "cs2": "Allow_Internal_Apps", "cs2Label": "fwRule",
        "cefSeverity": "3",
        "bytesOut": random.randint(1_000, 5_000),
        "bytesIn":  random.randint(5_000, 25_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "requestMethod":           "GET",
        "requestClientApplication": random.choice(
            config.get('user_agents', ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"])
        ),
        "msg":   "Internal HTTPS connection to application server allowed",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_server_to_database_event(config, src_ip):
    """App server → database connection (MSSQL/1433)."""
    db_servers = config.get('database_servers', [])
    app_accts  = config.get('service_accounts', {}).get('application', [])
    db_accts   = config.get('service_accounts', {}).get('database', [])
    if not db_servers or not app_accts or not db_accts:
        return None, None

    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    fields = _base_fields(config, src_ip, random.choice(app_accts))
    fields['deviceInboundInterface']  = internal_iface
    fields['deviceOutboundInterface'] = internal_iface
    fields['cs3'] = "App-Server-Zone"
    fields['cs4'] = "DB-Zone"

    dest_ip  = random.choice(db_servers)
    start_ms, end_ms = _conn_timing(random.randint(10, 500))

    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "MSSQL", "dst": dest_ip, "dpt": 1433,
        "duser": random.choice(db_accts),
        "cs1": _ac_policy(config), "cs1Label": "fwPolicy",
        "cs2": "Allow_App_to_DB",  "cs2Label": "fwRule",
        "cefSeverity": "3",
        "bytesOut": random.randint(5_000, 100_000),
        "bytesIn":  random.randint(50_000, 2_000_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":   "Application-to-database connection allowed",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_inbound_block_event(config):
    """Perimeter block — external host probing an internal server or FTD interface.

    Models the continuous background noise of inbound port probes and scanning that
    every internet-facing firewall blocks. These are expected baseline events (not
    active threat scenarios) matching the same pattern as ASA inbound_block and
    Checkpoint inbound_block events.

    deviceDirection=0 (inbound); zones/interfaces reversed vs. outbound events.
    """
    firepower_conf   = _get_config(config)
    attacker_ip      = _random_external_ip()
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    dest_ip          = random.choice(internal_servers)

    # Common attack-surface ports with app identification
    probe_ports = {
        22:   "SSH",
        23:   "Telnet",
        80:   "HTTP",
        443:  "HTTPS",
        445:  "SMB",
        1433: "MSSQL",
        3389: "RDP",
        8080: "HTTP",
        8443: "HTTPS",
    }
    dpt = random.choice(list(probe_ports.keys()))
    app = probe_ports[dpt]

    start_ms, end_ms = _conn_timing(random.randint(0, 50))   # blocked at first SYN

    fields = _base_fields(config, attacker_ip, "EXTERNAL_ATTACKER")
    # Inbound probe — reverse zones and interfaces
    fields['cs3']             = "Internet-Zone"
    fields['cs4']             = "Server-Zone"
    fields['deviceDirection'] = 0
    fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
    fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Block", "app": app,
        "dst": dest_ip, "dpt": dpt,
        "cs1": _ac_policy(config),      "cs1Label": "fwPolicy",
        "cs2": "Block_Inbound_Default", "cs2Label": "fwRule",
        "cs6": "Suspicious",            "cs6Label": "URLReputation",
        "cefSeverity": "7",  # Cisco: Block → severity 7
        "bytesOut": 0,
        "bytesIn":  random.randint(40, 100),
        "outcome": "FAILURE", "reason": "Access Control Rule",
        "msg":   f"Inbound connection from {attacker_ip} to port {dpt} blocked by perimeter rule",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_dns_benign_event(config, src_ip, user, shost=None):
    """Benign DNS query — internal host resolving a name via an external resolver.

    UDP/53 CONNECTION event logged by FTD for DNS traffic flowing through the firewall.
    bytesOut = DNS query (~40–100 bytes); bytesIn = DNS response (~80–400 bytes).
    Matches the DNS benign traffic generated by Checkpoint and ASA modules.
    """
    dns_resolvers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
    resolver      = random.choice(dns_resolvers)
    start_ms, end_ms = _conn_timing(random.randint(10, 200))

    fields = _base_fields(config, src_ip, user, shost)
    fields['proto'] = "17"
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "DNS",
        "dst": resolver, "dpt": 53,
        "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_DNS", "cs2Label": "fwRule",
        "cs6": "Trustworthy",        "cs6Label": "URLReputation",
        "cefSeverity": "3",
        "bytesOut": random.randint(40, 100),
        "bytesIn":  random.randint(80, 400),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":   f"DNS query to resolver {resolver}",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_email_traffic_event(config, src_ip, user, shost=None):
    """Outbound email client connection — SMTP/SMTPS/IMAPS to a corporate mail relay.

    Covers three common mail protocols:
      IMAPS/993  — client pulling mail from server (large bytesIn)
      SMTPS/465  — client submission (large bytesOut)
      SMTP/587   — mail relay submission (medium bytesOut)

    Uses stable_mail_servers() so each user connects to only 2-3 fixed relays,
    matching real enterprise behavior and avoiding XSIAM spam-bot false positives.
    """
    mail_ip = stable_mail_servers(user)
    proto_cfg  = random.choices(
        [("IMAPS", 993, "imaps"), ("SMTPS", 465, "smtps"), ("SMTP", 587, "smtp-alt")],
        weights=[50, 30, 20],
        k=1,
    )[0]
    app_name, dest_port, rule_label = proto_cfg

    start_ms, end_ms = _conn_timing(random.randint(5_000, 120_000))
    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": app_name,
        "dst": mail_ip, "dpt": dest_port,
        "cs1": _ac_policy(config),       "cs1Label": "fwPolicy",
        "cs2": f"Allow_{app_name}",      "cs2Label": "fwRule",
        "cs6": "Trustworthy",            "cs6Label": "URLReputation",
        "cefSeverity": "3",
        # IMAPS = mostly downloading (large bytesIn); SMTP* = mostly sending (large bytesOut)
        "bytesOut": random.randint(1_000, 300_000) if dest_port in (465, 587) else random.randint(500, 5_000),
        "bytesIn":  random.randint(1_000, 300_000) if dest_port == 993 else random.randint(200, 3_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":    f"Email {app_name} connection from {src_ip} to {mail_ip}:{dest_port}",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_ntp_sync_event(config, src_ip, user, shost=None):
    """NTP time synchronisation — UDP/123 to a public time server.

    Very short duration (single request/response) with tiny byte counts.
    Represents routine system clock sync from workstations and servers.
    """
    ntp_servers = ["216.239.35.0", "129.6.15.28", "132.163.96.1",
                   "17.253.52.125", "162.159.200.1", "198.60.22.240"]
    ntp_ip = random.choice(ntp_servers)
    start_ms, end_ms = _conn_timing(random.randint(5, 100))

    fields = _base_fields(config, src_ip, user, shost)
    fields['proto'] = "17"  # UDP
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "NTP",
        "dst": ntp_ip, "dpt": 123,
        "cs1": _ac_policy(config),      "cs1Label": "fwPolicy",
        "cs2": "Allow_NTP_Outbound",    "cs2Label": "fwRule",
        "cs6": "Trustworthy",           "cs6Label": "URLReputation",
        "cefSeverity": "3",
        "bytesOut": random.randint(48, 76),
        "bytesIn":  random.randint(48, 76),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":   f"NTP sync from {src_ip} to {ntp_ip}:123",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_software_update_event(config, src_ip, user, shost=None):
    """Software update download — Windows Update or AV definitions (large bytesIn).

    Represents routine patch management traffic: client sends a small HTTP GET,
    server returns a large payload (patch/definition file).
    """
    update_servers = [
        ("13.107.4.0/24",   "windowsupdate.com",      "Windows Update"),
        ("40.76.0.0/14",    "update.microsoft.com",   "Windows Update"),
        ("185.8.54.0/24",   "definitions.avast.com",  "AV Definitions"),
        ("161.69.0.0/16",   "update.nai.com",         "AV Definitions"),
        ("198.188.200.0/22","content.symantec.com",   "AV Definitions"),
    ]
    cidr, domain, update_type = random.choice(update_servers)
    server_ip  = rand_ip_from_network(ip_network(cidr, strict=False))
    # Large download, long duration
    duration_ms = random.randint(30_000, 600_000)
    start_ms, end_ms = _conn_timing(duration_ms)

    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "HTTPS",
        "dst": server_ip, "dpt": 443,
        "dhost": domain,
        "cs1": _ac_policy(config),         "cs1Label": "fwPolicy",
        "cs2": "Allow_Software_Updates",   "cs2Label": "fwRule",
        "cs6": "Trustworthy",              "cs6Label": "URLReputation",
        "cefSeverity": "3",
        "bytesOut": random.randint(300, 2_000),
        "bytesIn":  random.randint(5_000_000, 200_000_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":   f"{update_type} download from {src_ip} to {domain}",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


# --- Benign baseline generators for UEBA analytics ---
# These provide the "normal" traffic patterns that XSIAM UEBA needs to
# establish baselines.  Without benign SMB/SSH/RDP/VPN/FTP, detections
# like "Rare SMB session" or "Uncommon SSH session" have no reference
# for what is routine behaviour in this environment.

def _generate_benign_smb_event(config, src_ip, user, shost=None):
    """Benign internal SMB file access — user mapping a network drive or accessing a share.

    Routine SMB traffic to file servers establishes the XSIAM UEBA baseline
    for "Rare SMB session to a remote host" detections.
    """
    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    dest_ip = random.choice(internal_servers)
    start_ms, end_ms = _conn_timing(random.randint(500, 60_000))

    fields = _base_fields(config, src_ip, user, shost)
    fields['deviceInboundInterface']  = internal_iface
    fields['deviceOutboundInterface'] = internal_iface
    fields['cs3'] = "User-Zone"
    fields['cs4'] = "Server-Zone"
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SMB",
        "dst": dest_ip, "dpt": 445,
        "cs1": _ac_policy(config),       "cs1Label": "fwPolicy",
        "cs2": "Allow_Internal_SMB",     "cs2Label": "fwRule",
        "cs6": "Trustworthy",            "cs6Label": "URLReputation",
        "cefSeverity": "3",
        "bytesOut": random.randint(200, 10_000),
        "bytesIn":  random.randint(1_000, 100_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": f"SMB file share access from {src_ip} to {dest_ip}:445",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_benign_ssh_event(config, src_ip, user, shost=None):
    """Benign internal SSH session — admin connecting to a managed server.

    Routine SSH traffic from admin workstations to servers establishes the
    XSIAM UEBA baseline for "Uncommon SSH session" detections.
    """
    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    dest_ip = random.choice(internal_servers)
    start_ms, end_ms = _conn_timing(random.randint(30_000, 600_000))

    fields = _base_fields(config, src_ip, user, shost)
    fields['deviceInboundInterface']  = internal_iface
    fields['deviceOutboundInterface'] = internal_iface
    fields['cs3'] = "User-Zone"
    fields['cs4'] = "Server-Zone"
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SSH",
        "dst": dest_ip, "dpt": 22,
        "cs1": _ac_policy(config),       "cs1Label": "fwPolicy",
        "cs2": "Allow_Internal_SSH",     "cs2Label": "fwRule",
        "cs6": "Trustworthy",            "cs6Label": "URLReputation",
        "cefSeverity": "3",
        "bytesOut": random.randint(1_000, 20_000),
        "bytesIn":  random.randint(1_000, 20_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": f"SSH admin session from {src_ip} to {dest_ip}:22",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_benign_rdp_event(config, src_ip, user, shost=None):
    """Benign internal RDP session — admin or helpdesk accessing a server.

    Routine internal RDP traffic from admin workstations to servers establishes
    the XSIAM UEBA baseline for lateral movement RDP detections.
    """
    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    dest_ip = random.choice(internal_servers)
    start_ms, end_ms = _conn_timing(random.randint(60_000, 1_800_000))

    fields = _base_fields(config, src_ip, user, shost)
    fields['deviceInboundInterface']  = internal_iface
    fields['deviceOutboundInterface'] = internal_iface
    fields['cs3'] = "User-Zone"
    fields['cs4'] = "Server-Zone"
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "RDP",
        "dst": dest_ip, "dpt": 3389,
        "cs1": _ac_policy(config),       "cs1Label": "fwPolicy",
        "cs2": "Allow_Internal_RDP",     "cs2Label": "fwRule",
        "cs6": "Trustworthy",            "cs6Label": "URLReputation",
        "cefSeverity": "3",
        "bytesOut": random.randint(5_000, 100_000),
        "bytesIn":  random.randint(50_000, 1_000_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": f"RDP admin session from {src_ip} to {dest_ip}:3389",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_benign_vpn_event(config, src_ip, user, shost=None):
    """Benign RA-VPN session — legitimate remote worker logging in from home.

    Uses _stable_vpn_ip() so each user consistently connects from the same
    1-2 home IPs, giving XSIAM UEBA a learnable baseline for VPN anomaly
    detections (impossible travel, TOR login, rare source location).
    """
    firepower_conf = _get_config(config)
    gateway_ip     = firepower_conf.get('gateway_ip',
                         random.choice(config.get('internal_servers', ['10.0.10.1'])))
    # Stable per-user home IP (not random) so UEBA can learn normal locations
    vpn_src_ip     = stable_vpn_ip(user)
    duration_ms    = random.randint(1_800_000, 28_800_000)  # 30 min – 8 hours
    start_ms, end_ms = _conn_timing(duration_ms)

    fields = _base_fields(config, vpn_src_ip, user)
    fields['cs3']             = "Internet-Zone"
    fields['cs4']             = "VPN-Zone"
    fields['deviceDirection'] = 0
    fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
    fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SSL VPN",
        "dst": gateway_ip, "dpt": 443,
        "cs1": _ac_policy(config),        "cs1Label": "fwPolicy",
        "cs2": "VPN_Remote_Access",       "cs2Label": "fwRule",
        "cs5": "VPN Authentication",      "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(100_000, 10_000_000),
        "bytesIn":  random.randint(500_000, 50_000_000),
        "outcome": "SUCCESS", "reason": "VPN Session Established",
        "msg": f"VPN session for {user} from {vpn_src_ip}",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_benign_vpn_failure_event(config, src_ip, user, shost=None):
    """Benign VPN authentication failure — user mistyped password or expired cert.

    A real environment always has occasional benign auth failures (typos,
    expired passwords, MFA timeout).  Without these in the baseline, UEBA
    cannot distinguish a user's normal failure rate from brute-force attacks.

    Uses _stable_vpn_ip() for the same user-to-IP consistency as successful
    VPN logins.  Single failure event (not a burst like brute force).
    """
    firepower_conf = _get_config(config)
    gateway_ip     = firepower_conf.get('gateway_ip',
                         random.choice(config.get('internal_servers', ['10.0.10.1'])))
    vpn_src_ip     = stable_vpn_ip(user)
    start_ms, end_ms = _conn_timing(random.randint(500, 5_000))  # short — failed fast

    failure_reasons = [
        "VPN Authentication Failed - Invalid Credentials",
        "VPN Authentication Failed - Certificate Expired",
        "VPN Authentication Failed - MFA Timeout",
        "VPN Authentication Failed - Account Locked",
    ]

    fields = _base_fields(config, vpn_src_ip, user)
    fields['cs3']             = "Internet-Zone"
    fields['cs4']             = "VPN-Zone"
    fields['deviceDirection'] = 0
    fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
    fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Block", "app": "SSL VPN",
        "dst": gateway_ip, "dpt": 443,
        "cs1": _ac_policy(config),        "cs1Label": "fwPolicy",
        "cs2": "VPN_Remote_Access",       "cs2Label": "fwRule",
        "cs5": "VPN Authentication",      "cs5Label": "secIntelCategory",
        "cefSeverity": "5",
        "bytesOut": random.randint(200, 1_000),
        "bytesIn":  random.randint(200, 1_000),
        "outcome": "FAILURE",
        "reason": random.choice(failure_reasons),
        "msg": f"VPN auth failure for {user} from {vpn_src_ip} (benign - typo/expired)",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_benign_ftp_event(config, src_ip, user, shost=None):
    """Benign FTP session — scheduled file download from a known partner server.

    Routine FTP traffic from servers establishes the XSIAM UEBA baseline
    for "New FTP Server" detections.

    Byte ratio: bytesIn (download) >> bytesOut (control commands).
    This matches scheduled-pull patterns and contrasts with FTP exfiltration
    which has bytesOut >> bytesIn.
    """
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    server_ip        = random.choice(internal_servers)
    # Known partner FTP server (benign external destination)
    dest_ip          = _random_external_ip()
    start_ms, end_ms = _conn_timing(random.randint(10_000, 300_000))

    fields = _base_fields(config, server_ip, "SVC_FTP_TRANSFER")
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "FTP",
        "dst": dest_ip, "dpt": 21,
        "cs1": _ac_policy(config),         "cs1Label": "fwPolicy",
        "cs2": "Allow_FTP_Transfers",      "cs2Label": "fwRule",
        "cs5": "File Transfer",            "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(1_000, 50_000),          # small: FTP commands + ACKs
        "bytesIn":  random.randint(10_000, 5_000_000),      # large: downloaded file data
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": f"Scheduled FTP download from {dest_ip}:21 to {server_ip}",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_benign_log(config, session_context=None):
    """Generates a benign log from one of thirteen event categories.

    Distribution (rebalanced to include UEBA-baseline protocols):
      connection       43%  — outbound web browsing (allow 85% / block suspicious 15%)
      inbound_block    17%  — external probe blocked at perimeter (expected background noise)
      internal_tier    10%  — user -> app server -> database connection chain
      smb               5%  — internal SMB file share access (UEBA baseline)
      dns_query         5%  — outbound DNS resolution to external resolver
      email_traffic     1%  — SMTP/SMTPS/IMAPS mail client connections (low to avoid XSIAM anomaly triggers)
      ssh               4%  — internal SSH admin sessions (UEBA baseline)
      rdp               4%  — internal RDP admin sessions (UEBA baseline)
      vpn_success       3%  — RA-VPN remote worker logins (UEBA baseline)
      vpn_failure       2%  — RA-VPN auth failures: typo/expired (UEBA failure baseline)
      ntp_sync          2%  — UDP/123 NTP time synchronisation
      software_update   2%  — large HTTPS download (Windows Update / AV definitions)
      ftp               2%  — scheduled FTP file transfers (UEBA baseline)
    """
    user, src_ip, shost = _get_user_and_ip(config, session_context)
    roll = random.random()

    if roll < 0.43:  # 43% — outbound web connection
        fields, cef_name = _generate_connection_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name) if fields else None

    elif roll < 0.60:  # 17% — inbound perimeter block
        fields, cef_name = _generate_inbound_block_event(config)
        return _format_firepower_cef(config, fields, cef_name)

    elif roll < 0.70:  # 10% — internal app tier chain
        logs = []
        fields, cef_name = _generate_user_to_app_server_event(config, src_ip, user, shost)
        if fields:
            app_ip = fields.get('dst', src_ip)
            logs.append(_format_firepower_cef(config, fields, cef_name))
            db_fields, db_cef = _generate_server_to_database_event(config, app_ip)
            if db_fields:
                logs.append(_format_firepower_cef(config, db_fields, db_cef))
        return logs if logs else None

    elif roll < 0.75:  # 5% — internal SMB file share (UEBA baseline)
        fields, cef_name = _generate_benign_smb_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)

    elif roll < 0.80:  # 5% — outbound DNS query
        fields, cef_name = _generate_dns_benign_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)

    elif roll < 0.81:  # 1% — email traffic (kept low to avoid XSIAM anomaly triggers)
        fields, cef_name = _generate_email_traffic_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)

    elif roll < 0.85:  # 4% — internal SSH admin (UEBA baseline)
        fields, cef_name = _generate_benign_ssh_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)

    elif roll < 0.89:  # 4% — internal RDP admin (UEBA baseline)
        fields, cef_name = _generate_benign_rdp_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)

    elif roll < 0.92:  # 3% — RA-VPN successful login (UEBA baseline)
        fields, cef_name = _generate_benign_vpn_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)

    elif roll < 0.94:  # 2% — RA-VPN auth failure (UEBA failure baseline)
        fields, cef_name = _generate_benign_vpn_failure_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)

    elif roll < 0.96:  # 2% — NTP sync
        fields, cef_name = _generate_ntp_sync_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)

    elif roll < 0.98:  # 2% — software update download
        fields, cef_name = _generate_software_update_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)

    else:  # 2% — scheduled FTP transfer (UEBA baseline)
        fields, cef_name = _generate_benign_ftp_event(config, src_ip, user, shost)
        return _format_firepower_cef(config, fields, cef_name)


# ---------------------------------------------------------------------------
# Threat event generators
# ---------------------------------------------------------------------------

def _generate_ips_event(config):
    """Inbound IPS event — external attacker targeting an internal server.

    Primary IPS pattern: EXTERNAL source → INTERNAL server (inbound attack).
    Zones and interfaces are swapped vs. outbound events to reflect inbound flow.
    The IPS policy drops the traffic at the FTD boundary.

    Hunt fields: msg (rule + category), cs1 (policy), cs6 (IPS policy name),
                 deviceDirection=0 (inbound), start/end (near-zero duration = blocked).

    Triggers XSIAM: IPS / Intrusion Detection analytics detection.
    """
    print("    - Firepower Module simulating: IPS (inbound external -> internal server)")
    firepower_conf = _get_config(config)
    ips_rules      = firepower_conf.get('ips_rules', {})

    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    victim_ip    = random.choice(internal_servers)
    attacker_ip  = _random_external_ip()
    dest_port    = random.choice([80, 443, 445, 1433, 3389, 8080, 8443])

    if ips_rules:
        rule_name, category = random.choice(list(ips_rules.items()))
    else:
        rule_name, category = "ET-WEB-SQL-INJECTION", "Web Attack"

    ips_policy = random.choice(_IPS_POLICIES)
    start_ms, end_ms = _conn_timing(random.randint(0, 200))  # blocked nearly instantly

    fields = _base_fields(config, attacker_ip, "EXTERNAL_ATTACKER")
    # Inbound attack — reverse zones and interfaces vs. outbound traffic
    fields['cs3']            = "Internet-Zone"  # source zone = external
    fields['cs4']            = "Server-Zone"    # destination zone = internal server
    fields['deviceDirection'] = 0               # 0=inbound (override _base_fields default)
    fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
    fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')

    gen_id  = random.choice([1, 1, 1, 129])  # 1=Snort text rules, 129=preprocessor
    rule_id = random.randint(10000, 99999)
    fields.update({
        "_sig_id": f"INTRUSION:400:{gen_id}:{rule_id}",
        "act": "Blocked",
        "app": random.choice(["HTTP", "HTTPS", "SMB", "RDP"]),
        "dst": victim_ip, "dpt": dest_port,
        "cs1": _ac_policy(config), "cs1Label": "fwPolicy",
        "cs2": rule_name,          "cs2Label": "fwRule",
        "cs5": ips_policy,         "cs5Label": "ipsPolicy",
        "cs6": str(rule_id),       "cs6Label": "ruleId",
        "cat": category,
        "cefSeverity": random.choice(['7', '8', '9', '10']),
        "bytesOut": random.randint(200, 5_000),   # attacker's exploit payload
        "bytesIn":  random.randint(100, 1_000),  # partial response before IPS block
        "outcome": "FAILURE", "reason": "Intrusion Policy Violation",
        "requestClientApplication": random.choice(
            config.get('user_agents', ["python-requests/2.28.0", "curl/7.88.1"])
        ),
        "msg":   f"Intrusion Event: {rule_name} - {category}",
        "start": start_ms, "end": end_ms,
    })
    return fields, "INTRUSION EVENT"


def _generate_file_malware_event(config, src_ip, user, shost=None):
    """AMP file/malware detection — internal host downloading malware.

    Conversation-complete: DNS resolution of the malware delivery domain
    precedes the HTTP download + AMP block, matching real FTD log sequences.

    Hunt fields:
      cs1/cs1Label  = SHA256 hash (not policy — malware events use cs1 for SHA256)
      cs6/cs6Label  = DispositionSource (AMP Cloud / Threat Grid / Local)
      sproc         = source process (browser or suspicious process)
      filePath      = full path where file was written on the endpoint
      fileSize      = file size in bytes (for DLP/data volume correlation)
      dhost         = malware delivery domain (for domain-based hunting)
      requestMethod = "GET" (HTTP download)

    Uses MD5 hash for fileHash to match XIF: xdm.target.file.md5 = fileHash (32 hex chars).
    SHA256 is stored separately in cs1 — both hashes are available for hunting.

    Triggers XSIAM: Malware / File Threat analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    firepower_conf  = _get_config(config)
    malicious_files = firepower_conf.get('malicious_files', [])

    if malicious_files:
        file_info = random.choice(malicious_files)
    else:
        file_info = {"fname": "payload.exe", "fileType": "PE32", "threatname": "Trojan.Generic"}

    fname      = file_info.get("fname", "payload.exe")
    threatname = file_info.get("threatname", "Generic.Malware")
    ftype      = file_info.get("fileType", "PE32")

    # Unique seed per event ensures different hashes each time
    seed      = f"{src_ip}{time.time()}{fname}"
    file_hash = hashlib.md5(seed.encode()).hexdigest()   # 32 chars (unused, kept for compat)
    sha256    = hashlib.sha256(seed.encode()).hexdigest() # 64 chars -> fileHash (Cisco uses SHA-256)

    # Realistic file size by type
    if ftype in ("PE32", "EXE", "DLL"):
        file_size = random.randint(51_200, 10_485_760)      # 50 KB - 10 MB
    elif ftype in ("ZIP", "RAR", "7Z"):
        file_size = random.randint(1_048_576, 104_857_600)  # 1 MB - 100 MB
    else:
        file_size = random.randint(51_200, 5_242_880)       # 50 KB - 5 MB

    # Source process — browsers for drive-by downloads, suspicious for second-stage drops
    sproc = random.choice(_BROWSER_PROCESSES + _SUSPICIOUS_PROCESSES[:3])

    # File path on the endpoint
    user_dir   = user.split("@")[0] if "@" in user else user
    file_paths = [
        f"C:/Users/{user_dir}/Downloads/{fname}",
        f"C:/Users/{user_dir}/AppData/Local/Temp/{fname}",
        f"C:/Windows/Temp/{fname}",
        f"C:/ProgramData/{fname}",
    ]
    file_path  = random.choice(file_paths)

    malicious_domains = firepower_conf.get('malicious_dns_domains', ['malware-host.ru'])
    mal_domain = random.choice(malicious_domains)
    dest_ip    = _random_external_ip()

    start_ms, end_ms = _conn_timing(random.randint(1_000, 30_000))

    logs = []

    # Log 1: DNS resolution of the malware delivery domain
    logs.append(_dns_precursor_log(config, src_ip, user, mal_domain, shost))

    # Log 2: AMP malware block event
    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["MALWARE"],
        "act": "Malware Block", "app": "HTTP",
        "dst": dest_ip, "dpt": 80,
        "dhost": mal_domain,
        "fname":    fname,
        "fileHash": sha256,     # Cisco eStreamer puts SHA-256 in fileHash
        "fileType": ftype,
        "fsize": file_size,
        "filePath": file_path,
        "sproc":    sproc,
        # Malware (Record 125) cs fields per Cisco eStreamer:
        "cs1": _ac_policy(config), "cs1Label": "policy",
        "cs2": threatname,         "cs2Label": "virusName",
        "cs3": "Malware",          "cs3Label": "disposition",
        "cs4": "N/A",              "cs4Label": "speroDisposition",
        "cs5": f"Malware detected: {threatname}", "cs5Label": "eventDescription",
        "cefSeverity": "10",
        "request": f"http://{mal_domain}/{fname}",
        "requestMethod": "GET",
        "requestClientApplication": random.choice(_BROWSER_PROCESSES),
        "bytesOut": random.randint(200, 2_000),
        "bytesIn":  file_size,
        "dvcpid":   random.randint(1000, 9999),
        "outcome": "FAILURE",
        "reason":  f"File Blacklisted: {threatname}",
        "msg":     f"Malware detected: {threatname} in file {fname}",
        "start":   start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "FireAMP Event"))
    return logs


def _generate_large_file_upload_event(config, src_ip, user, shost=None):
    """Large outbound data transfer to a file-sharing service — potential exfiltration.

    Conversation-complete: DNS resolution of the file-sharing domain
    precedes the HTTPS upload, matching real FTD log sequences.

    bytesOut is 100 MB - 500 MB (client uploading a large file).
    bytesIn  is tiny (server HTTP 200 OK response).
    Duration is proportionally long (30 s - 10 min) to reflect realistic transfer speed.

    Hunt fields: dhost (upload subdomain), requestMethod (POST/PUT), cs6 (Suspicious rep),
                 msg (size summary), start/end (long session = visible in timeline hunting).

    Triggers XSIAM: Data Exfiltration / Large Upload analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    firepower_conf = _get_config(config)
    file_sharing_domains = firepower_conf.get(
        'file_sharing_domains', ['mega.nz', 'wetransfer.com', 'dropbox.com']
    )
    dest_domain = random.choice(file_sharing_domains)
    upload_host = f"upload.{dest_domain}"
    dest_ip     = _random_external_ip()
    bytes_out   = random.randint(104_857_600, 524_288_000)  # 100 MB - 500 MB
    mb_str      = f"{bytes_out // 1_048_576} MB"

    # Long duration proportional to file size (100 MB @ ~10 Mbps ~ 80 s)
    duration_ms = random.randint(30_000, 600_000)
    start_ms, end_ms = _conn_timing(duration_ms)

    upload_url = f"https://{upload_host}/upload/{random.randint(100_000, 999_999)}"

    logs = []

    # Log 1: DNS resolution of the file-sharing domain
    logs.append(_dns_precursor_log(config, src_ip, user, upload_host, shost))

    # Log 2: HTTPS upload
    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SSL",
        "dst": dest_ip, "dpt": 443,
        "dhost": upload_host,
        "request": upload_url,
        "requestMethod": random.choice(["POST", "PUT"]),
        "requestClientApplication": random.choice(
            config.get('user_agents', ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"])
        ),
        "cs1": _ac_policy(config),             "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_Web",           "cs2Label": "fwRule",
        "cs5": "File Sharing",                 "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": bytes_out,
        "bytesIn":  random.randint(1_000, 5_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":   f"Large file upload to {dest_domain}: {mb_str} transferred",
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_url_filtering_event(config, src_ip, user, shost=None):
    """URL category block — internal user requesting a prohibited domain/category.

    Hunt fields: dhost (blocked domain), requestMethod (GET), cs6 (URL reputation),
                 msg (category + URL), start/end (near-zero = blocked at first packet).

    Triggers XSIAM: URL Filtering / Policy Violation analytics detection.
    """
    firepower_conf = _get_config(config)
    blocked_urls   = firepower_conf.get('blocked_url_categories', {})

    if blocked_urls:
        cat, domain = random.choice(list(blocked_urls.items()))
    else:
        cat, domain = "Phishing", "fake-login-portal.xyz"

    # High-risk categories get "High Risk" reputation; others get generic suspicious
    if cat in ("Phishing", "Malware", "Command and Control"):
        url_rep = "High Risk"
    else:
        url_rep = random.choice(_URL_REP_SUSPECT)

    start_ms, end_ms = _conn_timing(random.randint(50, 500))  # blocked on first packet

    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["URL"],
        "act": "Block", "app": "HTTPS",
        "dst": _random_external_ip(), "dpt": 443,
        "dhost": domain,
        "request": f"https://{domain}/",
        "requestMethod": "GET",
        "requestClientApplication": random.choice(
            config.get('user_agents', ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"])
        ),
        "cs1": _ac_policy(config),     "cs1Label": "fwPolicy",
        "cs2": "Block_URL_Categories", "cs2Label": "fwRule",
        "cs5": cat,                    "cs5Label": "secIntelCategory",
        "cefSeverity": "7",  # Cisco: Block → severity 7
        "bytesOut": random.randint(200, 800),
        "bytesIn":  0,
        "outcome": "FAILURE", "reason": "URL Category Block",
        "msg":   f"URL blocked - category '{cat}': https://{domain}/",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_security_intel_event(config, src_ip, user, shost=None):
    """Security Intelligence DNS block — internal host querying a known-malicious domain.

    The FTD's Security Intelligence feed matches the domain before DNS resolution.
    Protocol is UDP/53 (DNS).

    Hunt fields: dhost (C2 domain), cs6 (feed category "DNS Block List"),
                 msg, start/end (very fast — DNS block happens in microseconds).

    Triggers XSIAM: Security Intelligence / C2 Domain analytics detection.
    """
    firepower_conf    = _get_config(config)
    malicious_domains = firepower_conf.get('malicious_dns_domains', ['c2-beacon.ru'])
    bad_domain        = random.choice(malicious_domains)

    start_ms, end_ms = _conn_timing(random.randint(0, 100))

    fields = _base_fields(config, src_ip, user, shost)
    fields['proto'] = "17"
    fields.update({
        "_sig_id": SIG_IDS["SECINTEL"],
        "act": "Block", "app": "DNS",
        "dst": "8.8.8.8", "dpt": 53,   # query destined for resolver; blocked before leaving
        "dhost": bad_domain,
        "request": bad_domain,
        "cs1": _ac_policy(config),           "cs1Label": "fwPolicy",
        "cs2": "Security_Intelligence_DNS",  "cs2Label": "fwRule",
        "cs5": "SecurityIntelligence",       "cs5Label": "secIntelCategory",
        "cefSeverity": "7",  # Cisco: Block → severity 7
        "bytesOut": random.randint(50, 150),       # DNS query bytes
        "bytesIn":  random.randint(60, 200),     # DNS NXDOMAIN/block response
        "outcome": "FAILURE", "reason": "Domain Blacklisted by Security Intelligence",
        "msg":   f"Security Intelligence: DNS request to '{bad_domain}' blocked",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_ssh_over_https_event(config, src_ip, user, shost=None):
    """SSH protocol detected on port 443 — protocol anomaly / tunnel evasion.

    Conversation-complete: DNS resolution precedes the SSH-over-443 session,
    matching real FTD log sequences.

    The connection is allowed by the web ACL rule (port 443 looks like HTTPS)
    but DPI identifies it as SSH — that mismatch is the XSIAM detection signal.

    Hunt fields: cs6 (Moderate Risk — allowed but anomalous), msg (protocol mismatch),
                 start/end (longer duration = interactive SSH session).

    Triggers XSIAM: Protocol Anomaly / SSH Evasion analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    dest_ip   = _random_external_ip()
    dest_host = f"tunnel-{dest_ip.replace('.', '-')}.example.net"
    start_ms, end_ms = _conn_timing(random.randint(5_000, 120_000))  # interactive session

    logs = []

    # Log 1: DNS resolution of the tunnel destination
    logs.append(_dns_precursor_log(config, src_ip, user, dest_host, shost))

    # Log 2: SSH tunneled over port 443
    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SSH",  # SSH on port 443 — the anomaly
        "dst": dest_ip, "dpt": 443,
        "dhost": dest_host,
        "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_Web", "cs2Label": "fwRule",
        "cs5": "Secure Shell",       "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(1_000, 50_000),
        "bytesIn":  random.randint(1_000, 50_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":   "Protocol anomaly: SSH application detected on port 443 (expected HTTPS)",
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_workstation_smb_event(config, src_ip, user, session_context=None, shost=None):
    """Blocked workstation-to-workstation SMB — lateral movement / ransomware indicator.

    Workstation-initiated SMB to another workstation is abnormal. The FTD blocks
    it via the lateral movement ACL rule. This is a key XSIAM detection pattern
    for pass-the-hash, ransomware spreading, and implant lateral movement.

    Hunt fields: cs6 (Suspicious), msg (lateral movement), start/end (near-zero = blocked).

    Triggers XSIAM: Lateral Movement / W-to-W SMB analytics detection.
    """
    # Pick a second workstation as the destination
    if session_context:
        dest_info = get_random_user(session_context, preferred_device_type='workstation')
        dest_ip   = dest_info['ip'] if dest_info and dest_info['ip'] != src_ip else None
    else:
        dest_ip = None

    if not dest_ip:
        internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
        try:
            dest_ip = rand_ip_from_network(ip_network(random.choice(internal_nets)))
        except (ValueError, IndexError):
            dest_ip = "192.168.1.101"
        if dest_ip == src_ip:
            dest_ip = "192.168.1.102"

    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    start_ms, end_ms = _conn_timing(random.randint(0, 300))

    fields = _base_fields(config, src_ip, user, shost)
    fields['deviceInboundInterface']  = internal_iface
    fields['deviceOutboundInterface'] = internal_iface
    fields['cs3'] = "User-Zone"
    fields['cs4'] = "User-Zone"  # same zone = workstation-to-workstation

    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Block", "app": "SMB", "dst": dest_ip, "dpt": 445,
        "cs1": _ac_policy(config),      "cs1Label": "fwPolicy",
        "cs2": "Block_Lateral_Movement", "cs2Label": "fwRule",
        "cs5": "Lateral Movement",       "cs5Label": "secIntelCategory",
        "cefSeverity": "7",  # Cisco: Block → severity 7
        "bytesOut": random.randint(200, 2_000),
        "bytesIn":  0,
        "outcome": "FAILURE", "reason": "Access Control Rule",
        "msg":   "Workstation-to-workstation SMB blocked: potential lateral movement",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_smb_new_host_lateral(config, src_ip, user, session_context=None, shost=None):
    """SMB connections from one workstation to multiple unfamiliar internal hosts.

    Generates 5–10 ALLOWED CONNECTION events on TCP/445, each to a DIFFERENT internal
    destination. The pattern of a single source reaching many new SMB endpoints in a
    short window is the XSIAM UEBA detection signal (lateral exploration, pass-the-hash,
    ransomware pre-encryption reconnaissance).

    Triggers XSIAM: Lateral Movement / SMB Sweep analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    print("    - Firepower Module simulating: SMB New-Host Lateral (exploring SMB on new hosts)")
    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    n_hosts        = random.randint(5, 10)

    dest_ips = set()
    if session_context:
        for _ in range(30):
            peer = get_random_user(session_context, preferred_device_type='workstation')
            if peer and peer.get('ip') and peer['ip'] != src_ip:
                dest_ips.add(peer['ip'])
            if len(dest_ips) >= n_hosts:
                break
    while len(dest_ips) < n_hosts:
        internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
        try:
            host = rand_ip_from_network(ip_network(random.choice(internal_nets), strict=False))
            if host != src_ip:
                dest_ips.add(host)
        except (ValueError, AddressValueError, IndexError):
            pass

    logs = []
    for dst_ip in list(dest_ips)[:n_hosts]:
        start_ms, end_ms = _conn_timing(random.randint(5, 120))
        fields = _base_fields(config, src_ip, user, shost)
        fields['deviceInboundInterface']  = internal_iface
        fields['deviceOutboundInterface'] = internal_iface
        fields['cs3'] = "User-Zone"
        fields['cs4'] = "User-Zone"
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Allow", "app": "SMB", "dst": dst_ip, "dpt": 445,
            "cs1": _ac_policy(config),       "cs1Label": "fwPolicy",
            "cs2": "Allow_Internal_SMB",     "cs2Label": "fwRule",
            "cs5": "Lateral Movement",       "cs5Label": "secIntelCategory",
            "cefSeverity": "3",  # Cisco: Allow → severity 3
            "bytesOut": random.randint(200, 5000),
            "bytesIn":  random.randint(2000, 50000),
            "outcome": "SUCCESS", "reason": "Access Control Rule",
            "msg": f"SMB connection to new host {dst_ip}: possible lateral movement",
            "start": start_ms, "end": end_ms,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_smb_rare_file_transfer(config, src_ip, user, shost=None):
    """Large SMB/445 session (100 MB – 1 GB) to an internal server — data staging signal.

    The anomalously large bytesIn (data read from a remote share) is the XSIAM UEBA
    detection signal. Session ALLOWED because no block rule matches — purely a
    volume-based detection (bulk read from sensitive file share).

    Returns (fields, cef_name) tuple (single-event generator).
    """
    firepower_conf   = _get_config(config)
    internal_iface   = firepower_conf.get('inbound_interface', 'inside')
    internal_servers = config.get('internal_servers', [])
    dst_ip = random.choice(
        [s for s in internal_servers if s != src_ip] or internal_servers or ['10.0.10.50']
    )
    file_size    = random.randint(104_857_600, 1_073_741_824)  # 100 MB – 1 GB
    start_ms, end_ms = _conn_timing(random.randint(120, 900))

    fields = _base_fields(config, src_ip, user, shost)
    fields['deviceInboundInterface']  = internal_iface
    fields['deviceOutboundInterface'] = internal_iface
    fields['cs3'] = "User-Zone"
    fields['cs4'] = "User-Zone"
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SMB", "dst": dst_ip, "dpt": 445,
        "cs1": _ac_policy(config),       "cs1Label": "fwPolicy",
        "cs2": "Allow_Internal_SMB",     "cs2Label": "fwRule",
        "cs5": "Data Staging",           "cs5Label": "secIntelCategory",
        "cefSeverity": "3",  # Cisco: Allow → severity 3
        "bytesOut": random.randint(1000, 50000),
        "bytesIn":  file_size,  # large read from file share = data staging
        "outcome": "SUCCESS", "reason": "Access Control Rule",
        "msg": f"Large SMB transfer ({file_size // (1024 * 1024)}MB) from {dst_ip}: possible data staging",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_smb_share_enumeration(config, src_ip, user, shost=None):
    """Rapid TCP/445 allowed connections to many different internal hosts — share scanning.

    15–40 ALLOWED CONNECTION events on SMB/445, each to a distinct internal IP.
    The connections succeed — XSIAM detects the scan from the volume of allowed SMB
    connections to new hosts, not from deny events (same principle as port_scan).
    Models a workstation probing for accessible file shares.

    Triggers XSIAM: SMB Network Scan / Port Scan analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    print("    - Firepower Module simulating: SMB Share Enumeration (scanning for open shares)")
    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    n_targets      = random.randint(15, 40)

    target_ips = set()
    while len(target_ips) < n_targets:
        internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
        try:
            host = rand_ip_from_network(ip_network(random.choice(internal_nets), strict=False))
            if host != src_ip:
                target_ips.add(host)
        except (ValueError, AddressValueError, IndexError):
            pass

    logs = []
    for dst_ip in list(target_ips)[:n_targets]:
        start_ms, end_ms = _conn_timing(random.randint(0, 100))
        fields = _base_fields(config, src_ip, user, shost)
        fields['deviceInboundInterface']  = internal_iface
        fields['deviceOutboundInterface'] = internal_iface
        fields['cs3'] = "User-Zone"
        fields['cs4'] = "User-Zone"
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Allow", "app": "SMB", "dst": dst_ip, "dpt": 445,
            "cs1": _ac_policy(config),       "cs1Label": "fwPolicy",
            "cs2": "Allow_Internal_SMB",     "cs2Label": "fwRule",
            "cs5": "Network Scan",           "cs5Label": "secIntelCategory",
            "cefSeverity": "3",  # Cisco: Allow -> severity 3
            "bytesOut": random.randint(100, 500),    # SMB negotiation + tree connect request
            "bytesIn":  random.randint(500, 5_000),  # share listing response (much larger)
            "outcome": "SUCCESS", "reason": "Access Control Rule",
            "msg": f"SMB probe allowed: {src_ip} -> {dst_ip}:445 (share enumeration)",
            "start": start_ms, "end": end_ms,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_port_scan_event(config):
    """External port scan — attacker probing sequential ports on an internal server.

    Generates 20–50 blocked CONNECTION events from the same external IP to the same
    internal server across different ports. The volume and sequential pattern is the
    XSIAM detection signal, not any individual event.

    Uses scan_target_ports from firepower_config if present (matches config.json key).
    Returns a list of CEF log strings (multi-event threat generator).
    Triggers XSIAM: Port Scan / Reconnaissance analytics detection.
    """
    print("    - Firepower Module simulating: Port Scan (external -> internal)")
    firepower_conf   = _get_config(config)
    attacker_ip      = _random_external_ip()
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    victim_ip        = random.choice(internal_servers)

    scan_ports = firepower_conf.get('scan_target_ports',
                 [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5900, 8080, 8443])
    n_ports       = random.randint(min(20, len(scan_ports)), min(50, len(scan_ports)))
    ports_to_scan = sorted(random.sample(scan_ports, n_ports))  # sorted = sequential scan pattern

    logs = []
    for dpt in ports_to_scan:
        start_ms, end_ms = _conn_timing(random.randint(0, 100))
        fields = _base_fields(config, attacker_ip, "EXTERNAL_ATTACKER")
        fields['cs3']             = "Internet-Zone"
        fields['cs4']             = "Server-Zone"
        fields['deviceDirection'] = 0
        fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
        fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Block", "app": "UNKNOWN",
            "dst": victim_ip, "dpt": dpt,
            "cs1": _ac_policy(config),      "cs1Label": "fwPolicy",
            "cs2": "Block_Inbound_Default", "cs2Label": "fwRule",
            "cs6": "Suspicious",            "cs6Label": "URLReputation",
            "cefSeverity": "7",  # Cisco: Block -> severity 7
            "bytesOut": random.randint(40, 60),   # SYN probe bytes from attacker
            "bytesIn":  random.randint(40, 60),   # RST/SYN-ACK before block
            "outcome": "FAILURE", "reason": "Access Control Rule",
            "msg":   f"Port scan blocked: {attacker_ip} probing {victim_ip}:{dpt}",
            "start": start_ms, "end": end_ms,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))

    # 1-2 open ports discovered — attacker finds live services
    open_ports = random.sample([22, 80, 443, 445, 3389, 8080, 8443], k=random.randint(1, 2))
    for dpt in open_ports:
        start_ms, end_ms = _conn_timing(random.randint(5000, 30000))
        fields = _base_fields(config, attacker_ip, "EXTERNAL_ATTACKER")
        fields['cs3']             = "Internet-Zone"
        fields['cs4']             = "Server-Zone"
        fields['deviceDirection'] = 0
        fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
        fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')
        svc_map = {22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP", 8443: "HTTPS"}
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Allow", "app": svc_map.get(dpt, "UNKNOWN"),
            "dst": victim_ip, "dpt": dpt,
            "cs1": _ac_policy(config),      "cs1Label": "fwPolicy",
            "cs2": "Allow_Inbound_Services", "cs2Label": "fwRule",
            "cs6": "Benign",                "cs6Label": "URLReputation",
            "cefSeverity": "3",
            "bytesOut": random.randint(500, 5000),
            "bytesIn":  random.randint(500, 5000),
            "outcome": "SUCCESS", "reason": "Traffic Allowed",
            "msg":   f"Port scan: {attacker_ip} connected to {victim_ip}:{dpt} (service responded)",
            "start": start_ms, "end": end_ms,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))

    return logs


def _generate_brute_force_event(config):
    """Connection-level brute force — external IP repeatedly targeting a service port.

    On FTD (unlike ASA which has AAA-specific 109001/109006 events), brute force appears
    as a high volume of blocked TCP connection attempts to the same service port from the
    same external source IP. The volume is the XSIAM detection signal.

    Targets: SSH/22, RDP/3389, SMB/445, or WinRM/5985–5986.
    Returns a list of CEF log strings (multi-event threat generator).
    Triggers XSIAM: Brute Force / Credential Stuffing analytics detection.
    """
    print("    - Firepower Module simulating: Brute Force (external -> service port)")
    firepower_conf   = _get_config(config)
    attacker_ip      = _random_external_ip()
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    victim_ip        = random.choice(internal_servers)

    target_services = {
        22:   "SSH",
        3389: "RDP",
        445:  "SMB",
        5985: "WinRM",
        5986: "WinRM",
    }
    dpt, app = random.choice(list(target_services.items()))
    n_attempts = random.randint(20, 60)

    logs = []
    for _ in range(n_attempts):
        start_ms, end_ms = _conn_timing(random.randint(10, 500))
        fields = _base_fields(config, attacker_ip, "EXTERNAL_ATTACKER")
        fields['cs3']             = "Internet-Zone"
        fields['cs4']             = "Server-Zone"
        fields['deviceDirection'] = 0
        fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
        fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Block", "app": app,
            "dst": victim_ip, "dpt": dpt,
            "cs1": _ac_policy(config),      "cs1Label": "fwPolicy",
            "cs2": "Block_Inbound_Default", "cs2Label": "fwRule",
            "cs6": "Suspicious",            "cs6Label": "URLReputation",
            "cefSeverity": "7",  # Cisco: Block -> severity 7
            "bytesOut": random.randint(100, 500),  # auth attempt payload from attacker
            "bytesIn":  random.randint(40, 200),   # reject/RST from server
            "outcome": "FAILURE", "reason": "Access Control Rule",
            "msg":   f"Brute force attempt blocked: {attacker_ip} -> {app} on {victim_ip}:{dpt}",
            "start": start_ms, "end": end_ms,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_tor_event(config, src_ip, user, shost=None):
    """Outbound connection to a known Tor exit node — anonymization / data exfiltration.

    FTD with URL filtering / App Control identifies and blocks Tor traffic.
    Tor uses port 443 (most common, evades filtering), 9001 (relay), or 9030 (directory).
    Matches the Tor connection events generated by the ASA and Checkpoint modules.

    Conversation-complete: DNS resolution of the Tor relay hostname precedes
    the outbound TCP connection, matching real FTD log sequences.

    Triggers XSIAM: Tor Network / Anonymization analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    _tor_nodes = config.get('tor_exit_nodes', [])
    dest_ip    = (random.choice(_tor_nodes).get('ip') or _random_external_ip()) if _tor_nodes else _random_external_ip()
    dpt            = random.choices([443, 9001, 9030], weights=[60, 30, 10])[0]
    tor_hostname   = f"tor-exit-{random.randint(1, 9999)}.unknown"
    start_ms, end_ms = _conn_timing(random.randint(1_000, 30_000))

    logs = []

    # Log 1: DNS resolution of the Tor relay/directory address
    logs.append(_dns_precursor_log(config, src_ip, user, tor_hostname, shost))

    # Log 2: Outbound Tor connection
    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "Tor",
        "dst": dest_ip, "dpt": dpt,
        "dhost": tor_hostname,
        "cs1": _ac_policy(config),     "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_Web",   "cs2Label": "fwRule",
        "cs5": "Tor",                  "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(10_240, 102_400),
        "bytesIn":  random.randint(51_200, 512_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":   f"Tor network connection: {src_ip} -> {dest_ip}:{dpt}",
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_server_outbound_http(config):
    """Internal server initiating anomalous outbound HTTP — potential C2 or compromise.

    Servers should not initiate web browsing. Outbound HTTP from a server IP is a
    strong anomaly signal — likely malware calling home, data exfiltration, or
    post-exploitation activity. Matches the same scenario on ASA and Checkpoint.

    Conversation-complete: DNS resolution precedes the HTTP request,
    matching real FTD log sequences.

    Triggers XSIAM: Server Outbound HTTP / Command and Control analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    print("    - Firepower Module simulating: Server Outbound HTTP (anomalous)")
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    server_ip        = random.choice(internal_servers)
    dest_ip          = _random_external_ip()
    dest_host        = f"c2-{dest_ip.replace('.', '-')}.example.com"
    start_ms, end_ms = _conn_timing(random.randint(200, 5_000))

    logs = []

    # Log 1: DNS resolution from the server (anomalous — servers use internal DNS)
    logs.append(_dns_precursor_log(config, server_ip, "SERVER_PROCESS", dest_host))

    # Log 2: Outbound HTTP connection
    fields = _base_fields(config, server_ip, "SERVER_PROCESS")
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "HTTP",
        "dst": dest_ip, "dpt": 80,
        "dhost": dest_host,
        "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_Web", "cs2Label": "fwRule",
        "cs5": "Uncategorized",      "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(200, 5_000),
        "bytesIn":  random.randint(500, 50_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "requestMethod": "GET",
        "msg":   f"Anomalous outbound HTTP from internal server {server_ip}",
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_rdp_lateral_event(config, src_ip, user, session_context=None, shost=None):
    """Internal RDP lateral movement — blocked attempts then one successful connection.

    Internal RDP is a top lateral movement vector for ransomware and hands-on-keyboard
    attackers. FTD blocks internal RDP between hosts via the lateral movement ACL rule,
    but the attacker eventually finds a host where the rule doesn't apply or pivots
    through an allowed path. The blocked-then-success pattern triggers XSIAM detection.
    Matches workstation_rdp in Checkpoint and workstation_lateral_rdp in ASA modules.

    Returns a list of CEF log strings (multi-event threat generator).
    Triggers XSIAM: Lateral Movement / RDP Lateral analytics detection.
    """
    print("    - Firepower Module simulating: RDP Lateral Movement (internal -> internal)")
    firepower_conf = _get_config(config)
    internal_iface = firepower_conf.get('inbound_interface', 'inside')

    # Pick destination: peer workstation (session_context) or fallback to server
    dest_ip = None
    if session_context and random.random() < 0.5:
        dest_info = get_random_user(session_context, preferred_device_type='workstation')
        dest_ip   = dest_info['ip'] if dest_info and dest_info['ip'] != src_ip else None

    if not dest_ip:
        servers = config.get('internal_servers', [])
        dest_ip = random.choice(servers) if servers else f"10.0.{random.randint(1, 20)}.{random.randint(10, 250)}"

    dest_zone = "Server-Zone" if dest_ip in config.get('internal_servers', []) else "User-Zone"

    logs = []

    # 3-8 blocked RDP attempts to various internal hosts
    n_blocked = random.randint(3, 8)
    for _ in range(n_blocked):
        start_ms, end_ms = _conn_timing(random.randint(0, 500))
        fields = _base_fields(config, src_ip, user, shost)
        fields['deviceInboundInterface']  = internal_iface
        fields['deviceOutboundInterface'] = internal_iface
        fields['cs3'] = "User-Zone"
        fields['cs4'] = dest_zone
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Block", "app": "RDP",
            "dst": dest_ip, "dpt": 3389,
            "cs1": _ac_policy(config),       "cs1Label": "fwPolicy",
            "cs2": "Block_Lateral_Movement", "cs2Label": "fwRule",
            "cs5": "Lateral Movement",       "cs5Label": "secIntelCategory",
            "cefSeverity": "7",
            "bytesOut": random.randint(200, 2_000),
            "bytesIn":  0,
            "outcome": "FAILURE", "reason": "Access Control Rule",
            "msg":   f"Internal RDP blocked: {src_ip} -> {dest_ip}:3389 - potential lateral movement",
            "start": start_ms, "end": end_ms,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))

    # Final successful RDP connection — attacker finds allowed path
    start_ms, end_ms = _conn_timing(random.randint(5000, 30000))
    fields = _base_fields(config, src_ip, user, shost)
    fields['deviceInboundInterface']  = internal_iface
    fields['deviceOutboundInterface'] = internal_iface
    fields['cs3'] = "User-Zone"
    fields['cs4'] = dest_zone
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "RDP",
        "dst": dest_ip, "dpt": 3389,
        "cs1": _ac_policy(config),       "cs1Label": "fwPolicy",
        "cs2": "Allow_Internal_Admin",   "cs2Label": "fwRule",
        "cs5": "Lateral Movement",       "cs5Label": "secIntelCategory",
        "cefSeverity": "5",
        "bytesOut": random.randint(5_000, 50_000),
        "bytesIn":  random.randint(5_000, 50_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg":   f"Internal RDP allowed: {src_ip} -> {dest_ip}:3389 - lateral movement succeeded",
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))

    return logs


def _generate_dns_c2_beacon(config, src_ip, user, shost=None):
    """DNS-based C2 beaconing — compromised host making many DNS queries to suspicious resolver.

    Unlike _generate_security_intel_event (single block on a known-bad domain), this models
    the VOLUME pattern: many allowed DNS queries to an external resolver on a regular cadence.
    The resolver IP isn't on a block list so FTD allows it; XSIAM detects the volume/regularity.
    Matches dns_c2_beacon on both ASA and Checkpoint modules.

    Returns a list of CEF log strings (multi-event threat generator).
    Triggers XSIAM: DNS C2 Beaconing / High-Volume DNS analytics detection.
    """
    print("    - Firepower Module simulating: DNS C2 Beacon (volume pattern)")
    c2_resolver = _random_external_ip()   # suspicious external resolver (not on block list)
    n_queries   = random.randint(15, 40)
    base_ms     = int(time.time() * 1000)

    logs = []
    for i in range(n_queries):
        query_start = base_ms + (i * random.randint(2_000, 15_000))
        query_end   = query_start + random.randint(50, 200)
        fields = _base_fields(config, src_ip, user, shost)
        fields['proto'] = "17"
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Allow", "app": "DNS",
            "dst": c2_resolver, "dpt": 53,
            "dhost": c2_resolver,
            "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
            "cs2": "Allow_Outbound_DNS", "cs2Label": "fwRule",
            "cs5": "Uncategorized",      "cs5Label": "secIntelCategory",
            "cefSeverity": "3",  # Cisco: Allow → severity 3
            "bytesOut": random.randint(40, 100),
            "bytesIn":  random.randint(60, 200),
            "outcome": "SUCCESS", "reason": "Traffic Allowed",
            "msg":   f"DNS query to suspicious resolver {c2_resolver}: potential C2 beacon",
            "start": query_start, "end": query_end,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


# ---------------------------------------------------------------------------
# VPN, SMTP, FTP, DDNS, App Control, Network Anomaly event generators
# ---------------------------------------------------------------------------

def _generate_vpn_brute_force(config, src_ip, user, shost=None):
    """VPN credential-stuffing attack — external IP repeatedly failing RA-VPN auth.

    Cisco FTD RA-VPN authentication events appear as connection events on port 443
    to the FTD outside interface. Failed attempts are blocked with reason
    "VPN Authentication Failed". Generates 20-50 failed connection events.

    Triggers XSIAM: Brute Force / Credential Scan analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    print("    - Firepower Module simulating: VPN Brute Force from external attacker")
    firepower_conf = _get_config(config)
    attacker_ip    = _random_external_ip()
    gateway_ip     = firepower_conf.get('gateway_ip',
                         random.choice(config.get('internal_servers', ['10.0.10.1'])))
    n_attempts     = random.randint(20, 50)

    logs = []
    for i in range(n_attempts):
        start_ms, end_ms = _conn_timing(random.randint(100, 2_000))
        fields = _base_fields(config, attacker_ip, "EXTERNAL_ATTACKER")
        fields['cs3']             = "Internet-Zone"
        fields['cs4']             = "VPN-Zone"
        fields['deviceDirection'] = 0
        fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
        fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Block", "app": "SSL VPN",
            "dst": gateway_ip, "dpt": 443,
            "cs1": _ac_policy(config),        "cs1Label": "fwPolicy",
            "cs2": "VPN_Remote_Access",       "cs2Label": "fwRule",
            "cs5": "VPN Authentication",      "cs5Label": "secIntelCategory",
            "cefSeverity": "7",
            "bytesOut": random.randint(200, 800),
            "bytesIn":  random.randint(100, 400),
            "outcome": "FAILURE", "reason": "VPN Authentication Failed",
            "msg": f"VPN authentication failed from {attacker_ip} (attempt {i + 1})",
            "start": start_ms, "end": end_ms,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_vpn_impossible_travel(config, src_ip, user, shost=None):
    """Impossible travel: same user VPN sessions from geographically distant IPs.

    Generates two allowed VPN connection events from the same user -- the legitimate
    session is back-dated 5-10 minutes. XSIAM detects two authentications from
    different geolocations within a time window that makes physical travel impossible.

    Triggers XSIAM: Impossible Travel / Anomalous VPN Location analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Firepower Module simulating: VPN Impossible Travel for {user}")
    firepower_conf = _get_config(config)
    gateway_ip     = firepower_conf.get('gateway_ip',
                         random.choice(config.get('internal_servers', ['10.0.10.1'])))

    benign_loc     = config.get('impossible_travel_scenario', {}).get('benign_location', {})
    suspicious_loc = config.get('impossible_travel_scenario', {}).get('suspicious_location', {})
    benign_ip      = benign_loc.get('ip',    '68.185.12.14')
    suspicious_ip  = suspicious_loc.get('ip', '175.45.176.10')

    gap_minutes    = random.randint(5, 10)
    gap_ms         = gap_minutes * 60 * 1000

    logs = []
    for vpn_src_ip, label, time_offset in [
        (benign_ip,     'home-office',        -gap_ms),
        (suspicious_ip, 'suspicious-foreign',  0),
    ]:
        duration_ms = random.randint(60_000, 300_000)
        start_ms    = int(time.time() * 1000) + time_offset
        end_ms      = start_ms + duration_ms
        bytes_out   = random.randint(50_000, 500_000)
        bytes_in    = random.randint(100_000, 2_000_000)

        fields = _base_fields(config, vpn_src_ip, user, shost if label == 'home-office' else None)
        fields['cs3']             = "Internet-Zone"
        fields['cs4']             = "VPN-Zone"
        fields['deviceDirection'] = 0
        fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
        fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Allow", "app": "SSL VPN",
            "dst": gateway_ip, "dpt": 443,
            "cs1": _ac_policy(config),        "cs1Label": "fwPolicy",
            "cs2": "VPN_Remote_Access",       "cs2Label": "fwRule",
            "cs5": "VPN Authentication",      "cs5Label": "secIntelCategory",
            "cefSeverity": "3",
            "bytesOut": bytes_out,
            "bytesIn":  bytes_in,
            "outcome": "SUCCESS", "reason": "VPN Session Established",
            "msg": (f"VPN session for {user} from {vpn_src_ip} ({label}) - "
                    f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in"),
            "start": start_ms, "end": end_ms,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_vpn_tor_login(config, src_ip, user, shost=None):
    """Successful RA-VPN session from a known TOR exit node IP.

    Valid corporate credentials authenticated via TOR -- credential theft
    or deliberate anonymisation.

    Conversation-complete — three phases matching real FTD log sequences:
      1. Inbound TLS handshake: Tor IP -> outside:443 (short, small bytes)
      2. VPN auth success: SSL VPN session established (the primary detection event)
      3. Post-auth internal activity: 1-3 connections from VPN-assigned inside IP
         to internal servers (SMB, RDP, HTTPS — what the attacker does after login)

    Triggers XSIAM: Suspicious VPN Login / TOR-based Access analytics detection.
    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Firepower Module simulating: VPN Login from TOR Exit Node for {user}")
    firepower_conf = _get_config(config)
    gateway_ip     = firepower_conf.get('gateway_ip',
                         random.choice(config.get('internal_servers', ['10.0.10.1'])))
    tor_nodes      = config.get('tor_exit_nodes', [])
    tor_ip         = (random.choice(tor_nodes).get('ip', _random_external_ip())
                      if tor_nodes else _random_external_ip())
    internal_iface = firepower_conf.get('inbound_interface', 'inside')
    outside_iface  = firepower_conf.get('outbound_interface', 'outside')

    # VPN-assigned inside IP (typical Cisco AnyConnect pool: 10.250.x.x)
    vpn_pool_net   = firepower_conf.get('vpn_pool', '10.250.0.0/16')
    try:
        vpn_inside_ip = rand_ip_from_network(ip_network(vpn_pool_net, strict=False))
    except (ValueError, AddressValueError):
        vpn_inside_ip = f"10.250.{random.randint(1, 254)}.{random.randint(1, 254)}"

    logs = []

    # --- Log 1: Inbound TLS handshake (Tor IP -> gateway outside:443) ---
    tls_start, tls_end = _conn_timing(random.randint(500, 3_000))
    tls_fields = _base_fields(config, tor_ip, user)
    tls_fields['cs3']             = "Internet-Zone"
    tls_fields['cs4']             = "VPN-Zone"
    tls_fields['deviceDirection'] = 0
    tls_fields['deviceInboundInterface']  = outside_iface
    tls_fields['deviceOutboundInterface'] = internal_iface
    tls_fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SSL",
        "dst": gateway_ip, "dpt": 443,
        "cs1": _ac_policy(config),        "cs1Label": "fwPolicy",
        "cs2": "VPN_Remote_Access",       "cs2Label": "fwRule",
        "cs5": "Tor",                     "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(500, 3_000),   # TLS Client Hello + handshake
        "bytesIn":  random.randint(1_000, 5_000), # TLS Server Hello + cert
        "outcome": "SUCCESS", "reason": "TLS Handshake",
        "msg": f"Inbound TLS handshake from TOR exit {tor_ip} to VPN gateway {gateway_ip}:443",
        "start": tls_start, "end": tls_end,
    })
    logs.append(_format_firepower_cef(config, tls_fields, "CONNECTION STATISTICS"))

    # --- Log 2: VPN auth success (the primary detection event) ---
    duration_ms = random.randint(300_000, 7_200_000)
    start_ms, end_ms = _conn_timing(duration_ms)
    bytes_out = random.randint(50_000, 2_000_000)
    bytes_in  = random.randint(100_000, 5_000_000)

    vpn_fields = _base_fields(config, tor_ip, user)
    vpn_fields['cs3']             = "Internet-Zone"
    vpn_fields['cs4']             = "VPN-Zone"
    vpn_fields['deviceDirection'] = 0
    vpn_fields['deviceInboundInterface']  = outside_iface
    vpn_fields['deviceOutboundInterface'] = internal_iface
    vpn_fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SSL VPN",
        "dst": gateway_ip, "dpt": 443,
        "cs1": _ac_policy(config),        "cs1Label": "fwPolicy",
        "cs2": "VPN_Remote_Access",       "cs2Label": "fwRule",
        "cs5": "Tor",                     "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": bytes_out,
        "bytesIn":  bytes_in,
        "outcome": "SUCCESS", "reason": "VPN Session Established",
        "msg": (f"VPN session for {user} from TOR exit node {tor_ip} - "
                f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in"),
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, vpn_fields, "CONNECTION STATISTICS"))

    # --- Logs 3-5: Post-auth internal activity from the VPN-assigned IP ---
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    post_auth_actions = [
        {"app": "SMB",   "dpt": 445,  "rule": "Allow_Internal_SMB",
         "cat": "Lateral Movement", "desc": "SMB file share access"},
        {"app": "RDP",   "dpt": 3389, "rule": "Allow_Internal_RDP",
         "cat": "Remote Access",    "desc": "RDP to internal server"},
        {"app": "HTTPS", "dpt": 443,  "rule": "Allow_Internal_Web",
         "cat": "Internal Web",     "desc": "internal web application access"},
        {"app": "SSH",   "dpt": 22,   "rule": "Allow_Internal_SSH",
         "cat": "Secure Shell",     "desc": "SSH to internal server"},
    ]
    n_post_auth = random.randint(1, 3)
    chosen_actions = random.sample(post_auth_actions, min(n_post_auth, len(post_auth_actions)))

    for action in chosen_actions:
        target_ip = random.choice(internal_servers)
        pa_start, pa_end = _conn_timing(random.randint(5_000, 300_000))
        pa_fields = _base_fields(config, vpn_inside_ip, user)
        # Post-auth traffic is inside-to-inside (VPN pool -> internal server)
        pa_fields['deviceInboundInterface']  = internal_iface
        pa_fields['deviceOutboundInterface'] = internal_iface
        pa_fields['cs3'] = "VPN-Zone"
        pa_fields['cs4'] = "Server-Zone"
        pa_fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Allow", "app": action["app"],
            "dst": target_ip, "dpt": action["dpt"],
            "cs1": _ac_policy(config),  "cs1Label": "fwPolicy",
            "cs2": action["rule"],      "cs2Label": "fwRule",
            "cs5": action["cat"],       "cs5Label": "secIntelCategory",
            "cefSeverity": "3",
            "bytesOut": random.randint(500, 50_000),
            "bytesIn":  random.randint(1_000, 200_000),
            "outcome": "SUCCESS", "reason": "Traffic Allowed",
            "msg": (f"Post-VPN {action['desc']} from {vpn_inside_ip} "
                    f"(VPN user {user}) to {target_ip}:{action['dpt']}"),
            "start": pa_start, "end": pa_end,
        })
        logs.append(_format_firepower_cef(config, pa_fields, "CONNECTION STATISTICS"))

    return logs


def _generate_rare_external_rdp(config, src_ip, user, shost=None):
    """Outbound RDP from internal workstation to a rare external IP.

    Internal workstations initiating RDP to external public IPs is a high-fidelity
    indicator: reverse RDP tunnels, C2 via RDP, or compromised endpoint pivoting.

    Conversation-complete: DNS resolution precedes the RDP session,
    matching real FTD log sequences.

    Triggers XSIAM: outbound RDP to rare/unusual external destination.
    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Firepower Module simulating: Rare External RDP from {src_ip}")
    dest_ip     = _random_external_ip()
    dest_host   = f"rdp-{dest_ip.replace('.', '-')}.example.net"
    duration_ms = random.randint(60_000, 1_800_000)
    start_ms, end_ms = _conn_timing(duration_ms)
    bytes_out = random.randint(10_000, 200_000)
    bytes_in  = random.randint(50_000, 2_000_000)

    logs = []

    # Log 1: DNS resolution of the RDP destination
    logs.append(_dns_precursor_log(config, src_ip, user, dest_host, shost))

    # Log 2: Outbound RDP connection
    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "RDP",
        "dst": dest_ip, "dpt": 3389,
        "dhost": dest_host,
        "cs1": _ac_policy(config),     "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_Web",   "cs2Label": "fwRule",
        "cs5": "Remote Access",        "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": bytes_out,
        "bytesIn":  bytes_in,
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": (f"Outbound RDP from {src_ip} to external {dest_ip}:3389 - "
                f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in"),
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_rare_ssh(config, src_ip, user, shost=None):
    """Outbound SSH to a rare (first-seen) external IP.

    Conversation-complete: DNS resolution precedes the SSH session,
    matching real FTD log sequences.

    Triggers XSIAM: outbound SSH to rare external destination.
    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Firepower Module simulating: Rare External SSH from {src_ip}")
    dest_ip      = _random_external_ip()
    dest_host    = f"ssh-{dest_ip.replace('.', '-')}.example.net"
    duration_ms  = random.randint(30_000, 600_000)
    start_ms, end_ms = _conn_timing(duration_ms)

    logs = []

    # Log 1: DNS resolution of the SSH destination
    logs.append(_dns_precursor_log(config, src_ip, user, dest_host, shost))

    # Log 2: Outbound SSH connection
    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SSH",
        "dst": dest_ip, "dpt": 22,
        "dhost": dest_host,
        "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_Web", "cs2Label": "fwRule",
        "cs5": "Secure Shell",       "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(1_000, 50_000),
        "bytesIn":  random.randint(1_000, 50_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": f"SSH from {src_ip} to rare external IP {dest_ip}:22",
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_smtp_spray(config, src_ip, user, shost=None):
    """Compromised workstation acting as spam bot -- direct SMTP to many external MX.

    Generates 30-50 short SMTP connection events from one internal workstation to
    DISTINCT external IPs on port 25 or 587. Workstations never connect directly
    to external MX servers in normal operations.

    Triggers XSIAM: anomalous SMTP from workstation / spam bot analytics.
    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Firepower Module simulating: SMTP Spray (spam bot) from {src_ip}")
    n_targets = random.randint(30, 50)
    dest_ips  = set()
    while len(dest_ips) < n_targets:
        dest_ips.add(_random_external_ip())

    logs = []
    for dst_ip in list(dest_ips)[:n_targets]:
        smtp_port   = random.choices([25, 587], weights=[70, 30], k=1)[0]
        duration_ms = random.randint(1_000, 30_000)
        start_ms, end_ms = _conn_timing(duration_ms)
        bytes_out = random.randint(2_000, 50_000)
        bytes_in  = random.randint(200, 2_000)

        fields = _base_fields(config, src_ip, user, shost)
        fields.update({
            "_sig_id": SIG_IDS["CONNECTION"],
            "act": "Allow", "app": "SMTP",
            "dst": dst_ip, "dpt": smtp_port,
            "cs1": _ac_policy(config),     "cs1Label": "fwPolicy",
            "cs2": "Allow_Outbound_Web",   "cs2Label": "fwRule",
            "cs5": "Email",                "cs5Label": "secIntelCategory",
            "cefSeverity": "3",
            "bytesOut": bytes_out,
            "bytesIn":  bytes_in,
            "outcome": "SUCCESS", "reason": "Traffic Allowed",
            "msg": f"Direct SMTP from workstation {src_ip} to external {dst_ip}:{smtp_port} - {bytes_out}B out",
            "start": start_ms, "end": end_ms,
        })
        logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_smtp_large_exfil(config, src_ip, user, shost=None):
    """Data exfiltration via large email attachment over SMTP.

    Conversation-complete: DNS MX lookup precedes the SMTP session,
    matching real FTD log sequences.

    Single long-duration SMTP/587 session with 100-500 MB outbound bytes.
    Normal attachments rarely exceed 25 MB.

    Triggers XSIAM: large outbound SMTP data transfer / email exfiltration analytics.
    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Firepower Module simulating: Large SMTP Exfiltration from {src_ip}")
    mail_mx_ranges = [
        "74.125.0.0/16", "40.76.0.0/14", "207.46.0.0/16",
        "198.2.128.0/18", "159.148.0.0/16",
    ]
    try:
        dest_ip = rand_ip_from_network(
            ip_network(random.choice(mail_mx_ranges), strict=False))
    except Exception:
        dest_ip = _random_external_ip()

    mx_domain   = random.choice(["smtp.gmail.com", "smtp.outlook.com", "smtp.mail.yahoo.com",
                                  "smtp.protonmail.ch", "mail.external-partner.com"])
    smtp_port   = random.choices([587, 25], weights=[80, 20], k=1)[0]
    duration_ms = random.randint(300_000, 1_200_000)
    start_ms, end_ms = _conn_timing(duration_ms)
    bytes_out = random.randint(104_857_600, 524_288_000)  # 100 MB - 500 MB
    bytes_in  = random.randint(500, 5_000)

    logs = []

    # Log 1: DNS/MX lookup for the mail server
    logs.append(_dns_precursor_log(config, src_ip, user, mx_domain, shost))

    # Log 2: SMTP session
    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SMTP",
        "dst": dest_ip, "dpt": smtp_port,
        "dhost": mx_domain,
        "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
        "cs2": "Allow_SMTP_Relay",   "cs2Label": "fwRule",
        "cs5": "Email",              "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": bytes_out,
        "bytesIn":  bytes_in,
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": f"Large SMTP from {src_ip} to {dest_ip}:{smtp_port} - {bytes_out // (1024 * 1024)}MB outbound",
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_ftp_large_exfil(config, src_ip, user, shost=None):
    """Data exfiltration via outbound FTP from an internal workstation.

    Conversation-complete: DNS resolution precedes the FTP session,
    matching real FTD log sequences.

    Single long-duration FTP session with 100-500 MB outbound bytes.
    FTP is rarely used in modern enterprises; this volume is a strong exfil signal.

    Triggers XSIAM: outbound FTP large data transfer / exfiltration analytics.
    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Firepower Module simulating: Large FTP Exfiltration from {src_ip}")
    dest_ip     = _random_external_ip()
    dest_host   = f"ftp-{dest_ip.replace('.', '-')}.example.net"
    duration_ms = random.randint(300_000, 1_800_000)
    start_ms, end_ms = _conn_timing(duration_ms)
    bytes_out = random.randint(104_857_600, 524_288_000)  # 100 MB - 500 MB
    bytes_in  = random.randint(500, 10_000)

    logs = []

    # Log 1: DNS resolution of the FTP destination
    logs.append(_dns_precursor_log(config, src_ip, user, dest_host, shost))

    # Log 2: FTP session
    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "FTP",
        "dst": dest_ip, "dpt": 21,
        "dhost": dest_host,
        "cs1": _ac_policy(config),     "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_Web",   "cs2Label": "fwRule",
        "cs5": "File Transfer",        "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": bytes_out,
        "bytesIn":  bytes_in,
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": f"Outbound FTP from {src_ip} to {dest_ip}:21 - {bytes_out // (1024 * 1024)}MB outbound",
        "start": start_ms, "end": end_ms,
    })
    logs.append(_format_firepower_cef(config, fields, "CONNECTION STATISTICS"))
    return logs


def _generate_ddns_connection(config, src_ip, user, shost=None):
    """Internal workstation connecting to a known dynamic DNS domain.

    Generates two logs: DNS query resolving the DDNS hostname, then an HTTPS
    session to the resolved IP. DDNS services are commonly used for cheap C2.

    Triggers XSIAM: connection to dynamic DNS domain / suspicious C2 infrastructure.
    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Firepower Module simulating: Dynamic DNS Connection from {src_ip}")

    ddns_providers = [
        "duckdns.org", "no-ip.com", "dynu.com", "afraid.org",
        "hopto.org", "zapto.org", "sytes.net", "ddns.net",
        "servebeer.com", "myftp.biz", "myvnc.com", "redirectme.net",
    ]
    provider  = random.choice(ddns_providers)
    subdomain = random.choice([
        "update-service", "cdn-relay", "mail-check", "vpn-gateway",
        "api-health", "sync-node", "cloud-backup", "office-proxy",
    ])
    ddns_hostname = f"{subdomain}.{provider}"
    resolved_ip   = _random_external_ip()

    logs = []

    # Log 1: DNS query resolving the DDNS hostname
    dns_start, dns_end = _conn_timing(random.randint(10, 200))
    dns_fields = _base_fields(config, src_ip, user, shost)
    dns_fields['proto'] = "17"
    dns_fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "DNS",
        "dst": "8.8.8.8", "dpt": 53,
        "dhost": ddns_hostname,
        "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_DNS", "cs2Label": "fwRule",
        "cs5": "Uncategorized",      "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(60, 120),
        "bytesIn":  random.randint(80, 300),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": f"DNS query for DDNS hostname {ddns_hostname} from {src_ip}",
        "start": dns_start, "end": dns_end,
    })
    logs.append(_format_firepower_cef(config, dns_fields, "CONNECTION STATISTICS"))

    # Log 2: HTTPS session to the resolved DDNS IP
    duration_ms = random.randint(30_000, 600_000)
    https_start, https_end = _conn_timing(duration_ms)
    https_fields = _base_fields(config, src_ip, user, shost)
    https_fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Allow", "app": "SSL",
        "dst": resolved_ip, "dpt": 443,
        "dhost": ddns_hostname,
        "cs1": _ac_policy(config),     "cs1Label": "fwPolicy",
        "cs2": "Allow_Outbound_Web",   "cs2Label": "fwRule",
        "cs5": "Dynamic DNS",          "cs5Label": "secIntelCategory",
        "cefSeverity": "3",
        "bytesOut": random.randint(1_000, 100_000),
        "bytesIn":  random.randint(5_000, 500_000),
        "outcome": "SUCCESS", "reason": "Traffic Allowed",
        "msg": (f"HTTPS from {src_ip} to DDNS host {ddns_hostname} "
                f"({resolved_ip}:443)"),
        "start": https_start, "end": https_end,
    })
    logs.append(_format_firepower_cef(config, https_fields, "CONNECTION STATISTICS"))
    return logs


def _generate_app_control(config, src_ip, user, shost=None):
    """Application Control block -- FTD identifies and blocks prohibited applications.

    DPI identifies applications regardless of port. Prohibited apps (P2P, anonymizers,
    gaming, unauthorized remote access) are blocked by Application Control policy.

    Triggers XSIAM: Application Control / prohibited application analytics.
    """
    print(f"    - Firepower Module simulating: App Control Block from {src_ip}")
    dest_ip = _random_external_ip()

    blocked_apps = [
        ("BitTorrent",     "Peer-to-Peer",      6881),
        ("Tor Browser",    "Anonymizer",         9001),
        ("TeamViewer",     "Remote Access",      5938),
        ("Skype",          "VoIP",               443),
        ("Dropbox",        "File Storage",       443),
        ("WhatsApp",       "Instant Messaging",  443),
        ("uTorrent",       "Peer-to-Peer",       6881),
        ("Freenet",        "Anonymizer",         9481),
        ("I2P",            "Anonymizer",         4444),
        ("Steam",          "Gaming",             27036),
        ("Psiphon",        "Anonymizer",         443),
        ("Remote Desktop", "Remote Access",      3389),
    ]
    app_name, app_category, dport = random.choice(blocked_apps)
    start_ms, end_ms = _conn_timing(random.randint(0, 500))

    fields = _base_fields(config, src_ip, user, shost)
    fields.update({
        "_sig_id": SIG_IDS["CONNECTION"],
        "act": "Block", "app": app_name,
        "dst": dest_ip, "dpt": dport,
        "cs1": _ac_policy(config),                  "cs1Label": "fwPolicy",
        "cs2": "Block_Unauthorized_Applications",   "cs2Label": "fwRule",
        "cs5": app_category,                        "cs5Label": "secIntelCategory",
        "cefSeverity": "7",
        "bytesOut": random.randint(100, 1_000),
        "bytesIn":  0,
        "outcome": "FAILURE", "reason": "Application Policy Violation",
        "msg": f"App Control block: {app_name} ({app_category}) from {src_ip}",
        "start": start_ms, "end": end_ms,
    })
    return fields, "CONNECTION STATISTICS"


def _generate_network_anomaly(config):
    """Network-level anomaly/DoS detection -- Cisco FTD Threat Defense drops.

    Models protocol anomalies, malformed packets, and volume-based attacks
    detected by the FTD's network analysis engine before the application layer.

    Triggers XSIAM: Network Anomaly / DoS analytics detection.
    """
    print("    - Firepower Module simulating: Network Anomaly/DoS")
    firepower_conf = _get_config(config)
    attacker_ip    = _random_external_ip()
    victim_ip      = random.choice(config.get('internal_servers', ['10.0.10.50']))

    protections = [
        ("SYN Flood",             "Consecutive SYN packets without completing handshake", "6",  80),
        ("IP Spoofing",           "Source IP address spoofing detected",                  "6",  443),
        ("TCP NULL Scan",         "TCP segment with no flags set",                        "6",  22),
        ("FIN Scan",              "TCP FIN without prior SYN/ACK",                        "6",  22),
        ("Xmas Scan",             "TCP segment with FIN/PSH/URG flags",                   "6",  22),
        ("DNS Protocol Anomaly",  "Malformed DNS query structure",                        "17", 53),
        ("HTTP Protocol Anomaly", "HTTP request violates RFC compliance checks",          "6",  80),
        ("ICMP Flood",            "ICMP echo request rate exceeds threshold",             "1",  0),
        ("Fragmentation Attack",  "Overlapping fragmented IP packets",                    "17", 0),
        ("Connection Rate Limit", "Connection rate from source exceeds threshold",        "6",  443),
    ]

    protection_name, description, proto_num, dport = random.choice(protections)
    if dport == 0:
        dport = random.choice([22, 80, 443, 445])
    start_ms, end_ms = _conn_timing(random.randint(0, 100))

    gen_id  = 129   # preprocessor
    rule_id = random.randint(1, 999)
    fields = _base_fields(config, attacker_ip, "EXTERNAL_ATTACKER")
    fields['cs3']             = "Internet-Zone"
    fields['cs4']             = "Server-Zone"
    fields['deviceDirection'] = 0
    fields['proto']           = proto_num
    fields['deviceInboundInterface']  = firepower_conf.get('outbound_interface', 'outside')
    fields['deviceOutboundInterface'] = firepower_conf.get('inbound_interface',  'inside')
    fields.update({
        "_sig_id": f"INTRUSION:400:{gen_id}:{rule_id}",
        "act": "Blocked", "app": "UNKNOWN",
        "dst": victim_ip, "dpt": dport,
        "cs1": _ac_policy(config),  "cs1Label": "fwPolicy",
        "cs2": protection_name,     "cs2Label": "fwRule",
        "cs5": random.choice(_IPS_POLICIES), "cs5Label": "ipsPolicy",
        "cs6": str(rule_id),        "cs6Label": "ruleId",
        "cat": "Network Anomaly",
        "cefSeverity": random.choice(["7", "8", "9"]),
        "bytesOut": random.randint(40, 200),
        "bytesIn":  random.randint(40, 200),
        "outcome": "FAILURE", "reason": "Network Analysis Policy",
        "msg": f"Network anomaly: {protection_name} from {attacker_ip} to {victim_ip} - {description}",
        "start": start_ms, "end": end_ms,
    })
    return fields, "INTRUSION EVENT"


# ---------------------------------------------------------------------------
# Scenario log generator
# ---------------------------------------------------------------------------

def _generate_scenario_log(config, scenario, session_context=None):
    """Generates a log for a scripted storytelling / coordinated scenario."""
    print(f"    - Firepower Module creating scenario log: {scenario.get('name', 'Unknown')}")
    user, src_ip, shost = _get_user_and_ip(config, session_context)
    start_ms, end_ms    = _conn_timing()

    fields = {
        "src":   scenario.get('source_ip', src_ip),
        "dst":   scenario.get('dest_ip', '1.2.3.4'),
        "spt":   random.randint(49152, 65535),
        "dpt":   scenario.get('dest_port', 443),
        "proto": "6",
        "suser": user,
        "act":   scenario.get('action', 'Block'),
        "reason": "Scenario Event",
        "cs1": _ac_policy(config),  "cs1Label": "fwPolicy",
        "cs2": "Scenario_Rule",     "cs2Label": "fwRule",
        "request": f"https://{scenario.get('dest_domain', 'scenario.com')}/",
        "requestMethod": "GET",
        "cefSeverity": "5",
        "outcome": "FAILURE" if scenario.get('action', 'Block') == "Block" else "SUCCESS",
        "deviceInboundInterface":  _get_config(config).get('inbound_interface',  'inside'),
        "deviceOutboundInterface": _get_config(config).get('outbound_interface', 'outside'),
        "cs3": "User-Zone",     "cs3Label": "ingressZone",
        "cs4": "Internet-Zone", "cs4Label": "egressZone",
        "cnt":             1,
        "deviceDirection": 1,
        "bytesOut": random.randint(200, 5_000),
        "bytesIn":  random.randint(500, 50_000),
        "msg":   f"Scenario event: {scenario.get('name', 'Unknown')}",
        "start": start_ms, "end": end_ms,
    }
    if shost:
        fields["shost"] = shost

    log_type = scenario.get("log_type", "url_filtering")
    cef_name = "CONNECTION STATISTICS"

    if log_type == "ips":
        _rule_id = random.randint(10000, 99999)
        fields["_sig_id"]      = f"INTRUSION:400:1:{_rule_id}"
        fields["cs5"]             = random.choice(_IPS_POLICIES)
        fields["cs5Label"]        = "ipsPolicy"
        fields["cs6"]             = str(_rule_id)
        fields["cs6Label"]        = "ruleId"
        fields["cat"]             = scenario.get("threat_category", "Exploit Kit")
        fields["deviceDirection"] = 0
        cef_name = "INTRUSION EVENT"
    elif log_type == "malware":
        fields["_sig_id"] = SIG_IDS["MALWARE"]
        fname = scenario.get("filename", "bad.exe")
        seed  = fname
        threatname = scenario.get("threat_category", "Trojan.Generic")
        fields["fname"]      = fname
        fields["fileHash"]   = hashlib.sha256(seed.encode()).hexdigest()
        fields["cs1"]        = _ac_policy(config)
        fields["cs1Label"]   = "policy"
        fields["cs2"]        = threatname
        fields["cs2Label"]   = "virusName"
        fields["cs3"]        = "Malware"
        fields["cs3Label"]   = "disposition"
        fields["cs4"]        = "N/A"
        fields["cs4Label"]   = "speroDisposition"
        fields["cs5"]        = f"Malware detected: {threatname}"
        fields["cs5Label"]   = "eventDescription"
        cef_name = "FireAMP Event"
    elif log_type == "url_filtering":
        fields["_sig_id"] = SIG_IDS["URL"]
        fields["cs5"]        = scenario.get("threat_category", "Phishing")
        fields["cs5Label"]   = "secIntelCategory"
    else:  # default to connection
        fields["_sig_id"] = SIG_IDS["CONNECTION"]
        cef_name = "CONNECTION STATISTICS"

    return _format_firepower_cef(config, fields, cef_name)


# ---------------------------------------------------------------------------
# Threat dispatcher
# ---------------------------------------------------------------------------

def _generate_threat_log(config, session_context=None, forced_event=None):
    """Picks and generates a random threat event from the configured or fallback mix.

    Multi-event generators return (list_of_cef_strings, event_name) directly.
    This includes volume-based (port_scan, brute_force, dns_c2_beacon, smtp_spray)
    and conversation-complete generators (tor, rare_ssh, rare_external_rdp,
    server_outbound_http, vpn_tor_login, malware, large_file_upload,
    ssh_over_https, smtp_large_exfil, ftp_large_exfil) that prepend DNS/TLS
    precursor events to match real FTD log sequences.

    Single-event generators return a single CEF string via the (fields, cef_name) path.
    If forced_event is given, that specific event is generated instead of a random pick.
    """
    user, src_ip, shost = _get_user_and_ip(config, session_context)

    if forced_event:
        # Resolve display name (may have "[Non-Analytic] " prefix) to raw event key
        chosen = _DISPLAY_TO_EVENT.get(forced_event, forced_event).lower()
    else:
        module_config = _get_config(config)
        event_mix     = module_config.get('event_mix', {})
        threat_events = event_mix.get('threat', [])

        if not threat_events:  # Fallback: use module-level defaults
            threat_events = _DEFAULT_THREAT_EVENTS

        chosen = random.choices(
            [e['event']  for e in threat_events],
            weights=[e['weight'] for e in threat_events],
            k=1,
        )[0]

    print(f"    - Firepower Module simulating: {chosen} from {src_ip}")

    # --- Multi-event generators -- return (list, event_name) ---
    if chosen == 'port_scan':
        return (_generate_port_scan_event(config), chosen)
    elif chosen == 'brute_force':
        return (_generate_brute_force_event(config), chosen)
    elif chosen == 'dns_c2_beacon':
        return (_generate_dns_c2_beacon(config, src_ip, user, shost), chosen)
    elif chosen == 'smb_new_host_lateral':
        return (_generate_smb_new_host_lateral(config, src_ip, user, session_context, shost), chosen)
    elif chosen == 'smb_share_enumeration':
        return (_generate_smb_share_enumeration(config, src_ip, user, shost), chosen)
    elif chosen == 'vpn_brute_force':
        return (_generate_vpn_brute_force(config, src_ip, user, shost), chosen)
    elif chosen == 'vpn_impossible_travel':
        return (_generate_vpn_impossible_travel(config, src_ip, user, shost), chosen)
    elif chosen == 'smtp_spray':
        return (_generate_smtp_spray(config, src_ip, user, shost), chosen)
    elif chosen == 'ddns_connection':
        return (_generate_ddns_connection(config, src_ip, user, shost), chosen)
    # Conversation-complete generators (DNS precursor + primary event, or full VPN session)
    elif chosen == 'tor':
        return (_generate_tor_event(config, src_ip, user, shost), chosen)
    elif chosen == 'server_outbound_http':
        return (_generate_server_outbound_http(config), chosen)
    elif chosen == 'vpn_tor_login':
        return (_generate_vpn_tor_login(config, src_ip, user, shost), chosen)
    elif chosen == 'rare_external_rdp':
        return (_generate_rare_external_rdp(config, src_ip, user, shost), chosen)
    elif chosen == 'rare_ssh':
        return (_generate_rare_ssh(config, src_ip, user, shost), chosen)
    elif chosen == 'malware':
        return (_generate_file_malware_event(config, src_ip, user, shost), chosen)
    elif chosen == 'large_file_upload':
        return (_generate_large_file_upload_event(config, src_ip, user, shost), chosen)
    elif chosen == 'ssh_over_https':
        return (_generate_ssh_over_https_event(config, src_ip, user, shost), chosen)
    elif chosen == 'smtp_large_exfil':
        return (_generate_smtp_large_exfil(config, src_ip, user, shost), chosen)
    elif chosen == 'ftp_large_exfil':
        return (_generate_ftp_large_exfil(config, src_ip, user, shost), chosen)

    # --- Single-event generators -- return via (fields, cef_name) path ---
    elif chosen == 'ips':
        fields, cef_name = _generate_ips_event(config)
    elif chosen == 'url_filtering':
        fields, cef_name = _generate_url_filtering_event(config, src_ip, user, shost)
    elif chosen == 'security_intel':
        fields, cef_name = _generate_security_intel_event(config, src_ip, user, shost)
    elif chosen == 'workstation_smb':
        fields, cef_name = _generate_workstation_smb_event(config, src_ip, user, session_context, shost)
    elif chosen == 'rdp_lateral':
        return (_generate_rdp_lateral_event(config, src_ip, user, session_context, shost), chosen)
    elif chosen == 'internal_smb':
        fields, cef_name = _generate_internal_smb_event(config, src_ip, user, shost)
    elif chosen == 'smb_rare_file_transfer':
        fields, cef_name = _generate_smb_rare_file_transfer(config, src_ip, user, shost)
    elif chosen == 'app_control':
        fields, cef_name = _generate_app_control(config, src_ip, user, shost)
    elif chosen == 'network_anomaly':
        fields, cef_name = _generate_network_anomaly(config)
    else:
        fields, cef_name = _generate_connection_event(config, src_ip, user, shost)

    if not fields:
        return None
    return (_format_firepower_cef(config, fields, cef_name), chosen)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_log(config, scenario=None, threat_level="Realistic",
                 benign_only=False, context=None, scenario_event=None):
    """
    Main log generation function for Cisco Firepower.

    Benign event mix (13 categories, includes UEBA baseline protocols):
      connection        43%  — outbound web browsing (allow 85% / block suspicious 15%)
      inbound_block     17%  — external probe blocked at perimeter (background noise)
      internal_app_tier 10%  — user -> app server -> database connection chain
      smb                5%  — internal SMB file share (UEBA baseline)
      dns_query          5%  — outbound DNS resolution to external resolver
      email_traffic      1%  — SMTP/SMTPS/IMAPS mail client connections (low to avoid XSIAM anomaly triggers)
      ssh                4%  — internal SSH admin sessions (UEBA baseline)
      rdp                4%  — internal RDP admin sessions (UEBA baseline)
      vpn                3%  — RA-VPN remote worker logins (UEBA baseline)
      ntp_sync           2%  — UDP/123 NTP time synchronisation
      software_update    2%  — large HTTPS download (Windows Update / AV definitions)
      ftp                2%  — scheduled FTP file transfers (UEBA baseline)

    Threat event fallback weights (used when event_mix absent from config):
      ips               18  - inbound IPS drop (external attacker -> internal server)
      malware           15  - AMP file/malware block (SHA256, fname, fileType, filePath)
      url_filtering     10  - URL category block (cs5 = category -> xdm.alert.category)
      security_intel     8  - Security Intelligence DNS block (UDP/53, single block event)
      port_scan         10  - external port scan (20-50 blocked CONNECTIONs, multi-event)
      brute_force        8  - connection brute force (20-60 blocked CONNECTIONs, multi-event)
      large_file_upload  6  - outbound data exfiltration (100 MB-500 MB bytesOut)
      ssh_over_https     5  - SSH app on port 443 (protocol anomaly, allowed)
      workstation_smb    4  - w/w SMB lateral movement (Block)
      rdp_lateral        3  - internal RDP blocked (w/w or w/s lateral movement)
      tor                3  - outbound Tor exit node connection (Allow)
      dns_c2_beacon      3  - many DNS queries to suspicious resolver (multi-event, Allow)
      server_outbound_http 2 - internal server -> external HTTP (anomalous, Allow)
      internal_smb       1  - internal file share access (Allow, anomalous volume)
      smb_new_host_lateral 4 - SMB connections to multiple new hosts (multi-event)
      smb_rare_file_transfer 3 - large SMB session to internal server (data staging)
      smb_share_enumeration 5 - rapid SMB probes to many internal hosts (multi-event)
      vpn_brute_force    6  - RA-VPN credential stuffing (20-50 failed, multi-event)
      vpn_impossible_travel 3 - same user from two distant IPs (multi-event)
      vpn_tor_login      3  - successful VPN from TOR exit node
      rare_external_rdp  3  - outbound RDP to external IP
      rare_ssh           3  - outbound SSH to rare external IP
      smtp_spray         3  - spam bot SMTP to many external MX (30-50, multi-event)
      smtp_large_exfil   2  - large SMTP attachment exfiltration (100-500 MB)
      ftp_large_exfil    2  - outbound FTP exfiltration (100-500 MB)
      ddns_connection    3  - connection to dynamic DNS domain (DNS + HTTPS, multi-event)
      app_control        4  - prohibited application blocked (P2P, anonymizer, etc.)
      network_anomaly    4  - network-level DoS/anomaly detection (IPS preprocessor)
    """
    global last_threat_event_time
    session_context = (context or {}).get('session_context')

    # --- Scenario mode ---
    if scenario:
        return _generate_scenario_log(config, scenario, session_context)

    # --- Scenario event from coordinated simulator ---
    if scenario_event and context:
        if scenario_event == "LARGE_EGRESS":
            print("    - Firepower Module simulating: Scenario LARGE_EGRESS")
            user, src_ip, shost = _get_user_and_ip(config, session_context)
            if context.get('src_ip'):
                src_ip = context['src_ip']
            dest  = random.choice(config.get('exfiltration_destinations', [{}]))
            try:
                dest_ip = rand_ip_from_network(ip_network(dest.get("ip_range", "154.53.224.0/24"), strict=False))
            except (AddressValueError, ValueError):
                dest_ip = _random_external_ip()
            bytes_sent  = context.get('bytes', random.randint(50_000_000, 200_000_000))
            mb_str      = f"{bytes_sent // 1_048_576} MB"
            duration_ms = random.randint(30_000, 900_000)
            start_ms, end_ms = _conn_timing(duration_ms)

            fields = _base_fields(config, src_ip, user, shost)
            fields.update({
                "_sig_id": SIG_IDS["CONNECTION"],
                "act": "Allow", "app": "SSL",
                "dst": dest_ip, "dpt": 443,
                "cs1": _ac_policy(config),   "cs1Label": "fwPolicy",
                "cs2": "Allow_Outbound_Web", "cs2Label": "fwRule",
                "cs6": "Suspicious",         "cs6Label": "URLReputation",
                "cefSeverity": "3",  # Cisco: Allow → severity 3
                "bytesOut": bytes_sent,
                "bytesIn":  random.randint(1_000, 5_000),
                "outcome": "SUCCESS", "reason": "Traffic Allowed",
                "msg":   f"Large egress event: {mb_str} transferred to {dest_ip}",
                "start": start_ms, "end": end_ms,
            })
            return _format_firepower_cef(config, fields, "CONNECTION STATISTICS")
        # Named threat from dashboard — dispatch to the specific event
        return _generate_threat_log(config, session_context, forced_event=scenario_event)

    # --- Benign only ---
    if benign_only or threat_level == "Benign Traffic Only":
        return _generate_benign_log(config, session_context)

    interval     = _get_threat_interval(threat_level, config)
    current_time = time.time()

    if threat_level == "Insane" and random.random() < 0.8:
        return _generate_threat_log(config, session_context)

    if interval > 0 and (current_time - last_threat_event_time) > interval:
        last_threat_event_time = current_time
        return _generate_threat_log(config, session_context)

    return _generate_benign_log(config, session_context)
