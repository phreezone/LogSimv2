# modules/checkpoint_firewall.py
# Simulates Check Point Firewall logs in CEF format, aligned with the XSIAM Data Model.
# Includes advanced analytics-triggering events like large uploads, port scans, and lateral movement.

import random
import re
import time
from datetime import datetime, timedelta, timezone
import uuid
from ipaddress import ip_network
try:
    from modules.session_utils import (get_random_user, get_user_by_name, rand_ip_from_network,
        stable_vpn_ip, stable_mail_servers, weighted_destination)
except ImportError:
    from session_utils import (get_random_user, get_user_by_name, rand_ip_from_network,
        stable_vpn_ip, stable_mail_servers, weighted_destination)

NAME = "Check Point Firewall"
DESCRIPTION = "Simulates Check Point traffic, threat prevention, URL filtering, and identity logs in CEF format."
XSIAM_PARSER = "check_point_vpn_1_firewall_1_raw"
# NOTE (PENDING): URL filtering events (cefDeviceEventClassId="url_filtering") and identity events
# ("identity") technically belong to the XSIAM datasets check_point_url_filtering_raw and
# check_point_identity_awareness_raw respectively. Currently all events are sent to a single
# parser/dataset. Research needed: does XSIAM route by cefDeviceEventClassId automatically, or
# does a second log stream / separate data connector need to be configured? Revisit at project
# completion to determine if separate log generation paths are required for full XDM coverage of
# the URL Filtering and Identity Awareness models.
CONFIG_KEY = "checkpoint_config"

# Single source of truth for threat event names and their default weights.
# Used as the fallback in _generate_threat_log and by get_threat_names().
# Add new entries here when adding a new dispatch case in _generate_threat_log.
#
# "analytic" indicates whether the event is expected to trigger an XSIAM
# Third-Party Firewall analytics detection.  Events marked False are still
# valuable for testing (IPS drops, App Control blocks, etc.) but XSIAM does
# not generate behavioral analytics alerts from them — those detections come
# from other data sources (XDR Agent, Identity, etc.).
# "xsiam_alert" is the matching XSIAM analytics alert name when analytic=True.
_NON_ANALYTIC_PREFIX = "[Non-Analytic] "
_DEFAULT_THREAT_EVENTS = [
    {"event": "ips",                   "weight": 18, "analytic": False,
     "xsiam_alert": None},
    {"event": "port_scan",             "weight": 14, "analytic": True,
     "xsiam_alert": "Port Scan"},
    {"event": "auth_brute_force",      "weight": 11, "analytic": False,
     "xsiam_alert": None},
    {"event": "lateral_movement",      "weight": 11, "analytic": True,
     "xsiam_alert": "Failed Connections"},
    {"event": "url_block",             "weight": 8,  "analytic": False,
     "xsiam_alert": None},
    {"event": "vpn_brute_force",       "weight": 8,  "analytic": False,
     "xsiam_alert": None},
    {"event": "large_upload",          "weight": 5,  "analytic": True,
     "xsiam_alert": "Large Upload (HTTPS)"},
    {"event": "rare_ssh",              "weight": 3,  "analytic": True,
     "xsiam_alert": "Uncommon SSH session was established"},
    {"event": "tor_connection",        "weight": 3,  "analytic": True,
     "xsiam_alert": "Recurring access to rare IP"},
    {"event": "vpn_impossible_travel", "weight": 3,  "analytic": False,
     "xsiam_alert": None},
    {"event": "dns_c2_beacon",         "weight": 3,  "analytic": True,
     "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain"},
    {"event": "server_outbound_http",  "weight": 2,  "analytic": True,
     "xsiam_alert": "New Administrative Behavior"},
    {"event": "workstation_rdp",       "weight": 2,  "analytic": False,
     "xsiam_alert": None},
    {"event": "identity",              "weight": 2,  "analytic": False,
     "xsiam_alert": None},
    {"event": "smartdefense",          "weight": 4,  "analytic": False,
     "xsiam_alert": None},
    {"event": "app_control",           "weight": 4,  "analytic": False,
     "xsiam_alert": None},
    {"event": "vpn_tor_login",         "weight": 3,  "analytic": True,
     "xsiam_alert": "Recurring access to rare IP"},
    {"event": "smb_new_host_lateral",  "weight": 4,  "analytic": True,
     "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "smb_rare_file_transfer","weight": 3,  "analytic": True,
     "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "smb_share_enumeration", "weight": 5,  "analytic": True,
     "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "rare_external_rdp",     "weight": 3,  "analytic": True,
     "xsiam_alert": "Rare RDP session to a remote host"},
    {"event": "smtp_spray",            "weight": 3,  "analytic": True,
     "xsiam_alert": "Spam Bot Traffic"},
    {"event": "smtp_large_exfil",      "weight": 2,  "analytic": True,
     "xsiam_alert": "Large Upload (SMTP)"},
    {"event": "ftp_large_exfil",       "weight": 2,  "analytic": True,
     "xsiam_alert": "New FTP Server"},
    {"event": "ddns_connection",       "weight": 3,  "analytic": True,
     "xsiam_alert": "Recurring rare domain access to dynamic DNS domain"},
]


# Build display-name mappings.  Non-analytic events are prefixed so operators
# can immediately distinguish events that will / won't generate XSIAM analytics.
_EVENT_DISPLAY_NAMES = {}   # event_key → display_name
_DISPLAY_TO_EVENT    = {}   # display_name → event_key  (reverse lookup)
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


last_threat_event_time = 0


# ---------------------------------------------------------------------------
# Check Point field generation helpers
# ---------------------------------------------------------------------------

def _generate_loguid():
    """Generate a Check Point-style loguid in the {0xhex,...} format used by R80+ gateways.

    Real format from Check Point R80.10+ SmartLog:
        {0xXXXXXXXX,0xXXXX,0xXXXX,0xXX,0xXX,{0xXX,0xXX,0xXX,0xXX,0xXX,0xXX}}
    """
    return (
        "{0x%08x,0x%04x,0x%04x,0x%02x,0x%02x,"
        "{0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x}}"
    ) % (
        random.randint(0, 0xFFFFFFFF),
        random.randint(0, 0xFFFF),
        random.randint(0, 0xFFFF),
        random.randint(0, 0xFF),
        random.randint(0, 0xFF),
        random.randint(0, 0xFF),
        random.randint(0, 0xFF),
        random.randint(0, 0xFF),
        random.randint(0, 0xFF),
        random.randint(0, 0xFF),
        random.randint(0, 0xFF),
    )


def _generate_session_id():
    """Generate a Check Point-style numeric session ID (connection table entry).

    In real Check Point logs session_id is an integer that identifies the connection
    in the gateway's state table.
    """
    return str(random.randint(100000, 4294967295))


# Deterministic namespace for policy-layer UUIDs (RFC 4122 DNS namespace UUID).
_LAYER_NAMESPACE = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')


def _get_layer_uuid(hostname):
    """Return a deterministic policy-layer UUID derived from the gateway hostname.

    Using uuid5 ensures every log from the same gateway carries the same layer_uuid,
    matching real Check Point R80+ behaviour where layer UUIDs are fixed identifiers
    assigned when the policy is compiled and installed.
    """
    return "{" + str(uuid.uuid5(_LAYER_NAMESPACE, hostname + "_Network")) + "}"


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

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
    """Realistic public (non-RFC-1918) IP address for simulated external attackers."""
    first_octets = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 194, 212, 213]
    return (f"{random.choice(first_octets)}."
            f"{random.randint(1, 254)}."
            f"{random.randint(1, 254)}."
            f"{random.randint(1, 254)}")


def _dns_precursor(config, src_ip, user, shost, domain, event_time=None):
    """Generate a DNS resolution log preceding an outbound connection."""
    ext = {
        "act": "Accept",
        "src": src_ip, "dst": "8.8.8.8",
        "spt": random.randint(49152, 65535), "dpt": 53,
        "proto": "17",
        "suser": user, "shost": shost, "dhost": "dns.google",
        "dns_query": domain, "dns_type": "A",
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": "domain-udp", "app": "DNS",
        "cs1": "Allow_DNS", "cs1Label": "Rule Name",
        "out": random.randint(60, 120), "in": random.randint(80, 300),
        "cn1": 0, "cn1Label": "Elapsed Time in Seconds",
        "ifname": "eth0",
        "msg": f"Accept DNS query for {domain} from {src_ip}",
        "cefDeviceEventClassId": "traffic",
    }
    return _format_checkpoint_cef(config, ext, event_time=event_time)


def _get_user_and_host_info(config, ip_address=None, session_context=None):
    """Retrieves a (username, hostname) pair.

    Prefers session_context; falls back to static maps for backward compatibility.
    If ip_address is provided with session_context, attempts to find a matching user.
    """
    if session_context:
        if ip_address:
            for uname, profile in session_context.items():
                for dev in profile.get('active_devices', {}).values():
                    if dev.get('ip') == ip_address:
                        return uname, dev.get('hostname')
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        if user_info:
            return user_info['username'], user_info['hostname']
    return None, None


def _format_checkpoint_cef(config, extensions_dict, device_product=None, event_time=None):
    """Formats a dictionary of fields into a Check Point CEF syslog string.

    CEF header fields (signatureId, name, severity) are popped from the dict before
    building the extension string.  Numeric severity values are auto-mapped to Check
    Point text values (low/medium/high/Very-high/unknown).

    Default values are applied for fields always present in real CP R80+ CEF exports:
        loguid       – unique log record identifier ({0xhex,...} format)
        origin       – reporting gateway IP address
        product      – blade/product name (matches CEF header Device Product)
        session_id   – connection-table session identifier (integer string)
        layer_name   – policy layer name ("Network")
        layer_uuid   – policy layer UUID (deterministic per gateway)
        inzone/outzone – derived from deviceInboundInterface/deviceOutboundInterface

    Firewall traffic events using cs1Label="Rule Name" are auto-migrated to cs2
    (the correct CEF key for Check Point firewall rule names).  Blade-specific events
    (IPS, App Control, URL Filtering, SmartDefense) use different cs1Labels and are
    not affected.

    device_product controls XSIAM dataset routing (CEF header field):
        None / "VPN-1 & FireWall-1"   → check_point_vpn_1_firewall_1_raw  (default)
        "SmartDefense"                 → check_point_smartdefense_raw
        "Application Control"         → check_point_app_control_raw
    """
    checkpoint_conf = config.get(CONFIG_KEY, {})
    ext = dict(extensions_dict)

    cef_version    = "0"
    device_vendor  = "Check Point"
    if device_product is None:
        device_product = "VPN-1 & FireWall-1"
    device_version = "R81.10"

    signature_id = ext.pop("signatureId", "Log")
    name         = ext.pop("name",        "Log")
    raw_severity = ext.pop("severity",    "unknown")

    # Map numeric CEF severity to Check Point text severity values.
    # CP internal: 0-1=low, 2=medium, 3=high, 4=Very-high, default=unknown.
    _TEXT_SEVERITIES = {"unknown", "low", "medium", "high", "Very-high"}
    _sev = str(raw_severity)
    if _sev in _TEXT_SEVERITIES:
        severity = _sev
    else:
        _sev_map = {
            "0": "low", "1": "low", "2": "low", "3": "low",
            "5": "medium", "6": "medium",
            "7": "high", "8": "high",
            "9": "Very-high", "10": "Very-high",
        }
        severity = _sev_map.get(_sev, "unknown")

    cef_header = (
        f"CEF:{cef_version}|{device_vendor}|{device_product}|"
        f"{device_version}|{signature_id}|{name}|{severity}|"
    )

    hostname   = checkpoint_conf.get("hostname", "CP-FW-1")
    gateway_ip = checkpoint_conf.get("gateway_ip", "203.0.113.10")
    ext.pop("cefDeviceEventClassId", None)
    # duration is kept — URL Filtering and App Control XSIAM parsers use it
    # for xdm.event.duration; VPN-1 parser uses it via coalesce with cn1.
    # service_id and ifname are kept — present in real Check Point CEF exports.
    ext.setdefault("loguid",      _generate_loguid())
    ext.setdefault("origin",      gateway_ip)
    ext.setdefault("product",     device_product)
    event_ts = event_time or datetime.now(timezone.utc)
    ext.setdefault("rt",          int(event_ts.timestamp() * 1000))
    ext.setdefault("session_id",  _generate_session_id())
    ext.setdefault("layer_name",  "Network")
    ext.setdefault("layer_uuid",  _get_layer_uuid(hostname))
    # Derive inzone/outzone from interface fields (Check Point exports both)
    _in_iface  = ext.get("deviceInboundInterface")
    _out_iface = ext.get("deviceOutboundInterface")
    if _in_iface:
        ext.setdefault("inzone", _in_iface)
    if _out_iface:
        ext.setdefault("outzone", _out_iface)
    # Auto-migrate cs1 "Rule Name" → cs2 for firewall traffic events.
    # Blade-specific events (IPS, App Control, URL Filtering, SmartDefense) use
    # distinct cs1Labels and are not affected by this migration.
    if ext.get("cs1Label") == "Rule Name" and "cs2" not in ext:
        ext["cs2"] = ext.pop("cs1")
        ext["cs2Label"] = ext.pop("cs1Label")

    # AD domain-qualify bare usernames so XSIAM Identity can stitch
    # firewall users (EXAMPLECORP\user) with cloud/SaaS users (user@examplecorp.com)
    for _ufield in ("suser", "duser"):
        _uval = ext.get(_ufield)
        if _uval and "\\" not in _uval and "@" not in _uval:
            ext[_ufield] = f"EXAMPLECORP\\{_uval}"

    extension_string = " ".join(
        f"{key}={_cef_escape(value)}" for key, value in ext.items() if value is not None
    )

    timestamp = event_ts.strftime('%b %d %H:%M:%S')
    return f"<134>{timestamp} {hostname} CheckPoint: {cef_header}{extension_string}"


# ---------------------------------------------------------------------------
# Benign event generators
# ---------------------------------------------------------------------------

def _generate_benign_log(config, session_context=None):
    """Generates a variety of benign log types (traffic, dns, icmp)."""
    user_info = get_random_user(session_context, preferred_device_type='workstation') if session_context else None
    if user_info:
        user, src_ip, shost = user_info['username'], user_info['ip'], user_info['hostname']
    else:
        user_map = (config.get(CONFIG_KEY, {}).get('user_ip_map')
                    or config.get('shared_user_ip_map', {}))
        if user_map:
            user, src_ip = random.choice(list(user_map.items()))
            _, shost = _get_user_and_host_info(config, src_ip)
        else:
            src_ip = random.choice(config.get('internal_servers', ['192.168.1.10']))
            user, shost = 'unknown', None

    log_type = random.choices(
        ['traffic', 'inbound_block', 'dns', 'icmp', 'smtp', 'ntp', 'smb_internal',
         'rdp_internal', 'ftp_download', 'vpn_login', 'vpn_failure'],
        weights=[40, 18, 8, 3, 4, 3, 3,
                 3, 2, 3, 1],
        k=1,
    )[0]

    destination = weighted_destination(user, config.get('benign_egress_destinations', [{}]))
    try:
        dest_ip = rand_ip_from_network(ip_network(destination.get("ip_range", "8.8.8.0/24"), strict=False))
    except (ValueError, Exception):
        dest_ip = "8.8.8.8"
    dhost = destination.get("name", "").lower().replace(" ", "")

    if log_type == 'icmp':
        _icmp_dur = random.randint(1, 3)
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": dest_ip, "proto": "1",
            "suser": user, "shost": shost, "dhost": dhost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
            "deviceDirection": "1",
            "service_id": "icmp-echo",
            "cs1": "Allow_Ping", "cs1Label": "Rule Name",
            "cn1": _icmp_dur, "cn1Label": "Elapsed Time in Seconds",
            "cn2": 8,  "cn2Label": "ICMP Type",   # 8 = Echo Request
            "cn3": 0,  "cn3Label": "ICMP Code",   # 0 = No code
            "duration": str(_icmp_dur),
            "ifname": "eth0",
            "msg": f"Accept ICMP echo from {src_ip} to {dest_ip}",
            "cefDeviceEventClassId": "traffic",
        }
    elif log_type == 'dns':
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": "8.8.8.8", "spt": random.randint(49152, 65535), "dpt": 53, "proto": "17",
            "suser": user, "shost": shost, "dhost": "dns.google",
            "dns_query": random.choice(config.get('benign_domains', ['example.com'])),
            "dns_type": "A",
            "cs1": "Allow_DNS", "cs1Label": "Rule Name",
            "deviceDirection": "1",
            "ifname": "eth0",
            "msg": f"Accept DNS query from {src_ip}",
            "cefDeviceEventClassId": "traffic",
        }
    elif log_type == 'inbound_block':
        # Simulates routine inbound Drop/Reject of unsolicited external connection attempts.
        # Represents normal internet background noise hitting the perimeter firewall —
        # a very common log type in real Check Point environments.
        # inzone=External, outzone=Internal (traffic arriving from outside, headed inward).
        # No suser/shost — external traffic has no associated identity.
        target_ip = random.choice(config.get('internal_servers', ['10.0.10.50']))
        # Ports commonly probed by internet scanners and opportunistic attackers
        scan_port_map = {
            22:   "ssh",   23:   "telnet",  25:   "smtp",
            80:   "http",  110:  "pop3",    143:  "imap",
            443:  "https", 445:  "smb",     1433: "mssql",
            3306: "mysql", 3389: "rdp",     5900: "vnc",
            8080: "http-alt", 8443: "https-alt",
        }
        target_port = random.choice(list(scan_port_map.keys()))
        service     = scan_port_map[target_port]
        # Generate a realistic public source IP (avoids RFC1918 / link-local ranges)
        ext_src_ip = _random_external_ip()
        act = random.choices(["Drop", "Reject"], weights=[70, 30])[0]
        extensions = {
            "act": act,
            "src": ext_src_ip, "dst": target_ip,
            "spt": random.randint(1024, 65535), "dpt": target_port,
            "proto": "6",
            "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
            "deviceDirection": "0",
            "cs1": "Default_Inbound_Block", "cs1Label": "Rule Name",
            "service_id": service,
            "reason": "Policy",
            "ifname": "eth0",
            "msg": f"{act} inbound {service.upper()} from {ext_src_ip} to {target_ip}:{target_port}",
            "cefDeviceEventClassId": "traffic",
        }

    elif log_type == 'smtp':
        # Outbound email to corporate mail relay — SMTP/25 or SMTPS/587.
        # Uses stable_mail_servers() so each user connects to only 2-3 fixed relays,
        # matching real enterprise behavior and avoiding XSIAM spam-bot false positives.
        smtp_port    = random.choice([25, 587])
        mail_dest_ip = stable_mail_servers(user)
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": mail_dest_ip,
            "spt": random.randint(49152, 65535), "dpt": smtp_port,
            "proto": "6",
            "suser": user, "shost": shost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
            "deviceDirection": "1",
            "service_id": "smtp" if smtp_port == 25 else "submission",
            "app": "SMTP",
            "cs1": "Allow_SMTP_Relay", "cs1Label": "Rule Name",
            "out": random.randint(1_000, 500_000),
            "in":  random.randint(200, 5_000),
            "ifname": "eth0",
            "msg": f"Accept SMTP relay from {src_ip} to {mail_dest_ip}:{smtp_port}",
            "cefDeviceEventClassId": "traffic",
        }

    elif log_type == 'ntp':
        # Outbound NTP time sync from internal host to public NTP pool — UDP/123
        ntp_servers = ["216.239.35.0", "129.6.15.28", "132.163.96.1", "198.60.22.240",
                       "17.253.52.125", "162.159.200.1"]
        ntp_dest = random.choice(ntp_servers)
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": ntp_dest,
            "spt": random.randint(49152, 65535), "dpt": 123,
            "proto": "17",  # UDP
            "suser": user, "shost": shost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
            "deviceDirection": "1",
            "service_id": "ntp",
            "cs1": "Allow_NTP_Outbound", "cs1Label": "Rule Name",
            "out": random.randint(48, 76),
            "in":  random.randint(48, 76),
            "ifname": "eth0",
            "msg": f"Accept NTP sync from {src_ip} to {ntp_dest}",
            "cefDeviceEventClassId": "traffic",
        }

    elif log_type == 'smb_internal':
        # Internal SMB file-share access — workstation to file server (intra-zone, both Internal)
        file_server = random.choice(config.get('internal_servers', [src_ip]))
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": file_server,
            "spt": random.randint(49152, 65535), "dpt": 445,
            "proto": "6",
            "suser": user, "shost": shost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
            "deviceDirection": "1",
            "service_id": "microsoft-ds",
            "app": "SMB",
            "cs1": "Allow_Internal_SMB", "cs1Label": "Rule Name",
            "out": random.randint(10_000, 5_000_000),
            "in":  random.randint(10_000, 50_000_000),
            "ifname": "eth1",
            "msg": f"Accept internal SMB from {src_ip} to {file_server}:445",
            "cefDeviceEventClassId": "traffic",
        }

    elif log_type == 'rdp_internal':
        # Internal RDP session — user to server (jump host / terminal server)
        rdp_server = random.choice(config.get('internal_servers', [src_ip]))
        rdp_dur = random.randint(300, 7200)
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": rdp_server,
            "spt": random.randint(49152, 65535), "dpt": 3389,
            "proto": "6",
            "suser": user, "shost": shost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
            "deviceDirection": "1",
            "service_id": "rdp", "app": "RDP",
            "cs1": "Allow_Internal_RDP", "cs1Label": "Rule Name",
            "out": random.randint(10_000, 200_000),
            "in":  random.randint(50_000, 2_000_000),
            "cn1": rdp_dur, "cn1Label": "Elapsed Time in Seconds",
            "reason": "TCP FIN",
            "ifname": "eth1",
            "msg": f"Accept internal RDP from {src_ip} to {rdp_server}:3389",
            "cefDeviceEventClassId": "traffic",
        }

    elif log_type == 'ftp_download':
        # Internal FTP download — workstation pulling files from internal FTP server
        ftp_server = random.choice(config.get('internal_servers', [src_ip]))
        ftp_dur = random.randint(10, 300)
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": ftp_server,
            "spt": random.randint(49152, 65535), "dpt": 21,
            "proto": "6",
            "suser": user, "shost": shost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
            "deviceDirection": "1",
            "service_id": "ftp", "app": "FTP",
            "cs1": "Allow_Internal_FTP", "cs1Label": "Rule Name",
            "out": random.randint(200, 5_000),
            "in":  random.randint(50_000, 50_000_000),
            "cn1": ftp_dur, "cn1Label": "Elapsed Time in Seconds",
            "reason": "TCP FIN",
            "ifname": "eth1",
            "msg": f"Accept internal FTP download from {ftp_server}:21 to {src_ip}",
            "cefDeviceEventClassId": "traffic",
        }

    elif log_type == 'vpn_login':
        # Benign VPN session from user's stable home IP
        checkpoint_conf = config.get(CONFIG_KEY, {})
        gateway_ip = checkpoint_conf.get('gateway_ip', '203.0.113.10')
        home_ip = stable_vpn_ip(user)
        vpn_dur = random.randint(1800, 28800)
        extensions = {
            "act": "Log In",
            "auth_status": "Log In",
            "src": home_ip, "dst": gateway_ip,
            "spt": random.randint(49152, 65535), "dpt": 443,
            "proto": "6",
            "suser": user,
            "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
            "deviceDirection": "0",
            "service_id": "https", "app": "SSL VPN",
            "cs1": "VPN_Remote_Access", "cs1Label": "Rule Name",
            "blade": "VPN",
            "out": random.randint(100_000, 10_000_000),
            "in":  random.randint(500_000, 50_000_000),
            "cn1": vpn_dur, "cn1Label": "Elapsed Time in Seconds",
            "reason": "TCP FIN",
            "ifname": "eth0",
            "msg": f"Accept VPN for {user} from {home_ip}",
        }

    elif log_type == 'vpn_failure':
        # Benign VPN auth failure — typo / expired cert
        checkpoint_conf = config.get(CONFIG_KEY, {})
        gateway_ip = checkpoint_conf.get('gateway_ip', '203.0.113.10')
        home_ip = stable_vpn_ip(user)
        fail_reasons = ["Credential Mismatch", "Expired Certificate", "MFA Timeout", "Account Locked"]
        extensions = {
            "signatureId": "45679",
            "name": "Identity Awareness",
            "severity": "3",
            "act": "Failed Log In",
            "auth_status": "Failed Log In",
            "src": home_ip, "dst": gateway_ip,
            "spt": random.randint(49152, 65535), "dpt": 443,
            "proto": "6",
            "suser": user,
            "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
            "deviceDirection": "0",
            "cs3": "user", "cs3Label": "User Type",
            "cs5": "VPN", "cs5Label": "Authentication Method",
            "blade": "Identity Awareness",
            "reason": random.choice(fail_reasons),
            "dhost": "vpn-gateway.examplecorp.com",
            "ifname": "eth0",
            "msg": f"VPN auth failed for {user} from {home_ip}",
            "cefDeviceEventClassId": "identity",
        }
        return _format_checkpoint_cef(config, extensions, device_product="Identity Awareness")

    else:  # HTTP/HTTPS traffic
        dest_port  = random.choice([80, 443])
        proto_name = "HTTPS" if dest_port == 443 else "HTTP"
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": dest_ip,
            "spt": random.randint(49152, 65535), "dpt": dest_port,
            "proto": "6",
            "suser": user, "shost": shost, "dhost": dhost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
            "deviceDirection": "1",
            "service_id": "https" if dest_port == 443 else "http",
            "app": "HTTPS" if dest_port == 443 else "HTTP",
            "cs1": "Standard_Web_Access", "cs1Label": "Rule Name",
            "out": random.randint(500, 15000),
            "in":  random.randint(10000, 200000),
            "ifname": "eth0",
            "msg": f"Accept {proto_name} from {src_ip} to {dest_ip}",
            "cefDeviceEventClassId": "traffic",
        }

    return _format_checkpoint_cef(config, extensions)


# ---------------------------------------------------------------------------
# Threat / analytics event generators
# ---------------------------------------------------------------------------

def _simulate_large_upload(config, src_ip, user, shost):
    """DNS precursor + large outbound HTTPS upload.

    Triggers XSIAM: large outbound data transfer / exfiltration analytics.
    """
    print(f"    - Check Point Module simulating: Large Upload from {src_ip}")
    destination = random.choice(config.get('exfiltration_destinations', [{}]))
    try:
        dest_ip = rand_ip_from_network(ip_network(destination.get("ip_range", "154.53.224.0/24"), strict=False))
    except (ValueError, Exception):
        dest_ip = "154.53.224.10"
    dhost = destination.get("domain", dest_ip)

    base_time = datetime.now(timezone.utc)
    logs = [_dns_precursor(config, src_ip, user, shost, dhost or dest_ip, event_time=base_time)]

    duration  = random.randint(300, 1200)
    bytes_out = random.randint(104857600, 524288000)  # 100 MB – 500 MB
    extensions = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": 443,
        "proto": "6",
        "suser": user, "shost": shost, "dhost": dhost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": "https", "app": "SSL",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": bytes_out,
        "in":  random.randint(1000, 5000),
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept HTTPS from {src_ip} to {dest_ip} — "
            f"{bytes_out // (1024 * 1024)}MB outbound in {duration}s"
        ),
    }
    logs.append(_format_checkpoint_cef(config, extensions,
                                        event_time=base_time + timedelta(seconds=1)))
    return logs


def _simulate_port_scan(config, src_ip, user, shost):
    """Simulates a lateral port scan: burst of accepted SYN probes to sequential ports.

    Generates 50–100 session-close logs from the same internal source to the same
    internal destination, each on a different destination port.  The firewall permits all
    traffic (no rule drops it); each connection closes immediately with a TCP RST
    because the probed port is closed on the target.  XSIAM detects the pattern from the
    volume of allowed connections from one source to many ports — not from drops.

    Triggers XSIAM: port scan analytics from third-party firewall data.
    """
    print(f"    - Check Point Module simulating: Port Scan from {src_ip}")
    dest_ip = random.choice(config.get('internal_servers', ["10.0.10.50"]))
    _, dhost = _get_user_and_host_info(config, dest_ip)

    logs = []
    base_time = datetime.now(timezone.utc)
    offset = 0.0
    for port in random.sample(range(1, 1024), k=random.randint(50, 100)):
        offset += random.uniform(0.5, 1.5)
        src_port = random.randint(49152, 65535)
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": dest_ip,
            "spt": src_port, "dpt": port,
            "proto": "6",
            "suser": user, "shost": shost, "dhost": dhost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
            "deviceDirection": "1",
            "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
            "out": 60, "in": random.randint(40, 54),
            "cn1": 0, "cn1Label": "Elapsed Time in Seconds",
            "reason": "TCP Reset",
            "ifname": "eth0",
            "msg": f"Accept TCP {src_ip}:{src_port} to {dest_ip}:{port} (RST — port closed)",
        }
        logs.append(_format_checkpoint_cef(config, extensions, event_time=base_time + timedelta(seconds=offset)))

    # 1-2 open ports discovered — successful connections (attacker finds live services)
    open_ports = random.sample([22, 80, 443, 445, 3389, 8080, 8443], k=random.randint(1, 2))
    for port in open_ports:
        offset += random.uniform(0.5, 1.5)
        src_port = random.randint(49152, 65535)
        conn_duration = random.randint(5, 30)
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": dest_ip,
            "spt": src_port, "dpt": port,
            "proto": "6",
            "suser": user, "shost": shost, "dhost": dhost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
            "deviceDirection": "1",
            "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
            "out": random.randint(500, 5000), "in": random.randint(500, 5000),
            "cn1": conn_duration, "cn1Label": "Elapsed Time in Seconds",
            "reason": "TCP FIN",
            "ifname": "eth0",
            "msg": f"Accept TCP {src_ip}:{src_port} to {dest_ip}:{port} (service responded)",
        }
        logs.append(_format_checkpoint_cef(config, extensions, event_time=base_time + timedelta(seconds=offset)))

    return logs


def _simulate_rare_ssh(config, src_ip, user, shost):
    """DNS precursor + outbound SSH to a rare external IP.

    Triggers XSIAM: outbound SSH to rare external destination.
    """
    print(f"    - Check Point Module simulating: Rare External SSH from {src_ip}")
    dest_ip = _random_external_ip()
    base_time = datetime.now(timezone.utc)
    logs = [_dns_precursor(config, src_ip, user, shost, dest_ip, event_time=base_time)]
    extensions = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": 22,
        "proto": "6",
        "suser": user, "shost": shost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": "ssh", "app": "SSH",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": random.randint(1000, 50000),
        "in":  random.randint(1000, 50000),
        "ifname": "eth0",
        "msg": f"Accept SSH from {src_ip} to rare external IP {dest_ip}",
        "cefDeviceEventClassId": "traffic",
    }
    logs.append(_format_checkpoint_cef(config, extensions,
                                        event_time=base_time + timedelta(seconds=0.5)))
    return logs


def _simulate_tor_connection(config, src_ip, user, shost):
    """DNS precursor + Tor connection.

    Triggers XSIAM: "Connection to Tor/Anonymous Proxy" analytics detection.
    """
    print(f"    - Check Point Module simulating: Tor Connection from {src_ip}")

    tor_nodes = config.get('tor_exit_nodes', [])
    dest_ip   = random.choice(tor_nodes).get('ip', _random_external_ip()) if tor_nodes else _random_external_ip()

    tor_port   = random.choices([443, 9001, 9030], weights=[60, 30, 10], k=1)[0]
    service_id = "https" if tor_port == 443 else "tor"
    app        = "SSL"         if tor_port == 443 else "Tor"

    duration  = random.randint(120, 1800)
    bytes_out = random.randint(10000, 100000)
    bytes_in  = random.randint(50000, 500000)

    base_time = datetime.now(timezone.utc)
    logs = [_dns_precursor(config, src_ip, user, shost, dest_ip, event_time=base_time)]

    extensions = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": tor_port,
        "proto": "6",
        "suser": user, "shost": shost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": service_id, "app": app,
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": bytes_out, "in": bytes_in,
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept {src_ip} to {dest_ip}:{tor_port} — "
            f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in, {duration}s"
        ),
    }
    logs.append(_format_checkpoint_cef(config, extensions,
                                        event_time=base_time + timedelta(seconds=0.5)))
    return logs


def _simulate_auth_brute_force(config, src_ip, user, shost):
    """Simulates an authentication brute force: rapid burst of failed logins from one source IP.

    Generates 20–50 failed Identity Awareness events in sequence from the same source,
    targeting a service-appropriate internal destination.  Destination host, username,
    and authentication method are matched to the selected port:
        SSH/22     → internal server, service account target
        LDAP/389   → Domain Controller, AD Query
        LDAPS/636  → Domain Controller, Secure LDAP
        VPN-SSL/443→ VPN gateway, VPN auth
        RADIUS/1812→ RADIUS server, RADIUS PAP/CHAP

    Triggers XSIAM: failed authentication burst / brute force analytics.
    """
    print(f"    - Check Point Module simulating: Auth Brute Force from {src_ip}")
    auth_port = random.choice([22, 389, 443, 636, 1812])
    port_service = {22: "ssh", 389: "ldap", 443: "https", 636: "ldaps", 1812: "radius"}

    checkpoint_conf = config.get(CONFIG_KEY, {})
    internal_servers = config.get('internal_servers', ["10.0.0.10"])

    # SSH brute force cycles through common service account names (suser varies per attempt).
    # Other auth types use the same user identity for every attempt.
    _ssh_targets = ["root", "admin", "ubuntu", "ec2-user", "deploy", "svc-backup"]
    if auth_port == 22:      # SSH → any internal server
        dest_ip     = random.choice(internal_servers)
        dhost       = dest_ip
        auth_method = "SSH Public Key"
    elif auth_port in [389, 636]:  # LDAP/LDAPS → Domain Controller
        dest_ip     = random.choice(internal_servers)
        dhost       = "dc01.examplecorp.com"
        auth_method = "LDAP"
    elif auth_port == 443:   # VPN-SSL → gateway
        dest_ip     = checkpoint_conf.get('gateway_ip', '203.0.113.10')
        dhost       = "vpn-gateway.examplecorp.com"
        auth_method = "VPN"
    else:                    # RADIUS/1812 → dedicated RADIUS server
        dest_ip     = random.choice(internal_servers)
        dhost       = "radius.examplecorp.com"
        auth_method = "RADIUS"

    logs = []
    base_time = datetime.now(timezone.utc)
    offset = 0.0
    for i in range(random.randint(20, 50)):
        offset += random.uniform(0.3, 0.8)
        extensions = {
            "signatureId": "45678",
            "name": "Identity Awareness",
            "severity": "7",
            "act": "Failed Log In",
            "auth_status": "Failed Log In",
            "src": src_ip, "dst": dest_ip,
            "spt": random.randint(49152, 65535), "dpt": auth_port,
            "proto": "17" if auth_port == 1812 else "6",
            "suser": random.choice(_ssh_targets) if auth_port == 22 else user,
            "shost": shost,
            "dhost": dhost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
            "deviceDirection": "1",
            "cs3": "user",        "cs3Label": "User Type",
            "cs5": auth_method,   "cs5Label": "Authentication Method",
            "blade": "Identity Awareness",
            "service_id": port_service.get(auth_port, "unknown"),
            "reason": "Authorization Failed",
            "ifname": "eth0",
            "msg": f"Authentication failed for {user} from {src_ip} to {dhost}:{auth_port} (attempt {i + 1})",
            "cefDeviceEventClassId": "identity",
        }
        logs.append(_format_checkpoint_cef(config, extensions, device_product="Identity Awareness",
                                           event_time=base_time + timedelta(seconds=offset)))
    # Final success — attacker found valid credentials; triggers XSIAM brute-force detection
    offset += random.uniform(0.3, 0.8)
    success_user = random.choice(_ssh_targets) if auth_port == 22 else user
    success_ext = {
        "signatureId": "45678",
        "name": "Identity Awareness",
        "severity": "3",
        "act": "Log In",
        "auth_status": "Successful Login",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": auth_port,
        "proto": "17" if auth_port == 1812 else "6",
        "suser": success_user,
        "shost": shost,
        "dhost": dhost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
        "deviceDirection": "1",
        "cs3": "user",        "cs3Label": "User Type",
        "cs5": auth_method,   "cs5Label": "Authentication Method",
        "blade": "Identity Awareness",
        "service_id": port_service.get(auth_port, "unknown"),
        "reason": "Authorization Succeeded",
        "ifname": "eth0",
        "msg": f"Authentication succeeded for {success_user} from {src_ip} to {dhost}:{auth_port}",
        "cefDeviceEventClassId": "identity",
    }
    logs.append(_format_checkpoint_cef(config, success_ext, device_product="Identity Awareness",
                                       event_time=base_time + timedelta(seconds=offset)))
    return logs


def _simulate_lateral_movement(config, src_ip, user, shost):
    """Simulates east-west lateral movement: an internal host probing multiple internal targets.

    Picks 4–8 internal destination IPs and probes each on 1–3 lateral movement ports
    (SMB/445, RDP/3389, SSH/22, MSRPC/135, WinRM/5985).  65 % of attempts are dropped
    (Stealth_Rule), 35 % accepted – reflecting real mixed firewall policy behaviour.

    Triggers XSIAM: internal scanning / east-west lateral movement analytics.
    """
    print(f"    - Check Point Module simulating: Lateral Movement from {src_ip}")
    internal_servers = config.get('internal_servers', ["10.0.10.10", "10.0.10.20", "10.0.10.30"])

    candidates = [ip for ip in internal_servers if ip != src_ip]
    if not candidates:
        candidates = ["10.0.10.10", "10.0.10.20", "10.0.10.30"]
    targets = random.sample(candidates, k=min(len(candidates), random.randint(4, 8)))

    lateral_ports = {445: "microsoft-ds", 3389: "rdp", 22: "ssh", 135: "msrpc", 5985: "winrm"}

    logs = []
    base_time = datetime.now(timezone.utc)
    offset = 0.0
    for dest_ip in targets:
        for port, service in random.sample(list(lateral_ports.items()), k=random.randint(1, 3)):
            offset += random.uniform(2.0, 8.0)
            act  = random.choices(["Accept", "Drop"], weights=[35, 65])[0]
            rule = "Stealth_Rule" if act == "Drop" else "Allow_Internal_Traffic"
            duration  = random.randint(1, 30) if act == "Accept" else 0
            bytes_out = random.randint(1000, 50000) if act == "Accept" else 0
            bytes_in  = random.randint(500, 20000) if act == "Accept" else 0
            extensions = {
                "act": act,
                "src": src_ip, "dst": dest_ip,
                "spt": random.randint(49152, 65535), "dpt": port,
                "proto": "6",
                "suser": user, "shost": shost,
                "service_id": service, "app": service.upper(),
                "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
                "deviceDirection": "1",
                "cs1":rule, "cs1Label": "Rule Name",
                "out": bytes_out, "in": bytes_in,
                "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
                "reason": "Policy" if act == "Drop" else "TCP FIN",
                "ifname": "eth1",
                "msg": f"{act} {service.upper()} from {src_ip} to {dest_ip}:{port}",
                "cefDeviceEventClassId": "traffic",
            }
            logs.append(_format_checkpoint_cef(config, extensions, event_time=base_time + timedelta(seconds=offset)))
    return logs


def _simulate_vpn_brute_force(config, src_ip, user, shost):
    """Simulates a VPN credential-stuffing attack from a single external IP.

    Generates 20–50 failed Identity Awareness / VPN login events from one attacker
    against the gateway on port 443, cycling through real usernames from session_context.
    Each failure uses act='Failed Log In' directed at the VPN gateway external interface.

    Triggers XSIAM: VPN Brute Force / Credential Scan analytics detection.
    """
    print("    - Check Point Module simulating: VPN Brute Force from external attacker")
    checkpoint_conf = config.get(CONFIG_KEY, {})
    gateway_ip      = checkpoint_conf.get('gateway_ip', '203.0.113.10')
    attacker_ip     = _random_external_ip()

    logs = []
    base_time = datetime.now(timezone.utc)
    offset = 0.0
    for i in range(random.randint(20, 50)):
        offset += random.uniform(0.3, 0.8)
        extensions = {
            "signatureId": "45679",
            "name":        "Identity Awareness",
            "severity":    "7",
            "act":         "Failed Log In",
            "auth_status": "Failed Log In",
            "src": attacker_ip, "dst": gateway_ip,
            "spt": random.randint(49152, 65535), "dpt": 443,
            "proto": "6",
            "suser": user, "shost": shost,
            "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
            "deviceDirection": "0",
            "cs3": "user",        "cs3Label": "User Type",
            "cs5": "VPN",         "cs5Label": "Authentication Method",
            "blade": "Identity Awareness",
            "reason": "Authorization Failed",
            "dhost": "vpn-gateway.examplecorp.com",
            "ifname": "eth0",
            "msg": f"VPN authentication failed for {user} from {attacker_ip} (attempt {i + 1})",
            "cefDeviceEventClassId": "identity",
        }
        logs.append(_format_checkpoint_cef(config, extensions, device_product="Identity Awareness",
                                           event_time=base_time + timedelta(seconds=offset)))
    # Final success — attacker found valid credentials; triggers XSIAM brute-force detection
    offset += random.uniform(0.3, 0.8)
    success_ext = {
        "signatureId": "45679",
        "name":        "Identity Awareness",
        "severity":    "3",
        "act":         "Log In",
        "auth_status": "Successful Login",
        "src": attacker_ip, "dst": gateway_ip,
        "spt": random.randint(49152, 65535), "dpt": 443,
        "proto": "6",
        "suser": user, "shost": shost,
        "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
        "deviceDirection": "0",
        "cs3": "user",        "cs3Label": "User Type",
        "cs5": "VPN",         "cs5Label": "Authentication Method",
        "blade": "Identity Awareness",
        "reason": "Authorization Succeeded",
        "dhost": "vpn-gateway.examplecorp.com",
        "ifname": "eth0",
        "msg": f"VPN authentication succeeded for {user} from {attacker_ip}",
        "cefDeviceEventClassId": "identity",
    }
    logs.append(_format_checkpoint_cef(config, success_ext, device_product="Identity Awareness",
                                       event_time=base_time + timedelta(seconds=offset)))
    return logs


def _simulate_vpn_impossible_travel(config, src_ip, user, shost):
    """Simulates an impossible travel alert: same user connects from two distant IPs.

    Generates two VPN session-close logs from the same user — the legitimate login
    is back-dated 5–10 minutes so XSIAM sees two authentications within the same
    analytics window but far enough apart to pass the circuit-breaker minimum.
    Models compromised credentials: the attacker uses stolen creds minutes after
    the real user authenticated from their home location.

    Triggers XSIAM: Impossible Travel / Anomalous VPN Location analytics detection.
    """
    print(f"    - Check Point Module simulating: VPN Impossible Travel for {user}")
    checkpoint_conf = config.get(CONFIG_KEY, {})
    gateway_ip      = checkpoint_conf.get('gateway_ip', '203.0.113.10')

    benign_loc     = config.get('impossible_travel_scenario', {}).get('benign_location', {})
    suspicious_loc = config.get('impossible_travel_scenario', {}).get('suspicious_location', {})
    benign_ip      = benign_loc.get('ip',      '68.185.12.14')
    suspicious_ip  = suspicious_loc.get('ip', '175.45.176.10')

    # Legitimate user logged in 5–10 minutes ago; attacker logs in now.
    gap_minutes    = random.randint(5, 10)
    t_benign_start = datetime.now(timezone.utc) - timedelta(minutes=gap_minutes)
    t_suspicious   = datetime.now(timezone.utc)

    logs = []
    for vpn_src_ip, label, t_start, vpn_shost in [
        (benign_ip,    'home-office',       t_benign_start, shost),
        (suspicious_ip, 'suspicious-foreign', t_suspicious, None),
    ]:
        src_port  = random.randint(49152, 65535)
        duration  = random.randint(60, 300)
        bytes_out = random.randint(50000, 500000)
        bytes_in  = random.randint(100000, 2000000)
        t_end     = t_start + timedelta(seconds=duration)
        ext = {
            "act": "Log In",
            "auth_status": "Log In",
            "src": vpn_src_ip, "dst": gateway_ip,
            "spt": src_port, "dpt": 443,
            "proto": "6",
            "suser": user, "shost": vpn_shost,
            "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
            "deviceDirection": "0",
            "service_id": "https", "app": "SSL VPN",
            "cs1": "VPN_Remote_Access", "cs1Label": "Rule Name",
            "blade": "VPN",
            "out": bytes_out, "in": bytes_in,
            "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
            "duration": str(duration),
            "reason": "TCP FIN",
            "ifname": "eth0",
            "msg": (
                f"Accept VPN for {user} from {vpn_src_ip} ({label}) — "
                f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in"
            ),
        }
        logs.append(_format_checkpoint_cef(config, ext, event_time=t_end))
    return logs


def _simulate_vpn_tor_login(config, src_ip, user, shost):
    """Full conversation: TLS handshake + VPN auth + post-auth internal activity from Tor.

    Triggers XSIAM: Suspicious VPN Login / TOR-based Access analytics detection.
    """
    print(f"    - Check Point Module simulating: VPN Login from TOR Exit Node for {user}")
    checkpoint_conf = config.get(CONFIG_KEY, {})
    gateway_ip      = checkpoint_conf.get('gateway_ip', '203.0.113.10')
    tor_nodes       = config.get('tor_exit_nodes', [])
    tor_ip          = random.choice(tor_nodes).get('ip', _random_external_ip()) if tor_nodes else _random_external_ip()

    # Assign a VPN pool inside IP for post-auth traffic
    vpn_pool = checkpoint_conf.get('vpn_pool', '10.250.0.0/16')
    try:
        vpn_inside_ip = rand_ip_from_network(ip_network(vpn_pool, strict=False))
    except Exception:
        vpn_inside_ip = f"10.250.{random.randint(1,254)}.{random.randint(1,254)}"

    base_time = datetime.now(timezone.utc)
    logs = []

    # Log 1: TLS handshake (Tor IP -> gateway:443)
    tls_ext = {
        "act": "Accept",
        "src": tor_ip, "dst": gateway_ip,
        "spt": random.randint(49152, 65535), "dpt": 443,
        "proto": "6",
        "suser": user,
        "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
        "deviceDirection": "0",
        "service_id": "https", "app": "SSL",
        "cs1": "VPN_Remote_Access", "cs1Label": "Rule Name",
        "out": random.randint(500, 2000), "in": random.randint(2000, 8000),
        "cn1": 1, "cn1Label": "Elapsed Time in Seconds",
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": f"Accept TLS handshake from TOR {tor_ip} to VPN gateway {gateway_ip}:443",
    }
    logs.append(_format_checkpoint_cef(config, tls_ext, event_time=base_time))

    # Log 2: VPN auth success (primary detection event)
    src_port  = random.randint(49152, 65535)
    duration  = random.randint(300, 7200)
    bytes_out = random.randint(50000, 2_000_000)
    bytes_in  = random.randint(100000, 5_000_000)
    auth_ext = {
        "act": "Log In",
        "auth_status": "Log In",
        "src": tor_ip, "dst": gateway_ip,
        "spt": src_port, "dpt": 443,
        "proto": "6",
        "suser": user,
        "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
        "deviceDirection": "0",
        "service_id": "https", "app": "SSL VPN",
        "cs1": "VPN_Remote_Access", "cs1Label": "Rule Name",
        "blade": "VPN",
        "out": bytes_out, "in": bytes_in,
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept VPN for {user} from TOR exit node {tor_ip} — "
            f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in"
        ),
    }
    logs.append(_format_checkpoint_cef(config, auth_ext,
                                        event_time=base_time + timedelta(seconds=2)))

    # Logs 3+: Post-auth internal activity from VPN pool IP
    post_auth_actions = [
        {"app": "SMB", "port": 445, "service": "microsoft-ds"},
        {"app": "RDP", "port": 3389, "service": "rdp"},
        {"app": "SSH", "port": 22, "service": "ssh"},
        {"app": "LDAP", "port": 389, "service": "ldap"},
    ]
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    n_post = random.randint(1, 3)
    for i, action in enumerate(random.sample(post_auth_actions, min(n_post, len(post_auth_actions)))):
        dst_ip = random.choice(internal_servers)
        pa_ext = {
            "act": "Accept",
            "src": vpn_inside_ip, "dst": dst_ip,
            "spt": random.randint(49152, 65535), "dpt": action["port"],
            "proto": "6",
            "suser": user,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
            "deviceDirection": "1",
            "service_id": action["service"], "app": action["app"],
            "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
            "out": random.randint(1000, 50000),
            "in":  random.randint(5000, 200000),
            "cn1": random.randint(5, 120), "cn1Label": "Elapsed Time in Seconds",
            "reason": "TCP FIN",
            "ifname": "eth1",
            "msg": f"Accept {action['app']} from VPN {vpn_inside_ip} to {dst_ip}:{action['port']}",
        }
        logs.append(_format_checkpoint_cef(config, pa_ext,
                                            event_time=base_time + timedelta(seconds=5 + i * 3)))
    return logs


def _simulate_smb_new_host_lateral(config, src_ip, user, shost):
    """SMB connections from one internal workstation to multiple unfamiliar internal hosts.

    Generates 5–10 session-close logs on TCP/445 to DIFFERENT internal destinations.
    The breadth of distinct SMB targets from a single workstation in a short window is
    the XSIAM UEBA detection signal (lateral exploration, pass-the-hash, ransomware
    pre-encryption reconnaissance).

    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Check Point Module simulating: SMB New-Host Lateral from {src_ip}")
    n_hosts       = random.randint(5, 10)
    internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
    dest_ips      = set()
    while len(dest_ips) < n_hosts:
        try:
            net  = ip_network(random.choice(internal_nets), strict=False)
            host = rand_ip_from_network(net)
            if host != src_ip:
                dest_ips.add(host)
        except Exception:
            dest_ips.add(f"192.168.1.{random.randint(101, 200)}")

    logs = []
    base_time = datetime.now(timezone.utc)
    offset = 0.0
    for dst_ip in list(dest_ips)[:n_hosts]:
        offset += random.uniform(3.0, 10.0)
        duration  = random.randint(5, 120)
        bytes_out = random.randint(1000, 50000)
        bytes_in  = random.randint(5000, 200000)
        src_port  = random.randint(49152, 65535)
        ext = {
            "act": "Accept",
            "src": src_ip, "dst": dst_ip,
            "spt": src_port, "dpt": 445,
            "proto": "6",
            "suser": user, "shost": shost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
            "deviceDirection": "1",
            "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
            "blade": "Firewall",
            "out": bytes_out, "in": bytes_in,
            "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
            "reason": "TCP FIN",
            "ifname": "eth0",
            "msg": f"Accept SMB {src_ip} -> {dst_ip}:445 (new destination), {duration}s",
        }
        logs.append(_format_checkpoint_cef(config, ext, event_time=base_time + timedelta(seconds=offset)))
    return logs


def _simulate_smb_rare_file_transfer(config, src_ip, user, shost):
    """Large SMB file transfer (100 MB – 1 GB) between internal hosts — data staging.

    A single session-close log for a long-duration SMB/445 session with anomalously large bytes.
    Models pre-exfiltration data staging, bulk copying from restricted shares, or
    insider file collection. Session ALLOWED — only volume analytics detect it.
    """
    print(f"    - Check Point Module simulating: SMB Rare File Transfer from {src_ip}")
    internal_servers = config.get('internal_servers', [])
    dst_ip = random.choice(
        [s for s in internal_servers if s != src_ip] or internal_servers or ['10.0.10.50']
    )
    file_size_bytes = random.randint(104_857_600, 1_073_741_824)  # 100 MB – 1 GB
    duration        = random.randint(120, 900)
    src_port        = random.randint(49152, 65535)

    ext = {
        "act": "Accept",
        "src": src_ip, "dst": dst_ip,
        "spt": src_port, "dpt": 445,
        "proto": "6",
        "suser": user, "shost": shost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
        "deviceDirection": "1",
        "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
        "blade": "Firewall",
        "out": file_size_bytes,
        "in":  random.randint(1000, 50000),
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept large SMB {src_ip} -> {dst_ip}:445 — "
            f"{file_size_bytes // (1024 * 1024)}MB in {duration}s"
        ),
    }
    return _format_checkpoint_cef(config, ext)


def _simulate_smb_share_enumeration(config, src_ip, user, shost):
    """Rapid TCP/445 connections to many different internal hosts — SMB share scanning.

    15–40 session-close logs on port 445, each to a distinct internal destination.
    The source probes for accessible file shares it has no business accessing. XSIAM
    detects the high-volume SMB connection pattern from a single workstation as a
    network scan / insider threat indicator.
    """
    print(f"    - Check Point Module simulating: SMB Share Enumeration from {src_ip}")
    n_targets     = random.randint(15, 40)
    internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
    target_ips    = set()
    while len(target_ips) < n_targets:
        try:
            net  = ip_network(random.choice(internal_nets), strict=False)
            host = rand_ip_from_network(net)
            if host != src_ip:
                target_ips.add(host)
        except Exception:
            target_ips.add(f"192.168.1.{random.randint(101, 254)}")

    logs = []
    base_time = datetime.now(timezone.utc)
    offset = 0.0
    for dst_ip in list(target_ips)[:n_targets]:
        offset += random.uniform(0.5, 2.0)
        src_port = random.randint(49152, 65535)
        # XSIAM detects SMB scan from ALLOWED connection volume — same principle as port_scan
        ext = {
            "act": "Accept",
            "src": src_ip, "dst": dst_ip,
            "spt": src_port, "dpt": 445,
            "proto": "6",
            "suser": user, "shost": shost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
            "deviceDirection": "1",
            "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
            "blade": "Firewall",
            "out": random.randint(40, 200), "in": random.randint(40, 200),
            "cn1": 0, "cn1Label": "Elapsed Time in Seconds",
            "reason": "TCP Reset",
            "ifname": "eth0",
            "msg": f"Accept SMB probe {src_ip} -> {dst_ip}:445 (RST)",
        }
        logs.append(_format_checkpoint_cef(config, ext, event_time=base_time + timedelta(seconds=offset)))
    return logs


def _simulate_dns_c2_beacon(config, src_ip, user, shost):
    """Simulates a DNS-based C2 beacon: internal host makes repeated small UDP/53 queries
    to a suspicious external resolver that is not a legitimate DNS service.

    The pattern — many tiny outbound DNS transactions to an anomalous external IP —
    is the signature XSIAM analytics use to detect DNS tunnelling / C2 beaconing.

    Triggers XSIAM: DNS Tunnelling / C2 Beacon analytics detection.
    """
    print(f"    - Check Point Module simulating: DNS C2 Beacon from {src_ip}")
    destination = random.choice(config.get('exfiltration_destinations', [{}]))
    try:
        dest_ip = rand_ip_from_network(ip_network(destination.get("ip_range", "154.53.224.0/24"), strict=False))
    except Exception:
        dest_ip = _random_external_ip()

    c2_domains = [
        "updates.totallylegit.xyz",    "cdn.fastdelivery.top",
        "api.cloudservicehelper.info",  "telemetry.softupdater.biz",
        "beacon.homenetworktools.ru",
    ]
    c2_domain = random.choice(c2_domains)

    logs = []
    base_time = datetime.now(timezone.utc)
    offset = 0.0
    for _ in range(random.randint(15, 40)):
        offset += random.uniform(15.0, 60.0)   # real beacon interval between queries
        src_port  = random.randint(49152, 65535)
        bytes_out = random.randint(60, 250)    # small DNS-like queries
        bytes_in  = random.randint(100, 500)   # small DNS-like responses
        ext = {
            "act": "Accept",
            "src": src_ip, "dst": dest_ip,
            "spt": src_port, "dpt": 53,
            "proto": "17",
            "suser": user, "shost": shost, "dhost": c2_domain,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
            "deviceDirection": "1",
            "service_id": "domain-udp", "app": "DNS",
            "cs1": "Allow_DNS", "cs1Label": "Rule Name",
            "out": bytes_out, "in": bytes_in,
            "cn1": 0, "cn1Label": "Elapsed Time in Seconds",
            "dns_query": f"{random.randint(100000,999999)}.{c2_domain}",
            "dns_type": "TXT",
            "ifname": "eth0",
            "msg": f"Accept DNS {src_ip} -> {dest_ip}:53 (suspicious C2 beacon query)",
        }
        logs.append(_format_checkpoint_cef(config, ext, event_time=base_time + timedelta(seconds=offset)))
    return logs


def _simulate_server_outbound_http(config):
    """DNS precursor + anomalous outbound HTTP from server.

    Triggers XSIAM: Anomalous server outbound HTTP / server browsing analytics.
    """
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    server_ip = random.choice(internal_servers)
    print(f"    - Check Point Module simulating: Anomalous Server Outbound HTTP from {server_ip}")

    destination = random.choice(config.get('benign_egress_destinations', [{}]))
    try:
        dest_ip = rand_ip_from_network(ip_network(destination.get("ip_range", "8.8.8.0/24"), strict=False))
    except Exception:
        dest_ip = _random_external_ip()

    dhost      = destination.get("name", dest_ip)
    bytes_out  = random.randint(300, 2000)
    bytes_in   = random.randint(5000, 500000)
    duration   = random.randint(1, 30)
    src_port   = random.randint(49152, 65535)

    base_time = datetime.now(timezone.utc)
    logs = [_dns_precursor(config, server_ip, None, server_ip, dhost or dest_ip, event_time=base_time)]

    ext = {
        "act": "Accept",
        "src": server_ip, "dst": dest_ip,
        "spt": src_port, "dpt": 80,
        "proto": "6",
        "shost": server_ip, "dhost": dhost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": "http", "app": "HTTP",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": bytes_out, "in": bytes_in,
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept anomalous HTTP from server {server_ip} to {dhost} — "
            f"{bytes_out}B out / {bytes_in // 1024}KB in, {duration}s"
        ),
    }
    logs.append(_format_checkpoint_cef(config, ext,
                                        event_time=base_time + timedelta(seconds=0.5)))
    return logs


def _simulate_workstation_rdp(config, src_ip, user, shost):
    """Simulates a workstation-to-workstation RDP connection — anomalous lateral movement.

    In normal operations, users connect via RDP to servers, not to peer workstations.
    A workstation initiating RDP to another workstation is a red flag for lateral movement
    via stolen credentials or a compromised endpoint being used as a pivot.

    Triggers XSIAM: Workstation-to-workstation RDP / lateral movement analytics.
    """
    print(f"    - Check Point Module simulating: Workstation-to-Workstation RDP from {src_ip}")
    try:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        net     = ip_network(internal_net, strict=False)
        dest_ip = rand_ip_from_network(net)
        if dest_ip == src_ip:
            dest_ip = rand_ip_from_network(net)
    except Exception:
        dest_ip = "192.168.1.101"

    dhost     = dest_ip
    bytes_out = random.randint(10000, 200000)
    bytes_in  = random.randint(50000, 2000000)
    duration  = random.randint(120, 3600)
    src_port  = random.randint(49152, 65535)

    ext = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": src_port, "dpt": 3389,
        "proto": "6",
        "suser": user, "shost": shost, "dhost": dhost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
        "deviceDirection": "1",
        "service_id": "rdp", "app": "RDP",
        "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
        "out": bytes_out, "in": bytes_in,
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "reason": "TCP FIN",
        "ifname": "eth1",
        "msg": (
            f"Accept W2W RDP {src_ip} -> {dest_ip}:3389 (anomalous) — "
            f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in, {duration}s"
        ),
    }
    return _format_checkpoint_cef(config, ext)


def _simulate_rare_external_rdp(config, src_ip, user, shost):
    """DNS precursor + outbound RDP to rare external IP.

    Triggers XSIAM: outbound RDP to rare/unusual external destination analytics.
    """
    print(f"    - Check Point Module simulating: Rare External RDP from {src_ip}")
    dest_ip  = _random_external_ip()
    duration = random.randint(60, 1800)
    bytes_out = random.randint(10000, 200000)
    bytes_in  = random.randint(50000, 2000000)

    base_time = datetime.now(timezone.utc)
    logs = [_dns_precursor(config, src_ip, user, shost, dest_ip, event_time=base_time)]

    ext = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": 3389,
        "proto": "6",
        "suser": user, "shost": shost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": "rdp", "app": "RDP",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": bytes_out, "in": bytes_in,
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept outbound RDP from {src_ip} to external {dest_ip}:3389 — "
            f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in, {duration}s"
        ),
        "cefDeviceEventClassId": "traffic",
    }
    logs.append(_format_checkpoint_cef(config, ext,
                                        event_time=base_time + timedelta(seconds=0.5)))
    return logs


def _simulate_smtp_spray(config, src_ip, user, shost):
    """Simulates a compromised workstation acting as a spam bot / email worm.

    Generates 30–50 short SMTP session-close logs from one internal workstation to
    DISTINCT external IPs on port 25 (SMTP) or 587 (submission).  In normal operations,
    workstations relay mail through an internal mail server — they never connect directly
    to external MX servers.  A single workstation opening direct SMTP connections to
    dozens of unique external hosts in rapid succession is a strong indicator of:
        - Spam bot / botnet node sending unsolicited mail
        - Email worm propagating via SMTP
        - Credential-phishing campaign originating from a compromised endpoint

    Each session is short (< 30 s) with small byte counts typical of a single
    spam message envelope.

    Triggers XSIAM: anomalous SMTP from workstation / spam bot analytics.
    """
    print(f"    - Check Point Module simulating: SMTP Spray (spam bot) from {src_ip}")

    n_targets = random.randint(30, 50)
    dest_ips  = set()
    while len(dest_ips) < n_targets:
        dest_ips.add(_random_external_ip())

    logs = []
    base_time = datetime.now(timezone.utc)
    offset = 0.0
    for dst_ip in list(dest_ips)[:n_targets]:
        offset   += random.uniform(1.0, 5.0)
        smtp_port = random.choices([25, 587], weights=[70, 30], k=1)[0]
        duration  = random.randint(1, 30)
        bytes_out = random.randint(2000, 50000)   # single message envelope
        bytes_in  = random.randint(200, 2000)      # SMTP responses
        ext = {
            "act": "Accept",
            "src": src_ip, "dst": dst_ip,
            "spt": random.randint(49152, 65535), "dpt": smtp_port,
            "proto": "6",
            "suser": user, "shost": shost,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
            "deviceDirection": "1",
            "service_id": "smtp" if smtp_port == 25 else "submission",
            "app": "SMTP",
            "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
            "out": bytes_out, "in": bytes_in,
            "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
            "duration": str(duration),
            "reason": "TCP FIN",
            "ifname": "eth0",
            "msg": (
                f"Accept direct SMTP from workstation {src_ip} to external "
                f"{dst_ip}:{smtp_port} — {bytes_out}B out, {duration}s"
            ),
            "cefDeviceEventClassId": "traffic",
        }
        logs.append(_format_checkpoint_cef(config, ext,
                                           event_time=base_time + timedelta(seconds=offset)))
    return logs


def _simulate_smtp_large_exfil(config, src_ip, user, shost):
    """DNS precursor + large SMTP exfiltration.

    Triggers XSIAM: large outbound SMTP data transfer / email exfiltration analytics.
    """
    print(f"    - Check Point Module simulating: Large SMTP Exfiltration from {src_ip}")

    mail_mx_ranges = [
        "74.125.0.0/16", "40.76.0.0/14", "207.46.0.0/16",
        "198.2.128.0/18", "159.148.0.0/16",
    ]
    try:
        dest_ip = rand_ip_from_network(
            ip_network(random.choice(mail_mx_ranges), strict=False)
        )
    except Exception:
        dest_ip = _random_external_ip()

    smtp_port   = random.choices([587, 25], weights=[80, 20], k=1)[0]
    duration    = random.randint(300, 1200)
    bytes_out   = random.randint(104_857_600, 524_288_000)
    bytes_in    = random.randint(500, 5000)

    base_time = datetime.now(timezone.utc)
    logs = [_dns_precursor(config, src_ip, user, shost, dest_ip, event_time=base_time)]

    ext = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": smtp_port,
        "proto": "6",
        "suser": user, "shost": shost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": "submission" if smtp_port == 587 else "smtp",
        "app": "SMTP",
        "cs1": "Allow_SMTP_Relay", "cs1Label": "Rule Name",
        "out": bytes_out,
        "in":  bytes_in,
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept SMTP from workstation {src_ip} to {dest_ip}:{smtp_port} — "
            f"{bytes_out // (1024 * 1024)}MB outbound in {duration}s"
        ),
        "cefDeviceEventClassId": "traffic",
    }
    logs.append(_format_checkpoint_cef(config, ext,
                                        event_time=base_time + timedelta(seconds=1)))
    return logs


def _simulate_ftp_large_exfil(config, src_ip, user, shost):
    """DNS precursor + large outbound FTP exfiltration.

    Triggers XSIAM: outbound FTP large data transfer / exfiltration analytics.
    """
    print(f"    - Check Point Module simulating: Large FTP Exfiltration from {src_ip}")

    dest_ip     = _random_external_ip()
    duration    = random.randint(300, 1800)
    bytes_out   = random.randint(104_857_600, 524_288_000)
    bytes_in    = random.randint(500, 10000)

    base_time = datetime.now(timezone.utc)
    logs = [_dns_precursor(config, src_ip, user, shost, dest_ip, event_time=base_time)]

    ext = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": 21,
        "proto": "6",
        "suser": user, "shost": shost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": "ftp", "app": "FTP",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": bytes_out,
        "in":  bytes_in,
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept outbound FTP from workstation {src_ip} to {dest_ip}:21 — "
            f"{bytes_out // (1024 * 1024)}MB outbound in {duration}s"
        ),
        "cefDeviceEventClassId": "traffic",
    }
    logs.append(_format_checkpoint_cef(config, ext,
                                        event_time=base_time + timedelta(seconds=1)))
    return logs


def _simulate_ddns_connection(config, src_ip, user, shost):
    """Simulates an internal workstation connecting to a known dynamic DNS domain.

    Dynamic DNS (DDNS) services let anyone point a free hostname at an arbitrary
    IP address.  Attackers use them for cheap, disposable C2 infrastructure —
    the hostname stays the same while the backing IP rotates to evade blocklists.
    Legitimate enterprise traffic almost never involves DDNS providers.

    Generates two logs in sequence:
        1. A DNS query (UDP/53) resolving the DDNS hostname via the internal resolver.
        2. An HTTPS session (TCP/443) to the resolved external IP with the DDNS
           hostname in dhost.

    The dns_query and dhost fields carry the full DDNS hostname so XSIAM
    analytics can match against DDNS provider domain lists.

    Triggers XSIAM: connection to dynamic DNS domain / suspicious C2 infrastructure.
    """
    print(f"    - Check Point Module simulating: Dynamic DNS Connection from {src_ip}")

    ddns_providers = [
        "duckdns.org",     "no-ip.com",       "dynu.com",
        "afraid.org",      "hopto.org",        "zapto.org",
        "sytes.net",       "ddns.net",         "servebeer.com",
        "myftp.biz",       "myvnc.com",        "redirectme.net",
    ]
    provider = random.choice(ddns_providers)
    # Random subdomain mimicking attacker-chosen hostnames
    subdomain = random.choice([
        "update-service", "cdn-relay", "mail-check", "vpn-gateway",
        "api-health", "sync-node", "cloud-backup", "office-proxy",
        "fw-mgmt", "dns-cache",
    ])
    ddns_hostname = f"{subdomain}.{provider}"
    resolved_ip   = _random_external_ip()

    checkpoint_conf = config.get(CONFIG_KEY, {})
    dns_server = "8.8.8.8"   # internal DNS forwarding query

    logs = []
    base_time = datetime.now(timezone.utc)

    # Log 1: DNS query resolving the DDNS hostname
    dns_ext = {
        "act": "Accept",
        "src": src_ip, "dst": dns_server,
        "spt": random.randint(49152, 65535), "dpt": 53,
        "proto": "17",
        "suser": user, "shost": shost, "dhost": "dns.google",
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": "domain-udp", "app": "DNS",
        "cs1": "Allow_DNS", "cs1Label": "Rule Name",
        "out": random.randint(60, 120),
        "in":  random.randint(80, 300),
        "cn1": 0, "cn1Label": "Elapsed Time in Seconds",
        "dns_query": ddns_hostname,
        "dns_type": "A",
        "ifname": "eth0",
        "msg": f"Accept DNS query for DDNS hostname {ddns_hostname} from {src_ip}",
        "cefDeviceEventClassId": "traffic",
    }
    logs.append(_format_checkpoint_cef(config, dns_ext, event_time=base_time))

    # Log 2: HTTPS session to the resolved DDNS IP
    duration  = random.randint(30, 600)
    bytes_out = random.randint(1000, 100000)
    bytes_in  = random.randint(5000, 500000)
    https_ext = {
        "act": "Accept",
        "src": src_ip, "dst": resolved_ip,
        "spt": random.randint(49152, 65535), "dpt": 443,
        "proto": "6",
        "suser": user, "shost": shost, "dhost": ddns_hostname,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "service_id": "https", "app": "SSL",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": bytes_out, "in": bytes_in,
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept HTTPS from {src_ip} to DDNS host {ddns_hostname} "
            f"({resolved_ip}:443) — {bytes_out // 1024}KB out / {bytes_in // 1024}KB in"
        ),
        "cefDeviceEventClassId": "traffic",
    }
    logs.append(_format_checkpoint_cef(config, https_ext,
                                       event_time=base_time + timedelta(seconds=1)))
    return logs


def _simulate_smartdefense_event(config, src_ip, user, shost):
    """Simulates a Check Point SmartDefense threat-prevention drop.

    SmartDefense protections operate at the network/protocol level (below the
    application layer) — they detect malformed packets, protocol anomalies, and
    volume-based DoS attacks before a connection is established.

    These events are emitted with device_product="SmartDefense" which routes them
    to the check_point_smartdefense_raw XSIAM dataset.

    Triggers XSIAM: SmartDefense / network anomaly detection.
    """
    print(f"    - Check Point Module simulating: SmartDefense Event from {src_ip}")
    attacker_ip = _random_external_ip()

    protections = [
        ("2001000", "SYN Attack",              "Consecutive SYN packets without completing handshake",         "6",  80),
        ("2001001", "Ping of Death",           "Oversized ICMP echo request",                                  "1",  0),
        ("2001002", "Teardrop Attack",         "Overlapping fragmented IP packets",                            "17", 0),
        ("2001003", "IP Spoofing",             "Source IP address spoofing detected",                          "6",  443),
        ("2001004", "LAND Attack",             "Source IP equals destination IP",                              "6",  0),
        ("2001005", "Smurf Attack",            "ICMP broadcast amplification attempt",                         "1",  0),
        ("2001006", "TCP NULL Scan",           "TCP segment with no flags set",                                "6",  22),
        ("2001007", "FIN Scan",                "TCP FIN without prior SYN/ACK",                                "6",  22),
        ("2001008", "Xmas Scan",               "TCP segment with FIN/PSH/URG flags",                           "6",  22),
        ("2001009", "Small PMTU",              "IP fragmentation with path MTU below threshold",               "6",  443),
        ("2001010", "Large ICMP Packet",       "ICMP packet size exceeds configured limit",                    "1",  0),
        ("2001011", "Port Sweep",              "Single source scanning multiple destination ports",            "6",  None),
        ("2001012", "Network Quota Exceeded",  "Connection rate from source exceeds configured quota",         "6",  None),
        ("2001013", "DNS Protocol Anomaly",    "Malformed DNS query structure",                                "17", 53),
        ("2001014", "HTTP Protocol Anomaly",   "HTTP request violates RFC compliance checks",                  "6",  80),
    ]

    sig_id, protection_name, description, proto_num, fixed_dport = random.choice(protections)
    if fixed_dport is None:
        fixed_dport = random.choice([22, 80, 443, 445, 3389]) if proto_num == "6" else 53
    victim_ip = random.choice(config.get('internal_servers', ['10.0.10.50']))

    extensions = {
        "signatureId": sig_id,
        "name":        protection_name,
        "severity":    "8",
        "act":         "Drop",
        "src": attacker_ip, "dst": victim_ip,
        "spt": random.randint(49152, 65535), "dpt": fixed_dport,
        "proto": proto_num,
        "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
        "deviceDirection": "0",
        "cs1": "Threat_Prevention_Policy",  "cs1Label": "Threat Prevention Rule Name",
        "cs3": "IPS",                        "cs3Label": "Protection Type",
        "cs4": protection_name,              "cs4Label": "Protection Name",
        "flexString2": description,          "flexString2Label": "Attack Information",
        "blade": "IPS",
        "session_id": _generate_session_id(),
        "ifname": "eth0",
        "msg": f"SmartDefense drop: {protection_name} from {attacker_ip} to {victim_ip} — {description}",
        "cefDeviceEventClassId": "smartdefense",
    }
    return _format_checkpoint_cef(config, extensions, device_product="SmartDefense")


def _simulate_app_control_block(config, src_ip, user, shost):
    """Simulates a Check Point Application Control block event.

    Application Control identifies applications by deep packet inspection
    regardless of port or protocol, and enforces policy against prohibited apps
    (social media, P2P, anonymisers, gaming, etc.).

    These events use device_product="Application Control" which routes them to
    the check_point_app_control_raw XSIAM dataset.

    Triggers XSIAM: Application Control / prohibited application analytics.
    """
    print(f"    - Check Point Module simulating: App Control Block from {src_ip}")
    dest_ip = _random_external_ip()

    blocked_apps = [
        ("BitTorrent",       "Peer-to-Peer",        "P2P file sharing",                    "17", 6881),
        ("Tor Browser",      "Anonymizer",          "Anonymous proxy network client",       "6",  9001),
        ("TeamViewer",       "Remote Access",       "Unauthorized remote access tool",      "6",  5938),
        ("Skype",            "VoIP",                "Encrypted P2P VOIP — policy violation","6",  443),
        ("Dropbox",          "File Storage",        "Unsanctioned cloud storage",           "6",  443),
        ("WhatsApp",         "Instant Messaging",   "Unsanctioned messaging app",           "6",  443),
        ("Facebook",         "Social Networking",   "Social media access blocked by policy","6",  443),
        ("uTorrent",         "Peer-to-Peer",        "P2P BitTorrent client",                "17", 6881),
        ("Freenet",          "Anonymizer",          "Anonymous P2P network — high risk",    "6",  9481),
        ("I2P",              "Anonymizer",          "Invisible Internet Project traffic",   "6",  4444),
        ("Steam",            "Gaming",              "Online gaming platform — blocked",     "6",  27036),
        ("Psiphon",          "Anonymizer",          "Anti-censorship proxy circumvention",  "6",  443),
        ("Hola VPN",         "Anonymizer",          "P2P VPN anonymiser — blocked",         "6",  443),
        ("Remote Desktop",   "Remote Access",       "RDP to external host — policy denied", "6",  3389),
        ("MediaFire",        "File Storage",        "File sharing to unsanctioned service", "6",  443),
    ]

    app_name, app_category, block_reason, proto_num, dport = random.choice(blocked_apps)

    extensions = {
        "signatureId": app_category,
        "name":        app_name,
        "severity":    "5",
        "act":         "Drop",
        "src": src_ip,  "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": dport,
        "proto": proto_num,
        "suser": user, "shost": shost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "cs1": "Block_Unauthorized_Applications", "cs1Label": "Application Rule Name",
        "cs2": "Block_Unauthorized_Applications", "cs2Label": "Rule Name",
        "cs6": app_name,                          "cs6Label": "Application Name",
        "blade": "Application Control",
        "app": app_name,
        "request": f"https://{dest_ip}/",  "requestMethod": "CONNECT",
        "duration": "0",
        "reason": "Application Policy Violation",
        "ifname": "eth0",
        "msg": f"App Control block: {app_name} ({app_category}) from {src_ip} — {block_reason}",
        "cefDeviceEventClassId": "app_control",
    }
    return _format_checkpoint_cef(config, extensions, device_product="Application Control")


# ---------------------------------------------------------------------------
# Main threat dispatcher
# ---------------------------------------------------------------------------

def _generate_threat_log(config, session_context=None, forced_event=None):
    """Generates a random threat event (IPS, URL Filtering, Identity, or Analytics-based).
    If forced_event is given, that specific event is generated instead of a random pick.
    """
    user_info = get_random_user(session_context, preferred_device_type='workstation') if session_context else None
    if user_info:
        user, src_ip, shost = user_info['username'], user_info['ip'], user_info['hostname']
    else:
        user_map = (config.get(CONFIG_KEY, {}).get('user_ip_map')
                    or config.get('shared_user_ip_map', {}))
        if user_map:
            user, src_ip = random.choice(list(user_map.items()))
            _, shost = _get_user_and_host_info(config, src_ip)
        else:
            src_ip = random.choice(config.get('internal_servers', ['192.168.1.10']))
            user, shost = 'unknown', None

    if forced_event:
        # Accept both display names ("[Non-Analytic] ips") and raw keys ("ips").
        threat_type = _DISPLAY_TO_EVENT.get(forced_event,
                      _DISPLAY_TO_EVENT.get(forced_event.lower(), forced_event.lower()))
    else:
        module_config = config.get(CONFIG_KEY, {})
        event_mix     = module_config.get('event_mix', {})
        threat_events = event_mix.get('threat', [])

        if not threat_events:  # Fallback: use module-level defaults
            threat_events = _DEFAULT_THREAT_EVENTS

        threat_type = random.choices(
            [e['event']  for e in threat_events],
            weights=[e['weight'] for e in threat_events],
            k=1,
        )[0]

    # Convert raw event key to display name for the returned tuple so the
    # dashboard / CLI threat_names set (built from get_threat_names()) matches.
    display_name = _EVENT_DISPLAY_NAMES.get(threat_type, threat_type)

    # --- multi-event generators ---
    if threat_type == 'large_upload':
        return (_simulate_large_upload(config, src_ip, user, shost), display_name)
    if threat_type == 'port_scan':
        return (_simulate_port_scan(config, src_ip, user, shost), display_name)
    if threat_type == 'auth_brute_force':
        return (_simulate_auth_brute_force(config, src_ip, user, shost), display_name)
    if threat_type == 'lateral_movement':
        return (_simulate_lateral_movement(config, src_ip, user, shost), display_name)
    if threat_type == 'rare_ssh':
        return (_simulate_rare_ssh(config, src_ip, user, shost), display_name)
    if threat_type == 'tor_connection':
        return (_simulate_tor_connection(config, src_ip, user, shost), display_name)
    if threat_type == 'vpn_brute_force':
        return (_simulate_vpn_brute_force(config, src_ip, user, shost), display_name)
    if threat_type == 'vpn_impossible_travel':
        return (_simulate_vpn_impossible_travel(config, src_ip, user, shost), display_name)
    if threat_type == 'dns_c2_beacon':
        return (_simulate_dns_c2_beacon(config, src_ip, user, shost), display_name)
    if threat_type == 'server_outbound_http':
        return (_simulate_server_outbound_http(config), display_name)
    if threat_type == 'workstation_rdp':
        return (_simulate_workstation_rdp(config, src_ip, user, shost), display_name)
    if threat_type == 'smartdefense':
        return (_simulate_smartdefense_event(config, src_ip, user, shost), display_name)
    if threat_type == 'app_control':
        return (_simulate_app_control_block(config, src_ip, user, shost), display_name)
    if threat_type == 'vpn_tor_login':
        return (_simulate_vpn_tor_login(config, src_ip, user, shost), display_name)
    if threat_type == 'smb_new_host_lateral':
        return (_simulate_smb_new_host_lateral(config, src_ip, user, shost), display_name)
    if threat_type == 'smb_rare_file_transfer':
        return (_simulate_smb_rare_file_transfer(config, src_ip, user, shost), display_name)
    if threat_type == 'smb_share_enumeration':
        return (_simulate_smb_share_enumeration(config, src_ip, user, shost), display_name)
    if threat_type == 'rare_external_rdp':
        return (_simulate_rare_external_rdp(config, src_ip, user, shost), display_name)
    if threat_type == 'smtp_spray':
        return (_simulate_smtp_spray(config, src_ip, user, shost), display_name)
    if threat_type == 'smtp_large_exfil':
        return (_simulate_smtp_large_exfil(config, src_ip, user, shost), display_name)
    if threat_type == 'ftp_large_exfil':
        return (_simulate_ftp_large_exfil(config, src_ip, user, shost), display_name)
    if threat_type == 'ddns_connection':
        return (_simulate_ddns_connection(config, src_ip, user, shost), display_name)

    # --- single-event generators: IPS, URL block, identity ---
    # Each builds its own complete extensions dict with correct src/dst/zones/blade.

    if threat_type == 'ips':
        # IPS: inbound attack — external attacker targets internal server.
        print("    - Check Point Module simulating: IPS Drop (external -> internal)")
        attacker_ip = _random_external_ip()
        victim_ip   = random.choice(config.get('internal_servers', ['10.0.10.50']))
        ips_protections = [
            ("1002100", "Apache Log4j Remote Code Execution (CVE-2021-44228)",          "tcp",  443),
            ("1001100", "Microsoft MS17-010 SMBv1 Remote Code Execution (EternalBlue)", "tcp",  445),
            ("1004321", "Microsoft Exchange Server ProxyLogon (CVE-2021-26855)",         "tcp",  443),
            ("1003456", "OpenSSL Heartbleed Buffer Over-read (CVE-2014-0160)",           "tcp",  443),
            ("1000789", "SQL Injection via HTTP",                                        "tcp",  80),
            ("1005678", "Shellshock Bash Remote Code Execution (CVE-2014-6271)",         "tcp",  80),
            ("1006543", "TCP SYN Flood DoS",                                             "tcp",  80),
            ("1009012", "SMB Brute Force Login Attempt",                                 "tcp",  445),
            ("1010123", "RDP BlueKeep Remote Code Execution (CVE-2019-0708)",            "tcp",  3389),
            ("1011234", "SMB Pass-the-Hash Authentication Attempt",                      "tcp",  445),
            ("1007890", "DNS Amplification Reflection Attack",                           "udp",  53),
            ("1008901", "ICMP Flood DoS",                                                "icmp", 0),
        ]
        sig_id, protection_name, attack_proto, attack_dport = random.choice(ips_protections)
        proto_num = {"tcp": "6", "udp": "17", "icmp": "1"}.get(attack_proto, "6")
        # Extract CVE reference from protection name if present
        _cve_match = re.search(r'CVE-\d{4}-\d+', protection_name)
        cve_ref = _cve_match.group(0) if _cve_match else "N/A"
        extensions = {
            "signatureId": protection_name,
            "name":        protection_name,
            "severity":    "8",
            "act":         "Drop",
            "src": attacker_ip, "dst": victim_ip,
            "spt": random.randint(49152, 65535), "dpt": attack_dport,
            "proto": proto_num,
            "deviceInboundInterface": "External", "deviceOutboundInterface": "Internal",
            "deviceDirection": "0",
            "cs1": "IPS_Protection",    "cs1Label": "Threat Prevention Rule Name",
            "flexNumber1": 4,           "flexNumber1Label": "Confidence",
            "cs3": "IPS",               "cs3Label": "Protection Type",
            "cs4": protection_name,     "cs4Label": "Protection Name",
            "blade": "IPS",
            "industry_reference": cve_ref if cve_ref != "N/A" else None,
            "protection_type": "Signature",
            "ifname": "eth0",
            "msg": f"IPS block: {protection_name} from {attacker_ip} to {victim_ip}:{attack_dport}",
            "cefDeviceEventClassId": "threat",
        }
        return (_format_checkpoint_cef(config, extensions, device_product="SmartDefense"), display_name)

    if threat_type == 'url_block':
        # URL filtering: internal user attempts to reach a blocked external domain.
        print(f"    - Check Point Module simulating: URL Filter Block from {src_ip}")
        blocked_cats = config.get(CONFIG_KEY, {}).get('blocked_url_categories', {})
        cat, domain = random.choice(list(blocked_cats.items())) if blocked_cats else ("Phishing", "evil-site.com")
        dest_ip = _random_external_ip()
        extensions = {
            "signatureId": cat,
            "name":        domain,
            "severity":    "5",
            "act":         "Drop",
            "src": src_ip,  "dst": dest_ip,
            "spt": random.randint(49152, 65535), "dpt": 443,
            "proto": "6",
            "suser": user, "shost": shost, "dhost": domain,
            "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
            "deviceDirection": "1",
            "cs1": "Block_Malicious_Categories", "cs1Label": "Application Rule Name",
            "cs2": "Block_Malicious_Categories", "cs2Label": "Rule Name",
            "cs5": cat,                           "cs5Label": "Matched Category",
            "cp_severity": "Medium",
            "blade": "URL Filtering",
            "request": f"https://{domain}/index.html", "requestMethod": "GET",
            "duration": "0",
            "reason": "URL Categorization",
            "ifname": "eth0",
            "msg": f"URL blocked: {domain} (category: {cat})",
            "cefDeviceEventClassId": "url_filtering",
        }
        return (_format_checkpoint_cef(config, extensions, device_product="URL Filtering"), display_name)

    # identity – single failed login (internal user → DC)
    print(f"    - Check Point Module simulating: Failed Login from {src_ip}")
    dc_ip = random.choice(config.get('internal_servers', ['10.0.0.10']))
    extensions = {
        "signatureId": "45678",
        "name":        "Identity Awareness",
        "severity":    "3",
        "act":         "Failed Log In",
        "auth_status": "Failed Log In",
        "src": src_ip, "dst": dc_ip,
        "spt": random.randint(49152, 65535), "dpt": 389,
        "proto": "6",
        "suser": user, "shost": shost,
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "Internal",
        "deviceDirection": "1",
        "cs3": "user",     "cs3Label": "User Type",
        "cs5": "LDAP", "cs5Label": "Authentication Method",
        "blade": "Identity Awareness",
        "reason": "Authorization Failed",
        "dhost": "dc01.examplecorp.com",
        "ifname": "eth0",
        "msg": f"Authentication failed for {user} from {src_ip}",
        "cefDeviceEventClassId": "identity",
    }
    return (_format_checkpoint_cef(config, extensions, device_product="Identity Awareness"), display_name)


# ---------------------------------------------------------------------------
# Scenario log generator
# ---------------------------------------------------------------------------

def _generate_scenario_log(config, scenario):
    """Generates a single log entry for a storytelling / scripted scenario."""
    print(f"    - Check Point Module creating scenario log: {scenario.get('name', 'Unknown')}")
    user, shost = _get_user_and_host_info(config, scenario.get('source_ip'))
    extensions = {
        "act": scenario.get('action', 'Accept'),
        "src": scenario.get('source_ip'),
        "dst": scenario.get('dest_ip'),
        "spt": random.randint(49152, 65535),
        "dpt": scenario.get('dest_port', 443),
        "proto": "6",
        "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
        "deviceDirection": "1",
        "cs1": "Scenario_Rule", "cs1Label": "Rule Name",
        "cefDeviceEventClassId": "traffic",
        "request": f"https://{scenario.get('dest_domain')}/",
        "suser": user,
        "shost": shost,
        "ifname": "eth0",
        "msg": f"Scenario traffic from {scenario.get('source_ip')} to {scenario.get('dest_domain')}",
    }
    return _format_checkpoint_cef(config, extensions)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_log(config, scenario=None, threat_level="Realistic", benign_only=False, context=None, scenario_event=None):
    """Main log generation function for Check Point."""
    global last_threat_event_time
    session_context = (context or {}).get('session_context')

    # ---- scenario_event string dispatch ----
    if scenario_event:
        ctx    = context or {}
        src_ip = ctx.get('src_ip')
        user   = ctx.get('user', 'unknown')
        shost  = None
        if src_ip:
            user, shost = _get_user_and_host_info(config, src_ip)
        else:
            user_info = get_random_user(session_context, preferred_device_type='workstation') if session_context else None
            if user_info:
                src_ip = user_info['ip']
                user   = user_info['username']
                shost  = user_info['hostname']
            else:
                internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
                src_ip = rand_ip_from_network(ip_network(random.choice(internal_nets)))

        if scenario_event == "THREAT_BLOCK":
            print(f"    - Check Point Module simulating: THREAT_BLOCK URL block from {src_ip}")
            blocked_cats = config.get(CONFIG_KEY, {}).get('blocked_url_categories', {})
            cat, domain  = random.choice(list(blocked_cats.items())) if blocked_cats else ("Phishing", "evil-site.com")
            dest_ip      = _random_external_ip()
            extensions   = {
                "signatureId": cat,
                "name":        domain,
                "severity":    "5",
                "act":         "Drop",
                "src": src_ip,  "dst": dest_ip,
                "spt": random.randint(49152, 65535), "dpt": 443,
                "proto": "6",
                "suser": user, "shost": shost, "dhost": domain,
                "deviceInboundInterface": "Internal", "deviceOutboundInterface": "External",
                "deviceDirection": "1",
                "cs1": "Block_Malicious_Categories", "cs1Label": "Application Rule Name",
                "cs2": "Block_Malicious_Categories", "cs2Label": "Rule Name",
                "cs5": cat,                           "cs5Label": "Matched Category",
                "cp_severity": "Medium",
                "blade": "URL Filtering",
                "request": f"https://{domain}/index.html", "requestMethod": "GET",
                "duration": "0",
                "reason": "URL Categorization",
                "ifname": "eth0",
                "msg": f"URL blocked: {domain} (category: {cat})",
                "cefDeviceEventClassId": "url_filtering",
            }
            result = _format_checkpoint_cef(config, extensions, device_product="URL Filtering")
            return (result, "THREAT_BLOCK")

        elif scenario_event == "LARGE_EGRESS":
            print(f"    - Check Point Module simulating: LARGE_EGRESS upload from {src_ip}")
            result = _simulate_large_upload(config, src_ip, user, shost)
            return (result, "LARGE_EGRESS")

        # Named threat from dashboard — dispatch to the specific event
        return _generate_threat_log(config, session_context, forced_event=scenario_event)

    if scenario:
        return _generate_scenario_log(config, scenario)

    if benign_only:
        return _generate_benign_log(config, session_context)

    interval     = _get_threat_interval(threat_level, config)
    current_time = time.time()

    if threat_level == "Insane" and random.random() < 0.8:
        return _generate_threat_log(config, session_context)

    if interval > 0 and (current_time - last_threat_event_time) > interval:
        last_threat_event_time = current_time
        return _generate_threat_log(config, session_context)

    return _generate_benign_log(config, session_context)
