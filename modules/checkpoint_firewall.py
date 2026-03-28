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
    from modules.session_utils import get_random_user, get_user_by_name, rand_ip_from_network
except ImportError:
    from session_utils import get_random_user, get_user_by_name, rand_ip_from_network

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
_DEFAULT_THREAT_EVENTS = [
    {"event": "ips",                  "weight": 18},
    {"event": "port_scan",            "weight": 14},
    {"event": "auth_brute_force",     "weight": 11},
    {"event": "lateral_movement",     "weight": 11},
    {"event": "url_block",            "weight": 8},
    {"event": "vpn_brute_force",      "weight": 8},
    {"event": "large_upload",         "weight": 5},
    {"event": "rare_ssh",             "weight": 3},
    {"event": "tor_connection",       "weight": 3},
    {"event": "vpn_impossible_travel","weight": 3},
    {"event": "dns_c2_beacon",        "weight": 3},
    {"event": "server_outbound_http", "weight": 2},
    {"event": "workstation_rdp",      "weight": 2},
    {"event": "identity",             "weight": 2},
    {"event": "smartdefense",         "weight": 4},
    {"event": "app_control",          "weight": 4},
    {"event": "vpn_tor_login",        "weight": 3},
    {"event": "smb_new_host_lateral", "weight": 4},
    {"event": "smb_rare_file_transfer","weight": 3},
    {"event": "smb_share_enumeration","weight": 5},
]


def get_threat_names():
    """Return available threat names dynamically from _DEFAULT_THREAT_EVENTS.
    Adding a new entry to _DEFAULT_THREAT_EVENTS automatically surfaces it here."""
    return [e["event"] for e in _DEFAULT_THREAT_EVENTS]


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
    building the extension string.  Default values are applied for fields that are
    always present in real Check Point R80+ logs but may not be set by callers:
        loguid       – unique log record identifier ({0xhex,...} format)
        origin       – reporting gateway hostname
        session_id_  – connection-table session identifier (integer string)
        layer_name   – policy layer name ("Network")
        layer_uuid   – policy layer UUID (deterministic per gateway)

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

    signature_id = ext.pop("signatureId", "0")
    name         = ext.pop("name",        "Log")
    severity     = ext.pop("severity",    "4")

    cef_header = (
        f"CEF:{cef_version}|{device_vendor}|{device_product}|"
        f"{device_version}|{signature_id}|{name}|{severity}|"
    )

    hostname = checkpoint_conf.get("hostname", "CP-FW-1")
    ext.pop("cefDeviceEventClassId", None)  # CEF header field, not an extension key
    ext.setdefault("loguid",      _generate_loguid())
    ext.setdefault("origin",      hostname)
    ext.setdefault("rt",          int(time.time() * 1000))
    ext.setdefault("session_id",  _generate_session_id())   # CP spec uses session_id (XIF bug fix pending)
    ext.setdefault("layer_name",  "Network")
    ext.setdefault("layer_uuid",  _get_layer_uuid(hostname))
    ext.setdefault("blade",       "Firewall")

    extension_string = " ".join(
        f"{key}={_cef_escape(value)}" for key, value in ext.items() if value is not None
    )

    timestamp = (event_time or datetime.now(timezone.utc)).strftime('%b %d %H:%M:%S')
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
        ['traffic', 'inbound_block', 'dns', 'icmp', 'smtp', 'ntp', 'smb_internal'],
        weights=[52, 22, 10, 4, 5, 4, 3],
        k=1,
    )[0]

    destination = random.choice(config.get('benign_egress_destinations', [{}]))
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
            "inzone": "Internal", "outzone": "External",
            "service_id": "icmp-echo",
            "cs1": "Allow_Ping", "cs1Label": "Rule Name",
            "cn1": _icmp_dur, "cn1Label": "Elapsed Time in Seconds",
            "duration": str(_icmp_dur),
            "ifname": "eth0",
            "msg": f"Accept ICMP echo from {src_ip} to {dest_ip}",
            "cefDeviceEventClassId": "traffic",
        }
    elif log_type == 'dns':
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": "8.8.8.8", "dpt": 53, "proto": "17",
            "suser": user, "shost": shost, "dhost": "dns.google",
            "dns_query": random.choice(config.get('benign_domains', ['example.com'])),
            "dns_type": "A",
            "cs1": "Allow_DNS", "cs1Label": "Rule Name",
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
            "inzone": "External", "outzone": "Internal",
            "cs1": "Default_Inbound_Block", "cs1Label": "Rule Name",
            "service_id": service,
            "action_reason": "Policy",
            "ifname": "eth0",
            "msg": f"{act} inbound {service.upper()} from {ext_src_ip} to {target_ip}:{target_port}",
            "cefDeviceEventClassId": "traffic",
        }

    elif log_type == 'smtp':
        # Outbound email from internal mail relay to external MX — SMTP/25 or SMTPS/587
        smtp_port   = random.choice([25, 587])
        smtp_server = random.choice(config.get('internal_servers', [src_ip]))
        mail_dest   = random.choice(["74.125.0.0/16", "40.76.0.0/14", "207.46.0.0/16"])
        try:
            mail_dest_ip = rand_ip_from_network(ip_network(mail_dest, strict=False))
        except Exception:
            mail_dest_ip = dest_ip
        extensions = {
            "act": "Accept",
            "src": smtp_server, "dst": mail_dest_ip,
            "spt": random.randint(49152, 65535), "dpt": smtp_port,
            "proto": "6",
            "suser": user, "shost": shost,
            "inzone": "Internal", "outzone": "External",
            "service_id": "smtp" if smtp_port == 25 else "submission",
            "app": "SMTP",
            "cs1": "Allow_SMTP_Relay", "cs1Label": "Rule Name",
            "out": random.randint(1_000, 500_000),
            "in":  random.randint(200, 5_000),
            "ifname": "eth0",
            "msg": f"Accept SMTP relay from {smtp_server} to {mail_dest_ip}:{smtp_port}",
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
            "spt": 123, "dpt": 123,
            "proto": "17",  # UDP
            "suser": user, "shost": shost,
            "inzone": "Internal", "outzone": "External",
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
            "inzone": "Internal", "outzone": "Internal",
            "service_id": "microsoft-ds",
            "app": "SMB",
            "cs1": "Allow_Internal_SMB", "cs1Label": "Rule Name",
            "out": random.randint(10_000, 5_000_000),
            "in":  random.randint(10_000, 50_000_000),
            "ifname": "eth1",
            "msg": f"Accept internal SMB from {src_ip} to {file_server}:445",
            "cefDeviceEventClassId": "traffic",
        }

    else:  # HTTP/HTTPS traffic
        dest_port  = random.choice([80, 443])
        proto_name = "HTTPS" if dest_port == 443 else "HTTP"
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": dest_ip,
            "spt": random.randint(49152, 65535), "dpt": dest_port,
            "proto": "6",
            "suser": user, "shost": shost, "dhost": dhost,
            "inzone": "Internal", "outzone": "External",
            "service_id": "https" if dest_port == 443 else "http",
            "app": "SSL" if dest_port == 443 else "HTTP",
            "cs1": "Standard_Web_Access", "cs1Label": "Rule Name",
            "out": random.randint(500, 15000),
            "in":  random.randint(10000, 200000),
            "client_outbound_packets": random.randint(1, 50),
            "server_outbound_packets": random.randint(5, 500),
            "ifname": "eth0",
            "msg": f"Accept {proto_name} from {src_ip} to {dest_ip}",
            "cefDeviceEventClassId": "traffic",
        }

    return _format_checkpoint_cef(config, extensions)


# ---------------------------------------------------------------------------
# Threat / analytics event generators
# ---------------------------------------------------------------------------

def _simulate_large_upload(config, src_ip, user, shost):
    """Simulates a large outbound file transfer — single session-close log with final byte counters.

    Produces one log at session close (100 MB – 500 MB outbound) matching real Check Point
    Log Exporter behaviour: one CEF record per session at close, act="Accept".

    Triggers XSIAM: large outbound data transfer / exfiltration analytics.
    """
    print(f"    - Check Point Module simulating: Large Upload from {src_ip}")
    destination = random.choice(config.get('exfiltration_destinations', [{}]))
    try:
        dest_ip = rand_ip_from_network(ip_network(destination.get("ip_range", "154.53.224.0/24"), strict=False))
    except (ValueError, Exception):
        dest_ip = "154.53.224.10"
    dhost = destination.get("domain", dest_ip)

    duration  = random.randint(300, 1200)
    bytes_out = random.randint(104857600, 524288000)  # 100 MB – 500 MB
    extensions = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": 443,
        "proto": "6",
        "suser": user, "shost": shost, "dhost": dhost,
        "service_id": "https", "app": "SSL",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": bytes_out,
        "in":  random.randint(1000, 5000),
        "client_outbound_packets": random.randint(1, 50),
        "server_outbound_packets": random.randint(5, 500),
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "action_reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept HTTPS from {src_ip} to {dest_ip} — "
            f"{bytes_out // (1024 * 1024)}MB outbound in {duration}s"
        ),
    }
    return _format_checkpoint_cef(config, extensions)


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
    for port in random.sample(range(1, 1024), k=random.randint(50, 100)):
        src_port = random.randint(49152, 65535)
        extensions = {
            "act": "Accept",
            "src": src_ip, "dst": dest_ip,
            "spt": src_port, "dpt": port,
            "proto": "6",
            "suser": user, "shost": shost, "dhost": dhost,
            "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
            "out": 60, "in": 0,
            "client_outbound_packets": random.randint(1, 3),
            "server_outbound_packets": 0,
            "cn1": 0, "cn1Label": "Elapsed Time in Seconds",
            "duration": "0",
            "action_reason": "TCP Reset",
            "ifname": "eth0",
            "msg": f"Accept TCP {src_ip}:{src_port} to {dest_ip}:{port} (RST — port closed)",
        }
        logs.append(_format_checkpoint_cef(config, extensions))
    return logs


def _simulate_rare_ssh(config, src_ip, user, shost):
    """Simulates an outbound SSH connection to a rare (first-seen) external IP.

    Triggers XSIAM: outbound SSH to rare external destination.
    """
    print(f"    - Check Point Module simulating: Rare External SSH from {src_ip}")
    dest_ip = _random_external_ip()
    extensions = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": 22,
        "proto": "6",
        "suser": user, "shost": shost,
        "service_id": "ssh", "app": "SSH",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": random.randint(1000, 50000),
        "in":  random.randint(1000, 50000),
        "client_outbound_packets": random.randint(1, 50),
        "server_outbound_packets": random.randint(5, 500),
        "ifname": "eth0",
        "msg": f"Accept SSH from {src_ip} to rare external IP {dest_ip}",
        "cefDeviceEventClassId": "traffic",
    }
    return _format_checkpoint_cef(config, extensions)


def _simulate_tor_connection(config, src_ip, user, shost):
    """Simulates an internal user connecting to a known Tor exit node.

    Generates a single session-close log for a full TCP session to a Tor relay
    on port 443 (camouflaged as HTTPS), 9001 (Tor OR port), or 9030 (directory).
    The connection was permitted by the outbound web rule — the threat is the
    successful anonymisation tunnel being established.

    Triggers XSIAM: "Connection to Tor/Anonymous Proxy" analytics detection.
    """
    print(f"    - Check Point Module simulating: Tor Connection from {src_ip}")

    tor_nodes = config.get('tor_exit_nodes', [{'ip': '198.51.100.77'}])
    dest_ip   = random.choice(tor_nodes).get('ip', '198.51.100.77')

    # 443 is most common (blends with HTTPS), 9001 is Tor OR port, 9030 directory
    tor_port   = random.choices([443, 9001, 9030], weights=[60, 30, 10], k=1)[0]
    service_id = "https" if tor_port == 443 else "tor"
    app        = "SSL"         if tor_port == 443 else "Tor"

    duration  = random.randint(120, 1800)
    bytes_out = random.randint(10000, 100000)
    bytes_in  = random.randint(50000, 500000)
    extensions = {
        "act": "Accept",
        "src": src_ip, "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": tor_port,
        "proto": "6",
        "suser": user, "shost": shost,
        "service_id": service_id, "app": app,
        "inzone": "Internal", "outzone": "External",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": bytes_out, "in": bytes_in,
        "client_outbound_packets": random.randint(1, 50),
        "server_outbound_packets": random.randint(5, 500),
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "action_reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept {src_ip} to Tor node {dest_ip}:{tor_port} — "
            f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in, {duration}s"
        ),
    }
    return _format_checkpoint_cef(config, extensions)


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

    if auth_port == 22:      # SSH → any internal server
        dest_ip    = random.choice(internal_servers)
        dhost      = dest_ip
        duser      = random.choice(["root", "admin", "ubuntu", "ec2-user"])
        auth_method = "SSH Public Key"
    elif auth_port in [389, 636]:  # LDAP/LDAPS → Domain Controller
        dest_ip    = random.choice(internal_servers)
        dhost      = "dc01.examplecorp.com"
        duser      = "DomainController1"
        auth_method = "LDAP"
    elif auth_port == 443:   # VPN-SSL → gateway
        dest_ip    = checkpoint_conf.get('gateway_ip', '203.0.113.10')
        dhost      = "vpn-gateway.examplecorp.com"
        duser      = user
        auth_method = "VPN"
    else:                    # RADIUS/1812 → dedicated RADIUS server
        dest_ip    = random.choice(internal_servers)
        dhost      = "radius.examplecorp.com"
        duser      = user
        auth_method = "RADIUS"

    logs = []
    for i in range(random.randint(20, 50)):
        extensions = {
            "signatureId": "45678",
            "name": "Identity Awareness",
            "severity": "7",
            "act": "Drop", "auth_status": "Failed Log In",
            "src": src_ip, "dst": dest_ip,
            "spt": random.randint(49152, 65535), "dpt": auth_port,
            "proto": "6",
            "suser": user, "shost": shost,
            "dhost": dhost, "duser": duser,
            "cs3": "user",        "cs3Label": "User Type",
            "cs5": auth_method,   "cs5Label": "Authentication Method",
            "blade": "Identity Awareness",
            "service_id": port_service.get(auth_port, "unknown"),
            "action_reason": "Authorization Failed",
            "ifname": "eth0",
            "msg": f"Authentication failed for {user} from {src_ip} to {dhost}:{auth_port} (attempt {i + 1})",
            "cefDeviceEventClassId": "identity",
        }
        logs.append(_format_checkpoint_cef(config, extensions, device_product="Identity Awareness"))
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

    lateral_ports = {445: "nbsession", 3389: "rdp", 22: "ssh", 135: "msrpc", 5985: "winrm"}

    logs = []
    for dest_ip in targets:
        for port, service in random.sample(list(lateral_ports.items()), k=random.randint(1, 3)):
            act  = random.choices(["Accept", "Drop"], weights=[35, 65])[0]
            rule = "Stealth_Rule" if act == "Drop" else "Allow_Internal_Traffic"
            extensions = {
                "act": act,
                "src": src_ip, "dst": dest_ip,
                "spt": random.randint(49152, 65535), "dpt": port,
                "proto": "6",
                "suser": user, "shost": shost,
                "service_id": service, "app": service.upper(),
                "inzone": "Internal", "outzone": "Internal",
                "cs1":rule, "cs1Label": "Rule Name",
                "client_outbound_packets": random.randint(1, 50),
                "server_outbound_packets": random.randint(5, 500),
                "action_reason": "Policy" if act == "Drop" else None,
                "ifname": "eth1",
                "msg": f"{act} {service.upper()} from {src_ip} to {dest_ip}:{port}",
                "cefDeviceEventClassId": "traffic",
            }
            logs.append(_format_checkpoint_cef(config, extensions))
    return logs


def _simulate_vpn_brute_force(config, src_ip, user, shost):
    """Simulates a VPN credential-stuffing attack from a single external IP.

    Generates 20–50 failed Identity Awareness / VPN login events from one attacker
    against the gateway on port 443, cycling through real usernames from session_context.
    Each failure uses act='Drop' (auth_status='Failed Log In') directed at the VPN gateway external interface.

    Triggers XSIAM: VPN Brute Force / Credential Scan analytics detection.
    """
    print("    - Check Point Module simulating: VPN Brute Force from external attacker")
    checkpoint_conf = config.get(CONFIG_KEY, {})
    gateway_ip      = checkpoint_conf.get('gateway_ip', '203.0.113.10')
    attacker_ip     = _random_external_ip()

    logs = []
    for i in range(random.randint(20, 50)):
        extensions = {
            "signatureId": "45679",
            "name":        "Identity Awareness",
            "severity":    "7",
            "act":         "Drop", "auth_status": "Failed Log In",
            "src": attacker_ip, "dst": gateway_ip,
            "spt": random.randint(49152, 65535), "dpt": 443,
            "proto": "6",
            "suser": user, "shost": shost,
            "inzone": "External", "outzone": "Internal",
            "cs3": "user",        "cs3Label": "User Type",
            "cs5": "VPN",         "cs5Label": "Authentication Method",
            "blade": "Identity Awareness",
            "action_reason": "Authorization Failed",
            "dhost": "vpn-gateway.examplecorp.com",
            "ifname": "eth0",
            "msg": f"VPN authentication failed for {user} from {attacker_ip} (attempt {i + 1})",
            "cefDeviceEventClassId": "identity",
        }
        logs.append(_format_checkpoint_cef(config, extensions, device_product="Identity Awareness"))
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
    for vpn_src_ip, label, t_start in [
        (benign_ip,    'home-office',       t_benign_start),
        (suspicious_ip, 'suspicious-foreign', t_suspicious),
    ]:
        src_port  = random.randint(49152, 65535)
        duration  = random.randint(60, 300)
        bytes_out = random.randint(50000, 500000)
        bytes_in  = random.randint(100000, 2000000)
        t_end     = t_start + timedelta(seconds=duration)
        ext = {
            "act": "Accept",
            "src": vpn_src_ip, "dst": gateway_ip,
            "spt": src_port, "dpt": 443,
            "proto": "6",
            "suser": user, "shost": shost,
            "inzone": "External", "outzone": "Internal",
            "service_id": "https", "app": "SSL VPN",
            "cs1": "VPN_Remote_Access", "cs1Label": "Rule Name",
            "blade": "VPN",
            "out": bytes_out, "in": bytes_in,
            "client_outbound_packets": random.randint(1, 50),
            "server_outbound_packets": random.randint(5, 500),
            "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
            "duration": str(duration),
            "action_reason": "TCP FIN",
            "ifname": "eth0",
            "msg": (
                f"Accept VPN for {user} from {vpn_src_ip} ({label}) — "
                f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in"
            ),
        }
        logs.append(_format_checkpoint_cef(config, ext, event_time=t_end))
    return logs


def _simulate_vpn_tor_login(config, src_ip, user, shost):
    """Successful VPN session established from a known TOR exit node IP.

    A valid corporate credential authenticated via TOR — indicating credential theft
    or deliberate anonymisation. The session SUCCEEDS (single session-close log). Detection
    signal: source IP in tor_exit_nodes + VPN blade + successful authentication.

    Triggers XSIAM: Suspicious VPN Login / TOR-based Access analytics detection.
    """
    print(f"    - Check Point Module simulating: VPN Login from TOR Exit Node for {user}")
    checkpoint_conf = config.get(CONFIG_KEY, {})
    gateway_ip      = checkpoint_conf.get('gateway_ip', '203.0.113.10')
    tor_nodes       = config.get('tor_exit_nodes', [])
    tor_ip          = random.choice(tor_nodes).get('ip', _random_external_ip()) if tor_nodes else _random_external_ip()

    src_port  = random.randint(49152, 65535)
    duration  = random.randint(300, 7200)
    bytes_out = random.randint(50000, 2_000_000)
    bytes_in  = random.randint(100000, 5_000_000)

    ext = {
        "act": "Accept",
        "src": tor_ip, "dst": gateway_ip,
        "spt": src_port, "dpt": 443,
        "proto": "6",
        "suser": user, "shost": shost,
        "inzone": "External", "outzone": "Internal",
        "service_id": "https", "app": "SSL VPN",
        "cs1": "VPN_Remote_Access", "cs1Label": "Rule Name",
        "blade": "VPN",
        "out": bytes_out, "in": bytes_in,
        "client_outbound_packets": random.randint(1, 50),
        "server_outbound_packets": random.randint(5, 500),
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "action_reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept VPN for {user} from TOR exit node {tor_ip} — "
            f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in"
        ),
    }
    return _format_checkpoint_cef(config, ext)


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
    for dst_ip in list(dest_ips)[:n_hosts]:
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
            "inzone": "Internal", "outzone": "Internal",
            "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
            "blade": "Firewall",
            "out": bytes_out, "in": bytes_in,
            "client_outbound_packets": random.randint(1, 50),
            "server_outbound_packets": random.randint(5, 500),
            "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
            "duration": str(duration),
            "action_reason": "TCP FIN",
            "ifname": "eth0",
            "msg": f"Accept SMB {src_ip} → {dst_ip}:445 (new destination), {duration}s",
        }
        logs.append(_format_checkpoint_cef(config, ext))
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
        "inzone": "Internal", "outzone": "Internal",
        "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
        "blade": "Firewall",
        "out": file_size_bytes,
        "in":  random.randint(1000, 50000),
        "client_outbound_packets": random.randint(1, 50),
        "server_outbound_packets": random.randint(5, 500),
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "action_reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept large SMB {src_ip} → {dst_ip}:445 — "
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
    for dst_ip in list(target_ips)[:n_targets]:
        src_port = random.randint(49152, 65535)
        # XSIAM detects SMB scan from ALLOWED connection volume — same principle as port_scan
        ext = {
            "act": "Accept",
            "src": src_ip, "dst": dst_ip,
            "spt": src_port, "dpt": 445,
            "proto": "6",
            "suser": user, "shost": shost,
            "inzone": "Internal", "outzone": "Internal",
            "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
            "blade": "Firewall",
            "out": random.randint(40, 200), "in": random.randint(40, 200),
            "client_outbound_packets": random.randint(1, 3),
            "server_outbound_packets": 0,
            "cn1": 0, "cn1Label": "Elapsed Time in Seconds",
            "duration": "0",
            "action_reason": "TCP Reset",
            "ifname": "eth0",
            "msg": f"Accept SMB probe {src_ip} → {dst_ip}:445 (RST)",
        }
        logs.append(_format_checkpoint_cef(config, ext))
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
    for _ in range(random.randint(15, 40)):
        src_port  = random.randint(49152, 65535)
        bytes_out = random.randint(60, 250)    # small DNS-like queries
        bytes_in  = random.randint(100, 500)   # small DNS-like responses
        ext = {
            "act": "Accept",
            "src": src_ip, "dst": dest_ip,
            "spt": src_port, "dpt": 53,
            "proto": "17",
            "suser": user, "shost": shost, "dhost": c2_domain,
            "inzone": "Internal", "outzone": "External",
            "service_id": "domain-udp", "app": "DNS",
            "cs1": "Allow_DNS", "cs1Label": "Rule Name",
            "out": bytes_out, "in": bytes_in,
            "client_outbound_packets": random.randint(1, 50),
            "server_outbound_packets": random.randint(5, 500),
            "cn1": 0, "cn1Label": "Elapsed Time in Seconds",
            "duration": "0",
            "action_reason": "UDP Timeout",
            "dns_query": f"{random.randint(100000,999999)}.{c2_domain}",
            "dns_type": "TXT",
            "ifname": "eth0",
            "msg": f"Accept DNS {src_ip} → {dest_ip}:53 (suspicious C2 beacon query)",
        }
        logs.append(_format_checkpoint_cef(config, ext))
    return logs


def _simulate_server_outbound_http(config):
    """Simulates an internal server making an anomalous outbound HTTP request.

    Servers should not initiate outbound web browsing — this pattern indicates
    possible compromise, reverse shell, or C2 call-back.  The server is chosen
    from internal_servers; the destination is a legitimate-looking external site
    (which makes the anomaly harder for simple rules to catch).

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

    ext = {
        "act": "Accept",
        "src": server_ip, "dst": dest_ip,
        "spt": src_port, "dpt": 80,
        "proto": "6",
        "shost": server_ip, "dhost": dhost,
        "inzone": "Internal", "outzone": "External",
        "service_id": "http", "app": "HTTP",
        "cs1": "Allow_Outbound_Web", "cs1Label": "Rule Name",
        "out": bytes_out, "in": bytes_in,
        "client_outbound_packets": random.randint(1, 50),
        "server_outbound_packets": random.randint(5, 500),
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "action_reason": "TCP FIN",
        "ifname": "eth0",
        "msg": (
            f"Accept anomalous HTTP from server {server_ip} to {dhost} — "
            f"{bytes_out}B out / {bytes_in // 1024}KB in, {duration}s"
        ),
    }
    return _format_checkpoint_cef(config, ext)


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
        "inzone": "Internal", "outzone": "Internal",
        "service_id": "rdp", "app": "Remote Desktop Protocol",
        "cs1": "Allow_Internal_Traffic", "cs1Label": "Rule Name",
        "out": bytes_out, "in": bytes_in,
        "client_outbound_packets": random.randint(1, 50),
        "server_outbound_packets": random.randint(5, 500),
        "cn1": duration, "cn1Label": "Elapsed Time in Seconds",
        "duration": str(duration),
        "action_reason": "TCP FIN",
        "ifname": "eth1",
        "msg": (
            f"Accept W2W RDP {src_ip} → {dest_ip}:3389 (anomalous) — "
            f"{bytes_out // 1024}KB out / {bytes_in // 1024}KB in, {duration}s"
        ),
    }
    return _format_checkpoint_cef(config, ext)


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
        "name":        "SmartDefense",
        "severity":    "8",
        "act":         "Drop",
        "src": attacker_ip, "dst": victim_ip,
        "spt": random.randint(49152, 65535), "dpt": fixed_dport,
        "proto": proto_num,
        "inzone": "External", "outzone": "Internal",
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
        ("Freenet",          "Anonymizer",          "Anonymous P2P network — high risk",    "6",  29900),
        ("I2P",              "Anonymizer",          "Invisible Internet Project traffic",   "6",  4444),
        ("Steam",            "Gaming",              "Online gaming platform — blocked",     "6",  27036),
        ("Psiphon",          "Anonymizer",          "Anti-censorship proxy circumvention",  "6",  443),
        ("Hola VPN",         "Anonymizer",          "P2P VPN anonymiser — blocked",         "6",  443),
        ("Remote Desktop",   "Remote Access",       "RDP to external host — policy denied", "6",  3389),
        ("MediaFire",        "File Storage",        "File sharing to unsanctioned service", "6",  443),
    ]

    app_name, app_category, block_reason, proto_num, dport = random.choice(blocked_apps)

    extensions = {
        "signatureId": str(random.randint(5000000, 5999999)),
        "name":        "Application Control",
        "severity":    "5",
        "act":         "Drop",
        "src": src_ip,  "dst": dest_ip,
        "spt": random.randint(49152, 65535), "dpt": dport,
        "proto": proto_num,
        "suser": user, "shost": shost,
        "inzone": "Internal", "outzone": "External",
        "cs1": "Block_Unauthorized_Applications", "cs1Label": "Rule Name",
        "cs3": app_category,                      "cs3Label": "Application Category",
        "cs4": app_name,                          "cs4Label": "Application Name",
        "blade": "Application Control",
        "app": app_name,
        "action_reason": "Drop",
        "ifname": "eth0",
        "msg": f"App Control block: {app_name} ({app_category}) from {src_ip} — {block_reason}",
        "cefDeviceEventClassId": "app_control",
    }
    return _format_checkpoint_cef(config, extensions, device_product="Application Control")


# ---------------------------------------------------------------------------
# Main threat dispatcher
# ---------------------------------------------------------------------------

def _generate_threat_log(config, session_context=None):
    """Generates a random threat event (IPS, URL Filtering, Identity, or Analytics-based)."""
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

    # --- multi-event generators ---
    if threat_type == 'large_upload':
        return _simulate_large_upload(config, src_ip, user, shost)
    if threat_type == 'port_scan':
        return _simulate_port_scan(config, src_ip, user, shost)
    if threat_type == 'auth_brute_force':
        return _simulate_auth_brute_force(config, src_ip, user, shost)
    if threat_type == 'lateral_movement':
        return _simulate_lateral_movement(config, src_ip, user, shost)
    if threat_type == 'rare_ssh':
        return _simulate_rare_ssh(config, src_ip, user, shost)
    if threat_type == 'tor_connection':
        return _simulate_tor_connection(config, src_ip, user, shost)
    if threat_type == 'vpn_brute_force':
        return _simulate_vpn_brute_force(config, src_ip, user, shost)
    if threat_type == 'vpn_impossible_travel':
        return _simulate_vpn_impossible_travel(config, src_ip, user, shost)
    if threat_type == 'dns_c2_beacon':
        return _simulate_dns_c2_beacon(config, src_ip, user, shost)
    if threat_type == 'server_outbound_http':
        return _simulate_server_outbound_http(config)
    if threat_type == 'workstation_rdp':
        return _simulate_workstation_rdp(config, src_ip, user, shost)
    if threat_type == 'smartdefense':
        return _simulate_smartdefense_event(config, src_ip, user, shost)
    if threat_type == 'app_control':
        return _simulate_app_control_block(config, src_ip, user, shost)
    if threat_type == 'vpn_tor_login':
        return _simulate_vpn_tor_login(config, src_ip, user, shost)
    if threat_type == 'smb_new_host_lateral':
        return _simulate_smb_new_host_lateral(config, src_ip, user, shost)
    if threat_type == 'smb_rare_file_transfer':
        return _simulate_smb_rare_file_transfer(config, src_ip, user, shost)
    if threat_type == 'smb_share_enumeration':
        return _simulate_smb_share_enumeration(config, src_ip, user, shost)

    # --- single-event generators: IPS, URL block, identity ---
    # Each builds its own complete extensions dict with correct src/dst/zones/blade.

    if threat_type == 'ips':
        # IPS: inbound attack — external attacker targets internal server.
        print("    - Check Point Module simulating: IPS Drop (external → internal)")
        attacker_ip = _random_external_ip()
        victim_ip   = random.choice(config.get('internal_servers', ['10.0.10.50']))
        ips_protections = [
            ("1002100", "Apache Log4j Remote Code Execution (CVE-2021-44228)",          "tcp",  443),
            ("1001100", "Microsoft MS17-010 SMBv1 Remote Code Execution (EternalBlue)", "tcp",  445),
            ("1004321", "Microsoft Exchange Server ProxyLogon (CVE-2021-26855)",         "tcp",  443),
            ("1003456", "OpenSSL Heartbleed Buffer Over-read (CVE-2014-0160)",           "tcp",  443),
            ("1000789", "SQL Injection via HTTP",                                        "tcp",  1433),
            ("1005678", "Shellshock Bash Remote Code Execution (CVE-2014-6271)",         "tcp",  80),
            ("1006543", "TCP SYN Flood DoS",                                             "tcp",  80),
            ("1009012", "SMB Brute Force Login Attempt",                                 "tcp",  445),
            ("1010123", "RDP BlueKeep Remote Code Execution (CVE-2019-0708)",            "tcp",  3389),
            ("1011234", "Mimikatz Credential Dumping (LSASS Access)",                    "tcp",  445),
            ("1007890", "DNS Amplification Reflection Attack",                           "udp",  53),
            ("1008901", "ICMP Flood DoS",                                                "icmp", 0),
        ]
        sig_id, protection_name, attack_proto, attack_dport = random.choice(ips_protections)
        proto_num = {"tcp": "6", "udp": "17", "icmp": "1"}.get(attack_proto, "6")
        # Extract CVE reference from protection name if present
        _cve_match = re.search(r'CVE-\d{4}-\d+', protection_name)
        cve_ref = _cve_match.group(0) if _cve_match else "N/A"
        extensions = {
            "signatureId": sig_id,
            "name":        "Threat Prevention",
            "severity":    "8",
            "act":         "Drop",
            "src": attacker_ip, "dst": victim_ip,
            "spt": random.randint(49152, 65535), "dpt": attack_dport,
            "proto": proto_num,
            "inzone": "External", "outzone": "Internal",
            "cs1": "IPS_Protection",    "cs1Label": "Rule Name",
            "cs3": "IPS",               "cs3Label": "Protection Type",
            "cs4": protection_name,     "cs4Label": "Protection Name",
            "blade": "IPS",
            "confidence_level": "High",
            "industry_reference": cve_ref,
            "protection_type": "Signature",
            "ifname": "eth0",
            "msg": f"IPS block: {protection_name} from {attacker_ip} to {victim_ip}:{attack_dport}",
            "cefDeviceEventClassId": "threat",
        }
        return _format_checkpoint_cef(config, extensions)

    if threat_type == 'url_block':
        # URL filtering: internal user attempts to reach a blocked external domain.
        print(f"    - Check Point Module simulating: URL Filter Block from {src_ip}")
        blocked_cats = config.get(CONFIG_KEY, {}).get('blocked_url_categories', {})
        cat, domain = random.choice(list(blocked_cats.items())) if blocked_cats else ("Phishing", "evil-site.com")
        dest_ip = _random_external_ip()
        extensions = {
            "signatureId": "98765",
            "name":        "URL Filtering",
            "severity":    "5",
            "act":         "Drop",
            "src": src_ip,  "dst": dest_ip,
            "spt": random.randint(49152, 65535), "dpt": 443,
            "proto": "6",
            "suser": user, "shost": shost, "dhost": domain,
            "inzone": "Internal", "outzone": "External",
            "cs1": "Block_Malicious_Categories", "cs1Label": "Rule Name",
            "blade": "URL Filtering",
            "cp_severity": "3",
            "urlf_reputation": "High Risk",
            "request": f"https://{domain}/index.html", "requestMethod": "GET",
            "action_reason": "URL Categorization",
            "ifname": "eth0",
            "msg": f"URL blocked: {domain} (category: {cat})",
            "cefDeviceEventClassId": "url_filtering",
        }
        return _format_checkpoint_cef(config, extensions, device_product="URL Filtering")

    # identity – single failed login (internal user → DC)
    print(f"    - Check Point Module simulating: Failed Login from {src_ip}")
    dc_ip = random.choice(config.get('internal_servers', ['10.0.0.10']))
    extensions = {
        "signatureId": "45678",
        "name":        "Identity Awareness",
        "severity":    "3",
        "act":         "Drop", "auth_status": "Failed Log In",
        "src": src_ip, "dst": dc_ip,
        "spt": random.randint(49152, 65535), "dpt": 389,
        "proto": "6",
        "suser": user, "shost": shost,
        "inzone": "Internal", "outzone": "Internal",
        "cs3": "user",     "cs3Label": "User Type",
        "cs5": "LDAP", "cs5Label": "Authentication Method",
        "blade": "Identity Awareness",
        "action_reason": "Authorization Failed",
        "duser": "DomainController1", "dhost": "dc01.examplecorp.com",
        "ifname": "eth0",
        "msg": f"Authentication failed for {user} from {src_ip}",
        "cefDeviceEventClassId": "identity",
    }
    return _format_checkpoint_cef(config, extensions, device_product="Identity Awareness")


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
                "signatureId": "98765",
                "name":        "URL Filtering",
                "severity":    "5",
                "act":         "Drop",
                "src": src_ip,  "dst": dest_ip,
                "spt": random.randint(49152, 65535), "dpt": 443,
                "proto": "6",
                "suser": user, "shost": shost, "dhost": domain,
                "inzone": "Internal", "outzone": "External",
                "cs1": "Block_Malicious_Categories", "cs1Label": "Rule Name",
                "blade": "URL Filtering",
                "cp_severity": "3",
                "urlf_reputation": "High Risk",
                "request": f"https://{domain}/index.html", "requestMethod": "GET",
                "action_reason": "URL Categorization",
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

        return None

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
