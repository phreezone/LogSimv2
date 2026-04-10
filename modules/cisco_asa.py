# modules/cisco_asa.py
# Simulates Cisco ASA firewall logs aligned with the XSIAM cisco_asa_raw dataset.
#
# Architecture note:
#   This module generates native Cisco ASA syslog messages (%ASA-N-MSGID: ...).
#   XSIAM's built-in Cisco ASA parsing rule receives the raw syslog and creates
#   the generalCiscoLog JSON structure.  The CiscoASA_1_4.xif modeling rule then
#   maps _json -> generalCiscoLog.* fields to xdm.* fields.
#
# XDM fields populated per event type:
#   All events:   xdm.observer.name, xdm.event.log_level, xdm.event.description
#   Connections:  xdm.network.ip_protocol, xdm.source.ipv4, xdm.source.port,
#                 xdm.source.interface, xdm.target.ipv4, xdm.target.port,
#                 xdm.target.interface, xdm.intermediate.ipv4 (NAT),
#                 xdm.source.user.username, xdm.event.duration,
#                 xdm.source.sent_bytes, xdm.target.sent_bytes,
#                 xdm.network.session_id, xdm.observer.action, xdm.event.outcome
#   Denied:       xdm.network.rule (policy_name/ACL name)
#   VPN:          xdm.source.user.username (vpn_user), xdm.network.application_protocol
#   IDS/IPS:      xdm.alert.severity (threat_level), xdm.alert.category (threat_category)
#   URL filter:   xdm.target.url

import random
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network, AddressValueError

try:
    from modules.session_utils import get_random_user, find_user_by_ip, get_user_by_name, rand_ip_from_network
except ImportError:
    from session_utils import get_random_user, find_user_by_ip, get_user_by_name, rand_ip_from_network

last_threat_event_time = 0

NAME        = "Cisco ASA Firewall"
DESCRIPTION = "Simulates Cisco ASA syslog messages for the XSIAM cisco_asa_raw dataset."
XSIAM_PARSER = "Cisco ASA"
CONFIG_KEY  = "cisco_asa_config"

# Single source of truth for threat event names used both as the generate_log fallback
# and by get_threat_names(). Add new threat names here when adding dispatch cases below.
_DEFAULT_THREAT_NAMES = [
    "ips_alert", "port_scan", "auth_brute_force", "lateral_movement",
    "large_single_upload_session", "cumulative_upload_session", "url_filter_block",
    "unusual_ssh_session", "unusual_rdp_session", "ssh_proxy_attack",
    "tor_connection", "vpn_bruteforce", "vpn_impossible_travel", "dns_c2_beacon",
    "server_outbound_http", "workstation_lateral_rdp", "targeted_admin_bruteforce",
    "vpn_tor_login", "smb_new_host_lateral", "smb_rare_file_transfer", "smb_share_enumeration",
]
_DEFAULT_THREAT_WEIGHTS = [20, 15, 13, 12, 8, 4, 8, 5, 3, 4, 3, 3, 2, 1, 1, 1, 4, 3, 4, 3, 5]


def get_threat_names():
    """Return available threat names dynamically from _DEFAULT_THREAT_NAMES.
    Adding a new entry to _DEFAULT_THREAT_NAMES automatically surfaces it here."""
    return list(_DEFAULT_THREAT_NAMES)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_asa_config(config):
    return config.get('cisco_asa_config', {})


def _get_asa_timestamp(dt=None):
    """Returns UTC timestamp in syslog format expected by the XSIAM parser.

    If dt (a datetime object) is provided its value is used instead of now,
    allowing callers to back-date or forward-date individual log lines.
    """
    t = dt if dt else datetime.now(timezone.utc)
    return t.strftime("%b %d %H:%M:%S")


def _format_duration(seconds):
    """
    Returns duration in H:MM:SS format consumed by the CiscoASA_1_4.xif regex:
      (\\d+)h?:(\\d+)m?:(\\d+)s?
    which converts to milliseconds for xdm.event.duration.
    """
    h, rem = divmod(int(seconds), 3600)
    m, s   = divmod(rem, 60)
    return f"{h:01d}:{m:02d}:{s:02d}"


def _random_external_ip():
    """Realistic public (non-RFC-1918) IP address."""
    first_octets = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 194, 212, 213]
    return (f"{random.choice(first_octets)}."
            f"{random.randint(1,254)}."
            f"{random.randint(1,254)}."
            f"{random.randint(1,254)}")


def _get_nat_ip(config):
    """Returns a random IP from the configured NAT/PAT pool."""
    try:
        nat_pool = ip_network(_get_asa_config(config).get('nat_pool_cidr', '203.0.113.0/28'))
        return rand_ip_from_network(nat_pool)
    except (ValueError, IndexError):
        return "203.0.113.2"


def _get_acl_name(config):
    """Returns the outside-in ACL name from config (default: OUTSIDE_IN)."""
    return _get_asa_config(config).get('outside_in_acl', 'OUTSIDE_IN')


def _generate_full_syslog_message(config, asa_message, event_time=None):
    """
    Wraps an ASA message with a syslog PRI header and device hostname.

    PRI = facility local4 (20*8) + severity digit extracted from %ASA-N- prefix.
    This ensures XSIAM xdm.event.log_level is populated correctly:
      local4 + informational (6) → <166>
      local4 + warning      (4) → <164>
      local4 + error        (3) → <163>
      local4 + critical     (2) → <162>

    event_time: optional datetime to embed instead of now (used by impossible travel
                to place the two sessions at distinct points in time).
    """
    hostname  = _get_asa_config(config).get('hostname', 'ASA-FW-01')
    timestamp = _get_asa_timestamp(event_time)

    sev = 6  # informational default
    for part in asa_message.split('-'):
        if len(part) == 1 and part.isdigit():
            sev = int(part)
            break

    pri = 20 * 8 + sev
    return f"<{pri}> {timestamp} {hostname} : {asa_message}"


def _get_user_ip_map(config):
    """Returns the user→IP map, preferring the module config then the shared top-level map."""
    return (config.get('cisco_asa_config', {}).get('user_ip_map')
            or config.get('shared_user_ip_map', {}))


def _get_user_from_ip(config, ip_address, session_context=None):
    """
    Resolves a username for an IP address.
    Checks session_context first (preferred), then falls back to the legacy
    cisco_asa_config.user_ip_map reverse lookup.
    """
    if session_context:
        username, _ = find_user_by_ip(session_context, ip_address)
        if username:
            return username
    user_map_rev = {
        v: k for k, v in
        _get_user_ip_map(config).items()
    }
    return user_map_rev.get(ip_address, "N/A")



# ---------------------------------------------------------------------------
# Session / connection generators
# ---------------------------------------------------------------------------

def _generate_connection_session(config, protocol, src_ip, dest_ip, dest_port,
                                  user, bytes_sent, bytes_received, duration_sec,
                                  direction="outbound",
                                  src_interface="inside", dest_interface="outside",
                                  teardown_reason="TCP FINs"):
    """
    Generates a Built + Teardown log pair for a TCP, UDP, or ICMP session.

    Syslog format (TCP/UDP outbound):
      %ASA-6-302013: Built outbound TCP connection N
        for outside:dest_ip/dest_port (dest_ip/dest_port)
        to inside:src_ip/src_port (nat_ip/nat_port) (user)
      %ASA-6-302014: Teardown TCP connection N
        for outside:dest_ip/dest_port to inside:src_ip/src_port
        duration H:MM:SS bytes N [reason] user username

    ICMP uses faddr/gaddr/laddr keywords (302020/302021).

    XDM fields extracted by the XSIAM parser:
      xdm.network.ip_protocol    ← protocol
      xdm.source.ipv4            ← src_ip (internal host)
      xdm.source.port            ← src_port
      xdm.source.interface       ← src_interface
      xdm.target.ipv4            ← dest_ip (remote host)
      xdm.target.port            ← dest_port
      xdm.target.interface       ← dest_interface
      xdm.intermediate.ipv4      ← nat_ip (NAT-translated address)
      xdm.intermediate.port      ← nat_port
      xdm.source.user.username   ← user (in parentheses at end of Built line)
      xdm.network.session_id     ← conn_id
      xdm.event.duration         ← duration_str (H:MM:SS → ms via XIF regex)
      xdm.source.sent_bytes      ← bytes_sent component of total bytes
      xdm.target.sent_bytes      ← bytes_received component
      xdm.observer.action        ← "allow" (Built) / "teardown" (Teardown)
      xdm.event.outcome          ← "success"
      xdm.event.operation        ← "Built" / "Teardown"
    """
    session_logs = []
    conn_id  = random.randint(100000, 999999)
    src_port = random.randint(49152, 65535)

    # Same-interface traffic (lateral movement) → direction reported as "inbound" (BUG-07)
    effective_direction = "inbound" if src_interface == dest_interface else direction

    # NAT/PAT only for outside-facing sessions
    nat_ip   = src_ip
    nat_port = src_port
    if dest_interface == "outside":
        nat_ip   = _get_nat_ip(config)
        nat_port = random.randint(1024, 65535)

    # ICMP uses the faddr/gaddr/laddr format (302020/302021)
    if protocol == "ICMP":
        icmp_type = random.choice([0, 8])
        icmp_code = 0
        faddr = dest_ip
        gaddr = nat_ip if dest_interface == "outside" else dest_ip
        laddr = src_ip
        session_logs.append(_generate_full_syslog_message(config,
            f"%ASA-6-302020: Built {effective_direction} ICMP connection for "
            f"faddr {faddr}/{icmp_type} gaddr {gaddr}/{icmp_type} laddr {laddr}/{icmp_code}"
        ))
        session_logs.append(_generate_full_syslog_message(config,
            f"%ASA-6-302021: Teardown ICMP connection for "
            f"faddr {faddr}/{icmp_type} gaddr {gaddr}/{icmp_type} laddr {laddr}/{icmp_code}"
        ))
        return session_logs

    # TCP / UDP event IDs
    if protocol == "TCP":
        built_id, teardown_id = "302013", "302014"
    else:
        built_id, teardown_id = "302015", "302016"
        teardown_reason = ""  # UDP teardowns have no reason field

    built_log = (
        f"%ASA-6-{built_id}: Built {effective_direction} {protocol} connection {conn_id} "
        f"for {dest_interface}:{dest_ip}/{dest_port} ({dest_ip}/{dest_port}) "
        f"to {src_interface}:{src_ip}/{src_port} ({nat_ip}/{nat_port})({user})"
    )
    session_logs.append(_generate_full_syslog_message(config, built_log))

    duration_str = _format_duration(duration_sec)
    reason_str   = f" {teardown_reason}" if teardown_reason else ""
    total_bytes  = bytes_sent + bytes_received

    teardown_log = (
        f"%ASA-6-{teardown_id}: Teardown {protocol} connection {conn_id} "
        f"for {dest_interface}:{dest_ip}/{dest_port} "
        f"to {src_interface}:{src_ip}/{src_port} "
        f"duration {duration_str} bytes {total_bytes}{reason_str} user {user}"
    )
    session_logs.append(_generate_full_syslog_message(config, teardown_log))
    return session_logs


def _generate_anyconnect_vpn_log(config, user=None, public_ip=None, session_context=None,
                                  event_time=None):
    """
    Generates a single AnyConnect VPN session start (113039) or end (113019).
    Session type / group name are read from cisco_asa_config.

    event_time: optional datetime; when set the syslog timestamp is back/forward-dated
                rather than stamped at the current wall-clock time.

    XDM fields:
      xdm.source.user.username  ← vpn_user / user from message
      xdm.source.ipv4           ← public_ip (client address)
      xdm.network.application_protocol ← AnyConnect / WebVPN
      xdm.event.duration        ← session duration (H:MM:SS)
      xdm.source.sent_bytes     ← Bytes xmt
      xdm.target.sent_bytes     ← Bytes rcv
    """
    asa_conf     = _get_asa_config(config)
    session_type = asa_conf.get('vpn_session_type', 'AnyConnect')
    group_name   = asa_conf.get('vpn_group_name',   'TunnelGroup_AnyConnect')

    if not user:
        if session_context:
            user_info = get_random_user(session_context, preferred_device_type='workstation')
            if user_info:
                user = user_info['username']
        if not user:
            user_ip_map = _get_user_ip_map(config)
            if not user_ip_map:
                return None
            user = random.choice(list(user_ip_map.keys()))

    if not public_ip:
        ingress_sources = config.get('benign_ingress_sources', [{}])
        source_ingress = random.choice(ingress_sources) if ingress_sources else {}
        try:
            public_ip = rand_ip_from_network(ip_network(source_ingress.get("ip_range", "1.1.1.0/24"), strict=False))
        except (AddressValueError, ValueError):
            public_ip = "1.1.1.1"

    if random.choice([True, False]):
        # Session Start
        message = (
            f"%ASA-4-113039: Group = {group_name}, Username = {user}, IP = {public_ip}, "
            f"AnyConnect session profile is {group_name}. "
            f"Session Type: {session_type}, Duration: 0:00:00, "
            f"Bytes xmt: 0, Bytes rcv: 0, Reason: User Initiated"
        )
    else:
        # Session End
        duration = random.randint(60, 3600)
        message = (
            f"%ASA-4-113019: Group = {group_name}, Username = {user}, IP = {public_ip}, "
            f"Session disconnected. Session Type: {session_type}, "
            f"Duration: {_format_duration(duration)}, "
            f"Bytes xmt: {random.randint(5000, 1000000)}, "
            f"Bytes rcv: {random.randint(10000, 5000000)}, Reason: User Requested"
        )
    return _generate_full_syslog_message(config, message, event_time)


def _generate_aaa_auth_log(config, user=None, session_context=None):
    """
    Generates a 109001 auth request + 109005 (success) or 109006 (failure) pair.
    Uses session_utils for user/IP resolution.

    XDM fields:
      xdm.source.user.username  ← user
      xdm.source.ipv4           ← src_ip
      xdm.target.ipv4           ← outside_ip
      xdm.event.outcome         ← success / failed
      xdm.event.outcome_reason  ← "Authentication succeeded" / "Authentication failed"
    """
    asa_conf   = _get_asa_config(config)
    outside_ip = asa_conf.get('outside_ip', '203.0.113.1')
    src_ip     = "192.168.1.100"

    if not user:
        if session_context:
            user_info = get_random_user(session_context, preferred_device_type='workstation')
            if user_info:
                user   = user_info['username']
                src_ip = user_info['ip'] or src_ip
        if not user:
            user_ip_map = _get_user_ip_map(config)
            if not user_ip_map:
                return None
            user   = random.choice(list(user_ip_map.keys()))
            src_ip = user_ip_map.get(user, src_ip)
    else:
        if session_context:
            user_info = get_user_by_name(session_context, user)
            if user_info:
                src_ip = user_info['ip'] or src_ip

    success = random.random() > 0.15

    req_msg = (
        f"%ASA-6-109001: Auth start for user '{user}' "
        f"from {src_ip}/0 to {outside_ip}/443 on interface outside"
    )
    if success:
        result_msg = (
            f"%ASA-6-109005: Authentication succeeded for user '{user}' "
            f"from {src_ip}/0 to {outside_ip}/443 on interface outside"
        )
    else:
        result_msg = (
            f"%ASA-6-109006: Authentication failed for user '{user}' "
            f"from {src_ip}/0 to {outside_ip}/443 on interface outside"
        )
    return [
        _generate_full_syslog_message(config, req_msg),
        _generate_full_syslog_message(config, result_msg),
    ]


# ---------------------------------------------------------------------------
# Benign event generators
# ---------------------------------------------------------------------------

def _simulate_benign_office_traffic(config, session_context=None):
    """
    Generates a realistic benign session — web, DNS, email, SSH, or ICMP.
    User and source IP resolved from session_utils (preferred) or legacy map.
    """
    if session_context:
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        if user_info:
            user   = user_info['username']
            src_ip = user_info['ip']
        else:
            return None
    else:
        user_ip_map = _get_user_ip_map(config)
        if not user_ip_map:
            return None
        user, src_ip = random.choice(list(user_ip_map.items()))

    service_type = random.choices(
        population=["Web Browsing", "DNS Query", "Email Client", "SSH", "ICMP Ping"],
        weights=[65, 15, 10, 5, 5],
        k=1
    )[0]

    benign_destinations = config.get('benign_egress_destinations', [])
    possible = [d for d in benign_destinations if service_type in d.get('service_types', [])]
    if not possible:
        possible = [d for d in benign_destinations if "Web Browsing" in d.get('service_types', [])]
    if not possible:
        return None

    destination = random.choice(possible)
    try:
        dest_ip = rand_ip_from_network(ip_network(destination.get("ip_range"), strict=False))
    except (ValueError, AddressValueError, TypeError):
        dest_ip = "8.8.8.8"

    if service_type == "Web Browsing":
        protocol   = "TCP"
        web_ports  = [p for p in destination.get('ports', [443]) if p in [80, 443]]
        dest_port  = random.choice(web_ports) if web_ports else 443
        bytes_sent = random.randint(500, 15000)
        bytes_recv = random.randint(50000, 5000000)
        duration   = random.randint(5, 120)
    elif service_type == "DNS Query":
        protocol, dest_port = "UDP", 53
        bytes_sent, bytes_recv, duration = random.randint(50, 150), random.randint(150, 500), random.randint(0, 1)
    elif service_type == "Email Client":
        protocol    = "TCP"
        email_ports = [p for p in destination.get('ports', [993]) if p in [25, 587, 993]]
        dest_port   = random.choice(email_ports) if email_ports else 993
        bytes_sent = random.randint(1000, 500000)
        bytes_recv = random.randint(500, 100000)
        duration   = random.randint(2, 30)
    elif service_type == "ICMP Ping":
        protocol, dest_port = "ICMP", 0
        bytes_sent = bytes_recv = 84
        duration = random.randint(0, 1)
    else:  # SSH
        protocol, dest_port = "TCP", 22
        bytes_sent = random.randint(1000, 20000)
        bytes_recv = random.randint(1000, 20000)
        duration   = random.randint(60, 1800)

    return _generate_connection_session(
        config, protocol, src_ip, dest_ip, dest_port,
        user, bytes_sent, bytes_recv, duration
    )


def _simulate_inbound_block(config):
    """
    Generates %ASA-4-106023 deny messages for inbound traffic blocked by the
    outside-in ACL.  Covers external port probes and exploit attempts.

    XDM fields:
      xdm.observer.action  ← "deny"
      xdm.network.rule     ← ACL name (policy_name)
      xdm.source.ipv4      ← external attacker IP
      xdm.source.port      ← attacker ephemeral port
      xdm.source.interface ← "outside"
      xdm.target.ipv4      ← internal host
      xdm.target.port      ← probed service port
      xdm.target.interface ← "inside"
      xdm.network.ip_protocol ← TCP / UDP

    Triggers: "Blocked Inbound Traffic" XSIAM detection.
    """
    acl_name   = _get_acl_name(config)
    scanner_ip = _random_external_ip()
    src_port   = random.randint(1024, 65535)

    # Common ports probed from the internet
    scan_ports = [22, 23, 25, 80, 135, 139, 443, 445, 1433, 1521,
                  3306, 3389, 4444, 5900, 6379, 8080, 8443]
    dest_port  = random.choice(scan_ports)
    protocol   = random.choices(["tcp", "udp"], weights=[85, 15], k=1)[0]

    internal_networks = config.get('internal_networks', ['10.10.1.0/24'])
    try:
        net       = ip_network(random.choice(internal_networks), strict=False)
        target_ip = rand_ip_from_network(net)
    except (ValueError, IndexError):
        target_ip = "10.10.1.50"

    hash1 = random.randint(0, 0xFFFFFFFF)
    message = (
        f"%ASA-4-106023: Deny {protocol} src outside:{scanner_ip}/{src_port} "
        f"dst inside:{target_ip}/{dest_port} "
        f"by access-group {acl_name} [0x{hash1:08x}, 0x0]"
    )
    return _generate_full_syslog_message(config, message)


def _simulate_ntp_sync(config):
    """NTP time synchronisation — %ASA-6-302015 + 302016 (Built/Teardown) for UDP/123.

    Represents routine clock-sync traffic from internal hosts and network devices
    to public NTP pool servers.  Short duration (< 1 second), tiny byte counts.

    XDM fields:
      xdm.network.ip_protocol    ← UDP (17)
      xdm.source.ipv4            ← internal host / device
      xdm.target.ipv4            ← public NTP server
      xdm.target.port            ← 123
      xdm.source.sent_bytes      ← ~48 bytes (NTP request)
      xdm.target.sent_bytes      ← ~48 bytes (NTP response)
    """
    ntp_servers = ["216.239.35.0", "129.6.15.28", "132.163.96.1",
                   "17.253.52.125", "162.159.200.1", "198.60.22.240"]
    ntp_dest = random.choice(ntp_servers)

    internal_networks = config.get('internal_networks', ['192.168.1.0/24'])
    try:
        net    = ip_network(random.choice(internal_networks), strict=False)
        src_ip = rand_ip_from_network(net)
    except (ValueError, AddressValueError, TypeError):
        src_ip = "192.168.1.100"

    return _generate_connection_session(
        config, "UDP", src_ip, ntp_dest, 123,
        user="", bytes_sent=random.randint(48, 76), bytes_received=random.randint(48, 76),
        duration_sec=0
    )


def _simulate_internal_traffic(config, session_context=None):
    """East-west LAN traffic — workstation to file/print/app server on inside interface.

    Simulates normal internal lateral connectivity (not a threat).  Both source
    and destination are inside, so the ASA routes the packet but neither interface
    is the outside.  Uses 302013/302014 (TCP) messages with src/dest both inside.

    XDM fields:
      xdm.source.interface       ← "inside"
      xdm.target.interface       ← "inside"
      xdm.network.ip_protocol    ← TCP
      xdm.source.ipv4            ← workstation
      xdm.target.ipv4            ← server / printer
      xdm.target.port            ← common internal service port
    """
    if session_context:
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        if user_info:
            user   = user_info['username']
            src_ip = user_info['ip']
        else:
            return None
    else:
        user_ip_map = _get_user_ip_map(config)
        if not user_ip_map:
            return None
        user, src_ip = random.choice(list(user_ip_map.items()))

    # Pick an internal server as the destination
    internal_servers = config.get('internal_servers', [])
    if internal_servers:
        dest_ip = random.choice(internal_servers)
    else:
        internal_networks = config.get('internal_networks', ['192.168.1.0/24'])
        try:
            net     = ip_network(random.choice(internal_networks), strict=False)
            dest_ip = rand_ip_from_network(net)
        except (ValueError, AddressValueError, TypeError):
            dest_ip = "192.168.1.50"

    # Common internal service ports
    service_cfg = random.choices(
        [("SMB/CIFS", 445), ("RPC", 135), ("LDAP", 389), ("HTTP-internal", 8080),
         ("MSSQL", 1433), ("Print", 9100), ("HTTPS-internal", 8443)],
        weights=[30, 15, 15, 15, 10, 10, 5],
        k=1,
    )[0]
    service_name, dest_port = service_cfg

    bytes_sent = random.randint(1_000, 500_000)
    bytes_recv = random.randint(1_000, 50_000_000)
    duration   = random.randint(1, 300)

    return _generate_connection_session(
        config, "TCP", src_ip, dest_ip, dest_port,
        user, bytes_sent, bytes_recv, duration,
        src_interface="inside", dest_interface="inside"
    )


def _simulate_dhcp_log(config):
    """DHCP address assignment log — %ASA-6-305011 (NAT entry built for DHCP client).

    ASAs with DHCP server or relay enabled emit 305011/305012 messages when a client
    obtains / releases an address.  Short-lived, small byte counts.

    XDM fields:
      xdm.event.description      ← DHCP lease detail
      xdm.source.ipv4            ← DHCP client IP (newly assigned)
      xdm.target.ipv4            ← DHCP server / relay target
    """
    internal_networks = config.get('internal_networks', ['192.168.1.0/24'])
    try:
        net       = ip_network(random.choice(internal_networks), strict=False)
        client_ip = rand_ip_from_network(net)
    except (ValueError, AddressValueError, TypeError):
        client_ip = "192.168.1.101"

    asa_config   = config.get(CONFIG_KEY, {})
    outside_ip   = asa_config.get('outside_ip', '203.0.113.1')
    event_type   = random.choices(["built", "teardown"], weights=[70, 30], k=1)[0]
    src_port     = random.randint(49152, 65535)
    mapped_port  = random.randint(1024, 65535)
    hash1        = random.randint(0, 0xFFFFFFFF)

    if event_type == "built":
        message = (
            f"%ASA-6-305011: Built dynamic TCP translation from inside:{client_ip}/{src_port} "
            f"to outside:{outside_ip}/{mapped_port}"
        )
    else:
        message = (
            f"%ASA-6-305012: Teardown dynamic TCP translation from inside:{client_ip}/{src_port} "
            f"to outside:{outside_ip}/{mapped_port} duration 0:01:00 [0x{hash1:08x}]"
        )
    return _generate_full_syslog_message(config, message)


# ---------------------------------------------------------------------------
# Threat event generators
# ---------------------------------------------------------------------------

def _simulate_auth_brute_force(config, session_context=None):
    """
    Rapid burst of 109006 auth failures from a single external IP targeting
    multiple users — simulates a credential stuffing / brute force attack.

    XDM fields:
      xdm.event.outcome         ← OUTCOME_FAILED
      xdm.source.user.username  ← username being attacked
      xdm.source.ipv4           ← attacker external IP
      xdm.target.ipv4           ← outside_ip (VPN gateway)

    Triggers: "Authentication Brute Force" XSIAM analytics detection.
    """
    print("    - ASA Module simulating: Auth Brute Force")

    asa_conf   = _get_asa_config(config)
    outside_ip = asa_conf.get('outside_ip', '203.0.113.1')
    attacker_ip = _random_external_ip()

    if session_context:
        target_users = random.sample(
            list(session_context.keys()),
            k=min(random.randint(3, 8), len(session_context))
        )
    else:
        target_users = [f"user{i}" for i in range(1, random.randint(4, 9))]

    auth_logs = []
    for _ in range(random.randint(20, 50)):
        user     = random.choice(target_users)
        src_port = random.randint(1024, 65535)
        fail_msg = (
            f"%ASA-6-109006: Authentication failed for user '{user}' "
            f"from {attacker_ip}/{src_port} to {outside_ip}/443 on interface outside"
        )
        auth_logs.append(_generate_full_syslog_message(config, fail_msg))
    return auth_logs


def _simulate_targeted_admin_bruteforce(config, session_context=None):
    """
    Targeted brute force against a specific high-value admin account from one
    external IP.  Unlike _simulate_auth_brute_force (credential stuffing across
    many usernames), this represents a focused password-spray against one known
    privileged account — e.g., the ASA admin SSH interface or ASDM (port 443).

    Generates 30–80 rapid 109001 (start) + 109006 (fail) pairs so XSIAM sees
    both the auth attempt and the failure for each cycle.

    XDM fields:
      xdm.event.outcome         ← OUTCOME_FAILED (109006)
      xdm.source.user.username  ← targeted admin account
      xdm.source.ipv4           ← external attacker IP
      xdm.target.ipv4           ← ASA outside IP / management interface

    Triggers: "Targeted Authentication Brute Force" / high-rate single-user
              auth failure XSIAM analytics detection.
    """
    print("    - ASA Module simulating: Targeted Admin Brute Force")

    asa_conf    = _get_asa_config(config)
    outside_ip  = asa_conf.get('outside_ip', '203.0.113.1')
    attacker_ip = _random_external_ip()

    # High-value admin accounts that attackers commonly target
    admin_accounts = ["admin", "administrator", "root", "cisco", "enable", "sysadmin"]

    # If we have session context, occasionally pick a real username to make it
    # more realistic (attacker obtained the username via OSINT/recon)
    if session_context and random.random() < 0.4:
        target_user = random.choice(list(session_context.keys()))
    else:
        target_user = random.choice(admin_accounts)

    # SSH management (22) or ASDM HTTPS (443) — both are common ASA attack surfaces
    target_port = random.choice([22, 443])
    interface   = "outside"

    attack_logs = []
    for _ in range(random.randint(30, 80)):
        src_port = random.randint(1024, 65535)
        # 109001: Auth attempt started
        start_msg = (
            f"%ASA-6-109001: Auth start for user '{target_user}' "
            f"from {attacker_ip}/{src_port} to {outside_ip}/{target_port} "
            f"on interface {interface}"
        )
        # 109006: Auth failed (each attempt)
        fail_msg = (
            f"%ASA-6-109006: Authentication failed for user '{target_user}' "
            f"from {attacker_ip}/{src_port} to {outside_ip}/{target_port} "
            f"on interface {interface}"
        )
        attack_logs.append(_generate_full_syslog_message(config, start_msg))
        attack_logs.append(_generate_full_syslog_message(config, fail_msg))
    return attack_logs


def _simulate_lateral_movement(config, src_ip, session_context=None):
    """
    Multi-target lateral movement from a compromised internal host.
    Attempts SMB (445), RDP (3389), SSH (22), MSRPC (135), and WinRM (5985/5986)
    across 4–8 internal targets.  Mix of allowed and denied connections.

    XDM fields (per connection):
      xdm.source.ipv4, xdm.source.interface  ← attacker internal IP / "inside"
      xdm.target.ipv4, xdm.target.interface  ← victim internal IP / "inside"
      xdm.target.port                         ← lateral port
      xdm.observer.action                     ← "allow" or "deny"
      xdm.network.rule                        ← ACL name (for denied events)
      xdm.source.user.username                ← compromised user

    Triggers: "Lateral Movement" XSIAM analytics detection.
    """
    print("    - ASA Module simulating: Lateral Movement")

    lateral_ports = {445: "TCP", 3389: "TCP", 22: "TCP", 135: "TCP", 5985: "TCP", 5986: "TCP"}
    acl_name = _get_acl_name(config)
    user     = _get_user_from_ip(config, src_ip, session_context)

    internal_networks = config.get('internal_networks', ['10.10.1.0/24'])
    try:
        net = ip_network(random.choice(internal_networks), strict=False)
    except (ValueError, IndexError):
        net = None

    movement_logs = []
    for _ in range(random.randint(4, 8)):
        target_ip = rand_ip_from_network(net) if net else f"10.10.1.{random.randint(2, 254)}"
        if target_ip == src_ip:
            continue

        port, protocol = random.choice(list(lateral_ports.items()))

        if random.random() < 0.65:
            # Blocked — 106023 deny with the internal ACL
            src_port = random.randint(49152, 65535)
            hash1    = random.randint(0, 0xFFFFFFFF)
            deny_msg = (
                f"%ASA-4-106023: Deny {protocol.lower()} src inside:{src_ip}/{src_port} "
                f"dst inside:{target_ip}/{port} "
                f"by access-group {acl_name} [0x{hash1:08x}, 0x0]"
            )
            movement_logs.append(_generate_full_syslog_message(config, deny_msg))
        else:
            # Allowed — full Built/Teardown session
            movement_logs.extend(_generate_connection_session(
                config, protocol, src_ip, target_ip, port, user,
                random.randint(1000, 50000), random.randint(1000, 50000),
                random.randint(2, 60),
                src_interface="inside", dest_interface="inside"
            ))
    return movement_logs


def _simulate_ips_alert(config, src_ip):
    """
    Generates Cisco ASA IDS/IPS alert messages using the 400xxx signature series.

    Syslog format:
      %ASA-N-4000NN: IDS:XXXX <description> from src_ip to dst_ip on interface iface

    XDM fields (extracted by the XSIAM Cisco ASA parsing rule):
      xdm.alert.severity   ← threat_level (high/medium/low from syslog severity)
      xdm.alert.category   ← threat_category (ICMP/TCP signature category)
      xdm.source.ipv4      ← src_ip (external attacker)
      xdm.target.ipv4      ← internal target
      xdm.network.rule     ← ACL name (from follow-up 106023 deny)

    Triggers: "IPS Threat Detection" XSIAM analytics detection.
    """
    print("    - ASA Module simulating: IPS/IDS Alert")

    # Real Cisco ASA IDS signature table — all are severity 4 (Warning) per Cisco docs.
    # Format: (event_id, "IDS:sig_num description", syslog_severity, protocol, dest_port)
    # dest_port = 0 for ICMP/IP-level attacks; specific port for TCP/UDP attacks.
    # Source: Cisco ASA Syslog Messages 400000–400032 documentation.
    ips_signatures = [
        ("400010", "IDS:2000 ICMP Echo Reply",           4, "icmp", 0),
        ("400014", "IDS:2004 ICMP Echo Request",         4, "icmp", 0),
        ("400013", "IDS:2003 ICMP Redirect",             4, "icmp", 0),
        ("400015", "IDS:2005 ICMP Time Exceeded",        4, "icmp", 0),
        ("400007", "IDS:1100 IP Fragment Attack",        4, "ip",   0),
        ("400008", "IDS:1101 IP Impossible Packet",      4, "ip",   0),
        ("400009", "IDS:1102 IP Teardrop Attack",        4, "ip",   0),
        ("400024", "IDS:3001 TCP NULL Flags Attack",     4, "tcp",  None),
        ("400025", "IDS:3002 TCP SYN+FIN Attack",        4, "tcp",  None),
        ("400026", "IDS:3003 TCP FIN Only Attack",       4, "tcp",  None),
        ("400027", "IDS:4000 UDP Bomb Attack",           4, "udp",  None),
        ("400028", "IDS:4001 UDP Snork Attack",          4, "udp",  None),
        ("400031", "IDS:5001 DNS Zone Transfer",         4, "tcp",  53),
    ]

    # Port pools for generic TCP/UDP attacks (None in the table → pick from pool)
    _tcp_attack_ports = [22, 80, 443, 445, 1433, 3389, 8080, 8443]
    _udp_attack_ports = [53, 67, 123, 137, 500, 4500]

    internal_networks = config.get('internal_networks', ['10.10.1.0/24'])
    try:
        net       = ip_network(random.choice(internal_networks), strict=False)
        target_ip = rand_ip_from_network(net)
    except (ValueError, IndexError):
        target_ip = "10.10.1.50"

    sig_id, sig_name, sev_digit, protocol, fixed_dport = random.choice(ips_signatures)

    # Resolve destination port: fixed value, pool lookup, or 0 for ICMP/IP
    if fixed_dport is not None:
        dest_port = fixed_dport
    elif protocol == "tcp":
        dest_port = random.choice(_tcp_attack_ports)
    elif protocol == "udp":
        dest_port = random.choice(_udp_attack_ports)
    else:
        dest_port = 0

    alert_logs = [_generate_full_syslog_message(config,
        f"%ASA-{sev_digit}-{sig_id}: {sig_name} from {src_ip} to {target_ip} on interface outside"
    )]

    # All IDS signatures are severity 4 — always emit a follow-up 106023 deny.
    acl_name = _get_acl_name(config)
    src_port = random.randint(1024, 65535)
    hash1    = random.randint(0, 0xFFFFFFFF)
    deny_msg = (
        f"%ASA-4-106023: Deny {protocol} src outside:{src_ip}/{src_port} "
        f"dst inside:{target_ip}/{dest_port} "
        f"by access-group {acl_name} [0x{hash1:08x}, 0x0]"
    )
    alert_logs.append(_generate_full_syslog_message(config, deny_msg))
    return alert_logs


def _simulate_url_filtering_block(config, src_ip):
    """
    Generates %ASA-5-304001 URL filtering deny messages.
    Requires Cisco ASA with URL content filtering / Websense integration enabled.

    Syslog format:
      %ASA-5-304001: src_ip Accessed URL url: URL Blocked

    XDM fields:
      xdm.target.url           ← blocked URL
      xdm.source.ipv4          ← internal host
      xdm.observer.action      ← "deny" (from "URL Blocked")
      xdm.source.user.username ← resolved from src_ip via session_utils

    Triggers: "URL Filtering Block" XSIAM analytics detection.
    """
    print("    - ASA Module simulating: URL Filtering Block")

    malicious_domains = [
        "malware-distribution.ru", "phishing-kit.cn", "c2-server.onion.ws",
        "exploit-kit.biz",         "botnet-cc.tk",    "dropper-site.top",
        "ransomware-payload.xyz",  "credential-harvest.info",
    ]
    malicious_paths = [
        "/payload.exe", "/dropper.ps1", "/c2/beacon",     "/gate.php",
        "/update/install",           "/admin/config.php", "/download/malware.zip",
    ]

    url_logs = []
    for _ in range(random.randint(1, 5)):
        domain  = random.choice(malicious_domains)
        path    = random.choice(malicious_paths)
        url     = f"http://{domain}{path}"
        message = f"%ASA-5-304001: {src_ip} Accessed URL {url}: URL Blocked"
        url_logs.append(_generate_full_syslog_message(config, message))
    return url_logs


def _simulate_large_upload_session(config, internal_host_ip, is_cumulative, session_context=None):
    """
    Data exfiltration — either a single massive upload or multiple sequential uploads
    that together exceed the XSIAM large-upload detection threshold.

    XDM fields:
      xdm.source.sent_bytes  ← bytes_sent (large value → triggers detection)
      xdm.target.ipv4        ← exfiltration destination
      xdm.target.port        ← 443
    """
    destination = random.choice(config.get('exfiltration_destinations', [{}]))
    try:
        dest_ip = rand_ip_from_network(ip_network(destination.get("ip_range", "154.53.224.0/24"), strict=False))
    except (AddressValueError, ValueError):
        dest_ip = "154.53.224.10"

    user = _get_user_from_ip(config, internal_host_ip, session_context)

    if not is_cumulative:
        return _generate_connection_session(
            config, "TCP", internal_host_ip, dest_ip, 443, user,
            random.randint(787_500_000, 1_610_612_736), random.randint(100_000, 500_000),
            random.randint(300, 900)
        )
    else:
        session_logs = []
        total = 0
        while total < 734_003_200:
            bs = random.randint(80_000_000, 150_000_000)
            total += bs
            session_logs.extend(_generate_connection_session(
                config, "TCP", internal_host_ip, dest_ip, 443, user,
                bs, random.randint(50_000, 200_000), random.randint(60, 240)
            ))
        return session_logs


def _simulate_dns_c2_beacon(config, internal_host_ip, session_context=None):
    """C2 beacon disguised as a DNS query to a suspicious external resolver."""
    dest_ip = _random_external_ip()

    user = _get_user_from_ip(config, internal_host_ip, session_context)
    return _generate_connection_session(
        config, "UDP", internal_host_ip, dest_ip, 53, user,
        random.randint(100, 250), random.randint(150, 500), random.randint(0, 2)
    )


def _simulate_server_outbound_http(config, session_context=None):
    """Anomalous outbound HTTP from an internal server (servers should not browse)."""
    if not config.get('internal_servers'):
        return None
    src_ip = random.choice(config.get('internal_servers'))
    user   = _get_user_from_ip(config, src_ip, session_context)

    destination = random.choice(config.get('benign_egress_destinations', [{}]))
    try:
        dest_ip = rand_ip_from_network(ip_network(destination.get("ip_range", "8.8.8.0/24"), strict=False))
    except (AddressValueError, ValueError):
        dest_ip = "8.8.8.8"

    return _generate_connection_session(
        config, "TCP", src_ip, dest_ip, 80, user,
        random.randint(300, 1000), random.randint(1000, 500000), random.randint(1, 10)
    )


def _simulate_workstation_lateral_rdp(config, internal_host_ip, session_context=None):
    """RDP from one internal workstation to another — suspicious lateral movement."""
    internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
    try:
        dest_ip = rand_ip_from_network(ip_network(internal_net))
    except (AddressValueError, IndexError):
        dest_ip = "192.168.1.101"
    if dest_ip == internal_host_ip:
        return None

    user = _get_user_from_ip(config, internal_host_ip, session_context)
    return _generate_connection_session(
        config, "TCP", internal_host_ip, dest_ip, 3389, user,
        50000, 50000, random.randint(120, 1800),
        src_interface="inside", dest_interface="inside"
    )


def _simulate_rdp_session(config, internal_host_ip, session_context=None):
    """Unusual RDP session from a workstation to an internal server."""
    if not config.get('internal_servers'):
        return None
    dest_ip = random.choice(config.get('internal_servers'))
    if dest_ip == internal_host_ip:
        return None
    user = _get_user_from_ip(config, internal_host_ip, session_context)
    return _generate_connection_session(
        config, "TCP", internal_host_ip, dest_ip, 3389, user,
        random.randint(1_000_000, 20_000_000), random.randint(5_000_000, 100_000_000),
        random.randint(120, 1800),
        src_interface="inside", dest_interface="inside"
    )


def _simulate_ssh_session(config, internal_host_ip, session_context=None):
    """Outbound SSH to an unusual external host — rare/anomalous behaviour."""
    dest_ip = _random_external_ip()
    user    = _get_user_from_ip(config, internal_host_ip, session_context)
    return _generate_connection_session(
        config, "TCP", internal_host_ip, dest_ip, 22, user,
        random.randint(1000, 50000), random.randint(1000, 50000), random.randint(30, 600)
    )


def _simulate_port_scan(config, scanner_ip, session_context=None):
    """
    Internal port scan — 100–200 rapid TCP connections to the same victim.
    All sessions use teardown_reason "TCP Reset-I" (no service listening).
    Triggers: "Port Scan" XSIAM analytics detection.
    """
    if not config.get('internal_servers'):
        return None
    victim_ip = random.choice(config.get('internal_servers'))
    if scanner_ip == victim_ip:
        return None

    user      = _get_user_from_ip(config, scanner_ip, session_context)
    scan_logs = []
    for port in random.sample(range(1, 65535), random.randint(100, 200)):
        scan_logs.extend(_generate_connection_session(
            config, "TCP", scanner_ip, victim_ip, port, user, 0, 0, 0,
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP Reset-I"
        ))
    return scan_logs


def _simulate_ssh_proxy_attack(config, attacker_ip, session_context=None):
    """SSH lateral movement to multiple internal servers via an internal attacker."""
    potential_victims = [ip for ip in config.get('internal_servers', []) if ip != attacker_ip]
    if len(potential_victims) < 2:
        return None

    k         = random.randint(2, min(len(potential_victims), 5))
    victim_ips = random.sample(potential_victims, k=k)
    user       = _get_user_from_ip(config, attacker_ip, session_context)

    attack_logs = []
    for victim_ip in victim_ips:
        attack_logs.extend(_generate_connection_session(
            config, "TCP", attacker_ip, victim_ip, 22, user,
            random.randint(500, 15000), random.randint(500, 15000), random.randint(10, 300),
            src_interface="inside", dest_interface="inside"
        ))
    return attack_logs


def _simulate_tor_connection_session(config, internal_host_ip, session_context=None):
    """Outbound connection to a known Tor exit node — anonymisation attempt."""
    tor_nodes = config.get('tor_exit_nodes', [])
    dest_ip   = random.choice(tor_nodes).get("ip") if tor_nodes else None
    if not dest_ip:
        dest_ip = _random_external_ip()

    user = _get_user_from_ip(config, internal_host_ip, session_context)
    return _generate_connection_session(
        config, "TCP", internal_host_ip, dest_ip, random.choice([443, 9001, 9030]), user,
        random.randint(10000, 100000), random.randint(50000, 500000), random.randint(10, 120)
    )


def _simulate_vpn_bruteforce_or_scan(config, session_context=None):
    """
    Credential stuffing attack against the VPN gateway — single external IP trying
    many usernames, each with 2–5 rapid 109006 auth failures.

    Uses %ASA-6-109006 (Authentication failed) on interface outside, which is the
    correct signal for XSIAM VPN brute force / credential scan detection.
    109006 is distinct from AnyConnect session events (113039/113019) — it fires
    when the auth exchange itself fails, before a session is built.

    Triggers: "VPN Brute Force / Credential Scan" analytics detection.
    """
    print("    - ASA Module simulating: VPN Brute-force/Scan")

    asa_conf    = _get_asa_config(config)
    outside_ip  = asa_conf.get('outside_ip', '203.0.113.1')
    attacker_ip = _random_external_ip()

    if session_context:
        users_to_try = random.sample(
            list(session_context.keys()),
            k=min(random.randint(5, 10), len(session_context))
        )
    else:
        user_ip_map = _get_user_ip_map(config)
        if len(user_ip_map) < 5:
            return None
        users_to_try = random.sample(list(user_ip_map.keys()), k=random.randint(5, 10))

    vpn_logs = []
    for user in users_to_try:
        # Multiple rapid failures per username (2–5 attempts before moving on)
        for _ in range(random.randint(2, 5)):
            src_port = random.randint(1024, 65535)
            fail_msg = (
                f"%ASA-6-109006: Authentication failed for user '{user}' "
                f"from {attacker_ip}/{src_port} to {outside_ip}/443 on interface outside"
            )
            vpn_logs.append(_generate_full_syslog_message(config, fail_msg))
    return vpn_logs


def _simulate_vpn_impossible_travel(config, session_context=None):
    """
    One user connecting from two geographically distant IPs in rapid succession.
    Triggers: "Impossible Travel" / "Anomalous VPN Location" analytics detection.
    """
    print("    - ASA Module simulating: VPN Impossible Travel")

    if session_context:
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        user      = user_info['username'] if user_info else None
    else:
        user = None

    if not user:
        user_ip_map = _get_user_ip_map(config)
        if not user_ip_map:
            return None
        user = random.choice(list(user_ip_map.keys()))

    benign_loc    = config.get('impossible_travel_scenario', {}).get('benign_location', {})
    suspicious_loc = config.get('impossible_travel_scenario', {}).get('suspicious_location', {})

    # Place the legitimate login 5–10 minutes in the past; the attacker login is
    # timestamped at now.  The gap is long enough for XSIAM to evaluate the pair
    # as an impossible travel sequence while short enough to model a credential
    # compromise (stolen creds used minutes after the real user authenticated).
    gap_minutes   = random.randint(5, 10)
    t_benign      = datetime.now(timezone.utc) - timedelta(minutes=gap_minutes)
    t_suspicious  = datetime.now(timezone.utc)

    asa_conf     = _get_asa_config(config)
    group_name   = asa_conf.get('vpn_group_name',   'TunnelGroup_AnyConnect')
    session_type = asa_conf.get('vpn_session_type', 'AnyConnect')

    def _vpn_start(public_ip, event_time):
        msg = (
            f"%ASA-4-113039: Group = {group_name}, Username = {user}, IP = {public_ip}, "
            f"AnyConnect session profile is {group_name}. "
            f"Session Type: {session_type}, Duration: 0:00:00, "
            f"Bytes xmt: 0, Bytes rcv: 0, Reason: User Initiated"
        )
        return _generate_full_syslog_message(config, msg, event_time)

    return [
        _vpn_start(benign_loc.get("ip", "68.185.12.14"),      t_benign),
        _vpn_start(suspicious_loc.get("ip", "175.45.176.10"), t_suspicious),
    ]


def _simulate_vpn_tor_login(config, session_context=None):
    """
    Successful AnyConnect VPN session initiated from a known TOR exit node IP.

    A valid corporate credential authenticated via TOR — indicating credential theft
    or deliberate anonymisation. The session START (113039) SUCCEEDS. Source IP is
    from tor_exit_nodes config; the username is a real corporate user.

    Triggers XSIAM: Suspicious VPN Login / TOR-based Access analytics detection.
    """
    print("    - ASA Module simulating: VPN Login from TOR Exit Node (successful)")
    tor_nodes = config.get('tor_exit_nodes', [])
    tor_ip    = random.choice(tor_nodes).get('ip', _random_external_ip()) if tor_nodes else _random_external_ip()

    if session_context:
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        user      = user_info['username'] if user_info else None
    else:
        user = None
    if not user:
        user_ip_map = _get_user_ip_map(config)
        if not user_ip_map:
            return None
        user = random.choice(list(user_ip_map.keys()))

    asa_conf     = _get_asa_config(config)
    group_name   = asa_conf.get('vpn_group_name',   'TunnelGroup_AnyConnect')
    session_type = asa_conf.get('vpn_session_type', 'AnyConnect')
    # Force session START (113039) — the successful auth from TOR is the detection signal
    message = (
        f"%ASA-4-113039: Group = {group_name}, Username = {user}, IP = {tor_ip}, "
        f"AnyConnect session profile is {group_name}. "
        f"Session Type: {session_type}, Duration: 0:00:00, "
        f"Bytes xmt: 0, Bytes rcv: 0, Reason: User Initiated"
    )
    return [_generate_full_syslog_message(config, message)]


def _simulate_smb_new_host_lateral(config, src_ip, session_context=None):
    """
    SMB connections from one internal workstation to multiple unfamiliar internal hosts.

    Generates 5–10 inbound TCP/445 Built+Teardown pairs, each to a DIFFERENT internal
    destination IP. The pattern of a single source reaching many new SMB endpoints in a
    short window is the XSIAM UEBA detection signal (lateral exploration, pass-the-hash
    staging, ransomware pre-encryption reconnaissance).

    Returns list of syslog strings (multi-event).
    """
    print("    - ASA Module simulating: SMB New-Host Lateral (exploring SMB on multiple hosts)")
    user      = _get_user_from_ip(config, src_ip, session_context)
    n_hosts   = random.randint(5, 10)
    dest_ips  = set()

    # Prefer real workstation IPs from session_context for realism
    if session_context:
        for _ in range(30):
            peer = get_random_user(session_context, preferred_device_type='workstation')
            if peer and peer.get('ip') and peer['ip'] != src_ip:
                dest_ips.add(peer['ip'])
            if len(dest_ips) >= n_hosts:
                break

    # Fallback: generate IPs from internal_networks
    internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
    while len(dest_ips) < n_hosts:
        try:
            net  = ip_network(random.choice(internal_nets), strict=False)
            host = rand_ip_from_network(net)
            if host != src_ip:
                dest_ips.add(host)
        except (ValueError, AddressValueError, IndexError):
            dest_ips.add(f"192.168.1.{random.randint(101, 200)}")

    logs = []
    for dst_ip in list(dest_ips)[:n_hosts]:
        logs.extend(_generate_connection_session(
            config, "TCP", src_ip, dst_ip, 445, user,
            random.randint(200, 5000), random.randint(2000, 50000),
            random.randint(1, 30),
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP FINs"
        ))
    return logs


def _simulate_smb_rare_file_transfer(config, src_ip, session_context=None):
    """
    Single large SMB/445 session (100 MB – 1 GB) to an internal server — data staging.

    The anomalously large data volume on SMB to an atypical destination is the XSIAM
    UEBA detection signal. The session is ALLOWED because no block rule matches.
    Models a user bulk-copying sensitive files from a share before exfiltration.

    Returns list of syslog strings (Built + Teardown pair).
    """
    print("    - ASA Module simulating: SMB Rare File Transfer (large internal SMB session)")
    user             = _get_user_from_ip(config, src_ip, session_context)
    internal_servers = config.get('internal_servers', [])
    dst_ip = random.choice([s for s in internal_servers if s != src_ip] or internal_servers or ['10.0.10.50'])

    file_size  = random.randint(104_857_600, 1_073_741_824)  # 100 MB – 1 GB
    duration_s = random.randint(120, 900)                    # 2 – 15 minutes
    return _generate_connection_session(
        config, "TCP", src_ip, dst_ip, 445, user,
        file_size, random.randint(1000, 50000),
        duration_s,
        src_interface="inside", dest_interface="inside",
        teardown_reason="TCP FINs"
    )


def _simulate_smb_share_enumeration(config, src_ip, session_context=None):
    """
    Rapid TCP/445 allowed sessions to many different internal hosts — SMB share scanning.

    15–40 short Built+Teardown session pairs from the same workstation to distinct
    internal IPs on port 445. The connections SUCCEED (firewall allows them) — XSIAM
    detects the scan pattern from the volume of allowed SMB connections to new hosts,
    not from deny events. Same detection principle as port_scan (allowed traffic volume).

    Returns list of syslog strings (multi-event).
    """
    print("    - ASA Module simulating: SMB Share Enumeration (scanning for open shares)")
    user      = _get_user_from_ip(config, src_ip, session_context)
    n_targets = random.randint(15, 40)

    target_ips    = set()
    internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
    while len(target_ips) < n_targets:
        try:
            net  = ip_network(random.choice(internal_nets), strict=False)
            host = rand_ip_from_network(net)
            if host != src_ip:
                target_ips.add(host)
        except (ValueError, AddressValueError, IndexError):
            target_ips.add(f"192.168.1.{random.randint(101, 254)}")

    logs = []
    for dst_ip in list(target_ips)[:n_targets]:
        # Brief session: small bytes, short duration — probe then immediately disconnect
        logs.extend(_generate_connection_session(
            config, "TCP", src_ip, dst_ip, 445, user,
            random.randint(40, 200), random.randint(40, 200),
            random.randint(0, 2),
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP Reset-I"
        ))
    return logs


# ---------------------------------------------------------------------------
# Main log generation entry point
# ---------------------------------------------------------------------------

def generate_log(config, scenario=None, threat_level="Realistic",
                 benign_only=False, context=None, scenario_event=None):
    """
    Generates a log or log batch for the Cisco ASA module.

    Benign event mix (default weights):
      benign_session  60%  — typical office traffic (web/DNS/email/SSH/ICMP)
      inbound_block   24%  — external traffic denied by outside-in ACL
      anyconnect_vpn  10%  — normal VPN connect/disconnect
      aaa_auth         6%  — normal authentication events

    Threat event fallback weights (used when event_mix is absent from config):
      ips_alert                  20  — IDS/IPS signature triggered (400xxx)
      port_scan                  15  — internal port scan (100–200 RST'd connections)
      auth_brute_force           13  — burst of 109006 auth failures
      lateral_movement           12  — multi-target SMB/RDP/SSH/WinRM attempts
      large_single_upload_session  8  — single large exfiltration session
      url_filter_block             8  — URL filter deny (304001)
      unusual_ssh_session          5  — outbound SSH to external IP
      smb_share_enumeration        5  — 15–40 rapid SMB/445 probes to many hosts
      cumulative_upload_session    4  — many small uploads to same external IP
      ssh_proxy_attack             4  — SSH to multiple internal servers
      targeted_admin_bruteforce    4  — focused 109001+109006 bursts against single admin account
      smb_new_host_lateral         4  — SMB connections to 5–10 new internal hosts
      unusual_rdp_session          3  — RDP to internal server
      tor_connection               3  — connection to Tor exit node
      vpn_bruteforce               3  — VPN credential scan
      vpn_tor_login                3  — successful VPN login from a Tor exit node IP
      smb_rare_file_transfer       3  — single large SMB session (100 MB – 1 GB)
      vpn_impossible_travel        2  — same user from two geographically distant IPs
      dns_c2_beacon                1  — DNS C2 beacon to suspicious external resolver
      server_outbound_http         1  — server making outbound HTTP to internet
      workstation_lateral_rdp      1  — workstation-to-workstation RDP
    """
    global last_threat_event_time
    session_context = (context or {}).get("session_context")

    # --- Scenario events from the coordinated simulator ---
    if scenario_event and context:
        if scenario_event == "LARGE_EGRESS":
            print("    - ASA Module simulating: Scenario LARGE_EGRESS")
            src_ip     = context.get('src_ip')
            bytes_sent = context.get('bytes', random.randint(20000000, 50000000))
            user       = _get_user_from_ip(config, src_ip, session_context)
            dest       = random.choice(config.get('exfiltration_destinations', [{}]))
            try:
                dest_ip = rand_ip_from_network(ip_network(dest.get("ip_range", "154.53.224.0/24"), strict=False))
            except (AddressValueError, ValueError):
                dest_ip = "154.53.224.10"
            return _generate_connection_session(
                config, "TCP", src_ip, dest_ip, 443, user,
                bytes_sent, random.randint(1000, 5000), random.randint(60, 300)
            )
        return None

    # --- Event mix from config or fallback defaults ---
    module_config = config.get(CONFIG_KEY, {})
    event_mix     = module_config.get('event_mix', {})

    benign_events   = event_mix.get('benign', [
        {"event": "benign_session",    "weight": 50},
        {"event": "inbound_block",     "weight": 22},
        {"event": "anyconnect_vpn",    "weight": 9},
        {"event": "aaa_auth",          "weight": 5},
        {"event": "ntp_sync",          "weight": 6},
        {"event": "internal_traffic",  "weight": 5},
        {"event": "dhcp_log",          "weight": 3},
    ])
    benign_functions = [e['event'] for e in benign_events]
    benign_weights   = [e['weight'] for e in benign_events]

    threat_events   = event_mix.get('threat', [])
    threat_functions = [e['event'] for e in threat_events]
    threat_weights   = [e['weight'] for e in threat_events]

    if not threat_functions:
        threat_functions = list(_DEFAULT_THREAT_NAMES)
        threat_weights   = list(_DEFAULT_THREAT_WEIGHTS)

    if benign_only or threat_level == "Benign Traffic Only":
        log_choice = random.choices(benign_functions, weights=benign_weights, k=1)[0]
    elif threat_level == "Insane":
        log_choice = random.choices(threat_functions, weights=threat_weights, k=1)[0]
    else:
        # Time-based throttling: only fire a threat if the configured interval has elapsed.
        # This matches the behaviour of Checkpoint, Fortinet, and Firepower.
        interval     = config.get('threat_generation_levels', {}).get(threat_level, 7200)
        current_time = time.time()
        if interval > 0 and (current_time - last_threat_event_time) > interval:
            last_threat_event_time = current_time
            log_choice = random.choices(threat_functions, weights=threat_weights, k=1)[0]
        else:
            log_choice = random.choices(benign_functions, weights=benign_weights, k=1)[0]

    # --- Resolve internal host IP for events that need one ---
    # Events that handle their own user/IP selection are excluded from this block.
    no_internal_ip_needed = {
        "anyconnect_vpn", "vpn_bruteforce", "vpn_impossible_travel",
        "server_outbound_http", "inbound_block", "auth_brute_force", "aaa_auth",
        "vpn_tor_login",    # resolves its own user/IP from TOR nodes config
        "ntp_sync",         # picks IP from internal_networks directly
        "internal_traffic", # resolves user/IP from session_context itself
        "dhcp_log",         # picks IP from internal_networks directly
    }
    internal_host_ip = "192.168.1.100"
    if log_choice not in no_internal_ip_needed:
        if session_context:
            user_info = get_random_user(session_context, preferred_device_type='workstation')
            if user_info and user_info.get('ip'):
                internal_host_ip = user_info['ip']
        else:
            user_ip_map = _get_user_ip_map(config)
            if user_ip_map:
                _, internal_host_ip = random.choice(list(user_ip_map.items()))

    # --- Dispatch ---
    _result = None
    if log_choice == "benign_session":
        _result = _simulate_benign_office_traffic(config, session_context)

    elif log_choice == "inbound_block":
        _result = _simulate_inbound_block(config)

    elif log_choice == "anyconnect_vpn":
        _result = _generate_anyconnect_vpn_log(config, session_context=session_context)

    elif log_choice == "aaa_auth":
        _result = _generate_aaa_auth_log(config, session_context=session_context)

    elif log_choice == "ntp_sync":
        _result = _simulate_ntp_sync(config)

    elif log_choice == "internal_traffic":
        _result = _simulate_internal_traffic(config, session_context)

    elif log_choice == "dhcp_log":
        _result = _simulate_dhcp_log(config)

    elif log_choice == "large_single_upload_session":
        print("    - ASA Module simulating: Large Single Upload Session")
        _result = _simulate_large_upload_session(config, internal_host_ip,
                                                  is_cumulative=False,
                                                  session_context=session_context)

    elif log_choice == "cumulative_upload_session":
        print("    - ASA Module simulating: Cumulative Large Upload Session")
        _result = _simulate_large_upload_session(config, internal_host_ip,
                                                  is_cumulative=True,
                                                  session_context=session_context)

    elif log_choice == "unusual_rdp_session":
        print("    - ASA Module simulating: Unusual Internal RDP Session")
        _result = _simulate_rdp_session(config, internal_host_ip, session_context)

    elif log_choice == "unusual_ssh_session":
        print("    - ASA Module simulating: Rare External SSH Session")
        _result = _simulate_ssh_session(config, internal_host_ip, session_context)

    elif log_choice == "port_scan":
        print("    - ASA Module simulating: Internal Port Scan")
        _result = _simulate_port_scan(config, scanner_ip=internal_host_ip,
                                       session_context=session_context)

    elif log_choice == "ssh_proxy_attack":
        print("    - ASA Module simulating: SSH Proxy Attack (Lateral Movement)")
        _result = _simulate_ssh_proxy_attack(config, attacker_ip=internal_host_ip,
                                              session_context=session_context)

    elif log_choice == "tor_connection":
        print("    - ASA Module simulating: Connection to Tor Exit Node")
        _result = _simulate_tor_connection_session(config, internal_host_ip, session_context)

    elif log_choice == "vpn_bruteforce":
        _result = _simulate_vpn_bruteforce_or_scan(config, session_context)

    elif log_choice == "vpn_impossible_travel":
        _result = _simulate_vpn_impossible_travel(config, session_context)

    elif log_choice == "dns_c2_beacon":
        print("    - ASA Module simulating: DNS C2 Beacon")
        _result = _simulate_dns_c2_beacon(config, internal_host_ip, session_context)

    elif log_choice == "server_outbound_http":
        print("    - ASA Module simulating: Anomalous Server Outbound HTTP")
        _result = _simulate_server_outbound_http(config, session_context)

    elif log_choice == "workstation_lateral_rdp":
        print("    - ASA Module simulating: Workstation-to-Workstation RDP")
        _result = _simulate_workstation_lateral_rdp(config, internal_host_ip, session_context)

    elif log_choice == "auth_brute_force":
        _result = _simulate_auth_brute_force(config, session_context)

    elif log_choice == "targeted_admin_bruteforce":
        _result = _simulate_targeted_admin_bruteforce(config, session_context)

    elif log_choice == "lateral_movement":
        _result = _simulate_lateral_movement(config, internal_host_ip, session_context)

    elif log_choice == "ips_alert":
        _result = _simulate_ips_alert(config, _random_external_ip())

    elif log_choice == "url_filter_block":
        _result = _simulate_url_filtering_block(config, internal_host_ip)

    elif log_choice == "vpn_tor_login":
        _result = _simulate_vpn_tor_login(config, session_context)

    elif log_choice == "smb_new_host_lateral":
        _result = _simulate_smb_new_host_lateral(config, internal_host_ip, session_context)

    elif log_choice == "smb_rare_file_transfer":
        _result = _simulate_smb_rare_file_transfer(config, internal_host_ip, session_context)

    elif log_choice == "smb_share_enumeration":
        _result = _simulate_smb_share_enumeration(config, internal_host_ip, session_context)

    return (_result, log_choice) if _result is not None else None
