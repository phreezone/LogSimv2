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
    from modules.session_utils import (get_random_user, find_user_by_ip, get_user_by_name,
        rand_ip_from_network, stable_vpn_ip, stable_mail_servers, weighted_destination)
except ImportError:
    from session_utils import (get_random_user, find_user_by_ip, get_user_by_name,
        rand_ip_from_network, stable_vpn_ip, stable_mail_servers, weighted_destination)

last_threat_event_time = 0


def _ad_user(user):
    """Format bare username as EXAMPLECORP\\username for syslog output.

    AD/LDAP-integrated firewalls show domain\\user in identity fields.
    This lets XSIAM Identity stitch firewall users (EXAMPLECORP\\user)
    with cloud/SaaS users (user@examplecorp.com) into one identity.
    """
    if user and "\\" not in user and "@" not in user:
        return f"EXAMPLECORP\\{user}"
    return user

NAME        = "Cisco ASA Firewall"
DESCRIPTION = "Simulates Cisco ASA syslog messages for the XSIAM cisco_asa_raw dataset."
XSIAM_PARSER = "Cisco ASA"
CONFIG_KEY  = "cisco_asa_config"

# Single source of truth for threat event names used both as the generate_log fallback
# and by get_threat_names(). Add new threat names here when adding dispatch cases below.
# Each entry maps 1:1 to a real Cortex XSIAM Third-Party Firewall or Third-Party
# VPN analytics detection that ASA syslog can drive directly. Detections that
# require AppID, process info, AD identity sync, or AnyConnect posture data are
# intentionally absent — ASA cannot supply the necessary fields.
_DEFAULT_THREAT_NAMES = [
    "port_scan", "failed_connections_burst",
    "large_single_upload_session", "cumulative_upload_session",
    "unusual_ssh_session", "unusual_rdp_session", "ssh_proxy_attack",
    "tor_connection", "vpn_bruteforce", "vpn_impossible_travel", "dns_c2_beacon",
    "server_outbound_http", "workstation_lateral_rdp",
    "vpn_tor_login", "smb_new_host_lateral", "smb_rare_file_transfer", "smb_share_enumeration",
    "smtp_spray", "smtp_large_exfil",
    "torrent_client", "new_ftp_server", "dc_smb_outbound",
]
_DEFAULT_THREAT_WEIGHTS = [15, 10, 8, 4, 5, 3, 4, 3, 3, 2, 1, 1, 1, 3, 4, 3, 5, 3, 2, 3, 2, 3]


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
    """Returns UTC timestamp in ISO 8601 format expected by the XSIAM parser.

    The XSIAM Cisco ASA parsing rule (CiscoASA.xif) only assigns _time when the
    extracted date matches "%Y-%m-%dT%H:%M:%SZ" or "%Y-%m-%dT%H:%M:%S%Ez".
    BSD-style "Mmm dd HH:MM:SS" timestamps cause _time to remain unset, which
    breaks every time-windowed detection (UEBA, brute-force, port-scan, etc.).

    This matches what a real Cisco ASA emits with `logging timestamp rfc5424`.
    """
    t = dt if dt else datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


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


# Stable per-src NAT mapping — real PAT keeps a sticky external IP for each
# internal host for the lifetime of its conntrack entries.  Without this every
# session for one user shows a different public IP, which corrupts source-IP
# pivots in XSIAM.
_nat_ip_map: dict[str, str] = {}

# Stable per-src DNS C2 beacon target — beacon detections only fire when the
# same destination is contacted repeatedly.  Random destinations every call
# produce noise, not a beacon pattern.
_beacon_target_map: dict[str, str] = {}


def _get_nat_ip(config, src_ip=None):
    """Returns the NAT/PAT IP for src_ip, sticky per internal host.

    Falls back to a random pool address when src_ip is not supplied (preserves
    legacy callers).
    """
    try:
        nat_pool = ip_network(_get_asa_config(config).get('nat_pool_cidr', '203.0.113.0/28'))
        if src_ip is None:
            return rand_ip_from_network(nat_pool)
        cached = _nat_ip_map.get(src_ip)
        if cached:
            return cached
        nat_ip = rand_ip_from_network(nat_pool)
        _nat_ip_map[src_ip] = nat_ip
        return nat_ip
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
    # RFC 5424 framing: <PRI>VERSION TIMESTAMP HOSTNAME : MSG
    # Matches Cisco ASA with `logging timestamp rfc5424` enabled, which is the
    # format the XSIAM parse_cisco() built-in is calibrated against.
    return f"<{pri}>1 {timestamp} {hostname} : {asa_message}"


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


def _dns_precursor(config, src_ip, user):
    """Generate a UDP/53 DNS Built+Teardown pair preceding an outbound connection."""
    return _generate_connection_session(
        config, "UDP", src_ip, "8.8.8.8", 53, user,
        random.randint(60, 150), random.randint(100, 400), 0,
    )


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

    # Same-interface traffic (intra-interface lateral) → direction reported as
    # "inbound" — matches real ASA behaviour with `same-security-traffic permit
    # intra-interface`, where the destination interface's ACL evaluates the
    # packet as inbound.
    effective_direction = "inbound" if src_interface == dest_interface else direction

    # NAT/PAT only for outside-facing sessions.  Sticky per internal src_ip so
    # one host keeps the same public IP across sessions (matches real PAT).
    nat_ip   = src_ip
    nat_port = src_port
    if dest_interface == "outside":
        nat_ip   = _get_nat_ip(config, src_ip)
        nat_port = random.randint(1024, 65535)

    # Identity firewall user clause — only emitted when a user is known.
    # Real ASA omits the parenthetical entirely for system / unattributed flows.
    fw_user      = _ad_user(user) if user else ""
    user_paren   = f" ({fw_user})" if fw_user else ""

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
            f"{user_paren}"
        ))
        session_logs.append(_generate_full_syslog_message(config,
            f"%ASA-6-302021: Teardown ICMP connection for "
            f"faddr {faddr}/{icmp_type} gaddr {gaddr}/{icmp_type} laddr {laddr}/{icmp_code}"
            f"{user_paren}"
        ))
        return session_logs

    # TCP / UDP event IDs
    if protocol == "TCP":
        built_id, teardown_id = "302013", "302014"
    else:
        built_id, teardown_id = "302015", "302016"
        teardown_reason = ""  # UDP teardowns have no reason field

    # Real Cisco ASA format puts a SPACE between the NAT mapping and the IDFW
    # user parenthetical, and omits the parenthetical entirely when no user is
    # mapped (system / unattributed sessions like NTP, DHCP).
    built_log = (
        f"%ASA-6-{built_id}: Built {effective_direction} {protocol} connection {conn_id} "
        f"for {dest_interface}:{dest_ip}/{dest_port} ({dest_ip}/{dest_port}) "
        f"to {src_interface}:{src_ip}/{src_port} ({nat_ip}/{nat_port})"
        f"{user_paren}"
    )
    session_logs.append(_generate_full_syslog_message(config, built_log))

    duration_str = _format_duration(duration_sec)
    reason_str   = f" {teardown_reason}" if teardown_reason else ""
    total_bytes  = bytes_sent + bytes_received

    teardown_log = (
        f"%ASA-6-{teardown_id}: Teardown {protocol} connection {conn_id} "
        f"for {dest_interface}:{dest_ip}/{dest_port} "
        f"to {src_interface}:{src_ip}/{src_port} "
        f"duration {duration_str} bytes {total_bytes}{reason_str}"
        f"{user_paren}"
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
        # Session Start — documented Cisco format is positional, severity 6:
        #   %ASA-6-113039: Group <group> User <user> IP <peer> AnyConnect parent session started.
        message = (
            f"%ASA-6-113039: Group <{group_name}> User <{_ad_user(user)}> IP <{public_ip}> "
            f"AnyConnect parent session started."
        )
    else:
        # Session End
        duration = random.randint(60, 3600)
        message = (
            f"%ASA-4-113019: Group = {group_name}, Username = {_ad_user(user)}, IP = {public_ip}, "
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
    src_port = random.randint(49152, 65535)

    req_msg = (
        f"%ASA-6-109001: Auth start for user '{_ad_user(user)}' "
        f"from {src_ip}/{src_port} to {outside_ip}/443 on interface outside"
    )
    if success:
        result_msg = (
            f"%ASA-6-109005: Authentication succeeded for user '{_ad_user(user)}' "
            f"from {src_ip}/{src_port} to {outside_ip}/443 on interface outside"
        )
    else:
        result_msg = (
            f"%ASA-6-109006: Authentication failed for user '{_ad_user(user)}' "
            f"from {src_ip}/{src_port} to {outside_ip}/443 on interface outside"
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

    destination = weighted_destination(user, possible)
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
        dest_ip     = stable_mail_servers(user)   # fixed 2-3 relays per user
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
    Single %ASA-4-106023 deny — represents normal internet background noise
    (untargeted probes hitting the outside-in ACL).  Used as a BENIGN event to
    build baseline; the `failed_connections_burst` threat generator handles the
    high-volume case that fires XSIAM "Failed Connections".

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
        f"%ASA-4-106023: Deny {protocol.lower()} src outside:{scanner_ip}/{src_port} "
        f"dst inside:{target_ip}/{dest_port} "
        f"by access_group {acl_name} [0x{hash1:08x}, 0x0]"
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

    if event_type == "built":
        message = (
            f"%ASA-6-305011: Built dynamic TCP translation from inside:{client_ip}/{src_port} "
            f"to outside:{outside_ip}/{mapped_port}"
        )
    else:
        message = (
            f"%ASA-6-305012: Teardown dynamic TCP translation from inside:{client_ip}/{src_port} "
            f"to outside:{outside_ip}/{mapped_port} duration 0:01:00"
        )
    return _generate_full_syslog_message(config, message)


# ---------------------------------------------------------------------------
# Threat event generators
# ---------------------------------------------------------------------------

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
    """C2 beacon disguised as a DNS query to a suspicious external resolver.

    Beacon detection requires the SAME destination across multiple intervals —
    that's what makes a beacon a beacon.  Cache the C2 IP per internal host so
    repeated invocations form a real beacon pattern.
    """
    dest_ip = _beacon_target_map.get(internal_host_ip)
    if not dest_ip:
        dest_ip = _random_external_ip()
        _beacon_target_map[internal_host_ip] = dest_ip

    user = _get_user_from_ip(config, internal_host_ip, session_context)
    return _generate_connection_session(
        config, "UDP", internal_host_ip, dest_ip, 53, user,
        random.randint(100, 250), random.randint(150, 500), random.randint(0, 2)
    )


def _simulate_server_outbound_http(config, session_context=None, src_ip_override=None):
    """Anomalous outbound HTTP from an internal server (servers should not browse).

    Triggers XSIAM "Abnormal Communication to a Rare IP" / "Recurring access to
    rare IP".  Both detections require the destination to be *rare* from the
    org's perspective — picking a benign destination defeats the signal because
    benign destinations have heavy baseline traffic from many other hosts.
    Use a stable rare external IP per server so recurrence emerges across runs.
    """
    if not config.get('internal_servers'):
        return None
    src_ip = src_ip_override or random.choice(config.get('internal_servers'))
    user   = _get_user_from_ip(config, src_ip, session_context)

    dest_ip = _beacon_target_map.get(f"srv_http::{src_ip}")
    if not dest_ip:
        dest_ip = _random_external_ip()
        _beacon_target_map[f"srv_http::{src_ip}"] = dest_ip

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
    # 1-2 successful connections on common open ports — attacker finds live services
    open_ports = random.sample([22, 80, 443, 445, 3389, 8080, 8443], k=random.randint(1, 2))
    for port in open_ports:
        scan_logs.extend(_generate_connection_session(
            config, "TCP", scanner_ip, victim_ip, port, user,
            random.randint(500, 5000), random.randint(500, 5000), random.randint(5, 30),
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP FINs"
        ))
    return scan_logs


def _simulate_ssh_proxy_attack(config, attacker_ip, session_context=None):
    """SSH proxy / jumphost behaviour — one source fans out to many internal
    SSH targets with high byte volume and long sessions, the signature pattern
    XSIAM's "Unusual SSH activity that resembles SSH proxy" detection matches.

    Real admin SSH is low volume (a few KB) to a small set of targets; SSH
    proxy/tunnel activity pushes megabytes through long-lived sessions across a
    wide target set.  The previous 500-15000 byte / 2-5 target shape looked
    like normal admin SSH and was below the detection's volume threshold.
    """
    potential_victims = [ip for ip in config.get('internal_servers', []) if ip != attacker_ip]
    if len(potential_victims) < 2:
        return None

    k          = random.randint(5, min(len(potential_victims), 10))
    victim_ips = random.sample(potential_victims, k=k)
    user       = _get_user_from_ip(config, attacker_ip, session_context)

    attack_logs = []
    for victim_ip in victim_ips:
        # Proxy/tunnel volumes: 5-50 MB per session, 5-30 minute durations
        attack_logs.extend(_generate_connection_session(
            config, "TCP", attacker_ip, victim_ip, 22, user,
            random.randint(5_000_000, 50_000_000),
            random.randint(5_000_000, 50_000_000),
            random.randint(300, 1800),
            src_interface="inside", dest_interface="inside"
        ))
    return attack_logs


def _simulate_tor_connection_session(config, internal_host_ip, session_context=None):
    """Outbound connection to a known Tor exit node — anonymisation attempt.

    Stable Tor node per src_ip so successive runs form a "Recurring access to
    rare IP" pattern.  Random per-call destinations look like noise to XSIAM,
    not a recurring rare-IP signal.
    """
    dest_ip = _beacon_target_map.get(f"tor::{internal_host_ip}")
    if not dest_ip:
        tor_nodes = config.get('tor_exit_nodes', [])
        if tor_nodes:
            dest_ip = random.choice(tor_nodes).get("ip")
        if not dest_ip:
            dest_ip = _random_external_ip()
        _beacon_target_map[f"tor::{internal_host_ip}"] = dest_ip

    user = _get_user_from_ip(config, internal_host_ip, session_context)
    return _generate_connection_session(
        config, "TCP", internal_host_ip, dest_ip, random.choice([443, 9001, 9030]), user,
        random.randint(10000, 100000), random.randint(50000, 500000), random.randint(10, 120)
    )


def _simulate_vpn_bruteforce_or_scan(config, session_context=None, victim_user=None, attacker_ip=None):
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
    attacker_ip = attacker_ip or _random_external_ip()

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

    # Ensure the scenario victim is among the targeted users and gets compromised,
    # so the brute-force (109006) → VPN-login (113039) correlation ties to one user.
    if victim_user and victim_user not in users_to_try:
        users_to_try = [victim_user] + users_to_try

    vpn_logs = []
    for user in users_to_try:
        # Rapid failures per username; the victim gets >=3 to satisfy the detection.
        n_fails = random.randint(3, 5) if user == victim_user else random.randint(2, 5)
        for _ in range(n_fails):
            src_port = random.randint(1024, 65535)
            start_msg = (
                f"%ASA-6-109001: Auth start for user '{_ad_user(user)}' "
                f"from {attacker_ip}/{src_port} to {outside_ip}/443 on interface outside"
            )
            fail_msg = (
                f"%ASA-6-109006: Authentication failed for user '{_ad_user(user)}' "
                f"from {attacker_ip}/{src_port} to {outside_ip}/443 on interface outside"
            )
            vpn_logs.append(_generate_full_syslog_message(config, start_msg))
            vpn_logs.append(_generate_full_syslog_message(config, fail_msg))
    # Final success — attacker found valid credentials; triggers XSIAM brute-force detection
    success_user = victim_user if victim_user else random.choice(users_to_try)
    src_port = random.randint(1024, 65535)
    success_start = (
        f"%ASA-6-109001: Auth start for user '{_ad_user(success_user)}' "
        f"from {attacker_ip}/{src_port} to {outside_ip}/443 on interface outside"
    )
    success_msg = (
        f"%ASA-6-109005: Authentication succeeded for user '{_ad_user(success_user)}' "
        f"from {attacker_ip}/{src_port} to {outside_ip}/443 on interface outside"
    )
    vpn_logs.append(_generate_full_syslog_message(config, success_start))
    vpn_logs.append(_generate_full_syslog_message(config, success_msg))
    return vpn_logs


def _simulate_vpn_impossible_travel(config, session_context=None, victim_user=None, vpn_inside_ip=None):
    """
    One user connecting from two geographically distant IPs in rapid succession.
    Triggers: "Impossible Travel" / "Anomalous VPN Location" analytics detection.
    """
    print("    - ASA Module simulating: VPN Impossible Travel")

    user = victim_user
    if not user and session_context:
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        user      = user_info['username'] if user_info else None

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

    asa_conf   = _get_asa_config(config)
    group_name = asa_conf.get('vpn_group_name', 'TunnelGroup_AnyConnect')

    # VPN pool IP assigned to the attacker session. The 722051 event binds the
    # compromised user to this internal IP, so lateral movement (SMB/RDP) sourced
    # from it stitches back to the same identity in XSIAM.
    if not vpn_inside_ip:
        vpn_pool = asa_conf.get('vpn_pool', '10.250.0.0/16')
        try:
            vpn_inside_ip = rand_ip_from_network(ip_network(vpn_pool, strict=False))
        except Exception:
            vpn_inside_ip = f"10.250.{random.randint(1,254)}.{random.randint(1,254)}"

    def _vpn_start(public_ip, event_time):
        msg = (
            f"%ASA-6-113039: Group <{group_name}> User <{_ad_user(user)}> IP <{public_ip}> "
            f"AnyConnect parent session started."
        )
        return _generate_full_syslog_message(config, msg, event_time)

    def _vpn_assign(public_ip, inside_ip, event_time):
        msg = (
            f"%ASA-6-722051: Group <{group_name}> User <{_ad_user(user)}> IP <{public_ip}> "
            f"Address <{inside_ip}> assigned to session"
        )
        return _generate_full_syslog_message(config, msg, event_time)

    # Randomize the host octet of each public IP so every run gets distinct
    # source IPs within the same /24 (same geo/country for the impossible-travel
    # logic). A fixed suspicious IP makes XSIAM bind every run's impossible-travel
    # alert to one shared source-IP incident; a per-run IP lets that alert group
    # by user into the victim's own incident instead.
    def _rand_host(ip, default):
        base = ip or default
        parts = base.split(".")
        if len(parts) != 4:
            return base
        return ".".join(parts[:3] + [str(random.randint(2, 254))])

    benign_ip = _rand_host(benign_loc.get("ip"), "68.185.12.14")
    susp_ip   = _rand_host(suspicious_loc.get("ip"), "175.45.176.10")
    return [
        _vpn_start(benign_ip, t_benign),
        _vpn_start(susp_ip, t_suspicious),
        _vpn_assign(susp_ip, vpn_inside_ip, t_suspicious),
    ]


def _simulate_vpn_tor_login(config, session_context=None):
    """Full conversation: TLS handshake + VPN auth + post-auth internal activity from Tor.

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

    asa_conf   = _get_asa_config(config)
    group_name = asa_conf.get('vpn_group_name', 'TunnelGroup_AnyConnect')

    # Assign VPN pool inside IP for post-auth traffic
    vpn_pool = asa_conf.get('vpn_pool', '10.250.0.0/16')
    try:
        vpn_inside_ip = rand_ip_from_network(ip_network(vpn_pool, strict=False))
    except Exception:
        vpn_inside_ip = f"10.250.{random.randint(1,254)}.{random.randint(1,254)}"

    base_time = datetime.now(timezone.utc)
    logs = []

    # Log 1: TLS handshake (Built+Teardown TCP to gateway:443)
    gateway_ip = asa_conf.get('outside_ip', '203.0.113.1')
    logs.extend(_generate_connection_session(
        config, "TCP", tor_ip, gateway_ip, 443, user,
        random.randint(500, 2000), random.randint(2000, 8000), 1,
        direction="inbound", src_interface="outside", dest_interface="inside"
    ))

    # Log 2: VPN session start (113039) — primary detection event.
    # Documented Cisco format: positional, severity 6.
    start_msg = (
        f"%ASA-6-113039: Group <{group_name}> User <{_ad_user(user)}> IP <{tor_ip}> "
        f"AnyConnect parent session started."
    )
    logs.append(_generate_full_syslog_message(config, start_msg,
                event_time=base_time + timedelta(seconds=2)))

    # Logs 3+: Post-auth internal activity from VPN pool IP
    post_auth_ports = [
        (445, "TCP", "SMB"), (3389, "TCP", "RDP"),
        (22, "TCP", "SSH"), (389, "TCP", "LDAP"),
    ]
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    n_post = random.randint(1, 3)
    for i, (port, proto, _) in enumerate(random.sample(post_auth_ports, min(n_post, len(post_auth_ports)))):
        dst_ip = random.choice(internal_servers)
        logs.extend(_generate_connection_session(
            config, proto, vpn_inside_ip, dst_ip, port, user,
            random.randint(1000, 50000), random.randint(5000, 200000),
            random.randint(5, 120),
            src_interface="inside", dest_interface="inside"
        ))
    return logs


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
        # Brief session: small bytes, short duration — probe then immediately disconnect.
        # Share enumeration completes the TCP handshake before walking shares, so
        # use TCP FINs (clean close) rather than TCP Reset-I (port-scan semantics).
        logs.extend(_generate_connection_session(
            config, "TCP", src_ip, dst_ip, 445, user,
            random.randint(40, 200), random.randint(40, 200),
            random.randint(0, 2),
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP FINs"
        ))
    return logs


def _simulate_smtp_spray(config, src_ip, session_context=None):
    """Compromised workstation acting as spam bot — direct SMTP to many external MX.

    Generates 30-50 TCP Built+Teardown session pairs from one internal workstation
    to DISTINCT external IPs on port 25 (SMTP) or 587 (submission).  Workstations
    never connect directly to external MX servers in normal operations — a single
    host opening direct SMTP connections to many destinations is a strong spam-bot
    indicator.

    Triggers XSIAM: anomalous SMTP from workstation / spam bot analytics.
    Returns list of syslog strings (multi-event).
    """
    print(f"    - ASA Module simulating: SMTP Spray (spam bot) from {src_ip}")
    user      = _get_user_from_ip(config, src_ip, session_context)
    n_targets = random.randint(30, 50)
    dest_ips  = set()
    while len(dest_ips) < n_targets:
        dest_ips.add(_random_external_ip())

    logs = []
    for dst_ip in list(dest_ips)[:n_targets]:
        smtp_port   = random.choices([25, 587], weights=[70, 30], k=1)[0]
        bytes_sent  = random.randint(2_000, 50_000)
        bytes_recv  = random.randint(200, 2_000)
        duration    = random.randint(1, 30)
        logs.extend(_generate_connection_session(
            config, "TCP", src_ip, dst_ip, smtp_port, user,
            bytes_sent, bytes_recv, duration,
            src_interface="inside", dest_interface="outside",
            teardown_reason="TCP FINs"
        ))
    return logs


def _simulate_smtp_large_exfil(config, src_ip, session_context=None):
    """Data exfiltration via large email attachment over SMTP.

    Single long-duration SMTP session with 100-500 MB outbound bytes.
    Normal email attachments rarely exceed 25 MB.  The DNS precursor is
    added by the dispatch block (same pattern as other exfil threats).

    Triggers XSIAM: large outbound SMTP data transfer / email exfiltration analytics.
    Returns list of syslog strings (multi-event).
    """
    print(f"    - ASA Module simulating: Large SMTP Exfiltration from {src_ip}")
    user = _get_user_from_ip(config, src_ip, session_context)
    mail_mx_ranges = [
        "74.125.0.0/16", "40.76.0.0/14", "207.46.0.0/16",
        "198.2.128.0/18", "159.148.0.0/16",
    ]
    try:
        dest_ip = rand_ip_from_network(
            ip_network(random.choice(mail_mx_ranges), strict=False))
    except Exception:
        dest_ip = _random_external_ip()

    smtp_port  = random.choices([587, 25], weights=[80, 20], k=1)[0]
    bytes_sent = random.randint(104_857_600, 524_288_000)   # 100 MB - 500 MB
    bytes_recv = random.randint(500, 5_000)
    duration   = random.randint(300, 1200)

    return _generate_connection_session(
        config, "TCP", src_ip, dest_ip, smtp_port, user,
        bytes_sent, bytes_recv, duration,
        src_interface="inside", dest_interface="outside",
        teardown_reason="TCP FINs"
    )


def _simulate_failed_connections_burst(config, attacker_ip=None):
    """High volume of 106023 denies from one external IP — XSIAM "Failed Connections" detection.

    The detection fires when a single source generates an abnormal count of blocked
    connections in a short window.  Single-shot inbound_block events don't reach
    the threshold; this generator emits 50–150 denies from one attacker IP across
    a varied internal target set.  `attacker_ip` pins the source so a scenario can
    key every perimeter stage to one external attacker.
    """
    print("    - ASA Module simulating: Failed Connections burst")
    acl_name    = _get_acl_name(config)
    attacker_ip = attacker_ip or _random_external_ip()

    internal_networks = config.get('internal_networks', ['10.10.1.0/24'])
    try:
        net = ip_network(random.choice(internal_networks), strict=False)
    except (ValueError, IndexError):
        net = None

    scan_ports = [22, 23, 25, 80, 135, 139, 443, 445, 1433, 1521,
                  3306, 3389, 4444, 5900, 6379, 8080, 8443]

    deny_logs = []
    for _ in range(random.randint(50, 150)):
        target_ip = rand_ip_from_network(net) if net else f"10.10.1.{random.randint(2, 254)}"
        dest_port = random.choice(scan_ports)
        src_port  = random.randint(1024, 65535)
        protocol  = random.choices(["tcp", "udp"], weights=[85, 15], k=1)[0]
        hash1     = random.randint(0, 0xFFFFFFFF)
        deny_msg = (
            f"%ASA-4-106023: Deny {protocol} src outside:{attacker_ip}/{src_port} "
            f"dst inside:{target_ip}/{dest_port} "
            f"by access_group {acl_name} [0x{hash1:08x}, 0x0]"
        )
        deny_logs.append(_generate_full_syslog_message(config, deny_msg))
    return deny_logs


# Known BitTorrent tracker / DHT node IP ranges seen in real traffic.  Used by
# the torrent_client generator so successive runs hit the same address space
# (XSIAM "Torrent client detected" pattern needs consistent peer destinations).
_TORRENT_TRACKER_IPS = [
    "82.221.103.244", "151.80.121.230", "208.83.20.20", "37.235.174.46",
    "5.45.105.117",   "176.31.250.174", "82.156.24.219", "104.244.77.32",
]
_TORRENT_PORTS = [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 51413, 25401]


def _simulate_torrent_client(config, internal_host_ip, session_context=None):
    """Outbound traffic from internal host to BitTorrent tracker IPs / ports.

    XSIAM "A Torrent client was detected on a host" matches traffic to known
    BitTorrent infrastructure and well-known torrent port ranges.  Real BT
    clients use BOTH TCP (peer connections, tracker announces) AND UDP
    (DHT, uTP, UDP trackers) — a TCP-only flow is the wrong fingerprint.
    """
    print(f"    - ASA Module simulating: Torrent client from {internal_host_ip}")
    user = _get_user_from_ip(config, internal_host_ip, session_context)

    logs = []
    for _ in range(random.randint(8, 15)):
        dest_ip   = random.choice(_TORRENT_TRACKER_IPS)
        dest_port = random.choice(_TORRENT_PORTS)
        # ~40% UDP (DHT / UDP tracker / uTP), 60% TCP (peer / tracker announce)
        protocol  = random.choices(["UDP", "TCP"], weights=[40, 60], k=1)[0]
        if protocol == "UDP":
            # DHT / UDP tracker — small payloads, short duration
            logs.extend(_generate_connection_session(
                config, "UDP", internal_host_ip, dest_ip, dest_port, user,
                random.randint(500, 5_000), random.randint(500, 5_000),
                random.randint(0, 5),
                src_interface="inside", dest_interface="outside",
            ))
        else:
            # TCP peer connection — larger transfers, longer sessions
            logs.extend(_generate_connection_session(
                config, "TCP", internal_host_ip, dest_ip, dest_port, user,
                random.randint(50_000, 500_000), random.randint(500_000, 5_000_000),
                random.randint(30, 600),
                src_interface="inside", dest_interface="outside",
                teardown_reason="TCP FINs"
            ))
    return logs


def _simulate_new_ftp_server(config):
    """Internal host serving inbound FTP (TCP/21) — XSIAM "New FTP Server" detection.

    Fires when an asset starts accepting inbound FTP connections it hasn't
    served before.  Generated as an inbound 302013 (external client connecting
    to internal IP on port 21) — i.e., src_interface=outside, dest_interface=inside.
    """
    print("    - ASA Module simulating: New FTP Server (inbound TCP/21)")
    internal_servers = config.get('internal_servers', [])
    if internal_servers:
        ftp_server_ip = random.choice(internal_servers)
    else:
        try:
            net = ip_network(random.choice(config.get('internal_networks', ['10.10.1.0/24'])), strict=False)
            ftp_server_ip = rand_ip_from_network(net)
        except (ValueError, IndexError):
            ftp_server_ip = "10.10.1.50"

    logs = []
    # 3–6 distinct external clients hitting the FTP server — establishes "serving" behaviour
    for _ in range(random.randint(3, 6)):
        client_ip = _random_external_ip()
        logs.extend(_generate_connection_session(
            config, "TCP", client_ip, ftp_server_ip, 21, "",
            random.randint(500, 5_000), random.randint(50_000, 5_000_000),
            random.randint(10, 300),
            direction="inbound",
            src_interface="outside", dest_interface="inside",
            teardown_reason="TCP FINs"
        ))
    return logs


def _simulate_dc_smb_outbound(config, session_context=None):
    """SMB/445 from a domain controller to a workstation — XSIAM "Suspicious SMB
    connection from domain controller" detection.

    Normal direction is workstation → DC.  DC → workstation SMB is anomalous and
    associated with credential-theft tooling (e.g., DCSync followers, secretsdump
    reverse paths).  Requires a `dc_servers` list in cisco_asa_config so the
    generator knows which internal_servers are DCs; falls back to the first
    internal_servers entry.
    """
    asa_conf      = _get_asa_config(config)
    dc_servers    = asa_conf.get('dc_servers') or config.get('dc_servers') or []
    if not dc_servers:
        internal_servers = config.get('internal_servers', [])
        if not internal_servers:
            return None
        dc_servers = [internal_servers[0]]

    dc_ip = random.choice(dc_servers)
    print(f"    - ASA Module simulating: DC SMB outbound from {dc_ip}")

    # Pick a workstation target
    target_ip = None
    if session_context:
        ws = get_random_user(session_context, preferred_device_type='workstation')
        if ws and ws.get('ip') and ws['ip'] != dc_ip:
            target_ip = ws['ip']
    if not target_ip:
        try:
            net = ip_network(random.choice(config.get('internal_networks', ['192.168.1.0/24'])), strict=False)
            target_ip = rand_ip_from_network(net)
        except (ValueError, IndexError):
            target_ip = "192.168.1.101"

    user = _get_user_from_ip(config, dc_ip, session_context) or "SYSTEM"

    logs = []
    # 2–4 SMB sessions from DC to the same workstation in a short window
    for _ in range(random.randint(2, 4)):
        logs.extend(_generate_connection_session(
            config, "TCP", dc_ip, target_ip, 445, user,
            random.randint(5_000, 50_000), random.randint(5_000, 200_000),
            random.randint(5, 60),
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP FINs"
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

    Threat event fallback weights (used when event_mix is absent from config).
    Each threat maps 1:1 to a Cortex XSIAM Third-Party Firewall or VPN detection
    that ASA syslog can drive directly.
      port_scan                  15  — XSIAM "Port Scan"
      failed_connections_burst   10  — XSIAM "Failed Connections" (50-150 106023 denies)
      large_single_upload_session  8  — XSIAM "Large Upload (HTTPS)"
      unusual_ssh_session          5  — XSIAM "Uncommon SSH session"
      smb_share_enumeration        5  — XSIAM "Rare SMB session to a remote host"
      cumulative_upload_session    4  — XSIAM "Large Upload (HTTPS)" via accumulation
      ssh_proxy_attack             4  — XSIAM "Unusual SSH activity that resembles SSH proxy"
      smb_new_host_lateral         4  — XSIAM "Rare SMB session to a remote host"
      unusual_rdp_session          3  — XSIAM "Rare RDP session" / "New Administrative Behavior"
      tor_connection               3  — XSIAM "Recurring access to rare IP"
      vpn_bruteforce               3  — XSIAM "VPN login Brute-Force" / "Password Spray"
      vpn_tor_login                3  — XSIAM "Successful VPN connection from TOR"
      smb_rare_file_transfer       3  — XSIAM "Rare SMB session" / large-volume internal
      smtp_spray                   3  — XSIAM "Spam Bot Traffic"
      torrent_client               3  — XSIAM "A Torrent client was detected on a host"
      dc_smb_outbound              3  — XSIAM "Suspicious SMB connection from domain controller"
      smtp_large_exfil             2  — XSIAM "Large Upload (SMTP)"
      vpn_impossible_travel        2  — XSIAM "Impossible traveler - VPN"
      new_ftp_server               2  — XSIAM "New FTP Server"
      dns_c2_beacon                1  — XSIAM "Recurring access to rare IP"
      server_outbound_http         1  — XSIAM "Abnormal Communication to a Rare IP"
      workstation_lateral_rdp      1  — XSIAM "Rare RDP session" / "New Administrative Behavior"
    """
    global last_threat_event_time
    session_context = (context or {}).get("session_context")

    # --- Scenario events from the coordinated simulator ---
    forced_choice = None
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
        # Named threat from dashboard — set forced_choice and fall through to dispatch
        forced_choice = scenario_event.lower()

    # --- Event mix from config or fallback defaults ---
    module_config = config.get(CONFIG_KEY, {})
    event_mix     = module_config.get('event_mix', {})

    benign_events   = event_mix.get('benign', [
        {"event": "benign_session",    "weight": 38},
        {"event": "inbound_block",     "weight": 18},
        {"event": "anyconnect_vpn",    "weight": 7},
        {"event": "aaa_auth",          "weight": 4},
        {"event": "ntp_sync",          "weight": 5},
        {"event": "internal_traffic",  "weight": 4},
        {"event": "dhcp_log",          "weight": 3},
        {"event": "vpn_login_benign",  "weight": 4},
        {"event": "vpn_failure_benign","weight": 2},
        {"event": "rdp_internal_benign","weight": 3},
        {"event": "ftp_internal_benign","weight": 2},
    ])
    benign_functions = [e['event'] for e in benign_events]
    benign_weights   = [e['weight'] for e in benign_events]

    threat_events   = event_mix.get('threat', [])
    threat_functions = [e['event'] for e in threat_events]
    threat_weights   = [e['weight'] for e in threat_events]

    if not threat_functions:
        threat_functions = list(_DEFAULT_THREAT_NAMES)
        threat_weights   = list(_DEFAULT_THREAT_WEIGHTS)

    if forced_choice is not None:
        # Named threat from dashboard — bypass random selection entirely
        log_choice = forced_choice
    elif benign_only or threat_level == "Benign Traffic Only":
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
        "server_outbound_http", "inbound_block", "aaa_auth",
        "vpn_tor_login",    # resolves its own user/IP from TOR nodes config
        "vpn_login_benign", "vpn_failure_benign",  # resolve own user/IP
        "ntp_sync",         # picks IP from internal_networks directly
        "internal_traffic", # resolves user/IP from session_context itself
        "dhcp_log",         # picks IP from internal_networks directly
        "failed_connections_burst",  # one external attacker IP, targets are random
        "new_ftp_server",            # picks server IP from internal_servers
        "dc_smb_outbound",           # picks DC from dc_servers config
    }
    internal_host_ip = "192.168.1.100"
    if log_choice not in no_internal_ip_needed:
        ctx_src = (context or {}).get('src_ip')
        if ctx_src:
            # Scenario victim — keep the internal host consistent across stages so
            # XSIAM entity-stitching can tie SMB/RDP/etc. to the same victim.
            internal_host_ip = ctx_src
        elif session_context:
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

    elif log_choice == "vpn_login_benign":
        # Benign VPN login from user's stable home IP
        if session_context:
            ui = get_random_user(session_context, preferred_device_type='workstation')
            _vpn_user = ui['username'] if ui else None
        else:
            umap = _get_user_ip_map(config)
            _vpn_user = random.choice(list(umap.keys())) if umap else None
        if _vpn_user:
            _result = _generate_anyconnect_vpn_log(config, user=_vpn_user,
                        public_ip=stable_vpn_ip(_vpn_user), session_context=session_context)

    elif log_choice == "vpn_failure_benign":
        # Benign VPN auth failure — typo / expired cert
        if session_context:
            ui = get_random_user(session_context, preferred_device_type='workstation')
            _vpn_user = ui['username'] if ui else None
        else:
            umap = _get_user_ip_map(config)
            _vpn_user = random.choice(list(umap.keys())) if umap else None
        if _vpn_user:
            asa_conf = _get_asa_config(config)
            outside_ip = asa_conf.get('outside_ip', '203.0.113.1')
            home_ip = stable_vpn_ip(_vpn_user)
            fail_msg = (
                f"%ASA-6-109006: Authentication failed for user '{_ad_user(_vpn_user)}' "
                f"from {home_ip}/{random.randint(49152, 65535)} to {outside_ip}/443 "
                f"on interface outside"
            )
            _result = _generate_full_syslog_message(config, fail_msg)

    elif log_choice == "rdp_internal_benign":
        # Benign internal RDP — user to jump host / terminal server
        if config.get('internal_servers'):
            rdp_dest = random.choice(config['internal_servers'])
            user = _get_user_from_ip(config, internal_host_ip, session_context)
            _result = _generate_connection_session(
                config, "TCP", internal_host_ip, rdp_dest, 3389, user,
                random.randint(10_000, 200_000), random.randint(50_000, 2_000_000),
                random.randint(300, 7200),
                src_interface="inside", dest_interface="inside"
            )

    elif log_choice == "ftp_internal_benign":
        # Internal FTP download from file server
        if config.get('internal_servers'):
            ftp_dest = random.choice(config['internal_servers'])
            user = _get_user_from_ip(config, internal_host_ip, session_context)
            _result = _generate_connection_session(
                config, "TCP", internal_host_ip, ftp_dest, 21, user,
                random.randint(200, 5_000), random.randint(50_000, 50_000_000),
                random.randint(10, 300),
                src_interface="inside", dest_interface="inside"
            )

    elif log_choice == "large_single_upload_session":
        print("    - ASA Module simulating: Large Single Upload Session")
        _user = _get_user_from_ip(config, internal_host_ip, session_context)
        _dns = _dns_precursor(config, internal_host_ip, _user)
        _upload = _simulate_large_upload_session(config, internal_host_ip,
                                                  is_cumulative=False,
                                                  session_context=session_context)
        _result = _dns + (_upload if isinstance(_upload, list) else [_upload]) if _upload else _dns

    elif log_choice == "cumulative_upload_session":
        print("    - ASA Module simulating: Cumulative Large Upload Session")
        _user = _get_user_from_ip(config, internal_host_ip, session_context)
        _dns = _dns_precursor(config, internal_host_ip, _user)
        _upload = _simulate_large_upload_session(config, internal_host_ip,
                                                  is_cumulative=True,
                                                  session_context=session_context)
        _result = _dns + (_upload if isinstance(_upload, list) else [_upload]) if _upload else _dns

    elif log_choice == "unusual_rdp_session":
        print("    - ASA Module simulating: Unusual Internal RDP Session")
        _result = _simulate_rdp_session(config, internal_host_ip, session_context)

    elif log_choice == "unusual_ssh_session":
        print("    - ASA Module simulating: Rare External SSH Session")
        _user = _get_user_from_ip(config, internal_host_ip, session_context)
        _dns = _dns_precursor(config, internal_host_ip, _user)
        _ssh = _simulate_ssh_session(config, internal_host_ip, session_context)
        _result = _dns + (_ssh if isinstance(_ssh, list) else [_ssh]) if _ssh else _dns

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
        _user = _get_user_from_ip(config, internal_host_ip, session_context)
        _dns = _dns_precursor(config, internal_host_ip, _user)
        _tor = _simulate_tor_connection_session(config, internal_host_ip, session_context)
        _result = _dns + (_tor if isinstance(_tor, list) else [_tor]) if _tor else _dns

    elif log_choice == "vpn_bruteforce":
        _result = _simulate_vpn_bruteforce_or_scan(config, session_context,
                                                   victim_user=(context or {}).get('user'),
                                                   attacker_ip=(context or {}).get('src_ip'))

    elif log_choice == "vpn_impossible_travel":
        _result = _simulate_vpn_impossible_travel(config, session_context,
                                                  victim_user=(context or {}).get('user'),
                                                  vpn_inside_ip=(context or {}).get('vpn_inside_ip'))

    elif log_choice == "dns_c2_beacon":
        print("    - ASA Module simulating: DNS C2 Beacon")
        _result = _simulate_dns_c2_beacon(config, internal_host_ip, session_context)

    elif log_choice == "server_outbound_http":
        print("    - ASA Module simulating: Anomalous Server Outbound HTTP")
        _srv_ip = (context or {}).get('src_ip') or random.choice(config.get('internal_servers', ['10.0.10.50']))
        _srv_user = _get_user_from_ip(config, _srv_ip, session_context)
        _dns = _dns_precursor(config, _srv_ip, _srv_user)
        _http = _simulate_server_outbound_http(config, session_context, src_ip_override=_srv_ip)
        _result = _dns + (_http if isinstance(_http, list) else [_http]) if _http else _dns

    elif log_choice == "workstation_lateral_rdp":
        print("    - ASA Module simulating: Workstation-to-Workstation RDP")
        _result = _simulate_workstation_lateral_rdp(config, internal_host_ip, session_context)

    elif log_choice == "failed_connections_burst":
        _result = _simulate_failed_connections_burst(config, attacker_ip=(context or {}).get('src_ip'))

    elif log_choice == "torrent_client":
        _result = _simulate_torrent_client(config, internal_host_ip, session_context)

    elif log_choice == "new_ftp_server":
        _result = _simulate_new_ftp_server(config)

    elif log_choice == "dc_smb_outbound":
        _result = _simulate_dc_smb_outbound(config, session_context)

    elif log_choice == "vpn_tor_login":
        _result = _simulate_vpn_tor_login(config, session_context)

    elif log_choice == "smb_new_host_lateral":
        _result = _simulate_smb_new_host_lateral(config, internal_host_ip, session_context)

    elif log_choice == "smb_rare_file_transfer":
        _result = _simulate_smb_rare_file_transfer(config, internal_host_ip, session_context)

    elif log_choice == "smb_share_enumeration":
        _result = _simulate_smb_share_enumeration(config, internal_host_ip, session_context)

    elif log_choice == "smtp_spray":
        _result = _simulate_smtp_spray(config, internal_host_ip, session_context)

    elif log_choice == "smtp_large_exfil":
        _user = _get_user_from_ip(config, internal_host_ip, session_context)
        _dns = _dns_precursor(config, internal_host_ip, _user)
        _exfil = _simulate_smtp_large_exfil(config, internal_host_ip, session_context)
        _result = _dns + (_exfil if isinstance(_exfil, list) else [_exfil]) if _exfil else _dns

    return (_result, log_choice) if _result is not None else None
