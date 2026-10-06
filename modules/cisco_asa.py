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
    from modules import resolver
    from modules.session_utils import (get_random_user, find_user_by_ip, get_user_by_name,
        rand_ip_from_network, stable_vpn_ip, stable_mail_servers, weighted_destination,
        novel_country_vpn_ip, tor_vpn_ip, random_external_ip,
        rare_external_ip, rare_internal_host, impossible_travel_ips, stable_beacon_pairs)
except ImportError:
    import resolver
    from session_utils import (get_random_user, find_user_by_ip, get_user_by_name,
        rand_ip_from_network, stable_vpn_ip, stable_mail_servers, weighted_destination,
        novel_country_vpn_ip, tor_vpn_ip, random_external_ip)

last_threat_event_time = 0

# Events that must happen at least once per UTC DAY, whatever the weighted draw does.
# Each is CLOCK-KEYED by its detector, so a probability-keyed emission wastes days:
#   vpn_new_country_login  the novel-country pool rotates one country per UTC day; a
#                          day with no emission permanently wastes that country.
#   web_c2_beacon          "Recurring access to rare IP" wants the same (host, IP) pair
#   cryptomining           "repeatedly over many days"; weighted draws hit each pair
#                          roughly once a fortnight.
# The first threat slots of each day claim these in order, one per slot; the remaining
# ~9 of ~12 daily slots stay weighted. Resets on restart, which at worst repeats an
# event within a day — harmless, every one of these dedups at >= 1 day.
_DAILY_EVENTS = ("vpn_new_country_login", "web_c2_beacon", "cryptomining")
_last_daily_emit: dict[str, int] = {}


def _ad_user(user):
    """Format bare username as EXAMPLECORP\\username for syslog output.

    AD/LDAP-integrated firewalls show domain\\user in identity fields.
    This lets XSIAM Identity stitch firewall users (EXAMPLECORP\\user)
    with cloud/SaaS users (user@examplecorp.com) into one identity.
    """
    # Unattributed / system flows have no identity-firewall user — real ASA omits
    # the user clause entirely rather than printing a placeholder like "N/A".
    if not user or user == "N/A":
        return ""
    if "\\" not in user and "@" not in user:
        return f"EXAMPLECORP\\{user}"
    return user


def _vpn_user(user):
    """Bare username for AnyConnect messages (113039 / 113019 / 722051).

    Deliberately NOT _ad_user().  XSIAM's Identity Analytics resolves the identity
    on VPN events by reducing "EXAMPLECORP\\jdoe" to the DOMAIN — alerts recorded
    user_name "examplecorp" for every user, so every VPN login collapsed into one
    synthetic identity.  TOR access then became that identity's normal behaviour and
    the anomaly detectors went quiet: "A Successful VPN connection from TOR" fired
    repeatedly with bare usernames and stopped firing once the
    EXAMPLECORP\\ prefix was introduced.

    Verified in-tenant: all four
    layouts parse, and xdm.source.user.username keeps the full string either way
    (bare -> "p.probealpha", prefixed -> "EXAMPLECORP\\p.probebravo") — the collapse
    happens in analytics identity resolution, downstream of XDM.  Connection-event
    IDFW parentheticals still use _ad_user(); they land in dst_fwuser, which the
    modeling rule never reads.
    """
    if not user or user == "N/A":
        return ""
    return user.split("\\")[-1] if "\\" in user else user


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
# NOTE: XSIAM's Cisco ASA analytics only consume connection messages
# (302013/302014/302015/302016) and AnyConnect session messages
# (113019/113039/716001/716002/722022/722023/722033/722034/722037/722051/722053).
# ICMP (302020/302021), NAT (305011/305012), deny (106023) and cut-through auth
# (109001/109005/109006) are all OUTSIDE that supported set. Two distinct consequences,
# do not conflate them:
#   - 106023 / 109xxx / 305xxx are not parsed into XDM at all -> inert.
#   - 302020/302021 ARE parsed into XDM (confirmed in-tenant: xdm.source.ipv4 and
#     xdm.network.ip_protocol="ICMP" populate) even though they are unsupported. They
#     drive no analytic, but a malformed one DAMAGES the baselines the supported
#     messages feed. See the orientation comment in _generate_connection_session.
# Threats built on unparsed messages can never fire a XSIAM analytic:
#   - external_port_scan (106023)  -> REMOVED (internal port_scan uses 302013/14 and works;
#                                      external denies are unparseable by XSIAM).
#   - vpn_bruteforce      (109006) -> DELISTED from this catalog (no supported AnyConnect
#                                      auth-failure message exists). The function is kept
#                                      only for the cross-source XQL-hunt scenario, which
#                                      reads the RAW cisco_asa_raw text, not XDM.
#   - large_download (302013/14)  -> REMOVED (ASA logs one TOTAL byte value that maps to
#                                      xdm.source.sent_bytes; a "download" is indistinguishable
#                                      from an upload, so it fired "Large Upload", never a
#                                      distinct download detection).
_DEFAULT_THREAT_NAMES = [
    "port_scan", "port_sweep", "failed_connections_burst",
    "large_single_upload_session", "cumulative_upload_session",
    "unusual_ssh_session", "unusual_rdp_session", "ssh_proxy_attack",
    "tor_connection", "vpn_impossible_travel", "dns_c2_beacon",
    "server_outbound_http", "workstation_lateral_rdp",
    # new_admin_behavior / abnormal_rdp_rare_host were ENABLED 2026-09-16 at weight 2.
    # They were held back while destinations came from the 25-address internal_servers
    # pool, where unproven ambient runs would burn scarce novel combinations. They now
    # draw from _rare_internal_host() over internal_networks /16s, so novelty is not
    # scarce. Both remain unproven against ASA because of the app_proto gap — see their
    # docstrings, and re-evaluate after 2026-10-16.
    "new_admin_behavior", "abnormal_rdp_rare_host",
    "vpn_tor_login", "vpn_new_country_login",
    "smb_new_host_lateral", "smb_rare_file_transfer", "smb_share_enumeration",
    "smtp_spray", "smtp_large_exfil",
    "torrent_client", "new_ftp_server", "dc_smb_outbound",
    "reverse_ssh_tunnel", "ldap_recon",
    # Formerly all Non-Analytic; web_c2_beacon, cryptomining, external_fanout and
    # vpn_concurrent_sessions were rebuilt toward real detectors 2026-09-17. The ones
    # still in _NON_ANALYTIC_EVENTS run only in long-running sessions (not on demand).
    "web_c2_beacon", "cryptomining", "rare_port_connection",
    "vpn_data_exfil", "vpn_concurrent_sessions", "external_fanout",
]
# Positional 1:1 with _DEFAULT_THREAT_NAMES — keep the two lists in step when editing.
# Line groupings mirror the groupings in _DEFAULT_THREAT_NAMES above: 13 / 2 / 2 / 10 / 6.
# This list carried 32 entries against 30 names until 2026-09-16, which would raise
# "ValueError: The number of weights does not match the population" from
# random.choices() on the fallback path (taken only when the config threat list is
# empty, which is why it stayed dormant). The stray pair was removed, then port_sweep,
# new_admin_behavior and abnormal_rdp_rare_host were added — 33 names, 33 weights.
_DEFAULT_THREAT_WEIGHTS = [15, 8, 10, 8, 4, 5, 3, 4, 3, 2, 1, 1, 1,
                           2, 2,
                           4, 4,
                           3, 4, 4, 3, 5, 3, 2, 3, 2, 3,
                           2, 2, 2, 2, 2, 2]

# Events with no built-in XSIAM detection. They still run in long-running sessions (raw /
# hunt / custom-rule use) but are not offered for on-demand firing. The "[Non-Analytic] "
# display prefix they used to carry is retired; it is still accepted and stripped on input.
_NON_ANALYTIC_PREFIX = "[Non-Analytic] "
_NON_ANALYTIC_EVENTS = {
    # REBUILT and moved OUT of this set 2026-09-17 (see each generator's docstring):
    #   web_c2_beacon, cryptomining  -> "Recurring access to rare IP" (stable
    #                                   host/IP pairs, recurring daily)
    #   external_fanout              -> "Port Sweep" (one worm port, many subnets)
    #   vpn_concurrent_sessions      -> "Impossible traveler - VPN" (two continents)
    #   smtp_spray                   -> "Spam Bot Traffic" (port 25, rare servers)
    # Everything still listed below failed on DATA the ASA parser cannot carry, not on
    # generator logic — each entry records the in-tenant measurement that proves it.
    #
    # rare_port_connection: an outbound connection to an unusual port on a one-off IP.
    # No third-party firewall analytic keys on (IP, port) alone — the "less common
    # port" variations all belong to RARE-DOMAIN detectors, and ASA carries no domain.
    "rare_port_connection",
    # large_single_upload_session / cumulative_upload_session / smtp_large_exfil were
    # here until 2026-10-02: connection byte counts never reached xdm.source.sent_bytes
    # because the shipped rule read only generalCiscoLog.sent_bytes (AnyConnect
    # family). Cisco ASA pack 2.0.9 added `_json -> sentBytes` as a fallback, which
    # parse_cisco populates on every 302014/302016 teardown; after the tenant upgrade
    # 11/11 test teardowns modelled their bytes (2026-10-02). They are analytic again
    # (see _ANALYTIC_ALERTS). Open risk: ASA carries no application, and the firing
    # Large Upload (HTTPS) alerts elsewhere show app_id 'ip,tcp,ssl'.
    # smtp_spray targets "Spam Bot Traffic", which needs the APPLICATION identified —
    # the firing alerts carry app_id 'ip,tcp,smtp'. Measured over the same
    # window: xdm.network.application_protocol populated 0/6,770 on ASA SMTP events vs
    # 816/816 (Firepower) and 1,054/1,054 (FortiGate), both of which fire it. It is NOT
    # a volume or breadth problem — ASA shows 184 distinct mail servers from one host
    # against Firepower's 50. ASA syslog is layer 3/4 and carries no application field,
    # so parse_cisco never yields generalCiscoLog.application. The raw traffic is still
    # good: the "Cisco ASA — Outbound SMTP Spam Bot Activity" correlation rule fires on
    # it. HISTORY ONLY: smtp_spray was rebuilt 2026-09-17 (port 25 only, rare servers,
    # spread over hours) and moved out of this set as a further attempt; the app-ID gap
    # above is its standing risk.
    # failed_connections_burst targets "Failed Connections", which needs XSIAM to be able
    # to tell a FAILED connection from a successful one. It cannot, for ASA: parse_cisco
    # DISCARDS the teardown reason entirely. Verified 2026-09-16 against the parsed JSON
    # of a live 302014 —
    #   _raw : ...Teardown TCP connection 437138 for outside:79.130.20.104/65372 to
    #          inside:192.168.10.173/3306 duration 0:00:00 bytes 0 SYN Timeout
    #   _json: {"action":"Teardown",...,"duration":"0:00:00","transferred_bytes":"0"}
    # — no reason, no outcome, no failure field in either _json or generalCiscoLog, and
    # xdm.event.outcome is null on 100% of 155,198 rows measured over 24h.
    #
    # This means the 2026-07-24 rework (106023 denies -> permitted-then-"SYN Timeout"
    # teardowns) did not achieve its goal: it swapped an unparsed MESSAGE for a parsed
    # message whose FAILURE INDICATOR is unparsed. XSIAM sees 50-150 successful
    # connections from one external host. port_scan survives the same erasure only
    # because it keys on destination-port BREADTH, not on failure — which is exactly why
    # port_scan fires and this does not.
    #
    # The traffic stays: it is a genuine perimeter-sweep pattern, it drives the
    # cross-source XQL hunt, and it keys scenarios to one attacker IP. It is simply not
    # a native analytic on ASA.
    "failed_connections_burst",
    # vpn_data_exfil stays Non-Analytic. It IS now the only ASA event whose volume
    # reaches xdm.source.sent_bytes (see _simulate_vpn_data_exfil), but that alone is
    # not enough for a volume detector. Measured: ASA events carrying
    # sent_bytes = 7,752; carrying sent_bytes AND any destination port = 0; AND port
    # 443 = 0 (Check Point, which fires Large Upload, has 1,243). The 113019 messages
    # that carry bytes have dst_ip/dst_port/application all null — they are session
    # summaries, not flow records — so nothing can satisfy "uploaded X to external
    # host Y over port 443". Volume-based analytics are UNREACHABLE for ASA.
    "vpn_data_exfil",
    # ldap_recon: LDAP enumeration is an XDR-agent detection ("Suspicious LDAP search
    # query executed"), not a Third-Party Firewall analytic — Firepower and Check Point
    # already classify it this way.
    "ldap_recon",
}

# Threat -> the XSIAM analytic it targets, for every threat NOT in _NON_ANALYTIC_EVENTS.
# Names are as the tenant raises them where observed. Feeds get_threat_info(), which
# modules/threat_catalog.py reads to build the on-demand threat list.
_ANALYTIC_ALERTS = {
    "port_scan":               "Port Scan",
    "port_sweep":              "Port Sweep",
    "unusual_ssh_session":     "Uncommon SSH session was established",
    "unusual_rdp_session":     "Rare RDP session to a remote host",
    "ssh_proxy_attack":        "Unusual, long SSH activity with tunnel characteristics",
    "tor_connection":          "Recurring access to rare IP",
    "vpn_impossible_travel":   "Impossible traveler - VPN",
    "dns_c2_beacon":           "Recurring access to rare IP",
    "server_outbound_http":    "Recurring access to rare IP",
    "workstation_lateral_rdp": "Rare RDP session to a remote host",
    "new_admin_behavior":      "New Administrative Behavior",
    "abnormal_rdp_rare_host":  "Abnormal RDP session to a remote host from a rarely seen host",
    "vpn_tor_login":           "A Successful VPN connection from TOR",
    "vpn_new_country_login":   "First successful VPN access from a country in organization",
    "smb_new_host_lateral":    "Rare SMB session to a remote host",
    "smb_rare_file_transfer":  "Rare SMB session to a remote host",
    "smb_share_enumeration":   "Rare SMB session to a remote host",
    "smtp_spray":              "Spam Bot Traffic",
    "torrent_client":          "A Torrent client was detected on a host",
    "new_ftp_server":          "New FTP Server",
    "dc_smb_outbound":         "Suspicious SMB connection from domain controller",
    "reverse_ssh_tunnel":      "Uncommon SSH session was established",
    "web_c2_beacon":           "Recurring access to rare IP",
    "cryptomining":            "Recurring access to rare IP",
    "vpn_concurrent_sessions": "Impossible traveler - VPN",
    "external_fanout":         "Port Sweep",
    "large_single_upload_session": "Large Upload (HTTPS)",
    "cumulative_upload_session":   "Large Upload (HTTPS)",
    "smtp_large_exfil":            "Large Upload (SMTP)",
}


def _strip_non_analytic_prefix(name):
    """Dashboard passes display names that may carry the '[Non-Analytic] ' prefix; strip it."""
    if name and name.lower().startswith(_NON_ANALYTIC_PREFIX.lower()):
        return name[len(_NON_ANALYTIC_PREFIX):]
    return name


def get_threat_names():
    """Return every threat name in _DEFAULT_THREAT_NAMES (analytic or not)."""
    return list(_DEFAULT_THREAT_NAMES)


def get_threat_info():
    """Per-threat metadata, same shape as the other firewall modules:
    event, display_name, analytic, xsiam_alert, weight."""
    return [{"event": n, "display_name": n,
             "analytic": n not in _NON_ANALYTIC_EVENTS,
             "xsiam_alert": _ANALYTIC_ALERTS.get(n) if n not in _NON_ANALYTIC_EVENTS else None,
             "weight": w}
            for n, w in zip(_DEFAULT_THREAT_NAMES, _DEFAULT_THREAT_WEIGHTS)]


# Internal helpers

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


def _format_vpn_duration(seconds):
    """VPN session duration for %ASA-4-113019: `Hh:MMm:SSs`.

    113019 is the one message that carries unit suffixes -- real ASA output reads
    `Duration: 0h:21m:47s`, not the bare `0:21:47` used by connection teardowns
    (302014/302016), which _format_duration above still serves.  The
    CiscoASA_1_4.xif regex treats the h/m/s suffixes as optional, so this parses
    identically while matching Cisco's documented format.
    """
    h, rem = divmod(int(seconds), 3600)
    m, s   = divmod(rem, 60)
    return f"{h:01d}h:{m:02d}m:{s:02d}s"


def _random_external_ip():
    """Public (non-RFC-1918) IP from the shared ambient external-traffic pool.

    DO NOT "FIX" THIS BACK to `random.choice(first_octets)` + 3 random octets.
    That construction picked a random host inside one of 14
    different /8 blocks; a /8 spans dozens of countries, and across all modules it
    was a primary driver of the 210 DISTINCT COUNTRIES seen in
    xdm.source.location.country over 30 days.  That saturation permanently
    silenced the XSIAM analytic "First successful VPN access from a country in
    organization", which only fires on a country unseen org-wide for 30 days.
    session_utils.random_external_ip() draws from 35 individually XSIAM-PROBED
    /24s that are disjoint from config['vpn_novel_country_pool'].
    """
    return random_external_ip()


def _rare_external_ip():
    """A public IP from the shared rare-destination pool (session_utils).

    Use for any threat whose detection depends on the DESTINATION being rare; use
    _random_external_ip() for traffic that should look ordinary. The pool moved to
    session_utils.RARE_EXTERNAL_RANGES on 2026-09-17 so all five firewall modules
    share one disjoint rare set instead of each carrying a copy.
    """
    return rare_external_ip()


# Stable per-src NAT mapping — real PAT keeps a sticky external IP for each
# internal host for the lifetime of its conntrack entries.  Without this every
# session for one user shows a different public IP, which corrupts source-IP
# pivots in XSIAM.
_nat_ip_map: dict[str, str] = {}

# Stable per-src DNS C2 beacon target — beacon detections only fire when the
# same destination is contacted repeatedly.  Random destinations every call
# produce noise, not a beacon pattern.
try:
    from modules.session_utils import beacon_targets as _beacon_targets
except ImportError:
    from session_utils import beacon_targets as _beacon_targets
# Persists across restarts (state/beacon_targets.json): a source keeps its C2, as a
# real implant does, so recurring-access detectors can see the pair on many days.
_beacon_target_map = _beacon_targets("cisco_asa")


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
    # Cisco ASA with `logging timestamp rfc5424`: <PRI>TIMESTAMP HOSTNAME : MSG
    # ASA only switches the TIMESTAMP to ISO8601 — it does NOT emit an RFC 5424
    # version digit or structured-data. Genuine sample from Cisco's syslog guide:
    #   <166>2018-06-27T12:17:46Z asa : %ASA-6-110002: Failed to locate egress ...
    # A spurious "1 " version token here breaks the XSIAM parse_cisco() built-in,
    # leaving _json empty so NO fields extract and NO analytics ever fire.
    return f"<{pri}>{timestamp} {hostname} : {asa_message}"


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
    """Generate a UDP/53 DNS Built+Teardown pair preceding an outbound connection.

    The client asks ITS Infoblox grid member (resolver.dns_server_for), the same
    member the Infoblox module logs that client's query on -- not 8.8.8.8, which
    in an Infoblox estate would be a resolver bypass. The grid sits on the inside.
    """
    _, grid_ip = resolver.dns_server_for(config, src_ip)
    return _generate_connection_session(
        config, "UDP", src_ip, grid_ip, 53, user,
        random.randint(60, 150), random.randint(100, 400), 0,
        dest_interface="inside",
    )


def _grid_recursion(config):
    """The grid's own upstream lookup: member -> forwarder, the only DNS that
    leaves the estate in normal operation. No user: it is a server flow."""
    member, grid_ip = resolver.dns_server_for(config, None)
    return _generate_connection_session(
        config, "UDP", grid_ip, random.choice(resolver.dns_forwarders(config)), 53, None,
        random.randint(60, 150), random.randint(100, 500), 0,
    )


# Session / connection generators

def _generate_connection_session(config, protocol, src_ip, dest_ip, dest_port,
                                  user, bytes_sent, bytes_received, duration_sec,
                                  direction="outbound",
                                  src_interface="inside", dest_interface="outside",
                                  teardown_reason="TCP FINs", event_time=None):
    """
    Generates a Built + Teardown log pair for a TCP, UDP, or ICMP session.

    event_time: optional datetime for the Built message; the Teardown is placed
                duration_sec later. Defaults to None, which keeps the original
                behaviour of stamping both messages with the current time.
                ASA syslog timestamps are second-resolution, so a multi-session
                generator that does not pass this lands its whole burst inside one
                second and any detection that reasons over time sees a single point.

    Syslog format (TCP/UDP outbound) — clause order intentionally SWAPPED versus
    genuine Cisco so that Cortex parse_cisco() resolves the internal host as the
    source; see the comment block at the emit site before changing this:
      %ASA-6-302013: Built outbound TCP connection N
        for inside:src_ip/src_port (nat_ip/nat_port)
        to outside:dest_ip/dest_port (dest_ip/dest_port)
      %ASA-6-302014: Teardown TCP connection N
        for inside:src_ip/src_port to outside:dest_ip/dest_port
        duration H:MM:SS bytes N [reason] (user)

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
      xdm.source.user.username   ← NOT populated for connection events: parse_cisco
                                   yields no src_fwuser for any user placement (A/B,
                                   2026-10-02). ASA usernames in XDM come only from
                                   vpn_user on AnyConnect events. Built carries no
                                   user; see the comment at the emit site.
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

    # Built at event_time, Teardown duration_sec later. Both stay None when the caller
    # does not ask for placement, so _generate_full_syslog_message falls back to now.
    built_time    = event_time
    teardown_time = (event_time + timedelta(seconds=max(0, int(duration_sec)))
                     if event_time else None)

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

    # ICMP uses the faddr/gaddr/laddr format (302020/302021). Verified against the
    # official Cisco PDF "Syslog Messages 302003 to 342008":
    #
    #   %ASA-6-302020: Built inbound ICMP connection for faddr src_ip_address/src_port
    #   gaddr dest_ip_address/dest_port laddr dest_ip_address/dest_port [(user)]
    #   type type code code
    #
    # and the field list defines: faddr = foreign host, gaddr = global host,
    # laddr = local host, "type — Specifies the ICMP type", "code — Specifies the ICMP
    # code". So the value after each address is a PORT, and the ICMP type and code are
    # SEPARATE TRAILING KEYWORD FIELDS.
    #
    # This module previously emitted `faddr <addr>/<icmp_seq> gaddr <addr>/<icmp_type>
    # laddr <addr>/<icmp_code>` with no trailing type/code, on the basis of a comment
    # claiming that was the official template. It is not — the doc has no icmp_seq_num
    # field at all. ICMP carries no ports, so real ASA logs /0.
    #
    # DELIBERATE DEVIATION FROM GENUINE CISCO — DO NOT "FIX" BACK.  Same root cause as
    # the `for`/`to` swap on TCP/UDP below.  Cortex's parse_cisco() assigns
    # faddr->src_ip and laddr->dst_ip unconditionally, while genuine Cisco puts the
    # FOREIGN (external) peer in faddr and the LOCAL host in laddr.  Emitting the
    # genuine order therefore recorded the external peer as the actor: measured
    # in-tenant 2026-09-16, 6,322 of 6,518 ICMP events (97%) landed with an external
    # source and an internal target, feeding reversed-direction records into the very
    # baselines the third-party firewall detectors profile.  Verified against the
    # parsed JSON — `faddr 91.189.89.253 ... laddr 192.168.140.2` produced
    # generalCiscoLog.src_ip = 91.189.89.253.
    #
    # The internal host therefore leads faddr, matching the TCP/UDP orientation.
    # gaddr keeps its real meaning (the NAT/global address of the internal host).
    #
    # NOTE: 302020/302021 are NOT in the XSIAM-supported Cisco ASA message list
    # (only 302013/302014/302015/302016 are), so these never drive an analytic on
    # their own — but they ARE parsed into XDM, so a reversed orientation actively
    # damages the baseline.  They are kept as realistic ambient traffic.
    if protocol == "ICMP":
        icmp_type = random.choice([0, 8])       # 8 = echo request, 0 = echo reply
        icmp_code = 0
        faddr = src_ip
        gaddr = nat_ip if dest_interface == "outside" else src_ip
        laddr = dest_ip
        icmp_tail = f"{user_paren} type {icmp_type} code {icmp_code}"
        session_logs.append(_generate_full_syslog_message(config,
            f"%ASA-6-302020: Built {effective_direction} ICMP connection for "
            f"faddr {faddr}/0 gaddr {gaddr}/0 laddr {laddr}/0"
            f"{icmp_tail}", built_time
        ))
        session_logs.append(_generate_full_syslog_message(config,
            f"%ASA-6-302021: Teardown ICMP connection for "
            f"faddr {faddr}/0 gaddr {gaddr}/0 laddr {laddr}/0"
            f"{icmp_tail}", teardown_time
        ))
        return session_logs

    # TCP / UDP event IDs
    if protocol == "TCP":
        built_id, teardown_id = "302013", "302014"
    else:
        built_id, teardown_id = "302015", "302016"
        teardown_reason = ""  # UDP teardowns have no reason field

    # DELIBERATE DEVIATION FROM GENUINE CISCO — DO NOT "FIX" BACK.  Real ASA logs an
    # outbound connection with the DESTINATION leading the `for` clause and the
    # initiator in the `to` clause:
    #   Built outbound TCP connection 506986 for outside:17.151.140.30/80
    #     (17.151.140.30/80) to inside:192.168.1.44/61094 (50.197.188.217/61094)
    # (Cisco Secure Firewall ASA Series Syslog Messages, 302003-342008.)  Cortex's
    # built-in parse_cisco() assigns `for`->src_ip and `to`->dst_ip unconditionally,
    # so emitting the genuine order made XSIAM record the EXTERNAL PEER as the actor
    # on ~91% of our events.  Analytics baseline the source entity, so nothing could
    # ever accumulate and cisco_asa_raw fired ZERO analytics while Check Point /
    # FortiGate / Firepower (all source-correct) fired normally.  Verified in-tenant
    # swapping the clauses makes generalCiscoLog.src_ip the internal host.
    # We choose parser-correctness over byte-fidelity here because driving XSIAM
    # analytics is this module's purpose.
    #
    # User placement, re-tested in-tenant 2026-10-02 against Cisco ASA pack 2.0.9
    # (_local_validation/asa_user_placement_ab.py). parse_cisco never yields
    # src_fwuser for ANY placement -- trailing, Cisco's per-side "(user)" after the
    # source tuple, or per-side with a space -- so a connection event cannot carry a
    # SOURCE user or identity into XDM; only AnyConnect's vpn_user does.
    #
    # The trailing form on a BUILT message is worse than nothing: parse_cisco files
    # it as dst_fwuser (parentheses included), and since pack 2.0.8 the rule maps
    # dst_fwuser to xdm.target.user/identity -- the employee who opened the connection
    # became its TARGET user on ~99% of 302013/302015 events after the upgrade. So
    # Built carries no user. The Teardown keeps the trailing user: it parses to
    # nothing, so it stays harmless in XDM and searchable in _raw_log.
    built_log = (
        f"%ASA-6-{built_id}: Built {effective_direction} {protocol} connection {conn_id} "
        f"for {src_interface}:{src_ip}/{src_port} ({nat_ip}/{nat_port}) "
        f"to {dest_interface}:{dest_ip}/{dest_port} ({dest_ip}/{dest_port})"
    )
    session_logs.append(_generate_full_syslog_message(config, built_log, built_time))

    duration_str = _format_duration(duration_sec)
    reason_str   = f" {teardown_reason}" if teardown_reason else ""
    total_bytes  = bytes_sent + bytes_received

    teardown_log = (
        f"%ASA-6-{teardown_id}: Teardown {protocol} connection {conn_id} "
        f"for {src_interface}:{src_ip}/{src_port} "
        f"to {dest_interface}:{dest_ip}/{dest_port} "
        f"duration {duration_str} bytes {total_bytes}{reason_str}"
        f"{user_paren}"
    )
    session_logs.append(_generate_full_syslog_message(config, teardown_log, teardown_time))
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
            f"%ASA-6-113039: Group <{group_name}> User <{_vpn_user(user)}> IP <{public_ip}> "
            f"AnyConnect parent session started."
        )
    else:
        # Session End
        duration = random.randint(60, 3600)
        message = (
            f"%ASA-4-113019: Group = {group_name}, Username = {_vpn_user(user)}, IP = {public_ip}, "
            f"Session disconnected. Session Type: {session_type}, "
            f"Duration: {_format_vpn_duration(duration)}, "
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


# Benign event generators

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
    # The address the destination's NAME resolves to -- the same answer Infoblox
    # gives for it -- not an unrelated host from the entry's CIDR.
    _domain, dest_ip = resolver.benign_target(config, destination)

    if service_type == "Web Browsing":
        protocol   = "TCP"
        web_ports  = [p for p in destination.get('ports', [443]) if p in [80, 443]]
        dest_port  = random.choice(web_ports) if web_ports else 443
        bytes_sent = random.randint(500, 15000)
        bytes_recv = random.randint(50000, 5000000)
        duration   = random.randint(5, 120)
    elif service_type == "DNS Query":
        # Clients resolve through the Infoblox grid; only the grid's recursion
        # crosses to the outside. A workstation talking to a public resolver
        # directly is left to the threat generators, where it belongs.
        if random.random() < 0.4:
            return _grid_recursion(config)
        _, dest_ip = resolver.dns_server_for(config, src_ip)
        return _generate_connection_session(
            config, "UDP", src_ip, dest_ip, 53, user,
            random.randint(50, 150), random.randint(150, 500), random.randint(0, 1),
            dest_interface="inside")
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
        f'by access-group "{acl_name}" [0x{hash1:08x}, 0x0]'
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


# Threat event generators

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
        dest_ip = _rare_external_ip()
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
    try:
        from modules.session_utils import stable_subset
    except ImportError:
        from session_utils import stable_subset
    src_ip = src_ip_override or random.choice(
        stable_subset(config.get('internal_servers'), "cisco_asa:server_outbound_http"))
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
    """RDP from one workstation to MULTIPLE internal hosts — lateral movement.

    UEBA lateral-movement detection keys on breadth: a single RDP is background noise,
    but one workstation opening RDP (3389) to many internal hosts in a short window is
    the anomaly. Generates 5-8 RDP sessions to DISTINCT internal destinations.
    Returns list of syslog strings (multi-event).
    """
    user     = _get_user_from_ip(config, internal_host_ip, session_context)
    n_hosts  = random.randint(5, 8)
    dest_ips = set()

    if session_context:
        for _ in range(30):
            peer = get_random_user(session_context, preferred_device_type='workstation')
            if peer and peer.get('ip') and peer['ip'] != internal_host_ip:
                dest_ips.add(peer['ip'])
            if len(dest_ips) >= n_hosts:
                break

    internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
    while len(dest_ips) < n_hosts:
        try:
            host = rand_ip_from_network(ip_network(random.choice(internal_nets), strict=False))
            if host != internal_host_ip:
                dest_ips.add(host)
        except (ValueError, AddressValueError, IndexError):
            dest_ips.add(f"192.168.1.{random.randint(101, 200)}")

    logs = []
    for dst_ip in list(dest_ips)[:n_hosts]:
        logs.extend(_generate_connection_session(
            config, "TCP", internal_host_ip, dst_ip, 3389, user,
            random.randint(5_000, 80_000), random.randint(5_000, 80_000),
            random.randint(30, 600),
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP FINs"
        ))
    return logs


# Remote-administration service ports. "New Administrative Behavior" counts NOVEL
# (destination, admin-port) pairs per source host over a 12-hour window, so breadth
# across both axes is the signal — volume to one destination is not.
_ADMIN_PORTS = [22, 23, 69, 161, 512, 513, 514, 623, 992]


def _rare_internal_host(config, exclude=()):
    """Internal address avoiding the hot server pool — see
    session_utils.rare_internal_host() for why rarity detectors need this."""
    return rare_internal_host(config, exclude=exclude)


# Small, STABLE pool of seldom-seen internal hosts, seeded once per process.
#
# "Rarely seen" is not the same as "never seen". A freshly minted address every run gives
# the detector a host with no profile at all, and a host drawn from the normal user pool
# carries ~500 events/day and is not rare by any measure. These addresses recur, so they
# accumulate a thin but real history — a handful of appearances against a tenant where an
# ordinary workstation logs hundreds of sessions a day.
_RARE_SOURCE_POOL: list[str] = []
_RARE_SOURCE_POOL_SIZE = 12


def _rare_source_host(config):
    """An internal address that appears occasionally and never in bulk.

    Used as the SOURCE for detectors whose premise is that the actor itself is seldom
    observed (abnormal_rdp_rare_host). Do not use this for destinations — that is what
    _rare_internal_host() is for.
    """
    if not _RARE_SOURCE_POOL:
        seen = set()
        for _ in range(_RARE_SOURCE_POOL_SIZE * 8):
            if len(_RARE_SOURCE_POOL) >= _RARE_SOURCE_POOL_SIZE:
                break
            candidate = _rare_internal_host(config, exclude=tuple(seen))
            if candidate not in seen:
                seen.add(candidate)
                _RARE_SOURCE_POOL.append(candidate)
    return random.choice(_RARE_SOURCE_POOL) if _RARE_SOURCE_POOL else _rare_internal_host(config)


def _simulate_new_admin_behavior(config, internal_host_ip, session_context=None):
    """One internal host performing many FIRST-TIME administrative actions.

    ENABLED IN AMBIENT TRAFFIC 2026-09-16 (weight 2) — still NOT PROVEN to fire from ASA.

    Standing risk: ASA supplies no xdm.network.application_protocol at all, while this
    detector's reference alerts carry an application in app_id. That gap is inside
    Cortex's built-in parse_cisco() and no change here can close it. The alert DID fire in
    this tenant in the 30 days to 2026-09-16, from Cisco/Firepower + Fortinet/Fortigate —
    both of which populate app_proto — so the gap remains the likeliest blocker. Cortex's
    own Required Data for this alert lists only "PANW Firewall traffic Logs OR XDR Agent
    OR Third-Party Firewalls", with no application requirement, which is why it is worth
    the attempt.

    The earlier objection to running it ambiently — that a first-seen detector burns
    scarce novel combinations — no longer applies: destinations come from
    _rare_internal_host(), which draws from internal_networks /16s (tens of thousands of
    addresses), not from the 25-address internal_servers pool.

    Re-evaluate after 2026-10-16 (14d activation + 30d training from the baseline
    changes). If it has not fired by then, the app_proto gap is confirmed fatal and this
    should be reclassified into _NON_ANALYTIC_EVENTS.

    Opens 8-11 DISTINCT (internal destination, admin port) pairs from a single source.
    Each pair is novel for that source, which is what the detector counts; repeat
    connections to one destination score as a single action and never fire.

    The source must be an internal host that already carries ambient traffic — the
    detector compares against that host's own administrative baseline, so a freshly
    minted address has nothing to deviate from.

    Sessions are placed across the past 30-75 minutes via event_time. ASA syslog
    timestamps are second-resolution, so without that the whole set lands in one second
    and reads as a single automated action rather than a behavioural pattern.

    Returns list of syslog strings (multi-event).
    """
    user      = _get_user_from_ip(config, internal_host_ip, session_context)
    n_actions = random.randint(8, 11)
    ports     = random.sample(_ADMIN_PORTS, min(n_actions, len(_ADMIN_PORTS)))

    pairs, used_dests = [], {internal_host_ip}
    for i in range(n_actions):
        # Reuse a destination across two admin ports sometimes — the reference pattern is
        # several actions spread over fewer destinations than actions, not one host each.
        if pairs and random.random() < 0.3:
            dest_ip = random.choice(pairs)[0]
        else:
            dest_ip = _rare_internal_host(config, exclude=used_dests)
            used_dests.add(dest_ip)
        pairs.append((dest_ip, ports[i % len(ports)]))

    now       = datetime.now(timezone.utc)
    window_s  = random.randint(30, 75) * 60
    offsets   = sorted(random.randint(0, window_s) for _ in pairs)

    logs = []
    for (dest_ip, dport), back_s in zip(pairs, offsets):
        duration = random.randint(2, 90)
        logs.extend(_generate_connection_session(
            config, "TCP", internal_host_ip, dest_ip, dport, user,
            random.randint(1_000, 40_000), random.randint(1_000, 60_000), duration,
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP FINs",
            event_time=now - timedelta(seconds=back_s),
        ))
    return logs


def _simulate_abnormal_rdp_rare_host(config, internal_host_ip, session_context=None):
    """A single RDP session from a seldom-seen internal host to a seldom-targeted one.

    ENABLED IN AMBIENT TRAFFIC 2026-09-16 (weight 2) — still NOT PROVEN to fire from ASA.

    Standing risk, and it is the larger of the two enabled on that date: the detector's
    alerts carry app_id 'ip,tcp,rdp' (Firepower fires it with 'ip,rdp'), but ASA supplies
    no xdm.network.application_protocol at all, so it cannot present an application by any
    route available to this module. The same shape DOES fire from Firepower, Check Point
    and FortiGate. Re-evaluate after 2026-10-16; if silent, move to _NON_ANALYTIC_EVENTS.

    The detector needs three rarity conditions at once: the source is rarely observed,
    the RDP pattern is abnormal for the segment, and the destination has rarely RECEIVED
    RDP from other hosts.

    Source: _rare_source_host(), a small STABLE pool of seldom-seen addresses. The
    dispatcher's default internal_host_ip is an ordinary user workstation carrying ~500
    events/day, which fails the "rarely observed" condition outright — so this generator
    overrides it rather than accepting the caller's value.

    Destination: _rare_internal_host(), NOT config['internal_servers'] — funnelling RDP
    into that small pool makes every destination a frequent receiver.

    Deliberately ONE session, not a burst: repeated attempts to the same host describe
    brute force or a lateral sweep, which are different detections.

    Returns list of syslog strings (Built+Teardown pair).
    """
    src_ip  = _rare_source_host(config)
    dest_ip = _rare_internal_host(config, exclude={src_ip, internal_host_ip})
    user    = _get_user_from_ip(config, src_ip, session_context)
    return _generate_connection_session(
        config, "TCP", src_ip, dest_ip, 3389, user,
        random.randint(20_000, 400_000), random.randint(50_000, 3_000_000),
        random.randint(120, 2_400),
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
    """Outbound SSH to an unusual external host — rare/anomalous behaviour.

    Targets XSIAM "Uncommon SSH session was established to a rare IP address", which
    scores the DESTINATION's rarity — hence _rare_external_ip(), not the ambient pool.
    Benign SSH goes to GitHub (140.82.112.0/20 via benign_egress_destinations), so the
    contrast is a rare netblock against a single well-known one.
    """
    dest_ip = _rare_external_ip()
    user    = _get_user_from_ip(config, internal_host_ip, session_context)
    return _generate_connection_session(
        config, "TCP", internal_host_ip, dest_ip, 22, user,
        random.randint(1000, 50000), random.randint(1000, 50000), random.randint(30, 600)
    )


def _simulate_port_scan(config, scanner_ip, session_context=None):
    """
    Internal port scan — 100–200 rapid TCP connections to the same victim.
    All sessions use teardown_reason "TCP Reset - I" (no service listening).

    NOTE THE SPACES. Cisco's TCP Termination Reasons table (Syslog Messages 302003 to
    342008, message 302014) documents the value as "TCP Reset - I" — "Reset was from
    the inside" — alongside "TCP Reset - O" and "TCP Reset - APPLIANCE". This module
    previously emitted "TCP Reset-I" (no spaces), which is not a real ASA value.
    Verified against the official PDF: "TCP Reset-I" does not appear anywhere in it.
    Triggers: "Port Scan" XSIAM analytics detection.
    """
    if not config.get('internal_servers'):
        return None
    victim_ip = random.choice(config.get('internal_servers'))
    if scanner_ip == victim_ip:
        return None

    user      = _get_user_from_ip(config, scanner_ip, session_context)
    scan_logs = []
    # Scan WELL-KNOWN SERVICE PORTS only (1-1023), matching checkpoint_firewall and
    # fortinet_fortigate — both of which fire "Suspicious port scan" reliably, and both
    # of which use random.sample(range(1, 1024), ...).
    #
    # This previously sampled range(1, 65535). Uniform sampling over the full range puts
    # ~75% of probes in the EPHEMERAL range (49152-65535), which reads as ordinary return
    # traffic rather than service enumeration; measured in-tenant, whole ASA
    # scans landed at 49247..65503 / 49442..65490 with not a single service port. The one
    # ASA "Suspicious port scan" that ever fired scanned ports 2, 4, 25, 33,
    # 60, 63, 77, 80, 86, 95, 102, 525... — all low. Check Point/FortiGate scans that fire
    # today sit at 2..8443 / 1..1013.
    for port in random.sample(range(1, 1024), random.randint(100, 200)):
        scan_logs.extend(_generate_connection_session(
            config, "TCP", scanner_ip, victim_ip, port, user, 0, 0, 0,
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP Reset - I"
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


# Privileged ports that "serve a well-defined function" — the Port Sweep detector's own
# wording. A sweep is defined by ONE such port across MANY hosts, so the port must be a
# recognisable service, not an arbitrary number.
# Privileged ports only. The Cortex "Port Sweep" analytic counts connections to many
# hosts "using privileged ports that serve a well-defined function"; privileged means
# below 1024. This pool used to include 1433 (MSSQL) and 3389 (RDP), so a quarter of
# sweeps -- in all four firewall modules, which shared the list -- could never satisfy
# the detector. RDP and MSSQL sweeps are real attacker behaviour, but they belong to
# the RDP/SQL analytics, not to Port Sweep.
_SWEEP_PORTS = [21, 22, 23, 88, 135, 139, 389, 445, 636]


def _simulate_port_sweep(config, scanner_ip, session_context=None):
    """One internal host probing the SAME privileged port across MANY internal hosts —
    XSIAM "Port Sweep".

    The mirror image of _simulate_port_scan: a scan is many ports on one host, a sweep is
    one port on many hosts. Cortex documents Port Sweep as "connected, or attempted to
    connect, to multiple hosts using privileged ports that serve a well-defined function"
    (Discovery / T1046, Activation 14d, Training 30d, Test 1h, Dedup 1d), on the same
    "Palo Alto Networks Firewall traffic Logs OR XDR Agent OR Third-Party Firewalls"
    requirement that Port Scan carries.

    This needs nothing ASA cannot supply — source, destination and destination port only.
    No bytes (never reach XDM), no application (never reaches XDM), no failure indicator
    (parse_cisco discards the teardown reason). That is precisely why Port Scan is the one
    third-party firewall detector ASA is confirmed to fire, and why this is the strongest
    remaining candidate.

    Shape:
      * 30-80 DISTINCT internal destinations, ONE port for the whole sweep.
      * Destinations drawn across SEVERAL internal_networks — Cortex lists "Port Sweep to
        multiple subnets" as a higher-severity variation, and a sweep confined to one /24
        reads as ordinary segment chatter.
      * Mostly unanswered (`TCP Reset - I`, 0 bytes); 1-3 hosts answer, which is what a
        real sweep looks like and gives the operator something to pivot on.
      * Spread across the past 2-10 minutes via event_time. ASA syslog is second-
        resolution, so an unplaced burst lands inside one second and reads as a single
        automated action rather than a sweep over a window (same lesson as
        _simulate_new_admin_behavior).

    Deliberately distinct from smb_share_enumeration, which is SMB-specific (445 only,
    15-40 hosts) and targets "Rare SMB session to a remote host".

    Returns list of syslog strings (multi-event).
    """
    print("    - ASA Module simulating: Port Sweep (one privileged port across many hosts)")
    sweep_port = random.choice(_SWEEP_PORTS)
    n_targets  = random.randint(30, 80)
    user       = _get_user_from_ip(config, scanner_ip, session_context)

    try:
        from modules.session_utils import sweep_targets
    except ImportError:
        from session_utils import sweep_targets
    # Known live hosts over several /24s (session_utils.sweep_targets): random
    # addresses in the /16s are hosts the analytics engine has never seen.
    targets = set(sweep_targets(config, exclude={scanner_ip}, n_range=(n_targets, n_targets)))
    if not targets:
        return None

    targets   = list(targets)
    responders = set(random.sample(targets, max(1, int(len(targets) * random.uniform(0.10, 0.30)))))

    now      = datetime.now(timezone.utc)
    window_s = random.randint(120, 600)
    offsets  = sorted(random.randint(0, window_s) for _ in targets)

    logs = []
    for dst_ip, back_s in zip(targets, offsets):
        answered = dst_ip in responders
        logs.extend(_generate_connection_session(
            config, "TCP", scanner_ip, dst_ip, sweep_port, user,
            random.randint(400, 6_000) if answered else 0,
            random.randint(400, 20_000) if answered else 0,
            random.randint(2, 45) if answered else 0,
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP FINs" if answered else "TCP Reset - I",
            event_time=now - timedelta(seconds=back_s),
        ))
    return logs


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
    Credential stuffing against the VPN gateway — single external IP trying many
    usernames, each with 2–5 rapid 109006 auth failures, then one 109005 success.

    RAW-ONLY: this is built on 109001/109005/109006 cut-through-auth
    messages, which XSIAM's Cisco ASA analytics do NOT parse into XDM — so it can
    never fire a XSIAM analytic and is intentionally DELISTED from the threat catalog
    (_DEFAULT_THREAT_NAMES). It is retained only for the cross-source XQL-hunt scenario
    (ASA vpn_bruteforce username ∩ Okta impossible_travel), which correlates the RAW
    cisco_asa_raw text, not XDM. There is no supported AnyConnect auth-failure message,
    so failed VPN logins cannot be represented in a XSIAM-parseable way.
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
    One user with two SUCCESSFUL AnyConnect logins from two geographically distant
    source IPs within an impossible time window.

    IMPORTANT: XSIAM's Cisco ASA analytics only parse AnyConnect SESSION
    messages (113039/722051/…), NOT the 109001/109005/109006 cut-through-auth messages.
    The earlier fail→success "door-knock" design (109006 failures then 109005 success)
    is therefore invisible to XSIAM for ASA — those lines never model into XDM. The
    genuine, parseable impossible-travel signal is two SUCCESSFUL AnyConnect sessions
    for the same user from impossibly-distant IPs. Each login emits the supported
    session sequence 113039 (parent session started) + 722051 (address assigned), with
    a 5–10 minute gap between the two locations.

    Returns list of syslog strings (multi-event).
    """
    print("    - ASA Module simulating: VPN Impossible Travel (door-knock + success x2 geos)")

    user = victim_user
    if not user and session_context:
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        user      = user_info['username'] if user_info else None

    if not user:
        user_ip_map = _get_user_ip_map(config)
        if not user_ip_map:
            return None
        user = random.choice(list(user_ip_map.keys()))

    benign_loc     = config.get('impossible_travel_scenario', {}).get('benign_location', {})
    suspicious_loc = config.get('impossible_travel_scenario', {}).get('suspicious_location', {})

    # Randomize the host octet so each run gets distinct source IPs within the same
    # /24 (same geo/country) — lets the alert group by user into the victim's incident
    # instead of binding every run to one shared source-IP incident.
    def _rand_host(ip, default):
        base = ip or default
        parts = base.split(".")
        if len(parts) != 4:
            return base
        return ".".join(parts[:3] + [str(random.randint(2, 254))])

    benign_ip = _rand_host(benign_loc.get("ip"), "68.185.12.14")
    susp_ip   = _rand_host(suspicious_loc.get("ip"), "175.45.176.10")

    # Legit login 5–10 min in the past; attacker login now. The gap between the two
    # SUCCESSFUL logins is what makes the travel impossible.
    gap_minutes  = random.randint(5, 10)
    t_benign     = datetime.now(timezone.utc) - timedelta(minutes=gap_minutes)
    t_suspicious = datetime.now(timezone.utc)

    asa_conf   = _get_asa_config(config)
    group_name = asa_conf.get('vpn_group_name', 'TunnelGroup_AnyConnect')
    outside_ip = asa_conf.get('outside_ip', '203.0.113.1')
    vpn_pool   = asa_conf.get('vpn_pool', '10.250.0.0/16')

    def _inside_ip():
        try:
            return rand_ip_from_network(ip_network(vpn_pool, strict=False))
        except Exception:
            return f"10.250.{random.randint(1,254)}.{random.randint(1,254)}"

    logs = []
    for loc_ip, t_base in [(benign_ip, t_benign), (susp_ip, t_suspicious)]:
        # Bind the compromised (suspicious) session to the caller's inside IP so
        # scenario lateral movement stitches to this identity.
        inside_ip = vpn_inside_ip if (loc_ip == susp_ip and vpn_inside_ip) else _inside_ip()
        # Genuine successful-login AnyConnect sequence (supported messages only).
        logs.append(_generate_full_syslog_message(config,
            f"%ASA-6-113039: Group <{group_name}> User <{_vpn_user(user)}> IP <{loc_ip}> "
            f"AnyConnect parent session started.", t_base))
        logs.append(_generate_full_syslog_message(config,
            f"%ASA-6-722051: Group <{group_name}> User <{_vpn_user(user)}> IP <{loc_ip}> "
            f"Address <{inside_ip}> assigned to session", t_base + timedelta(seconds=1)))
    return logs


def _simulate_vpn_new_country_login(config, session_context=None):
    """One SUCCESSFUL AnyConnect login from a country the org has never seen.

    Drives the XSIAM analytic "First successful VPN access from a country in
    organization", whose description reads:
        "The user <u> connected to AnyConnect from <country>. The result of the
         connection attempt was a SUCCESS. This behavior has not been observed
         in the organization in the last 30 days."

    WHY THIS EXISTS / DO NOT "FIX" IT AWAY:
    The analytic is FIRST-SEEN and ORG-SCOPED. It had been silent because the
    simulator had already emitted VPN logins
    from 210 distinct countries in 30 days — every country on Earth was "seen",
    so nothing could ever be novel.  Scarcity alone is not enough to restart it:
    something has to deliberately visit a country the ambient baseline never
    touches.  That is this function.

    session_utils.novel_country_vpn_ip() picks from config['vpn_novel_country_pool']
    (70 XSIAM-PROBED single-country /24s, disjoint from benign_ingress_sources,
    external_traffic_sources and the Tor prefix allowlist) and rotates on the day
    number, so a given country recurs every 70 days — comfortably outside the
    detector's 30-day novelty window.  The rotation is day-keyed rather than
    random so that ASA, Check Point, FortiGate, Firepower and Zscaler all choose
    the SAME country on the same day: the detector is org-scoped, so five sources
    picking five different countries per day would burn the pool in 14 days.

    Emits the supported successful-session sequence only (113039 parent session
    started + 722051 address assigned) — XSIAM's Cisco ASA analytics do not parse
    the 109001/109005 cut-through-auth messages, see _simulate_vpn_impossible_travel.
    """
    novel_ip, cc, country, isp = novel_country_vpn_ip(config)
    if not novel_ip:
        return None
    print(f"    - ASA Module simulating: First VPN access from new country "
          f"({country} / {isp} / {novel_ip})")

    user = None
    if session_context:
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        user = user_info['username'] if user_info else None
    if not user:
        user_ip_map = _get_user_ip_map(config)
        if not user_ip_map:
            return None
        user = random.choice(list(user_ip_map.keys()))

    asa_conf   = _get_asa_config(config)
    group_name = asa_conf.get('vpn_group_name', 'TunnelGroup_AnyConnect')
    vpn_pool   = asa_conf.get('vpn_pool', '10.250.0.0/16')
    try:
        inside_ip = rand_ip_from_network(ip_network(vpn_pool, strict=False))
    except Exception:
        inside_ip = f"10.250.{random.randint(1,254)}.{random.randint(1,254)}"

    t0 = datetime.now(timezone.utc)
    return [
        _generate_full_syslog_message(config,
            f"%ASA-6-113039: Group <{group_name}> User <{_vpn_user(user)}> IP <{novel_ip}> "
            f"AnyConnect parent session started.", t0),
        _generate_full_syslog_message(config,
            f"%ASA-6-722051: Group <{group_name}> User <{_vpn_user(user)}> IP <{novel_ip}> "
            f"Address <{inside_ip}> assigned to session", t0 + timedelta(seconds=1)),
    ]


def _simulate_vpn_tor_login(config, session_context=None):
    """Full conversation: TLS handshake + VPN auth + post-auth internal activity from Tor.

    Triggers XSIAM: Suspicious VPN Login / TOR-based Access analytics detection.
    """
    print("    - ASA Module simulating: VPN Login from TOR Exit Node (successful)")
    # DO NOT "FIX" THIS BACK to random.choice(config['tor_exit_nodes']).
    # Probing the full live exit-node list through the tenant
    # resolved them to 55 DISTINCT COUNTRIES with a rotating long tail
    # (Seychelles, Belize, Nicaragua, Panama, Peru ...).  As the SOURCE IP of a
    # successful VPN login that tail kept marking reserve countries "already
    # seen", permanently silencing the analytic "First successful VPN access
    # from a country in organization".  tor_vpn_ip() restricts the pool to the
    # 182 probed /16 prefixes that resolve ONLY to the genuine Tor-heavy
    # countries (US/DE/NL/FR/RO) — still 930 live nodes, so the HIGH-severity
    # "A Successful VPN connection from TOR" analytic is unaffected.
    tor_ip    = tor_vpn_ip(config, default=_random_external_ip())

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
        f"%ASA-6-113039: Group <{group_name}> User <{_vpn_user(user)}> IP <{tor_ip}> "
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

    The session is ALLOWED because no block rule matches. Models a user bulk-copying
    sensitive files from a share before exfiltration.

    The VOLUME half of this signal is unreachable on ASA — connection byte counts never
    reach XDM (parse_cisco files them under generalCiscoLog.transferred_bytes and
    _json.sentBytes; CiscoASA_1_4.xif reads only generalCiscoLog.sent_bytes, so
    xdm.source.sent_bytes is populated on AnyConnect 113019 events ONLY). What remains
    reachable is "Rare SMB session to a remote host", which scores the DESTINATION's
    rarity — so the destination must be a host that rarely receives SMB.

    It used to be drawn from config['internal_servers']. That list is small and every
    SMB generator hit it, and separately _generate_ldap_kerberos_benign sends benign
    AD-auth SMB to the five domain controllers all day (measured: 538-584 hits each per
    7 days, the busiest SMB receivers in the tenant). A destination from either set is
    the opposite of rare. _rare_internal_host() draws from the wide internal_networks
    space while excluding the hot server pool.

    Returns list of syslog strings (Built + Teardown pair).
    """
    print("    - ASA Module simulating: SMB Rare File Transfer (large internal SMB session)")
    user   = _get_user_from_ip(config, src_ip, session_context)
    try:
        from modules.session_utils import rare_known_host
    except ImportError:
        from session_utils import rare_known_host
    # A live workstation in another subnet: rare_internal_host() addresses were never
    # seen anywhere, and Rare SMB/RDP never fired from any vendor while using them.
    dst_ip = rare_known_host(config, exclude=(src_ip,), avoid_subnet_of=src_ip)

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
        # use TCP FINs (clean close) rather than "TCP Reset - I" (port-scan semantics).
        logs.extend(_generate_connection_session(
            config, "TCP", src_ip, dst_ip, 445, user,
            random.randint(40, 200), random.randint(40, 200),
            random.randint(0, 2),
            src_interface="inside", dest_interface="inside",
            teardown_reason="TCP FINs"
        ))
    return logs


def _simulate_smtp_spray(config, src_ip, session_context=None):
    """Compromised workstation acting as a spam bot — XSIAM "Spam Bot Traffic".

    REBUILT 2026-09-17. Cortex: "The endpoint connected to an excessive number of
    external SMTP servers ... the volume of traffic is not considered. A count is
    performed based on the number of domains being contacted, as well as the number
    of unresolved IP addresses." Test period 3 days, dedup 3 days.

    What was wrong with the previous version, all of which worked against that count:
      * 30% of sessions went to 587 — authenticated SUBMISSION to the sender's own
        provider, the opposite of a spam bot delivering straight to many MX hosts on 25;
      * destinations came from the AMBIENT pool, whose 35 /24s every module's normal
        traffic also touches;
      * 30-50 sessions landed in one second (no event_time).
    Now: port 25 only, 60-150 DISTINCT servers from the rare-destination pool with no
    DNS precursor (unresolved IPs are exactly what the count includes), spread across
    the past 1-3 hours.

    Standing risk: the Spam Bot alerts that fire in this tenant (Check Point) carry
    app_id 'ip,tcp,smtp' and ASA carries no application_protocol. Re-evaluate after
    2026-10-16; if still silent, the app-ID gap is confirmed fatal on ASA.
    """
    print(f"    - ASA Module simulating: SMTP spam bot from {src_ip}")
    user      = _get_user_from_ip(config, src_ip, session_context)
    n_targets = random.randint(60, 150)
    dest_ips  = set()
    while len(dest_ips) < n_targets:
        dest_ips.add(_rare_external_ip())

    now      = datetime.now(timezone.utc)
    window_s = random.randint(3600, 3 * 3600)
    logs = []
    for dst_ip in dest_ips:
        logs.extend(_generate_connection_session(
            config, "TCP", src_ip, dst_ip, 25, user,
            random.randint(2_000, 30_000), random.randint(200, 1_500),
            random.randint(1, 20),
            src_interface="inside", dest_interface="outside",
            teardown_reason="TCP FINs",
            event_time=now - timedelta(seconds=random.randint(0, window_s)),
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
    """High volume of unanswered connection attempts from one external source.

    NON-ANALYTIC — this does NOT fire XSIAM "Failed Connections", and cannot.

    The 2026-07-24 rework moved this off ACL denies (106023, unparsed) onto a
    permitted-then-abandoned flow: 302013 Built followed by 302014 Teardown with reason
    "SYN Timeout" and 0 bytes. The messages do parse — but parse_cisco DISCARDS the
    teardown reason, so the only thing marking these as failures is erased. Verified
    2026-09-16 on live data: no reason/outcome field in _json or generalCiscoLog, and
    xdm.event.outcome null on 100% of rows. XSIAM sees 50-150 SUCCESSFUL connections.
    See the _NON_ANALYTIC_EVENTS entry for the full evidence.

    Kept because the raw pattern is genuine, drives the cross-source XQL hunt, and
    `attacker_ip` pins the source so a scenario can key every perimeter stage to one
    external attacker. Emits 50-150 Built+Teardown pairs.
    """
    print("    - ASA Module simulating: Failed Connections burst (302013/302014 SYN Timeout)")
    attacker_ip = attacker_ip or _random_external_ip()

    internal_networks = config.get('internal_networks', ['10.10.1.0/24'])
    try:
        net = ip_network(random.choice(internal_networks), strict=False)
    except (ValueError, IndexError):
        net = None

    scan_ports = [22, 23, 25, 80, 135, 139, 443, 445, 1433, 1521,
                  3306, 3389, 4444, 5900, 6379, 8080, 8443]

    logs = []
    for _ in range(random.randint(50, 150)):
        target_ip = rand_ip_from_network(net) if net else f"10.10.1.{random.randint(2, 254)}"
        dest_port = random.choice(scan_ports)
        # Permitted inbound flow that the internal host never answers -> SYN Timeout,
        # zero bytes. Emitted as a genuine 302013 (Built inbound) + 302014 (Teardown) pair.
        logs.extend(_generate_connection_session(
            config, "TCP", attacker_ip, target_ip, dest_port, "N/A", 0, 0, 0,
            direction="inbound", src_interface="outside", dest_interface="inside",
            teardown_reason="SYN Timeout"
        ))
    return logs


# XSIAM-firewall-analytics-aligned threat generators
# ASA native syslog does not log DNS query names, so DNS tunnelling and VPN
# client-OS anomalies are NOT feasible here (no mappable field) and are omitted.

def _asa_domain_controllers(config):
    """DC IPs for LDAP/Kerberos traffic; falls back to synthesized DC addresses."""
    asa_conf = _get_asa_config(config)
    dcs = asa_conf.get('dc_servers') or config.get('domain_controllers')
    return dcs or ["10.0.10.10", "10.0.20.10", "10.1.5.10", "192.168.1.10", "172.16.10.10"]


def _simulate_reverse_ssh_tunnel(config, internal_host_ip, session_context=None):
    """Internal host -> EXTERNAL IP on SSH/22 — reverse SSH tunnel / C2 over SSH.
    Long-lived, high bidirectional volume; a few sessions to the SAME external host
    (stable destination = the recurring-rare-destination signal). Returns list."""
    dest_ip = _beacon_target_map.get(f"revssh::{internal_host_ip}")
    if not dest_ip:
        dest_ip = _rare_external_ip()
        _beacon_target_map[f"revssh::{internal_host_ip}"] = dest_ip
    user = _get_user_from_ip(config, internal_host_ip, session_context)
    logs = []
    for _ in range(random.randint(2, 4)):
        logs.extend(_generate_connection_session(
            config, "TCP", internal_host_ip, dest_ip, 22, user,
            random.randint(5, 80) * 1024 * 1024,
            random.randint(5, 80) * 1024 * 1024,
            random.randint(1800, 14400)
        ))
    return logs


def _simulate_ldap_recon(config, internal_host_ip, session_context=None):
    """One host querying MANY domain controllers on LDAP 389/636 — AD reconnaissance
    (breadth + volume is the signal). Internal-to-internal sessions. Returns list."""
    user = _get_user_from_ip(config, internal_host_ip, session_context)
    logs = []
    for dc in _asa_domain_controllers(config):
        for _ in range(random.randint(3, 6)):
            port = random.choice([389, 389, 636])
            logs.extend(_generate_connection_session(
                config, "TCP", internal_host_ip, dc, port, user,
                random.randint(2_000, 40_000),      # large search requests
                random.randint(20_000, 400_000),    # bulk directory results
                random.randint(0, 5),
                src_interface="inside", dest_interface="inside"
            ))
    return logs


# Non-analytic events — genuine, XSIAM-parseable connection/session
# patterns with NO built-in XSIAM analytic. Raw / XQL-hunt / custom-rule targets.
# Every one emits only supported message IDs (302013-16 / 113039 / 113019 / 722051).

_MINING_PORTS    = [3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700]
_RARE_DEST_PORTS = [1080, 1337, 2222, 5222, 6667, 8443, 9001, 9050]


def _simulate_web_c2_beacon(config, internal_host_ip, session_context=None):
    """HTTPS C2 beaconing from a small set of STABLE infected hosts, each to its own
    STABLE rare external IP — XSIAM "Recurring access to rare IP": "The endpoint is
    periodically accessing an external fixed-IP address that its peers rarely use.
    Access to this external IP address has occurred repeatedly over many days."

    REBUILT 2026-09-17. The previous version beaconed from whatever random host the
    dispatcher handed it, so a given (host, IP) pair appeared once and never again —
    "repeatedly over many days" could not be satisfied however often it ran. Now:
      * session_utils.stable_beacon_pairs() fixes 4 (host, rare IP) pairs from a hash,
        with host IPs derived deterministically so they SURVIVE RESTARTS;
      * every call beacons from ALL pairs, and generate_log() guarantees one call per
        UTC day (_DAILY_EVENTS), so each pair recurs every day;
      * 12-24 small sessions per pair at a jittered 2-5 min cadence over the past hour.
    `internal_host_ip` is deliberately ignored.
    """
    logs = []
    now  = datetime.now(timezone.utc)
    for host_ip, uname, c2_ip in stable_beacon_pairs("asa:web_c2_beacon", config, n=4):
        user = uname or _get_user_from_ip(config, host_ip, session_context)
        t = now - timedelta(minutes=60)
        for _ in range(random.randint(12, 24)):
            t += timedelta(seconds=random.randint(120, 300))
            if t > now:
                break
            logs.extend(_generate_connection_session(
                config, "TCP", host_ip, c2_ip, 443, user,
                random.randint(200, 900), random.randint(200, 1_500), random.randint(0, 3),
                event_time=t,
            ))
    return logs


def _simulate_cryptomining(config, internal_host_ip, session_context=None):
    """Cryptominer on a small set of STABLE hosts, each holding long-lived sessions to
    its own STABLE rare pool IP on a mining port — XSIAM "Recurring access to rare IP".

    REBUILT 2026-09-17 for the same reason as _simulate_web_c2_beacon: a random host
    per run meant no (host, IP) pair recurred across days. Uses its own pair set
    (different hash key), 2 hosts, and is in _DAILY_EVENTS so each pair recurs daily.
    A miner never goes quiet, which is the whole point of the pattern.
    `internal_host_ip` is deliberately ignored.
    """
    logs = []
    now  = datetime.now(timezone.utc)
    for i, (host_ip, uname, pool_ip) in enumerate(
            stable_beacon_pairs("asa:cryptomining", config, n=2)):
        user = uname or _get_user_from_ip(config, host_ip, session_context)
        port = _MINING_PORTS[i % len(_MINING_PORTS)]
        for _ in range(random.randint(3, 6)):
            dur = random.randint(1800, 7200)
            logs.extend(_generate_connection_session(
                config, "TCP", host_ip, pool_ip, port, user,
                random.randint(50_000, 500_000), random.randint(100_000, 2_000_000), dur,
                event_time=now - timedelta(seconds=random.randint(dur, dur + 3 * 3600)),
            ))
    return logs


def _simulate_rare_port_connection(config, internal_host_ip, session_context=None):
    """Uncommon destination port — a host making an outbound connection to an unusual
    service port it never normally uses. Returns list (Built+Teardown pair)."""
    dest_ip = _rare_external_ip()
    port    = random.choice(_RARE_DEST_PORTS)
    user    = _get_user_from_ip(config, internal_host_ip, session_context)
    return _generate_connection_session(
        config, "TCP", internal_host_ip, dest_ip, port, user,
        random.randint(2_000, 50_000), random.randint(5_000, 200_000), random.randint(30, 600)
    )


def _simulate_external_fanout(config, internal_host_ip, session_context=None):
    """One internal host sweeping ONE privileged service port across many EXTERNAL
    hosts in many subnets — worm propagation. XSIAM "Port Sweep" (and its higher-
    severity "Port Sweep to multiple subnets" variation).

    REBUILT 2026-09-17. The previous version picked 80/443 two times in three.
    Cortex's scan detectors explicitly discount "destination ports that are normally
    used by many endpoints", and every workstation in the tenant uses 443 all day, so
    a 443 fan-out is indistinguishable from browsing. It also landed 60-150 sessions
    in one second. Now: a single worm-propagation port (SMB/RDP/SSH/RPC/Telnet) for
    the whole run, 40-100 distinct external hosts drawn from BOTH external pools so
    they span many /24s, mostly unanswered, spread across the past 3-15 minutes.

    Complements port_sweep, which sweeps INTERNAL hosts.
    """
    user  = _get_user_from_ip(config, internal_host_ip, session_context)
    port  = random.choice([445, 445, 3389, 22, 135, 23])
    n     = random.randint(40, 100)
    dests = set()
    while len(dests) < n:
        dests.add(_rare_external_ip() if random.random() < 0.5 else _random_external_ip())
    responders = set(random.sample(sorted(dests), k=random.randint(1, 3)))

    now      = datetime.now(timezone.utc)
    window_s = random.randint(180, 900)
    logs = []
    for dest_ip in dests:
        ok = dest_ip in responders
        logs.extend(_generate_connection_session(
            config, "TCP", internal_host_ip, dest_ip, port, user,
            random.randint(300, 4_000) if ok else 0,
            random.randint(300, 8_000) if ok else 0,
            random.randint(2, 30) if ok else 0,
            teardown_reason="TCP FINs" if ok else "TCP Reset - O",
            event_time=now - timedelta(seconds=random.randint(0, window_s)),
        ))
    return logs


def _resolve_vpn_user_ip(config, session_context):
    """Resolve a (user, public_ip) pair for the VPN-session non-analytic generators."""
    user = None
    if session_context:
        ui = get_random_user(session_context, preferred_device_type='workstation')
        user = ui['username'] if ui else None
    if not user:
        umap = _get_user_ip_map(config)
        user = random.choice(list(umap.keys())) if umap else None
    ingress = config.get('benign_ingress_sources', [{}])
    src = random.choice(ingress) if ingress else {}
    try:
        public_ip = rand_ip_from_network(ip_network(src.get("ip_range", "68.185.12.0/24"), strict=False))
    except (AddressValueError, ValueError):
        public_ip = f"68.185.12.{random.randint(2, 254)}"
    return user, public_ip


def _simulate_vpn_data_exfil(config, session_context=None):
    """AnyConnect session with anomalously high UPLOAD volume — data exfiltration over VPN.
    Session start (113039) + disconnect (113019) carrying the volume. Returns list.

    THE ONLY ASA PATH TO BYTE-VOLUME ANALYTICS. Connection events (302013/302014) can
    never carry volume into XDM: parse_cisco puts the teardown byte count at
    `_json.sentBytes`, but CiscoASA_1_4.xif reads `_json.generalCiscoLog.sent_bytes`,
    which is ALWAYS null. Measured in-tenant across production
    302014 teardowns, generalCiscoLog.sent_bytes populated 0 times while
    _json.sentBytes populated 65,427 times. Only 113019/113039 reach
    xdm.source.sent_bytes. So large_single_upload_session / cumulative_upload_session /
    smtp_large_exfil / torrent_client CANNOT drive a volume detector however big their
    byte values are — this generator is the substitute.

    Field mapping verified in-tenant:
        'Bytes xmt' -> xdm.source.sent_bytes   (what the detector profiles as upload)
        'Bytes rcv' -> xdm.target.sent_bytes
    The large value therefore goes in **Bytes xmt**. Putting it in Bytes rcv (the prior
    behaviour) parked 5-50 GB in target.sent_bytes, the wrong side for an upload
    analytic, which is why this event never fired and was marked Non-Analytic.
    """
    print("    - ASA Module simulating: VPN Data Exfiltration (high upload volume)")
    user, public_ip = _resolve_vpn_user_ip(config, session_context)
    if not user:
        return None
    asa_conf     = _get_asa_config(config)
    group_name   = asa_conf.get('vpn_group_name', 'TunnelGroup_AnyConnect')
    session_type = asa_conf.get('vpn_session_type', 'AnyConnect')
    duration  = random.randint(1800, 14400)
    bytes_xmt = random.randint(5 * 1024**3, 50 * 1024**3)     # 5-50 GB -> source.sent_bytes
    bytes_rcv = random.randint(10 * 1024**2, 300 * 1024**2)   # modest inbound
    now = datetime.now(timezone.utc)
    return [
        _generate_full_syslog_message(config,
            f"%ASA-6-113039: Group <{group_name}> User <{_vpn_user(user)}> IP <{public_ip}> "
            f"AnyConnect parent session started.", now - timedelta(seconds=duration)),
        _generate_full_syslog_message(config,
            f"%ASA-4-113019: Group = {group_name}, Username = {_vpn_user(user)}, IP = {public_ip}, "
            f"Session disconnected. Session Type: {session_type}, "
            f"Duration: {_format_vpn_duration(duration)}, "
            f"Bytes xmt: {bytes_xmt}, Bytes rcv: {bytes_rcv}, Reason: User Requested", now),
    ]


def _simulate_vpn_concurrent_sessions(config, session_context=None):
    """Same user, two OVERLAPPING AnyConnect sessions from two continents — XSIAM
    "Impossible traveler - VPN" ("A user connected to a VPN service from multiple
    remote countries in a short period of time").

    REBUILT 2026-09-17. The previous version drew BOTH IPs at random from the
    5-country ingress pool, so the pair was often the same country or a plausible
    same-continent hop (UK->DE), and neither was the user's real home IP — nothing
    about it was impossible. Now the first session comes from the user's own stable
    home IP and the second from a home-pool range on a DIFFERENT continent
    (session_utils.impossible_travel_ips). Both locations are already in the org
    baseline, so this adds ZERO new countries and cannot burn the org-scoped
    new-country detector.

    Differs from vpn_impossible_travel only in shape: overlapping sessions (account
    co-use) rather than sequential ones.
    """
    print("    - ASA Module simulating: Concurrent VPN sessions from two continents")
    user, _ = _resolve_vpn_user_ip(config, session_context)
    if not user:
        return None
    ip1, cc1, ip2, cc2 = impossible_travel_ips(_vpn_user(user), config)
    asa_conf   = _get_asa_config(config)
    group_name = asa_conf.get('vpn_group_name', 'TunnelGroup_AnyConnect')
    vpn_pool   = asa_conf.get('vpn_pool', '10.250.0.0/16')

    def _inside():
        try:
            return rand_ip_from_network(ip_network(vpn_pool, strict=False))
        except Exception:
            return f"10.250.{random.randint(1,254)}.{random.randint(1,254)}"

    now  = datetime.now(timezone.utc)
    logs = []
    # First session from home a few minutes ago; second from the far continent now,
    # while the first is still up.
    for ip, t in ((ip1, now - timedelta(minutes=random.randint(4, 12))), (ip2, now)):
        logs.append(_generate_full_syslog_message(config,
            f"%ASA-6-113039: Group <{group_name}> User <{_vpn_user(user)}> IP <{ip}> "
            f"AnyConnect parent session started.", t))
        logs.append(_generate_full_syslog_message(config,
            f"%ASA-6-722051: Group <{group_name}> User <{_vpn_user(user)}> IP <{ip}> "
            f"Address <{_inside()}> assigned to session", t + timedelta(seconds=1)))
    return logs


def _generate_ldap_kerberos_benign(config, internal_host_ip, session_context=None):
    """Normal AD auth: workstation -> its DC on LDAP/Kerberos/SMB (baseline so LDAP
    recon stands out). Returns list of syslog strings."""
    user = _get_user_from_ip(config, internal_host_ip, session_context)
    dc   = random.choice(_asa_domain_controllers(config))
    port = random.choice([389, 389, 636, 88, 88, 445])
    return _generate_connection_session(
        config, "TCP", internal_host_ip, dc, port, user,
        random.randint(500, 4_000), random.randint(1_000, 20_000), random.randint(0, 3),
        src_interface="inside", dest_interface="inside"
    )


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
    # Never a hot internal_servers host: after weeks every one of them has served FTP,
    # so none is a NEW FTP server. A workstation that starts serving is (see helper).
    try:
        from modules.session_utils import new_ftp_server_host
    except ImportError:
        from session_utils import new_ftp_server_host
    ftp_server_ip = new_ftp_server_host(config)

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
    reverse paths).

    THE SOURCE MUST BE A HOST XSIAM ALREADY BELIEVES IS A DOMAIN CONTROLLER — that
    belief is the detector's entire premise.  This used to fall back to
    internal_servers[0] (10.0.10.50), an address that appears nowhere else in the
    simulation as a DC.  Measured in-tenant over 14 days: 10.0.10.50 sourced the
    DC-SMB bursts and otherwise received 2 SMB, 2 RDP and 2 SSH sessions in total —
    no DC profile at all — while the five hosts that DO look like DCs (each
    receiving ~1,100 LDAP/389 + Kerberos/88 queries per week from
    _generate_ldap_kerberos_benign) never sourced a single packet.  The detector
    could never fire.

    It now shares _asa_domain_controllers() with ldap_recon and the benign AD-auth
    generator, so the host seen serving LDAP/Kerberos all week is the same host that
    turns around and speaks SMB to a workstation.  Keep these in step.
    """
    dc_servers = _asa_domain_controllers(config)
    if not dc_servers:
        return None

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


# Main log generation entry point

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
      failed_connections_burst   10  — NON-ANALYTIC (teardown reason is discarded by
                                       parse_cisco; XSIAM cannot see the failure)
      large_single_upload_session  8  — XSIAM "Large Upload (HTTPS)"
      unusual_ssh_session          5  — XSIAM "Uncommon SSH session"
      smb_share_enumeration        5  — XSIAM "Rare SMB session to a remote host"
      cumulative_upload_session    4  — XSIAM "Large Upload (HTTPS)" via accumulation
      ssh_proxy_attack             4  — XSIAM "Unusual SSH activity that resembles SSH proxy"
      smb_new_host_lateral         4  — XSIAM "Rare SMB session to a remote host"
      unusual_rdp_session          3  — XSIAM "Rare RDP session"
      tor_connection               3  — XSIAM "Recurring access to rare IP"
      vpn_bruteforce               3  — XSIAM "VPN login Brute-Force" / "Password Spray"
      vpn_tor_login                3  — XSIAM "Successful VPN connection from TOR"
      vpn_new_country_login        4  — XSIAM "First successful VPN access from a country
                                        in organization" (see _simulate_vpn_new_country_login)
      smb_rare_file_transfer       3  — XSIAM "Rare SMB session" / large-volume internal
      smtp_spray                   3  — XSIAM "Spam Bot Traffic"
      torrent_client               3  — XSIAM "A Torrent client was detected on a host"
      dc_smb_outbound              3  — XSIAM "Suspicious SMB connection from domain controller"
      smtp_large_exfil             2  — XSIAM "Large Upload (SMTP)"
      vpn_impossible_travel        2  — XSIAM "Impossible traveler - VPN"
      new_ftp_server               2  — XSIAM "New FTP Server"
      dns_c2_beacon                1  — XSIAM "Recurring access to rare IP"
      server_outbound_http         1  — XSIAM "Abnormal Communication to a Rare IP"
      workstation_lateral_rdp      1  — XSIAM "Rare RDP session"
      new_admin_behavior           4  — XSIAM "New Administrative Behavior"
      abnormal_rdp_rare_host       4  — XSIAM "Abnormal RDP session to a remote host
                                        from a rarely seen host"
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
            # A scenario pins the destination: the address Infoblox just answered
            # for the name. Without it this event invents its own and the
            # DNS-to-connection join the scenario demonstrates cannot be made.
            dest_ip = context.get('dst_ip')
            if not dest_ip:
                try:
                    dest_ip = rand_ip_from_network(ip_network(dest.get("ip_range", "154.53.224.0/24"), strict=False))
                except (AddressValueError, ValueError):
                    dest_ip = "154.53.224.10"
            return _generate_connection_session(
                config, "TCP", src_ip, dest_ip, 443, user,
                bytes_sent, random.randint(1000, 5000), random.randint(60, 300)
            )
        # Named threat from dashboard — strip any "[Non-Analytic] " prefix, then dispatch
        forced_choice = _strip_non_analytic_prefix(scenario_event).lower()

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
        {"event": "ad_auth_benign",     "weight": 5},
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
            # vpn_new_country_login is CLOCK-KEYED, not probability-keyed, and the two must
            # not be left mismatched.
            #
            # novel_country_vpn_ip() advances one country per UTC day (pool[day % 84]) so
            # that every VPN-capable module picks the SAME country and the pool lasts 84
            # days. That rotation advances whether or not we emit anything. Selecting the
            # event by weighted draw meant most rotation days were never emitted at all,
            # and a skipped day is a PERMANENTLY wasted country — the pool moves on.
            #
            # Measured 2026-09-17: only 2 rotation-country logins reached the tenant in 14
            # days (New Zealand 09-10, Papua New Guinea 09-15) against ~6 expected at the
            # old weight, and the detector has never fired in 90 days. Separately, 6 of the
            # last 30 rotation days landed on a country the reversed-ICMP bug had already
            # made non-novel org-wide (Ghana, Ireland, Kenya, Nepal, New Zealand, Nigeria).
            #
            # So: claim the day's country exactly once per UTC day, using one of the ~12
            # daily threat slots. The same applies to the recurring-beacon events, so
            # this is driven by _DAILY_EVENTS (see its definition). Remaining slots stay
            # weighted as before.
            today_utc = int(current_time // 86400)
            due = next((e for e in _DAILY_EVENTS
                        if e in threat_functions and _last_daily_emit.get(e) != today_utc), None)
            if due:
                _last_daily_emit[due] = today_utc
                log_choice = due
            else:
                log_choice = random.choices(threat_functions, weights=threat_weights, k=1)[0]
        else:
            log_choice = random.choices(benign_functions, weights=benign_weights, k=1)[0]

    # --- Resolve internal host IP for events that need one ---
    # Events that handle their own user/IP selection are excluded from this block.
    no_internal_ip_needed = {
        "anyconnect_vpn", "vpn_bruteforce", "vpn_impossible_travel",
        "server_outbound_http", "inbound_block", "aaa_auth",
        "vpn_tor_login",    # resolves its own user/IP from TOR nodes config
        "vpn_new_country_login",  # resolves its own user/IP from vpn_novel_country_pool
        "vpn_login_benign", "vpn_failure_benign",  # resolve own user/IP
        "ntp_sync",         # picks IP from internal_networks directly
        "internal_traffic", # resolves user/IP from session_context itself
        "dhcp_log",         # picks IP from internal_networks directly
        "failed_connections_burst",  # one external attacker IP, targets are random
        "new_ftp_server",            # picks server IP from internal_servers
        "dc_smb_outbound",           # picks DC from dc_servers config
        "vpn_data_exfil",            # resolves own VPN user/IP
        "vpn_concurrent_sessions",   # resolves own VPN user/IP
    }
    internal_host_ip = "192.168.1.100"
    if log_choice not in no_internal_ip_needed:
        ctx_src = (context or {}).get('src_ip')
        if ctx_src:
            # Scenario victim — keep the internal host consistent across stages so
            # XSIAM entity-stitching can tie SMB/RDP/etc. to the same victim.
            internal_host_ip = ctx_src
        elif session_context and log_choice in ("dns_c2_beacon", "tor_connection",
                                                "reverse_ssh_tunnel"):
            # Recurring-access detectors need the same host on many days (see
            # session_utils.recurring_host); a scenario's pinned victim still wins above.
            try:
                from modules.session_utils import recurring_host
            except ImportError:
                from session_utils import recurring_host
            _h = recurring_host(f"cisco_asa:{log_choice}")
            if _h:
                internal_host_ip = _h[0]
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

    elif log_choice == "port_sweep":
        _result = _simulate_port_sweep(config, scanner_ip=internal_host_ip,
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

    elif log_choice == "new_admin_behavior":
        print("    - ASA Module simulating: New Administrative Behavior (novel admin-port pairs)")
        _result = _simulate_new_admin_behavior(config, internal_host_ip, session_context)

    elif log_choice == "abnormal_rdp_rare_host":
        print("    - ASA Module simulating: Abnormal RDP session to a rare internal host")
        _result = _simulate_abnormal_rdp_rare_host(config, internal_host_ip, session_context)

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

    elif log_choice == "vpn_new_country_login":
        _result = _simulate_vpn_new_country_login(config, session_context)

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

    elif log_choice == "reverse_ssh_tunnel":
        print("    - ASA Module simulating: Reverse SSH Tunnel to external host")
        _result = _simulate_reverse_ssh_tunnel(config, internal_host_ip, session_context)

    elif log_choice == "ldap_recon":
        print("    - ASA Module simulating: LDAP Reconnaissance across DCs")
        _result = _simulate_ldap_recon(config, internal_host_ip, session_context)

    # --- Non-analytic events (no built-in XSIAM detection; raw/hunt value) ---
    elif log_choice == "web_c2_beacon":
        print("    - ASA Module simulating: Web/HTTPS C2 Beacon (recurring rare IP)")
        _result = _simulate_web_c2_beacon(config, internal_host_ip, session_context)

    elif log_choice == "cryptomining":
        print("    - ASA Module simulating: Cryptomining pool connection")
        _result = _simulate_cryptomining(config, internal_host_ip, session_context)

    elif log_choice == "rare_port_connection":
        print("    - ASA Module simulating: Uncommon destination port")
        _result = _simulate_rare_port_connection(config, internal_host_ip, session_context)

    elif log_choice == "external_fanout":
        print("    - ASA Module simulating: Connection fan-out to many external IPs")
        _result = _simulate_external_fanout(config, internal_host_ip, session_context)

    elif log_choice == "vpn_data_exfil":
        _result = _simulate_vpn_data_exfil(config, session_context)

    elif log_choice == "vpn_concurrent_sessions":
        _result = _simulate_vpn_concurrent_sessions(config, session_context)

    elif log_choice == "ad_auth_benign":
        _result = _generate_ldap_kerberos_benign(config, internal_host_ip, session_context)

    return (_result, log_choice) if _result is not None else None
