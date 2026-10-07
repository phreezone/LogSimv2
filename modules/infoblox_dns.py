# modules/infoblox_dns.py
# Simulates Infoblox NIOS DNS, DHCP, and Audit logs in raw format for XSIAM Data Model parsing.
# OVERHAULED: Full alignment with real Infoblox NIOS production log formats verified against
# Elastic, Splunk TA, Azure Sentinel parsers, and Infoblox documentation.
# Includes CEF threat events, cross-module public API, and 7 threat scenarios.

import hashlib
import random
import time
from datetime import datetime, timezone
from ipaddress import ip_network, IPv4Address

try:
    from modules.session_utils import (get_random_user, rand_ip_from_network,
                                       weighted_dns_domain, rare_external_ip, host_mac)
    from modules import resolver
    from modules import threat_domains
except ImportError:
    from session_utils import (get_random_user, rand_ip_from_network,
                               weighted_dns_domain, rare_external_ip, host_mac)
    import resolver
    import threat_domains

NAME = "Infoblox NIOS"
DESCRIPTION = "Simulates Infoblox DNS, DHCP, Audit, RPZ, and Threat Protect logs in raw syslog/CEF format."
XSIAM_VENDOR = "infoblox"
XSIAM_PRODUCT = "infoblox"
CONFIG_KEY = "infoblox_config"

# No threat here is offered for on-demand firing (modules/threat_catalog.py): Cortex
# publishes no analytics for Infoblox data, and none has fired from it in the tenant --
# its alerts come from correlation rules and threat intel. Every threat still runs
# in long-running sessions.
ANALYTIC_ALERTS = {}

def get_threat_names():
    """Return available threat names from _SCENARIO_FUNCTIONS.
    _SCENARIO_FUNCTIONS is defined after the generator functions lower in this file."""
    return list(_SCENARIO_FUNCTIONS.keys())


last_threat_event_time = 0

# PRI values verified from real Infoblox NIOS production log captures:
# facility 3 (daemon) × 8 + severity 6 (info)   = 30  — named, dhcpd
# facility 3 (daemon) × 8 + severity 5 (notice) = 29  — httpd audit
# threat-protect-log and RPZ use ISO timestamp + "daemon" keyword (no PRI number)
_DNS_PRI   = "<30>"   # daemon+info — verified from named log captures
_DHCP_PRI  = "<30>"   # daemon+info — consistent across all dhcpd examples
_AUDIT_PRI = "<29>"   # daemon+notice — verified from httpd audit log captures

_DGA_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
_NIOS_THREAT_CATEGORIES = ["Malware", "Phishing", "C&C", "Potential DDoS related Domains", "Exploit Kit"]
_NIOS_VERSION = "9.0.3-33548"

# CEF severity numbers, per NIOS "Monitoring through Syslog":
#   8 = Critical, 7 = Major, 6 = Warning, 4 = Informational
# Every CEF event used to be hardcoded 7, so severity carried no information and
# a Malware DROP looked exactly as urgent as a DDoS-domain lookup.
_CEF_SEVERITY_NAME = {8: "Critical", 7: "Major", 6: "Warning", 4: "Informational"}

# Syslog PRI for the CEF events. facility 3 (daemon) * 8 + severity:
#   crit 2 -> 26, err 3 -> 27, warning 4 -> 28, info 6 -> 30
# so the wire PRI actually tracks the rule severity instead of being a constant.
_CEF_PRI = {8: "<26>", 7: "<27>", 6: "<28>", 4: "<30>"}

# A NIOS threat-protection rule has a STABLE SID (the rule id) and a fixed
# severity -- both are properties of the rule, not of the packet that hit it.
# Measured in-tenant 2026-09-18 before this fix: 411 events carried 411 distinct
# SIDs, because the SID was random.randint(100000000, 999999999) per event. No
# rule could ever be seen to fire twice, so grouping or tuning by SID was
# impossible. 120601943 is the real SID from the Infoblox documentation sample.
#   (category, CEF severity, SID, CEF Name phrase)
_THREAT_RULES = {
    "Malware":                        (8, 130100101, "Malware domain"),
    "C&C":                            (8, 130100207, "C&C domain"),
    "Exploit Kit":                    (7, 130100314, "Exploit kit domain"),
    "Phishing":                       (7, 130100422, "Phishing domain"),
    "Potential DDoS related Domains": (6, 120601943, "Potential DDoS related domain"),
}

# RPZ rule trigger types and mitigation actions, per the NIOS RPZ syslog format
#   rpz <TYPE> <ACTION> rewrite <QUERY> [<qtype>] via <RPZ_RECORD>
# TYPE is one of QNAME, IP, CLIENT-IP, NSDNAME, NSIP.
# PASSTHRU is deliberately NOT in the block list: it is an explicit ALLOW (the
# rule matched and the answer was let through untouched). It used to be one of
# three entries in _RPZ_ACTIONS, so a third of every "RPZ block storm" was
# actually permitted traffic -- 199 of 587 RPZ events in the tenant.
_RPZ_BLOCK_ACTIONS = ["NXDOMAIN", "NODATA", "Local-Data"]
_RPZ_TRIGGERS      = ["QNAME", "IP", "CLIENT-IP", "NSDNAME"]
# Audit verbs NIOS actually writes. Object_Add / Object_Modify / Object_Delete,
# which this module used until 2026-09-18, are NOT among them -- NIOS logs an
# object change as Created(POST) / Modified(PUT) / Deleted(DELETE) with the WAPI
# call that made it, and a login-shaped body (to=/auth=/group=/apparently_via=)
# on an object change says nothing about WHICH object changed.
_AUDIT_LOGIN_TYPES  = ["Login_Allowed", "Login_Denied", "Logout"]
_AUDIT_OBJECT_TYPES = ["Created", "Modified", "Deleted"]
_AUDIT_WAPI_METHOD  = {"Created": "POST", "Modified": "PUT", "Deleted": "DELETE"}
_AUDIT_AUTH_TYPES   = ["Local", "AD", "LDAP", "RADIUS"]
_AUDIT_GROUPS       = ["admin-group", "GridAdmins", "local-admin", "noc-operators"]
_AUDIT_LOGIN_ERRORS = ["invalid login or password", "account locked out",
                       "remote authentication failed"]

# (WAPI object path, display type) pairs an Infoblox admin actually touches.
_AUDIT_WAPI_OBJECTS = [
    ("record:a",       "ARecord"),
    ("record:host",    "HostRecord"),
    ("record:cname",   "CnameRecord"),
    ("zone_auth",      "AuthZone"),
    ("network",        "Network"),
    # "Range", not "DHCPRange": the Infoblox content pack's DHCP section claims
    # any line matching DHCP\w+, so an audit line naming a DHCPRange object was
    # modelled as a DHCP event and lost its admin (seen in-tenant 2026-09-21).
    ("range",          "Range"),
    ("fixedaddress",   "FixedAddress"),
    ("record:ptr",     "PtrRecord"),
]

# Realistic CDN/SaaS domains for CNAME chains
_CDN_DOMAINS = [
    "cloudfront.net", "akamaiedge.net", "azureedge.net",
    "fastly.net", "cdn.cloudflare.com", "edgekey.net",
]
_SRV_SERVICES = [
    "_ldap._tcp", "_kerberos._tcp", "_kerberos._udp",
    "_sip._tcp", "_sip._udp", "_sipfederationtls._tcp",
    "_http._tcp", "_https._tcp",
]


# Timestamp helpers

def _get_syslog_timestamp():
    """RFC 3164 syslog timestamp: 'Oct 11 22:14:15'"""
    return datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')


def _get_iso_timestamp():
    """ISO 8601 UTC — used in threat-protect-log and RPZ CEF syslog headers."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S+00:00')


def _get_audit_body_timestamp():
    """Infoblox audit log body timestamp: '2012-11-28 14:43:53.601Z'"""
    now = datetime.now(timezone.utc)
    ms  = now.strftime('%f')[:3]
    return now.strftime(f'%Y-%m-%d %H:%M:%S.{ms}Z')


def _get_threat_interval(threat_level, config):
    levels = config.get('threat_generation_levels', {})
    return levels.get(threat_level, 86400 * 365)


# DNS log builders

# ---------------------------------------------------------------------------
# Appliance identity: which grid member, which process, which address.
# ---------------------------------------------------------------------------

# One pid per (appliance, daemon) for the life of the run. A daemon keeps its pid
# until it restarts, and the content pack maps it to xdm.source.process.pid.
# Before 2026-09-21 every builder rolled a fresh pid per LINE, so one named
# process appeared as named[2006], named[2944], named[2751] ... within a second.
# Reload-safe, like resolver.RESOLVER_STATE.
_PIDS = globals().get("_PIDS") or {}
_PID_RANGES = {"named": (1800, 4000), "dhcpd": (4000, 6000),
               "threat-protect-log": (10000, 30000)}


def _pid(hostname, daemon):
    key = (hostname, daemon)
    if key not in _PIDS:
        lo, hi = _PID_RANGES.get(daemon, (2000, 30000))
        _PIDS[key] = random.randint(lo, hi)
    return _PIDS[key]


def reset_state():
    """Reset per-process state for a hermetic (Training Mode) run.

    Daemon PIDs are drawn from the RNG the first time each (appliance, daemon) is seen
    and then cached. Without clearing them, a seeded replay skips those draws and every
    later random value shifts -- which broke Training Mode determinism from the NIOS
    rewrite on (test-scenario-18: a Windows Logon ID downstream came out different).
    """
    global last_threat_event_time
    _PIDS.clear()
    last_threat_event_time = 0


def _members(config):
    """[(hostname, ipv4)] grid members -- shared with every network module."""
    return resolver.grid_members(config)


def _appliance(config, key=None):
    """(hostname, server_ip) of the grid member serving `key` (client IP or MAC).

    Pinned per client, and computed by resolver.dns_server_for() so every
    firewall that logs the same client's DNS names the same member. Before
    2026-09-21 the hostname and server address were drawn independently per line.
    """
    return resolver.dns_server_for(config, key)


def _member_for_ip(config, server_ip):
    for name, ip in _members(config):
        if ip == server_ip:
            return name
    return _members(config)[0][0]


# ---------------------------------------------------------------------------
# IPv6. Clients are dual-stack: each workstation also holds a SLAAC address
# (ULA prefix per /24 + EUI-64 from its MAC), and a share of its queries travel
# over IPv6. That is what populates xdm.source.ipv6 / xdm.intermediate.ipv6,
# which no event reached before.
# ---------------------------------------------------------------------------

def _ula_prefix(ipv4):
    o = [int(x) for x in str(ipv4).split(".")]
    return f"fd00:{o[0]:x}:{o[1]:x}:{o[2]:x}"


def _eui64(mac):
    b = [int(x, 16) for x in mac.split(":")]
    b[0] ^= 0x02                                   # flip universal/local bit
    return f"{b[0]:02x}{b[1]:02x}:{b[2]:02x}ff:fe{b[3]:02x}:{b[4]:02x}{b[5]:02x}"


def _client_ipv6(ipv4, mac):
    return f"{_ula_prefix(ipv4)}:{_eui64(mac)}"


def _server_ipv6(ipv4):
    return f"{_ula_prefix(ipv4)}::{str(ipv4).split('.')[-1]}"


def _aaaa_for(domain):
    """Stable IPv6 answer for an external name, from the IPv6 documentation
    prefix (2001:db8::/32, RFC 3849) -- the v6 twin of the TEST-NET fallback in
    _answer_for. Every AAAA used to answer 2001:4860:4860::8888, which is
    Google's public DNS resolver, for every domain."""
    d = hashlib.sha256(domain.encode()).digest()
    return f"2001:db8:{d[0]:x}{d[1]:02x}:{d[2]:x}::{d[3]:x}{d[4]:02x}"


# ---------------------------------------------------------------------------
# Query and response flags, per NIOS "Capturing DNS Queries and Responses":
#   query    + recursion desired, - not; S TSIG, E EDNS, T TCP, D DO, C CD
#   response + recursion AVAILABLE, - not; A authoritative, t truncated,
#            E EDNS OPT present, D DNSSEC OK, V validated, L DTC synthetic
# The response sign is about recursion, not transport. It used to be "-A" for UDP
# and "+A" for TCP, which (a) told every client our recursive resolvers had
# recursion switched off and (b) marked every answer authoritative, including
# zoom.us, which this grid does not host. The pack maps the A flag straight to
# xdm.network.dns.authoritative.
# ---------------------------------------------------------------------------

def _is_authoritative(config, name):
    """True for names in zones this grid hosts: the AD zone and the internal
    reverse zones."""
    n  = str(name).rstrip(".").lower()
    ad = resolver.internal_domain(config)
    if n == ad or n.endswith("." + ad):
        return True
    if n.endswith(".in-addr.arpa"):
        labels = n[:-len(".in-addr.arpa")].split(".")
        if len(labels) == 4:
            try:
                return IPv4Address(".".join(reversed(labels))).is_private
            except ValueError:
                return False
    return False


def _query_flags(q_type, ip_protocol="UDP"):
    if q_type in ("AXFR", "IXFR"):
        return "-T"                                  # transfers: no RD, always TCP
    flags = "+E" if q_type == "TXT" else "+ED"
    return flags + ("T" if ip_protocol == "TCP" else "")


def _response_flags(query_flags, authoritative):
    return ("+" + ("A" if authoritative else "")
            + ("E" if "E" in query_flags else "")
            + ("D" if "D" in query_flags else ""))


def _client_ptr(client_ip, client_port):
    # BIND prints the address of the client memory object: a 12-hex-digit
    # userspace heap pointer on x86-64, stable for the client's burst.
    return "0x7f" + hashlib.sha256(f"{client_ip}:{client_port // 256}".encode()).hexdigest()[:10]


def _build_dns_query_log(config, client_ip, domain, q_type="A", dns_server_ip=None,
                         hostname=None, client_port=None, pid=None, flags=None):
    r"""
    Builds a RFC 3164 syslog message for a DNS query from named[pid].

    Verified real format:
    <30>Dec 23 12:54:05 infoblox1 named[12821]: client @0x7fbc3c0cc6e0 192.168.80.1#57296 (server1.fwd1): query: server1.fwd1 IN A +ED (192.168.80.200)

    Routed to infoblox_infoblox_raw; the content pack models it into
    xdm.network.dns.dns_question.* and xdm.source.* (see ModelingRules/Infoblox_1_3).
    """
    if hostname is None or dns_server_ip is None:
        h, s = _appliance(config, client_ip)
        hostname      = hostname or h
        dns_server_ip = dns_server_ip or s
    pid         = pid or _pid(hostname, "named")
    client_port = client_port or random.randint(49152, 65535)
    flags       = flags or _query_flags(q_type)
    msg = (f"{_get_syslog_timestamp()} {hostname} named[{pid}]: "
           f"client @{_client_ptr(client_ip, client_port)} {client_ip}#{client_port} ({domain}): "
           f"query: {domain} IN {q_type} {flags} ({dns_server_ip})")
    return f"{_DNS_PRI}{msg}"


def _build_query_failed_log(config, client_ip, domain, q_type, rcode,
                            hostname=None, client_port=None, pid=None):
    """BIND's 'query failed' line, logged when it could not answer:
        client @0x7f.. 10.0.20.74#53211 (x.com): query failed (SERVFAIL) for x.com/IN/A at query.c:6880
    The pack's DNS Query section reads the rcode out of 'query failed (X)' into
    xdm.event.outcome = FAILED / xdm.event.outcome_reason -- the only path to
    those two fields for DNS."""
    if hostname is None:
        hostname, _ = _appliance(config, client_ip)
    pid         = pid or _pid(hostname, "named")
    client_port = client_port or random.randint(49152, 65535)
    msg = (f"{_get_syslog_timestamp()} {hostname} named[{pid}]: "
           f"client @{_client_ptr(client_ip, client_port)} {client_ip}#{client_port} ({domain}): "
           f"query failed ({rcode}) for {domain}/IN/{q_type} at query.c:6880")
    return f"{_DNS_PRI}{msg}"


def _build_dns_response_log(config, client_ip, domain, q_type, rcode, response_records=None,
                            ip_protocol="UDP", hostname=None, client_port=None, pid=None,
                            flags=None):
    """
    Builds a RFC 3164 syslog message for a DNS response from named[pid].

    Documented format (NIOS "Capturing DNS Queries and Responses"):
    ... client 10.120.20.198#57398 UDP: query: a2.foo.com IN A response: NOERROR +AED a2.foo.com. 28800 IN A 1.1.1.2;

    Each resource record is terminated by ';' as in the documented sample; the
    pack splits the RR section on ';' to model xdm.network.dns.dns_resource_record.*
    and xdm.target.ipv4 / ipv6 -- the fields the DNS-to-connection join uses.
    """
    if hostname is None:
        hostname, _ = _appliance(config, client_ip)
    pid         = pid or _pid(hostname, "named")
    client_port = client_port or random.randint(49152, 65535)
    if flags is None:
        auth  = _is_authoritative(config, domain) and rcode in ("NOERROR", "NXDOMAIN")
        flags = _response_flags(_query_flags(q_type, ip_protocol), auth)
    records = [r.strip() for r in (response_records or []) if r and r.strip()]
    rr = " ".join(r if r.endswith(";") else r + ";" for r in records)
    # No colon between the port and the protocol, as in the documented sample. The
    # tenant parser models both spellings identically (A/B, 2026-09-29), so this is
    # about matching real NIOS output, not about field population.
    msg = (f"{_get_syslog_timestamp()} {hostname} named[{pid}]: "
           f"client {client_ip}#{client_port} {ip_protocol}: "
           f"query: {domain} IN {q_type} response: {rcode} {flags} {rr}").rstrip()
    return f"{_DNS_PRI}{msg}"


def _build_dns_pair(config, client_ip, domain, q_type="A", rcode="NOERROR",
                    response_records=None, ip_protocol="UDP", dns_server_ip=None,
                    client_ipv6=None, failed=False):
    """A DNS query and its response as ONE transaction.

    Query and answer share the client's source port, the appliance that served
    them and the named process that logged them. Every pair used to build the two
    halves independently, so a query from 10.0.20.74#61934 on infoblox-dc1-01 was
    answered to #60856 on infoblox-dc2-01.

    client_ipv6: send the transaction over IPv6 from that address; the appliance
    is still chosen by the client's IPv4 identity, so a dual-stack host keeps one
    resolver. failed=True adds BIND's 'query failed (RCODE)' line between query
    and response, as named logs it for SERVFAIL/REFUSED.
    """
    if dns_server_ip:
        hostname, server = _member_for_ip(config, dns_server_ip), dns_server_ip
    else:
        hostname, server = _appliance(config, client_ip)
    src = client_ip
    if client_ipv6:
        src, server = client_ipv6, _server_ipv6(server)
    pid    = _pid(hostname, "named")
    port   = random.randint(49152, 65535)
    qflags = _query_flags(q_type, ip_protocol)
    auth   = _is_authoritative(config, domain) and rcode in ("NOERROR", "NXDOMAIN")
    lines  = [_build_dns_query_log(config, src, domain, q_type, dns_server_ip=server,
                                   hostname=hostname, client_port=port, pid=pid, flags=qflags)]
    if failed:
        lines.append(_build_query_failed_log(config, src, domain, q_type, rcode,
                                             hostname=hostname, client_port=port, pid=pid))
    lines.append(_build_dns_response_log(config, src, domain, q_type, rcode, response_records,
                                         ip_protocol, hostname=hostname, client_port=port,
                                         pid=pid, flags=_response_flags(qflags, auth)))
    return lines


def _named_line(config, hostname, text, pri=None):
    """A named[pid] operational line (zone loads, notifies, transfers, DDNS,
    lame servers, RPZ reloads). These carry a BIND category prefix -- general:,
    notify:, xfer-out:, update:, security:, rpz: -- which the pack's fallback
    section turns into xdm.event.type 'DNS <category>' and, for rpz:, reads the
    policy zone into xdm.target.zone."""
    return (f"{pri or _DNS_PRI}{_get_syslog_timestamp()} {hostname} "
            f"named[{_pid(hostname, 'named')}]: {text}")


def _zone_serial():
    # YYYYMMDDnn, the convention NIOS uses for zone serials.
    return datetime.now(timezone.utc).strftime("%Y%m%d") + f"{random.randint(1, 40):02d}"


def _reverse_zone(ip):
    o = str(ip).split(".")
    return f"{o[2]}.{o[1]}.{o[0]}.in-addr.arpa"


def _ptr_name(ip):
    return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"


def _build_ddns_update(config, key, fqdn, ip, delete=False):
    """The DNS side of a DHCP lease: NIOS's DHCP service updates the zone it
    hosts, so each new lease adds an A and a PTR and each release removes them.
    This is what ties a DHCP hostname to its address inside DNS itself.
        update: client @0x7f.. 127.0.0.1#5353/key dhcp_updater_default: updating zone 'examplecorp.local/IN': adding an RR at 'eng-ws-022.examplecorp.local' A 192.168.20.187
    The updater is the co-located DHCP service, hence 127.0.0.1."""
    hostname, _ = _appliance(config, key)
    ad   = resolver.internal_domain(config)
    port = random.randint(1024, 65535)
    head = f"update: client @{_client_ptr('127.0.0.1', port)} 127.0.0.1#{port}/key dhcp_updater_default"
    if delete:
        return [
            _named_line(config, hostname, f"{head}: updating zone '{ad}/IN': deleting rrset at '{fqdn}' A"),
            _named_line(config, hostname, f"{head}: updating zone '{_reverse_zone(ip)}/IN': "
                                          f"deleting rrset at '{_ptr_name(ip)}' PTR"),
        ]
    return [
        _named_line(config, hostname, f"{head}: updating zone '{ad}/IN': adding an RR at '{fqdn}' A {ip}"),
        _named_line(config, hostname, f"{head}: updating zone '{_reverse_zone(ip)}/IN': "
                                      f"adding an RR at '{_ptr_name(ip)}' PTR {fqdn}."),
    ]


# DHCP log builder

def _lease_for(client_ip):
    """One lease time per scope (the client's /24), as set on the DHCP range.
    OFFER and ACK used to draw independently, so an exchange could offer 12h and
    grant 8h. Renewals happen at T1 = half this."""
    h = int(hashlib.sha256(_relay_for(client_ip).encode()).hexdigest(), 16)
    return (28800, 43200, 86400, 28800)[h % 4]


def _dhcpd(config, key, body):
    hostname, _ = _appliance(config, key)
    return f"{_DHCP_PRI}{_get_syslog_timestamp()} {hostname} dhcpd[{_pid(hostname, 'dhcpd')}]: {body}"


def _build_dhcp_log(config, msg_type, client_ip, client_mac, client_hostname, transaction_id,
                    relay_ip=None, server_ip=None, renewal=False):
    r"""
    Builds a RFC 3164 syslog message for a DHCP event from dhcpd[pid].

    Verified real formats (Infoblox NIOS / ISC dhcpd, as used by the Elastic and
    Splunk NIOS parsers):
    <30>Mar 27 08:32:59 infoblox.localdomain dhcpd[1761]: DHCPDISCOVER from 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 TransID a76ecf84 uid 01:00:50:56:83:6c:a0
    <30>Mar 27 08:32:59 infoblox.localdomain dhcpd[2567]: DHCPOFFER on 192.168.0.4 to 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 relay eth3 lease-duration 119 offered-duration 1800 uid 01:00:50:56:83:6c:a0
    ... DHCPRELEASE of 10.10.4.125 from 13:e7:28:32:a5:2c (host.corp) via eth0 (found)

    The whole exchange is served by ONE appliance, keyed by the client's MAC (the
    only identity a DISCOVER carries).
    """
    via       = relay_ip if relay_ip else "eth1"
    trans_hex = transaction_id[2:] if transaction_id.startswith('0x') else transaction_id
    # Option 61 client identifier: hardware type 01 (Ethernet) + the MAC.
    uid   = f"01:{client_mac}"
    lease = _lease_for(client_ip if client_ip != "255.255.255.255" else (relay_ip or "192.168.1.1"))
    _, member_ip = _appliance(config, client_mac)

    if msg_type == "DHCPDISCOVER":
        body = (f"DHCPDISCOVER from {client_mac} ({client_hostname}) "
                f"via {via} TransID {trans_hex} uid {uid}")
    elif msg_type == "DHCPOFFER":
        body = (f"DHCPOFFER on {client_ip} to {client_mac} ({client_hostname}) "
                f"via {via} relay {via} lease-duration {lease} "
                f"offered-duration {lease} uid {uid}")
    elif msg_type == "DHCPREQUEST":
        # SELECTING: names the server whose offer it accepted -> siaddr/target.ipv4.
        # RENEWING: unicast to the lease holder, no server id, tagged ': RENEW'
        # (the pack keys xdm.event.operation_sub_type off it).
        sid = "" if renewal else f" ({server_ip or member_ip})"
        tag = ": RENEW" if renewal else ""
        body = (f"DHCPREQUEST for {client_ip}{sid} from {client_mac} "
                f"({client_hostname}) via {via} TransID {trans_hex} uid {uid}{tag}")
    elif msg_type == "DHCPACK":
        body = (f"DHCPACK on {client_ip} to {client_mac} ({client_hostname}) "
                f"via {via} TransID {trans_hex} lease-duration {lease} uid {uid}")
    elif msg_type == "DHCPNAK":
        body = f"DHCPNAK on {client_ip} to {client_mac} via {via}"
    elif msg_type == "DHCPRELEASE":
        body = (f"DHCPRELEASE of {client_ip} from {client_mac} "
                f"({client_hostname}) via {via} (found)")
    else:
        return None
    return _dhcpd(config, client_mac, body)


# Audit log builder

def _admin_ip(config, admin):
    """An admin works from one management workstation, not a random host on a
    random subnet per event (which is what an audit trail of one admin logging
    in from 40 addresses a day would look like -- a credential-sharing signal)."""
    nets = config.get('internal_networks', ['192.168.1.0/24'])
    d = int(hashlib.sha256(admin.encode()).hexdigest(), 16)
    return resolver._stable_host(nets[d % len(nets)], admin) or "192.168.1.50"


def _build_audit_log(config, event_type=None, via="GUI", admin_user=None, hostname=None):
    r"""
    Builds an httpd audit log in the real Infoblox format.

    Documented shapes:
      Login:   [admin]: Login_Allowed - - to=AdminConnector ip=1.1.1.1 auth=Local group=GridAdmins apparently_via=GUI
      Console: [admin]: Login_Allowed - - to=Serial\040Console apparently_via=Direct auth=Local group=.admin-group
      Denied:  [admin]: Login_Denied - - to=Serial\040Console apparently_via=Direct error=invalid\040login\040or\040password
      First:   [user]: First_Login - - to=AdminConnector ip=10.0.0.2 auth=LOCAL group=admin-group apparently_via=GUI\040first\040login
      Object:  [admin]: Modified(PUT) v2.2/zone_auth {"comment":"testing auditlogs"} 1.930 AuthZone foo.com DnsView=default: Changed comment:NULL->"testing auditlogs"

    Routed to infoblox_infoblox_raw; the pack sets xdm.event.type = "AUDIT" and
    maps the admin to xdm.source.user.username.
    """
    infoblox_conf = config.get(CONFIG_KEY, {})
    # The Grid Master serves the GUI and WAPI; an admin session stays on it.
    hostname      = hostname or _members(config)[0][0]
    admin_users   = infoblox_conf.get('admin_users', ['infoadmin', 'noc-user', 'admin'])
    admin_user    = admin_user or random.choice(admin_users)

    if event_type is None:
        event_type = random.choices(_AUDIT_LOGIN_TYPES, weights=[60, 10, 30], k=1)[0]

    source_ip = _admin_ip(config, admin_user)
    connector = "RESTAPIGateway" if via == "API" else "AdminConnector"
    head      = (f"{_get_syslog_timestamp()} {hostname} httpd: "
                 f"{_get_audit_body_timestamp()} [{admin_user}]:")

    if event_type in _AUDIT_OBJECT_TYPES:
        wapi_path, obj_type = random.choice(_AUDIT_WAPI_OBJECTS)
        method   = _AUDIT_WAPI_METHOD[event_type]
        wapi_ver = random.choice(["v2.6", "v2.9", "v2.11", "v2.12"])
        duration = f"{random.uniform(0.2, 3.5):.3f}"
        view     = random.choice(infoblox_conf.get('dns_views') or ['default'])
        ad       = resolver.internal_domain(config)
        if obj_type in ("Network", "Range", "FixedAddress"):
            obj_name = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
            view_kv  = f"NetworkView={random.choice(infoblox_conf.get('network_views') or ['default'])}"
        else:
            obj_name = f"{random.choice(['app', 'svc', 'web', 'db', 'print'])}{random.randint(1, 99)}.{ad}"
            view_kv  = f"DnsView={view}"
        if event_type == "Created":
            body, detail = '{"name":"%s"}' % obj_name, f': Set name="{obj_name}"'
        elif event_type == "Modified":
            comment = random.choice(["decommission pending", "owner updated",
                                     "ticket CHG0041", "ttl review"])
            body, detail = '{"comment":"%s"}' % comment, f': Changed comment:NULL->"{comment}"'
        else:
            body, detail = "{}", " exclude_subobj=False"
        return (f"{_AUDIT_PRI}{head} {event_type}({method}) {wapi_ver}/{wapi_path} "
                f"{body} {duration} {obj_type} {obj_name} {view_kv}{detail}")

    if event_type == "Console_Login":
        # Out-of-band serial console: no client IP exists. Verbatim doc shape.
        return (f"{_AUDIT_PRI}{head} Login_Allowed - - to=Serial\\040Console "
                f"apparently_via=Direct auth=Local group=.admin-group")

    if event_type == "Login_Denied":
        err = random.choice(_AUDIT_LOGIN_ERRORS).replace(" ", "\\040")
        return (f"{_AUDIT_PRI}{head} {event_type} - - "
                f"to={connector} ip={source_ip} auth={random.choice(_AUDIT_AUTH_TYPES)} "
                f"error={err} apparently_via={via}")

    if event_type == "Logout":
        return (f"{_AUDIT_PRI}{head} {event_type} - - "
                f"to={connector} ip={source_ip} apparently_via={via}")

    if event_type == "First_Login":
        return (f"{_AUDIT_PRI}{head} First_Login - - to=AdminConnector ip={source_ip} "
                f"auth=LOCAL group={random.choice(_AUDIT_GROUPS)} apparently_via=GUI\\040first\\040login")

    return (f"{_AUDIT_PRI}{head} {event_type} - - "
            f"to={connector} ip={source_ip} auth={random.choice(_AUDIT_AUTH_TYPES)} "
            f"group={random.choice(_AUDIT_GROUPS)} apparently_via={via}")


# CEF threat log builders

def _build_threat_cef_log(config, client_ip, client_port, domain, threat_category,
                          action="DROP", hit_count=1, hostname=None, dns_server_ip=None,
                          pid=None):
    """
    Builds an Infoblox NIOS threat-protect-log CEF event.

    Documented format (Infoblox "Monitoring through Syslog"), rendered as the
    appliance writes it to its LOCAL log file:
    2020-12-21T22:47:37-08:00 daemon ibflex2.com threat-protect-log[12674]: err CEF:0|Infoblox|NIOS Threat|8.5.2-408818|120601943|Potential DDoS related domain: phackt.com|7|src=10.120.20.93 spt=42236 dst=10.35.139.5 dpt=53 act="DROP" cat="Potential DDoS related Domains" nat=0 nfpt=0 nlpt=0 fqdn=phackt.com hit_count=1

    We emit the ON-THE-WIRE form instead: RFC 3164 PRI + timestamp + host +
    process[pid], which is what NIOS forwards to an external syslog server and
    what the Elastic/Splunk NIOS parsers are written against:
    <27>Sep 18 22:03:05 infoblox-dc1-01 threat-protect-log[12674]: CEF:0|Infoblox|NIOS Threat|...

    That change is why this function exists in its current shape. Measured
    in-tenant 2026-09-18 over 7 days, with the local-file rendering above:

        rows with a <PRI> header : 443,955   ->  303,940 carried xdm.source.ipv4
        rows without one         :     998   ->        0 carried ANY XDM field

    All 998 were these CEF events. XSIAM set xdm.event.type = "Threat" off a raw
    substring match and dropped every field after it -- src, dst, act, cat, fqdn
    and hit_count all landed nowhere. The facility/severity the doc spells out in
    words ("daemon", "err") is exactly what a PRI encodes, so moving it into the
    PRI loses nothing and makes the event parseable.

    Routed to infoblox_infoblox_raw (there is no infoblox_threat_raw).
    """
    infoblox_conf  = config.get(CONFIG_KEY, {})
    version        = infoblox_conf.get('nios_version', _NIOS_VERSION)
    if hostname is None or dns_server_ip is None:
        h, s = _appliance(config, client_ip)
        hostname, dns_server_ip = hostname or h, dns_server_ip or s
    pid = pid or _pid(hostname, "threat-protect-log")

    # Severity, SID and the event name are all properties of the RULE that
    # matched, so they are looked up per category rather than rolled per event.
    severity, sig_id, rule_msg = _THREAT_RULES.get(
        threat_category, (7, 130100999, f"{threat_category} domain"))
    pri = _CEF_PRI.get(severity, "<27>")

    cef_header = (f"CEF:0|Infoblox|NIOS Threat|{version}|{sig_id}|"
                  f"{rule_msg}: {domain}|{severity}|")
    cef_ext    = (f"src={client_ip} spt={client_port} dst={dns_server_ip} dpt=53 "
                  f"act=\"{action}\" cat=\"{threat_category}\" "
                  f"nat=0 nfpt=0 nlpt=0 fqdn={domain} hit_count={hit_count}")

    return (f"{pri}{_get_syslog_timestamp()} {hostname} "
            f"threat-protect-log[{pid}]: {cef_header}{cef_ext}")


def _rpz_record(trigger, domain, zone, client_ip=None, answer_ip=None):
    """The RPZ *record* that matched -- the value after 'via' in the RPZ msg field.

    It is the trigger encoded as a name inside the policy zone, not the zone
    itself. Infoblox's own samples show 'via passthru.com.rpz_1.com' and
    'via nxd1.com.rpz1.com': the queried name prefixed onto the zone. We used to
    emit the bare zone ('via bloxone-rpz-malware'), which loses which rule fired.

    Each trigger type has its own namespace inside the zone, per the RPZ spec
    (RFC-draft / BIND): an address trigger is the reversed address with its
    prefix length under .rpz-ip, a client trigger under .rpz-client-ip, and a
    nameserver-name trigger under .rpz-nsdname.
    """
    if trigger == "IP" and answer_ip:
        return f"32.{'.'.join(reversed(answer_ip.split('.')))}.rpz-ip.{zone}"
    if trigger == "CLIENT-IP" and client_ip:
        return f"32.{'.'.join(reversed(client_ip.split('.')))}.rpz-client-ip.{zone}"
    if trigger == "NSDNAME":
        return f"ns1.{domain}.rpz-nsdname.{zone}"
    return f"{domain}.{zone}"


def _build_rpz_cef_log(config, client_ip, domain, rpz_type="QNAME", rpz_action="NXDOMAIN",
                       q_type="A", client_port=None, dns_server_ip=None, hostname=None,
                       view=None, answer_ip=None, pid=None):
    """
    Builds an Infoblox RPZ (Response Policy Zone) CEF event from named.

    NIOS 9.0 documented form (ISO timestamp, facility word, host, named[pid]):
    2018-04-20T09:43:21+00:00 daemon infoblox.localdomain named[14792]: info CEF:0|Infoblox|NIOS|8.3.0-369415|RPZ-QNAME|Local-Data|7|app=DNS dst=10.34.173.11 src=10.120.20.28 spt=52240 view=_default qtype=A msg="rpz QNAME Local-Data rewrite a_rec [A] via a_rec.local.com" ... CAT=RPZ

    On-the-wire form (what NIOS forwards to a syslog server, and what the Elastic
    NIOS parser is written against) -- this is what we emit:
    <30>Mar 11 23:51:31 infoblox.localdomain named[28468]: CEF:0|Infoblox|NIOS|8.6.2-49634|RPZ-QNAME|NXDOMAIN|7|app=DNS dst=192.168.0.1 src=192.168.0.1 spt=51424 view=_default qtype=A msg="rpz QNAME NXDOMAIN rewrite nxd1.com [A] via nxd1.com.rpz1.com" CAT=RPZ

    Three things were wrong before 2026-09-18:

      1. the header was 'daemon info rpz:' -- the NIOS 6.12 rendering, with no
         hostname and no pid, while we advertise version 9.0.3. Current NIOS logs
         RPZ from named[pid] like every other DNS event. It also carried no PRI,
         so XSIAM modelled none of it (see _build_threat_cef_log for the counts).
      2. 'via' named the bare policy zone instead of the record that matched.
      3. the trailing CAT=RPZ was missing.

    Routed to infoblox_infoblox_raw.
    """
    infoblox_conf = config.get(CONFIG_KEY, {})
    version       = infoblox_conf.get('nios_version', _NIOS_VERSION)
    rpz_zone      = random.choice(infoblox_conf.get('rpz_zones', ['rpz.infoblox.internal']))

    # These four identify the appliance and the client transaction. They are
    # passed in by the caller so the CEF event matches the named query log it
    # belongs to -- they used to be re-rolled here, so the RPZ hit reported a
    # different DNS server and a different source port than the query that
    # triggered it, and the two could not be joined.
    if client_port is None:
        client_port = random.randint(49152, 65535)
    if hostname is None or dns_server_ip is None:
        h, s = _appliance(config, client_ip)
        hostname, dns_server_ip = hostname or h, dns_server_ip or s
    if view is None:
        view = random.choice(infoblox_conf.get('dns_views') or ['_default'])
    pid = pid or _pid(hostname, "named")

    record  = _rpz_record(rpz_type, domain, rpz_zone, client_ip, answer_ip)
    rpz_msg = f"rpz {rpz_type} {rpz_action} rewrite {domain} [{q_type}] via {record}"

    cef_header = f"CEF:0|Infoblox|NIOS|{version}|RPZ-{rpz_type}|{rpz_action}|7|"
    cef_ext    = (f"app=DNS dst={dns_server_ip} src={client_ip} spt={client_port} "
                  f"view={view} qtype={q_type} msg=\"{rpz_msg}\" CAT=RPZ")

    return f"{_DNS_PRI}{_get_syslog_timestamp()} {hostname} named[{pid}]: {cef_header}{cef_ext}"


# DHCP client detail helper

def _get_random_dhcp_client_details(config, session_context=None):
    """Returns (client_ip, client_mac, client_hostname, transaction_id, relay_ip)."""
    client_ip       = "192.168.1.100"
    client_hostname = "UNKNOWN-HOST"
    device_type = os_type = None

    if session_context:
        user_info = get_random_user(session_context, preferred_device_type='workstation')
        if user_info:
            client_ip       = user_info['ip'] or client_ip
            client_hostname = user_info['hostname'] or client_hostname
            device_type     = user_info.get('device_type')
            os_type         = user_info.get('os_type')
    else:
        infoblox_conf = config.get(CONFIG_KEY, {})
        user_ip_map   = infoblox_conf.get('user_ip_map', {})
        device_map    = infoblox_conf.get('device_map', {})
        if user_ip_map and device_map:
            username        = random.choice(list(user_ip_map.keys()))
            client_ip       = user_ip_map.get(username, client_ip)
            client_hostname = device_map.get(username, {}).get('hostname', client_hostname)

    # One stable MAC per host (the key lease history hangs off), with a vendor
    # prefix that fits the device -- see session_utils.host_mac.
    client_mac     = host_mac(client_hostname, device_type, os_type)
    transaction_id = hex(random.randint(0, 2**32))
    # The relay agent is the client's own default gateway.
    relay_ip = _relay_for(client_ip)
    return client_ip, client_mac, client_hostname, transaction_id, relay_ip


def _dhcp_server_ip(config, key=None):
    """The appliance serving DHCP for `key` -- the same member that serves its DNS."""
    return _appliance(config, key)[1]


def _relay_for(client_ip):
    """The relay agent (gateway) address for a client: .1 on the client's /24."""
    try:
        o = str(client_ip).split(".")
        return f"{o[0]}.{o[1]}.{o[2]}.1"
    except Exception:
        return "192.168.1.1"


def _answer_for(domain, default=None):
    """The A-record answer for `domain` -- resolver.answer_for(), the same call
    every firewall uses for its destination, so the DNS answer IS the connection
    target. Pinned curated/internal names come from the table; any other name
    gets a stable address from the ambient external pool, keyed by the name.
    (Until 2026-09-22 unknown names answered from TEST-NET-2, which no firewall
    ever connected to, so long-tail lookups could never join.)"""
    if default and not resolver.resolve_one(domain):
        return default
    return resolver.answer_for(domain)


def _reverse_map(config, session_context):
    """{ip: fqdn} for every host that really exists: the session's devices on
    the AD suffix, plus the resolver's internal servers. PTR answers come from
    here, so a reverse lookup names the same host every other module logs --
    it used to invent 'host-10-0-20-74.internal' for any address."""
    ad = resolver.internal_domain(config)
    out = {}
    for prof in (session_context or {}).values():
        for dev in (prof.get('active_devices') or {}).values():
            if dev.get('ip') and dev.get('hostname'):
                out[dev['ip']] = f"{dev['hostname'].lower()}.{ad}"
    for name in resolver.known_domains():
        if name.endswith(ad):
            for ip in resolver.resolve(name):
                if ip not in out and resolver.reverse(ip):
                    out[ip] = resolver.reverse(ip)
    return out


# CNAME targets and SPF policies are properties of the DOMAIN, not of the query.
def _cname_for(domain):
    d = hashlib.sha256(domain.encode()).digest()
    return f"{domain.split('.')[0]}-{d[0]:02x}{d[1]:02x}.{_CDN_DOMAINS[d[2] % len(_CDN_DOMAINS)]}"


_SPF_INCLUDES = ["_spf.google.com", "spf.protection.outlook.com", "_spf.salesforce.com",
                 "mail.zendesk.com", "servers.mcsv.net", "sendgrid.net", "amazonses.com"]


def _spf_for(domain):
    d = hashlib.sha256(domain.encode()).digest()
    inc = sorted({_SPF_INCLUDES[d[0] % 7], _SPF_INCLUDES[d[1] % 7]})
    return '"v=spf1 ' + " ".join(f"include:{i}" for i in inc) + (' -all"' if d[2] % 3 else ' ~all"')


# Default benign mix, per 10,000 events. DNS is the overwhelming majority of what
# a NIOS grid logs; DHCP is a few percent (workstations renew at T1 = half the
# lease); admin audit is a few dozen events a day. The previous mix put audit at
# 15% and DHCP at 20% -- about 12,000 admin actions a day from three admins,
# which is itself an anomaly that buries any real admin-abuse signal.
_DEFAULT_BENIGN_MIX = [
    ("dns_a", 4000), ("dns_aaaa", 1400), ("dns_internal", 1800), ("dns_cname", 700),
    ("dns_srv", 300), ("dns_ptr", 250), ("dns_ipv6", 300), ("dns_windows_probe", 250),
    ("dns_nxdomain_benign", 250), ("dns_search_suffix", 150), ("dns_txt", 60),
    ("dns_mx", 30), ("dns_refused", 20), ("dns_lame", 15), ("dns_ops", 25), ("dns_chaos", 3),
    ("dhcp_renewal", 200), ("dhcp_session", 30), ("dhcp_release", 15), ("dhcp_inform", 15),
    ("dhcp_expire", 10), ("dhcp_leasequery", 10), ("dhcp_nak", 4), ("dhcp_decline", 2),
    ("audit", 4), ("audit_api", 1),
]


# Benign log generator

def _generate_benign_log(config, session_context=None):
    """Realistic benign DNS, DHCP and audit activity for a NIOS grid.

    Beyond the usual query types this covers every event family the Infoblox
    content pack models, so every XDM field it maps can be reached:
      DNS query section     IPv4 + IPv6 clients, 'query failed (RCODE)'
      DNS response section  A/AAAA/CNAME/MX/TXT/PTR/SRV, authoritative flag, IPv6 answers
      DHCP section          DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE/INFORM/DECLINE/
                            EXPIRE/LEASEQUERY, RENEW, relay vs local interface
      Audit section         GUI/API/console logins, WAPI object changes
      Fallback section      update:/xfer-out:/notify:/general:/rpz:/lame-servers:
    """
    infoblox_conf = config.get(CONFIG_KEY, {})
    benign_events = infoblox_conf.get('event_mix', {}).get('benign', [])
    if benign_events:
        population = [e['event']  for e in benign_events]
        weights    = [e['weight'] for e in benign_events]
    else:
        population = [e for e, _ in _DEFAULT_BENIGN_MIX]
        weights    = [w for _, w in _DEFAULT_BENIGN_MIX]
    log_type = random.choices(population=population, weights=weights, k=1)[0]

    # Query the names the rest of the estate actually CONNECTS to (the resolver's
    # curated set) plus config benign_domains, so the DNS->connection join holds.
    benign_domains = list(config.get('benign_domains',
                                     ["www.google.com", "microsoft.com", "office365.com"]))
    ad = resolver.internal_domain(config)
    try:
        benign_domains = sorted(set(benign_domains) | {
            d for d in resolver.known_domains() if not d.endswith(ad)})
    except Exception:
        pass

    internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
    _user = (get_random_user(session_context, preferred_device_type='workstation')
             if session_context else None)
    if _user and _user.get("ip"):
        client_ip = _user["ip"]
        dns_key   = _user["username"]
        client_mac = host_mac(_user.get("hostname"), _user.get("device_type"), _user.get("os_type"))
    else:
        client_ip  = rand_ip_from_network(ip_network(internal_net))
        dns_key    = client_ip
        client_mac = host_mac(client_ip)

    # ---- DNS ----

    if log_type == "dns_a":
        domain = weighted_dns_domain(dns_key, benign_domains)
        return _build_dns_pair(config, client_ip, domain, "A", "NOERROR",
                               [f"{domain}. 60 IN A {_answer_for(domain)}"])

    if log_type == "dns_aaaa":
        # Windows asks AAAA alongside A. External names answer with a stable v6
        # address; internal hosts are v4-only in DNS, so they answer NOERROR with
        # no records (NODATA), authoritatively.
        if random.random() < 0.25:
            name = random.choice(infoblox_conf.get('internal_domains') or [ad])
            return _build_dns_pair(config, client_ip, name, "AAAA", "NOERROR")
        domain = weighted_dns_domain(dns_key, benign_domains)
        return _build_dns_pair(config, client_ip, domain, "AAAA", "NOERROR",
                               [f"{domain}. 300 IN AAAA {_aaaa_for(domain)}"])

    if log_type == "dns_ipv6":
        # The same host asking over its IPv6 address (SLAAC, EUI-64 from its MAC).
        domain = weighted_dns_domain(dns_key, benign_domains)
        q = random.choice(["A", "AAAA"])
        rr = (f"{domain}. 60 IN A {_answer_for(domain)}" if q == "A"
              else f"{domain}. 300 IN AAAA {_aaaa_for(domain)}")
        return _build_dns_pair(config, client_ip, domain, q, "NOERROR", [rr],
                               client_ipv6=_client_ipv6(client_ip, client_mac))

    if log_type == "dns_cname":
        domain = weighted_dns_domain(dns_key, benign_domains)
        alias  = _cname_for(domain)
        return _build_dns_pair(config, client_ip, domain, "A", "NOERROR", [
            f"{domain}. 300 IN CNAME {alias}.",
            f"{alias}. 60 IN A {_answer_for(domain)}",
        ])

    if log_type == "dns_mx":
        domain = weighted_dns_domain(dns_key, benign_domains)
        return _build_dns_pair(config, client_ip, domain, "MX", "NOERROR",
                               [f"{domain}. 3600 IN MX 10 mail.{domain}."])

    if log_type == "dns_txt":
        domain = weighted_dns_domain(dns_key, benign_domains)
        return _build_dns_pair(config, client_ip, domain, "TXT", "NOERROR",
                               [f"{domain}. 3600 IN TXT {_spf_for(domain)}"])

    if log_type == "dns_ptr":
        # Reverse lookups name hosts that exist. A miss is an authoritative NXDOMAIN.
        rmap = _reverse_map(config, session_context)
        if rmap and random.random() < 0.85:
            ip = random.choice(list(rmap))
            return _build_dns_pair(config, client_ip, _ptr_name(ip), "PTR", "NOERROR",
                                   [f"{_ptr_name(ip)}. 3600 IN PTR {rmap[ip]}."])
        ip = rand_ip_from_network(ip_network(internal_net))
        if ip in rmap:
            return _build_dns_pair(config, client_ip, _ptr_name(ip), "PTR", "NOERROR",
                                   [f"{_ptr_name(ip)}. 3600 IN PTR {rmap[ip]}."])
        return _build_dns_pair(config, client_ip, _ptr_name(ip), "PTR", "NXDOMAIN")

    if log_type == "dns_srv":
        svc = random.choice(_SRV_SERVICES)
        name = f"{svc}.{ad}"
        port = {"_ldap._tcp": 389, "_kerberos._tcp": 88, "_kerberos._udp": 88,
                "_sip._tcp": 5060, "_sip._udp": 5060, "_sipfederationtls._tcp": 5061,
                "_http._tcp": 80, "_https._tcp": 443}.get(svc, 443)
        # Both DCs answer every service record, as AD registers them.
        return _build_dns_pair(config, client_ip, name, "SRV", "NOERROR", [
            f"{name}. 600 IN SRV 0 100 {port} dc01.{ad}.",
            f"{name}. 600 IN SRV 0 100 {port} dc02.{ad}.",
        ])

    if log_type == "dns_internal":
        internal_domains = infoblox_conf.get('internal_domains') or [ad]
        domain  = random.choice(internal_domains)
        resp_ip = _answer_for(domain) or rand_ip_from_network(ip_network(internal_net))
        return _build_dns_pair(config, client_ip, domain, "A", "NOERROR",
                               [f"{domain}. 300 IN A {resp_ip}"])

    if log_type == "dns_windows_probe":
        # What every Windows host does unprompted: connectivity checks, DC
        # locator SRV lookups, time sync and a WPAD probe that fails.
        probe = random.choices(["ncsi", "dc_locator", "time", "wpad"],
                               weights=[40, 30, 20, 10], k=1)[0]
        if probe == "ncsi":
            d = "www.msftconnecttest.com"
            return _build_dns_pair(config, client_ip, d, "A", "NOERROR",
                                   [f"{d}. 60 IN A {_answer_for(d)}"])
        if probe == "time":
            d = "time.windows.com"
            return _build_dns_pair(config, client_ip, d, "A", "NOERROR",
                                   [f"{d}. 300 IN A {_answer_for(d)}"])
        if probe == "wpad":
            return _build_dns_pair(config, client_ip, f"wpad.{ad}", "A", "NXDOMAIN")
        name = f"_ldap._tcp.dc._msdcs.{ad}"
        return _build_dns_pair(config, client_ip, name, "SRV", "NOERROR", [
            f"{name}. 600 IN SRV 0 100 389 dc01.{ad}.",
            f"{name}. 600 IN SRV 0 100 389 dc02.{ad}.",
        ])

    if log_type == "dns_search_suffix":
        # The DNS client appends its search suffix before trying the bare name:
        # 'zoom.us.examplecorp.local' fails authoritatively, then the real name
        # resolves. This is where most benign NXDOMAINs come from.
        domain = weighted_dns_domain(dns_key, benign_domains)
        return (_build_dns_pair(config, client_ip, f"{domain}.{ad}", "A", "NXDOMAIN")
                + _build_dns_pair(config, client_ip, domain, "A", "NOERROR",
                                  [f"{domain}. 60 IN A {_answer_for(domain)}"]))

    if log_type == "dns_nxdomain_benign":
        stale = ['legacy', 'deprecated', 'old', 'test', 'dev', 'stg', 'intranet', 'portal']
        domain = f"{random.choice(stale)}.{weighted_dns_domain(dns_key, benign_domains)}"
        return _build_dns_pair(config, client_ip, domain, "A", "NXDOMAIN")

    if log_type == "dns_refused":
        # A client on the DMZ view, where recursion is disabled, asking for an
        # external name: BIND refuses and logs 'query failed (REFUSED)'.
        domain = weighted_dns_domain(dns_key, benign_domains)
        return _build_dns_pair(config, client_ip, domain, "A", "REFUSED", failed=True)

    if log_type == "dns_lame":
        # A long-tail domain whose delegated nameserver refuses us: the resolver
        # logs the lame server, then the client gets SERVFAIL.
        domain = weighted_dns_domain(dns_key, benign_domains)
        hostname, _ = _appliance(config, client_ip)
        ns_ip = _answer_for(f"ns1.{domain}")
        return ([_named_line(config, hostname,
                             f"lame-servers: connection refused resolving '{domain}/A/IN': {ns_ip}#53")]
                + _build_dns_pair(config, client_ip, domain, "A", "SERVFAIL", failed=True))

    if log_type == "dns_chaos":
        # The vulnerability scanner fingerprinting the resolver: a CHAOS-class TXT
        # query for version.bind / hostname.bind. NIOS hides the BIND version, so
        # the answer is REFUSED. The only query class other than IN we emit; the
        # pack maps it to xdm.network.dns.dns_question.class = 3.
        scanners = config.get('internal_servers') or ["10.0.10.50"]
        scanner  = scanners[int(hashlib.sha256(b"vuln-scanner").hexdigest(), 16) % len(scanners)]
        name     = random.choice(["version.bind", "hostname.bind", "id.server"])
        hostname, server = random.choice(_members(config))
        port = random.randint(49152, 65535)
        pid  = _pid(hostname, "named")
        q = (f"{_DNS_PRI}{_get_syslog_timestamp()} {hostname} named[{pid}]: "
             f"client @{_client_ptr(scanner, port)} {scanner}#{port} ({name}): "
             f"query: {name} CH TXT - ({server})")
        r = (f"{_DNS_PRI}{_get_syslog_timestamp()} {hostname} named[{pid}]: "
             f"client {scanner}#{port} UDP: query: {name} CH TXT response: REFUSED +")
        return [q, r]

    if log_type == "dns_ops":
        members  = _members(config)
        hostname, server = random.choice(members)
        serial = _zone_serial()
        op = random.choice(["load", "notify", "xfer", "xfer", "rpz", "dnssec"])
        if op == "load":
            zone = random.choice([ad, _reverse_zone(client_ip)])
            return [_named_line(config, hostname, f"general: zone {zone}/IN: loaded serial {serial}")]
        if op == "notify":
            return [_named_line(config, hostname, f"notify: zone {ad}/IN: sending notifies (serial {serial})")]
        if op == "dnssec":
            # The validating resolver rejecting a badly-signed external answer.
            domain = weighted_dns_domain(dns_key, benign_domains)
            return [_named_line(config, hostname,
                                f"dnssec: validating {domain}/A: no valid signature found")]
        if op == "rpz":
            zone = random.choice(infoblox_conf.get('rpz_zones') or ['rpz.infoblox.internal'])
            return [_named_line(config, hostname, f"rpz: {zone}: reload start"),
                    _named_line(config, hostname, f"rpz: {zone}: reload done")]
        # A secondary grid member pulling the zone: the authorised baseline that
        # makes an unauthorised transfer attempt stand out.
        peers = [m for m in members if m[0] != hostname] or members
        _, peer_ip = random.choice(peers)
        port = random.randint(1024, 65535)
        head = f"xfer-out: client @{_client_ptr(peer_ip, port)} {peer_ip}#{port} ({ad}): transfer of '{ad}/IN'"
        peer_name = _member_for_ip(config, peer_ip)
        recs = random.randint(180, 900)
        src  = f"xfer-in: transfer of '{ad}/IN' from {server}#53"
        return [_named_line(config, hostname, f"{head}: AXFR started (serial {serial})"),
                _named_line(config, hostname, f"{head}: AXFR ended"),
                # The same transfer as the secondary logs it. 'Transfer status:
                # success' is the one message the pack's fallback section maps to
                # xdm.event.outcome = SUCCESS.
                _named_line(config, peer_name, f"{src}: Transfer status: success"),
                _named_line(config, peer_name,
                            f"{src}: Transfer completed: 1 messages, {recs} records, "
                            f"{recs * 31} bytes, 0.00{random.randint(2, 9)} secs "
                            f"(serial {serial})")]

    # ---- DHCP ----

    if log_type in ("dhcp_session", "dhcp_renewal", "dhcp_release", "dhcp_nak",
                    "dhcp_decline", "dhcp_expire", "dhcp_leasequery"):
        client_ip, client_mac, client_hostname, txid, relay_ip = \
            _get_random_dhcp_client_details(config, session_context)
        if not client_ip:
            return None
        fqdn = f"{str(client_hostname).lower()}.{ad}"

        if log_type == "dhcp_session":
            return [
                _build_dhcp_log(config, "DHCPDISCOVER", "255.255.255.255", client_mac, client_hostname, txid, relay_ip),
                _build_dhcp_log(config, "DHCPOFFER",    client_ip, client_mac, client_hostname, txid, relay_ip),
                _build_dhcp_log(config, "DHCPREQUEST",  client_ip, client_mac, client_hostname, txid, relay_ip),
                _build_dhcp_log(config, "DHCPACK",      client_ip, client_mac, client_hostname, txid, relay_ip),
            ] + _build_ddns_update(config, client_mac, fqdn, client_ip)

        if log_type == "dhcp_renewal":
            return [
                _build_dhcp_log(config, "DHCPREQUEST", client_ip, client_mac, client_hostname, txid, relay_ip,
                                renewal=True),
                _build_dhcp_log(config, "DHCPACK",     client_ip, client_mac, client_hostname, txid, relay_ip),
            ]

        if log_type == "dhcp_release":
            return ([_build_dhcp_log(config, "DHCPRELEASE", client_ip, client_mac, client_hostname, txid, relay_ip)]
                    + _build_ddns_update(config, client_mac, fqdn, client_ip, delete=True))

        if log_type == "dhcp_nak":
            # The client asks for the lease it held on another segment.
            invalid_ip = str(ip_network(internal_net).broadcast_address - 1)
            return [_build_dhcp_log(config, "DHCPNAK", invalid_ip, client_mac, client_hostname, txid, relay_ip)]

        if log_type == "dhcp_decline":
            # The client ARP-probed the offered address, found it in use, and
            # declined it; dhcpd abandons the address.
            return [
                _build_dhcp_log(config, "DHCPOFFER", client_ip, client_mac, client_hostname, txid, relay_ip),
                _dhcpd(config, client_mac, f"DHCPDECLINE of {client_ip} from {client_mac} "
                                           f"({client_hostname}) via {relay_ip}: abandoned"),
                _dhcpd(config, client_mac, f"Abandoning IP address {client_ip}: declined."),
            ]

        if log_type == "dhcp_expire":
            # A device that left without releasing: the lease times out and its
            # DNS records are removed.
            return ([_dhcpd(config, client_mac, f"DHCPEXPIRE on {client_ip} to {client_mac}")]
                    + _build_ddns_update(config, client_mac, fqdn, client_ip, delete=True))

        # dhcp_leasequery: an access switch doing DHCP snooping asks which client
        # holds an address (RFC 4388) and is told it is active.
        # Mostly the address is held; sometimes the switch asks about one that
        # is free (UNASSIGNED) or outside any scope the server owns (UNKNOWN) --
        # the two replies the pack scores as failed outcomes.
        reply = random.choices(["active", "unassigned", "unknown"], weights=[80, 15, 5], k=1)[0]
        if reply == "active":
            ans = f"DHCPLEASEACTIVE to {relay_ip} for {client_ip} ({client_mac})"
        elif reply == "unassigned":
            client_ip = str(IPv4Address(int(IPv4Address(relay_ip)) + random.randint(200, 250)))
            ans = f"DHCPLEASEUNASSIGNED to {relay_ip} for {client_ip}"
        else:
            client_ip = f"{relay_ip.rsplit('.', 2)[0]}.{random.randint(240, 254)}.{random.randint(2, 250)}"
            ans = f"DHCPLEASEUNKNOWN to {relay_ip} for {client_ip}"
        return [
            _dhcpd(config, client_mac, f"DHCPLEASEQUERY from {relay_ip} for {client_ip}"),
            _dhcpd(config, client_mac, ans),
        ]

    if log_type == "dhcp_inform":
        # Hosts with static addresses asking only for options. Servers sit behind
        # a relay; devices on the appliance's own segment arrive on its interface
        # directly ('via eth1'), which is what reaches xdm.source.interface.
        servers = config.get('internal_servers') or ["10.0.10.50"]
        if random.random() < 0.7:
            ip   = random.choice(servers)
            via  = _relay_for(ip)
            name = (resolver.reverse(ip) or f"srv-{ip.replace('.', '-')}").split(".")[0]
            mac  = host_mac(name, "server")
        else:
            _, member_ip = random.choice(_members(config))
            ip   = f"{member_ip.rsplit('.', 1)[0]}.{random.randint(20, 60)}"
            via  = "eth1"
            mac  = host_mac(f"PRN-{ip}", "workstation")
        return [
            _dhcpd(config, mac, f"DHCPINFORM from {ip} via {via}"),
            _dhcpd(config, mac, f"DHCPACK to {ip} ({mac}) via {via}"),
        ]

    # ---- Audit ----

    if log_type == "audit":
        ev = random.choices(
            _AUDIT_LOGIN_TYPES + _AUDIT_OBJECT_TYPES + ["First_Login", "Console_Login"],
            weights=[34, 6, 20, 14, 20, 6, 1, 1], k=1)[0]
        return [_build_audit_log(config, event_type=ev)]

    if log_type == "audit_api":
        # WAPI automation authenticates, then changes an object.
        api_event = random.choices(_AUDIT_OBJECT_TYPES, weights=[30, 50, 20], k=1)[0]
        # One session: the same account, on the same appliance, logs in and acts.
        admin = random.choice(infoblox_conf.get('admin_users', ['infoadmin']))
        gm    = _members(config)[0][0]
        return [_build_audit_log(config, "Login_Allowed", "API", admin, gm),
                _build_audit_log(config, api_event, "API", admin, gm)]

    return None


# Threat generators

def _generate_c2_beacon(config, client_ip=None, session_context=None, domain=None,
                        answer_ip=None):
    """
    Generates a C2 beacon: DNS query to a known-malicious domain → NXDOMAIN.

    Hunt signals: xdm.source.ip + xdm.target.hostname (known-bad) +
                  xdm.network.dns.dns_response_code = "NXDOMAIN"
                  Repeated queries to same bad domain from one source IP.

    `domain`: when supplied (an orchestrated/XDR-triggered event pins the same C2
    domain the endpoint technique uses), the beacon queries that domain instead of
    a random malicious one. The log format is identical — only the queried name
    changes. Ambient generation passes no domain, so its behavior is unchanged.
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    # threat_domains.pick keeps the curated names in circulation for manual hunts
    # and generates the rest, so a long run does not beacon to the same 25 hosts.
    # family "c2" guarantees the "command-control" substring the DNS C2 Beacon
    # correlation rule matches.
    domain  = domain or threat_domains.pick(config, family="c2")
    beacons = random.randint(12, 18)   # rule fires on >=10 queries to one domain from one IP
    # answer_ip: the beacon RESOLVES (the implant reaches its C2) and every query
    # answers with the address the firewall session goes to. Without it the beacon
    # is a blocked lookup (NXDOMAIN), which is the RPZ story, not the C2 one.
    if answer_ip:
        logs = []
        for _ in range(beacons):
            logs += _build_dns_pair(config, client_ip, domain, "A", "NOERROR",
                                    [f"{domain}. 60 IN A {answer_ip}"])
        return logs
    print(f"    - Infoblox Module simulating: C2 Beacon ({beacons} queries to {domain}) from {client_ip}")
    logs = []
    for _ in range(beacons):
        logs.extend(_build_dns_pair(config, client_ip, domain, "A", "NXDOMAIN"))
    return logs


def _generate_dns_tunnel(config, client_ip=None, session_context=None):
    """
    Generates a DNS tunneling (TXT exfiltration) event.

    Pattern: 16–48 char alphanumeric subdomain under a base domain, TXT type → SERVFAIL.
    Hunt signals: q_type=TXT + len(domain) > 50 + SERVFAIL + high volume of unique subdomains.
    Normal enterprise TXT rate is very low (2% of DNS) — TXT storms are highly anomalous.
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    base_domain = threat_domains.pick(config, pool_key="dga_domains")
    txt_count   = random.randint(18, 26)   # rule fires on >=15 TXT queries from one IP
    print(f"    - Infoblox Module simulating: DNS Tunneling ({txt_count} TXT queries) from {client_ip}")
    logs = []
    for _ in range(txt_count):
        subdomain = ''.join(random.choices(_DGA_CHARSET, k=random.randint(16, 48)))
        domain    = f"{subdomain}.{base_domain}"
        logs.extend(_build_dns_pair(config, client_ip, domain, "TXT", "SERVFAIL"))
    return logs


def _generate_rpz_block(config, client_ip=None, session_context=None):
    """
    Generates an RPZ (Response Policy Zone) block event: DNS query + RPZ CEF log.

    Hunt signals: CEF msg field contains 'rpz QNAME NXDOMAIN rewrite';
                  xdm.observer.action = block; correlate src IP with firewall datasets.
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    infoblox_conf = config.get(CONFIG_KEY, {})
    # A base per block, not one base for the burst: the label was already unique
    # per query, but 50-65 blocks all sharing one registrable domain is a single
    # TI hit, not a storm of distinct blocked infrastructure.
    _base = lambda: threat_domains.pick(config)
    blocks = random.randint(50, 65)   # rule needs >=30 blocks; extra margin for syslog burst loss

    # One appliance handles the client for the whole burst, and one view matched.
    # These were re-rolled inside each builder, so a single blocked query was
    # logged against two different DNS servers -- the named line said 10.2.1.2
    # and the RPZ CEF said dst=10.1.1.2 for the same event.
    hostname, dns_server_ip = _appliance(config, client_ip)
    view = random.choice(infoblox_conf.get('dns_views') or ['_default'])
    pid  = _pid(hostname, "named")

    print(f"    - Infoblox Module simulating: RPZ block storm ({blocks} blocks) from {client_ip}")
    logs = []
    for _ in range(blocks):
        rpz_type   = random.choices(_RPZ_TRIGGERS, weights=[70, 15, 8, 7], k=1)[0]
        rpz_action = random.choices(_RPZ_BLOCK_ACTIONS, weights=[75, 15, 10], k=1)[0]
        label  = ''.join(random.choices(_DGA_CHARSET, k=random.randint(8, 14)))   # unique blocked domain each time
        domain = f"{label}.{_base()}"
        # The client's source port is the key that ties the query to its RPZ
        # verdict; both logs are the same transaction, so both must carry it.
        client_port = random.randint(49152, 65535)
        # An IP-trigger rule matched on the address the answer WOULD have had,
        # so the record needs one -- from the rare pool, never a real address.
        answer_ip = rare_external_ip() if rpz_type == "IP" else None
        logs.append(_build_dns_query_log(config, client_ip, domain, "A",
                                        dns_server_ip=dns_server_ip, hostname=hostname,
                                        client_port=client_port, pid=pid))
        logs.append(_build_rpz_cef_log(config, client_ip, domain, rpz_type, rpz_action, "A",
                                       client_port=client_port, dns_server_ip=dns_server_ip,
                                       hostname=hostname, view=view, answer_ip=answer_ip,
                                       pid=pid))
    return logs


def _generate_threat_protect(config, client_ip=None, session_context=None):
    """
    Generates a single BloxOne Threat Protect CEF DROP event.

    Single event (no query/response pair — block happens before response).
    Hunt signals: xdm.alert.category ∈ {Malware,Phishing,C&C,Exploit Kit};
                  xdm.observer.action = DROP; correlate src IP with DHCP to identify device.
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    infoblox_conf = config.get(CONFIG_KEY, {})
    cats         = config.get('infoblox_threats', {}).get('threat_categories', _NIOS_THREAT_CATEGORIES)
    _base = lambda: threat_domains.pick(config)
    alerts = random.randint(36, 48)   # rule fires on >=30 alerts AND >=3 distinct categories from one src

    # One client is served by one appliance (see _generate_rpz_block).
    hostname, dns_server_ip = _appliance(config, client_ip)
    pid = _pid(hostname, "threat-protect-log")

    print(f"    - Infoblox Module simulating: Threat Protect DROP storm ({alerts} drops) from {client_ip}")
    logs = []
    # hit_count is the appliance's running count of hits on that rule for the
    # client within the aggregation window -- it climbs during a storm. It was
    # pinned at 1 on every event, which is the one value a repeated block cannot
    # keep producing, and it made the burst look like 40 unrelated single hits.
    hits = {}
    for i in range(alerts):
        category    = cats[i % len(cats)]   # cycle categories to guarantee >=3 distinct
        label       = ''.join(random.choices(_DGA_CHARSET, k=random.randint(8, 14)))
        domain      = f"{label}.{_base()}"
        client_port = random.randint(49152, 65535)
        hits[category] = hits.get(category, 0) + 1
        entry = _build_threat_cef_log(config, client_ip, client_port, domain, category,
                                      action="DROP", hit_count=hits[category],
                                      hostname=hostname, dns_server_ip=dns_server_ip, pid=pid)
        if entry:
            logs.extend(entry if isinstance(entry, list) else [entry])
    return logs


def _generate_nxdomain_storm(config, client_ip=None, session_context=None):
    """
    Generates a DGA NXDOMAIN storm: 20–50 query+NXDOMAIN pairs (40–100 total events) from one source IP.

    Hunt signals: high ratio of NXDOMAIN from single xdm.source.ip;
                  high-entropy subdomain labels in xdm.target.hostname;
                  all unique domains, same TLD, burst within seconds.
    Normal enterprise NXDOMAIN rate 2-6%; this produces 50-90% within the burst window.
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    # One base for the storm is correct -- a DGA family cycles labels under a
    # fixed seed domain -- but it must not be the same base every storm.
    tld       = threat_domains.pick(config, pool_key="dga_domains")
    count     = random.randint(95, 125)   # rule counts NXDOMAIN RESPONSES only (=pairs); needs >=80

    print(f"    - Infoblox Module simulating: NXDOMAIN Storm ({count} DGA pairs) from {client_ip}")
    logs = []
    for _ in range(count):
        dga_len    = random.randint(8, 15)
        dga_label  = ''.join(random.choices(_DGA_CHARSET, k=dga_len))
        domain     = f"{dga_label}.{tld}"
        logs.extend(_build_dns_pair(config, client_ip, domain, "A", "NXDOMAIN"))
    return logs


def _generate_dns_flood(config, client_ip=None, session_context=None):
    """
    Generates a DNS flood / reconnaissance sweep: 20–50 rapid queries from one source.

    Hunt signals: xdm.source.ip generates > 20 DNS events within 10-second window;
                  query mix includes unusual types (ANY, MX, NS);
                  queries span diverse domains (both benign and DGA-like).
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    benign_domains = config.get('benign_domains', ["www.google.com"])
    _dga_base      = lambda: threat_domains.pick(config, pool_key="dga_domains")
    q_types        = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    count          = random.randint(220, 260)   # rule fires on >=200 queries AND >=50 distinct

    print(f"    - Infoblox Module simulating: DNS Flood ({count} rapid queries) from {client_ip}")
    logs = []
    for i in range(count):
        q_type = random.choice(q_types)
        if i % 3 == 0:
            dga_len  = random.randint(5, 12)
            dga_lbl  = ''.join(random.choices(_DGA_CHARSET, k=dga_len))
            domain   = f"{dga_lbl}.{_dga_base()}"
        else:
            sub = ''.join(random.choices(_DGA_CHARSET, k=random.randint(4, 8)))
            domain = f"{sub}.{random.choice(benign_domains)}"
        logs.append(_build_dns_query_log(config, client_ip, domain, q_type))
    return logs


def _generate_dhcp_starvation(config, client_ip=None, session_context=None):
    """
    Generates a DHCP starvation attack: 20–50 DHCPDISCOVER from spoofed random MACs.

    Hunt signals: high volume of DISCOVER with all-different xdm.source.host.mac_address;
                  no corresponding DHCPACK following the DISCOVERs;
                  fully-random OUI octets (no organisational prefix pattern).
    Threshold reference: Infoblox default detection = ~1.2 DISCOVER/sec/MAC.
    """
    internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
    net_obj      = ip_network(internal_net)
    relay_ip     = str(net_obj.network_address + 1)
    count        = random.randint(160, 200)   # rule fires on >=150 DHCPDISCOVER

    print(f"    - Infoblox Module simulating: DHCP Starvation ({count} spoofed DISCOVERs)")
    logs = []
    # The scope's free pool. dhcpd OFFERs an address to each spoofed MAC until
    # the pool is gone, then logs 'no free leases' for every further DISCOVER --
    # the outcome that makes this an attack rather than noise. The pack reads the
    # scope out of 'network x/y' into xdm.target.subnet.
    scope  = str(ip_network(f"{relay_ip}/24", strict=False))
    pool   = int(count * random.uniform(0.45, 0.65))
    first  = int(ip_network(scope).network_address) + 50
    lease  = _lease_for(relay_ip)
    for n in range(count):
        # Randomised MAC with no organisational OUI — that IS the starvation
        # signal.  The first octet is masked to locally-administered UNICAST
        # ((b & 0xFE) | 0x02): a random octet sets the multicast bit half the
        # time, and a multicast source address is invalid in a DHCP chaddr, so
        # it would be dropped rather than logged.  This is what Yersinia and
        # dhcpstarv actually put on the wire.
        _first = (random.randint(0, 255) & 0xFE) | 0x02
        mac  = ":".join([f"{_first:02x}"] + [f"{random.randint(0,255):02x}" for _ in range(5)])
        txid = hex(random.randint(0, 2**32))[2:]
        # Starvation tools send no hostname and no client identifier, so dhcpd
        # prints neither the '(host)' nor the 'uid'.
        if n < pool:
            offer_ip = str(IPv4Address(first + n))
            logs.append(_dhcpd(config, relay_ip, f"DHCPDISCOVER from {mac} via {relay_ip} TransID {txid}"))
            logs.append(_dhcpd(config, relay_ip, f"DHCPOFFER on {offer_ip} to {mac} via {relay_ip} "
                                                 f"relay {relay_ip} lease-duration {lease} "
                                                 f"offered-duration {lease}"))
        else:
            logs.append(_dhcpd(config, relay_ip, f"DHCPDISCOVER from {mac} via {relay_ip}: "
                                                 f"network {scope}: no free leases"))
    return logs


def _generate_zone_transfer(config, client_ip=None, session_context=None):
    """
    Generates a DNS zone transfer attempt (AXFR/IXFR) from an unauthorized host.

    Hunt signals: q_type=AXFR or IXFR from non-authorized IP → REFUSED response;
                  single query (unlike NXDOMAIN storm which is many queries);
                  source IP is a workstation, not a secondary DNS server.
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    infoblox_conf    = config.get(CONFIG_KEY, {})
    ad               = resolver.internal_domain(config)
    internal_domains = infoblox_conf.get('internal_domains') or [ad, f"ad.{ad}"]
    attempts         = random.randint(4, 6)  # attacker probes several internal zones → rule needs >=3 xfer queries/60m
    zones            = list(internal_domains)
    random.shuffle(zones)

    print(f"    - Infoblox Module simulating: Zone Transfer x{attempts} for internal zones from {client_ip}")
    logs = []
    for i in range(attempts):
        z        = zones[i % len(zones)]
        xfr_type = random.choices(["AXFR", "IXFR"], weights=[70, 30])[0]
        # A zone transfer is a TCP operation -- it cannot fit in a UDP datagram
        # and BIND only ever serves it over TCP. These were logged as UDP, which
        # is the one transport an AXFR can never arrive on.
        pair = _build_dns_pair(config, client_ip, z, xfr_type, "REFUSED", ip_protocol="TCP")
        # named also logs the ACL decision itself, in the security category at
        # error level. The pack's fallback section models it as 'DNS security'.
        hostname, _ = _appliance(config, client_ip)
        port = int(pair[0].split("#", 1)[1].split(" ", 1)[0])
        deny = _named_line(config, hostname,
                           f"security: client @{_client_ptr(client_ip, port)} {client_ip}#{port} "
                           f"({z}): zone transfer '{z}/{xfr_type}/IN' denied", pri="<27>")
        logs.extend([pair[0], deny, pair[1]])
    return logs


def _generate_fast_flux_dns(config, client_ip=None, session_context=None):
    """
    Generates a fast-flux DNS event: same C2 domain resolves to different IPs, TTL=0.

    Hunt signals: same xdm.target.hostname → multiple different xdm.target.ip within seconds;
                  TTL=0 in each response RR (no caching = rapid rotation signal);
                  all resolved IPs in unrelated /8 ranges (not CDN-pattern IP blocks).
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    domain = threat_domains.pick(config, family="c2_infra")
    count  = random.randint(3, 6)

    print(f"    - Infoblox Module simulating: Fast-Flux DNS ({count} rotations) for {domain} from {client_ip}")
    logs = []
    for _ in range(count):
        # Rotating answers ARE the fast-flux signal, so these deliberately vary --
        # but they come from the shared rare-destination pool, not the old random
        # /8 construction, so they stay disjoint from the ambient and benign pools.
        flux_ip = rare_external_ip()
        resp_rr = [f"{domain}. 0 IN A {flux_ip}"]   # TTL=0 = fast-flux signal
        logs.extend(_build_dns_pair(config, client_ip, domain, "A", "NOERROR", resp_rr))
    return logs


def _generate_dns_rebinding(config, client_ip=None, session_context=None):
    """
    Generates a DNS rebinding attack: external-named domain resolves to an internal RFC-1918 IP.

    Hunt signals: xdm.target.ip = RFC-1918 address for an externally-named domain;
                  TTL=1 (minimal TTL allows rapid rebind before browser cache expires);
                  client is a workstation (browser attack vector — cross-origin bypass).
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    domain       = f"attacker-{random.randint(1000, 9999)}.{random.choice(['com', 'net', 'xyz', 'io'])}"
    int_net      = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
    internal_ip  = rand_ip_from_network(ip_network(int_net))
    resp_rr      = [f"{domain}. 1 IN A {internal_ip}"]   # TTL=1 = rebinding signal

    print(f"    - Infoblox Module simulating: DNS Rebinding -- {domain} -> {internal_ip} from {client_ip}")
    return _build_dns_pair(config, client_ip, domain, "A", "NOERROR", resp_rr)


def _generate_ptr_sweep(config, client_ip=None, session_context=None):
    """
    Generates a PTR reverse-lookup sweep: sequential in-addr.arpa queries mapping internal network.

    Hunt signals: same xdm.source.ip generates > 15 PTR queries within seconds;
                  sequential xdm.target.hostname values in arpa format;
                  high NXDOMAIN rate (~75%) — most hosts have no PTR record.
    Returns list (20–40 query+response pairs = 40–80 events).
    """
    if client_ip is None:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    # An attacker maps the segment it landed on, and the answers name the hosts
    # that really live there -- the same names DHCP, Windows and the firewalls
    # use. Misses are authoritative NXDOMAINs. The old sweep hit a random subnet
    # and answered 25% of addresses with invented 'host-a-b-c-d.internal' names.
    net_obj      = ip_network(f"{client_ip}/24", strict=False)
    rmap         = _reverse_map(config, session_context)
    base_int     = int(net_obj.network_address)
    max_start    = max(1, net_obj.num_addresses - 230)
    start_offset = random.randint(1, min(4, max_start))
    count        = random.randint(140, 220)  # realistic reverse-DNS /24 sweep → rule needs >=100 queries / >=50 distinct PTRs

    print(f"    - Infoblox Module simulating: PTR Sweep ({count} sequential) from {client_ip}")
    logs = []
    for i in range(count):
        target_int = base_int + start_offset + i
        if target_int >= int(net_obj.broadcast_address):
            break
        target_ip  = str(IPv4Address(target_int))
        octets     = target_ip.split('.')
        ptr_domain = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
        if target_ip in rmap:
            host_rr = [f"{ptr_domain}. 3600 IN PTR {rmap[target_ip]}."]
            logs.extend(_build_dns_pair(config, client_ip, ptr_domain, "PTR", "NOERROR", host_rr))
        else:
            logs.extend(_build_dns_pair(config, client_ip, ptr_domain, "PTR", "NXDOMAIN"))
    return logs


# Scenario functions dict — single source of truth for named-event dispatch.
# Keys are the exact strings returned by get_threat_names() and shown in the
# dashboard "Fire Threat" dropdown.  All values share the signature
# (config, client_ip=None, session_context=None).

_SCENARIO_FUNCTIONS = {
    "C2_BEACON":       _generate_c2_beacon,
    "DNS_TUNNEL":      _generate_dns_tunnel,
    "RPZ_BLOCK":       _generate_rpz_block,
    "THREAT_PROTECT":  _generate_threat_protect,
    "NXDOMAIN_STORM":  _generate_nxdomain_storm,
    "DNS_FLOOD":       _generate_dns_flood,
    "DHCP_STARVATION": _generate_dhcp_starvation,
    "ZONE_TRANSFER":   _generate_zone_transfer,
    "FAST_FLUX_DNS":   _generate_fast_flux_dns,
    "DNS_REBINDING":   _generate_dns_rebinding,
    "PTR_SWEEP":       _generate_ptr_sweep,
}


# Threat log dispatcher

def _generate_threat_log(config, session_context=None, forced_event=None):
    """Weighted threat dispatcher — pool pattern matching Firepower/ASA/Checkpoint.
    If forced_event is given, that specific named event is generated instead of a random pick.
    """
    # The infected client is a real session host, so the threat's DNS lines share
    # an IP with that user's DHCP lease, Windows logons and firewall sessions. A
    # random address from a random subnet belonged to nobody and joined to nothing.
    _victim = (get_random_user(session_context, preferred_device_type='workstation')
               if session_context else None)
    if _victim and _victim.get("ip"):
        client_ip = _victim["ip"]
    else:
        internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
        client_ip    = rand_ip_from_network(ip_network(internal_net))

    if forced_event:
        event = forced_event.upper()
        if event in _SCENARIO_FUNCTIONS:
            content = _SCENARIO_FUNCTIONS[event](config, client_ip, session_context)
            return (content, event)
        return None

    infoblox_conf  = config.get(CONFIG_KEY, {})
    threat_events  = infoblox_conf.get('event_mix', {}).get('threat', [])

    if not threat_events:
        threat_events = [
            {"event": "c2_beacon",        "weight": 25},
            {"event": "dns_tunnel",        "weight": 20},
            {"event": "rpz_block",         "weight": 18},
            {"event": "threat_protect",    "weight": 15},
            {"event": "nxdomain_storm",    "weight": 12},
            {"event": "dns_flood",         "weight": 6},
            {"event": "dhcp_starvation",   "weight": 4},
            {"event": "zone_transfer",     "weight": 8},
            {"event": "fast_flux_dns",     "weight": 7},
            {"event": "dns_rebinding",     "weight": 5},
            {"event": "ptr_sweep",         "weight": 4},
        ]

    threat_type = random.choices(
        [e['event']  for e in threat_events],
        weights=[e['weight'] for e in threat_events],
        k=1,
    )[0]

    if threat_type == "c2_beacon":
        content = _generate_c2_beacon(config, client_ip, session_context)
    elif threat_type == "dns_tunnel":
        content = _generate_dns_tunnel(config, client_ip, session_context)
    elif threat_type == "rpz_block":
        content = _generate_rpz_block(config, client_ip, session_context)
    elif threat_type == "threat_protect":
        content = _generate_threat_protect(config, client_ip, session_context)
    elif threat_type == "nxdomain_storm":
        content = _generate_nxdomain_storm(config, client_ip, session_context)
    elif threat_type == "dns_flood":
        content = _generate_dns_flood(config, client_ip, session_context)
    elif threat_type == "dhcp_starvation":
        content = _generate_dhcp_starvation(config, client_ip, session_context)
    elif threat_type == "zone_transfer":
        content = _generate_zone_transfer(config, client_ip, session_context)
    elif threat_type == "fast_flux_dns":
        content = _generate_fast_flux_dns(config, client_ip, session_context)
    elif threat_type == "dns_rebinding":
        content = _generate_dns_rebinding(config, client_ip, session_context)
    elif threat_type == "ptr_sweep":
        content = _generate_ptr_sweep(config, client_ip, session_context)
    else:
        return None
    return (content, threat_type.upper())


# Legacy scenario log generator (dict-based — kept for backward compatibility)

def _generate_scenario_log(config, scenario):
    """Generates a specific DNS event for a correlated scenario (legacy dict format)."""
    print(f"    - DNS Module creating scenario log for: {scenario.get('dest_domain')}")
    client_ip = scenario.get('source_ip')
    domain    = scenario.get('dest_domain')
    q_type    = scenario.get('dns_q_type', 'A')

    if not client_ip or not domain:
        return None

    if 'dns_response' in scenario and scenario['dns_response']:
        rcode            = scenario.get('dns_rcode', 'NOERROR')
        response_records = scenario.get('dns_response_records', [" "])
        print(f"      -> Generating DNS Response: {rcode} for {domain}")
        return _build_dns_response_log(config, client_ip, domain, q_type, rcode, response_records)
    else:
        print(f"      -> Generating DNS Query for {domain}")
        return _build_dns_query_log(config, client_ip, domain, q_type)


# Public cross-module API

def generate_dns_pair(config, client_ip, domain, q_type="A", dns_server_ip=None,
                      answer_ip=None):
    """
    Public API — generates a (query, response) DNS log pair for cross-module use.

    Returns (list[str], "DNS_QUERY") ready for process_and_send().
    Automatically returns NXDOMAIN if domain is in infoblox_threats; otherwise NOERROR.

    Usage in orchestrator (log_simulator.py):
        infoblox_module = modules.get("Infoblox NIOS")
        if infoblox_module:
            dns_logs, dns_name = infoblox_module.generate_dns_pair(config, src_ip, domain)
            process_and_send(dns_logs, infoblox_module, config, dns_name)
    """
    # answer_ip: pin the answer to the address the caller's NEXT event connects
    # to. Orchestrated scenarios need this -- a scenario's C2 or exfil host is
    # invented per run, so the shared table cannot know it, and without the pin
    # the DNS answer and the firewall session that follows name different
    # addresses (the join the scenarios' own hunt queries ask the analyst to run).
    # Membership of the config pool used to decide this. Once threat domains are
    # generated that test silently answers False for every one of them, and a C2
    # lookup starts resolving NOERROR -- breaking both the NXDOMAIN storm rule and
    # the "C2 domain resolves NOERROR" rule with no error anywhere. is_threat()
    # recognises generated domains by their family token and by the issue registry,
    # and still honours the config pools.
    is_malicious    = threat_domains.is_threat(domain, config)

    if answer_ip:
        rcode   = "NOERROR"
        resp_rr = [f"{domain}. 60 IN {q_type} {answer_ip}"]
    elif is_malicious:
        rcode   = "NXDOMAIN"
        resp_rr = None
    else:
        rcode   = "NOERROR"
        # Shared resolution table, so a pair generated on behalf of another module
        # answers with the address that module will connect to.
        answer = _answer_for(domain)
        # Use the actual q_type in the response record
        resp_rr = [f"{domain}. 60 IN {q_type} {answer}"]

    return (_build_dns_pair(config, client_ip, domain, q_type, rcode, resp_rr,
                            dns_server_ip=dns_server_ip), "DNS_QUERY")


def generate_dhcp_ack(config, client_ip, client_mac, client_hostname):
    """
    Public API — generates a DHCPACK log establishing the IP→MAC→hostname triad.

    Returns (str, "DHCP_ACK") ready for process_and_send().

    Used at the start of any scenario that involves a workstation being 'on network'
    — establishes the IP→MAC→hostname triad in infoblox_dhcp_raw before any
    connection events appear in Firepower/ASA/Checkpoint datasets.
    Enables the 'who was using that IP?' cross-dataset hunt query.
    """
    transaction_id = hex(random.randint(0, 2**32))
    relay_ip       = _relay_for(client_ip)
    log = _build_dhcp_log(config, "DHCPACK", client_ip, client_mac, client_hostname, transaction_id, relay_ip)
    return (log, "DHCP_ACK")


# Main entry point

def generate_log(config, scenario=None, threat_level="Realistic",
                 benign_only=False, context=None, scenario_event=None):
    """
    Main log generation function for Infoblox NIOS.

    scenario_event strings (9 supported):
      Cross-module: "DNS_LOOKUP", "DHCP_ACK"
      Standalone threats: "C2_BEACON", "DNS_TUNNEL", "RPZ_BLOCK", "THREAT_PROTECT",
                          "NXDOMAIN_STORM", "DNS_FLOOD", "DHCP_STARVATION"

    All scenario_event paths return (content, event_name) tuple.
    """
    global last_threat_event_time
    session_context = (context or {}).get('session_context')
    ctx             = context or {}

    # ---- scenario_event dispatch (string-based, new pattern) ----
    if scenario_event:
        src_ip   = ctx.get('src_ip') or ctx.get('client_ip')
        domain   = ctx.get('domain', random.choice(config.get('benign_domains', ['www.google.com'])))
        client_hostname = ctx.get('hostname', 'CORP-WORKSTATION')
        client_mac      = ctx.get('client_mac') or host_mac(client_hostname)

        if not src_ip:
            # A fired event with no pinned client lands on a real session host.
            _v = (get_random_user(session_context, preferred_device_type='workstation')
                  if session_context else None)
            if _v and _v.get("ip"):
                src_ip = _v["ip"]
            else:
                internal_net = random.choice(config.get('internal_networks', ['192.168.1.0/24']))
                src_ip       = rand_ip_from_network(ip_network(internal_net))

        # Benign helper events (used by orchestrated scenarios, not in the threat dropdown)
        if scenario_event == "DNS_LOOKUP":
            return generate_dns_pair(config, src_ip, domain)

        if scenario_event == "DHCP_ACK":
            return generate_dhcp_ack(config, src_ip, client_mac, client_hostname)

        # Named threat dispatch via _SCENARIO_FUNCTIONS dict
        event = scenario_event.upper()
        if event in _SCENARIO_FUNCTIONS:
            # Orchestrated events may pin the C2 domain so the DNS beacon matches
            # the domain the paired endpoint technique/network logs use. Only
            # C2_BEACON honors it today; ambient generation passes no domain.
            domain_override = ctx.get('domain')
            if event == "C2_BEACON" and (domain_override or ctx.get('dst_ip')):
                content = _generate_c2_beacon(config, src_ip, session_context,
                                              domain=domain_override,
                                              answer_ip=ctx.get('dst_ip'))
            else:
                content = _SCENARIO_FUNCTIONS[event](config, src_ip, session_context)
            return (content, event)

        return None

    # ---- legacy scenario dict path ----
    if scenario:
        return _generate_scenario_log(config, scenario)

    # ---- benign-only ----
    if benign_only:
        return _generate_benign_log(config, session_context)

    # ---- threat-level dispatch ----
    if threat_level == "Insane":
        return _generate_threat_log(config, session_context) if random.random() < 0.5 \
            else _generate_benign_log(config, session_context)

    interval     = _get_threat_interval(threat_level, config)
    current_time = time.time()

    if interval > 0 and (current_time - last_threat_event_time) > interval:
        last_threat_event_time = current_time
        return _generate_threat_log(config, session_context)
    else:
        return _generate_benign_log(config, session_context)
