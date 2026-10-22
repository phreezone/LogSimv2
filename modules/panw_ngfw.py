# modules/panw_ngfw.py
# Simulates Palo Alto Networks Next-Generation Firewall (PAN-OS) TRAFFIC logs in CEF
# syslog format for XSIAM detection testing.  Dataset: panw_ngfw_traffic_raw.
#
# Transport & routing
# -------------------
# CEF over syslog (TCP 514 by default) to the Broker VM's Syslog Collector applet with
# Format=CEF.  The header and extension layout are PAN-OS's own "Custom Log Format" for
# the Syslog Collector (Cortex XDR/XSIAM "Ingest NGFW logs using the Syslog collector"):
#
#   CEF:0|PANW|NGFW_CEF|<sw_version>|<subtype>|<type>|1| __firewall_type=firewall.traffic
#       __timestamp=<start> __tz=<high_res_ts> log_type=TRAFFIC subtype=end
#       log_time=.. time_generated=.. source_ip=.. dest_ip=.. ... <literal key=value> ..
#
# IMPORTANT: PAN-OS does NOT use the ArcSight numbered extension keys (cs1/cs4/flexNumber1).
# Its CEF custom format emits LITERAL key names (source_ip, dest_port, app, bytes_sent, ...)
# that match the panw_ngfw_traffic_raw column names 1:1.  The native Cortex PAN-OS parser
# reads `__firewall_type` + `log_type`/`subtype` to land the event in panw_ngfw_traffic_raw;
# no content pack install is required (Cortex parses PAN-OS natively).
#
# Do NOT send product=ngfw_cef on the *derived* ingest route — that lands in
# panw_ngfw_cef_raw with no_hit=drop and is discarded.  The NGFW_CEF product here is the
# native Syslog-Collector custom format, parsed by `__firewall_type`, which is the
# supported path.  An `rt=<epoch-ms>` extension is also emitted so bursts can be
# back-dated (the broker honours CEF `rt` during generic extraction), letting the
# detectors' 14-day activation / 30-day training windows be seeded in minutes.
#
# XDM field mapping (native PAN-OS traffic modeling rule)
#   source_ip / source_port            -> xdm.source.ipv4|ipv6 / port
#   dest_ip / dest_port                -> xdm.target.ipv4|ipv6 / port
#   nat_source / nat_source_port       -> xdm.source NAT (intermediate when is_proxy)
#   nat_dest / nat_dest_port           -> xdm.target NAT
#   source_user / dest_user            -> xdm.source/target.user.username
#   source_device_host / dest_device_* -> xdm.source/target.host.*
#   app / app_category / app_sub_category / technology_of_app / risk_of_app
#                                      -> xdm.target.application.* / network.application_protocol*
#   protocol                           -> xdm.network.ip_protocol
#   action (+ sub_type deny/drop)      -> xdm.observer.action / xdm.event.outcome (FAILED on deny/drop)
#   bytes_sent / bytes_received        -> xdm.source.sent_bytes / xdm.target.sent_bytes
#   packets_sent / packets_received    -> xdm.source.sent_packets / xdm.target.sent_packets
#   total_time_elapsed (s)             -> xdm.event.duration (x1000 ms)
#   session_id                         -> xdm.event.id / xdm.session_context_id
#   rule_matched (+ _uuid)             -> xdm.network.rule
#   from_zone / to_zone                -> xdm.source/target zone
#   session_end_reason                 -> hunt field (aged-out/tcp-fin/tcp-rst-*/threat)
#   url_category                       -> xdm.network.http.url_category
#   log_type                           -> xdm.event.type ; sub_type -> operation_sub_type
#
# Real data learned from the tenant's live CLCS feed (panw_ngfw_traffic_raw, READ-ONLY):
# every row is sub_type=end; end reasons aged-out / tcp-rst-from-server / tcp-fin /
# tcp-rst-from-client dominate; risk_of_app is a word (High/Medium/Low/Informational);
# categories are lowercase; the top apps are dns-base, ssl, web-browsing, ping, quic-base,
# ntp-base, ms-office365-base, ms-ds-smb*, ms-rdp, ssh, kerberos, ldap.  App metadata below
# (category / sub-category / technology / risk / default ports) is taken from Applipedia and
# cross-checked against those rows.  No real IPs/users/hosts are copied in — shapes only.

import random
import time
import uuid
import hashlib
from ipaddress import ip_network, ip_address

try:
    from modules.session_utils import (get_random_user, find_user_by_ip, get_user_by_name,
                                        rand_ip_from_network, host_mac, pick_active_session,
                                        weighted_destination, random_external_ip, rare_external_ip,
                                        rare_internal_host, rare_known_host, new_ftp_server_host,
                                        known_internal_hosts, sweep_targets, stable_external_ip,
                                        rare_source_host, rare_domain, to_nonstandard_https,
                                        correlated_or_random_user, beacon_targets, recurring_host)
    from modules import resolver
    from modules import threat_domains
    from modules import mgmt_plane
except ImportError:
    from session_utils import (get_random_user, find_user_by_ip, get_user_by_name,
                                rand_ip_from_network, host_mac, pick_active_session,
                                weighted_destination, random_external_ip, rare_external_ip,
                                rare_internal_host, rare_known_host, new_ftp_server_host,
                                known_internal_hosts, sweep_targets, stable_external_ip,
                                rare_source_host, rare_domain, to_nonstandard_https,
                                correlated_or_random_user, beacon_targets, recurring_host)
    import resolver
    import threat_domains
    import mgmt_plane

# Module identity
NAME        = "Palo Alto Networks NGFW"
DESCRIPTION = "Simulates Palo Alto Networks NGFW (PAN-OS) traffic logs in CEF syslog format."
XSIAM_PARSER = "panw_ngfw_traffic_raw"
CONFIG_KEY   = "panw_ngfw_config"

last_threat_event_time = 0

# ---------------------------------------------------------------------------
# Static data — App-ID catalog (Applipedia, cross-checked against live tenant rows)
# ---------------------------------------------------------------------------
# (app, category, sub_category, technology, risk, [default ports])
_APP = {
    "web-browsing":    ("general-internet", "internet-utility",  "browser-based",   "High",          [80, 8080]),
    "ssl":             ("networking",       "encrypted-tunnel",  "browser-based",   "High",          [443]),
    "dns-base":        ("networking",       "infrastructure",    "network-protocol","Medium",        [53]),
    "quic-base":       ("networking",       "infrastructure",    "browser-based",   "Informational", [443]),
    "ntp-base":        ("networking",       "infrastructure",    "network-protocol","Low",           [123]),
    "ms-office365-base":("saas",            "office-programs",   "browser-based",   "Informational", [443]),
    "outlook-web-online":("saas",           "email",             "browser-based",   "Informational", [443]),
    "sharepoint-online":("collaboration",   "social-business",   "browser-based",   "Informational", [443]),
    "ms-onedrive-base":("saas",             "file-sharing",      "client-server",   "Informational", [443]),
    "ms-teams":        ("collaboration",    "internet-conferencing","client-server","Informational", [443]),
    "zoom-base":       ("saas",             "internet-conferencing","client-server","Low",           [443]),
    "slack-base":      ("collaboration",    "instant-messaging", "browser-based",   "Medium",        [443]),
    "google-base":     ("general-internet", "internet-utility",  "browser-based",   "High",          [443]),
    "gmail-base":      ("saas",             "email",             "browser-based",   "Informational", [443]),
    "salesforce-base": ("business-systems", "erp-crm",           "browser-based",   "Informational", [443]),
    "github-base":     ("business-systems", "software-development","browser-based", "Medium",        [443]),
    "paloalto-updates":("business-systems", "software-update",   "client-server",   "Low",           [443]),
    "ms-update":       ("business-systems", "software-update",   "client-server",   "High",          [443, 80]),
    "apple-update":    ("business-systems", "software-update",   "client-server",   "Medium",        [443, 80]),
    "ocsp":            ("networking",       "infrastructure",    "client-server",   "Low",           [80]),
    "ssh":             ("networking",       "encrypted-tunnel",  "client-server",   "High",          [22]),
    "ms-rdp":          ("networking",       "remote-access",     "client-server",   "High",          [3389]),
    "ms-ds-smb-base":  ("business-systems", "storage-backup",    "client-server",   "Medium",        [445]),
    "ms-ds-smbv2":     ("business-systems", "storage-backup",    "client-server",   "Medium",        [445]),
    "ms-ds-smbv3":     ("business-systems", "storage-backup",    "client-server",   "Medium",        [445]),
    "kerberos":        ("business-systems", "auth-service",      "client-server",   "Low",           [88]),
    "ldap":            ("business-systems", "auth-service",      "client-server",   "Low",           [389]),
    "msrpc-base":      ("networking",       "infrastructure",    "client-server",   "Medium",        [135]),
    "smtp":            ("collaboration",    "email",             "client-server",   "Medium",        [25, 587]),
    "ftp":             ("general-internet", "file-sharing",      "client-server",   "Critical",      [21]),
    "icmp":            ("networking",       "ip-protocol",       "network-protocol","High",          [0]),
    "ping":            ("general-internet", "internet-utility",  "network-protocol","Low",           [0]),
    "snmp-base":       ("networking",       "infrastructure",    "client-server",   "Low",           [161]),
    "incomplete":      ("unknown",          "unknown",           "unknown",         "Informational", []),
    "insufficient-data":("unknown",         "unknown",           "unknown",         "Informational", []),
    "unknown-tcp":     ("unknown",          "unknown",           "unknown",         "Informational", []),
    "unknown-udp":     ("unknown",          "unknown",           "unknown",         "Informational", []),
    # Risky / threat-adjacent App-IDs used by the threat generators.
    "bittorrent":      ("general-internet", "file-sharing",      "peer-to-peer",    "High",          [6881]),
    "gnutella":        ("general-internet", "file-sharing",      "peer-to-peer",    "Critical",      [6346]),
    "ipfs":            ("general-internet", "file-sharing",      "peer-to-peer",    "High",          [4001]),
    "socks":           ("networking",       "proxy",             "network-protocol","Critical",      [1080]),
    "tor":             ("networking",       "encrypted-tunnel",  "browser-based",   "Critical",      [9001, 443]),
    "cryptocurrency":  ("general-internet", "internet-utility",  "peer-to-peer",    "High",          [3333, 4444, 8333]),
    "dns-over-https":  ("general-internet", "internet-utility",  "browser-based",   "Medium",        [443]),
    "tftp":            ("general-internet", "file-sharing",      "client-server",   "High",          [69]),
}

# Benign external destination-domain -> the App-ID that destination's traffic is
# identified as, so `app` stays coherent with the destination name and port (the real
# feed's App-ID always matches the actual service).  Substring match on the domain.
_DOMAIN_APP = [
    ("office365", "ms-office365-base"), ("outlook", "outlook-web-online"),
    ("sharepoint", "sharepoint-online"), ("onedrive", "ms-onedrive-base"),
    ("windowsupdate", "ms-update"), ("microsoft", "ms-update"),
    ("googleapis", "google-base"), ("google", "google-base"),
    ("zoom", "zoom-base"), ("slack", "slack-base"), ("salesforce", "salesforce-base"),
    ("github", "ssl"), ("gmail", "gmail-base"),
    ("paloaltonetworks", "paloalto-updates"), ("apple", "apple-update"),
    ("okta", "ssl"), ("service-now", "ssl"), ("zendesk", "ssl"), ("atlassian", "ssl"),
    ("docusign", "ssl"), ("workday", "ssl"), ("twilio", "ssl"), ("stripe", "ssl"),
    ("fedex", "ssl"), ("ups", "ssl"), ("ubuntu", "web-browsing"), ("redhat", "web-browsing"),
]


def _app_for_dest(domain, port):
    """App-ID coherent with the destination name and port."""
    if port == 53:
        return "dns-base"
    if port == 22:
        return "ssh"
    if port in (123,):
        return "ntp-base"
    d = (domain or "").lower()
    for token, app in _DOMAIN_APP:
        if token in d:
            return app
    if port == 80:
        return "web-browsing"
    return random.choice(["ssl", "ssl", "web-browsing", "quic-base"])

# Internal east-west benign apps (host -> internal server), so AD/file/RDP baselines exist.
_INTERNAL_APP_MIX = [
    ("dns-base", 20), ("kerberos", 16), ("ldap", 12), ("ms-ds-smbv3", 14),
    ("msrpc-base", 8), ("ms-rdp", 6), ("ssl", 6), ("snmp-base", 4), ("ntp-base", 4),
]

# PAN-OS traffic session end reasons, weighted from the live feed.
_END_REASONS_TCP = [("tcp-rst-from-server", 42), ("aged-out", 16), ("tcp-fin", 28),
                    ("tcp-rst-from-client", 13), ("tcp-reuse", 1)]
_END_REASONS_UDP = [("aged-out", 97), ("unknown", 3)]

_PROTO_BY_PORT = {53: "udp", 123: "udp", 161: "udp", 0: "icmp", 67: "udp", 68: "udp", 500: "udp"}

# PAN-OS URL categories (lowercase, as in the live feed).
_URL_CAT_BENIGN  = ["business-and-economy", "computer-and-internet-info", "search-engines",
                    "web-advertisements", "content-delivery-networks", "internet-communications",
                    "financial-services", "government", "health-and-medicine", "games",
                    "streaming-media", "social-networking", "web-based-email", "online-storage-and-backup"]
_URL_CAT_RISKY   = ["malware", "command-and-control", "phishing", "proxy-avoidance-and-anonymizers",
                    "dynamic-dns", "newly-registered-domain", "hacking", "unknown",
                    "peer-to-peer", "questionable", "grayware"]

_SW_VERSION = "11.1.4"       # PAN-OS release stamped in the CEF device-version slot
_SYSLOG_PRI = 14             # facility LOG_USER(1)*8 + notice(6)=14 (PAN syslog default LOG_USER)

# Device-ID OS families seen on endpoints, for source_device_osfamily.
_SRC_OSFAMILY = [("Windows", 60), ("Mac", 18), ("Linux", 12), ("iOS", 6), ("Android", 4)]
_DEVICE_CATEGORY = ["workstation", "server", "mobile", "iot"]


# ---------------------------------------------------------------------------
# Config / small helpers
# ---------------------------------------------------------------------------
def _get_config(config):
    return config.get(CONFIG_KEY, {})


def _get_threat_interval(threat_level, config):
    if threat_level == "Benign Traffic Only":
        return 86400 * 365
    return config.get("threat_generation_levels", {}).get(threat_level, 7200)


def _cef_escape(v):
    """Escape a CEF extension value.  PAN-OS escapes '\\' and '=' with a backslash
    (the Syslog Collector doc sets Escaped Characters='\\=' , Escape Character='\\')."""
    s = str(v)
    s = s.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")
    return s


def _serial(config):
    return _get_config(config).get("serial_number", "007051000012345")


def _fw_name(config):
    return _get_config(config).get("hostname", "PA-VM-01")


def _session_id():
    return str(random.randint(100000, 2147483647))


def _seqno():
    return str(random.randint(7000000000000000000, 7999999999999999999))


def _random_mac(host=None):
    if host:
        return host_mac(host)
    ouis = ["00:50:56", "b4:0c:25", "00:1b:17", "e4:a7:a0"]
    return f"{random.choice(ouis)}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"


def _src_osfamily():
    names, w = zip(*_SRC_OSFAMILY)
    return random.choices(names, weights=w)[0]


def _proto_for(app, dpt):
    if dpt in _PROTO_BY_PORT:
        return _PROTO_BY_PORT[dpt]
    meta = _APP.get(app)
    if meta and meta[2] == "network-protocol" and dpt == 0:
        return "icmp"
    return "tcp"


def _end_reason(proto):
    table = _END_REASONS_UDP if proto in ("udp", "icmp") else _END_REASONS_TCP
    names, w = zip(*table)
    return random.choices(names, weights=w)[0]


def _nat_for(src_ip, config, bus_egress=None):
    """Public NAT address an internal source egresses behind.  Prefers the egress IP a
    correlated cloud sign-in published to the activity bus (so the PAN NAT matches the
    Entra/Okta egress for the same user), else a stable address in the configured NAT pool."""
    if bus_egress:
        return bus_egress
    pool = _get_config(config).get("nat_pool_cidr", "203.0.113.0/27")
    try:
        net = ip_network(pool, strict=False)
        h = int(hashlib.sha256(str(src_ip).encode()).hexdigest(), 16)
        return str(net.network_address + 1 + (h % max(1, net.num_addresses - 2)))
    except ValueError:
        return "203.0.113.10"


def _is_internal(ip):
    try:
        a = ip_address(ip)
    except ValueError:
        return False
    return any(a in ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


# ---------------------------------------------------------------------------
# CEF builder
# ---------------------------------------------------------------------------
def _format_cef(config, subtype, fields, log_type="TRAFFIC", severity=1, ts=None):
    """Build one PAN-OS NGFW_CEF syslog line.

    Header:  CEF:0|PANW|NGFW_CEF|<sw>|<subtype>|<type>|<sev>|
    Body:    literal key=value pairs (PAN custom log format), space separated.
    `ts` is the event epoch seconds (defaults to now); it drives log_time/time_generated/rt.
    """
    t = ts if ts is not None else time.time()
    serial, name = _serial(config), _fw_name(config)
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t))
    base = {
        "__firewall_type": f"firewall.{log_type.lower()}",
        "__timestamp":     iso,
        "__tz":            "+00:00",
        "log_type":        log_type,
        "subtype":         subtype,
        "log_time":        iso,
        "time_generated":  iso,
        "rt":              str(int(t * 1000)),   # epoch ms — broker honours CEF rt for _time
        "log_source_id":   serial,
        "log_source_name": name,
        "sequence_no":     _seqno(),
        "vsys":            _get_config(config).get("vsys", "vsys1"),
        "vsys_name":       _get_config(config).get("vsys", "vsys1"),
        "device_name":     name,
        "severity":        str(severity),
    }
    merged = {**base, **fields}
    # AD-qualify bare usernames so XSIAM Identity stitches firewall users with cloud users.
    for uf in ("source_user", "dest_user"):
        uv = merged.get(uf)
        if uv and "\\" not in str(uv) and "@" not in str(uv) and not merged.pop("_no_user_qualify", False):
            merged[uf] = f"EXAMPLECORP\\{uv}"
    merged.pop("_no_user_qualify", None)
    ext = " ".join(f"{k}={_cef_escape(v)}" for k, v in merged.items() if v is not None and v != "")
    header = f"CEF:0|PANW|NGFW_CEF|{_SW_VERSION}|{subtype}|{log_type.lower()}|{severity}|"
    syslog_ts = time.strftime("%b %d %H:%M:%S", time.gmtime(t))
    return f"<{_SYSLOG_PRI}>{syslog_ts} {name} {header} {ext}"


def _traffic_fields(config, src_ip, dst_ip, dpt, app, action="allow", *,
                    shost=None, suser=None, dhost=None, duser=None, proto=None,
                    from_zone="trust", to_zone="untrust", bytes_sent=None, bytes_received=None,
                    duration_s=None, end_reason=None, url_cat=None, nat_src=None, nat_dpt=None,
                    spt=None, src_osfamily=None, src_category="workstation", rule=None):
    """Common extension dict for a traffic:end session (or deny/drop)."""
    forti = _get_config(config)
    meta = _APP.get(app, _APP["incomplete"])
    proto = proto or _proto_for(app, dpt)
    end_reason = end_reason or _end_reason(proto)
    spt = spt if spt is not None else random.randint(1025, 65535)
    bytes_sent = bytes_sent if bytes_sent is not None else random.randint(300, 40000)
    bytes_received = bytes_received if bytes_received is not None else random.randint(400, 300000)
    duration_s = duration_s if duration_s is not None else random.randint(1, 600)
    lan_if = forti.get("interface_lan", "ethernet1/2")
    wan_if = forti.get("interface_wan", "ethernet1/1")
    internal_dst = _is_internal(dst_ip)
    if action in ("deny", "drop"):
        bytes_sent, bytes_received, duration_s = random.randint(0, 74), 0, 0
        end_reason = "policy-deny" if action == "deny" else "aged-out"
    f = {
        "source_ip":        src_ip,
        "source_port":      spt,
        "dest_ip":          dst_ip,
        "dest_port":        dpt,
        "protocol":         proto,
        "action":           action,
        "app":              app,
        "app_category":     meta[0],
        "app_sub_category": meta[1],
        "technology_of_app":meta[2],
        "risk_of_app":      meta[3],
        "from_zone":        from_zone,
        "to_zone":          to_zone,
        "inbound_if":       lan_if,
        "outbound_if":      lan_if if internal_dst else wan_if,
        "session_id":       _session_id(),
        "rule_matched":     rule or forti.get("default_rule", "Allow-Users-Outbound"),
        "rule_matched_uuid":str(uuid.uuid4()),
        "bytes_sent":       bytes_sent,
        "bytes_received":   bytes_received,
        "bytes_total":      bytes_sent + bytes_received,
        "packets_sent":     max(1, bytes_sent // 600),
        "packets_received": max(1, bytes_received // 1200),
        "total_time_elapsed": duration_s,
        "session_end_reason": end_reason,
        "source_user":      suser,
        "dest_user":        duser,
        "source_device_category": src_category,
        "source_device_host":     shost,
        "source_device_osfamily": src_osfamily or _src_osfamily(),
        "dest_device_host":       dhost,
        "url_category":     url_cat or (random.choice(_URL_CAT_BENIGN) if meta[2] == "browser-based" else ""),
    }
    if shost:
        f["source_device_mac"] = _random_mac(shost)
    # NAT only when the destination is external.
    if not internal_dst:
        f["nat_source"]      = nat_src or _nat_for(src_ip, config)
        f["nat_source_port"] = random.randint(20000, 65000)
        f["nat_dest"]        = dst_ip
        f["nat_dest_port"]   = nat_dpt or dpt
    return f


# ---------------------------------------------------------------------------
# Benign generators
# ---------------------------------------------------------------------------
def _user_src(config, session_context, prefer_active=True):
    """(src_ip, username, hostname) for a benign actor, preferring a bus-correlated user."""
    if session_context:
        info = (correlated_or_random_user(session_context, preferred_device_type="workstation")
                if prefer_active else get_random_user(session_context, preferred_device_type="workstation"))
        if info:
            return info["ip"], info["username"], info.get("hostname")
    umap = config.get("shared_user_ip_map", {})
    if umap:
        u, ip = random.choice(list(umap.items()))
        return ip, u, None
    return "192.168.1.100", "unknown", None


def _bus_egress_for(username):
    """Egress IP a correlated cloud sign-in published for this user, if any."""
    s = pick_active_session() if pick_active_session else None
    if s and s.get("username") == username and s.get("egress_ip"):
        return s["egress_ip"]
    return None


def _benign_external(config, session_context):
    """Outbound session to an Internet destination, named via the resolver so the
    DNS answer and the firewall destination agree."""
    src_ip, user, shost = _user_src(config, session_context)
    dests = config.get("benign_egress_destinations") or [{}]
    dest = weighted_destination(user, dests)
    domain, dst_ip = resolver.benign_target(config, dest)
    ports = dest.get("ports") or [443]
    dpt = random.choice(ports)
    app = _app_for_dest(domain, dpt)
    if app == "dns-base":
        # Client resolves through its own Infoblox grid member (matches the Infoblox feed).
        gname, gip = resolver.dns_server_for(config, src_ip)
        f = _traffic_fields(config, src_ip, gip, 53, "dns-base", shost=shost, suser=user,
                            dhost=f"{gname}.{resolver.internal_domain(config)}",
                            from_zone="trust", to_zone="trust",
                            bytes_sent=random.randint(60, 140), bytes_received=random.randint(80, 400),
                            duration_s=0)
        return _format_cef(config, "end", f)
    f = _traffic_fields(config, src_ip, dst_ip, dpt, app, shost=shost, suser=user, dhost=domain,
                        nat_src=_bus_egress_for(user))
    return _format_cef(config, "end", f)


def _benign_internal(config, session_context):
    """East-west session: workstation -> internal server (AD / file / RDP baseline)."""
    src_ip, user, shost = _user_src(config, session_context)
    app = random.choices([a for a, _ in _INTERNAL_APP_MIX],
                         weights=[w for _, w in _INTERNAL_APP_MIX])[0]
    if app == "dns-base":
        # A client's DNS always goes to ITS own Infoblox grid member (same member the
        # Infoblox feed logs the query on), never a random internal server.
        gname, gip = resolver.dns_server_for(config, src_ip)
        f = _traffic_fields(config, src_ip, gip, 53, "dns-base", shost=shost, suser=user,
                            dhost=f"{gname}.{resolver.internal_domain(config)}",
                            from_zone="trust", to_zone="trust",
                            bytes_sent=random.randint(60, 140), bytes_received=random.randint(80, 400),
                            duration_s=0)
        return _format_cef(config, "end", f)
    servers = config.get("internal_servers") or ["10.0.10.50"]
    dst_ip = random.choice(servers)
    dpt = (_APP.get(app, (None,)*5)[4] or [445])[0]
    dhost = resolver.internal_fqdn(config, dst_ip)
    f = _traffic_fields(config, src_ip, dst_ip, dpt, app, shost=shost, suser=user, dhost=dhost,
                        from_zone="trust", to_zone="trust",
                        bytes_sent=random.randint(500, 60000), bytes_received=random.randint(800, 120000))
    return _format_cef(config, "end", f)


def _benign_inbound_block(config):
    """Internet noise denied at the perimeter (traffic:deny) — ambient, not an analytic."""
    ext = random_external_ip()
    servers = config.get("internal_servers") or ["10.0.10.50"]
    dpt = random.choice([22, 23, 445, 3389, 3306, 1433, 8080, 5900])
    f = _traffic_fields(config, ext, random.choice(servers), dpt, "incomplete", action="deny",
                        from_zone="untrust", to_zone="trust", rule="Deny-Inbound-Default")
    return _format_cef(config, "deny", f)


def _generate_benign_log(config, session_context=None):
    r = random.random()
    if r < 0.60:
        return _benign_external(config, session_context)
    if r < 0.90:
        return _benign_internal(config, session_context)
    return _benign_inbound_block(config)


# ---------------------------------------------------------------------------
# Threat catalog
# ---------------------------------------------------------------------------
# analytic: True  -> built to fire a native PAN NGFW traffic-log analytic (offered on demand)
# analytic: False -> realistic traffic for hunts / correlation, but no traffic-log analytic
#                    will fire (Kerberos/NTLM/dormant-account detectors need EAL-decoded
#                    protocol fields a CEF traffic log does not carry; uncommon-AppID and the
#                    SSH-to-cloud/process variations additionally require the XDR Agent).
_DEFAULT_THREAT_EVENTS = [
    {"event": "port_scan",            "weight": 8,  "analytic": True,  "xsiam_alert": "Port Scan"},
    {"event": "port_sweep",           "weight": 6,  "analytic": True,  "xsiam_alert": "Port Sweep"},
    {"event": "failed_connections",   "weight": 6,  "analytic": True,  "xsiam_alert": "Failed Connections"},
    {"event": "large_upload_https",   "weight": 5,  "analytic": True,  "xsiam_alert": "Large Upload (HTTPS)"},
    {"event": "large_upload_https_nonstd", "weight": 2, "analytic": True, "xsiam_alert": "Large Upload (HTTPS)"},
    {"event": "large_upload_smtp",    "weight": 3,  "analytic": True,  "xsiam_alert": "Large Upload (SMTP)"},
    {"event": "large_upload_ftp",     "weight": 3,  "analytic": True,  "xsiam_alert": "Large Upload (FTP)"},
    {"event": "large_upload_generic", "weight": 2,  "analytic": True,  "xsiam_alert": "Large Upload (Generic)"},
    {"event": "rare_rdp",             "weight": 4,  "analytic": True,  "xsiam_alert": "Rare RDP session to a remote host"},
    {"event": "abnormal_rdp_rare_host","weight": 3, "analytic": True,  "xsiam_alert": "Abnormal RDP session to a remote host from a rarely seen host"},
    {"event": "rdp_unmanaged",        "weight": 2,  "analytic": True,  "xsiam_alert": "RDP from an unmanaged endpoint in a typically managed subnet"},
    {"event": "rare_smb",             "weight": 4,  "analytic": True,  "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "smb_from_dc",          "weight": 3,  "analytic": True,  "xsiam_alert": "Suspicious SMB connection from domain controller"},
    {"event": "dcsync_non_dc",        "weight": 2,  "analytic": True,  "xsiam_alert": "Possible DCSync from a non domain controller"},
    {"event": "rare_smtp",            "weight": 2,  "analytic": True,  "xsiam_alert": "Rare SMTP/S Session"},
    {"event": "spam_bot",             "weight": 3,  "analytic": True,  "xsiam_alert": "Spam Bot Traffic"},
    {"event": "uncommon_ssh",         "weight": 4,  "analytic": True,  "xsiam_alert": "Uncommon SSH session was established"},
    {"event": "unusual_ssh",          "weight": 2,  "analytic": True,  "xsiam_alert": "Unusual SSH Activity"},
    {"event": "ssh_proxy",            "weight": 2,  "analytic": True,  "xsiam_alert": "Unusual SSH activity that resembles SSH proxy"},
    {"event": "rare_ssh_external",    "weight": 2,  "analytic": True,  "xsiam_alert": "Rare process created an SSH session to an uncommon external host"},
    {"event": "recurring_rare_ip",    "weight": 4,  "analytic": True,  "xsiam_alert": "Recurring access to rare IP"},
    {"event": "recurring_rare_domain","weight": 4,  "analytic": True,  "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain"},
    {"event": "rare_domain_comm",     "weight": 3,  "analytic": True,  "xsiam_alert": "Abnormal Communication to a Rare Domain"},
    {"event": "ddns_access",          "weight": 2,  "analytic": True,  "xsiam_alert": "Recurring rare domain access to dynamic DNS domain"},
    {"event": "crypto_miner",         "weight": 3,  "analytic": True,  "xsiam_alert": "A Possible crypto miner was detected on a host"},
    {"event": "torrent",              "weight": 3,  "analytic": True,  "xsiam_alert": "A Torrent client was detected on a host"},
    {"event": "p2p_upload",           "weight": 2,  "analytic": True,  "xsiam_alert": "Upload pattern that resembles Peer to Peer traffic"},
    {"event": "p2p_download",         "weight": 2,  "analytic": True,  "xsiam_alert": "Download pattern that resembles Peer to Peer traffic"},
    {"event": "ipfs",                 "weight": 2,  "analytic": True,  "xsiam_alert": "Possible use of IPFS was detected"},
    {"event": "rare_appid",           "weight": 3,  "analytic": True,  "xsiam_alert": "Rare AppID usage to a rare destination"},
    {"event": "new_ftp_server",       "weight": 2,  "analytic": True,  "xsiam_alert": "New FTP Server"},
    {"event": "new_admin_behavior",   "weight": 3,  "analytic": True,  "xsiam_alert": "New Administrative Behavior"},
    {"event": "dormant_host_conn",    "weight": 2,  "analytic": True,  "xsiam_alert": "Abnormal connections to a dormant host from a newly seen endpoint"},
    # Realistic network patterns whose dedicated analytic needs EAL-decoded fields the CEF
    # traffic log cannot carry — kept for hunts / correlation, NOT offered on demand.
    {"event": "kerberos_preauth_pattern", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "ntlm_relay_pattern",   "weight": 2,  "analytic": False, "xsiam_alert": None},
    {"event": "dns_tunnel_pattern",   "weight": 2,  "analytic": False, "xsiam_alert": None},
    {"event": "ldap_recon",           "weight": 2,  "analytic": False, "xsiam_alert": None},
]

_EVENT_DISPLAY_NAMES = {e["event"]: e["event"] for e in _DEFAULT_THREAT_EVENTS}
_DISPLAY_TO_EVENT = {}
for _e in _DEFAULT_THREAT_EVENTS:
    _DISPLAY_TO_EVENT[_e["event"]] = _e["event"]


def get_threat_names():
    """Every threat name (analytic or not); on-demand firing filters to the analytic ones."""
    return [e["event"] for e in _DEFAULT_THREAT_EVENTS]


def get_threat_info():
    """Per-threat metadata: event, display_name, analytic flag, target XSIAM alert, weight."""
    return [{"event": e["event"], "display_name": e["event"], "analytic": e.get("analytic", True),
             "xsiam_alert": e.get("xsiam_alert"), "weight": e["weight"]} for e in _DEFAULT_THREAT_EVENTS]


# Privileged service ports the port-scan / admin detectors profile.
_PRIV_PORTS = [21, 22, 23, 25, 53, 88, 110, 135, 139, 389, 443, 445, 636, 993, 1433, 3306, 3389, 5432, 5900]
_ADMIN_PORTS = [22, 3389, 445, 135, 5985, 5986]
_MINER_POOL_PORTS = [3333, 4444, 5555, 7777, 8333, 14444, 45700]
_DDNS_SUFFIXES = ["duckdns.org", "no-ip.org", "ddns.net", "dynu.net", "hopto.org", "sytes.net"]


def _dcs(config):
    """Domain-controller IPs XSIAM already classifies as DCs."""
    return (_get_config(config).get("domain_controllers")
            or config.get("domain_controllers") or ["10.0.10.10", "10.0.20.10"])


def _conn(config, src, dst, dpt, app, action="allow", *, suser=None, shost=None, duser=None,
          dhost=None, bytes_sent=None, bytes_received=None, duration_s=None, ts=None,
          from_zone="trust", to_zone="untrust", url_cat=None, end_reason=None, proto=None,
          src_category="workstation", no_qualify=False, rule=None):
    """One PAN-OS traffic:end (or deny/drop) CEF line."""
    subtype = action if action in ("deny", "drop") else "end"
    f = _traffic_fields(config, src, dst, dpt, app, action=action, shost=shost, suser=suser,
                        dhost=dhost, duser=duser, proto=proto, from_zone=from_zone, to_zone=to_zone,
                        bytes_sent=bytes_sent, bytes_received=bytes_received, duration_s=duration_s,
                        url_cat=url_cat, end_reason=end_reason, src_category=src_category, rule=rule)
    if no_qualify:
        f["_no_user_qualify"] = True
    return _format_cef(config, subtype, f, ts=ts)


def _threat_actor(config, session_context):
    """(src_ip, user, hostname) for a user-attributed threat, preferring a correlated user."""
    return _user_src(config, session_context, prefer_active=True)


# --- Reconnaissance -------------------------------------------------------------------
def _sim_port_scan(config, session_context):
    """One host hits ~20-24 distinct privileged ports on a single internal server."""
    src, user, shost = _threat_actor(config, session_context)
    target = random.choice(config.get("internal_servers") or ["10.0.10.50"])
    ports = random.sample(_PRIV_PORTS, min(len(_PRIV_PORTS), random.randint(20, 24)))
    print(f"    - PAN NGFW simulating: port scan {src} -> {target} ({len(ports)} ports)")
    t0 = time.time() - len(ports) * 2
    out = []
    for i, p in enumerate(ports):
        act = "allow" if p in (443, 445, 22) else random.choice(["deny", "drop", "allow"])
        out.append(_conn(config, src, target, p, "incomplete" if act != "allow" else _APP_for_port(p),
                         action=act, suser=user, shost=shost, from_zone="trust", to_zone="trust",
                         dhost=resolver.internal_fqdn(config, target), ts=t0 + i * 2))
    return out


def _APP_for_port(p):
    return {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns-base", 88: "kerberos", 135: "msrpc-base",
            389: "ldap", 443: "ssl", 445: "ms-ds-smbv3", 3389: "ms-rdp", 1433: "incomplete"}.get(p, "incomplete")


def _sim_port_sweep(config, session_context):
    """One privileged port swept across many internal hosts in >= 3 subnets."""
    src, user, shost = _threat_actor(config, session_context)
    port = random.choice([445, 3389, 22, 139])
    targets = sweep_targets(config, exclude=(src,))
    print(f"    - PAN NGFW simulating: port sweep {src} -> {len(targets)} hosts on {port}")
    t0 = time.time() - len(targets) * 2
    out = []
    for i, dst in enumerate(targets):
        act = random.choice(["allow", "deny", "deny"])
        out.append(_conn(config, src, dst, port, _APP_for_port(port) if act == "allow" else "incomplete",
                         action=act, suser=user, shost=shost, from_zone="trust", to_zone="trust",
                         ts=t0 + i * 2))
    return out


def _sim_failed_connections(config, session_context):
    """~120 zero-byte denied connections to 40 never-seen internal hosts."""
    src, user, shost = _threat_actor(config, session_context)
    hosts = [rare_internal_host(config) for _ in range(random.randint(38, 44))]
    print(f"    - PAN NGFW simulating: failed connections {src} -> {len(hosts)} inactive hosts")
    t0 = time.time() - 300
    out = []
    for i in range(random.randint(110, 130)):
        dst = random.choice(hosts)
        out.append(_conn(config, src, dst, random.choice([445, 139, 3389, 22, 1433]), "incomplete",
                         action="deny", suser=user, shost=shost, from_zone="trust", to_zone="trust",
                         ts=t0 + i * 2, end_reason="aged-out"))
    return out


# --- Exfil / large uploads ------------------------------------------------------------
def _rare_ext(config, seed=None):
    """(domain, ip) for a rare external destination."""
    dom = rare_domain(seed)
    return dom, resolver.answer_for(dom, config)


def _sim_large_upload(config, session_context, app, dpt, alert_port=None):
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"up|{user}")
    size = random.randint(200, 2000) * 1024 * 1024
    print(f"    - PAN NGFW simulating: large upload ({app}) {src} -> {dom} {size//(1024*1024)}MB")
    return [_conn(config, src, dst, alert_port or dpt, app, suser=user, shost=shost, dhost=dom,
                  bytes_sent=size, bytes_received=random.randint(2000, 50000),
                  duration_s=random.randint(300, 3600), url_cat="online-storage-and-backup")]


def _sim_large_upload_https(config, sc):      return _sim_large_upload(config, sc, "ssl", 443)
def _sim_large_upload_https_nonstd(config, sc):
    return to_nonstandard_https(_sim_large_upload(config, sc, "ssl", 443))
def _sim_large_upload_smtp(config, sc):       return _sim_large_upload(config, sc, "smtp", 587)
def _sim_large_upload_ftp(config, sc):        return _sim_large_upload(config, sc, "ftp", 21)
def _sim_large_upload_generic(config, sc):    return _sim_large_upload(config, sc, "unknown-tcp", random.choice([4444, 9001, 8888, 6667]))


# --- Rare lateral / remote-access -----------------------------------------------------
def _sim_rare_rdp(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    dst = rare_known_host(config, exclude=(src,))
    return [_conn(config, src, dst, 3389, "ms-rdp", suser=user, shost=shost,
                  dhost=resolver.internal_fqdn(config, dst), from_zone="trust", to_zone="trust",
                  bytes_sent=random.randint(40000, 400000), bytes_received=random.randint(200000, 4000000),
                  duration_s=random.randint(120, 3000))]


def _sim_abnormal_rdp_rare_host(config, session_context):
    """RDP initiated from a rarely-seen internal source host (no busy user attached)."""
    src, shost = rare_source_host(config, "panw_rdp")
    dst = rare_known_host(config, exclude=(src,))
    print(f"    - PAN NGFW simulating: abnormal RDP from rarely-seen host {shost} ({src})")
    return [_conn(config, src, dst, 3389, "ms-rdp", shost=shost, src_category="workstation",
                  dhost=resolver.internal_fqdn(config, dst), from_zone="trust", to_zone="trust",
                  bytes_sent=random.randint(30000, 300000), bytes_received=random.randint(150000, 2000000),
                  duration_s=random.randint(120, 2400))]


def _sim_rdp_unmanaged(config, session_context):
    """RDP from an unmanaged endpoint (category=unknown) inside a typically-managed subnet."""
    servers = config.get("internal_servers") or ["10.0.10.50"]
    subnet = random.choice(servers).rsplit(".", 1)[0]
    src = f"{subnet}.{random.randint(200, 250)}"
    dst = random.choice(servers)
    print(f"    - PAN NGFW simulating: RDP from unmanaged endpoint {src} in managed subnet {subnet}.0/24")
    return [_conn(config, src, dst, 3389, "ms-rdp", src_category="unknown",
                  dhost=resolver.internal_fqdn(config, dst), from_zone="trust", to_zone="trust",
                  bytes_sent=random.randint(30000, 300000), bytes_received=random.randint(150000, 2000000),
                  duration_s=random.randint(120, 2400))]


def _sim_rare_smb(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    dst = rare_known_host(config, exclude=(src,))
    return [_conn(config, src, dst, 445, "ms-ds-smbv3", suser=user, shost=shost,
                  dhost=resolver.internal_fqdn(config, dst), from_zone="trust", to_zone="trust",
                  bytes_sent=random.randint(20000, 300000), bytes_received=random.randint(50000, 2000000),
                  duration_s=random.randint(10, 300))]


def _sim_smb_from_dc(config, session_context):
    """A domain controller initiates SMB to a workstation (abnormal direction)."""
    dc = random.choice(_dcs(config))
    nets = config.get("internal_networks") or ["192.168.1.0/24"]
    try:
        dst = rand_ip_from_network(ip_network(random.choice(nets), strict=False))
    except (ValueError, IndexError):
        dst = "192.168.1.101"
    print(f"    - PAN NGFW simulating: DC->workstation SMB from {dc}")
    out = []
    for _ in range(random.randint(2, 4)):
        out.append(_conn(config, dc, dst, 445, "ms-ds-smbv3", suser="SYSTEM", no_qualify=True,
                         shost=resolver.internal_fqdn(config, dc), from_zone="trust", to_zone="trust",
                         bytes_sent=random.randint(5000, 50000), bytes_received=random.randint(5000, 200000),
                         duration_s=random.randint(5, 60)))
    return out


def _sim_dcsync_non_dc(config, session_context):
    """A NON-DC host performs AD-replication RPC (DRSUAPI) to a DC — DCSync over the wire."""
    src, user, shost = _threat_actor(config, session_context)
    dc = random.choice(_dcs(config))
    print(f"    - PAN NGFW simulating: DCSync (DRSUAPI) {src} -> DC {dc}")
    out = [_conn(config, src, dc, 135, "msrpc-base", suser=user, shost=shost,
                 dhost=resolver.internal_fqdn(config, dc), from_zone="trust", to_zone="trust",
                 bytes_sent=random.randint(2000, 9000), bytes_received=random.randint(5000, 40000),
                 duration_s=random.randint(1, 10))]
    for _ in range(random.randint(3, 6)):     # dynamic RPC high ports carrying the replication
        out.append(_conn(config, src, dc, random.randint(49152, 65535), "msrpc-base", suser=user,
                         shost=shost, dhost=resolver.internal_fqdn(config, dc), from_zone="trust",
                         to_zone="trust", bytes_sent=random.randint(20000, 400000),
                         bytes_received=random.randint(200000, 8000000), duration_s=random.randint(2, 40)))
    return out


# --- SMTP ------------------------------------------------------------------------------
def _sim_rare_smtp(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"smtp|{user}")
    return [_conn(config, src, dst, random.choice([25, 587, 465]), "smtp", suser=user, shost=shost,
                  dhost=dom, bytes_sent=random.randint(5000, 80000), bytes_received=random.randint(300, 4000),
                  duration_s=random.randint(1, 30))]


def _sim_spam_bot(config, session_context):
    """One host connects to an excessive number of external SMTP servers (port 25)."""
    src, user, shost = _threat_actor(config, session_context)
    n = random.randint(40, 90)
    print(f"    - PAN NGFW simulating: spam bot {src} -> {n} external SMTP servers")
    t0 = time.time() - n * 30
    out = []
    for i in range(n):
        dst = random_external_ip()
        out.append(_conn(config, src, dst, 25, "smtp", suser=user, shost=shost,
                         bytes_sent=random.randint(2000, 40000), bytes_received=random.randint(200, 2000),
                         duration_s=random.randint(1, 20), ts=t0 + i * 30))
    return out


# --- SSH -------------------------------------------------------------------------------
def _sim_uncommon_ssh(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    dst = rare_known_host(config, exclude=(src,))
    return [_conn(config, src, dst, 22, "ssh", suser=user, shost=shost,
                  dhost=resolver.internal_fqdn(config, dst), from_zone="trust", to_zone="trust",
                  bytes_sent=random.randint(3000, 60000), bytes_received=random.randint(4000, 120000),
                  duration_s=random.randint(30, 600))]


def _sim_unusual_ssh(config, session_context):
    """Long, high-volume SSH session (tunnel characteristics)."""
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"ssh|{user}")
    return [_conn(config, src, dst, 22, "ssh", suser=user, shost=shost, dhost=dom,
                  bytes_sent=random.randint(50, 400) * 1024 * 1024,
                  bytes_received=random.randint(50, 400) * 1024 * 1024,
                  duration_s=random.randint(7200, 28800))]


def _sim_ssh_proxy(config, session_context):
    """A host both receives and initiates SSH within a window (SSH-proxy shape)."""
    src, user, shost = _threat_actor(config, session_context)
    inbound = random_external_ip()
    dom, outbound = _rare_ext(config, f"sshproxy|{user}")
    t0 = time.time() - 600
    return [
        _conn(config, inbound, src, 22, "ssh", duser=user, dhost=shost, from_zone="untrust",
              to_zone="trust", bytes_sent=random.randint(20, 200) * 1024 * 1024,
              bytes_received=random.randint(20, 200) * 1024 * 1024, duration_s=random.randint(1800, 10800), ts=t0),
        _conn(config, src, outbound, 22, "ssh", suser=user, shost=shost, dhost=dom,
              bytes_sent=random.randint(20, 200) * 1024 * 1024, bytes_received=random.randint(20, 200) * 1024 * 1024,
              duration_s=random.randint(1800, 10800), ts=t0 + 60),
    ]


def _sim_rare_ssh_external(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"sshext|{user}")
    return [_conn(config, src, dst, random.choice([22, 2222]), "ssh", suser=user, shost=shost, dhost=dom,
                  bytes_sent=random.randint(5000, 200000), bytes_received=random.randint(5000, 400000),
                  duration_s=random.randint(30, 1200))]


# --- Recurring / beaconing (back-dated across days so the baseline accrues) ------------
def _beacon_dst(config, key, src):
    """A stable rare external (ip, domain) this src beacons to — persists across restarts."""
    store = beacon_targets("panw_ngfw")
    k = f"{key}|{src}"
    if k in store:
        v = store[k]
        return (v[0], v[1]) if isinstance(v, (list, tuple)) else (v, None)
    dom = rare_domain(k)
    ip = resolver.answer_for(dom, config)
    store[k] = [ip, dom]
    return ip, dom


def _sim_recurring_rare_ip(config, session_context):
    """Same source reaches the same rare external IP on many back-dated days (C2 cadence)."""
    hit = recurring_host("panw_rare_ip") if recurring_host else None
    src, user, shost = hit if hit else _threat_actor(config, session_context)
    ip, _dom = _beacon_dst(config, "rare_ip", src)
    print(f"    - PAN NGFW simulating: recurring access to rare IP {src} -> {ip}")
    out = []
    for day in range(random.randint(6, 12)):
        ts = time.time() - day * 86400 - random.randint(0, 3600)
        out.append(_conn(config, src, ip, random.choice([443, 8443, 4443]), "ssl", suser=user,
                         shost=shost, bytes_sent=random.randint(400, 4000),
                         bytes_received=random.randint(400, 4000), duration_s=random.randint(1, 30),
                         ts=ts, url_cat="unknown"))
    return out


def _sim_recurring_rare_domain(config, session_context):
    hit = recurring_host("panw_rare_dom") if recurring_host else None
    src, user, shost = hit if hit else _threat_actor(config, session_context)
    ip, dom = _beacon_dst(config, "rare_dom", src)
    print(f"    - PAN NGFW simulating: recurring access to rare domain {src} -> {dom}")
    out = []
    for day in range(random.randint(6, 12)):
        ts = time.time() - day * 86400 - random.randint(0, 3600)
        out.append(_conn(config, src, ip, random.choice([443, 8080, 8443]), "ssl", suser=user,
                         shost=shost, dhost=dom, bytes_sent=random.randint(400, 4000),
                         bytes_received=random.randint(400, 4000), duration_s=random.randint(1, 30),
                         ts=ts, url_cat="command-and-control"))
    return out


def _sim_rare_domain_comm(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"rdc|{user}")
    return [_conn(config, src, dst, random.choice([443, 8443, 4444]), "ssl", suser=user, shost=shost,
                  dhost=dom, bytes_sent=random.randint(500, 20000), bytes_received=random.randint(500, 40000),
                  duration_s=random.randint(1, 120), url_cat="newly-registered-domain")]


def _sim_ddns_access(config, session_context):
    hit = recurring_host("panw_ddns") if recurring_host else None
    src, user, shost = hit if hit else _threat_actor(config, session_context)
    label = rare_domain(f"ddns|{src}").split(".")[0]
    dom = f"{label}.{random.choice(_DDNS_SUFFIXES)}"
    ip = resolver.answer_for(dom, config)
    print(f"    - PAN NGFW simulating: recurring dynamic-DNS access {src} -> {dom}")
    out = []
    for day in range(random.randint(5, 10)):
        ts = time.time() - day * 86400 - random.randint(0, 3600)
        out.append(_conn(config, src, ip, 443, "ssl", suser=user, shost=shost, dhost=dom,
                         bytes_sent=random.randint(400, 5000), bytes_received=random.randint(400, 5000),
                         duration_s=random.randint(1, 60), ts=ts, url_cat="dynamic-dns"))
    return out


# --- Malware-shaped application traffic ------------------------------------------------
def _sim_crypto_miner(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"miner|{user}")
    port = random.choice(_MINER_POOL_PORTS)
    print(f"    - PAN NGFW simulating: crypto miner {src} -> pool {dom}:{port}")
    out = []
    t0 = time.time() - 1800
    for i in range(random.randint(8, 16)):
        out.append(_conn(config, src, dst, port, "cryptocurrency", suser=user, shost=shost, dhost=dom,
                         bytes_sent=random.randint(2000, 30000), bytes_received=random.randint(2000, 30000),
                         duration_s=random.randint(60, 600), ts=t0 + i * 120, url_cat="unknown"))
    return out


def _sim_torrent(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    print(f"    - PAN NGFW simulating: torrent client on {src}")
    out = []
    for _ in range(random.randint(10, 20)):
        out.append(_conn(config, src, random_external_ip(), random.choice([6881, 6882, 6889, 51413]),
                         "bittorrent", suser=user, shost=shost, bytes_sent=random.randint(50000, 5000000),
                         bytes_received=random.randint(50000, 20000000), duration_s=random.randint(60, 1800),
                         url_cat="peer-to-peer"))
    return out


def _sim_p2p(config, session_context, upload):
    src, user, shost = _threat_actor(config, session_context)
    out = []
    for _ in range(random.randint(15, 30)):
        big, small = (random.randint(2_000_000, 50_000_000), random.randint(2000, 50000))
        out.append(_conn(config, src, random_external_ip(), random.randint(1024, 65535),
                         random.choice(["bittorrent", "gnutella"]), suser=user, shost=shost,
                         bytes_sent=big if upload else small, bytes_received=small if upload else big,
                         duration_s=random.randint(30, 600), url_cat="peer-to-peer"))
    return out


def _sim_ipfs(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    print(f"    - PAN NGFW simulating: IPFS traffic on {src}")
    out = []
    for _ in range(random.randint(12, 24)):
        out.append(_conn(config, src, random_external_ip(), random.choice([4001, 5001, 8080]),
                         "ipfs", suser=user, shost=shost, bytes_sent=random.randint(10000, 500000),
                         bytes_received=random.randint(10000, 2000000), duration_s=random.randint(10, 300),
                         url_cat="peer-to-peer"))
    return out


def _sim_rare_appid(config, session_context):
    """A rarely-used App-ID to a rare destination on an unusual port."""
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"appid|{user}")
    app = random.choice(["socks", "tor", "gnutella", "dns-over-https", "tftp"])
    port = random.choice(_APP.get(app, (None,)*5)[4] or [1080])
    return [_conn(config, src, dst, port, app, suser=user, shost=shost, dhost=dom,
                  bytes_sent=random.randint(2000, 200000), bytes_received=random.randint(2000, 400000),
                  duration_s=random.randint(10, 600), url_cat="proxy-avoidance-and-anonymizers")]


def _sim_new_ftp_server(config, session_context):
    """A host not previously seen serving FTP starts accepting inbound FTP."""
    server = new_ftp_server_host(config)
    client, user, shost = _threat_actor(config, session_context)
    print(f"    - PAN NGFW simulating: new FTP server {server}")
    out = []
    for _ in range(random.randint(2, 5)):
        out.append(_conn(config, client, server, 21, "ftp", suser=user, shost=shost,
                         dhost=resolver.internal_fqdn(config, server), from_zone="trust", to_zone="trust",
                         bytes_sent=random.randint(2000, 50000), bytes_received=random.randint(50000, 5000000),
                         duration_s=random.randint(5, 300)))
    return out


def _sim_new_admin_behavior(config, session_context):
    """A host performs new administrative actions to many internal destinations."""
    src, user, shost = _threat_actor(config, session_context)
    targets = sweep_targets(config, exclude=(src,), n_range=(12, 24), min_subnets=2)
    print(f"    - PAN NGFW simulating: new admin behavior {src} -> {len(targets)} hosts")
    t0 = time.time() - len(targets) * 10
    out = []
    for i, dst in enumerate(targets):
        port = random.choice(_ADMIN_PORTS)
        out.append(_conn(config, src, dst, port, _APP_for_port(port) if port in (22, 3389, 445, 135) else "ssl",
                         suser=user, shost=shost, from_zone="trust", to_zone="trust",
                         dhost=resolver.internal_fqdn(config, dst), bytes_sent=random.randint(3000, 80000),
                         bytes_received=random.randint(5000, 400000), duration_s=random.randint(5, 120),
                         ts=t0 + i * 10))
    return out


def _sim_dormant_host_conn(config, session_context):
    """A newly-seen endpoint makes multiple connections to a long-inactive (dormant) host."""
    src, shost = rare_source_host(config, "panw_dormant")
    dormant = rare_internal_host(config)
    print(f"    - PAN NGFW simulating: connections to dormant host {dormant} from new endpoint {src}")
    out = []
    for _ in range(random.randint(6, 14)):
        out.append(_conn(config, src, dormant, random.choice([445, 3389, 22, 443]), "ssl",
                         shost=shost, from_zone="trust", to_zone="trust",
                         dhost=resolver.internal_fqdn(config, dormant),
                         bytes_sent=random.randint(2000, 60000), bytes_received=random.randint(2000, 200000),
                         duration_s=random.randint(5, 300)))
    return out


# --- Non-analytic realistic network patterns (hunts / correlation only) ---------------
def _sim_kerberos_preauth_pattern(config, session_context):
    """Repeated Kerberos (88) from one host to a DC — realistic pre-auth spray shape. The
    analytic needs EAL-decoded Kerberos error codes, so no traffic-log alert fires."""
    src, user, shost = _threat_actor(config, session_context)
    dc = random.choice(_dcs(config))
    out = []
    t0 = time.time() - 600
    for i in range(random.randint(20, 60)):
        out.append(_conn(config, src, dc, 88, "kerberos", suser=user, shost=shost,
                         dhost=resolver.internal_fqdn(config, dc), from_zone="trust", to_zone="trust",
                         bytes_sent=random.randint(300, 2000), bytes_received=random.randint(0, 200),
                         duration_s=0, ts=t0 + i * 10, end_reason="aged-out"))
    return out


def _sim_ntlm_relay_pattern(config, session_context):
    """SMB/RPC auth fan-out consistent with NTLM relay; the NTProofStr the analytic needs
    is EAL-only, so this is realistic traffic for hunts, not a traffic-log alert."""
    relay, _u, rhost = rare_source_host(config, "panw_ntlm"), None, None
    relay_ip, rhost = relay
    out = []
    for dst in (config.get("internal_servers") or ["10.0.10.50"])[:random.randint(3, 6)]:
        out.append(_conn(config, relay_ip, dst, 445, "ms-ds-smbv3", shost=rhost, from_zone="trust",
                         to_zone="trust", dhost=resolver.internal_fqdn(config, dst),
                         bytes_sent=random.randint(3000, 40000), bytes_received=random.randint(3000, 100000),
                         duration_s=random.randint(1, 30)))
    return out


def _sim_dns_tunnel_pattern(config, session_context):
    """High-volume DNS (53) to one resolver — DNS-tunnel shape. The qname entropy the
    analytic reads is EAL-only (not carried on CEF traffic logs), so no alert fires."""
    src, user, shost = _threat_actor(config, session_context)
    gname, gip = resolver.dns_server_for(config, src)
    out = []
    t0 = time.time() - 600
    for i in range(random.randint(40, 90)):
        out.append(_conn(config, src, gip, 53, "dns-base", suser=user, shost=shost,
                         dhost=f"{gname}.{resolver.internal_domain(config)}", from_zone="trust",
                         to_zone="trust", bytes_sent=random.randint(120, 300),
                         bytes_received=random.randint(120, 600), duration_s=0, ts=t0 + i * 6))
    return out


def _sim_ldap_recon(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    dc = random.choice(_dcs(config))
    out = []
    for _ in range(random.randint(10, 25)):
        out.append(_conn(config, src, dc, random.choice([389, 636]), "ldap", suser=user, shost=shost,
                         dhost=resolver.internal_fqdn(config, dc), from_zone="trust", to_zone="trust",
                         bytes_sent=random.randint(500, 8000), bytes_received=random.randint(2000, 200000),
                         duration_s=random.randint(1, 30)))
    return out


_THREAT_DISPATCH = {
    "port_scan": _sim_port_scan, "port_sweep": _sim_port_sweep,
    "failed_connections": _sim_failed_connections,
    "large_upload_https": _sim_large_upload_https,
    "large_upload_https_nonstd": _sim_large_upload_https_nonstd,
    "large_upload_smtp": _sim_large_upload_smtp, "large_upload_ftp": _sim_large_upload_ftp,
    "large_upload_generic": _sim_large_upload_generic,
    "rare_rdp": _sim_rare_rdp, "abnormal_rdp_rare_host": _sim_abnormal_rdp_rare_host,
    "rdp_unmanaged": _sim_rdp_unmanaged, "rare_smb": _sim_rare_smb, "smb_from_dc": _sim_smb_from_dc,
    "dcsync_non_dc": _sim_dcsync_non_dc, "rare_smtp": _sim_rare_smtp, "spam_bot": _sim_spam_bot,
    "uncommon_ssh": _sim_uncommon_ssh, "unusual_ssh": _sim_unusual_ssh, "ssh_proxy": _sim_ssh_proxy,
    "rare_ssh_external": _sim_rare_ssh_external, "recurring_rare_ip": _sim_recurring_rare_ip,
    "recurring_rare_domain": _sim_recurring_rare_domain, "rare_domain_comm": _sim_rare_domain_comm,
    "ddns_access": _sim_ddns_access, "crypto_miner": _sim_crypto_miner, "torrent": _sim_torrent,
    "p2p_upload": lambda c, s: _sim_p2p(c, s, True), "p2p_download": lambda c, s: _sim_p2p(c, s, False),
    "ipfs": _sim_ipfs, "rare_appid": _sim_rare_appid, "new_ftp_server": _sim_new_ftp_server,
    "new_admin_behavior": _sim_new_admin_behavior, "dormant_host_conn": _sim_dormant_host_conn,
    "kerberos_preauth_pattern": _sim_kerberos_preauth_pattern, "ntlm_relay_pattern": _sim_ntlm_relay_pattern,
    "dns_tunnel_pattern": _sim_dns_tunnel_pattern, "ldap_recon": _sim_ldap_recon,
}


def _generate_threat_log(config, session_context=None, forced_event=None):
    """Dispatch a threat scenario.  Returns (log_or_list, display_name)."""
    if forced_event:
        chosen = _DISPLAY_TO_EVENT.get(forced_event, _DISPLAY_TO_EVENT.get(forced_event.lower(), forced_event.lower()))
    else:
        events = [e["event"] for e in _DEFAULT_THREAT_EVENTS]
        weights = [e["weight"] for e in _DEFAULT_THREAT_EVENTS]
        chosen = random.choices(events, weights=weights, k=1)[0]
    fn = _THREAT_DISPATCH.get(chosen)
    if not fn:
        fn = _sim_port_scan
        chosen = "port_scan"
    return fn(config, session_context), _EVENT_DISPLAY_NAMES.get(chosen, chosen)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def generate_log(config, scenario=None, threat_level="Realistic", benign_only=False,
                 context=None, scenario_event=None):
    """Main log generation entry point.  Returns a CEF string or a list of CEF strings."""
    global last_threat_event_time
    session_context = (context or {}).get("session_context")

    # Orchestrated / dashboard-forced named threat.
    if scenario_event:
        if scenario_event in ("LARGE_EGRESS",):
            return _sim_large_upload_https(config, session_context)
        if scenario_event in _THREAT_DISPATCH or scenario_event.lower() in _THREAT_DISPATCH:
            return _generate_threat_log(config, session_context, forced_event=scenario_event)[0]

    if benign_only:
        return _generate_benign_log(config, session_context)

    interval = _get_threat_interval(threat_level, config)
    now = time.time()
    if threat_level == "Insane" and random.random() < 0.8:
        return _generate_threat_log(config, session_context)[0]
    if interval > 0 and (now - last_threat_event_time) > interval:
        last_threat_event_time = now
        return _generate_threat_log(config, session_context)[0]
    return _generate_benign_log(config, session_context)
