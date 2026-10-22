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
# Main entry point (threats added in the next stage)
# ---------------------------------------------------------------------------
def generate_log(config, scenario=None, threat_level="Realistic", benign_only=False,
                 context=None, scenario_event=None):
    """Main log generation entry point.  Returns a CEF string or a list of CEF strings."""
    global last_threat_event_time
    session_context = (context or {}).get("session_context")

    if benign_only:
        return _generate_benign_log(config, session_context)

    # Threat dispatch is wired in the next commit; until then emit benign baseline so the
    # module is importable and runnable.
    interval = _get_threat_interval(threat_level, config)
    now = time.time()
    if threat_level == "Insane" and random.random() < 0.8:
        pass
    if interval > 0 and (now - last_threat_event_time) > interval:
        last_threat_event_time = now
    return _generate_benign_log(config, session_context)
