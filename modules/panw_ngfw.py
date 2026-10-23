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
# native Syslog-Collector custom format, routed by `__firewall_type`, which is the
# supported path.  The collector routes on that key but does not rewrite the body: every
# key lands as a column of the same name, so keys must use the dataset's column names.
#
# NO BACK-DATING on this path (measured 2026-10-22): _time is always the ingestion time.
# Neither `rt` nor `__timestamp` (epoch ms, "YYYY/MM/DD HH:MM:SS", ISO-Z, or PAN's
# cef-formatted time) moves it; the intended time survives only in time_generated / rt.
# So anything a detector must see on SEPARATE DAYS (recurring beacons, an SSH habit) has to
# be emitted on real days while the module runs: see _DAILY_EVENTS and _ssh_habit_users().
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
                                        rare_source_host, rare_domain, NONSTD_HTTPS_PORTS, exfil_destination,
                                        correlated_or_random_user, beacon_targets, recurring_host, stable_subset,
                                        ip_country, get_user_agent)
    from modules import resolver
    from modules import threat_domains
    from modules import mgmt_plane
except ImportError:
    from session_utils import (get_random_user, find_user_by_ip, get_user_by_name,
                                rand_ip_from_network, host_mac, pick_active_session,
                                weighted_destination, random_external_ip, rare_external_ip,
                                rare_internal_host, rare_known_host, new_ftp_server_host,
                                known_internal_hosts, sweep_targets, stable_external_ip,
                                rare_source_host, rare_domain, NONSTD_HTTPS_PORTS, exfil_destination,
                                correlated_or_random_user, beacon_targets, recurring_host, stable_subset,
                                        ip_country, get_user_agent)
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
    # Active Directory App-IDs (names per Applipedia: active-directory-base,
    # ms-dc-replication; the category/risk attributes here are best estimates -- the
    # Applipedia detail API is reCAPTCHA-gated and the live feed has no AD traffic).
    "active-directory-base": ("business-systems", "auth-service", "client-server",   "Medium",        [135, 389]),
    "ms-dc-replication":     ("business-systems", "auth-service", "client-server",   "Medium",        []),
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
    "telnet":          ("networking",       "remote-access",     "client-server",   "High",          [23]),
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
    """The firewall's name — user-customisable via panw_ngfw_config.hostname."""
    return _get_config(config).get("hostname", "PA-VM-01")


def _fw_ip(config):
    """The firewall's own management/source IP — user-customisable via
    panw_ngfw_config.mgmt_ip (PAN stamps this in the syslog header when the device's
    'Syslog HOSTNAME Format' is set to ipv4-address)."""
    return _get_config(config).get("mgmt_ip", "10.0.0.1")


def _syslog_host(config):
    """The HOSTNAME field of the syslog header.  PAN-OS can emit either the device name
    or its IP there (Device -> Setup -> Management -> Syslog HOSTNAME Format); honour the
    panw_ngfw_config.syslog_hostname_format setting ('hostname' default, or 'ipv4-address')."""
    fmt = str(_get_config(config).get("syslog_hostname_format", "hostname")).lower()
    return _fw_ip(config) if fmt in ("ipv4-address", "ip", "ipv4", "ipv6-address") else _fw_name(config)


def _session_id():
    return str(random.randint(100000, 2147483647))


def _seqno():
    return str(random.randint(7000000000000000000, 7999999999999999999))


def _random_mac(host=None):
    if host:
        return host_mac(host)
    ouis = ["00:50:56", "b4:0c:25", "00:1b:17", "e4:a7:a0"]
    return f"{random.choice(ouis)}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"


# --- Device-ID: one stable profile per host ---------------------------------------------
# PAN Device-ID fields (source_/dest_device_category, profile, model, vendor, osfamily,
# osversion, mac) are documented columns of the traffic format. They are stable properties
# of a machine, so they come from the session identity (os_type/os_version/device_type)
# when the host is a known user device, else from a hash of the host: never a per-event
# draw, which used to flip a host's OS family between consecutive logs.
_HOST_INFO = {}          # source ip -> session user info, filled as identities are picked

_DEVICE_MODELS = {
    "Windows": [("Dell Inc.", "Latitude 7440"), ("Lenovo", "ThinkPad T14 Gen 4"),
                ("HP", "EliteBook 840 G10")],
    "Mac":     [("Apple", "MacBookPro18,3"), ("Apple", "MacBookAir10,1")],
    "Linux":   [("Dell Inc.", "Precision 3660"), ("Lenovo", "ThinkPad P1 Gen 6")],
    "iOS":     [("Apple", "iPhone15,2"), ("Apple", "iPad13,1")],
    "Android": [("Samsung", "SM-S911B"), ("Google", "Pixel 8")],
}
_SERVER_MODELS = [("Dell Inc.", "PowerEdge R750"), ("VMware, Inc.", "VMware Virtual Platform"),
                  ("HPE", "ProLiant DL380 Gen10")]
_OS_VERSIONS = {"Windows": ["11", "10"], "Mac": ["14.5", "13.6"], "Linux": ["22.04", "24.04"],
                "iOS": ["17.5"], "Android": ["14"]}
_PROFILES = {"Windows": "Windows Workstation", "Mac": "Apple Mac", "Linux": "Linux Workstation",
             "iOS": "Apple iPhone", "Android": "Android Phone"}


def _h(s):
    return int(hashlib.sha256(str(s).encode()).hexdigest(), 16)


def _remember(info):
    """Record a picked identity so every log for its address carries the same device."""
    if info and info.get("ip"):
        _HOST_INFO[info["ip"]] = info
    return info


def _osfamily(os_type):
    o = str(os_type or "").lower()
    if "win" in o:
        return "Windows"
    if "mac" in o or "darwin" in o or "os x" in o:
        return "Mac"
    if "ios" in o or "iphone" in o or "ipad" in o:
        return "iOS"
    if "android" in o:
        return "Android"
    if "linux" in o or "ubuntu" in o:
        return "Linux"
    return None


def _src_device(ip, host, category="workstation"):
    """Device-ID columns for a source host (prefix 'source_device_')."""
    if not _is_internal(ip):            # Device-ID profiles only the firewall's own networks
        return {}
    if category == "unknown":           # unmanaged: Device-ID has no profile for it
        return {"category": "unknown"}
    if category in ("server", "dc"):
        return _server_device(ip, host, "Windows" if category == "dc" else None)
    info = _HOST_INFO.get(ip) or {}
    fam = _osfamily(info.get("os_type"))
    if not fam:
        names, w = zip(*_SRC_OSFAMILY)
        fam = random.Random(_h(f"fam|{host or ip}")).choices(names, weights=w)[0]
    if str(info.get("device_type", "")).lower() in ("mobile", "phone", "tablet") and fam in ("Windows", "Mac", "Linux"):
        fam = "iOS" if fam == "Mac" else "Android"
    vendor, model = _DEVICE_MODELS[fam][_h(f"model|{host or ip}") % len(_DEVICE_MODELS[fam])]
    osver = str(info.get("os_version") or _OS_VERSIONS[fam][_h(f"osv|{host or ip}") % len(_OS_VERSIONS[fam])])
    return {"category": "mobile" if fam in ("iOS", "Android") else category,
            "profile": _PROFILES[fam], "model": model, "vendor": vendor,
            "osfamily": fam, "osversion": osver, "mac": host_mac(host) if host else None,
            "host": host}


def _dst_device(config, ip, host):
    """Device-ID columns for an internal destination (prefix 'dest_device_')."""
    if not _is_internal(ip):
        return {}
    if ip in set(_dcs(config)):
        return _server_device(ip, host, "Windows")
    if ip in set(config.get("internal_servers") or []):
        return _server_device(ip, host)
    return _src_device(ip, host)       # a workstation on the receiving end


def _server_device(ip, host, fam=None):
    """Device-ID columns for a server: DCs are Windows; others Windows or Linux, stable."""
    fam = fam or ("Windows" if _h(f"srvos|{ip}") % 3 else "Linux")
    vendor, model = _SERVER_MODELS[_h(f"srvmodel|{ip}") % len(_SERVER_MODELS)]
    return {"category": "server", "profile": f"{fam} Server", "model": model, "vendor": vendor,
            "osfamily": fam, "osversion": "Server 2022" if fam == "Windows" else "22.04",
            "mac": host_mac(host) if host else None, "host": host}


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
def _format_cef(config, subtype, fields, log_type="TRAFFIC", severity=1, ts=None, fw_type=None):
    """Build one PAN-OS NGFW_CEF syslog line.

    Header:  CEF:0|PANW|NGFW_CEF|<sw>|<subtype>|<type>|<sev>|
    Body:    literal key=value pairs (PAN custom log format), space separated.
    `ts` is the event epoch seconds (defaults to now); it drives log_time/time_generated/rt.
    `fw_type` overrides the __firewall_type routing key: a URL log is log_type THREAT but
    routes as firewall.url (into panw_ngfw_url_raw).
    """
    t = ts if ts is not None else time.time()
    serial, name = _serial(config), _fw_name(config)
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t))
    # The documented __timestamp is $start (session START) and __tz is $high_res_timestamp;
    # time_generated is when the log was written, i.e. the session end.
    try:
        start = t - float(fields.get("total_time_elapsed") or 0)
    except (TypeError, ValueError):
        start = t
    start_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(start))
    hires = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}+00:00"
    base = {
        "__firewall_type": fw_type or f"firewall.{log_type.lower()}",
        "__timestamp":     start_iso,
        "__tz":            hires,
        # The Syslog Collector routes on __firewall_type but does NOT rename the body: each
        # key lands as a column of that name. So the documented `subtype` is sent alongside
        # `sub_type`, the column the dataset (and its modeling rule's FAILED-on-deny/drop
        # outcome) actually reads, and log_type is lowercase as in the live CLCS rows.
        "log_type":        log_type.lower(),
        "subtype":         subtype,
        "sub_type":        subtype,
        "log_time":        iso,
        "time_generated":  iso,
        "rt":              str(int(t * 1000)),   # event time; _time is still the ingest time
        "time_generated_high_res": hires,
        "session_start_time": start_iso,
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
    keep_bare = merged.pop("_no_user_qualify", False)
    for uf in ("source_user", "dest_user", "users"):
        uv = merged.get(uf)
        if uf == "users" and uv == merged.get("source_ip"):
            continue                    # no User-ID: the column holds the address
        if uv and "\\" not in str(uv) and "@" not in str(uv) and not keep_bare:
            merged[uf] = f"EXAMPLECORP\\{uv}"
    ext = " ".join(f"{k}={_cef_escape(v)}" for k, v in merged.items() if v is not None and v != "")
    sw = _get_config(config).get("sw_version", _SW_VERSION)
    header = f"CEF:0|PANW|NGFW_CEF|{sw}|{subtype}|{log_type.lower()}|{severity}|"
    syslog_ts = time.strftime("%b %d %H:%M:%S", time.gmtime(t))
    return f"<{_SYSLOG_PRI}>{syslog_ts} {_syslog_host(config)} {header} {ext}"


def _traffic_fields(config, src_ip, dst_ip, dpt, app, action="allow", *,
                    shost=None, suser=None, dhost=None, duser=None, proto=None,
                    from_zone="trust", to_zone="untrust", bytes_sent=None, bytes_received=None,
                    duration_s=None, end_reason=None, url_cat=None, nat_src=None, nat_dpt=None,
                    spt=None, src_category="workstation", rule=None):
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
        # A blocked connection is zero-byte: PAN logs the dropped SYN with no payload, and
        # the Failed Connections detector keys on failed, zero-byte attempts.
        bytes_sent, bytes_received, duration_s = 0, 0, 0
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
        # Real column: the User-ID user when known, else the source address (as in the
        # live CLCS rows, which have no User-ID and show the IP).
        "users":            suser or src_ip,
        "url_category":     url_cat or (random.choice(_URL_CAT_BENIGN) if meta[2] == "browser-based" else ""),
        # Columns the traffic modeling rule reads (phantom data_source.yaml) and the live rows
        # carry; not in the documented custom format, so sent under their column names.
        "log_source":       "firewall",
        "is_nat":           "false" if internal_dst else "true",
        "is_proxy":         "false",
        "source_location":  _location(src_ip, config),
        "dest_location":    _location(dst_ip, config),
    }
    defaults = meta[4]
    nonstd = bool(defaults) and dpt not in defaults and app not in ("incomplete", "insufficient-data")
    f["is_non_std_dest_port"] = 1 if nonstd else 0
    f["non_standard_dest_port"] = dpt if nonstd else 0
    for k, v in _src_device(src_ip, shost, src_category).items():
        f[f"source_device_{k}"] = v
    for k, v in _dst_device(config, dst_ip, dhost).items():
        f[f"dest_device_{k}"] = v
    # dest_device_host also names EXTERNAL destinations (the resolved FQDN): the modeling
    # rule maps it to xdm.target.host.hostname, the only hostname a traffic log can carry.
    f["dest_device_host"] = dhost
    # NAT only when the destination is external.
    if not internal_dst:
        f["nat_source"]      = nat_src or _nat_for(src_ip, config)
        f["nat_source_port"] = random.randint(20000, 65000)
        f["nat_dest"]        = dst_ip
        f["nat_dest_port"]   = nat_dpt or dpt
    return f


_PRIVATE_RANGES = (("10.0.0.0/8", "10.0.0.0-10.255.255.255"),
                   ("172.16.0.0/12", "172.16.0.0-172.31.255.255"),
                   ("192.168.0.0/16", "192.168.0.0-192.168.255.255"))


def _location(ip, config):
    """source_/dest_location as the live rows show it: the RFC1918 range for private
    addresses, the two-letter country for public ones when the address comes from a
    probed pool, else omitted (XSIAM geolocates the address itself)."""
    try:
        a = ip_address(ip)
    except ValueError:
        return None
    for net, label in _PRIVATE_RANGES:
        if a in ip_network(net):
            return label
    code, _name = ip_country(ip, config)
    return code


# Keys a URL log shares with the traffic log of the same session.
_URL_SHARED_KEYS = ("source_ip", "source_port", "dest_ip", "dest_port", "nat_source",
                    "nat_source_port", "nat_dest", "nat_dest_port", "protocol", "source_user",
                    "dest_user", "users", "app", "app_category", "app_sub_category",
                    "technology_of_app", "risk_of_app", "rule_matched", "rule_matched_uuid",
                    "from_zone", "to_zone", "inbound_if", "outbound_if", "session_id",
                    "log_source", "is_nat", "is_proxy", "source_location", "dest_location",
                    "source_device_category", "source_device_profile", "source_device_model",
                    "source_device_vendor", "source_device_osfamily", "source_device_osversion",
                    "source_device_mac", "source_device_host")


_UA_TOKEN = {"Windows": "Windows NT", "Mac": "Macintosh", "Linux": "X11; Linux",
             "iOS": "iPhone", "Android": "Android"}
_BROWSER_UAS = {
    "Windows": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"],
    "Mac":     ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"],
    "Linux":   ["Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0"],
    "iOS":     ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"],
    "Android": ["Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36"],
}


def _browser_ua(fam, session_ua, key):
    """The host's browser User-Agent: its session identity's UA when that matches the
    device's OS family, else a stable one for the family (the session pool does not
    always agree with os_type, and a Linux UA on a Windows device is a tell)."""
    fam = fam if fam in _BROWSER_UAS else "Windows"
    if session_ua and _UA_TOKEN[fam] in session_ua:
        return session_ua
    pool = _BROWSER_UAS[fam]
    return pool[_h(f"ua|{key}") % len(pool)]


def _url_record(config, traffic_fields, domain, path="/", category=None, action="alert",
                ts=None, method=None, user_agent=None):
    """The URL-filtering log PAN-OS writes for a web session (log_type THREAT, subtype url).

    Shape learned from the live panw_ngfw_url_raw feed: action=alert for an allowed,
    logged URL; uri=<host><path> (the parser derives url_domain from it); http_method
    'unknown' for undecrypted SSL. This is the only PAN log that names the DOMAIN — traffic
    logs carry addresses only — so the rare-domain / dynamic-DNS detectors need it.
    """
    f = {k: traffic_fields[k] for k in _URL_SHARED_KEYS if traffic_fields.get(k) not in (None, "")}
    cat = category or traffic_fields.get("url_category") or "computer-and-internet-info"
    risk = "high-risk" if cat in _URL_CAT_RISKY else "low-risk"
    clear = f.get("app") != "ssl"          # undecrypted SSL exposes the SNI host only
    info = _HOST_INFO.get(f.get("source_ip")) or {}
    f.update({
        "action":            action,
        "uri":               f"{domain}{path}",
        "url_domain":        domain,      # no parser derives it from uri on this path
        "url_category":      cat,
        "url_category_list": f"{cat},{risk}",
        "http_method":       method or ("get" if clear else "unknown"),
        "threat_id":         "9999",
        "threat_name":       "",
        "direction":         "client-to-server",
        "direction_of_attack": "client to server",   # the live column (doc key: direction)
        "severity":          "Informational",          # the live column's value
        # The user's own browser (one stable UA per user/device), or the caller's override
        # (scripted / non-browser clients).
        "user_agent":        user_agent or _browser_ua(f.get("source_device_osfamily"),
                                                       info.get("user_agent"), f.get("source_ip")),
        "content_type":      ("text/html" if clear else None),
        "http2_connection":  0,
        "referer":           (f"https://{domain}/" if clear and path not in ("/", "") else None),
    })
    return _format_cef(config, "url", f, log_type="THREAT", severity=1, ts=ts, fw_type="firewall.url")


# ---------------------------------------------------------------------------
# Benign generators
# ---------------------------------------------------------------------------
def _user_src(config, session_context, prefer_active=True):
    """(src_ip, username, hostname) for a benign actor, preferring a bus-correlated user."""
    if session_context:
        info = (correlated_or_random_user(session_context, preferred_device_type="workstation")
                if prefer_active else get_random_user(session_context, preferred_device_type="workstation"))
        if info:
            _remember(info)
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
    line = _format_cef(config, "end", dict(f))
    # Web sessions also get the URL log the URL-filtering profile writes (~1 in 6 traffic
    # logs in the live feed), so the domain baseline exists on this firewall too.
    if dpt in (80, 443, 8080) and random.random() < 0.35:
        return [line, _url_record(config, f, domain, path=random.choice(["/", "/", "/api/", "/login"]))]
    return line


# Users with an everyday SSH habit (admins/engineers reaching their usual jump host). The
# "Uncommon SSH session" detector judges an SSH session against the source's OWN SSH
# history, and with no back-dating that history has to accrue on real days in the benign
# baseline; _sim_uncommon_ssh then comes from one of these users.
_SSH_HABIT_N = 8


def _ssh_habit_users(session_context):
    return stable_subset(list(session_context or {}), "panw_ssh_habit", n=_SSH_HABIT_N)


def _usual_jump_host(config, user):
    hosts = (mgmt_plane.conf(config).get("jump_hosts") or config.get("internal_servers")
             or ["10.0.30.30"])
    return hosts[int(hashlib.sha256(f"jump|{user}".encode()).hexdigest(), 16) % len(hosts)]


def _benign_ssh_habit(config, session_context):
    """One of the SSH-habit users opens an ordinary SSH session to their usual jump host."""
    user = random.choice(_ssh_habit_users(session_context))
    info = _remember(get_user_by_name(session_context, user, "workstation"))
    if not info:
        return None
    jump = _usual_jump_host(config, user)
    f = _traffic_fields(config, info["ip"], jump, 22, "ssh", shost=info.get("hostname"), suser=user,
                        dhost=resolver.internal_fqdn(config, jump), from_zone="trust", to_zone="trust",
                        bytes_sent=random.randint(3000, 40000), bytes_received=random.randint(5000, 90000),
                        duration_s=random.randint(60, 1800))
    return _format_cef(config, "end", f)


def _benign_internal(config, session_context):
    """East-west session: workstation -> internal server (AD / file / RDP baseline)."""
    if session_context and random.random() < 0.04:
        line = _benign_ssh_habit(config, session_context)
        if line:
            return line
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
    if app in ("kerberos", "ldap", "msrpc-base") or (app == "ms-ds-smbv3" and random.random() < 0.3):
        # AD authentication, directory lookups, RPC and SYSVOL/NETLOGON SMB go to the domain
        # controllers. XSIAM classifies a host as a DC from exactly this traffic, which the
        # SMB-from-DC and DCSync-from-non-DC detectors depend on.
        dst_ip = random.choice(_dcs(config))
    else:
        dst_ip = random.choice(config.get("internal_servers") or ["10.0.10.50"])
    dpt = (_APP.get(app, (None,)*5)[4] or [445])[0]
    dhost = resolver.internal_fqdn(config, dst_ip)
    f = _traffic_fields(config, src_ip, dst_ip, dpt, app, shost=shost, suser=user, dhost=dhost,
                        from_zone="trust", to_zone="trust",
                        bytes_sent=random.randint(500, 60000), bytes_received=random.randint(800, 120000))
    return _format_cef(config, "end", f)


def _dmz_servers(config):
    """The published web servers: the Apache httpd module's servers when configured (so the
    firewall and the httpd access logs describe the same hosts), else a stable pair."""
    a = config.get("apache_config") or {}
    ips = a.get("server_ips") or ([a["server_ip"]] if a.get("server_ip") else [])
    return ips or stable_subset(config.get("internal_servers") or ["10.0.10.50"], "panw_dmz", n=2)


def _ingress_client(config):
    """An internet client address from the probed benign ingress ranges."""
    srcs = [s for s in config.get("benign_ingress_sources") or [] if s.get("ip_range")]
    if srcs:
        try:
            return rand_ip_from_network(ip_network(random.choice(srcs)["ip_range"], strict=False))
        except ValueError:
            pass
    return random_external_ip()


def _benign_published_service(config):
    """Internet client -> the published web site (untrust -> dmz, 443, allowed). It is also
    what makes the DMZ servers "internet-facing" to XSIAM, the premise of the
    internet-facing-server detector variations."""
    srv = random.choice(_dmz_servers(config))
    # The server's own grid name: a private host is named on examplecorp.local; the public
    # site name (www.examplecorp.com) resolves to a public address, not to this one.
    f = _traffic_fields(config, _ingress_client(config), srv, 443, "ssl",
                        dhost=resolver.internal_fqdn(config, srv),
                        from_zone="untrust", to_zone="dmz", rule="Allow-Inbound-Web",
                        bytes_sent=random.randint(600, 20000), bytes_received=random.randint(3000, 600000),
                        duration_s=random.randint(1, 120))
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
    if r < 0.58:
        return _benign_external(config, session_context)
    if r < 0.86:
        return _benign_internal(config, session_context)
    if r < 0.93:
        return _benign_published_service(config)
    return _benign_inbound_block(config)


# ---------------------------------------------------------------------------
# Threat catalog
# ---------------------------------------------------------------------------
# analytic: True  -> built to fire a native PAN NGFW traffic-log analytic (offered on demand)
# analytic: False -> realistic traffic for hunts / correlation, but no traffic-log analytic
#                    will fire (Kerberos/NTLM/dormant-account detectors need EAL-decoded
#                    protocol fields a CEF traffic log does not carry; uncommon-AppID and the
#                    SSH-to-cloud/process variations additionally require the XDR Agent).
# Targets name the alert the tenant actually raises: where a detector's base name is
# Informational (never shown in the alerts table) and the shape produces a Low variation,
# the variation is the target (e.g. Port Scan fires as "Suspicious port scan").
_DEFAULT_THREAT_EVENTS = [
    {"event": "port_scan",            "weight": 8,  "analytic": True,  "xsiam_alert": "Suspicious port scan"},
    {"event": "port_sweep",           "weight": 6,  "analytic": True,  "xsiam_alert": "Port Sweep to multiple subnets"},
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
    {"event": "uncommon_ssh_rare_internal", "weight": 2, "analytic": True, "xsiam_alert": "Uncommon SSH session was established to a rare internal IP"},
    {"event": "uncommon_ssh_nonstd_port", "weight": 2, "analytic": True, "xsiam_alert": "An Uncommon SSH session was established using a nonstandard SSH port"},
    {"event": "unusual_ssh",          "weight": 2,  "analytic": True,  "xsiam_alert": "Unusual, long SSH activity with tunnel characteristics"},
    {"event": "unusual_ssh_external", "weight": 2,  "analytic": True,  "xsiam_alert": "Unusual SSH activity with tunnel characteristics to external destination"},
    {"event": "ssh_proxy",            "weight": 2,  "analytic": True,  "xsiam_alert": "Unusual SSH activity that resembles SSH proxy"},
    # Re-targeted: "Rare process created an SSH session ..." keys on the PROCESS, which a
    # firewall log cannot carry (docs/firewall-analytics.md section 4). An SSH-habit user
    # reaching a rare external IP is the traffic-only "Uncommon SSH ... to a rare IP" variation.
    {"event": "rare_ssh_external",    "weight": 2,  "analytic": True,  "xsiam_alert": "An Uncommon SSH session was established to a rare IP address"},
    {"event": "recurring_rare_ip",    "weight": 4,  "analytic": True,  "xsiam_alert": "Recurring access to rare IP"},
    {"event": "recurring_rare_domain","weight": 4,  "analytic": True,  "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain With a Less Common Port"},
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
    # Traffic-only detector VARIATIONS (2026-10-22), each targeting the variation's own alert
    # name as Cortex lists it. HASSH / banner / process variations need EAL or the agent.
    {"event": "port_scan_aggressive", "weight": 2,  "analytic": True,  "xsiam_alert": "Highly suspicious port scan"},
    {"event": "ipfs_peering",         "weight": 2,  "analytic": True,  "xsiam_alert": "Possible IPFS traffic was detected"},
    {"event": "rare_domain_attack_port", "weight": 2, "analytic": True, "xsiam_alert": "Abnormal Communication to a Rare Domain With a Port Commonly Used by Attack Platforms"},
    {"event": "recurring_rare_domain_attack_port", "weight": 2, "analytic": True, "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain With a Port Commonly Used by Attack Platforms"},
    {"event": "recurring_rare_domain_suspicious_as", "weight": 2, "analytic": True, "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain to a Suspicious Autonomous System (AS)"},
    {"event": "dormant_host_known_source", "weight": 2, "analytic": True, "xsiam_alert": "Abnormal connections to a dormant host"},
    {"event": "large_upload_generic_small", "weight": 1, "analytic": True, "xsiam_alert": "Large Upload (Generic) Lower than 100 MB"},
    {"event": "new_ssh_admin_behavior", "weight": 2, "analytic": True,  "xsiam_alert": "New SSH Administrative Behavior"},
    {"event": "new_ftp_server_external", "weight": 2, "analytic": True, "xsiam_alert": "New FTP Server from an external source"},
    {"event": "dcsync_non_dc_appid", "weight": 1,  "analytic": True,  "xsiam_alert": "DCSync from a non domain controller"},
    {"event": "dcsync_internet_facing", "weight": 1, "analytic": True,  "xsiam_alert": "Possible DCSync from an internet-facing server"},
    {"event": "dcsync_large",         "weight": 1,  "analytic": True,  "xsiam_alert": "Large DCSync from a non domain controller"},
    {"event": "dcsync_large_appid",   "weight": 1,  "analytic": True,  "xsiam_alert": "Large DCSync from a non domain controller by AppID"},
    {"event": "rare_appid_internet_facing", "weight": 2, "analytic": True, "xsiam_alert": "Rare AppID usage to a rare destination from an internet-facing server"},
    # "Failed Spam Bot Traffic" is Informational: it never reaches the alerts table, so it
    # is not offered on demand. The traffic stays as background realism.
    {"event": "spam_bot_failed",      "weight": 2,  "analytic": False, "xsiam_alert": None},
    {"event": "ssh_suspicious_nonstd", "weight": 2, "analytic": True,  "xsiam_alert": "A suspicious SSH session was established"},
    {"event": "ssh_high_volume",      "weight": 2,  "analytic": True,  "xsiam_alert": "Uncommon SSH session was established that involved a higher than usual volume"},
    {"event": "ssh_proxy_high_volume", "weight": 1, "analytic": True,  "xsiam_alert": "High Volume Unusual SSH activity that resembles SSH proxy"},
    {"event": "ssh_proxy_suspicious", "weight": 1,  "analytic": True,  "xsiam_alert": "Suspicious SSH activity that resembles SSH proxy"},
    {"event": "ssh_proxy_detected",   "weight": 1,  "analytic": True,  "xsiam_alert": "Unusual SSH activity that resembles SSH proxy detected"},
    {"event": "host_attack_chain",    "weight": 2,  "analytic": True,  "xsiam_alert": "Multiple network-related alerts produced by different detectors on the same host"},
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


# Privileged service ports the port-scan / admin detectors profile.  Needs to be well
# above 24 so a scan can draw 20-24 DISTINCT ports (the "Suspicious port scan" threshold).
_PRIV_PORTS = [21, 22, 23, 25, 53, 88, 110, 111, 135, 137, 139, 143, 161, 389, 443, 445,
               465, 587, 636, 873, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
               5985, 5986]
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


def _web(config, src, dst, dpt, app, domain, *, path="/", url_cat=None, method=None, ts=None,
         user_agent=None, **kw):
    """[traffic:end, url] for one web session: same session_id, ports and NAT on both."""
    f = _traffic_fields(config, src, dst, dpt, app, dhost=domain, url_cat=url_cat,
                        **{k: v for k, v in kw.items() if k != "no_qualify"})
    if kw.get("no_qualify"):
        f["_no_user_qualify"] = True
    return [_format_cef(config, "end", dict(f), ts=ts),
            _url_record(config, f, domain, path=path, category=url_cat, method=method,
                        ts=(ts if ts is not None else time.time()), user_agent=user_agent)]


def _threat_actor(config, session_context):
    """(src_ip, user, hostname) for a user-attributed threat, preferring a correlated user."""
    return _user_src(config, session_context, prefer_active=True)


# --- Reconnaissance -------------------------------------------------------------------
def _scan_burst(config, src, user, shost, ports, end=None, step=2):
    """One source probing `ports` on a single internal server, ending at `end`."""
    target = random.choice(config.get("internal_servers") or ["10.0.10.50"])
    print(f"    - PAN NGFW simulating: port scan {src} -> {target} ({len(ports)} ports)")
    t0 = (end or time.time()) - len(ports) * step
    out = []
    for i, p in enumerate(ports):
        act = "allow" if p in (443, 445, 22) else random.choice(["deny", "drop", "allow"])
        out.append(_conn(config, src, target, p, "incomplete" if act != "allow" else _APP_for_port(p),
                         action=act, suser=user, shost=shost, from_zone="trust", to_zone="trust",
                         dhost=resolver.internal_fqdn(config, target), ts=t0 + i * step))
    return out


def _sim_port_scan(config, session_context):
    """One host hits 20-24 distinct privileged ports on a single internal server."""
    src, user, shost = _threat_actor(config, session_context)
    return _scan_burst(config, src, user, shost,
                       random.sample(_PRIV_PORTS, min(len(_PRIV_PORTS), random.randint(20, 24))))


def _sim_port_scan_aggressive(config, session_context):
    """"Highly suspicious port scan": every privileged port plus 60-100 high ports on one
    server inside ~3 minutes -- a full-range sweep, not a 20-port service check."""
    src, user, shost = _threat_actor(config, session_context)
    high = random.sample(range(1024, 10000), random.randint(60, 100))
    ports = list(dict.fromkeys(_PRIV_PORTS + high))
    random.shuffle(ports)
    return _scan_burst(config, src, user, shost, ports, step=1)


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


def _failed_burst(config, src, user, shost, end=None):
    """~120 zero-byte denied connections to ~40 never-seen internal hosts, ending at `end`."""
    hosts = [rare_internal_host(config) for _ in range(random.randint(38, 44))]
    print(f"    - PAN NGFW simulating: failed connections {src} -> {len(hosts)} inactive hosts")
    n = random.randint(110, 130)
    t0 = (end or time.time()) - n * 2
    out = []
    for i in range(n):
        dst = random.choice(hosts)
        out.append(_conn(config, src, dst, random.choice([445, 139, 3389, 22, 1433]), "incomplete",
                         action="deny", suser=user, shost=shost, from_zone="trust", to_zone="trust",
                         ts=t0 + i * 2, end_reason="aged-out"))
    return out


def _sim_failed_connections(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    return _failed_burst(config, src, user, shost)


# --- Exfil / large uploads ------------------------------------------------------------
def _rare_answer(domain, seed=None):
    """Pin `domain` to an address in the RARE external pool and return it.

    resolver.answer_for() alone is wrong for threat destinations: an unknown name falls back
    to stable_external_ip(), which is the AMBIENT pool every module's normal traffic uses, so
    the destination can never score as rare (docs/firewall-analytics.md, root cause R3).
    Pinning keeps the Infoblox answer and the firewall destination identical."""
    ip = rare_external_ip(seed if seed is not None else domain)
    return resolver.pin(domain, f"{ip}/32") or ip


def _rare_ext(config, seed=None):
    """(domain, ip) for a rare external destination."""
    dom = rare_domain(seed)
    return dom, _rare_answer(dom, seed)


def _sim_large_upload(config, session_context, app, dpt, size_mb=(300, 700), actor=None, end=None):
    src, user, shost = actor or _threat_actor(config, session_context)
    # One 300-700 MB session: the size of the Check Point uploads that fire Large Upload
    # (HTTPS) in this tenant ("uploaded 347.2MB ... over 1 sessions"); 5-100 MB is under
    # the threshold and multi-GB is not what fired.
    size = random.randint(*size_mb) * 1024 * 1024
    kw = dict(suser=user, shost=shost, bytes_sent=size, bytes_received=random.randint(2000, 50000),
              duration_s=random.randint(300, 1200), ts=end)
    if app == "ssl":
        # HTTPS goes to the shared exfil pool (file-sharing services plus long-tail hosts),
        # the destinations the firing Check Point alerts used. PAN also writes the URL log
        # (SNI host), the only record that names the site.
        dom, dst, url, is_tail = exfil_destination(config, "upload")
        path = "/" + url.split("://", 1)[-1].split("/", 1)[1] if "/" in url.split("://", 1)[-1] else "/"
        cat = "unknown" if is_tail else "online-storage-and-backup"
        print(f"    - PAN NGFW simulating: large upload (ssl) {src} -> {dom}:{dpt} {size//(1024*1024)}MB")
        return _web(config, src, dst, dpt, app, dom, path=path, url_cat=cat, **kw)
    dom, dst = _rare_ext(config, f"up|{app}|{user}")
    print(f"    - PAN NGFW simulating: large upload ({app}) {src} -> {dom}:{dpt} {size//(1024*1024)}MB")
    return [_conn(config, src, dst, dpt, app, dhost=dom, url_cat="online-storage-and-backup", **kw)]


def _sim_large_upload_https(config, sc):      return _sim_large_upload(config, sc, "ssl", 443)
def _sim_large_upload_https_nonstd(config, sc):
    # session_utils.to_nonstandard_https() rewrites the ArcSight `dpt=` key; PAN logs carry
    # dest_port, so pick the alternate HTTPS port here instead.
    return _sim_large_upload(config, sc, "ssl", random.choice(NONSTD_HTTPS_PORTS))
def _sim_large_upload_smtp(config, sc):       return _sim_large_upload(config, sc, "smtp", 587)
def _sim_large_upload_ftp(config, sc):        return _sim_large_upload(config, sc, "ftp", 21)
def _sim_large_upload_generic(config, sc):    return _sim_large_upload(config, sc, "unknown-tcp", random.choice([4444, 9001, 8888, 6667]))
def _sim_large_upload_generic_small(config, sc):
    """"Large Upload (Generic) Lower than 100 MB": the same shape at 60-95 MB."""
    return _sim_large_upload(config, sc, "unknown-tcp", random.choice([9001, 8888, 6667, 7000]), size_mb=(60, 95))


def _sim_host_attack_chain(config, session_context):
    """One host trips several DIFFERENT detectors within the hour -- internal port scan,
    failed connections across the subnet, then a generic-protocol upload out -- the shape
    XSIAM rolls up into "Multiple network-related alerts produced by different detectors on
    the same host" (the NDR-insight case seen from the real pa440). Each stage on its own is
    a detector this module confirmed firing; the roll-up only needs them on one host."""
    src, user, shost = _threat_actor(config, session_context)
    now = time.time()
    print(f"    - PAN NGFW simulating: multi-detector attack chain on {src}")
    return (_scan_burst(config, src, user, shost,
                        random.sample(_PRIV_PORTS, min(len(_PRIV_PORTS), random.randint(20, 24))),
                        end=now - 40 * 60)
            + _failed_burst(config, src, user, shost, end=now - 20 * 60)
            + _sim_large_upload(config, session_context, "unknown-tcp", random.choice([9001, 8888, 6667]),
                                actor=(src, user, shost), end=now - 60))


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
        out.append(_conn(config, dc, dst, 445, "ms-ds-smbv3", suser="SYSTEM", no_qualify=True, src_category="dc",
                         shost=resolver.internal_fqdn(config, dc), from_zone="trust", to_zone="trust",
                         bytes_sent=random.randint(5000, 50000), bytes_received=random.randint(5000, 200000),
                         duration_s=random.randint(5, 60)))
    return out


def _dcsync(config, src, user, shost, from_zone="trust", large=False, src_category="workstation",
            appid=False):
    """AD-replication RPC (DRSUAPI) from a NON-DC host to a DC: the endpoint mapper on 135,
    then the replication itself on dynamic high ports. `large` pulls the whole directory
    (hundreds of MB), the "Large DCSync" variations. `appid` has App-ID name the replication
    sessions ms-dc-replication (the "... by AppID" / App-ID-identified variations) instead of
    leaving them as generic msrpc-base."""
    dc = random.choice(_dcs(config))
    dcname = resolver.internal_fqdn(config, dc)
    repl_app = "ms-dc-replication" if appid else "msrpc-base"
    print(f"    - PAN NGFW simulating: DCSync{' (large)' if large else ''} {src} -> DC {dc} as {repl_app}")
    out = [_conn(config, src, dc, 135, "msrpc-base", suser=user, shost=shost, dhost=dcname,
                 from_zone=from_zone, to_zone="trust", src_category=src_category,
                 bytes_sent=random.randint(2000, 9000), bytes_received=random.randint(5000, 40000),
                 duration_s=random.randint(1, 10))]
    n = random.randint(3, 6)
    for _ in range(n):
        rcvd = (random.randint(150, 600) * 1024 * 1024 // n) if large else random.randint(200000, 8000000)
        out.append(_conn(config, src, dc, random.randint(49152, 65535), repl_app, suser=user,
                         shost=shost, dhost=dcname, from_zone=from_zone, to_zone="trust",
                         src_category=src_category, bytes_sent=random.randint(20000, 400000),
                         bytes_received=rcvd, duration_s=random.randint(20, 300) if large else random.randint(2, 40)))
    return out


def _sim_dcsync_non_dc(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    return _dcsync(config, src, user, shost)


def _sim_dcsync_non_dc_appid(config, session_context):
    """"DCSync from a non domain controller": replication App-ID-identified as
    ms-dc-replication, ordinary volume."""
    src, user, shost = _threat_actor(config, session_context)
    return _dcsync(config, src, user, shost, appid=True)


def _sim_dcsync_large(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    return _dcsync(config, src, user, shost, large=True)


def _sim_dcsync_large_appid(config, session_context):
    """"Large DCSync from a non domain controller by AppID": the whole directory pulled over
    sessions App-ID-identified as ms-dc-replication."""
    src, user, shost = _threat_actor(config, session_context)
    return _dcsync(config, src, user, shost, large=True, appid=True)


def _sim_dcsync_internet_facing(config, session_context):
    """DCSync from a DMZ web server: an internet-facing host compromised and used as a rogue
    DC ("Possible DCSync from an internet-facing server"). Runs as the service account."""
    srv = random.choice(_dmz_servers(config))
    return _dcsync(config, srv, "svc_web", resolver.internal_fqdn(config, srv), from_zone="dmz",
                   src_category="server")


# --- SMTP ------------------------------------------------------------------------------
def _sim_rare_smtp(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"smtp|{user}")
    return [_conn(config, src, dst, random.choice([25, 587, 465]), "smtp", suser=user, shost=shost,
                  dhost=dom, bytes_sent=random.randint(5000, 80000), bytes_received=random.randint(300, 4000),
                  duration_s=random.randint(1, 30))]


def _recipient_domain(i):
    """A recipient mail domain: a real long-tail registrable domain when the corpus is
    loaded, else a synthetic one."""
    try:
        from modules import domain_corpus
    except ImportError:
        import domain_corpus
    d = domain_corpus.tail_domain("web") if domain_corpus.available() else None
    return d or rare_domain(f"rcpt|{i}|{random.random()}")


def _sim_spam_bot(config, session_context):
    """One host talking SMTP straight to an excessive number of external mail servers.

    Per the detector: "the volume of traffic is not considered. A count is performed based
    on the number of domains being contacted, as well as the number of unresolved IP
    addresses." So about half the servers are the MX hosts of distinct recipient domains
    (named, resolver-consistent) and the rest are bare, never-resolved IPs, on 25 / 587 /
    465. The Spam Bot alerts that fire here (Check Point, Firepower, FortiGate) read
    "connected to 13-48 SMTP servers in the last 3 days" with app_id ip,tcp,smtp."""
    src, user, shost = _threat_actor(config, session_context)
    # A spam run: 150-300 distinct mail servers, 400-800 SMTP sessions (some servers take
    # several deliveries), spread over the last ~2 hours.
    servers, domains = [], set()
    for i in range(random.randint(150, 300)):
        if random.random() < 0.5:
            dom = _recipient_domain(i)
            domains.add(dom)
            mx = f"{random.choice(['mx', 'mx1', 'mail', 'smtp'])}.{dom}"
            servers.append((resolver.answer_for(mx, config), mx))
        else:
            servers.append((random_external_ip(), None))      # unresolved: no DNS behind it
    n = random.randint(max(400, len(servers)), 800)
    picks = servers + [random.choice(servers) for _ in range(n - len(servers))]
    random.shuffle(picks)
    span = random.randint(5400, 7200)
    t0 = time.time() - span
    out = []
    for i, (dst, dhost) in enumerate(picks):
        port = random.choices([25, 587, 465], weights=[70, 20, 10])[0]
        out.append(_conn(config, src, dst, port, "ssl" if port == 465 else "smtp", suser=user,
                         shost=shost, dhost=dhost, bytes_sent=random.randint(2000, 40000),
                         bytes_received=random.randint(200, 2000), duration_s=random.randint(1, 20),
                         ts=t0 + span * i / n))
    print(f"    - PAN NGFW simulating: spam bot {src} -> {n} SMTP sessions to {len(servers)} servers "
          f"({len(domains)} recipient domains, {len(servers) - len(domains)} unresolved IPs)")
    return out


def _sim_spam_bot_failed(config, session_context):
    """"Failed Spam Bot Traffic": the same fan-out to external SMTP servers, but most of them
    refuse it (reset by the server or never answering), as blocklisted spam senders see."""
    src, user, shost = _threat_actor(config, session_context)
    n = random.randint(40, 90)
    print(f"    - PAN NGFW simulating: failed spam bot {src} -> {n} external SMTP servers")
    t0 = time.time() - n * 30
    out = []
    for i in range(n):
        ok = random.random() < 0.2
        out.append(_conn(config, src, random_external_ip(), 25, "smtp" if ok else "incomplete",
                         suser=user, shost=shost,
                         bytes_sent=random.randint(2000, 20000) if ok else random.randint(60, 180),
                         bytes_received=random.randint(200, 2000) if ok else 0,
                         duration_s=random.randint(1, 20) if ok else 0,
                         end_reason=None if ok else random.choice(["tcp-rst-from-server", "aged-out"]),
                         ts=t0 + i * 30))
    return out


# --- SSH -------------------------------------------------------------------------------
_NONSTD_SSH_PORTS = (2222, 2022, 22222, 8022, 10022)


def _ssh_habit_actor(config, session_context):
    """(src, user, shost) of an SSH-habit user (has real SSH history), else any actor."""
    habit = _ssh_habit_users(session_context)
    info = _remember(get_user_by_name(session_context, random.choice(habit), "workstation")) if habit else None
    if info:
        return info["ip"], info["username"], info.get("hostname")
    return _threat_actor(config, session_context)


def _sim_ssh_suspicious_nonstd(config, session_context):
    """"A suspicious SSH session was established": SSH to a globally rare external IP on a
    non-standard SSH port (App-ID still identifies ssh on any port)."""
    src, user, shost = _ssh_habit_actor(config, session_context)
    dom, dst = _rare_ext(config, f"sshnonstd|{user}")
    port = random.choice(_NONSTD_SSH_PORTS)
    print(f"    - PAN NGFW simulating: SSH to rare external {dst}:{port} from {src}")
    return [_conn(config, src, dst, port, "ssh", suser=user, shost=shost, dhost=dom,
                  bytes_sent=random.randint(5000, 200000), bytes_received=random.randint(5000, 400000),
                  duration_s=random.randint(60, 1800))]


def _sim_ssh_high_volume(config, session_context):
    """"Uncommon SSH session ... higher than usual volume": an SSH-habit user's ordinary SSH
    to their usual jump host, but moving hundreds of MB instead of their usual KB."""
    src, user, shost = _ssh_habit_actor(config, session_context)
    jump = _usual_jump_host(config, user)
    print(f"    - PAN NGFW simulating: high-volume SSH {src} -> usual jump host {jump}")
    return [_conn(config, src, jump, 22, "ssh", suser=user, shost=shost,
                  dhost=resolver.internal_fqdn(config, jump), from_zone="trust", to_zone="trust",
                  bytes_sent=random.randint(300, 900) * 1024 * 1024,
                  bytes_received=random.randint(5, 40) * 1024 * 1024,
                  duration_s=random.randint(1800, 7200), end_reason="tcp-fin")]


# --- SSH (habit users reaching rare destinations) ----------------------------------------
def _uncommon_ssh(config, session_context, dest="known", port=22):
    """An SSH session from an SSH-habit user (real per-host SSH history, the baseline the
    detector compares against) to an uncommon destination. `dest`: "known" a rarely-used but
    previously-seen internal host; "rare_internal" a never-seen internal address."""
    src, user, shost = _ssh_habit_actor(config, session_context)
    if dest == "rare_internal":
        dst = rare_internal_host(config, exclude=(src, _usual_jump_host(config, user)))
    else:
        dst = rare_known_host(config, exclude=(src,))
    print(f"    - PAN NGFW simulating: uncommon SSH {src} -> {dst}:{port} ({dest})")
    return [_conn(config, src, dst, port, "ssh", suser=user, shost=shost,
                  dhost=resolver.internal_fqdn(config, dst), from_zone="trust", to_zone="trust",
                  bytes_sent=random.randint(3000, 60000), bytes_received=random.randint(4000, 120000),
                  duration_s=random.randint(30, 600))]


def _sim_uncommon_ssh(config, session_context):
    """Base "Uncommon SSH session was established": a rarely-used internal host on 22."""
    return _uncommon_ssh(config, session_context, dest="known")


def _sim_uncommon_ssh_rare_internal(config, session_context):
    """"Uncommon SSH session was established to a rare internal IP": a never-seen internal."""
    return _uncommon_ssh(config, session_context, dest="rare_internal")


def _sim_uncommon_ssh_nonstd_port(config, session_context):
    """"An Uncommon SSH session was established using a nonstandard SSH port": internal, 22xx."""
    return _uncommon_ssh(config, session_context, dest="known", port=random.choice(_NONSTD_SSH_PORTS))


def _unusual_ssh(config, session_context, mb_range=(5, 80)):
    """A few long-lived SSH sessions to ONE stable rare external host (tunnel shape).

    Mirrors the Check Point reverse-SSH-tunnel shape that fires "Unusual, long SSH activity
    with tunnel characteristics" in this tenant: 2-4 sessions of 30 min - 4 h moving
    5-80 MB each way. A single multi-hundred-MB session reads as a Large Upload instead."""
    hit = recurring_host("panw_ssh_tunnel") if recurring_host else None
    src, user, shost = hit if hit else _threat_actor(config, session_context)
    dst, dom = _beacon_dst(config, "ssh_tunnel", src)
    n = random.randint(2, 4)
    print(f"    - PAN NGFW simulating: long SSH tunnel {src} -> {dst} ({n} sessions)")
    out, t = [], time.time() - n * 4 * 3600
    for _ in range(n):
        dur = random.randint(1800, 14400)
        t += random.randint(60, 600)
        out.append(_conn(config, src, dst, 22, "ssh", suser=user, shost=shost, dhost=dom,
                         bytes_sent=random.randint(*mb_range) * 1024 * 1024,
                         bytes_received=random.randint(*mb_range) * 1024 * 1024,
                         duration_s=dur, ts=min(t + dur, time.time()), end_reason="tcp-fin"))
        t += dur
    return out


def _sim_unusual_ssh(config, session_context):
    return _unusual_ssh(config, session_context)


def _sim_unusual_ssh_external(config, session_context):
    """"Unusual SSH activity with tunnel characteristics to external destination": the same
    tunnel shape carrying more data (50-200 MB each way), emphasising the external leg."""
    return _unusual_ssh(config, session_context, mb_range=(50, 200))


def _ssh_relay(config, src, user, shost, mb_range, dur_range, inbound):
    """A host relaying SSH: an inbound SSH session and an outbound one it opens 30-120 s
    later, overlapping in time, with the bytes of one leg passing through the other.

    Volumes mirror (+-5%) because a relay forwards what it receives: client->relay equals
    relay->target, and target->relay equals relay->client. Both logs are written at session
    end and both ends fall before now."""
    dom, outbound = _rare_ext(config, f"sshproxy|{user or src}")
    up = random.randint(*mb_range) * 1024 * 1024           # flowing client -> target
    down = random.randint(*mb_range) * 1024 * 1024         # flowing target -> client
    jitter = lambda b: int(b * random.uniform(0.95, 1.05))
    dur_in = random.randint(*dur_range)
    lag = random.randint(30, 120)
    dur_out = max(60, dur_in - lag - random.randint(10, 60))
    start = time.time() - dur_in - 30
    print(f"    - PAN NGFW simulating: SSH relay on {src}: {inbound} -> {src} -> {outbound} "
          f"({up // 2**20} MB / {down // 2**20} MB)")
    return [
        _conn(config, inbound, src, 22, "ssh", duser=user, dhost=shost, from_zone="untrust",
              to_zone="trust", bytes_sent=up, bytes_received=jitter(down),
              duration_s=dur_in, ts=start + dur_in, end_reason="tcp-fin"),
        _conn(config, src, outbound, 22, "ssh", suser=user, shost=shost, dhost=dom,
              bytes_sent=jitter(up), bytes_received=down,
              duration_s=dur_out, ts=start + lag + dur_out, end_reason="tcp-fin"),
    ]


def _sim_ssh_proxy(config, session_context):
    """A host both receives and initiates SSH within a window (SSH-proxy shape).

    Relay volume stays modest (1-20 MB each way): at 20-200 MB the outbound leg read as
    exfiltration and fired Large Upload (Generic) instead (detector test, 2026-10-22)."""
    src, user, shost = _threat_actor(config, session_context)
    return _ssh_relay(config, src, user, shost, (1, 20), (1800, 10800), random_external_ip())


def _sim_ssh_proxy_high_volume(config, session_context):
    """"High Volume Unusual SSH activity that resembles SSH proxy": the relay moving hundreds
    of MB each way for 2-6 hours. The relay is an SSH-habit user's host (real per-host SSH
    history to deviate from) and the inbound client is a rare external host, not ambient
    internet noise. Expect Large Upload (Generic) alongside it: the outbound leg is a big
    transfer to a rare external host, which a real relay of this size also is."""
    src, user, shost = _ssh_habit_actor(config, session_context)
    return _ssh_relay(config, src, user, shost, (200, 600), (7200, 21600),
                      rare_external_ip(f"sshproxy-in|{src}"))


def _sim_ssh_proxy_suspicious(config, session_context):
    """"Suspicious SSH activity that resembles SSH proxy": the relay where BOTH ends are rare
    external hosts and the inbound leg arrives on a non-standard SSH port -- the shape that
    reads as a hop in a chain rather than a legitimate bastion. Criteria for this specific
    variation are undocumented, so this is exploratory."""
    src, user, shost = _ssh_habit_actor(config, session_context)
    legs = _ssh_relay(config, src, user, shost, (20, 120), (3600, 14400),
                      rare_external_ip(f"sshproxy-susp|{src}"))
    # inbound leg on a non-standard SSH port
    import re as _re
    legs[0] = _re.sub(r"(?<![0-9])dest_port=22(?![0-9])",
                      f"dest_port={random.choice(_NONSTD_SSH_PORTS)}", legs[0], count=1)
    return legs


def _sim_ssh_proxy_detected(config, session_context):
    """"Unusual SSH activity that resembles SSH proxy detected": a plain-volume relay from a
    non-habit host (an ordinary workstation suddenly relaying is itself the signal).
    Exploratory -- the distinction from the base variation is not documented."""
    src, user, shost = _threat_actor(config, session_context)
    return _ssh_relay(config, src, user, shost, (5, 40), (1800, 7200),
                      rare_external_ip(f"sshproxy-det|{src}"))


def _sim_rare_ssh_external(config, session_context):
    """"An Uncommon SSH session was established to a rare IP address": an SSH-habit user
    (real per-host SSH history) reaches a rare external IP on the standard port."""
    src, user, shost = _ssh_habit_actor(config, session_context)
    dom, dst = _rare_ext(config, f"sshext|{user}")
    print(f"    - PAN NGFW simulating: SSH to rare external IP {dst} from {src}")
    return [_conn(config, src, dst, 22, "ssh", suser=user, shost=shost, dhost=dom,
                  bytes_sent=random.randint(5000, 200000), bytes_received=random.randint(5000, 400000),
                  duration_s=random.randint(30, 1200))]


# --- Recurring / beaconing ------------------------------------------------------------
# These detectors want the SAME (host, destination) pair "repeatedly over many days". With
# no back-dating on this path (see the header), each emission is ONE day of beacons from
# one fixed host to its persistent rare destination, and _DAILY_EVENTS makes the module
# emit each of them once per UTC day while it runs, so the pair recurs on real days.
_DAILY_EVENTS = ("recurring_rare_ip", "recurring_rare_domain", "recurring_rare_domain_attack_port",
                 "recurring_rare_domain_suspicious_as", "ddns_access")
_last_daily_emit = {}


def _beacon_host(config, session_context, key):
    """The one fixed host (same on every run) that owns the beacon for `key`."""
    hit = recurring_host(key, n=1) if recurring_host else None
    return hit if hit else _threat_actor(config, session_context)


def _beacon_day(config, src, user, shost, ip, port, domain=None, url_cat="unknown"):
    """Today's beacons: 3-6 short sessions at a jittered cadence over the last ~2 hours."""
    n = random.randint(3, 6)
    step = random.randint(900, 1800)
    t = time.time() - n * step
    out = []
    for _ in range(n):
        t += step + random.randint(-120, 120)
        kw = dict(suser=user, shost=shost, bytes_sent=random.randint(400, 4000),
                  bytes_received=random.randint(400, 4000), duration_s=random.randint(1, 30),
                  ts=min(t, time.time()))
        if domain:
            out += _web(config, src, ip, port, "ssl", domain, url_cat=url_cat, **kw)
        else:
            out.append(_conn(config, src, ip, port, "ssl", url_cat=url_cat, **kw))
    return out


def _beacon_dst(config, key, src):
    """A stable rare external (ip, domain) this src beacons to — persists across restarts."""
    store = beacon_targets("panw_ngfw")
    # "rare|" namespace: entries written before destinations moved to the rare pool held
    # ambient addresses; a new key space keeps them from being reused.
    k = f"rare|{key}|{src}"
    if k in store:
        v = store[k]
        return (v[0], v[1]) if isinstance(v, (list, tuple)) else (v, None)
    dom = rare_domain(k)
    ip = _rare_answer(dom, k)
    store[k] = [ip, dom]
    return ip, dom


def _beacon_port(key, src, ports):
    """One port per beacon, the same every day."""
    return ports[int(hashlib.sha256(f"{key}|{src}".encode()).hexdigest(), 16) % len(ports)]


def _sim_recurring_rare_ip(config, session_context):
    """One fixed host -> its persistent rare IP, today's beacons (no domain: IP-only C2)."""
    src, user, shost = _beacon_host(config, session_context, "panw_rare_ip")
    ip, _dom = _beacon_dst(config, "rare_ip", src)
    port = _beacon_port("rare_ip", src, [443, 8443, 4443])
    print(f"    - PAN NGFW simulating: daily beacon to rare IP {src} -> {ip}:{port}")
    return _beacon_day(config, src, user, shost, ip, port)


def _sim_recurring_rare_domain(config, session_context):
    """One fixed host -> its persistent rare domain (with URL logs), today's beacons. The
    'less common port' variation is the one that fires here from the real pa440."""
    src, user, shost = _beacon_host(config, session_context, "panw_rare_dom")
    ip, dom = _beacon_dst(config, "rare_dom", src)
    port = _beacon_port("rare_dom", src, [8443, 8080, 4443])
    print(f"    - PAN NGFW simulating: daily beacon to rare domain {src} -> {dom}:{port}")
    return _beacon_day(config, src, user, shost, ip, port, domain=dom, url_cat="command-and-control")


def _sim_recurring_rare_domain_suspicious_as(config, session_context):
    """"Abnormal Recurring Communications to a Rare Domain to a Suspicious Autonomous System":
    a daily beacon on the standard 443 (no attack port, no odd suffix), so the only
    distinguishing attribute left for XSIAM is the destination's AS. The rare pool
    (RARE_EXTERNAL_RANGES) is bulletproof-hosting-style space, which is what the real pa440's
    firing of this variation resolved into; the AS label is XSIAM's own enrichment, not ours."""
    src, user, shost = _beacon_host(config, session_context, "panw_rare_dom_as")
    ip, dom = _beacon_dst(config, "rare_dom_as", src)
    print(f"    - PAN NGFW simulating: daily beacon to rare domain (suspicious AS) {src} -> {dom}")
    return _beacon_day(config, src, user, shost, ip, 443, domain=dom, url_cat="command-and-control")


# Default listener ports of common attack frameworks (Metasploit 4444, Cobalt Strike team
# server 50050, Sliver/Empire-style 31337/1337, ...): the "Port Commonly Used by Attack
# Platforms" variations of the rare-domain detectors.
_ATTACK_PORTS = (4444, 50050, 31337, 1337, 6666, 9999)


def _sim_rare_domain_comm(config, session_context):
    """One session to a newly registered rare domain on 443/8443 (+ URL log)."""
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"rdc|{user}")
    return _web(config, src, dst, random.choice([443, 8443]), "ssl", dom,
                url_cat="newly-registered-domain", suser=user, shost=shost,
                bytes_sent=random.randint(500, 20000), bytes_received=random.randint(500, 40000),
                duration_s=random.randint(1, 120))


def _sim_rare_domain_attack_port(config, session_context):
    """"Abnormal Communication to a Rare Domain With a Port Commonly Used by Attack
    Platforms": a rare domain reached on an attack-framework listener port (+ URL log)."""
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"rdcatk|{user}")
    port = random.choice(_ATTACK_PORTS)
    print(f"    - PAN NGFW simulating: rare domain on attack-platform port {src} -> {dom}:{port}")
    return _web(config, src, dst, port, "ssl", dom, url_cat="unknown", suser=user, shost=shost,
                bytes_sent=random.randint(500, 20000), bytes_received=random.randint(500, 40000),
                duration_s=random.randint(1, 120))


def _sim_recurring_rare_domain_attack_port(config, session_context):
    """Second daily beacon pair, on an attack-framework port: the "Abnormal Recurring
    Communications to a Rare Domain With a Port Commonly Used by Attack Platforms" variation."""
    src, user, shost = _beacon_host(config, session_context, "panw_rare_dom_atk")
    ip, dom = _beacon_dst(config, "rare_dom_atk", src)
    port = _beacon_port("rare_dom_atk", src, list(_ATTACK_PORTS))
    print(f"    - PAN NGFW simulating: daily beacon to rare domain {src} -> {dom}:{port}")
    return _beacon_day(config, src, user, shost, ip, port, domain=dom, url_cat="unknown")


def _sim_ddns_access(config, session_context):
    """One fixed host -> its persistent dynamic-DNS name (with URL logs), today's beacons."""
    src, user, shost = _beacon_host(config, session_context, "panw_ddns")
    label = rare_domain(f"ddns|{src}").split(".")[0]
    # Suffix stable per source, so every day extends the SAME recurring (host, domain) pair.
    suffix = _DDNS_SUFFIXES[int(hashlib.sha256(f"ddns|{src}".encode()).hexdigest(), 16) % len(_DDNS_SUFFIXES)]
    dom = f"{label}.{suffix}"
    ip = _rare_answer(dom)
    print(f"    - PAN NGFW simulating: daily beacon to dynamic-DNS {src} -> {dom}")
    return _beacon_day(config, src, user, shost, ip, 443, domain=dom, url_cat="dynamic-dns")


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


def _sim_ipfs_peering(config, session_context):
    """"Possible IPFS traffic was detected" (the host "attempted to access other nodes in an
    IPFS manner"): a node bootstrapping its DHT dials 25-45 swarm peers on 4001 over TCP and
    UDP/QUIC within ~15 minutes; about half the dials never complete."""
    src, user, shost = _threat_actor(config, session_context)
    n = random.randint(25, 45)
    print(f"    - PAN NGFW simulating: IPFS swarm dialing from {src} ({n} peers)")
    t0 = time.time() - n * 20
    out = []
    for i in range(n):
        fail = random.random() < 0.5
        out.append(_conn(config, src, random_external_ip(), 4001, "incomplete" if fail else "ipfs",
                         suser=user, shost=shost, proto=random.choice(["tcp", "udp"]),
                         bytes_sent=random.randint(60, 400) if fail else random.randint(2000, 60000),
                         bytes_received=0 if fail else random.randint(2000, 90000),
                         duration_s=0 if fail else random.randint(2, 60),
                         end_reason="aged-out" if fail else None, ts=t0 + i * 20, url_cat="peer-to-peer"))
    return out


def _rare_appid(config, src, user, shost, from_zone="trust", src_category="workstation"):
    """A rarely-used App-ID to a rare destination on its own (unusual) port."""
    dom, dst = _rare_ext(config, f"appid|{src}")
    app = random.choice(["socks", "tor", "gnutella", "dns-over-https", "tftp"])
    port = random.choice(_APP.get(app, (None,)*5)[4] or [1080])
    print(f"    - PAN NGFW simulating: rare App-ID {app} {src} -> {dst}:{port}")
    return [_conn(config, src, dst, port, app, suser=user, shost=shost, dhost=dom,
                  from_zone=from_zone, src_category=src_category,
                  bytes_sent=random.randint(2000, 200000), bytes_received=random.randint(2000, 400000),
                  duration_s=random.randint(10, 600), url_cat="proxy-avoidance-and-anonymizers")]


def _sim_rare_appid(config, session_context):
    src, user, shost = _threat_actor(config, session_context)
    return _rare_appid(config, src, user, shost)


def _sim_rare_appid_internet_facing(config, session_context):
    """The same from a published DMZ web server: "Rare AppID usage to a rare destination from
    an internet-facing server" (a compromised web server opening a tunnel/proxy out)."""
    srv = random.choice(_dmz_servers(config))
    return _rare_appid(config, srv, "svc_web", resolver.internal_fqdn(config, srv), from_zone="dmz",
                       src_category="server")


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


def _sim_new_ftp_server_external(config, session_context):
    """"New FTP Server from an external source": internet clients log in to and pull files
    from an internal host that never served FTP before (untrust -> trust, :21 allowed by a
    stale or rogue rule) -- data staged for pickup from outside."""
    server = new_ftp_server_host(config)
    sname = resolver.internal_fqdn(config, server)
    print(f"    - PAN NGFW simulating: new FTP server {server} reached from the internet")
    out = []
    for _ in range(random.randint(2, 5)):
        out.append(_conn(config, _ingress_client(config), server, 21, "ftp", dhost=sname,
                         from_zone="untrust", to_zone="trust", rule="Allow-Inbound-FTP-Legacy",
                         bytes_sent=random.randint(500, 8000), bytes_received=random.randint(500000, 80000000),
                         duration_s=random.randint(10, 900)))
    return out


# Remote-administration services "New Administrative Behavior" counts, with the App-ID PAN
# reports for each (unknown-tcp/udp where App-ID has no decoder, as real PAN does).
_REMOTE_ADMIN = {22: "ssh", 23: "telnet", 69: "tftp", 161: "snmp-base", 512: "unknown-tcp",
                 513: "unknown-tcp", 514: "unknown-tcp", 623: "unknown-udp", 992: "ssl"}
# Ports confirmed (FortiGate, 2026-09) to count toward the novel-admin-action total.
_ADMIN_FILL = (22, 69)


def _sim_new_admin_behavior(config, session_context, ssh_only=False):
    """One established host performing many FIRST-TIME remote-administration actions.

    The detector counts NOVEL (destination, admin port) pairs per source over 12 hours, so
    breadth across both axes is the signal, not volume (shape that fires for Firepower,
    FortiGate, Check Point and Zscaler here). Destinations are fresh internal addresses
    (never the hot internal_servers pool); every admin port appears once and the rest of
    the 8-11 actions use the confirmed-counted ports; actions are spread over 30-75 min.
    `ssh_only` is the "New SSH Administrative Behavior" variation: every action is SSH."""
    src, user, shost = _threat_actor(config, session_context)
    n = random.randint(8, 11)
    if ssh_only:
        ports = [22] * n
    else:
        ports = random.sample(list(_REMOTE_ADMIN), random.randint(4, 6))
        while len(ports) < n:
            ports.append(random.choice(_ADMIN_FILL))
        random.shuffle(ports)
    pairs, used = [], {src}
    for p in ports:
        if pairs and random.random() < 0.3 and (pairs[-1][0], p) not in pairs:
            dst = pairs[-1][0]                     # same box, another admin service
        else:
            dst = rare_internal_host(config, exclude=used)
            used.add(dst)
        pairs.append((dst, p))
    window = random.randint(30, 75) * 60
    offsets = sorted(random.randint(0, window) for _ in pairs)
    now = time.time()
    print(f"    - PAN NGFW simulating: new admin behavior {src} -> {len(used) - 1} hosts, {len(pairs)} actions")
    out = []
    for (dst, p), back in zip(pairs, reversed(offsets)):
        out.append(_conn(config, src, dst, p, _REMOTE_ADMIN[p], suser=user, shost=shost,
                         from_zone="trust", to_zone="trust", dhost=resolver.internal_fqdn(config, dst),
                         bytes_sent=random.randint(800, 30000), bytes_received=random.randint(1500, 120000),
                         duration_s=random.randint(2, 90), ts=now - back,
                         proto="udp" if p in (69, 161, 623) else "tcp"))
    return out


def _dormant_conns(config, src, shost, user=None):
    dormant = rare_internal_host(config)
    out = []
    for _ in range(random.randint(6, 14)):
        port = random.choice([445, 3389, 22, 443])
        out.append(_conn(config, src, dormant, port, _APP_for_port(port), suser=user,
                         shost=shost, from_zone="trust", to_zone="trust",
                         dhost=resolver.internal_fqdn(config, dormant),
                         bytes_sent=random.randint(2000, 60000), bytes_received=random.randint(2000, 200000),
                         duration_s=random.randint(5, 300)))
    print(f"    - PAN NGFW simulating: {len(out)} connections to dormant host {dormant} from {src}")
    return out


def _sim_dormant_host_conn(config, session_context):
    """A newly-seen endpoint makes multiple connections to a long-inactive (dormant) host."""
    src, shost = rare_source_host(config, "panw_dormant")
    return _dormant_conns(config, src, shost)


def _sim_dormant_host_known_source(config, session_context):
    """"Abnormal connections to a dormant host": the same, from an established workstation."""
    src, user, shost = _threat_actor(config, session_context)
    return _dormant_conns(config, src, shost, user)


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
    "port_scan_aggressive": _sim_port_scan_aggressive, "ipfs_peering": _sim_ipfs_peering,
    "rare_domain_attack_port": _sim_rare_domain_attack_port,
    "recurring_rare_domain_attack_port": _sim_recurring_rare_domain_attack_port,
    "dormant_host_known_source": _sim_dormant_host_known_source,
    "large_upload_generic_small": _sim_large_upload_generic_small,
    "new_ssh_admin_behavior": lambda c, s: _sim_new_admin_behavior(c, s, ssh_only=True),
    "new_ftp_server_external": _sim_new_ftp_server_external,
    "dcsync_internet_facing": _sim_dcsync_internet_facing, "dcsync_large": _sim_dcsync_large,
    "rare_appid_internet_facing": _sim_rare_appid_internet_facing,
    "spam_bot_failed": _sim_spam_bot_failed, "ssh_suspicious_nonstd": _sim_ssh_suspicious_nonstd,
    "ssh_high_volume": _sim_ssh_high_volume, "host_attack_chain": _sim_host_attack_chain,
    "ssh_proxy_high_volume": _sim_ssh_proxy_high_volume,
    "uncommon_ssh_rare_internal": _sim_uncommon_ssh_rare_internal,
    "uncommon_ssh_nonstd_port": _sim_uncommon_ssh_nonstd_port,
    "unusual_ssh_external": _sim_unusual_ssh_external,
    "ssh_proxy_suspicious": _sim_ssh_proxy_suspicious, "ssh_proxy_detected": _sim_ssh_proxy_detected,
    "dcsync_non_dc_appid": _sim_dcsync_non_dc_appid, "dcsync_large_appid": _sim_dcsync_large_appid,
    "recurring_rare_domain_suspicious_as": _sim_recurring_rare_domain_suspicious_as,
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

    # Orchestrated / dashboard-forced named threat. Return the (logs, display_name) tuple
    # so the caller records WHICH threat fired; returning the bare logs (the old `[0]`) made
    # the dashboard worker record event_name=None, so ambient threats were counted as benign
    # and the UI showed zero threats — they only appeared via the fire/scenario path, which
    # supplies the name itself.
    if scenario_event:
        if scenario_event in ("LARGE_EGRESS",):
            return _sim_large_upload_https(config, session_context), "large_upload_https"
        if scenario_event in _THREAT_DISPATCH or scenario_event.lower() in _THREAT_DISPATCH:
            return _generate_threat_log(config, session_context, forced_event=scenario_event)

    if benign_only:
        return _generate_benign_log(config, session_context)

    interval = _get_threat_interval(threat_level, config)
    now = time.time()
    if threat_level == "Insane" and random.random() < 0.8:
        return _generate_threat_log(config, session_context, forced_event=_due_daily(now))
    if interval > 0 and (now - last_threat_event_time) > interval:
        last_threat_event_time = now
        return _generate_threat_log(config, session_context, forced_event=_due_daily(now))
    return _generate_benign_log(config, session_context)


def _due_daily(now):
    """The first _DAILY_EVENTS entry not yet emitted this UTC day (claimed), else None so the
    slot stays a weighted draw. Resets on restart, which at worst repeats a beacon once in a
    day; each of these detectors dedups at >= 1 day."""
    today = int(now // 86400)
    due = next((e for e in _DAILY_EVENTS if _last_daily_emit.get(e) != today), None)
    if due:
        _last_daily_emit[due] = today
    return due
