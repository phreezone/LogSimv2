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
    # Seen in the live pa440 threat/traffic rows (category / sub-category / technology / risk
    # exactly as the tenant records them).
    "portmapper":      ("networking",       "infrastructure",    "network-protocol","Medium",        [111]),
    "rpc":             ("networking",       "infrastructure",    "network-protocol","Low",           [111]),
    "nfs":             ("business-systems", "storage-backup",    "client-server",   "Medium",        [2049]),
    "smtp":            ("collaboration",    "email",             "client-server",   "Medium",        [25, 587]),
    "ftp":             ("general-internet", "file-sharing",      "client-server",   "Critical",      [21]),
    "icmp":            ("networking",       "ip-protocol",       "network-protocol","High",          [0]),
    "ping":            ("general-internet", "internet-utility",  "network-protocol","Low",           [0]),
    "snmp-base":       ("networking",       "infrastructure",    "client-server",   "Low",           [161]),
    # IAX2 (Asterisk) is identified as voip-video (user-confirmed App-ID); the category,
    # technology and risk are assumed, not read from Applipedia (its API is gated).
    "voip-video":      ("collaboration",    "voip-video",        "client-server",   "Medium",        []),
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
    # Seen in the pa440 scanner-run threat rows (2026-11-19); category/sub-category/risk are assumed, not
    # read from Applipedia (its API is reCAPTCHA-gated).
    "lpd":             ("general-internet", "internet-utility",  "client-server",   "Medium",        [515]),
    "smtp-base":       ("collaboration",    "email",             "client-server",   "Medium",        [25]),
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
                    "web-advertisements", "content-delivery-networks", "internet-communications-and-telephony",
                    "financial-services", "government", "health-and-medicine", "games",
                    "streaming-media", "social-networking", "web-based-email", "online-storage-and-backup",
                    "shopping", "news", "reference-and-research", "ai-conversational-assistant",
                    "internet-portals", "travel"]
_URL_CAT_RISKY   = ["malware", "command-and-control", "phishing", "proxy-avoidance-and-anonymizers",
                    "dynamic-dns", "newly-registered-domain", "hacking", "unknown",
                    "peer-to-peer", "questionable", "grayware", "ransomware", "compromised-website",
                    "scanning-activity", "parked"]

_SW_VERSION = "12.2.4-h1"    # PAN-OS release stamped in the CEF device-version slot (the lab pa440's)
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


_SEQ = [random.randint(7000000000000000000, 7999999999999999000)]


def _seqno():
    """sequence_no is a per-device counter shared by every log type (the live pa440 rows rise
    monotonically: ...642205570 -> ...642224005 over 35 min), not a random number per log."""
    _SEQ[0] += random.randint(1, 3)
    return str(_SEQ[0])


def _pan_time(t):
    """log_time/time_generated as PAN-OS writes them in the CEF custom format: the live pa440
    Syslog rows show 'Nov 16 2026 18:46:43 GMT'."""
    return time.strftime("%b %d %Y %H:%M:%S GMT", time.gmtime(t))


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


_UNTRUST_ZONES = ("untrust", "internet", "external", "wan")
_DMZ_ZONES = ("dmz",)
# Interfaces of the zones beyond WAN / DMZ / LAN (the LAN interface faces the user zone). Every
# one is overridable per zone in panw_ngfw_config.zones.<name>.interface.
_ZONE_IF_DEFAULT = {"servers": "ethernet1/4", "database": "ethernet1/5", "identity": "ethernet1/6"}


def _zone_if(forti, zone):
    """The firewall interface that faces `zone`: WAN for untrust, the DMZ interface for the
    DMZ, a per-zone interface for the server / database / identity zones, the LAN interface for
    the user zone and anything else internal."""
    z = str(zone or "").lower()
    spec = (forti.get("zones") or {}).get(z) or {}
    if spec.get("interface"):
        return spec["interface"]
    if z in _UNTRUST_ZONES:
        return forti.get("interface_wan", "ethernet1/1")
    if z in _DMZ_ZONES:
        return forti.get("interface_dmz", "ethernet1/3")
    if z in _ZONE_IF_DEFAULT:
        return _ZONE_IF_DEFAULT[z]
    return forti.get("interface_lan", "ethernet1/2")


# Zone model. An internal address belongs to the zone of the role it plays: the published DMZ
# servers, the domain controllers (identity), the database servers, the other internal servers,
# then anything covered by panw_ngfw_config.zones.<name>.{hosts,cidrs}, and otherwise the user
# zone. Exact hosts beat CIDRs; a longer CIDR beats a shorter one; the configured hosts beat
# the role lists. Everything that is not RFC1918 is untrust.
_zone_cache = {"key": None, "hosts": {}, "nets": []}


def _zone_tables(config):
    forti = _get_config(config)
    zc = forti.get("zones") or {}
    ap = config.get("apache_config") or {}
    key = (tuple(config.get("internal_servers") or ()), tuple(forti.get("domain_controllers") or ()),
           tuple(config.get("domain_controllers") or ()), tuple(config.get("database_servers") or ()),
           tuple(ap.get("server_ips") or ()), ap.get("server_ip"), repr(sorted(zc.items(), key=lambda kv: kv[0])))
    if _zone_cache["key"] == key:
        return _zone_cache["hosts"], _zone_cache["nets"]
    hosts, nets = {}, []
    for h in config.get("internal_servers") or ():
        hosts[h] = "servers"
    for h in config.get("database_servers") or ():
        hosts[h] = "database"
    for h in _dcs(config):
        hosts[h] = "identity"
    for h in _dmz_servers(config):
        hosts[h] = "dmz"
    for name, spec in zc.items():
        for h in (spec or {}).get("hosts") or ():
            hosts[h] = name
        for c in (spec or {}).get("cidrs") or ():
            try:
                nets.append((ip_network(c, strict=False), name))
            except ValueError:
                pass
    nets.sort(key=lambda t: -t[0].prefixlen)
    _zone_cache.update(key=key, hosts=hosts, nets=nets)
    return hosts, nets


def _zone_of(config, ip):
    """The security zone an address sits in (see the zone model above)."""
    if not _is_internal(ip):
        return "untrust"
    hosts, nets = _zone_tables(config)
    if ip in hosts:
        return hosts[ip]
    a = ip_address(ip)
    for net, name in nets:
        if a in net:
            return name
    return "users"


def _resolve_zone(config, ip, hint):
    """Callers pass the legacy generic internal zone ("trust") for any internal side; that is
    replaced by the address's real zone. An explicit untrust / dmz / custom zone is kept."""
    return _zone_of(config, ip) if str(hint or "trust").lower() == "trust" else hint


def _zone_rule(forti, from_zone, to_zone, denied=False):
    """The security rule a flow between two zones would hit when the caller names none."""
    if to_zone in _UNTRUST_ZONES and from_zone not in ("dmz", "servers", "database", "identity")             and from_zone not in _UNTRUST_ZONES:
        return forti.get("default_rule", "Allow-Users-Outbound")
    lab = lambda z: "DMZ" if z == "dmz" else str(z).capitalize()
    pre = "Deny" if denied else "Allow"
    if from_zone in _UNTRUST_ZONES:
        return f"{pre}-Inbound-{lab(to_zone)}"
    if from_zone == to_zone:
        return f"{pre}-{lab(from_zone)}-Internal"
    return f"{pre}-{lab(from_zone)}-to-{lab(to_zone)}"


# ---------------------------------------------------------------------------
# CEF builder
# ---------------------------------------------------------------------------
def _format_cef(config, subtype, fields, log_type="TRAFFIC", severity=1, ts=None, fw_type=None,
                sig=None):
    """Build one PAN-OS NGFW_CEF syslog line.

    Header:  CEF:0|PANW|NGFW_CEF|<sw>|<sig>|<type>|<sev>|
    Body:    literal key=value pairs (PAN custom log format), space separated.
    `ts` is the event epoch seconds (defaults to now); it drives log_time/time_generated/rt.
    `fw_type` overrides the __firewall_type routing key: a URL log is log_type THREAT but
    routes as firewall.url (into panw_ngfw_url_raw).
    `sig` is the CEF signature slot: the documented format puts $subtype there for traffic and
    URL logs but $threatid for threat (and file-data) logs; it defaults to the subtype.
    """
    t = ts if ts is not None else time.time()
    serial, name = _serial(config), _fw_name(config)
    pan_ts = _pan_time(t)
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
        # outcome) actually reads, and log_type is uppercase as in the live pa440 Syslog rows.
        "log_type":        log_type.upper(),
        "subtype":         subtype,
        "sub_type":        subtype,
        "log_time":        pan_ts,
        "time_generated":  pan_ts,
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
    header = f"CEF:0|PANW|NGFW_CEF|{sw}|{sig or subtype}|{log_type.upper()}|{severity}|"
    syslog_ts = time.strftime("%b %d %H:%M:%S", time.gmtime(t))
    return f"<{_SYSLOG_PRI}>{syslog_ts} {_syslog_host(config)} {header} {ext}"


def _traffic_fields(config, src_ip, dst_ip, dpt, app, action="allow", *,
                    shost=None, suser=None, dhost=None, duser=None, proto=None,
                    from_zone=None, to_zone=None, bytes_sent=None, bytes_received=None,
                    duration_s=None, end_reason=None, url_cat=None, nat_src=None, nat_dpt=None,
                    spt=None, src_category="workstation", rule=None):
    """Common extension dict for a traffic:end session (or deny/drop). A zone left unset (or the
    generic "trust") is taken from the address; an explicit untrust / dmz / custom zone stays."""
    forti = _get_config(config)
    from_zone = _resolve_zone(config, src_ip, from_zone)
    to_zone = _resolve_zone(config, dst_ip, to_zone)
    meta = _APP.get(app, _APP["incomplete"])
    proto = proto or _proto_for(app, dpt)
    end_reason = end_reason or _end_reason(proto)
    spt = spt if spt is not None else random.randint(1025, 65535)
    bytes_sent = bytes_sent if bytes_sent is not None else random.randint(300, 40000)
    bytes_received = bytes_received if bytes_received is not None else random.randint(400, 300000)
    duration_s = duration_s if duration_s is not None else random.randint(1, 600)
    # Ingress/egress interfaces follow the ZONES the session crossed, not the destination:
    # an outbound session enters on the LAN and leaves on the WAN; an inbound one (untrust ->
    # dmz/trust, e.g. a published service) enters on the WAN and leaves on the LAN/DMZ.
    src_internal, internal_dst = _is_internal(src_ip), _is_internal(dst_ip)
    outbound = src_internal and not internal_dst
    in_if = _zone_if(forti, from_zone)
    out_if = _zone_if(forti, to_zone)
    denied = action in ("deny", "drop")
    if denied:
        # A blocked connection is the client's SYN with no response: zero bytes, the one
        # outbound packet, nothing back. Both deny and drop carry the policy-block end reason.
        bytes_sent, bytes_received, duration_s = 0, 0, 0
        end_reason = "policy-deny"
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
        "inbound_if":       in_if,
        "outbound_if":      out_if,
        "session_id":       _session_id(),
        "rule_matched":     rule or _zone_rule(forti, from_zone, to_zone, denied),
        "rule_matched_uuid":str(uuid.uuid4()),
        "bytes_sent":       bytes_sent,
        "bytes_received":   bytes_received,
        "bytes_total":      bytes_sent + bytes_received,
        # A packet count is 0 when that direction carried no bytes (a blocked SYN gets one
        # sent packet and no reply), else at least one.
        "packets_sent":     (1 if denied else (max(1, bytes_sent // 600) if bytes_sent else 0)),
        "packets_received": (0 if denied else (max(1, bytes_received // 1200) if bytes_received else 0)),
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
        # Source NAT is applied to outbound Internet sessions; east-west and inbound sessions
        # are not NATed here (no DNAT/VIP map is modelled, and the real TAP feed shows none).
        "is_nat":           "true" if outbound else "false",
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
    # Source NAT on outbound Internet egress only (the client's private address is translated
    # to the firewall's public pool); the destination is not NATed.
    if outbound:
        f["nat_source"]      = nat_src or _nat_for(src_ip, config)
        f["nat_source_port"] = random.randint(20000, 65000)
    else:
        # The live pa440 rows send the NAT columns on every log, zeroed when no NAT applied.
        f["nat_source"], f["nat_source_port"] = "0.0.0.0", 0
    f["nat_dest"], f["nat_dest_port"] = "0.0.0.0", 0
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
    # Cleartext HTTP exposes the request to PAN-OS; undecrypted TLS (app "ssl", or an explicit
    # https scheme) exposes only the SNI host. Without decryption PAN cannot see the HTTP
    # method, User-Agent, referer or content type, so those are emitted ONLY for cleartext.
    # (This is why case 68482's User-Agent/HTTP-Server evidence needs decrypted HTTP or EAL,
    # not an encrypted session.)
    clear = f.get("app") in ("web-browsing", "http", "http-proxy", "http-video", "soap")
    info = _HOST_INFO.get(f.get("source_ip")) or {}
    f.update({
        "action":            action,
        "uri":               f"{domain}{path}",
        "url_domain":        domain,      # no parser derives it from uri on this path
        "url_category":      cat,
        "url_category_list": f"{cat},{risk}",
        # Live CEF URL rows: threat_id and threat_name are both "9999(9999)", threat_category
        # N/A, severity the number 1 and pcap_id 0.
        "threat_id":         "9999(9999)",
        "threat_name":       "9999(9999)",
        "threat_category":   "N/A",
        "direction":         "client-to-server",
        "direction_of_attack": "client to server",   # the live column (doc key: direction)
        "severity":          "1",
        "pcap_id":           0,
        "http2_connection":  0,
    })
    if clear:
        f["http_method"] = method or "get"
        f["user_agent"] = user_agent or _browser_ua(f.get("source_device_osfamily"),
                                                     info.get("user_agent"), f.get("source_ip"))
        f["content_type"] = "text/html"
        if path not in ("/", ""):
            f["referer"] = f"http://{domain}/"
    else:
        # Undecrypted: method is logged as unknown; no UA/referer/content type are available.
        f["http_method"] = "unknown"
        if user_agent:                 # caller explicitly supplied one (decrypted/inspected)
            f["user_agent"] = user_agent
    return _format_cef(config, "url", f, log_type="THREAT", severity=1, ts=ts, fw_type="firewall.url")


# ---------------------------------------------------------------------------
# Threat logs (log_type THREAT, subtype vulnerability) -> panw_ngfw_threat_raw
# ---------------------------------------------------------------------------
# The signatures below are the ones the tenant's real pa440 threat feed carries (read-only
# query, 2026-11-15): same Threat ID, name, severity and category as recorded there. IDs are
# never invented, so the catalog is limited to signatures whose ID is confirmed; add more in
# panw_ngfw_config.threat_signatures ({key: [id, name, severity, category, subtype]}) once
# their IDs are known (spyware / virus / wildfire-virus signatures need that).
_SEVERITY_NUM = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_THREAT_SIGS = {
    "log4j":      (92046, "Apache Log4j Remote Code Execution Vulnerability", "critical", "code-execution", "vulnerability"),
    "dnsmasq":    (30109, "Dnsmasq Integer Underflow Vulnerability",          "high",     "code-execution", "vulnerability"),
    "nmap_nse":   (58433, "Nmap Scripting Engine Detection",                  "medium",   "hacktool",       "vulnerability"),
    "openvas":    (55283, "OpenVAS Vulnerability Scanner Detection",          "medium",   "info-leak",      "vulnerability"),
    "rpc_dump":   (32796, "RPC Portmapper DUMP Request Detected",             "medium",   "info-leak",      "vulnerability"),
    "nfs_export": (32788, "UNIX NFS Export Directory Attempt",                "medium",   "info-leak",      "vulnerability"),
    "rpc_frag":   (54578, "Sun ONC RPC Small Piece fragmentation Evasion Detection", "medium", "code-execution", "vulnerability"),
    "ssh_brute":  (40015, "SSH User Authentication Brute Force Attempt",      "high",     "brute-force",    "vulnerability"),
    # From Threat Vault signature details (current content, PAN-OS 8.1+), not from the tenant feed:
    # ID, name, severity and category are as shown there; the subtype follows the documented
    # Threat ID ranges (30000-44999 vulnerability, 10000-19999 spyware). The App-ID each session
    # carries: voip-video for IAX2 (user-confirmed); web-browsing for the bot beacon is assumed.
    "iax2_dos":   (40020, "Digium Asterisk IAX2 Call Number Denial Of Service Vulnerability", "medium", "brute-force", "vulnerability"),
    "bot_qxx":    (19900, "Bot: Backdoor_Win32_Agent_qxx",                      "high",     "backdoor",       "spyware"),
    "bot_agobot": (19999, "Bot: Backdoor_Win32_Agobot_pnd_pnj",                 "high",     "backdoor",       "spyware"),
    "default_creds": (59995, "Manufacturer default username and password found in HTTP Basic Authentication",
                      "informational", "insecure-credentials", "vulnerability"),
    # One name, three IDs: each is a separate signature that logs under its own Threat ID.
    "pastebin_c2_a": (21975, "Pastebin Command and Control Traffic Detection", "critical", "spyware", "spyware"),
    "pastebin_c2_b": (21976, "Pastebin Command and Control Traffic Detection", "critical", "spyware", "spyware"),
    "pastebin_c2_c": (21980, "Pastebin Command and Control Traffic Detection", "critical", "spyware", "spyware"),
    "schoolboy":  (21985, "Schoolboy Downloader Traffic Detection",             "critical", "downloader",     "spyware"),
    # One name, three IDs (PHP RCE, CVE pair); the IDs are separate signatures.
    "php_rce_a":  (97622, "PHP Remote Code Execution Vulnerability",            "critical", "code-execution", "vulnerability"),
    "php_rce_b":  (97623, "PHP Remote Code Execution Vulnerability",            "critical", "code-execution", "vulnerability"),
    "php_rce_c":  (97625, "PHP Remote Code Execution Vulnerability",            "critical", "code-execution", "vulnerability"),
    "moxa_tn5900": (97630, "Moxa TN-5900 Firmware Command Injection Vulnerability", "critical", "code-execution", "vulnerability"),
    "trendnet_tew432brp": (97650, "TRENDnet TEW-432BRP Firmware Command Injection Vulnerability", "critical", "code-execution", "vulnerability"),
    "php_memcorrupt": (543004, "PHP Memory Corruption Vulnerability",         "critical", "code-execution", "vulnerability"),
}
# Signatures read from the tenant's pa440 feed (read-only query 2026-11-16, last ~1000 min; 195
# Threat IDs, of which 186 were not in the catalog yet): (id, name, severity, category, subtype,
# action, app, file_name/$misc). Every field is as the tenant row carries it; the action/app/$misc
# are each signature's own dominant values. Host names and IPs seen inside $misc were dropped.
_TENANT_SIGS = [
    (18011, 'Western Digital My Cloud Backdoor', 'critical', 'backdoor', 'spyware', 'reset-server', 'web-browsing', 'nas_sharing.cgi'),
    (30101, 'Webhints Improper URI Sanitization Remote Command Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-both', 'web-browsing', '/hints.pl?|id|'),
    (30554, 'Netgear Routers Arbitrary Command Injection Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', '/cgi-bin/;cat$IFS/etc/passwd'),
    (30844, 'HTTP Directory Traversal Request Attempt', 'medium', 'info-leak', 'vulnerability', 'alert', 'jaspersoft', 'win.ini'),
    (30847, 'Generic HTTP Cross Site Scripting Attempt', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/<script>foo</script>'),
    (30851, 'Microsoft Windows win.ini Access Attempt Detected', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'win.ini'),
    (30852, 'HTTP /etc/passwd Access Attempt', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/../../etc/passwd'),
    (31002, 'Multiple Products Arbitrary File Location Upload Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', '/ap_spec_rec/upload/'),
    (31003, 'Squid Proxy TRACE Request Denial of Service', 'medium', 'dos', 'vulnerability', 'reset-server', 'webdav', '/'),
    (31475, 'Generic HTTP Cross Site Scripting Attempt', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/profil.php?id=1%20<script>foo</script>'),
    (31476, 'Generic HTTP Cross Site Scripting Attempt', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', "/search=<script>alert('XSS')</script>"),
    (31477, 'Generic HTTP Cross Site Scripting Attempt', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', "/index.php?gadget=Glossary&action=ViewTerm&term=<script>alert('crtx397162412');</script>"),
    (31699, 'Trihedral VTScada WAP Filter Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/file://etc/passwd'),
    (32658, 'HTTP Cross Site Scripting Attempt', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', "/index.php?gadget=Glossary&action=ViewTerm&term=<script>alert('crtx397162412');</script>"),
    (32721, 'Alcatel OmniPCX Office MasterCGI Remote Command Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/cgi-bin/masterCGI?ping=nomip&user=;id;'),
    (32775, 'Microsoft IIS 5.0 Form_JScript.asp XSS Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', 'Form_JScript.asp_889426325'),
    (33073, 'Microsoft IIS ServerVariables_JScript. asp Information Disclosure', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', '/iissamples/sdk/asp/interaction/ServerVariables_Jscript.asp_471833835'),
    (33452, 'Adobe ColdFusion Multiple Directory Traversal Vulnerabilities', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'enter.cfm'),
    (33678, 'OPIE and Konica FTP Buffer Overflow Vulnerability', 'high', 'overflow', 'vulnerability', 'reset-server', 'ftp', None),
    (33756, 'Oracle 9i Application Server Dynamic Monitoring Services Anonymous Access', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', '/fcgi-bin/echo?foo=<SCRIPT>alert(document.domain)</SCRIPT>'),
    (34181, 'IBM Rational Quality Manager and Test Lab Manager Remote Code Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/manager/html'),
    (34804, 'PHP CGI Query String Parameter Handling Information Disclosure Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', '/php-cgi/php?-d%20allow_url_include=on%20-d%20safe_mode=off%20-d%20suhosin.simulation=on%2'),
    (35107, 'HTTP /etc/passwd Access Attempt', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', 'weblogin.cgi'),
    (35283, 'Dahua HDCVI and IPC Backdoor Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'Account1'),
    (36102, 'PCCS Mysql Database Admin Tool Username and Password Disclosure Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/pccsmysqladm/incs/dbconnect.inc_1167841198'),
    (36124, 'Oracle 9I Application Server PL/SQL Apache Module Buffer Overflow Vulnerability', 'critical', 'overflow', 'vulnerability', 'reset-server', 'web-browsing', None),
    (36274, 'Spring Data Commons Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-both', 'web-browsing', '/account'),
    (36729, 'Bash Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-both', 'web-browsing', 'test'),
    (36736, 'Bash Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-both', 'ftp', None),
    (37040, 'Rejetto HTTP File Server Remote Command Execution Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', '/?search=='),
    (37610, 'Microsoft Windows HTTP.sys Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/'),
    (38768, 'D-Link Routers Information Disclosure Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'passwd'),
    (38926, 'Dahua Security DVR Appliances Authentication Bypass Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'passwd'),
    (39268, 'ElasticSearch Groovy Script Engine Remote Command Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '_search'),
    (39766, 'Novell ZENworks Mobile Management Cross-Site Scripting Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', "/index.php?gadget=Glossary&action=ViewTerm&term=<script>alert('crtx397162412');</script>"),
    (40031, 'HTTP Unauthorized Brute Force Attack', 'high', 'brute-force', 'vulnerability', 'alert', 'web-browsing', 'run'),
    (40483, 'PAN-OS Authentication Bypass Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-client', 'web-browsing', '/esp/cms_changeDeviceContext.esp?device=aaaaa:a\'";user|s."1337";'),
    (40627, 'Drupal Core Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'register'),
    (40740, 'Linksys Devices Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-both', 'web-browsing', '/error.php?err=404'),
    (40797, 'Cisco Adaptive Security Appliance Web Services Denial of Service Vulnerability', 'high', 'dos', 'vulnerability', 'reset-both', 'web-browsing', 'file_list.json'),
    (40992, 'Pivotal Spring Data Commons Remote File Read XXE Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'autodiscover'),
    (54119, 'Novell File Reporter FSFUI Arbitrary File Retrieval Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/FSF/CMD'),
    (54426, 'Squid HTTP Header Remote Buffer Overflow Vulnerability', 'high', 'overflow', 'vulnerability', 'reset-server', 'web-browsing', 'openid-configuration'),
    (54505, 'DLink DSL Remote OS Command Injection Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/login.cgi?username=&command=simple&do=edit&password=&file=|id|'),
    (54519, 'IBM Lotus Domino HTTP Redirect Buffer Overflow Vulnerability', 'medium', 'overflow', 'vulnerability', 'alert', 'web-browsing', 'openid-configuration'),
    (54701, 'HTTP Directory Traversal Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'webspirs.cgi'),
    (54817, 'Multiple Products Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'upgrade_handle.php'),
    (54825, 'ThinkPHP Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'index.php'),
    (55025, 'Cisco RV320/RV325 Router Unauthenticated Configuration Export Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'config.exp'),
    (55155, 'Sonatype Nexus Repository Manager Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'extdirect'),
    (55385, 'Drupal core Remote Code Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/node/1?_format=hal_json'),
    (55462, 'Atlassian Confluence Directory Traversal Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'preview'),
    (55505, 'Zimbra Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'ms-exchange', 'Autodiscover.xml'),
    (55558, 'Spring Cloud Config Server Directory Traversal Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', '/etc/passwd'),
    (55570, 'Oracle WebLogic wls9-async Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/wls-wsat/CoordinatorPortType'),
    (55852, 'phpunit Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'),
    (56365, 'Fortinet FortiOS SSL VPN Path Traversal Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'fgt_lang'),
    (56609, 'Ysoserial Java Object Deserialization Payloads Detection', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'amf'),
    (56613, 'D-Link DNS-320 ShareCenter Remote Command Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'login_mgr.cgi'),
    (56635, 'Ysoserial Java Object Deserialization Payloads Detection', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'amf'),
    (56815, 'Ysoserial Java Object Deserialization Payloads Detection', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'amf'),
    (56868, 'Jenkins Script Security Plugin Sandbox Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'checkScriptCompile'),
    (56954, 'Webmin Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'password_change.cgi'),
    (57497, 'Citrix Application Delivery Controller And Gateway Directory Traversal Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'smb.conf'),
    (57557, 'Siemens Solid Edge ST4 Information Disclosure Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', '/cgi-bin/chklogin.cgi?file=config.ini'),
    (57806, 'Zyxel Multiple Products Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'weblogin.cgi'),
    (57887, 'Liferay Portal Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'invoke'),
    (57897, 'Draytek Vigor Remote Command Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'mainfunction.cgi'),
    (57993, 'Unraid Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/webGui/images/green-on.png/?path=x&site[x][text]=<?php%20echo%20md5("CVE-2020-5847");%20?'),
    (58062, 'Liferay Portal JSON Web Service Insecure Deserialization Vulnerability', 'critical', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'invoke'),
    (58132, 'Apache Shiro Improper Authentication Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'test'),
    (58460, 'Possible HTTP Malicious Payload Detection', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'index.php'),
    (58465, 'Amcrest IPM-721S Information Disclosure Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'Sha1Account1'),
    (58618, 'YAWS Unauthenticated Remote File Disclosure Vulnerability', 'high', 'info-leak', 'vulnerability', 'alert', 'web-browsing', '/../../../../../../etc/passwd'),
    (58623, 'F5 Traffic Management User Interface Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'fileRead.jsp'),
    (58628, 'DataLife Engine Remote Code Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'alert', 'web-browsing', '/datalife/engine/preview.php'),
    (58671, 'Citrix Multiple Products Authorization Bypass Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'report'),
    (58688, 'F5 Traffic Management User Interface Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'hsqldb'),
    (58986, 'SAP NetWeaver AS JAVA Authentication Vulnerability', 'critical', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'ConfigServlet'),
    (59021, 'Cisco ASA and FTD Arbitrary File Read Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'translation-table'),
    (59133, 'vBulletin Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'widget_tabbedcontainer_tab_panel'),
    (59315, 'phpMyadmin Scripts Deserialization Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'setup.php'),
    (59335, 'MobileIron Core and Connector Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'LogService'),
    (59505, 'Nette Code Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/index.php/nette.micro/?callback=shell_exec&cmd=id&what=-1'),
    (59623, 'Oracle WebLogic Server Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'console.portal'),
    (59940, 'Oracle WebLogic Server Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'console.portal'),
    (90136, 'Car Rental Management System File Inclusion Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/index.php?page=../../../../../../../../../../../etc/passwd'),
    (90152, 'WordPress Duplicator Plugin Directory Traversal Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../etc/passwd'),
    (90183, 'Zyxel USG Backdoor Account Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/?username=zyfwp&password=PrOw!aN_fXp'),
    (90196, 'Apache Flink Directory Traversal Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '3MAYwwxfqaTJDraP0BYB3zrm9wY.txt'),
    (90244, 'Elasticsearch Groovy Script Engine Remote Command Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '_search'),
    (90776, 'Yealink DM Pre Auth Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'getPingData'),
    (90879, 'F5 BIG-IP Authentication Bypass Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'login'),
    (91201, 'VMware vCenter Server Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'getClusterCapabilityData'),
    (91314, 'Cisco Adaptive Security Appliance Cross-Site Scripting Vulnerability', 'medium', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/+CSCOE+/saml/sp/acs?tgname=a'),
    (91368, 'Microsoft Exchange Server SSRF Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'autodiscover.json'),
    (91443, 'Microsoft Outlook Web Access Login Form Remote URI Redirection Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'outlook-web', '/exchweb/bin/auth/owalogon.asp?url=http://12345678910'),
    (91471, 'Buffalo WSR-2533DHPL2 Path Traversal Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'info.html'),
    (91594, 'Confluence Server OGNL Injection Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'doenterpagevariables.action'),
    (91676, 'ZOHOcorp ManageEngine Improper Authentication Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'LogonCustomization'),
    (91752, 'Apache HTTP Server Path Traversal Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/../../../../../../../etc/passwd'),
    (91805, 'Draytek VigoConnect Local File Inclusion Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'WebServlet'),
    (91832, 'Atlassian Confluence Server Information Disclosure Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', 'web.xml'),
    (91940, 'Metabase Information Disclosure Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/api/geojson?url=file:///c://windows/win.ini'),
    (91970, 'SonicWall SMA SQL Injection Vulnerability', 'high', 'sql-injection', 'vulnerability', 'reset-server', 'web-browsing', 'supportInstaller'),
    (91991, 'Apache Log4j Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'utils.js'),
    (92271, 'D-LINK DIR Information Disclosure Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'getcfg.php'),
    (92295, 'Primetek Primefaces Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'dynamiccontent.properties.xhtml'),
    (92329, 'Grafana Labs Grafana Snapshot Authentication Bypass Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/api/snapshots/:key'),
    (92386, 'Ivanti Endpoint Manager Cloud Services Appliance Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'index.php'),
    (92389, 'Spring Cloud SPEL Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/functionRouter'),
    (92397, 'Eclipse Jetty Information Disclosure Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', 'concat'),
    (92483, 'VMware Server-Side Template Injection Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'verify'),
    (92526, 'Sophos Firewall Authentication Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'Controller'),
    (92570, 'F5 BIG-IP Authentication Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'bash'),
    (92626, 'SolarView Compact Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'conf_mail.php'),
    (92712, 'Eclipse Jetty Information Disclosure Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', 'web.xml'),
    (92934, 'Atlassian Confluence Authentication Bypass Vulnerability', 'critical', 'insecure-credentials', 'vulnerability', 'reset-server', 'web-browsing', 'dologin.action'),
    (93079, 'GLPI htmlawed Module Code Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'htmLawedTest.php'),
    (93114, 'Adobe ColdFusion Remote Code Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'ChannelListener.cfc'),
    (93295, 'Dahua Improper Authentication Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'RPC2_Login'),
    (93512, 'Joomla Improper Access Control Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', '/api/index.php/v1/config/application?public=true'),
    (93588, 'JAI-EXT Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'wms'),
    (93713, 'Adobe ColdFusion Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'iedit.cfc'),
    (94087, 'Adobe ColdFusion Improper Access Control Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'utils.cfc'),
    (94246, 'TOTOlink A7100RU Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'cstecgi.cgi'),
    (94248, 'Chamilo Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'additional_webservices.php'),
    (94261, 'vBulletin Deserialization Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'save'),
    (94275, 'Adobe ColdFusion IPFilterUtils Improper Access Control Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'utils.cfc'),
    (94299, 'PaperCut NG and MF Path Traversal Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/../../deployment/sharp/icons/home-app.png'),
    (94328, 'Generic Cross-Site Scripting Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', '/calendar_scheduler.php?start="><script>alert(document.cookie)</script>'),
    (94344, 'Stakater Forecastle Directory Traversal Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', 'test'),
    (94409, 'JetBrains TeamCity Authentication Bypass Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/app/rest/users/id:1/tokens/RPC2'),
    (94413, 'Cacti Group Cacti SQL Injection Vulnerability', 'critical', 'sql-injection', 'vulnerability', 'reset-server', 'web-browsing', 'graph_view.php'),
    (94475, 'IBM Aspera Faspex Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'relay_package'),
    (94666, 'Qlik Sense Enterprise HTTP Request Smuggling Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-both', 'web-browsing', 'CVE-2023-41265.ttf'),
    (94701, 'ownCloud Information Disclosure Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/YARg.css'),
    (94842, 'Qlik Sense Enterprise Path Traversal Vulnerability', 'medium', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'localhost:8080/qrs/ReloadTask?xrfkey=1333333333333337&filter=.ttf'),
    (94845, 'cPanel ErrorPage Cross-Site Scripting Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', '<img src=x onerror="prompt(document.domain)">9264863'),
    (94885, 'Ivanti Multiple Products Authentication Bypass Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'system-information'),
    (94975, 'D-Link D-View TftpSendFileThread Directory Traversal Vulnerability', 'high', 'info-leak', 'vulnerability', 'drop', 'tftp', None),
    (95095, 'JetBrains TeamCity Authentication Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'hax'),
    (95102, 'JetBrains TeamCity Path Traversal Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'diagnostic.jsp'),
    (95132, 'aiohttp Directory Traversal Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/../../../../../../../../etc/passwd.'),
    (95258, 'Check Point Security Gateway Directory Traversal Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'MyCRL'),
    (95295, 'PHP CGI Argument Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'status.php'),
    (95308, 'Microsoft Exchange Server Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'autodiscover.json'),
    (95311, 'Zoho ManageEngine Desktop Central Authentication Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'agentLogUploader'),
    (95373, 'SAP Solution Manager Privilege Escalation Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'soap', 'EemAdmin'),
    (95382, 'Progress Kemp LoadMaster REST API Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'set'),
    (95393, 'Splunk Enterprise Path Traversal Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'passwd'),
    (95408, 'TerraMaster TOS Remote Code Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'api.php'),
    (95410, 'Minio Information Disclosure Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'verify'),
    (95415, 'ServiceNow Platform Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'login.do'),
    (95423, 'Openfire Directory Traversal Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'log.jsp'),
    (95433, 'Apache Airflow Experimental API Authentication Bypass Vulnerability', 'critical', 'code-obfuscation', 'vulnerability', 'reset-server', 'web-browsing', '/api/experimental/latest_runs'),
    (95567, 'SolarWinds Web Help Desk Hardcoded Credential Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '/helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets/'),
    (95568, 'Apache HTTP Server on Windows Server-Side Request Forgery Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/etc/passwd#vt/test'),
    (95792, 'Ivanti Cloud Services Appliance Broker Authentication Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'users.php'),
    (96109, 'Ingress Nginx Admission Controller Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/'),
    (96143, 'Langflow Unauthenticated Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'code'),
    (96194, 'Apache HTTP Server Information Disclosure Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'temp.db?.1.1.1.1a-1.css'),
    (96267, 'Ivanti Endpoint Manager Mobile Remote Code Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/mifs/rs/api/v2/featureusage?format=${4427*4428}'),
    (96314, 'Oracle Business Intelligence Local File Inclusion Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'saw.dll'),
    (96343, 'Cisco IOS XE WLC Arbitrary File Upload Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/ap_spec_rec/upload/'),
    (96481, 'Microsoft Sharepoint Authentication Bypass Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'ToolPane.aspx'),
    (96497, 'Fortinet FortiWeb SQL Injection Vulnerability', 'critical', 'sql-injection', 'vulnerability', 'reset-server', 'web-browsing', 'status'),
    (96509, 'Microsoft Sharepoint Authentication Bypass Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'ToolPane.aspx'),
    (96606, 'PTZOptics PT30X-SDINDI Cameras param.cgi Information Disclosure Vulnerability', 'critical', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'param.cgi'),
    (96611, 'SimpleHelp SimpleHelp WebDownloadServer Directory Traversal Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'serverconfig.xml'),
    (96643, 'Cisco Secure Firewall ASA and Cisco Secure FTD Authentication Bypass Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', 'file_action.html'),
    (96671, 'Fortra GoAnywhere MFT Insecure Deserialization Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/goanywhere/license/Unlicensed.xhtml/xjprn?javax.faces.ViewState=xjprn&GARequestAction=act'),
    (96700, 'Kentico Xperience Authentication Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'soap', 'SyncServer.asmx'),
    (96738, 'Apache Tomcat Rewrite Rules Relative Path Traversal Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'confluence-base', 'web.xml'),
    (96742, 'Fortinet FortiWeb Path Traversal Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'fwbcgi'),
    (96755, 'Oracle Identity Manager REST WebServices Authentication Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'groovyscriptstatus;.wadl'),
    (96787, 'React Server Components Remote Code Execution Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', '/'),
    (96795, 'Apache Tika XML External Entity Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-both', 'web-browsing', 'tika'),
    (97003, 'Zimbra Collaboration Server RestFilter Local File Inclusion Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'rest'),
    (97012, 'Ivanti Endpoint Manager Remote Control logintype Authentication Bypass Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'Auth'),
    (97127, 'GeoServer GetMap XML External Entity Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'wfs'),
    (97135, 'XWiki SolrSearchMacros Code Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'SolrSearch'),
    (97291, 'Ivanti Sentry Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'handleMessage'),
    (97413, 'SolarView Compact Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'downloader.php'),
    (97417, 'HTTP Bash History Access Attempt', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', '.bash_history'),
    (510004, 'Palo Alto Networks GlobalProtect Cross-Site Scripting Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'getconfig.esp'),
    (30514, 'HTTP SQL Injection Attempt', 'medium', 'sql-injection', 'vulnerability', 'alert', 'web-browsing', 'view.php'),
    (33338, 'HTTP SQL Injection Attempt', 'medium', 'sql-injection', 'vulnerability', 'alert', 'web-browsing', 'printdetail.asp'),
    (38531, 'HTTP SQL Injection Attempt', 'medium', 'sql-injection', 'vulnerability', 'alert', 'web-browsing', 'forum_answer.php'),
    (37008, 'PHP-Charts PHP Code Execution Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'url.php'),
    (55358, 'Ruby on Rails File Content Disclosure Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'profiles'),
    (58435, 'Brother MFC-J6520DW Authentication Bypass Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'status.html'),
    (96441, 'TBK DVR-4104 and DVR-4216 Command Injection Vulnerability', 'medium', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'device.rsp'),
    (95922, 'jQuery File Upload Plugin Unrestricted File Upload Vulnerability', 'medium', 'code-execution', 'vulnerability', 'alert', 'web-browsing', 'index.php'),
    (37765, 'PHPMoAdmin Object Parameter Handling Code Execution Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'moadmin.php'),
    (56480, 'Flexible Poll 1.2 SQL Injection Vulnerability', 'critical', 'sql-injection', 'vulnerability', 'reset-server', 'web-browsing', 'index.php'),
    (97356, 'Adobe ColdFusion Path Traversal Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'ide.cfm'),
    (97710, 'Atlassian Web Resource Download Path Traversal Vulnerability', 'high', 'info-leak', 'vulnerability', 'reset-server', 'web-browsing', 'download/resources/jira.webresources:color-picker-popup/images/..::..::..::..::..::WEB-INF::web.xml'),
    # 2026-11-19/20 vulnerability-scanner runs against the pa440 (cases 73849-73864): signatures the tenant
    # raised native PAN NGFW alerts for. misc keeps only the request path, never the scanned host.
    (56335, 'ABB PB610 Panel Builder 600 IDAL HTTP Host Stack Buffer Overflow Vulnerability', 'high', 'overflow', 'vulnerability', 'reset-server', 'web-browsing', None),
    (30147, 'Novell GroupWise Messenger Accept Language Header Overflow Vulnerability', 'high', 'overflow', 'vulnerability', 'alert', 'web-browsing', None),
    (55363, 'Nginx Unit Router Process Heap-based Buffer Overflow Vulnerability', 'critical', 'overflow', 'vulnerability', 'reset-server', 'web-browsing', None),
    (95187, 'Palo Alto Networks GlobalProtect OS Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'global-protect/login.esp'),
    (95191, 'Palo Alto Networks GlobalProtect OS Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', None),
    (90135, 'Siemens SIMATIC S7-300 CPU Denial-of-Service Vulnerability', 'high', 'dos', 'vulnerability', 'alert', 'web-browsing', None),
    (54679, 'Smart Software Solutions CoDeSys ControlService Stack Buffer Overflow Vulnerability', 'high', 'overflow', 'vulnerability', 'reset-server', 'web-browsing', None),
    (97000, 'DNN Platform Unauthenticated File Upload Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'Providers/HtmlEditorProviders/DNNConnect.CKE/Browser/FileUploader.ashx'),
    (59523, 'Cogent DataHub Information Disclosure Vulnerability', 'medium', 'info-leak', 'vulnerability', 'alert', 'web-browsing', 'index.asp'),
    (31769, 'HTTP Long If-Modified-Since Header Anomaly', 'high', 'overflow', 'vulnerability', 'reset-server', 'web-browsing', None),
    (38761, 'Apache Tomcat Remote Code Execution Via JSP Upload Vulnerability', 'high', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', None),
    (96989, 'SmarterTools SmarterMail guid Directory Traversal Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'api/upload'),
    (97182, 'WordPress Breeze Cache Arbitrary File Upload Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'blog-posting', 'wp-comments-post.php'),
    (97173, 'Fortinet FortiSandbox Command Injection Vulnerability', 'critical', 'code-execution', 'vulnerability', 'reset-server', 'web-browsing', 'fortisandbox/job-detail/tracer-behavior'),
    (35614, 'Lighttpd Connection Type Denial-of-Service Vulnerability', 'high', 'dos', 'vulnerability', 'reset-server', 'web-browsing', None),
    (35823, 'HTTP SQL Injection Attempt', 'medium', 'sql-injection', 'vulnerability', 'alert', 'web-browsing', 'index.php'),
    (91579, 'HTTP SQL Injection Attempt', 'medium', 'sql-injection', 'vulnerability', 'alert', 'web-browsing', 'index.php'),
    # Non-web services seen in the same scans (legacy-service family): TFTP drop, telnet, LPD, SMTP, FTP alert.
    (30173, 'TFTP Server FileName Buffer Overflow Vulnerability', 'high', 'code-execution', 'vulnerability', 'drop', 'tftp', None),
    (37249, 'Microsoft Windows Telnet Service Buffer Overflow Vulnerability', 'critical', 'overflow', 'vulnerability', 'reset-server', 'telnet', None),
    (54430, 'HylaFAXplus LDAP Authentication User Name Buffer Overflow Vulnerability', 'medium', 'overflow', 'vulnerability', 'alert', 'ftp', None),
    (54692, 'Hummingbird InetD LPD Component Buffer Overflow Vulnerability', 'high', 'overflow', 'vulnerability', 'reset-server', 'lpd', None),
    (30384, 'Mail Server SMTP EHLO/HELO Buffer Overflow Vulnerability', 'critical', 'overflow', 'vulnerability', 'reset-server', 'smtp-base', None),
]
for _r in _TENANT_SIGS:
    _THREAT_SIGS["t%d" % _r[0]] = _r[:5]
_TENANT_PROFILE = {"t%d" % _r[0]: (_r[5], _r[6], _r[7]) for _r in _TENANT_SIGS}
# Actions that end the session: the matching traffic log ends with session_end_reason=threat.
_SESSION_ENDING_ACTIONS = ("drop", "reset-server", "reset-client", "reset-both", "block-ip")


def _sig(config, key):
    extra = (_get_config(config).get("threat_signatures") or {}).get(key)
    return tuple(extra) if extra else _THREAT_SIGS[key]


def _threat_record(config, tf, sig, action, ts, misc=None, user_agent=None, repeats=1):
    """One PAN-OS THREAT log (firewall.threat) for the session described by `tf`.

    `tf` is the traffic-field dict of the session it fired in, so the threat log shares that
    session's addresses, ports, zones, interfaces, users, App-ID, rule and session_id.
    Documented extras over the traffic format: misc, threat_id, threat_name, threat_category,
    direction, user_agent, xff / xff_ip. Header signature slot is the Threat ID.
    """
    tid, tname, sev, cat, subtype = sig
    f = {k: tf[k] for k in _URL_SHARED_KEYS if tf.get(k) not in (None, "")}
    fmt = str(_get_config(config).get("threat_severity_format", "number")).lower()
    f.update({
        "action":              action,
        "misc":                misc,
        "file_name":           misc,                 # the live column that holds $misc
        # Live CEF rows: the documented `threat_id=$threatid` expands to "Name(ID)" and the tenant
        # turns it into the numeric ID column; a bare number sent from here is dropped instead
        # (all 56 of our rows lacked threat_id while all 613 of the pa440's had it).
        "threat_id":           f"{tname}({tid})",
        "threat_name":         f"{tname}({tid})",
        "threat_name_firewall": tname,
        "threat_category":     cat,
        "direction":           "client-to-server",
        "direction_of_attack": "client to server",   # the live column (doc key: direction)
        # The documented format sends the NUMERIC severity ($number-of-severity); the live
        # columns carry the word. Send the number as `severity` and the word as
        # `vendor_severity`; threat_severity_format=word swaps them (the probe decides).
        "severity":            (sev.capitalize() if fmt == "word" else str(_SEVERITY_NUM[sev])),
        "vendor_severity":     sev.capitalize(),
        "count_of_repeats":    repeats,
        "user_agent":          user_agent,
    })
    # Live CEF rows put "Name(ID)" in the header signature slot ($threatid expands to it).
    return _format_cef(config, subtype, f, log_type="THREAT", severity=_SEVERITY_NUM[sev], ts=ts,
                       fw_type="firewall.threat", sig=f"{tname}({tid})")


def _threat_session(config, key, src, dst, dpt, app, *, action, end, suser=None, shost=None,
                    dhost=None, from_zone="trust", to_zone="trust", proto=None, rule=None,
                    misc=None, user_agent=None, repeats=1, src_category="workstation",
                    threat_only=False):
    """[threat log, traffic log] for one session that tripped signature `key`
    ([threat log] alone with threat_only=True: the session's traffic log is not generated).

    The firewall logs the threat part-way through the session. If the action ends the session
    (drop / reset-*), the traffic log for it ends with session_end_reason=threat and, as in the
    live feed, still records action=allow (the session was permitted by policy). An 'alert'
    action leaves the session to end normally. Both logs share one session_id and finish at or
    before `end`."""
    sig = _sig(config, key)
    ends = action in _SESSION_ENDING_ACTIONS
    dur = random.randint(1, 6) if ends else random.randint(2, 40)
    tf = _traffic_fields(config, src, dst, dpt, app, action="allow", shost=shost, suser=suser,
                         dhost=dhost, proto=proto, from_zone=from_zone, to_zone=to_zone,
                         bytes_sent=random.randint(300, 6000),
                         bytes_received=(random.randint(0, 600) if ends else random.randint(400, 40000)),
                         duration_s=dur, end_reason=("threat" if ends else None),
                         src_category=src_category, rule=rule)
    start = end - dur
    threat = _threat_record(config, tf, sig, action, ts=start + random.uniform(0.3, max(0.4, dur * 0.6)),
                            misc=misc, user_agent=user_agent, repeats=repeats)
    return [threat] if threat_only else [threat, _format_cef(config, "end", tf, ts=end)]


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
# analytic: True  -> traffic pattern maps to a documented detector and is selectable on
#                    demand, including informational variants that may not appear in alerts.
# analytic: False -> realistic traffic for hunts / correlation, but CEF traffic alone cannot
#                    represent the detector's required evidence.
# Targets name the alert the tenant actually raises: where a detector's base name is
# Informational (never shown in the alerts table) and the shape produces a Low variation,
# the variation is the target (e.g. Port Scan fires as "Suspicious port scan").
_DEFAULT_THREAT_EVENTS = [
    {"event": "port_scan",            "weight": 8,  "analytic": True,  "xsiam_alert": "Suspicious port scan"},
    {"event": "port_sweep",           "weight": 6,  "analytic": True,  "xsiam_alert": "Port Sweep to multiple subnets"},
    {"event": "failed_connections",   "weight": 6,  "analytic": True,  "xsiam_alert": "Failed Connections"},
    {"event": "large_upload_https",   "weight": 5,  "analytic": True,  "xsiam_alert": "Large Upload (HTTPS)"},
    {"event": "large_upload_https_nonstd", "weight": 2, "analytic": True, "xsiam_alert": "Large Upload (HTTPS) to non-standard port"},
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
    {"event": "rare_appid",           "weight": 3,  "analytic": False, "xsiam_alert": None},  # Informational: "Rare AppID usage to a rare destination" — never surfaces in the alerts table; background only
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
    {"event": "rare_domain_less_common_port", "weight": 1, "analytic": True, "xsiam_alert": "Abnormal Communication to a Rare Domain With a Less Common Port"},
    {"event": "rare_domain_suspicious_as", "weight": 1, "analytic": True, "xsiam_alert": "Abnormal Communication to a Rare Domain to a Suspicious Autonomous System (AS)"},
    {"event": "recurring_rare_domain_abnormal_suffix", "weight": 1, "analytic": True, "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain With an Abnormal Domain Suffix"},
    {"event": "large_upload_generic_popular_target", "weight": 1, "analytic": True, "xsiam_alert": "Large Upload (Generic) to a Frequently Used Upload Target"},
    {"event": "new_ftp_server_port_scan", "weight": 1, "analytic": True, "xsiam_alert": "New FTP Server Accessed Via a Port Scan"},
    {"event": "uncommon_ssh_internal", "weight": 1, "analytic": True, "xsiam_alert": "Uncommon SSH session was established to an internal IP"},
    {"event": "rdp_unmanaged_dense_subnet", "weight": 1, "analytic": True, "xsiam_alert": "RDP from an unmanaged endpoint in a typically managed subnet with a significantly higher number of managed endpoints in the subnet"},
    {"event": "dormant_host_known_source", "weight": 2, "analytic": True, "xsiam_alert": "Abnormal connections to a dormant host"},
    {"event": "large_upload_generic_small", "weight": 1, "analytic": True, "xsiam_alert": "Large Upload (Generic) Lower than 100 MB"},
    {"event": "new_ssh_admin_behavior", "weight": 2, "analytic": True, "xsiam_alert": "New SSH Administrative Behavior"},
    {"event": "new_ftp_server_external", "weight": 2, "analytic": True, "xsiam_alert": "New FTP Server from an external source"},
    {"event": "dcsync_non_dc_appid", "weight": 1,  "analytic": True,  "xsiam_alert": "DCSync from a non domain controller"},
    {"event": "dcsync_internet_facing", "weight": 1, "analytic": True,  "xsiam_alert": "Possible DCSync from an internet-facing server"},
    {"event": "dcsync_large",         "weight": 1,  "analytic": True,  "xsiam_alert": "Large DCSync from a non domain controller"},
    {"event": "dcsync_large_appid",   "weight": 1,  "analytic": True,  "xsiam_alert": "Large DCSync from a non domain controller by AppID"},
    {"event": "rare_appid_internet_facing", "weight": 2, "analytic": True, "xsiam_alert": "Rare AppID usage to a rare destination from an internet-facing server"},
    # "Failed Spam Bot Traffic" is Informational; it remains selectable for raw-event and
    # analytics validation even though it may not produce an alerts-table row.
    {"event": "spam_bot_failed",      "weight": 2,  "analytic": True,  "xsiam_alert": "Failed Spam Bot Traffic"},
    {"event": "ssh_suspicious_nonstd", "weight": 2, "analytic": True,  "xsiam_alert": "A suspicious SSH session was established"},
    {"event": "ssh_high_volume",      "weight": 2,  "analytic": True,  "xsiam_alert": "Uncommon SSH session was established that involved a higher than usual volume"},
    {"event": "ssh_proxy_high_volume", "weight": 1, "analytic": True,  "xsiam_alert": "High Volume Unusual SSH activity that resembles SSH proxy"},
    {"event": "ssh_proxy_suspicious", "weight": 1,  "analytic": True,  "xsiam_alert": "Suspicious SSH activity that resembles SSH proxy"},
    {"event": "ssh_proxy_detected",   "weight": 1,  "analytic": True,  "xsiam_alert": "Unusual SSH activity that resembles SSH proxy detected"},
    {"event": "host_attack_chain",    "weight": 2,  "analytic": True,  "xsiam_alert": "Multiple network-related alerts produced by different detectors on the same host"},
    # THREAT logs (panw_ngfw_threat_raw). The firewall's own signature raises a native PAN_NGFW
    # alert named after the signature, so each target is the Threat name the tenant shows.
    {"event": "threat_log4j_exploit", "weight": 3, "analytic": True, "xsiam_alert": "Apache Log4j Remote Code Execution Vulnerability(92046)"},
    {"event": "threat_dnsmasq_exploit", "weight": 2, "analytic": True, "xsiam_alert": "Dnsmasq Integer Underflow Vulnerability(30109)"},
    {"event": "threat_nmap_nse_scan", "weight": 2, "analytic": True, "xsiam_alert": "Nmap Scripting Engine Detection(58433)"},
    {"event": "threat_openvas_scan",  "weight": 2, "analytic": True, "xsiam_alert": "OpenVAS Vulnerability Scanner Detection(55283)"},
    {"event": "threat_rpc_portmapper_dump", "weight": 1, "analytic": True, "xsiam_alert": "RPC Portmapper DUMP Request Detected(32796)"},
    {"event": "threat_nfs_export_probe", "weight": 1, "analytic": True, "xsiam_alert": "UNIX NFS Export Directory Attempt(32788)"},
    {"event": "threat_rpc_fragmentation_evasion", "weight": 1, "analytic": True, "xsiam_alert": "Sun ONC RPC Small Piece fragmentation Evasion Detection(54578)"},
    {"event": "threat_ssh_bruteforce", "weight": 2, "analytic": True, "xsiam_alert": "SSH User Authentication Brute Force Attempt(40015)"},
    {"event": "threat_iax2_dos",       "weight": 1, "analytic": True, "xsiam_alert": "Digium Asterisk IAX2 Call Number Denial Of Service Vulnerability(40020)"},
    {"event": "threat_bot_backdoor_beacon", "weight": 2, "analytic": True, "xsiam_alert": "Bot: Backdoor_Win32_Agent_qxx(19900)"},
    {"event": "threat_bot_agobot_backdoor", "weight": 2, "analytic": True, "xsiam_alert": "Bot: Backdoor_Win32_Agobot_pnd_pnj(19999)"},
    {"event": "threat_pastebin_c2",    "weight": 2, "analytic": True, "xsiam_alert": "Pastebin Command and Control Traffic Detection(21975) / Pastebin Command and Control Traffic Detection(21976) / Pastebin Command and Control Traffic Detection(21980)"},
    {"event": "threat_schoolboy_downloader", "weight": 2, "analytic": True, "xsiam_alert": "Schoolboy Downloader Traffic Detection(21985)"},
    {"event": "threat_php_rce",        "weight": 3, "analytic": True, "xsiam_alert": "PHP Remote Code Execution Vulnerability(97622) / PHP Remote Code Execution Vulnerability(97623) / PHP Remote Code Execution Vulnerability(97625)"},
    {"event": "threat_moxa_tn5900_injection", "weight": 1, "analytic": True, "xsiam_alert": "Moxa TN-5900 Firmware Command Injection Vulnerability(97630)"},
    {"event": "threat_trendnet_tew432brp_injection", "weight": 1, "analytic": True, "xsiam_alert": "TRENDnet TEW-432BRP Firmware Command Injection Vulnerability(97650)"},
    {"event": "threat_php_memory_corruption", "weight": 2, "analytic": True, "xsiam_alert": "PHP Memory Corruption Vulnerability(543004)"},
    # Informational: never surfaces in the alerts table; background only.
    {"event": "threat_default_credentials_http", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "threat_web_rce",          "weight": 4, "analytic": True, "xsiam_alert": "Name(ID) of the signature hit: code-execution signature, any of the web-RCE family"},
    {"event": "threat_web_infoleak",     "weight": 3, "analytic": True, "xsiam_alert": "Name(ID) of the signature hit: info-leak signature, any of the web info-leak family"},
    {"event": "threat_web_detect_only",  "weight": 3, "analytic": True, "xsiam_alert": "Name(ID) of the signature hit: alert-only signature, any of the detect-only family"},
    {"event": "threat_web_sqli_overflow_dos", "weight": 1, "analytic": True, "xsiam_alert": "Name(ID) of the signature hit: sqli/overflow/dos signature, any of that family"},
    {"event": "threat_legacy_service_exploit", "weight": 1, "analytic": True, "xsiam_alert": "Name(ID) of the signature hit: FTP/TFTP exploit signature, any of the legacy family"},
    {"event": "threat_wd_mycloud_backdoor", "weight": 1, "analytic": True, "xsiam_alert": "Western Digital My Cloud Backdoor(18011)"},
    {"event": "threat_scanner_campaign", "weight": 1, "analytic": True, "xsiam_alert": "Multiple network-related alerts produced by different detectors on the same host"},
    # Realistic network patterns whose dedicated analytic needs EAL-decoded fields the CEF
    # traffic log cannot carry — kept for hunts / correlation, NOT offered on demand.
    {"event": "kerberos_preauth_pattern", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "ntlm_relay_pattern",   "weight": 2,  "analytic": False, "xsiam_alert": None},
    {"event": "dns_tunnel_pattern",   "weight": 2,  "analytic": False, "xsiam_alert": None},
    {"event": "ldap_recon",           "weight": 2,  "analytic": False, "xsiam_alert": None},
    # Traffic-based hits ported from the other firewall generators (names and alert targets
    # match the FortiGate / Check Point / ASA / Firepower registries).
    {"event": "tor_connection",       "weight": 3,  "analytic": True,  "xsiam_alert": "Recurring access to rare IP"},
    {"event": "server_outbound_http", "weight": 2,  "analytic": True,  "xsiam_alert": "Recurring access to rare IP"},
    {"event": "dns_c2_beacon",        "weight": 3,  "analytic": True,  "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain"},
    {"event": "smb_new_host_lateral", "weight": 4,  "analytic": True,  "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "smb_rare_file_transfer","weight": 3, "analytic": True,  "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "smb_share_enumeration","weight": 5,  "analytic": True,  "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "rare_external_rdp",    "weight": 2,  "analytic": True,  "xsiam_alert": "Rare RDP session to a remote host"},
    {"event": "large_download",       "weight": 3,  "analytic": False, "xsiam_alert": None},
    {"event": "dos_anomaly",          "weight": 3,  "analytic": False, "xsiam_alert": None},
    {"event": "external_port_scan",   "weight": 3,  "analytic": False, "xsiam_alert": None},
    {"event": "snmp_unexpected_source","weight": 1, "analytic": False, "xsiam_alert": None},
    # File Data logs (firewall.filedata): file-type identification, severity low, never an alert.
    {"event": "file_data_web",        "weight": 3,  "analytic": False, "xsiam_alert": None},
    {"event": "file_data_internal",   "weight": 3,  "analytic": False, "xsiam_alert": None},
    {"event": "file_data_ocsp",       "weight": 2,  "analytic": False, "xsiam_alert": None},
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
          from_zone=None, to_zone=None, url_cat=None, end_reason=None, proto=None,
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
def _scan_burst(config, src, user, shost, ports, end=None, step=2, target=None):
    """One source probing `ports` on a single internal server, ending at `end`."""
    target = target or random.choice(config.get("internal_servers") or ["10.0.10.50"])
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


def _sim_large_upload_generic_popular_target(config, session_context):
    """Large generic-protocol upload to a popular target also present in benign egress.

    GitHub is configured as a commonly reached benign destination with SSH/22 support;
    a large push over SSH is generic (not HTTP/S, FTP, or SMTP) and stays coherent with
    the benign destination/App-ID model.
    """
    src, user, shost = _threat_actor(config, session_context)
    targets = config.get("benign_egress_destinations") or []
    dest = next((d for d in targets if d.get("domain", "").lower() == "github.com"),
                {"domain": "github.com", "ports": [22]})
    domain, dst = resolver.benign_target(config, dest)
    size = random.randint(300, 700) * 1024 * 1024
    print(f"    - PAN NGFW simulating: large generic upload to common SSH target {src} -> {domain}")
    return [_conn(config, src, dst, 22, "ssh", suser=user, shost=shost, dhost=domain,
                  bytes_sent=size, bytes_received=random.randint(2000, 50000),
                  duration_s=random.randint(300, 1200), url_cat="computer-and-internet-info")]


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


def _sim_rdp_unmanaged_dense_subnet(config, session_context):
    """Seed many managed-looking peers in a subnet, then RDP from an unknown endpoint.

    PAN traffic can represent the source subnet and endpoint distinction, but whether XSIAM
    counts the peers as managed is tenant enrichment; the generated neighbors are evidence
    for the variation, not a guarantee of its inventory predicate.
    """
    servers = config.get("internal_servers") or ["10.0.10.50"]
    server = random.choice(servers)
    subnet = server.rsplit(".", 1)[0]
    managed_peers = random.sample(range(20, 180), random.randint(15, 25))
    baseline = []
    for host_octet in managed_peers:
        peer = f"{subnet}.{host_octet}"
        dst = random.choice(servers)
        port = random.choice([443, 445, 389])
        baseline.append(_conn(config, peer, dst, port, _APP_for_port(port), src_category="workstation",
                              shost=resolver.internal_fqdn(config, peer),
                              dhost=resolver.internal_fqdn(config, dst), from_zone="trust", to_zone="trust",
                              bytes_sent=random.randint(1000, 30000), bytes_received=random.randint(2000, 80000),
                              duration_s=random.randint(2, 45)))
    src = f"{subnet}.{random.randint(220, 250)}"
    print(f"    - PAN NGFW simulating: unmanaged RDP source {src} in subnet with {len(managed_peers)} managed peers")
    baseline.append(_conn(config, src, server, 3389, "ms-rdp", src_category="unknown",
                          shost=f"unknown-{src.replace('.', '-')}",
                          dhost=resolver.internal_fqdn(config, server), from_zone="trust", to_zone="trust",
                          bytes_sent=random.randint(30000, 300000), bytes_received=random.randint(150000, 2000000),
                          duration_s=random.randint(120, 2400)))
    return baseline


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
    refuse it (reset by the server or never answering), as blocklisted spam senders see.
    Preserve the detector's named-domain plus unresolved-IP signal; volume itself is not
    the Spam Bot criterion. The event is Informational, but remains selectable for testing."""
    src, user, shost = _threat_actor(config, session_context)
    servers, domains = [], set()
    for i in range(random.randint(150, 300)):
        if random.random() < 0.5:
            domain = _recipient_domain(i)
            domains.add(domain)
            mx = f"{random.choice(['mx', 'mx1', 'mail', 'smtp'])}.{domain}"
            servers.append((resolver.answer_for(mx, config), mx))
        else:
            servers.append((random_external_ip(), None))
    n = random.randint(max(400, len(servers)), 800)
    picks = servers + [random.choice(servers) for _ in range(n - len(servers))]
    random.shuffle(picks)
    span = random.randint(5400, 7200)
    t0 = time.time() - span
    print(f"    - PAN NGFW simulating: failed spam bot {src} -> {n} SMTP sessions to {len(servers)} servers "
          f"({len(domains)} recipient domains, {len(servers) - len(domains)} unresolved IPs)")
    out = []
    for i, (dst, dhost) in enumerate(picks):
        ok = random.random() < 0.2
        port = random.choices([25, 587, 465], weights=[70, 20, 10])[0]
        received = random.randint(200, 2000) if ok else (random.randint(40, 160) if random.random() < 0.55 else 0)
        reason = None if ok else ("tcp-rst-from-server" if received else "aged-out")
        out.append(_conn(config, src, dst, port, "ssl" if port == 465 else "smtp", suser=user,
                         shost=shost, dhost=dhost,
                         bytes_sent=random.randint(2000, 20000) if ok else random.randint(60, 180),
                         bytes_received=received, duration_s=random.randint(1, 20) if ok else random.randint(0, 3),
                         end_reason=reason, ts=t0 + span * i / n))
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


def _sim_uncommon_ssh_internal(config, session_context):
    """Uncommon SSH to an internal destination, without requiring the destination to be rare."""
    src, user, shost = _ssh_habit_actor(config, session_context)
    servers = config.get("internal_servers") or ["10.0.10.50"]
    dst = random.choice([h for h in servers if h != src] or servers)
    print(f"    - PAN NGFW simulating: uncommon SSH to internal IP {src} -> {dst}:22")
    return [_conn(config, src, dst, 22, "ssh", suser=user, shost=shost,
                  dhost=resolver.internal_fqdn(config, dst), from_zone="trust", to_zone="trust",
                  bytes_sent=random.randint(3000, 60000), bytes_received=random.randint(4000, 120000),
                  duration_s=random.randint(30, 600))]


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
                 "recurring_rare_domain_suspicious_as", "recurring_rare_domain_abnormal_suffix",
                 "ddns_access")
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


_ABNORMAL_DOMAIN_SUFFIXES = ("zip", "click", "top", "xyz")


def _beacon_dst_abnormal_suffix(config, src):
    """Stable rare destination with an uncommon suffix for the recurring-domain variation."""
    store = beacon_targets("panw_ngfw")
    key = f"rare|rare_dom_suffix|{src}"
    if key in store:
        value = store[key]
        return (value[0], value[1]) if isinstance(value, (list, tuple)) else (value, None)
    label = rare_domain(key).split(".", 1)[0]
    suffix_index = int(hashlib.sha256(key.encode()).hexdigest(), 16) % len(_ABNORMAL_DOMAIN_SUFFIXES)
    domain = f"{label}.{_ABNORMAL_DOMAIN_SUFFIXES[suffix_index]}"
    ip = _rare_answer(domain, key)
    store[key] = [ip, domain]
    return ip, domain


def _sim_recurring_rare_domain_abnormal_suffix(config, session_context):
    """Daily beacon to one stable rare domain with a less common TLD."""
    src, user, shost = _beacon_host(config, session_context, "panw_rare_dom_suffix")
    ip, domain = _beacon_dst_abnormal_suffix(config, src)
    print(f"    - PAN NGFW simulating: daily rare-domain beacon with unusual suffix {src} -> {domain}")
    return _beacon_day(config, src, user, shost, ip, 443, domain=domain,
                       url_cat="newly-registered-domain")


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


def _sim_rare_domain_less_common_port(config, session_context):
    """One rare-domain connection on an uncommon service port (informational variation)."""
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"rdclp|{user}")
    port = random.choice([8080, 8081, 8443, 8888, 9443])
    print(f"    - PAN NGFW simulating: rare domain on less-common port {src} -> {dom}:{port}")
    return _web(config, src, dst, port, "ssl", dom, url_cat="unknown", suser=user, shost=shost,
                bytes_sent=random.randint(500, 12000), bytes_received=random.randint(1000, 30000),
                duration_s=random.randint(1, 90))


def _sim_rare_domain_suspicious_as(config, session_context):
    """One rare-domain connection; destination AS reputation is XSIAM-enriched."""
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"rdcas|{user}")
    print(f"    - PAN NGFW simulating: rare domain (AS-enrichment candidate) {src} -> {dom}")
    return _web(config, src, dst, 443, "ssl", dom, url_cat="command-and-control", suser=user, shost=shost,
                bytes_sent=random.randint(500, 12000), bytes_received=random.randint(1000, 30000),
                duration_s=random.randint(1, 90))


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


def _sim_new_ftp_server_port_scan(config, session_context):
    """Probe a new FTP server across privileged ports, then establish FTP to that host."""
    src, user, shost = _threat_actor(config, session_context)
    server = new_ftp_server_host(config)
    other_ports = [p for p in _PRIV_PORTS if p != 21]
    ports = [21] + random.sample(other_ports, min(len(other_ports), random.randint(19, 23)))
    random.shuffle(ports)
    now = time.time()
    print(f"    - PAN NGFW simulating: port scan then new FTP service {src} -> {server}:21")
    out = _scan_burst(config, src, user, shost, ports, end=now - 1, step=2, target=server)
    out.append(_conn(config, src, server, 21, "ftp", suser=user, shost=shost,
                     dhost=resolver.internal_fqdn(config, server), from_zone="trust", to_zone="trust",
                     bytes_sent=random.randint(2000, 20000), bytes_received=random.randint(50000, 3000000),
                     duration_s=random.randint(10, 180), ts=now))
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


def _dormant_host(config):
    """A PREVIOUSLY-SEEN internal host that is now quiet — the detector profiles a
    'relatively inactive endpoint', so it must be an address XSIAM already knows, not a
    never-seen one. Drawn from a small stable set of live, rarely-contacted hosts so the same
    hosts recur as the dormant targets across runs (a never-seen address is not equivalent
    evidence)."""
    pool = stable_subset(known_internal_hosts(config), "panw_dormant_hosts", n=6)
    return random.choice(pool) if pool else rare_known_host(config)


def _dormant_conns(config, src, shost, user=None):
    dormant = _dormant_host(config)
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


# --- Traffic-based hits ported from the other firewall generators -----------------------------
# Same behaviours the ASA / FortiGate / Check Point / Firepower modules fire (Tor, SMB lateral
# movement, server egress, DNS C2, DoS, SNMP walk ...), expressed as PAN-OS traffic logs.
def _tor_exit(config):
    nodes = config.get("tor_exit_nodes") or []
    if nodes:
        n = random.choice(nodes)
        return n.get("ip") if isinstance(n, dict) else n
    return rare_external_ip()


def _sim_tor_connection(config, session_context):
    """DNS lookup of the Tor project, then one long Tor session to an exit/relay address."""
    src, user, shost = _threat_actor(config, session_context)
    gname, gip = resolver.dns_server_for(config, src)
    port = random.choices([443, 9001, 9030], weights=[60, 30, 10])[0]
    tor_ip = _tor_exit(config)
    print(f"    - PAN NGFW simulating: Tor connection {src} -> {tor_ip}:{port}")
    now = time.time()
    return [
        _conn(config, src, gip, 53, "dns-base", suser=user, shost=shost, proto="udp",
              dhost=f"{gname}.{resolver.internal_domain(config)}", from_zone="trust", to_zone="trust",
              bytes_sent=random.randint(70, 120), bytes_received=random.randint(100, 300),
              duration_s=0, ts=now - 3),
        _conn(config, src, tor_ip, port, "tor" if port != 443 else "ssl", suser=user, shost=shost,
              bytes_sent=random.randint(10000, 100000), bytes_received=random.randint(50000, 500000),
              duration_s=random.randint(60, 3600), url_cat="proxy-avoidance-and-anonymizers"),
    ]


def _sim_server_outbound_http(config, session_context):
    """An internal server (never a browsing host) making plain HTTP to a rare external host."""
    servers = config.get("internal_servers") or ["10.0.10.50"]
    src = random.choice(stable_subset(servers, "panw_ngfw:server_outbound_http") or servers)
    ip, dom = _beacon_dst(config, "srv_http", src)
    dom = dom or rare_domain(f"srvhttp|{src}")
    print(f"    - PAN NGFW simulating: server outbound HTTP {src} -> {dom}")
    return _web(config, src, ip, 80, "web-browsing", dom, url_cat="unknown", suser=None,
                shost=None, from_zone="dmz", to_zone="untrust", src_category="server",
                user_agent=random.choice(_CLIENT_UAS[:3]),
                bytes_sent=random.randint(300, 4000), bytes_received=random.randint(500, 60000),
                duration_s=random.randint(5, 120))


def _smb_conns(config, src, user, shost, dests, step=20):
    out, t0 = [], time.time() - len(dests) * step
    for i, d in enumerate(dests):
        out.append(_conn(config, src, d, 445, "ms-ds-smbv3", suser=user, shost=shost,
                         dhost=resolver.internal_fqdn(config, d), from_zone="trust", to_zone="trust",
                         bytes_sent=random.randint(2000, 60000), bytes_received=random.randint(2000, 200000),
                         duration_s=random.randint(5, 120), ts=t0 + i * step))
    return out


def _sim_smb_new_host_lateral(config, session_context):
    """SMB from one workstation to 5-10 internal hosts it has never talked to."""
    src, user, shost = _threat_actor(config, session_context)
    n, dests = random.randint(5, 10), []
    for _ in range(30):
        peer = get_random_user(session_context, preferred_device_type="workstation") if session_context else None
        if peer and peer.get("ip") and peer["ip"] != src and peer["ip"] not in dests:
            dests.append(peer["ip"])
        if len(dests) >= n:
            break
    while len(dests) < n:
        dests.append(rare_internal_host(config, exclude=(src,)))
    print(f"    - PAN NGFW simulating: SMB new-host lateral movement {src} -> {len(dests)} hosts")
    return _smb_conns(config, src, user, shost, dests)


def _sim_smb_rare_file_transfer(config, session_context):
    """One 100 MB - 1 GB SMB session to a rarely-contacted workstation (data staging)."""
    src, user, shost = _threat_actor(config, session_context)
    dst = rare_known_host(config, exclude=(src,), avoid_subnet_of=src)
    size = random.randint(100 * 1024 * 1024, 1024 * 1024 * 1024)
    print(f"    - PAN NGFW simulating: SMB rare file transfer {src} -> {dst} {size // (1024 * 1024)}MB")
    return [_conn(config, src, dst, 445, "ms-ds-smbv3", suser=user, shost=shost,
                  dhost=resolver.internal_fqdn(config, dst), from_zone="trust", to_zone="trust",
                  bytes_sent=size, bytes_received=random.randint(1000, 50000),
                  duration_s=random.randint(120, 900))]


def _sim_smb_share_enumeration(config, session_context):
    """Rapid, tiny TCP/445 sessions to 15-40 distinct internal hosts: share hunting."""
    src, user, shost = _threat_actor(config, session_context)
    n = random.randint(15, 40)
    pool = list(sweep_targets(config, exclude=(src,)))
    random.shuffle(pool)
    dests = pool[:n]
    while len(dests) < n:
        dests.append(rare_internal_host(config, exclude=(src,)))
    print(f"    - PAN NGFW simulating: SMB share enumeration {src} -> {len(dests)} hosts")
    out, t0 = [], time.time() - n * 3
    for i, d in enumerate(dests):
        out.append(_conn(config, src, d, 445, "ms-ds-smbv3", suser=user, shost=shost,
                         from_zone="trust", to_zone="trust", bytes_sent=random.randint(40, 200),
                         bytes_received=random.randint(40, 200), duration_s=0, ts=t0 + i * 3))
    return out


def _sim_large_download(config, session_context):
    """One multi-GB INBOUND HTTPS session (huge received, tiny sent): the mirror of an upload."""
    src, user, shost = _threat_actor(config, session_context)
    dom, dst, url, is_tail = exfil_destination(config, "download")
    tail = url.split("://", 1)[-1]
    path = "/" + tail.split("/", 1)[1] if "/" in tail else "/"
    recv_mb = random.randint(500, 4000)
    print(f"    - PAN NGFW simulating: large download {dom} -> {src} {recv_mb}MB")
    return _web(config, src, dst, 443, "ssl", dom, path=path,
                url_cat="unknown" if is_tail else "online-storage-and-backup", suser=user, shost=shost,
                bytes_sent=random.randint(20000, 200000), bytes_received=recv_mb * 1024 * 1024,
                duration_s=random.randint(300, 2400))


def _sim_dns_c2_beacon(config, session_context):
    """One fixed host querying a rare external DNS server on a steady cadence (DNS C2)."""
    src, user, shost = _beacon_host(config, session_context, "panw_dns_c2")
    ip, dom = _beacon_dst(config, "dns_c2", src)
    n = random.randint(8, 15)
    step = random.randint(60, 240)
    print(f"    - PAN NGFW simulating: DNS C2 beacon {src} -> {ip} ({n} queries)")
    t = time.time() - n * step
    out = []
    for _ in range(n):
        t += step + random.randint(-10, 10)
        out.append(_conn(config, src, ip, 53, "dns-base", suser=user, shost=shost, proto="udp", dhost=dom,
                         bytes_sent=random.randint(80, 200), bytes_received=random.randint(100, 500),
                         duration_s=0, ts=min(t, time.time())))
    return out


def _sim_dos_anomaly(config, session_context):
    """80-150 tiny sessions from distinct external sources to one published server: a flood."""
    target = random.choice(config.get("internal_servers") or ["10.0.10.50"])
    port, app = random.choice([(80, "web-browsing"), (443, "ssl")])
    n = random.randint(80, 150)
    print(f"    - PAN NGFW simulating: DoS flood -> {target}:{port} ({n} sources)")
    out, t0 = [], time.time() - n * 0.5
    for i in range(n):
        out.append(_conn(config, random_external_ip(), target, port, app,
                         action=random.choice(["allow", "allow", "drop"]), from_zone="untrust",
                         to_zone="dmz", bytes_sent=random.randint(60, 200),
                         bytes_received=random.randint(0, 200), duration_s=0, ts=t0 + i * 0.5,
                         rule="Allow-Inbound-Web"))
    return out


def _sim_snmp_unexpected_source(config, session_context):
    """A workstation walking every network device on UDP/161 (the SNMP-harvest shape; the
    failed-community config logs are a different PAN log type and are not modelled)."""
    src, user, shost = _threat_actor(config, session_context)
    devs = mgmt_plane.network_devices(config)
    print(f"    - PAN NGFW simulating: SNMP walk {src} -> {len(devs)} devices")
    out, t = [], time.time() - 60
    for dev in devs:
        out.append(_conn(config, src, dev, 161, "snmp-base", suser=user, shost=shost, proto="udp",
                         from_zone="trust", to_zone="trust", bytes_sent=random.randint(60, 200),
                         bytes_received=random.randint(800, 40000), duration_s=random.randint(0, 3), ts=t))
        t += random.randint(1, 4)
    return out


def _sim_external_port_scan(config, session_context):
    """An Internet host probing 20-24 privileged ports on a published server; mostly blocked."""
    src = random_external_ip()
    target = random.choice(config.get("internal_servers") or ["10.0.10.50"])
    ports = random.sample(_PRIV_PORTS, min(len(_PRIV_PORTS), random.randint(20, 24)))
    print(f"    - PAN NGFW simulating: external port scan {src} -> {target} ({len(ports)} ports)")
    out, t0 = [], time.time() - len(ports) * 2
    for i, p in enumerate(ports):
        act = random.choices(["deny", "drop", "allow"], weights=[5, 3, 1])[0]
        out.append(_conn(config, src, target, p, "incomplete" if act != "allow" else _APP_for_port(p),
                         action=act, from_zone="untrust", to_zone="dmz", ts=t0 + i * 2,
                         rule="Deny-Inbound-Default" if act != "allow" else "Allow-Inbound-Web"))
    return out


def _sim_rare_external_rdp(config, session_context):
    """RDP from a workstation straight to a rare Internet host."""
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"extrdp|{user}")
    print(f"    - PAN NGFW simulating: rare external RDP {src} -> {dst}")
    return [_conn(config, src, dst, 3389, "ms-rdp", suser=user, shost=shost, dhost=dom,
                  bytes_sent=random.randint(40000, 400000), bytes_received=random.randint(200000, 4000000),
                  duration_s=random.randint(120, 3000), url_cat="unknown")]


# --- File Data logs (log_type THREAT, subtype file -> __firewall_type firewall.filedata) ----------
# The file-type identification entries the live pa440 writes when a profile alerts on a file type
# (read-only pull of its native CSV feed, 2026-11-16: ~12k rows, all severity low, action alert,
# threat category N/A, direction server-to-client). Name and Threat ID are as the device records
# them; the `filetype` token is each signature's file extension / type word (assumed: the native CSV
# has no such column) and `file_url` / `filedigest` are not in the CSV either (digest stays empty:
# only a WildFire verdict carries one).
_FILE_SIGS = {
    "bin":  (52081, "Unknown Binary File",                      "bin"),
    "php":  (52256, "Hypertext Preprocessor PHP File",          "php"),
    "xml":  (52384, "XML File",                                 "xml"),
    "jsp":  (52255, "JavaServer Pages JSP File",                "jsp"),
    "asp":  (52239, "Active Server Page ASP File",              "asp"),
    "aspx": (52257, "Active Server Page Extended ASPX File",    "aspx"),
    "json": (52380, "JSON File",                                "json"),
    "pdf":  (52021, "Adobe Portable Document Format (PDF)",     "pdf"),
    "der":  (52209, "DER Encoded X509 Certificate",             "der"),
    "crt":  (52390, "X509 Certificate File",                    "crt"),
    "perl": (52017, "Perl Script",                              "pl"),
    "py":   (52193, "Python File",                              "py"),
    "dat":  (52418, "DAT file",                                 "dat"),
}
# (signature key, file name pool, weight) as the live feed's name distribution
_FILE_WEB_NAMES = [
    ("php",  ["index.php", "login.php", "main.php", "calendar.php", "setup.php"], 8),
    ("xml",  ["sitemap.xml", "device-desc.xml", "dd.xml", "web.xml"], 5),
    ("jsp",  ["login.jsp", "index.jsp", "welcome.jsp"], 3),
    ("asp",  ["index.asp", "default.asp", "login.asp", "home.asp"], 3),
    ("aspx", ["Login.aspx", "Default.aspx", "index.aspx"], 3),
    ("json", ["composer.json", "manifest.json"], 2),
    ("pdf",  ["report.pdf", "brochure.pdf"], 2),
    ("crt",  ["gd_tls_issuing_dv-r1v1.crt"], 1),
    ("perl", ["index.pl"], 1),
    ("py",   ["index.py"], 1),
    ("dat",  ["users.dat"], 1),
    ("bin",  ["inform", "update", "firmware"], 6),
]
_OCSP_HOSTS = ["ocsp.digicert.com", "ocsp.pki.goog", "ocsp.sectigo.com", "ocsp.godaddy.com",
               "ocsp.entrust.net", "r3.o.lencr.org"]


def _file_record(config, tf, sigkey, misc, ts, file_url=None, action="alert"):
    """One PAN-OS file-type THREAT log (documented File Data format: firewall.filedata).

    Header signature slot is the Threat ID. `tf` is the traffic-field dict of the session it
    fired in, so the file log shares its addresses, ports, zones, users, App-ID and session_id.
    """
    tid, tname, ftype = _FILE_SIGS[sigkey]
    f = {k: tf[k] for k in _URL_SHARED_KEYS if tf.get(k) not in (None, "")}
    fmt = str(_get_config(config).get("threat_severity_format", "number")).lower()
    f.update({
        "action":              action,
        "misc":                misc,
        "file_name":           misc,
        # Live CEF File Data rows: threat_id, threat_name and the header signature are all "Name(ID)".
        "threat_id":           f"{tname}({tid})",
        "threat_name":         f"{tname}({tid})",
        "threat_name_firewall": tname,
        "threat_category":     "N/A",
        "direction":           "server-to-client",
        "direction_of_attack": "server to client",
        "severity":            ("Low" if fmt == "word" else str(_SEVERITY_NUM["low"])),
        "vendor_severity":     "Low",
        "count_of_repeats":    1,
        "file_url":            file_url,
        "filetype":            ftype,
        "pcap_id":             0,
    })
    return _format_cef(config, "file", f, log_type="THREAT", severity=_SEVERITY_NUM["low"], ts=ts,
                       fw_type="firewall.filedata", sig=f"{tname}({tid})")


def _file_session(config, src, dst, dpt, app, domain, sigkey, name, *, suser=None, shost=None,
                  from_zone=None, to_zone=None, url_cat=None, path=None, with_url=True,
                  dhost=None, url_host=None):
    """[traffic:end, (url), file] for one cleartext download: all three share one session_id."""
    dur = random.randint(1, 12)
    f = _traffic_fields(config, src, dst, dpt, app, shost=shost, suser=suser, dhost=dhost or domain,
                        from_zone=from_zone, to_zone=to_zone, url_cat=url_cat, duration_s=dur,
                        bytes_sent=random.randint(300, 1500), bytes_received=random.randint(800, 90000))
    end = time.time() - random.uniform(0, 3)
    out = [_format_cef(config, "end", dict(f), ts=end)]
    host = url_host or domain
    path = path or f"/{name}"
    if with_url:
        out.append(_url_record(config, f, host, path=path, category=url_cat, ts=end - dur / 2))
    out.append(_file_record(config, f, sigkey, name, ts=end - dur / 2,
                            file_url=f"{host}{path}"))
    return out


def _sim_file_data_web(config, session_context):
    """A user fetching a file over cleartext HTTP from an Internet web server: the device
    identifies the file type and logs it (alert) next to the URL and traffic logs."""
    src, user, shost = _user_src(config, session_context)
    dests = config.get("benign_egress_destinations") or [{}]
    domain, dst = resolver.benign_target(config, weighted_destination(user, dests))
    sigkey, names, _w = random.choices(_FILE_WEB_NAMES, weights=[w[2] for w in _FILE_WEB_NAMES])[0]
    name = random.choice(names)
    print(f"    - PAN NGFW simulating: file data {_FILE_SIGS[sigkey][1]} {domain} -> {src}")
    return _file_session(config, src, dst, 80, "web-browsing", domain, sigkey, name, suser=user,
                         shost=shost, url_cat=random.choice(_URL_CAT_BENIGN))


def _sim_file_data_internal(config, session_context):
    """A host fetching a file from an internal web application on 8080 / 9080 (intranet
    portals, device description XML, admin pages): the bulk of the live file-type rows."""
    src, user, shost = _user_src(config, session_context)
    servers = [s for s in (config.get("internal_servers") or ["10.0.10.50"]) if s != src] or ["10.0.10.50"]
    dst = random.choice(stable_subset(servers, "panw_ngfw:file_data_internal") or servers)
    sigkey, names, _w = random.choices(_FILE_WEB_NAMES, weights=[w[2] for w in _FILE_WEB_NAMES])[0]
    name = random.choice(names)
    port = random.choices([8080, 9080, 80], weights=[5, 3, 2])[0]
    host = resolver.internal_fqdn(config, dst)
    print(f"    - PAN NGFW simulating: file data (internal) {_FILE_SIGS[sigkey][1]} {dst}:{port} -> {src}")
    return _file_session(config, src, dst, port, "web-browsing", host, sigkey, name, suser=user,
                         shost=shost, from_zone="trust", to_zone="trust", url_cat="private-ip-addresses",
                         url_host=f"{host}:{port}" if port != 80 else host)


def _sim_file_data_ocsp(config, session_context):
    """Certificate validation: the client's OCSP lookup returns a DER X509 certificate blob
    (App-ID ocsp, tcp/80), logged as a file-type identification."""
    src, user, shost = _user_src(config, session_context)
    host = random.choice(_OCSP_HOSTS)
    dst = rare_external_ip()
    print(f"    - PAN NGFW simulating: file data OCSP {host} -> {src}")
    return _file_session(config, src, dst, 80, "ocsp", host, "der", random.choice(["ocsp", "responder", "ocsp"]),
                         suser=user, shost=shost, url_cat="computer-and-internet-info", path="/",
                         with_url=random.random() < 0.5)


# --- Threat-log scenarios (THREAT + the matching traffic log of each session) ---------------
_SCANNER_UA = {
    "nmap_nse": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "openvas":  "Mozilla/5.0 [en] (X11, U; OpenVAS-VT)",
}
_CLIENT_UAS = ["python-requests/2.31.0", "curl/8.4.0", "Go-http-client/1.1",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/129.0.0.0 Safari/537.36"]
_PROBE_PATHS = ["/", "/login", "/api/v1/auth", "/index.jsp", "/admin", "/manager/html", "/actuator/health"]


def _inbound_threat(config, key, app, ports, actions, *, proto="tcp", n=(3, 8), rule="Allow-Inbound-Web",
                    cleartext_web=False, threat_only=False, misc=None):
    """An internet attacker repeatedly tripping signature `key` against a published DMZ server
    (untrust -> dmz). Web exploits ride cleartext HTTP so PAN can see the request (it cannot
    inspect undecrypted TLS), and carry the request path in `misc` and the client User-Agent."""
    attacker = rare_external_ip()
    dst = random.choice(_dmz_servers(config))
    dname = resolver.internal_fqdn(config, dst)
    now = time.time()
    count = random.randint(*n)
    gap = random.randint(8, 25)
    t = now - count * gap
    ua = random.choice(_CLIENT_UAS)
    print(f"    - PAN NGFW simulating: {key} threat {attacker} -> {dst} x{count}")
    out = []
    for _ in range(count):
        t = min(t + gap + random.randint(-3, 3), now)
        out += _threat_session(config, key, attacker, dst, random.choice(ports), app,
                               action=random.choice(actions), end=t, dhost=dname, from_zone="untrust",
                               to_zone="dmz", proto=proto, rule=rule, src_category="unknown",
                               misc=(misc or (random.choice(_PROBE_PATHS) if cleartext_web else None)),
                               user_agent=(ua if cleartext_web else None), threat_only=threat_only)
    return out


def _scanner_threat(config, session_context, key, app, ports, action, *, proto="tcp", end=None,
                    actor=None, target_n=(5, 12), http=False, target=None):
    """An internal host running a vulnerability scanner against internal servers: one session
    per target, each tripping signature `key` (scanner detections alert rather than block)."""
    src, user, shost = actor or _threat_actor(config, session_context)
    servers = [h for h in (config.get("internal_servers") or ["10.0.10.50"]) if h != src]
    targets = [target] if target else random.sample(servers, min(len(servers), random.randint(*target_n)))
    end = end or time.time()
    gap = random.randint(6, 18)
    t = end - len(targets) * gap
    print(f"    - PAN NGFW simulating: {key} scanner {src} -> {len(targets)} servers")
    out = []
    for dst in targets:
        t = min(t + gap, end)
        out += _threat_session(config, key, src, dst, random.choice(ports), app, action=action, end=t,
                               suser=user, shost=shost, dhost=resolver.internal_fqdn(config, dst),
                               proto=proto, misc=(random.choice(_PROBE_PATHS) if http else None),
                               user_agent=(_SCANNER_UA.get(key) if http else None))
    return out


def _sim_threat_log4j_exploit(config, session_context):
    """Critical code-execution signature, blocked: Log4j exploitation attempts on cleartext web."""
    return _inbound_threat(config, "log4j", "web-browsing", [80, 8080], ["drop"] * 4 + ["reset-server"],
                           cleartext_web=True)


def _sim_threat_dnsmasq_exploit(config, session_context):
    """High code-execution signature, dropped: malformed DNS to a published resolver (UDP)."""
    return _inbound_threat(config, "dnsmasq", "dns-base", [53], ["drop"], proto="udp", n=(2, 5),
                           rule="Allow-Inbound-DNS")


def _sim_threat_nmap_nse_scan(config, session_context):
    return _scanner_threat(config, session_context, "nmap_nse", "web-browsing", [80, 8080], "alert", http=True)


def _sim_threat_openvas_scan(config, session_context):
    return _scanner_threat(config, session_context, "openvas", "web-browsing", [80, 8080], "alert", http=True)


def _sim_threat_rpc_portmapper_dump(config, session_context):
    """Portmapper DUMP is reset by the firewall (as in the live feed): session ends 'threat'."""
    return _scanner_threat(config, session_context, "rpc_dump", "portmapper", [111], "reset-server")


def _sim_threat_nfs_export_probe(config, session_context):
    return _scanner_threat(config, session_context, "nfs_export", "nfs", [2049], "alert")


def _sim_threat_rpc_fragmentation_evasion(config, session_context):
    return _scanner_threat(config, session_context, "rpc_frag", "rpc", [111], "alert", target_n=(3, 6))


def _sim_threat_ssh_bruteforce(config, session_context):
    """An internet host guessing SSH credentials against a published server. The first few
    attempts are ordinary short SSH sessions; once the guess count crosses the signature's
    threshold each further session also logs the threat, with the running attempt count in
    count_of_repeats."""
    attacker = rare_external_ip()
    dst = random.choice(_dmz_servers(config))
    dname = resolver.internal_fqdn(config, dst)
    count = random.randint(10, 14)
    now = time.time()
    t = now - count * 12
    print(f"    - PAN NGFW simulating: SSH brute force {attacker} -> {dst} ({count} attempts)")
    out = []
    for i in range(count):
        t = min(t + 12 + random.randint(-3, 3), now)
        if i < 4:
            out.append(_conn(config, attacker, dst, 22, "ssh", action="allow", ts=t, dhost=dname,
                             from_zone="untrust", to_zone="dmz", rule="Allow-Inbound-SSH",
                             bytes_sent=random.randint(1500, 3500), bytes_received=random.randint(1500, 4000),
                             duration_s=random.randint(1, 4), src_category="unknown"))
        else:
            out += _threat_session(config, "ssh_brute", attacker, dst, 22, "ssh", action="alert", end=t,
                                   dhost=dname, from_zone="untrust", to_zone="dmz", rule="Allow-Inbound-SSH",
                                   repeats=i - 3, src_category="unknown")
    return out


def _sim_threat_iax2_dos(config, session_context):
    """Medium IAX2 call-number exhaustion against a published Asterisk-style server: an
    internet host floods UDP/4569 (alert only, the signature's default action) as
    App-ID voip-video, which is what PAN assigns IAX2."""
    return _inbound_threat(config, "iax2_dos", "voip-video", [4569], ["alert"], proto="udp",
                           n=(6, 14), rule="Allow-Inbound-IAX2")


def _sim_threat_bot_backdoor_beacon(config, session_context):
    """High spyware signature, reset-client: an infected internal host's backdoor beacons to a
    rare external host. The first beacon is reset; the malware retries on a timer, so the same
    host/C2 pair repeats a handful of times. App-ID assumed web-browsing (cleartext HTTP)."""
    src, user, shost = _threat_actor(config, session_context)
    dom, dst = _rare_ext(config, f"bot|{user}")
    count = random.randint(3, 6)
    gap = random.randint(45, 90)
    now = time.time()
    t = now - count * gap
    print(f"    - PAN NGFW simulating: Bot backdoor beacon {src} -> {dom} x{count}")
    out = []
    for _ in range(count):
        t = min(t + gap + random.randint(-8, 8), now)
        out += _threat_session(config, "bot_qxx", src, dst, 80, "web-browsing", action="reset-client", end=t,
                               suser=user, shost=shost, dhost=dom, from_zone="trust", to_zone="untrust")
    return out


def _threat_only_outbound(config, session_context, key, dst, dom, dpt, app, action, *, count, gap):
    """Threat logs only (no traffic log): an infected internal host trips signature `key` `count`
    times against one external server, `gap` seconds apart, the last no later than now."""
    src, user, shost = _threat_actor(config, session_context)
    now = time.time()
    t = now - count * gap
    print(f"    - PAN NGFW simulating: {key} threat {src} -> {dom or dst} x{count}")
    out = []
    for _ in range(count):
        t = min(t + gap + random.randint(-5, 5), now)
        out += _threat_session(config, key, src, dst, dpt, app, action=action, end=t, suser=user,
                               shost=shost, dhost=dom, from_zone="trust", to_zone="untrust",
                               threat_only=True)
    return out


def _sim_threat_bot_agobot_backdoor(config, session_context):
    """High spyware signature (Agobot backdoor), reset-both: threat log only. App-ID assumed."""
    dom, dst = _rare_ext(config, f"agobot|{random.random()}")
    return _threat_only_outbound(config, session_context, "bot_agobot", dst, dom, 80, "web-browsing",
                                 "reset-both", count=random.randint(2, 5), gap=random.randint(45, 90))


def _sim_threat_pastebin_c2(config, session_context):
    """Critical spyware signature: C2 that hides in Pastebin traffic, reset-both. Threat log only.
    One of the three signature IDs per event. The destination is the real pastebin.com (a
    well-known site, so the resolver answer is the same everywhere); the App-ID is assumed ssl."""
    key = random.choice(["pastebin_c2_a", "pastebin_c2_b", "pastebin_c2_c"])
    return _threat_only_outbound(config, session_context, key, resolver.answer_for("pastebin.com", config),
                                 "pastebin.com", 443, "ssl", "reset-both", count=random.randint(1, 3),
                                 gap=random.randint(60, 180))


def _sim_threat_default_credentials_http(config, session_context):
    """Informational, alert: an HTTP Basic login with a manufacturer default username/password
    to an internal web admin page. Threat log only; informational severity never reaches the
    alerts table, so this is background-only."""
    src, user, shost = _threat_actor(config, session_context)
    servers = [h for h in (config.get("internal_servers") or ["10.0.10.50"]) if h != src]
    dst = random.choice(servers)
    print(f"    - PAN NGFW simulating: default-credentials HTTP Basic {src} -> {dst}")
    return _threat_session(config, "default_creds", src, dst, random.choice([80, 8080]), "web-browsing",
                           action="alert", end=time.time(), suser=user, shost=shost,
                           dhost=resolver.internal_fqdn(config, dst), threat_only=True)


def _sim_threat_schoolboy_downloader(config, session_context):
    """Critical downloader signature, reset-both: threat logs only. App-ID assumed web-browsing."""
    dom, dst = _rare_ext(config, f"schoolboy|{random.random()}")
    return _threat_only_outbound(config, session_context, "schoolboy", dst, dom, 80, "web-browsing",
                                 "reset-both", count=random.randint(1, 3), gap=random.randint(60, 150))


def _sim_threat_php_rce(config, session_context):
    """Critical PHP RCE (one of three signature IDs), reset-server: an internet attacker's crafted
    HTTP requests to a DMZ web server. Threat logs only."""
    return _php_rce_event(config, random.choice(["php_rce_a", "php_rce_b", "php_rce_c"]))


def _php_rce_event(config, key):
    return _inbound_threat(config, key, "web-browsing", [80, 8080], ["reset-server"], n=(2, 6),
                           cleartext_web=True, threat_only=True)


def _sim_threat_moxa_tn5900_injection(config, session_context):
    """Critical Moxa TN-5900 firmware command injection, reset-server, over cleartext HTTP.
    Threat logs only."""
    return _inbound_threat(config, "moxa_tn5900", "web-browsing", [80, 8080], ["reset-server"], n=(1, 4),
                           cleartext_web=True, threat_only=True)


def _sim_threat_trendnet_tew432brp_injection(config, session_context):
    """Critical TRENDnet TEW-432BRP firmware command injection, reset-server, cleartext HTTP.
    Threat logs only."""
    return _inbound_threat(config, "trendnet_tew432brp", "web-browsing", [80, 8080], ["reset-server"],
                           n=(1, 4), cleartext_web=True, threat_only=True)


def _sim_threat_php_memory_corruption(config, session_context):
    """Critical PHP memory corruption (remote code execution), reset-server, cleartext HTTP.
    Threat logs only."""
    return _inbound_threat(config, "php_memcorrupt", "web-browsing", [80, 8080], ["reset-server"],
                           n=(2, 5), cleartext_web=True, threat_only=True)


# The hand-curated vulnerability signatures (not in the tenant catalogue) each have a dedicated event above.
# This maps a signature key to the generator that fires exactly that signature, for the per-signature
# Vulnerabilities module (modules/panw_ngfw_vulns.py).
_CURATED_SIG_EVENTS = {
    "log4j": _sim_threat_log4j_exploit, "dnsmasq": _sim_threat_dnsmasq_exploit,
    "nmap_nse": _sim_threat_nmap_nse_scan, "openvas": _sim_threat_openvas_scan,
    "rpc_dump": _sim_threat_rpc_portmapper_dump, "nfs_export": _sim_threat_nfs_export_probe,
    "rpc_frag": _sim_threat_rpc_fragmentation_evasion, "ssh_brute": _sim_threat_ssh_bruteforce,
    "iax2_dos": _sim_threat_iax2_dos, "default_creds": _sim_threat_default_credentials_http,
    "php_rce_a": lambda c, s: _php_rce_event(c, "php_rce_a"),
    "php_rce_b": lambda c, s: _php_rce_event(c, "php_rce_b"),
    "php_rce_c": lambda c, s: _php_rce_event(c, "php_rce_c"),
    "moxa_tn5900": _sim_threat_moxa_tn5900_injection,
    "trendnet_tew432brp": _sim_threat_trendnet_tew432brp_injection,
    "php_memcorrupt": _sim_threat_php_memory_corruption,
}


def curated_sig_event(config, session_context, key):
    """Fire the one hand-curated signature `key` (a _THREAT_SIGS key that has a dedicated event)."""
    return _CURATED_SIG_EVENTS[key](config, session_context)


def _tenant_keys(pred):
    return sorted(k for k, (act, app, _m) in _TENANT_PROFILE.items() if pred(_THREAT_SIGS[k], act, app))


_WEB_APPS_EXCLUDED = ("ftp", "tftp", "telnet", "lpd", "smtp-base")
_LEGACY_PORT = {"telnet": 23, "lpd": 515, "smtp-base": 25}
_LEGACY_RULE = {"telnet": "Allow-Inbound-Legacy", "lpd": "Allow-Inbound-Legacy", "smtp-base": "Allow-Inbound-SMTP"}
_TENANT_FAMILIES = {
    "web_rce":    lambda g, a, p: g[3] == "code-execution" and a != "alert" and p not in _WEB_APPS_EXCLUDED and g[4] == "vulnerability",
    "web_leak":   lambda g, a, p: g[3] == "info-leak" and a != "alert" and p not in _WEB_APPS_EXCLUDED,
    "web_detect": lambda g, a, p: a == "alert" and p not in _WEB_APPS_EXCLUDED,
    "web_other":  lambda g, a, p: (g[3] in ("sql-injection", "overflow", "dos", "code-obfuscation", "brute-force",
                                            "insecure-credentials") and a != "alert" and p not in _WEB_APPS_EXCLUDED),
    "legacy":     lambda g, a, p: p in _WEB_APPS_EXCLUDED,
    "spyware":    lambda g, a, p: g[4] == "spyware",
}


def _tenant_family_event(config, family):
    """One internet attacker tripping a tenant-confirmed signature of `family` against a DMZ
    server: the signature's own action, App-ID and $misc as the tenant feed carries them.
    Threat logs only, like the other catalog-driven exploit events."""
    return tenant_sig_event(config, random.choice(_tenant_keys(_TENANT_FAMILIES[family])))


def tenant_sig_event(config, key):
    """One internet attacker tripping the single tenant-confirmed signature `key` ("t<id>") against a
    DMZ server, with the signature's own action, App-ID and $misc. Used by the family events (a random
    key) and by the per-signature Vulnerabilities module (a chosen key). Threat logs only."""
    act, app, misc = _TENANT_PROFILE[key]
    if app == "tftp":
        return _inbound_threat(config, key, app, [69], [act], proto="udp", n=(1, 3),
                               rule="Allow-Inbound-FTP-Legacy", threat_only=True)
    if app == "ftp":
        return _inbound_threat(config, key, app, [21], [act], n=(1, 3),
                               rule="Allow-Inbound-FTP-Legacy", threat_only=True)
    if app in _LEGACY_PORT:
        return _inbound_threat(config, key, app, [_LEGACY_PORT[app]], [act], n=(1, 3),
                               rule=_LEGACY_RULE[app], threat_only=True)
    return _inbound_threat(config, key, app, [80, 8080], [act], n=(1, 4), cleartext_web=True,
                           threat_only=True, misc=misc)


def _sim_threat_web_rce(config, session_context):
    """Code-execution web exploits (115+ signatures, blocked with reset-*): cleartext HTTP."""
    return _tenant_family_event(config, "web_rce")


def _sim_threat_web_infoleak(config, session_context):
    """Information-disclosure / traversal / auth-bypass signatures, blocked (reset-server)."""
    return _tenant_family_event(config, "web_leak")


def _sim_threat_web_detect_only(config, session_context):
    """Signatures the policy only alerts on (XSS, /etc/passwd, directory traversal requests, ...)."""
    return _tenant_family_event(config, "web_detect")


def _sim_threat_web_sqli_overflow_dos(config, session_context):
    """SQL injection, buffer overflow, DoS and other categories, blocked."""
    return _tenant_family_event(config, "web_other")


def _sim_threat_legacy_service_exploit(config, session_context):
    """FTP / TFTP / telnet / LPD / SMTP service exploits (buffer overflow, directory traversal)."""
    return _tenant_family_event(config, "legacy")


def _sim_threat_wd_mycloud_backdoor(config, session_context):
    """Spyware-subtype signature (Western Digital My Cloud Backdoor), reset-server, cleartext HTTP."""
    return _tenant_family_event(config, "spyware")


def _sim_threat_scanner_campaign(config, session_context):
    """One internal host works through a whole recon sequence within the hour: a port scan,
    failed connections, then scanner-signature hits (Nmap NSE, OpenVAS, portmapper) on the
    same server. The firewall's own threat alerts plus the XDR analytics on the traffic land on
    one host, the shape XSIAM rolls up into "Multiple network-related alerts produced by
    different detectors on the same host" (case 68482's insight)."""
    actor = _threat_actor(config, session_context)
    src, user, shost = actor
    servers = [h for h in (config.get("internal_servers") or ["10.0.10.50"]) if h != src]
    target = random.choice(servers)
    now = time.time()
    print(f"    - PAN NGFW simulating: scanner campaign on {src}")
    out = _scan_burst(config, src, user, shost,
                      random.sample(_PRIV_PORTS, min(len(_PRIV_PORTS), random.randint(20, 24))),
                      end=now - 45 * 60, target=target)
    out += _failed_burst(config, src, user, shost, end=now - 25 * 60)
    out += _scanner_threat(config, session_context, "nmap_nse", "web-browsing", [80, 8080], "alert",
                           actor=actor, end=now - 12 * 60, http=True, target=target)
    out += _scanner_threat(config, session_context, "openvas", "web-browsing", [80, 8080], "alert",
                           actor=actor, end=now - 6 * 60, http=True, target=target)
    out += _scanner_threat(config, session_context, "rpc_dump", "portmapper", [111], "reset-server",
                           actor=actor, end=now - 60, target=target)
    return out


_THREAT_DISPATCH = {
    "port_scan": _sim_port_scan, "port_sweep": _sim_port_sweep,
    "failed_connections": _sim_failed_connections,
    "large_upload_https": _sim_large_upload_https,
    "large_upload_https_nonstd": _sim_large_upload_https_nonstd,
    "large_upload_smtp": _sim_large_upload_smtp, "large_upload_ftp": _sim_large_upload_ftp,
    "large_upload_generic": _sim_large_upload_generic,
    "large_upload_generic_popular_target": _sim_large_upload_generic_popular_target,
    "rare_rdp": _sim_rare_rdp, "abnormal_rdp_rare_host": _sim_abnormal_rdp_rare_host,
    "rdp_unmanaged": _sim_rdp_unmanaged, "rdp_unmanaged_dense_subnet": _sim_rdp_unmanaged_dense_subnet,
    "rare_smb": _sim_rare_smb, "smb_from_dc": _sim_smb_from_dc,
    "dcsync_non_dc": _sim_dcsync_non_dc, "rare_smtp": _sim_rare_smtp, "spam_bot": _sim_spam_bot,
    "uncommon_ssh": _sim_uncommon_ssh, "unusual_ssh": _sim_unusual_ssh, "ssh_proxy": _sim_ssh_proxy,
    "rare_ssh_external": _sim_rare_ssh_external, "recurring_rare_ip": _sim_recurring_rare_ip,
    "recurring_rare_domain": _sim_recurring_rare_domain, "rare_domain_comm": _sim_rare_domain_comm,
    "rare_domain_less_common_port": _sim_rare_domain_less_common_port,
    "rare_domain_suspicious_as": _sim_rare_domain_suspicious_as,
    "ddns_access": _sim_ddns_access, "crypto_miner": _sim_crypto_miner, "torrent": _sim_torrent,
    "p2p_upload": lambda c, s: _sim_p2p(c, s, True), "p2p_download": lambda c, s: _sim_p2p(c, s, False),
    "ipfs": _sim_ipfs, "rare_appid": _sim_rare_appid, "new_ftp_server": _sim_new_ftp_server,
    "new_admin_behavior": _sim_new_admin_behavior, "dormant_host_conn": _sim_dormant_host_conn,
    "kerberos_preauth_pattern": _sim_kerberos_preauth_pattern, "ntlm_relay_pattern": _sim_ntlm_relay_pattern,
    "dns_tunnel_pattern": _sim_dns_tunnel_pattern, "ldap_recon": _sim_ldap_recon,
    "tor_connection": _sim_tor_connection, "server_outbound_http": _sim_server_outbound_http,
    "dns_c2_beacon": _sim_dns_c2_beacon, "smb_new_host_lateral": _sim_smb_new_host_lateral,
    "smb_rare_file_transfer": _sim_smb_rare_file_transfer, "smb_share_enumeration": _sim_smb_share_enumeration,
    "rare_external_rdp": _sim_rare_external_rdp, "large_download": _sim_large_download,
    "dos_anomaly": _sim_dos_anomaly, "external_port_scan": _sim_external_port_scan,
    "snmp_unexpected_source": _sim_snmp_unexpected_source,
    "file_data_web": _sim_file_data_web, "file_data_internal": _sim_file_data_internal,
    "file_data_ocsp": _sim_file_data_ocsp,
    "port_scan_aggressive": _sim_port_scan_aggressive, "ipfs_peering": _sim_ipfs_peering,
    "rare_domain_attack_port": _sim_rare_domain_attack_port,
    "recurring_rare_domain_attack_port": _sim_recurring_rare_domain_attack_port,
    "dormant_host_known_source": _sim_dormant_host_known_source,
    "large_upload_generic_small": _sim_large_upload_generic_small,
    "new_ssh_admin_behavior": lambda c, s: _sim_new_admin_behavior(c, s, ssh_only=True),
    "new_ftp_server_external": _sim_new_ftp_server_external,
    "new_ftp_server_port_scan": _sim_new_ftp_server_port_scan,
    "dcsync_internet_facing": _sim_dcsync_internet_facing, "dcsync_large": _sim_dcsync_large,
    "rare_appid_internet_facing": _sim_rare_appid_internet_facing,
    "spam_bot_failed": _sim_spam_bot_failed, "ssh_suspicious_nonstd": _sim_ssh_suspicious_nonstd,
    "ssh_high_volume": _sim_ssh_high_volume, "host_attack_chain": _sim_host_attack_chain,
    "ssh_proxy_high_volume": _sim_ssh_proxy_high_volume,
    "uncommon_ssh_rare_internal": _sim_uncommon_ssh_rare_internal,
    "uncommon_ssh_nonstd_port": _sim_uncommon_ssh_nonstd_port,
    "uncommon_ssh_internal": _sim_uncommon_ssh_internal,
    "unusual_ssh_external": _sim_unusual_ssh_external,
    "ssh_proxy_suspicious": _sim_ssh_proxy_suspicious, "ssh_proxy_detected": _sim_ssh_proxy_detected,
    "dcsync_non_dc_appid": _sim_dcsync_non_dc_appid, "dcsync_large_appid": _sim_dcsync_large_appid,
    "recurring_rare_domain_suspicious_as": _sim_recurring_rare_domain_suspicious_as,
    "recurring_rare_domain_abnormal_suffix": _sim_recurring_rare_domain_abnormal_suffix,
    "threat_log4j_exploit": _sim_threat_log4j_exploit, "threat_dnsmasq_exploit": _sim_threat_dnsmasq_exploit,
    "threat_nmap_nse_scan": _sim_threat_nmap_nse_scan, "threat_openvas_scan": _sim_threat_openvas_scan,
    "threat_rpc_portmapper_dump": _sim_threat_rpc_portmapper_dump,
    "threat_nfs_export_probe": _sim_threat_nfs_export_probe,
    "threat_rpc_fragmentation_evasion": _sim_threat_rpc_fragmentation_evasion,
    "threat_ssh_bruteforce": _sim_threat_ssh_bruteforce,
    "threat_bot_agobot_backdoor": _sim_threat_bot_agobot_backdoor, "threat_pastebin_c2": _sim_threat_pastebin_c2,
    "threat_default_credentials_http": _sim_threat_default_credentials_http,
    "threat_schoolboy_downloader": _sim_threat_schoolboy_downloader, "threat_php_rce": _sim_threat_php_rce,
    "threat_moxa_tn5900_injection": _sim_threat_moxa_tn5900_injection,
    "threat_trendnet_tew432brp_injection": _sim_threat_trendnet_tew432brp_injection,
    "threat_php_memory_corruption": _sim_threat_php_memory_corruption,
    "threat_web_rce": _sim_threat_web_rce, "threat_web_infoleak": _sim_threat_web_infoleak,
    "threat_web_detect_only": _sim_threat_web_detect_only,
    "threat_web_sqli_overflow_dos": _sim_threat_web_sqli_overflow_dos,
    "threat_legacy_service_exploit": _sim_threat_legacy_service_exploit,
    "threat_wd_mycloud_backdoor": _sim_threat_wd_mycloud_backdoor,
    "threat_iax2_dos": _sim_threat_iax2_dos, "threat_bot_backdoor_beacon": _sim_threat_bot_backdoor_beacon, "threat_scanner_campaign": _sim_threat_scanner_campaign,
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
