# modules/zscaler.py
# Simulates Zscaler NSS feed logs in CEF format for web proxy, cloud firewall,
# DLP, sandbox, and network threat detection events for XSIAM Broker VM.

import random
import time
from datetime import datetime, timezone
from ipaddress import ip_network
import hashlib
try:
    from modules.session_utils import get_random_user, get_user_by_name, get_zscaler_device_info, rand_ip_from_network
except ImportError:
    from session_utils import get_random_user, get_user_by_name, get_zscaler_device_info, rand_ip_from_network

def _cef_escape(value):
    """Escape CEF extension values per the CEF spec (backslash, equals, newlines)."""
    s = str(value)
    s = s.replace('\\', '\\\\')
    s = s.replace('=', '\\=')
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    return s


NAME = "Zscaler Web Gateway"
DESCRIPTION = (
    "Simulates Zscaler NSS feed CEF events: web proxy, cloud firewall, DLP, sandbox, "
    "port scan, brute force, DNS C2, TOR, lateral movement, and data exfiltration."
)
XSIAM_PARSER = "zscaler"
CONFIG_KEY = "zscaler_config"

last_threat_event_time = 0

# Realistic external IP first octets — same list used by all other modules
_EXT_FIRST_OCTETS = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 194, 212, 213]


def _random_external_ip():
    """Return a realistic-looking random external IP."""
    return f"{random.choice(_EXT_FIRST_OCTETS)}.{random.randint(0,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _get_threat_interval(threat_level, config):
    levels = config.get('threat_generation_levels', {})
    return levels.get(threat_level, 7200)


def _get_random_internal_ip(config):
    """Pick a random host IP from internal_networks."""
    nets = config.get('internal_networks', ['192.168.1.0/24'])
    net_str = random.choice(nets)
    try:
        return rand_ip_from_network(ip_network(net_str, strict=False))
    except Exception:
        return "192.168.1.100"


def _get_threat_destination(config):
    """Returns a TOR exit node (50%) or suspicious IP from config (50%)."""
    if random.random() < 0.5:
        tor_nodes = config.get('tor_exit_nodes', [])
        if tor_nodes:
            return random.choice(tor_nodes)
    dests = config.get('zscaler_config', {}).get('firewall_threat_destinations', [])
    if dests:
        return random.choice(dests)
    return {"ip": _random_external_ip(), "country": "Unknown", "category": "Suspicious Destination"}


def _get_user_and_device_info(config, user_override=None, session_context=None):
    """
    Gets a random user and their associated device info.
    Prefers session_context; falls back to static config maps.
    Returns (username, department, ip, device_info_dict).
    """
    if session_context:
        if user_override:
            user_info = get_user_by_name(session_context, user_override)
        else:
            user_info = get_random_user(session_context, preferred_device_type='workstation')
        if user_info:
            device_info = get_zscaler_device_info(user_info)
            return user_info['username'], user_info.get('department', 'Unknown'), user_info['ip'], device_info

    # Legacy static-map fallback
    zscaler_conf = config.get(CONFIG_KEY, {})
    user_ip_map = zscaler_conf.get('user_ip_map', {})
    zscaler_users = zscaler_conf.get('users', {})
    zscaler_device_map = zscaler_conf.get('device_map', {})
    if not user_ip_map:
        return ("unknown_user", "Unknown", _get_random_internal_ip(config),
                {"hostname": "unknown-host", "owner": "unknown_owner",
                 "os_type": "Windows", "os_version": "11"})
    user = (user_override if user_override and user_override in user_ip_map
            else random.choice(list(user_ip_map.keys())))
    ip = user_ip_map.get(user) or _get_random_internal_ip(config)
    dept = zscaler_users.get(user, "Unknown")
    d = zscaler_device_map.get(user, {})
    device_info = {
        "hostname":   d.get('hostname',   f"{user}-desktop"),
        "owner":      d.get('owner',      user),
        "os_type":    d.get('os_type',    'Windows'),
        "os_version": d.get('os_version', '11'),
    }
    return user, dept, ip, device_info


# ---------------------------------------------------------------------------
# BENIGN WEB GENERATORS
# ---------------------------------------------------------------------------

def _generate_benign_web_traffic(config, user, dept, internal_host_ip, device_info):
    """Allowed outbound web browsing (nssweblog)."""
    zscaler_conf = config.get('zscaler_config', {})
    _default_dest = [{"ip_range": "8.8.8.0/24", "name": "google.com",
                      "ports": [443], "service_types": ["HTTPS"], "country": "US"}]
    destination = random.choice(zscaler_conf.get('benign_egress_destinations', _default_dest))
    dest_ip_range = destination.get("ip_range", "8.8.8.0/24")
    if dest_ip_range.endswith("/32"):
        dest_ip = dest_ip_range[:-3]
    else:
        try:
            dest_ip = rand_ip_from_network(ip_network(dest_ip_range, strict=False))
        except Exception:
            dest_ip = "8.8.8.1"
    domain = destination.get("name", "example.com").replace(" ", "").lower()
    app_details = random.choice(zscaler_conf.get('app_details', [{"name": "General Browsing", "class": "Web"}]))
    fields = {
        "action": "Allow",
        "urlcat":     random.choice(zscaler_conf.get('benign_url_categories', ["Technology"])),
        "urlsupercat":random.choice(zscaler_conf.get('url_super_categories', ["Technology"])),
        "urlclass":   "Business and Productivity",
        "riskscore":  str(random.randint(1, 20)),
        "responsecode": "200", "reason": "Allowed", "reqmethod": "GET",
        "useragent":  random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "appname":    app_details.get('name'), "appclass": app_details.get('class'),
        "contenttype": "text/html",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl": f"https://www.{domain}/", "ehost": domain,
        "cip": internal_host_ip, "sip": dest_ip, "proto": "HTTPS",
        "bytesin": random.randint(5000, 50000), "bytesout": random.randint(500, 5000),
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "2",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


# ---------------------------------------------------------------------------
# BENIGN FIREWALL GENERATORS
# ---------------------------------------------------------------------------

def _generate_benign_firewall_traffic(config, user, dept, internal_host_ip, device_info):
    """Allowed outbound TCP connection — normal workstation traffic (nssfwlog)."""
    zscaler_conf = config.get('zscaler_config', {})
    _default_dest = [{"ip_range": "8.8.8.0/24", "name": "google.com",
                      "ports": [443], "service_types": ["HTTPS"], "country": "United States"}]
    destination = random.choice(zscaler_conf.get('benign_egress_destinations', _default_dest))
    dest_ip_range = destination.get("ip_range", "8.8.8.0/24")
    if dest_ip_range.endswith("/32"):
        dest_ip = dest_ip_range[:-3]
    else:
        try:
            dest_ip = rand_ip_from_network(ip_network(dest_ip_range, strict=False))
        except Exception:
            dest_ip = "8.8.8.1"
    fields = {
        "srcip": internal_host_ip, "sport": random.randint(49152, 65535),
        "destip": dest_ip, "destport": random.choice(destination.get("ports", [443])),
        "proto": "6",
        "action": "Allow", "rulelabel": "Allow_Web_Outbound", "reason": "Allowed",
        "threatcat": None, "threatname": None,
        "destCountry": destination.get("country", "United States"),
        "srcCountry": "United States",
        "bytesin": random.randint(5000, 50000), "bytesout": random.randint(500, 5000),
        "nwsvc": random.choice(destination.get("service_types", ["Web Browsing"])).replace(" ", ""),
        "spriv": "domain users", "duration_ms": random.randint(100, 300000), "cefSeverity": "3",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "destinationTranslatedAddress": dest_ip,
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssfwlog')


def _generate_benign_dns_query(config, user, dept, internal_host_ip, device_info):
    """Benign outbound DNS query (UDP/53) to a public resolver (nssfwlog).

    Matches the dns_query benign event type present in Checkpoint, Firepower,
    FortiGate, and Cisco ASA modules for baseline DNS traffic fidelity.
    """
    zscaler_conf = config.get('zscaler_config', {})
    dns_resolvers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"]
    resolver = random.choice(dns_resolvers)
    fields = {
        "srcip": internal_host_ip, "sport": random.randint(49152, 65535),
        "destip": resolver, "destport": 53,
        "proto": "17",  # UDP
        "action": "Allow", "rulelabel": "Allow_DNS_Outbound", "reason": "Allowed",
        "threatcat": None, "threatname": None, "destCountry": "United States",
        "srcCountry": "United States",
        "bytesin": random.randint(64, 512), "bytesout": random.randint(32, 128),
        "nwsvc": "DNS", "spriv": "domain users",
        "duration_ms": random.randint(1, 500), "cefSeverity": "1",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "destinationTranslatedAddress": resolver,
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssfwlog')


def _generate_benign_inbound_block(config, user, dept, internal_host_ip, device_info):
    """External probe reaching an internal resource, blocked at perimeter (nssfwlog).

    Simulates reconnaissance or unsolicited inbound connection attempts blocked by
    Zscaler's cloud firewall — matches the inbound_block benign pattern in ASA,
    Checkpoint, Firepower, and FortiGate modules.
    """
    zscaler_conf = config.get('zscaler_config', {})
    attacker_ip = _random_external_ip()
    internal_targets = config.get('internal_servers', []) or [internal_host_ip]
    target_ip = random.choice(internal_targets)
    probe_cfg = [
        (80,   "HTTP"), (443, "HTTPS"), (22,   "SSH"),  (3389, "RDP"),
        (8080, "HTTP"), (445, "SMB"),   (25,   "SMTP"), (3306, "MySQL"),
    ]
    target_port, nwsvc = random.choice(probe_cfg)
    fields = {
        "srcip": attacker_ip, "sport": random.randint(1024, 65535),
        "destip": target_ip, "destport": target_port,
        "proto": "6",
        "action": "Block", "rulelabel": "Block_Inbound_Probe", "reason": "Policy Block",
        "threatcat": "Network Scan", "threatname": "InboundProbe",
        "destCountry": "United States",
        "srcCountry": random.choice(_THREAT_COUNTRIES),
        "bytesin": 0, "bytesout": random.randint(40, 100),
        "nwsvc": nwsvc, "spriv": "N/A", "duration_ms": 0, "cefSeverity": "4",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "sourceTranslatedAddress": attacker_ip,
        "destinationTranslatedAddress": target_ip,
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssfwlog')


def _generate_benign_saas_upload(config, user, dept, internal_host_ip, device_info):
    """Cloud storage / SaaS sync upload — PUT/POST with large bytesOut (nssweblog).

    Simulates OneDrive, Box, or Dropbox sync traffic where the client pushes data
    to a cloud storage endpoint.  bytesOut is intentionally large (client-to-server)
    while bytesIn is small (server acknowledgement).
    """
    zscaler_conf = config.get('zscaler_config', {})
    saas_destinations = [
        ("onedrive.live.com",    "40.99.0.0/16",  "Cloud Storage"),
        ("d.docs.live.net",      "40.99.0.0/16",  "Cloud Storage"),
        ("content.dropboxapi.com","162.125.0.0/16","Cloud Storage"),
        ("upload.box.com",       "74.112.186.0/24","Cloud Storage"),
        ("www.googleapis.com",   "142.250.0.0/15", "Cloud Storage"),
        ("sharepoint.com",       "40.96.0.0/13",  "Office 365"),
    ]
    dest_name, dest_cidr, url_cat = random.choice(saas_destinations)
    try:
        dest_ip = rand_ip_from_network(ip_network(dest_cidr, strict=False))
    except Exception:
        dest_ip = "40.99.1.1"
    method = random.choice(["PUT", "POST"])
    fields = {
        "action": "Allow",
        "urlcat":      url_cat,
        "urlsupercat": "Technology",
        "urlclass":    "Business and Productivity",
        "riskscore":   str(random.randint(1, 15)),
        "responsecode": random.choice(["200", "201", "204"]),
        "reason":      "Allowed",
        "reqmethod":   method,
        "useragent":   random.choice(config.get('user_agents', ["Microsoft OneDrive/22.0"])),
        "appname":     "Cloud Storage",
        "appclass":    "Web",
        "contenttype": "application/octet-stream",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"https://{dest_name}/upload",
        "ehost": dest_name,
        "cip":   internal_host_ip,
        "sip":   dest_ip,
        "proto": "HTTPS",
        # bytesout = client→server (large: uploading files); bytesin = server→client (small: ACK)
        "bytesout": random.randint(500_000, 50_000_000),
        "bytesin":  random.randint(200, 2_000),
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "2",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


def _generate_benign_software_update(config, user, dept, internal_host_ip, device_info):
    """Software update download — Windows Update, antivirus definitions, or OS patches (nssweblog).

    Very large bytesIn (server→client) with small bytesOut. Low risk score.
    Represents routine patch management traffic seen on every corporate network.
    """
    zscaler_conf = config.get('zscaler_config', {})
    update_sources = [
        ("windowsupdate.com",        "13.107.4.0/24",   "Computer and Internet Info"),
        ("download.windowsupdate.com","13.107.4.0/24",   "Computer and Internet Info"),
        ("update.microsoft.com",     "40.76.0.0/14",    "Computer and Internet Info"),
        ("download.microsoft.com",   "23.102.0.0/18",   "Computer and Internet Info"),
        ("definitions.avast.com",    "185.8.54.0/24",   "Computer and Internet Info"),
        ("content.symantec.com",     "198.188.200.0/22","Computer and Internet Info"),
        ("update.nai.com",           "161.69.0.0/16",   "Computer and Internet Info"),
    ]
    dest_name, dest_cidr, url_cat = random.choice(update_sources)
    try:
        dest_ip = rand_ip_from_network(ip_network(dest_cidr, strict=False))
    except Exception:
        dest_ip = "13.107.4.1"
    fields = {
        "action": "Allow",
        "urlcat":      url_cat,
        "urlsupercat": "Technology",
        "urlclass":    "Business and Productivity",
        "riskscore":   str(random.randint(1, 10)),
        "responsecode": "200",
        "reason":      "Allowed",
        "reqmethod":   "GET",
        "useragent":   "Microsoft-CryptoAPI/10.0",
        "appname":     "Windows Update",
        "appclass":    "Software Updates",
        "contenttype": "application/octet-stream",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"https://{dest_name}/update",
        "ehost": dest_name,
        "cip":   internal_host_ip,
        "sip":   dest_ip,
        "proto": "HTTPS",
        # bytesin = client←server (large: downloading patch); bytesout = client→server (small: request)
        "bytesin":  random.randint(5_000_000, 200_000_000),
        "bytesout": random.randint(300, 2_000),
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "1",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


def _generate_benign_video_streaming(config, user, dept, internal_host_ip, device_info):
    """Video streaming — YouTube, Teams video, Webex, or Zoom (nssweblog).

    Characterised by very large bytesIn (sustained video download) and a streaming
    content-type.  Represents training, meetings, and conference calls during business
    hours — a dominant traffic type in modern corporate environments.
    """
    zscaler_conf = config.get('zscaler_config', {})
    streaming_destinations = [
        ("googlevideo.com",      "216.58.0.0/17",   "Streaming Media",     "video/webm"),
        ("youtube.com",          "216.58.192.0/19", "Streaming Media",     "video/mp4"),
        ("teams.microsoft.com",  "52.112.0.0/14",   "Web Conferencing",    "application/octet-stream"),
        ("webex.com",            "170.133.128.0/18","Web Conferencing",    "application/octet-stream"),
        ("zoom.us",              "170.114.0.0/16",  "Web Conferencing",    "application/octet-stream"),
        ("nflxvideo.net",        "45.57.0.0/17",    "Streaming Media",     "video/mp4"),
    ]
    dest_name, dest_cidr, url_cat, content_type = random.choice(streaming_destinations)
    try:
        dest_ip = rand_ip_from_network(ip_network(dest_cidr, strict=False))
    except Exception:
        dest_ip = "216.58.1.1"
    fields = {
        "action": "Allow",
        "urlcat":      url_cat,
        "urlsupercat": "Entertainment",
        "urlclass":    "Business and Productivity",
        "riskscore":   str(random.randint(1, 20)),
        "responsecode": "200",
        "reason":      "Allowed",
        "reqmethod":   "GET",
        "useragent":   random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "appname":     url_cat,
        "appclass":    "Web",
        "contenttype": content_type,
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"https://www.{dest_name}/",
        "ehost": dest_name,
        "cip":   internal_host_ip,
        "sip":   dest_ip,
        "proto": "HTTPS",
        # bytesin = sustained video stream (very large); bytesout = small client requests
        "bytesin":  random.randint(10_000_000, 500_000_000),
        "bytesout": random.randint(1_000, 10_000),
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "2",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


# ---------------------------------------------------------------------------
# THREAT WEB GENERATORS
# ---------------------------------------------------------------------------

def _generate_threat_web_traffic(config, user, dept, internal_host_ip, device_info):
    """Blocked malicious web traffic — malware download or C2 callback (nssweblog)."""
    zscaler_conf = config.get('zscaler_config', {})
    web_threats = zscaler_conf.get('web_threats', {})
    if not web_threats:
        return None
    threat_name, details = random.choice(list(web_threats.items()))
    malware_details = random.choice(zscaler_conf.get('malware_details', [{"class": "Trojan", "type": "Generic"}]))
    filename = details.get('filename', f"payload_{random.randint(100, 999)}.exe")
    filetype  = details.get('filetype', "Windows Executable")
    fields = {
        "action": "Block",
        "urlcat": details.get('category', "Malware"), "urlsupercat": "Security",
        "urlclass": "Malicious Content",
        "riskscore": str(random.randint(75, 100)),
        "responsecode": "403", "reason": "Policy Block",
        "malwarecat": details.get('category', "Malware"), "threatname": threat_name,
        "threatscore": str(random.randint(75, 100)),
        "malwareclass": malware_details.get('class'), "malwaretype": malware_details.get('type'),
        "reqmethod": "GET",
        "useragent": random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"http://{details.get('domain', 'malware.example.com')}/{filename}",
        "ehost": details.get('domain', 'malware.example.com'),
        "cip": internal_host_ip, "sip": _random_external_ip(),
        "proto": "HTTP", "bytesin": 0, "bytesout": 60,
        "filename": filename, "filetype": filetype,
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "8",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


def _generate_data_exfil_web_traffic(config, user, dept, internal_host_ip, device_info):
    """Large file upload to cloud storage — data exfiltration (nssweblog, ALLOWED).

    The event is ALLOWED because Zscaler hasn't blocked it (DLP may not be
    tuned for this destination or file type). The 5-100 MB upload is the signal.
    """
    zscaler_conf = config.get('zscaler_config', {})
    _default_exfil = [{"url": "https://drive.google.com/upload", "domain": "drive.google.com"}]
    exfil_dest = random.choice(zscaler_conf.get('exfil_destinations', _default_exfil))
    file_size_bytes = random.randint(5_242_880, 104_857_600)  # 5MB–100MB
    fields = {
        "action": "Allow",
        "urlcat": "Online Storage", "urlsupercat": "Productivity and Collaboration",
        "responsecode": "201", "reason": "Allowed", "reqmethod": "POST",
        "useragent": random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "appname": "File Transfer", "appclass": "General", "contenttype": "application/zip",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl": exfil_dest.get('url'), "ehost": exfil_dest.get('domain'),
        "cip": internal_host_ip, "sip": f"104.18.30.{random.randint(1, 254)}", "proto": "HTTPS",
        "bytesin": random.randint(100, 500), "bytesout": file_size_bytes,
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "7",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


def _generate_dlp_web_traffic(config, user, dept, internal_host_ip, device_info):
    """DLP engine triggers block on sensitive data upload (nssweblog)."""
    zscaler_conf = config.get('zscaler_config', {})
    dlp_conf   = zscaler_conf.get('dlp_engines_and_rules', {})
    engines    = dlp_conf.get('engines', [])
    if not engines:
        return None
    engine     = random.choice(engines)
    dicts      = dlp_conf.get('dictionaries', {}).get(engine, [])
    if not dicts:
        return None
    dictionary = random.choice(dicts)
    rule       = random.choice(dlp_conf.get('rules', ["DLP-Default-Rule"]))
    _default_exfil = [{"url": "https://drive.google.com/upload", "domain": "drive.google.com"}]
    exfil_dest = random.choice(zscaler_conf.get('exfil_destinations', _default_exfil))
    fields = {
        "action": "Block",
        "urlcat": "Online Storage", "urlsupercat": "Productivity and Collaboration",
        "responsecode": "403", "reason": "DLP Block", "reqmethod": "POST",
        "useragent": random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "contenttype": "application/zip",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl": exfil_dest.get('url'), "ehost": exfil_dest.get('domain'),
        "cip": internal_host_ip, "sip": f"104.18.30.{random.randint(1, 254)}", "proto": "HTTPS",
        "bytesin": random.randint(100, 500), "bytesout": random.randint(1000, 50000),
        "dlpengine": engine, "dlpdictionary": dictionary, "dlprule": rule,
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "6", "event_type": "dlp",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


def _generate_cloud_app_control_event(config, user, dept, internal_host_ip, device_info):
    """Cloud Application Control enforcement — block or caution (nssweblog)."""
    zscaler_conf = config.get('zscaler_config', {})
    policy = zscaler_conf.get('cloud_app_control_policy', [])
    if not policy:
        return None
    app     = random.choice(policy)
    blocked = app.get('action') == "Block"
    fields = {
        "action": app.get('action', "Block"),
        "urlcat": "Information Technology", "urlsupercat": "Information Technology",
        "responsecode": "403" if blocked else "200",
        "reason": f"Cloud App Control: {app.get('name', 'Unknown App')}",
        "reqmethod": "GET", "appname": app.get('name'), "appclass": app.get('class'),
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"https://{app.get('name', 'app').lower()}.com",
        "ehost": f"{app.get('name', 'app').lower()}.com",
        "cip": internal_host_ip, "sip": f"104.20.10.{random.randint(1, 254)}", "proto": "HTTPS",
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "5" if blocked else "2",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


def _generate_sandbox_event(config, user, dept, internal_host_ip, device_info):
    """File blocked after sandbox detonation — definitive malware verdict (nssweblog)."""
    zscaler_conf = config.get('zscaler_config', {})
    threats = zscaler_conf.get('sandbox_threats', [])
    if not threats:
        return None
    threat    = random.choice(threats)
    filename  = f"document_{random.randint(1000, 9999)}.{threat.get('type', 'exe').lower()}"
    file_hash = hashlib.md5(f"{filename}{time.time()}".encode()).hexdigest()
    fields = {
        "action": "Block",
        "urlcat": "Malicious Content", "urlsupercat": "Security",
        "urlclass": "Malicious Content",
        "riskscore": "100",
        "responsecode": "403", "reason": "Sandbox Verdict",
        "malwarecat": threat.get('category', "Malware"), "threatname": threat.get('name', "Unknown"),
        "threatscore": "100", "malwareclass": "Sandbox", "malwaretype": threat.get('type', "exe"),
        "fileHash": file_hash, "filename": filename, "filetype": threat.get('type', "exe"),
        "reqmethod": "GET",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"http://download.unsafe-storage.com/{filename}",
        "ehost": "download.unsafe-storage.com",
        "cip": internal_host_ip, "sip": _random_external_ip(),
        "proto": "HTTP", "bytesin": 0, "bytesout": 60,
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "10", "event_type": "sandbox",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


# ---------------------------------------------------------------------------
# FIREWALL EVENT HELPER — shared by all nssfwlog generators
# ---------------------------------------------------------------------------

def _is_internal_ip(ip):
    """Return True if the IP string looks like a private/internal address."""
    return (ip.startswith("10.") or ip.startswith("192.168.") or
            ip.startswith("172.16.") or ip.startswith("172.17.") or
            ip.startswith("172.18.") or ip.startswith("172.19.") or
            any(ip.startswith(f"172.{x}.") for x in range(16, 32)))

_THREAT_COUNTRIES = ["Russia", "China", "Iran", "North Korea", "Romania", "Ukraine"]


def _fw_event(config, user, dept, device_info, src_ip, dst_ip, dst_port, proto,
              action, rule, nwsvc, threat_cat, threat_name, dest_country, sev,
              bytes_in=0, bytes_out=60):
    """Build a single nssfwlog CEF event — used by all firewall scenario generators."""
    zscaler_conf = config.get('zscaler_config', {})
    src_country = "United States" if _is_internal_ip(src_ip) else random.choice(_THREAT_COUNTRIES)
    return _format_nss_log_as_cef({
        "srcip": src_ip, "sport": random.randint(49152, 65535),
        "destip": dst_ip, "destport": dst_port, "proto": proto,
        "action": action, "rulelabel": rule,
        "reason": "Policy Block" if action == "Block" else "Allowed",
        "threatcat": threat_cat, "threatname": threat_name,
        "destCountry": dest_country,
        "srcCountry": src_country,
        "bytesin": bytes_in, "bytesout": bytes_out,
        "nwsvc": nwsvc, "spriv": "domain users",
        "duration_ms": random.randint(100, 300000), "cefSeverity": sev,
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "destinationTranslatedAddress": dst_ip,
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
    }, user, dept, 'nssfwlog')


# ---------------------------------------------------------------------------
# THREAT FIREWALL GENERATORS — single-event
# ---------------------------------------------------------------------------

def _generate_threat_firewall_traffic(config, user, dept, internal_host_ip, device_info):
    """Outbound connection to a suspicious or TOR destination, blocked (nssfwlog)."""
    print("    - Zscaler Module simulating: Threat Firewall (outbound to suspicious IP)")
    threat_dest = _get_threat_destination(config)
    dest_ip     = threat_dest.get("ip") or _random_external_ip()
    tor_ips     = {n.get("ip") for n in config.get('tor_exit_nodes', [])}
    threat_name = "TOR Exit Node" if dest_ip in tor_ips else "SuspiciousIP"
    r = random.random()
    if r < 0.01:
        dest_port, nwsvc = 3389, "RDP"
    elif r < 0.02:
        dest_port, nwsvc = 22, "SSH"
    else:
        dest_port, nwsvc = 443, "HTTPS"
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, dest_ip, dest_port, "6",
                     "Block", "Block_HighRisk_Geo", nwsvc,
                     threat_dest.get('category', 'Suspicious'), threat_name,
                     threat_dest.get('country', 'Unknown'), "7")


def _generate_tor_connection(config, user, dept, internal_host_ip, device_info):
    """Outbound connection to a known TOR exit node (nssfwlog, Block).

    Port distribution: 443 (60%), 9001 (30%), 9030 (10%) — matches Checkpoint
    and FortiGate TOR simulation patterns.
    """
    print("    - Zscaler Module simulating: TOR Exit Node connection")
    tor_nodes = config.get('tor_exit_nodes', [])
    tor_dest  = random.choice(tor_nodes) if tor_nodes else {"ip": _random_external_ip(), "country": "Unknown"}
    dest_ip   = tor_dest.get("ip") or _random_external_ip()
    dest_port = random.choices([443, 9001, 9030], weights=[60, 30, 10])[0]
    nwsvc_map = {443: "HTTPS", 9001: "TOR", 9030: "TOR"}
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, dest_ip, dest_port, "6",
                     "Block", "Block_TOR_Traffic", nwsvc_map.get(dest_port, "HTTPS"),
                     "TOR", "TOR Exit Node",
                     tor_dest.get('country', 'Unknown'), "8")


def _generate_server_outbound_http(config, user, dept, internal_host_ip, device_info):
    """Internal server initiating outbound HTTP (port 80) — anomalous (nssfwlog, Allow).

    Servers should not initiate HTTP sessions. Allowed because no block rule matches,
    making it a detection gap. Signal: server as source + port 80 + Allow.
    Matches the server_outbound_http pattern in ASA, Checkpoint, and FortiGate modules.
    """
    print("    - Zscaler Module simulating: Server Outbound HTTP (anomalous)")
    internal_servers = config.get('internal_servers', [])
    server_ip = random.choice(internal_servers) if internal_servers else _get_random_internal_ip(config)
    return _fw_event(config, user, dept, device_info,
                     server_ip, _random_external_ip(), 80, "6",
                     "Allow", "Allow_Web_Outbound", "HTTP",
                     "Suspicious Outbound", "ServerOutboundHTTP",
                     "Unknown", "5",
                     random.randint(100, 2000), random.randint(200, 5000))


def _generate_rdp_lateral(config, user, dept, internal_host_ip, device_info):
    """Workstation-to-workstation RDP (port 3389) — lateral movement signal (nssfwlog).

    Normal users don't RDP between workstations. Blocked by cloud firewall policy.
    Matches the rdp_lateral / workstation_rdp pattern in ASA, Checkpoint, and Firepower.
    """
    print("    - Zscaler Module simulating: RDP Lateral Movement (workstation → workstation)")
    dest_ip = _get_random_internal_ip(config)
    for _ in range(5):
        if dest_ip != internal_host_ip:
            break
        dest_ip = _get_random_internal_ip(config)
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, dest_ip, 3389, "6",
                     "Block", "Block_RDP_Lateral", "RDP",
                     "Lateral Movement", "RDPLateralMovement",
                     "Internal", "6")


def _generate_ssh_over_https(config, user, dept, internal_host_ip, device_info):
    """Suspicious outbound SSH or tunneled connection over non-standard port (nssfwlog).

    SSH on TCP/443 (70%) suggests reverse tunnel or traffic blending.
    Direct outbound TCP/22 from a workstation (30%) is also anomalous.
    Matches the ssh_over_https / unusual_ssh patterns in ASA and Firepower modules.
    """
    print("    - Zscaler Module simulating: SSH over HTTPS / suspicious SSH tunnel")
    if random.random() < 0.70:
        dest_port, nwsvc, threat_name = 443, "HTTPS", "SSHoverHTTPS"
    else:
        dest_port, nwsvc, threat_name = 22,  "SSH",   "SuspiciousSSH"
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, _random_external_ip(), dest_port, "6",
                     "Block", "Block_SuspiciousSSH", nwsvc,
                     "Tunneling", threat_name,
                     "Unknown", "7")


# ---------------------------------------------------------------------------
# THREAT FIREWALL GENERATORS — multi-event (return list)
# ---------------------------------------------------------------------------

def _generate_port_scan(config, user, dept, internal_host_ip, device_info):
    """External attacker probing sequential ports on an internal server (nssfwlog).

    Generates 20-50 blocked TCP connections from the same attacker IP to the same
    internal target across sequential ports. Volume + sequential pattern = XSIAM signal.
    Matches the port_scan pattern in Checkpoint, Firepower, ASA, and FortiGate modules.
    Returns a list of CEF log strings.
    """
    print("    - Zscaler Module simulating: Port Scan (external → internal server)")
    attacker_ip     = _random_external_ip()
    internal_targets = config.get('internal_servers', []) or [_get_random_internal_ip(config)]
    target_ip       = random.choice(internal_targets)
    scan_ports      = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5900, 8080, 8443]
    n = random.randint(min(20, len(scan_ports)), min(50, len(scan_ports)))
    ports_to_scan   = sorted(random.sample(scan_ports, n))
    logs = []
    for port in ports_to_scan:
        logs.append(_fw_event(config, user, dept, device_info,
                              attacker_ip, target_ip, port, "6",
                              "Block", "Block_PortScan", "PortScan",
                              "Network Scan", "PortScan",
                              "Unknown", "6", 0, random.randint(40, 80)))
    return logs


def _generate_brute_force(config, user, dept, internal_host_ip, device_info):
    """High-volume blocked connections from same external IP to same service port (nssfwlog).

    Models a brute force attack against SSH, RDP, SMB, or WinRM.
    20-60 events from the same attacker; the volume is the XSIAM detection signal.
    Matches the brute_force / auth_brute_force pattern across all other modules.
    Returns a list of CEF log strings.
    """
    print("    - Zscaler Module simulating: Brute Force (external → internal service)")
    attacker_ip     = _random_external_ip()
    internal_targets = config.get('internal_servers', []) or [_get_random_internal_ip(config)]
    target_ip       = random.choice(internal_targets)
    service_choice  = random.choice([
        (22,   "SSH",   "BruteForce_SSH"),
        (3389, "RDP",   "BruteForce_RDP"),
        (445,  "SMB",   "BruteForce_SMB"),
        (5985, "WinRM", "BruteForce_WinRM"),
    ])
    dest_port, nwsvc, threat_name = service_choice
    n_attempts = random.randint(20, 60)
    logs = []
    for _ in range(n_attempts):
        logs.append(_fw_event(config, user, dept, device_info,
                              attacker_ip, target_ip, dest_port, "6",
                              "Block", "Block_BruteForce", nwsvc,
                              "Brute Force Attack", threat_name,
                              "Unknown", "7", 0, random.randint(40, 100)))
    return logs


def _generate_dns_c2_beacon(config, user, dept, internal_host_ip, device_info):
    """Repeated DNS queries (UDP/53) to a suspicious external resolver — C2 beacon pattern.

    15-40 ALLOWED events to the same external IP. The volume of allowed queries
    to a consistent suspicious resolver is the XSIAM UEBA detection signal, NOT
    a single blocked event. Matches dns_c2_beacon in all other modules.
    Returns a list of CEF log strings.
    """
    print("    - Zscaler Module simulating: DNS C2 Beacon (volume DNS to suspicious resolver)")
    # Suspicious resolvers that are not on standard block lists
    suspicious_resolvers = (
        [_random_external_ip() for _ in range(3)] +
        ["91.108.4.1", "176.10.104.240", "185.220.101.1"]
    )
    resolver_ip = random.choice(suspicious_resolvers)
    n_queries   = random.randint(15, 40)
    logs = []
    for _ in range(n_queries):
        logs.append(_fw_event(config, user, dept, device_info,
                              internal_host_ip, resolver_ip, 53, "17",
                              "Allow", "Allow_DNS_Outbound", "DNS",
                              "N/A", "SuspiciousDNS",
                              "Unknown", "4",
                              random.randint(64, 256), random.randint(32, 128)))
    return logs


# ---------------------------------------------------------------------------
# SMB THREAT GENERATORS — internal east-west SMB scenarios
# ---------------------------------------------------------------------------

def _generate_smb_new_host_lateral(config, user, dept, internal_host_ip, device_info):
    """SMB connections from one internal workstation to multiple unfamiliar internal hosts.

    Generates 5–10 firewall Allow events on TCP/445 to DIFFERENT internal destinations.
    The breadth of distinct SMB targets from a single workstation in a short window is
    the XSIAM UEBA detection signal (lateral exploration, pass-the-hash, ransomware
    pre-encryption reconnaissance).

    Returns list of CEF log strings (multi-event, nssfwlog).
    """
    print("    - Zscaler Module simulating: SMB New-Host Lateral (exploring SMB on new hosts)")
    n_hosts    = random.randint(5, 10)
    dest_ips   = set()
    internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
    while len(dest_ips) < n_hosts:
        try:
            net  = ip_network(random.choice(internal_nets), strict=False)
            host = rand_ip_from_network(net)
            if host != internal_host_ip:
                dest_ips.add(host)
        except Exception:
            dest_ips.add(f"192.168.1.{random.randint(101, 200)}")

    logs = []
    for dst_ip in list(dest_ips)[:n_hosts]:
        logs.append(_fw_event(config, user, dept, device_info,
                              internal_host_ip, dst_ip, 445, "6",
                              "Allow", "Allow_Internal_SMB", "SMB",
                              "Lateral Movement", "SMBNewHostLateral",
                              "Internal", "6",
                              random.randint(200, 5000), random.randint(2000, 50000)))
    return logs


def _generate_smb_rare_file_transfer(config, user, dept, internal_host_ip, device_info):
    """Large SMB file transfer (100 MB – 1 GB) to an unusual internal server — data staging.

    A single Allow event with anomalously large bytesOut (data sent / read from the share).
    The large volume on an internal SMB session is the XSIAM UEBA detection signal.
    Session ALLOWED because no block rule matches — purely volume-based detection.

    Returns single CEF log string (nssfwlog).
    """
    print("    - Zscaler Module simulating: SMB Rare File Transfer (large internal SMB)")
    internal_servers = config.get('internal_servers', [])
    dst_ip     = random.choice([s for s in internal_servers if s != internal_host_ip]
                                or internal_servers or [_get_random_internal_ip(config)])
    file_size  = random.randint(104_857_600, 1_073_741_824)  # 100 MB – 1 GB
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, dst_ip, 445, "6",
                     "Allow", "Allow_Internal_SMB", "SMB",
                     "Data Staging", "SMBRareFileTransfer",
                     "Internal", "7",
                     file_size, random.randint(1000, 50000))


def _generate_smb_share_enumeration(config, user, dept, internal_host_ip, device_info):
    """Rapid TCP/445 allowed connections to many different internal hosts — SMB share scanning.

    15–40 Allow events on port 445 to distinct internal IPs in rapid succession.
    Connections SUCCEED — XSIAM detects the scan from the volume of allowed SMB
    connections to new hosts, not from denies (same principle as port_scan).
    Models a workstation probing for accessible file shares.

    Returns list of CEF log strings (multi-event, nssfwlog).
    """
    print("    - Zscaler Module simulating: SMB Share Enumeration (scanning for open shares)")
    n_targets     = random.randint(15, 40)
    internal_nets = config.get('internal_networks', ['192.168.1.0/24'])
    target_ips    = set()
    while len(target_ips) < n_targets:
        try:
            net  = ip_network(random.choice(internal_nets), strict=False)
            host = rand_ip_from_network(net)
            if host != internal_host_ip:
                target_ips.add(host)
        except Exception:
            target_ips.add(f"192.168.1.{random.randint(101, 254)}")

    logs = []
    for dst_ip in list(target_ips)[:n_targets]:
        logs.append(_fw_event(config, user, dept, device_info,
                              internal_host_ip, dst_ip, 445, "6",
                              "Allow", "Allow_Internal_SMB", "SMB",
                              "Network Scan", "SMBShareEnumeration",
                              "Internal", "7",
                              random.randint(40, 200), random.randint(40, 200)))
    return logs


# Module-level dispatch map for named-threat mode (keys match THREAT_NAMES).
# Functions accept (config, user, dept, internal_host_ip, device_info).
_NAMED_THREATS = {
    "web_threat":           _generate_threat_web_traffic,
    "data_exfil":           _generate_data_exfil_web_traffic,
    "dlp_threat":           _generate_dlp_web_traffic,
    "cloud_app_threat":     _generate_cloud_app_control_event,
    "sandbox_threat":       _generate_sandbox_event,
    "fw_threat":            _generate_threat_firewall_traffic,
    "port_scan":            _generate_port_scan,
    "brute_force":          _generate_brute_force,
    "tor_connection":       _generate_tor_connection,
    "dns_c2_beacon":        _generate_dns_c2_beacon,
    "server_outbound_http": _generate_server_outbound_http,
    "rdp_lateral":          _generate_rdp_lateral,
    "ssh_over_https":       _generate_ssh_over_https,
    "smb_new_host_lateral": _generate_smb_new_host_lateral,
    "smb_rare_file_transfer": _generate_smb_rare_file_transfer,
    "smb_share_enumeration":  _generate_smb_share_enumeration,
}


def get_threat_names():
    """Return available threat names dynamically from _NAMED_THREATS.
    Adding a new entry to _NAMED_THREATS automatically surfaces it here."""
    return list(_NAMED_THREATS.keys())


# ---------------------------------------------------------------------------
# CEF FORMATTER (unchanged from original)
# ---------------------------------------------------------------------------

def _format_nss_log_as_cef(fields, user, dept, log_product):
    """Builds the final CEF log string for Zscaler NSS feeds."""
    rt = int(time.time() * 1000)

    common_map = {
        "rt": rt,
        "suser": user if '@' in user else f"{user}@example.com",
        "externalId": str(random.randint(1000000, 9999999999)),
        "deviceHostName":              fields.get("devicehostname"),
        "deviceOwner":                 fields.get("deviceowner"),
        "deviceOperatingSystem":       fields.get("deviceostype"),
        "deviceOperatingSystemVersion":fields.get("deviceosversion"),
        "sourceTranslatedAddress":     fields.get("sourceTranslatedAddress"),
        "flexString1": fields.get("flexString1"), "flexString1Label": "location",
        "dept": dept,
        "clienttranstime": random.randint(10, 2000),
        "servertranstime": random.randint(10, 5000),
        "ssldecrypted":    random.choice(["Yes", "No"]),
        "contentclass":    fields.get("contentclass", "Web Browsing"),
    }

    if log_product == 'nssweblog':
        cef_name = "Web Traffic"
        cef_map  = {
            # XIF-mapped cs/cn fields:
            "cs2": fields.get("urlcat"),       "cs2Label": "urlcat",
            "cs4": fields.get("malwarecat"),   "cs4Label": "malwarecat",
            "cs5": fields.get("threatname"),   "cs5Label": "threatname",
            "cn1": fields.get("threatscore"),  "cn1Label": "threatscore",
            # Raw dataset hunting fields:
            "cs1": fields.get("urlclass"),     "cs1Label": "urlclass",
            "cs3": fields.get("malwareclass"), "cs3Label": "malwareclass",
            "cs6": fields.get("riskscore"),    "cs6Label": "riskscore",
            "cn2": fields.get("filesize"),     "cn2Label": "filesize",
            "cn3": fields.get("totalsize"),    "cn3Label": "totalsize",
            # Standard XIF-mapped fields:
            "act": fields.get("action"),
            "outcome": fields.get("responsecode"),
            "reason": fields.get("reason"),
            "app": fields.get("proto"),
            "cat": fields.get("urlcat"),
            "dhost": fields.get("ehost"),
            "dst": fields.get("sip"),    "src": fields.get("cip"),
            "request": fields.get("eurl"),
            "requestMethod": fields.get("reqmethod"),
            "requestClientApplication": fields.get("useragent"),
            "contenttype": fields.get("contenttype"),
            "in": fields.get("bytesin"),  "out": fields.get("bytesout"),
            "fileName": fields.get("filename"), "fileType": fields.get("filetype"),
            "fileHash": fields.get("fileHash"),
            "appclass": fields.get("appclass"),
        }
        if fields.get("event_type") == "dlp":
            cef_map.update({
                "cs1": fields.get("dlpengine"),    "cs1Label": "dlpeng",
                "cs2": fields.get("dlpdictionary"),"cs2Label": "dlpdict",
                "cs3": fields.get("dlprule"),      "cs3Label": "dlprulename",
                "cs4": None, "cs4Label": None,
                "cs5": None, "cs5Label": None,
                "cn1": None, "cn1Label": None,
            })

    else:  # nssfwlog
        cef_name = "Firewall Traffic"
        cef_map  = {
            # XIF-mapped cs/cn fields:
            "cs2": fields.get("rulelabel"),    "cs2Label": "nwapp",
            "cs3": fields.get("nwsvc"),        "cs3Label": "nwsvc",
            "cs5": fields.get("urlcat"),       "cs5Label": "urlcat",
            "cs6": fields.get("threatname"),   "cs6Label": "threatname",
            "cn1": fields.get("duration_ms"),  "cn1Label": "duration",
            "cat": fields.get("threatcat"),
            # Raw dataset hunting fields:
            "cs1": fields.get("nwsvc"),        "cs1Label": "nwsvc",
            "cs4": fields.get("destCountry"),  "cs4Label": "destCountry",
            # Standard XIF-mapped fields:
            "act": fields.get("action"),
            "reason": fields.get("reason"),
            "proto": fields.get("proto"),
            "src": fields.get("srcip"),     "dst": fields.get("destip"),
            "spt": fields.get("sport"),     "dpt": fields.get("destport"),
            "in": fields.get("bytesin"),    "out": fields.get("bytesout"),
            "destCountry": fields.get("destCountry"),
            "srcCountry": fields.get("srcCountry"),
            "spriv": fields.get("spriv"),
            "sourceTranslatedAddress":      fields.get("sourceTranslatedAddress"),
            "destinationTranslatedAddress": fields.get("destinationTranslatedAddress"),
        }

    merged = dict(common_map)
    merged.update(cef_map)
    cef_severity = fields.get('cefSeverity', '3')
    cef_header   = f"CEF:0|Zscaler|{log_product}|6.1|0|{cef_name}|{cef_severity}|"
    extension_parts  = [f"{key}={_cef_escape(value)}" for key, value in merged.items() if value is not None]
    extension_string = " ".join(extension_parts)
    return f"<14>{datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} zscaler-nss {cef_header}{extension_string}"


# ---------------------------------------------------------------------------
# SCENARIO SUPPORT
# ---------------------------------------------------------------------------

def _generate_scenario_log(config, scenario):
    """Generates a scenario-driven threat log from an explicit scenario dict."""
    user, dept, ip, device_info = _get_user_and_device_info(
        config, user_override=scenario.get('source_user'))
    if not ip:
        ip = scenario.get('source_ip', _get_random_internal_ip(config))
    zscaler_conf = config.get('zscaler_config', {})
    fields = {
        "action": "Block", "urlcat": "Malware", "urlsupercat": "Security",
        "responsecode": "403", "reason": "Threat Block",
        "malwarecat": scenario.get('threat_category', 'Adware'),
        "threatname":  scenario.get('threat_name',     'JS/Adware.Gen'),
        "reqmethod": "GET", "useragent": "Mozilla/5.0",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"http://{scenario.get('dest_domain', 'malware.example.com')}/",
        "ehost": scenario.get('dest_domain', 'malware.example.com'),
        "cip": ip, "sip": scenario.get('dest_ip', _random_external_ip()),
        "proto": "HTTP", "bytesin": 0, "bytesout": 60,
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "8",
    }
    return _format_nss_log_as_cef(fields, user, dept, 'nssweblog')


# ---------------------------------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------------------------------

def generate_log(config, scenario=None, threat_level="Realistic", benign_only=False, context=None, scenario_event=None):
    """Generates a Zscaler NSS CEF log with variable threat rates.

    Benign pool (4 types):
        web(x3), firewall(x2), dns_query, inbound_block

    Threat pool (16 types, weighted):
        Web layer:  web_threat(12), data_exfil(8), dlp_threat(6),
                    cloud_app_threat(5), sandbox_threat(4)
        Firewall:   fw_threat(8), port_scan(10), brute_force(8),
                    tor_connection(6), dns_c2_beacon(5),
                    server_outbound_http(4), rdp_lateral(3), ssh_over_https(3)
        SMB:        smb_new_host_lateral(4), smb_rare_file_transfer(3),
                    smb_share_enumeration(5)

    scenario_event values:
        THREAT_BLOCK — victim browser hits malicious domain (phishing kill chain step 3)
        DATA_EXFIL   — insider uploads large data to external cloud storage (insider threat step 5)
    """
    global last_threat_event_time
    session_context = (context or {}).get('session_context')

    if scenario:
        return _generate_scenario_log(config, scenario)

    if scenario_event == "THREAT_BLOCK":
        # Kill chain step 3: victim's browser reaches phishing domain after click-permitted
        src_ip      = (context or {}).get("src_ip")
        victim_user = (context or {}).get("user")
        user, dept, internal_host_ip, device_info = _get_user_and_device_info(
            config, user_override=victim_user, session_context=session_context)
        if src_ip:
            internal_host_ip = src_ip
        return _generate_threat_web_traffic(config, user, dept, internal_host_ip, device_info)

    if scenario_event == "DATA_EXFIL":
        # Insider threat step 5: large data upload to external cloud storage triggers DLP alert
        src_ip       = (context or {}).get("src_ip")
        insider_user = (context or {}).get("user")
        user, dept, internal_host_ip, device_info = _get_user_and_device_info(
            config, user_override=insider_user, session_context=session_context)
        if src_ip:
            internal_host_ip = src_ip
        result = _generate_dlp_web_traffic(config, user, dept, internal_host_ip, device_info)
        if result is None:
            result = _generate_data_exfil_web_traffic(config, user, dept, internal_host_ip, device_info)
        return result

    if scenario_event and scenario_event in _NAMED_THREATS:
        user, dept, internal_host_ip, device_info = _get_user_and_device_info(
            config, session_context=session_context)
        if not internal_host_ip:
            internal_host_ip = _get_random_internal_ip(config)
        return _NAMED_THREATS[scenario_event](config, user, dept, internal_host_ip, device_info)

    user, dept, internal_host_ip, device_info = _get_user_and_device_info(
        config, session_context=session_context)
    if not internal_host_ip:
        internal_host_ip = _get_random_internal_ip(config)

    # Benign pool — weighted so web traffic dominates, matching real Zscaler proportions.
    # web_traffic×3 + firewall_traffic×2 + video_streaming×2 + saas_upload×1 + software_update×1
    # + dns_query×1 + inbound_block×1 = 11 slots → ~27/18/18/9/9/9/9 %
    benign_pool = (
        [lambda: _generate_benign_web_traffic(config, user, dept, internal_host_ip, device_info)] * 3 +
        [lambda: _generate_benign_firewall_traffic(config, user, dept, internal_host_ip, device_info)] * 2 +
        [lambda: _generate_benign_video_streaming(config, user, dept, internal_host_ip, device_info)] * 2 +
        [lambda: _generate_benign_saas_upload(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_software_update(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_dns_query(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_inbound_block(config, user, dept, internal_host_ip, device_info)]
    )

    if benign_only:
        return random.choice(benign_pool)()

    # Threat pool with weights — aligned with other module distributions
    _threat_map = [
        # label,                  weight, callable
        ("web_threat",            12, lambda: _generate_threat_web_traffic(config, user, dept, internal_host_ip, device_info)),
        ("data_exfil",             8, lambda: _generate_data_exfil_web_traffic(config, user, dept, internal_host_ip, device_info)),
        ("dlp_threat",             6, lambda: _generate_dlp_web_traffic(config, user, dept, internal_host_ip, device_info)),
        ("cloud_app_threat",       5, lambda: _generate_cloud_app_control_event(config, user, dept, internal_host_ip, device_info)),
        ("sandbox_threat",         4, lambda: _generate_sandbox_event(config, user, dept, internal_host_ip, device_info)),
        ("fw_threat",              8, lambda: _generate_threat_firewall_traffic(config, user, dept, internal_host_ip, device_info)),
        ("port_scan",             10, lambda: _generate_port_scan(config, user, dept, internal_host_ip, device_info)),
        ("brute_force",            8, lambda: _generate_brute_force(config, user, dept, internal_host_ip, device_info)),
        ("tor_connection",         6, lambda: _generate_tor_connection(config, user, dept, internal_host_ip, device_info)),
        ("dns_c2_beacon",          5, lambda: _generate_dns_c2_beacon(config, user, dept, internal_host_ip, device_info)),
        ("server_outbound_http",   4, lambda: _generate_server_outbound_http(config, user, dept, internal_host_ip, device_info)),
        ("rdp_lateral",            3, lambda: _generate_rdp_lateral(config, user, dept, internal_host_ip, device_info)),
        ("ssh_over_https",         3, lambda: _generate_ssh_over_https(config, user, dept, internal_host_ip, device_info)),
        ("smb_new_host_lateral",   4, lambda: _generate_smb_new_host_lateral(config, user, dept, internal_host_ip, device_info)),
        ("smb_rare_file_transfer", 3, lambda: _generate_smb_rare_file_transfer(config, user, dept, internal_host_ip, device_info)),
        ("smb_share_enumeration",  5, lambda: _generate_smb_share_enumeration(config, user, dept, internal_host_ip, device_info)),
    ]
    weights   = [t[1] for t in _threat_map]
    callables = [t[2] for t in _threat_map]

    def _pick_threat():
        fn = random.choices(callables, weights=weights, k=1)[0]
        return fn()

    if threat_level == "Insane":
        if random.random() < 0.6:
            result = _pick_threat()
            return result if result is not None else random.choice(benign_pool)()
        else:
            return random.choice(benign_pool)()
    else:
        interval     = _get_threat_interval(threat_level, config)
        current_time = time.time()
        if (current_time - last_threat_event_time) > interval:
            last_threat_event_time = current_time
            result = _pick_threat()
            return result if result is not None else random.choice(benign_pool)()
        else:
            return random.choice(benign_pool)()
