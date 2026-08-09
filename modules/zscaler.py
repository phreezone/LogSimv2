# modules/zscaler.py
# Simulates Zscaler NSS feed logs in CEF format for web proxy, cloud firewall,
# DLP, sandbox, and network threat detection events for XSIAM Broker VM.

import random
import time
from datetime import datetime, timezone
from ipaddress import ip_network
import hashlib
try:
    from modules.session_utils import (get_random_user, get_user_by_name,
        get_zscaler_device_info, rand_ip_from_network,
        stable_vpn_ip, stable_mail_servers, weighted_destination,
        novel_country_vpn_ip, tor_vpn_ip, random_external_ip)
except ImportError:
    from session_utils import (get_random_user, get_user_by_name,
        get_zscaler_device_info, rand_ip_from_network,
        stable_vpn_ip, stable_mail_servers, weighted_destination,
        novel_country_vpn_ip, tor_vpn_ip, random_external_ip)

def _cef_escape(value):
    """Encode an NSS extension value the way a real Zscaler feed does.

    NOT plain CEF backslash-escaping. Zscaler HEX-ENCODES the characters listed in the
    feed's "Feed Escape Character" setting rather than backslash-escaping them, and
    XSIAM's onboarding guide configures that setting to `=`. So a genuine Zscaler ->
    XSIAM feed never contains a literal `=` inside a value; it contains `%3D` and the
    receiver can split on `=` safely.

    The previous implementation emitted `\\=`, which leaves a real `=` in the value and
    only helps a parser that honours CEF escaping. XSIAM's does not reliably: we already
    measured this class of failure on this module, where unrecognised extension keys
    caused devicehostname to swallow everything up to the next known key. Hex-encoding
    removes the ambiguity at the source, which is what the documented configuration does.

    Refs: "General Guidelines for NSS Feeds and Feed Formats" (Zscaler) — the service
    encodes the characters entered in Feed Escape Character, e.g. a comma becomes %2C;
    "Ingest logs from Zscaler Internet Access" (Cortex XDR 3.x) — Feed Escape Character `=`.
    """
    s = str(value)
    s = s.replace('\\', '\\\\')
    s = s.replace('=', '%3D')
    s = s.replace('\n', '%0A')
    s = s.replace('\r', '%0D')
    return s


_DEVICE_MODELS = [
    "20L8S7WC08", "20XW004QUS", "21CB007PUS",      # ThinkPad
    "MacBookPro18,3", "MacBookAir10,1", "Mac14,7",  # Apple
    "Latitude 7440", "Latitude 5550", "XPS 9530",   # Dell
    "EliteBook 840 G10", "ProBook 450 G9",          # HP
]


def _device_model(hostname):
    """Stable hardware model per device — %s{devicemodel} in the NSS field reference.

    Sticky by hostname so a given endpoint keeps the same model across events; a
    workstation whose reported hardware changes every log line is a giveaway.
    """
    if not hostname:
        return None
    return _DEVICE_MODELS[hash(("model", str(hostname))) % len(_DEVICE_MODELS)]


def _zscaler_url_encode(url):
    """Hex-encode a URL the way Zscaler does before streaming it to a SIEM.

    "The Zscaler service hex encodes all non-printable ASCII characters that are in URLs
    when it sends logs to the NSS. Any URL character that is less than or equal to 0x20,
    or greater than or equal to 0x7F, is encoded as %HH." — so a space becomes %20 and a
    newline %0A. Applied to url/referer fields only; Zscaler does this for URLs, not for
    every field.
    """
    if url is None:
        return None
    out = []
    for ch in str(url):
        o = ord(ch)
        out.append("%%%02X" % o if (o <= 0x20 or o >= 0x7F) else ch)
    return "".join(out)


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


# Realistic file names for upload / data-transfer events, grouped by the kind of
# content being moved. Used to populate fileName/fileType/filesize (cn2) so web
# upload events carry the file metadata a real Zscaler NSS web feed reports.
_UPLOAD_FILES = {
    "document": [("Q3_Financial_Report.xlsx", "xlsx"), ("Board_Deck_Draft.pptx", "pptx"),
                 ("Contract_Amendment.docx", "docx"), ("2026_Budget_Forecast.xlsx", "xlsx"),
                 ("Strategy_Review.pdf", "pdf"), ("Vendor_SOW.docx", "docx")],
    "archive":  [("project_backup.zip", "zip"), ("export_bundle.tar.gz", "gz"),
                 ("photos_archive.7z", "7z"), ("case_files.zip", "zip")],
    "pii":      [("customer_records.csv", "csv"), ("employee_roster.xlsx", "xlsx"),
                 ("account_export.csv", "csv"), ("payroll_run.xlsx", "xlsx")],
    "source":   [("app_source.tar.gz", "gz"), ("build_pipeline.py", "py"),
                 ("api_service.java", "java"), ("repo_snapshot.zip", "zip")],
}


def _pick_upload_file(kind="document"):
    """Return (filename, filetype) for an upload event of the given content kind."""
    return random.choice(_UPLOAD_FILES.get(kind, _UPLOAD_FILES["document"]))


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
    # Fall back to the shared map like cisco_firepower does. zscaler_config has no
    # user_ip_map of its own (0 entries), so without this the legacy path returned
    # the "unknown_user"/"unknown-host" placeholders — which then land in XSIAM as
    # a real identity. Benign generation with no session
    # context produced placeholder identities on every event.
    user_ip_map = (zscaler_conf.get('user_ip_map')
                   or config.get('shared_user_ip_map', {}))
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


def _identity_from_context(config, ctx):
    """Build (user, dept, ip, device_info) directly from an orchestrator-pinned
    identity in context — the REAL box user/hostname/IP — bypassing the random
    identity maps (which don't contain a bring-your-own box user).

    Used ONLY when context carries 'user' (an XDR-orchestrated event). Ambient
    generation never takes this path, so its identities/format are unchanged. The
    emitted fields (suser, devicehostname, deviceowner, cip) keep their normal
    format — only the values are the real ones, so the synthetic web logs align
    with the endpoint the Cortex agent reports."""
    user     = ctx.get("user") or "unknown_user"
    ip       = ctx.get("src_ip") or _get_random_internal_ip(config)
    hostname = ctx.get("hostname") or f"{user}-desktop"
    device_info = {
        "hostname":   hostname,
        "owner":      user,
        "os_type":    ctx.get("os_type", "Windows"),
        "os_version": ctx.get("os_version", "11"),
    }
    return user, ctx.get("department", "Unknown"), ip, device_info


def _dns_precursor_event(config, user, dept, device_info, src_ip, domain=None,
                         event_time_ms=None):
    """Generate a DNS resolution NSSFWlog event that precedes a connection.

    Returns a single CEF string representing the UDP/53 query that must
    logically precede any outbound TCP connection to an external host.

    domain: the name being resolved. Pass it whenever the caller knows it. This function
            previously took no domain at all and emitted a content-free UDP/53 event to
            8.8.8.8, so the log recorded "this host made a DNS query" without recording
            WHAT it resolved. Both comparison modules carry the name — Check Point's
            `_dns_precursor(config, src_ip, user, shost, domain, ...)` and Firepower's
            `_dns_precursor_log(config, src_ip, user, dest_hostname, shost)` — and that
            host-to-domain association is precisely what the C2 / rare-domain /
            dynamic-DNS detectors consume. Emitted as cdfqdn (Client Destination FQDN).
    """
    return _fw_event(config, user, dept, device_info,
                     src_ip, random.choice(["8.8.8.8", "8.8.4.4", "1.1.1.1"]),
                     53, "17",
                     "Allow", "Allow_DNS_Outbound", "DNS",
                     "N/A", "DNSQuery",
                     "United States", "1",
                     random.randint(64, 512), random.randint(32, 128),
                     dst_fqdn=domain, event_time_ms=event_time_ms,
                     duration_ms=random.randint(1, 500))


# ---------------------------------------------------------------------------
# BENIGN WEB GENERATORS
# ---------------------------------------------------------------------------

def _generate_benign_web_traffic(config, user, dept, internal_host_ip, device_info):
    """Allowed outbound web browsing (nssweblog)."""
    zscaler_conf = config.get('zscaler_config', {})
    _default_dest = [{"ip_range": "8.8.8.0/24", "name": "google.com",
                      "ports": [443], "service_types": ["HTTPS"], "country": "US"}]
    destination = weighted_destination(user, zscaler_conf.get('benign_egress_destinations', _default_dest))
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
        "action": "Allowed",
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
    destination = weighted_destination(user, zscaler_conf.get('benign_egress_destinations', _default_dest))
    dest_ip_range = destination.get("ip_range", "8.8.8.0/24")
    if dest_ip_range.endswith("/32"):
        dest_ip = dest_ip_range[:-3]
    else:
        try:
            dest_ip = rand_ip_from_network(ip_network(dest_ip_range, strict=False))
        except Exception:
            dest_ip = "8.8.8.1"
    dest_port = random.choice(destination.get("ports", [443]))
    # nwsvc is the network SERVICE, so derive it from the destination port. The
    # config's service_types are application categories ("Web Browsing",
    # "PackageManagement", "ZoomMeeting", "Email"), and feeding them through here put
    # non-service values into xdm.network.application_protocol — the field the
    # app-aware detectors read. Fall back to the config value only when it is already
    # a real service name (several entries are "SSH" / "RDP" / "HTTPS").
    _cfg_svc = random.choice(destination.get("service_types", ["HTTPS"])).replace(" ", "")
    fields = {
        "srcip": internal_host_ip, "sport": random.randint(49152, 65535),
        "destip": dest_ip, "destport": dest_port,
        "proto": "6",
        "action": "Allow", "rulelabel": "Allow_Web_Outbound", "reason": "Allowed",
        "threatcat": None, "threatname": None,
        "destCountry": destination.get("country", "United States"),
        "srcCountry": "United States",
        "bytesin": random.randint(5000, 50000), "bytesout": random.randint(500, 5000),
        "nwsvc": _port_service(dest_port) or (_cfg_svc if _cfg_svc in _PORT_SERVICE.values() else None),
        # The config's service_types ("Web Browsing", "PackageManagement",
        # "ZoomMeeting", "Email") are APPLICATIONS, not services — the vendor sample
        # pairs nwsvc=HTTP with nwapp=ebay. They were never valid nwsvc values, so
        # route them to nwapp where they are correct, and prefer the destination's own
        # name when it has one.
        "nwapp": destination.get("name") or _cfg_svc or None,
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
        "action": "Blocked", "rulelabel": "Block_Inbound_Probe", "reason": "Policy Block",
        "threatcat": "Network Scan", "threatname": "InboundProbe",
        "destCountry": "United States",
        "srcCountry": random.choice(_THREAT_COUNTRIES),
        "bytesin": random.randint(40, 100), "bytesout": random.randint(40, 100),
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
    # bytesout = client→server (large: uploading files); bytesin = server→client (small: ACK)
    upload_bytes = random.randint(500_000, 50_000_000)
    ack_bytes    = random.randint(200, 2_000)
    filename, filetype = _pick_upload_file(random.choice(["document", "archive"]))
    fields = {
        "action": "Allowed",
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
        "bytesout": upload_bytes,
        "bytesin":  ack_bytes,
        # file metadata: cn2=filesize (the uploaded file), cn3=totalsize (transaction)
        "filename": filename, "filetype": filetype,
        "filesize": upload_bytes, "totalsize": upload_bytes + ack_bytes,
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
        "action": "Allowed",
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
        "action": "Allowed",
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
# BENIGN PROTOCOL BASELINE GENERATORS (UEBA)
# ---------------------------------------------------------------------------

def _generate_benign_smb_event(config, user, dept, internal_host_ip, device_info):
    """Internal SMB file-share access — baseline for SMB lateral movement alerts (nssfwlog)."""
    internal_servers = config.get('internal_servers', [])
    dst_ip = random.choice(internal_servers) if internal_servers else _get_random_internal_ip(config)
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, dst_ip, 445, "6",
                     "Allow", "Allow_Internal_SMB", "SMB",
                     None, None,
                     "Internal", "1",
                     random.randint(2_000, 50_000), random.randint(500, 5_000))


def _generate_benign_ssh_event(config, user, dept, internal_host_ip, device_info):
    """Internal SSH admin session — baseline for rare_ssh alerts (nssfwlog)."""
    internal_servers = config.get('internal_servers', [])
    dst_ip = random.choice(internal_servers) if internal_servers else _get_random_internal_ip(config)
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, dst_ip, 22, "6",
                     "Allow", "Allow_Internal_SSH", "SSH",
                     None, None,
                     "Internal", "1",
                     random.randint(1_000, 20_000), random.randint(500, 10_000))


def _generate_benign_rdp_event(config, user, dept, internal_host_ip, device_info):
    """Internal RDP admin session — baseline for rare_external_rdp alerts (nssfwlog)."""
    internal_servers = config.get('internal_servers', [])
    dst_ip = random.choice(internal_servers) if internal_servers else _get_random_internal_ip(config)
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, dst_ip, 3389, "6",
                     "Allow", "Allow_Internal_RDP", "RDP",
                     None, None,
                     "Internal", "1",
                     random.randint(50_000, 500_000), random.randint(10_000, 100_000))


def _generate_benign_vpn_event(config, user, dept, internal_host_ip, device_info):
    """Successful RA-VPN login from user's stable home IP — VPN baseline (nssfwlog)."""
    zscaler_conf = config.get('zscaler_config', {})
    gateway_ip = zscaler_conf.get('vpn_gateway_ip',
                     random.choice(config.get('internal_servers', ['10.0.10.1'])))
    home_ip = stable_vpn_ip(user)
    return _fw_event(config, user, dept, device_info,
                     home_ip, gateway_ip, 443, "6",
                     "Allow", "Allow_VPN_Access", "HTTPS",
                     None, None,
                     "United States", "2",
                     random.randint(100_000, 5_000_000),
                     random.randint(50_000, 2_000_000))


def _generate_vpn_new_country_login(config, user, dept, internal_host_ip, device_info):
    """One SUCCESSFUL RA-VPN/ZPA login from a country the org has never seen (nssfwlog).

    Drives the XSIAM analytic "First successful VPN access from a country in
    organization" — a FIRST-SEEN, ORG-SCOPED detector that fires only on a country
    not observed anywhere in the org in the last 30 days.

    WHY THIS EXISTS / DO NOT "FIX" IT AWAY:
    The analytic had been silent because the
    simulator was already emitting source IPs resolving to 210 distinct countries
    over 30 days — every country on Earth was "seen", so nothing could be novel.
    Restoring it needs BOTH a tight ambient baseline and something that
    deliberately visits an unused country; this is the latter.

    session_utils.novel_country_vpn_ip() draws from config['vpn_novel_country_pool']
    (70 XSIAM-PROBED single-country /24s, disjoint from benign_ingress_sources,
    external_traffic_sources and the Tor prefix allowlist) and rotates on the day
    number => 70-day recurrence per country.  Day-keyed rather than random so that
    ASA, Check Point, FortiGate, Firepower and Zscaler all pick the SAME country on
    a given day; the detector is org-scoped, so five sources choosing independently
    would consume the pool five times faster and never satisfy the 30-day window.
    """
    novel_ip, cc, country, isp = novel_country_vpn_ip(config)
    if not novel_ip:
        return None
    print(f"    - Zscaler Module simulating: First VPN access from new country "
          f"({country} / {isp} / {novel_ip})")
    zscaler_conf = config.get('zscaler_config', {})
    gateway_ip = zscaler_conf.get('vpn_gateway_ip',
                     random.choice(config.get('internal_servers', ['10.0.10.1'])))
    return _fw_event(config, user, dept, device_info,
                     novel_ip, gateway_ip, 443, "6",
                     "Allow", "Allow_VPN_Access", "HTTPS",
                     None, None,
                     "United States", "2",
                     random.randint(100_000, 5_000_000),
                     random.randint(50_000, 2_000_000),
                     src_country=country or "Unknown")


def _generate_benign_vpn_failure_event(config, user, dept, internal_host_ip, device_info):
    """Failed VPN auth attempt — baseline for vpn_brute_force detection (nssfwlog).

    Real users fail auth for mundane reasons: typo, expired cert, MFA timeout,
    or locked-out account. Generating occasional failures prevents UEBA from
    treating any single auth failure as anomalous.
    """
    zscaler_conf = config.get('zscaler_config', {})
    gateway_ip = zscaler_conf.get('vpn_gateway_ip',
                     random.choice(config.get('internal_servers', ['10.0.10.1'])))
    home_ip = stable_vpn_ip(user)
    failure_reasons = ["Credential Mismatch", "Expired Certificate",
                       "MFA Timeout", "Account Locked"]
    return _fw_event(config, user, dept, device_info,
                     home_ip, gateway_ip, 443, "6",
                     "Blocked", "Block_VPN_AuthFail", "HTTPS",
                     "Authentication", random.choice(failure_reasons),
                     "United States", "3",
                     random.randint(200, 1_000), random.randint(100, 500))


def _generate_benign_email_event(config, user, dept, internal_host_ip, device_info):
    """Outbound email via corporate SMTP relay — baseline for smtp_spray / smtp_large_exfil.

    Uses stable_mail_servers() so each user connects to only 2-3 fixed relays,
    matching real enterprise behavior and avoiding XSIAM spam-bot false positives.
    """
    dest_ip = stable_mail_servers(user)
    smtp_port = random.choices([587, 25], weights=[80, 20], k=1)[0]
    nwsvc = "SMTPS" if smtp_port == 587 else "SMTP"
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, dest_ip, smtp_port, "6",
                     "Allow", "Allow_SMTP_Relay", nwsvc,
                     None, None,
                     "United States", "1",
                     random.randint(500, 5_000),
                     random.randint(1_000, 500_000))


def _generate_benign_ftp_event(config, user, dept, internal_host_ip, device_info):
    """Scheduled FTP download — baseline for ftp_large_exfil alerts (nssfwlog).

    Benign FTP is predominantly download: bytesIn >> bytesOut (opposite of exfil).
    """
    internal_servers = config.get('internal_servers', [])
    dst_ip = random.choice(internal_servers) if internal_servers else _get_random_internal_ip(config)
    return _fw_event(config, user, dept, device_info,
                     internal_host_ip, dst_ip, 21, "6",
                     "Allow", "Allow_FTP_Internal", "FTP",
                     None, None,
                     "Internal", "1",
                     random.randint(1_000_000, 50_000_000),
                     random.randint(200, 5_000))


# ---------------------------------------------------------------------------
# THREAT WEB GENERATORS
# ---------------------------------------------------------------------------

def _generate_threat_web_traffic(config, user, dept, internal_host_ip, device_info):
    """Blocked malicious web traffic — malware download or C2 callback.

    Returns [DNS precursor, NSSFWlog TCP/80 blocked, NSSWeblog blocked].
    Zscaler logs both a firewall connection event and a web proxy event for
    the same HTTP session; UEBA platforms correlate across both log types.
    """
    zscaler_conf = config.get('zscaler_config', {})
    web_threats = zscaler_conf.get('web_threats', {})
    if not web_threats:
        return None
    threat_name, details = random.choice(list(web_threats.items()))
    malware_details = random.choice(zscaler_conf.get('malware_details', [{"class": "Trojan", "type": "Generic"}]))
    filename = details.get('filename', f"payload_{random.randint(100, 999)}.exe")
    filetype  = details.get('filetype', "Windows Executable")
    dest_ip = _random_external_ip()
    logs = []
    # Log 1: DNS precursor
    logs.append(_dns_precursor_event(config, user, dept, device_info, internal_host_ip))
    # Log 2: NSSFWlog — TCP/80 blocked connection
    logs.append(_fw_event(config, user, dept, device_info,
                          internal_host_ip, dest_ip, 80, "6",
                          "Blocked", "Block_HighRisk_Geo", "HTTP",
                          details.get('category', "Malware"), threat_name,
                          "Unknown", "8",
                          random.randint(200, 2_000), random.randint(300, 1_500)))
    # Log 3: NSSWeblog — web proxy event with full URL/content inspection
    fields = {
        "action": "Blocked",
        "urlcat": details.get('category', "Malware"), "urlsupercat": "Security",
        "urlclass": "Malicious Content",
        "riskscore": str(random.randint(75, 100)),
        "responsecode": "403", "reason": "Policy Block",
        "malwarecat": details.get('category', "Malware"), "threatname": threat_name,
        "threatscore": str(random.randint(75, 100)),
        "malwareclass": malware_details.get('class'), "malwaretype": malware_details.get('type'),
        "reqmethod": "GET",
        "useragent": random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "contenttype": "application/octet-stream",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"http://{details.get('domain', 'malware.example.com')}/{filename}",
        "ehost": details.get('domain', 'malware.example.com'),
        "cip": internal_host_ip, "sip": dest_ip,
        "proto": "HTTP",
        "bytesin":  random.randint(200, 2_000),
        "bytesout": random.randint(300, 1_500),
        "filename": filename, "filetype": filetype,
        "filesize": details.get('filesize', random.randint(50_000, 5_000_000)),
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "8",
    }
    logs.append(_format_nss_log_as_cef(fields, user, dept, 'nssweblog'))
    return logs


def _exfil_destination(config, kind="upload"):
    """Pick a cloud-storage destination from the SHARED 25-entry pool.

    Returns (domain, ip, url).

    Every upload/DLP/download generator here used to hardcode
    `dest_ip = f"104.18.30.{random.randint(1, 254)}"` and draw its domain from
    zscaler_config.exfil_destinations, which holds only TWO entries. So all three threats
    shared one /24 and two domains: LargeUpload reached
    166 destinations, LargeDownload 90, DLP_Block 95 — all inside 104.18.30.0/24 and
    mutually overlapping. Check Point and FortiGate both use
    config['exfiltration_destinations'] instead: 25 entries spanning 352,512 addresses
    across mega/dropbox/box/anonfiles/pastebin/wetransfer/proton, and the Check Point
    "Large Upload (HTTPS)" alerts show that diversity in remote_ip (185.109.146.51,
    205.196.121.147, 162.125.40.246, 154.53.224.128). A detector keying on "rare
    destination" cannot treat 166 addresses in a single /24 as rare, and cannot tell
    upload traffic from download traffic when both resolve into the same block.

    Uploads and downloads draw from disjoint halves of the pool so the two directions
    are distinguishable as destinations.
    """
    dests = config.get('exfiltration_destinations') or []
    if not dests:
        zc = config.get('zscaler_config', {})
        entry = random.choice(zc.get('exfil_destinations')
                             or [{"domain": "drive.google.com"}])
        domain = entry.get('domain', 'drive.google.com')
        return domain, _random_external_ip(), entry.get('url') or f"https://{domain}/upload"
    ordered = sorted(dests, key=lambda d: d.get('domain') or '')
    half    = max(1, len(ordered) // 2)
    pool    = ordered[:half] if kind == "download" else ordered[half:]
    entry   = random.choice(pool or ordered)
    domain  = entry.get('domain') or 'drive.google.com'
    # Some pool entries are wildcard patterns (e.g. "*.digitaloceanspaces.com"). A real log
    # carries a concrete FQDN, never a wildcard, so substitute a plausible label.
    if domain.startswith('*.'):
        domain = random.choice(["files", "cdn", "assets", "static", "data"]) + domain[1:]
    try:
        dest_ip = rand_ip_from_network(ip_network(entry.get('ip_range'), strict=False))
    except Exception:
        dest_ip = _random_external_ip()
    path = "/download" if kind == "download" else "/upload"
    return domain, dest_ip, f"https://{domain}{path}"


def _generate_data_exfil_web_traffic(config, user, dept, internal_host_ip, device_info):
    """Large file upload to cloud storage — data exfiltration (ALLOWED).

    Returns [DNS precursor, NSSFWlog TCP/443 allowed, NSSWeblog allowed].
    """
    zscaler_conf = config.get('zscaler_config', {})
    _exfil_domain, dest_ip, _exfil_url = _exfil_destination(config, "upload")
    exfil_dest = {"url": _exfil_url, "domain": _exfil_domain}
    # 300 MB - 700 MB. "Large Upload (HTTPS)" has fired 85 times for Check Point and never
    # for Zscaler; max xdm.source.sent_bytes on port 443 was 105 MB for
    # Zscaler vs 523-524 MB for Check Point and FortiGate, and the Check Point sessions that
    # actually fired were 300-500 MB (alert text: "uploaded 347.2MB to the external host
    # ... over 1 sessions in the last 24 hours"). 5-100 MB was simply below the threshold.
    file_size_bytes = random.randint(314_572_800, 734_003_200)
    ack_bytes = random.randint(100, 500)
    filename, filetype = _pick_upload_file(random.choice(["archive", "pii", "document"]))
    logs = []
    # Log 1: DNS precursor — carries the resolved domain so the host/domain association
    # exists for rare-domain detectors (it previously resolved nothing).
    logs.append(_dns_precursor_event(config, user, dept, device_info, internal_host_ip,
                                    domain=_exfil_domain))
    # Log 2: NSSFWlog — TCP/443 allowed connection (large upload)
    logs.append(_fw_event(config, user, dept, device_info,
                          internal_host_ip, dest_ip, 443, "6",
                          # nwsvc -> cs3 -> xdm.network.application_protocol. HYPOTHESIS
                          # (unproven): the Check Point alerts that fire Large Upload (HTTPS)
                          # carry app_id 'ip,tcp,ssl', and Zscaler emitted "HTTPS" here and
                          # never "ssl". Cortex appears to derive app_id from the application
                          # protocol, so "SSL" is what the firing vendor presents. "SSL" is a
                          # legitimate Zscaler network-service name, so this costs no
                          # fidelity. If Large Upload (HTTPS) still does not fire after the
                          # byte-volume increase below, revert this to "HTTPS" and rule it out.
                          "Allow", "Allow_Web_Outbound", "SSL",
                          "Data Exfiltration", "LargeUpload",
                          "Unknown", "7",
                          ack_bytes, file_size_bytes,
                          dst_fqdn=_exfil_domain,
                          duration_ms=random.randint(300_000, 1_200_000),
                          url_category="Online Storage and Backup"))
    # Log 3: NSSWeblog — web proxy event
    fields = {
        "action": "Allowed",
        "urlcat": "Online Storage", "urlsupercat": "Productivity and Collaboration",
        "urlclass": "Business and Productivity",
        "riskscore": str(random.randint(40, 70)),
        "responsecode": "201", "reason": "Allowed", "reqmethod": "POST",
        "useragent": random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "appname": "File Transfer", "appclass": "General", "contenttype": "application/zip",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl": exfil_dest.get('url'), "ehost": exfil_dest.get('domain'),
        "cip": internal_host_ip, "sip": dest_ip, "proto": "HTTPS",
        "bytesin": ack_bytes, "bytesout": file_size_bytes,
        # file metadata: cn2=filesize (uploaded file), cn3=totalsize (transaction)
        "filename": filename, "filetype": filetype,
        "filesize": file_size_bytes, "totalsize": file_size_bytes + ack_bytes,
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "7",
    }
    logs.append(_format_nss_log_as_cef(fields, user, dept, 'nssweblog'))
    return logs


def _generate_dlp_web_traffic(config, user, dept, internal_host_ip, device_info):
    """DLP engine triggers block on sensitive data upload.

    Returns [DNS precursor, NSSFWlog TCP/443 blocked, NSSWeblog DLP block] or None.
    """
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
    _exfil_domain, dest_ip, _exfil_url = _exfil_destination(config, "upload")
    exfil_dest = {"url": _exfil_url, "domain": _exfil_domain}
    upload_bytes = random.randint(1000, 50000)
    ack_bytes = random.randint(100, 500)
    # Pick a filename whose type matches the DLP engine that fired.
    _engine_kind = {"Source Code": "source", "PII": "pii"}.get(engine, "document")
    filename, filetype = _pick_upload_file(_engine_kind)
    logs = []
    # Log 1: DNS precursor — carries the resolved domain
    logs.append(_dns_precursor_event(config, user, dept, device_info, internal_host_ip,
                                    domain=_exfil_domain))
    # Log 2: NSSFWlog — TCP/443 blocked
    logs.append(_fw_event(config, user, dept, device_info,
                          internal_host_ip, dest_ip, 443, "6",
                          "Blocked", "Block_DLP_Upload", "HTTPS",
                          "DLP", "DLP_Block",
                          "Unknown", "6",
                          ack_bytes, upload_bytes,
                          dst_fqdn=_exfil_domain,
                          url_category="Online Storage and Backup"))
    # Log 3: NSSWeblog — DLP block with engine details
    fields = {
        "action": "Blocked",
        "urlcat": "Online Storage", "urlsupercat": "Productivity and Collaboration",
        "urlclass": "Business and Productivity",
        "riskscore": str(random.randint(45, 75)),
        "responsecode": "403", "reason": "DLP Block", "reqmethod": "POST",
        "useragent": random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "contenttype": "application/zip",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl": exfil_dest.get('url'), "ehost": exfil_dest.get('domain'),
        "cip": internal_host_ip, "sip": dest_ip, "proto": "HTTPS",
        "bytesin": ack_bytes, "bytesout": upload_bytes,
        # file metadata: cn2=filesize (blocked upload), cn3=totalsize (transaction)
        "filename": filename, "filetype": filetype,
        "filesize": upload_bytes, "totalsize": upload_bytes + ack_bytes,
        "dlpengine": engine, "dlpdictionary": dictionary, "dlprule": rule,
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "6", "event_type": "dlp",
    }
    logs.append(_format_nss_log_as_cef(fields, user, dept, 'nssweblog'))
    return logs


def _generate_cloud_app_control_event(config, user, dept, internal_host_ip, device_info):
    """Cloud Application Control enforcement — block or caution.

    Returns [DNS precursor, NSSFWlog TCP/443, NSSWeblog app control] or None.
    """
    zscaler_conf = config.get('zscaler_config', {})
    policy = zscaler_conf.get('cloud_app_control_policy', [])
    if not policy:
        return None
    app     = random.choice(policy)
    blocked = app.get('action', "Block") in ("Block", "Blocked")
    action_str = "Blocked" if blocked else "Allow"
    dest_ip = f"104.20.10.{random.randint(1, 254)}"
    logs = []
    # Log 1: DNS precursor
    logs.append(_dns_precursor_event(config, user, dept, device_info, internal_host_ip))
    # Log 2: NSSFWlog — TCP/443 connection
    logs.append(_fw_event(config, user, dept, device_info,
                          internal_host_ip, dest_ip, 443, "6",
                          action_str, "Block_CloudApp" if blocked else "Allow_Web_Outbound", "HTTPS",
                          "Cloud Application", app.get('name', 'Unknown App'),
                          "Unknown", "5" if blocked else "2",
                          random.randint(100, 500), random.randint(200, 2_000)))
    # Log 3: NSSWeblog — app control event
    fields = {
        "action": "Blocked" if blocked else "Allowed",
        "urlcat": "Information Technology", "urlsupercat": "Information Technology",
        "urlclass": "Business and Productivity",
        "riskscore": str(random.randint(30, 60)),
        "responsecode": "403" if blocked else "200",
        "reason": f"Cloud App Control: {app.get('name', 'Unknown App')}",
        "reqmethod": "GET", "appname": app.get('name'), "appclass": app.get('class'),
        "contenttype": "text/html",
        "useragent": random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"https://{app.get('name', 'app').lower()}.com",
        "ehost": f"{app.get('name', 'app').lower()}.com",
        "cip": internal_host_ip, "sip": dest_ip, "proto": "HTTPS",
        "bytesin": random.randint(500, 5_000), "bytesout": random.randint(200, 2_000),
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "5" if blocked else "2",
    }
    logs.append(_format_nss_log_as_cef(fields, user, dept, 'nssweblog'))
    return logs


def _generate_sandbox_event(config, user, dept, internal_host_ip, device_info):
    """File blocked after sandbox detonation — definitive malware verdict.

    Returns [DNS precursor, NSSFWlog TCP/80 blocked, NSSWeblog sandbox block] or None.
    """
    zscaler_conf = config.get('zscaler_config', {})
    threats = zscaler_conf.get('sandbox_threats', [])
    if not threats:
        return None
    threat    = random.choice(threats)
    filename  = f"document_{random.randint(1000, 9999)}.{threat.get('type', 'exe').lower()}"
    file_hash = hashlib.md5(f"{filename}{time.time()}".encode()).hexdigest()
    dest_ip = _random_external_ip()
    logs = []
    # Log 1: DNS precursor
    logs.append(_dns_precursor_event(config, user, dept, device_info, internal_host_ip))
    # Log 2: NSSFWlog — TCP/80 blocked
    logs.append(_fw_event(config, user, dept, device_info,
                          internal_host_ip, dest_ip, 80, "6",
                          "Blocked", "Block_Sandbox_Verdict", "HTTP",
                          threat.get('category', "Malware"), threat.get('name', "Unknown"),
                          "Unknown", "10",
                          random.randint(200, 2_000), random.randint(300, 1_500)))
    # Log 3: NSSWeblog — sandbox verdict
    fields = {
        "action": "Blocked",
        "urlcat": "Malicious Content", "urlsupercat": "Security",
        "urlclass": "Malicious Content",
        "riskscore": "100",
        "responsecode": "403", "reason": "Sandbox Verdict",
        "malwarecat": threat.get('category', "Malware"), "threatname": threat.get('name', "Unknown"),
        "threatscore": "100", "malwareclass": "Sandbox", "malwaretype": threat.get('type', "exe"),
        "fileHash": file_hash, "filename": filename, "filetype": threat.get('type', "exe"),
        "filesize": threat.get('filesize', random.randint(20_000, 8_000_000)),
        "reqmethod": "GET",
        "contenttype": "application/octet-stream",
        "useragent": random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"http://download.unsafe-storage.com/{filename}",
        "ehost": "download.unsafe-storage.com",
        "cip": internal_host_ip, "sip": dest_ip,
        "proto": "HTTP",
        "bytesin":  random.randint(200, 2_000),
        "bytesout": random.randint(300, 1_500),
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "10", "event_type": "sandbox",
    }
    logs.append(_format_nss_log_as_cef(fields, user, dept, 'nssweblog'))
    return logs


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

# Destination port -> Zscaler network service (CEF cs3 -> xdm.network.application_protocol).
# The firewall feed identifies the SERVICE being reached, so a probe to 21 is FTP whether
# it was allowed or blocked. Anything not listed returns None and the key is omitted:
# real Zscaler leaves the field out rather than inventing a value, and a synthetic value
# pollutes the application-protocol baseline for that port.
_PORT_SERVICE = {
    21: "FTP",    22: "SSH",     23: "Telnet",  25: "SMTP",    53: "DNS",
    # Remote administration services. Without these three the administrative-behaviour
    # ports resolve to no service at all, so cs3 is omitted and
    # xdm.network.application_protocol lands null on exactly the events the NDR
    # lateral-movement analytics needs an application for.
    69: "TFTP",   512: "REXEC",  992: "TELNETS",
    80: "HTTP",   110: "POP3",   135: "RPC",    139: "NetBIOS", 143: "IMAP",
    389: "LDAP",  443: "HTTPS",  445: "SMB",    465: "SMTPS",  587: "SMTPS",
    636: "LDAPS", 993: "IMAPS",  995: "POP3S",  1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP",  5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
    5986: "WinRM", 8080: "HTTP", 8443: "HTTPS",
}


def _port_service(port):
    """Zscaler network service for a destination port, or None when unclassified."""
    try:
        return _PORT_SERVICE.get(int(port))
    except (TypeError, ValueError):
        return None


def _fw_event(config, user, dept, device_info, src_ip, dst_ip, dst_port, proto,
              action, rule, nwsvc, threat_cat, threat_name, dest_country, sev,
              bytes_in=0, bytes_out=60, event_time_ms=None, src_country=None,
              dst_fqdn=None, duration_ms=None, url_category=None, nwapp=None):
    """Build a single nssfwlog CEF event — used by all firewall scenario generators.

    event_time_ms: optional ms-epoch to back-date the event (sets CEF rt -> XSIAM _time);
                   used by time-spread threats such as impossible travel.
    duration_ms:   session duration. Defaults to a <=5 minute session, which is wrong for
                   any long-lived threat: this was hard-coded at randint(100, 300000) and
                   NO generator could override it, so "long-lived reverse SSH tunnel"
                   reported a 5-minute session. Max xdm.event.duration:
                   Zscaler 299,981 ms vs FortiGate 14,334,000 and Check Point 143,460,000.
                   Both comparison modules pass duration_s=randint(1800, 14400) for the
                   same tunnel threat. Pass an explicit value whenever the session is not
                   a short transaction.
    dst_fqdn:      the destination FQDN, emitted as %s{cdfqdn} ("The client destination
                   FDQN (e.g., the HTTP host header)" -> Insights "Client Destination
                   Name") per Zscaler's NSS Feed Output Format: Firewall Logs. Pass it
                   whenever the generator already knows a domain. Leave it None for pure
                   IP traffic — real Zscaler omits the field rather than echoing the IP,
                   and putting an address in a name field corrupts host/destination
                   entity resolution in XSIAM.
    url_category:  Zscaler URL category, emitted as CEF cs5. The nssfwlog modeling rule
                   uppercases cs5 and derives xdm.network.http.url_category from it via a
                   long substring ladder — "DYNAMIC DNS" -> URL_CATEGORY_DYNAMIC_DNS,
                   "COMMAND AND CONTROL"/"C&C" -> URL_CATEGORY_COMMAND_AND_CONTROL, plus
                   MALWARE, PHISHING, CRYPTO, PROXY/ANONYMIZERS, "ONLINE STORAGE"+"BACKUP",
                   "PEER TO PEER" and ~60 more NO firewall
                   generator set it, so cs5 was 0% on nssfwlog and url_category was
                   empty on every firewall event. Use the literal Zscaler category strings
                   so the substring match actually hits.
    """
    zscaler_conf = config.get('zscaler_config', {})
    # src_country is normally a decorative label (XSIAM geo-resolves srcip itself),
    # but callers that care about the resolved country pass it explicitly so the
    # CEF field and the IP agree — see _generate_vpn_new_country_login.
    if src_country is None:
        src_country = "United States" if _is_internal_ip(src_ip) else random.choice(_THREAT_COUNTRIES)
    fields = {
        "srcip": src_ip, "sport": random.randint(49152, 65535),
        "destip": dst_ip, "destport": dst_port, "proto": proto,
        "action": action, "rulelabel": rule,
        "reason": "Policy Block" if action in ("Block", "Blocked") else "Allowed",
        "threatcat": threat_cat, "threatname": threat_name,
        "destCountry": dest_country,
        "srcCountry": src_country,
        "bytesin": bytes_in, "bytesout": bytes_out,
        "nwsvc": nwsvc, "spriv": "domain users",
        # %s{nwapp} — the specific application. Defaults to the service name, which is
        # what Zscaler's own doc shows for non-web protocols (nwapp example: SSH).
        # Pass it explicitly when the generator knows a real application (a site or
        # SaaS product), matching the vendor sample's nwsvc=HTTP / nwapp=ebay pairing.
        "nwapp": nwapp,
        "urlcat": url_category,          # -> cs5 -> xdm.network.http.url_category
        "duration_ms": random.randint(100, 300000) if duration_ms is None else duration_ms,
        "cefSeverity": sev,
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "destinationTranslatedAddress": dst_ip,
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cdfqdn": dst_fqdn,
    }
    if event_time_ms is not None:
        fields["rt"] = event_time_ms
    return _format_nss_log_as_cef(fields, user, dept, 'nssfwlog')


# ---------------------------------------------------------------------------
# THREAT FIREWALL GENERATORS — single-event
# ---------------------------------------------------------------------------

def _generate_threat_firewall_traffic(config, user, dept, internal_host_ip, device_info):
    """Outbound connection to a suspicious or TOR destination, blocked.

    Returns [DNS precursor, NSSFWlog blocked connection].
    """
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
    logs = [_dns_precursor_event(config, user, dept, device_info, internal_host_ip)]
    logs.append(_fw_event(config, user, dept, device_info,
                     internal_host_ip, dest_ip, dest_port, "6",
                     "Blocked", "Block_HighRisk_Geo", nwsvc,
                     threat_dest.get('category', 'Suspicious'), threat_name,
                     threat_dest.get('country', 'Unknown'), "7",
                     random.randint(40, 200), random.randint(100, 500)))
    return logs


def _generate_tor_connection(config, user, dept, internal_host_ip, device_info):
    """Outbound connection to a known TOR exit node.

    Returns [DNS precursor, NSSFWlog Tor block].
    Port distribution: 443 (60%), 9001 (30%), 9030 (10%).
    """
    print("    - Zscaler Module simulating: TOR Exit Node connection")
    tor_nodes = config.get('tor_exit_nodes', [])
    tor_dest  = random.choice(tor_nodes) if tor_nodes else {"ip": _random_external_ip(), "country": "Unknown"}
    dest_ip   = tor_dest.get("ip") or _random_external_ip()
    dest_port = random.choices([443, 9001, 9030], weights=[60, 30, 10])[0]
    # Tor's ORPort/DirPort carry TLS, so the network SERVICE is SSL. "TOR" is not a
    # Zscaler service name — the Tor attribution belongs in the threat category and
    # threat name below, which already carry it.
    nwsvc_map = {443: "HTTPS", 9001: "SSL", 9030: "SSL"}
    logs = [_dns_precursor_event(config, user, dept, device_info, internal_host_ip)]
    logs.append(_fw_event(config, user, dept, device_info,
                     internal_host_ip, dest_ip, dest_port, "6",
                     "Blocked", "Block_TOR_Traffic", nwsvc_map.get(dest_port, "HTTPS"),
                     "TOR", "TOR Exit Node",
                     tor_dest.get('country', 'Unknown'), "8",
                     random.randint(40, 200), random.randint(100, 500)))
    return logs


def _generate_server_outbound_http(config, user, dept, internal_host_ip, device_info):
    """Internal server initiating outbound HTTP — anomalous.

    Returns [DNS precursor, NSSFWlog HTTP allowed].
    Servers should not initiate HTTP sessions. Allowed because no block rule matches.
    """
    print("    - Zscaler Module simulating: Server Outbound HTTP (anomalous)")
    internal_servers = config.get('internal_servers', [])
    server_ip = random.choice(internal_servers) if internal_servers else _get_random_internal_ip(config)
    logs = [_dns_precursor_event(config, user, dept, device_info, server_ip)]
    logs.append(_fw_event(config, user, dept, device_info,
                     server_ip, _random_external_ip(), 80, "6",
                     "Allow", "Allow_Web_Outbound", "HTTP",
                     "Suspicious Outbound", "ServerOutboundHTTP",
                     "Unknown", "5",
                     random.randint(100, 2000), random.randint(200, 5000)))
    return logs


def _generate_rdp_lateral(config, user, dept, internal_host_ip, device_info):
    """Workstation-to-workstation RDP (port 3389) — lateral movement signal (nssfwlog).

    Generates 3-8 blocked RDP attempts then one successful connection — the attacker
    eventually finds a host where the policy doesn't apply. The blocked-then-success
    pattern triggers XSIAM lateral movement detection.
    Matches the rdp_lateral / workstation_rdp pattern in ASA, Checkpoint, and Firepower.
    Returns a list of CEF log strings.
    """
    print("    - Zscaler Module simulating: RDP Lateral Movement (workstation -> workstation)")
    # Fan out across MANY destinations, not one. Lateral movement is detected from a host
    # reaching hosts it has never spoken to before, so a single destination gives the
    # detector one new edge instead of many. Distinct destinations per
    # burst: Zscaler 1, FortiGate 10, Check Point 7-8 (tenant, 7 d: RDPLateralMovement
    # n=560 across 83 sources and 82 destinations — exactly one dest per source).
    dest_ips = set()
    while len(dest_ips) < random.randint(5, 10):
        cand = _get_random_internal_ip(config)
        if cand != internal_host_ip:
            dest_ips.add(cand)
    dest_ips = sorted(dest_ips)

    # Spread the sweep over time so it reads as a sequence of attempts rather than one
    # instantaneous observation (see the note in _generate_port_scan).
    base_ms = int(time.time() * 1000)
    offset_ms = 0
    logs = []

    # Blocked RDP attempts across every candidate host
    for dest_ip in dest_ips:
        for _ in range(random.randint(1, 3)):
            offset_ms += random.randint(500, 4000)
            logs.append(_fw_event(config, user, dept, device_info,
                                  internal_host_ip, dest_ip, 3389, "6",
                                  "Blocked", "Block_RDP_Lateral", "RDP",
                                  "Lateral Movement", "RDPLateralMovement",
                                  "Internal", "6",
                                  0, random.randint(200, 2_000),
                                  event_time_ms=base_ms + offset_ms,
                                  duration_ms=random.randint(100, 5000)))

    # Final successful RDP connection — attacker finds an allowed path on one host
    offset_ms += random.randint(500, 4000)
    logs.append(_fw_event(config, user, dept, device_info,
                          internal_host_ip, random.choice(dest_ips), 3389, "6",
                          "Allowed", "Allow_Internal_Admin", "RDP",
                          "Lateral Movement", "RDPLateralMovement",
                          "Internal", "5",
                          random.randint(5_000, 50_000), random.randint(5_000, 50_000),
                          event_time_ms=base_ms + offset_ms,
                          duration_ms=random.randint(600_000, 3_600_000)))

    return logs


def _generate_ssh_over_https(config, user, dept, internal_host_ip, device_info):
    """Suspicious outbound SSH or tunneled connection.

    Returns [DNS precursor, NSSFWlog SSH-over-443 or SSH/22 blocked].
    """
    print("    - Zscaler Module simulating: SSH over HTTPS / suspicious SSH tunnel")
    if random.random() < 0.70:
        dest_port, nwsvc, threat_name = 443, "HTTPS", "SSHoverHTTPS"
    else:
        dest_port, nwsvc, threat_name = 22,  "SSH",   "SuspiciousSSH"
    logs = [_dns_precursor_event(config, user, dept, device_info, internal_host_ip)]
    logs.append(_fw_event(config, user, dept, device_info,
                     internal_host_ip, _random_external_ip(), dest_port, "6",
                     "Blocked", "Block_SuspiciousSSH", nwsvc,
                     "Tunneling", threat_name,
                     "Unknown", "7",
                     random.randint(40, 200), random.randint(100, 500)))
    return logs


# ---------------------------------------------------------------------------
# THREAT FIREWALL GENERATORS — multi-event (return list)
# ---------------------------------------------------------------------------

def _generate_port_scan(config, user, dept, internal_host_ip, device_info):
    """Internal host probing many ports on an internal server (nssfwlog).

    Generates 100-200 blocked TCP connections from the same internal host to the same
    internal target across a wide port range, spread over time. Breadth + volume is the
    XSIAM signal. Matches the port_scan pattern in Checkpoint, ASA, and FortiGate.
    Returns a list of CEF log strings.

    THE SOURCE MUST BE INTERNAL — DO NOT change this back to an external attacker IP.
    "Suspicious port scan" profiles the SOURCE entity and alerts on deviation from that
    entity's own baseline, so a freshly-minted random public IP has nothing to deviate
    from and the detector stays silent however many ports are probed. Breadth is not the
    blocker: an externally-sourced scan with the widest port range of any module here
    still fired nothing. If an external-sourced scan is wanted, add it as a separate
    `external_port_scan` threat rather than changing this one.
    """
    print("    - Zscaler Module simulating: Port Scan (internal host -> internal server)")
    scanner_ip      = internal_host_ip or _get_random_internal_ip(config)
    internal_targets = [t for t in (config.get('internal_servers', []) or [])
                        if t != scanner_ip] or [_get_random_internal_ip(config)]
    target_ip       = random.choice(internal_targets)
    # Breadth of distinct destination ports is the signal, so sample widely and keep the
    # well-known services as a guaranteed subset — the scan should read as service
    # discovery, not noise. Sample service ports only (1-1023): the ephemeral range reads
    # as ordinary return traffic rather than enumeration.
    WELL_KNOWN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
                        445, 1433, 1521, 3306, 3389, 5900, 8080, 8443]
    n = random.randint(100, 200)
    extra_ports = random.sample(
        [p for p in range(1, 1024) if p not in WELL_KNOWN_PORTS],
        max(0, n - len(WELL_KNOWN_PORTS)))
    ports_to_scan = sorted(set(WELL_KNOWN_PORTS + extra_ports))
    # Spread the probes over time. Without an explicit event_time the whole loop finishes
    # inside one millisecond bucket, and a scan collapsed to a single instant counts as
    # one observation rather than N.
    base_ms = int(time.time() * 1000)
    offset_ms = 0
    logs = []
    for port in ports_to_scan:
        offset_ms += random.randint(300, 1500)
        # nwsvc must be the SERVICE on the probed port, not the name of the threat.
        # "PortScan" is not a Zscaler network service; emitting it here overwrote FTP on
        # 21, SSH on 22, SMB on 445 and SMTP on 25 with a synthetic value, polluting
        # xdm.network.application_protocol for exactly the ports the app-aware detectors
        # read. The threat name belongs in cs6, which already carries it.
        logs.append(_fw_event(config, user, dept, device_info,
                              scanner_ip, target_ip, port, "6",
                              "Blocked", "Block_PortScan", _port_service(port),
                              "Network Scan", "PortScan",
                              "Unknown", "6",
                              random.randint(40, 60), random.randint(40, 80),
                              event_time_ms=base_ms + offset_ms,
                              duration_ms=random.randint(0, 200)))

    # 1-2 open ports discovered — the scanner finds live services
    open_ports = random.sample([22, 80, 443, 445, 3389, 8080, 8443], k=random.randint(1, 2))
    for port in open_ports:
        offset_ms += random.randint(300, 1500)
        logs.append(_fw_event(config, user, dept, device_info,
                              scanner_ip, target_ip, port, "6",
                              "Allowed", "Allow_Inbound_Services", _port_service(port),
                              # real None (not the string) so the builder omits
                              # cat/cs6 entirely — "None" was landing in XSIAM as a
                              # threat category literally named None.
                              None, None,
                              "Unknown", "3",
                              random.randint(500, 5000), random.randint(500, 5000),
                              event_time_ms=base_ms + offset_ms))
    return logs


def _generate_brute_force(config, user, dept, internal_host_ip, device_info):
    """High-volume blocked connections from same external IP to same service port (nssfwlog).

    Models a brute force attack against SSH, RDP, SMB, or WinRM.
    20-60 events from the same attacker; the volume is the XSIAM detection signal.
    Matches the brute_force / auth_brute_force pattern across all other modules.
    Returns a list of CEF log strings.
    """
    print("    - Zscaler Module simulating: Brute Force (external -> internal service)")
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
                              "Blocked", "Block_BruteForce", nwsvc,
                              "Brute Force Attack", threat_name,
                              "Unknown", "7",
                              random.randint(100, 500), random.randint(40, 200)))
    return logs


_beacon_target_map: dict = {}   # internal_host_ip -> stable C2 resolver for recurring-rare-IP detection


def _generate_dns_c2_beacon(config, user, dept, internal_host_ip, device_info):
    """Repeated DNS queries (UDP/53) to a suspicious external resolver — C2 beacon pattern.

    15-40 ALLOWED events to the same external IP. The volume of allowed queries
    to a consistent suspicious resolver is the XSIAM UEBA detection signal, NOT
    a single blocked event. Matches dns_c2_beacon in all other modules.
    Returns a list of CEF log strings.
    """
    print("    - Zscaler Module simulating: DNS C2 Beacon (volume DNS to suspicious resolver)")
    # Stable resolver per source so successive runs recur to the same rare IP
    # (the recurring-rare-IP detection signal), not random noise.
    resolver_ip = _beacon_target_map.get(internal_host_ip)
    if not resolver_ip:
        suspicious_resolvers = (
            [_random_external_ip() for _ in range(3)] +
            ["91.108.4.1", "176.10.104.240", "185.220.101.1"]
        )
        resolver_ip = random.choice(suspicious_resolvers)
        _beacon_target_map[internal_host_ip] = resolver_ip
    n_queries   = random.randint(15, 40)
    # A beacon is defined by its CADENCE, so the queries must carry distinct timestamps
    # spread over a realistic window. Previously every event called time.time() inside one
    # millisecond bucket, so 15-40 queries collapsed to a single _time. Recurrence
    # detectors then see one observation instead of a tempo. Check Point accumulates an
    # explicit offset for exactly this reason.
    base_ms  = int(time.time() * 1000)
    interval = random.randint(45, 120) * 1000      # steady beacon tempo
    jitter   = int(interval * 0.08)
    logs = []
    for _i in range(n_queries):
        logs.append(_fw_event(config, user, dept, device_info,
                              internal_host_ip, resolver_ip, 53, "17",
                              "Allow", "Allow_DNS_Outbound", "DNS",
                              "N/A", "SuspiciousDNS",
                              "Unknown", "4",
                              random.randint(64, 256), random.randint(32, 128),
                              event_time_ms=base_ms - (n_queries - 1 - _i) * interval
                                            + random.randint(-jitter, jitter),
                              duration_ms=random.randint(1, 500),
                              url_category="Command and Control"))
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


# Rare-SMB peer bookkeeping: "smbrare::<src_ip>" -> list of peers this host has already
# used. Same in-memory idiom as _beacon_target_map / "revssh::" (deliberately NOT
# persisted to disk — single-session operation is the assumption), and deliberately NOT
# seeded from hash(): CPython salts str hashing per process, so a hash-derived "sticky"
# value re-rolls on every restart.
_smb_rare_peer_map: dict = {}

# Quiet internal /24s that are the SMB destination of nothing else in the estate. They
# sit outside config['internal_networks'], so the two fan-out SMB generators
# (share_enumeration, new_host_lateral) draw random targets from a pool that cannot
# collide with these — which is what keeps every peer allocated here at an SMB fan-in of
# 1. Four /24s give ~1,012 peers before wraparound.
_SMB_RARE_SERVER_NETS = ["192.168.4.0/24", "192.168.5.0/24",
                         "192.168.6.0/24", "192.168.7.0/24"]

# Peers handed out across ALL source hosts. Allocation must be globally unique, not
# per-host: birthday collisions inside a 253-host /24 otherwise give some peers a fan-in
# of 2, weakening the "destination rarely receives SMB from other hosts" half of the
# shape. Global allocation pins fan-in at exactly 1.
_smb_rare_peers_taken: set = set()

# Alternates the rare session between TCP/139 and TCP/445 (see the port-choice note in
# _generate_smb_rare_file_transfer). A list rather than a module-level int so it can be
# appended to from inside the generator without a `global` declaration.
_smb_rare_port_toggle: list = []

# Real workstation IPs this generator has been invoked for, used as the preferred pool of
# rare SMB peers. The detector profiles the destination as a host as well as the source,
# and an invented address that appears nowhere else in the estate may never resolve to a
# profiled host entity at all. Drawing the peer from hosts that genuinely appear as
# traffic sources elsewhere gives the destination a real identity. Naming the peer in the
# log is not an available substitute: xdm.target.host.hostname is ~0% on all five
# firewall feeds and nssfwlog's cdfqdn maps to no target-host XDM field.
_smb_known_internal_hosts: set = set()


def _next_rare_smb_peer(src_ip, prefer_known_host=False):
    """Allocate a globally NEVER-BEFORE-USED rare SMB peer for this source host.

    Grows the host's SMB destination set by exactly ONE per invocation. That is the
    shape the "Rare SMB session to a remote host" detector describes: the host stays a
    rare SMB *initiator* (fan-out of 1-3, not the 15-69 the fan-out generators produce),
    while each newly allocated peer is a rare SMB *receiver* reached by this one host and
    nothing else. Verbatim detector text: "This host is rarely seen initiating SMB
    sessions to other hosts. The destination host is also rarely seen receiving SMB
    connections from other hosts in the network In the past 30 days".

    prefer_known_host: draw the peer from hosts this module has actually generated traffic
                       for, so the destination is a real entity rather than an address that
                       exists in three log lines and nowhere else. Falls back to a quiet-
                       band address until enough real hosts have been observed.
    """
    used = _smb_rare_peer_map.setdefault("smbrare::%s" % src_ip, [])
    if prefer_known_host:
        pool = [h for h in _smb_known_internal_hosts
                if h != src_ip and h not in _smb_rare_peers_taken and h not in used]
        # Require a warm pool, else the first few invocations would all collide on the
        # handful of hosts seen so far and drive their fan-in above 1.
        if len(_smb_known_internal_hosts) >= 12 and pool:
            cand = random.choice(pool)
            _smb_rare_peers_taken.add(cand)
            used.append(cand)
            return cand
    for _ in range(256):
        try:
            net  = ip_network(random.choice(_SMB_RARE_SERVER_NETS), strict=False)
            cand = rand_ip_from_network(net)
        except Exception:
            cand = "192.168.%d.%d" % (random.randint(4, 7), random.randint(2, 254))
        if cand not in _smb_rare_peers_taken and cand != src_ip:
            _smb_rare_peers_taken.add(cand)
            used.append(cand)
            return cand
    # Pool exhausted (>1,000 sessions in one process). Fall back to any unused-by-this-
    # host address rather than looping forever; fan-in may reach 2 for these.
    cand = "192.168.%d.%d" % (random.randint(4, 7), random.randint(2, 254))
    used.append(cand)
    return cand


def _generate_smb_rare_file_transfer(config, user, dept, internal_host_ip, device_info):
    """A RARE SMB session from a workstation to a seldom-used internal server.

    Targets the analytics detector "Rare SMB session to a remote host" ("The endpoint
    performed a rare SMB activity to a remote host", TA0008 / T1021, category Lateral
    Movement, DT:NDR Lateral Movement Analytics).

    The detector needs TWO rarity conditions at once: the SOURCE rarely initiates SMB,
    AND the DESTINATION rarely receives it. Each is easy to satisfy alone and their
    intersection is not — pointing this generator at config['internal_servers'] gave a
    rare initiator but a destination with heavy fan-in, while the fan-out generators
    (share_enumeration, new_host_lateral) give rare destinations but sources with a
    fan-out of 11-69. A per-host sticky peer in an estate-wide-unused /24 creates the
    missing intersection: fan-out 1-3 AND fan-in 1 on the same session.

    Emits ONE session as 3 flows to the SAME peer, so the pipeline sees a session rather
    than an isolated packet while the destination count stays at 1. Breadth belongs to
    the sibling detector "Abnormal SMB activity to multiple hosts", not here.

    NOTE: this shape has not been observed to fire. See the project memory on network
    analytics tuning before investing further in it.

    Returns list of CEF log strings (nssfwlog).
    """
    print("    - Zscaler Module simulating: SMB Rare Session to a rare remote host")
    # NB: the peer is allocated further down, AFTER the prior-history guard. Allocating it
    # here instead silently disabled that guard, because _next_rare_smb_peer() creates the
    # host's map entry via setdefault() and the guard tests that same entry for emptiness.
    _smb_known_internal_hosts.add(internal_host_ip)   # real host, usable as a peer later
    file_size  = random.randint(104_857_600, 1_073_741_824)  # 100 MB – 1 GB
    # Byte direction: _fw_event takes (bytes_in, bytes_out) and the modeling rule maps
    # xdm.source.sent_bytes = to_integer(out). DO NOT re-invert — the staging volume must
    # stay in bytes_out or it never reaches the field the upload analytics read.
    #
    # Explicit per-flow event_time_ms: without it every flow calls time.time() inside the
    # same millisecond and the session collapses to a single _time bucket, so recurrence
    # logic sees one observation instead of a session.
    base_ms = int(time.time() * 1000) - random.randint(12, 25) * 60_000
    logs = []
    # Decided before the history block so the back-dated baseline and today's rare session
    # sit on the SAME port — a host whose history is on 445 but whose new session is on 139
    # presents two unrelated profiles rather than one thin, coherent SMB record.
    _smb_rare_port_toggle.append(1)
    dst_port = 139 if len(_smb_rare_port_toggle) % 2 else 445

    # --- thin, multi-day PRIOR SMB history, emitted once per host -----------------
    # A host with an EMPTY SMB history is unknown to the profiler, not "rare" — the
    # detector describes a host "rarely seen initiating SMB sessions", which presupposes
    # it has been seen at all. So on a host's first invocation, back-date a few short
    # sessions to ONE established share across earlier days, then do today's session to a
    # brand-new peer. Fan-out becomes 2 (still firmly rare) and the host reads as "known,
    # rarely does SMB" rather than "never seen doing SMB".
    if not _smb_rare_peer_map.get("smbrare::%s" % internal_host_ip):
        home_share = _next_rare_smb_peer(internal_host_ip)
        for day in (9, 7, 5, 3, 2):
            day_ms = (int(time.time() * 1000) - day * 86_400_000
                      + random.randint(-4, 4) * 3_600_000
                      + random.randint(0, 59) * 60_000)
            logs.append(_fw_event(config, user, dept, device_info,
                                  internal_host_ip, home_share, dst_port, "6",
                                  "Allow", "Allow_Internal_SMB", "SMB",
                                  None, None,
                                  "Internal", "1",
                                  random.randint(2_000, 40_000),
                                  random.randint(1_000, 30_000),
                                  event_time_ms=day_ms,
                                  duration_ms=random.randint(2_000, 90_000)))

    # --- today's RARE session to a peer nothing has ever contacted ----------------
    # Port choice: every alert this detector has been observed to produce was on
    # remote_port 139 (NetBIOS Session Service), never 445, whereas every firing of the
    # breadth sibling ("Abnormal SMB activity to multiple hosts") was on 445. Alternate
    # 139/445 per invocation: 139 reproduces the only shape observed to fire, 445 keeps
    # the variant the rest of the estate uses, and whichever fires is attributable from
    # the alert's remote_port. Both are well-known ports — 49152+ reads as return traffic.
    # prefer_known_host: make the peer a host that exists elsewhere in the feed, so the
    # destination can be profiled as an entity (see _smb_known_internal_hosts). The
    # back-dated home_share above stays synthetic — a routine file share, not a workstation.
    dst_ip = _next_rare_smb_peer(internal_host_ip, prefer_known_host=True)
    flows = [
        # tree connect / negotiate, then the bulk read, then session teardown
        (random.randint(600, 2_400),   random.randint(400, 1_800), random.randint(200, 900)),
        (random.randint(1_000, 50_000), file_size,                 random.randint(300_000, 1_200_000)),
        (random.randint(300, 1_500),   random.randint(200, 1_200), random.randint(100, 600)),
    ]
    for i, (b_in, b_out, dur) in enumerate(flows):
        logs.append(_fw_event(config, user, dept, device_info,
                              internal_host_ip, dst_ip, dst_port, "6",
                              "Allow", "Allow_Internal_SMB", "SMB",
                              "Lateral Movement", "SMBRareSession",
                              "Internal", "7",
                              b_in, b_out,
                              event_time_ms=base_ms + i * random.randint(45_000, 90_000),
                              duration_ms=dur))
    return logs


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
                              random.randint(100, 500), random.randint(500, 5_000)))
    return logs


# ---------------------------------------------------------------------------
# RARE-RDP peer bookkeeping — same idiom as the rare-SMB block above
# ---------------------------------------------------------------------------
# "rdprare::<src_ip>" -> peers this host has already reached on 3389. In memory only,
# by design (single-session operation), and deliberately NOT seeded from hash(): CPython
# salts str hashing per process, so a hash-derived "sticky" value re-rolls on restart.
_rdp_rare_peer_map: dict = {}

# Quiet internal /24s that receive RDP from nothing else in the estate. They sit outside
# config['internal_networks'], so _generate_rdp_lateral — which draws its 5-10 targets
# from those networks — cannot collide with them, and they are disjoint from
# _SMB_RARE_SERVER_NETS so the two rare-session shapes never share a peer.
_RDP_RARE_SERVER_NETS = ["192.168.12.0/24", "192.168.13.0/24",
                         "192.168.14.0/24", "192.168.15.0/24"]

# Peers handed out across ALL source hosts. Allocation must be globally unique, not
# per-host: birthday collisions inside a 253-host /24 otherwise give some peers an RDP
# fan-in of 2, which breaks the "destination rarely receives RDP" half of the shape.
_rdp_rare_peers_taken: set = set()

# Real workstation IPs this generator has been invoked for, used as the preferred pool of
# rare RDP peers. The detector profiles the destination as a host as well as the source,
# and an address that appears nowhere else in the estate may never resolve to a profiled
# entity. Drawing the peer from hosts that genuinely appear as traffic sources elsewhere
# gives the destination a real identity.
_rdp_known_internal_hosts: set = set()


def _next_rare_rdp_peer(src_ip, prefer_known_host=False):
    """Allocate a globally NEVER-BEFORE-USED rare RDP peer for this source host.

    Grows the host's RDP destination set by exactly ONE per invocation, which is the
    shape the detector describes: the source stays a rare RDP initiator while each newly
    allocated peer is a rare RDP receiver reached by this one host and nothing else.

    prefer_known_host: draw the peer from hosts this module has actually generated traffic
                       for, so the destination is a real entity rather than an address that
                       exists in three log lines and nowhere else. Falls back to a quiet-
                       band address until enough real hosts have been observed.
    """
    used = _rdp_rare_peer_map.setdefault("rdprare::%s" % src_ip, [])
    if prefer_known_host:
        pool = [h for h in _rdp_known_internal_hosts
                if h != src_ip and h not in _rdp_rare_peers_taken and h not in used]
        # Require a warm pool, else the first few invocations all collide on the handful
        # of hosts seen so far and drive their fan-in above 1.
        if len(_rdp_known_internal_hosts) >= 12 and pool:
            cand = random.choice(pool)
            _rdp_rare_peers_taken.add(cand)
            used.append(cand)
            return cand
    for _ in range(256):
        try:
            net  = ip_network(random.choice(_RDP_RARE_SERVER_NETS), strict=False)
            cand = rand_ip_from_network(net)
        except Exception:
            cand = "192.168.%d.%d" % (random.randint(12, 15), random.randint(2, 254))
        if cand not in _rdp_rare_peers_taken and cand != src_ip:
            _rdp_rare_peers_taken.add(cand)
            used.append(cand)
            return cand
    # Pool exhausted (>1,000 sessions in one process). Fall back to any address this host
    # has not used rather than looping forever; fan-in may reach 2 for these.
    cand = "192.168.%d.%d" % (random.randint(12, 15), random.randint(2, 254))
    used.append(cand)
    return cand


def _generate_rdp_rare_session(config, user, dept, internal_host_ip, device_info):
    """A RARE internal RDP session from a seldom-seen workstation to a seldom-used host.

    Targets "Abnormal RDP session to a remote host from a rarely seen host" (category
    Lateral Movement, DT:NDR Lateral Movement Analytics). That detector needs THREE
    rarity conditions at once: the source host is rarely observed, the RDP pattern is
    abnormal for the network segment, and the destination rarely RECEIVES RDP from other
    hosts. Each is easy alone and the intersection is not — _generate_rdp_lateral fans out
    to 5-10 destinations, which makes its source a frequent RDP initiator and its targets
    ordinary members of the estate's RDP mesh.

    This generator produces the intersection instead, reusing the rare-SMB idiom: a
    per-host sticky peer drawn from a band nothing else reaches on 3389, so the session has
    an RDP fan-out of 1-2 and an RDP fan-in of exactly 1 at the same time. Do NOT point it
    at config['internal_networks'] or config['internal_servers'] — both are already dense
    RDP destinations and the fan-in condition is lost.

    Emits ONE session as 3 flows to the SAME peer so the pipeline sees a session rather
    than an isolated packet while the destination count stays at 1. Breadth belongs to the
    sibling shape in _generate_rdp_lateral, not here.

    Returns list of CEF log strings (nssfwlog).
    """
    print(f"    - Zscaler Module simulating: Rare RDP Session from {internal_host_ip} (rarely seen host)")
    # NB: the peer is allocated AFTER the prior-history guard below. Allocating it here
    # silently disables that guard, because _next_rare_rdp_peer() creates the host's map
    # entry via setdefault() and the guard tests that same entry for emptiness.
    _rdp_known_internal_hosts.add(internal_host_ip)   # real host, usable as a peer later

    # Explicit per-flow event_time_ms throughout: without it every flow calls time.time()
    # inside the same millisecond and the whole session collapses into one _time bucket,
    # so recurrence logic sees a single observation instead of a session.
    logs = []

    # --- thin, multi-day PRIOR RDP history, emitted once per host -------------------
    # A host with an EMPTY RDP history is unknown to the profiler, not "rarely seen" — the
    # detector describes a host that HAS been observed, just seldom. On a host's first
    # invocation, back-date a couple of short sessions to ONE established peer across
    # earlier days, then do today's session to a brand-new one. RDP fan-out becomes 2,
    # still firmly rare, and the host reads as "known, hardly ever does RDP".
    if not _rdp_rare_peer_map.get("rdprare::%s" % internal_host_ip):
        home_peer = _next_rare_rdp_peer(internal_host_ip)
        for day in (11, 6, 3):
            day_ms = (int(time.time() * 1000) - day * 86_400_000
                      + random.randint(-4, 4) * 3_600_000
                      + random.randint(0, 59) * 60_000)
            logs.append(_fw_event(config, user, dept, device_info,
                                  internal_host_ip, home_peer, 3389, "6",
                                  "Allow", "Allow_Internal_Admin", _port_service(3389),
                                  None, None,
                                  "Internal", "1",
                                  random.randint(20_000, 200_000),
                                  random.randint(10_000, 90_000),
                                  event_time_ms=day_ms,
                                  duration_ms=random.randint(120_000, 900_000)))

    # --- today's RARE session to a peer nothing has ever RDP'd to --------------------
    # prefer_known_host: make the peer a host that exists elsewhere in the feed so the
    # destination can be profiled as an entity. The back-dated home_peer above stays
    # synthetic — an established jump box, not a workstation.
    dst_ip  = _next_rare_rdp_peer(internal_host_ip, prefer_known_host=True)
    base_ms = int(time.time() * 1000) - random.randint(20, 40) * 60_000
    # Interactive RDP: a short negotiation, a long screen-data session, then teardown.
    flows = [
        (random.randint(1_200, 4_000),   random.randint(800, 3_000),      random.randint(1_000, 6_000)),
        (random.randint(200_000, 900_000), random.randint(40_000, 500_000), random.randint(600_000, 3_600_000)),
        (random.randint(2_000, 12_000),  random.randint(1_000, 6_000),    random.randint(2_000, 20_000)),
    ]
    for i, (b_in, b_out, dur) in enumerate(flows):
        logs.append(_fw_event(config, user, dept, device_info,
                              internal_host_ip, dst_ip, 3389, "6",
                              "Allow", "Allow_Internal_Admin", _port_service(3389),
                              "Lateral Movement", "RDPRareSession",
                              "Internal", "7",
                              b_in, b_out,
                              event_time_ms=base_ms + i * random.randint(60_000, 150_000),
                              duration_ms=dur))
    return logs


# ---------------------------------------------------------------------------
# ADMINISTRATIVE-BEHAVIOUR ANALYTICS SUPPORT
# ---------------------------------------------------------------------------
# Destination ports the detector actually COUNTS as an administrative action. Measured
# against the tenant: 22 and 69 count reliably, 512 was never counted on any feed and 992
# counts on some feeds and not others. So 22/69 carry the budget and the other two are
# emitted only for fidelity with the port set the alert reports — never counted on as
# contributing to the threshold. A burst spread evenly over all four wastes most of itself.
# TFTP is emitted over TCP here rather than its real-world UDP: that is what the feeds
# observed to fire this detector carry, and matching them matters more than protocol purity.
_ADMIN_COUNTED_PORTS  = [22, 69]
_ADMIN_FIDELITY_PORTS = [512, 992]
_ADMIN_SERVICE_PORTS  = _ADMIN_COUNTED_PORTS + _ADMIN_FIDELITY_PORTS

# Dedicated internal management segment for administrative sessions. 172.19.0.0/16 is
# RFC1918 (so _is_internal_ip and XSIAM both read the destinations as internal) and carries
# no traffic at all on any feed in this estate, which is what keeps every (destination,
# port) pair here genuinely first-seen. It also sits OUTSIDE config['internal_networks'],
# so no other generator in this module can draw an address from it by accident, and it is
# disjoint from the management segments the Check Point and FortiGate modules reserve —
# novelty appears to be scored estate-wide per (destination, port), not per source host,
# so an overlapping segment would burn another module's pairs as well as its own.
_ADMIN_SEGMENT_PREFIX = "172.19"
_ADMIN_SEGMENT_BASE3  = 0            # full /16
_ADMIN_SEGMENT_SPAN   = 256 * 256    # addresses available in the segment
_ADMIN_BLOCK_SIZE     = 24           # addresses reserved per invocation

# In-memory only, by design: single-session operation, no disk persistence.
_admin_block_cursor = None

# "admin::<src_ip>" -> (destination, port) pairs this host has already used, so a repeat
# invocation on the same workstation still contributes only NEW pairs.
_admin_pair_map: dict = {}


def _next_admin_targets(count):
    """Reserve `count` internal destinations not yet used on an administrative port.

    The detector counts FIRST-SEEN (destination, administrative port) pairs, so a generator
    that reuses destinations exhausts itself after one run — which is exactly how this
    shape went quiet before: admin-port traffic only ever reached the 25 addresses in
    config['internal_servers'], and every pair there was used up.

    The cursor never moves backwards and is floored at the current hour, so it keeps pace
    with the wall clock and a restart resumes ahead of any block a previous run spent in an
    earlier hour. Hour granularity is deliberate: the segment holds enough blocks for ~114
    days before wrapping, comfortably longer than the detector's lookback, whereas a finer
    slot would wrap inside it.
    """
    global _admin_block_cursor
    hour_slot = int(time.time() // 3600)
    if _admin_block_cursor is None or _admin_block_cursor < hour_slot:
        _admin_block_cursor = hour_slot
    block = _admin_block_cursor
    _admin_block_cursor += 1

    targets = []
    for i in range(count):
        idx = (block * _ADMIN_BLOCK_SIZE + i) % _ADMIN_SEGMENT_SPAN
        targets.append("%s.%d.%d" % (_ADMIN_SEGMENT_PREFIX,
                                     _ADMIN_SEGMENT_BASE3 + (idx // 256), idx % 256))
    return targets


def _admin_port_sequence(count):
    """Port list of length `count`, all on ports the detector actually counts.

    Returns `count` entries drawn only from _ADMIN_COUNTED_PORTS. The fidelity ports are
    appended by the caller as extra sessions rather than taken out of this budget, so the
    counted total never drops when they are included.
    """
    return [random.choice(_ADMIN_COUNTED_PORTS) for _ in range(count)]


def _generate_new_admin_behavior(config, user, dept, internal_host_ip, device_info):
    """One workstation opens administrative sessions to many NEW internal destinations.

    Targets "New Administrative Behavior" (category Lateral Movement, DT:NDR Lateral
    Movement Analytics). The detector profiles, per source host, the set of (destination,
    administrative port) pairs that host has used before, and alerts when the number of
    previously unseen pairs inside a 12-HOUR window is uncharacteristically high for that
    host — the reported threshold shape is 7 new actions. Breadth over new destinations
    inside a short window is the whole signal: repeating a destination the host already
    reached counts for nothing, and the same breadth spread thinly across weeks does not
    count either.

    Emits 14-16 accepted sessions on the ports that actually count (SSH and TFTP) plus two
    on rexec/telnets for fidelity with the port set the alert reports, each to a
    destination from the reserved management segment that nothing in the estate has ever
    reached on an administrative port, spread over 1-2 hours so the burst never lands on a
    single timestamp. The count deliberately sits at roughly twice the reported threshold:
    a burst sized to the threshold exactly leaves no margin for sessions the detector
    declines to count, which is the observed failure mode for this shape.

    THE SOURCE MUST BE AN INTERNAL HOST WITH ITS OWN BASELINE. The detector alerts on
    deviation from that host's profile, so a freshly minted address has nothing to deviate
    from. The back-dated block below gives a first-seen workstation a thin prior record of
    routine administration, so today's burst reads as a deviation rather than as the only
    thing ever known about the host.

    Returns list of CEF log strings (nssfwlog).
    """
    print(f"    - Zscaler Module simulating: New Administrative Behavior from {internal_host_ip}")
    used_pairs = _admin_pair_map.setdefault("admin::%s" % internal_host_ip, set())
    logs = []

    # --- thin, multi-day ROUTINE administration, emitted once per host --------------
    # One jump host reached on SSH across earlier days. Two pairs total, so the host's
    # normal rate of NEW administrative actions is well under one per 12 hours.
    if not used_pairs:
        jump_hosts = _next_admin_targets(1)
        for day in (12, 8, 5, 2):
            day_ms = (int(time.time() * 1000) - day * 86_400_000
                      + random.randint(-3, 3) * 3_600_000
                      + random.randint(0, 59) * 60_000)
            logs.append(_fw_event(config, user, dept, device_info,
                                  internal_host_ip, jump_hosts[0], 22, "6",
                                  "Allow", "Allow_Internal_Admin", _port_service(22),
                                  None, None,
                                  "Internal", "1",
                                  random.randint(4_000, 60_000),
                                  random.randint(2_000, 40_000),
                                  event_time_ms=day_ms,
                                  duration_ms=random.randint(30_000, 600_000)))
        used_pairs.add((jump_hosts[0], 22))

    # --- today's burst of NEW (destination, administrative port) pairs ---------------
    # Counted sessions first, then one session per fidelity port on its own fresh
    # destination. Every destination is distinct, so no pair can repeat inside the burst.
    n_counted  = random.randint(14, 16)
    n_sessions = n_counted + len(_ADMIN_FIDELITY_PORTS)
    targets    = _next_admin_targets(n_sessions)
    ports      = _admin_port_sequence(n_counted) + list(_ADMIN_FIDELITY_PORTS)

    # A second operator account on part of the run: administrative sweeps are usually run
    # under a shared or secondary credential rather than one identity, and the detector
    # reports the account set it observed.
    alt_user = None
    users_map = (config.get(CONFIG_KEY, {}).get('user_ip_map')
                 or config.get('shared_user_ip_map', {}))
    candidates = [u for u in users_map if u != user]
    if candidates:
        alt_user = random.choice(candidates)

    # Span the burst over 1-2 hours: comfortably inside the detector's 12-hour window,
    # and never collapsed onto one millisecond the way an un-timestamped loop would be.
    span_ms   = random.randint(70, 140) * 60_000
    base_ms   = int(time.time() * 1000) - span_ms
    step_ms   = span_ms // max(n_sessions, 1)
    for i, (dest_ip, port) in enumerate(zip(targets, ports)):
        if (dest_ip, port) in used_pairs:
            continue
        used_pairs.add((dest_ip, port))
        ev_user  = alt_user if (alt_user and random.random() < 0.3) else user
        duration = random.randint(20_000, 900_000)
        logs.append(_fw_event(config, ev_user, dept, device_info,
                              internal_host_ip, dest_ip, port, "6",
                              # nwsvc must be the SERVICE on the port, never the threat
                              # name — a synthetic value pollutes the application-protocol
                              # baseline for exactly the ports this detector reads.
                              "Allow", "Allow_Internal_Admin", _port_service(port),
                              "Lateral Movement", "NewAdminBehavior",
                              "Internal", "6",
                              random.randint(2_000, 250_000),
                              random.randint(2_000, 90_000),
                              event_time_ms=base_ms + i * step_ms + random.randint(0, 45_000),
                              duration_ms=duration))
    return logs


# ---------------------------------------------------------------------------
# VPN / REMOTE ACCESS GENERATORS — Zscaler ZPA / RA-VPN via cloud firewall
# ---------------------------------------------------------------------------

def _generate_vpn_brute_force(config, user, dept, internal_host_ip, device_info):
    """External IP repeatedly failing VPN/ZPA authentication — brute force (nssfwlog).

    Generates 20-50 blocked TCP/443 connection events from a single external
    attacker to the Zscaler cloud connector / RA-VPN gateway. Volume of failed
    attempts from one source is the XSIAM detection signal.

    Returns list of CEF log strings (multi-event).
    """
    print("    - Zscaler Module simulating: VPN Brute Force (external credential-stuffing)")
    attacker_ip = _random_external_ip()
    zscaler_conf = config.get('zscaler_config', {})
    gateway_ip = zscaler_conf.get('vpn_gateway_ip',
                     random.choice(config.get('internal_servers', ['10.0.10.1'])))
    n_attempts = random.randint(20, 50)
    logs = []
    for _ in range(n_attempts):
        logs.append(_fw_event(config, user, dept, device_info,
                              attacker_ip, gateway_ip, 443, "6",
                              "Blocked", "Block_VPN_BruteForce", "HTTPS",
                              "Brute Force Attack", "VPN_BruteForce",
                              "Unknown", "7",
                              random.randint(100, 400), random.randint(200, 800)))
    return logs


def _generate_vpn_impossible_travel(config, user, dept, internal_host_ip, device_info):
    """Same user: FAILED then SUCCESSFUL VPN/ZPA auth from two distant IPs (nssfwlog).

    The XSIAM UEBA impossible-travel detector fires on a failed-then-succeeded auth
    pattern (compromised creds) in EACH location — not on bare successful sessions. So
    each of the two geos emits several Blocked auth attempts (door-knocking) followed
    by an Allowed VPN session. Same user; the benign location is back-dated 5-10 min
    (via rt) so the two successes sit an impossible distance apart in time.

    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Zscaler Module simulating: VPN Impossible Travel (door-knock + success x2 geos) for {user}")
    zscaler_conf = config.get('zscaler_config', {})
    gateway_ip = zscaler_conf.get('vpn_gateway_ip',
                     random.choice(config.get('internal_servers', ['10.0.10.1'])))
    benign_loc     = config.get('impossible_travel_scenario', {}).get('benign_location', {})
    suspicious_loc = config.get('impossible_travel_scenario', {}).get('suspicious_location', {})
    benign_ip      = benign_loc.get('ip', '68.185.12.14')
    suspicious_ip  = suspicious_loc.get('ip', '175.45.176.10')

    now_ms = int(time.time() * 1000)
    gap_ms = random.randint(5, 10) * 60 * 1000

    logs = []
    for vpn_src_ip, country, base_offset in [
        (benign_ip,     "United States",                 -gap_ms),
        (suspicious_ip, random.choice(_THREAT_COUNTRIES), 0),
    ]:
        n_fails = random.randint(3, 5)
        for i in range(n_fails):     # door-knocking: blocked auth attempts
            logs.append(_fw_event(config, user, dept, device_info,
                                  vpn_src_ip, gateway_ip, 443, "6",
                                  "Blocked", "Block_VPN_AuthFail", "HTTPS",
                                  "Authentication", "VPN_AuthFailed",
                                  country, "5",
                                  random.randint(100, 400), random.randint(200, 800),
                                  event_time_ms=now_ms + base_offset + i * 3000))
        # successful session after the failures — the pattern the detector fires on
        logs.append(_fw_event(config, user, dept, device_info,
                              vpn_src_ip, gateway_ip, 443, "6",
                              "Allow", "Allow_VPN_Access", "HTTPS",
                              "N/A", "VPN_Session",
                              country, "3",
                              random.randint(100_000, 2_000_000), random.randint(50_000, 500_000),
                              event_time_ms=now_ms + base_offset + n_fails * 3000))
    return logs


def _generate_vpn_tor_login(config, user, dept, internal_host_ip, device_info):
    """Successful VPN/ZPA session from a known TOR exit node IP.

    Returns [TLS handshake, VPN auth success, 1-3 post-auth internal connections].
    Full conversation: Tor IP negotiates TLS, authenticates to VPN, then the
    VPN-assigned IP accesses internal resources (SMB, RDP, HTTPS, SSH).
    """
    print(f"    - Zscaler Module simulating: VPN Login from TOR Exit Node for {user}")
    zscaler_conf = config.get('zscaler_config', {})
    gateway_ip = zscaler_conf.get('vpn_gateway_ip',
                     random.choice(config.get('internal_servers', ['10.0.10.1'])))
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
    tor_ip = tor_vpn_ip(config, default=_random_external_ip())
    # VPN-assigned inside IP (typical ZPA/AnyConnect pool: 10.250.x.x)
    vpn_pool_net = zscaler_conf.get('vpn_pool', '10.250.0.0/16')
    try:
        vpn_inside_ip = rand_ip_from_network(ip_network(vpn_pool_net, strict=False))
    except Exception:
        vpn_inside_ip = f"10.250.{random.randint(1,254)}.{random.randint(1,254)}"
    logs = []
    # Log 1: Inbound TLS handshake (Tor IP -> gateway:443)
    logs.append(_fw_event(config, user, dept, device_info,
                     tor_ip, gateway_ip, 443, "6",
                     "Allow", "Allow_VPN_TLS", "HTTPS",
                     "TOR", "VPN_TLS_Handshake",
                     "Unknown", "5",
                     random.randint(500, 2_000), random.randint(500, 2_000)))
    # Log 2: VPN auth success (the primary detection event)
    logs.append(_fw_event(config, user, dept, device_info,
                     tor_ip, gateway_ip, 443, "6",
                     "Allow", "Allow_VPN_Access", "HTTPS",
                     "TOR", "VPN_TOR_Login",
                     "Unknown", "7",
                     random.randint(100_000, 5_000_000),
                     random.randint(50_000, 2_000_000)))
    # Logs 3-5: Post-auth internal activity from VPN-assigned IP
    internal_servers = config.get('internal_servers', ['10.0.10.50'])
    post_auth_actions = [
        {"nwsvc": "SMB",   "port": 445,  "rule": "Allow_Internal_SMB"},
        {"nwsvc": "RDP",   "port": 3389, "rule": "Allow_Internal_RDP"},
        {"nwsvc": "HTTPS", "port": 443,  "rule": "Allow_Web_Outbound"},
        {"nwsvc": "SSH",   "port": 22,   "rule": "Allow_Internal_SSH"},
    ]
    n_post_auth = random.randint(1, 3)
    for action in random.sample(post_auth_actions, min(n_post_auth, len(post_auth_actions))):
        dst_ip = random.choice(internal_servers)
        logs.append(_fw_event(config, user, dept, device_info,
                         vpn_inside_ip, dst_ip, action["port"], "6",
                         "Allow", action["rule"], action["nwsvc"],
                         None, None,
                         "Internal", "3",
                         random.randint(1_000, 100_000),
                         random.randint(500, 50_000)))
    return logs


# ---------------------------------------------------------------------------
# RARE OUTBOUND SERVICE GENERATORS
# ---------------------------------------------------------------------------

def _generate_rare_external_rdp(config, user, dept, internal_host_ip, device_info):
    """Outbound RDP from internal workstation to a rare external IP.

    Returns [DNS precursor, NSSFWlog RDP allowed].
    """
    print(f"    - Zscaler Module simulating: Rare External RDP from {internal_host_ip}")
    logs = [_dns_precursor_event(config, user, dept, device_info, internal_host_ip)]
    logs.append(_fw_event(config, user, dept, device_info,
                     internal_host_ip, _random_external_ip(), 3389, "6",
                     "Allow", "Allow_Web_Outbound", "RDP",
                     "Suspicious Outbound", "RareExternalRDP",
                     "Unknown", "5",
                     random.randint(50_000, 2_000_000),
                     random.randint(10_000, 200_000)))
    return logs


def _generate_rare_ssh(config, user, dept, internal_host_ip, device_info):
    """Outbound SSH to a rare (first-seen) external IP.

    Returns [DNS precursor, NSSFWlog SSH allowed].
    """
    print(f"    - Zscaler Module simulating: Rare External SSH from {internal_host_ip}")
    logs = [_dns_precursor_event(config, user, dept, device_info, internal_host_ip)]
    logs.append(_fw_event(config, user, dept, device_info,
                     internal_host_ip, _random_external_ip(), 22, "6",
                     "Allow", "Allow_Web_Outbound", "SSH",
                     "Suspicious Outbound", "RareExternalSSH",
                     "Unknown", "5",
                     random.randint(1_000, 50_000),
                     random.randint(1_000, 50_000)))
    return logs


# ---------------------------------------------------------------------------
# SMTP / FTP EXFILTRATION GENERATORS
# ---------------------------------------------------------------------------

def _generate_smtp_spray(config, user, dept, internal_host_ip, device_info):
    """Compromised workstation acting as spam bot — direct SMTP to many external MX (nssfwlog).

    30-50 short ALLOWED TCP connections on port 25/587 to DISTINCT external IPs.
    Workstations should never connect directly to external MX servers.
    XSIAM detects the volume of outbound SMTP from a single non-mail source.

    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Zscaler Module simulating: SMTP Spray (spam bot) from {internal_host_ip}")
    n_targets = random.randint(30, 50)
    dest_ips = set()
    while len(dest_ips) < n_targets:
        dest_ips.add(_random_external_ip())

    logs = []
    for dst_ip in list(dest_ips)[:n_targets]:
        smtp_port = random.choices([25, 587], weights=[70, 30], k=1)[0]
        nwsvc = "SMTP" if smtp_port == 25 else "SMTPS"
        logs.append(_fw_event(config, user, dept, device_info,
                              internal_host_ip, dst_ip, smtp_port, "6",
                              "Allow", "Allow_Web_Outbound", nwsvc,
                              "Spam Bot", "SMTP_Spray",
                              "Unknown", "5",
                              random.randint(200, 2_000),
                              random.randint(2_000, 50_000)))
    return logs


def _generate_smtp_large_exfil(config, user, dept, internal_host_ip, device_info):
    """Data exfiltration via large email attachment over SMTP.

    Returns [DNS/MX precursor, NSSFWlog SMTP session].
    """
    print(f"    - Zscaler Module simulating: Large SMTP Exfiltration from {internal_host_ip}")
    mail_mx_ranges = [
        "74.125.0.0/16", "40.76.0.0/14", "207.46.0.0/16",
        "198.2.128.0/18", "159.148.0.0/16",
    ]
    try:
        dest_ip = rand_ip_from_network(
            ip_network(random.choice(mail_mx_ranges), strict=False))
    except Exception:
        dest_ip = _random_external_ip()
    smtp_port = random.choices([587, 25], weights=[80, 20], k=1)[0]
    logs = [_dns_precursor_event(config, user, dept, device_info, internal_host_ip)]
    logs.append(_fw_event(config, user, dept, device_info,
                     internal_host_ip, dest_ip, smtp_port, "6",
                     "Allow", "Allow_SMTP_Relay", "SMTP",
                     "Data Exfiltration", "SMTP_LargeExfil",
                     "Unknown", "6",
                     random.randint(500, 5_000),
                     random.randint(104_857_600, 524_288_000)))
    return logs


def _generate_ftp_large_exfil(config, user, dept, internal_host_ip, device_info):
    """Data exfiltration via outbound FTP.

    Returns [DNS precursor, NSSFWlog FTP session].
    """
    print(f"    - Zscaler Module simulating: Large FTP Exfiltration from {internal_host_ip}")
    logs = [_dns_precursor_event(config, user, dept, device_info, internal_host_ip)]
    logs.append(_fw_event(config, user, dept, device_info,
                     internal_host_ip, _random_external_ip(), 21, "6",
                     "Allow", "Allow_Web_Outbound", "FTP",
                     "Data Exfiltration", "FTP_LargeExfil",
                     "Unknown", "6",
                     random.randint(500, 10_000),
                     random.randint(104_857_600, 524_288_000)))
    return logs


# ---------------------------------------------------------------------------
# DDNS C2 GENERATOR
# ---------------------------------------------------------------------------

def _generate_ddns_connection(config, user, dept, internal_host_ip, device_info):
    """Internal workstation connecting to a known dynamic DNS domain (nssfwlog).

    Generates two logs: DNS query resolving the DDNS hostname, then an HTTPS
    session to the resolved IP. DDNS services are commonly used for cheap C2
    infrastructure. Both events are ALLOWED — detection is UEBA-driven.

    Returns list of CEF log strings (multi-event).
    """
    print(f"    - Zscaler Module simulating: Dynamic DNS Connection from {internal_host_ip}")
    ddns_providers = [
        "duckdns.org", "no-ip.com", "dynu.com", "afraid.org",
        "hopto.org", "zapto.org", "sytes.net", "ddns.net",
        "servebeer.com", "myftp.biz", "myvnc.com", "redirectme.net",
    ]
    subdomains = [
        "update-service", "cdn-relay", "mail-check", "vpn-gateway",
        "api-health", "sync-node", "cloud-backup", "office-proxy",
    ]
    # STICKY PER SOURCE HOST — XSIAM's "Recurring rare domain access to dynamic DNS
    # domain" needs one endpoint returning to ONE rare domain repeatedly. A fresh
    # provider x subdomain per call (12 x 8 combinations) with a random source
    # produced scattered single hits, the opposite of recurrence. A concentrated replay
    # (1 host -> 1 domain, many sessions) produces the correct shape.
    # DO NOT restore per-call randomisation.
    if internal_host_ip not in _ddns_beacon_map:
        _rnd = random.Random(hash(("ddns", internal_host_ip)) & 0xFFFFFFFF)
        _ddns_beacon_map[internal_host_ip] = (
            f"{_rnd.choice(subdomains)}.{_rnd.choice(ddns_providers)}",
            _random_external_ip(),
        )
    ddns_hostname, resolved_ip = _ddns_beacon_map[internal_host_ip]

    logs = []
    # Log 1: DNS query resolving the DDNS hostname
    logs.append(_fw_event(config, user, dept, device_info,
                          internal_host_ip, "8.8.8.8", 53, "17",
                          "Allow", "Allow_DNS_Outbound", "DNS",
                          "N/A", "DDNS_Query",
                          "United States", "3",
                          random.randint(80, 300), random.randint(60, 120),
                          dst_fqdn=ddns_hostname,
                          # -> URL_CATEGORY_DYNAMIC_DNS, the category the
                          # "Recurring rare domain access to dynamic DNS domain"
                          # detector is named after
                          url_category="Dynamic DNS"))
    # Logs 2..N: a BURST of web callbacks to the same DDNS host.
    #
    # These are nssweblog events. The web feed carries the domain as ehost/eurl and
    # maps it to xdm.network.http.domain, which is what "Recurring rare domain access
    # to dynamic DNS domain" keys on: zscaler ddns_connection
    # produced zero populated domain fields until these were switched from _fw_event.
    # (An earlier note here said the FIREWALL feed "carries NO hostname field". That is
    # wrong: Zscaler's firewall field reference defines %s{cdfqdn}, the client
    # destination FQDN, and the DNS-query event above now emits it. The firewall feed
    # simply is not where a web callback belongs.)
    #
    # The callbacks must also be SPREAD OVER TIME. "Recurring" is a temporal property: a
    # burst of 8-16 callbacks stamped with one timestamp is a single observation, not
    # recurrence, and this detector has never fired from any source in this project.
    # Zscaler DDNS bursts spanned 1-2 distinct timestamps while
    # Check Point spanned 30-53 and FortiGate 15-72 for the same threat.
    zscaler_conf = config.get('zscaler_config', {})
    n_callbacks  = random.randint(8, 16)
    ddns_base_ms = int(time.time() * 1000)
    ddns_gap     = random.randint(3, 12) * 60 * 1000    # minutes apart, over hours
    for _i in range(n_callbacks):
        fields = {
            "action": "Allowed",
            # walk backwards so the beacon train occupies the recent past
            "rt": ddns_base_ms - (n_callbacks - 1 - _i) * ddns_gap
                  + random.randint(-20_000, 20_000),
            "urlcat":      "Dynamic DNS",
            "urlsupercat": "Information Technology",
            "urlclass":    "Business and Productivity",
            "riskscore":   str(random.randint(45, 80)),
            "responsecode": "200", "reason": "Allowed", "reqmethod": "POST",
            "useragent":   random.choice(config.get('user_agents', ["Mozilla/5.0"])),
            "appname":     "General Browsing", "appclass": "Web",
            "contenttype": "application/octet-stream",
            "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
            "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
            "eurl": f"https://{ddns_hostname}/", "ehost": ddns_hostname,
            "cip": internal_host_ip, "sip": resolved_ip, "proto": "HTTPS",
            "bytesin":  random.randint(5_000, 500_000),
            "bytesout": random.randint(1_000, 100_000),
            "sourceTranslatedAddress": random.choice(
                zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
            "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
            "cefSeverity": "5",
        }
        logs.append(_format_nss_log_as_cef(fields, user, dept, 'nssweblog'))
    return logs


# Single source of truth for threat event names, weights, and analytics metadata.
# analytic: True  -> event is expected to trigger an XSIAM Third-Party analytics alert
# analytic: False -> event is realistic but won't fire a dedicated XSIAM alert
# xsiam_alert:    -> name of the matching XSIAM analytics alert (or None)
_ddns_beacon_map: dict = {}   # src_ip -> stable (ddns_hostname, resolved_ip) for DDNS recurrence

_NON_ANALYTIC_PREFIX = "[Non-Analytic] "
_DEFAULT_THREAT_EVENTS = [
    {"event": "web_threat",           "weight": 12, "analytic": False,
     "xsiam_alert": None},
    {"event": "data_exfil",           "weight": 8,  "analytic": True,
     "xsiam_alert": "Large Upload (HTTPS)"},
    {"event": "dlp_threat",           "weight": 6,  "analytic": False,
     "xsiam_alert": None},
    {"event": "cloud_app_threat",     "weight": 5,  "analytic": False,
     "xsiam_alert": None},
    {"event": "sandbox_threat",       "weight": 4,  "analytic": False,
     "xsiam_alert": None},
    {"event": "fw_threat",            "weight": 8,  "analytic": False,
     "xsiam_alert": None},
    {"event": "port_scan",            "weight": 10, "analytic": True,
     "xsiam_alert": "Port Scan"},
    {"event": "brute_force",          "weight": 8,  "analytic": False,
     "xsiam_alert": None},
    {"event": "tor_connection",       "weight": 6,  "analytic": True,
     "xsiam_alert": "Recurring access to rare IP"},
    {"event": "dns_c2_beacon",        "weight": 5,  "analytic": True,
     "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain"},
    {"event": "server_outbound_http", "weight": 4,  "analytic": True,
     "xsiam_alert": "New Administrative Behavior"},
    {"event": "rdp_lateral",          "weight": 3,  "analytic": True,
     "xsiam_alert": "Failed Connections"},
    {"event": "rdp_rare_session",     "weight": 4,  "analytic": True,
     "xsiam_alert": "Abnormal RDP session to a remote host from a rarely seen host"},
    {"event": "new_admin_behavior",   "weight": 4,  "analytic": True,
     "xsiam_alert": "New Administrative Behavior"},
    {"event": "ssh_over_https",       "weight": 3,  "analytic": False,
     "xsiam_alert": None},
    {"event": "smb_new_host_lateral", "weight": 4,  "analytic": True,
     "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "smb_rare_file_transfer","weight": 3, "analytic": True,
     "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "smb_share_enumeration","weight": 5,  "analytic": True,
     "xsiam_alert": "Rare SMB session to a remote host"},
    {"event": "vpn_brute_force",      "weight": 6,  "analytic": False,
     "xsiam_alert": None},
    {"event": "vpn_impossible_travel","weight": 3,  "analytic": False,
     "xsiam_alert": None},
    {"event": "vpn_tor_login",        "weight": 3,  "analytic": True,
     "xsiam_alert": "Recurring access to rare IP"},
    {"event": "vpn_new_country_login","weight": 3,  "analytic": True,
     "xsiam_alert": "First successful VPN access from a country in organization"},
    {"event": "rare_external_rdp",    "weight": 3,  "analytic": True,
     "xsiam_alert": "Rare RDP session to a remote host"},
    {"event": "rare_ssh",             "weight": 3,  "analytic": True,
     "xsiam_alert": "Uncommon SSH session was established"},
    {"event": "smtp_spray",           "weight": 3,  "analytic": True,
     "xsiam_alert": "Spam Bot Traffic"},
    {"event": "smtp_large_exfil",     "weight": 2,  "analytic": True,
     "xsiam_alert": "Large Upload (SMTP)"},
    {"event": "ftp_large_exfil",      "weight": 2,  "analytic": True,
     "xsiam_alert": "New FTP Server"},
    {"event": "ddns_connection",      "weight": 3,  "analytic": True,
     "xsiam_alert": "Recurring rare domain access to dynamic DNS domain"},
    {"event": "large_download",       "weight": 3,  "analytic": True,
     "xsiam_alert": "Large Download"},
    # Was annotated "Uncommon reverse SSH tunnel to external domain/ip" — that alert name
    # does not exist in the tenant (searched the whole alerts dataset
    # for every name containing SSH or tunnel). The real detector this drives is
    {"event": "reverse_ssh_tunnel",   "weight": 2,  "analytic": True,
     "xsiam_alert": "Unusual, long SSH activity with tunnel characteristics"},
    # web_c2_beacon was ORPHANED: present in _NAMED_THREATS but absent from this list and
    # from generate_log's threat map, so it never fired ambiently, never appeared in
    # get_threat_names(), and was reachable only via the single hardcoded
    # scenario_event="web_c2_beacon" call in log_simulator.py. Registering it here makes
    # the generator actually reachable.
    {"event": "web_c2_beacon",        "weight": 4,  "analytic": True,
     "xsiam_alert": "Abnormal Recurring Communications to a Rare Domain"},
]

# --- Display-name mapping (same pattern as checkpoint_firewall.py) ---
_EVENT_DISPLAY_NAMES = {}   # event_key -> display_name
_DISPLAY_TO_EVENT    = {}   # display_name -> event_key  (reverse lookup)
for _e in _DEFAULT_THREAT_EVENTS:
    _key  = _e["event"]
    _name = _key if _e.get("analytic", True) else _NON_ANALYTIC_PREFIX + _key
    _EVENT_DISPLAY_NAMES[_key]  = _name
    _DISPLAY_TO_EVENT[_name]    = _key
    _DISPLAY_TO_EVENT[_key]     = _key      # also accept raw key for back-compat

def _generate_web_c2_beacon(config, user, dept, internal_host_ip, device_info,
                            c2_domain_override=None, exact_user=False):
    """Web-layer C2 beacon (nssweblog) — repeated small HTTP callbacks to a C2 host at a
    regular cadence. The web-proxy counterpart to the DNS C2 beacon: same host, same
    tempo, uncategorized destination, non-browser user-agent, tiny symmetric byte counts.

    `c2_domain_override`: when supplied (orchestrated event pinning the same C2
    domain the endpoint + DNS beacon use), callbacks target that host instead of a
    random one. Log format is identical — only the destination host/URL change.
    """
    zscaler_conf = config.get('zscaler_config', {})
    c2_domain = c2_domain_override or random.choice(zscaler_conf.get('c2_domains',
                ["cdn-analytics-sync.com", "telemetry-edge-api.net", "update-check-svc.org", "cloud-metric-relay.io"]))
    # Use the shared helper, NOT a hand-rolled random /8. Picking a random host inside a
    # random octet range is the exact construction the "DO NOT FIX THIS BACK" note near
    # the top of this module warns about: it scattered sources across 210 distinct
    # countries and destroyed geo-based detection. _random_external_ip() draws from the
    # curated external ranges instead.
    c2_ip     = _random_external_ip()
    beacon_ua = random.choice(["python-requests/2.31.0", "Go-http-client/1.1", "curl/8.4.0",
                               "Mozilla/5.0 (Windows NT 10.0) WinHTTP/1.0"])
    # A beacon is defined by its CADENCE, so the callbacks must carry distinct timestamps.
    # Every event previously called time.time() inside one millisecond bucket, so 12-20
    # callbacks landed on a single _time — one observation, not a regular tempo. Beacon
    # detectors ("Abnormal Recurring Communications to a Rare Domain") cannot measure
    # periodicity from a single instant.
    base_ms   = int(time.time() * 1000)
    interval  = random.randint(30, 90) * 1000          # fixed tempo per beacon
    jitter    = int(interval * 0.05)                   # small jitter, still regular
    logs = []
    n_beacons = random.randint(12, 20)
    for _i in range(n_beacons):
        method = random.choices(["GET", "POST"], weights=[70, 30])[0]
        uri    = random.choice(["/api/v1/checkin", "/gate.php", "/submit.php", "/beacon", "/j/collect"])
        fields = {
            "action": "Allowed",
            "urlcat": "Miscellaneous or Unknown", "urlsupercat": "Miscellaneous",
            "urlclass": "Uncategorized", "riskscore": str(random.randint(60, 90)),
            "responsecode": "200", "reason": "Allowed", "reqmethod": method,
            "useragent": beacon_ua, "appname": "General Browsing", "appclass": "Web",
            "contenttype": "application/octet-stream",
            "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
            "deviceostype": device_info['os_type'], "deviceosversion": device_info['os_version'],
            "eurl": f"http://{c2_domain}{uri}", "ehost": c2_domain,
            "cip": internal_host_ip, "sip": c2_ip, "proto": "HTTP",
            "bytesin": random.randint(120, 400), "bytesout": random.randint(200, 900),  # small, regular
            "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
            "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
            "cefSeverity": "5",
            # Orchestrated events pin the EXACT box user (no @examplecorp.com) so the
            # web log's user matches the endpoint identity. Ambient events leave this
            # unset and get the usual synthesized UPN.
            "suser": user if exact_user else None,
            # walk backwards from now so the beacon train sits in the recent past at a
            # steady cadence rather than all arriving in the same millisecond
            "rt": base_ms - (n_beacons - 1 - _i) * interval
                  + random.randint(-jitter, jitter),
        }
        logs.append(_format_nss_log_as_cef(fields, user, dept, 'nssweblog'))
    return logs


# Module-level dispatch map for named-threat mode.
# Functions accept (config, user, dept, internal_host_ip, device_info).
def _generate_large_download(config, user, dept, internal_host_ip, device_info):
    """Large INBOUND web transfer — 'Large Download' volume anomaly. The proxy
    counterpart to data_exfil: huge bytesin (download) / small bytesout (request).
    Returns [DNS precursor, NSSFWlog TCP/443 allow, NSSWeblog allow]."""
    print("    - Zscaler Module simulating: Large Download (inbound volume anomaly)")
    zscaler_conf = config.get('zscaler_config', {})
    # `download_destinations` is not present in config, so this silently fell back to the
    # 2-entry upload list and downloads resolved to the SAME hosts as uploads. Draw from
    # the download half of the shared pool instead — see _exfil_destination().
    _dl_domain, dest_ip, _dl_url = _exfil_destination(config, "download")
    dl_dest        = {"url": _dl_url, "domain": _dl_domain}
    download_bytes = random.randint(524_288_000, 4_294_967_296)  # 500 MB - 4 GB
    req_bytes      = random.randint(200, 2000)
    filename, filetype = _pick_upload_file(random.choice(["archive", "document"]))

    logs = [_dns_precursor_event(config, user, dept, device_info, internal_host_ip,
                                domain=_dl_domain)]
    # NSSFWlog — bytes_in = download (large), bytes_out = request (small)
    logs.append(_fw_event(config, user, dept, device_info,
                          internal_host_ip, dest_ip, 443, "6",
                          "Allow", "Allow_Web_Outbound", "HTTPS",
                          "Large Download", "LargeDownload",
                          "Unknown", "5",
                          download_bytes, req_bytes,
                          dst_fqdn=_dl_domain,
                          duration_ms=random.randint(300_000, 1_200_000),
                          url_category="Online Storage and Backup"))
    fields = {
        "action": "Allowed",
        "urlcat": "Online Storage", "urlsupercat": "Productivity and Collaboration",
        "urlclass": "Business and Productivity",
        "riskscore": str(random.randint(30, 60)),
        "responsecode": "200", "reason": "Allowed", "reqmethod": "GET",
        "useragent": random.choice(config.get('user_agents', ["Mozilla/5.0"])),
        "appname": "File Transfer", "appclass": "General", "contenttype": "application/octet-stream",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl": dl_dest.get('url'), "ehost": dl_dest.get('domain'),
        "cip": internal_host_ip, "sip": dest_ip, "proto": "HTTPS",
        "bytesin": download_bytes, "bytesout": req_bytes,
        "filename": filename, "filetype": filetype,
        "filesize": download_bytes, "totalsize": download_bytes + req_bytes,
        "sourceTranslatedAddress": random.choice(zscaler_conf.get('source_translated_ips', ["203.0.113.1"])),
        "flexString1": random.choice(zscaler_conf.get('locations', ["HQ"])),
        "cefSeverity": "5",
    }
    logs.append(_format_nss_log_as_cef(fields, user, dept, 'nssweblog'))
    return logs


def _generate_reverse_ssh_tunnel(config, user, dept, internal_host_ip, device_info):
    """Internal host -> EXTERNAL IP on SSH/22 through the ZIA firewall — reverse SSH
    tunnel / C2 over SSH. Long-lived, high bidirectional volume; a few sessions to the
    SAME external host (stable destination = recurring-rare-destination signal).
    Returns list of nssfwlog CEF events."""
    print("    - Zscaler Module simulating: Reverse SSH tunnel to external host")
    # --- STICKY PEER (the "tracker") ---------------------------------------------
    # One internal host must keep returning to ONE novel external IP. The map lives for
    # the life of the process, which is the right scope here: LogSim is normally left
    # running, so every later invocation for this host reuses the same peer and the
    # multi-day pattern deepens on its own. (Deliberately NOT persisted to disk —
    # single-session operation is the assumption.)
    #
    # Do NOT reseed this from hash(): CPython salts str hashing with PYTHONHASHSEED, so
    # hash(("x", ip)) returns a different value in every interpreter (verified
    # different values for identical input). Irrelevant
    # while the process stays up, but it is why any restart re-rolls a "sticky" target.
    peer_key = f"revssh::{internal_host_ip}"
    dest_ip  = _beacon_target_map.get(peer_key)
    if not dest_ip:
        # _random_external_ip() draws a specific /32 from 35 XSIAM-probed /24s. The exact
        # address is effectively novel, which is what a rare-destination detector keys on
        # — the same helper already sustains "An Uncommon SSH session was established to a
        # rare IP" for Zscaler (n=155).
        dest_ip = _random_external_ip()
        _beacon_target_map[peer_key] = dest_ip

    # --- SHAPE ------------------------------------------------------------------
    # Determined by manual inspection of the detector (rule
    # f1545c54-11c4-4af8-9119-4a21b890b7c3, "Unusual, long SSH activity with tunnel
    # characteristics"). It needs SUCCESSFUL SSH connections to the SAME previously
    # unseen external IP, observed ACROSS MULTIPLE DAYS — not a burst.
    #
    # So emit exactly TWO successful sessions per invocation, hours apart, with the
    # first back-dated far enough that the pair straddles two calendar days. A single
    # injection therefore already presents the multi-day shape instead of waiting a day
    # for the second observation to arrive naturally.
    #
    # Earlier attempts and why they failed, so this is not re-litigated:
    #   * 2-4 sessions all on ONE timestamp     -> one observation, no recurrence
    #   * sessions 45 min - 3 h apart           -> same calendar day, still not multi-day
    #   * 5-80 MB volume                        -> below the ~171 MB the Check Point
    #                                              session that fired actually carried
    #   * app_proto was NEVER the gap: Zscaler already emits SSH, identical to the
    #     Check Point event that fired. An earlier note here
    #     blaming app_id was wrong — that app_id came off a Large Upload alert.
    now_ms = int(time.time() * 1000)
    session_offsets = [
        random.randint(26, 34) * 3600 * 1000,   # yesterday
        random.randint(1, 5) * 3600 * 1000,     # today, hours later
    ]
    logs = []
    for offset_ms in session_offsets:
        logs.append(_fw_event(config, user, dept, device_info,
                              internal_host_ip, dest_ip, 22, "6",
                              # SUCCESSFUL — a blocked attempt cannot satisfy this
                              # detector. Do not change to Block/Blocked.
                              "Allow", "Allow_Web_Outbound", "SSH",
                              "Remote Access", "ReverseSSHTunnel",
                              "Unknown", "6",
                              # 120-350 MB each way: the detector wants "a higher than
                              # usual volume of data transfer" AND "an abnormally long
                              # session". The Check Point session that fired carried
                              # ~171 MB at 117,350,000 ms (32.6 h), app_proto SSH.
                              random.randint(120, 350) * 1024 * 1024,
                              random.randint(120, 350) * 1024 * 1024,
                              event_time_ms=now_ms - offset_ms,
                              # 6-20 h per session: abnormally long, but short enough
                              # that the two sessions read as distinct connections
                              # rather than one continuously overlapping tunnel.
                              duration_ms=random.randint(21_600_000, 72_000_000)))
    return logs


_NAMED_THREATS = {
    "web_c2_beacon":        _generate_web_c2_beacon,
    "large_download":       _generate_large_download,
    "reverse_ssh_tunnel":   _generate_reverse_ssh_tunnel,
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
    "rdp_rare_session":     _generate_rdp_rare_session,
    "new_admin_behavior":   _generate_new_admin_behavior,
    "ssh_over_https":       _generate_ssh_over_https,
    "smb_new_host_lateral": _generate_smb_new_host_lateral,
    "smb_rare_file_transfer": _generate_smb_rare_file_transfer,
    "smb_share_enumeration":  _generate_smb_share_enumeration,
    "vpn_brute_force":        _generate_vpn_brute_force,
    "vpn_impossible_travel":  _generate_vpn_impossible_travel,
    "vpn_tor_login":          _generate_vpn_tor_login,
    "vpn_new_country_login":  _generate_vpn_new_country_login,
    "rare_external_rdp":      _generate_rare_external_rdp,
    "rare_ssh":               _generate_rare_ssh,
    "smtp_spray":             _generate_smtp_spray,
    "smtp_large_exfil":       _generate_smtp_large_exfil,
    "ftp_large_exfil":        _generate_ftp_large_exfil,
    "ddns_connection":        _generate_ddns_connection,
}


def get_threat_names():
    """Return available threat names dynamically from _DEFAULT_THREAT_EVENTS.

    Non-analytic events (those that won't trigger an XSIAM Third-Party Firewall
    analytics detection) are prefixed with '[Non-Analytic] ' so operators can
    focus on events that will produce alerts.
    """
    return [_EVENT_DISPLAY_NAMES[e["event"]] for e in _DEFAULT_THREAT_EVENTS]


def get_threat_info():
    """Return full metadata for each threat event (name, analytic flag, XSIAM alert).

    Returns a list of dicts with keys: event, display_name, analytic, xsiam_alert, weight.
    """
    result = []
    for e in _DEFAULT_THREAT_EVENTS:
        result.append({
            "event":        e["event"],
            "display_name": _EVENT_DISPLAY_NAMES[e["event"]],
            "analytic":     e.get("analytic", True),
            "xsiam_alert":  e.get("xsiam_alert"),
            "weight":       e["weight"],
        })
    return result


# ---------------------------------------------------------------------------
# CEF FORMATTER (unchanged from original)
# ---------------------------------------------------------------------------

def _format_nss_log_as_cef(fields, user, dept, log_product):
    """Builds the final CEF log string for Zscaler NSS feeds.

    CEF header: CEF:0|Zscaler|{NSSWeblog|NSSFWlog}|6.1|{action}|{action}|{severity}|
    Syslog PRI <14> = facility user (1<<3=8) + info (6) = 14.

    Per Zscaler/Azure Sentinel: signatureId (position 4) and name (position 5)
    are both the action string (Allowed/Blocked for web, Allow/Blocked for FW).
    deviceProduct uses mixed case: NSSWeblog, NSSFWlog.
    """
    # XSIAM keys _time off the CEF rt field. Respect an explicitly-set rt (ms epoch)
    # so time-spread threats (e.g. impossible travel) can back-date events; else now.
    rt = fields.get("rt") or int(time.time() * 1000)
    # Zscaler NSS deviceProduct uses mixed case per XSIAM dataset naming
    _PRODUCT_MAP = {"nssweblog": "NSSWeblog", "nssfwlog": "NSSFWlog"}
    cef_product = _PRODUCT_MAP.get(log_product, log_product)

    common_map = {
        "rt": rt,
        # Ambient events synthesize a UPN (user@examplecorp.com). Orchestrated
        # (XDR-triggered) events set fields['suser'] to the EXACT box username so it
        # matches the endpoint identity XSIAM stores (which does no user
        # normalization) — no fake email domain appended.
        "suser": fields.get("suser") or (user if '@' in user else f"{user}@examplecorp.com"),
        "externalId": str(random.randint(1000000, 9999999999)),
        # Lowercase `devicehostname` is the key the Zscaler modeling rule reads, not
        # CEF-standard deviceHostName. The nssweblog block maps it to
        # xdm.source.host.hostname; the nssfwlog block assigns no hostname at all, so
        # the firewall feed reaches XDM without one. That is a pack-side mapping gap,
        # not a missing field — the value is present as a native CEF column and is
        # usable from XQL and correlation rules. Do not try to close it with more CEF
        # keys; it needs native-JSON transport or a tenant-side modeling rule.
        "devicehostname":              fields.get("devicehostname"),
        # `shost` MUST stay immediately after `devicehostname`. It is a recognised CEF
        # key and acts as the VALUE TERMINATOR: the parser absorbs unrecognised keys
        # into the preceding value, and deviceOwner / deviceOperatingSystem /
        # deviceOperatingSystemVersion below are not recognised. Without shost between
        # them, devicehostname swallows all three and runs on to the next known key.
        "shost":                       fields.get("devicehostname"),
        "deviceOwner":                 fields.get("deviceowner"),
        "deviceOperatingSystem":       fields.get("deviceostype"),
        "deviceOperatingSystemVersion":fields.get("deviceosversion"),
        "sourceTranslatedAddress":     fields.get("sourceTranslatedAddress"),
        "flexString1": fields.get("flexString1"), "flexString1Label": "location",
        "dept": dept,
        # %s{eedone} — "Indicates if the characters specified in the Feed Escape
        # Character field of the NSS feed configuration page were hex encoded".
        # _cef_escape() hex-encodes `=` (the character XSIAM's onboarding guide
        # specifies), so a real feed in this configuration reports Yes.
        "eedone": "Yes",
        "clienttranstime": random.randint(10, 2000),
        "servertranstime": random.randint(10, 5000),
        "ssldecrypted":    random.choice(["Yes", "No"]),
        "contentclass":    fields.get("contentclass", "Web Browsing"),
        # Additional documented NSS fields (present in BOTH the web-log and
        # firewall-log field references, "Zscaler Client Connector Device
        # Information" and "Miscellaneous"). Cheap fidelity: they are what a real
        # Client Connector-enrolled endpoint reports. Appended AFTER the fields that
        # matter for XDM so that, if the CEF parser absorbs an unrecognised key into
        # the preceding value, it cannot damage devicehostname (which is terminated
        # by the recognised `shost` immediately after it) — see the note above.
        "devicetype":       "Zscaler Client Connector",
        "devicemodel":      _device_model(fields.get("devicehostname")),
        "deviceappversion": "2.0.0.120",
        "ztunnelversion":   "ZTUNNEL_1_0",
        "flow_type":        "ZIA",
        "company":          "ExampleCorp",
        "cloudname":        "zscaler.net",
        "nsssvcip":         "10.10.102.30",
        "productversion":   "5.0.902.95524_04",
    }

    if log_product == 'nssweblog':
        # totalsize = full transaction bytes. Fall back to bytesin+bytesout when a
        # generator doesn't set it explicitly, so cn3 is never empty on a web
        # transaction that reported byte counts.
        _totalsize = fields.get("totalsize")
        if _totalsize is None and (fields.get("bytesin") is not None
                                   or fields.get("bytesout") is not None):
            _totalsize = (fields.get("bytesin") or 0) + (fields.get("bytesout") or 0)
        # Raw-completeness fields: present in the zscaler_nssweblog_raw schema but
        # NOT XDM-mapped by the web modeling rule (queryable via XQL). Derive sane
        # values from what the generator already provides.
        _web_proto = fields.get("proto")
        _web_dpt = fields.get("destport") or {"HTTPS": 443, "HTTP": 80}.get(_web_proto, 443)
        _web_spt = fields.get("sport") or random.randint(49152, 65535)
        _web_destcountry = fields.get("destCountry") or (
            "United States" if fields.get("action") in ("Allow", "Allowed") else "Unknown")
        _web_desttrans = fields.get("destinationTranslatedAddress") or fields.get("sip")
        cef_map  = {
            # XIF-mapped cs/cn fields (consumed by XSIAM ZscalerModelingRule):
            "cs2": fields.get("urlcat"),       "cs2Label": "urlcat",       # -> http.url_category
            "cs4": fields.get("malwarecat"),   "cs4Label": "malwarecat",   # -> alert.category
            "cs5": fields.get("threatname"),   "cs5Label": "threatname",   # -> alert.name
            # cn1 -> xdm.alert.severity: use threatscore on threats, else riskscore,
            # so severity is populated on benign web events too.
            "cn1": fields.get("threatscore") or fields.get("riskscore"), "cn1Label": "threatscore",
            # URL class -> xdm.event.type. XSIAM reads the custom key
            # ZscalerNSSWeblogURLClass; cs1 is kept for back-compat with
            # correlation rules that filter `cs1 = "Malicious Content"`.
            "ZscalerNSSWeblogURLClass": fields.get("urlclass"),
            "spriv": fields.get("spriv", "domain users"),                  # -> source.zone
            "destinationServiceName": fields.get("appname"),              # -> target.interface
            # Raw dataset hunting fields (queryable, not XDM-mapped by XSIAM):
            "cs1": fields.get("urlclass"),     "cs1Label": "urlclass",
            "cs3": fields.get("malwareclass"), "cs3Label": "malwareclass",
            "cs6": fields.get("riskscore"),    "cs6Label": "riskscore",
            "cn2": fields.get("filesize"),     "cn2Label": "filesize",
            "cn3": _totalsize,                 "cn3Label": "totalsize",
            # Standard XIF-mapped fields:
            "act": fields.get("action"),
            "outcome": fields.get("responsecode"),
            "reason": fields.get("reason"),
            "app": fields.get("proto"),
            "cat": fields.get("urlcat"),
            # `ehost` / `eurl` are the HEX-ENCODED variants in Zscaler's web-log field
            # reference (%s{ehost}, %s{eurl}) — the plain forms are %s{host}/%s{url}.
            # Our internal field names already use the e-prefixed spelling, so both
            # must actually carry the encoding to match what a real feed streams.
            "dhost": _zscaler_url_encode(fields.get("ehost")),
            "dst": fields.get("sip"),    "src": fields.get("cip"),
            # Zscaler hex-encodes URL characters <=0x20 / >=0x7F before streaming
            # (space -> %20, newline -> %0A). Applied centrally here so every
            # generator's eurl gets it without touching each call site.
            "request": _zscaler_url_encode(fields.get("eurl")),
            "requestMethod": fields.get("reqmethod"),
            "requestClientApplication": fields.get("useragent"),
            "contenttype": fields.get("contenttype"),
            "in": fields.get("bytesin"),  "out": fields.get("bytesout"),
            "fileName": fields.get("filename"), "fileType": fields.get("filetype"),
            "fileHash": fields.get("fileHash"),
            "appname": fields.get("appname"),
            "appclass": fields.get("appclass"),
            "urlsupercat": fields.get("urlsupercat"),
            # Raw schema columns (not XDM-mapped for web; complete the raw dataset):
            "proto": _web_proto,
            "spt": _web_spt, "dpt": _web_dpt,
            "destCountry": _web_destcountry,
            "destinationTranslatedAddress": _web_desttrans,
        }
        if fields.get("event_type") == "dlp":
            cef_map.update({
                "cs1": fields.get("dlpengine"),    "cs1Label": "dlpeng",
                "cs2": fields.get("dlpdictionary"),"cs2Label": "dlpdict",
                "cs3": fields.get("dlprule"),      "cs3Label": "dlprulename",
                "cs4": None, "cs4Label": None,
                "cs5": None, "cs5Label": None,
                # DLP isn't a malware threat, so clear threatscore — but keep cn1
                # populated from riskscore so xdm.alert.severity still resolves.
                "cn1": fields.get("riskscore"),    "cn1Label": "riskscore",
            })

    else:  # nssfwlog
        cef_map  = {
            # XIF-mapped cs/cn fields:
            # cs2 carries the firewall RULE name and the modeling rule maps it to
            # xdm.network.rule, so the label must say so. It previously read "nwapp"
            # (network application), which described neither the value nor the mapping.
            "cs2": fields.get("rulelabel"),    "cs2Label": "rulelabel",
            "cs3": fields.get("nwsvc"),        "cs3Label": "nwsvc",
            # %s{nwapp} "The network application that was accessed" (example: SSH) —
            # a documented firewall-feed field and one of the five keys Zscaler
            # aggregates on. Distinct from nwsvc, "the network service that was used"
            # (example: HTTP): the vendor's own sample log carries nwsvc=HTTP with
            # nwapp=ebay, i.e. service vs the specific application. Defaults to the
            # service, which is what the doc shows for non-web protocols.
            #
            # POSITION IS DELIBERATE — keep `nwapp` immediately after `cs3Label`. The
            # CEF parser absorbs an unrecognised key into the PRECEDING value, so if
            # nwapp is not recognised on this feed the only casualty is cs3Label, a
            # label string nothing maps or reads. Moving it next to a value-bearing
            # key risks destroying that value instead.
            "nwapp": fields.get("nwapp") or fields.get("nwsvc"),
            "cs5": fields.get("urlcat"),       "cs5Label": "urlcat",
            "cs6": fields.get("threatname"),   "cs6Label": "threatname",
            "cn1": fields.get("duration_ms"),  "cn1Label": "duration",
            "cat": fields.get("threatcat"),
            # Raw dataset hunting fields:
            "cs1": dept,                       "cs1Label": "department",
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
            # %s{cdfqdn} — client destination FQDN (Insights "Client Destination
            # Name"). Carried as CEF dhost so it lands in a destination-name field.
            # Only set when the generator genuinely knows a domain; None for pure
            # IP traffic, and the builder drops None.
            "cdfqdn": fields.get("cdfqdn"),
            "dhost":  fields.get("cdfqdn"),
        }

    merged = dict(common_map)
    merged.update(cef_map)
    # Drop any "<base>Label" whose partner value is absent — otherwise a dropped
    # None value (e.g. filesize on a browsing event) leaves an orphan label like
    # "cn2Label=filesize" with no matching cn2 in the output.
    for _lbl in [k for k in merged if k.endswith("Label")]:
        if merged.get(_lbl[:-5]) is None:
            merged[_lbl] = None

    # The CEF parser recognises a fixed key set PER FEED, and an unrecognised
    # `key=value` is absorbed into the PRECEDING key's value instead of becoming its
    # own column. Every key we emit on the FIREWALL feed is recognised. On the WEB feed
    # the keys below are not, and each one silently destroyed the field preceding it:
    #     out               <- swallowed fileName
    #     dpt               <- swallowed destCountry
    #     flexString1Label  <- swallowed dept..contentclass
    #     shost             <- swallowed deviceOwner/OS/OSVersion
    #     fileType          <- swallowed appname/appclass/urlsupercat
    # `out` is the damaging one: the web modeling rule assigns
    # xdm.source.sent_bytes = to_integer(out), and "39550844 fileName=records.csv" is
    # not an integer — so sent_bytes sat at 0% (0/1754) and Large Upload could never
    # fire from the web feed no matter how many bytes a generator claimed.
    #
    # Keep emitting these keys (they are real NSS web-log fields and stay useful for
    # XQL hunting) but move them into one contiguous block at the END of the
    # extension, behind a sacrificial recognised key. The parser can then only
    # corrupt the sacrificial value. `dvchost` is CEF-standard, recognised, and
    # redundant here — devicehostname and shost already carry the hostname — so
    # losing it to the absorb costs nothing.
    if log_product == 'nssweblog':
        _WEB_UNRECOGNISED = (
            "deviceOwner", "deviceOperatingSystem", "deviceOperatingSystemVersion",
            "dept", "eedone", "clienttranstime", "servertranstime", "ssldecrypted",
            "contentclass", "devicetype", "devicemodel", "deviceappversion",
            "ztunnelversion", "flow_type", "company", "cloudname", "nsssvcip",
            "productversion", "fileName", "appname", "appclass", "urlsupercat",
            "destCountry")
        _tail = [(k, merged.pop(k)) for k in _WEB_UNRECOGNISED if k in merged]
        if any(v is not None for _k, v in _tail):
            merged["dvchost"] = fields.get("devicehostname")
        for _k, _v in _tail:
            merged[_k] = _v

    cef_severity = fields.get('cefSeverity', '3')
    # Zscaler uses the action string as both signatureId (pos 4) and name (pos 5)
    action_str   = fields.get('action', 'Allow')
    cef_header   = f"CEF:0|Zscaler|{cef_product}|6.1|{action_str}|{action_str}|{cef_severity}|"
    extension_parts  = [f"{key}={_cef_escape(value)}" for key, value in merged.items() if value is not None]
    extension_string = " ".join(extension_parts)
    # XSIAM's Zscaler onboarding guide specifies a DIFFERENT syslog identifier per NSS
    # feed type, and both feeds were previously emitted as "zscaler-nss":
    #   NSS for Firewall -> "%s{mon} %02d{dd} %02d{hh}:%02d{mm}:%02d{ss} zscaler-nss-fw CEF:0"
    #   NSS for Web      -> "%s{mon} %02d{dd} %02d{hh}:%02d{mm}:%02d{ss} zscaler-nss CEF:0"
    # (Ingest logs from Zscaler Internet Access, Cortex XDR 3.x documentation.)
    syslog_host = "zscaler-nss-fw" if log_product == "nssfwlog" else "zscaler-nss"
    return (f"<14>{datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} "
            f"{syslog_host} {cef_header}{extension_string}")


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
        "action": "Blocked", "urlcat": "Malware", "urlsupercat": "Security",
        "urlclass": "Malicious Content",
        "riskscore": str(random.randint(75, 100)),
        "responsecode": "403", "reason": "Threat Block",
        "malwarecat": scenario.get('threat_category', 'Adware'),
        "threatname":  scenario.get('threat_name',     'JS/Adware.Gen'),
        "reqmethod": "GET", "useragent": "Mozilla/5.0",
        "contenttype": "text/html",
        "devicehostname": device_info['hostname'], "deviceowner": device_info['owner'],
        "deviceostype":   device_info['os_type'],  "deviceosversion": device_info['os_version'],
        "eurl":  f"http://{scenario.get('dest_domain', 'malware.example.com')}/",
        "ehost": scenario.get('dest_domain', 'malware.example.com'),
        "cip": ip, "sip": scenario.get('dest_ip', _random_external_ip()),
        "proto": "HTTP",
        "bytesin":  random.randint(200, 2_000),
        "bytesout": random.randint(300, 1_500),
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

    Benign pool (14 types, ~20 slots):
        web(x3), firewall(x2), video_streaming(x2), saas_upload,
        software_update, dns_query, inbound_block, smb, ssh, rdp,
        vpn_success, vpn_failure, email, ftp

    Threat pool (25 types, weighted) — all conversation-complete:
        Web layer:  web_threat(12), data_exfil(8), dlp_threat(6),
                    cloud_app_threat(5), sandbox_threat(4)
        Firewall:   fw_threat(8), port_scan(10), brute_force(8),
                    tor_connection(6), dns_c2_beacon(5),
                    server_outbound_http(4), rdp_lateral(3), ssh_over_https(3)
        SMB:        smb_new_host_lateral(4), smb_rare_file_transfer(3),
                    smb_share_enumeration(5)
        VPN:        vpn_brute_force(6), vpn_impossible_travel(3), vpn_tor_login(3)
        Rare:       rare_external_rdp(3), rare_ssh(3)
        Exfil:      smtp_spray(3), smtp_large_exfil(2), ftp_large_exfil(2)
        C2:         ddns_connection(3)

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
        _ctx = context or {}
        if _ctx.get("user"):
            # Orchestrated (XDR-triggered) event: pin the REAL box identity so the
            # web log carries the same user/host the Cortex agent reports.
            user, dept, internal_host_ip, device_info = _identity_from_context(config, _ctx)
        else:
            user, dept, internal_host_ip, device_info = _get_user_and_device_info(
                config, session_context=session_context)
            # Pin the source host from context so a scenario keys the web stage to one host.
            _ctx_src = _ctx.get("src_ip")
            if _ctx_src:
                internal_host_ip = _ctx_src
        if not internal_host_ip:
            internal_host_ip = _get_random_internal_ip(config)
        # C2-style beacons may pin the destination domain so it matches the endpoint
        # technique + the paired DNS beacon, and pin the exact box user (no UPN
        # suffix). Only web_c2_beacon honors these today.
        _domain = _ctx.get("domain")
        _exact_user = bool(_ctx.get("user"))
        if scenario_event == "web_c2_beacon" and (_domain or _exact_user):
            return _generate_web_c2_beacon(config, user, dept, internal_host_ip, device_info,
                                           c2_domain_override=_domain, exact_user=_exact_user)
        return _NAMED_THREATS[scenario_event](config, user, dept, internal_host_ip, device_info)

    user, dept, internal_host_ip, device_info = _get_user_and_device_info(
        config, session_context=session_context)
    if not internal_host_ip:
        internal_host_ip = _get_random_internal_ip(config)

    # Benign pool — 14 types, ~20 slots.
    # Rebalanced to include UEBA protocol baselines for SMB, SSH, RDP, VPN,
    # email, and FTP so UEBA platforms can build 'normal' behavioral profiles.
    benign_pool = (
        [lambda: _generate_benign_web_traffic(config, user, dept, internal_host_ip, device_info)] * 3 +
        [lambda: _generate_benign_firewall_traffic(config, user, dept, internal_host_ip, device_info)] * 2 +
        [lambda: _generate_benign_video_streaming(config, user, dept, internal_host_ip, device_info)] * 2 +
        [lambda: _generate_benign_saas_upload(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_software_update(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_dns_query(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_inbound_block(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_smb_event(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_ssh_event(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_rdp_event(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_vpn_event(config, user, dept, internal_host_ip, device_info)] +
        # On the BENIGN pool on purpose: the threat pool is interval-gated and then
        # weighted, which yields well under one emission per day, but the country
        # rotation is keyed on the day number — a day with zero emissions silently
        # skips that day's country.  Every emission on a given day carries the SAME
        # country, so firing often costs exactly one reserve country per day.
        [lambda: _generate_vpn_new_country_login(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_vpn_failure_event(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_email_event(config, user, dept, internal_host_ip, device_info)] +
        [lambda: _generate_benign_ftp_event(config, user, dept, internal_host_ip, device_info)]
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
        ("rdp_rare_session",       4, lambda: _generate_rdp_rare_session(config, user, dept, internal_host_ip, device_info)),
        ("new_admin_behavior",     4, lambda: _generate_new_admin_behavior(config, user, dept, internal_host_ip, device_info)),
        ("ssh_over_https",         3, lambda: _generate_ssh_over_https(config, user, dept, internal_host_ip, device_info)),
        ("smb_new_host_lateral",   4, lambda: _generate_smb_new_host_lateral(config, user, dept, internal_host_ip, device_info)),
        ("smb_rare_file_transfer", 3, lambda: _generate_smb_rare_file_transfer(config, user, dept, internal_host_ip, device_info)),
        ("smb_share_enumeration",  5, lambda: _generate_smb_share_enumeration(config, user, dept, internal_host_ip, device_info)),
        ("vpn_brute_force",        6, lambda: _generate_vpn_brute_force(config, user, dept, internal_host_ip, device_info)),
        ("vpn_impossible_travel",  3, lambda: _generate_vpn_impossible_travel(config, user, dept, internal_host_ip, device_info)),
        ("vpn_tor_login",          3, lambda: _generate_vpn_tor_login(config, user, dept, internal_host_ip, device_info)),
        ("vpn_new_country_login",  3, lambda: _generate_vpn_new_country_login(config, user, dept, internal_host_ip, device_info)),
        ("rare_external_rdp",      3, lambda: _generate_rare_external_rdp(config, user, dept, internal_host_ip, device_info)),
        ("rare_ssh",               3, lambda: _generate_rare_ssh(config, user, dept, internal_host_ip, device_info)),
        ("smtp_spray",             3, lambda: _generate_smtp_spray(config, user, dept, internal_host_ip, device_info)),
        ("smtp_large_exfil",       2, lambda: _generate_smtp_large_exfil(config, user, dept, internal_host_ip, device_info)),
        ("ftp_large_exfil",        2, lambda: _generate_ftp_large_exfil(config, user, dept, internal_host_ip, device_info)),
        ("ddns_connection",        3, lambda: _generate_ddns_connection(config, user, dept, internal_host_ip, device_info)),
        ("large_download",         3, lambda: _generate_large_download(config, user, dept, internal_host_ip, device_info)),
        ("reverse_ssh_tunnel",     2, lambda: _generate_reverse_ssh_tunnel(config, user, dept, internal_host_ip, device_info)),
        ("web_c2_beacon",          4, lambda: _generate_web_c2_beacon(config, user, dept, internal_host_ip, device_info)),
    ]
    labels    = [t[0] for t in _threat_map]
    weights   = [t[1] for t in _threat_map]
    callables = [t[2] for t in _threat_map]

    def _pick_threat():
        idx    = random.choices(range(len(callables)), weights=weights, k=1)[0]
        result = callables[idx]()
        return (result, labels[idx]) if result is not None else None

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
