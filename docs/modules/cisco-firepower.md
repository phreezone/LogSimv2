# Cisco Firepower

**Dataset:** `cisco_firepower_raw`
**Transport:** Syslog (TCP)
**Format:** CEF (ArcSight Common Event Format)

Simulates Cisco FTD/FMC (Firepower Threat Defense / Firepower Management Center) CEF syslog events for the XSIAM `cisco_firepower_raw` dataset. XSIAM auto-parses `cefDeviceVendor="Cisco"` and `cefDeviceProduct="Firepower"` from the CEF header. The `CiscoFirepower_1_3.xif` XIF rule then maps CEF extension fields to XDM. Syslog PRI is `<13>` (facility local0 + informational). The CEF SignatureID (position 4) carries the FTD syslog ID.

### CEF Syslog IDs

| Syslog ID | Event Type |
|---|---|
| `430002` | Connection Statistics (allow/block) |
| `430001` | Intrusion Prevention System (IPS) |
| `411002` | AMP File / Malware detection |
| `410001` | URL Filtering block |
| `430005` | Security Intelligence (DNS block) |

### Hunt-Relevant Extra Fields

These fields are not modeled by `CiscoFirepower_1_3.xif` but are preserved in the raw dataset and available for custom detection rules and threat hunting:

| Field | Description |
|---|---|
| `msg` | Human-readable event description; key field for free-text hunting searches |
| `cs1` / `cs1Label` | Access Control Policy name on connection/IPS/URL/secintel/SMB events; SHA256 hash on malware events (`cs1Label="SHA256"`) |
| `cs6` / `cs6Label` | URL Reputation string on connection/URL/upload/SMB events (`cs6Label="URLReputation"`); Intrusion Policy name on IPS events (`cs6Label="IntrusionPolicy"`); Disposition source on malware events (`cs6Label="DispositionSource"`) |
| `start` / `end` | Connection start and end times in epoch milliseconds |
| `deviceDirection` | Traffic direction: `1`=outbound (LAN→WAN, default); `0`=inbound (WAN→LAN, set on IPS and inbound_block events) |
| `cnt` | Always `1` for individual (non-aggregated) events |
| `requestMethod` | HTTP method on HTTP/HTTPS events: `GET` (browsing/malware/URL), `POST`/`PUT` (uploads) |
| `shost` | Source hostname when available from session context |
| `dhost` | Destination hostname: malware delivery domain, blocked URL domain, or C2 domain |
| `sproc` | Source process name on malware events (browser or suspicious process) |
| `filePath` | Full endpoint path on malware events (e.g., `C:/Users/user/Downloads/fname`) |
| `fileSize` (`fsize`) | File size in bytes on malware events |

### Interface Naming Convention

FTD packet-flow perspective: `deviceInboundInterface` = interface where the ingress packet arrived; `deviceOutboundInterface` = interface where the egress packet departed.
- Outbound (LAN→WAN): `deviceInboundInterface=inside`, `deviceOutboundInterface=outside`
- Inbound/IPS (WAN→LAN): `deviceInboundInterface=outside`, `deviceOutboundInterface=inside`
- Internal (LAN→LAN): both interfaces = `inside`

XIF mapping: `xdm.source.interface = deviceOutboundInterface`; `xdm.target.interface = deviceInboundInterface`

---

## Benign Events

Benign events are dispatched from `_generate_benign_log` with roll-based proportions. The `_base_fields` helper sets `cnt=1`, `deviceDirection=1` (outbound), and zone/interface defaults for all events. `_conn_timing` generates `start`/`end` epoch-millisecond timestamps.

| Event Type | Description | Key Fields | Weight |
|---|---|---|---|
| `connection` | Outbound web browsing (85%) or blocked suspicious port (15%). Browsing: Allow on TCP/80 or 443, 0.5–15 KB request, 20–500 KB response. Blocked: non-standard port (23/137/138/666/4444/31337), Block, cefSeverity=5. | `_syslog_id=430002`, `act=Allow or Block`, `dpt=80/443 or suspicious`, `app=HTTPS/HTTP or UNKNOWN`, `cs2=Allow_Outbound_Web or Block_Suspicious_Ports`, `bytesOut=500–15000`, `bytesIn=20000–500000`, `cs6=url_rep`, `requestMethod=GET` (browsing only), `cefSeverity=3 or 5` | 50% |
| `internal_app_tier` | Two-event chain: user→app-server HTTPS (TCP/443), then app-server→database MSSQL (TCP/1433). Both are internal sessions (both interfaces = inside). May return a list of 2 events. | `_syslog_id=430002`, `act=Allow`, user→app: `dpt=443`, `app=HTTPS`, `cs4=App-Server-Zone`; app→db: `dpt=1433`, `app=MSSQL`, `cs3=App-Server-Zone`, `cs4=DB-Zone`, both `cefSeverity=3` | 13% |
| `inbound_block` | External probe blocked at perimeter. `deviceDirection=0`, zones/interfaces reversed. Ports: 22/23/80/443/445/1433/3389/8080/8443. Duration 0–50 ms (blocked at first SYN). | `_syslog_id=430002`, `act=Block`, `src=external`, `dst=internal_server`, `dpt=probe_port`, `cs3=Internet-Zone`, `cs4=Server-Zone`, `deviceDirection=0`, `deviceInboundInterface=outside`, `deviceOutboundInterface=inside`, `bytesOut=0`, `bytesIn=40–100`, `cefSeverity` by port (6 for 445/1433/3389, 3 for 80/443/8080/8443, 5 for 22/23) | 22% |
| `dns_query` | Benign outbound DNS resolution. UDP/53 to a public resolver (8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9, 208.67.222.222). Small bytes (~40–100 query, ~80–400 response). | `_syslog_id=430002`, `act=Allow`, `app=DNS`, `dpt=53`, `proto=17`, `cs2=Allow_Outbound_DNS`, `cs6=Trustworthy`, `bytesOut=40–100`, `bytesIn=80–400`, `cefSeverity=3` | 5% |
| `email_traffic` | Outbound email client connection — IMAPS/993 (50%), SMTPS/465 (30%), or SMTP/587 (20%). IMAPS has large bytesIn (downloading mail); SMTP* has large bytesOut (sending). Duration 5–120 seconds. | `_syslog_id=430002`, `act=Allow`, `app=IMAPS/SMTPS/SMTP`, `dpt=993/465/587`, `proto=6`, `cs2=Allow_IMAPS/Allow_SMTPS/Allow_SMTP`, `cs6=Trustworthy`, `cefSeverity=3`, `bytesIn=1000–300000` (IMAPS) or `bytesOut=1000–300000` (SMTP*) | 5% |
| `ntp_sync` | NTP time synchronisation. UDP/123 to a public NTP server (pool.ntp.org cluster). Tiny payload (~48–76 bytes each direction). Duration under 100 ms. | `_syslog_id=430002`, `act=Allow`, `app=NTP`, `dpt=123`, `proto=17`, `cs2=Allow_NTP_Outbound`, `cs6=Trustworthy`, `bytesOut=48–76`, `bytesIn=48–76`, `cefSeverity=3` | 3% |
| `software_update` | Large software patch download from Windows Update, Microsoft Update, or AV definition servers. Very large bytesIn (5 MB–200 MB), small bytesOut. Duration 30 seconds–10 minutes. | `_syslog_id=430002`, `act=Allow`, `app=HTTPS`, `dpt=443`, `cs2=Allow_Software_Updates`, `cs6=Trustworthy`, `cefSeverity=3`, `bytesOut=300–2000`, `bytesIn=5MB–200MB`, `dhost=windowsupdate.com/update.microsoft.com/etc.` | 2% |

---

## Threat Events

Threat events are dispatched from `_generate_threat_log`. Multi-event generators return a list of CEF strings and are noted below. Single-event generators return a `(fields, cef_name)` tuple that is formatted by `_format_firepower_cef`.

| Threat Key | Category | Description | Syslog ID / Key Fields | Weight |
|---|---|---|---|---|
| `ips` | Intrusion Prevention | Inbound IPS event: external attacker targeting an internal server. `deviceDirection=0`, zones/interfaces reversed. Picks from `firepower_config.ips_rules` or falls back to `ET-WEB-SQL-INJECTION`. | `_syslog_id=430001` (Intrusion Event), `act=Block`, `src=external`, `dst=internal_server`, `dpt=80/443/445/1433/3389/8080/8443`, `cs5=category/cs5Label=ThreatCategory`, `cs6=ips_policy/cs6Label=IntrusionPolicy`, `cefSeverity=7–10`, `deviceDirection=0`, `bytesIn=0`, `reason=Intrusion Policy Violation` | 20 |
| `malware` | AMP File Malware | Internal host downloading a file detected as malware. Picks from `firepower_config.malicious_files`. MD5 hash in `fileHash` (32 chars → xdm.target.file.md5); SHA256 in `cs1`. File size: EXE/DLL 50 KB–10 MB, ZIP/RAR/7Z 1–100 MB. Source process: browser or suspicious processes. | `_syslog_id=411002` (Malware Event), `act=Block`, `dpt=80`, `app=HTTP`, `fname`, `fileHash=md5(32)`, `fileType`, `fsize`, `filePath=C:/Users/.../fname`, `sproc=browser_or_suspicious`, `dhost=malware_domain`, `request=http://domain/fname`, `cs1=sha256/cs1Label=SHA256`, `cs6=disposition_source/cs6Label=DispositionSource`, `cefSeverity=10`, `requestMethod=GET` | 15 |
| `url_filtering` | URL Category Block | Internal user blocked from accessing a prohibited URL category. Picks from `firepower_config.blocked_url_categories`. | `_syslog_id=410001` (URL logging), `act=Block`, `dpt=443`, `app=HTTPS`, `dhost=blocked_domain`, `request=https://domain/`, `cs5=category/cs5Label=URLCategory`, `cs6=url_rep/cs6Label=URLReputation`, `cefSeverity=5`, `bytesOut=200–800`, `bytesIn=0`, `requestMethod=GET` | 12 |
| `security_intel` | Security Intelligence | DNS query to a known-malicious domain blocked by the Security Intelligence feed. UDP/53. Near-instant block (0–100 ms). | `_syslog_id=430005` (Security Intelligence Event), `act=Block`, `dpt=53`, `proto=17`, `dst=8.8.8.8`, `dhost=malicious_domain`, `request=malicious_domain`, `cs5=SecurityIntelligence`, `cs6=DNS Block List/cs6Label=SecurityIntelligenceCategory`, `cefSeverity=8`, `bytesOut=50–150`, `bytesIn=0` | 10 |
| `port_scan` | Reconnaissance | External attacker scanning sequential ports on an internal server. 20–50 blocked CONNECTION events from the same source IP. `deviceDirection=0`. Returns list. | `_syslog_id=430002`, `act=Block`, `src=external`, `dst=internal_server`, `dpt` varies (sorted sample from 21/22/23/25/53/80/110/135/139/443/445/1433/1521/3306/3389/5900/8080/8443), `cs6=Suspicious`, `cefSeverity=6`, `bytesOut=0`, `bytesIn=40–60`, `deviceDirection=0` | 10 |
| `brute_force` | Credential Attack | External IP making 20–60 blocked TCP connection attempts to the same service port on an internal server. `deviceDirection=0`. Services: SSH/22 (sev 7), RDP/3389 (sev 8), SMB/445 (sev 7), WinRM/5985 (sev 6), WinRM/5986 (sev 6). Returns list. | `_syslog_id=430002`, `act=Block`, `src=external`, `dst=internal_server`, `dpt=22/3389/445/5985/5986`, `app=SSH/RDP/SMB/WinRM`, `cefSeverity=7–8`, `deviceDirection=0`, `bytesOut=0`, `bytesIn=40–80` | 8 |
| `large_file_upload` | Data Exfiltration | Internal user uploading 100–500 MB to a file-sharing service (mega.nz, wetransfer.com, dropbox.com, etc.) on TCP/443. Duration 30 s–10 min. Single event. | `_syslog_id=430002`, `act=Allow`, `dpt=443`, `app=SSL`, `dhost=upload.domain`, `bytesOut=100MB–500MB`, `bytesIn=1000–5000`, `requestMethod=POST or PUT`, `cs5=File Sharing/cs5Label=URLCategory`, `cs6=Suspicious`, `cefSeverity=6`, long `start/end` window | 6 |
| `ssh_over_https` | Protocol Anomaly | SSH protocol detected on TCP/443 — DPI reveals SSH inside an HTTPS port. Connection is allowed by web rule. Single event. | `_syslog_id=430002`, `act=Allow`, `dpt=443`, `app=SSH` (anomaly: SSH on 443 not HTTPS), `cs5=Secure Shell/cs5Label=ApplicationProtocol`, `cs6=Moderate Risk`, `cefSeverity=6`, `bytesOut=1000–50000`, `bytesIn=1000–50000` | 5 |
| `workstation_smb` | Lateral Movement | Workstation-to-workstation SMB/445 blocked. Both interfaces = inside, both zones = User-Zone. Near-instant block (0–300 ms). Single event. | `_syslog_id=430002`, `act=Block`, `dpt=445`, `app=SMB`, `cs2=Block_Lateral_Movement`, `cs5=Lateral Movement`, `cs6=Suspicious`, `cefSeverity=8`, both interfaces = `inside`, `bytesOut=200–2000`, `bytesIn=0` | 4 |
| `rdp_lateral` | Lateral Movement | Internal RDP blocked — workstation to workstation (50%) or workstation to server. Both interfaces = inside. Single event. | `_syslog_id=430002`, `act=Block`, `dpt=3389`, `app=RDP`, `cs2=Block_Lateral_Movement`, `cs5=Lateral Movement`, `cefSeverity=7`, both interfaces = `inside` | 3 |
| `tor` | Anonymization | Outbound connection to a Tor exit node. Port: 443 (60%), 9001 (30%), 9030 (10%). Blocked by URL category policy. Single event. | `_syslog_id=430002`, `act=Block`, `dpt=443/9001/9030`, `app=Tor`, `dhost=tor-exit-N.unknown`, `cs5=Tor Network`, `cs6=High Risk`, `cefSeverity=7`, `bytesOut=1000–10000`, `bytesIn=1000–10000` | 3 |
| `dns_c2_beacon` | C2 / DNS Tunneling | 15–40 UDP/53 `ALLOW` events to the same suspicious resolver. Volume of allowed queries to a consistent suspicious resolver is the XSIAM detection signal (not a single block). Returns list. | `_syslog_id=430002`, `act=Allow`, `dpt=53`, `proto=17`, `cs2=Allow_Outbound_DNS`, `cs6=Trustworthy` (resolver not on block list), `bytesOut=40–100`, `bytesIn=80–400` | 2 |
| `server_outbound_http` | Command and Control | Internal server initiating outbound HTTP on TCP/80. Allowed (no block rule); the server-as-source + port-80 anomaly is the signal. Single event. | `_syslog_id=430002`, `act=Allow`, `src=internal_server`, `dpt=80`, `app=HTTP`, `suser=SERVER_PROCESS`, `cs5=Uncategorized`, `cs6=Suspicious`, `cefSeverity=7`, `requestMethod=GET` | 2 |
| `internal_smb` | Lateral Movement | Internal user accessing a LAN file server via SMB/445. Both interfaces = inside. Normal business traffic that may appear in threat context. Single event. | `_syslog_id=430002`, `act=Allow`, `dpt=445`, `app=SMB`, `cs2=Allow_Internal_SMB`, `cs3=User-Zone`, `cs4=Server-Zone`, `duser=FILE_SERVER_SVC`, `cs6=Trustworthy`, `cefSeverity=3`, both interfaces = `inside` | 1 |
| `smb_new_host_lateral` | Lateral Movement | SMB/445 ALLOW events from one workstation to 5–10 different internal hosts. Breadth of distinct SMB targets is the XSIAM UEBA signal. Returns list. | `_syslog_id=430002`, `act=Allow`, `dpt=445`, `app=SMB`, `cs5=Lateral Movement`, `cs6=Suspicious`, `cefSeverity=6`, both interfaces = `inside`, 5–10 distinct `dst` addresses | 4 |
| `smb_rare_file_transfer` | Data Staging | Single large SMB/445 session (100 MB – 1 GB bytesIn = reading from share). Volume is the UEBA signal. Single event tuple returned. | `_syslog_id=430002`, `act=Allow`, `dpt=445`, `app=SMB`, `bytesIn=100MB–1GB`, `cs5=Data Staging`, `cs6=Suspicious`, `cefSeverity=7`, both interfaces = `inside`, duration 120–900s | 3 |
| `smb_share_enumeration` | Reconnaissance | 15–40 ALLOW TCP/445 probes to distinct internal IPs. Near-instant sessions (0–100 ms, tiny bytes). Returns list. | `_syslog_id=430002`, `act=Allow`, `dpt=445`, `app=SMB`, `bytesOut=40–200`, `bytesIn=40–200`, `cs5=Network Scan`, `cs6=Suspicious`, `cefSeverity=7`, both interfaces = `inside`, 15–40 distinct `dst` | 5 |
