# Zscaler Web Gateway

**Dataset:** `zscaler` (XSIAM parser)
**Transport:** HTTP (Broker VM NSS feed simulation)
**Format:** CEF (ArcSight Common Event Format)

Simulates Zscaler NSS (Nanolog Streaming Service) feed events covering web proxy, cloud firewall, DLP, sandbox, and network threat detection. Two distinct log streams are generated: `nssweblog` (web proxy events) and `nssfwlog` (cloud firewall events). These correspond to the two Zscaler NSS feed types and produce different CEF structures.

### Log Stream Differences

| Stream | `log_product` in CEF header | `cef_name` | Typical Events |
|---|---|---|---|
| `nssweblog` | `nssweblog` | `Web Traffic` | Web browsing, malware downloads, DLP, sandbox, data exfil, cloud app control |
| `nssfwlog` | `nssfwlog` | `Firewall Traffic` | Outbound/inbound TCP/UDP, port scan, brute force, Tor, DNS C2, RDP, SSH, SMB |

### CEF Header Format

```
CEF:0|Zscaler|{log_product}|6.1|0|{cef_name}|{cefSeverity}|
```

Syslog PRI is `<14>`. All events include `rt` (epoch ms), `suser` (user@domain), `externalId`, `deviceHostName`, `deviceOwner`, `deviceOperatingSystem`, `deviceOperatingSystemVersion`, `sourceTranslatedAddress`, `flexString1`/`flexString1Label=location`, `dept`, `clienttranstime`, `servertranstime`, `ssldecrypted`, `contentclass`.

### Key CEF Field Mappings

**nssweblog fields:**
- `act` → action (Allow/Block)
- `cs2`/`cs2Label=urlcat` → URL category
- `cs5`/`cs5Label=threatname` → threat name
- `cn1`/`cn1Label=threatscore` → threat score
- `dst` → server IP (`sip` field); `src` → client IP (`cip` field)
- `request` → URL (`eurl`); `dhost` → hostname (`ehost`)
- `in`/`out` → bytes in/out
- DLP events override `cs1-cs3` with `dlpengine`, `dlpdictionary`, `dlprulename`

**nssfwlog fields:**
- `act` → action (Allow/Block)
- `cs2`/`cs2Label=nwapp` → rule label
- `cs3`/`cs3Label=nwsvc` → network service name
- `cs6`/`cs6Label=threatname` → threat name
- `cn1`/`cn1Label=duration` → duration in ms
- `src`/`dst` → source/dest IP; `spt`/`dpt` → ports
- `proto` → IP protocol (6=TCP, 17=UDP)
- `cat` → threat category
- `cs4`/`cs4Label=destCountry` → destination country

---

## Benign Events

Benign events are selected from a pool of 11 lambda functions using `random.choice`. The effective slot distribution is: web 3/11 ≈27%, firewall 2/11 ≈18%, video_streaming 2/11 ≈18%, saas_upload 1/11 ≈9%, software_update 1/11 ≈9%, dns 1/11 ≈9%, inbound_block 1/11 ≈9%.

| Event Type | Log Stream | Description | Key Fields |
|---|---|---|---|
| `benign_web_traffic` (×3) | `nssweblog` | Allowed outbound HTTPS web browsing to a configured destination. URL category from `benign_url_categories`. Risk score 1–20. HTTP GET, response 200. | `act=Allow`, `proto=HTTPS`, `requestMethod=GET`, `responsecode=200`, `reason=Allowed`, `urlclass=Business and Productivity`, `riskscore=1–20`, `bytesin=5000–50000`, `bytesout=500–5000`, `cefSeverity=2` |
| `benign_firewall_traffic` (×2) | `nssfwlog` | Allowed outbound TCP connection to a configured destination. Rule `Allow_Web_Outbound`. | `act=Allow`, `proto=6`, `rulelabel=Allow_Web_Outbound`, `reason=Allowed`, `threatcat=None`, `threatname=None`, `spriv=domain users`, `duration_ms=100–300000`, `bytesin=5000–50000`, `bytesout=500–5000`, `cefSeverity=3` |
| `benign_video_streaming` (×2) | `nssweblog` | Video streaming to YouTube, Google Video, Microsoft Teams, Webex, Zoom, or Netflix. Very large bytesIn (sustained download), small bytesOut (client requests). Content-type is `video/mp4`, `video/webm`, or `application/octet-stream`. | `act=Allow`, `proto=HTTPS`, `requestMethod=GET`, `responsecode=200`, `urlcat=Streaming Media or Web Conferencing`, `urlsupercat=Entertainment`, `contenttype=video/mp4 or video/webm or application/octet-stream`, `bytesin=10MB–500MB`, `bytesout=1000–10000`, `cefSeverity=2` |
| `benign_saas_upload` (×1) | `nssweblog` | Cloud storage sync upload — PUT/POST to OneDrive, Box, Dropbox, Google APIs, or SharePoint. Large bytesOut (client→server file sync), small bytesIn (server acknowledgement). | `act=Allow`, `proto=HTTPS`, `requestMethod=PUT or POST`, `responsecode=200/201/204`, `urlcat=Cloud Storage or Office 365`, `contenttype=application/octet-stream`, `appname=Cloud Storage`, `bytesin=200–2000`, `bytesout=500KB–50MB`, `cefSeverity=2` |
| `benign_software_update` (×1) | `nssweblog` | Patch or definition download from Windows Update, Microsoft, Avast, or Symantec servers. Very large bytesIn (patch download), small bytesOut (request). `useragent=Microsoft-CryptoAPI`. | `act=Allow`, `proto=HTTPS`, `requestMethod=GET`, `responsecode=200`, `urlcat=Computer and Internet Info`, `contenttype=application/octet-stream`, `appclass=Software Updates`, `bytesin=5MB–200MB`, `bytesout=300–2000`, `cefSeverity=1` |
| `benign_dns_query` (×1) | `nssfwlog` | Benign UDP/53 query to a public DNS resolver (8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9, 208.67.222.222). Tiny packets. | `act=Allow`, `proto=17`, `destport=53`, `rulelabel=Allow_DNS_Outbound`, `nwsvc=DNS`, `bytesin=64–512`, `bytesout=32–128`, `duration_ms=1–500`, `cefSeverity=1` |
| `benign_inbound_block` (×1) | `nssfwlog` | External probe blocked at perimeter — simulates inbound reconnaissance or unsolicited connection. Ports: 80/443/22/3389/8080/445/25/3306. | `act=Block`, `proto=6`, `src=ext_ip`, `dst=internal_server`, `rulelabel=Block_Inbound_Probe`, `nwsvc=HTTP/HTTPS/SSH/RDP/etc.`, `threatcat=Network Scan`, `threatname=InboundProbe`, `bytesin=0`, `bytesout=40–100`, `duration_ms=0`, `cefSeverity=4` |

---

## Threat Events

Threat events are selected by weighted random choice from `_threat_map` (16 entries). Multi-event generators return a Python list of CEF strings (noted below). The `scenario_event` parameter supports `THREAT_BLOCK` (web_threat) and `DATA_EXFIL` (dlp_threat or data_exfil_web_traffic). Named threats are also accessible via `_NAMED_THREATS` dispatch map.

| Threat Key | Log Stream | Category | Description | Key Fields | Weight |
|---|---|---|---|---|---|
| `web_threat` | `nssweblog` | Malware Download / C2 | Blocked malicious web traffic — malware download or C2 callback. Picks from `zscaler_config.web_threats`. HTTP GET request blocked with 403. | `act=Block`, `responsecode=403`, `reason=Policy Block`, `urlcat=malware_category`, `urlsupercat=Security`, `urlclass=Malicious Content`, `riskscore=75–100`, `malwarecat`, `threatname=threat_name`, `malwareclass`, `malwaretype`, `requestMethod=GET`, `filename`, `filetype`, `bytesin=0`, `bytesout=60`, `cefSeverity=8` | 12 |
| `data_exfil` | `nssweblog` | Data Exfiltration | Large file upload to cloud storage (5–100 MB) — ALLOWED. The upload is not blocked; the large outbound bytes are the detection signal. | `act=Allow`, `responsecode=201`, `reason=Allowed`, `requestMethod=POST`, `urlcat=Online Storage`, `appname=File Transfer`, `contenttype=application/zip`, `bytesout=5MB–100MB`, `bytesin=100–500`, `cefSeverity=7` | 8 |
| `dlp_threat` | `nssweblog` | Data Loss Prevention | DLP engine blocks sensitive data upload. Picks from configured DLP engines, dictionaries, and rules. CEF fields use DLP-specific cs1/cs2/cs3 mapping. | `act=Block`, `responsecode=403`, `reason=DLP Block`, `requestMethod=POST`, `contenttype=application/zip`, `dlpengine`, `dlpdictionary`, `dlprule`, `cefSeverity=6`, cs1=dlpengine/cs2=dlpdictionary/cs3=dlprulename (overrides normal urlcat mapping) | 6 |
| `cloud_app_threat` | `nssweblog` | Application Control | Cloud App Control policy enforcement. Picks from `cloud_app_control_policy`. Block (403) or caution (200) depending on app's configured action. | `act=Block or Allow` (per policy), `responsecode=403 or 200`, `appname=app_name`, `appclass=app_class`, `reason=Cloud App Control: app_name`, `cefSeverity=5 (block) or 2 (caution)` | 5 |
| `sandbox_threat` | `nssweblog` | Sandbox Detonation | File blocked after sandbox detonation — definitive malware verdict. Risk score and threat score both = 100. MD5 hash in `fileHash`. | `act=Block`, `responsecode=403`, `reason=Sandbox Verdict`, `urlcat=Malicious Content`, `riskscore=100`, `malwarecat`, `threatname`, `malwareclass=Sandbox`, `malwaretype`, `fileHash=md5`, `filename`, `filetype`, `threatscore=100`, `bytesin=0`, `bytesout=60`, `cefSeverity=10` | 4 |
| `fw_threat` | `nssfwlog` | Suspicious Outbound | Outbound connection to a TOR exit node (50%) or suspicious IP from config (50%). Port: RDP/3389 (1%), SSH/22 (1%), HTTPS/443 (98%). Blocked. | `act=Block`, `proto=6`, `rulelabel=Block_HighRisk_Geo`, `nwsvc=HTTPS/RDP/SSH`, `threatcat=dest_category`, `threatname=TOR Exit Node or SuspiciousIP`, `cefSeverity=7`, `bytesin=0`, `bytesout=60` | 8 |
| `port_scan` | `nssfwlog` | Reconnaissance | External attacker probing sequential ports on an internal server. 20–50 blocked TCP events from the same attacker IP. Returns list. | `act=Block`, `proto=6`, `src=ext_ip`, `dst=internal_server`, `dpt` varies (21/22/23/25/53/80/110/135/139/443/445/1433/1521/3306/3389/5900/8080/8443 subset), `rulelabel=Block_PortScan`, `nwsvc=PortScan`, `threatcat=Network Scan`, `threatname=PortScan`, `cefSeverity=6`, `bytesin=0`, `bytesout=40–80` | 10 |
| `brute_force` | `nssfwlog` | Credential Attack | High-volume blocked connections from one external IP to one internal server on a single service port. 20–60 events. Services: SSH/22, RDP/3389, SMB/445, WinRM/5985. Returns list. | `act=Block`, `proto=6`, `src=ext_ip`, `dst=internal_server`, `dpt=22/3389/445/5985`, `rulelabel=Block_BruteForce`, `nwsvc=SSH/RDP/SMB/WinRM`, `threatcat=Brute Force Attack`, `threatname=BruteForce_SSH/RDP/SMB/WinRM`, `cefSeverity=7`, `bytesin=0`, `bytesout=40–100` | 8 |
| `tor_connection` | `nssfwlog` | Anonymization | Outbound connection to a known Tor exit node. Port: 443 (60%), 9001 (30%), 9030 (10%). Blocked. Single event. | `act=Block`, `proto=6`, `dst=tor_exit_ip`, `dpt=443/9001/9030`, `rulelabel=Block_TOR_Traffic`, `nwsvc=HTTPS/TOR`, `threatcat=TOR`, `threatname=TOR Exit Node`, `cefSeverity=8` | 6 |
| `dns_c2_beacon` | `nssfwlog` | C2 / DNS Tunneling | 15–40 ALLOWED UDP/53 events to a suspicious resolver (not on block list). Volume pattern is the XSIAM UEBA signal, not a single block. Returns list. | `act=Allow`, `proto=17`, `dpt=53`, `dst=suspicious_resolver`, `rulelabel=Allow_DNS_Outbound`, `nwsvc=DNS`, `threatname=SuspiciousDNS`, `bytesin=64–256`, `bytesout=32–128`, `cefSeverity=4` | 5 |
| `server_outbound_http` | `nssfwlog` | Command and Control | Internal server initiating outbound HTTP on TCP/80. Allowed — detection gap. Anomaly: server as source + port 80 + Allow. Single event. | `act=Allow`, `proto=6`, `src=internal_server`, `dpt=80`, `rulelabel=Allow_Web_Outbound`, `nwsvc=HTTP`, `threatcat=Suspicious Outbound`, `threatname=ServerOutboundHTTP`, `cefSeverity=5`, `bytesin=100–2000`, `bytesout=200–5000` | 4 |
| `rdp_lateral` | `nssfwlog` | Lateral Movement | Workstation-to-workstation RDP on TCP/3389. Blocked by cloud firewall policy. Single event. | `act=Block`, `proto=6`, `src=workstation`, `dst=workstation`, `dpt=3389`, `rulelabel=Block_RDP_Lateral`, `nwsvc=RDP`, `threatcat=Lateral Movement`, `threatname=RDPLateralMovement`, `cefSeverity=6` | 3 |
| `ssh_over_https` | `nssfwlog` | Protocol Anomaly | Suspicious outbound SSH: TCP/443 (70%, suggesting reverse tunnel) or direct TCP/22 from workstation (30%). Blocked. Single event. | `act=Block`, `proto=6`, `dpt=443 or 22`, `rulelabel=Block_SuspiciousSSH`, `nwsvc=HTTPS or SSH`, `threatcat=Tunneling`, `threatname=SSHoverHTTPS or SuspiciousSSH`, `cefSeverity=7` | 3 |
| `smb_new_host_lateral` | `nssfwlog` | Lateral Movement | SMB/445 ALLOW events from one workstation to 5–10 different internal hosts. Breadth of distinct SMB targets is the XSIAM UEBA signal. Returns list. | `act=Allow`, `proto=6`, `dpt=445`, `rulelabel=Allow_Internal_SMB`, `nwsvc=SMB`, `threatcat=Lateral Movement`, `threatname=SMBNewHostLateral`, `cefSeverity=6`, `bytesin=200–5000`, `bytesout=2000–50000` | 4 |
| `smb_rare_file_transfer` | `nssfwlog` | Data Staging | Single ALLOW event with 100 MB – 1 GB `bytesin` (data read from share) on TCP/445. Volume is UEBA detection signal. Single event. | `act=Allow`, `proto=6`, `dpt=445`, `rulelabel=Allow_Internal_SMB`, `nwsvc=SMB`, `threatcat=Data Staging`, `threatname=SMBRareFileTransfer`, `bytesin=100MB–1GB`, `bytesout=1000–50000`, `cefSeverity=7` | 3 |
| `smb_share_enumeration` | `nssfwlog` | Reconnaissance | 15–40 ALLOW TCP/445 events to distinct internal IPs with tiny bytes (40–200 each). Returns list. | `act=Allow`, `proto=6`, `dpt=445`, `rulelabel=Allow_Internal_SMB`, `nwsvc=SMB`, `threatcat=Network Scan`, `threatname=SMBShareEnumeration`, `bytesin=40–200`, `bytesout=40–200`, `cefSeverity=7` | 5 |

### Scenario Events

The `scenario_event` parameter in `generate_log` enables coordinated kill-chain simulation:

| `scenario_event` value | Mapped To | Description |
|---|---|---|
| `THREAT_BLOCK` | `_generate_threat_web_traffic` | Kill chain step 3: victim's browser hits a phishing/malware domain after a click. Generates a blocked `nssweblog` web threat event for the specified `src_ip` and `user`. |
| `DATA_EXFIL` | `_generate_dlp_web_traffic` (or `_generate_data_exfil_web_traffic` fallback) | Insider threat step 5: large data upload triggers DLP alert. Generates a blocked DLP event or an allowed large-upload event if DLP config is absent. |
