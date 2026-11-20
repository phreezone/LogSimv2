# Zscaler Web Gateway

**Dataset:** `zscaler` (XSIAM parser)
**Transport:** native syslog to the Broker VM Syslog Collector (Cribl fallback); lands in `zscaler_nssweblog_raw` / `zscaler_nssfwlog_raw`
**Format:** CEF (ArcSight Common Event Format)

Simulates Zscaler NSS (Nanolog Streaming Service) feed events covering web proxy, cloud firewall, DLP, sandbox, and network threat detection. Two distinct log streams are generated: `nssweblog` (web proxy events) and `nssfwlog` (cloud firewall events). These correspond to the two Zscaler NSS feed types and produce different CEF structures.

### Log Stream Differences

| Stream | `log_product` in CEF header | `cef_name` | Typical Events |
|---|---|---|---|
| `nssweblog` | `nssweblog` | `Web Traffic` | Web browsing, malware downloads, DLP, sandbox, data exfil, cloud app control |
| `nssfwlog` | `nssfwlog` | `Firewall Traffic` | Outbound/inbound TCP/UDP, port scan, brute force, Tor, DNS C2, RDP, SSH, SMB |

### Web feed (`nssweblog`): the Cortex feed template

The web line is built by `_format_nss_weblog_cef` in exactly the Feed Output Format that
the Cortex guide *Ingest logs from Zscaler Internet Access* (Syslog Collector applet)
tells admins to paste (Feed Output Type = Custom, Feed Escape Character `=`). The
Zscaler modeling rule (`demisto/content` → `Packs/Zscaler/ModelingRules/ZscalerModelingRule_2_11`)
reads exactly these keys.

```
<14>%s{mon} %02d{dd} %02d{hh}:%02d{mm}:%02d{ss} zscaler-nss CEF:0|Zscaler|NSSWeblog|5.0|%s{action}|%s{reason}|3|
```

| CEF key | Zscaler field | XDM (modeling rule) |
|---|---|---|
| `act` | `%s{action}` | `xdm.observer.action` |
| `app` | `%s{proto}` | `xdm.network.protocol_layers` |
| `cat` | `%s{urlcat}` | `xdm.network.application_protocol_category` |
| `dhost` | `%s{ehost}` | `xdm.network.http.domain` |
| `dst` / `src` | `%s{sip}` / `%s{cip}` | target / source IPs |
| `in` / `out` | `%d{respsize}` / `%d{reqsize}` | `xdm.target.sent_bytes` / `xdm.source.sent_bytes` |
| `outcome` | `%s{respcode}` | `xdm.network.http.response_code` |
| `request` | `%s{eurl}` (no protocol) | `xdm.network.http.url` |
| `rt` | `%s{mon} %02d{dd} %d{yy} %02d{hh}:%02d{mm}:%02d{ss}` (UTC) | sets `_time`; back-dating works (verified) |
| `sourceTranslatedAddress` | `%s{cintip}` | `xdm.source.ipv4` |
| `requestClientApplication` | `%s{ua}` | `xdm.source.user_agent` |
| `requestMethod` | `%s{reqmethod}` | `xdm.network.http.method` |
| `suser` | `%s{login}` | `xdm.source.user.username` |
| `spriv` | `%s{location}` | `xdm.source.zone` |
| `externalId` | `%d{recordid}` | `xdm.session_context_id` |
| `fileType` | `%s{filetype}` (DOWNLOADED file type name, e.g. `RAR Files`) | `xdm.target.process.executable.file_type` |
| `reason` | `%s{reason}` | `xdm.event.outcome_reason` |
| `destinationServiceName` | `%s{appname}` | `xdm.target.interface` |
| `cn1` / `cn1Label=riskscore` | `%d{riskscore}` | `xdm.alert.severity` |
| `cs1` / `cs1Label=dept` | `%s{dept}` | raw only |
| `cs2` / `cs2Label=urlsupercat` | `%s{urlsupercat}` | `xdm.network.http.url_category` |
| `cs3` / `cs3Label=appclass` | `%s{appclass}` | raw only |
| `cs4` / `cs4Label=malwarecat` | `%s{malwarecat}` | `xdm.alert.category` |
| `cs5` / `cs5Label=threatname` | `%s{threatname}` | `xdm.alert.name` |
| `cs6` / `cs6Label=dlpeng` | `%s{dlpeng}` | raw only |
| `ZscalerNSSWeblogURLClass` | `%s{urlclass}` | `xdm.event.type` |
| `ZscalerNSSWeblogDLPDictionaries` | `%s{dlpdict}` | raw only |
| `requestContext` | `%s{ereferer}` | raw only |
| `contenttype` | `%s{contenttype}` | `xdm.network.http.content_type` |
| `unscannabletype` | `%s{unscannabletype}` | raw only |
| `deviceowner` | `%s{deviceowner}` | raw only |
| `devicehostname` | `%s{devicehostname}` | `xdm.source.host.hostname` |

**Opt-in: file names.** The template has no file name. The Zscaler fields are
`%s{filename}` (downloaded file) and `%s{upload_filename}` (uploaded file). They are
appended in labelled slots whose label is the Zscaler field name:

```
flexString1=%s{filename} flexString1Label=filename
flexString2=%s{upload_filename} flexString2Label=upload_filename
```

A file on a POST/PUT is an upload (`flexString2`); otherwise it is a download
(`flexString1`, plus `fileType`). Hunting example:
`dataset = zscaler_nssweblog_raw | filter flexString2Label = "upload_filename" and flexString2 contains "Financial"`.

**Why labelled slots and not the Zscaler names.** Cortex creates a column only for
keys in the CEF dictionary or in its own template. Any other `key=value` is folded
into the value of the key before it, corrupting that field. Live tests (2026-11-14/15)
showed this for `filename=`, `upload_filename=`, `ZscalerNSSWeblogFileName=` and
`ZscalerNSSWeblogUploadFileName=`. The modeling rule maps no file name either. So
nothing outside this table is emitted on the web feed.

Every key is printed on every line, and an empty field reads `None` (as NSS renders a
fixed template). That string therefore also reaches XDM, e.g. `xdm.alert.name = "None"`
on benign events, as it would from a real feed.

### Firewall feed (`nssfwlog`): the Cortex feed template

Built by `_format_nss_fwlog_cef` in exactly the firewall Feed Output Format from the same
Cortex guide, including its `cs6label` (lower-case l; Cortex still files it under the
`cs6Label` column) and `cs5Label` placed before `cs5`. No opt-in fields: the firewall
reference has no file names.

```
<14>%s{mon} %02d{dd} %02d{hh}:%02d{mm}:%02d{ss} zscaler-nss-fw CEF:0|Zscaler|NSSFWlog|5.7|%s{action}|%s{rulelabel}|3|
```

| CEF key | Zscaler field | XDM (modeling rule) |
|---|---|---|
| `act` | `%s{action}` (`Allowed` / `Blocked`) | `xdm.observer.action` |
| `suser` | `%s{login}` | `xdm.source.user.username` |
| `src` / `spt` | `%s{csip}` / `%d{csport}` | `xdm.source.ipv4` / `xdm.source.port` |
| `dst` / `dpt` | `%s{cdip}` / `%d{cdport}` | `xdm.target.ipv4` / `xdm.target.port` |
| `deviceTranslatedAddress` / `deviceTranslatedPort` | `%s{ssip}` / `%d{ssport}` (Zscaler egress) | raw only |
| `destinationTranslatedAddress` / `destinationTranslatedPort` | `%s{sdip}` / `%d{sdport}` | `xdm.target.host.ipv4_addresses` |
| `sourceTranslatedAddress` / `sourceTranslatedPort` | `%s{tsip}` / `%d{tsport}` (client tunnel IP) | `xdm.source.host.ipv4_addresses` |
| `proto` | `%s{ipproto}` (`TCP`; Cortex stores the raw column as `6`) | `xdm.network.ip_protocol` |
| `tunnelType` / `dnat` / `stateful` | `%s{ttype}` / `%s{dnat}` / `%s{stateful}` | raw only |
| `spriv` | `%s{location}` | `xdm.source.user.groups` |
| `reason` | `%s{rulelabel}` | `xdm.event.outcome_reason` |
| `in` / `out` | `%ld{inbytes}` / `%ld{outbytes}` | `xdm.target.sent_bytes` / `xdm.source.sent_bytes` |
| `rt` | `%s{mon} %02d{dd} %02d{hh}:%02d{mm}:%02d{ss}` (no year; UTC) | sets `_time`; back-dating works (verified) |
| `deviceDirection` | literal `1` | raw only |
| `cs1` / `cs1Label=dept` | `%s{dept}` | raw only |
| `cs2` / `cs2Label=nwService` | `%s{nwsvc}` | `xdm.network.rule` (Cortex maps the service here) |
| `cs3` / `cs3Label=nwApp` | `%s{nwapp}` | `xdm.network.application_protocol` |
| `cs4` / `cs4Label=aggregated` | `%s{aggregate}` | raw only |
| `cs6` / `cs6label=threatname` | `%s{threatname}` | `xdm.alert.name` |
| `cn1` / `cn1Label=durationms` | `%d{durationms}` | `xdm.event.duration` |
| `cn2` / `cn2Label=numsessions` | `%d{numsessions}` | raw only |
| `cs5Label=ipCat`, `cs5` | `%s{ipcat}` | `xdm.network.http.url_category` (enum-mapped) |
| `cat` | `%s{threatcat}` | `xdm.alert.category` |
| `destCountry` | `%s{destcountry}` (code, e.g. `USA`) | `xdm.target.location.country` |
| `avgduration` | `%d{avgduration}` | raw only |

The header name is the rule label (`xdm.event.type`). Severity is the template's fixed
`3` (`xdm.alert.severity`). Sessions are not aggregated: `aggregated=No`,
`numsessions=1`, `avgduration=0`. `ttype` is `Z-Tunnel 2.0` for Client Connector users
and `GRE` for site traffic. Neither of those two values is verified against a tenant.

The per-event tables below list the values each generator SETS. The wire format is
the template above.

---

## Benign Events

Benign events are selected from a pool of 11 lambda functions using `random.choice`. The effective slot distribution is: web 3/11 ≈27%, firewall 2/11 ≈18%, video_streaming 2/11 ≈18%, saas_upload 1/11 ≈9%, software_update 1/11 ≈9%, dns 1/11 ≈9%, inbound_block 1/11 ≈9%.

| Event Type | Log Stream | Description | Key Fields |
|---|---|---|---|
| `benign_web_traffic` (×3) | `nssweblog` | Allowed outbound HTTPS web browsing to a configured destination. URL category from `benign_url_categories`. Risk score 1–20. HTTP GET, response 200. | `act=Allow`, `proto=HTTPS`, `requestMethod=GET`, `responsecode=200`, `reason=Allowed`, `urlclass=Business and Productivity`, `riskscore=1–20`, `bytesin=5000–50000`, `bytesout=500–5000`, `cefSeverity=2` |
| `benign_firewall_traffic` (×2) | `nssfwlog` | Allowed outbound TCP connection to a configured destination. Rule `Allow_Web_Outbound`. | `act=Allow`, `proto=6`, `rulelabel=Allow_Web_Outbound`, `reason=Allowed`, `threatcat=None`, `threatname=None`, `spriv=domain users`, `duration_ms=100–300000`, `bytesin=5000–50000`, `bytesout=500–5000`, `cefSeverity=3` |
| `benign_video_streaming` (×2) | `nssweblog` | Video streaming to YouTube, Google Video, Microsoft Teams, Webex, Zoom, or Netflix. Very large bytesIn (sustained download), small bytesOut (client requests). Content-type is `video/mp4`, `video/webm`, or `application/octet-stream`. | `act=Allow`, `proto=HTTPS`, `requestMethod=GET`, `responsecode=200`, `urlcat=Streaming Media or Web Conferencing`, `urlsupercat=Entertainment`, `contenttype=video/mp4 or video/webm or application/octet-stream`, `bytesin=10MB–500MB`, `bytesout=1000–10000`, `cefSeverity=2` |
| `benign_saas_upload` (×1) | `nssweblog` | Cloud storage sync upload — PUT/POST to OneDrive, Box, Dropbox, Google APIs, or SharePoint. Large bytesOut (client→server file sync), small bytesIn (server acknowledgement). | `act=Allow`, `proto=HTTPS`, `requestMethod=PUT or POST`, `responsecode=200/201/204`, `urlcat=Cloud Storage or Office 365`, `contenttype=application/octet-stream`, `appname=Cloud Storage`, `fileName`, `fileType`, `cn2=filesize` (=bytesOut), `cn3=totalsize`, `bytesin=200–2000`, `bytesout=500KB–50MB`, `cefSeverity=2` |
| `benign_software_update` (×1) | `nssweblog` | Patch or definition download from Windows Update, Microsoft, Avast, or Symantec servers. Very large bytesIn (patch download), small bytesOut (request). `useragent=Microsoft-CryptoAPI`. | `act=Allow`, `proto=HTTPS`, `requestMethod=GET`, `responsecode=200`, `urlcat=Computer and Internet Info`, `contenttype=application/octet-stream`, `appclass=Software Updates`, `bytesin=5MB–200MB`, `bytesout=300–2000`, `cefSeverity=1` |
| `benign_dns_query` (×1) | `nssfwlog` | Benign UDP/53 query to a public DNS resolver (8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9, 208.67.222.222). Tiny packets. | `act=Allow`, `proto=17`, `destport=53`, `rulelabel=Allow_DNS_Outbound`, `nwsvc=DNS`, `bytesin=64–512`, `bytesout=32–128`, `duration_ms=1–500`, `cefSeverity=1` |
| `benign_inbound_block` (×1) | `nssfwlog` | External probe blocked at perimeter — simulates inbound reconnaissance or unsolicited connection. Ports: 80/443/22/3389/8080/445/25/3306. | `act=Block`, `proto=6`, `src=ext_ip`, `dst=internal_server`, `rulelabel=Block_Inbound_Probe`, `nwsvc=HTTP/HTTPS/SSH/RDP/etc.`, `threatcat=Network Scan`, `threatname=InboundProbe`, `bytesin=0`, `bytesout=40–100`, `duration_ms=0`, `cefSeverity=4` |

---

## Threat Events

Threat events are selected by weighted random choice from the module's internal `_THREAT_CATALOG` (27 weighted entries, each carrying `weight`, `analytic`, and `xsiam_alert`). **Unlike the other four network modules, Zscaler has no `event_mix.threat` block in `config.json`** — the catalog *is* the effective source of ambient weights, so weights are changed in `modules/zscaler.py`, not config. Multi-event generators return a Python list of CEF strings (noted below). The `scenario_event` parameter supports `THREAT_BLOCK` (web_threat) and `DATA_EXFIL` (dlp_threat or data_exfil_web_traffic). Named threats — including scenario-only ones like `web_c2_beacon` — are also accessible via the `_NAMED_THREATS` dispatch map, and honor a pinned source host via `context['src_ip']`.

| Threat Key | Log Stream | Category | Description | Key Fields | Weight |
|---|---|---|---|---|---|
| `web_threat` | `nssweblog` | Malware Download / C2 | Blocked malicious web traffic — malware download or C2 callback. Picks from `zscaler_config.web_threats`. HTTP GET request blocked with 403. | `act=Block`, `responsecode=403`, `reason=Policy Block`, `urlcat=malware_category`, `urlsupercat=Security`, `urlclass=Malicious Content`, `riskscore=75–100`, `malwarecat`, `threatname=threat_name`, `malwareclass`, `malwaretype`, `requestMethod=GET`, `filename`, `filetype`, `bytesin=0`, `bytesout=60`, `cefSeverity=8` | 12 |
| `data_exfil` | `nssweblog` | Data Exfiltration | Large file upload to cloud storage (5–100 MB) — ALLOWED. The upload is not blocked; the large outbound bytes are the detection signal. | `act=Allow`, `responsecode=201`, `reason=Allowed`, `requestMethod=POST`, `urlcat=Online Storage`, `appname=File Transfer`, `contenttype=application/zip`, `fileName`, `fileType` (archive/pii/document), `cn2=filesize` (=bytesOut), `cn3=totalsize`, `bytesout=5MB–100MB`, `bytesin=100–500`, `cefSeverity=7` | 8 |
| `web_c2_beacon` | `nssweblog` | Command and Control | Web-layer C2 beacon — 12–20 small HTTP callbacks from one host to a C2 host at a regular cadence (the web-proxy counterpart to the DNS C2 beacon). Non-browser user-agent, uncategorized destination, tiny symmetric bytes. Returns list. Named/scenario-only (used by the Beaconing Implant chain). | `act=Allowed`, `responsecode=200`, `reqmethod=GET/POST`, `urlcat=Miscellaneous or Unknown`, `urlclass=Uncategorized`, `useragent=python-requests/Go-http-client/curl/WinHTTP`, `eurl=http://c2/checkin\|/gate.php`, `riskscore=60–90`, `bytesin=120–400`, `bytesout=200–900`, `cefSeverity=5` | *(named)* |
| `dlp_threat` | `nssweblog` | Data Loss Prevention | DLP engine blocks sensitive data upload. Picks from configured DLP engines, dictionaries, and rules. `fileType` matches the engine that fired (Source Code→`.py`/`.java`, PII→`.csv`/`.xlsx`). CEF fields use DLP-specific cs1/cs2/cs3 mapping. | `act=Block`, `responsecode=403`, `reason=DLP Block`, `requestMethod=POST`, `contenttype=application/zip`, `fileName`, `fileType` (engine-matched), `cn2=filesize`, `cn3=totalsize`, `dlpengine`, `dlpdictionary`, `dlprule`, `cefSeverity=6`, cs1=dlpengine/cs2=dlpdictionary/cs3=dlprulename (overrides normal urlcat mapping) | 6 |
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
| `vpn_tor_login` | `nssfwlog` | Credential Theft | Successful VPN/ZPA session from a known Tor exit node. **Conversation-complete**: Tor IP negotiates TLS, authenticates to the VPN, then the VPN-assigned inside IP accesses internal resources (SMB/RDP/HTTPS/SSH). Returns `[TLS handshake, VPN auth success, 1–3 post-auth internal connections]`. XSIAM alert: **Recurring access to rare IP**. | `act=Allow`, `dpt=443` then internal service ports, `src=tor_exit_ip` from `tor_exit_nodes`, VPN-assigned inside IP from `zscaler_config.vpn_pool` (default `10.250.0.0/16`), `rulelabel=Allow_VPN_TLS`, `threatcat=TOR` | 3 |
| `rare_external_rdp` | `nssfwlog` | Lateral Movement / C2 | Outbound RDP from an internal workstation to a **rare external** IP — reverse RDP tunnel or compromised-endpoint pivot. Returns `[DNS precursor, NSSFWlog RDP allowed]`. XSIAM alert: **Rare RDP session to a remote host**. | `act=Allow`, `proto=6`, `dpt=3389`, `nwsvc=RDP`, `rulelabel=Allow_Web_Outbound`, `threatcat=Suspicious Outbound`, `threatname=RareExternalRDP`, `bytesin=50 KB–2 MB`, `bytesout=10–200 KB`, `cefSeverity=5` | 3 |
| `rare_ssh` | `nssfwlog` | Suspicious Activity | Outbound SSH to a rare (first-seen) external IP. Returns `[DNS precursor, NSSFWlog SSH allowed]`. XSIAM alert: **Uncommon SSH session was established**. | `act=Allow`, `proto=6`, `dpt=22`, `nwsvc=SSH`, `rulelabel=Allow_Web_Outbound`, `threatcat=Suspicious Outbound`, `threatname=RareExternalSSH`, `bytesin`/`bytesout` = 1–50 KB each, `cefSeverity=5` | 3 |
| `smtp_spray` | `nssfwlog` | Spam Bot / Malware | Compromised workstation acting as a spam bot — 30–50 short **allowed** TCP connections to **distinct external** IPs on `25`/`587`. Workstations should never connect directly to external MX; XSIAM detects the volume of outbound SMTP from a single non-mail source. Returns list. XSIAM alert: **Spam Bot Traffic**. | `act=Allow`, `proto=6`, `dpt=25` (70%) / `587` (30%), `nwsvc=SMTP`/`SMTPS`, 30–50 distinct `dst`, `threatcat=Spam Bot`, `threatname=SMTP_Spray`, `cefSeverity=5` | 3 |
| `smtp_large_exfil` | `nssfwlog` | Data Exfiltration | Exfiltration via oversized email attachment — one SMTP session carrying 100–500 MB to a real MX range. Returns `[DNS/MX precursor, NSSFWlog SMTP session]`. XSIAM alert: **Large Upload (SMTP)**. | `act=Allow`, `proto=6`, `dpt=587` (80%) / `25` (20%), `nwsvc=SMTP`, `rulelabel=Allow_SMTP_Relay`, `threatcat=Data Exfiltration`, `threatname=SMTP_LargeExfil`, 100–500 MB transfer, dest from MX ranges 74.125.0.0/16, 40.76.0.0/14, 207.46.0.0/16, 198.2.128.0/18, 159.148.0.0/16, `cefSeverity=6` | 2 |
| `ftp_large_exfil` | `nssfwlog` | Data Exfiltration | Exfiltration via outbound FTP — one TCP/21 session carrying 100–500 MB. Returns `[DNS precursor, NSSFWlog FTP session]`. No dedicated Zscaler analytic targets it. | `act=Allow`, `proto=6`, `dpt=21`, `nwsvc=FTP`, `rulelabel=Allow_Web_Outbound`, `threatcat=Data Exfiltration`, `threatname=FTP_LargeExfil`, 100–500 MB transfer, `cefSeverity=6` | 2 |
| `ddns_connection` | `nssfwlog` | C2 Infrastructure | Internal workstation connecting to a known **dynamic DNS** domain — cheap, disposable C2 infrastructure. Two logs: a UDP/53 query resolving the DDNS hostname, then an HTTPS session to the resolved IP. Both events are **allowed** — detection is UEBA-driven. Returns list. XSIAM alert: **Recurring rare domain access to dynamic DNS domain**. | `act=Allow`, `dpt=53` (`proto=17`, `nwsvc=DNS`, `rulelabel=Allow_DNS_Outbound`) then `dpt=443`; hostname = `<subdomain>.<provider>` where provider ∈ {duckdns.org, no-ip.com, dynu.com, afraid.org, hopto.org, zapto.org, sytes.net, ddns.net, servebeer.com, myftp.biz, myvnc.com, redirectme.net} | 3 |
| `large_download` | `nssfwlog` + `nssweblog` | Data Transfer Anomaly | Large **inbound** web transfer — the proxy counterpart to `data_exfil` (huge `bytesin`, small `bytesout`). Returns `[DNS precursor, NSSFWlog TCP/443 allow, NSSWeblog allow]`. XSIAM alert: **Large Download**. | `act=Allow`/`Allowed`, `dpt=443`, `nwsvc=HTTPS`, `threatcat=Large Download`, `threatname=LargeDownload`, `bytesin=500 MB–4 GB`, `bytesout=200–2000`, weblog `urlcat=Online Storage`, `urlclass=Business and Productivity`, `responsecode=200`, `reqmethod=GET`, `riskscore=30–60`; destinations from `zscaler_config.download_destinations` (falls back to `exfil_destinations`) | 3 |
| `reverse_ssh_tunnel` | `nssfwlog` | C2 / Tunneling | Internal host → **external** IP on TCP/22 through the ZIA firewall; 2–4 long-lived sessions to the **same** external host (stable destination = the recurring-rare-destination signal, pinned per source via `_beacon_target_map`). Returns list. XSIAM alert: **Uncommon reverse SSH tunnel to external domain/ip**. | `act=Allow`, `proto=6`, `dpt=22`, `nwsvc=SSH`, stable `dst`, `rulelabel=Allow_Web_Outbound`, `threatcat=Remote Access`, `threatname=ReverseSSHTunnel`, `bytesin`/`bytesout` = 5–80 MB each, `cefSeverity=6` | 2 |

### Non-Analytic events (no built-in XSIAM detection)

> **Rebuild:** every event formerly in this section was re-examined against the Cortex Analytics Alert Reference. Several were rebuilt toward real detectors, new correctly shaped successors were added, and the ones still Non-Analytic now carry the reason. **Rebuilt: ssh_over_https. New: rare_domain_communication.** The per-event verdicts and the cross-module root causes (bare VPN usernames, truthful country labels, rare/recurring destination pools, success-based impossible travel) are in [../firewall-analytics.md](../firewall-analytics.md). Where this page disagrees, that document is current.

The `_THREAT_CATALOG` marks these `analytic: False` — realistic and parseable, but with **no native XSIAM analytic**, so they run only in long-running sessions and are not offered for on-demand firing. Use them for XQL hunting and custom correlation rules. Among the rows above, `web_threat`, `dlp_threat`, `cloud_app_threat`, `sandbox_threat`, `fw_threat`, `brute_force`, and `ssh_over_https` are also `analytic: False` (they are policy/signature blocks Zscaler already decided on, not behavioral analytics).

| Threat Key | Log Stream | Purpose | Key Fields | Weight |
|---|---|---|---|---|
| `vpn_brute_force` | `nssfwlog` | External IP repeatedly failing VPN/ZPA authentication — 20–50 blocked TCP/443 events from a single attacker to the Zscaler cloud connector / RA-VPN gateway. Volume of failures from one source is the signal. Returns list. | `act=Blocked`, `proto=6`, `dpt=443`, `rulelabel=Block_VPN_BruteForce`, `nwsvc=HTTPS`, `threatcat=Brute Force Attack`, `threatname=VPN_BruteForce`, `cefSeverity=7`, gateway from `zscaler_config.vpn_gateway_ip` | 6 |
| `vpn_impossible_travel` | `nssfwlog` | Same user authenticating from two impossibly-distant geos. Each geo emits several **Blocked** door-knock attempts followed by an **Allowed** VPN session — the UEBA impossible-travel detector keys on a fail→success (compromised-credential) pattern, not on bare successful sessions. The benign location is back-dated 5–10 min via `rt` so the two successes sit an impossible distance apart in time. Returns list. | `act=Blocked` ×N then `Allow`, per geo; `benign_ip` (default `68.185.12.14`, United States) then `suspicious_ip` (default `175.45.176.10`, from `_THREAT_COUNTRIES`), IPs from `impossible_travel_scenario` | 3 |

### Scenario Events

The `scenario_event` parameter in `generate_log` enables coordinated kill-chain simulation:

| `scenario_event` value | Mapped To | Description |
|---|---|---|
| `THREAT_BLOCK` | `_generate_threat_web_traffic` | Kill chain step 3: victim's browser hits a phishing/malware domain after a click. Generates a blocked `nssweblog` web threat event for the specified `src_ip` and `user`. |
| `DATA_EXFIL` | `_generate_dlp_web_traffic` (or `_generate_data_exfil_web_traffic` fallback) | Insider threat step 5: large data upload triggers DLP alert. Generates a blocked DLP event or an allowed large-upload event if DLP config is absent. |

## Generated Upload File Names

`_UPLOAD_FILES` was 20 names with no placeholders, so every upload in a month-long run was
one of twenty and a DLP or file-name-cardinality detector could not tell one exfil from the
next. Names are now composed by `modules/threat_files.py` — ~99% unique per draw. See
[value-cardinality.md](../value-cardinality.md).

Zscaler's C2 **domains** were already generated (`session_utils.rare_domain()`), so
cardinality was never the problem there. They carry no family token, which is correct: no
Zscaler rule matches a domain substring — its rules match category fields, which are a
fixed vocabulary by design.
