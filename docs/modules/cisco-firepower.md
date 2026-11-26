# Cisco Firepower

**Dataset:** `cisco_firepower_raw`
**Transport:** Syslog (TCP)
**Format:** CEF, as written by Cisco's eStreamer eNcore client

Simulates the CEF that Cisco's eStreamer eNcore client writes for FMC events, which the
Cortex Cisco Firepower pack ingests into `cisco_firepower_raw` (the pack's "CEF via
eStreamer" path; its other path, raw FTD syslog, is a different format). The reference is
eNcore's CEF adapter, `estreamer/adapters/cef.py` in `CiscoSecurity/fp-05-firepower-cef-connector-arcsight`.
The pack's modeling rule `CiscoFirepower_2_11` maps the extension keys to XDM.

### Line format

`<13>{now} {eNcore host} CEF:0|Cisco|Firepower|6.0|<sig id>|<name>|<severity>|<extension>`

- The syslog header is eNcore's own: the time it wrote the line and the eNcore server's
  hostname (`firepower_config.encore_hostname`, default `encore-01`), not the FTD. The
  FTD's name is `dvchost`.
- Extension keys are sorted. Empty and zero values are dropped. Values are escaped the
  way eNcore does it: backslash, `"`, `]` and `|`.
- `rt`, `start` and `end` are whole seconds × 1000 (eStreamer timestamps are seconds).
- `deviceExternalId` is the FMC's numeric device id (`firepower_config.device_id`).

| Record | Sig id | Name |
|---|---|---|
| Connection (71) | `RNA:1003:1` | `CONNECTION STATISTICS` |
| Intrusion (400) | `INTRUSION:400:<gid>:<sid>` | The rule message |
| File (500) | `File:500:1` | `File Event` |
| File Malware (502) | `FileMalware:502:1` | `File Malware Event` |
| Malware (125) | `FireAMP:125:1` | `FireAMP Event` |

### Fields per record

The formatter (`_fp_encore_fields`) keeps only the keys eNcore can write for the record
(`_FP_ENCORE_KEYS`) and always writes eNcore's constant labels, whatever a generator
built:

| Record | Keys | Always-present labels |
|---|---|---|
| Connection (71) | `src dst spt dpt proto act reason app requestClientApplication suser cs1`–`cs5 deviceInbound/OutboundInterface bytesIn bytesOut rt start end request destinationDnsDomain externalId dvcpid dvchost deviceExternalId`, plus `msg` (kept for hunting; not an eNcore key) | `cs1Label=fwPolicy cs2Label=fwRule cs3Label=ingressZone cs4Label=egressZone cs5Label=secIntelCategory` |
| Intrusion (400) | `src dst spt dpt proto act app requestClientApplication suser cat cn2 cs1`–`cs6 deviceInbound/OutboundInterface rt start externalId dvcpid dvchost deviceExternalId` | `cs1Label=fwPolicy cs2Label=fwRule cs3Label=ingressZone cs4Label=egressZone cs5Label=ipsPolicy cs6Label=ruleId cn1Label=vlan cn2Label=impact` |
| File / File Malware (500/502) | `src dst spt dpt proto act app requestClientApplication suser fname fileHash fileType fsize deviceDirection request cs1`–`cs3 rt start dvcpid dvchost deviceExternalId` | `cs1Label=filePolicy cs2Label=disposition cs3Label=speroDisposition` |
| Malware (125) | as eNcore 125, incl. `outcome` (malware event type) and `deviceDirection` | `cs1Label=policy cs2Label=virusName cs3Label=disposition cs4Label=speroDisposition cs5Label=eventDescription` |

Not in eNcore, so never sent: `shost`, `dhost`, `requestMethod`, `cs6` URL reputation,
`cnt`, `outcome` and `deviceDirection` on connections, `duser` outside 125, `msg` on
intrusion events. `xdm.event.outcome` and `xdm.source.host.hostname` are therefore empty.

### Field values

| Field | Value |
|---|---|
| `app` | Application-protocol name as Cisco's detector list spells it ([appid.cisco.com](https://appid.cisco.com/home)): `NetBIOS-ssn (SMB)`, `DCE/RPC`, `SQL Server`, `Telnet`, `AnyConnect` (RA VPN), `Microsoft WSMan` (WinRM), `RDP`, `DNS`, `HTTPS`, ... `Unknown` when FMC identified none |
| `requestClientApplication` | FMC client name, not a user agent: `Chrome`, `Firefox`, `Safari`, `Edge`, `Internet Explorer`, `cURL`, `AnyConnect SSL Client`, or the protocol client for apps Cisco has a same-name client detector for (`SSH`, `RDP`, `SMTP`, ...). Tools Cisco has no detector for (sqlmap, Nikto, gobuster) and everything else: `Unknown` |
| `suser` | The FMC user (`EXAMPLECORP\user`; Cisco: the username is preceded by the realm). `Unknown` when FMC has no user for the traffic (external attackers, server processes), as eNcore resolves user id 0 |
| `reason` (71) | eNcore's rule reason: `N/A` for a plain access-control match; the number for reasons eNcore has no name for (`2048` = DNS Block on Security Intelligence DNS blocks) |
| `cs5` (71) | Security Intelligence list, only on an SI hit: a Cisco Talos feed category (`CnC`, `Malware`, ...) |
| `cs2` | Access-control rule on connection and intrusion events (`xdm.network.rule`); on intrusion events, the rule that passed the flow to the intrusion policy |
| `cat` (400) | Snort classification description (`Web Application Attack`, `Attempted Information Leak`, ...). None on built-in decoder/stream rules, which carry no classtype in Snort 3 (unverified against FMC) |
| `cs6` (400) | The Snort rule id (sid) |
| `request` | The URL (`clientUrl`); a Security Intelligence DNS block has `destinationDnsDomain` instead |
| `externalId` (71) | eStreamer connection counter, 16-bit |
| `dvcpid` | Snort instance number (1–8) |
| `deviceDirection` (500/502/125) | `1`=Download, `2`=Upload |

### Severity

Severity follows eNcore's CEF adapter and is written only in the CEF header, never as an
extension key:

| Record | Rule |
|---|---|
| Connection (71, `RNA:1003:1`) | `3` when the FMC rule-action id is below 4 (Pending=1, Allow=2, Trust=3), otherwise `7` (Block=4, Block with Reset=5, Interactive Block=7/8). No other value occurs. |
| Intrusion (400) | Snort rule priority × impact level, carried as `cn2` / `cn2Label=impact`: High 10/9/7/8/9, Medium 7/6/4/5/6, Low 3/2/0/1/2 for impact 1 (Red) to 5 (Gray). The priority is the rule's classtype priority (Snort 3 `default_classifications`). |
| File (500), File Malware (502), FireAMP (125) | Threat score ÷ 10 (`0` for a clean file). |

Rule-action ids come from the FMC eStreamer Integration Guide, *Access Control Rule Action
Record Metadata*.

### Intrusion event names

eNcore sets an intrusion event's CEF name to the rule's message, not a fixed label, and
the signature ID is `INTRUSION:400:<gid>:<sid>`. Filter intrusion events with
`cefDeviceEventClassId ~= "^INTRUSION:400:"`. Read the signature from `cefName`; `cs2` is the
access-control rule, and intrusion events have no `msg`.

| Generator | gid | `cefName` |
|---|---|---|
| `ips` | 1 (text rule) | A Cisco Talos rule from the public Snort 3 community ruleset, with its real sid and classtype, e.g. `SERVER-OTHER Apache Log4j logging remote code execution attempt` (58722, attempted-user), `OS-WINDOWS Microsoft Windows SMB remote code execution attempt` (41978, attempted-admin). `firepower_config.ips_rules` may override: `{message: {"sid", "classtype", "ports"}}` |
| `network_anomaly` | 116 / 119 / 123 / 129 / 131 | A Snort 3 built-in rule shown as `(module) message`, e.g. `(stream_tcp) SYN on established session` (129:1), `(tcp) Nmap XMAS attack detected` (116:401), `(stream_ip) teardrop attack` (123:2) |
| scenario `log_type=ips` | 1 | The scenario's `signature`, else the Talos Log4j rule; classification and sid when the message is a known Talos rule |

### File and malware events (eNcore records 500 / 502 / 125)

Firepower's CEF keys are fixed by Cisco's eStreamer eNcore client
(`estreamer/adapters/cef.py`), the CEF path the Cortex Cisco Firepower pack documents.
`_fp_file_events` follows it exactly:

| Record | Header sig / name | When | Labels |
|---|---|---|---|
| 500 | `File:500:1` / `File Event` | A file the file policy identified, clean or unknown (`act=Malware Cloud Lookup`) | `cs1=filePolicy`, `cs2=disposition`, `cs3=speroDisposition` |
| 502 | `FileMalware:502:1` / `File Malware Event` | The file policy blocked malware (`act=Malware Block`) | same as 500 |
| 125 | `FireAMP:125:1` / `FireAMP Event` | The malware event FMC raises for the same network transfer (`outcome=Threat Detected in Network File Transfer`, `act=4`, the raw action byte) | `cs1=policy`, `cs2=virusName`, `cs3=disposition`, `cs4=speroDisposition`, `cs5Label=eventDescription` |

All three carry `fname`, `fileHash` (SHA-256), `fileType`, `fsize`, `deviceDirection`
(eStreamer direction: `1`=Download, `2`=Upload), `dvcpid`, `src`/`dst`/`spt`/`dpt`,
`app`, `suser`, `rt`, `start`, `requestClientApplication` (`Unknown` off HTTP) and
`request` on HTTP.
Severity is the threat score / 10, in the header only. Keys are written sorted, with
no `externalId`, `msg`, zones or endpoint fields (`filePath`, `sproc`), as eNcore
writes them. A network detection has no endpoint path or parent process.

`fileType` is the Firepower file-type name: `MSEXE`, `MSOLE2` (legacy Office) and
`NEW_OFFICE` (Office Open XML) are confirmed in Cisco documentation; `PDF`, `ZIP`, `RAR`,
`7Z` and `ISO` are Snort file-type names. A file the policy wouldn't identify (lnk, js,
hta, csv, txt, gz, images) produces no file event.

Where file events are emitted:

| Generator | Direction | Notes |
|---|---|---|
| `malware` | Download | 502 + 125 after the DNS lookup; the file is redrawn until its type is one Firepower identifies |
| benign FTP (scheduled pull) | Download | `app=FTP Data` on a passive port |
| `ftp_large_exfil` | Upload | 1-3 files (archive / PII / document) within the session's bytes |
| `smtp_large_exfil` | Upload | Only on port 25; 587 is STARTTLS, so the FTD sees no attachment |
| `smb_rare_file_transfer` | Download | 1-3 files read from the share |
| scenario `log_type=malware` | Download | 502 + 125; an unidentified type gives the 125 alone |

The HTTPS upload generators (`large_file_upload`, `large_download`) stay connection-only:
without SSL decryption the FTD cannot see the file.

Hunting example: `dataset = cisco_firepower_raw | filter cefName = "File Event" and deviceDirection = 2 and fname contains "Financial"`.

### Interface Naming Convention

FTD packet-flow perspective: `deviceInboundInterface` = interface where the ingress packet arrived; `deviceOutboundInterface` = interface where the egress packet departed.
- Outbound (LAN→WAN): `deviceInboundInterface=inside`, `deviceOutboundInterface=outside`
- Inbound/IPS (WAN→LAN): `deviceInboundInterface=outside`, `deviceOutboundInterface=inside`
- Internal (LAN→LAN): both interfaces = `inside`

XIF mapping: `xdm.source.interface = deviceOutboundInterface`; `xdm.target.interface = deviceInboundInterface`

---

## Benign Events

The *Key Fields* columns below describe what each generator builds; *Line format* and *Fields per record* above decide what is sent (for example `cs6`, `dhost` and `_syslog_id` never reach the wire, and `app=SMB` goes out as `NetBIOS-ssn (SMB)`).

Benign events are dispatched from `_generate_benign_log` with roll-based proportions. The `_base_fields` helper sets the zone/interface defaults for all events. `_conn_timing` generates `start`/`end` epoch-millisecond timestamps.

| Event Type | Description | Key Fields | Weight |
|---|---|---|---|
| `connection` | Outbound web browsing (85%) or blocked suspicious port (15%). Browsing: Allow on TCP/80 or 443, 0.5–15 KB request, 20–500 KB response. Blocked: non-standard port (23/137/138/666/4444/31337), Block, cefSeverity=7. | `_syslog_id=430002`, `act=Allow or Block`, `dpt=80/443 or suspicious`, `app=HTTPS/HTTP or UNKNOWN`, `cs2=Allow_Outbound_Web or Block_Suspicious_Ports`, `bytesOut=500–15000`, `bytesIn=20000–500000`, `cs6=url_rep`, `requestMethod=GET` (browsing only), `cefSeverity=3` (Allow) or `7` (Block) | 50% |
| `internal_app_tier` | Two-event chain: user→app-server HTTPS (TCP/443), then app-server→database MSSQL (TCP/1433). Both are internal sessions (both interfaces = inside). May return a list of 2 events. | `_syslog_id=430002`, `act=Allow`, user→app: `dpt=443`, `app=HTTPS`, `cs4=App-Server-Zone`; app→db: `dpt=1433`, `app=MSSQL`, `cs3=App-Server-Zone`, `cs4=DB-Zone`, both `cefSeverity=3` | 13% |
| `inbound_block` | External probe blocked at perimeter. zones/interfaces reversed. Ports: 22/23/80/443/445/1433/3389/8080/8443. Duration 0–50 ms (blocked at first SYN). | `_syslog_id=430002`, `act=Block`, `src=external`, `dst=internal_server`, `dpt=probe_port`, `cs3=Internet-Zone`, `cs4=Server-Zone`, `deviceInboundInterface=outside`, `deviceOutboundInterface=inside`, `bytesOut=0`, `bytesIn=40–100`, `cefSeverity=7` | 22% |
| `dns_query` | Benign outbound DNS resolution. UDP/53 to a public resolver (8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9, 208.67.222.222). Small bytes (~40–100 query, ~80–400 response). | `_syslog_id=430002`, `act=Allow`, `app=DNS`, `dpt=53`, `proto=17`, `cs2=Allow_Outbound_DNS`, `cs6=Trustworthy`, `bytesOut=40–100`, `bytesIn=80–400`, `cefSeverity=3` | 5% |
| `email_traffic` | Outbound email client connection — IMAPS/993 (50%), SMTPS/465 (30%), or SMTP/587 (20%). IMAPS has large bytesIn (downloading mail); SMTP* has large bytesOut (sending). Duration 5–120 seconds. | `_syslog_id=430002`, `act=Allow`, `app=IMAPS/SMTPS/SMTP`, `dpt=993/465/587`, `proto=6`, `cs2=Allow_IMAPS/Allow_SMTPS/Allow_SMTP`, `cs6=Trustworthy`, `cefSeverity=3`, `bytesIn=1000–300000` (IMAPS) or `bytesOut=1000–300000` (SMTP*) | 5% |
| `ntp_sync` | NTP time synchronisation. UDP/123 to a public NTP server (pool.ntp.org cluster). Tiny payload (~48–76 bytes each direction). Duration under 100 ms. | `_syslog_id=430002`, `act=Allow`, `app=NTP`, `dpt=123`, `proto=17`, `cs2=Allow_NTP_Outbound`, `cs6=Trustworthy`, `bytesOut=48–76`, `bytesIn=48–76`, `cefSeverity=3` | 3% |
| `software_update` | Large software patch download from Windows Update, Microsoft Update, or AV definition servers. Very large bytesIn (5 MB–200 MB), small bytesOut. Duration 30 seconds–10 minutes. | `_syslog_id=430002`, `act=Allow`, `app=HTTPS`, `dpt=443`, `cs2=Allow_Software_Updates`, `cs6=Trustworthy`, `cefSeverity=3`, `bytesOut=300–2000`, `bytesIn=5MB–200MB`, `dhost=windowsupdate.com/update.microsoft.com/etc.` | 2% |

---

## Threat Events

Threat events are dispatched from `_generate_threat_log`. Multi-event generators return a list of CEF strings and are noted below. Single-event generators return a `(fields, cef_name)` tuple that is formatted by `_format_firepower_cef`.

The **effective** weights are those in `config.json` → `firepower_config.event_mix.threat`; the module's `_DEFAULT_THREAT_EVENTS` catalog is only a fallback used when that config list is absent. A non-empty config list **fully shadows** the catalog, so an event added to the catalog alone is dashboard-selectable but never fires ambiently — add it to both. The Weight column below is the config weight, and each row's XSIAM alert name comes from the catalog's `xsiam_alert` field.

| Threat Key | Category | Description | Syslog ID / Key Fields | Weight |
|---|---|---|---|---|
| `ips` | Intrusion Prevention | Inbound IPS event: external attacker targeting an internal server. zones/interfaces reversed. Picks from `firepower_config.ips_rules` (the message becomes `cefName`). | `INTRUSION:400:1:<sid>`, `act=Blocked`, `src=external`, `dst=internal_server`, `dpt=80/443/445/1433/3389/8080/8443`, `cs2=Allow_Inbound_Published_Services` (fwRule), `cs5=ips_policy` (ipsPolicy), `cs6=<sid>` (ruleId), `cat=classification`, no `msg`, `cn2=impact` (1–5), `cefSeverity` from priority × impact (see *Severity*), `bytesIn=0`, `reason=Intrusion Policy Violation` | 30 |
| `malware` | AMP File Malware | Internal host downloads malware over HTTP; the FTD file policy blocks it. Emits the DNS lookup, a File Malware Event (502) and the matching FireAMP Event (125). File name from `threat_files`, redrawn until Firepower identifies the type. See *File and malware events* above. | `FileMalware:502:1` + `FireAMP:125:1`, `dpt=80`, `app=HTTP`, `fname`, `fileHash=sha256`, `fileType` (Firepower name), `fsize`, `deviceDirection=1`, `request=http://domain/fname` | 25 |
| `url_filtering` | URL Category Block | Internal user blocked from accessing a prohibited URL category. Picks from `firepower_config.blocked_url_categories`. | `_syslog_id=410001` (URL logging), `act=Block`, `dpt=443`, `app=HTTPS`, `dhost=blocked_domain`, `request=https://domain/`, `cs5=category/cs5Label=URLCategory`, `cs6=url_rep/cs6Label=URLReputation`, `cefSeverity=7`, `bytesOut=200–800`, `bytesIn=0`, `requestMethod=GET` | 20 |
| `security_intel` | Security Intelligence | DNS query to a known-malicious domain blocked by the Security Intelligence feed. UDP/53. Near-instant block (0–100 ms). | `_syslog_id=430005` (Security Intelligence Event), `act=Block`, `dpt=53`, `proto=17`, `dst=8.8.8.8`, `dhost=malicious_domain`, `request=malicious_domain`, `cs5=SecurityIntelligence`, `cs6=DNS Block List/cs6Label=SecurityIntelligenceCategory`, `cefSeverity=7`, `bytesOut=50–150`, `bytesIn=0` | 15 |
| `port_scan` | Reconnaissance | External attacker scanning sequential ports on an internal server. 20–50 blocked CONNECTION events from the same source IP. . Returns list. | `_syslog_id=430002`, `act=Block`, `src=external`, `dst=internal_server`, `dpt` varies (sorted sample from 21/22/23/25/53/80/110/135/139/443/445/1433/1521/3306/3389/5900/8080/8443), `cs6=Suspicious`, `cefSeverity=7`, `bytesOut=0`, `bytesIn=40–60`, | 10 |
| `brute_force` | Credential Attack | External IP making 20–60 blocked TCP connection attempts to the same service port on an internal server. . Services: SSH/22, RDP/3389, SMB/445, WinRM/5985, WinRM/5986. Returns list. | `_syslog_id=430002`, `act=Block`, `src=external`, `dst=internal_server`, `dpt=22/3389/445/5985/5986`, `app=SSH/RDP/SMB/WinRM`, `cefSeverity=7`, `bytesOut=0`, `bytesIn=40–80` | 8 |
| `large_file_upload` | Data Exfiltration | Internal user uploading 100–500 MB to a file-sharing service (mega.nz, wetransfer.com, dropbox.com, etc.) on TCP/443. Duration 30 s–10 min. Single event. | `_syslog_id=430002`, `act=Allow`, `dpt=443`, `app=SSL`, `dhost=upload.domain`, `bytesOut=100MB–500MB`, `bytesIn=1000–5000`, `requestMethod=POST or PUT`, `cs5=File Sharing/cs5Label=URLCategory`, `cs6=Suspicious`, `cefSeverity=3`, long `start/end` window | 10 |
| `ssh_over_https` | Protocol Anomaly | SSH protocol detected on TCP/443 — DPI reveals SSH inside an HTTPS port. Connection is allowed by web rule. Single event. | `_syslog_id=430002`, `act=Allow`, `dpt=443`, `app=SSH` (anomaly: SSH on 443 not HTTPS), `cs5=Secure Shell/cs5Label=ApplicationProtocol`, `cs6=Moderate Risk`, `cefSeverity=3`, `bytesOut=1000–50000`, `bytesIn=1000–50000` | 5 |
| `workstation_smb` | Lateral Movement | Workstation-to-workstation SMB/445 blocked. Both interfaces = inside, both zones = User-Zone. Near-instant block (0–300 ms). Single event. | `_syslog_id=430002`, `act=Block`, `dpt=445`, `app=SMB`, `cs2=Block_Lateral_Movement`, `cs5=Lateral Movement`, `cs6=Suspicious`, `cefSeverity=7`, both interfaces = `inside`, `bytesOut=200–2000`, `bytesIn=0` | 5 |
| `rdp_lateral` | Lateral Movement | Internal RDP blocked — workstation to workstation (50%) or workstation to server. Both interfaces = inside. Single event. | `_syslog_id=430002`, `act=Block`, `dpt=3389`, `app=RDP`, `cs2=Block_Lateral_Movement`, `cs5=Lateral Movement`, `cefSeverity=7`, both interfaces = `inside` | 3 |
| `tor` | Anonymization | Outbound connection to a Tor exit node. Port: 443 (60%), 9001 (30%), 9030 (10%). Blocked by URL category policy. Single event. | `_syslog_id=430002`, `act=Block`, `dpt=443/9001/9030`, `app=Tor`, `dhost=tor-exit-N.unknown`, `cs5=Tor Network`, `cs6=High Risk`, `cefSeverity=7`, `bytesOut=1000–10000`, `bytesIn=1000–10000` | 3 |
| `dns_c2_beacon` | C2 / DNS Tunneling | 15–40 UDP/53 `ALLOW` events to the same suspicious resolver. Volume of allowed queries to a consistent suspicious resolver is the XSIAM detection signal (not a single block). Returns list. | `_syslog_id=430002`, `act=Allow`, `dpt=53`, `proto=17`, `cs2=Allow_Outbound_DNS`, `cs6=Trustworthy` (resolver not on block list), `bytesOut=40–100`, `bytesIn=80–400` | 2 |
| `server_outbound_http` | Command and Control | Internal server initiating outbound HTTP on TCP/80. Allowed (no block rule); the server-as-source + port-80 anomaly is the signal. Single event. | `_syslog_id=430002`, `act=Allow`, `src=internal_server`, `dpt=80`, `app=HTTP`, `suser=SERVER_PROCESS`, `cs5=Uncategorized`, `cs6=Suspicious`, `cefSeverity=3`, `requestMethod=GET` | 2 |
| `internal_smb` | Lateral Movement | Internal user accessing a LAN file server via SMB/445. Both interfaces = inside. Normal business traffic that may appear in threat context. Single event. | `_syslog_id=430002`, `act=Allow`, `dpt=445`, `app=SMB`, `cs2=Allow_Internal_SMB`, `cs3=User-Zone`, `cs4=Server-Zone`, `duser=FILE_SERVER_SVC`, `cs6=Trustworthy`, `cefSeverity=3`, both interfaces = `inside` | 1 |
| `smb_new_host_lateral` | Lateral Movement | SMB/445 ALLOW events from one workstation to 5–10 different internal hosts. Breadth of distinct SMB targets is the XSIAM UEBA signal. Returns list. | `_syslog_id=430002`, `act=Allow`, `dpt=445`, `app=SMB`, `cs5=Lateral Movement`, `cs6=Suspicious`, `cefSeverity=3`, both interfaces = `inside`, 5–10 distinct `dst` addresses | 4 |
| `smb_rare_file_transfer` | Data Staging | Single large SMB/445 session (100 MB – 1 GB bytesIn = reading from share). Volume is the UEBA signal. Single event tuple returned. | `_syslog_id=430002`, `act=Allow`, `dpt=445`, `app=SMB`, `bytesIn=100MB–1GB`, `cs5=Data Staging`, `cs6=Suspicious`, `cefSeverity=3`, both interfaces = `inside`, duration 120–900s | 3 |
| `smb_share_enumeration` | Reconnaissance | 15–40 ALLOW TCP/445 probes to distinct internal IPs. Near-instant sessions (0–100 ms, tiny bytes). Returns list. | `_syslog_id=430002`, `act=Allow`, `dpt=445`, `app=SMB`, `bytesOut=40–200`, `bytesIn=40–200`, `cs5=Network Scan`, `cs6=Suspicious`, `cefSeverity=3`, both interfaces = `inside`, 15–40 distinct `dst` | 5 |
| `vpn_tor_login` | Credential Theft | Successful RA-VPN session from a known Tor exit node — valid corporate credentials authenticated via Tor. **Conversation-complete** in three phases: (1) inbound TLS handshake Tor→`outside:443`, (2) SSL VPN session established (the primary detection event), (3) 1–3 post-auth connections from the VPN-assigned inside IP (pool `firepower_config.vpn_pool`, default `10.250.0.0/16`) to internal servers over SMB/RDP/HTTPS. XSIAM alert: **Recurring access to rare IP**. Returns list. | `_syslog_id=430002`, `src=tor_exit_ip`, `dpt=443` then internal `dpt=445/3389/443`, VPN-assigned `10.250.x.x` source on post-auth events | 3 |
| `rare_external_rdp` | Lateral Movement / C2 | Outbound RDP from an internal workstation to a **rare external** public IP — reverse RDP tunnel, RDP-based C2, or a compromised endpoint pivoting. Conversation-complete: DNS resolution precedes the session. XSIAM alert: **Rare RDP session to a remote host**. Returns list. | `_syslog_id=430002`, `dpt=3389`, `dhost=rdp-<ip>.example.net`, `bytesOut=10–200 KB`, `bytesIn=50 KB–2 MB`, `duration=1–30min`, preceded by a DNS precursor log | 3 |
| `rare_ssh` | Suspicious Activity | Outbound SSH to a rare (first-seen) external IP. Conversation-complete: DNS resolution precedes the session. XSIAM alert: **Uncommon SSH session was established**. Returns list. | `_syslog_id=430002`, `act=Allow`, `app=SSH`, `dpt=22`, `dhost=ssh-<ip>.example.net`, `duration=30s–10min`, preceded by a DNS precursor log | 3 |
| `smtp_spray` | Spam Bot / Malware | Compromised workstation acting as a spam bot — 30–50 short SMTP sessions to **distinct external** IPs on `25`/`587`. Workstations never connect directly to external MX in normal operation. XSIAM alert: **Spam Bot Traffic**. Returns list. | `_syslog_id=430002`, `act=Allow`, `app=SMTP`, `dpt=25` (70%) / `587` (30%), 30–50 distinct `dst`, `bytesOut=2–50 KB`, `bytesIn=200–2000`, `duration=1–30s` | 3 |
| `smtp_large_exfil` | Data Exfiltration | Exfiltration via oversized email attachment — one long SMTP session carrying 100–500 MB outbound to a real MX range (normal attachments rarely exceed 25 MB). Conversation-complete: DNS MX lookup precedes the session. XSIAM alert: **Large Upload (SMTP)**. Returns list. | `_syslog_id=430002`, `app=SMTP`, `dpt=587` (80%) / `25` (20%), `dhost∈{smtp.gmail.com, smtp.outlook.com, smtp.mail.yahoo.com, smtp.protonmail.ch, mail.external-partner.com}`, `bytesOut=100–500 MB`, `duration=5–20min` | 2 |
| `ftp_large_exfil` | Data Exfiltration | Exfiltration via outbound FTP from an internal workstation — one long session with 100–500 MB outbound. FTP is rare in modern enterprises, so this volume is a strong signal. Conversation-complete: DNS resolution precedes the session. XSIAM alert: **Large Upload (FTP)**. Returns list. | `_syslog_id=430002`, `app=FTP`, `dhost=ftp-<ip>.example.net`, `bytesOut=100–500 MB`, `bytesIn=500–10000`, `duration=5–30min`, preceded by a DNS precursor log | 2 |
| `ddns_connection` | C2 Infrastructure | Internal workstation connecting to a known **dynamic DNS** domain — DDNS is commonly used for cheap C2. Two logs: the DNS query resolving the DDNS hostname, then an HTTPS session to the resolved IP. XSIAM alert: **Recurring rare domain access to dynamic DNS domain**. Returns list. | `_syslog_id=430002`, DNS query then `dpt=443`, `dhost=<subdomain>.<provider>` where provider ∈ {duckdns.org, no-ip.com, dynu.com, afraid.org, hopto.org, zapto.org, sytes.net, ddns.net, servebeer.com, myftp.biz, myvnc.com, redirectme.net} | 3 |
| `large_download` | Data Transfer Anomaly | Large **inbound** transfer — flips the byte direction of `large_file_upload` (huge `bytesIn`, small `bytesOut`). DNS precursor then a 500 MB–4 GB download from a file-sharing CDN. XSIAM alert: **Large Download**. Returns list. | `_syslog_id=430002`, `act=Allow`, `app=SSL`, `dpt=443`, `dhost=cdn.<file_sharing_domain>`, `requestMethod=GET`, `bytesIn=500 MB–4 GB`, `bytesOut=2–40 KB`, `cs5=File Sharing`, `duration=1–15min` | 3 |
| `dns_tunneling` | C2 / DNS Tunneling | High-volume DNS with long, high-entropy **encoded labels** to one resolver — data-in-DNS exfil. Distinct from `dns_c2_beacon` (recurrence-only): here the signal is qname **length + entropy + query volume**. 40–90 queries; resolver and tunnel domain are **stable per source** via `_dns_tunnel_target_map`. XSIAM alert: **DNS Tunneling**. Returns list. | `_syslog_id=430002`, `app=DNS`, `proto=17`, `dpt=53`, `destinationDnsDomain=<b32(32–48)>.<b32(16–32)>.<tunnel_domain>` (genuine FTD DNS field → `dnsQuery.data`), tunnel domains from `firepower_config.dns_tunnel_domains` | 3 |
| `reverse_ssh_tunnel` | C2 / Tunneling | Internal host → **external** IP on TCP/22; 2–4 long-lived sessions to the **same** external host with high bidirectional volume. XSIAM alert: **Uncommon reverse SSH tunnel to external domain/ip**. Returns list. | `_syslog_id=430002`, `act=Allow`, `app=SSH`, `dpt=22`, stable `dst`, `bytesOut`/`bytesIn` = 5–80 MB each, `duration=30min–4h`, `cs5=Remote Access` | 2 |
| `ldap_recon` | Reconnaissance | One host querying **many** domain controllers on LDAP `389`/`636`, 3–6 sessions per DC — breadth plus bulk result volume is the signal. XSIAM alert: **Suspicious reconnaissance using LDAP**. Returns list. | `_syslog_id=430002`, `app=LDAP`/`LDAPS`, `dpt=389/636`, small requests (2–40 KB) / large responses (20–400 KB), `cs4=User-Zone`, `cs5=Reconnaissance`, DCs from `domain_controllers` | 3 |

### Non-Analytic events (no built-in XSIAM detection)

> **Rebuild:** every event formerly in this section was re-examined against the Cortex Analytics Alert Reference. Several were rebuilt toward real detectors, new correctly shaped successors were added, and the ones still Non-Analytic now carry the reason. **Rebuilt: vpn_brute_force, vpn_impossible_travel, ssh_over_https, internal_smb. New: torrent_client.** The per-event verdicts and the cross-module root causes (bare VPN usernames, truthful country labels, rare/recurring destination pools, success-based impossible travel) are in [../firewall-analytics.md](../firewall-analytics.md). Where this page disagrees, that document is current.

The module's `_DEFAULT_THREAT_EVENTS` catalog marks these `analytic: False` — they are realistic and parseable but have **no native XSIAM 3rd-party-firewall analytic**, so they run only in long-running sessions and are not offered for on-demand firing. They are intended for XQL hunting and custom correlation rules. Among the rows already listed above, `ips`, `malware`, `url_filtering`, `security_intel`, `brute_force`, `ssh_over_https`, and `internal_smb` are also `analytic: False` (their detections come from other data sources — XDR Agent, Identity, etc.).

| Threat Key | Purpose | Syslog ID / Key Fields | Weight |
|---|---|---|---|
| `vpn_brute_force` | RA-VPN credential stuffing — one external IP failing auth 20–50 times. FTD RA-VPN auth appears as connection events to the outside interface on 443, blocked (`reason=N/A`: eNcore has no VPN failure reason; real RA-VPN auth failures arrive as FTD syslog, not eStreamer connection events). Returns list. | `_syslog_id=430002`, `src=external attacker`, `dpt=443`, `cs3=Internet-Zone`, `cs4=VPN-Zone`, `suser=EXTERNAL_ATTACKER`, 20–50 failures | 6 |
| `vpn_impossible_travel` | Same user authenticating from two impossibly-distant geos. Each location emits several **FAILED** auth events then a **SUCCESS** — the UEBA impossible-travel detector keys on a fail→success (compromised-credential) pattern, not on bare successful logins. Legitimate location back-dated 5–10 min; `rt`/`start` carry the gap. IPs from `impossible_travel_scenario`. Returns list. | `_syslog_id=430002`, `dpt=443`, `outcome=FAILURE` ×N then `outcome=SUCCESS`, per geo; `benign_ip` (default `68.185.12.14`) then `suspicious_ip` (default `175.45.176.10`), 5–10 min apart | 3 |
| `app_control` | Application Control block — DPI identifies and blocks prohibited apps regardless of port (P2P, anonymizers, remote access, gaming). | `_syslog_id=430002`, `act=Block`, app ∈ {BitTorrent/6881, Tor Browser/9001, TeamViewer/5938, Skype/443, Dropbox/443, WhatsApp/443, uTorrent/6881, Freenet/9481, I2P/4444, Steam/27036, Psiphon/443, Remote Desktop/3389} with its category | 4 |
| `network_anomaly` | Network-level anomaly / DoS drop by the FTD network-analysis engine, before the application layer — protocol anomalies, malformed packets, volume attacks. | `INTRUSION:400:<gid>:<sid>` with a Snort 3 built-in rule as `cefName` (see *Intrusion event names*), `cs2=Allow_Inbound_Published_Services`, `cs6=<sid>`, no `msg`, `proto=6/17/1`, `src=external`, `dst=internal_server` | 4 |

## Generated Values

See [value-cardinality.md](../value-cardinality.md) for the full reasoning.

- **Malicious DNS domains** were **three** fixed entries, so every AMP and
  security-intelligence event in a run named one of three hosts. Now generated, with the
  family token preserved (`malware-distro-*` for delivery, `command-control-*` for
  callbacks).
- **Malware file identity** was six fixed dicts. `fname`, `fileType` and `threatname` are
  now generated together, and the AV detection name's prefix matches the file type —
  `JS.Trojan.Nemucod`, `W97M.Downloader.gen`, `Android.Agent.G` — rather than being
  picked independently of it.
- **Large uploads and downloads** now draw from the shared `exfiltration_destinations`
  pool (60 real services) that Check Point, ASA, FortiGate and Zscaler already used.
  Firepower was the one outlier, with three defects: a separate four-entry
  `file_sharing_domains` list (since removed from `config.json`), a destination IP
  unrelated to the domain, and an invented `upload.` / `cdn.` host prefix
  (`upload.pastebin.com` does not exist). Destinations went from 4 to ~130 distinct per 300
  events, each curated IP now falls inside that service's own range so the DNS precursor
  and the transfer name the same host, and links use the service's real format
  (`pastebin.com/raw/...`, `filebin.net/...`). Long-tail destinations are labelled
  `Uncategorized` rather than `File Sharing`.
