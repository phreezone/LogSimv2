# Fortinet FortiGate

**Dataset:** `fortinet_fortigate_raw`
**Transport:** Syslog (TCP)
**Format:** CEF (ArcSight Common Event Format)

Simulates Fortinet FortiGate 7.6.4 CEF syslog events for the XSIAM `fortinet_fortigate_raw` dataset. The `FortiGate_1_3.xif` XIF rule maps CEF extension fields to XDM. The CEF header format is `CEF:0|Fortinet|Fortigate|7.6.4|{logid}|{log_type}:{subtype}|{severity}|`. Syslog PRI is `<182>` (facility local6 = 22×8=176, plus informational = 6). All events include `devid`, `deviceExternalId`, `dvchost`, `FTNTFGTlogid`, `FTNTFGTlevel`, `FTNTFGTsubtype`, `FTNTFGTvd`, and `FTNTFGTeventtime`.

### XDM Field Mappings (key fields from FortiGate_1_3.xif)

| CEF Extension Field | XDM Field |
|---|---|
| `src/spt/shost/suser` | `xdm.source.*` |
| `dst/dpt/dhost/duser` | `xdm.target.*` |
| `out` / `in` | `xdm.source.sent_bytes` / `xdm.target.sent_bytes` |
| `FTNTFGTsentpkt` / `FTNTFGTrcvdpkt` | `xdm.source/target.sent_packets` |
| `FTNTFGTduration` | `xdm.event.duration` (×1000 ms) |
| `FTNTFGTpolicyname` / `profile` / `applist` | `xdm.network.rule` |
| `FTNTFGTattack` / `virus` / `vulnname` | `xdm.alert.original_threat_name` |
| `FTNTFGTattackid` / `virusid` / `vulnid` / `cveid` | `xdm.alert.original_threat_id` |
| `FTNTFGTviruscat` | `xdm.alert.category` |
| `FTNTFGTCRlevel` / `FTNTFGTseverity` | `xdm.alert.severity` |
| `FTNTFGTlogdesc` | `xdm.alert.subcategory` |
| `FTNTFGTqname` / `qtype` / `qclass` | `xdm.network.dns.*` |
| `FTNTFGThttpmethod` / `FTNTFGThttpcode` | `xdm.network.http.*` |
| `request` + `dhost` + `dpt` | `xdm.network.http.url` / `xdm.target.url` |
| `FTNTFGTcipher` / `FTNTFGTtlsver` | `xdm.network.tls.cipher` / `version` |
| `FTNTFGTfilehash` (32 chars=MD5, 64=SHA256) | `xdm.target.file.md5` / `sha256` |
| `FTNTFGTfiletype` / `fname` / `fsize` | `xdm.target.file.*` |
| `FTNTFGTtunnelip` / `FTNTFGTassignip` | `xdm.intermediate.*` |
| `act` / `FTNTFGTsslaction` / `FTNTFGTutmaction` | `xdm.observer.action` |
| `outcome` / `FTNTFGTresult` | `xdm.event.outcome` |
| `FTNTFGTapp` + `FTNTFGTappid` | `xdm.target.application.name` |
| `FTNTFGTsrccountry/city/region` | `xdm.source.location.*` |
| `FTNTFGTdstcountry/city/region` | `xdm.target.location.*` |
| `dvchost` / `deviceExternalId` | `xdm.observer.name` / `unique_identifier` |
| `externalId` | `xdm.network.session_id` |

---

## Benign Events

Benign events are dispatched from `_generate_benign_log` which reads `event_mix.benign` from `fortinet_config` or falls back to hardcoded weights. All traffic events use `_base_traffic_fields` which populates source/dest MAC, source OS, app identification, policy fields, and geo data.

| Event Type | Log ID | Log Type:Subtype | Description | Key Fields | Default Weight |
|---|---|---|---|---|---|
| `traffic_forward` | `0000000013` | `traffic:forward` | Normal outbound web browsing to a benign egress destination. TCP/443 HTTPS, action=accept. Includes TLS cipher/version, HTTP method (GET), referral URL, user agent, and destination geo. | `act=accept`, `dpt=443`, `app=HTTPS`, `FTNTFGThttpmethod=GET`, `FTNTFGThttpcode=200/301/304`, `FTNTFGTcipher=TLS_*`, `FTNTFGTtlsver=TLSv1.3/1.2`, `FTNTFGTscertcname=*.domain`, `outcome=success`, log_level=notice | 45 |
| `inbound_block` | `0000000014` | `traffic:forward` | External probe denied at perimeter by implicit-deny policy. `FTNTFGTpolicyid=0`, `policyname=implicit-deny`. Includes source geo. | `act=deny`, `src=ext_ip`, `dst=internal_server`, `dpt=22/23/80/443/445/1433/3306/3389/8080/8443`, `proto=6`, `FTNTFGTpolicyid=0`, `FTNTFGTpolicyname=implicit-deny`, `outcome=failed`, `reason=no-policy-match`, includes `FTNTFGTsrccountry/city/region` | 18 |
| `webfilter_allow` | `0201009218` | `utm:webfilter` | Outbound web request inspected and allowed by FortiGuard web filter. `FTNTFGTeventtype=ftgd_allow`. Benign FortiGuard category ID in `cat`. | `act=accept`, `dpt=443`, `app=HTTPS`, `FTNTFGTeventtype=ftgd_allow`, `cat=benign_cat_id`, `FTNTFGTcatdesc=General Interest`, `requestContext=General Interest`, `FTNTFGThttpmethod=GET`, `FTNTFGThttpcode=200`, `outcome=success`, log_level=notice | 11 |
| `dns_query` | `1501054802` | `utm:dns` | Outbound DNS query passing through the DNS filter profile. `FTNTFGTeventtype=dns-query`. Query types: A (70%), AAAA (15%), MX (10%), TXT (5%). | `act=passthrough`, `dpt=53`, `proto=17`, `app=DNS`, `FTNTFGTeventtype=dns-query`, `FTNTFGTqname=domain`, `FTNTFGTqtype=A/AAAA/MX/TXT`, `FTNTFGTqclass=IN`, `FTNTFGTipaddr=resolved_ip`, `outcome=success`, log_level=information | 7 |
| `admin_event` | `0100032001` (success) / `0100032002` (failure) | `event:system` | Admin login success (85%) or failure (15%) via HTTPS. Failure uses `reason=name_invalid`. | Success: `act=login`, `outcome=success`, `FTNTFGTlogdesc=Admin login successful`, `duser=admin`, `FTNTFGTmethod=https`, `sproc=https(src_ip)`, log_level=notice; Failure: `outcome=failed`, `reason=name_invalid`, log_level=alert | 4 |
| `vpn_event` | `0101039426` (up) / `0101039428` (down) | `event:vpn` | SSL VPN tunnel up (90%) or login failed/down (10%). Includes tunnel IP, assigned IP, VPN group, and source geo. | Up: `act=tunnel-up`, `outcome=success`, `FTNTFGTtunneltype=ssl-vpn`, `FTNTFGTxauthuser=user`, `FTNTFGTxauthgroup=VPN_Users`, `FTNTFGTtunnelip=10.212.134.x`, `FTNTFGTassignip=...`, log_level=notice; Down: `act=tunnel-down`, `outcome=failed`, `reason=sslvpn_login_permission_denied`, log_level=warning | 4 |
| `ssl_inspection` | `0002000001` | `utm:ssl` | SSL deep-packet inspection certificate event for an HTTPS session. | `act=accept`, `FTNTFGTsslaction=inspect`, `FTNTFGTcipher`, `FTNTFGTtlsver`, `FTNTFGTscertcname=*.domain`, `FTNTFGTscertissuer`, `FTNTFGTccertissuer`, log_level=information | 2 |
| `ntp_sync` | `0000000013` | `traffic:forward` | NTP time synchronisation — UDP/123 to a public NTP pool server. Very short duration (0–1 s), tiny bytes (48–76 each direction). Logged as a standard traffic forward event with `app=NTP`. | `act=accept`, `dpt=123`, `proto=17`, `app=NTP`, `FTNTFGTapp=NTP`, `FTNTFGTappid=16195`, `FTNTFGTappcat=Network.Service`, `FTNTFGTapprisk=low`, `out=48–76`, `in=48–76`, log_level=notice | 4 |
| `antivirus_allow` | `0211008192` | `utm:antivirus` | FortiAV scan verdict: clean file allowed. Models the normal baseline of AV inspection events (the vast majority are clean). Covers file downloads, email attachments, and web content. | `FTNTFGTeventtype=viruscleaned`, `FTNTFGTvirusname=Clean`, `FTNTFGTvirusstatus=Pass`, `FTNTFGTdtype=File`, `FTNTFGTfiletype=EXE/DLL/ZIP/DOCX/XLSX/PDF/MSI/CAB`, `FTNTFGTfilesize=10KB–50MB`, `FTNTFGTfilename=download.ext`, `FTNTFGTurl=https://domain/download.ext`, log_level=information | 3 |
| `ipsec_vpn` | `0101037127` (Phase-1) / `0101037141` (Phase-2) | `event:vpn` | IPSec VPN IKE negotiation — Phase-1 (40%) or Phase-2 (60%), success (90%) or failure (10%). Distinct from SSL VPN; represents site-to-site tunnels or IPSec remote-access clients using IKE (UDP/500) or NAT-T (UDP/4500). | `FTNTFGTeventtype=ike-negotiate or ipsec-negotiate`, `FTNTFGTtunneltype=ipsec`, `FTNTFGTvpntunnel=Site-to-HQ/Branch-VPN/Azure-IPSec/Remote-Access`, `FTNTFGTremotegw=peer_ip`, `dpt=500 or 4500`, `proto=17`, `act=negotiate`, includes source geo | 2 |

---

## Threat Events

Threat events are dispatched from `_generate_threat_log` which reads `event_mix.threat` from `fortinet_config` or falls back to `_DEFAULT_THREAT_EVENTS`. Multi-event generators return a list of CEF strings. All IPS/UTM events use the `FTNTFGTutmaction` field in addition to `act` for the XIF `xdm.observer.action` mapping.

| Threat Key | Log ID | Log Type:Subtype | Category | Description | Key Fields | Weight |
|---|---|---|---|---|---|---|
| `ips` | `0419016384` | `utm:ips` | Intrusion Prevention | Inbound IPS signature trigger. External attacker targeting an internal server. Picks from 15 real FortiGuard IPS signatures or `ips_rules` config. Severity: critical→log_level=critical, high→alert, others→warning. Single event. | `act=reset`, `FTNTFGTutmaction=reset`, `FTNTFGTeventtype=signature`, `FTNTFGTattack=sig_name`, `FTNTFGTattackid`, `FTNTFGTvulncat=Exploit/SQL.Injection/etc.`, `FTNTFGTcveid=CVE-...`, `FTNTFGTseverity=critical/high/medium`, `FTNTFGTCRlevel`, `FTNTFGTref=fortiguard_url`, `FTNTFGTincidentserialno`, `FTNTFGThttpmethod=POST`, includes src geo | 18 |
| `antivirus` | `0702038400` | `utm:antivirus` | Malware | File download blocked by antivirus. SHA256 hash in `FTNTFGTfilehash` (64 chars → `xdm.target.file.sha256`). Picks from `malicious_files` config. `FTNTFGTeventtype=virus`. | `act=blocked`, `FTNTFGTutmaction=blocked`, `FTNTFGTeventtype=virus`, `fname`, `fsize`, `FTNTFGTfilehash=sha256(64)`, `FTNTFGTfiletype`, `FTNTFGTvirus=threat_name`, `FTNTFGTvirusid`, `FTNTFGTviruscat=Virus`, `FTNTFGTCRlevel=critical`, `FTNTFGTseverity=critical`, `outcome=failed`, `app=HTTP`, `dpt=80`, includes dst geo, log_level=alert | 15 |
| `webfilter_block` | `0201008192` | `utm:webfilter` | URL Filtering | URL blocked by FortiGuard category. `FTNTFGTeventtype=ftgd_blk`. Blocked FortiGuard category ID in `cat`. | `act=blocked`, `FTNTFGTutmaction=blocked`, `FTNTFGTeventtype=ftgd_blk`, `cat=blocked_cat_id`, `FTNTFGTcatdesc=category_name`, `requestContext=category_name`, `FTNTFGThttpcode=403`, `FTNTFGTCRlevel=high`, `FTNTFGTseverity=high`, `outcome=failed`, log_level=warning | 12 |
| `large_upload` | `0000000013` | `traffic:forward` | Data Exfiltration | Anomalously large outbound data transfer (100–500 MB) to an exfil destination on TCP/443. `FTNTFGTapp=HTTPS.Upload`, `FTNTFGTappcat=Cloud.Storage`. Single event. | `act=accept`, `dpt=443`, `out=100MB–500MB`, `in=1000–10000`, `FTNTFGTduration=300–1800s`, `FTNTFGTapprisk=high`, log_level=warning | 8 |
| `port_scan` | `0000000014` | `traffic:forward` | Reconnaissance | 30–80 deny events from one internal source to one internal server, each on a different port (1–1023 sample). `FTNTFGTpolicyid=0`, `policyname=implicit-deny`. Returns list. | `act=deny`, `dst=internal_server`, `dpt` varies, `out=0`, `in=0`, `FTNTFGTsentpkt=1`, `FTNTFGTrcvdpkt=0`, `outcome=failed`, `reason=no-policy-match`, log_level=warning | 8 |
| `waf_attack` | `0930022816` | `utm:waf` | Web Attack | WAF HTTP constraint violation. Payloads include SQL injection, XSS, path traversal, SSTI, Log4Shell. 5 WAF event types. Source uses suspicious user agents. Single event. | `act=blocked`, `FTNTFGTutmaction=blocked`, `FTNTFGTeventtype=one_of_waf_events`, `FTNTFGTconstraint=url-param-num/illegal-http-method/etc.`, `FTNTFGTseverity=medium/high`, `request=url?q=payload`, `FTNTFGThttpmethod=GET/POST/PUT`, includes src geo, log_level=warning | 6 |
| `auth_brute_force` | `0100032002` | `event:system` | Credential Attack | Admin console brute force: 20–50 `Admin login failed` events from one external IP against one admin account. `reason` varies: `name_invalid`, `passwd_invalid`, `two-factor-auth-failed`. Returns list. | `FTNTFGTlogdesc=Admin login failed`, `duser=admin_account`, `src=attacker_ip`, `act=login`, `outcome=failed`, `FTNTFGTmethod=https or ssh`, `sproc=https(attacker_ip)`, includes `FTNTFGTsrccountry`, log_level=alert | 7 |
| `vpn_brute_force` | `0101039428` | `event:vpn` | Credential Attack | SSL VPN credential stuffing: 15–40 `tunnel-down` / `sslvpn_login_permission_denied` events from one IP, cycling through 10 candidate usernames. Returns list. | `act=tunnel-down`, `outcome=failed`, `reason=sslvpn_login_permission_denied`, `FTNTFGTxauthuser=user`, `src=attacker_ip`, `dpt=443`, includes `FTNTFGTsrccountry/city`, log_level=warning | 6 |
| `vpn_impossible_travel` | `0101039426` | `event:vpn` | Identity Anomaly | Same user with two `tunnel-up` events from geographically distant IPs in rapid succession. Returns list of 2 events. | Both events: `act=tunnel-up`, `outcome=success`, `FTNTFGTxauthuser=same_user`, `FTNTFGTxauthgroup=VPN_Users`; event 1: `src=benign_ip`, event 2: `src=suspect_ip`, different `FTNTFGTsrccountry/city` | 3 |
| `lateral_movement` | `0000000013` (accept) / `0000000014` (deny) | `traffic:forward` | Lateral Movement | East-west connections to 3–6 internal servers on a single lateral port (445/22/3389/5985/1433/8080). 70% accept, 30% deny. Returns list. | `act=accept or deny`, `dpt=lateral_port`, both interfaces = LAN interface, `FTNTFGTpolicyname=allow-outbound or implicit-deny`, `outcome=success or failed` | 5 |
| `tor_connection` | `0000000013` | `traffic:forward` | Anonymization | Outbound connection to a Tor exit node. Port: 443 (60%), 9001 (30%), 9030 (10%). `FTNTFGTapp=Tor.Browser`, `FTNTFGTappid=16390`, `FTNTFGTappcat=Proxy`, `FTNTFGTapprisk=critical`. Single event. | `act=accept`, `dst=tor_ip`, `dpt=443/9001/9030`, `FTNTFGTapp=Tor.Browser`, `FTNTFGTappcat=Proxy`, `FTNTFGTapprisk=critical`, `FTNTFGTdstcountry=Reserved`, log_level=warning | 3 |
| `dns_c2_beacon` | `1501054802` | `utm:dns` | C2 / DNS Tunneling | 15–40 DNS queries to a suspicious external resolver using DGA-style subdomains of a C2 domain. Query types: A (50%), TXT (35%), MX (15%). `act=passthrough` (not blocked — volume is detection signal). Returns list. | `act=passthrough`, `dpt=53`, `proto=17`, `FTNTFGTeventtype=dns-query`, `FTNTFGTqname=uuid8.c2domain`, `FTNTFGTqtype=A/TXT/MX`, `out=50–100`, `in=50–150`, log_level=warning | 3 |
| `server_outbound_http` | `0000000013` | `traffic:forward` | Command and Control | Internal server initiating outbound HTTP on TCP/80. Anomalous — servers should not browse. `FTNTFGTappcat=Network.Service`. Single event. | `act=accept`, `src=internal_server`, `dpt=80`, `app=HTTP`, `FTNTFGTduration=varies`, log_level (uses `_base_traffic_fields` default) | 2 |
| `rdp_lateral` | (via `_base_traffic_fields`) | `traffic:forward` | Lateral Movement | Internal RDP session on TCP/3389 from a workstation to another workstation or server. Both interfaces = LAN. Single event. | `act=accept or deny` (70/30), `dpt=3389`, `app=RDP`, both interfaces = LAN interface, internal zones | 2 |
| `app_control_block` | (via `_base_traffic_fields`) | `utm:app-ctrl` | Application Control | FortiGuard app control block for a prohibited app from `_APP_CONTROL_BLOCKS` (10 apps: BitTorrent, Tor.Network, TeamViewer, Ultrasurf, CryptoMining.Generic, Hola.VPN, AnyDesk, Discord, Telegram.Desktop, Cobalt.Strike.Beacon). Single event. | `act=blocked`, `FTNTFGTapp=app_name`, `FTNTFGTappid`, `FTNTFGTappcat`, `FTNTFGTapprisk=critical/high/medium/low` | 2 |
| `vpn_tor_login` | `0101039426` | `event:vpn` | Credential Theft | Successful SSL VPN tunnel-up from a Tor exit node IP. Source country=Unknown. Detection signal: TOR IP + tunnel-up + outcome=success. Returns list of 1 event. | `act=tunnel-up`, `outcome=success`, `src=tor_exit_ip`, `FTNTFGTsrccountry=Unknown`, `FTNTFGTxauthuser=user`, `FTNTFGTtunnelip`, `FTNTFGTassignip`, log_level=notice | 3 |
| `smb_new_host_lateral` | `0000000013` | `traffic:forward` | Lateral Movement | SMB/445 accept events from one workstation to 5–10 different internal hosts (LAN east-west). Breadth of distinct SMB targets is XSIAM UEBA signal. Returns list. | `act=accept`, `dpt=445`, `app=SMB`, both interfaces = LAN interface, `FTNTFGTpolicyname=Allow_Internal_SMB`, `outcome=success`, 5–10 distinct `dst` | 4 |
| `smb_rare_file_transfer` | `0000000013` | `traffic:forward` | Data Staging | Single large SMB/445 session (100 MB – 1 GB `out` bytes = reading from share). Duration 120–900 s. Both interfaces = LAN. Single event. | `act=accept`, `dpt=445`, `app=SMB`, `out=100MB–1GB`, `FTNTFGTduration=120–900`, both interfaces = LAN interface, `outcome=success`, `FTNTFGTsentpkt=100000–1000000` | 3 |
| `smb_share_enumeration` | `0000000013` | `traffic:forward` | Reconnaissance | 15–40 short TCP/445 accept probes to distinct internal IPs. `FTNTFGTduration=0`, `FTNTFGTsentpkt=1`, `FTNTFGTrcvdpkt=0`. Returns list. | `act=accept`, `dpt=445`, `app=SMB`, `FTNTFGTduration=0`, `out=40–200`, `in=40–200`, both interfaces = LAN interface, 15–40 distinct `dst` | 5 |
