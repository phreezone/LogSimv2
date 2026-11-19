# Palo Alto Networks NGFW

**Dataset:** `panw_ngfw_traffic_raw`
**Transport:** Syslog (TCP, default port 514 — `panw_ngfw_config.syslog_port`)
**Format:** CEF (PAN-OS Syslog Collector custom log format)
**Module:** `modules/panw_ngfw.py`

Simulates Palo Alto Networks Next-Generation Firewall (PAN-OS) **traffic** logs for the
XSIAM `panw_ngfw_traffic_raw` dataset. Logs are sent as CEF over syslog to the Broker VM's
**Syslog Collector** applet configured with **Format = CEF** (Cortex XDR/XSIAM *"Ingest
Next-Generation Firewall logs using the Syslog collector"*). Cortex parses PAN-OS natively —
no content pack install is required.

## CEF format

```
CEF:0|PANW|NGFW_CEF|<sw_version>|<subtype>|<type>|1| __firewall_type=firewall.traffic
    __timestamp=<iso> __tz=+00:00 log_type=TRAFFIC subtype=end log_time=<iso>
    time_generated=<iso> rt=<epoch-ms> source_ip=.. dest_ip=.. source_port=.. dest_port=..
    protocol=.. action=.. app=.. app_category=.. app_sub_category=.. technology_of_app=..
    risk_of_app=.. rule_matched=.. from_zone=.. to_zone=.. inbound_if=.. outbound_if=..
    session_id=.. bytes_sent=.. bytes_received=.. packets_sent=.. packets_received=..
    total_time_elapsed=.. session_end_reason=.. source_user=.. source_device_host=.. ..
```

Unlike ArcSight CEF, PAN-OS does **not** use numbered extension keys (`cs1`/`flexNumber1`).
Its custom log format emits **literal key names** (`source_ip`, `dest_port`, `app`,
`bytes_sent`, …) that match the `panw_ngfw_traffic_raw` columns 1:1. The header's product is
`NGFW_CEF` and the native parser routes the event by the `__firewall_type` discriminator plus
`log_type`/`subtype`.

> **Routing caveat.** `NGFW_CEF` here is the **native Syslog-Collector custom format** routed
> by `__firewall_type`. Do **not** confuse it with the *derived* ingest route (CEF vendor
> `panw`, product `ngfw_cef`), which lands in `panw_ngfw_cef_raw` with `no_hit=drop` and is
> discarded.

What the collector does with the body (measured in-tenant, 2026-10-22):

- **Routing works:** `firewall.traffic` lands in `panw_ngfw_traffic_raw`, `firewall.url` in
  `panw_ngfw_url_raw`, and XDR Analytics evaluate it (see *Detector coverage* below).
- **The body is not rewritten.** The `__firewall_type` key is consumed for routing, but every
  other key becomes a column of exactly that name (plus `cefDevice*` columns). So keys must
  use the dataset's real column names: the module sends `sub_type` (the column the modeling
  rule's FAILED-on-deny/drop outcome reads) alongside the documented `subtype`, sends
  `url_domain` alongside `uri` on URL logs, and lowercases `log_type` as in the CLCS rows.
- **No back-dating.** `_time` is always the ingestion time. Neither `rt` nor `__timestamp`
  (tried as epoch ms, `YYYY/MM/DD HH:MM:SS`, ISO-8601 `Z`, and PAN's cef-formatted time)
  moves it; the intended time survives only in `time_generated` / `rt`. Anything a detector
  must see on **separate days** has to be emitted on real days while the module runs (see
  *Daily events* below).

Syslog PRI is `<14>` (facility `LOG_USER`=1×8 + notice=6), matching PAN-OS's default syslog
facility.

### Field coverage vs. the documented format

Every key of the Syslog Collector's Traffic custom format is emitted, plus the columns the
dataset's modeling rule and the live CLCS rows carry. Checked field by field 2026-10-22:

| Documented / live key | Emitted as |
|---|---|
| `__firewall_type` `log_type` `subtype` | `firewall.traffic` / `firewall.url`; `log_type` lowercase as in the live rows; `subtype` **and** `sub_type` (the column the modeling rule reads) |
| `__timestamp=$start`, `__tz=$high_res_timestamp` | session start; high-res timestamp (`…ss.mmm+00:00`), also as `time_generated_high_res` |
| `log_time`, `time_generated` | PAN's native `Nov 16 2026 18:46:43 GMT`, as the live pa440 Syslog rows write them; `session_start_time` stays ISO-8601 |
| `log_type` / header type | uppercase (`TRAFFIC`, `THREAT`), as the live pa440 Syslog rows |
| `nat_source`, `nat_dest`, `nat_*_port` | always sent; `0.0.0.0` / `0` when no NAT applied (as the pa440 does) |
| `sequence_no` | a rising per-device counter shared by every log type |
| `log_source_id` / `log_source_name` / `sequence_no` / `vsys` / `vsys_name` | from `panw_ngfw_config` |
| `source_ip/port`, `dest_ip/port`, `nat_source/dest(_port)`, `protocol`, `action` | as documented; NAT only toward the internet |
| `source_user`, `dest_user`, `users` | `EXAMPLECORP\user`; `users` falls back to the source address (as the live rows do without User-ID) |
| `app`, `app_category`, `app_sub_category` (+ live `technology_of_app`, `risk_of_app`) | from the App-ID table, cross-checked against the live feed |
| `rule_matched`, `rule_matched_uuid`, `from_zone`, `to_zone`, `inbound_if`, `outbound_if`, `session_id` | as documented |
| `source_device_category/profile/model/vendor/osfamily/osversion/mac` | one stable Device-ID profile per host, from the session identity's `os_type`/`os_version`/`device_type` (internet sources get none) |
| `dest_device_category/profile/model/vendor/osfamily/osversion/mac` | for internal destinations (DCs and servers get server profiles) |
| `bytes_sent/received`, `packets_sent/received`, `total_time_elapsed`, `session_end_reason`, `url_category` | as documented; denies/drops are zero-byte |
| live: `log_source`, `is_nat`, `is_proxy`, `source_location`, `dest_location`, `is_non_std_dest_port`, `non_standard_dest_port`, `bytes_total` | added |
| `xff_ip` | omitted (no proxy in front of the clients) |
| URL format: `uri`, `url_category`, `url_category_list`, `http_method`, `threat_id`, `direction`, `user_agent`, `content_type`, `referer`, `http2_connection` | all emitted, plus live `url_domain`, `direction_of_attack`, `severity` |

## Key field → XDM mappings (native PAN-OS traffic modeling rule)

| CEF key | XDM field |
|---|---|
| `source_ip` / `source_port` | `xdm.source.ipv4|ipv6` / `port` |
| `dest_ip` / `dest_port` | `xdm.target.ipv4|ipv6` / `port` |
| `nat_source` / `nat_source_port` | source NAT (intermediate when `is_proxy`) |
| `nat_dest` / `nat_dest_port` | target NAT |
| `source_user` / `dest_user` | `xdm.source/target.user.username` |
| `source_device_host` / `dest_device_*` | `xdm.source/target.host.*` |
| `app` / `app_category` / `app_sub_category` / `technology_of_app` / `risk_of_app` | `xdm.target.application.*`, `xdm.network.application_protocol*` |
| `protocol` | `xdm.network.ip_protocol` |
| `action` (+ `sub_type` deny/drop) | `xdm.observer.action` / `xdm.event.outcome` (FAILED on deny/drop) |
| `bytes_sent` / `bytes_received` | `xdm.source.sent_bytes` / `xdm.target.sent_bytes` |
| `packets_sent` / `packets_received` | `xdm.source/target.sent_packets` |
| `total_time_elapsed` (s) | `xdm.event.duration` (×1000 ms) |
| `session_id` | `xdm.event.id` / `xdm.session_context_id` |
| `rule_matched` (+ `_uuid`) | `xdm.network.rule` |
| `from_zone` / `to_zone` | source / target security zone |
| `url_category` | `xdm.network.http.url_category` |
| `log_type` / `sub_type` | `xdm.event.type` / `operation_sub_type` |

## What the real tenant feed taught (read-only CLCS query of `panw_ngfw_traffic_raw`)

A single PA-440 (`pa440`) in TAP mode, ~640k rows/day, every row `sub_type=end`,
`action=allow`. Session end reasons observed (used as the generator's weights):
`tcp-rst-from-server`, `aged-out`, `tcp-fin`, `tcp-rst-from-client`, plus a ~1% `threat`
tail. `risk_of_app` is a word (`High`/`Medium`/`Low`/`Informational`); categories are
lowercase. The top App-IDs are `dns-base`, `ssl`, `web-browsing` (often on 8080), `ping`,
`quic-base`, `ntp-base`, `ms-office365-base`, `ms-ds-smb*`, `ms-rdp`, `ssh`, `kerberos`,
`ldap`. DNS-enrichment fields (`dns_query_name` etc.) are **not** present on traffic rows —
they are EAL-only. No real IPs/users/hosts are copied into the generator; only shapes are.

## URL logs

PAN traffic logs carry addresses only; the domain lives in the URL-filtering log. The module
writes one for web sessions, keyed to the traffic log by `session_id`:

```
CEF:0|PANW|NGFW_CEF|<sw>|url|threat|1| __firewall_type=firewall.url log_type=threat
    subtype=url sub_type=url action=alert uri=<host><path> url_domain=<host>
    url_category=.. url_category_list=<cat>,<low|high>-risk http_method=unknown threat_id=9999(9999) threat_name=9999(9999)
    threat_category=N/A severity=1 pcap_id=0 ..
```

Shape learned from the live `panw_ngfw_url_raw` rows (`action=alert` for an allowed, logged
URL; `http_method=unknown` for undecrypted SSL). About 35% of benign web sessions emit one, and
every domain-based threat does. In this tenant the rare-domain detectors have fired only from
PANW data that names the domain, which is what these logs provide.

**Interfaces, NAT and direction.** Ingress/egress interfaces follow the zones a session
crosses, not the destination: outbound (trust → untrust) enters on `interface_lan` and
leaves on `interface_wan`; inbound (untrust → dmz/trust, e.g. the published web service)
enters on `interface_wan` and leaves on `interface_dmz`/`interface_lan`; east-west stays on
the LAN. Source NAT (`is_nat=true`, `nat_source`) is applied only to outbound Internet
egress; east-west and inbound sessions are not NATed (no DNAT/VIP map is modelled, and the
real TAP feed carries none). A denied/dropped session is the client's SYN with no reply:
zero bytes, `packets_sent=1`, `packets_received=0`, `session_end_reason=policy-deny`.

**Encrypted vs cleartext URL logs.** A URL log for cleartext HTTP (`app=web-browsing`/`http`)
carries `http_method`, `user_agent`, `referer` and `content_type`; an undecrypted TLS
session (`app=ssl`) exposes only the SNI host, so its URL log carries `url_domain` with
`http_method=unknown` and **no** User-Agent, referer or content type — PAN-OS cannot see
those without decryption. Reproducing case 68482's rare-User-Agent/HTTP-Server evidence
therefore needs cleartext or decrypted HTTP (or the EAL logs), not an encrypted session.

## Benign mix

Dispatched from `_generate_benign_log`:

- **Internet egress (60%)** — `_benign_external`: outbound session to a destination from
  `benign_egress_destinations`, named via `resolver` so the DNS answer and the firewall
  destination agree. The App-ID is coherent with the destination/port (`_app_for_dest`), and
  the source NATs behind `panw_ngfw_config.nat_pool_cidr` — or, when the user has a correlated
  cloud sign-in on the activity bus, behind that sign-in's egress IP.
- **Internal east-west (30%)** — `_benign_internal`: workstation → internal server on
  DNS / Kerberos / LDAP / SMB / RPC / RDP, so the AD/file/RDP baselines the analytics profile
  against exist. Client DNS always goes to the client's own Infoblox grid member.
- **Perimeter deny (10%)** — `_benign_inbound_block`: Internet noise denied inbound
  (`subtype=deny`).

## Cross-log alignment

The module shares the simulation's identity/network model (`session_utils`, `resolver`):

- client DNS → the client's own Infoblox grid member (`resolver.dns_server_for`);
- benign external name → the grid's answer (`resolver.benign_target` / `answer_for`);
- RFC1918 internal hosts carry `examplecorp.local` names (`resolver.internal_fqdn`);
- one stable MAC per host, equal to the MAC Infoblox DHCP leased it (`host_mac`);
- follow-on traffic prefers a **currently-active** user from the activity bus
  (`correlated_or_random_user`), and reuses that user's cloud-sign-in egress IP as the NGFW
  `nat_source` — so an Entra/Okta sign-in and the matching NGFW HTTPS to Office 365 share one
  identity and egress address.

## Threat logs

PAN threat logs land in `panw_ngfw_threat_raw` (`__firewall_type=firewall.threat`). The format is
the Threat row of the Syslog Collector's custom log format (Cortex *Ingest NGFW logs using the
Syslog Collector*):

```
CEF:0|PANW|NGFW_CEF|<sw>|<threatid>|threat|<number-of-severity>| __firewall_type=firewall.threat
    __timestamp=<time_generated> __tz=<high_res> log_type=threat subtype=vulnerability ... <the
    common traffic block: addresses, ports, NAT, users, app, rule, zones, interfaces, session_id,
    source/dest device> ... misc=<uri or file name> threat_id=<name>(<id>) threat_name=<name>(<id>)
    threat_category=<category> direction=client-to-server user_agent=<UA> severity=<1-5>
```

The header's signature slot is **`Name(ID)`** (traffic and URL logs put the subtype there), and
`threat_name` and `threat_id` are the same `Name(ID)` string: that is what the
pa440's own CEF rows carry (`$threatid` expands to name and ID). A bare
numeric `threat_id` is silently dropped by the tenant, whereas `Name(ID)` is stored as the numeric `threat_id` column
that the native PAN NGFW alerts need; they are named `Name(ID)` too, and the registry's alert targets use that form. `severity` is the numeric `$number-of-severity` (1 informational … 5 critical). The live
CLCS rows spell several of these differently, so the module also sends the column names the
tenant's own rows use: `file_name` (holds `$misc`), `direction_of_attack`, `vendor_severity`
(the severity word) and `threat_name_firewall`. `panw_ngfw_config.threat_severity_format`
(`number` default, or `word`) chooses whether `severity` itself carries the number or the word;
the number is what the documented format sends.

**What the real feed carries** (the pa440's own rows in `panw_ngfw_threat_raw`): every row is subtype `vulnerability`;
severity Critical / High / Medium; actions `drop`, `reset-server` and `alert`. The first
eight catalog signatures are exactly the ones seen there, with the Threat IDs, names,
severities and categories as the tenant records them:

| Threat ID | Name | Severity | Category | Typical action |
|---|---|---|---|---|
| 92046 | Apache Log4j Remote Code Execution Vulnerability | critical | code-execution | drop / reset-server |
| 30109 | Dnsmasq Integer Underflow Vulnerability | high | code-execution | drop |
| 58433 | Nmap Scripting Engine Detection | medium | hacktool | alert |
| 55283 | OpenVAS Vulnerability Scanner Detection | medium | info-leak | alert |
| 32796 | RPC Portmapper DUMP Request Detected | medium | info-leak | reset-server |
| 32788 | UNIX NFS Export Directory Attempt | medium | info-leak | alert |
| 54578 | Sun ONC RPC Small Piece fragmentation Evasion Detection | medium | code-execution | alert |
| 40015 | SSH User Authentication Brute Force Attempt | high | brute-force | alert |

Two more come from Palo Alto's Threat Vault signature details (documentation, **not** the tenant
feed, so no real tenant row backs them yet); the subtype follows the documented Threat ID ranges:

| Threat ID | Name | Severity | Category | Subtype | Action | App-ID |
|---|---|---|---|---|---|---|
| 40020 | Digium Asterisk IAX2 Call Number Denial Of Service Vulnerability | medium | brute-force | vulnerability | alert | `voip-video` (user-confirmed) |
| 19900 | Bot: Backdoor_Win32_Agent_qxx | high | backdoor | spyware | reset-client | `web-browsing` (assumed) |
| 19999 | Bot: Backdoor_Win32_Agobot_pnd_pnj | high | backdoor | spyware | reset-both | `web-browsing` (assumed) |
| 59995 | Manufacturer default username and password found in HTTP Basic Authentication | informational | insecure-credentials | vulnerability | alert | `web-browsing` (assumed) |
| 21975 / 21976 / 21980 | Pastebin Command and Control Traffic Detection (three signatures, one name) | critical | spyware | spyware | reset-both | `ssl` (assumed) |
| 21985 | Schoolboy Downloader Traffic Detection | critical | downloader | spyware | reset-both | `web-browsing` (assumed) |
| 97622 / 97623 / 97625 | PHP Remote Code Execution Vulnerability (three signatures, one name; CVE pair) | critical | code-execution | vulnerability | reset-server | `web-browsing` (assumed) |
| 97630 | Moxa TN-5900 Firmware Command Injection Vulnerability (CVE-2021-46560) | critical | code-execution | vulnerability | reset-server | `web-browsing` (assumed) |
| 97650 | TRENDnet TEW-432BRP Firmware Command Injection Vulnerability (CVE-2026-10061) | critical | code-execution | vulnerability | reset-server | `web-browsing` (assumed) |
| 543004 | PHP Memory Corruption Vulnerability (same CVE pair as the PHP RCE signatures) | critical | code-execution | vulnerability | reset-server | `web-browsing` (assumed) |

The `voip-video` App-ID metadata (category, technology, risk) is assumed. Replace these
as soon as a real tenant row shows them.

Threat IDs are never invented. Signatures whose ID is known can be added without code in
`panw_ngfw_config.threat_signatures` (`{key: [id, name, severity, category, subtype]}`); spyware,
virus and wildfire-virus logs need that (see *Not built yet* below). File-type logs are built (see *File Data logs*).

**Each threat is a pair of logs.** The threat log shares its session with a traffic log:
same 5-tuple, zones, interfaces, rule, users, App-ID and `session_id`. The firewall logs the
threat part-way through the session; when the action ends the session (`drop`, `reset-*`) the
traffic log ends with `session_end_reason=threat` and still records `action=allow`, exactly as
the live feed does (its traffic rows with that end reason are all `allow`). An `alert` action
leaves the session to end normally. Web exploits ride cleartext HTTP (`web-browsing`, ports
80/8080), because PAN cannot inspect undecrypted TLS; the request path goes in `misc` and the
client's User-Agent in `user_agent`.

| Event | Shape |
|---|---|
| `threat_log4j_exploit` | an internet attacker, 3–8 attempts at a DMZ web server (untrust → dmz, WAN in / DMZ out), dropped or reset |
| `threat_dnsmasq_exploit` | malformed DNS (udp/53) to a published DMZ resolver, dropped |
| `threat_nmap_nse_scan` / `threat_openvas_scan` | an internal host scanning 5–12 servers over cleartext HTTP with the scanner's own User-Agent, alert |
| `threat_rpc_portmapper_dump` | portmapper DUMP to 5–12 servers on 111, reset (session ends `threat`) |
| `threat_nfs_export_probe` | NFS export probe to 5–12 servers on 2049, alert |
| `threat_rpc_fragmentation_evasion` | fragmented RPC on 111 to 3–6 servers, alert |
| `threat_ssh_bruteforce` | an internet host, 10–14 SSH attempts at a DMZ server; the first four are plain SSH sessions, then each further session also logs the threat with a rising `count_of_repeats` |
| `threat_iax2_dos` | an internet host, 6–14 UDP/4569 sessions at a DMZ server (`voip-video`), alert |
| `threat_bot_backdoor_beacon` | one internal host beaconing 3–6 times to one rare external host, spyware `reset-client` |
| `threat_bot_agobot_backdoor` | threat logs only (no traffic log): one internal host, 2–5 reset-both hits to one rare external host |
| `threat_pastebin_c2` | threat logs only: 1–3 reset-both hits to pastebin.com:443 from one internal host, one of the three Pastebin signature IDs |
| `threat_default_credentials_http` | threat log only, informational, **background only** (never raised on demand): an HTTP Basic login with a default credential to an internal server |
| `threat_schoolboy_downloader` | threat logs only: one internal host, 1–3 reset-both hits to one rare external host |
| `threat_php_rce` | threat logs only: an internet attacker, 2–6 crafted HTTP requests at a DMZ web server (one of the three PHP IDs), reset-server |
| `threat_moxa_tn5900_injection` | threat logs only: an internet attacker, 1–4 command-injection requests at a DMZ web server, reset-server |
| `threat_trendnet_tew432brp_injection` | threat logs only: an internet attacker, 1–4 command-injection requests at a DMZ web server, reset-server |
| `threat_php_memory_corruption` | threat logs only: an internet attacker, 2–5 crafted HTTP requests at a DMZ web server, reset-server |
| `threat_scanner_campaign` | one internal host: port scan → failed connections → Nmap NSE, OpenVAS and portmapper hits on the same server within the hour. The firewall's own threat alerts and the XDR analytics on the traffic land on one host, the shape of case 68482's "Multiple network-related alerts…" roll-up |

**More from the pa440's native CSV feed.** The same device also writes its plain PAN-OS CSV syslog into
`unknown_unknown_raw` (unparsed `_raw_log`). Its vulnerability rows supplied ten further signatures (30514, 33338,
38531, 37008, 55358, 58435, 96441, 95922, 37765, 56480), added with the category, action and `$misc` the real rows
carry. Two more (97356 Adobe ColdFusion Path Traversal, 97710 Atlassian Web Resource Download Path Traversal) came from
the pa440's own CEF rows.

**Signatures from vulnerability-scanner runs.** A scanner pointed at the pa440 adds signatures the catalog did not
have; 22 were added from the pa440's own CEF rows (request paths only, never the scanned host): 17 web signatures
and 5 legacy services (TFTP `drop`, telnet, FTP `alert`, LPD, SMTP). The catalog holds 220 tenant signatures; the
family counts below include them. A signature the pa440 hits is delivered by two routes, the CEF row with `(ID)` in
the name and the older row without, so alert names appear in both forms.

**Tenant-confirmed signature catalog.** Read from the pa440's own `panw_ngfw_threat_raw` rows (id, name, severity,
category and `sub_type` exactly as the tenant records them; the action, App-ID and `$misc` are each signature's own
dominant values, with host names and IPs stripped from `$misc`). Almost all are subtype `vulnerability`; one is
`spyware` (18011 Western Digital My Cloud Backdoor, backdoor, reset-server). No other subtype (virus, wildfire,
url, data, scan, flood) has been seen. Six grouped events fire them (all threat logs only, an internet
attacker `untrust -> dmz`, each hit using the signature's own action / App-ID / `$misc`; a family picks
one signature per fire at random):

| Event | Family | Signatures |
|---|---|---|
| `threat_web_rce` | code-execution vulnerability, blocked (reset-server / reset-both / reset-client / drop) | 103 |
| `threat_web_infoleak` | info-leak (traversal, disclosure, auth bypass), blocked | 43 |
| `threat_web_detect_only` | signatures the policy only alerts on (XSS, /etc/passwd, directory traversal, scanner probes) | 50 |
| `threat_web_sqli_overflow_dos` | sql-injection, overflow, dos, code-obfuscation, brute-force, insecure-credentials, blocked | 15 |
| `threat_legacy_service_exploit` | FTP (tcp/21), TFTP (udp/69), telnet (23), LPD (515) and SMTP (25) service exploits | 8 |
| `threat_wd_mycloud_backdoor` | the one spyware signature (18011) | 1 |

All six are **alert-capable** (`analytic: True`): the firewall's own signature raises a native `PAN NGFW` alert named
`Name(ID)` of the signature hit once `threat_id` is sent as `Name(ID)`, so a family event's `xsiam_alert` is a descriptor
("Name(ID) of the signature hit") rather than one fixed name. Informational signatures (the default-credentials one)
never reach the alerts table. Ports for the non-HTTP apps are assumed standard (ftp 21, tftp 69, telnet 23, lpd 515,
smtp-base 25); everything web rides 80/8080.

<details><summary>All 220 added signatures</summary>

| Threat ID | Name | Severity | Category | Subtype | Action | App-ID |
|---|---|---|---|---|---|---|
| 18011 | Western Digital My Cloud Backdoor | critical | backdoor | spyware | reset-server | `web-browsing` |
| 30101 | Webhints Improper URI Sanitization Remote Command Execution Vulnerability | high | code-execution | vulnerability | reset-both | `web-browsing` |
| 30554 | Netgear Routers Arbitrary Command Injection Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 30844 | HTTP Directory Traversal Request Attempt | medium | info-leak | vulnerability | alert | `jaspersoft` |
| 30847 | Generic HTTP Cross Site Scripting Attempt | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 30851 | Microsoft Windows win.ini Access Attempt Detected | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 30852 | HTTP /etc/passwd Access Attempt | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 31002 | Multiple Products Arbitrary File Location Upload Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 31003 | Squid Proxy TRACE Request Denial of Service | medium | dos | vulnerability | reset-server | `webdav` |
| 31475 | Generic HTTP Cross Site Scripting Attempt | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 31476 | Generic HTTP Cross Site Scripting Attempt | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 31477 | Generic HTTP Cross Site Scripting Attempt | medium | code-execution | vulnerability | alert | `web-browsing` |
| 31699 | Trihedral VTScada WAP Filter Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 32658 | HTTP Cross Site Scripting Attempt | medium | code-execution | vulnerability | alert | `web-browsing` |
| 32721 | Alcatel OmniPCX Office MasterCGI Remote Command Execution Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 32775 | Microsoft IIS 5.0 Form_JScript.asp XSS Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 33073 | Microsoft IIS ServerVariables_JScript. asp Information Disclosure | medium | info-leak | vulnerability | alert | `web-browsing` |
| 33452 | Adobe ColdFusion Multiple Directory Traversal Vulnerabilities | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 33678 | OPIE and Konica FTP Buffer Overflow Vulnerability | high | overflow | vulnerability | reset-server | `ftp` |
| 33756 | Oracle 9i Application Server Dynamic Monitoring Services Anonymous Access | medium | info-leak | vulnerability | alert | `web-browsing` |
| 34181 | IBM Rational Quality Manager and Test Lab Manager Remote Code Execution Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 34804 | PHP CGI Query String Parameter Handling Information Disclosure Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 35107 | HTTP /etc/passwd Access Attempt | medium | info-leak | vulnerability | alert | `web-browsing` |
| 35283 | Dahua HDCVI and IPC Backdoor Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 36102 | PCCS Mysql Database Admin Tool Username and Password Disclosure Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 36124 | Oracle 9I Application Server PL/SQL Apache Module Buffer Overflow Vulnerability | critical | overflow | vulnerability | reset-server | `web-browsing` |
| 36274 | Spring Data Commons Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-both | `web-browsing` |
| 36729 | Bash Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-both | `web-browsing` |
| 36736 | Bash Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-both | `ftp` |
| 37040 | Rejetto HTTP File Server Remote Command Execution Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 37610 | Microsoft Windows HTTP.sys Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 38768 | D-Link Routers Information Disclosure Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 38926 | Dahua Security DVR Appliances Authentication Bypass Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 39268 | ElasticSearch Groovy Script Engine Remote Command Execution Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 39766 | Novell ZENworks Mobile Management Cross-Site Scripting Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 40031 | HTTP Unauthorized Brute Force Attack | high | brute-force | vulnerability | alert | `web-browsing` |
| 40483 | PAN-OS Authentication Bypass Vulnerability | critical | info-leak | vulnerability | reset-client | `web-browsing` |
| 40627 | Drupal Core Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 40740 | Linksys Devices Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-both | `web-browsing` |
| 40797 | Cisco Adaptive Security Appliance Web Services Denial of Service Vulnerability | high | dos | vulnerability | reset-both | `web-browsing` |
| 40992 | Pivotal Spring Data Commons Remote File Read XXE Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 54119 | Novell File Reporter FSFUI Arbitrary File Retrieval Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 54426 | Squid HTTP Header Remote Buffer Overflow Vulnerability | high | overflow | vulnerability | reset-server | `web-browsing` |
| 54505 | DLink DSL Remote OS Command Injection Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 54519 | IBM Lotus Domino HTTP Redirect Buffer Overflow Vulnerability | medium | overflow | vulnerability | alert | `web-browsing` |
| 54701 | HTTP Directory Traversal Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 54817 | Multiple Products Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 54825 | ThinkPHP Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 55025 | Cisco RV320/RV325 Router Unauthenticated Configuration Export Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 55155 | Sonatype Nexus Repository Manager Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 55385 | Drupal core Remote Code Execution Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 55462 | Atlassian Confluence Directory Traversal Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 55505 | Zimbra Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `ms-exchange` |
| 55558 | Spring Cloud Config Server Directory Traversal Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 55570 | Oracle WebLogic wls9-async Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 55852 | phpunit Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 56365 | Fortinet FortiOS SSL VPN Path Traversal Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 56609 | Ysoserial Java Object Deserialization Payloads Detection | medium | code-execution | vulnerability | alert | `web-browsing` |
| 56613 | D-Link DNS-320 ShareCenter Remote Command Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 56635 | Ysoserial Java Object Deserialization Payloads Detection | medium | code-execution | vulnerability | alert | `web-browsing` |
| 56815 | Ysoserial Java Object Deserialization Payloads Detection | medium | code-execution | vulnerability | alert | `web-browsing` |
| 56868 | Jenkins Script Security Plugin Sandbox Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 56954 | Webmin Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 57497 | Citrix Application Delivery Controller And Gateway Directory Traversal Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 57557 | Siemens Solid Edge ST4 Information Disclosure Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 57806 | Zyxel Multiple Products Command Injection Vulnerability | critical | code-execution | vulnerability | alert | `web-browsing` |
| 57887 | Liferay Portal Remote Code Execution Vulnerability | critical | code-execution | vulnerability | alert | `web-browsing` |
| 57897 | Draytek Vigor Remote Command Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 57993 | Unraid Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 58062 | Liferay Portal JSON Web Service Insecure Deserialization Vulnerability | critical | code-execution | vulnerability | alert | `web-browsing` |
| 58132 | Apache Shiro Improper Authentication Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 58460 | Possible HTTP Malicious Payload Detection | medium | code-execution | vulnerability | alert | `web-browsing` |
| 58465 | Amcrest IPM-721S Information Disclosure Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 58618 | YAWS Unauthenticated Remote File Disclosure Vulnerability | high | info-leak | vulnerability | alert | `web-browsing` |
| 58623 | F5 Traffic Management User Interface Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 58628 | DataLife Engine Remote Code Execution Vulnerability | high | code-execution | vulnerability | alert | `web-browsing` |
| 58671 | Citrix Multiple Products Authorization Bypass Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 58688 | F5 Traffic Management User Interface Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 58986 | SAP NetWeaver AS JAVA Authentication Vulnerability | critical | code-execution | vulnerability | alert | `web-browsing` |
| 59021 | Cisco ASA and FTD Arbitrary File Read Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 59133 | vBulletin Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 59315 | phpMyadmin Scripts Deserialization Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 59335 | MobileIron Core and Connector Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 59505 | Nette Code Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 59623 | Oracle WebLogic Server Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 59940 | Oracle WebLogic Server Remote Code Execution Vulnerability | critical | code-execution | vulnerability | alert | `web-browsing` |
| 90136 | Car Rental Management System File Inclusion Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 90152 | WordPress Duplicator Plugin Directory Traversal Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 90183 | Zyxel USG Backdoor Account Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 90196 | Apache Flink Directory Traversal Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 90244 | Elasticsearch Groovy Script Engine Remote Command Execution Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 90776 | Yealink DM Pre Auth Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 90879 | F5 BIG-IP Authentication Bypass Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 91201 | VMware vCenter Server Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 91314 | Cisco Adaptive Security Appliance Cross-Site Scripting Vulnerability | medium | code-execution | vulnerability | reset-server | `web-browsing` |
| 91368 | Microsoft Exchange Server SSRF Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 91443 | Microsoft Outlook Web Access Login Form Remote URI Redirection Vulnerability | medium | info-leak | vulnerability | alert | `outlook-web` |
| 91471 | Buffalo WSR-2533DHPL2 Path Traversal Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 91594 | Confluence Server OGNL Injection Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 91676 | ZOHOcorp ManageEngine Improper Authentication Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 91752 | Apache HTTP Server Path Traversal Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 91805 | Draytek VigoConnect Local File Inclusion Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 91832 | Atlassian Confluence Server Information Disclosure Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 91940 | Metabase Information Disclosure Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 91970 | SonicWall SMA SQL Injection Vulnerability | high | sql-injection | vulnerability | reset-server | `web-browsing` |
| 91991 | Apache Log4j Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 92271 | D-LINK DIR Information Disclosure Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 92295 | Primetek Primefaces Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 92329 | Grafana Labs Grafana Snapshot Authentication Bypass Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 92386 | Ivanti Endpoint Manager Cloud Services Appliance Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 92389 | Spring Cloud SPEL Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 92397 | Eclipse Jetty Information Disclosure Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 92483 | VMware Server-Side Template Injection Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 92526 | Sophos Firewall Authentication Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 92570 | F5 BIG-IP Authentication Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 92626 | SolarView Compact Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 92712 | Eclipse Jetty Information Disclosure Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 92934 | Atlassian Confluence Authentication Bypass Vulnerability | critical | insecure-credentials | vulnerability | reset-server | `web-browsing` |
| 93079 | GLPI htmlawed Module Code Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 93114 | Adobe ColdFusion Remote Code Execution Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 93295 | Dahua Improper Authentication Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 93512 | Joomla Improper Access Control Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 93588 | JAI-EXT Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 93713 | Adobe ColdFusion Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 94087 | Adobe ColdFusion Improper Access Control Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 94246 | TOTOlink A7100RU Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 94248 | Chamilo Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 94261 | vBulletin Deserialization Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 94275 | Adobe ColdFusion IPFilterUtils Improper Access Control Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 94299 | PaperCut NG and MF Path Traversal Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 94328 | Generic Cross-Site Scripting Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 94344 | Stakater Forecastle Directory Traversal Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 94409 | JetBrains TeamCity Authentication Bypass Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 94413 | Cacti Group Cacti SQL Injection Vulnerability | critical | sql-injection | vulnerability | reset-server | `web-browsing` |
| 94475 | IBM Aspera Faspex Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 94666 | Qlik Sense Enterprise HTTP Request Smuggling Vulnerability | critical | code-execution | vulnerability | reset-both | `web-browsing` |
| 94701 | ownCloud Information Disclosure Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 94842 | Qlik Sense Enterprise Path Traversal Vulnerability | medium | code-execution | vulnerability | reset-server | `web-browsing` |
| 94845 | cPanel ErrorPage Cross-Site Scripting Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 94885 | Ivanti Multiple Products Authentication Bypass Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 94975 | D-Link D-View TftpSendFileThread Directory Traversal Vulnerability | high | info-leak | vulnerability | drop | `tftp` |
| 95095 | JetBrains TeamCity Authentication Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 95102 | JetBrains TeamCity Path Traversal Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 95132 | aiohttp Directory Traversal Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 95258 | Check Point Security Gateway Directory Traversal Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 95295 | PHP CGI Argument Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 95308 | Microsoft Exchange Server Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 95311 | Zoho ManageEngine Desktop Central Authentication Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 95373 | SAP Solution Manager Privilege Escalation Vulnerability | critical | code-execution | vulnerability | reset-server | `soap` |
| 95382 | Progress Kemp LoadMaster REST API Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 95393 | Splunk Enterprise Path Traversal Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 95408 | TerraMaster TOS Remote Code Execution Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 95410 | Minio Information Disclosure Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 95415 | ServiceNow Platform Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 95423 | Openfire Directory Traversal Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 95433 | Apache Airflow Experimental API Authentication Bypass Vulnerability | critical | code-obfuscation | vulnerability | reset-server | `web-browsing` |
| 95567 | SolarWinds Web Help Desk Hardcoded Credential Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 95568 | Apache HTTP Server on Windows Server-Side Request Forgery Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 95792 | Ivanti Cloud Services Appliance Broker Authentication Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 96109 | Ingress Nginx Admission Controller Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 96143 | Langflow Unauthenticated Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 96194 | Apache HTTP Server Information Disclosure Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 96267 | Ivanti Endpoint Manager Mobile Remote Code Execution Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 96314 | Oracle Business Intelligence Local File Inclusion Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 96343 | Cisco IOS XE WLC Arbitrary File Upload Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 96481 | Microsoft Sharepoint Authentication Bypass Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 96497 | Fortinet FortiWeb SQL Injection Vulnerability | critical | sql-injection | vulnerability | reset-server | `web-browsing` |
| 96509 | Microsoft Sharepoint Authentication Bypass Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 96606 | PTZOptics PT30X-SDINDI Cameras param.cgi Information Disclosure Vulnerability | critical | info-leak | vulnerability | reset-server | `web-browsing` |
| 96611 | SimpleHelp SimpleHelp WebDownloadServer Directory Traversal Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 96643 | Cisco Secure Firewall ASA and Cisco Secure FTD Authentication Bypass Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 96671 | Fortra GoAnywhere MFT Insecure Deserialization Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 96700 | Kentico Xperience Authentication Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `soap` |
| 96738 | Apache Tomcat Rewrite Rules Relative Path Traversal Vulnerability | high | code-execution | vulnerability | reset-server | `confluence-base` |
| 96742 | Fortinet FortiWeb Path Traversal Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 96755 | Oracle Identity Manager REST WebServices Authentication Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 96787 | React Server Components Remote Code Execution Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 96795 | Apache Tika XML External Entity Injection Vulnerability | critical | code-execution | vulnerability | reset-both | `web-browsing` |
| 97003 | Zimbra Collaboration Server RestFilter Local File Inclusion Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 97012 | Ivanti Endpoint Manager Remote Control logintype Authentication Bypass Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 97127 | GeoServer GetMap XML External Entity Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 97135 | XWiki SolrSearchMacros Code Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 97291 | Ivanti Sentry Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 97413 | SolarView Compact Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 97417 | HTTP Bash History Access Attempt | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 510004 | Palo Alto Networks GlobalProtect Cross-Site Scripting Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 30514 | HTTP SQL Injection Attempt | medium | sql-injection | vulnerability | alert | `web-browsing` |
| 33338 | HTTP SQL Injection Attempt | medium | sql-injection | vulnerability | alert | `web-browsing` |
| 38531 | HTTP SQL Injection Attempt | medium | sql-injection | vulnerability | alert | `web-browsing` |
| 37008 | PHP-Charts PHP Code Execution Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 55358 | Ruby on Rails File Content Disclosure Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 58435 | Brother MFC-J6520DW Authentication Bypass Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 96441 | TBK DVR-4104 and DVR-4216 Command Injection Vulnerability | medium | code-execution | vulnerability | reset-server | `web-browsing` |
| 95922 | jQuery File Upload Plugin Unrestricted File Upload Vulnerability | medium | code-execution | vulnerability | alert | `web-browsing` |
| 37765 | PHPMoAdmin Object Parameter Handling Code Execution Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 56480 | Flexible Poll 1.2 SQL Injection Vulnerability | critical | sql-injection | vulnerability | reset-server | `web-browsing` |
| 97356 | Adobe ColdFusion Path Traversal Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 97710 | Atlassian Web Resource Download Path Traversal Vulnerability | high | info-leak | vulnerability | reset-server | `web-browsing` |
| 56335 | ABB PB610 Panel Builder 600 IDAL HTTP Host Stack Buffer Overflow Vulnerability | high | overflow | vulnerability | reset-server | `web-browsing` |
| 30147 | Novell GroupWise Messenger Accept Language Header Overflow Vulnerability | high | overflow | vulnerability | alert | `web-browsing` |
| 55363 | Nginx Unit Router Process Heap-based Buffer Overflow Vulnerability | critical | overflow | vulnerability | reset-server | `web-browsing` |
| 95187 | Palo Alto Networks GlobalProtect OS Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 95191 | Palo Alto Networks GlobalProtect OS Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 90135 | Siemens SIMATIC S7-300 CPU Denial-of-Service Vulnerability | high | dos | vulnerability | alert | `web-browsing` |
| 54679 | Smart Software Solutions CoDeSys ControlService Stack Buffer Overflow Vulnerability | high | overflow | vulnerability | reset-server | `web-browsing` |
| 97000 | DNN Platform Unauthenticated File Upload Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 59523 | Cogent DataHub Information Disclosure Vulnerability | medium | info-leak | vulnerability | alert | `web-browsing` |
| 31769 | HTTP Long If-Modified-Since Header Anomaly | high | overflow | vulnerability | reset-server | `web-browsing` |
| 38761 | Apache Tomcat Remote Code Execution Via JSP Upload Vulnerability | high | code-execution | vulnerability | reset-server | `web-browsing` |
| 96989 | SmarterTools SmarterMail guid Directory Traversal Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 97182 | WordPress Breeze Cache Arbitrary File Upload Vulnerability | critical | code-execution | vulnerability | reset-server | `blog-posting` |
| 97173 | Fortinet FortiSandbox Command Injection Vulnerability | critical | code-execution | vulnerability | reset-server | `web-browsing` |
| 35614 | Lighttpd Connection Type Denial-of-Service Vulnerability | high | dos | vulnerability | reset-server | `web-browsing` |
| 35823 | HTTP SQL Injection Attempt | medium | sql-injection | vulnerability | alert | `web-browsing` |
| 91579 | HTTP SQL Injection Attempt | medium | sql-injection | vulnerability | alert | `web-browsing` |
| 30173 | TFTP Server FileName Buffer Overflow Vulnerability | high | code-execution | vulnerability | drop | `tftp` |
| 37249 | Microsoft Windows Telnet Service Buffer Overflow Vulnerability | critical | overflow | vulnerability | reset-server | `telnet` |
| 54430 | HylaFAXplus LDAP Authentication User Name Buffer Overflow Vulnerability | medium | overflow | vulnerability | alert | `ftp` |
| 54692 | Hummingbird InetD LPD Component Buffer Overflow Vulnerability | high | overflow | vulnerability | reset-server | `lpd` |
| 30384 | Mail Server SMTP EHLO/HELO Buffer Overflow Vulnerability | critical | overflow | vulnerability | reset-server | `smtp-base` |

</details>

Their targets are the signature names, because the firewall's own signature raises a native
`PAN_NGFW` alert named after the threat (the tenant already shows Log4j, Nmap, OpenVAS, portmapper
and NFS alerts from the real pa440). The ambient benign mix deliberately carries **no** threat
logs: each one is self-alerting, and the lesson from the Entra baseline is that a benign draw
that raises alerts pollutes every later test. Threats fire only through the threat gate or on demand.

**File Data logs (`firewall.filedata`).** The documented File Data format (header signature slot, `threat_id` and
`threat_name` all `Name(ID)` as the pa440's own File Data rows carry them; type THREAT, severity number) is built as three background-only events (`analytic: False`, severity low,
action alert, direction server-to-client, threat category N/A): `file_data_web` (a user fetching a file over
cleartext HTTP from an Internet server), `file_data_internal` (a host fetching from an internal web app on
8080/9080/80) and `file_data_ocsp` (an OCSP lookup returning a DER X509 certificate, App-ID `ocsp`, tcp/80).
Each fires traffic + file (+ URL) logs on one `session_id`. Names, IDs and the file-name distribution come
from the pa440's native CSV feed: 52081 Unknown Binary File, 52256 PHP,
52384 XML, 52255 JSP, 52239 ASP, 52257 ASPX, 52380 JSON, 52021 PDF, 52209 DER X509, 52390 X509 file, 52017
Perl, 52193 Python, 52418 DAT. **Assumed:** the `filetype` token (extension), `file_url` (host + path) and the
empty `filedigest` (only a WildFire verdict carries one); the CSV has none of these three. How XSIAM parses
the CEF File Data route's parsing is taken from the pa440's own CEF rows.

**Not built yet, and what is needed.** Virus, wildfire-virus, wildfire, data, scan and flood logs
have not appeared in the tenant feed (only `vulnerability`, `file`, `url` and `spyware` rows have), so no
IDs, names or subtype-specific columns can be copied. Spyware C2/DNS signatures beyond 18011 likewise. Supplying real IDs and names (or enough threat
rows to read them from) is all that is needed to add them. Whether the syslog-delivered logs
raise the same native `PAN_NGFW` alerts as the CLCS rows is settled for the vulnerability and spyware signatures; the other subtypes need a probe.

## Vulnerabilities (on-demand module)

A separate module, **Palo Alto Networks NGFW Vulnerabilities** (`modules/panw_ngfw_vulns.py`), lists every
vulnerability signature as its own entry so one exact signature can be fired ad hoc: **Threats &
Scenarios → Fire Individual Threat**, pick the module, then the signature (the dropdown groups each entry under the
alert it targets, `Name(ID)`). The MCP `fire_event` tool and the CLI specific-threat menu list the same entries.

| | |
|---|---|
| Entries | 235, `vuln_<id>` (also accepted as a bare ID, `97710`, or `t97710`): the 219 tenant-confirmed vulnerability signatures plus the 16 hand-curated ones that have a dedicated event in the NGFW module (Log4j, Dnsmasq, Nmap NSE, OpenVAS, RPC portmapper / fragmentation, NFS export, SSH brute force, IAX2, default credentials, PHP RCE x3, Moxa, TRENDnet, PHP memory corruption). Spyware signatures (WD 18011, bot beacon, Agobot, Pastebin C2, Schoolboy) are not listed |
| What a fire sends | what `panw_ngfw` builds for that signature. Tenant entries: an internet attacker (`untrust -> dmz`) trips it against a DMZ server, 1-4 threat-log sessions (1-3 for the legacy services), the signature's own action, App-ID, port and request path. Curated entries run their dedicated event with the ID pinned (the three PHP RCE IDs each fire only their own), so scanner and RPC signatures come from an internal host and the SSH brute force carries its preceding sessions. `threat_id` is sent as `Name(ID)` |
| Expect | the native `PAN NGFW` alert named `Name(ID)` within minutes (default credentials, 59995, is informational and never alerts; its dropdown label says so) |
| Background | none: in a long-running session the module generates nothing (the same signatures already ride the grouped events of the NGFW module) |
| Config | none of its own: it shares `panw_ngfw_config` (syslog host and port, `zones`, DMZ servers) |

## Threat scenarios

Dispatched from `_generate_threat_log` (weighted) or forced by name via `scenario_event`.
Traffic-shaped scenarios are offered on demand when CEF traffic can represent the documented
detector evidence. This includes informational variants for controlled validation; they may
not appear in the alerts table. Protocol-decoded, endpoint-process, or account-state patterns
that CEF cannot represent remain hunt/correlation-only.

Targets name the alert the tenant actually raises. Informational alerts never reach the
alerts table, so where a detector's base name is Informational and the shape produces a Low
variation, the variation is the target (Port Scan fires as *Suspicious port scan*).

**Status** is the in-tenant result of the 2026-10-22 detector test (each event fired at the
broker from its own source host, alerts attributed by the `DS:PANW/NGFW_CEF` tag and host):

- ✅ **fired** from this module's PAN data
- ⏳ **pending** — rebuilt on the shape that fires for a sibling firewall here; waiting on a
  long test window or on real days of history (no back-dating on this path)
- ✗ **never fired in this tenant from any feed** in 30 days, though the other firewall
  modules have targeted it for weeks: most likely not reachable here, not a PAN-shape issue
- ? **PAN-only detector, untested beyond one round** (no other feed can drive it)
- new — added 2026-10-22 for a traffic-only variation; not yet fired at the tenant

| Event | XSIAM analytic | Shape | Status |
|---|---|---|---|
| `port_scan` | Suspicious port scan | one host → 20–24 distinct privileged ports on one server | ✅ *Suspicious port scan* |
| `failed_connections` | Failed Connections | ~120 zero-byte denies to ~40 inactive hosts | ✅ |
| `large_upload_generic` | Large Upload (Generic) | one large upload on an uncommon port | ✅ |
| `large_upload_https` | Large Upload (HTTPS) | one 300–700 MB session to the shared exfil pool (`session_utils.exfil_destination`) + URL log | ✅ |
| `large_upload_https_nonstd` | Large Upload (HTTPS) | same on 8443/4443/9443/10443/2083 | ✅ *…to non-standard port* |
| `large_upload_smtp` | Large Upload (SMTP) | 300–700 MB over 587 to a rare server | ⏳ 1-day test |
| `large_upload_ftp` | Large Upload (FTP) | 300–700 MB over 21 to a rare server | ⏳ 1-day test (fired once from Firepower) |
| `spam_bot` | Spam Bot Traffic | one host → 400–800 SMTP sessions to 150–300 servers over ~2 h on 25/587/465; half are MX hosts of distinct recipient domains, half unresolved IPs (the detector counts domains + unresolved IPs, not volume) | ⏳ 3-day test |
| `new_admin_behavior` | New Administrative Behavior | 8–11 novel (fresh internal host, remote-admin port) pairs over 30–75 min; ports 22/23/69/161/512–514/623/992, filled with 22/69 | ⏳ 12-hour test |
| `unusual_ssh` | Unusual, long SSH activity with tunnel characteristics | 2–4 sessions of 30 min–4 h, 5–80 MB each way, to one stable rare host | ⏳ 2-hour test |
| `unusual_ssh_external` | Unusual SSH activity with tunnel characteristics to external destination | the tunnel shape at 50–200 MB each way | new |
| `uncommon_ssh` | Uncommon SSH session was established | an SSH-habit user (`_SSH_HABIT_USERS`) reaches a rare internal host | ⏳ needs the habit to accrue on real days |
| `uncommon_ssh_rare_internal` | Uncommon SSH session was established to a rare internal IP | SSH-habit user → never-seen internal host | new |
| `uncommon_ssh_nonstd_port` | An Uncommon SSH session was established using a nonstandard SSH port | SSH-habit user → internal host on 2222/2022/… | new |
| `recurring_rare_domain` | Abnormal Recurring Communications to a Rare Domain With a Less Common Port | one fixed host → its persistent rare domain on a less-common port, with URL logs; daily | ⏳ needs real days (fires here from the real pa440) |
| `recurring_rare_ip` | Recurring access to rare IP | one fixed host → its persistent rare IP; daily | ⏳ needs real days; ✗ never fired from any feed |
| `ddns_access` | Recurring rare domain access to dynamic DNS domain | one fixed host → its persistent dyn-DNS name, with URL logs; daily | ⏳ needs real days |
| `port_sweep` | Port Sweep to multiple subnets | one privileged port across many hosts in ≥3 subnets | ✗ (the only "Port Sweep" here was a Check Point vendor alert) |
| `rare_rdp` | Rare RDP session to a remote host | RDP to a rarely-seen host | ✗ |
| `abnormal_rdp_rare_host` | Abnormal RDP … from a rarely seen host | RDP from a stable rare source host | ✗ |
| `rare_smb` | Rare SMB session to a remote host | SMB to a rarely-seen host | ✗ |
| `smb_from_dc` | Suspicious SMB connection from domain controller | DC → workstation SMB | ✗ |
| `rare_smtp` | Rare SMTP/S Session | SMTP to a rare external server | ✗ |
| `torrent` | A Torrent client was detected on a host | BitTorrent to many peers | ✗ |
| `rare_appid` | Rare AppID usage to a rare destination | rare App-ID to a rare dest | ✗ |
| `new_ftp_server` | New FTP Server | first-seen internal FTP server | ✗ |
| `rare_domain_comm` | Abnormal Communication to a Rare Domain | one session to a newly-registered domain, with URL log | ✗ |
| `rare_domain_less_common_port` | Abnormal Communication to a Rare Domain With a Less Common Port | rare domain over SSL on an uncommon port, with URL log | new (informational) |
| `rare_domain_suspicious_as` | Abnormal Communication to a Rare Domain to a Suspicious Autonomous System (AS) | single rare-domain session on 443; XSIAM supplies AS reputation | new (informational; enrichment-dependent) |
| `recurring_rare_domain_abnormal_suffix` | Abnormal Recurring Communications to a Rare Domain With an Abnormal Domain Suffix | daily beacons to a stable rare domain with an uncommon suffix | new (informational; daily) |
| `dcsync_non_dc` | Possible DCSync from a non domain controller | DRSUAPI RPC (135 + dynamic) from a non-DC → DC | ? |
| `rdp_unmanaged` | RDP from an unmanaged endpoint … | RDP from an unmanaged source in a managed subnet | ? |
| `rdp_unmanaged_dense_subnet` | RDP from an unmanaged endpoint in a typically managed subnet with a significantly higher number of managed endpoints in the subnet | seeds 15–25 workstation-category peers in the same subnet before an unmanaged RDP source; XSIAM must classify peers as managed | new (inventory-dependent) |
| `dormant_host_conn` | Abnormal connections to a dormant host … | new endpoint → long-inactive host | ? |
| `crypto_miner` | A Possible crypto miner was detected on a host | mining-pool traffic on stratum ports | ? |
| `ipfs` | Possible use of IPFS was detected | IPFS node traffic | ? |
| `p2p_upload` / `p2p_download` | Upload / Download pattern that resembles P2P | asymmetric P2P transfers | ? |
| `ssh_proxy` | Unusual SSH activity that resembles SSH proxy | relay: inbound SSH, then an overlapping outbound SSH, mirrored volumes, 1–20 MB each way | ? |
| `ssh_proxy_high_volume` | High Volume Unusual SSH activity that resembles SSH proxy | the same relay on an SSH-habit host, rare client and target, 200–600 MB each way over 2–6 h (also expected to trip Large Upload (Generic)) | new |
| `ssh_proxy_suspicious` | Suspicious SSH activity that resembles SSH proxy | relay with both ends rare external, inbound on a non-standard port (exploratory) | new |
| `ssh_proxy_detected` | Unusual SSH activity that resembles SSH proxy detected | plain-volume relay from a non-habit host (exploratory) | new |
| `rare_ssh_external` | An Uncommon SSH session was established to a rare IP address | SSH-habit user → rare external IP on 22 (re-targeted from the process-based detector) | new |
| `port_scan_aggressive` | Highly suspicious port scan | every privileged port + 60–100 high ports on one server in ~3 min | new |
| `ipfs_peering` | Possible IPFS traffic was detected | 25–45 swarm dials on 4001 tcp+udp, ~half never complete | new |
| `rare_domain_attack_port` | Abnormal Communication to a Rare Domain With a Port Commonly Used by Attack Platforms | rare domain on 4444/50050/31337/1337/6666/9999 + URL log | new |
| `recurring_rare_domain_attack_port` | Abnormal Recurring Communications … Attack Platforms | a second daily beacon pair, on an attack-framework port | new (daily) |
| `recurring_rare_domain_suspicious_as` | Abnormal Recurring Communications to a Rare Domain to a Suspicious Autonomous System (AS) | daily beacon on 443 to a rare-pool (bulletproof-hosting-style) IP | new (daily) |
| `dormant_host_known_source` | Abnormal connections to a dormant host | established workstation → long-inactive host | new |
| `large_upload_generic_small` | Large Upload (Generic) Lower than 100 MB | 60–95 MB on an uncommon port | new |
| `large_upload_generic_popular_target` | Large Upload (Generic) to a Frequently Used Upload Target | 300–700 MB SSH push to configured, commonly used GitHub destination | new (informational; depends on destination baseline) |
| `new_ssh_admin_behavior` | New SSH Administrative Behavior | 8–11 novel SSH-only admin pairs | new |
| `new_ftp_server_external` | New FTP Server from an external source | internet clients pulling files from a newly serving internal :21 | new |
| `new_ftp_server_port_scan` | New FTP Server Accessed Via a Port Scan | privileged-port scan followed by successful FTP to the same newly observed server | new (informational) |
| `dcsync_internet_facing` | Possible DCSync from an internet-facing server | DMZ web server → DC DRSUAPI | new |
| `dcsync_large` | Large DCSync from a non domain controller | non-DC pulls 150–600 MB from a DC | new |
| `dcsync_non_dc_appid` | DCSync from a non domain controller | replication App-ID-identified as `ms-dc-replication` | new |
| `dcsync_large_appid` | Large DCSync from a non domain controller by AppID | 150–600 MB pull, App-ID `ms-dc-replication` | new |
| `rare_appid_internet_facing` | Rare AppID usage … from an internet-facing server | DMZ web server, rare App-ID, rare destination | new |
| `uncommon_ssh_internal` | Uncommon SSH session was established to an internal IP | SSH-habit user connects to an internal server over port 22 | new (informational) |
| `spam_bot_failed` | Failed Spam Bot Traffic | 400–800 SMTP sessions to 150–300 servers, with named MX domains plus unresolved IPs and ~80% reset/unanswered | new (informational) |
| `ssh_suspicious_nonstd` | A suspicious SSH session was established | SSH to a rare external IP on 2222/2022/22222/8022/10022 | new |
| `ssh_high_volume` | Uncommon SSH … higher than usual volume | SSH-habit user → usual jump host, 300–900 MB | new |
| `host_attack_chain` | Multiple network-related alerts produced by different detectors on the same host | one host: port scan → failed connections → generic upload within the hour | new |
| `kerberos_preauth_pattern` | *(non-analytic)* | Kerberos (88) burst to a DC | — |
| `ntlm_relay_pattern` | *(non-analytic)* | SMB auth fan-out (relay shape) | — |
| `dns_tunnel_pattern` | *(non-analytic)* | high-volume DNS to one resolver | — |
| `ldap_recon` | *(non-analytic)* | LDAP (389/636) enumeration against a DC | — |
| `tor_connection` | Recurring access to rare IP | DNS lookup, then a long Tor session (443/9001/9030) to an exit address | ported |
| `server_outbound_http` | Recurring access to rare IP | internal server (DMZ) making plain HTTP to one rare external host, with a URL log | ported |
| `dns_c2_beacon` | Abnormal Recurring Communications to a Rare Domain | one fixed host querying a rare external DNS server on a steady cadence (8–15 queries) | ported |
| `smb_new_host_lateral` | Rare SMB session to a remote host | one workstation → 5–10 internal hosts on 445 | ported |
| `smb_rare_file_transfer` | Rare SMB session to a remote host | one 100 MB–1 GB SMB session to a rarely-contacted workstation | ported |
| `smb_share_enumeration` | Rare SMB session to a remote host | tiny 445 sessions to 15–40 distinct internal hosts | ported |
| `rare_external_rdp` | Rare RDP session to a remote host | workstation → rare Internet host on 3389 | ported |
| `large_download` | *(non-analytic)* | 500–4000 MB inbound HTTPS (received ≫ sent) + URL log | ported |
| `dos_anomaly` | *(non-analytic)* | 80–150 tiny sessions from distinct external sources to one published server | ported |
| `external_port_scan` | *(non-analytic)* | Internet host probing 20–24 privileged ports on a published server, mostly denied | ported |
| `snmp_unexpected_source` | *(non-analytic)* | a workstation walking every network device on UDP/161 (traffic only; the SNMP config logs are a different PAN log type) | ported |
| `file_data_web` / `file_data_internal` / `file_data_ocsp` | *(non-analytic)* | File Data (`firewall.filedata`) logs: file-type identification alongside traffic and URL logs | native CSV |

The *ported* events replicate the traffic-based hits of the other firewall generators (their alert targets are the same names those registries use). `dns_tunneling` and `reverse_ssh_tunnel` are already covered by `dns_tunnel_pattern` and the SSH events above.

All sequences end at or before the current time.

### Daily events and internet-facing servers

Detectors that want the same (host, destination) pair "repeatedly over many days" cannot be
fed by a back-dated burst on this path. `_DAILY_EVENTS` (`recurring_rare_ip`,
`recurring_rare_domain`, `recurring_rare_domain_attack_port`, `recurring_rare_domain_suspicious_as`,
`recurring_rare_domain_abnormal_suffix`, `ddns_access`) claim the first threat slots of each UTC day, as Cisco
ASA does, so each pair — one fixed host (`recurring_host(key, n=1)`) and its destination
persisted in the beacon map — recurs on every real day the module runs at a threat level.
Likewise `_ssh_habit_users()` (8 stable users) make everyday SSH to their usual jump host part of
the benign mix, giving `uncommon_ssh`, `rare_ssh_external`, `ssh_suspicious_nonstd` and
`ssh_high_volume` the per-host SSH history their detector compares against.

The internet-facing variations need hosts XSIAM knows receive internet traffic. The benign
mix publishes the web site: internet clients (from `benign_ingress_sources`) reach the Apache
httpd module's servers (`apache_config.server_ips`, `www.examplecorp.com`) on 443 through
`untrust → dmz`, so the firewall and the httpd access logs describe the same servers, and
`dcsync_internet_facing` / `rare_appid_internet_facing` originate from those servers.

**Informational variants.** Traffic-shaped informational scenarios are selectable for explicit generation so their ingestion and analytic behavior can be checked. Informational severity means they may not produce an alerts-table row; verify their raw events or analytics output separately. Variants requiring process causality, DNS query contents, Kerberos/NTLM protocol results, account state, or an XDR Agent remain excluded from the traffic-only catalog.

## Detector coverage vs. the 49 PAN NGFW traffic-log alerts

**Confirmed (5 detectors, 6 alert names)** from this module's data: Suspicious port scan,
Failed Connections, Large Upload (Generic), Large Upload (HTTPS) and its non-standard-port
variation.

**What fires in this tenant at all.** A 30-day read of the `alerts` dataset, split by data
source, shows only these traffic-family XDR Analytics firing from *any* feed: Suspicious port
scan, Spam Bot Traffic, New Administrative Behavior, Large Upload (HTTPS / non-std / Generic /
FTP), Failed Connections, Unusual long SSH with tunnel characteristics, Uncommon SSH, Abnormal
Recurring Communications to a Rare Domain (from the real pa440), and Kerberos Pre-Auth
Failures by Host (from Windows events). The pending events above target exactly that set.

**Not reachable over CEF syslog** — the remaining traffic-log alerts need
Enhanced-Application-Logging (EAL) decoded protocol fields, process data or an XDR Agent:

- **Kerberos** — Pre-Auth Failures (by Host; by User and Host), User Enumeration,
  Weakly-Encrypted / Multiple Weakly-Encrypted Kerberos Tickets, Kerberoasting without SPNs
  (need Kerberos encryption-type / error / TGS fields).
- **NTLM** — NTLM Relay, Machine Account NTLM Relay, NTLM Password Spray, NTLM Hash
  Harvesting, Rare NTLM Access By User To Host (need the NTLM `NTProofStr`).
- **Account state** — Authentication Attempt From a Dormant Account, Failed Login For
  Locked-Out Account (need Kerberos TGS + AD account state).
- **Process / agent** — A user accessed an uncommon AppID, Rare process created an SSH session
  to an uncommon cloud resource / external host; Suspicious DNS traffic needs EAL
  `dns_query_name` entropy.

## Zones

The firewall is modelled inline with six security zones, not the pa440's single `Tap` zone. An address
belongs to the zone of the role it plays (`modules/panw_ngfw.py`, `_zone_of`), checked in this order:

1. not RFC1918 -> `untrust`
2. `panw_ngfw_config.zones.<name>.hosts` (exact address), then the role lists below
3. the published DMZ servers (the Apache module's `server_ips`, else a stable pair of the internal servers) -> `dmz`
4. `domain_controllers` -> `identity`
5. `database_servers` -> `database`
6. `internal_servers` -> `servers`
7. `zones.<name>.cidrs` (longest prefix wins)
8. any other internal address (the workstation /24s) -> `users`

Callers still pass the generic internal zone, and `_traffic_fields` replaces it with the address's zone, so every
traffic, URL, threat and file log carries `from_zone` / `to_zone`, the matching `inbound_if` / `outbound_if`
(`users` ethernet1/2, `untrust` 1/1, `dmz` 1/3, `servers` 1/4, `database` 1/5, `identity` 1/6) and a rule named for the
zone pair (`Allow-Users-to-Servers`, `Deny-Users-to-DMZ`, `Allow-DMZ-to-Untrust`, ...). A flow inside one zone is
`Allow-<Zone>-Internal`. Events that name a rule (the inbound web, SSH and FTP rules) keep it, and an explicit
`untrust` or `dmz` stays as given. Zone names are lower case; add a zone, move a host or change an interface in
`panw_ngfw_config.zones`, for example `{"guest": {"cidrs": ["192.168.150.0/24"], "interface": "ethernet1/7"}}`.

## Config (`panw_ngfw_config`)

All firewall identity is driven from config, so the firewall's name and IP can be set to
whatever the environment uses; every event builds its header and `log_source_*` fields off
these values.

| Key | Default | Meaning |
|---|---|---|
| `syslog_port` | `514` | Broker VM Syslog Collector port |
| `serial_number` | `007051000012345` | firewall serial (`log_source_id`) |
| `hostname` | `PA-VM-01` | firewall name (`log_source_name` / `device_name`, and the syslog header host when `syslog_hostname_format=hostname`) |
| `mgmt_ip` | `10.0.0.1` | firewall management/source IP (used as the syslog header host when `syslog_hostname_format=ipv4-address`) |
| `syslog_hostname_format` | `hostname` | what PAN stamps in the syslog header HOSTNAME field: `hostname` or `ipv4-address` (uses `mgmt_ip`) |
| `sw_version` | `12.2.4-h1` | PAN-OS release in the CEF device-version slot |
| `vsys` | `vsys1` | virtual system |
| `interface_lan` / `interface_wan` / `interface_dmz` | `ethernet1/2` / `ethernet1/1` / `ethernet1/3` | the user-zone (LAN), untrust (WAN) and DMZ interfaces; the server, database and identity zones default to `ethernet1/4` / `1/5` / `1/6` |
| `zones` | `{}` | extra or overriding zone definitions, `{name: {hosts: [ips], cidrs: [networks], interface: "ethernet1/N"}}`; see Zones |
| `default_rule` | `Allow-Users-Outbound` | `rule_matched` of user-to-Internet flows; other zone pairs get `Allow-<From>-to-<To>` / `Deny-...` unless the event names a rule |
| `nat_pool_cidr` | `203.0.113.0/27` | source-NAT egress pool |
| `domain_controllers` | `["10.0.10.10","10.0.20.10"]` | DCs for SMB-from-DC / DCSync / Kerberos |
