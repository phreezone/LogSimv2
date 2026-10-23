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
| `log_time`, `time_generated`, `session_start_time` | ISO-8601 (the dataset types `time_generated` as a timestamp) |
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
    url_category=.. url_category_list=<cat>,<low|high>-risk http_method=unknown threat_id=9999 ..
```

Shape learned from the live `panw_ngfw_url_raw` rows (`action=alert` for an allowed, logged
URL; `http_method=unknown` for undecrypted SSL). About 35% of benign web sessions emit one, and
every domain-based threat does. In this tenant the rare-domain detectors have fired only from
PANW data that names the domain, which is what these logs provide.

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

## Threat scenarios

Dispatched from `_generate_threat_log` (weighted) or forced by name via `scenario_event`.
49 analytic events are built to satisfy a specific native PAN NGFW traffic-log detector or
one of its traffic-only variations, and are offered on demand; 4 further events are realistic
network patterns kept for hunts / correlation but **not** offered on demand (their detectors
need EAL-decoded fields a CEF traffic log cannot carry).

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
| `port_scan` | Port Scan | one host → 20–24 distinct privileged ports on one server | ✅ *Suspicious port scan* |
| `failed_connections` | Failed Connections | ~120 zero-byte denies to ~40 inactive hosts | ✅ |
| `large_upload_generic` | Large Upload (Generic) | one large upload on an uncommon port | ✅ |
| `large_upload_https` | Large Upload (HTTPS) | one 300–700 MB session to the shared exfil pool (`session_utils.exfil_destination`) + URL log | ✅ |
| `large_upload_https_nonstd` | Large Upload (HTTPS) | same on 8443/4443/9443/10443/2083 | ✅ *…to non-standard port* |
| `large_upload_smtp` | Large Upload (SMTP) | 300–700 MB over 587 to a rare server | ⏳ 1-day test |
| `large_upload_ftp` | Large Upload (FTP) | 300–700 MB over 21 to a rare server | ⏳ 1-day test (fired once from Firepower) |
| `spam_bot` | Spam Bot Traffic | one host → 40–90 external SMTP servers on 25 | ⏳ 3-day test |
| `new_admin_behavior` | New Administrative Behavior | 8–11 novel (fresh internal host, remote-admin port) pairs over 30–75 min; ports 22/23/69/161/512–514/623/992, filled with 22/69 | ⏳ 12-hour test |
| `unusual_ssh` | Unusual SSH Activity | 2–4 sessions of 30 min–4 h, 5–80 MB each way, to one stable rare host | ⏳ 2-hour test |
| `uncommon_ssh` | Uncommon SSH session was established | an SSH-habit user (`_SSH_HABIT_USERS`) reaches a rare internal host | ⏳ needs the habit to accrue on real days |
| `recurring_rare_domain` | Abnormal Recurring Communications to a Rare Domain | one fixed host → its persistent rare domain on a less-common port, with URL logs; daily | ⏳ needs real days (fires here from the real pa440) |
| `recurring_rare_ip` | Recurring access to rare IP | one fixed host → its persistent rare IP; daily | ⏳ needs real days; ✗ never fired from any feed |
| `ddns_access` | Recurring rare domain access to dynamic DNS domain | one fixed host → its persistent dyn-DNS name, with URL logs; daily | ⏳ needs real days |
| `port_sweep` | Port Sweep | one privileged port across many hosts in ≥3 subnets | ✗ (the only "Port Sweep" here was a Check Point vendor alert) |
| `rare_rdp` | Rare RDP session to a remote host | RDP to a rarely-seen host | ✗ |
| `abnormal_rdp_rare_host` | Abnormal RDP … from a rarely seen host | RDP from a stable rare source host | ✗ |
| `rare_smb` | Rare SMB session to a remote host | SMB to a rarely-seen host | ✗ |
| `smb_from_dc` | Suspicious SMB connection from domain controller | DC → workstation SMB | ✗ |
| `rare_smtp` | Rare SMTP/S Session | SMTP to a rare external server | ✗ |
| `torrent` | A Torrent client was detected on a host | BitTorrent to many peers | ✗ |
| `rare_appid` | Rare AppID usage to a rare destination | rare App-ID to a rare dest | ✗ |
| `new_ftp_server` | New FTP Server | first-seen internal FTP server | ✗ |
| `rare_domain_comm` | Abnormal Communication to a Rare Domain | one session to a newly-registered domain, with URL log | ✗ |
| `dcsync_non_dc` | Possible DCSync from a non domain controller | DRSUAPI RPC (135 + dynamic) from a non-DC → DC | ? |
| `rdp_unmanaged` | RDP from an unmanaged endpoint … | RDP from an unmanaged source in a managed subnet | ? |
| `dormant_host_conn` | Abnormal connections to a dormant host … | new endpoint → long-inactive host | ? |
| `crypto_miner` | A Possible crypto miner was detected on a host | mining-pool traffic on stratum ports | ? |
| `ipfs` | Possible use of IPFS was detected | IPFS node traffic | ? |
| `p2p_upload` / `p2p_download` | Upload / Download pattern that resembles P2P | asymmetric P2P transfers | ? |
| `ssh_proxy` | Unusual SSH activity that resembles SSH proxy | relay: inbound SSH, then an overlapping outbound SSH, mirrored volumes, 1–20 MB each way | ? |
| `ssh_proxy_high_volume` | High Volume Unusual SSH activity that resembles SSH proxy | the same relay on an SSH-habit host, rare client and target, 200–600 MB each way over 2–6 h (also expected to trip Large Upload (Generic)) | new |
| `rare_ssh_external` | An Uncommon SSH session was established to a rare IP address | SSH-habit user → rare external IP on 22 (re-targeted from the process-based detector) | new |
| `port_scan_aggressive` | Highly suspicious port scan | every privileged port + 60–100 high ports on one server in ~3 min | new |
| `ipfs_peering` | Possible IPFS traffic was detected | 25–45 swarm dials on 4001 tcp+udp, ~half never complete | new |
| `rare_domain_attack_port` | Abnormal Communication to a Rare Domain With a Port Commonly Used by Attack Platforms | rare domain on 4444/50050/31337/1337/6666/9999 + URL log | new |
| `recurring_rare_domain_attack_port` | Abnormal Recurring Communications … Attack Platforms | a second daily beacon pair, on an attack-framework port | new (daily) |
| `dormant_host_known_source` | Abnormal connections to a dormant host | established workstation → long-inactive host | new |
| `large_upload_generic_small` | Large Upload (Generic) Lower than 100 MB | 60–95 MB on an uncommon port | new |
| `new_ssh_admin_behavior` | New SSH Administrative Behavior | 8–11 novel SSH-only admin pairs | new |
| `new_ftp_server_external` | New FTP Server from an external source | internet clients pulling files from a newly serving internal :21 | new |
| `dcsync_internet_facing` | Possible DCSync from an internet-facing server | DMZ web server → DC DRSUAPI | new |
| `dcsync_large` | Large DCSync from a non domain controller | non-DC pulls 150–600 MB from a DC | new |
| `rare_appid_internet_facing` | Rare AppID usage … from an internet-facing server | DMZ web server, rare App-ID, rare destination | new |
| `spam_bot_failed` | Failed Spam Bot Traffic | 40–90 external SMTP servers, ~80% reset/unanswered | new |
| `ssh_suspicious_nonstd` | A suspicious SSH session was established | SSH to a rare external IP on 2222/2022/22222/8022/10022 | new |
| `ssh_high_volume` | Uncommon SSH … higher than usual volume | SSH-habit user → usual jump host, 300–900 MB | new |
| `host_attack_chain` | Multiple network-related alerts produced by different detectors on the same host | one host: port scan → failed connections → generic upload within the hour | new |
| `kerberos_preauth_pattern` | *(non-analytic)* | Kerberos (88) burst to a DC | — |
| `ntlm_relay_pattern` | *(non-analytic)* | SMB auth fan-out (relay shape) | — |
| `dns_tunnel_pattern` | *(non-analytic)* | high-volume DNS to one resolver | — |
| `ldap_recon` | *(non-analytic)* | LDAP (389/636) enumeration against a DC | — |

All sequences end at or before the current time.

### Daily events and internet-facing servers

Detectors that want the same (host, destination) pair "repeatedly over many days" cannot be
fed by a back-dated burst on this path. `_DAILY_EVENTS` (`recurring_rare_ip`,
`recurring_rare_domain`, `ddns_access`) claim the first threat slots of each UTC day, as Cisco
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
| `sw_version` | `11.1.4` | PAN-OS release in the CEF device-version slot |
| `vsys` | `vsys1` | virtual system |
| `interface_lan` / `interface_wan` | `ethernet1/2` / `ethernet1/1` | inbound / outbound interfaces |
| `default_rule` | `Allow-Users-Outbound` | benign `rule_matched` |
| `nat_pool_cidr` | `203.0.113.0/27` | source-NAT egress pool |
| `domain_controllers` | `["10.0.10.10","10.0.20.10"]` | DCs for SMB-from-DC / DCSync / Kerberos |
