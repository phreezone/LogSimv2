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
    __timestamp=<session-start> __tz=<high-res> log_type=traffic type=TRAFFIC
    subtype=end sub_type=end log_time=<iso> time_generated=<iso>
    receive_time=<iso> high_res_timestamp=<high-res>
    session_start_time=<iso> serial=<firewall-serial> log_source_id=<firewall-serial>
    log_source_name=<hostname> device_name=<hostname>
    src=.. dst=.. sport=.. dport=.. proto=.. rule=.. from=.. to=.. sessionid=..
    source_ip=.. dest_ip=.. source_port=.. dest_port=.. protocol=.. rule_matched=..
    action=.. app=.. app_category=.. app_sub_category=.. technology_of_app=..
    risk_of_app=.. from_zone=.. to_zone=.. inbound_if=.. outbound_if=..
    session_id=.. bytes_sent=.. bytes_received=.. packets_sent=.. packets_received=..
    total_time_elapsed=.. session_end_reason=.. source_user=.. source_device_host=.. ..
```

The official [Traffic Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields)
list is the source of truth for which keys exist. Both the documented PAN key (`serial`,
`src`, `dst`, `sport`, `dport`, `proto`, `rule`, `from`, `to`, `sessionid`, …) and the
dataset column (`log_source_id`, `source_ip`, `dest_ip`, `source_port`, `dest_port`,
`protocol`, `rule_matched`, `from_zone`, `to_zone`, `session_id`, …) are emitted. The
collector does not rewrite the body, so this keeps the wire line schema-faithful while
preserving the existing dataset mappings. Fields that were added only because the live
CLCS rows carry them — and which have no documented equivalent — are not generated.

Unlike ArcSight CEF, PAN-OS does **not** use numbered extension keys (`cs1`/`flexNumber1`).
The documented custom format emits **literal key names** (`serial`, `receive_time`, `src`,
`dst`, `sport`, `dport`, `proto`, `rule`, `from`, `to`, …), while `panw_ngfw_traffic_raw`
stores **normalized columns** (`log_source_id`, `source_ip`, `dest_ip`, `source_port`,
`dest_port`, `protocol`, `rule_matched`, `from_zone`, `to_zone`, …). The collector does not
rewrite the body, so the module sends both (see `_PAN_ALIASES` in the module). The header's
product is `NGFW_CEF` and the native parser routes the event by the `__firewall_type`
discriminator plus `log_type`/`subtype`.

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
  moves it; the intended time survives only in the event-time fields (`log_time`,
  `time_generated`, `high_res_timestamp`, `session_start_time`). `rt` is a CEF
  device-receipt convention, **not** a PAN traffic-log field (the live CLCS rows have
  `rt=null`), so it is omitted unless `panw_ngfw_config.emit_rt` is set to `true`. Anything a
  detector must see on **separate days** has to be emitted on real days while the module runs
  (see *Daily events* below).

Syslog PRI is `<14>` (facility `LOG_USER`=1×8 + notice=6), matching PAN-OS's default syslog
facility.

### CEF header severity slot

The header's severity slot is the numeric severity the CEF spec requires (integer 0-10). The
traffic rows keep the live feed's literal `1` body value — which passes through as `1`, the
CEF "unrated" default. Documented THREAT severity words (Threat Log Fields: informational,
low, medium, high, critical) map onto the 0-10 scale — `informational`=0, `low`=3, `medium`=6,
`high`=8, `critical`=10 — and `_format_cef` derives the header slot from the same `severity`
value the body carries, so the two can never disagree. The URL log's body
`severity=Informational` (the live URL rows' value) therefore carries `|0|` in the header.

### Field coverage vs. the documented format

Every documented traffic-log field this simulator has a real source for is emitted, plus the
dataset columns the modeling rule reads. Checked against the official Traffic Log Fields
page on 2026-10-27:

| Documented key | Emitted as |
|---|---|
| `__firewall_type` `log_type` `subtype` `type` | routing keys; `log_type` lowercase as in the live rows, `type=TRAFFIC`/`THREAT`; `subtype` **and** `sub_type` (the dataset column the modeling rule reads) |
| `__timestamp=$start`, `__tz=$high_res_timestamp` | session start; high-res timestamp (`…ss.mmm+00:00`), also as `high_res_timestamp` |
| `receive_time` | ISO-8601. The doc defines Receive Time as `receive_time **or** cef-formatted-receive_time` (alternatives, plain vs CEF-escaped), so only `receive_time` is emitted |
| `time_generated` | ISO-8601 (the dataset types it as a timestamp). The doc defines it as `time_generated **or** cef-formatted-time_generated`; only the plain form is emitted |
| `log_time`, `session_start_time` | ISO-8601 (dataset columns, kept for the modeling rule) |
| `serial` / `log_source_id` / `log_source_name` / `device_name` / `sequence_no` / `vsys` / `vsys_name` | from `panw_ngfw_config` (`serial` and `log_source_id` carry the same value) |
| `src`/`dst`/`sport`/`dport`/`proto`/`rule`/`rule_uuid`/`from`/`to`/`sessionid`/`seqno` | documented aliases of `source_ip`/`dest_ip`/`source_port`/`dest_port`/`protocol`/`rule_matched`/`rule_matched_uuid`/`from_zone`/`to_zone`/`session_id`/`sequence_no` |
| `natsrc`/`natdst`/`natsport`/`natdport` | aliases of `nat_source`/`nat_dest`/`nat_source_port`/`nat_dest_port`; NAT only toward the internet |
| `srcuser`/`dstuser` | aliases of `source_user`/`dest_user`; `EXAMPLECORP\user` |
| `app`, `category_of_app`, `subcategory_of_app`, `technology_of_app`, `risk_of_app`, `characteristic_of_app` | from the App-ID table, cross-checked against the live feed (`characteristic_of_app` carries the App-ID's sub-category) |
| `container_of_app`, `tunneled_app`, `is_saas_of_app`, `sanctioned_state_of_app` | derived from the App-ID (`container_of_app` drops a `-base` suffix and folds `ms-ds-smb*`; `tunneled_app` is the App-ID itself) |
| `bytes`, `packets`, `pkts_sent`, `pkts_received`, `start`, `elapsed`, `category`, `srcloc`, `dstloc` | aliases of `bytes_total`, `packets_sent + packets_received`, `packets_sent`, `packets_received`, `session_start_time`, `total_time_elapsed`, `url_category`, `source_location`, `dest_location` |
| `action`, `action_source`, `actionflags`, `logset`, `repeatcnt`, `flags` | as documented (`logset` from `panw_ngfw_config.log_set`, `repeatcnt=1`, `flags`/`actionflags` = 0) |
| `bytes_sent/received`, `packets_sent/received`, `total_time_elapsed`, `session_end_reason` | as documented; denies/drops are zero-byte (`packets_sent=1`, `packets_received=0`) |
| `rule_matched`, `rule_matched_uuid`, `from_zone`, `to_zone`, `inbound_if`, `outbound_if`, `session_id` | dataset columns (the modeling rule reads these) |
| Dataset-only columns the modeling rule also reads | `users`, `log_source`, `is_nat`, `is_proxy`, `source_location`, `dest_location`, `is_non_std_dest_port`, `non_standard_dest_port`, `bytes_total` (kept because the collector does not rename the body; not documented PAN fields) |
| `src_category/profile/model/vendor/osfamily/osversion/host/mac` | one stable Device-ID profile per host, from the session identity's `os_type`/`os_version`/`device_type` (internet sources get none); also as dataset `source_device_*` |
| `dst_category/profile/model/vendor/osfamily/osversion/host/mac` | for internal destinations (DCs and servers get server profiles); also as dataset `dest_device_*` |
| `hostid` / `serialnumber` | GlobalProtect Host ID and user-device serial for a known source device (stable per host) |
| `offloaded`, `flow_type`, `ai_traffic`, `ai_fwd_error` | `offloaded=0`, `flow_type=NonProxyTraffic`, `ai_traffic=false`, `ai_fwd_error=false` |
| `src_adv_dev_id`, `dst_adv_dev_id` | Advanced Device IDs (PAN-OS 12.1.2+); the module stamps `12.1.12` and emits them for known internal endpoints |
| `rt` | **omitted by default** — not a PAN traffic-log field and ignored for `_time` on this route; set `panw_ngfw_config.emit_rt=true` to emit it (CEF receipt-time convention) |
| `xff_ip` | omitted (no proxy in front of the clients) |
| `threatid`, `misc` (Threat / URL Filtering Log Fields) | documented alias keys of the URL log's `threat_id`/`uri` live columns (Threat/Content Name; URL/Filename — "the actual URI when the subtype is url"), emitted on URL logs |
| `thr_category`, `contentver`, `pcap_id`, `url_idx` (URL Filtering / Threat Log Fields) | emitted on URL logs: `thr_category=URL filtering` (the threat class of subtype url); `contentver` (config `content_version`, default `8872-8916` — no live CLCS column); `pcap_id=0` — a live-anchored dataset column: every populated url row shows 0 (no associated pcap for an alert); `url_idx=0` — the live per-session URL-entry counter starts at 0 |
| URL format: `uri`, `url_category`, `url_category_list`, `http_method`, `threat_id`, `direction`, `user_agent`, `content_type`, `referer`, `http2_connection` | all emitted, plus live `url_domain`, `direction_of_attack`, `severity`; URL logs share the traffic session's addresses, app metadata, Device-ID, `hostid`/`serialnumber` and advanced Device ID |

Fields documented for the Traffic log but **not generated** because this simulator has no
source for them: device-group hierarchy (`dg_hier_level_1..4`), VM UUIDs, tunnel/IMSI/IMEI,
parent session, SCTP counters, app flap count, SD-WAN fields, dynamic user group, container
/ POD / K8S fields, EDL and DAG names, session owner, network-slice fields, `cluster_name`,
and the internal-use `tcp_*` telemetry fields. Threat-documentation fields that need a
subtype this module does not generate are likewise not emitted (`filetype`, `cloud`,
`filedigest`, `reportid`, `partial_hash` are WildFire/Data-Filtering fields; `sender`,
`subject`, `recipient` are email fields), and `request_headers`/`response_headers`/
`http_status_code` stay omitted because the simulated URL-filtering profile does not enable
header or response-code logging (the docs note they are populated only then).

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
CEF:0|PANW|NGFW_CEF|<sw>|url|threat|0| __firewall_type=firewall.url log_type=threat
    subtype=url sub_type=url action=alert uri=<host><path> misc=<host><path>
    url_domain=<host> url_category=.. url_category_list=<cat>,<low|high>-risk
    http_method=unknown threat_id=9999 threatid=9999 thr_category=URL filtering
    contentver=<content_version> pcap_id=0 url_idx=0 ..
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
  cloud sign-in on the activity bus, behind that sign-in's egress IP. The egress catalog is
  35 destinations: the infrastructure/update/SaaS names plus streaming (YouTube, Netflix,
  Spotify), social (LinkedIn, Facebook), storage (Dropbox, Box, Google Drive) — each mapped to
  a specific App-ID (`dropbox-base`, `youtube-base`, …) and, for browser-based apps, to the
  domain-coherent URL category (`streaming-media`, `social-networking`,
  `online-storage-and-backup`) that both the traffic log and its URL log carry.
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
Traffic-shaped scenarios are offered on demand when CEF traffic can represent the documented
detector evidence. This includes informational variants for controlled validation; they may
not appear in the alerts table. Protocol-decoded, endpoint-process, or account-state patterns
that CEF cannot represent remain hunt/correlation-only.

Targets name the alert the tenant actually raises. Informational alerts never reach the
alerts table, so where a detector's base name is Informational and the shape produces a Low
variation, the variation is the target (Port Scan fires as *Suspicious port scan*).

### Rare-event budgeting

The classic fixed weights made event rarity independent of runtime: at the Realistic gate
(one threat event per 2 h) a 30-day month has ~360 threat slots, so `port_scan` fired ~18×
and `rare_rdp`-class events ~9× — nothing was rare in the "at most once per month" sense a
UEBA rollout needs, no matter how broad the address pools are. Budgeting (added 2026-10-27)
re-allocates the same pie: every analytic event **not** in `_HIGH_VOLUME_EVENTS`
(`port_scan`, `port_sweep`, `failed_connections`, large-upload https/smtp/ftp, `spam_bot`,
`crypto_miner`, `torrent`) is capped so its **expected count ≤ 1 per
`panw_ngfw_config.rarity_horizon_days` (default 30)** at the Realistic gate cadence, and the
freed probability mass (≈16% of threat slots) flows to the high-volume vectors in proportion
to their classic weights — a month is still 360 threat events, dealt as ~1 each to every
analytic scenario plus a dozen-odd port scans/failed-connection volleys.

- The six `_DAILY_EVENTS` (`recurring_rare_*`, `ddns_access`) are exempt: their cadence is
  the once-per-UTC-day claim (`_due_daily`), which is the beacon-recurrence signal their
  detectors key on; they are no longer in the weighted draw at all.
- The cap is a probability (1/anchor-slots), so shorter intervals scale every event's
  expected count proportionally (Extreme ≈ 12×/month, High ≈ 4×) — predictable, not magic.
- `Insane` (80% of every call a threat, ~20.7M threat slots/30 days) **cannot** be budgeted
  mathematically and always keeps the classic weights: it is a stress-test mode, not a
  realism level.
- `rarity_horizon_days: 0` restores the classic fixed-weight draw.

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

## Config (`panw_ngfw_config`)

All firewall identity is driven from config, so the firewall's name and IP can be set to
whatever the environment uses; every event builds its header and `log_source_*` fields off
these values.

| Key | Default | Meaning |
|---|---|---|
| `syslog_port` | `514` | Broker VM Syslog Collector port |
| `serial_number` | `007051000012345` | firewall serial — emitted as both `serial` (documented) and `log_source_id` (dataset column) |
| `hostname` | `PA-VM-01` | firewall name (`log_source_name` / `device_name`, and the syslog header host when `syslog_hostname_format=hostname`) |
| `mgmt_ip` | `10.0.0.1` | firewall management/source IP (used as the syslog header host when `syslog_hostname_format=ipv4-address`) |
| `syslog_hostname_format` | `hostname` | what PAN stamps in the syslog header HOSTNAME field: `hostname` or `ipv4-address` (uses `mgmt_ip`) |
| `sw_version` | `12.1.12` | PAN-OS release in the CEF device-version slot |
| `content_version` | `8872-8916` | Apps and Threats content version stamped in the threat (url) logs' `contentver` field |
| `rarity_horizon_days` | `30` | Rare-event budgeting horizon: each non-high-volume analytic event's expected count ≤1 per this many days at the Realistic gate; `0` = classic fixed weights (see *Rare-event budgeting* above). Insane always uses classic weights. |
| `vsys` | `vsys1` | virtual system |
| `emit_rt` | `false` | emit the CEF `rt` receipt-time key; not a PAN traffic-log field and ignored for `_time` here |
| `log_set` | `Full EAL Logging` | value of the documented `logset` (Log Action) field |
| `action_source` | `from-policy` | `action_source` (matches the live CLCS rows) |
| `interface_lan` / `interface_wan` | `ethernet1/2` / `ethernet1/1` | inbound / outbound interfaces |
| `default_rule` | `Allow-Users-Outbound` | benign `rule_matched` |
| `nat_pool_cidr` | `203.0.113.0/27` | source-NAT egress pool |
| `domain_controllers` | `["10.0.10.10","10.0.20.10"]` | DCs for SMB-from-DC / DCSync / Kerberos |
