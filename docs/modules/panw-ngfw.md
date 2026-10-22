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

> **Routing caveat.** `NGFW_CEF` here is the **native Syslog-Collector custom format** parsed
> by `__firewall_type`. Do **not** confuse it with the *derived* ingest route (CEF vendor
> `panw`, product `ngfw_cef`), which lands in `panw_ngfw_cef_raw` with `no_hit=drop` and is
> discarded. An `rt=<epoch-ms>` extension is emitted so bursts can be back-dated — the broker
> honours CEF `rt` as `_time` during generic extraction, letting the detectors' 14-day
> activation / 30-day training windows be seeded in minutes. **Open question for the canary:**
> whether the native traffic-log analytics evaluate *syslog-delivered* PAN logs, or only the
> CLCS/direct-collector path (XDM mapping is not sufficient on its own).

Syslog PRI is `<14>` (facility `LOG_USER`=1×8 + notice=6), matching PAN-OS's default syslog
facility.

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
33 analytic events are built to satisfy a specific native PAN NGFW traffic-log detector and
are offered on demand; 4 further events are realistic network patterns kept for hunts /
correlation but **not** offered on demand (their detectors need EAL-decoded fields a CEF
traffic log cannot carry).

| Event | XSIAM analytic | Shape |
|---|---|---|
| `port_scan` | Port Scan | one host → ~20–24 privileged ports on one server |
| `port_sweep` | Port Sweep | one privileged port across many hosts in ≥3 subnets |
| `failed_connections` | Failed Connections | ~120 zero-byte denies to ~40 inactive hosts |
| `large_upload_https` | Large Upload (HTTPS) | big `bytes_sent` over 443 to a rare dest |
| `large_upload_https_nonstd` | Large Upload (HTTPS) | same over a non-standard HTTPS port |
| `large_upload_smtp` | Large Upload (SMTP) | big upload over 587/25 |
| `large_upload_ftp` | Large Upload (FTP) | big upload over 21 |
| `large_upload_generic` | Large Upload (Generic) | big upload over an uncommon port |
| `rare_rdp` | Rare RDP session to a remote host | RDP to a rarely-seen host |
| `abnormal_rdp_rare_host` | Abnormal RDP … from a rarely seen host | RDP from a rare source host |
| `rdp_unmanaged` | RDP from an unmanaged endpoint … | RDP from an unmanaged src in a managed subnet |
| `rare_smb` | Rare SMB session to a remote host | SMB to a rarely-seen host |
| `smb_from_dc` | Suspicious SMB connection from domain controller | DC → workstation SMB |
| `dcsync_non_dc` | Possible DCSync from a non domain controller | DRSUAPI RPC from a non-DC → DC |
| `rare_smtp` | Rare SMTP/S Session | SMTP to a rare external server |
| `spam_bot` | Spam Bot Traffic | one host → 40–90 external SMTP servers |
| `uncommon_ssh` | Uncommon SSH session was established | SSH to a rare host |
| `unusual_ssh` | Unusual SSH Activity | long, high-volume SSH |
| `ssh_proxy` | Unusual SSH activity that resembles SSH proxy | host both receives and initiates SSH |
| `rare_ssh_external` | Rare process created an SSH session to an uncommon external host | SSH to a rare external host |
| `recurring_rare_ip` | Recurring access to rare IP | same src → same rare IP, back-dated over days |
| `recurring_rare_domain` | Abnormal Recurring Communications to a Rare Domain | beacon to a rare domain over days |
| `rare_domain_comm` | Abnormal Communication to a Rare Domain | single comm to a newly-registered domain |
| `ddns_access` | Recurring rare domain access to dynamic DNS domain | recurring access to a dyn-DNS domain |
| `crypto_miner` | A Possible crypto miner was detected on a host | mining-pool traffic (stratum ports) |
| `torrent` | A Torrent client was detected on a host | BitTorrent app |
| `p2p_upload` | Upload pattern that resembles Peer to Peer traffic | asymmetric P2P upload |
| `p2p_download` | Download pattern that resembles Peer to Peer traffic | asymmetric P2P download |
| `ipfs` | Possible use of IPFS was detected | IPFS node traffic |
| `rare_appid` | Rare AppID usage to a rare destination | rare App-ID to a rare dest |
| `new_ftp_server` | New FTP Server | first-seen internal FTP server |
| `new_admin_behavior` | New Administrative Behavior | host does admin services to many new dests |
| `dormant_host_conn` | Abnormal connections to a dormant host … | new endpoint → long-inactive host |
| `kerberos_preauth_pattern` | *(non-analytic)* | Kerberos (88) burst to a DC |
| `ntlm_relay_pattern` | *(non-analytic)* | SMB auth fan-out (relay shape) |
| `dns_tunnel_pattern` | *(non-analytic)* | high-volume DNS to one resolver |
| `ldap_recon` | *(non-analytic)* | LDAP (389/636) enumeration against a DC |

All multi-event sequences end at or before the current time; back-dated recurring bursts
carry their `rt` across the past several days so the detectors' training history accrues.

## Detector coverage vs. the 49 PAN NGFW traffic-log alerts

**Covered (33 on demand)** — every detector above that keys on connection metadata the CEF
traffic log carries: reconnaissance (port scan/sweep, failed connections), exfil (the four
Large Upload detectors), rare lateral/remote-access (RDP/SMB/SMTP/SSH families, SMB-from-DC,
DCSync-over-the-wire), beaconing (recurring rare IP/domain, dynamic-DNS), application-shape
(crypto miner, torrent, P2P, IPFS, rare AppID), and profiling (new FTP server, new admin
behavior, dormant-host connections).

**Not reachable over CEF syslog** — the remaining ~14 traffic-log alerts need
Enhanced-Application-Logging (EAL) decoded protocol fields a CEF traffic log does not carry,
or an XDR Agent:

- **Kerberos** — Pre-Auth Failures (by Host; by User and Host), User Enumeration,
  Weakly-Encrypted / Multiple Weakly-Encrypted Kerberos Tickets, Kerberoasting without SPNs
  (need Kerberos encryption-type / error / TGS fields).
- **NTLM** — NTLM Relay, Machine Account NTLM Relay, NTLM Password Spray, NTLM Hash
  Harvesting, Rare NTLM Access By User To Host (need the NTLM `NTProofStr`).
- **Account state** — Authentication Attempt From a Dormant Account, Failed Login For
  Locked-Out Account (need Kerberos TGS + AD account state).
- **Agent-only** — A user accessed an uncommon AppID, Rare process created an SSH session to
  an uncommon cloud resource (require the XDR Agent); Suspicious DNS traffic / DNS-tunnelling
  need EAL `dns_query_name` entropy.

The `kerberos_preauth_pattern`, `ntlm_relay_pattern`, `dns_tunnel_pattern` and `ldap_recon`
events still emit the realistic network shapes for hunting and correlation-rule coverage,
but are flagged non-analytic so they are not offered on demand.

## Config (`panw_ngfw_config`)

| Key | Default | Meaning |
|---|---|---|
| `syslog_port` | `514` | Broker VM Syslog Collector port |
| `serial_number` | `007051000012345` | firewall serial (`log_source_id`) |
| `hostname` | `PA-VM-01` | firewall name (`log_source_name` / syslog host) |
| `vsys` | `vsys1` | virtual system |
| `interface_lan` / `interface_wan` | `ethernet1/2` / `ethernet1/1` | inbound / outbound interfaces |
| `default_rule` | `Allow-Users-Outbound` | benign `rule_matched` |
| `nat_pool_cidr` | `203.0.113.0/27` | source-NAT egress pool |
| `domain_controllers` | `["10.0.10.10","10.0.20.10"]` | DCs for SMB-from-DC / DCSync / Kerberos |
