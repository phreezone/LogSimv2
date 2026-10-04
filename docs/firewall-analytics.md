# Firewall & VPN analytics — what can fire, and why the rest can't

Cross-module reference for the five network modules (Cisco ASA, Cisco Firepower,
Fortinet FortiGate, Check Point, Zscaler) against the Cortex XSIAM **Third-Party
Firewalls** and **Third-Party VPNs** analytics.

Last reviewed **2026-09-17**. Every claim below was measured in-tenant or checked
against the Cortex Analytics Alert Reference. Detectors have a 14-day activation and a
30-day training period. Several fixes below also change the data those detectors
baseline on, so don't treat silence before **2026-10-16** as evidence.

## 1. What each dataset can carry into XDM

This constrains everything else: a generator can't drive a detector with a field its
dataset never delivers to XDM. Figures are % of rows over 24h (2026-09-17).

| dataset | internal src | dst port | app ID | bytes | domain / URL | user | outcome |
|---|---|---|---|---|---|---|---|
| `cisco_asa_raw` | 85% | 90% | **0%** | **5%** | **0%** | 11% | **0%** |
| `cisco_firepower_raw` | 78% | 100% | 100% | 83% | **0%** | 100% | 100% |
| `fortinet_fortigate_raw` | 90% | 95% | 90% | 86% | 71% | 92% | 100% |
| `check_point_vpn_1_firewall_1_raw` | 80% | 97% | 91% | 67% | labels only¹ | 80% | **0%** |
| `zscaler_nssfwlog_raw` | 67% | 100% | 99% | 100% | 0% | 100% | 0% |
| `zscaler_nssweblog_raw` | egress IP² | 100% | 0% | 100% | 100% | 100% | 0% |

Which raw field feeds `xdm.network.application_protocol`:
FortiGate `app` (not `FTNTFGTapp`) · Firepower `app` · Check Point `app` → `service_id` ·
Zscaler FW `cs3` (from `nwsvc`). ASA has none.

¹ Check Point filled `xdm.target.host.hostname` with service **labels**
(`zoom`, `docusign`, `atlassian(jira/confluence)`) from `benign_egress_destinations[].name`,
not FQDNs — 81% of values, and Zscaler Web the same on 39% of `http.domain` values.
**Fixed 2026-09-18** (see §6): each `benign_egress_destinations` entry now carries a real
`domain` FQDN, and both benign generators emit it.
² Zscaler Web attributes `xdm.source.ipv4` to the egress/translated address: 3 distinct
values tenant-wide. The internal client is only in `xdm.source.host.ipv4_addresses`.

## 2. Root causes fixed on 2026-09-17 (cross-module)

| # | Defect | Effect | Fix |
|---|---|---|---|
| R1 | **Every FortiGate, Firepower and Check Point VPN auth event was `EXAMPLECORP\user`** (6,561 / 5,132 / 6,318 per week; ASA 9,043 bare) | Identity Analytics collapses every VPN user into one identity called `examplecorp` (proven by A/B on ASA 2026-07-28). ASA is the only vendor whose VPN analytics have ever fired. | Each formatter forces VPN auth events bare via `session_utils.vpn_username()`. Non-VPN identity-firewall fields keep the prefix for identity stitching. |
| R2 | **FortiGate's XIF takes `xdm.source.location.country` from `FTNTFGTsrccountry` text**, and benign VPN logins stamped a random `_ext_geo()` country | Every FortiGate user had a ~10-country VPN baseline including China and Russia (~1,400 logins/week each) | `session_utils.ip_country()`: every FortiGate VPN event now carries its IP's real country |
| R3 | Rarity detectors fed from **ambient** pools | A destination drawn from the busiest networks in the tenant is never rare | `session_utils.RARE_EXTERNAL_RANGES` / `rare_external_ip()` (24 /24s, provably disjoint from ambient, benign, Tor /16 allowlist, and novel-country pools) · `rare_internal_host()` · `rare_domain()` |
| R4 | "Recurring" detectors fed a **random host per run** | No (host, destination) pair ever recurred across days | `session_utils.stable_beacon_pairs()`: deterministic pairs that survive restarts. ASA also guarantees them daily via `_DAILY_EVENTS`. |
| R5 | Impossible travel built on **fail→succeed** | The detector keys on successful connections from multiple countries | Rebuilt everywhere on `session_utils.impossible_travel_ips()`: home IP, then a home-pool range on another continent. **Adds zero new countries** to the org baseline. |
| R6 | ASA ICMP emitted `faddr`=external | 97% of ICMP rows recorded an external actor. They made up 43 of ASA's 51 source countries and burned 10 novel-pool countries. | Internal host now leads `faddr` (see [cisco-asa.md](modules/cisco-asa.md)) |

## 3. Every formerly Non-Analytic event: verdict

**Rebuilt** means the logic was replaced and the event now targets a real detector.
**New** means a correctly shaped successor event was added and the original kept as vendor
noise, because the original's premise (a *block*) is the opposite of what the detector
wants. **Kept** means no rebuild can make it fire, for the reason shown.

### Cisco ASA
| event | verdict | target / reason |
|---|---|---|
| `web_c2_beacon` | Rebuilt | Recurring access to rare IP (stable pairs, daily) |
| `cryptomining` | Rebuilt | Recurring access to rare IP (stable pairs, daily) |
| `external_fanout` | Rebuilt | Port Sweep: one worm port, many subnets (was 80/443, which the detectors discount) |
| `vpn_concurrent_sessions` | Rebuilt | Impossible traveler - VPN (was two random, often same-country, IPs) |
| `smtp_spray` | Rebuilt | Spam Bot Traffic: port 25 only, rare servers. **Risk:** firing alerts carry an app ID, and ASA has none. |
| `large_single_upload_session`, `cumulative_upload_session`, `smtp_large_exfil` | Kept | Connection bytes never reach XDM: they land in `transferred_bytes` / `_json.sentBytes`, which `CiscoASA_1_4.xif` doesn't read |
| `failed_connections_burst` | Kept | `parse_cisco` discards the teardown reason, and `xdm.event.outcome` is null on 100% of rows |
| `rare_port_connection` | Kept | No firewall analytic keys on (IP, port) alone. The "less common port" variants belong to rare-*domain* detectors, and ASA has no domain. |
| `vpn_data_exfil` | Kept | No VPN-volume analytic exists |

### Cisco Firepower
| event | verdict | target / reason |
|---|---|---|
| `vpn_brute_force` | Rebuilt | VPN login Brute-Force attempt (was attributed to the literal user `EXTERNAL_ATTACKER`) |
| `vpn_impossible_travel` | Rebuilt | Impossible traveler - VPN |
| `ssh_over_https` | Rebuilt | Rare AppID usage to a rare destination (the destination was ambient) |
| `internal_smb` | Rebuilt | Rare SMB session to a remote host (was a copy of the *benign* file-server generator) |
| `app_control` | Kept + **New** `torrent_client` | A Torrent client was detected on a host. The original was one blocked event with BitTorrent 1 of 12 random apps. |
| `url_filtering`, `security_intel` | Kept | Firepower's XDM carries no domain (0 of 209k rows over 7 days) |
| `ips`, `malware`, `network_anomaly` | Kept | Vendor signature events. No Third-Party Firewall analytic consumes them. |
| `brute_force` | Kept | Non-VPN auth: there's no Third-Party Firewall analytic for it |

### Fortinet FortiGate
| event | verdict | target / reason |
|---|---|---|
| `vpn_brute_force` | Rebuilt | VPN login Brute-Force attempt. The original was a password spray (10 names, 1–4 failures each, half not real users). |
| — | **New** `vpn_password_spray` | VPN Login Password Spray: the old shape, rebuilt with real users |
| `vpn_impossible_travel` | Rebuilt | Impossible traveler - VPN (labelled a North Korean IP "China") |
| `webfilter_block` | Kept + **New** `rare_domain_communication` | Abnormal Communication to a Rare Domain: allowed session to a fresh rare-TLD domain with DNS, webfilter passthrough and traffic records |
| `app_control_block` | Kept + **New** `torrent_client` | Torrent client. The original put the app in `FTNTFGTapp`, which never reaches XDM. |
| `ips`, `antivirus`, `waf_attack`, `dos_anomaly`, `dlp_block` | Kept | Vendor signature/policy events. No analytic consumes them. |
| `auth_brute_force` | Kept | Admin-console auth: there's no Third-Party analytic for it |

Also fixed, though already labelled analytic: `vpn_abnormal_os` now comes from the user's own home IP
and real country, so only the OS is anomalous.

### Check Point
| event | verdict | target / reason |
|---|---|---|
| `vpn_brute_force` | Rebuilt | VPN login Brute-Force attempt (Identity Awareness dataset; spread over minutes) |
| `vpn_impossible_travel` | Rebuilt | Impossible traveler - VPN |
| `workstation_rdp` | Rebuilt | Rare RDP session to a remote host (was a 5–8 host sweep, 60% dropped) |
| `app_control` | Kept + **New** `torrent_client` | Torrent client via the firewall product. `Application Control` routes to a separate dataset. |
| `url_block` | Kept | No FQDN reaches XDM (hostname labels only, ¹ above) |
| `ips`, `smartdefense`, `identity` | Kept | Vendor signature/policy events |
| `auth_brute_force` | Kept | No Third-Party analytic for non-VPN auth |

### Zscaler
| event | verdict | target / reason |
|---|---|---|
| `ssh_over_https` | Rebuilt | Rare AppID usage to a rare destination (was a *blocked* event to an ambient IP) |
| `web_threat` | Kept + **New** `rare_domain_communication` | Abnormal Communication to a Rare Domain. **Risk:** egress-IP source attribution (² above). |
| `vpn_brute_force`, `vpn_impossible_travel`, `brute_force` | Kept | NSS FW logs carry no VPN/auth semantics: no auth outcome is modelled (outcome 0%) |
| `dlp_threat`, `sandbox_threat`, `cloud_app_threat`, `fw_threat` | Kept | Vendor signature/policy events |

**Open, not changed:** Zscaler's `vpn_tor_login` and `vpn_new_country_login` are labelled
*analytic*, but for the reason above they can't reach a Third-Party VPN detector from NSS FW data.

## 4. Unreachable from any of these five sources

- **Recurring access to rare domain.** It *requires* PANW firewall EAL or threat logs in addition to firewall data.
- **Rare process created an SSH session (×2).** These need agent process data.

## 5. Re-evaluation

Run the 30-day alert query on **2026-09-30** and **2026-10-16**. Any rebuilt event
still silent on 2026-10-16 should go back into its module's Non-Analytic set, with the
measurement recorded here.

## 6. Update 2026-09-18 — label fix, data fixes, and full detector coverage

Three follow-on workstreams. All changes verified by generating and re-parsing events;
none has been confirmed firing in-tenant yet (same 14d activation / 30d training caveat).

### 6a. Service-label → real FQDN (footnote ¹)

Every `benign_egress_destinations` entry (top-level and `zscaler_config`) gained a real
`domain`. Check Point's benign `dhost` and Zscaler's benign `ehost` now emit it, so
`xdm.target.host.hostname` / `xdm.network.http.domain` carry `zoom.us`, not `zoom`. This
un-pollutes the rare-domain baselines for both vendors. `_local_validation/domain_corpus_check.py`
was updated to detect curated sites by `domain` rather than the slugified name.

### 6b. Data fixes that unblocked existing generators

Applied across FP / FG / CP / ZS (ASA was done 2026-09-17):

- **Rarity generators repointed from the ambient pool to the rare pool** — `rare_external_rdp`,
  `rare_ssh`, `reverse_ssh_tunnel`, `dns_c2_beacon` (resolver), `server_outbound_http`,
  `web_c2_beacon` (ZS). A destination drawn from the 35 `.20.0/24` ambient networks that
  all modules use for normal traffic can never be *rare*; they now draw from
  `session_utils.RARE_EXTERNAL_RANGES`, stable per source via the beacon map.
- **`smb_rare_file_transfer` repointed** from `internal_servers` (the hot pool every SMB
  generator hits) to `rare_internal_host()`.
- **Wrong `xsiam_alert` targets corrected.** `reverse_ssh_tunnel` → *Uncommon SSH session
  was established*; `server_outbound_http` and `dns_c2_beacon` (FP/CP/ZS, no domain in XDM)
  → *Recurring access to rare IP*.
- **Reclassified Non-Analytic** (no matching Third-Party Firewall analytic exists):
  `large_download`, `dns_tunneling`, `ldap_recon` (an XDR-Agent alert, not firewall),
  and `ddns_connection` on **Firepower/Check Point only** (their XDM carries no domain; kept
  analytic on FortiGate/Zscaler, which do).

### 6c. New detectors — every reachable alert now covered

Added so all four CEF modules cover every Third-Party Firewall alert their data can drive:

| new generator | alert | FP | FG | CP | ZS |
|---|---|---|---|---|---|
| `port_sweep` | Port Sweep (one privileged port × many hosts, several subnets) | ✅ | ✅ | ✅ | ✅ |
| `dc_smb_outbound` | Suspicious SMB connection from domain controller (source is a real DC) | ✅ | ✅ | ✅ | ✅ |
| `new_ftp_server` | New FTP Server (inbound external clients → internal :21 — the correct shape) | ✅ | ✅ | ✅ | ✅ |
| `rare_smtp_session` | Rare SMTP/S Session (single session to a rare mail server; app in the AppID field) | ✅ | ✅ | ✅ | ✅ |
| `rare_appid` | Rare AppID usage to a rare destination | — | ✅ | ✅ | — |
| `abnormal_rdp_rare_host` | Abnormal RDP session … from a rarely seen host (stable rare-source pool) | — | ✅ | ✅ | — |
| `torrent_client` | A Torrent client was detected on a host | — | — | — | ✅ |

(— = the module already covered that alert.) **ASA was deliberately excluded from Rare
SMTP/S**: it carries no application ID, the same gap that keeps ASA `smtp_spray`
Non-Analytic.

### 6d. What remains Non-Analytic, and why (final)

Everything below is blocked by data the parser cannot deliver or by the absence of a
matching analytic — no generator change can make them fire:

- **Vendor signature/policy events** (kept as realistic noise): `ips`, `malware`,
  `antivirus`, `url_filtering`/`url_block`/`webfilter_block`, `security_intel`,
  `smartdefense`, `waf_attack`, `dos_anomaly`, `dlp_block`/`dlp_threat`, `sandbox_threat`,
  `cloud_app_threat`, `fw_threat`, `app_control`/`app_control_block`, `network_anomaly`,
  `identity`.
- **Non-VPN auth brute force** (`brute_force`, `auth_brute_force`) — no Third-Party
  Firewall analytic exists for it.
- **`large_download`, `dns_tunneling`, `ldap_recon`** — no matching Third-Party Firewall
  analytic (see 6b). ASA's `ldap_recon` joined its `_NON_ANALYTIC_EVENTS` on 2026-09-29;
  LDAP enumeration is an XDR-agent detection.
- **`ddns_connection` (FP/CP)** — no domain reaches XDM.
- **Zscaler `vpn_*`** — NSS FW logs carry no VPN auth semantics.
- **ASA volume/failure/SMTP events** — bytes, teardown reason, and application never
  reach ASA's XDM (documented in [modules/cisco-asa.md](modules/cisco-asa.md)).

`ftp_large_exfil` was on this list until 2026-09-29. It is an outbound upload, not a New
FTP Server, but *Large Upload (FTP)* is a real analytic missing from the published
Third-Party Firewalls list: it fired from Firepower data on 2026-09-25. It is analytic
again on Firepower, Check Point and FortiGate.

Everything in this section runs only in long-running sessions. Since 2026-09-29 the
dashboard, MCP and CLI offer on demand only the threats marked analytic
(`modules/threat_catalog.py`); the old `[Non-Analytic] ` display prefix is retired.

### 6e. Still open

- **Zscaler Web egress-IP source attribution** (footnote ²) — unchanged; it caps the
  effectiveness of Zscaler's domain-based and web-sourced detectors and needs a
  modeling-rule change, not a generator change.
- **Unreachable from these sources** (§4): *Recurring access to rare domain* (needs PANW
  EAL/threat logs) and the two *Rare process created an SSH session* alerts (need agent
  process data).
