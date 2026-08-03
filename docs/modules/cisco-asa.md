# Cisco ASA Firewall

**Dataset:** `cisco_asa_raw`
**Transport:** Syslog (TCP)
**Format:** Native Cisco ASA syslog (`%ASA-N-MSGID: ...`)

Simulates Cisco ASA firewall syslog messages for the XSIAM `cisco_asa_raw` dataset. The module generates native ASA syslog format; XSIAM's built-in Cisco ASA parsing rule creates the `generalCiscoLog` JSON structure, and `CiscoASA_1_4.xif` maps `_json -> generalCiscoLog.*` fields to XDM. Each message is wrapped with a syslog PRI header using facility local4 (20×8=160) plus the severity digit from the `%ASA-N-` prefix, e.g., `<166>` for informational and `<164>` for warning.

### Timestamp format is mandatory — RFC 5424 / ISO 8601 only

The wire format is `<PRI>YYYY-MM-DDThh:mm:ssZ HOSTNAME : %ASA-N-MSGID: text` — verified genuine against Cisco's own RFC 5424 example (`<166>2018-06-27T12:17:46Z asa : %ASA-6-110002: ...`), standard **non-EMBLEM** format. This is not cosmetic: the Cortex `CiscoASA` **ParsingRule** extracts `_time` **only** when the timestamp matches `%Y-%m-%dT%H:%M:%SZ` (contains `Z`) or `%Y-%m-%dT%H:%M:%S%Ez` (numeric offset). It has **no pattern for the ASA default BSD timestamp** (`Mmm dd hh:mm:ss`). A real ASA out-of-the-box therefore ingests with `_time` unset, silently breaking every time-windowed detection (UEBA, brute-force, port-scan, impossible-travel). To onboard a real ASA to XSIAM you **must** configure `logging timestamp rfc5424` (ASA 9.10+) — the XSIAM Cisco ASA onboarding page omits this, which is the most likely cause of "ASA logs ingest but no analytics fire." The simulator emits this format by design; do **not** revert it to a BSD-style timestamp.

### Format fidelity — verified against official Cisco docs (source of truth)

All emitted message bodies were cross-checked against the Cisco Secure Firewall ASA Series Syslog Messages guide: `302013`/`302014` Built/Teardown (incl. `duration H:MM:SS bytes N reason`), `302015`/`302016` UDP, `106023` deny (`by access-group "ACL" [0x..., 0x0]`), `109005`/`109006` auth (`for user 'user' from ip/port to ip/port on interface`), and the AnyConnect `113019`/`113039`/`722051` — all match, **with one deliberate exception documented under "Source orientation" below**. **ICMP `302020`/`302021`** was corrected 2026-07-24: Cisco's template is `faddr <addr>/<icmp_seq_num> gaddr <addr>/<icmp_type> laddr <addr>/<icmp_code>`; the module previously emitted the ICMP *type* in both the faddr and gaddr slots and now emits a sequence number after `faddr` and the type after `gaddr`.

### XSIAM only models a fixed set of message IDs

Per the XSIAM Cisco ASA onboarding doc, XSIAM's ASA analytics **only parse into XDM**:
- **Connections:** `302013`, `302014`, `302015`, `302016`
- **AnyConnect:** `113019`, `113039`, `716001`, `716002`, `722022`, `722023`, `722033`, `722034`, `722037`, `722051`, `722053`

Every ASA analytics detection therefore has to be driven by connection events or AnyConnect session events. **Deny (`106023`), cut-through auth (`109001`/`109005`/`109006`), IDS (`4000xx`), ICMP (`302020`/`302021`), and NAT (`305011`/`305012`) messages are NOT modeled** — they land in `cisco_asa_raw` as raw text (usable for XQL hunting) but never fire an analytic. Changes made 2026-07-24 to keep every catalog threat parseable:
- **`failed_connections_burst`** — reworked from `106023` denies to a burst of `302013`+`302014` inbound flows with reason `SYN Timeout` and 0 bytes (a permitted-but-unanswered connection = a genuine, parseable failed connection).
- **`vpn_impossible_travel`** — reworked from a `109006`→`109005` fail→success door-knock (invisible to XSIAM) to two SUCCESSFUL AnyConnect sessions (`113039`+`722051`) from impossibly-distant IPs. *The fail→success pattern cannot apply to ASA because XSIAM does not parse ASA auth-failure messages.*
- **`external_port_scan`** — REMOVED (it used `106023`; the internal `port_scan` already covers scanning via `302013`/`302014`, and external denies are unparseable).
- **`vpn_bruteforce`** — DELISTED from the threat catalog (no supported AnyConnect auth-failure message exists). Its generator is retained only for the cross-source XQL-hunt scenario that reads the raw `109006` text.
- **Benign** `aaa_auth`/`inbound_block`/ICMP/NAT are intentionally kept as realistic raw-stream noise (they don't parse; harmless).

### Source orientation — a deliberate deviation from genuine Cisco

Genuine Cisco logs an **outbound** connection with the destination leading the `for` clause and the initiator in the `to` clause:

```
Built outbound TCP connection 506986 for outside:17.151.140.30/80 (17.151.140.30/80) to inside:192.168.1.44/61094 (50.197.188.217/61094)
```

Cortex's built-in `parse_cisco()` assigns `for`→`src_ip` and `to`→`dst_ip` unconditionally, so emitting the genuine order made XSIAM record the **external peer as the actor** on ~91% of events. Analytics baseline the source entity, so nothing could accumulate. Measured in-tenant 2026-07-28: `xdm.source.ipv4` was an internal address on only **9.02%** of ASA rows, versus 77–88% for Firepower / Check Point / FortiGate, which were the only three firing network analytics.

**The module therefore emits the clauses swapped** (internal host leads `for`), which took the same measurement to **100%**. This is intentional — the emit site in `modules/cisco_asa.py` carries a `DO NOT "FIX" BACK` comment. Inbound sessions are unaffected: genuine inbound ASA is already source-first, so only outbound output deviates.

### VPN identity must be a BARE username — no `EXAMPLECORP\` prefix

AnyConnect messages (`113039`/`113019`/`722051`) use `_vpn_user()`, **not** `_ad_user()`. XSIAM's Identity Analytics reduces `EXAMPLECORP\jdoe` to the **domain**, collapsing every VPN user into one identity called `examplecorp`. Proven by controlled A/B in-tenant 2026-07-28 — two different probe users sent with the prefix both surfaced as `examplecorp`, while bare usernames surfaced correctly:

| sent | alert `user_name` |
|---|---|
| `p.probealpha` (bare) | `p.probealpha` |
| `p.probecharlie` (bare) | `p.probecharlie` |
| `EXAMPLECORP\p.probebravo` **and** `EXAMPLECORP\p.probedelta` | both → `examplecorp` |

The prefix was added on 2026-04-27 (`6befff4`) for cross-source identity stitching and had the opposite effect: with all logins merged into one identity, Tor access became that identity's baseline-normal behaviour and **"A Successful VPN connection from TOR" stopped firing on 2026-05-18 after 343 alerts**. Bare usernames restored it within minutes. The message *format* (`Group <G> User <U> IP <P>` vs `Group = G, Username = U, IP = P`) makes no difference — both parse identically. Connection-event IDFW parentheticals still use `_ad_user()`; they parse to `dst_fwuser`, which the modeling rule never reads.

### What ASA analytics actually fire

Two different subsystems, and only one of them works for ASA today:

- **Identity Analytics (works).** Driven by AnyConnect session events — e.g. *A Successful VPN connection from TOR*, *First successful VPN access from a country in organization*. These are the ~11% of ASA rows where `xdm.source.user.username` is populated (from `vpn_user`).
- **Third-party firewall analytics (essentially unproven).** In this tenant ASA has fired exactly **one** — a single *Suspicious port scan* on 2026-04-16 — across the whole alert history. The source-orientation fix above targets this gap, but each detector still needs a fresh baseline before it can fire, so the `xsiam_alert` values in the threat table below are the alert each generator is **designed** to drive, not a confirmed firing.

Note also that non-VPN user attribution is **unreachable**: `parse_cisco` files the connection IDFW user under `dst_fwuser`, and `CiscoASA_1_4.xif` sets `xdm.source.user.username` from `coalesce(user, src_fwuser, vpn_user)` only.

---

## Benign Events

Benign events are dispatched from `generate_log` using weighted random choice. The primary generator `_simulate_benign_office_traffic` picks a service type and builds a `Built` + `Teardown` session pair (or ICMP pair). `_simulate_inbound_block` generates single-line `106023` deny messages. `_generate_anyconnect_vpn_log` generates VPN session start (`113039`) or end (`113019`) messages. `_generate_aaa_auth_log` generates `109001` + `109005/109006` pairs. Duration is formatted as `H:MM:SS` for XIF regex parsing into `xdm.event.duration`.

| Event Type | Description | Key Fields | Weight |
|---|---|---|---|
| `benign_session` | Standard office traffic: Web Browsing (65%), DNS Query (15%), Email Client (10%), SSH (5%), ICMP Ping (5%). Generates `302013`/`302014` Built+Teardown pairs for TCP, `302015`/`302016` for UDP, or `302020`/`302021` for ICMP. NAT/PAT applied for outbound sessions. | Web: `%ASA-6-302013/302014`, `dpt=80 or 443`, duration 5–120s; DNS: `302015/302016`, `dpt=53`, proto=UDP; Email: `302013/302014`, `dpt=25/587/993`; SSH: `302013/302014`, `dpt=22`; ICMP: `302020/302021` | 50 |
| `inbound_block` | External internet probe blocked by outside-in ACL. Single `%ASA-4-106023` deny message per event. | `%ASA-4-106023: Deny tcp/udp src outside:ext_ip/port dst inside:target_ip/port by access-group "ACL_NAME"`, `dpt` one of 22/23/25/80/135/139/443/445/1433/1521/3306/3389/4444/5900/6379/8080/8443, proto TCP (85%) or UDP (15%) | 22 |
| `anyconnect_vpn` | AnyConnect VPN session start (113039) or end (113019), chosen randomly. Session start has 0 bytes; session end has duration 60–3600s and byte counters. | `%ASA-6-113039` (start): `Group <group> User <user> IP <public_ip> AnyConnect parent session started.`; `%ASA-4-113019` (end): `Group = group, Username = user, IP = ip, ... Duration: H:MM:SS, Bytes xmt: N, Bytes rcv: N` — username is **bare**, see "VPN identity" above | 9 |
| `aaa_auth` | AAA authentication request+result pair. `109001` auth start followed by `109005` success (85%) or `109006` failure (15%). | `%ASA-6-109001: Auth start for user 'user' from src/0 to outside/443`; `%ASA-6-109005: Authentication succeeded` or `%ASA-6-109006: Authentication failed` | 5 |
| `ntp_sync` | NTP time synchronisation — UDP/123 Built+Teardown pair from an internal host to a public NTP pool server. Very short duration (0 seconds), tiny bytes (~48–76 each direction). | `%ASA-7-302015/302016: Built/Teardown UDP connection`, `src=internal_host/random_port`, `dst=ntp_server/123`, `duration=0:00:00`, `bytes=48–76` | 6 |
| `internal_traffic` | East-west LAN traffic — workstation to internal file/app/print server (both interfaces = inside). Service types: SMB/445 (30%), RPC/135 (15%), LDAP/389 (15%), HTTP-internal/8080 (15%), MSSQL/1433 (10%), Print/9100 (10%), HTTPS-internal/8443 (5%). Returns Built+Teardown pair. | `%ASA-6-302013/302014`, `src_interface=inside`, `dest_interface=inside`, `dpt=445/135/389/8080/1433/9100/8443`, `bytes_sent=1000–500000`, `bytes_recv=1000–50MB`, `duration=1–300s` | 5 |
| `dhcp_log` | DHCP address assignment/release — `%ASA-6-305011` (translation built) or `%ASA-6-305012` (teardown). Models DHCP client activity seen by an ASA running a DHCP server or relay. Picks built (70%) or teardown (30%). | `%ASA-6-305011: Built dynamic TCP translation from inside:client_ip/68 to outside:nat_ip/port`; `%ASA-6-305012: Teardown dynamic TCP translation ...` | 3 |

---

## Threat Events

Threat events are dispatched from `generate_log` by weighted random choice. The **effective** weights are those in `config.json` → `cisco_asa_config.event_mix.threat`; the module's `_DEFAULT_THREAT_NAMES`/`_DEFAULT_THREAT_WEIGHTS` catalog is only a fallback used when that config list is absent. A non-empty config list **fully shadows** the catalog, so an event added to the catalog alone is dashboard-selectable but never fires ambiently — add it to both. The Weight column below is the config weight. Most generators return a list of syslog strings. Session pairs (`Built`+`Teardown`) are generated by `_generate_connection_session` and use `H:MM:SS` duration format.

| Threat Key | Category | Description | Syslog IDs / Key Fields | Weight |
|---|---|---|---|---|
| `port_scan` | Reconnaissance | 100–200 rapid TCP `Built`+`Teardown` pairs from one internal scanner IP to one internal victim, each on a different port. Teardown reason `TCP Reset-I` (no service listening). Returns list. | `%ASA-6-302013/302014`, `src_interface=inside`, `dest_interface=inside`, `teardown_reason=TCP Reset-I`, `bytes=0`, `duration=0:00:00`, large number of distinct `dpt` | 1 |
| `large_single_upload_session` | Data Exfiltration | Single large TCP session to an exfiltration destination on TCP/443. 750 MB – 1.5 GB sent bytes, duration 300–900s. Returns list of 2 (Built+Teardown). | `%ASA-6-302013/302014`, `dpt=443`, `bytes=750MB–1.5GB`, `duration=H:MM:SS(5–15min)` | 1 |
| `cumulative_upload_session` | Data Exfiltration | Multiple successive TCP sessions to the same exfil destination, each 80–150 MB, until total exceeds ~700 MB. Models slow-drip exfiltration. Returns list of many Built+Teardown pairs. | `%ASA-6-302013/302014`, `dpt=443`, multiple sessions with cumulative bytes exceeding 700MB | 1 |
| `unusual_ssh_session` | Suspicious Activity | Single outbound SSH session on TCP/22 to a random external IP. Returns list of 2 (Built+Teardown). | `%ASA-6-302013/302014`, `dpt=22`, `duration=30–600s` | 2 |
| `unusual_rdp_session` | Lateral Movement | RDP session from workstation to internal server on TCP/3389 with large byte counts (1–100 MB each direction). Returns list of 2. | `%ASA-6-302013/302014`, `dpt=3389`, `src_interface=inside`, `dest_interface=inside`, `bytes=1MB–100MB each direction`, `duration=2–30min` | 2 |
| `ssh_proxy_attack` | Lateral Movement | SSH sessions from one internal host to 2–5 different internal server IPs (SSH proxy/jump host pattern). Returns list of 2 logs per victim. | `%ASA-6-302013/302014`, `dpt=22`, `src_interface=inside`, `dest_interface=inside`, 2–5 distinct destinations | 1 |
| `tor_connection` | Anonymization | Single outbound TCP session to a Tor exit node IP on port 443, 9001, or 9030. Returns list of 2 (Built+Teardown). | `%ASA-6-302013/302014`, `dst=tor_exit_ip`, `dpt=443/9001/9030`, `duration=10–120s` | 2 |
| `vpn_bruteforce` | Credential Attack | **DELISTED / raw-only** (not in the threat catalog; retained only for the cross-source XQL-hunt scenario). Built on `109006` auth-failures which XSIAM does not parse, so it cannot fire an analytic. Credential stuffing: one external IP tries 5–10 usernames with 2–5 rapid `109006` failures each. Returns list. | `%ASA-6-109006: Authentication failed for user 'user' from attacker_ip/port to outside_ip/443 on interface outside` (raw text only) | — |
| `vpn_impossible_travel` | Identity Anomaly | Two SUCCESSFUL AnyConnect logins for the same user from impossibly-distant IPs (benign IP back-dated 5–10 min, suspicious foreign IP now). Reworked 2026-07-24 to session-only messages — the prior `109006`→`109005` fail→success is invisible to XSIAM. Returns list of 4. | `%ASA-6-113039` parent session started + `%ASA-6-722051` address assigned, per login; `IP=benign_ip` then `IP=suspicious_ip`, 5–10 min apart | 2 |
| `dns_c2_beacon` | C2 / DNS Tunneling | Single short UDP/53 session to a random external IP (C2 beacon disguised as DNS). Returns list of 2 (Built+Teardown). | `%ASA-6-302015/302016`, `dpt=53`, `proto=UDP`, `bytes_sent=100–250`, `bytes_recv=150–500`, `duration=0–2s` | 2 |
| `server_outbound_http` | Command and Control | Internal server initiating outbound TCP/80 HTTP session (anomalous). Returns list of 2. | `%ASA-6-302013/302014`, `src=internal_server`, `dpt=80`, `bytes_sent=300–1000`, `duration=1–10s` | 1 |
| `workstation_lateral_rdp` | Lateral Movement | Workstation-to-workstation RDP on TCP/3389. Returns list of 2 (Built+Teardown). | `%ASA-6-302013/302014`, `dpt=3389`, `src_interface=inside`, `dest_interface=inside`, `bytes=50000 each direction`, `duration=2–30min` | 1 |
| `vpn_tor_login` | Credential Theft | Successful AnyConnect VPN session start from a Tor exit node IP. Single `113039` message — the success from a Tor IP is the detection signal. Returns list of 1. | `%ASA-6-113039: Group <group> User <user> IP <tor_exit_ip> AnyConnect parent session started.` — bare username (a domain prefix collapses every user into `examplecorp` and kills the detector); Tor IP comes from the live exit-node list fetched at startup | 3 |
| `smb_new_host_lateral` | Lateral Movement | TCP/445 Built+Teardown pairs to 5–10 different internal destination IPs. Distinct SMB destinations from one source is the XSIAM UEBA signal. Returns list. | `%ASA-6-302013/302014`, `dpt=445`, `src_interface=inside`, `dest_interface=inside`, 5–10 distinct `dst` addresses, `duration=1–30s` | 4 |
| `smb_rare_file_transfer` | Data Staging | Single large SMB/445 session (100 MB – 1 GB sent, 2–15 min duration) to an internal server. Returns list of 2. | `%ASA-6-302013/302014`, `dpt=445`, `src_interface=inside`, `dest_interface=inside`, `bytes_sent=100MB–1GB`, `duration=2–15min` | 3 |
| `smb_share_enumeration` | Reconnaissance | 15–40 short TCP/445 Built+Teardown pairs to distinct internal IPs, each with 0–2 bytes and `TCP Reset` teardown. Returns list. | `%ASA-6-302013/302014`, `dpt=445`, `src_interface=inside`, `dest_interface=inside`, 15–40 distinct `dst`, `bytes=40–200`, `teardown_reason=TCP Reset`, `duration=0s` | 5 |
| `failed_connections_burst` | Reconnaissance | 50–150 permitted-but-unanswered connections from one external source to many internal host/port pairs — XSIAM **"Failed Connections"**. Because XSIAM does not parse ACL denies (`106023`), a *parseable* failed connection is one the ASA permits then tears down with `SYN Timeout` and 0 bytes. `attacker_ip` pins the source so a scenario can key every perimeter stage to one attacker. Returns list. | `%ASA-6-302013/302014`, `teardown_reason=SYN Timeout`, `bytes=0`, many distinct `dst`/`dpt` from ports {22,23,25,80,135,139,443,445,1433,1521,3306,3389,4444,5900,6379,8080,8443} | 10 |
| `reverse_ssh_tunnel` | C2 / Tunneling | Internal host → **external** IP on TCP/22, 2–4 long-lived sessions to the **same** external host (stable destination is the recurring-rare-destination signal). High bidirectional volume. Returns list. | `%ASA-6-302013/302014`, `dpt=22`, `dest_interface=outside`, stable `dst`, `bytes=5–80 MB each direction`, `duration=30min–4h` | 2 |
| `ldap_recon` | Reconnaissance | One host querying **many** domain controllers on LDAP `389`/`636`, 3–6 sessions per DC — breadth plus bulk result volume is the signal. Internal-to-internal. DC list from `domain_controllers` config key. Returns list. | `%ASA-6-302013/302014`, `dpt=389/636`, `src_interface=inside`, `dest_interface=inside`, small requests (2–40 KB) / large responses (20–400 KB), `duration=0–5s` | 3 |
| `smtp_spray` | Spam Bot / Malware | Compromised workstation acting as a spam bot — 30–50 direct SMTP sessions to **distinct external** IPs on `25`/`587`. Workstations never talk directly to external MX in normal operation, so one host fanning out over SMTP is the indicator. Returns list. | `%ASA-6-302013/302014`, `dpt=25` (70%) / `587` (30%), 30–50 distinct `dst`, `bytes_sent=2–50 KB`, `duration=1–30s` | 3 |
| `smtp_large_exfil` | Data Exfiltration | Exfiltration via oversized email attachment — a single long SMTP session carrying 100–500 MB outbound to a real MX range (normal attachments rarely exceed 25 MB). DNS precursor added by the dispatch block. Returns list. | `%ASA-6-302013/302014`, `dpt=587` (80%) / `25` (20%), `bytes_sent=100–500 MB`, `duration=5–20min` | 2 |
| `torrent_client` | Policy Violation | Internal host → BitTorrent tracker IPs/ports — XSIAM **"A Torrent client was detected on a host"**. Emits 8–15 sessions mixing **UDP** (DHT / UDP tracker / uTP, ~40%) and **TCP** (peer + tracker announce, ~60%); a TCP-only flow is the wrong fingerprint. Returns list. | `%ASA-6-302013/302014` (TCP) and `%ASA-6-302015/302016` (UDP), `dst∈_TORRENT_TRACKER_IPS`, `dpt∈_TORRENT_PORTS` | 3 |
| `new_ftp_server` | Suspicious Service | Internal host begins **serving** inbound FTP — XSIAM **"New FTP Server"**. 3–6 distinct external clients connect inbound to TCP/21, which establishes the "serving" behaviour rather than a one-off hit. Returns list. | `%ASA-6-302013/302014`, `dpt=21`, `direction=inbound`, `src_interface=outside`, `dest_interface=inside`, 3–6 distinct external `src`, `bytes_recv=50 KB–5 MB` | 2 |
| `dc_smb_outbound` | Credential Theft | SMB/445 **from a domain controller to a workstation** — XSIAM **"Suspicious SMB connection from domain controller"**. Normal direction is workstation→DC, so the reverse is anomalous and associated with credential-theft tooling. Needs `dc_servers` in `cisco_asa_config` (falls back to the first `internal_servers` entry; returns `None` if neither exists). Returns list. | `%ASA-6-302013/302014`, `dpt=445`, `src=dc_ip`, `src_interface=inside`, `dest_interface=inside` | 3 |

### Non-Analytic events (no built-in XSIAM detection)

These are genuine, XSIAM-parseable connection/session patterns (they emit only supported message IDs) but have **no native XSIAM 3rd-party-firewall analytic**, so they are surfaced with a **`[Non-Analytic] `** prefix in the dashboard (via `_NON_ANALYTIC_EVENTS`) and are intended for XQL hunting / custom correlation rules rather than out-of-the-box detections. Added 2026-07-24.

| Threat Key | Purpose | Syslog IDs / Key Fields | Weight |
|---|---|---|---|
| `web_c2_beacon` | HTTP(S) C2 beacon — 15–40 small TCP/443 connections to a **stable** rare external IP (web counterpart to `dns_c2_beacon`). | `%ASA-6-302013/302014`, `dpt=443`, stable `dst`, `bytes` 200–1500, `duration=0–3s` | 2 |
| `cryptomining` | Long-lived, steady connections to a **stable** external IP on a mining-pool port. | `%ASA-6-302013/302014`, `dpt∈{3333,4444,5555,7777,8888,9999,14444,45700}`, `duration=30min–4h` | 2 |
| `rare_port_connection` | Outbound connection to an unusual service port the host never normally uses. | `%ASA-6-302013/302014`, `dpt∈{1080,1337,2222,5222,6667,8443,9001,9050}` | 2 |
| `vpn_data_exfil` | AnyConnect session with anomalously high upload — `Bytes rcv` = 5–50 GB. | `%ASA-6-113039` start + `%ASA-4-113019` disconnect with high `Bytes rcv` | 2 |
| `vpn_concurrent_sessions` | Same user, two AnyConnect sessions from **different** public IPs in the same window (account sharing / co-use — distinct from impossible travel). | `%ASA-6-113039` + `%ASA-6-722051` ×2, same user, two IPs, overlapping | 2 |
| `external_fanout` | One internal host → 60–150 **distinct external IPs** rapidly (mass scan / worm — distinct from `port_scan`'s many-ports-one-dest). | `%ASA-6-302013/302014`, many distinct `dst`, `dpt∈{80,443,445}` | 2 |
