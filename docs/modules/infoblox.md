# Infoblox NIOS

**Dataset:** `infoblox_infoblox_raw` (all NIOS events — DNS, DHCP, audit, RPZ, Threat Protect)
**Transport:** Syslog (TCP)
**Format:** Native Infoblox NIOS syslog (DNS/DHCP queries and responses) + CEF (RPZ, Threat Protect)

> **Correction (2026-09-18).** This page and every builder docstring previously claimed
> events route to `infoblox_dns_raw` / `infoblox_dhcp_raw` / `infoblox_audit_raw` /
> `infoblox_threat_raw`. **None of those datasets exist.** Verified in-tenant: everything
> lands in **`infoblox_infoblox_raw`**, the `<vendor>_<product>_raw` dataset for
> vendor=`infoblox`/product=`infoblox` (409,869 rows over 7 days). The built-in parser
> *does* model it — measured coverage over 441k rows: `xdm.network.dns.dns_question.name`
> 265,064 · `xdm.source.ipv4` 301,601 · `xdm.target.ipv4` 84,263 ·
> `xdm.network.dns.response_code` 132,121 — with `xdm.event.type` resolving to
> DNS Query / DNS Response / DHCP / AUDIT / Threat. `xdm.observer.name` and
> `xdm.source.host.hostname` are **not** mapped (0 rows).

Simulates Infoblox NIOS DNS, DHCP, audit, RPZ and Threat Protect syslog events into the
single XSIAM `infoblox_infoblox_raw` dataset. DNS and DHCP events use the native Infoblox
`named`/`dhcpd` syslog format; RPZ and Threat Protect use CEF. The XSIAM built-in Infoblox
parser distinguishes them by the syslog **process** field.

- **DNS syslog format:** `<30>timestamp server named[pid]: client @0x7f… src_ip#port (domain): query: domain IN A +ED (dns_ip)` and the matching response line
- **DHCP syslog format:** `<30>timestamp server dhcpd[pid]: DHCPDISCOVER/OFFER/REQUEST/ACK … via relay TransID txid uid 01:mac`
- **Audit:** `<29>timestamp server httpd: ISO-TS [user]: Login_Allowed - - …` and `Created(POST)`/`Modified(PUT)`/`Deleted(DELETE)` WAPI object changes
- **RPZ CEF:** `<30>timestamp server named[pid]: CEF:0|Infoblox|NIOS|…|RPZ-QNAME|NXDOMAIN|7|… CAT=RPZ`
- **Threat Protect CEF:** `<27>timestamp server threat-protect-log[pid]: CEF:0|Infoblox|NIOS Threat|…`

---

## Cross-matching: DNS answers are the connection targets

Infoblox is only useful alongside the network modules if a DNS answer and the session
that follows it carry **the same address**. Until 2026-09-18 they did not, and the join
was empty. Measured in-tenant over 7 days:

| | |
|---|---|
| Infoblox `zoom.us` → | `45.25.97.136`, `213.199.25.93`, `142.254.180.140` … |
| FortiGate `zoom.us` → | `13.107.4.50` |
| **intersection** | **EMPTY** |

Three root causes, all fixed:

1. **Answers were invented per query.** `_random_external_ip()` here was the
   `random.choice(first_octets)` + 3-random-octets construction that `session_utils`
   carries a DO-NOT-FIX-THIS-BACK warning against — this module was never migrated when
   the others were. `ups.com` returned **3,009 distinct answers across 3,009 queries**;
   internal names got random public addresses.
2. **The namespace did not match the estate.** Internal DNS used `corp.local` while
   Windows, the ASA IDFW users and `xsiam_client.LOGSIM_DOMAIN` all use
   **`examplecorp.local`**, so internal lookups could never correlate with AD or endpoint data.
3. **DHCP had no host identity.** The MAC was regenerated per event — host `DS-WS-025`
   carried **90 distinct MACs across 90 DHCPACKs**, so no lease could be tied to a host.

### How it works now

[`modules/resolver.py`](../../modules/resolver.py) owns one name→address table that this
module answers from *and* the firewall modules take their destination from, so the answer
**is** the connection target by construction. Three zones:

| zone | source | looked up live? |
|---|---|---|
| **Internal** — `examplecorp.local`, DCs, member servers | synthetic, pinned to real `internal_servers` | never (RFC1918, does not exist publicly) |
| **Curated** — the ~28 real SaaS domains in `benign_egress_destinations` | resolved **once at startup**, pinned for the run, cached to `domain_cache/resolver.json` with a TTL | yes |
| **Synthetic/threat** — rare pool, DGA/C2, dynamic DNS, Tor, novel-country | authored | **never** — resolving them would be meaningless, would leak simulator activity to public resolvers, and would break the pools' disjointness |

Resolution is *not* per-event: real DNS is far more volatile than the detectors tolerate
(`salesforce.com` returns eight rotating Akamai addresses), and CDN anycast spans dozens of
countries — which is what silenced the org-scoped VPN new-country detector at a
210-country footprint. So the table is built once and **pinned**.

Degradation is soft. With no network the curated zone falls back to a deterministic host
inside each domain's configured CIDR, so **the join still holds** — the addresses simply
stop being real. `/api/health` reports which mode is in effect.

Guarded by [`_local_validation/resolver_check.py`](../../_local_validation/resolver_check.py), which asserts the
join across both feeds, answer stability, zone rules, offline determinism, reload safety
and one-MAC-per-host.

### All five network modules now agree with Infoblox (2026-09-22)

Phase 1 wired only FortiGate to the resolver. ASA, Firepower, Check Point and Zscaler
still picked a random host in each destination's CIDR, and **every** module sent benign
client DNS straight to `8.8.8.8`/`1.1.1.1`/`9.9.9.9`. In an Infoblox estate that is a
resolver bypass, and it meant no firewall DNS flow ever lined up with an Infoblox query.

| What | Now | Shared helper (`modules/resolver.py`) |
|---|---|---|
| Client DNS | goes to **that client's** grid member, the one Infoblox logs the query on | `dns_server_for(config, client)` |
| DNS reaching the Internet | only the grid's own recursion, member → forwarder (`infoblox_config.forwarders`, default 8.8.8.8/8.8.4.4); Zscaler logs this as location traffic with no Client Connector device fields | `grid_members`, `dns_forwarders` |
| Benign destinations | the address the name resolves to | `benign_target(config, dest)` |
| Long-tail names | a stable address from the ambient pool, keyed by name (was TEST-NET-2 in Infoblox, and random per event on the firewalls) | `answer_for(domain)` |
| Vendor/update hosts and the VPN gateway | pinned inside their real range, so Infoblox answers them identically | `pin(domain, cidr)` |
| Internal names | Check Point's `srv-N.examplecorp.com` / `dc01.examplecorp.com` now use the grid's `examplecorp.local` names, and its LDAP flows go to a real DC (the name and address used to disagree) | `internal_fqdn(config, ip)` |
| MACs | FortiGate `FTNTFGTsrcmac` was random per event; it is now the NIC Infoblox DHCP leased to that host | `session_utils.host_mac` |

Threat traffic is deliberately exempt from the DNS rule. Malware talking to a public
resolver directly is a real signal, and it only stands out because benign clients no
longer do it. Also fixed in passing: Zscaler web events claimed two hosts in one event
(`https://www.teams.microsoft.com/` against `ehost=teams.microsoft.com`), and the resolver's
reverse table named domain controllers after the zone apex (`examplecorp.local`) instead
of `dc01`.

Guarded by [`_local_validation/network_alignment_check.py`](../../_local_validation/network_alignment_check.py)
(32 checks): each client asks its own grid member; recursion goes to the forwarders; the
name and address of every benign connection agree with the grid (ASA 1,647 flows,
Firepower 1,139/1,139, Check Point 1,550/1,550, FortiGate 2,038/2,038, plus Zscaler); no
internal host is named on the public zone; and FortiGate MACs equal the Infoblox DHCP
lease for 349 shared hosts.

---

## Standalone Threat Events

* **C2 Beaconing:** A compromised internal workstation queries Infoblox DNS for a known-malicious domain. The domain is on the RPZ blocklist, so the response returns `NXDOMAIN`. Generates a `named` query log + `named` response log pair (→ `infoblox_infoblox_raw`). *Hunt signals:* `xdm.target.hostname` = known-bad domain; `xdm.network.dns.dns_response_code` = `NXDOMAIN`; repeated queries to same blocked domain from one `xdm.source.ip` within a short window.

* **DNS Tunneling (Data Exfiltration):** Malware encodes stolen data into DNS TXT query subdomain labels (16–48 character alphanumeric strings, e.g., `a7b2kcqxpwrldmfz.exfiltrationtunnel.com`). The DNS server returns `SERVFAIL`. Generates query + response pair (→ `infoblox_infoblox_raw`). *Hunt signals:* `xdm.network.dns.dns_query_type` = `TXT`; `len(xdm.target.hostname)` > 50; `xdm.network.dns.dns_response_code` = `SERVFAIL`; high volume of unique subdomains under same parent domain from one source IP. Normal enterprise TXT rate is ~2% of DNS traffic — TXT storms are highly anomalous.

* **RPZ Block (Response Policy Zone):** Infoblox NIOS enforces a DNS firewall policy via RPZ. When a client queries a domain covered by RPZ, `named` emits a CEF event showing the trigger and mitigation (`QNAME`/`IP`/`CLIENT-IP`/`NSDNAME` × `NXDOMAIN`/`NODATA`/`Local-Data`). Generates a query log + RPZ CEF event pair from `named[pid]`, sharing one source port and appliance (→ `infoblox_infoblox_raw`). **PASSTHRU is deliberately excluded** — it is an explicit *allow*, and counting it as a block previously made a third of every "block storm" permitted traffic. *Hunt signals:* CEF `msg` contains `"rpz QNAME NXDOMAIN rewrite"`; the `via` value names the RPZ record that matched; correlate `xdm.source.ip` with firewall/Zscaler for connection attempt confirmation.

* **Threat Protect Block (BloxOne):** The Infoblox BloxOne Threat Defense service identifies a query as matching a threat intelligence category (Malware, Phishing, C&C, Exploit Kit, Potential DDoS) and emits a CEF DROP event from `threat-protect-log`. Single event — block happens before response is sent (→ `infoblox_infoblox_raw`). *Hunt signals:* `xdm.alert.category` ∈ {Malware, Phishing, C&C, Exploit Kit}; `xdm.observer.action` = DROP; `xdm.target.hostname` = blocked FQDN; correlate `xdm.source.ip` with DHCP logs to identify the device.

* **NXDOMAIN Storm (DGA — Domain Generation Algorithm):** Malware implementing a DGA cycles through dozens of randomly-generated candidate C2 domain names in rapid succession, all returning `NXDOMAIN` (attacker has not yet activated the current day's domain). Generates 40–100 query+NXDOMAIN pairs (→ `infoblox_infoblox_raw`). *Hunt signals:* High ratio of NXDOMAIN from a single `xdm.source.ip`; `xdm.target.hostname` values share a common TLD but have high-entropy labels (8–15 random alphanumeric chars); time delta between first and last query < 30 seconds. Normal enterprise NXDOMAIN rate is 2–6%; this pattern produces 50–90% within the burst window.

* **DNS Flood (Volumetric / Reconnaissance):** An attacker or compromised host generates 20–50 DNS queries within seconds across diverse domains and record types (A, AAAA, MX, NS, TXT, SOA). Simulates either a volumetric DoS against the DNS server or an automated reconnaissance sweep (→ `infoblox_infoblox_raw`). *Hunt signals:* `xdm.source.ip` generates > 20 DNS events within a 10-second window; query mix includes `NS`, `SOA`, and `TXT` types (unusual for legitimate workstations); queries span both benign domains and DGA-like names — the mix is the anomaly.

* **DHCP Starvation:** An attacker sends 20–50 DHCPDISCOVER messages using spoofed fully-random MAC addresses in rapid succession, exhausting the DHCP address pool (→ `infoblox_infoblox_raw`). *Hunt signals:* High volume of `DHCPDISCOVER` events within a short window with all-different `xdm.source.host.mac_address` values; no corresponding `DHCPACK` follows the DISCOVERs; source MAC addresses have no organisational OUI prefix pattern (fully random octets). Reference threshold: Infoblox default detection ~1.2 DISCOVER/sec/MAC.

* **Zone Transfer Attempt (AXFR/IXFR):** An unauthorized internal host sends an `AXFR` or `IXFR` query for an internal zone (e.g., `corp.local`). The authoritative Infoblox server returns `REFUSED`. Generates query + response pair (→ `infoblox_infoblox_raw`). *Hunt signals:* `xdm.network.dns.dns_query_type` = `AXFR` or `IXFR` from a non-DNS-server IP; `xdm.network.dns.dns_response_code` = `REFUSED`; single event from a workstation is highly anomalous — zone transfers are only expected from secondary DNS servers on a known IP list.

* **Fast-Flux DNS:** A C2 domain returns a different IP address on every query with `TTL=0`, preventing caching and making blacklisting by IP ineffective. Generates 3–6 query+NOERROR pairs (→ `infoblox_infoblox_raw`). *Hunt signals:* Same `xdm.target.hostname` resolves to different `xdm.target.ip` values within seconds; `TTL=0` in response records; resolved IPs span unrelated `/8` ranges (no CDN IP-block pattern). Distinct from fast-flux CDN: CDNs use short TTLs (30–60s) and IP blocks are owned by the same ASN.

* **DNS Rebinding:** An attacker's domain initially resolves to a valid external IP (bypassing allow-list checks) then rapidly rebinds to an internal RFC-1918 address, letting browser JavaScript attack internal services. Generates query + NOERROR response with internal IP and `TTL=1` (→ `infoblox_infoblox_raw`). *Hunt signals:* `xdm.target.ip` = RFC-1918 address for an externally-named domain (`xdm.target.hostname` does not match internal domain list); `TTL=1` in response RR; source is a workstation (browser attack vector).

* **PTR Reverse-Lookup Sweep:** An attacker maps the internal network by querying sequential `in-addr.arpa` PTR records (e.g., `1.168.192.in-addr.arpa`, `2.168.192.in-addr.arpa`, …). Generates 20–40 sequential PTR query+response pairs; ~75% return NXDOMAIN since most hosts lack PTR records (→ `infoblox_infoblox_raw`). *Hunt signals:* Same `xdm.source.ip` generates > 15 PTR queries within seconds; `xdm.target.hostname` values are sequential in arpa format; high NXDOMAIN ratio. Distinct from routine PTR lookups (monitoring, mail server rDNS) which are non-sequential and low-frequency.

---

## Infoblox NIOS — Syslog Receiver Setup (Broker VM)

The Infoblox NIOS module sends raw RFC 3164 syslog over TCP to the XSIAM Broker VM. The XSIAM Infoblox content pack parser routes logs **by process name automatically** — no manual routing rules needed.

**XSIAM Configuration:**
1. Settings → Data Sources → Add Data Source → Syslog
2. Port: `1516` (TCP) — set by `infoblox_config.syslog_port` in `config.json`
3. Vendor: `infoblox` / Product: `infoblox`

| Syslog Process | XSIAM Dataset | Content |
|---|---|---|
| `named[` | `infoblox_infoblox_raw` | DNS query/response + RPZ CEF events |
| `dhcpd[` | `infoblox_infoblox_raw` | DHCP lease events (DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE) |
| `httpd:` | `infoblox_infoblox_raw` | Admin GUI login/logout/config changes |
| `threat-protect-log[` | `infoblox_infoblox_raw` | BloxOne Threat Intelligence CEF DROP events |
| `rpz:` | `infoblox_infoblox_raw` | RPZ Response Policy Zone CEF block events |

`.env` entry: `SYSLOG_HOST=<broker_vm_ip>` (shared with other syslog modules — no separate entry needed if already set).

---

## Infoblox NIOS — Complete Event Reference

### Log Format Reference

Infoblox NIOS produces four distinct syslog formats. Each is identified by its **process name**, which the XSIAM Infoblox content pack uses to route automatically to the correct dataset — no manual rules needed.

| Process | Syslog PRI | Format Pattern |
|---|---|---|
| `named[pid]` — query | `<30>` | `<30>MMM DD HH:MM:SS hostname named[pid]: client @0x7fXXXXXXXXXX src_ip#port (domain): query: domain IN qtype +ED (dns_server_ip)` |
| `named[pid]` — response | `<30>` | `<30>MMM DD HH:MM:SS hostname named[pid]: client src_ip#port UDP: query: domain IN qtype response: RCODE -A domain. TTL IN qtype answer` |
| `named[pid]` — RPZ CEF | `<30>` | `<30>MMM DD HH:MM:SS hostname named[pid]: CEF:0\|Infoblox\|NIOS\|ver\|RPZ-QNAME\|NXDOMAIN\|7\|app=DNS dst=dns_ip src=ip spt=port view=view qtype=A msg="rpz QNAME NXDOMAIN rewrite domain [A] via domain.zone" CAT=RPZ` |
| `dhcpd[pid]` | `<30>` | `<30>MMM DD HH:MM:SS hostname dhcpd[pid]: DHCPACK on ip to mac (hostname) via relay TransID txid lease-duration N uid 01:mac` |
| `httpd:` — login | `<29>` | `<29>MMM DD HH:MM:SS hostname httpd: YYYY-MM-DD HH:MM:SS.mmmZ [user]: Login_Allowed - - to=Connector ip=ip auth=type group=group apparently_via=GUI` |
| `httpd:` — object change | `<29>` | `<29>… [user]: Modified(PUT) v2.9/record:a {"comment":"…"} 1.930 ARecord name DnsView=view: Changed comment:NULL->"…"` |
| `threat-protect-log[pid]` | `<26>`/`<27>`/`<28>` | `<27>MMM DD HH:MM:SS hostname threat-protect-log[pid]: CEF:0\|Infoblox\|NIOS Threat\|ver\|sid\|Rule phrase: fqdn\|sev\|src=ip spt=port dst=dns_ip dpt=53 act="DROP" cat="cat" nat=0 nfpt=0 nlpt=0 fqdn=domain hit_count=N` |

**PRI values:** `<30>` = daemon(3)×8 + info(6). `<29>` = daemon(3)×8 + notice(5).
The CEF events derive theirs from the rule severity: `<26>` crit (sev 8), `<27>` err
(sev 7), `<28>` warning (sev 6), `<30>` info (sev 4).

#### CEF conformance rewrite (2026-09-18)

Infoblox publishes its CEF samples as the appliance renders them to its **local log
file** — ISO timestamp, the facility as a word, no PRI:

```
2020-12-21T22:47:37-08:00 daemon ibflex2.com threat-protect-log[12674]: err CEF:0|Infoblox|NIOS Threat|...
```

This module emitted that rendering verbatim. Measured in-tenant over 7 days:

| | rows | carried `xdm.source.ipv4` |
|---|---|---|
| with a `<PRI>` header | 443,955 | 303,940 |
| **without one** | **998** | **0** |

All 998 were the RPZ and threat-protect CEF events. XSIAM set
`xdm.event.type = "Threat"` off a raw substring match and dropped everything after
it — `src`, `dst`, `act`, `cat`, `fqdn` and `hit_count` all landed nowhere, so the
entire Infoblox threat feed was unqueryable by any XDM field.

We now emit the **on-the-wire** form (RFC 3164 PRI + timestamp + host +
`process[pid]`), which is what NIOS forwards to an external syslog server and what
the Elastic and Splunk NIOS parsers are written against. The facility and severity
the doc spells out in words are exactly what a PRI encodes, so nothing is lost.

Also corrected in the same pass:

| Field | Was | Now |
|---|---|---|
| RPZ process | `daemon info rpz:` (the NIOS 6.12 rendering, no host/pid/PRI) | `named[pid]:`, as NIOS 8.3+ logs it |
| RPZ `via` | the bare policy zone (`via bloxone-rpz-malware`) | the RPZ **record** that matched (`via domain.zone`, `via 32.<rev-ip>.rpz-ip.zone`) |
| RPZ trailer | *(missing)* | `CAT=RPZ` |
| RPZ actions | `NXDOMAIN`, `PASSTHRU`, `IP/NXDOMAIN` — a third of a "block storm" was **PASSTHRU**, an explicit *allow* (199 of 587 events in tenant) | `NXDOMAIN` / `NODATA` / `Local-Data`, over QNAME / IP / CLIENT-IP / NSDNAME triggers |
| Threat SID | `random.randint(1e8, 1e9)` per event — **411 events, 411 distinct SIDs** | one stable SID per rule category (the DDoS rule uses Infoblox's real `120601943`) |
| Threat severity | hardcoded `7` on every event | per-category `8`/`7`/`6`, per the documented 8=Critical / 7=Major / 6=Warning / 4=Informational scale |
| Threat CEF Name | `cat: fqdn` (the category jammed into the name) | the rule phrase, as documented (`Potential DDoS related domain: phackt.com`) |
| `hit_count` | pinned at `1` | climbs across the aggregation window |
| Query ↔ verdict | re-rolled independently: one blocked query logged `(10.2.1.2)` while its RPZ CEF said `dst=10.1.1.2`, with a different `spt` | one appliance, one pid, one source port per transaction |

> **In-tenant result (2026-09-21): the PRI change did NOT make the CEF events model.**
> 44 threat-protect and 59 RPZ events in the new format arrived and still carried zero
> network fields. The content pack's Threat section
> (`Packs/Infoblox/ModelingRules/Infoblox_1_3`) does not regex `_raw_log` — it reads
> **pre-parsed CEF columns** (`cefName`, `cefDeviceEventClassId`, `src`, `spt`, `dst`,
> `dpt`, `act`, `cat`, `msg`, `fqdn`) and its filter is `_raw_log = null or _raw_log ~= "CEF:0"`.
> Those columns exist only when the **Broker VM syslog collector parses CEF on ingest**.
> In this tenant `infoblox_infoblox_raw` has **0** CEF-parsed rows ever: the Infoblox
> syslog source is configured so the whole feed lands as raw text. This is a
> **tenant-side ingestion setting** (Broker VM → Syslog Collector → the Infoblox source's
> *Format*: Auto-Detect / CEF / RAW), not a generator defect. The PRI header is kept
> because it is the correct on-the-wire form.

#### Content-pack routing (checked 2026-09-21)

Each raw line becomes one XDM row per modeling-rule section it matches, so
`_local_validation/infoblox_format_check.py` now replays every generated line through the pack's
section filters:

- **`DHCPRange` audit objects were modeled as DHCP.** The DHCP section claims any line
  matching `DHCP\w+`, so those audit rows lost their admin username. NIOS calls the object
  `Range`, and the generator now does too.
- **`DHCPREQUEST`** now names the accepted server (`for 10.0.0.5 (10.1.1.2) from …`) on a
  SELECTING request, which maps to `xdm.network.dhcp.siaddr` / `xdm.target.ipv4`. A
  renewal is tagged `: RENEW`, which maps to `xdm.event.operation_sub_type`.
- **Known pack defect, not fixed here:** the audit section accepts `httpd:` with or
  without a pid, but the fallback section only excludes `httpd[pid]`. Every pid-less audit
  line, which is the documented NIOS form, is therefore modeled twice, and the second
  copy has a null `xdm.event.type`. That's the source of the exact 50% split.
- **By design in the pack:** WAPI object changes (`Modified(PUT) …`) model only the
  admin username. The pack's audit regexes look for `ip=` and `… - -`, which appear only
  in login-style lines. The documented object-change format has neither.

#### Realism pass (2026-09-21)

| Area | Was | Now |
|---|---|---|
| Process IDs | a new random pid on every line | one pid per appliance per daemon for the run (`xdm.source.process.pid`) |
| Appliance | hostname and addressed server picked independently per line; a DHCP exchange hopped between members | each client is pinned to one grid member (`hostnames[i]` ↔ `dns_server_ips[i]`), keyed by IP for DNS and by MAC for DHCP |
| Response flags | `-A` for UDP, `+A` for TCP: "recursion unavailable" and authoritative on every answer | `+` (recursion available); `A` only for the AD zone and the internal reverse zones; `E`/`D` mirror the query (NIOS flag definitions) |
| RR terminator | none | `;` after every record, as in the documented sample |
| AAAA | every domain answered `2001:4860:4860::8888` (Google's resolver) | a stable per-domain address in `2001:db8::/32`; internal names answer NODATA |
| CNAME / TXT | random CDN alias per query; one SPF for every domain | stable per domain |
| PTR | invented `host-a-b-c-d.internal` | real session hostnames on `examplecorp.local`, else authoritative NXDOMAIN; the PTR sweep walks the attacker's own /24 |
| Zone transfer | query flags `+ED` | `-T`, plus BIND's `security: … zone transfer … denied` line |
| MAC | every host `00:50:56` (VMware) | `session_utils.host_mac()`: Apple, Dell/Lenovo, Dell/HP or VMware by device; stable per host |
| Lease | OFFER and ACK drew independently | one lease time per scope |
| Admin source | a random address per event; login and change by different admins | one workstation per admin; audit only from the Grid Master; a WAPI login and its change share one account |
| Threat victims | a random address in a random subnet | a real session host, so threat DNS joins to that user's DHCP, logons and firewall sessions |
| Event mix | DNS 66%, DHCP 16%, audit 18% (≈12,000 admin actions a day) | DNS 96.4%, named ops 0.8%, DHCP 2.8%, audit 0.05% (≈80 a day at 1 event/s) |

#### New events for data-model coverage (2026-09-21)

Every event family the content pack models is now emitted, so every XDM field it maps is
reachable. `coverage()` in `_local_validation/infoblox_format_check.py` probes each one.

| Event | Example | Fields it reaches |
|---|---|---|
| `dns_ipv6` | client `fd00:c0:a8:1e:…#54795` → server `(fd00:a:2:1::2)` | `xdm.source.ipv6`, `xdm.intermediate.ipv6`, `xdm.target.ipv6` |
| `dns_refused` / `dns_lame` | `query failed (REFUSED)`, `lame-servers: connection refused resolving 'x/A/IN'` | `xdm.event.outcome` / `outcome_reason` for DNS, fallback `dns_question.name` |
| `dns_windows_probe` | NCSI, `_ldap._tcp.dc._msdcs`, `time.windows.com`, `wpad` NXDOMAIN | realistic Windows baseline |
| `dns_search_suffix` | `zoom.us.examplecorp.local` NXDOMAIN, then `zoom.us` | the real source of most benign NXDOMAINs |
| `dns_ops` | `general: zone … loaded serial`, `notify:`, `xfer-out: … AXFR started/ended`, `rpz: <zone>: reload start` | `xdm.event.type` "DNS general/notify/xfer-out/rpz", `xdm.target.zone` |
| DDNS (with session / release / expire) | `update: client … 127.0.0.1#…/key dhcp_updater_default: updating zone … adding an RR at 'host.examplecorp.local' A …` | `xdm.event.type` "DNS update"; ties the DHCP hostname to its address inside DNS |
| `dhcp_inform` | `DHCPINFORM from 10.0.20.10 via 10.0.20.1`, `DHCPACK to …` | `xdm.source.ipv4`, `xdm.source.interface` (`via eth1`) |
| `dhcp_decline` | `DHCPDECLINE of … : abandoned`, `Abandoning IP address …` | `ciaddr`, `outcome` FAILED |
| `dhcp_expire` | `DHCPEXPIRE on … to <mac>` + DDNS delete | `ciaddr`, `source.ipv4` |
| `dhcp_leasequery` | `DHCPLEASEQUERY from <relay> for <ip>`, `DHCPLEASEACTIVE to …` | `message_type`, `source.ipv4` |
| DHCP starvation | OFFERs until the pool is gone, then `network x/24: no free leases` | `xdm.target.subnet`, `outcome_reason` |
| Audit | `First_Login`, serial-console login (`to=Serial\040Console apparently_via=Direct`), WAPI login before a change | `intermediate.process.name`, `auth_method` |

| `dns_chaos` | the vulnerability scanner asking `version.bind CH TXT`, answered REFUSED | `xdm.network.dns.dns_question.class` = 3 (the only non-IN class) |
| `dns_ops` (xfer-in) | the secondary's `xfer-in: … Transfer status: success` / `Transfer completed` | fallback `xdm.event.outcome` = SUCCESS, event type "DNS xfer-in" |
| `dns_ops` (dnssec) | `dnssec: validating x/A: no valid signature found` | event type "DNS dnssec" |
| `dhcp_leasequery` replies | `DHCPLEASEUNASSIGNED` / `DHCPLEASEUNKNOWN` alongside ACTIVE | DHCP `message_type` values the pack scores as failed |

The LEASEQUERY and EXPIRE lines follow the shapes the content pack's regexes expect; I
found no published Infoblox sample for either.

**Fields no generator change can reach:**
- `xdm.network.dns.is_truncated`: the pack captures response flags with `[ATEDVL]`, uppercase only, then tests for a lowercase `t`, so it can never be true.
- The Threat-section fields (`xdm.alert.*`, `xdm.intermediate.port`, `xdm.target.domain`): they come only from ingest-parsed CEF columns (see *In-tenant result* above).
- Per-event gaps inside CEF: documented RPZ events carry no `fqdn`, `act` or `dpt`, and documented Threat Protect events carry no `msg`. Adding them would mean inventing fields.

#### Non-CEF fidelity (same pass)

| Area | Was | Now |
|---|---|---|
| Audit object verbs | `Object_Add` / `Object_Modify` / `Object_Delete` — **not NIOS verbs at all** — carrying a *login-shaped* body (`to=`/`auth=`/`group=`) that named no object | `Created(POST)` / `Modified(PUT)` / `Deleted(DELETE)` with the WAPI path, request body, call duration, object type, name and view |
| `Login_Denied` | reported `group=`, implying a successful group lookup on an attempt that never authenticated | reports `error=` with the failure reason, octal-escaped (`\040`) as NIOS escapes audit values |
| `Logout` | carried `auth=`/`group=` | carries neither — a logout re-runs no authentication |
| DHCP `TransID` | only on `DHCPACK` | on `DHCPDISCOVER`/`DHCPREQUEST`/`DHCPACK`, so the exchange can be tied together |
| DHCP `uid` | absent | option-61 client identifier (`01:<mac>`) on all four |
| `DHCPOFFER` | `lease-duration` only | `relay`, `lease-duration`, `offered-duration`, `uid` |
| `DHCPRELEASE` | no hostname, no lease state | `(hostname) via relay (found)` |
| Relay agent | pinned `192.168.1.1` for every client — a host at `10.0.20.74` sat behind a relay it has no route to | the client's own gateway |
| AXFR/IXFR | logged over **UDP** — the one transport a zone transfer can never use | TCP |
| Query ↔ response | every pair rolled its own port, pid and appliance: `#61934` asked, `#60856` answered, on a different server | one transaction (verified 1,968 pairs, 0 mismatches) |
| BIND client pointer | `hex(random.randint(0, 2**48))` — 11–12 digit values no BIND build emits | a 12-digit `0x7f…` heap address, stable per client |

`_local_validation/infoblox_format_check.py` (46 checks) pins every one of these to the published
Infoblox sample it came from.

> **Deliberately not changed yet:** real NIOS also prints a high-precision body timestamp
> (`03-May-2018 16:30:50.385`) after `named[pid]:` and a `view N:` segment before the
> protocol. Both are authentic, but adding them changes the line shape, and the XSIAM
> built-in parser currently extracts this format correctly (265k query names, 132k rcodes,
> 84k answers modelled). Breaking a working parse for cosmetic fidelity is the worse trade,
> so these should be added and then **validated in-tenant** before being kept.

---

### Benign Events (25 Types)

> **Weights changed 2026-09-21.** The per-event weights in the tables below are the
> retired mix. The current defaults are `_DEFAULT_BENIGN_MIX` in `modules/infoblox_dns.py`
> (per 10,000 events, mirrored in `config.json`), and the ten new event types are described
> under *New events for data-model coverage* above.

Generated continuously in Mode 1 as background noise. Weights are tunable in `infoblox_config.event_mix.benign` in `config.json`. Default weights are calibrated to match real enterprise DNS/DHCP traffic ratios (Vercara/UltraDNS 2024 global data).

#### DNS Events

| Event Code | Default Weight | Dataset | What It Generates | Notes |
|---|---|---|---|---|
| `dns_a` | 30 | `infoblox_infoblox_raw` | A query + NOERROR response with a public IP. Domain from `benign_domains`. | Most common query type in enterprise. |
| `dns_internal` | 15 | `infoblox_infoblox_raw` | A or AAAA query for a corp name (`examplecorp.local`, `dc01.examplecorp.local`) → NOERROR with internal RFC-1918 IP. Domain from `infoblox_config.internal_domains`. | Critical for realistic baseline — a large portion of real enterprise DNS is internal name resolution. Without this, all DNS queries target internet names, which is anomalous by itself. |
| `dns_aaaa` | 10 | `infoblox_infoblox_raw` | AAAA (IPv6) query + NOERROR response with `2001:4860:4860::8888`. | Dual-stack endpoints query both A and AAAA. |
| `dns_cname` | 6 | `infoblox_infoblox_raw` | A query resolving via a CDN CNAME chain (e.g., `d1234.cloudfront.net → A 104.x.x.x`). Two RRs in response: CNAME + A. | Common for cloud SaaS. Response includes both the CNAME and final A record. |
| `dns_nxdomain_benign` | 5 | `infoblox_infoblox_raw` | A query for a stale or typo subdomain (e.g., `legacy.company.com`) → NXDOMAIN query+response pair. | **Required for anomaly detection.** Establishes the 2–6% normal NXDOMAIN rate. Without this baseline, any NXDOMAIN triggers false-positive alerts. The NXDOMAIN storm threat scenario only becomes detectable when this baseline exists. |
| `dns_ptr` | 3 | `infoblox_infoblox_raw` | PTR reverse lookup for a random internal IP → NOERROR with `host-IP.internal`. | Generated by monitoring tools, mail servers doing rDNS checks. |
| `dns_mx` | 3 | `infoblox_infoblox_raw` | MX record query + NOERROR response with `mail.<domain> MX 10`. | Generated by mail clients during send/receive. |
| `dns_srv` | 2 | `infoblox_infoblox_raw` | SRV query for a service record (`_ldap._tcp.examplecorp.local`, `_kerberos._tcp`, `_sip._tcp`, etc.) → NOERROR with DC/server hostname and port. | Windows domain-joined machines query SRV records during authentication and service discovery. |
| `dns_txt` | 2 | `infoblox_infoblox_raw` | TXT query + NOERROR response containing an SPF or DKIM record value. | **Baseline for TXT storm detection.** Normal enterprise TXT rate is ~2% of DNS — any storm stands out. |

#### DHCP Events

| Event Code | Default Weight | Dataset | What It Generates | Notes |
|---|---|---|---|---|
| `dhcp_session` | 11 | `infoblox_infoblox_raw` | Full 4-way handshake: DHCPDISCOVER → DHCPOFFER → DHCPREQUEST → DHCPACK. 4 events, all sharing one `TransID` and the host's option-61 `uid`. | Represents a device joining the network for the first time or after a full lease expiry. |
| `dhcp_renewal` | 8 | `infoblox_infoblox_raw` | Lease T1 renewal: DHCPREQUEST → DHCPACK only. 2 events (no DISCOVER/OFFER). | T1 renewals are the most frequent DHCP event in enterprise — workstations renew at 50% of lease time (every 4–12 hours). Previously unrepresented; without this the DHCP starvation threat (DISCOVER flood without ACK) was harder to baseline. |
| `dhcp_release` | 3 | `infoblox_infoblox_raw` | DHCPRELEASE — client gracefully releases its IP before shutdown/logout. | |
| `dhcp_nak` | 2 | `infoblox_infoblox_raw` | DHCPNAK — server rejects a DHCPREQUEST due to IP conflict or scope change. | The requested address is deliberately off-segment relative to the client's relay: a NAK is the server refusing an address the client should not have asked for (typically a laptop replaying the lease from its last office). |

#### Audit Events

| Event Code | Default Weight | Dataset | What It Generates | Notes |
|---|---|---|---|---|
| `audit` | 16 | `infoblox_infoblox_raw` | `httpd:` audit log with `apparently_via=GUI`, `to=AdminConnector`. Event type weighted: `Login_Allowed`(34%), `Logout`(20%), `Modified`(20%), `Created`(14%), `Login_Denied`(6%), `Deleted`(6%). | Simulates human admin activity on the Infoblox NIOS web UI. Object changes use the real NIOS verbs `Created(POST)` / `Modified(PUT)` / `Deleted(DELETE)` and name the WAPI object they touched. |
| `audit_api` | 2 | `infoblox_infoblox_raw` | `httpd:` audit log with `apparently_via=API`, `to=RESTAPIGateway`. Event type: `Modified`(50%), `Created`(30%), `Deleted`(20%). | Simulates WAPI/REST automation (scripts, Ansible, Terraform). Automation changes objects rather than sitting at a login prompt, so this path emits no login events. Distinguishable from GUI access by `to=RESTAPIGateway` and `apparently_via=API`. |

---

### Threat Events (11 Types)

All 11 types are available as named `scenario_event` strings (usable in Mode 2 or via the orchestrator). Weights are tunable in `infoblox_config.event_mix.threat` in `config.json`.

| scenario_event | Weight | Dataset(s) | Events Generated | Key Hunt Signals |
|---|---|---|---|---|
| `C2_BEACON` | 25 | `infoblox_infoblox_raw` | 1 query + 1 NXDOMAIN response | Domain on threat intel list; repeated from same `xdm.source.ip`; `dns_response_code=NXDOMAIN` |
| `DNS_TUNNEL` | 20 | `infoblox_infoblox_raw` | 1 TXT query (16–48 char alphanumeric subdomain) + 1 SERVFAIL response | `q_type=TXT`; domain len > 50; `SERVFAIL`; high unique-subdomain volume from one src IP |
| `RPZ_BLOCK` | 18 | `infoblox_infoblox_raw` | 1 query + 1 RPZ CEF event (`rpz:` process) | CEF `msg` = `rpz QNAME NXDOMAIN rewrite`; correlate src IP in firewall dataset |
| `THREAT_PROTECT` | 15 | `infoblox_infoblox_raw` | 1 `threat-protect-log` CEF DROP event | `act=DROP`; `cat` ∈ {Malware, Phishing, C&C, Exploit Kit}; `fqdn` = blocked domain |
| `NXDOMAIN_STORM` | 12 | `infoblox_infoblox_raw` | 20–50 query+NXDOMAIN pairs (40–100 total events) | High-entropy 8–15 char labels; all same TLD; burst from single src IP within < 30s |
| `DNS_FLOOD` | 6 | `infoblox_infoblox_raw` | 20–50 query-only events | > 20 queries/10s from one src IP; mixed A/AAAA/MX/NS/TXT/SOA types |
| `ZONE_TRANSFER` | 8 | `infoblox_infoblox_raw` | 1 AXFR or IXFR query + 1 REFUSED response | `q_type=AXFR/IXFR` from non-DNS-server IP; `dns_response_code=REFUSED` |
| `FAST_FLUX_DNS` | 7 | `infoblox_infoblox_raw` | 3–6 query+NOERROR pairs, same domain, different IPs | Same `xdm.target.hostname` → different `xdm.target.ip` per query; `TTL=0` in every response RR |
| `DNS_REBINDING` | 5 | `infoblox_infoblox_raw` | 1 query + 1 NOERROR response with internal RFC-1918 IP | Response IP = private range for external-named domain; `TTL=1` |
| `DHCP_STARVATION` | 4 | `infoblox_infoblox_raw` | 20–50 DHCPDISCOVER events from fully-random MACs | All-different MACs with no OUI prefix pattern; no DHCPACK follows; burst volume |
| `PTR_SWEEP` | 4 | `infoblox_infoblox_raw` | 20–40 sequential in-addr.arpa PTR query+response pairs | Sequential arpa labels from one src IP; ~75% NXDOMAIN; burst timing |

## Generated Threat Domains

`infoblox_threats.malicious_domains` and `dga_domains` were 25 fixed entries each, so a
long run beaconed to the same 25 hosts and an NXDOMAIN storm of 230 lookups revisited the
same 25 DGA names about nine times each. Both are now generated — see
[value-cardinality.md](../value-cardinality.md).

Two things a user should know:

- **The curated names stay in circulation.** `infoblox_threats.generated_share` (default
  `0.75`) controls the split. The curated pool is the head you can hunt for by hand; set
  the share to `0` to pin everything back to `config.json`.
- **The family token is a contract.** Nine tokens are matched as literal substrings of
  these domain names, across five correlation rules — `command-control`, `credential-stealer`, `exploit-kit`,
  `malware-distro`, `phishing-login`, `phishing-kit`, `ransomware-payload`. Every generated
  domain of a family reproduces its token verbatim. Renaming one silences live detections
  with no error anywhere.

Two of those tokens did not previously exist anywhere in the project: the pool shipped
`phish-kit-host.ru` where the rules match `phishing-kit`, and `ransomware-payment-page.biz`
where they match `ransomware-payload`. Near misses, two rules each — four detections
that could never fire.

NXDOMAIN behaviour is unchanged and deliberate: a generated threat domain still answers
NXDOMAIN unless a scenario pins an address for it, because the DNS answer and the firewall
session that follows have to name the same host. `threat_domains.is_threat()` is what
recognises a generated domain — anything that needs to ask "is this one of ours" must
use it rather than testing membership of the config pool.
