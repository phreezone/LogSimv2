# Infoblox NIOS

**Dataset:** `infoblox_dns_raw` (DNS/DHCP events) · `infoblox_threat_raw` (BloxOne Threat Protect events)
**Transport:** Syslog (TCP)
**Format:** Native Infoblox NIOS syslog (DNS/DHCP queries and responses) + CEF (Threat Protect blocks)

Simulates Infoblox NIOS DNS and DHCP syslog events and BloxOne Threat Defense blocks for the XSIAM `infoblox_dns_raw` and `infoblox_threat_raw` datasets. DNS and DHCP events use the native Infoblox `named`/`dhcpd` syslog format. BloxOne Threat Protect block events use CEF format with the `threat-protect-log` process identifier. The XSIAM built-in Infoblox parser routes events to the appropriate dataset based on the syslog process field.

- **DNS syslog format:** `<pri>timestamp server named[pid]: client src_ip#port: query: domain type class +ED(dest_ip)` (query) and corresponding response lines
- **DHCP syslog format:** `<pri>timestamp server dhcpd: DHCPDISCOVER/OFFER/REQUEST/ACK from mac_address ...`
- **RPZ events:** `daemon info rpz: client src_ip#port: rpz QNAME NXDOMAIN rewrite domain ...` (ISO timestamp format)
- **Threat Protect CEF:** standard `CEF:0|Infoblox|NIOS|...` header with `threat-protect-log` process

---

## Standalone Threat Events

* **C2 Beaconing:** A compromised internal workstation queries Infoblox DNS for a known-malicious domain. The domain is on the RPZ blocklist, so the response returns `NXDOMAIN`. Generates a `named` query log + `named` response log pair (→ `infoblox_dns_raw`). *Hunt signals:* `xdm.target.hostname` = known-bad domain; `xdm.network.dns.dns_response_code` = `NXDOMAIN`; repeated queries to same blocked domain from one `xdm.source.ip` within a short window.

* **DNS Tunneling (Data Exfiltration):** Malware encodes stolen data into DNS TXT query subdomain labels (16–48 character alphanumeric strings, e.g., `a7b2kcqxpwrldmfz.exfiltrationtunnel.com`). The DNS server returns `SERVFAIL`. Generates query + response pair (→ `infoblox_dns_raw`). *Hunt signals:* `xdm.network.dns.dns_query_type` = `TXT`; `len(xdm.target.hostname)` > 50; `xdm.network.dns.dns_response_code` = `SERVFAIL`; high volume of unique subdomains under same parent domain from one source IP. Normal enterprise TXT rate is ~2% of DNS traffic — TXT storms are highly anomalous.

* **RPZ Block (Response Policy Zone):** Infoblox NIOS enforces a DNS firewall policy via RPZ. When a client queries a domain covered by RPZ, `named` emits a CEF event showing the rewrite action (`QNAME NXDOMAIN`, `IP NXDOMAIN`, or `QNAME PASSTHRU`). Generates a query log + RPZ CEF event pair using ISO timestamp + `daemon info rpz:` syslog format (→ `infoblox_dns_raw`). *Hunt signals:* CEF `msg` field contains `"rpz QNAME NXDOMAIN rewrite"` or `"rpz IP NXDOMAIN"`; correlate `xdm.source.ip` with firewall/Zscaler for connection attempt confirmation.

* **Threat Protect Block (BloxOne):** The Infoblox BloxOne Threat Defense service identifies a query as matching a threat intelligence category (Malware, Phishing, C&C, Exploit Kit, Potential DDoS) and emits a CEF DROP event from `threat-protect-log`. Single event — block happens before response is sent (→ `infoblox_threat_raw`). *Hunt signals:* `xdm.alert.category` ∈ {Malware, Phishing, C&C, Exploit Kit}; `xdm.observer.action` = DROP; `xdm.target.hostname` = blocked FQDN; correlate `xdm.source.ip` with DHCP logs to identify the device.

* **NXDOMAIN Storm (DGA — Domain Generation Algorithm):** Malware implementing a DGA cycles through dozens of randomly-generated candidate C2 domain names in rapid succession, all returning `NXDOMAIN` (attacker has not yet activated the current day's domain). Generates 40–100 query+NXDOMAIN pairs (→ `infoblox_dns_raw`). *Hunt signals:* High ratio of NXDOMAIN from a single `xdm.source.ip`; `xdm.target.hostname` values share a common TLD but have high-entropy labels (8–15 random alphanumeric chars); time delta between first and last query < 30 seconds. Normal enterprise NXDOMAIN rate is 2–6%; this pattern produces 50–90% within the burst window.

* **DNS Flood (Volumetric / Reconnaissance):** An attacker or compromised host generates 20–50 DNS queries within seconds across diverse domains and record types (A, AAAA, MX, NS, TXT, SOA). Simulates either a volumetric DoS against the DNS server or an automated reconnaissance sweep (→ `infoblox_dns_raw`). *Hunt signals:* `xdm.source.ip` generates > 20 DNS events within a 10-second window; query mix includes `NS`, `SOA`, and `TXT` types (unusual for legitimate workstations); queries span both benign domains and DGA-like names — the mix is the anomaly.

* **DHCP Starvation:** An attacker sends 20–50 DHCPDISCOVER messages using spoofed fully-random MAC addresses in rapid succession, exhausting the DHCP address pool (→ `infoblox_dhcp_raw`). *Hunt signals:* High volume of `DHCPDISCOVER` events within a short window with all-different `xdm.source.host.mac_address` values; no corresponding `DHCPACK` follows the DISCOVERs; source MAC addresses have no organisational OUI prefix pattern (fully random octets). Reference threshold: Infoblox default detection ~1.2 DISCOVER/sec/MAC.

* **Zone Transfer Attempt (AXFR/IXFR):** An unauthorized internal host sends an `AXFR` or `IXFR` query for an internal zone (e.g., `corp.local`). The authoritative Infoblox server returns `REFUSED`. Generates query + response pair (→ `infoblox_dns_raw`). *Hunt signals:* `xdm.network.dns.dns_query_type` = `AXFR` or `IXFR` from a non-DNS-server IP; `xdm.network.dns.dns_response_code` = `REFUSED`; single event from a workstation is highly anomalous — zone transfers are only expected from secondary DNS servers on a known IP list.

* **Fast-Flux DNS:** A C2 domain returns a different IP address on every query with `TTL=0`, preventing caching and making blacklisting by IP ineffective. Generates 3–6 query+NOERROR pairs (→ `infoblox_dns_raw`). *Hunt signals:* Same `xdm.target.hostname` resolves to different `xdm.target.ip` values within seconds; `TTL=0` in response records; resolved IPs span unrelated `/8` ranges (no CDN IP-block pattern). Distinct from fast-flux CDN: CDNs use short TTLs (30–60s) and IP blocks are owned by the same ASN.

* **DNS Rebinding:** An attacker's domain initially resolves to a valid external IP (bypassing allow-list checks) then rapidly rebinds to an internal RFC-1918 address, letting browser JavaScript attack internal services. Generates query + NOERROR response with internal IP and `TTL=1` (→ `infoblox_dns_raw`). *Hunt signals:* `xdm.target.ip` = RFC-1918 address for an externally-named domain (`xdm.target.hostname` does not match internal domain list); `TTL=1` in response RR; source is a workstation (browser attack vector).

* **PTR Reverse-Lookup Sweep:** An attacker maps the internal network by querying sequential `in-addr.arpa` PTR records (e.g., `1.168.192.in-addr.arpa`, `2.168.192.in-addr.arpa`, …). Generates 20–40 sequential PTR query+response pairs; ~75% return NXDOMAIN since most hosts lack PTR records (→ `infoblox_dns_raw`). *Hunt signals:* Same `xdm.source.ip` generates > 15 PTR queries within seconds; `xdm.target.hostname` values are sequential in arpa format; high NXDOMAIN ratio. Distinct from routine PTR lookups (monitoring, mail server rDNS) which are non-sequential and low-frequency.

---

## Infoblox NIOS — Syslog Receiver Setup (Broker VM)

The Infoblox NIOS module sends raw RFC 3164 syslog over TCP to the XSIAM Broker VM. The XSIAM Infoblox content pack parser routes logs **by process name automatically** — no manual routing rules needed.

**XSIAM Configuration:**
1. Settings → Data Sources → Add Data Source → Syslog
2. Port: `1516` (TCP) — set by `infoblox_config.syslog_port` in `config.json`
3. Vendor: `infoblox` / Product: `infoblox`

| Syslog Process | XSIAM Dataset | Content |
|---|---|---|
| `named[` | `infoblox_dns_raw` | DNS query/response + RPZ CEF events |
| `dhcpd[` | `infoblox_dhcp_raw` | DHCP lease events (DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE) |
| `httpd:` | `infoblox_audit_raw` | Admin GUI login/logout/config changes |
| `threat-protect-log[` | `infoblox_threat_raw` | BloxOne Threat Intelligence CEF DROP events |
| `rpz:` | `infoblox_dns_raw` | RPZ Response Policy Zone CEF block events |

`.env` entry: `SYSLOG_HOST=<broker_vm_ip>` (shared with other syslog modules — no separate entry needed if already set).

---

## Infoblox NIOS — Complete Event Reference

### Log Format Reference

Infoblox NIOS produces four distinct syslog formats. Each is identified by its **process name**, which the XSIAM Infoblox content pack uses to route automatically to the correct dataset — no manual rules needed.

| Process | Syslog PRI | Format Pattern |
|---|---|---|
| `named[pid]` | `<30>` | `<30>MMM DD HH:MM:SS hostname named[pid]: client @0xMEMADDR src_ip#port (domain): query: domain IN qtype +ED (dns_server_ip)` |
| `named[pid]` — response | `<30>` | `<30>MMM DD HH:MM:SS hostname named[pid]: client src_ip#port: UDP: query: domain IN qtype response: RCODE A rr_records` |
| `dhcpd[pid]` | `<30>` | `<30>MMM DD HH:MM:SS hostname dhcpd[pid]: DHCPACK on ip to mac (hostname) via relay TransID txid` |
| `httpd:` | `<29>` | `<29>MMM DD HH:MM:SS hostname httpd: YYYY-MM-DD HH:MM:SS.mmmZ [user]: EventType - - to=Connector ip=ip auth=type group=group apparently_via=GUI` |
| `threat-protect-log[pid]` | *(none — ISO header)* | `ISO-TS daemon hostname threat-protect-log[pid]: err CEF:0\|Infoblox\|NIOS Threat\|ver\|sigid\|cat: fqdn\|7\|src=ip spt=port dst=dns_ip dpt=53 act="DROP" cat="cat" fqdn=domain hit_count=N` |
| `rpz:` | *(none — ISO header)* | `ISO-TS daemon info rpz: CEF:0\|Infoblox\|NIOS\|ver\|RPZ-QNAME\|NXDOMAIN\|7\|app=DNS dst=dns_ip src=ip spt=port view=_default qtype=A msg="rpz QNAME NXDOMAIN rewrite domain"` |

**PRI values:** `<30>` = daemon(3)×8 + info(6). `<29>` = daemon(3)×8 + notice(5). CEF events (`threat-protect-log`, `rpz`) use ISO 8601 timestamp with `daemon` keyword — no numeric PRI.

---

### Benign Events (15 Types)

Generated continuously in Mode 1 as background noise. Weights are tunable in `infoblox_config.event_mix.benign` in `config.json`. Default weights are calibrated to match real enterprise DNS/DHCP traffic ratios (Vercara/UltraDNS 2024 global data).

#### DNS Events

| Event Code | Default Weight | Dataset | What It Generates | Notes |
|---|---|---|---|---|
| `dns_a` | 30 | `infoblox_dns_raw` | A query + NOERROR response with a public IP. Domain from `benign_domains`. | Most common query type in enterprise. |
| `dns_internal` | 15 | `infoblox_dns_raw` | A or AAAA query for a corp name (`corp.local`, `dc01.corp.local`) → NOERROR with internal RFC-1918 IP. Domain from `infoblox_config.internal_domains`. | Critical for realistic baseline — a large portion of real enterprise DNS is internal name resolution. Without this, all DNS queries target internet names, which is anomalous by itself. |
| `dns_aaaa` | 10 | `infoblox_dns_raw` | AAAA (IPv6) query + NOERROR response with `2001:4860:4860::8888`. | Dual-stack endpoints query both A and AAAA. |
| `dns_cname` | 6 | `infoblox_dns_raw` | A query resolving via a CDN CNAME chain (e.g., `d1234.cloudfront.net → A 104.x.x.x`). Two RRs in response: CNAME + A. | Common for cloud SaaS. Response includes both the CNAME and final A record. |
| `dns_nxdomain_benign` | 5 | `infoblox_dns_raw` | A query for a stale or typo subdomain (e.g., `legacy.company.com`) → NXDOMAIN query+response pair. | **Required for anomaly detection.** Establishes the 2–6% normal NXDOMAIN rate. Without this baseline, any NXDOMAIN triggers false-positive alerts. The NXDOMAIN storm threat scenario only becomes detectable when this baseline exists. |
| `dns_ptr` | 3 | `infoblox_dns_raw` | PTR reverse lookup for a random internal IP → NOERROR with `host-IP.internal`. | Generated by monitoring tools, mail servers doing rDNS checks. |
| `dns_mx` | 3 | `infoblox_dns_raw` | MX record query + NOERROR response with `mail.<domain> MX 10`. | Generated by mail clients during send/receive. |
| `dns_srv` | 2 | `infoblox_dns_raw` | SRV query for a service record (`_ldap._tcp.corp.local`, `_kerberos._tcp`, `_sip._tcp`, etc.) → NOERROR with DC/server hostname and port. | Windows domain-joined machines query SRV records during authentication and service discovery. |
| `dns_txt` | 2 | `infoblox_dns_raw` | TXT query + NOERROR response containing an SPF or DKIM record value. | **Baseline for TXT storm detection.** Normal enterprise TXT rate is ~2% of DNS — any storm stands out. |

#### DHCP Events

| Event Code | Default Weight | Dataset | What It Generates | Notes |
|---|---|---|---|---|
| `dhcp_session` | 11 | `infoblox_dhcp_raw` | Full 4-way handshake: DHCPDISCOVER → DHCPOFFER (with `lease-duration`) → DHCPREQUEST → DHCPACK (with `TransID`). 4 events. | Represents a device joining the network for the first time or after a full lease expiry. |
| `dhcp_renewal` | 8 | `infoblox_dhcp_raw` | Lease T1 renewal: DHCPREQUEST → DHCPACK only. 2 events (no DISCOVER/OFFER). | T1 renewals are the most frequent DHCP event in enterprise — workstations renew at 50% of lease time (every 4–12 hours). Previously unrepresented; without this the DHCP starvation threat (DISCOVER flood without ACK) was harder to baseline. |
| `dhcp_release` | 3 | `infoblox_dhcp_raw` | DHCPRELEASE — client gracefully releases its IP before shutdown/logout. | |
| `dhcp_nak` | 2 | `infoblox_dhcp_raw` | DHCPNAK — server rejects a DHCPREQUEST due to IP conflict or scope change. | |

#### Audit Events

| Event Code | Default Weight | Dataset | What It Generates | Notes |
|---|---|---|---|---|
| `audit` | 16 | `infoblox_audit_raw` | `httpd:` audit log with `apparently_via=GUI`, `to=AdminConnector`. Event type weighted: `Login_Allowed`(30%), `Object_Modify`(20%), `Object_Add`(20%), `Logout`(20%), `Login_Denied`(5%), `Object_Delete`(5%). | Simulates human admin activity on the Infoblox NIOS web UI. |
| `audit_api` | 2 | `infoblox_audit_raw` | `httpd:` audit log with `apparently_via=API`, `to=RESTAPIGateway`. Event type: `Object_Modify`(50%), `Object_Add`(30%), `Object_Delete`(20%). | Simulates WAPI/REST automation (scripts, Ansible, Terraform). Distinguishable from GUI access by the `to=RESTAPIGateway` and `apparently_via=API` fields. |

---

### Threat Events (11 Types)

All 11 types are available as named `scenario_event` strings (usable in Mode 2 or via the orchestrator). Weights are tunable in `infoblox_config.event_mix.threat` in `config.json`.

| scenario_event | Weight | Dataset(s) | Events Generated | Key Hunt Signals |
|---|---|---|---|---|
| `C2_BEACON` | 25 | `infoblox_dns_raw` | 1 query + 1 NXDOMAIN response | Domain on threat intel list; repeated from same `xdm.source.ip`; `dns_response_code=NXDOMAIN` |
| `DNS_TUNNEL` | 20 | `infoblox_dns_raw` | 1 TXT query (16–48 char alphanumeric subdomain) + 1 SERVFAIL response | `q_type=TXT`; domain len > 50; `SERVFAIL`; high unique-subdomain volume from one src IP |
| `RPZ_BLOCK` | 18 | `infoblox_dns_raw` | 1 query + 1 RPZ CEF event (`rpz:` process) | CEF `msg` = `rpz QNAME NXDOMAIN rewrite`; correlate src IP in firewall dataset |
| `THREAT_PROTECT` | 15 | `infoblox_threat_raw` | 1 `threat-protect-log` CEF DROP event | `act=DROP`; `cat` ∈ {Malware, Phishing, C&C, Exploit Kit}; `fqdn` = blocked domain |
| `NXDOMAIN_STORM` | 12 | `infoblox_dns_raw` | 20–50 query+NXDOMAIN pairs (40–100 total events) | High-entropy 8–15 char labels; all same TLD; burst from single src IP within < 30s |
| `DNS_FLOOD` | 6 | `infoblox_dns_raw` | 20–50 query-only events | > 20 queries/10s from one src IP; mixed A/AAAA/MX/NS/TXT/SOA types |
| `ZONE_TRANSFER` | 8 | `infoblox_dns_raw` | 1 AXFR or IXFR query + 1 REFUSED response | `q_type=AXFR/IXFR` from non-DNS-server IP; `dns_response_code=REFUSED` |
| `FAST_FLUX_DNS` | 7 | `infoblox_dns_raw` | 3–6 query+NOERROR pairs, same domain, different IPs | Same `xdm.target.hostname` → different `xdm.target.ip` per query; `TTL=0` in every response RR |
| `DNS_REBINDING` | 5 | `infoblox_dns_raw` | 1 query + 1 NOERROR response with internal RFC-1918 IP | Response IP = private range for external-named domain; `TTL=1` |
| `DHCP_STARVATION` | 4 | `infoblox_dhcp_raw` | 20–50 DHCPDISCOVER events from fully-random MACs | All-different MACs with no OUI prefix pattern; no DHCPACK follows; burst volume |
| `PTR_SWEEP` | 4 | `infoblox_dns_raw` | 20–40 sequential in-addr.arpa PTR query+response pairs | Sequential arpa labels from one src IP; ~75% NXDOMAIN; burst timing |
