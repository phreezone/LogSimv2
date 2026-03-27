# Attack Scenarios

The following scenarios can be run using **Mode 2**. Scenarios 3–6 include optional Infoblox DNS/DHCP correlation steps that activate automatically when the Infoblox NIOS module is loaded.

---

### Scenario 1 — Compromised Account & Data Exfiltration via Google Drive *(CURRENTLY NOT WORKING UNTIL GOOGLE IS RESTORED)*

*Narrative:* An attacker uses stolen credentials to log into Google Workspace from a Tor exit node IP, accesses sensitive files in Google Drive, shares them publicly, then downloads them. The Cisco ASA records the large outbound data transfer.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Okta SSO | `okta_raw` | Successful login from Tor IP | `xdm.source.ip` = Tor exit node |
| 2 | Google Workspace | Built-in login dataset | Login from same Tor IP | `xdm.source.ip` matches Step 1 |
| 3 | Google Workspace | `google_workspace_drive_raw` | Drive view of sensitive file | `xdm.target.resource.name` = sensitive filename |
| 4 | Google Workspace | `google_workspace_drive_raw` | File shared publicly | ACL change; visibility = public |
| 5 | Google Workspace | `google_workspace_drive_raw` | File downloaded | `xdm.event.type` = Download |
| 6 | Cisco ASA | `cisco_asa_raw` | Large outbound TCP session | `xdm.source.sent_bytes` > threshold |

*Hunt:* Find `xdm.source.ip` values appearing in both Okta login events and Google Workspace drive events within the same session window. Correlate with ASA large-egress events from same IP.

---

### Scenario 2 — AWS Cloud Pentest (Privilege Escalation + Defense Evasion)

*Narrative:* An attacker launches a Kali Linux instance in AWS, logs into the console from a Tor exit node as a second compromised user, escalates privileges by attaching the AdministratorAccess policy, then disables CloudTrail and GuardDuty before making an S3 bucket public for data staging.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | AWS CloudTrail | `amazon_aws_raw` | RunInstances (Kali AMI) | AMI contains "kali" |
| 2 | AWS CloudTrail | `amazon_aws_raw` | ConsoleLogin from Tor IP | `xdm.source.ip` = Tor node |
| 3 | AWS CloudTrail | `amazon_aws_raw` | AttachUserPolicy (AdministratorAccess) | `xdm.event.operation` = AttachUserPolicy |
| 4 | AWS CloudTrail | `amazon_aws_raw` | StopLogging (CloudTrail) | Defense evasion |
| 5 | AWS CloudTrail | `amazon_aws_raw` | DisableDetector (GuardDuty) | Defense evasion |
| 6 | AWS CloudTrail | `amazon_aws_raw` | PutBucketAcl (public ACL) | `xdm.target.resource.name` = bucket |

*Hunt:* Sequence query: same `xdm.auth.auth_username` performs AttachPolicy → StopLogging → DisableDetector within 10 minutes.

---

### Scenario 3 — Phishing Kill Chain (Email → Click → DNS → C2 → Credential Theft)

*Narrative:* A phishing email is delivered to a victim and not blocked. The victim clicks the malicious link. The browser resolves the phishing domain via Infoblox DNS *(if loaded)*, Zscaler or Check Point detects and may block the web request, Cisco Firepower/ASA/Checkpoint records the C2 callback, and the attacker authenticates to Okta with stolen credentials.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Proofpoint | `proofpoint_tap_raw` | Phishing email delivered | `xdm.email.recipients`; `shared_guid` |
| 2 | Proofpoint | `proofpoint_tap_raw` | URL click permitted | `xdm.network.http.url` = phishing URL |
| 2b *(if Infoblox loaded)* | Infoblox | `infoblox_dns_raw` | DNS A query for phishing domain | `xdm.source.ip` = victim; `xdm.target.hostname` = phishing domain |
| 3 | Zscaler or Check Point | `zscaler` / `check_point_url_filtering_raw` | Threat block or allowed web request | `xdm.source.ip` = victim; phishing URL |
| 4 | Cisco Firepower / ASA / Check Point | respective dataset | Large outbound egress (C2 callback) | `xdm.source.sent_bytes` = large |
| 5 | Okta | `okta_raw` | Login success from external IP | `xdm.source.ip` = attacker |

*Hunt:* Correlate `shared_guid` across Proofpoint events. Find victim `xdm.source.ip` appearing in Proofpoint click → Infoblox DNS query → Zscaler/Firepower egress within same session window.

---

### Scenario 4 — Insider Threat / Cloud Data Exfiltration (with DNS correlation)

*Narrative:* A malicious insider authenticates normally via Okta, accesses cloud credentials in AWS Secrets Manager/SSM, disables AWS Security Hub and Config, resolves the exfil destination domain via Infoblox DNS *(if loaded)*, uploads a large file to external cloud storage via Zscaler, and the outbound transfer is recorded by the network firewall.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Okta | `okta_raw` | Normal login from office IP | `xdm.event.outcome` = Success |
| 2 | AWS CloudTrail | `amazon_aws_raw` | GetSecretValue on credential path | `xdm.target.resource.name` contains "credential" |
| 3 | AWS CloudTrail | `amazon_aws_raw` | DisableSecurityHub | Defense evasion |
| 4 | AWS CloudTrail | `amazon_aws_raw` | StopConfigurationRecorder | Defense evasion |
| 4b *(if Infoblox loaded)* | Infoblox | `infoblox_dns_raw` | DNS A query for cloud storage domain | `xdm.source.ip` = insider; `xdm.target.hostname` = exfil destination |
| 5 | Zscaler | `zscaler` | DLP event: large upload to cloud storage | `xdm.source.sent_bytes` > threshold |
| 6 | Cisco Firepower / ASA / Check Point | respective dataset | Large outbound TCP session | `xdm.source.sent_bytes` > 50MB |

*Hunt:* Find `xdm.auth.auth_username` that appears in both AWS `DisableSecurityHub` and Zscaler DLP events within same day. Correlate `xdm.source.ip` across Okta login → Infoblox DNS → Zscaler upload.

---

### Scenario 5 — DNS C2 Kill Chain *(requires Infoblox NIOS)*

*Narrative:* An attacker's implant on a compromised internal host attempts to beacon to a C2 controller. The first domain attempt is blocked at DNS (RPZ). The implant cycles through DGA-generated names (NXDOMAIN storm). The second domain is blocked at the network firewall (Security Intel). The third domain is new infrastructure — it resolves successfully and the C2 connection is established.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Infoblox | `infoblox_dhcp_raw` | DHCPACK — victim host gets IP lease | `xdm.source.ip`; `xdm.source.host.mac_address`; `xdm.source.host.hostname` |
| 2 | Infoblox | `infoblox_dns_raw` | DNS A query — benign domain (connectivity check) | Normal NOERROR — establishes baseline |
| 3 | Infoblox | `infoblox_dns_raw` | DNS query + RPZ NXDOMAIN — 1st C2 domain blocked | `xdm.target.hostname` = C2 domain; `xdm.network.dns.dns_response_code` = NXDOMAIN |
| 4 | Infoblox | `infoblox_dns_raw` | NXDOMAIN storm — DGA cycling (2nd domain attempts) | 20–50 query+NXDOMAIN pairs (40–100 events); high-entropy subdomains; same `xdm.source.ip` |
| 5 | Firepower / ASA / Check Point | respective dataset | Security Intel / URL block — 2nd domain blocked at FW | `xdm.observer.action` = Block |
| 6 | Infoblox | `infoblox_dns_raw` | DNS A query — 3rd domain resolves (NOERROR) | `xdm.network.dns.dns_response_code` = NOERROR |
| 7 | Firepower / ASA / Check Point | respective dataset | Allow — outbound connection established | `xdm.observer.action` = Allow |

*Hunt:* Find `xdm.source.ip` generating both a NXDOMAIN storm in `infoblox_dns_raw` AND a successful outbound connection in the firewall dataset within the same hour. Join on `xdm.source.ip` across three datasets: DHCP (who is the device?) → DNS (what did they try to resolve?) → Firewall (what did they connect to?).

---

### Scenario 6 — Device Compromise: Full Lifecycle (DHCP → DNS → C2 → Threat Protect) *(requires Infoblox NIOS)*

*Narrative:* Complete device compromise story from the moment a device joins the network through C2 establishment. Spans **four XSIAM datasets**. The Threat Protect event at Step 7 is often the first alert — use it to pivot backward and build the full timeline.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Infoblox | `infoblox_dhcp_raw` | DHCPACK — device joins network | `xdm.source.mac_address`; `xdm.source.host.hostname`; lease timestamp |
| 2 | Infoblox | `infoblox_dns_raw` | DNS A query — normal domain (baseline) | NOERROR — establishes device is active |
| 3 | Firepower / ASA / Check Point | respective dataset | Allow — normal outbound web browsing | Legitimate destination; benign baseline |
| 4 | Infoblox | `infoblox_dns_raw` | DNS query + RPZ NXDOMAIN — 1st C2 attempt | `xdm.target.hostname` = C2 domain; RPZ CEF event logged |
| 5 | Firepower / ASA / Check Point | respective dataset | URL/Security Intel block — 2nd C2 attempt | `xdm.target.hostname` = C2 domain 2; Block action |
| 6 | Infoblox | `infoblox_dns_raw` | DNS A query — 3rd domain resolves (not yet blocked) | NOERROR; `xdm.target.hostname` = C2 domain 3 |
| 7 | Infoblox | `infoblox_threat_raw` | Threat Protect CEF DROP — post-connection detection | `xdm.alert.category` = C&C; `threat-protect-log` process |

*Hunt:* Find device MAC in `infoblox_dhcp_raw` → find same IP in `infoblox_dns_raw` NXDOMAIN storm → find same IP in `infoblox_threat_raw` CEF within same day. The Threat Protect event (Step 7) is likely the first alert; pivot backward through Steps 1–6 to build the complete device compromise timeline.

---

### Scenarios 7–13 — Infoblox Standalone Threat Tests

These single-event scenarios allow direct testing and validation of any specific Infoblox threat type without running a full multi-module kill chain.

| # | Name | Description |
|---|---|---|
| 7 | Infoblox — C2 Beacon | DNS query to C2 domain → NXDOMAIN (query+response pair) |
| 8 | Infoblox — DNS Tunneling | TXT exfil subdomain → SERVFAIL (query+response pair) |
| 9 | Infoblox — RPZ Block | `named` RPZ CEF NXDOMAIN/PASSTHRU event (query+CEF pair) |
| 10 | Infoblox — Threat Protect Block | BloxOne `threat-protect-log` CEF DROP (single event) |
| 11 | Infoblox — NXDOMAIN Storm / DGA | 20–50 query+NXDOMAIN pairs (40–100 total events) from one source IP |
| 12 | Infoblox — DNS Flood | 20–50 rapid queries across diverse domains/types |
| 13 | Infoblox — DHCP Starvation | 20–50 DHCPDISCOVER events from spoofed random MACs |
| 14 | Infoblox — Zone Transfer | AXFR/IXFR query → REFUSED (query+response pair) |
| 15 | Infoblox — Fast-Flux DNS | 3–6 queries for same domain → different IPs, TTL=0 per response |
| 16 | Infoblox — DNS Rebinding | External-named domain resolves to internal RFC-1918 IP, TTL=1 |
| 17 | Infoblox — PTR Sweep | 20–40 sequential in-addr.arpa PTR queries (~75% NXDOMAIN) |

---

### Cross-Module DNS/DHCP Correlation API

The Infoblox NIOS module exposes two public functions that other scenarios can call via the orchestrator:

* **`generate_dns_pair(config, client_ip, domain, q_type, dns_server_ip)`** — Returns `(list[str], "DNS_QUERY")` ready for `process_and_send()`. Automatically returns `NXDOMAIN` if the domain appears in `infoblox_threats.malicious_domains` or `dga_domains`; otherwise `NOERROR` with a synthesised response record matching the requested `q_type`. Calling pattern: `dns_logs, dns_name = infoblox_module.generate_dns_pair(config, src_ip, domain)`

* **`generate_dhcp_ack(config, client_ip, client_mac, client_hostname)`** — Returns `(str, "DHCP_ACK")`. Used at the start of any scenario that involves a workstation being on network — establishes the IP→MAC→hostname triad in `infoblox_dhcp_raw` before connection events appear in firewall datasets. Enables the "who was using that IP at this time?" cross-dataset hunt query.

DNS and DHCP correlation steps are automatically included in Scenarios 3 and 4 when the Infoblox NIOS module is in the selected modules list.
