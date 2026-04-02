# Attack Scenarios

The following scenarios can be run using **Mode 2**. Scenarios 2 and 3 include optional Infoblox DNS/DHCP correlation steps that activate automatically when the Infoblox NIOS module is loaded. Scenarios 9–10 require Infoblox NIOS. Scenarios 1–8 require no Infoblox and run with any combination of the other modules.

---

> **XSIAM Out-of-the-Box Detection Coverage**
>
> XSIAM includes built-in (out-of-the-box) detectors for only a subset of the individual steps across these scenarios. Most kill chain steps will produce raw dataset events that are **visible in search but will not automatically trigger an alert or open a case** without a custom correlation rule.
>
> Steps covered by XSIAM OOB detectors include (non-exhaustive):
> - AWS: Kali AMI launch, Tor IP console login, AdministratorAccess policy attachment, CloudTrail StopLogging, GuardDuty DisableDetector, public S3 bucket ACL, StopConfigurationRecorder
> - GCP: None — all steps require custom correlation rules
> - Okta: impossible travel, MFA bypass, brute-force login, AiTM phishing
> - Proofpoint: phishing delivered with click permitted, malware attachment delivered
>
> **All other steps — including firewall C2 connections, DNS NXDOMAIN storms, lateral movement, SMB enumeration, VPN compromise, web shell activity, and Infoblox Threat Protect events — require you to build custom XSIAM correlation rules** to surface them as alerts and stitch them into a single case. Use these scenarios to generate the raw data, then build the rules to detect it.

> **Google Workspace scenario (Compromised Account & Data Exfiltration via Google Drive) is currently disabled** — the Google Workspace module is not yet functional. It will be re-added to the menu once the module is restored.

---

### Scenario 1 — AWS Cloud Pentest (Privilege Escalation + Defense Evasion)

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

*OOB Detections:* Steps 1, 2, 3, 4, 5 have XSIAM built-in detectors.

---

### Scenario 2 — Phishing Kill Chain (Email → Click → DNS → C2 → Credential Theft)

*Narrative:* A phishing email is delivered to a victim and not blocked. The victim clicks the malicious link. The browser resolves the phishing domain via Infoblox DNS *(if loaded)*, Zscaler or Check Point detects and may block the web request, all loaded network firewalls record the C2 callback, and the attacker authenticates to Okta with stolen credentials.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Proofpoint | `proofpoint_tap_raw` | Phishing email delivered | `xdm.email.recipients`; `shared_guid` |
| 2 | Proofpoint | `proofpoint_tap_raw` | URL click permitted | `xdm.network.http.url` = phishing URL |
| 2b *(if Infoblox loaded)* | Infoblox | `infoblox_dns_raw` | DNS A query for phishing domain | `xdm.source.ip` = victim; `xdm.target.hostname` = phishing domain |
| 3 | Zscaler or Check Point | `zscaler` / `check_point_url_filtering_raw` | Threat block or allowed web request | `xdm.source.ip` = victim; phishing URL |
| 4 | **All loaded firewalls** (Firepower, ASA, Checkpoint, Fortinet, Zscaler) | respective datasets | Large outbound egress (C2 callback) | `xdm.source.sent_bytes` = large |
| 5 | Okta | `okta_raw` | Login success from external IP | `xdm.source.ip` = attacker |

*Hunt:* Correlate `shared_guid` across Proofpoint events. Find victim `xdm.source.ip` appearing in Proofpoint click → Infoblox DNS query → firewall egress events within same session window.

*OOB Detections:* Steps 1–2 (Proofpoint delivered + click). Step 5 may trigger Okta impossible travel if IP is unexpected. Steps 3–4 require custom correlation rules.

---

### Scenario 3 — Insider Threat / Cloud Data Exfiltration (with DNS correlation)

*Narrative:* A malicious insider authenticates normally via Okta, accesses cloud credentials in AWS Secrets Manager/SSM, disables AWS Security Hub and Config, resolves the exfil destination domain via Infoblox DNS *(if loaded)*, uploads a large file to external cloud storage via Zscaler, and the outbound transfer is recorded by the network firewall.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Okta | `okta_raw` | Normal login from office IP | `xdm.event.outcome` = Success |
| 2 | AWS CloudTrail | `amazon_aws_raw` | GetSecretValue on credential path | `xdm.target.resource.name` contains "credential" |
| 3 | AWS CloudTrail | `amazon_aws_raw` | DisableSecurityHub | Defense evasion |
| 4 | AWS CloudTrail | `amazon_aws_raw` | StopConfigurationRecorder | Defense evasion |
| 4b *(if Infoblox loaded)* | Infoblox | `infoblox_dns_raw` | DNS A query for cloud storage domain | `xdm.source.ip` = insider; `xdm.target.hostname` = exfil destination |
| 5 | Zscaler | `zscaler` | DLP event: large upload to cloud storage | `xdm.source.sent_bytes` > threshold |
| 6 | **All loaded firewalls** (Firepower, ASA, Checkpoint, Fortinet, Zscaler) | respective datasets | Large outbound TCP session | `xdm.source.sent_bytes` > 50MB |

*Hunt:* Find `xdm.auth.auth_username` that appears in both AWS `DisableSecurityHub` and Zscaler DLP events within same day. Correlate `xdm.source.ip` across Okta login → Infoblox DNS → Zscaler upload.

*OOB Detections:* Steps 3–4 have AWS defense-evasion detectors. All other steps require custom correlation rules.

---

### Scenario 4 — GCP Cloud Pentest (Privilege Escalation + Defense Evasion)

*Narrative:* An attacker accesses the GCP API from a Tor exit node to conduct reconnaissance, escalates privileges via IAM policy binding, creates a service account key for persistence, then disables Cloud Audit Logging and Security Command Center before making a GCS bucket public and exfiltrating a disk snapshot to an attacker-controlled project.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | GCP | `google_cloud_logging_raw` | API access from Tor exit node | `protoPayload.requestMetadata.callerIp` = Tor node |
| 2 | GCP | `google_cloud_logging_raw` | SetIamPolicy → roles/owner (privilege escalation) | `protoPayload.methodName` = SetIamPolicy |
| 3 | GCP | `google_cloud_logging_raw` | CreateServiceAccountKey (persistence) | `protoPayload.methodName` = CreateKey |
| 4 | GCP | `google_cloud_logging_raw` | UpdateSink (disable audit logging) | Defense evasion |
| 5 | GCP | `google_cloud_logging_raw` | UpdateNotificationConfig (disable SCC) | Defense evasion |
| 6 | GCP | `google_cloud_logging_raw` | SetIamPolicy on GCS bucket (make public) | `resource.type` = gcs_bucket |
| 7 | GCP | `google_cloud_logging_raw` | CreateSnapshot + SetIamPolicy (exfiltrate disk) | `protoPayload.methodName` = CreateSnapshot |

*Hunt:* Chain on `protoPayload.authenticationInfo.principalEmail` + Tor `callerIp` across SetIamPolicy → CreateKey → UpdateSink → SetBucketAcl events within the same 15-minute window.

*OOB Detections:* None for this scenario — all steps require custom correlation rules.

---

### Scenario 5 — Web Application Compromise → Server C2

*Narrative:* An attacker scans a web application, exploits a web shell upload vulnerability, delivers a malicious payload through the shell, then the compromised server initiates anomalous outbound connections (post-exploit C2 beacon) — an unusual pattern since servers should not initiate external connections. The outbound beacon is visible across all loaded network firewall datasets.

**Firewall coverage:** Step 4 (server C2 beacon) sends to **all** loaded firewall modules simultaneously. Hunt by finding the server IP appearing as a *source* (not destination) in outbound Allow events — this reversal of normal traffic direction is the key detection signal.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Apache httpd | `apache_httpd_raw` | Recon scan — directory traversal / scanner probing | `src_ip` = attacker; 4xx burst |
| 2 | Apache httpd | `apache_httpd_raw` | Web shell execution — POST to upload/script path | Unusual response code + body size pattern |
| 3 | Apache httpd | `apache_httpd_raw` | Malicious payload delivery via web shell | Error log entries; `AH01276` / script execution |
| 4 | **All loaded firewalls** | `cisco_firepower_raw`, `cisco_asa_raw`, `check_point_vpn_1_firewall_1_raw`, `fortinet_raw`, `zscaler_*` | Anomalous outbound Allow from server IP | `xdm.source.ip` = server (not client!); `xdm.observer.action` = Allow |

*Hunt:* Find the server IP in `apache_httpd_raw` (victim of web shell) then find the same IP as `xdm.source.ip` in firewall Allow events shortly after. Servers initiating outbound connections to unknown external IPs is a high-fidelity indicator.

*OOB Detections:* None for this scenario — all steps require custom correlation rules.

---

### Scenario 6 — VPN Compromise → Lateral Movement

*Narrative:* An attacker brute-forces VPN credentials, authenticates with impossible travel (same user connecting from two geographically distant IPs within minutes), then uses the VPN-assigned internal IP to enumerate SMB shares and move laterally to high-value hosts. Okta logs an impossible travel alert when the attacker also authenticates to SSO using the stolen credentials.

**Firewall coverage:** Steps 3–4 (SMB enumeration and lateral movement) send to **all** loaded firewall modules simultaneously. Join on the VPN-assigned IP across ASA VPN session logs → firewall SMB events to trace the full intrusion path.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Cisco ASA | `cisco_asa_raw` | VPN brute-force — 109006 auth failures against VPN gateway | `xdm.source.ip` = attacker; `xdm.auth.auth_username` = victim |
| 2 | Cisco ASA | `cisco_asa_raw` | Impossible travel — VPN login from distant IP | Same username; different country in short time window |
| 3 | **All loaded firewalls** | respective datasets | SMB share enumeration from VPN-assigned IP | `xdm.source.ip` = VPN-assigned; `xdm.network.application_protocol` = SMB |
| 4 | **All loaded firewalls** | respective datasets | SMB lateral movement — new host target | `xdm.target.ip` = new internal host; SMB port 445 |
| 5 | Okta | `okta_raw` | Impossible travel — SSO login from attacker IP | `xdm.source.ip` = attacker; `xdm.auth.auth_username` = victim |

*Hunt:* Find `xdm.auth.auth_username` in both `cisco_asa_raw` (vpn_bruteforce → vpn_impossible_travel) and `okta_raw` (impossible_travel) within 30 min. Pivot on VPN-assigned IP across firewall SMB lateral events.

*OOB Detections:* Okta impossible travel may fire (Step 5). All other steps require custom correlation rules.

---

### Scenario 7 — AiTM Session Hijack → Cloud Abuse

*Narrative:* An attacker delivers a QR-code phishing email that bypasses Proofpoint's URL scanner (QR code images are not followed). The victim authenticates through an attacker-controlled reverse proxy (Adversary-in-the-Middle), and the session cookie is stolen. The attacker replays the token from a new IP, the session roams to an unrecognized device, and the attacker then pivots to AWS using the hijacked cloud session to assume a cross-account role and disable Security Hub.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Proofpoint | `proofpoint_tap_raw` | QR-code phishing delivered — bypasses link scan | `xdm.email.recipients`; attachment type = image |
| 2 | Okta | `okta_raw` | AiTM phishing — victim auth through reverse proxy | Session anomaly; `xdm.source.ip` = proxy IP |
| 3 | Okta | `okta_raw` | Token reuse — stolen session cookie replayed | New IP; same session token |
| 4 | Okta | `okta_raw` | Session roaming — hijacked session on new device | IP/device mismatch |
| 5 | AWS CloudTrail | `amazon_aws_raw` | AssumeRole — cross-account pivot with hijacked creds | `xdm.auth.auth_username` = victim; source = attacker IP |
| 6 | AWS CloudTrail | `amazon_aws_raw` | DisableSecurityHub — suppress GuardDuty findings | Defense evasion |

*Hunt:* Correlate Okta session start for the victim → AWS API calls from same access key or source IP within 10 min. Chain: aitm_phishing → token_reuse → session_roaming → AssumeRole → DisableSecurityHub on same `xdm.auth.auth_username`.

*OOB Detections:* Proofpoint QR-code phishing delivered; Okta impossible travel may fire if IP changes are extreme. All other steps require custom correlation rules.

---

### Scenario 8 — Ransomware Precursor Kill Chain

*Narrative:* Multi-phase attack spanning the broadest module coverage in the simulator. A malware attachment is delivered via email. The attacker uses harvested credentials to brute-force Okta and bypass MFA. Once on the network, SMB shares are enumerated, files are staged via rare SMB transfers, AWS security controls are disabled, and large outbound egress sessions — consistent with pre-encryption data staging — appear across all loaded network firewall datasets.

**Firewall coverage:** Steps 4–5 (SMB enumeration + file staging) and Step 8 (large egress) send to **all** loaded firewall modules simultaneously.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Proofpoint | `proofpoint_tap_raw` | Malware attachment delivered to victim mailbox | `xdm.email.attachments`; `xdm.event.outcome` = delivered |
| 2 | Okta | `okta_raw` | Credential brute-force — attacker cycling harvested passwords | High-volume auth failures; `xdm.source.ip` = attacker |
| 3 | Okta | `okta_raw` | MFA bypass — second factor bypassed after credential success | `xdm.event.type` = MFA bypass |
| 4 | **All loaded firewalls** | respective datasets | SMB share enumeration — discovering accessible file shares | Port 445; many short connections to diverse internal hosts |
| 5 | **All loaded firewalls** | respective datasets | SMB rare file transfer — bulk staging of sensitive data | Large `xdm.source.sent_bytes`; unusual file paths |
| 6 | AWS CloudTrail | `amazon_aws_raw` | StopConfigurationRecorder — halt AWS Config change tracking | Defense evasion before encryption |
| 7 | AWS CloudTrail | `amazon_aws_raw` | DeleteWebACL — remove inbound WAF protection | Defense evasion |
| 8 | **All loaded firewalls** | respective datasets | Large egress — data staging outbound (pre-encryption exfil) | `xdm.source.sent_bytes` > 50MB; unusual destination |

*Hunt:* Timeline from Proofpoint delivery → Okta auth compromise → firewall SMB enumeration → AWS defense evasion → LARGE_EGRESS on the same day. Look for the victim username spanning Proofpoint → Okta → AWS events, and victim IP spanning all firewall datasets.

*OOB Detections:* Proofpoint malware attachment delivered; Okta brute_force and mfa_bypass may fire. AWS StopConfigurationRecorder has a built-in detector. All other steps require custom correlation rules.

---

### Scenario 9 — DNS C2 Kill Chain *(requires Infoblox NIOS)*

*Narrative:* An attacker's implant on a compromised internal host attempts to beacon to a C2 controller. The first domain attempt is blocked at DNS (RPZ). The implant cycles through DGA-generated names (NXDOMAIN storm). The second domain is blocked at **every loaded network firewall** simultaneously. The third domain is new infrastructure — it resolves successfully and the C2 connection is established across all loaded firewalls.

**Firewall coverage:** This scenario sends firewall events to **all** loaded firewall modules simultaneously — Cisco Firepower, Cisco ASA, Check Point, Fortinet FortiGate, and Zscaler — each generating a block (Step 5) and an allowed connection (Step 7) in their respective log format and dataset. Load only the firewall modules you want to hunt in, or load all of them to practice cross-dataset correlation.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Infoblox | `infoblox_dhcp_raw` | DHCPACK — victim host gets IP lease | `xdm.source.ip`; `xdm.source.host.mac_address`; `xdm.source.host.hostname` |
| 2 | Infoblox | `infoblox_dns_raw` | DNS A query — benign domain (connectivity check) | Normal NOERROR — establishes baseline |
| 3 | Infoblox | `infoblox_dns_raw` | DNS query + RPZ NXDOMAIN — 1st C2 domain blocked | `xdm.target.hostname` = C2 domain; `xdm.network.dns.dns_response_code` = NXDOMAIN |
| 4 | Infoblox | `infoblox_dns_raw` | NXDOMAIN storm — DGA cycling (2nd domain attempts) | 20–50 query+NXDOMAIN pairs (40–100 events); high-entropy subdomains; same `xdm.source.ip` |
| 5 | **All loaded firewalls** | `cisco_firepower_raw`, `cisco_asa_raw`, `check_point_vpn_1_firewall_1_raw`, `fortinet_raw`, `zscaler_*` | Security Intel / URL block — 2nd domain blocked at FW | `xdm.observer.action` = Block; same `xdm.source.ip` across all datasets |
| 6 | Infoblox | `infoblox_dns_raw` | DNS A query — 3rd domain resolves (NOERROR) | `xdm.network.dns.dns_response_code` = NOERROR |
| 7 | **All loaded firewalls** | same as Step 5 | Allow — outbound connection established | `xdm.observer.action` = Allow; same `xdm.source.ip` across all datasets |

*Hunt:* Find `xdm.source.ip` generating both a NXDOMAIN storm in `infoblox_dns_raw` AND a successful outbound connection in any firewall dataset within the same hour. Join on `xdm.source.ip` across three datasets: DHCP (who is the device?) → DNS (what did they try to resolve?) → Firewall (what did they connect to?).

*OOB Detections:* None for this scenario — all steps require custom correlation rules.

---

### Scenario 10 — Device Compromise: Full Lifecycle (DHCP → DNS → C2 → Threat Protect) *(requires Infoblox NIOS)*

*Narrative:* Complete device compromise story from the moment a device joins the network through C2 establishment. Spans **four or more XSIAM datasets**. The Threat Protect event at Step 7 is often the first alert — use it to pivot backward and build the full timeline. Steps 3 and 5 generate events across **all loaded network firewalls** simultaneously.

**Firewall coverage:** Steps 3 (benign baseline) and 5 (C2 block) send to **all** loaded firewall modules — Cisco Firepower, Cisco ASA, Check Point, Fortinet FortiGate, and Zscaler. Each produces events in its own dataset and format, giving you correlated evidence across all your network security tools for a single device's activity.

| Step | Module | Dataset | Event | Key Hunt Fields |
|---|---|---|---|---|
| 1 | Infoblox | `infoblox_dhcp_raw` | DHCPACK — device joins network | `xdm.source.mac_address`; `xdm.source.host.hostname`; lease timestamp |
| 2 | Infoblox | `infoblox_dns_raw` | DNS A query — normal domain (baseline) | NOERROR — establishes device is active |
| 3 | **All loaded firewalls** | respective datasets | Allow — normal outbound web browsing | Legitimate destination; benign baseline for this IP |
| 4 | Infoblox | `infoblox_dns_raw` | DNS query + RPZ NXDOMAIN — 1st C2 attempt | `xdm.target.hostname` = C2 domain; RPZ CEF event logged |
| 5 | **All loaded firewalls** | respective datasets | URL/Security Intel block — 2nd C2 attempt | `xdm.target.hostname` = C2 domain 2; Block action across all firewall datasets |
| 6 | Infoblox | `infoblox_dns_raw` | DNS A query — 3rd domain resolves (not yet blocked) | NOERROR; `xdm.target.hostname` = C2 domain 3 |
| 7 | Infoblox | `infoblox_threat_raw` | Threat Protect CEF DROP — post-connection detection | `xdm.alert.category` = C&C; `threat-protect-log` process |

*Hunt:* Find device MAC in `infoblox_dhcp_raw` → find same IP in `infoblox_dns_raw` NXDOMAIN storm → find same IP in `infoblox_threat_raw` CEF within same day. The Threat Protect event (Step 7) is likely the first alert; pivot backward through Steps 1–6 to build the complete device compromise timeline.

*OOB Detections:* None for this scenario — all steps require custom correlation rules.

---

### Scenarios 11–17 — Infoblox Standalone Threat Tests

These single-event scenarios allow direct testing and validation of any specific Infoblox threat type without running a full multi-module kill chain.

| # | Name | Description |
|---|---|---|
| 11 | Infoblox — C2 Beacon | DNS query to C2 domain → NXDOMAIN (query+response pair) |
| 12 | Infoblox — DNS Tunneling | TXT exfil subdomain → SERVFAIL (query+response pair) |
| 13 | Infoblox — RPZ Block | `named` RPZ CEF NXDOMAIN/PASSTHRU event (query+CEF pair) |
| 14 | Infoblox — Threat Protect Block | BloxOne `threat-protect-log` CEF DROP (single event) |
| 15 | Infoblox — NXDOMAIN Storm / DGA | 20–50 query+NXDOMAIN pairs (40–100 total events) from one source IP |
| 16 | Infoblox — DNS Flood | 20–50 rapid queries across diverse domains/types |
| 17 | Infoblox — DHCP Starvation | 20–50 DHCPDISCOVER events from spoofed random MACs |

---

### Cross-Module DNS/DHCP Correlation API

The Infoblox NIOS module exposes two public functions that other scenarios can call via the orchestrator:

* **`generate_dns_pair(config, client_ip, domain, q_type, dns_server_ip)`** — Returns `(list[str], "DNS_QUERY")` ready for `process_and_send()`. Automatically returns `NXDOMAIN` if the domain appears in `infoblox_threats.malicious_domains` or `dga_domains`; otherwise `NOERROR` with a synthesised response record matching the requested `q_type`. Calling pattern: `dns_logs, dns_name = infoblox_module.generate_dns_pair(config, src_ip, domain)`

* **`generate_dhcp_ack(config, client_ip, client_mac, client_hostname)`** — Returns `(str, "DHCP_ACK")`. Used at the start of any scenario that involves a workstation being on network — establishes the IP→MAC→hostname triad in `infoblox_dhcp_raw` before connection events appear in firewall datasets. Enables the "who was using that IP at this time?" cross-dataset hunt query.

DNS and DHCP correlation steps are automatically included in Scenarios 2 and 3 when the Infoblox NIOS module is in the selected modules list.
