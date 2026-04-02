# How to Run

## Starting the Simulator

1. Open a terminal and navigate to the project root directory.
2. Run the main script:
   ```bash
   python log_simulator.py
   ```
3. On startup the simulator will:
   - Load `config.json` and `.env`
   - Auto-discover and load all modules from `modules/`
   - Attempt to fetch a live Tor exit node list from `check.torproject.org` (falls back to `tor_exit_nodes` in `config.json` on failure)
   - Build a **session context** — a stable user → device → IP mapping that persists for the entire run, so correlated events from different modules consistently reference the same identities
4. Select a simulation mode from the menu.

---

## Simulation Modes

### Mode 1 — Independent Product Logs (Continuous)

Runs all selected modules continuously, generating a realistic mix of benign background traffic and randomised threat events. This is the primary mode for populating analytics baselines and training detection rules.

**Flow:**

1. **Select modules** — choose which log sources to run (e.g., `1,3,5` or `all`)
2. **Select threat level** — controls how frequently threat events are injected (see [Threat Generation Levels](#threat-generation-levels) below)
3. **Select execution mode:**
   - **Serial** — modules run round-robin, one at a time. Each module fires once per cycle before moving to the next. Predictable, easier to follow in logs.
   - **Parallel** — each module runs in its own dedicated thread simultaneously. All modules generate at the same time, producing a denser and more realistic concurrent log stream. Recommended when running many modules together.

**When to use:** XSIAM baseline building, XDM mapping validation, alerting rule tuning, analytics warm-up.

---

### Mode 2 — Correlated Attack Scenarios

Runs a single pre-built, multi-step kill chain one time and then returns to the menu. Each scenario fires events across multiple modules in a coordinated sequence, with shared user identities and IPs, so the events correlate correctly in XSIAM.

**Flow:** Select a numbered scenario from the list → the scenario runs → the menu reappears.

All 17 available scenarios are documented in detail in [Attack Scenarios](attack-scenarios.md). A summary:

> **XSIAM OOB detection coverage:** XSIAM includes built-in detectors for only a subset of steps across these scenarios. Most steps produce raw dataset events that are **visible in search but will not automatically trigger an alert** without a custom correlation rule. See [attack-scenarios.md](attack-scenarios.md) for which steps have OOB coverage.

| # | Scenario | Primary Modules | Notes |
|---|---|---|---|
| 1 | AWS Cloud Pentest — Privilege Escalation & Defense Evasion | AWS CloudTrail | Kali launch → Tor login → attach admin policy → stop CloudTrail → disable GuardDuty → public S3. OOB detectors on all 6 steps. |
| 2 | Phishing Kill Chain — Email → Click → DNS → C2 → Credential Theft | Proofpoint, Infoblox *(optional)*, Zscaler / Check Point, **All firewalls**, Okta | Infoblox DNS steps auto-activate if the module is loaded. C2 beacon fires on all loaded firewall modules. |
| 3 | Insider Threat — Cloud Data Exfiltration with DNS Correlation | Okta, AWS CloudTrail, Infoblox *(optional)*, Zscaler, **All firewalls** | Infoblox DNS steps auto-activate if the module is loaded. Exfil egress fires on all loaded firewall modules. |
| 4 | GCP Cloud Pentest — Privilege Escalation & Defense Evasion | GCP Cloud Audit Logs | Tor API access → IAM escalation → SA key → disable audit logging → disable SCC → public GCS → snapshot exfil. |
| 5 | Web App Compromise → Server C2 | Apache httpd, **All firewalls** *(optional)* | Recon scan → web shell → payload delivery → anomalous outbound beacon from server IP on all loaded firewalls. |
| 6 | VPN Compromise → Lateral Movement | Cisco ASA, **All firewalls** *(optional)*, Okta *(optional)* | VPN brute-force → impossible travel → SMB enumeration → lateral movement. Hunt: join victim username across ASA → firewalls → Okta. |
| 7 | AiTM Session Hijack → Cloud Abuse | Proofpoint *(optional)*, Okta, AWS *(optional)* | QR-code phishing → AiTM → token reuse → session roaming → cross-account role assumption → disable Security Hub. |
| 8 | Ransomware Precursor Kill Chain | Proofpoint *(optional)*, Okta *(optional)*, **All firewalls**, AWS *(optional)* | Broadest module coverage — malware delivery → credential compromise → SMB enumeration → file staging → AWS defense evasion → large egress on all loaded firewalls. |
| 9 | DNS C2 Kill Chain | Infoblox, **All firewalls** *(optional)* | DHCP → benign DNS → RPZ block → DGA NXDOMAIN storm → firewall block → new domain resolves → C2 established on all loaded firewalls. **Requires Infoblox NIOS.** |
| 10 | Device Compromise — Full Lifecycle: DHCP → DNS → C2 → Threat Protect | Infoblox, **All firewalls** *(optional)* | Network join → benign baseline → C2 attempts → Threat Protect CEF DROP. **Requires Infoblox NIOS.** Spans 4 XSIAM datasets. |
| 11 | Infoblox — C2 Beacon | Infoblox | DNS query to C2 domain → NXDOMAIN pair |
| 12 | Infoblox — DNS Tunneling | Infoblox | TXT exfil subdomain → SERVFAIL pair |
| 13 | Infoblox — RPZ Block | Infoblox | `named` RPZ CEF NXDOMAIN/PASSTHRU event |
| 14 | Infoblox — Threat Protect Block | Infoblox | BloxOne `threat-protect-log` CEF DROP event |
| 15 | Infoblox — NXDOMAIN Storm / DGA | Infoblox | 20–50 query+NXDOMAIN pairs from one source IP |
| 16 | Infoblox — DNS Flood | Infoblox | 20–50 rapid queries across diverse domains and record types |
| 17 | Infoblox — DHCP Starvation | Infoblox | 20–50 DHCPDISCOVER events from spoofed random MACs |

> **Scenarios 1–8** do not require Infoblox. Any module marked *(optional)* will have its steps gracefully skipped if not loaded — the scenario still runs with the remaining modules.

> **Scenarios 9–10** require Infoblox NIOS. Scenarios 11–17 are Infoblox standalone validation tests.

**When to use:** Testing XSIAM correlation rules, incident response playbook validation, SOC analyst training exercises.

---

### Mode 3 — Specific Threat (Targeted)

Lets you fire a single named threat event type from a specific module, on demand. This is useful when you want to verify that a particular detection rule fires, test a specific XDM field mapping, or replay a single technique without the noise of Mode 1.

**Flow:**

1. Select a module from the list
2. Select a named threat from that module's available threat types (the full list is shown for each module)
3. Choose to run **once** or **repeat until Ctrl+C**

When set to repeat, the same threat fires continuously with a short delay between each event — useful for high-volume testing or ensuring an alert triggers reliably.

**When to use:** Single-rule validation, XDM field debugging, demonstrating a specific attack technique.

---

## Threat Generation Levels

Applies to **Mode 1 only**. Controls the minimum interval between threat events per module. The interval is enforced per-module — each module tracks its own last-threat timestamp independently.

| Level | Min. interval between threats | Effective behaviour |
|---|---|---|
| **Benign Traffic Only** | Never | Zero threats. Only benign background traffic is generated. Use this to build a clean analytics baseline before introducing threats. |
| **Realistic** | 2 hours | Roughly 1 threat event per module per 2 hours. Mirrors a low-noise enterprise environment where threats are infrequent against a high volume of benign traffic. |
| **Elevated** | 1 hour | 1 threat per module per hour. Appropriate for environments with heightened risk, or when you want more threat signal without overwhelming the benign-to-threat ratio. |
| **High** | 30 minutes | 1 threat per module every 30 minutes. A noticeably higher threat cadence — good for testing alert fatigue handling and priority tuning in XSIAM. |
| **Extreme** | 10 minutes | 1 threat per module every 10 minutes. Heavy threat activity alongside normal benign traffic. Useful for bulk-populating incidents and testing detection rule performance under load. |
| **Insane** | None (0 s) | Every single event cycle can generate a threat. Threat and benign events interleave at maximum speed. Use for stress testing, rapid data generation, or pipeline throughput validation. Not representative of realistic traffic. |

> **Tip — building a clean baseline:** Run on **Benign Traffic Only** for a period before switching to a threat level. XSIAM analytics engines (UEBA, XDR) need a baseline window of normal activity to establish behavioural profiles. Introducing threats immediately on a cold dataset produces unreliable anomaly scores.

> **Tip — threat level vs. scenario:** Threat levels only affect the frequency of randomly-injected threats in Mode 1. Attack Scenarios (Mode 2) and Specific Threats (Mode 3) are unaffected by this setting and always run at full intensity.
