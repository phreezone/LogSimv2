# XSIAM High-Fidelity Log Simulator

A modular, high-fidelity log simulation tool for **Palo Alto Networks Cortex XSIAM** — generates realistic logs to test XDM mapping, analytics baselines, UEBA behavioral profiles, detection rules, and multi-stage attack scenarios.

## Core Features

- **Modular Architecture** — each log source is a self-contained Python module; the simulator auto-discovers any module in `modules/`
- **Flask Web Dashboard** — real-time UI for controlling all modules, adjusting threat levels and event rates, firing individual threats, scheduling jobs, and monitoring health checks
- **Centralized Configuration** — all settings (IPs, users, hostnames, threat intel, transport) in a single `config.json`
- **Multiple Transports** — Syslog (TCP with persistent connections), HTTP Collector, AWS S3 (cached client), Google Cloud Pub/Sub, WEC (Windows Event Collector via WS-Management)
- **Dynamic Threat Levels** — six levels from Benign Traffic Only to Insane; controls threat event frequency per module
- **XSIAM Detection-Ready Sequences** — attack generators produce complete detection patterns (e.g., failed logins followed by success) that trigger XSIAM UEBA analytics out of the box
- **Correlated Attack Scenarios** — 17 pre-built multi-module kill chains (phishing, cloud pentest, ransomware precursor, AiTM session hijack, VPN compromise, web app compromise, insider threat, DNS C2, and more)
- **Live Threat Intel** — fetches current Tor exit nodes on startup for realistic indicators
- **Job Scheduler** — queue module start/stop, rate changes, and scenario runs at specific times or delays
- **Health Checks** — validates .env configuration, syslog connectivity, HTTP collector reachability, AWS S3 permissions, and GCP Pub/Sub credentials

## Quick Start

1. [Install dependencies and create your `.env` file](docs/getting-started.md)
2. Run: `python log_simulator.py`
   - **Mode 1** — continuous background + threats
   - **Mode 2** — single attack scenario
   - **Mode 3** — specific named threat
   - **Mode 4** — Flask Web Dashboard (opens at `http://localhost:5000`)
     - Start/stop modules, adjust rates and threat levels, fire individual threats, schedule jobs, monitor health

> `config.json` ships pre-configured and does not need to be edited. All environment-specific values (project IDs, account IDs) are read from `.env` automatically at startup. See [Configuration](docs/configuration.md) for the full reference.

See [How to Run](docs/how-to-run.md) for full details.

## Flask Dashboard

The web dashboard provides full control over log generation without touching the CLI:

- **Module Control** — start/stop individual modules or all at once with per-module threat level and event rate sliders
- **Global Controls** — header bar with global threat level dropdown, rate slider, and Start All / Stop All buttons
- **Real-Time Metrics** — per-module log counts, events/sec rate, threat counts, and threat breakdown histograms
- **Event Timeline** — rolling 2-minute chart showing event volume per module with red dots marking threat events
- **Fire Individual Threats** — select any module and any of its named threats to fire on demand
- **Attack Scenarios** — run any of the 17 pre-built multi-module kill chains from the UI
- **Job Scheduler** — queue future actions (module start/stop, rate changes, scenario runs) by delay or exact time
- **Health Checks** — preflight validation of all transport connections, credentials, and environment variables
- **Live Notifications** — browser notifications on module errors and health status changes

### Threat Levels

| Level | Threat Interval | Description |
|-------|----------------|-------------|
| Benign Traffic Only | n/a | Only background/benign events, no threats |
| Realistic | 7200s (2 hrs) | Occasional threats mixed into normal traffic |
| Elevated | 3600s (1 hr) | More frequent threat events |
| High | 1800s (30 min) | Regular threat events |
| Extreme | 600s (10 min) | Frequent threat events |
| Insane | 0s | Every other event is a threat (50/50 split) |

## XSIAM Detection Patterns

All attack sequence generators produce **complete detection-ready event chains** that trigger XSIAM UEBA analytics. XSIAM requires specific patterns to fire detections — isolated suspicious events are not enough.

### Brute Force / Password Spray

All brute force and password spray generators across all modules end with a **successful authentication** after the series of failures. XSIAM only triggers brute force detections on the failure-then-success pattern.

- **Okta** — `user.session.start` SUCCESS after failed attempts; SSO brute force ends with SSO SUCCESS
- **Cisco ASA** — `%ASA-6-109005 Authentication succeeded` after 109006 failures
- **Check Point** — `act=Log In, auth_status=Successful Login` after failures
- **Fortinet** — tunnel-up/success event after VPN failures; admin login success after admin failures
- **Okta RADIUS** — `auth_via_radius` SUCCESS after 20-50 failures

### Port Scan

All port scan generators produce 20-100 blocked/reset probes followed by **1-2 successful connections** on discovered open ports. The attacker finds live services after scanning.

- **Cisco ASA** — full TCP connection sessions (build/teardown) on open ports
- **Check Point** — Accept events with TCP FIN and real data transfer
- **Cisco Firepower** — Allow events with service-appropriate app names (SSH, HTTPS, RDP, etc.)
- **Fortinet** — accept/success events with policy=allow-internal
- **Zscaler** — Allowed events via cloud firewall

### RDP Lateral Movement

RDP lateral generators produce **3-8 blocked attempts followed by 1 successful connection** — the attacker eventually finds an allowed path through the network.

- **Cisco Firepower** — Block events then Allow with Allow_Internal_Admin rule
- **Zscaler** — Blocked events then Allowed with Allow_Internal_Admin rule

### Windows Events — XSIAM UEBA Detections

The Windows Events module generates native Windows Security Event XML targeting XSIAM's Identity Analytics (UEBA) engine. Events are delivered to the Broker VM via the **WEC (Windows Event Collector)** transport using direct WS-Management over mutual TLS.

**Confirmed Working Detections:**

| Generator | XSIAM Detection | Severity | MITRE |
|---|---|---|---|
| `dcsync` | Possible DCSync by an unusual user | High | T1003.006 |
| `delegation_change` | User account delegation to KRBTGT | High | T1558 |
| `delegation_change` | User account delegation to a DC | Low | T1098 |
| `dnshostname_spoofing` | dNSHostName attribute spoofing | Medium | T1078 |
| `samaccountname_spoofing` | sAMAccountName spoofing | Medium | T1078 |
| `multiple_service_tickets` | Abnormal issuance of weakly encrypted service tickets | Low | T1558.003 |
| `priv_group_addition` | User added to a privileged group | Medium | T1098.002 |
| `priv_group_add_remove` | User added to a privileged group and removed | Low-Medium | T1098.002 |
| `account_lockout` | Excessive user lockouts | Low | T1110 |
| `suspicious_account_lockout` | Suspicious account lockout pattern | Low | T1110 |
| `default_account_enabled` | User enabled a default local account | Low | T1078.001 |
| `sms_admins_addition` | User added to SMS Admins group | Medium | T1098 |
| `suspicious_account_creation` | Suspicious hidden user account created | Low | T1136 |
| `mass_account_deletion` | Multiple user accounts deleted | Medium | T1531 |

**WIP Detections** (prefixed with `wip_` — generating events but not yet triggering detections):

| Generator | Reason |
|---|---|
| `wip_adminsdholder_acl_modification` | Identity graph dependent — needs real AD object GUIDs/SIDs |
| `wip_dmsa_privesc` | Events ingested correctly, detection not yet firing |
| `wip_sensitive_password_reset` | Training period — needs 30-day Identity Analytics baseline |
| `wip_password_never_expires` | Training period — needs identity graph baseline |
| `wip_as_rep_roasting` | Identity graph dependent — needs baseline of normal TGT patterns |
| `wip_irregular_service_tgs` | Identity graph dependent — needs baseline of normal service access |
| `wip_priv_cert_request` | Not yet investigated |
| `wip_sccm_container_recon` | Environment dependent — requires SCCM/ConfigMgr deployment |

## WEC Transport Setup

The Windows Events module uses **WEC (Windows Event Collector)** transport to deliver events directly to the XSIAM Broker VM via WS-Management (HTTPS port 5986) with mutual TLS client certificate authentication.

This is the same protocol used by Windows Event Forwarding (WEF) source-initiated subscriptions. LogSim constructs the SOAP/XML envelopes directly, which allows it to simulate events from hundreds of different hostnames on a single machine — something native WEF cannot do since it always stamps the local machine's hostname.

### Prerequisites

1. **XSIAM Broker VM** with WEC (Windows Event Collector) activated
2. **PFX client certificate** exported from the XSIAM console
3. **Subscription Manager URL** from the XSIAM WEC configuration page

### Getting the PFX Certificate and Subscription URL

Follow the XSIAM documentation to configure WEC on your Broker VM:

> **Cortex XSIAM → Settings → Configurations → Data Collection → Broker VMs → [your Broker VM] → Windows Event Collector**
>
> See: [Palo Alto Networks XSIAM Documentation — Configure WEC on the Broker VM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Configure-WEC-on-the-Broker-VM)

From the XSIAM console WEC configuration page:

1. **Download the PFX certificate** — this is the client certificate used for mutual TLS authentication. Note the export password.
2. **Copy the Subscription Manager URL** — it looks like:
   ```
   Server=HTTPS://<broker-host>:5986/wsman/SubscriptionManager/WEC,Refresh=600,IssuerCA=<thumbprint>
   ```
   Extract:
   - **Broker URL**: `https://<broker-host>:5986/wsman` (everything before `/SubscriptionManager`)
   - **IssuerCA thumbprint**: the hex string after `IssuerCA=`

### Configuration

Set these environment variables in your `.env` file:

```bash
WEC_BROKER_URL=https://brokervm1.local.lab:5986/wsman
WEC_PFX_PATH=/path/to/broker-vm-cert.pfx
WEC_PFX_PASSWORD=your-pfx-export-password
WEC_ISSUER_CA=471F21505EB2B0F12A5E6063E2DDA5FF6D7534B1
```

In `config.json`, set the transport to `"wec"` in the `windows_events_config` section:

```json
{
    "windows_events_config": {
        "transport": "wec"
    }
}
```

### Broker VM Subscription Filter

Configure the Broker VM WEC subscription to accept **all Event IDs** from the Security channel rather than listing specific Event IDs. LogSim generates 20+ different Event IDs (4624, 4625, 4634, 4647, 4648, 4656, 4662, 4663, 4672, 4688, 4689, 4720, 4722, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4741, 4742, 4756, 4757, 4767, 4768, 4769, 4771, 4776, 4886, 4887, 4888, 5136, 5137), and accepting all Security events avoids needing to update the filter every time a new generator is added.

### How It Works

1. LogSim establishes a mutual TLS session with the Broker VM using the PFX certificate
2. Sends a WS-Management `Enumerate` request to discover the active subscription
3. Generates Windows Event XML with per-event `<Computer>` hostnames (simulating hundreds of machines)
4. Delivers events in SOAP envelopes via `Events` requests to the subscription endpoint
5. Sends periodic heartbeats to keep the subscription alive

Events appear in XSIAM under the `microsoft_windows_raw` dataset, indexed by the simulated hostname in the `<Computer>` field.

## Documentation

| Topic | File |
|---|---|
| Installation & `.env` setup | [docs/getting-started.md](docs/getting-started.md) |
| `config.json` reference (all sections) | [docs/configuration.md](docs/configuration.md) |
| Running modes & available modules | [docs/how-to-run.md](docs/how-to-run.md) |
| Attack scenarios (17 kill chains) | [docs/attack-scenarios.md](docs/attack-scenarios.md) |
| Adding a new module | [docs/extensibility.md](docs/extensibility.md) |

## Module Reference

| Module | Transport | Benign Event Types | Threat Event Types | Reference |
|---|---|---|---|---|
| Windows Events | WEC (WS-Management) | 20 types (interactive logon, network share, RDP, service, cached, unlock, logoff, process, DC Kerberos, DC directory service, LDAP, NTLM, SQL, web app access) | 21 named threat generators (13 confirmed, 8 WIP) | See WEC Transport Setup above |
| AWS CloudTrail | S3 | 69 event types across 15+ AWS services | 40 named threat scenarios | [docs/modules/aws.md](docs/modules/aws.md) |
| GCP Cloud Audit Logs | Pub/Sub | 42 event types with @type proto annotations and LRO operation pairs | 75 named threat scenarios | [docs/modules/gcp.md](docs/modules/gcp.md) |
| Okta SSO | HTTP Collector | 183+ event types across auth, SSO, MFA, lifecycle, policy, OAuth2, IAM, device, and zone domains | 82 named threat scenarios | [docs/modules/okta.md](docs/modules/okta.md) |
| Check Point Firewall | Syslog (TCP) | 5 types (web, DNS, VPN session, internal traffic, connection logs) | 25 types | [docs/modules/checkpoint.md](docs/modules/checkpoint.md) |
| Cisco ASA Firewall | Syslog (TCP) | 6 types (office traffic, DHCP, DNS, inbound block, VPN, connections) | 23 types | [docs/modules/cisco-asa.md](docs/modules/cisco-asa.md) |
| Cisco Firepower | Syslog (TCP) | 14 types (web, FTP, SSH, SMB, RDP, DNS, VPN, mail, connections) | 28 types | [docs/modules/cisco-firepower.md](docs/modules/cisco-firepower.md) |
| Fortinet FortiGate | Syslog (TCP) | 10 types (traffic forward, web filter, DNS, email, inbound block, VPN, connections) | 24 types | [docs/modules/fortinet.md](docs/modules/fortinet.md) |
| Zscaler Web Gateway | Syslog (TCP) | 17 types (web, DNS, email, FTP, firewall, VPN, cloud app, DLP, sandbox) | 25 types | [docs/modules/zscaler.md](docs/modules/zscaler.md) |
| Apache httpd | Syslog (TCP) | 5 types | 12 attack types | [docs/modules/httpd.md](docs/modules/httpd.md) |
| Infoblox NIOS | Syslog (TCP) | 15 types | 11 types | [docs/modules/infoblox.md](docs/modules/infoblox.md) |
| Proofpoint Email | HTTP Collector | 1 type (delivered email) | 11 types | [docs/modules/proofpoint.md](docs/modules/proofpoint.md) |
| Google Workspace | HTTP Collector | *(not operational)* | *(not operational)* | [docs/modules/google-workspace.md](docs/modules/google-workspace.md) |

**Totals:** 377 unique threat event types and 420+ benign event types across all modules.

## Recent Changes

### Windows Events Module
- New module generating native Windows Security Event XML for XSIAM UEBA/Identity Analytics detection testing
- **WEC transport** — delivers events directly to the Broker VM via WS-Management (HTTPS/mutual TLS), bypassing the need for Filebeat/XDRC
- Multi-hostname simulation — generates events from 500+ simulated hostnames on a single machine, each with a unique `<Computer>` field
- Parallel internal threading — separate DC, workstation, and threat workers with output queue for consistent delivery
- 20 benign generators covering interactive logon, network share, RDP, service, cached, unlock, logoff, process creation, DC Kerberos, DC directory service, LDAP, NTLM, SQL, and web app access patterns
- 21 threat generators targeting 14+ XSIAM UEBA detections, 13 confirmed working
- Event XML validated field-by-field against real Windows events from production DCs (single quotes, lowercase GUIDs, `%{GUID}` ObjectName format, nanosecond timestamps, correct `%%` code rendering in message fields)
- 5136 directory service events use proper delete/add pairs (`%%14675`/`%%14674`) matching real AD modification patterns
- Filebeat transport removed — WEC is the primary transport for Windows events

### XSIAM Detection Completeness
- All brute force generators (10 across Okta, ASA, Check Point, Fortinet) now end with a successful login
- All password spray generators (3 in Okta) now end with one successful auth from a random target user
- All port scan generators (5 across ASA, Check Point, Firepower, Fortinet, Zscaler) now include 1-2 successful connections after blocked probes
- RDP lateral generators (Firepower, Zscaler) converted from all-blocked to blocked-then-success sequences

### Flask Dashboard
- Full web UI with real-time module control, metrics, event timeline, and threat breakdown
- Per-module and global rate sliders (logarithmic scale: 0.1/sec to 10/sec)
- Per-module and global threat level controls with live updates (no restart needed)
- Job scheduler for timed module start/stop, rate changes, and scenario execution
- Health check system validating all transport connections and credentials
- "Start All" correctly propagates both threat level and event rate to all modules
- Per-card threat level dropdowns stay in sync with backend state

### Performance
- Persistent TCP syslog connections — reuses a single socket per (host, port) instead of connect/send/close per message
- Cached boto3 S3 client — reuses HTTPS connection pool instead of creating a new session per upload
- Rate-aware worker loop subtracts elapsed time from sleep interval so generate + send latency doesn't inflate cycle time

### GCP Cloud Audit Logs
- @type proto annotations auto-injected into request/response bodies via centralized lookup table
- Long-Running Operation (LRO) support — async operations produce paired first/last audit entries with shared operation IDs
- 6 new benign generators (Dataproc, Cloud Scheduler, Cloud Tasks, Firestore)
- New threat generators: OAuth consent screen abuse, budget alert deletion
- Workspace login failures diversified to 6 variants (wrong password, invalid TOTP, security key timeout, SAML failure, account suspended, device compliance)
- Benign permission denied generator with 6 denial variants across storage, compute, bigquery, secretmanager, iam, cloudkms

### Threat Classification
- Removed benign events that were incorrectly registered as threats: AWS `ASSUME_ROLE_WITH_SAML`, GCP `WORKSPACE_LOGIN_SUCCESS`/`WORKSPACE_LOGIN_FAILURE`, Okta `benign_retry`/`mfa_factor_update`/`policy_rule_update`/`device_assigned`/`new_device_enrolled`/`zone_update`
- Threat names now indicate Tor involvement when it's the primary detection signal (e.g., `tor_zone_bypass_access`, `tor_admin_app_pivot`)
