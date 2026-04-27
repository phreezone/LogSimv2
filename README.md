# XSIAM High-Fidelity Log Simulator

A modular, high-fidelity log simulation tool for **Palo Alto Networks Cortex XSIAM** — generates realistic logs to test XDM mapping, analytics baselines, UEBA behavioral profiles, detection rules, and multi-stage attack scenarios.

## Core Features

- **Modular Architecture** — each log source is a self-contained Python module; the simulator auto-discovers any module in `modules/`
- **Flask Web Dashboard** — real-time UI for controlling all modules, adjusting threat levels and event rates, firing individual threats, scheduling jobs, and monitoring health checks
- **Centralized Configuration** — all settings (IPs, users, hostnames, threat intel, transport) in a single `config.json`
- **Multiple Transports** — Syslog (TCP with persistent connections), HTTP Collector, AWS S3 (cached client), Google Cloud Pub/Sub
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

### Run with Docker

The repo ships a `Dockerfile` and `docker-compose.yml` that launch the Flask dashboard by default — visible in your browser on the host.

```sh
cp .env.example .env       # fill in your endpoints / credentials
docker compose up -d       # build and start the dashboard
open http://localhost:5000 # macOS; otherwise just open the URL
```

> **macOS port 5000 conflict:** AirPlay Receiver binds port 5000 by default. Either disable it (System Settings → General → AirDrop & Handoff → AirPlay Receiver) or override the host-side port: `LOGSIM_HOST_PORT=5050 docker compose up -d` and browse to `http://localhost:5050`.

Edit `config.json` on the host and restart the container to pick up changes (it's bind-mounted read-only). To run the original interactive CLI instead of the WebUI, use the `cli` profile:

```sh
docker compose run --rm logsim-cli
```

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

**Totals:** 356 unique threat event types and 400+ benign event types across all modules.

## Recent Changes

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
