# XSIAM High-Fidelity Log Simulator

A modular, high-fidelity log simulation tool for **Palo Alto Networks Cortex XSIAM** — generates realistic logs to test XDM mapping, analytics baselines, UEBA behavioral profiles, detection rules, and multi-stage attack scenarios.

## Core Features

- **Modular Architecture** — each log source is a self-contained Python module; the simulator auto-discovers any module in `modules/`
- **Flask Web Dashboard** — real-time UI for controlling all modules, adjusting threat levels and event rates, firing individual threats, scheduling jobs, and monitoring health checks
- **Centralized Configuration** — all settings (IPs, users, hostnames, threat intel, transport) in a single `config.json`
- **Generated High-Cardinality Values** — threat domains, file names, cloud resource identifiers and browser user-agents are *composed* per event rather than drawn from fixed lists, so a month-long run never recycles the same 25 C2 domains or 26 EC2 instance IDs. The curated `config.json` pools remain in circulation as a recognisable head for manual hunting — see [docs/value-cardinality.md](docs/value-cardinality.md)
- **Multiple Transports** — Syslog (TCP with persistent connections), HTTP Collector, AWS S3 (cached client), Google Cloud Pub/Sub, WEC (Windows Event Collector via WS-Management), and the **XSIAM Cribl receiver** for the Microsoft Entra ID / Office 365 feeds (direct, no Cribl Stream instance or Microsoft tenant needed — see [docs/modules/microsoft-entra.md](docs/modules/microsoft-entra.md#transport-the-cribl-receiver-no-cribl-instance-needed))
- **Microsoft Entra ID & Office 365** — seven native-shaped feeds (Graph sign-ins and directory audit, O365 Azure AD, Exchange Online, SharePoint/OneDrive, DLP, General) plus cross-feed identity campaigns, all on the same users as every other module
- **Dynamic Threat Levels** — six levels from Benign Traffic Only to Insane; controls threat event frequency per module
- **XSIAM Detection-Ready Sequences** — attack generators produce complete detection patterns (e.g., failed logins followed by success) that trigger XSIAM UEBA analytics out of the box
- **Correlated Attack Scenarios** — 23 pre-built multi-module kill chains (phishing, cloud pentest, ransomware precursor, AiTM session hijack, VPN compromise, web app compromise, insider threat, DNS C2, and more) — including 6 *advanced linked kill chains* (Domain Dominance, Beaconing Implant, Server Breach → Cloud, Cloud Ransomware, Perimeter Intrusion, Identity Attack → Cloud) built around a single pivot entity with full alert-field enrichment
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
- **Fire Individual Threats** — fire any threat that is built to trigger an XSIAM analytics alert, on demand. The dropdown groups threats by the analytic each one targets, and the result names the alert to look for. Threats with no analytic behind them (policy blocks, signature hits, hunt-only patterns) still run in long-running sessions but are not offered here
- **Attack Scenarios** — run any of the 23 pre-built multi-module kill chains from the UI
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

The intervals apply per module. The **Microsoft Entra / Office 365** feeds pace threats
differently: as *episodes* from a wall-clock Poisson process, after a 500-record benign
warmup. Episodes per module per hour: Realistic 0.03 (about 5 a day across the seven
feeds), Elevated 0.15, High 0.6, Extreme 2.0, Insane 6.0. See
[docs/modules/microsoft-entra.md](docs/modules/microsoft-entra.md#threat-model).

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
| `as_rep_roasting` | Excessive TGT requests for users that do not require Kerberos pre-authentication | Medium | T1558.004 |
| `dmsa_privesc` | Possible Privilege Escalation using Delegated MSA account attempt | High | T1098 |
| `sensitive_password_reset` | Sensitive account password reset attempt for the first time | Medium | T1098 |

`as_rep_roasting`, `dmsa_privesc` and `sensitive_password_reset` were `wip_`-prefixed until
2026-09-29, when their detections were found firing in the tenant. The old names still work.

**WIP Detections** (prefixed with `wip_` — generating events but not yet seen triggering their detection):

| Generator | Reason |
|---|---|
| `wip_adminsdholder_acl_modification` | Identity graph dependent — needs real AD object GUIDs/SIDs |
| `wip_password_never_expires` | Training period — needs identity graph baseline |
| `wip_irregular_service_tgs` | Only ever raises the weak-encryption ticket alert that `multiple_service_tickets` owns; `irregular_tgt_burst` covers its intended detection. Background only — not offered on demand |
| `wip_priv_cert_request` | Not yet investigated |
| `wip_sccm_container_recon` | Environment dependent — requires SCCM/ConfigMgr deployment |

**Endpoint execution telemetry** (for the advanced linked kill chains): the module also generates **4688 process trees** (Office → PowerShell → cmd → LOLBin, with real parent/child linkage and command lines), **4697** (a service was installed — malware persistence), and **1102** (the audit log was cleared — anti-forensics). Emitted via the `PROCESS_TREE`, `SERVICE_INSTALL`, and `CLEAR_LOGS` scenario events. Verified to ingest and parse in `microsoft_windows_raw`. *Note:* the Broker VM's WEC subscription must forward these Event IDs for them to reach XSIAM — see the Subscription Filter note below.

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
WEC_BROKER_URL=https://<your-broker-vm-hostname>:5986/wsman
WEC_PFX_PATH=/path/to/broker-vm-cert.pfx
WEC_PFX_PASSWORD=your-pfx-export-password
```

The IssuerCA thumbprint is not needed: LogSim authenticates with the PFX alone. An older
`WEC_ISSUER_CA` setting is harmless, but nothing reads it.

In `config.json`, set the transport to `"wec"` in the `windows_events_config` section:

```json
{
    "windows_events_config": {
        "transport": "wec"
    }
}
```

### Broker VM Subscription Filter

Configure the Broker VM WEC subscription to accept **all Event IDs** rather than listing
specific ones. LogSim generates 45+ Event IDs, and accepting everything avoids updating
the filter every time a generator is added. Include these channels:

- **Security**: logon, Kerberos, account and group management, object access, AD
  replication and trusts, certificate services, share access (5140/5145), scheduled tasks
  (4698/4699), service install (4697), log clear (1102).
- **System**: 7045, service installed (Service Control Manager).
- **Microsoft-Windows-PowerShell/Operational**: 4104 script-block logging (Exchange
  mailbox-export threats).

A Security-only filter silently drops the 7045 and 4104 events.

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
| Attack scenarios (23 kill chains) | [docs/attack-scenarios.md](docs/attack-scenarios.md) |
| Training Mode (deterministic bulk stage + live stream) | [docs/training-mode.md](docs/training-mode.md) |
| Adding a new module | [docs/extensibility.md](docs/extensibility.md) |
| Value cardinality (generated domains, files, cloud IDs, user-agents) | [docs/value-cardinality.md](docs/value-cardinality.md) |
| Microsoft Entra ID feeds, the Cribl receiver transport, identity campaigns | [docs/modules/microsoft-entra.md](docs/modules/microsoft-entra.md) |
| Microsoft 365 workloads (Exchange, SharePoint/OneDrive, DLP, General) | [docs/modules/microsoft-365.md](docs/modules/microsoft-365.md) |
| Microsoft detection research and coverage | [MICROSOFT_DETECTION_CATALOG.md](MICROSOFT_DETECTION_CATALOG.md) |
| Firewall & VPN analytics — what each firewall can fire, and why the rest can't | [docs/firewall-analytics.md](docs/firewall-analytics.md) |
| Firewall management plane (device admin, config changes, logging suppression, SNMP) | [docs/firewall-management-plane.md](docs/firewall-management-plane.md) |

## Module Reference

| Module | Transport | Benign Event Types | Threat Event Types | Reference |
|---|---|---|---|---|
Threat counts are named threats (`get_threat_names()`), with the number offered on demand
from the dashboard in brackets (see [On-Demand Threats](#on-demand-threats--analytics-only)).

| Module | Transport | Benign Event Types | Threat Event Types | Reference |
|---|---|---|---|---|
| Windows Events | WEC (WS-Management) | 25 generators (interactive logon, network share + server-side 5140/5145 share audit, RDP, service, cached, unlock, logoff, process 4688/4689, DC Kerberos, DC directory service, LDAP, NTLM, SQL, web app, audited file access, account unlock/disable, updater scheduled tasks 4698, service installs 4697+7045) | 39 (27 on demand) + endpoint execution (4688 trees, 4697, 1102) and SMB remote execution (PsExec/smbexec, atexec, share enumeration) | [docs/modules/windows.md](docs/modules/windows.md) |
| AWS CloudTrail | S3 | 69 event types across 15+ AWS services | 70 (61 on demand) | [docs/modules/aws.md](docs/modules/aws.md) |
| GCP Cloud Audit Logs | Pub/Sub | 42 event types with @type proto annotations and LRO operation pairs | 75 (60 on demand) | [docs/modules/gcp.md](docs/modules/gcp.md) |
| Okta SSO | HTTP Collector | 183+ event types across auth, SSO, MFA, lifecycle, policy, OAuth2, IAM, device, and zone domains | 83 (42 on demand), incl. break-glass account use | [docs/modules/okta.md](docs/modules/okta.md) |
| Azure AD / Entra sign-ins | Cribl receiver | Graph signIns: non-interactive token refresh, interactive sign-in, routine failures; Event Hub copies + Graph API activity to `msft_azure_raw` | 37 | [docs/modules/microsoft-entra.md](docs/modules/microsoft-entra.md) |
| Azure AD / Entra directory audit | Cribl receiver | Graph directoryAudits: user, group, app and device maintenance, admin actions in business hours; Graph requests behind threat changes | 39 | [docs/modules/microsoft-entra.md](docs/modules/microsoft-entra.md) |
| Office 365 Azure AD | Cribl receiver | Management Activity RecordType 15 sign-ins / 8 directory ops | 14 | [docs/modules/microsoft-entra.md](docs/modules/microsoft-entra.md) |
| Office 365 Exchange Online | Cribl receiver | MailItemsAccessed, Send, Move, inbox rules, light admin | 28 | [docs/modules/microsoft-365.md](docs/modules/microsoft-365.md) |
| Office 365 SharePoint / OneDrive | Cribl receiver | File and sharing operations, business-hours weighted; Graph requests behind threat activity | 19 | [docs/modules/microsoft-365.md](docs/modules/microsoft-365.md) |
| Azure Activity | Cribl receiver | 140 threat scenarios across ARM, AKS kube-audit, Storage, Key Vault, and AI data-plane; all 186 Cortex Azure Audit Log entries mapped with adjacent Entra/Graph/M365 generators (three names verified in the 2026-10-23 smoke run) | 140 Azure Activity scenarios | [docs/modules/azure-activity.md](docs/modules/azure-activity.md) |
| Office 365 DLP | Cribl receiver | Low-severity notify-only rule matches | 4 | [docs/modules/microsoft-365.md](docs/modules/microsoft-365.md) |
| Office 365 General | Cribl receiver | Copilot interactions, Power BI views | 2 | [docs/modules/microsoft-365.md](docs/modules/microsoft-365.md) |
| Azure AD Identity Protection | Cribl receiver | Entra ProvisioningLogs (SCIM/HR sync) and UserRiskEvents/ServicePrincipalRiskEvents — benign identity-protection baseline | 0 (benign only) | [docs/modules/microsoft-entra.md](docs/modules/microsoft-entra.md) |
| Identity Threat Campaigns | *(coordinator — Cribl + WEC)* | *(none)* | 21 cross-feed identity kill chains, run from **Threats & Scenarios → Run Attack Scenario** (no module card) | [docs/modules/microsoft-entra.md](docs/modules/microsoft-entra.md#azuread_campaigns--cross-feed-identity-campaigns) |
| Check Point Firewall | Syslog (TCP) | 5 types (web, DNS, VPN session, internal traffic, connection logs) + management plane (SmartConsole admin sessions, nightly backup, SNMP polling) | 45 (29 on demand) | [docs/modules/checkpoint.md](docs/modules/checkpoint.md) |
| Cisco ASA Firewall | Syslog (TCP) | 6 types (office traffic, DHCP, DNS, inbound block, VPN, connections) + management plane (CLI admin sessions, nightly backup, SNMP polling) | 38 (29 on demand) | [docs/modules/cisco-asa.md](docs/modules/cisco-asa.md) |
| Cisco Firepower | Syslog (TCP) | 14 types (web, FTP, SSH, SMB, RDP, DNS, VPN, mail, connections) + management plane | 46 (30 on demand) | [docs/modules/cisco-firepower.md](docs/modules/cisco-firepower.md) |
| Fortinet FortiGate | Syslog (TCP) | 10 types (traffic forward, web filter, DNS, email, inbound block, VPN, connections) + management plane | 49 (32 on demand) | [docs/modules/fortinet.md](docs/modules/fortinet.md) |
| Zscaler Web Gateway | Syslog (TCP) | 17 types (web, DNS, email, FTP, firewall, VPN, cloud app, DLP, sandbox) | 38 (28 on demand) | [docs/modules/zscaler.md](docs/modules/zscaler.md) |
| Apache httpd | Syslog (TCP) | 5 types | 12 attack types | [docs/modules/httpd.md](docs/modules/httpd.md) |
| Infoblox NIOS | Syslog (TCP) | 15 types | 11 types | [docs/modules/infoblox.md](docs/modules/infoblox.md) |
| Proofpoint Email | HTTP Collector | 1 type (delivered email) | 11 types | [docs/modules/proofpoint.md](docs/modules/proofpoint.md) |
| XDR Attack Orchestration | WinRM (real endpoint) + network transports | *(coordinator — real Atomic Red Team techniques on a live Cortex-agent box + synthetic network logs pinned to its identity)* | *Phase 1 — foundation validated; stories in progress* | [docs/modules/xdr-orchestration.md](docs/modules/xdr-orchestration.md) |

**Totals:** 660 named threats across the 21 log-source modules, 338 of them offered on demand, plus 21 cross-feed identity campaigns.

## Recent Changes

### Microsoft Entra ID & Office 365 — Seven Native Feeds over the Cribl Receiver

New modules emit Microsoft records in the shapes XSIAM's own collectors store:
- Graph sign-ins and Graph directory audit.
- O365 Management Activity for the Azure AD, Exchange Online, SharePoint/OneDrive, DLP
  and General workloads.

All share LogSim's user model, so an Entra sign-in, a Windows logon and a Zscaler session
belong to the same person. Details: [Entra](docs/modules/microsoft-entra.md) and
[Microsoft 365](docs/modules/microsoft-365.md).

- **New transport `cribl`.** Records post straight into XSIAM's integrated Cribl receiver
  (`integrations/cribl_direct.py`), each under its feed's catalog Source-Identifier, and
  land *parsed* in the native dataset. They're eligible for analytics once the Microsoft
  content packs are installed. No Cribl Stream instance or Microsoft tenant is involved;
  set `CRIBL_COLLECTOR_URL` and `CRIBL_TOKEN` from XSIAM's free Cribl integration (see
  `.env.example`).
- **Episode-based threat rate.** Microsoft threats fire as wall-clock Poisson episodes
  after a benign warmup, so rate doesn't depend on poll frequency or burst size.
- **Identity Threat Campaigns** (Threats & Scenarios → Run Attack Scenario): 21 cross-feed kill chains (BEC, ransomware,
  OAuth abuse, golden SAML, AiTM token theft, hybrid on-prem→cloud, and more) that span
  the Graph, O365 and Windows datasets. They're sent over Cribl and WEC together.
- **Validation:** `_local_validation/threat_harness.py` fires a threat, confirms
  ingestion and polls for the alert. Confirmed firing so far: *Suspicious Azure AD
  Administrator Role assignment*, *Rare unverified domain addition to Azure AD*, *A
  successful Azure domain federation settings modification*.

### Firewall Management Plane — Device Administration on All Four Firewalls

ASA, FortiGate, Check Point and Firepower now carry a device-administration baseline
from one shared operations team (`modules/mgmt_plane.py`): admins on an admin subnet,
jump hosts, a nightly config-backup job and an SNMP poller. On top of that are five
threats from the management-plane detection patterns:
- admin login from an unexpected source;
- configuration or route change (rogue next hop, permit-any, capture/tunnel);
- logging suppressed for a window — the device really goes silent, then re-enables;
- scripted config harvesting across several devices;
- SNMP from anything but the poller.

The vendor message IDs and where each lands in XSIAM are in
[docs/firewall-management-plane.md](docs/firewall-management-plane.md).

### Windows — SMB Remote Execution, and Record IDs That Follow Time

- **New events:** share access 5140/5145, scheduled task created/deleted 4698/4699, and
  System-channel service install 7045, alongside 4697.
- **New threats:** PsExec / Impacket smbexec lateral movement, atexec remote scheduled
  task, SMB share enumeration, malicious service install.
- **New baseline:** server-side share audit on every file-server logon, plus updater
  scheduled tasks and service installs a few times a month per host, with stable
  per-host task names.
- **Time-ordered release.** Workers schedule events and a release thread hands each one
  out when its timestamp arrives, assigning its `EventRecordID` at that moment. Per host
  and channel, IDs now rise with time as on a real machine; about 16% of consecutive IDs
  used to run backwards. A sequence arrives over its own duration: a process's 4689 exit
  lands when the process exits.
- **Single-threaded mode removed.** The per-host workers are the only ambient path, and
  `parallel_hosts` is no longer read. The subscription filter must now include the
  System and PowerShell/Operational channels (see
  [Broker VM Subscription Filter](#broker-vm-subscription-filter)).

### Timing — Nothing Is Stamped in the Future

A debug pass found multi-event sequences built as "start now, add gaps", which shipped
their tails ahead of wall clock:
- Windows process exits and AdminSDHolder chains: ~9 minutes ahead.
- Okta MFA bombing: ~90 seconds ahead.
- Okta "SSO at an unusual time": hours ahead between 00:00 and 05:00 UTC.

Every generator now ends at or before now, and training packs keep time-of-day events
inside their window. Rates were also corrected:
- FortiGate's legacy admin login: from ~3,500 to ~40 a day.
- Windows software-install registrations: from ~1,300 to a few a month per host.

Guarded by `_local_validation/mgmt_timing_cardinality_audit.py` and
`_local_validation/windows_smoke.py`.

### Okta — Break-Glass Account Use

`break_glass_login`: an emergency-access account (`okta_config.break_glass_accounts`)
signs in password-only from a non-corporate address, opens the Admin Console, then
grants Super Administrator to a regular user or creates an API token. These accounts
exist only for an IdP outage, so any authentication by one is the finding.

### On-Demand Threats — Analytics Only

The dashboard's **Fire Individual Threat** panel, the MCP `list_module_threats` /
`fire_event` tools and the CLI "specific threat" menu now offer only threats that are built
to trigger an XSIAM analytics alert (XDR Analytics or Analytics BIOC). Everything else —
signature and policy blocks, correlation-rule and hunt-only patterns, benign baselines —
keeps running in long-running module sessions, just not on demand.

- **One mapping per module.** Each threat either names the analytic it targets or is
  background-only: `ANALYTIC_ALERTS` in AWS, GCP, Okta and Windows; the existing
  `analytic` / `xsiam_alert` fields in the firewall modules, which ASA now shares via
  `get_threat_info()`. `modules/threat_catalog.py` reads both. Mappings were made against
  the published Cortex analytics list for each data source and 90 days of tenant alerts;
  alert names are the tenant's own wording where the alert has been seen there.
- **The dropdown groups threats by target analytic**, lists only modules with at least one
  (with a count), and a successful fire reports the alert to look for.
- **Proofpoint, Infoblox and Apache httpd offer nothing on demand.** Cortex publishes no
  analytics for those data sources, and none has fired from them in the tenant; their
  alerts come from correlation rules and threat intel.
- **`POST /api/modules/<name>/fire` rejects** a threat with no analytic (HTTP 400).
  `GET /api/modules/<name>/threats` still returns `threats` (event names) and adds
  `options` (`[{event, alert}]`).
- **The `[Non-Analytic] ` prefix is retired.** It was only a dropdown hint. Old prefixed
  names are still accepted. Removing it also fixes ASA's threat counter, which never
  counted its non-analytic threats because the generator returned the unprefixed name.
- **Renamed:** Windows `wip_as_rep_roasting`, `wip_dmsa_privesc` and
  `wip_sensitive_password_reset` became `as_rep_roasting`, `dmsa_privesc` and
  `sensitive_password_reset`, since their detections now fire. The old names still dispatch.
- **Reclassified:** `ftp_large_exfil` (Firepower, Check Point, FortiGate) now targets
  *Large Upload (FTP)*, which fired from Firepower data. ASA `ldap_recon` is background-only,
  matching Firepower and Check Point: LDAP enumeration is an XDR-agent detection.

Coverage: 310 of 457 threats are offered on demand. Guarded by
`_local_validation/on_demand_catalog_check.py`, which fires every one of them through its
module (nothing is sent) and checks that each produces logs.

### Value Cardinality — Generated Domains, Files, Cloud IDs and User-Agents

Long runs previously recycled a small number of values, which quietly defeats every
detection that reasons about novelty ("never-seen host", "rare destination", "new C2
infrastructure", "uncommon user-agent"). Rarity cannot come from weighting a 25-entry
list, only from cardinality. Details and the full rationale in
[docs/value-cardinality.md](docs/value-cardinality.md).

- **Threat domains are composed, tokens preserved** — `modules/threat_domains.py` builds
  domains around 28 threat families (`command-control-relay.top`,
  `cdn.credential-stealer-api.icu`). Nine tokens are matched as literal substrings of
  these names by five correlation rules, so the family token is reproduced verbatim and is
  a **contract** — the token leads and everything else varies. ~850 distinct domains per
  1,000 draws, versus 25 fixed.
- **Four detections that could never fire now can** — the shipped pools had
  `phish-kit-host.ru` where the rules match `phishing-kit`, and
  `ransomware-payment-page.biz` where they match `ransomware-payload`. Near misses,
  two rules each.
- **File names and attachment types** — `modules/threat_files.py` composes business
  document names and malware lures with the content type always matching the extension.
  The malicious extension mix now spans the whole OR-chain the Proofpoint malware rule
  matches, including `.lnk` and `.iso` container delivery, which the old macro-document
  templates never produced.
- **Cloud identifiers** — `modules/cloud_ids.py` generates correctly-shaped AWS/GCP ids
  (`i-` + 17 hex, `AKIA`/`ASIA` keys, 12-digit accounts) and grows the `aws_config` pools
  at startup: instances 26 → 400, volumes 26 → 600, snapshots 26 → 900, GCP service
  accounts 5 → 60. VPCs deliberately stay in the low tens, because a real estate has few.
  Your own AWS account ID never changes — only *foreign* accounts vary.
- **Browser user-agents** — `modules/user_agents.py` composes agents with a realistic
  version spread. **Okta now reports each user's own device agent** instead of a random
  one per event, which previously made every user look like they owned 33 browsers —
  backwards for "new device for this user".
- **File-sharing destinations** — the shared `exfiltration_destinations` pool used by
  every network module grew from 25 to **60 real services**. They stay real rather than
  generated because the Infoblox unsanctioned-cloud-storage rule matches them as literals;
  three of its literals (`filebin`, `transfer.sh`, `send.now`) were absent from the
  project until now. Firepower's large upload/download generators moved onto this pool
  from a separate four-entry list, which also fixed a destination IP that was unrelated to
  the domain and invented hosts like `upload.pastebin.com`.
- **Per-host Windows LSASS PID** — was `584` on every host in the estate; now derived per
  host (stable across restarts, multiples of 4 as Windows allocates).
- **`infoblox_threats.generated_share`** (default `0.75`) tunes how much threat traffic is
  generated versus drawn from the curated pools. Set it to `0` to pin everything back to
  `config.json`. See [docs/configuration.md](docs/configuration.md).
- **Correctness fixes found while auditing** — `Windows NT 11.0` does not exist (Windows 11
  reports `NT 10.0`); Safari and macOS versions are now paired (Sequoia ships Safari 18,
  not 17); and a benign business sender can no longer be an adult or gambling domain.
- **Validation harnesses moved** to `_local_validation/`, so they can be excluded from a
  sync or release. Run them as `python _local_validation/<name>.py`.

### Correlation Rules — Replacements in `XSIAM imports/`

Five rules in `XSIAM imports/` are **replacements** for rules that could never fire. If you
have imported the originals into a tenant, the new versions are additive — import them,
confirm they fire, then disable or delete the originals.

| New rule | Replaces | Why the original could not fire |
|---|---|---|
| `Cisco Firepower - IPS Event with Critical Severity (v2)` | rule id **72** | Filtered `cefName = "Intrusion Detected"`. Real FTD/FMC CEF carries the eStreamer eNcore name `INTRUSION EVENT`; the tenant held no such value, ever. |
| `Cisco Firepower - Malicious File Transferred (v2)` | rule id **75** | Filtered `cefName = "Malicious File Detected"`. FTD emits `FireAMP Event`. |
| `Cisco ASA - High Volume of Failed Inbound Connections from One IP (v2)` | `... Denied Inbound Connections ...` | ANDed a `106023` raw match with `xdm.observer.action = "Deny"`. The ASA parser never sets that value — across 21,435 rows it produced only `Built`, `Teardown` and null. |
| `DNS C2 Kill Chain - NXDOMAIN Storm + Outbound Firewall Activity (v2)` | same name | Suppression named a column its own `fields` stage dropped, so it errored on every run; and it matched ASA `dst_interface = "inside"`, i.e. traffic *inbound* to the host, in a rule about outbound activity. |
| `GCP - API Access From External / Non-Corporate IP (v2)` | same name | Same suppression defect, plus it grouped by event description rather than by the caller, so the alert carried no address entity at all. |

Also corrected in the replacements: direction on the Firepower IPS rule (`src` is the
external attacker, so it maps to `action_remote_ip`, not `action_local_ip`), username
normalisation so `EXAMPLECORP\\user` and `user@examplecorp.com` group into one case, and
`cs3`/`cs4` no longer mapped as interfaces on FireAMP rows where they mean disposition.

Two authoring notes, learned the hard way and worth knowing if you write your own:

- A **CUSTOM-mapped rule needs an explicit `| fields` stage**. Without one it saves,
  validates, runs — and produces nothing, with no error.
- **`suppression_fields` must name output columns**, not `xdm.*` columns the query aliases
  away, or the rule fails every run.

### Advanced Linked Kill Chains & Enrichment
- **6 new advanced scenarios** (18–23), each built around a single pivot entity for clean case stitching: Domain Dominance, Beaconing Implant, Server Breach → Cloud, Cloud Ransomware, Perimeter Intrusion, and Identity Attack → Cloud — see [docs/attack-scenarios.md](docs/attack-scenarios.md)
- **New telemetry:** Windows 4697 (service install), 1102 (log cleared), and 4688 process trees; Zscaler web-layer C2 beacon (`zscaler_nssweblog_raw`); AWS KMS key destruction, IMDS/SSRF credential theft, and `AssumeRoleWithSAML` federation
- **Full alert-field enrichment** — IP-keyed DNS/SMB detections resolve the user via a 4624 network-logon binding (`actor_effective_username`); AWS identity-scenario stages pin the victim principal; user-less external-attacker rules left correctly user-less
- **Single-pivot pinning** — firewall (port scan / denied inbound / VPN brute force) and AWS (ransomware, SAML) generators honor a pinned attacker IP / principal so all stages of a chain group into one case
- **Cross-identity pre-staging** — Okta↔AWS and on-prem↔cloud chains carry the matching identity value on both sides, ready for XSIAM's identity-unification feature to merge them automatically

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
- Per-module and global rate sliders (logarithmic scale: 0.1/sec to 10,000/sec)
- Per-module and global threat level controls with live updates (no restart needed)
- Job scheduler for timed module start/stop, rate changes, and scenario execution
- Health check system validating all transport connections and credentials
- "Start All" correctly propagates both threat level and event rate to all modules
- Per-card threat level dropdowns stay in sync with backend state

### Performance
- **Batched HTTP collector and Cribl sends** — many events per request (newline-delimited / gzip NDJSON, ≤1,000 events and ≤1 MiB per request) instead of one request per event. Against a 50 ms-latency collector: HTTP 145 → ~19,000 events/s, Cribl 143 → ~9,400 events/s. One event per request also could never exceed the collector's 400 requests/s limit.
- **Per-transport sender lanes** — HTTP and Cribl have their own queues and sender pools (`BATCH_SEND_WORKERS`), so a slow collector no longer holds syslog behind it (1,500 syslog events beside an HTTP backlog: 10.4 s → 0.2 s)
- **Hot-path caches** — memoised identity-cohort lookups (Exchange generation 1,000 → 20,000 events/s; other Microsoft feeds 2.5–3×) and a once-per-session AWS IAM pool merge (1.5×)
- **Batched syslog writes** — syslog has its own sender lane and writes many newline-framed lines per TCP `sendall` (≤256 KB, lines never split), with a lock per (host, port) instead of one global lock. Local sink: 1 module 8,000 → ~170,000 events/s, 4 modules on 4 ports 7,000 → ~190,000 events/s
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
