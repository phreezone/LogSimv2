# XSIAM High-Fidelity Log Simulator

A modular, high-fidelity log simulation tool for **Palo Alto Networks Cortex XSIAM** — generates realistic logs to test XDM mapping, analytics baselines, detection rules, and multi-stage attack scenarios.

## Core Features

- **Modular Architecture** — each log source is a self-contained Python module; the simulator auto-discovers any module in `modules/`
- **Centralized Configuration** — all settings (IPs, users, hostnames, threat intel, transport) in a single `config.json`
- **Multiple Transports** — Syslog (TCP), HTTP Collector, AWS S3, Google Cloud Pub/Sub
- **Dynamic Threat Levels** — from Benign Traffic Only to Insane; controls threat event frequency
- **Correlated Attack Scenarios** — 17 pre-built multi-module kill chains (phishing, cloud pentest, ransomware precursor, AiTM session hijack, VPN compromise, web app compromise, insider threat, DNS C2, and more)
- **Live Threat Intel** — fetches Tor exit nodes on startup for realistic indicators

## Quick Start

1. [Install dependencies and create your `.env` file](docs/getting-started.md)
2. Run: `python log_simulator.py`
3. Select **Mode 1** (continuous background + threats), **Mode 2** (single attack scenario), or **Mode 3** (specific named threat)

> `config.json` ships pre-configured and does not need to be edited. All environment-specific values (project IDs, account IDs) are read from `.env` automatically at startup. See [Configuration](docs/configuration.md) for the full reference.

See [How to Run](docs/how-to-run.md) for full details.

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
| AWS CloudTrail | S3 | 66+ event types across 15 AWS services | 34 named threat scenarios | [docs/modules/aws.md](docs/modules/aws.md) |
| GCP Cloud Audit Logs | Pub/Sub | 38 event types | 71 named threat scenarios | [docs/modules/gcp.md](docs/modules/gcp.md) |
| Check Point Firewall | Syslog (TCP) | 4 types | 20 types | [docs/modules/checkpoint.md](docs/modules/checkpoint.md) |
| Cisco ASA Firewall | Syslog (TCP) | 4 types | 21 types | [docs/modules/cisco-asa.md](docs/modules/cisco-asa.md) |
| Cisco Firepower | Syslog (TCP) | 4 types | 17 types | [docs/modules/cisco-firepower.md](docs/modules/cisco-firepower.md) |
| Fortinet FortiGate | Syslog (TCP) | 7 types | 19 types | [docs/modules/fortinet.md](docs/modules/fortinet.md) |
| Apache httpd | Syslog (TCP) | 5 types | 12 attack types | [docs/modules/httpd.md](docs/modules/httpd.md) |
| Infoblox NIOS | Syslog (TCP) | 15 types | 11 types | [docs/modules/infoblox.md](docs/modules/infoblox.md) |
| Okta SSO | HTTP Collector | ~100 event types | 88 types | [docs/modules/okta.md](docs/modules/okta.md) |
| Proofpoint Email | HTTP Collector | 1 type | 11 types | [docs/modules/proofpoint.md](docs/modules/proofpoint.md) |
| Zscaler Web Gateway | Syslog (TCP) | 4 types | 16 types | [docs/modules/zscaler.md](docs/modules/zscaler.md) |
| Google Workspace | HTTP Collector | *(not operational)* | *(not operational)* | [docs/modules/google-workspace.md](docs/modules/google-workspace.md) |
