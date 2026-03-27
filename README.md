# XSIAM High-Fidelity Log Simulator

A modular, high-fidelity log simulation tool for **Palo Alto Networks Cortex XSIAM** — generates realistic logs to test XDM mapping, analytics baselines, detection rules, and multi-stage attack scenarios.

## Core Features

- **Modular Architecture** — each log source is a self-contained Python module; the simulator auto-discovers any module in `modules/`
- **Centralized Configuration** — all settings (IPs, users, hostnames, threat intel, transport) in a single `config.json`
- **Multiple Transports** — Syslog (TCP), HTTP Collector, AWS S3, Google Cloud Pub/Sub
- **Dynamic Threat Levels** — from Benign Traffic Only to Insane; controls threat event frequency
- **Correlated Attack Scenarios** — 13 pre-built multi-module kill chains (phishing, cloud pentest, insider threat, DNS C2, and more)
- **Live Threat Intel** — fetches Tor exit nodes on startup for realistic indicators

## Quick Start

1. [Install dependencies and configure your environment](docs/getting-started.md)
2. [Set up config.json](docs/configuration.md)
3. Run: `python log_simulator.py`
4. Select **Mode 1** (continuous background + threats) or **Mode 2** (single attack scenario)

See [How to Run](docs/how-to-run.md) for full details.

## Documentation

| Topic | File |
|---|---|
| Installation & `.env` setup | [docs/getting-started.md](docs/getting-started.md) |
| `config.json` reference (all sections) | [docs/configuration.md](docs/configuration.md) |
| Running modes & available modules | [docs/how-to-run.md](docs/how-to-run.md) |
| Attack scenarios (13 kill chains) | [docs/attack-scenarios.md](docs/attack-scenarios.md) |
| Adding a new module | [docs/extensibility.md](docs/extensibility.md) |

## Module Reference

| Module | Transport | Benign Events | Threat Events | Reference |
|---|---|---|---|---|
| AWS CloudTrail | S3 | Yes | Yes | [docs/modules/aws.md](docs/modules/aws.md) |
| GCP Cloud Audit Logs | Pub/Sub | 38 types | 71 types | [docs/modules/gcp.md](docs/modules/gcp.md) |
| Check Point Firewall | Syslog (TCP) | Yes | Yes | [docs/modules/checkpoint.md](docs/modules/checkpoint.md) |
| Cisco ASA Firewall | Syslog (TCP) | Yes | Yes | [docs/modules/cisco-asa.md](docs/modules/cisco-asa.md) |
| Cisco Firepower | Syslog (TCP) | Yes | Yes | [docs/modules/cisco-firepower.md](docs/modules/cisco-firepower.md) |
| Fortinet FortiGate | Syslog (TCP) | Yes | Yes | [docs/modules/fortinet.md](docs/modules/fortinet.md) |
| Apache httpd | Syslog (TCP) | Yes | Yes | [docs/modules/httpd.md](docs/modules/httpd.md) |
| Infoblox NIOS | Syslog (TCP) | 15 types | 11 types | [docs/modules/infoblox.md](docs/modules/infoblox.md) |
| Okta SSO | HTTP Collector | ~100 types | 88 types | [docs/modules/okta.md](docs/modules/okta.md) |
| Proofpoint Email | HTTP Collector | Yes | Yes | [docs/modules/proofpoint.md](docs/modules/proofpoint.md) |
| Zscaler Web Gateway | Syslog (TCP) | Yes | Yes | [docs/modules/zscaler.md](docs/modules/zscaler.md) |
| Google Workspace | HTTP Collector | Yes | Yes | [docs/modules/google-workspace.md](docs/modules/google-workspace.md) |
