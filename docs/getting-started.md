## Getting Started

Follow these steps to get the simulator up and running.

### Prerequisites

- **Python 3.10+** — developed and tested on 3.10; 3.11/3.12 also supported
- **Cortex XSIAM instance** with at least one data collection method configured:
  - Broker VM for Syslog-based modules (firewall, proxy, DNS, web server)
  - S3 bucket + SQS queue for the AWS module
  - HTTP Collector URL + API key for Okta, Proofpoint, and GCP
  - Google Cloud Pub/Sub topic + subscription for the GCP module

---

### Installation

1. Clone or download the repository into a local directory.
2. Confirm the directory structure:
   ```
   LogSim/
   ├── log_simulator.py
   ├── config.json
   ├── .env                  ← create this (see below)
   ├── modules/
   │   ├── aws.py
   │   ├── gcp.py
   │   ├── cisco_asa.py
   │   └── ...
   ├── terraform/
   │   └── gcp_pubsub/
   └── CloudFormation/
       └── S3LogSim.yaml
   ```
3. Install Python dependencies (see below).

---

### Python Dependencies

#### Core — required for all deployments

```bash
pip install requests python-dotenv
```

| Package | Used by |
|---|---|
| `requests` | HTTP Collector transport (Okta, Proofpoint, GCP, Google Workspace) |
| `python-dotenv` | Loads `.env` secrets into the runtime environment |

#### AWS module — required only when using the `aws` module

```bash
pip install boto3
```

| Package | Used by |
|---|---|
| `boto3` | Writes gzip-compressed CloudTrail JSON to the configured S3 bucket |

> **IAM requirement:** The AWS IAM user (created by the CloudFormation stack) needs `s3:PutObject` on the log bucket. The CloudFormation template creates this automatically — see [CloudFormation setup in Configuration](configuration.md#aws-s3-setup-cloudformation--recommended).

#### GCP module — required only when using the `gcp` module

```bash
pip install google-cloud-pubsub
```

| Package | Used by |
|---|---|
| `google-cloud-pubsub` | Publishes single-event JSON LogEntry objects to Google Cloud Pub/Sub |

> **Auth requirement:** A GCP service account key with `roles/pubsub.publisher` on the topic. The Terraform template creates this automatically — see [Terraform setup in Configuration](configuration.md#gcp-pubsub-setup-terraform--recommended).

#### All dependencies at once

```bash
pip install requests python-dotenv boto3 google-cloud-pubsub
```

On Debian/Ubuntu you can use system packages for the core libraries:
```bash
apt install python3-requests python3-dotenv
pip install boto3 google-cloud-pubsub
```

---

### .env File

Create a `.env` file at the **project root** (same directory as `log_simulator.py`). This file stores all secrets and environment-specific values. It must **never** be committed to source control — add `.env` to your `.gitignore`.

Format: one `KEY=value` per line, no spaces around `=`, no quotes required (but allowed).

Below is a complete example showing every supported key. Only include the sections relevant to the modules you are running.

```bash
# =============================================================================
# TRANSPORT — SYSLOG
# Required for all syslog-based modules:
#   Cisco ASA, Cisco Firepower, Check Point, Fortinet, Zscaler,
#   Apache httpd, Infoblox
# =============================================================================

# IP address or hostname of your XSIAM Broker VM running the syslog listener
SYSLOG_HOST=10.0.0.1


# =============================================================================
# TRANSPORT — HTTP COLLECTOR
# Required for HTTP-based modules: Okta, Proofpoint
# The base URL is shared; each module uses its own API key.
# =============================================================================

# XSIAM HTTP Collector endpoint — from Settings > Data Sources > HTTP Collector
# Format: https://api-<tenant>.xdr.<region>.paloaltonetworks.com/logs/v1/event
HTTP_COLLECTOR_URL=https://api-myorg.xdr.us.paloaltonetworks.com/logs/v1/event

# API key for the Okta HTTP Collector (generated in XSIAM when you create the HTTP collector)
OKTA_KEY=your-okta-collector-api-key-here

# API key for the Proofpoint HTTP Collector
PROOFPOINT_KEY=your-proofpoint-collector-api-key-here


# =============================================================================
# AWS MODULE
# Required for the aws module. All values come from the CloudFormation stack
# outputs — see docs/configuration.md for setup instructions.
# =============================================================================

# S3 bucket name where simulated CloudTrail logs are written
# CloudFormation output: S3BucketName
s3_bucket_name=my-logsim-cloudtrail-bucket

# Your 12-digit AWS account ID (used to build the correct S3 key path)
aws_account_id=123456789012

# AWS region where the bucket lives (e.g. us-east-1, eu-west-1)
aws_region=us-east-1

# IAM access key for the LogSimulator IAM user
# CloudFormation output: LogSimulatorAccessKeyId
aws_access_key_id=AKIAIOSFODNN7EXAMPLE

# IAM secret key for the LogSimulator IAM user
# CloudFormation output: LogSimulatorSecretAccessKey
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY


# =============================================================================
# GCP MODULE
# Required for the gcp module. All values are generated automatically by the
# Terraform apply_and_configure.sh script — see docs/configuration.md.
# =============================================================================

# GCP project ID that owns the Pub/Sub topic (short project ID, not project number)
GCP_PROJECT_ID=my-org-siem-prod

# Pub/Sub topic name only — NOT the full resource path
# Correct:   xsiam-audit-logs
# Incorrect: projects/my-org-siem-prod/topics/xsiam-audit-logs
GCP_PUBSUB_TOPIC=xsiam-audit-logs

# --- Authentication: choose ONE of the following two options ---

# Option A (recommended): Inline service account key as compact single-line JSON.
# The Terraform script writes this automatically. If setting manually, collapse
# the downloaded key JSON to one line — the \n sequences in private_key must
# remain as two-character escape sequences, not actual newlines.
GCP_SERVICE_ACCOUNT_KEY_JSON={"type":"service_account","project_id":"my-org-siem-prod","private_key_id":"abc123def456","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq...\n-----END PRIVATE KEY-----\n","client_email":"logsim-publisher@my-org-siem-prod.iam.gserviceaccount.com","client_id":"123456789","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token"}

# Option B (alternative): Path to the service account key file on disk.
# Use this if you prefer file-based credentials instead of the inline JSON above.
# Comment out GCP_SERVICE_ACCOUNT_KEY_JSON and uncomment this line instead.
# GOOGLE_APPLICATION_CREDENTIALS=/path/to/logsim-publisher-key.json
```

> **Security note:** The `.env` file contains credentials. Protect it with `chmod 600 .env` on Linux/macOS. Never commit it to source control.


Inside XSIAM you will need to configure your BrokerVM Syslog applets with the following config (adjust ports to match the config in the Json.config)

Port / Protocol / Format / Vendor / Product

    Port 1513 /   TCP     Autodetect
    Port 1514 /   TCP   / CISCO /  Cisco   / ASA
    Port 1515 /   TCP   / RAW   /  apache  / httpd
    Port 1516 /   TCP   / RAW   /  infoblox / infoblox
    Port 514  /   TCP    Autodetect

---

### Quick Verification

After creating your `.env` and installing dependencies, verify the setup:

```bash
# Confirm Python version
python3 --version

# Confirm all packages are importable
python3 -c "import requests, dotenv, boto3, google.cloud.pubsub_v1; print('All OK')"

# Run the simulator
python3 log_simulator.py
```

On first run the simulator will:
1. Load `.env` and `config.json`
2. Auto-discover all modules in `modules/`
3. Attempt to fetch live Tor exit nodes (falls back to `tor_exit_nodes` in `config.json` on failure)
4. Display a menu to select run mode and threat level
