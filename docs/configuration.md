# Configuration (config.json)

This file is the engine of the simulator. You must configure it with your environment's details. **Do not** check sensitive keys or IPs into public source control.

Here is a breakdown of the key sections:

## A. Global Simulator Settings

These settings control the simulator's overall behavior.

```json
{
  "syslog_port": 514,
  "base_event_interval_seconds": 1.5,
  "threat_generation_levels": {
    "Benign Traffic Only": 86400,
    "Realistic": 7200,
    "Elevated": 3600,
    "High": 1800,
    "Extreme": 600,
    "Insane": 0
  }
}
```

**`syslog_port`** — The global default TCP port for Syslog transport. Individual modules can override this with their own `syslog_port` setting.

---

> ### ⚡ `base_event_interval_seconds` — Event Generation Rate
>
> **This is the most important tuning knob in the simulator.** It controls the sleep delay between every individual log event across all modules. A lower value means events are generated faster; a higher value means fewer events per second.
>
> **Lower bound: `0.01` seconds** (100 events/sec). Values below this are not effective — Python's sleep precision and socket overhead make sub-10ms intervals unreliable.
>
> **How to calculate throughput:**
>
> In **Serial mode** (round-robin), the interval is divided evenly across all running modules:
> `events per second ≈ number_of_modules / base_event_interval_seconds`
>
> | `base_event_interval_seconds` | 3 modules | 6 modules | 12 modules |
> |---|---|---|---|
> | `0.01` | ~300 events/sec | ~600 events/sec | ~1,200 events/sec |
> | `0.1` | ~30 events/sec | ~60 events/sec | ~120 events/sec |
> | `0.5` | ~6 events/sec | ~12 events/sec | ~24 events/sec |
> | `1.5` *(default)* | ~2 events/sec | ~4 events/sec | ~8 events/sec |
> | `5.0` | ~0.6 events/sec | ~1.2 events/sec | ~2.4 events/sec |
>
> In **Parallel mode** (each module in its own thread), all modules fire simultaneously so throughput scales differently — each module independently sleeps for `base_event_interval_seconds` between its own events, giving approximately `1 / base_event_interval_seconds` events/sec *per module*.
>
> **Note:** Some threat generators (port scan, brute force, DGA storm) return bursts of 20–100 events at once — these are sent without inter-event sleep, so peak throughput will briefly spike above the steady-state rate during a threat injection.

---

**`threat_generation_levels`** — Defines the *minimum time in seconds* that must pass between threat events, per module. `0` means a threat can fire on any cycle. See [Threat Generation Levels](how-to-run.md#threat-generation-levels) for full details on each level.

## B. Transport Configuration

This section defines *how* logs are sent. Each module uses one of four transport mechanisms: Syslog TCP, HTTP Collector, AWS S3, or Google Cloud Pub/Sub.

```json
"http_collectors": {
  "okta_collector": {
    "url_env_var": "OKTA_COLLECTOR_URL",
    "auth_type_env_var": "OKTA_AUTH_TYPE",
    "api_key_env_var": "OKTA_KEY",
    "content_type": "application/json"
  },
  "proofpoint_collector": {
    "url_env_var": "PROOFPOINT_COLLECTOR_URL",
    "auth_type_env_var": "PROOFPOINT_AUTH_TYPE",
    "api_key_env_var": "PROOFPOINT_KEY",
    "content_type": "application/json"
  },
  "google_login_collector": {
    "url_env_var": "GOOGLE_LOGIN_COLLECTOR_URL",
    "auth_type_env_var": "GOOGLE_AUTH_TYPE",
    "api_key_env_var": "GOOGLE_LOGIN_KEY",
    "content_type": "application/json"
  },
  "google_drive_collector": {
    "url_env_var": "GOOGLE_DRIVE_COLLECTOR_URL",
    "auth_type_env_var": "GOOGLE_AUTH_TYPE",
    "api_key_env_var": "GOOGLE_DRIVE_KEY",
    "content_type": "application/json"
  },
  "google_admin_collector": {
    "url_env_var": "GOOGLE_ADMIN_COLLECTOR_URL",
    "auth_type_env_var": "GOOGLE_AUTH_TYPE",
    "api_key_env_var": "GOOGLE_ADMIN_KEY",
    "content_type": "application/json"
  },
  "google_user_accounts_collector": {
    "url_env_var": "GOOGLE_USER_ACCOUNTS_COLLECTOR_URL",
    "auth_type_env_var": "GOOGLE_AUTH_TYPE",
    "api_key_env_var": "GOOGLE_USER_ACCOUNTS_KEY",
    "content_type": "application/json"
  },
  "google_token_collector": {
    "url_env_var": "GOOGLE_TOKEN_COLLECTOR_URL",
    "auth_type_env_var": "GOOGLE_AUTH_TYPE",
    "api_key_env_var": "GOOGLE_TOKEN_KEY",
    "content_type": "application/json"
  }
},
"aws_config": {
  "transport": "s3",
  "users_and_roles": [ ... ]
},
"gcp_config": {
  "transport": "pubsub",
  "gcp_project_id": "PLACEHOLDER_GCP_PROJECT_ID",
  "pubsub_topic": "xsiam-audit-logs",
  "organization_id": "PLACEHOLDER_ORG_ID"
}
```

**`http_collectors`** — required for HTTP-based modules (Okta, Proofpoint, Google Workspace). Each entry has four fields:
- `url_env_var` — names the `.env` variable holding the XSIAM HTTP Collector endpoint URL for this collector
- `auth_type_env_var` — names the `.env` variable holding the authentication type (e.g., `"api_key"`)
- `api_key_env_var` — names the `.env` variable holding the API key for this collector
- `content_type` — MIME type sent in the `Content-Type` header (always `"application/json"`)

The dict key (e.g., `"okta_collector"`) is referenced by the module's `collector_id` setting. The five `google_*` collectors are used by the Google Workspace module, which is currently not operational.

**`aws_config`** — required for the AWS module. Contains `transport: "s3"` and a `users_and_roles` array defining the simulated IAM identities used to generate CloudTrail events. All AWS credentials (access key, secret key, bucket name, region, account ID) live in `.env` — see [Getting Started](getting-started.md) for the full `.env` reference.

**`gcp_config`** — required for the GCP module. Contains `transport: "pubsub"`, the `gcp_project_id` and `pubsub_topic` (fallbacks if the env vars `GCP_PROJECT_ID` and `GCP_PUBSUB_TOPIC` are not set), plus extensive simulated environment data (regions, projects, service accounts, resources). Replace every `PLACEHOLDER_GCP_PROJECT_ID` with your real project ID. GCP credentials are set via `.env` — see [Getting Started](getting-started.md).

---

### AWS S3 Setup — CloudFormation (Recommended)

The `CloudFormation/S3LogSim.yaml` template creates all required AWS infrastructure in a single stack. It provisions: an S3 bucket, an SQS notification queue (XSIAM polls this for new log files), an IAM user for LogSim (write-only S3 access), and an IAM role for XSIAM (read S3 + SQS). Permissions follow the principle of least privilege.

> **Reference:** [AWS CloudFormation User Guide](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/GettingStarted.html) · [How XSIAM S3 ingestion works](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)

**Step-by-step:**

1. Open the AWS Console → **CloudFormation** → **Create Stack** → **With new resources**.

2. Under **Template source**, choose **Upload a template file** and upload `CloudFormation/S3LogSim.yaml`.

3. Enter the stack parameters:

   | Parameter | Description | Example |
   |---|---|---|
   | `BucketName` | Globally unique S3 bucket name for log storage | `myorg-logsim-cloudtrail-prod` |
   | `ExternalId` | Secret string for XSIAM role assumption — generate a UUID | `550e8400-e29b-41d4-a716-446655440000` |

4. Click through **Configure stack options** (defaults are fine) and **Create stack**. Wait for `CREATE_COMPLETE` (~2 minutes).

5. Open the stack's **Outputs** tab. Copy these values:

   | Output key | Where it goes |
   |---|---|
   | `LogSimulatorAccessKeyId` | `.env` → `aws_access_key_id` |
   | `LogSimulatorSecretAccessKey` | `.env` → `aws_secret_access_key` |
   | `S3BucketName` | `.env` → `s3_bucket_name` AND `config.json` → `aws_config.s3_bucket_name` |
   | `SQSQueueURL` | XSIAM data source configuration (SQS URL field) |
   | `XSIAMRoleARN` | XSIAM data source configuration (Role ARN field) |
   | `XSIAMRoleExternalId` | XSIAM data source configuration (External ID field) — same as the `ExternalId` parameter you entered |

6. In XSIAM, create an **AWS S3** data source and fill in:
   - **S3 Bucket Name** — from `S3BucketName` output
   - **SQS Queue URL** — from `SQSQueueURL` output
   - **Role ARN** — from `XSIAMRoleARN` output
   - **External ID** — from `XSIAMRoleExternalId` output (the UUID you chose)
   - **AWS Region** — the region you deployed the stack in
   - **Select Audit logs and then check for use in Analytics**

**Resources created by the CloudFormation stack:**

| Resource | Type | Purpose |
|---|---|---|
| `<BucketName>` | S3 Bucket | LogSim writes gzipped CloudTrail JSON here |
| `<BucketName>-sqs-queue` | SQS Queue | S3 notifies this queue on each new object; XSIAM polls it |
| `xsiam-log-simulator-user-<BucketName>` | IAM User | LogSim identity — `s3:PutObject` on bucket only |
| `XSIAM-S3-Collector-Role-<BucketName>` | IAM Role | XSIAM assumes this role — read S3 + read/delete SQS messages |

**Manual teardown:** Delete the CloudFormation stack to remove all resources. The bucket has `DeletionPolicy: Delete` — empty it first if it contains objects.

---

### AWS S3 Setup — Manual (without CloudFormation)

1. Create a private S3 bucket (Block all public access enabled).
2. Create an SQS queue. Add an S3 event notification on the bucket to send `s3:ObjectCreated:*` events to the queue.
3. Create an IAM user for LogSim with an inline policy granting `s3:PutObject` on `arn:aws:s3:::<bucket>/*`.
4. Create an IAM role with a trust policy allowing `006742885340` (Palo Alto Networks XSIAM account) to `sts:AssumeRole` with your chosen External ID. Attach a policy granting `s3:GetObject` on the bucket and `sqs:ReceiveMessage`/`sqs:DeleteMessage`/`sqs:GetQueueAttributes` on the queue.
5. Populate `.env` with the IAM user access key/secret and `config.json` with the bucket name and region.

---

### GCP Pub/Sub Setup — Terraform (Recommended)

The `terraform/gcp_pubsub/` directory contains a complete Terraform configuration. It creates the Pub/Sub topic and subscription, two service accounts (one for LogSim to publish, one for XSIAM to subscribe), and all IAM bindings. The `apply_and_configure.sh` script runs Terraform and **automatically writes the correct values to your `.env` file**.

> **Prerequisites:** [Install Terraform](https://developer.hashicorp.com/terraform/install) · [Authenticate gcloud](https://cloud.google.com/sdk/docs/authorizing) (`gcloud auth application-default login`)
>
> **Reference:** [Google Cloud Pub/Sub overview](https://cloud.google.com/pubsub/docs/overview) · [Creating service account keys](https://cloud.google.com/iam/docs/keys-create-delete)

**Step-by-step:**

1. Navigate to the Terraform directory:
   ```bash
   cd terraform/gcp_pubsub
   ```

2. Copy the example variables file and set your GCP project ID:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars — set: project_id = "your-gcp-project-id"
   ```
   The only required variable is `project_id`. All other variables (topic name, subscription name, service account names) have sensible defaults.

3. Run the automated setup script:
   ```bash
   chmod +x apply_and_configure.sh
   ./apply_and_configure.sh
   ```
   This script runs `terraform init` + `terraform apply`, extracts all outputs, saves service account key files (chmod 600), and **automatically rewrites your `.env`** with `GCP_PROJECT_ID`, `GCP_PUBSUB_TOPIC`, and `GCP_SERVICE_ACCOUNT_KEY_JSON`.

4. At the end of the script, the XSIAM configuration values are printed to the terminal:
   - **Project ID** — your GCP project ID
   - **Subscription Name** — the pull subscription (default: `xsiam-logsim-pull`)
   - **Service Account Key JSON** — full JSON for the XSIAM subscriber SA (also saved to `terraform/gcp_pubsub/xsiam-subscriber-key.json`)

5. In XSIAM, create a **GCP Pub/Sub** data source and enter:
   - **Project ID** — your GCP project ID
   - **Subscription Name** — from the script output
   - **Service Account Key** — paste the full JSON printed at the end of the script

**Resources created by Terraform:**

| Resource | Name (default) | Purpose |
|---|---|---|
| Pub/Sub topic | `xsiam-audit-logs` | LogSim publishes one JSON LogEntry per message here |
| Pub/Sub subscription | `xsiam-logsim-pull` | XSIAM uses a pull subscription to ingest messages |
| Service account | `logsim-publisher` | LogSim — `roles/pubsub.publisher` on the topic |
| Service account | `xsiam-subscriber` | XSIAM — `roles/pubsub.subscriber` on the subscription + `roles/pubsub.viewer` on the topic |

**Useful Terraform commands (run manually if needed):**
```bash
# Print the ready-to-paste .env block for LogSim:
terraform -chdir=terraform/gcp_pubsub output -raw logsim_env_file

# Print the XSIAM subscriber key JSON (paste into XSIAM data source):
terraform -chdir=terraform/gcp_pubsub output -raw xsiam_sa_key_json
```

> **Important:** The `GCP_SERVICE_ACCOUNT_KEY_JSON` value in `.env` must be compact single-line JSON. Terraform uses `jsonencode(jsondecode(...))` to guarantee this. Do not reformat the key JSON or it will break dotenv parsing.

---

### GCP Pub/Sub Setup — Manual (without Terraform)

1. In the [GCP Console](https://console.cloud.google.com/) or with `gcloud`, create a Pub/Sub topic (e.g., `xsiam-audit-logs`).
2. Create a pull subscription on that topic (e.g., `xsiam-logsim-pull`).
3. Create a service account for LogSim. Grant it `roles/pubsub.publisher` on the topic. Download its JSON key.
4. Create a second service account for XSIAM. Grant it `roles/pubsub.subscriber` on the subscription and `roles/pubsub.viewer` on the topic. Download its JSON key.
5. In `.env`, set `GCP_PROJECT_ID` and `GCP_PUBSUB_TOPIC`.
6. Set `GCP_SERVICE_ACCOUNT_KEY_JSON` to the LogSim service account key **collapsed to a single line** (no literal newlines; `\n` escape sequences in `private_key` must remain as two-character sequences).
7. In `config.json`, replace all `PLACEHOLDER_GCP_PROJECT_ID` values with your real project ID.
8. In XSIAM, create a **GCP Pub/Sub** data source: enter your project ID, the subscription name, and paste the XSIAM service account key JSON.

## C. Module-Specific Configuration

These sections allow modules to override global settings or provide their own metadata.

```json
"cisco_asa_config": {
  "transport": "tcp",
  "syslog_port": 1514,
  "hostname": "ASA-FW-01"
},
"checkpoint_config": {
  "hostname": "CP-FW-1"
},
"okta_config": {
  "transport": "http",
  "collector_id": "okta_collector"
}
```

* **Example 1 (cisco_asa_config):** This module overrides the global syslog_port and sends to port 1514 instead.
* **Example 2 (okta_config):** This module specifies its transport is http and tells the simulator to use the collector details found in `http_collectors["okta_collector"]`.

## D. Simulated Environment & Threat Intel

These sections build the "world" your simulated logs live in. They provide realistic and consistent data for users, devices, and external sites.

```json
"internal_networks": ["192.168.1.0/24", "10.0.10.0/24"],
"internal_servers": ["10.0.10.50", "192.168.1.100"],

"firepower_config": {
  "hostname": "DC1-FTD-01",
  "user_ip_map": {
    "j.doe": "192.168.1.50",
    "a.smith": "192.168.1.51",
    "b.jones": "192.168.1.52"
  }
},
"zscaler_config": {
  "users": {"j.doe": "Sales", "a.smith": "Engineering", "b.jones": "Marketing"},
  "device_map": {
    "j.doe": {"hostname": "SALES-LT-01", "owner": "John Doe"},
    "a.smith": {"hostname": "ENG-WS-05", "owner": "Alice Smith"},
    "b.jones": {"hostname": "MKTG-MBP-12", "owner": "Bob Jones"}
  }
},

"benign_egress_destinations": [
  {"name": "Google DNS", "ip_range": "8.8.8.0/24", "country": "US", "asn": 15169}
],
"benign_ingress_sources": [
  {"name": "Comcast USA", "ip_range": "68.0.0.0/11", "country": "US", "asn": 7922, "isp": "Comcast"}
],
"exfiltration_destinations": [
  {"name": "Mega NZ", "ip_range": "154.53.224.0/24", "domain": "mega.nz"}
],
"tor_exit_nodes": [
  {"ip": "185.220.101.28", "country": "NL"}
],
"scenario_threats": {
  "JS/Adware.Gen": {"domain": "popunder-adnetwork.biz", "ip": "199.59.243.220", "category": "Adware"}
}
```

* **User & Device Mapping:** Sections like `firepower_config` (for `user_ip_map`) and `zscaler_config` (for `device_map` and `users`) are crucial. Modules cross-reference these to ensure that an event from 192.168.1.50 is *always* associated with user j.doe and hostname SALES-LT-01.
* **Traffic Destinations:** `benign_egress_destinations` and `exfiltration_destinations` are used by firewall and web proxy modules to generate realistic outbound traffic.
* **Threat Intelligence:** `tor_exit_nodes` (a fallback if the live fetch fails) and `scenario_threats` provide IPs and domains for threat events.
