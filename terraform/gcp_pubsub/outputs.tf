# =============================================================================
# OUTPUTS
# After running `terraform apply`, use these values to configure LogSim and
# Cortex XSIAM.
#
# Sensitive outputs (service account keys) are hidden by default.
# To retrieve them run:
#   terraform output -raw logsim_env_file
#   terraform output -raw xsiam_sa_key_json
#
# Key JSON format note: all key outputs use jsonencode(jsondecode(...)) to
# guarantee compact single-line JSON.  The private_key field's \n sequences
# are preserved correctly through the encode/decode round-trip.
# This matches the format required by GCP_SERVICE_ACCOUNT_KEY_JSON in .env.
# =============================================================================

locals {
  # Compact (single-line) JSON for the LogSim publisher key.
  # jsonencode re-serializes the decoded object with no whitespace or newlines,
  # keeping \n sequences inside the private_key value intact.
  logsim_key_compact = jsonencode(jsondecode(base64decode(google_service_account_key.logsim.private_key)))

  # Compact (single-line) JSON for the XSIAM subscriber key.
  xsiam_key_compact = jsonencode(jsondecode(base64decode(google_service_account_key.xsiam.private_key)))
}


# ── Quick-copy .env snippet ───────────────────────────────────────────────────
# Run:  terraform output -raw logsim_env_file
# Paste the output directly into your LogSim .env file — no editing needed.
output "logsim_env_file" {
  description = "Ready-to-paste .env block for the LogSim GCP module. Run: terraform output -raw logsim_env_file"
  sensitive   = true
  value       = <<-ENV
# --- GCP Cloud Audit Logs (Pub/Sub Transport) ---
GCP_PROJECT_ID=${var.project_id}
GCP_PUBSUB_TOPIC=${google_pubsub_topic.logsim.name}
GCP_SERVICE_ACCOUNT_KEY_JSON=${local.logsim_key_compact}
ENV
}


# ── LogSim individual values ──────────────────────────────────────────────────
output "GCP_PROJECT_ID" {
  description = ".env: GCP_PROJECT_ID"
  value       = var.project_id
}

output "GCP_PUBSUB_TOPIC" {
  description = ".env: GCP_PUBSUB_TOPIC"
  value       = google_pubsub_topic.logsim.name
}

output "logsim_sa_email" {
  description = "LogSim publisher service account email (for reference)."
  value       = google_service_account.logsim.email
}

output "logsim_sa_key_json" {
  description = ".env GCP_SERVICE_ACCOUNT_KEY_JSON value — compact single-line JSON. Run: terraform output -raw logsim_sa_key_json"
  sensitive   = true
  value       = local.logsim_key_compact
}

output "logsim_sa_key_file_path_suggestion" {
  description = "Suggested path if you prefer saving the key as a file (GOOGLE_APPLICATION_CREDENTIALS) instead of inline JSON."
  value       = "${path.root}/logsim-publisher-key.json"
}


# ── XSIAM configuration values ───────────────────────────────────────────────
output "xsiam_subscription_name" {
  description = "XSIAM GCP Pub/Sub data source — Subscription Name field."
  value       = google_pubsub_subscription.xsiam.name
}

output "xsiam_sa_email" {
  description = "XSIAM subscriber service account email (for reference)."
  value       = google_service_account.xsiam.email
}

output "xsiam_sa_key_json" {
  description = "XSIAM GCP Pub/Sub data source — Service Account Key JSON field (compact single-line). Run: terraform output -raw xsiam_sa_key_json"
  sensitive   = true
  value       = local.xsiam_key_compact
}


# ── Summary ───────────────────────────────────────────────────────────────────
output "next_steps" {
  description = "What to do after apply."
  value       = <<-STEPS
    ┌─────────────────────────────────────────────────────────────────────┐
    │  LogSim .env — run and paste directly (no editing needed):          │
    │    terraform output -raw logsim_env_file >> ../../.env              │
    │                                                                     │
    │  XSIAM GCP Pub/Sub data source — configure with:                   │
    │    Project ID  : ${var.project_id}
    │    Subscription: ${google_pubsub_subscription.xsiam.name}
    │    SA Key JSON : terraform output -raw xsiam_sa_key_json            │
    └─────────────────────────────────────────────────────────────────────┘
  STEPS
}
