# ── Enable required GCP APIs ──────────────────────────────────────────────────
resource "google_project_service" "pubsub" {
  project            = var.project_id
  service            = "pubsub.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam" {
  project            = var.project_id
  service            = "iam.googleapis.com"
  disable_on_destroy = false
}


# ── Pub/Sub Topic ─────────────────────────────────────────────────────────────
# LogSim publishes one JSON log entry per message to this topic.
# XSIAM reads from the subscription below.
resource "google_pubsub_topic" "logsim" {
  project = var.project_id
  name    = var.topic_name

  # Retain messages at the topic level for 24 hours so nothing is lost
  # if the subscription falls behind.
  message_retention_duration = "86400s"

  labels = {
    managed-by = "terraform"
    purpose    = "logsim-xsiam"
  }

  depends_on = [google_project_service.pubsub]
}


# ── Pub/Sub Subscription ──────────────────────────────────────────────────────
# Cortex XSIAM uses a pull subscription to ingest messages.
# Configure the XSIAM GCP Pub/Sub data source with this subscription name.
resource "google_pubsub_subscription" "xsiam" {
  project = var.project_id
  name    = var.subscription_name
  topic   = google_pubsub_topic.logsim.id

  ack_deadline_seconds       = var.subscription_ack_deadline_seconds
  message_retention_duration = var.subscription_message_retention_seconds

  # Keep unacknowledged messages; XSIAM will ack after successful ingestion.
  retain_acked_messages = false

  # Subscription never auto-expires.
  expiration_policy {
    ttl = ""
  }

  labels = {
    managed-by = "terraform"
    purpose    = "xsiam-ingest"
  }
}


# ── LogSim Publisher Service Account ─────────────────────────────────────────
# Used by log_simulator.py to authenticate when publishing to the topic.
resource "google_service_account" "logsim" {
  project      = var.project_id
  account_id   = var.logsim_sa_name
  display_name = "LogSim Pub/Sub Publisher"
  description  = "Allows log_simulator.py (LogSim) to publish GCP audit log events to the ${var.topic_name} Pub/Sub topic."

  depends_on = [google_project_service.iam]
}

# Grant the LogSim SA permission to publish to the topic.
resource "google_pubsub_topic_iam_member" "logsim_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.logsim.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.logsim.email}"
}

# Create a JSON key for the LogSim SA.
# The private_key output is used to set GCP_SERVICE_ACCOUNT_KEY_JSON in .env
# (or saved to a file for GOOGLE_APPLICATION_CREDENTIALS).
resource "google_service_account_key" "logsim" {
  service_account_id = google_service_account.logsim.name
}


# ── XSIAM Subscriber Service Account ─────────────────────────────────────────
# Used by Cortex XSIAM to pull and acknowledge messages from the subscription.
resource "google_service_account" "xsiam" {
  project      = var.project_id
  account_id   = var.xsiam_sa_name
  display_name = "XSIAM Pub/Sub Subscriber"
  description  = "Allows Cortex XSIAM to pull messages from the ${var.subscription_name} Pub/Sub subscription."

  depends_on = [google_project_service.iam]
}

# Grant the XSIAM SA permission to pull and ack messages from the subscription.
resource "google_pubsub_subscription_iam_member" "xsiam_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.xsiam.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.xsiam.email}"
}

# Grant the XSIAM SA viewer access to the topic (required to verify subscription).
resource "google_pubsub_topic_iam_member" "xsiam_viewer" {
  project = var.project_id
  topic   = google_pubsub_topic.logsim.name
  role    = "roles/pubsub.viewer"
  member  = "serviceAccount:${google_service_account.xsiam.email}"
}

# Create a JSON key for the XSIAM SA.
# Paste the decoded key into the XSIAM GCP Pub/Sub data source configuration.
resource "google_service_account_key" "xsiam" {
  service_account_id = google_service_account.xsiam.name
}
