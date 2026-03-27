variable "project_id" {
  description = "GCP project ID where all resources will be created."
  type        = string
}

variable "region" {
  description = "GCP region for Pub/Sub resources."
  type        = string
  default     = "us-central1"
}

variable "topic_name" {
  description = "Name of the Pub/Sub topic that LogSim publishes log entries to."
  type        = string
  default     = "xsiam-audit-logs"
}

variable "subscription_name" {
  description = "Name of the Pub/Sub pull subscription that Cortex XSIAM reads from."
  type        = string
  default     = "xsiam-logsim-pull"
}

variable "logsim_sa_name" {
  description = "Service account ID for LogSim (granted roles/pubsub.publisher on the topic)."
  type        = string
  default     = "logsim-publisher"
}

variable "xsiam_sa_name" {
  description = "Service account ID for Cortex XSIAM (granted roles/pubsub.subscriber on the subscription)."
  type        = string
  default     = "xsiam-subscriber"
}

variable "subscription_ack_deadline_seconds" {
  description = "Seconds XSIAM has to acknowledge a message before it is redelivered."
  type        = number
  default     = 60
}

variable "subscription_message_retention_seconds" {
  description = "How long (in seconds) unacknowledged messages are retained in the subscription. Default 7 days."
  type        = string
  default     = "604800s"
}
