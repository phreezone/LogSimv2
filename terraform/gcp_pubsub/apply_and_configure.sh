#!/usr/bin/env bash
# apply_and_configure.sh
#
# Runs `terraform apply`, extracts the service account keys, and updates the
# LogSim .env file at the project root automatically.
#
# Usage:
#   cd terraform/gcp_pubsub
#   chmod +x apply_and_configure.sh
#   ./apply_and_configure.sh
#
# Requirements: terraform, jq (optional, for pretty-printing the key)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"

# ── Ensure tfvars exists ───────────────────────────────────────────────────────
if [[ ! -f "${SCRIPT_DIR}/terraform.tfvars" ]]; then
  echo "ERROR: terraform.tfvars not found."
  echo "  cp ${SCRIPT_DIR}/terraform.tfvars.example ${SCRIPT_DIR}/terraform.tfvars"
  echo "  Then set your project_id and run this script again."
  exit 1
fi

# ── Terraform init + apply ─────────────────────────────────────────────────────
echo "==> Initializing Terraform..."
terraform -chdir="${SCRIPT_DIR}" init -upgrade

echo ""
echo "==> Applying Terraform (this creates the Pub/Sub topic, subscription, and service accounts)..."
terraform -chdir="${SCRIPT_DIR}" apply

# ── Extract outputs ────────────────────────────────────────────────────────────
echo ""
echo "==> Extracting outputs..."

GCP_PROJECT_ID="$(terraform -chdir="${SCRIPT_DIR}" output -raw GCP_PROJECT_ID)"
GCP_PUBSUB_TOPIC="$(terraform -chdir="${SCRIPT_DIR}" output -raw GCP_PUBSUB_TOPIC)"
LOGSIM_KEY_JSON="$(terraform -chdir="${SCRIPT_DIR}" output -raw logsim_sa_key_json)"
XSIAM_SUBSCRIPTION="$(terraform -chdir="${SCRIPT_DIR}" output -raw xsiam_subscription_name)"
XSIAM_KEY_JSON="$(terraform -chdir="${SCRIPT_DIR}" output -raw xsiam_sa_key_json)"

# Save the LogSim publisher key to a file (compact single-line JSON from Terraform)
LOGSIM_KEY_FILE="${SCRIPT_DIR}/logsim-publisher-key.json"
echo "${LOGSIM_KEY_JSON}" > "${LOGSIM_KEY_FILE}"
chmod 600 "${LOGSIM_KEY_FILE}"
echo "  Saved LogSim key to: ${LOGSIM_KEY_FILE}"

# Save the XSIAM subscriber key to a file for reference
XSIAM_KEY_FILE="${SCRIPT_DIR}/xsiam-subscriber-key.json"
echo "${XSIAM_KEY_JSON}" > "${XSIAM_KEY_FILE}"
chmod 600 "${XSIAM_KEY_FILE}"
echo "  Saved XSIAM key to:  ${XSIAM_KEY_FILE}"

# ── Update .env ────────────────────────────────────────────────────────────────
# The key JSON is already compact single-line from the Terraform logsim_sa_key_json output.
# We write GCP_SERVICE_ACCOUNT_KEY_JSON inline — no file path needed.
echo ""
echo "==> Updating ${ENV_FILE}..."

if grep -q "GCP_PROJECT_ID" "${ENV_FILE}"; then
  # Replace existing GCP values in-place
  sed -i \
    -e "s|^GCP_PROJECT_ID=.*|GCP_PROJECT_ID=${GCP_PROJECT_ID}|" \
    -e "s|^GCP_PUBSUB_TOPIC=.*|GCP_PUBSUB_TOPIC=${GCP_PUBSUB_TOPIC}|" \
    -e "s|^GOOGLE_APPLICATION_CREDENTIALS=.*|# GOOGLE_APPLICATION_CREDENTIALS=${LOGSIM_KEY_FILE}|" \
    "${ENV_FILE}"
  # Append the inline key if not already present
  if ! grep -q "^GCP_SERVICE_ACCOUNT_KEY_JSON=" "${ENV_FILE}"; then
    printf '\nGCP_SERVICE_ACCOUNT_KEY_JSON=%s\n' "${LOGSIM_KEY_JSON}" >> "${ENV_FILE}"
  else
    # Escape forward slashes and special chars for sed
    ESCAPED_KEY="$(echo "${LOGSIM_KEY_JSON}" | sed 's/[&/\]/\\&/g')"
    sed -i "s|^GCP_SERVICE_ACCOUNT_KEY_JSON=.*|GCP_SERVICE_ACCOUNT_KEY_JSON=${ESCAPED_KEY}|" "${ENV_FILE}"
  fi
else
  # Append fresh block
  cat >> "${ENV_FILE}" <<ENVBLOCK

# --- GCP Cloud Audit Logs (Pub/Sub Transport) ---
GCP_PROJECT_ID=${GCP_PROJECT_ID}
GCP_PUBSUB_TOPIC=${GCP_PUBSUB_TOPIC}
GOOGLE_APPLICATION_CREDENTIALS=${LOGSIM_KEY_FILE}
GCP_SERVICE_ACCOUNT_KEY_JSON=${LOGSIM_KEY_JSON}
ENVBLOCK
fi

echo "  .env updated."

# ── Print XSIAM instructions ───────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  DONE — LogSim .env has been updated automatically.                 ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  Now configure the XSIAM GCP Pub/Sub data source with:             ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf  "║  Project ID   : %-52s ║\n" "${GCP_PROJECT_ID}"
printf  "║  Subscription : %-52s ║\n" "${XSIAM_SUBSCRIPTION}"
echo "║  SA Key JSON  : printed below — copy everything between the lines  ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "── XSIAM Service Account Key JSON (copy this into XSIAM) ─────────────"
echo "${XSIAM_KEY_JSON}"
echo "───────────────────────────────────────────────────────────────────────"
echo ""
echo "Key also saved to: ${XSIAM_KEY_FILE}"
echo ""
echo "WARNING: ${LOGSIM_KEY_FILE} and ${XSIAM_KEY_FILE} contain"
echo "         sensitive credentials. Do not commit them to source control."
