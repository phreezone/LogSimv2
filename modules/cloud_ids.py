"""Generated AWS and GCP identifiers: correct formats, unbounded cardinality.

The third instance of the pool problem, in the cloud modules. `aws_config` alone
carries ~20 pools of 25-26 resource identifiers each -- `ec2_instances`,
`ebs_volumes`, `ec2_snapshots`, `security_groups`, `vpcs`, `route_tables`,
`s3_buckets`, `kms_keys`, `log_groups`, `rds_instances`, `lambda_functions`,
`foreign_account_ids` -- so over a long run the same 26 instance ids are launched,
stopped and snapshotted over and over. Any detection that reasons about a *new* or
*rare* resource has 26 possibilities to learn, and an analyst pivoting on
`i-01a2b3c4d5e6f7a1` finds a month of unrelated history.

Formats here are the real ones, because they are parsed and pivoted on, not just
displayed:

    i-0a1b2c3d4e5f67890        EC2 instance      "i-" + 17 hex
    vol-0a1b2c3d4e5f67890      EBS volume        "vol-" + 17 hex
    snap-0a1b2c3d4e5f67890     snapshot          "snap-" + 17 hex
    sg-0a1b2c3d4e5f67890       security group    "sg-" + 17 hex
    AKIAY4J2K7QWERTZ5A3B       access key        "AKIA" + 16 upper/digit
    ASIAY4J2K7QWERTZ5A3B       temp credential   "ASIA" + 16  (STS)
    Z0A1B2C3D4E5F6              Route 53 zone    "Z" + upper/digit

AWS switched from 8 to 17 hex characters for resource ids in 2016; emitting the
short form would date the data and break anything matching the modern shape.

## What may not drift

The org's OWN account id stays fixed. It is the tenant's identity, it appears in
every ARN, and `aws_config.aws_account_id` is substituted from the environment at
run time. Only FOREIGN account ids -- the counterparty in a cross-account
AssumeRole -- are generated, which is exactly the field a cross-account rule keys on.

Several literals below are matched by correlation rules and are reproduced verbatim:

  * secret names: `rootCredentials`, `MasterKey`, `SuperUser`, `service_account_key`,
    `encryption_key`, `BreakGlass`. Before this module the "AWS - Secret or Parameter
    Retrieval Targeting Credentials" rule was held up by ONE alternative, and only
    through a case-insensitive match on `emergency-breakglass-key`; if the tenant's
    XQL case sensitivity were ever switched on, the rule would have died outright.
    Note `service_account_key` is spelled with UNDERSCORES: the shipped pool had
    `/corp/iam/service-account-key` with hyphens, which the rule never matched.
  * S3 public exposure: the canned ACL values `public-read` / `public-read-write`
    and the conventional bucket-policy Sid `PublicReadGetObject`.
  * `iam:*`, the wildcard action in an inline admin policy document.
  * `roles/iam.serviceAccountUser` for GCP privilege escalation.
  * Service-role and instance-profile principals (`AWSServiceRoleFor...`,
    `/aws-service-role/`, `InstanceProfile`). These appear only in NEGATED clauses --
    four rules exclude them so automation does not alert -- so emitting them does not
    make a rule fire; it exercises the suppression path that keeps those rules quiet
    in a real account. Absence was harmless, presence is more faithful.
"""

import random
import string

_HEX = "0123456789abcdef"
# AWS key ids use uppercase letters and digits; real ones avoid nothing in practice,
# so the full uppercase+digit alphabet is right.
_KEY_ALPHABET = string.ascii_uppercase + string.digits


def _hex17():
    return "".join(random.choice(_HEX) for _ in range(17))


# --- EC2 / VPC resource ids -------------------------------------------------

def instance_id():
    return "i-" + _hex17()


def volume_id():
    return "vol-" + _hex17()


def snapshot_id():
    return "snap-" + _hex17()


def security_group_id():
    return "sg-" + _hex17()


def vpc_id():
    return "vpc-" + _hex17()


def subnet_id():
    return "subnet-" + _hex17()


def route_table_id():
    return "rtb-" + _hex17()


def ami_id():
    return "ami-" + _hex17()


def eni_id():
    return "eni-" + _hex17()


# --- credentials ------------------------------------------------------------

def access_key_id(temporary=False):
    """AKIA... for a long-lived IAM key, ASIA... for STS temporary credentials."""
    prefix = "ASIA" if temporary else "AKIA"
    return prefix + "".join(random.choice(_KEY_ALPHABET) for _ in range(16))


def account_id():
    """A 12-digit AWS account id. For FOREIGN accounts only -- see module docstring."""
    return "".join(random.choice(string.digits) for _ in range(12))


# --- names ------------------------------------------------------------------

_BUCKET_ENV = ("prod", "dev", "staging", "test", "qa", "sandbox", "corp", "shared")
_BUCKET_PURPOSE = ("customer-data", "finance-reports", "app-logs", "backups",
                   "analytics-exports", "audit-archive", "media-assets",
                   "terraform-state", "data-lake", "etl-staging", "ml-features",
                   "invoices", "hr-records", "clickstream", "cdn-origin")
_REGIONS = ("us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1",
            "eu-central-1", "ap-southeast-1", "ap-northeast-1", "ca-central-1")


def region():
    return random.choice(_REGIONS)


def bucket_name():
    """A DNS-compliant S3 bucket name in the house style."""
    parts = [random.choice(_BUCKET_ENV), random.choice(_BUCKET_PURPOSE)]
    if random.random() < 0.55:
        parts.append(random.choice(_REGIONS))
    if random.random() < 0.3:
        parts.append(str(random.randint(2026, 2027)))
    return "-".join(parts)


def log_group():
    kind = random.random()
    if kind < 0.5:
        return f"/aws/lambda/{_lambda_name()}"
    if kind < 0.75:
        return f"/aws/eks/{random.choice(_BUCKET_ENV)}-cluster/cluster"
    return f"/aws/rds/instance/{rds_instance()}/{random.choice(('error','audit','slowquery'))}"


_LAMBDA_VERB = ("Process", "Handle", "Sync", "Generate", "Validate", "Ingest",
                "Publish", "Reconcile", "Archive", "Notify", "Transform",
                "Enrich", "Dispatch", "Aggregate", "Export", "Audit", "Rotate")
_LAMBDA_NOUN = ("Order", "Invoice", "Payment", "User", "Report", "Event",
                "Webhook", "Inventory", "Shipment", "Session", "Document",
                "Subscription", "Refund", "Ledger", "Catalog", "Entitlement")


def _lambda_name():
    return f"{random.choice(_LAMBDA_VERB)}{random.choice(_LAMBDA_NOUN)}Function"


def lambda_function():
    return _lambda_name()


def rds_instance():
    env = random.choice(_BUCKET_ENV)
    role = random.choice(("main", "replica-a", "replica-b", "reporting", "analytics"))
    return f"{env}-db-{role}-{random.randint(1, 9)}"


def kms_key_arn(acct, rgn=None):
    """A KMS multi-region key ARN. `acct` is the owning account -- pass the org's own."""
    return (f"arn:aws:kms:{rgn or region()}:{acct}:key/"
            f"mrk-{''.join(random.choice(_HEX) for _ in range(32))}")


def route53_zone_id():
    return "Z" + "".join(random.choice(_KEY_ALPHABET) for _ in range(random.randint(13, 20)))


def key_pair_name():
    env = random.choice(_BUCKET_ENV)
    role = random.choice(("admin", "bastion", "deploy", "analytics", "jump",
                          "worker", "build", "ops"))
    return f"{env}-{role}-key-{random.randint(1, 99)}"


# --- secrets and parameters -------------------------------------------------
#
# The leaf names below are a CONTRACT with "AWS - Secret or Parameter Retrieval
# Targeting Credentials". Do not rename them; add alongside.
_SECRET_LEAF_RULE = ("rootCredentials", "MasterKey", "SuperUser",
                     "service_account_key", "encryption_key", "BreakGlass")
_SECRET_LEAF_OTHER = ("aws-access-key", "secret-access-key", "access-key-id",
                      "api-token", "signing-key", "db-password",
                      "private-key", "oauth-client-secret", "session-token")
_SECRET_PREFIX = ("/prod", "/corp", "/ci", "/svc", "/ec2", "/credentials",
                  "/platform", "/data", "/security")
_SECRET_MID = ("aws", "iam", "deploy", "pipeline", "vault", "sre", "app",
               "break-glass", "root")


def sensitive_parameter(force_rule_token=None):
    """An SSM parameter / Secrets Manager name for a credential-bearing secret.

    A little over half of these carry one of the leaf names the detection matches,
    so the rule has many live alternatives instead of resting on one.
    """
    if force_rule_token:
        leaf = force_rule_token
    elif random.random() < 0.55:
        leaf = random.choice(_SECRET_LEAF_RULE)
    else:
        leaf = random.choice(_SECRET_LEAF_OTHER)
    return f"{random.choice(_SECRET_PREFIX)}/{random.choice(_SECRET_MID)}/{leaf}"


def rule_secret_names():
    """The leaf names a correlation rule matches, for tests and for coverage sweeps."""
    return tuple(_SECRET_LEAF_RULE)


# --- S3 public exposure -----------------------------------------------------

# Canned ACLs the "S3 Bucket Made Publicly Accessible" rule matches, plus the
# conventional Sid of a public-read bucket policy.
PUBLIC_ACLS = ("public-read", "public-read-write")
PUBLIC_POLICY_SID = "PublicReadGetObject"


def public_acl():
    return random.choice(PUBLIC_ACLS)


def public_bucket_policy(bucket):
    """A bucket policy document granting the world s3:GetObject.

    The Sid is the one the AWS documentation example uses, which is why detections
    match it and why real offending buckets carry it.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": PUBLIC_POLICY_SID,
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
        }],
    }


# --- IAM principals and policies --------------------------------------------

# (service principal prefix, real service-linked role name). Capitalising the
# service prefix would give AWSServiceRoleForEks and AWSServiceRoleForRds, which do
# not exist -- the real names are AWSServiceRoleForAmazonEKS and AWSServiceRoleForRDS.
# An analyst who knows AWS spots an invented role name immediately, so these are the
# actual ones AWS creates.
_SERVICE_LINKED_ROLES = (
    ("autoscaling",          "AWSServiceRoleForAutoScaling"),
    ("ecs",                  "AWSServiceRoleForECS"),
    ("eks",                  "AWSServiceRoleForAmazonEKS"),
    ("rds",                  "AWSServiceRoleForRDS"),
    ("elasticloadbalancing", "AWSServiceRoleForElasticLoadBalancing"),
    ("support",              "AWSServiceRoleForSupport"),
    ("trustedadvisor",       "AWSServiceRoleForTrustedAdvisor"),
    ("config",               "AWSServiceRoleForConfig"),
    ("ssm",                  "AWSServiceRoleForAmazonSSM"),
    ("organizations",        "AWSServiceRoleForOrganizations"),
    ("guardduty",            "AWSServiceRoleForAmazonGuardDuty"),
    ("backup",               "AWSServiceRoleForBackup"),
    ("cloudtrail",           "AWSServiceRoleForCloudTrail"),
)


def service_linked_role_arn(acct):
    """An AWS service-linked role ARN.

    Carries both `/aws-service-role/` and `AWSServiceRoleFor`, the two strings four
    rules EXCLUDE so that AWS's own automation does not raise alerts. Emitting these
    exercises that suppression path.
    """
    svc, role = random.choice(_SERVICE_LINKED_ROLES)
    return f"arn:aws:iam::{acct}:role/aws-service-role/{svc}.amazonaws.com/{role}"


def instance_profile_arn(acct):
    """An EC2 instance-profile ARN -- the `InstanceProfile` exclusion path."""
    env = random.choice(_BUCKET_ENV)
    role = random.choice(("Worker", "App", "Build", "Bastion", "Data"))
    return f"arn:aws:iam::{acct}:instance-profile/{env}-{role}InstanceProfile"


# `iam:*` is the wildcard action that makes an inline policy administrative, and is
# what the AttachUserPolicy rule matches alongside the managed-policy names.
ADMIN_WILDCARD_ACTION = "iam:*"


def admin_inline_policy(name=None):
    """An inline IAM policy document granting wildcard admin, including `iam:*`."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": name or "FullAdminAccess",
            "Effect": "Allow",
            "Action": [ADMIN_WILDCARD_ACTION, "sts:AssumeRole", "*"],
            "Resource": "*",
        }],
    }


# --- GCP --------------------------------------------------------------------

_GCP_WORD_A = ("acme", "corp", "shared", "core", "data", "platform", "infra",
               "prod", "dev", "analytics", "ml", "web")
_GCP_WORD_B = ("services", "workloads", "pipeline", "hosting", "runtime",
               "network", "store", "compute", "lake", "edge")


def gcp_project_id():
    """A GCP project id: lowercase words plus digits, 6-30 chars."""
    return (f"{random.choice(_GCP_WORD_A)}-{random.choice(_GCP_WORD_B)}-"
            f"{random.randint(100000, 999999)}")


_SA_ROLE = ("terraform-runner", "gke-node-sa", "ci-cd-deployer", "data-pipeline-sa",
            "monitoring-agent", "backup-agent", "bq-loader", "pubsub-publisher",
            "cloudrun-invoker", "secrets-reader", "vertex-trainer", "log-router")


def service_account_email(project=None):
    """A GCP service-account email."""
    return f"{random.choice(_SA_ROLE)}-{random.randint(1, 99)}@" \
           f"{project or gcp_project_id()}.iam.gserviceaccount.com"


def _numeric_id(length):
    """A numeric id with no leading zero -- real GCP ids never have one."""
    return random.choice("123456789") + "".join(
        random.choice(string.digits) for _ in range(length - 1))


def service_account_unique_id():
    """A GCP service-account numeric unique id (21 digits)."""
    return _numeric_id(21)


def gcp_instance_id():
    """A GCE numeric instance id (19 digits)."""
    return _numeric_id(19)


# Roles the GCP privilege-escalation rule matches. serviceAccountUser was absent
# from the project entirely, so that branch of the rule had never been exercised.
ESCALATION_ROLES = ("roles/owner", "roles/editor",
                    "roles/iam.serviceAccountUser",
                    "roles/iam.serviceAccountTokenCreator",
                    "roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin")


def escalation_role():
    return random.choice(ESCALATION_ROLES)


# --- pool expansion ---------------------------------------------------------
#
# The cloud modules read their identifiers through ~100 `random.choice(conf[pool])`
# call sites. Rather than rewrite every one, the POOLS are grown once at startup,
# the same way domain_corpus.load() and resolver.load() are called. Every call site
# then benefits with no edit and no regression risk.
#
# Growing a pool is also more faithful than generating per event, for anything that
# PERSISTS. A real account does keep a stable set of instances, volumes and buckets;
# the same instance is legitimately started, stopped and snapshotted for months. The
# defect was never that identifiers recur -- it is that there were 26 of them for an
# organisation of ~250 users. So each pool grows to a size that is plausible for this
# estate, and the shape of the estate is respected: snapshots accumulate in the
# thousands, VPCs stay in the low tens.
_POOL_TARGETS = {
    "ec2_instances":      (400, instance_id),
    "ebs_volumes":        (600, volume_id),
    "ec2_snapshots":      (900, snapshot_id),
    "security_groups":    (120, security_group_id),
    "vpcs":               (24,  vpc_id),            # VPCs are few, by design
    "route_tables":       (60,  route_table_id),
    "s3_buckets":         (200, bucket_name),
    "log_groups":         (250, log_group),
    "rds_instances":      (40,  rds_instance),
    "lambda_functions":   (200, lambda_function),
    "foreign_account_ids": (150, account_id),
    "key_pair_names":     (80,  key_pair_name),
    "route53_zones":      (30,  route53_zone_id),
    # Secrets persist and are re-read, so a pool is right; the rule leaf names are
    # force-seeded below rather than left to chance.
    "sensitive_credential_paths": (60, sensitive_parameter),
}

# Deliberately NOT expanded:
#   pentest_ami_ids -- the curated ids encode distro names (ami-kali-linux-official,
#     ami-parrot-sec-os), and "AWS - Kali / Penetration-Testing AMI Launched" matches
#     those names. Random ami-0<hex> entries would dilute the signal the rule needs.
_POOLS_KEPT_CURATED = ("pentest_ami_ids",)


def expand_pools(config, verbose=True):
    """Grow the AWS/GCP identifier pools in `config`, in place.

    Call once at startup, AFTER the PLACEHOLDER_* substitution so generated ARNs
    embed the real account id, and BEFORE the modules load.
    """
    aws = config.get("aws_config")
    if not isinstance(aws, dict):
        return
    acct = str(aws.get("aws_account_id") or "")
    grown = []

    for key, (target, gen) in _POOL_TARGETS.items():
        pool = aws.get(key)
        if not isinstance(pool, list):
            continue
        before = len(pool)
        if before >= target:
            continue
        seen = set(pool)
        # Force the leaf names the secret rule matches, so the rule never rests on
        # a lucky draw (it was resting on exactly one, case-insensitively).
        if key == "sensitive_credential_paths":
            for leaf in _SECRET_LEAF_RULE:
                cand = sensitive_parameter(force_rule_token=leaf)
                if cand not in seen:
                    pool.append(cand)
                    seen.add(cand)
        guard = 0
        while len(pool) < target and guard < target * 40:
            cand = gen()
            if cand not in seen:
                pool.append(cand)
                seen.add(cand)
            guard += 1
        grown.append(f"{key} {before}->{len(pool)}")

    # KMS keys and the ARN-bearing pools need the account id woven in.
    for key, builder in (("kms_keys", lambda: kms_key_arn(acct)),):
        pool = aws.get(key)
        if not isinstance(pool, list) or not acct:
            continue
        before = len(pool)
        seen = set(pool)
        guard = 0
        while len(pool) < 60 and guard < 2400:
            cand = builder()
            if cand not in seen:
                pool.append(cand)
                seen.add(cand)
            guard += 1
        if len(pool) != before:
            grown.append(f"{key} {before}->{len(pool)}")

    # Automation principals. Four rules EXCLUDE these so AWS's own service roles and
    # EC2 instance roles do not raise alerts, but the account contained neither, so
    # the exclusions had nothing to act on and were never exercised. CloudTrail shows
    # a service-linked role as an AssumedRole whose ARN carries both
    # `/aws-service-role/` and `AWSServiceRoleFor`; an EC2 instance role commonly
    # carries the instance-profile name, which is where `InstanceProfile` comes from.
    identities = aws.get("users_and_roles")
    if isinstance(identities, list) and identities:
        have = {e.get("name") for e in identities if isinstance(e, dict)}
        added = 0
        for svc, name in _SERVICE_LINKED_ROLES:
            if name in have:
                continue
            identities.append({
                "type": "Role", "name": name,
                "arn_suffix": f"role/aws-service-role/{svc}.amazonaws.com/{name}",
            })
            have.add(name)
            added += 1
        for env in ("prod", "staging", "dev", "corp"):
            for role in ("Worker", "App", "Build", "Data"):
                name = f"{env}-{role}InstanceProfile"
                if name in have:
                    continue
                identities.append({"type": "Role", "name": name,
                                   "arn_suffix": f"role/{name}"})
                have.add(name)
                added += 1
        if added:
            grown.append(f"users_and_roles +{added} automation principals")

    # GCP: five service accounts for the whole estate was the tightest pool of all.
    gcp = config.get("gcp_config")
    if isinstance(gcp, dict):
        pool = gcp.get("service_accounts")
        project = gcp.get("gcp_project_id")
        if isinstance(pool, list) and project:
            before = len(pool)
            seen = set(pool)
            guard = 0
            while len(pool) < 60 and guard < 2400:
                cand = service_account_email(project)
                if cand not in seen:
                    pool.append(cand)
                    seen.add(cand)
                guard += 1
            if len(pool) != before:
                grown.append(f"gcp service_accounts {before}->{len(pool)}")

    if verbose and grown:
        print(f"[cloud_ids] expanded {len(grown)} identifier pool(s): "
              f"{', '.join(grown[:6])}"
              f"{f' (+{len(grown) - 6} more)' if len(grown) > 6 else ''}")
    return grown
