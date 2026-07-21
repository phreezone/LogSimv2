# modules/aws_guardduty.py
# Simulates Amazon GuardDuty findings in the exact schemaVersion 2.0 format that
# GuardDuty exports to S3 / emits over EventBridge, so XSIAM parses them into the
# aws_guardduty_raw dataset and models them to xdm.alert.* identically to native
# GuardDuty data.
#
# Transport: XSIAM HTTP Event Collector bound to vendor="aws" / product="guardduty"
# (routing verified against demisto/content Packs/AWS-GuardDuty parsing rule:
#   [INGEST: vendor="aws", product="guardduty", target_dataset="aws_guardduty_raw"]).
#
# Findings are inherently detections — unlike raw telemetry there is no benign
# GuardDuty "activity", so Mode 1 emits findings sparingly and only the low-severity
# Recon/Discovery types show up as background; the higher-severity types are reserved
# for threat levels and for the correlated attack scenarios, where each finding is
# keyed to the SAME principal / instance / IP pivot as the CloudTrail step it
# corroborates, so the finding stitches into the same XSIAM case.

import json
import gzip
import random
import uuid
import os
from datetime import datetime, timezone, timedelta

try:
    from modules.session_utils import get_random_anon_ip_ctx
except ImportError:
    from session_utils import get_random_anon_ip_ctx

# --- Module Metadata ---
NAME = "AWS GuardDuty"
DESCRIPTION = "Simulates Amazon GuardDuty findings (schemaVersion 2.0) into aws_guardduty_raw."
XSIAM_VENDOR = "aws"          # must be lowercase to match the parsing-rule INGEST directive
XSIAM_PRODUCT = "guardduty"   # -> target_dataset aws_guardduty_raw
CONFIG_KEY = "aws_guardduty_config"

# S3 transport descriptors (read by log_simulator's send_s3_message / flush_s3_batch).
# GuardDuty's native export is <prefix>/<UUID>.jsonl.gz — newline-delimited findings,
# written under an AWSLogs/<account>/GuardDuty/<region>/ prefix, distinct from the
# CloudTrail prefix + {"Records":[...]} envelope so XSIAM parses it as GuardDuty.
S3_LOG_TYPE = "GuardDuty"
S3_RECORD_FORMAT = "jsonl"
# Optional: land in a dedicated bucket. If GUARDDUTY_S3_BUCKET_NAME is unset, the
# transport falls back to the shared S3_BUCKET_NAME (same bucket, GuardDuty/ prefix).
S3_BUCKET_ENV = "GUARDDUTY_S3_BUCKET_NAME"

last_threat_event_time = 0

# GuardDuty numeric severity bands: 1-3.9 Low, 4-6.9 Medium, 7-8.9 High.
# XSIAM modeling maps the numeric `severity` -> xdm.alert.severity.
_SEV_LOW, _SEV_MED, _SEV_HIGH = 2, 5, 8

# Realistic remote-IP enrichment blocks GuardDuty attaches to a caller IP.
_ORGS = [
    {"asn": "14061", "asnOrg": "DIGITALOCEAN-ASN", "isp": "DigitalOcean", "org": "DigitalOcean, LLC"},
    {"asn": "16509", "asnOrg": "AMAZON-02", "isp": "Amazon.com", "org": "Amazon Technologies Inc."},
    {"asn": "9009", "asnOrg": "M247", "isp": "M247 Europe SRL", "org": "M247 Europe SRL"},
    {"asn": "60068", "asnOrg": "CDN77", "isp": "Datacamp Limited", "org": "Datacamp Limited"},
    {"asn": "51167", "asnOrg": "Contabo", "isp": "Contabo GmbH", "org": "Contabo GmbH"},
]
_GEOS = [
    {"country": {"countryName": "Russia"}, "city": {"cityName": "Moscow"}, "lat": 55.7522, "lon": 37.6156},
    {"country": {"countryName": "Netherlands"}, "city": {"cityName": "Amsterdam"}, "lat": 52.374, "lon": 4.8897},
    {"country": {"countryName": "Romania"}, "city": {"cityName": "Bucharest"}, "lat": 44.4323, "lon": 26.1063},
    {"country": {"countryName": "Germany"}, "city": {"cityName": "Frankfurt"}, "lat": 50.1109, "lon": 8.6821},
    {"country": {"countryName": "Seychelles"}, "city": {"cityName": "Victoria"}, "lat": -4.6167, "lon": 55.45},
]

# --- Finding catalog -------------------------------------------------------
# Each entry: the real GuardDuty finding type, its severity band, a title/description
# template, and which resource shape + action to build. `resource_kind` drives the
# `resource` block; `api`/`service_name` drive the awsApiCallAction.
_FINDINGS = {
    # ── Tor / malicious-IP identity access (scenario 1, 23) ──
    "TOR_IP_CALLER": {
        "type": "UnauthorizedAccess:IAMUser/TorIPCaller",
        "severity": _SEV_MED, "resource_kind": "access_key",
        "title": "An API was invoked from a Tor exit node IP address.",
        "description": "An API commonly used to discover resources in an AWS environment was invoked "
                       "from a Tor exit node IP address {ip}. Tor is software that enables anonymous "
                       "communication and is frequently used to mask an attacker's true origin.",
        "api": "GetCallerIdentity", "service_name": "sts.amazonaws.com",
    },
    "MALICIOUS_IP_CALLER": {
        "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        "severity": _SEV_MED, "resource_kind": "access_key",
        "title": "An API was invoked from an IP address on a custom threat list.",
        "description": "An API was invoked from IP address {ip}, which is included on a custom threat "
                       "intelligence list, against principal {user}.",
        "api": "DescribeInstances", "service_name": "ec2.amazonaws.com",
    },
    # ── Privilege escalation (scenario 1, 21, 23) ──
    "ADMIN_PRIVESC": {
        "type": "PrivilegeEscalation:IAMUser/AdministrativePermissions",
        "severity": _SEV_HIGH, "resource_kind": "access_key",
        "title": "A user gained unusually high-level administrative permissions.",
        "description": "Principal {user} attempted to assign a highly permissive policy "
                       "(AdministratorAccess) to themselves, which is a common privilege-escalation "
                       "technique following a credential compromise.",
        "api": "AttachUserPolicy", "service_name": "iam.amazonaws.com",
    },
    # ── Defense evasion (scenario 1, 21) ──
    "CLOUDTRAIL_DISABLED": {
        "type": "Stealth:IAMUser/CloudTrailLoggingDisabled",
        "severity": _SEV_HIGH, "resource_kind": "access_key",
        "title": "AWS CloudTrail logging was disabled.",
        "description": "An AWS CloudTrail trail was disabled by principal {user} from IP {ip}. This can "
                       "be an attacker attempting to disable logging to cover their tracks.",
        "api": "StopLogging", "service_name": "cloudtrail.amazonaws.com",
    },
    "S3_LOGGING_DISABLED": {
        "type": "Stealth:S3/ServerAccessLoggingDisabled",
        "severity": _SEV_LOW, "resource_kind": "s3",
        "title": "S3 server access logging was disabled.",
        "description": "S3 server access logging was disabled for a bucket by principal {user}. "
                       "Disabling access logging is a defense-evasion technique.",
        "api": "PutBucketLogging", "service_name": "s3.amazonaws.com",
    },
    # ── Instance credential theft (scenario 20) ──
    "INSTANCE_CRED_EXFIL": {
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": _SEV_HIGH, "resource_kind": "access_key",
        "title": "Credentials created exclusively for an EC2 instance are being used from an external IP.",
        "description": "Credentials created exclusively for EC2 instance {instance} via the instance "
                       "metadata service are being used from external IP {ip} outside of AWS. This "
                       "indicates the instance role credentials were exfiltrated (e.g. via SSRF/IMDS).",
        "api": "ListBuckets", "service_name": "s3.amazonaws.com",
    },
    # ── S3 exfil / impact (scenario 20, 21) ──
    "S3_EXFIL": {
        "type": "Exfiltration:S3/AnomalousBehavior",
        "severity": _SEV_MED, "resource_kind": "s3",
        "title": "An IAM entity invoked S3 APIs in an anomalous way to retrieve data.",
        "description": "Principal {user} invoked S3 data-retrieval APIs (GetObject) in a manner that "
                       "deviates from its established baseline, from IP {ip}, consistent with data exfiltration.",
        "api": "GetObject", "service_name": "s3.amazonaws.com",
    },
    "S3_IMPACT": {
        "type": "Impact:S3/AnomalousBehavior",
        "severity": _SEV_HIGH, "resource_kind": "s3",
        "title": "An IAM entity invoked S3 APIs to tamper with or destroy data at scale.",
        "description": "Principal {user} invoked S3 write/delete APIs (PutObject/DeleteObjects) at a "
                       "volume and pattern that deviates from baseline, from IP {ip}, consistent with "
                       "ransomware encryption or destructive impact.",
        "api": "DeleteObjects", "service_name": "s3.amazonaws.com",
    },
    "S3_PUBLIC": {
        "type": "Policy:S3/BucketPublicAccessGranted",
        "severity": _SEV_HIGH, "resource_kind": "s3",
        "title": "An S3 bucket was granted public access.",
        "description": "Principal {user} granted public access to an S3 bucket. Public buckets can lead "
                       "to unauthorized data disclosure.",
        "api": "PutBucketAcl", "service_name": "s3.amazonaws.com",
    },
    # ── Low-severity recon (Mode-1 background) ──
    "RECON_IP": {
        "type": "Recon:IAMUser/MaliciousIPCaller.Custom",
        "severity": _SEV_LOW, "resource_kind": "access_key",
        "title": "Reconnaissance APIs were invoked from a suspicious IP.",
        "description": "Reconnaissance APIs commonly used to discover resources were invoked from IP "
                       "{ip}, which is included on a custom threat list.",
        "api": "DescribeSecurityGroups", "service_name": "ec2.amazonaws.com",
    },
    "S3_DISCOVERY": {
        "type": "Discovery:S3/AnomalousBehavior",
        "severity": _SEV_LOW, "resource_kind": "s3",
        "title": "An IAM entity invoked an S3 discovery API in an anomalous way.",
        "description": "Principal {user} invoked S3 discovery APIs (ListBuckets/GetBucketAcl) in a "
                       "manner that deviates from its established baseline.",
        "api": "ListBuckets", "service_name": "s3.amazonaws.com",
    },
}


# --- Helpers ---------------------------------------------------------------
def _now_iso(offset_sec=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_sec)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + "Z"


def _account_id(config):
    # Keep in lockstep with the CloudTrail module so findings share the account pivot.
    aws_conf = config.get('aws_config', {})
    return os.getenv('AWS_ACCOUNT_ID', aws_conf.get('aws_account_id', '123456789012'))


def _region(config, context):
    if context and context.get('aws_region'):
        return context['aws_region']
    aws_conf = config.get('aws_config', {})
    return os.getenv('AWS_REGION', aws_conf.get('aws_region', 'us-east-1'))


def _detector_id():
    return uuid.uuid4().hex[:32]


def _finding_id():
    return uuid.uuid4().hex[:40]


def _access_key():
    return "AKIA" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", k=16))


def _principal_id():
    return "AIDA" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", k=17))


def _pick_principal(config, context):
    """Resolve the IAM principal for the finding, preferring the pivot the scenario
    pinned (context user_identity), then a session_context linked IAM user, then the
    aws_config user pool, then a sane default."""
    ctx = context or {}
    ui = ctx.get('user_identity')
    if isinstance(ui, dict) and ui.get('name'):
        return ui['name']
    if isinstance(ui, str) and ui:
        return ui
    sc = ctx.get('session_context') or {}
    linked = [p.get('aws_iam_user') for p in sc.values() if p.get('aws_iam_user')]
    if linked:
        return random.choice(linked)
    pool = config.get('aws_config', {}).get('users_and_roles', [])
    names = [u.get('name') for u in pool if u.get('name')]
    if names:
        return random.choice(names)
    return random.choice(["j.harding", "s.patel", "m.russo", "devops-svc"])


def _pick_ip(context):
    ctx = context or {}
    for k in ('ip_address', 'src_ip', 'attacker_ip'):
        if ctx.get(k):
            return ctx[k]
    # Fall back to a fresh anonymised external IP.
    try:
        ipinfo = get_random_anon_ip_ctx(ctx)
        if isinstance(ipinfo, dict) and ipinfo.get('ip'):
            return ipinfo['ip']
        if isinstance(ipinfo, str):
            return ipinfo
    except Exception:
        pass
    return f"{random.randint(45,199)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _instance_id(context):
    ctx = context or {}
    return ctx.get('instance_id') or ("i-0" + uuid.uuid4().hex[:16])


def _remote_ip_details(ip):
    org = random.choice(_ORGS)
    geo = random.choice(_GEOS)
    return {
        "ipAddressV4": ip,
        "organization": org,
        "country": geo["country"],
        "city": geo["city"],
        "geoLocation": {"lat": geo["lat"], "lon": geo["lon"]},
    }


def _build_resource(kind, config, context, user_name, ip):
    account = _account_id(config)
    region = _region(config, context)
    if kind == "instance":
        return {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": _instance_id(context),
                "instanceType": "t3.large",
                "launchTime": _now_iso(-86400),
                "availabilityZone": f"{region}a",
                "iamInstanceProfile": {
                    "arn": f"arn:aws:iam::{account}:instance-profile/app-server-role",
                    "id": _principal_id(),
                },
                "networkInterfaces": [{"privateIpAddress": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
                                       "publicIp": ip, "vpcId": "vpc-" + uuid.uuid4().hex[:8]}],
                "tags": [{"key": "Name", "value": "app-server-prod"}],
            },
        }
    if kind == "s3":
        bucket = random.choice(["corp-financials-prod", "customer-pii-store", "app-backups-prod", "data-lake-raw"])
        return {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [{
                "arn": f"arn:aws:s3:::{bucket}",
                "name": bucket,
                "type": "Destination",
                "createdAt": _now_iso(-864000),
                "owner": {"id": uuid.uuid4().hex},
                "defaultServerSideEncryption": {"encryptionType": "aws:kms"},
                "publicAccess": {"effectivePermission": "PUBLIC" if kind == "s3" else "NOT_PUBLIC"},
            }],
            "accessKeyDetails": {
                "accessKeyId": _access_key(), "principalId": _principal_id(),
                "userType": "IAMUser", "userName": user_name,
            },
        }
    # default: access_key
    return {
        "resourceType": "AccessKey",
        "accessKeyDetails": {
            "accessKeyId": _access_key(), "principalId": _principal_id(),
            "userType": "IAMUser", "userName": user_name,
        },
    }


def build_finding(finding_key, config, context=None, count=1):
    """Assemble one full GuardDuty schemaVersion-2.0 finding for the given catalog key,
    keyed to the scenario's principal / instance / IP pivot. Returns a dict."""
    spec = _FINDINGS.get(finding_key)
    if not spec:
        return None
    context = context or {}
    account = _account_id(config)
    region = _region(config, context)
    user_name = _pick_principal(config, context)
    ip = _pick_ip(context)
    instance = _instance_id(context)
    detector = _detector_id()
    fid = _finding_id()
    now = _now_iso()
    first_seen = _now_iso(-random.randint(120, 900))

    resource = _build_resource(spec["resource_kind"], config, context, user_name, ip)

    action = {
        "actionType": "AWS_API_CALL",
        "awsApiCallAction": {
            "api": spec["api"],
            "serviceName": spec["service_name"],
            "callerType": "Remote IP",
            "remoteIpDetails": _remote_ip_details(ip),
            "affectedResources": {},
        },
    }

    desc = spec["description"].format(user=user_name, ip=ip, instance=instance)

    finding = {
        "schemaVersion": "2.0",
        "accountId": account,
        "region": region,
        "partition": "aws",
        "id": fid,
        "arn": f"arn:aws:guardduty:{region}:{account}:detector/{detector}/finding/{fid}",
        "type": spec["type"],
        "resource": resource,
        "service": {
            "serviceName": "guardduty",
            "detectorId": detector,
            "action": action,
            "resourceRole": "TARGET",
            "additionalInfo": {"threatListName": "CustomThreatList", "value": spec["type"]},
            "evidence": {"threatIntelligenceDetails": [{"threatListName": "CustomThreatList",
                                                        "threatNames": [spec["type"].split(":")[-1]]}]},
            "eventFirstSeen": first_seen,
            "eventLastSeen": now,
            "archived": False,
            "count": count,
        },
        "severity": spec["severity"],
        "createdAt": first_seen,
        "updatedAt": now,
        "title": spec["title"],
        "description": desc,
    }
    return finding


def _emit(finding_key, config, context=None, count=1):
    """Return a one-element list holding the finding DICT. Serialisation to the wire
    format happens in _serialize() based on the configured transport."""
    f = build_finding(finding_key, config, context, count=count)
    if not f:
        return None
    return [f]


def _serialize(findings, config):
    """Turn a list of finding dicts into the shape the configured transport expects.

    - s3 (default): a gzipped JSON array of findings (bytes). log_simulator batches
      these per module and re-emits them as newline-delimited .jsonl.gz — matching
      GuardDuty's native S3 export.
    - http: a list of JSON strings, one per finding (each POSTed as one event).
    """
    if not findings:
        return None
    transport = config.get(CONFIG_KEY, {}).get('transport', 's3')
    if transport == 'http':
        return [json.dumps(f) for f in findings]
    return gzip.compress(json.dumps(findings, default=str).encode('utf-8'))


# --- Scenario entry points (called via generate_log(scenario_event=...)) ----
# Keys are referenced from the correlated attack scenarios in log_simulator.py so a
# finding fires at the corroborating CloudTrail step, on the same pivot/context.
def _sc_tor_login(config, context=None):        return _emit("TOR_IP_CALLER", config, context)
def _sc_malicious_ip(config, context=None):     return _emit("MALICIOUS_IP_CALLER", config, context)
def _sc_admin_privesc(config, context=None):    return _emit("ADMIN_PRIVESC", config, context)
def _sc_cloudtrail_off(config, context=None):   return _emit("CLOUDTRAIL_DISABLED", config, context)
def _sc_s3_logging_off(config, context=None):   return _emit("S3_LOGGING_DISABLED", config, context)
def _sc_instance_cred_exfil(config, context=None): return _emit("INSTANCE_CRED_EXFIL", config, context)
def _sc_s3_exfil(config, context=None):         return _emit("S3_EXFIL", config, context)
def _sc_s3_impact(config, context=None):        return _emit("S3_IMPACT", config, context, count=random.randint(50, 250))
def _sc_s3_public(config, context=None):        return _emit("S3_PUBLIC", config, context)


SCENARIO_FUNCTIONS = {
    "GD_TOR_LOGIN": _sc_tor_login,
    "GD_MALICIOUS_IP": _sc_malicious_ip,
    "GD_ADMIN_PRIVESC": _sc_admin_privesc,
    "GD_CLOUDTRAIL_DISABLED": _sc_cloudtrail_off,
    "GD_S3_LOGGING_DISABLED": _sc_s3_logging_off,
    "GD_INSTANCE_CRED_EXFIL": _sc_instance_cred_exfil,
    "GD_S3_EXFIL": _sc_s3_exfil,
    "GD_S3_IMPACT": _sc_s3_impact,
    "GD_S3_PUBLIC": _sc_s3_public,
}

# Mode-1 pools. GuardDuty has no benign "activity", so benign mode surfaces only rare
# low-severity recon; higher severities appear when a threat level injects them.
BENIGN_KEYS = ["RECON_IP", "S3_DISCOVERY"]
SUSPICIOUS_KEYS = ["MALICIOUS_IP_CALLER", "TOR_IP_CALLER", "S3_EXFIL", "S3_LOGGING_DISABLED", "S3_DISCOVERY"]
THREAT_KEYS = ["ADMIN_PRIVESC", "CLOUDTRAIL_DISABLED", "INSTANCE_CRED_EXFIL", "S3_IMPACT", "S3_PUBLIC"]


def get_threat_names():
    """Named threats for Mode 3 (specific-threat) selection."""
    return list(SCENARIO_FUNCTIONS.keys())


def _get_threat_interval(threat_level, config):
    if threat_level == "Benign Traffic Only":
        return 86400 * 365
    levels = config.get('threat_generation_levels', {})
    return levels.get(threat_level, 7200)


def generate_log(config, context=None, threat_level="Benign", benign_only=False, scenario_event=None):
    """Return findings serialised for the configured transport, or None.

    Wire shape (see _serialize): s3 -> gzipped JSON array (bytes, batched to .jsonl.gz);
    http -> list of JSON strings.

    - scenario_event: fire a specific catalog finding (used by correlated scenarios).
    - benign_only / Benign Traffic Only: near-silent, only rare low-severity recon.
    - threat levels: time-gated injection of suspicious/threat findings.
    """
    import time, logging
    logger = logging.getLogger('simulator.aws_guardduty')
    global last_threat_event_time
    context = context or {}

    # Enrich the IAM pool from session_context so findings reference linked identities.
    sc = context.get('session_context')
    if sc and 'aws_config' in config:
        existing = {u.get('name') for u in config['aws_config'].get('users_and_roles', [])}
        for p in sc.values():
            iam = p.get('aws_iam_user')
            if iam and iam not in existing:
                config['aws_config'].setdefault('users_and_roles', []).append(
                    {"type": "IAMUser", "name": iam, "arn_suffix": f"user/{iam}"})
                existing.add(iam)

    findings = None  # list of finding dicts

    if scenario_event:
        fn = SCENARIO_FUNCTIONS.get(scenario_event)
        if not fn:
            logger.warning("Unknown GuardDuty scenario_event: %s", scenario_event)
            return None
        try:
            findings = fn(config, context)
        except Exception as e:
            logger.exception("GuardDuty scenario generator %s failed: %s", scenario_event, e)
            return None
        return _serialize(findings, config)

    # Non-scenario (Mode 1) selection.
    if benign_only or threat_level == "Benign Traffic Only":
        # Real GuardDuty is quiet in a clean environment — emit a low-sev finding rarely.
        if random.random() < 0.15:
            findings = _emit(random.choice(BENIGN_KEYS), config, context)
        return _serialize(findings, config)

    if threat_level == "Insane":
        key = random.choice(BENIGN_KEYS + SUSPICIOUS_KEYS + THREAT_KEYS)
        return _serialize(_emit(key, config, context), config)

    interval = _get_threat_interval(threat_level, config)
    now = time.time()
    if interval > 0 and (now - last_threat_event_time) > interval:
        last_threat_event_time = now
        key = random.choice(SUSPICIOUS_KEYS + THREAT_KEYS)
        return _serialize(_emit(key, config, context), config)

    # Between threats: mostly silent, occasional low-sev background.
    if random.random() < 0.10:
        findings = _emit(random.choice(BENIGN_KEYS), config, context)
    return _serialize(findings, config)
