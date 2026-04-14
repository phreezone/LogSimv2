import json
import datetime
import random
import uuid
import gzip
import io
import time # Added for sleep between actions
from ipaddress import ip_network, ip_address # Added for IP generation
import base64 # Added for UserData simulation

try:
    from modules.session_utils import get_random_anon_ip_ctx, get_random_vpn_ip_ctx
except ImportError:
    from session_utils import get_random_anon_ip_ctx, get_random_vpn_ip_ctx

# Realistic AWS SDK/CLI user agents for CloudTrail events.
# CloudTrail records the SDK/CLI used by the caller, NOT browser user agents.
_AWS_USER_AGENTS = [
    "aws-cli/2.15.30 Python/3.11.8 Linux/5.15.0-113-generic exe/x86_64 prompt/off",
    "aws-cli/2.17.4 Python/3.12.3 Windows/10 exe/AMD64 prompt/off",
    "aws-cli/2.13.21 Python/3.11.5 Darwin/22.6.0 source/x86_64 prompt/off",
    "aws-cli/1.33.2 Python/3.11.8 Linux/5.15.0-113-generic botocore/1.35.2",
    "Boto3/1.34.69 Python/3.11.8 Linux/5.15.0-113-generic Botocore/1.34.69",
    "Boto3/1.35.0 Python/3.12.1 Windows/10 Botocore/1.35.0",
    "Boto3/1.33.11 Python/3.10.12 Linux/5.15.0-91-generic Botocore/1.33.11",
    "aws-sdk-go/1.55.5 (go1.22.0; linux; amd64)",
    "aws-sdk-go-v2/1.30.5 os/linux lang/go/1.22.0 md/GOOS/linux md/GOARCH/amd64",
    "aws-sdk-go/1.44.180 (go1.20.4; linux; amd64)",
    "aws-sdk-java/2.25.16 ua/2.1 os/linux/5.15 lang/java/21 md/OpenJDK_JVM/21.0.1",
    "aws-sdk-java/1.12.600 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/21.0.1 Java/21.0.1",
    "aws-sdk-js/2.1691.0 OS/linux OS/20.14.0 lang/js md/nodejs/20.14.0",
    "aws-sdk-js-v3/3.540.0 os/Linux lang/js/20.14.0 md/nodejs/20.14.0",
    "HashiCorp Terraform/1.9.5 (+https://www.terraform.io) terraform-provider-aws/5.65.0",
    "HashiCorp Terraform/1.7.4 (+https://www.terraform.io) terraform-provider-aws/5.40.0",
    "aws-sdk-ruby3/3.187.0 ruby/3.2.0 x86_64-linux",
    "aws-sdk-php/3.300.0 OS/Linux/5.15.0 PHP/8.2.0",
    "aws-cdk/2.150.0 Node.js/20.14.0 (linux; x64)",
    "Ansible/2.16.3 (Python 3.11.8)",
]

# --- Module Metadata ---
NAME = "aws"
DESCRIPTION = "Simulates various AWS CloudTrail events to trigger XSIAM analytics."
XSIAM_VENDOR = "AWS"
XSIAM_PRODUCT = "CloudTrail"
CONFIG_KEY = "aws_config"
last_threat_event_time = 0


# --- Helper Functions ---
def _get_threat_interval(threat_level, config):
    """Gets the threat interval based on the selected level."""
    if threat_level == "Benign Traffic Only":
        return 86400 * 365 # Effectively infinite for benign mode
    levels = config.get('threat_generation_levels', {})
    # Default to 2 hours if level not found
    return levels.get(threat_level, 7200)


def _get_random_user(config, allow_root=False):
    """Gets a random user/role identity from the config."""
    aws_conf = config.get(CONFIG_KEY, {})
    user_pool = aws_conf.get('users_and_roles', [])
    account_id = aws_conf.get('aws_account_id', '123456789012')

    # Special case for Root user simulation
    if allow_root and random.random() < 0.05: # Reduced chance for Root activity
         return {"type": "Root", "name": "Root", "arn": f"arn:aws:iam::{account_id}:root", "principalId": account_id, "accountId": account_id} # Fully specify for Root

    if not user_pool:
        # Provide a default fallback user if the config list is empty
        default_user = {"type": "IAMUser", "name": "DefaultUser", "arn_suffix": "user/DefaultUser"}
        # Pre-build ARN and Principal ID for the default user
        default_user['arn'] = f"arn:aws:iam::{account_id}:{default_user['arn_suffix']}"
        default_user['principalId'] = f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
        default_user['accountId'] = account_id
        return default_user

    chosen_identity_template = random.choice(user_pool)

    # --- Pre-calculate ARN and Principal ID ---
    final_identity = chosen_identity_template.copy() # Avoid modifying the original config entry
    final_identity['accountId'] = account_id # Ensure accountId is set

    # Build ARN if not present
    if 'arn' not in final_identity and 'arn_suffix' in final_identity:
        final_identity['arn'] = f"arn:aws:iam::{account_id}:{final_identity['arn_suffix']}"

    # Build PrincipalId if not present
    if 'principalId' not in final_identity:
        principal_id_prefix = ""
        principal_id_main = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=17))
        id_type = final_identity.get('type', 'IAMUser')

        if id_type == 'IAMUser':
            principal_id_prefix = "AIDA"
        elif id_type in ['AssumedRole', 'Role']:
            principal_id_prefix = "AROA"
        elif id_type in ['FederatedUser', 'SAMLUser']:
            principal_id_prefix = "AIDAF"
        elif id_type == 'Root':
             final_identity['principalId'] = account_id
             return final_identity
        else: # AWSAccount, Service, etc. - less common for API calls we simulate but possible
            principal_id_prefix = "AIDAU" # U for unknown/unspecified generator logic

        if id_type in ['AssumedRole', 'Role']:
             role_id_part = f"{principal_id_prefix}{principal_id_main}"
             # Ensure 'name' exists before splitting
             session_name_part = final_identity.get('name', 'DefaultSession').split('/')[-1] if '/' in final_identity.get('name', 'DefaultSession') else 'DefaultSession'
             final_identity['principalId'] = f"{role_id_part}:{session_name_part}"
             # Store the base Role ID for sessionIssuer later
             final_identity['_baseRoleId'] = role_id_part # Internal helper field
        else:
            final_identity['principalId'] = f"{principal_id_prefix}{principal_id_main}"

    return final_identity


def _get_random_ip(config, use_tor=False, force_external=False, use_anon=False):
    """Gets a random IP address, from internal, external, Tor, or anonymizer (VPN/Tor mix) sources.

    use_tor=True  — always a Tor exit node (use for Tor-specific detections)
    use_anon=True — 70% commercial VPN / 30% Tor mix (use for general anonymizer scenarios)
    """
    if use_anon:
        return get_random_anon_ip_ctx(config)["ip"]
    if use_tor:
        tor_nodes = config.get('tor_exit_nodes', [])
        if tor_nodes:
            return random.choice(tor_nodes)['ip']
        else:
            print("Warning: Tor IP requested but 'tor_exit_nodes' list is empty in config. Falling back.")

    # Simulate internal IPs more often, unless forced external
    if not force_external and random.random() < 0.7:
        internal_cidrs = config.get('internal_networks', ["192.168.1.0/24"])
        if internal_cidrs:
            chosen_cidr = random.choice(internal_cidrs)
            try:
                network = ip_network(chosen_cidr, strict=False)
                # Generate an IP within the network range (avoiding network/broadcast if possible)
                if network.num_addresses > 2:
                     addr_int = random.randint(int(network.network_address) + 1, int(network.broadcast_address) - 1)
                elif network.num_addresses == 2: # Handle /31
                     addr_int = random.randint(int(network.network_address), int(network.broadcast_address))
                else: # Handle /32 or invalid single IPs defined without CIDR
                    addr_int = int(network.network_address)

                return str(ip_address(addr_int))
            except ValueError:
                 # Fallback for invalid CIDR or single IP definition like "1.2.3.4"
                 parts = chosen_cidr.split('/')[0].split('.')
                 if len(parts) == 4:
                     try:
                         # Check if it's just a single IP address
                         ip_address(chosen_cidr.split('/')[0])
                         return chosen_cidr.split('/')[0]
                     except ValueError:
                         # Invalid IP format, generate random internal
                         return f"192.168.1.{random.randint(2, 254)}"
                 else:
                    return f"192.168.1.{random.randint(2, 254)}" # Default internal
        else:
             return f"192.168.1.{random.randint(2, 254)}" # Default internal


    # Simulate external benign IPs (or any external if force_external is True)
    benign_sources = config.get('benign_ingress_sources', [])
    if benign_sources and (force_external or random.random() < 0.9):
        source_info = random.choice(benign_sources)
        source_cidr = source_info.get('ip_range') # Use .get for safety
        if source_cidr:
            try:
                network = ip_network(source_cidr, strict=False)
                addr_int = random.randint(int(network.network_address), int(network.broadcast_address))
                return str(ip_address(addr_int))
            except ValueError:
                 # Fallback for invalid CIDR in benign sources
                 parts = source_cidr.split('/')[0].split('.')
                 if len(parts) == 4:
                     return f"{parts[0]}.{parts[1]}.{random.randint(0, 255)}.{random.randint(2, 254)}"
                 # If CIDR is bad and not IPv4-like, fall through to random public
        # Fall through if no ip_range or it's invalid

    # Fallback public IP if other methods fail or are skipped
    # Avoid reserved ranges like 192.0.2.0/24 (TEST-NET-1), etc.
    while True:
        ip = ".".join(map(str, (random.randint(1, 223) for _ in range(4))))
        try:
            addr = ip_address(ip)
            if not addr.is_private and not addr.is_loopback and not addr.is_link_local and not addr.is_multicast and not addr.is_reserved:
                 # Basic check against common documentation ranges
                 if not (ip.startswith("192.0.2.") or ip.startswith("198.51.100.") or ip.startswith("203.0.113.")):
                     return ip
        except ValueError:
            continue # Should not happen with current generation logic


def _get_base_event(config, user_identity, ip_address, region, event_name, event_source, api_version=None, read_only=False):
    """
    Creates the comprehensive base structure for a CloudTrail event.
    Comments map raw fields to their corresponding XDM fields.
    """
    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012')) # Use accountId from identity if present

    # Use timezone-aware datetime object
    now = datetime.datetime.now(datetime.UTC)

    # Check if ARN and PrincipalId are *already provided* (e.g., from an assumed role object).
    # If not, build them from arn_suffix.
    user_arn = user_identity.get('arn')
    if not user_arn:
        user_arn = f"arn:aws:iam::{account_id}:{user_identity.get('arn_suffix', 'user/DefaultFallbackArn')}"

    principal_id = user_identity.get('principalId')
    if not principal_id:
        principal_id_prefix = ""
        principal_id_main = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=17))
        id_type = user_identity.get('type', 'IAMUser')

        if id_type == 'IAMUser':
            principal_id_prefix = "AIDA"
        elif id_type in ['AssumedRole', 'Role']:
            principal_id_prefix = "AROA"
        elif id_type in ['FederatedUser', 'SAMLUser']:
            principal_id_prefix = "AIDAF"
        elif id_type == 'Root':
             principal_id = account_id # Special case for Root
        else: # AWSAccount, Service, etc.
            principal_id_prefix = "AIDAU"

        if id_type in ['AssumedRole', 'Role']:
             role_id_part = f"{principal_id_prefix}{principal_id_main}"
             # Ensure 'name' exists before splitting
             session_name_part = user_identity.get('name', 'DefaultSession').split('/')[-1] if '/' in user_identity.get('name', 'DefaultSession') else 'DefaultSession'
             principal_id = f"{role_id_part}:{session_name_part}"
             # Store the base Role ID for sessionIssuer later
             user_identity['_baseRoleId'] = role_id_part # Internal helper field
        elif id_type != 'Root': # Avoid overwriting Root's principalId
            principal_id = f"{principal_id_prefix}{principal_id_main}"


    # Build accessKeyId - AKIA for long-term IAM/Root keys, ASIA for temporary STS credentials
    # Not present for ConsoleLogin events per AWS docs
    if event_name != "ConsoleLogin":
        if 'accessKeyId' in user_identity:
            _access_key_id = user_identity['accessKeyId']
        else:
            id_type_for_key = user_identity.get('type', 'IAMUser')
            if id_type_for_key in ['AssumedRole', 'FederatedUser', 'SAMLUser']:
                _access_key_id = f"ASIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}"
            elif id_type_for_key in ['IAMUser', 'Root']:
                _access_key_id = f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}"
            else:
                _access_key_id = None
    else:
        _access_key_id = None

    user_identity_block = {
        "type": user_identity['type'],                                     # -> xdm.source.user.user_type
        "principalId": principal_id,                                       # -> xdm.source.user.identifier (partially)
        "arn": user_arn,                                                   # -> xdm.source.user.identifier (partially) / used to derive username sometimes
        "accountId": account_id                                            # -> xdm.source.cloud.project_id
    }

    if _access_key_id:
        user_identity_block["accessKeyId"] = _access_key_id               # -> used by "Remote usage of Lambda role" detector

    # Add userName if explicitly provided or derivable.
    # Real CloudTrail only includes top-level userName for IAMUser and Root identity types.
    # AssumedRole identities do NOT have a top-level userName — the role name lives exclusively
    # in sessionContext.sessionIssuer.userName. Adding it here would be detectable as synthetic.
    if 'userName' in user_identity:
         user_identity_block["userName"] = user_identity['userName']
    elif user_identity['type'] == 'IAMUser' and 'name' in user_identity:
         user_identity_block["userName"] = user_identity['name']


    # Build sessionContext if needed and not already provided
    if 'sessionContext' in user_identity:
        user_identity_block["sessionContext"] = user_identity['sessionContext']
    elif user_identity['type'] in ['AssumedRole', 'Role']:
         # Ensure 'name' exists before splitting
         session_name = user_identity.get('name', 'DefaultSession').split('/')[-1] if '/' in user_identity.get('name', 'DefaultSession') else 'DefaultSession'
         role_name_for_issuer = user_identity['name'].split('/')[0] if '/' in user_identity.get('name','') else user_identity.get('name','')
         role_arn_for_issuer = f"arn:aws:iam::{account_id}:role/{role_name_for_issuer}" # Construct role ARN for issuer
         role_id_for_issuer = user_identity.get('_baseRoleId', f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}") # Use stored base ID or generate

         user_identity_block["sessionContext"] = {
            "sessionIssuer": {
                "type": "Role",
                "principalId": role_id_for_issuer,
                "arn": role_arn_for_issuer,
                "accountId": account_id,
                "userName": role_name_for_issuer # -> xdm.source.user.groups (partially)
            },
            "attributes": {
                "mfaAuthenticated": str(random.choice([True, False])).lower(),
                "creationDate": now.strftime('%Y-%m-%dT%H:%M:%SZ')
            }
        }
         # Add invokedBy for AssumedRole if relevant (simulating a service assuming the role)
         invoker_service = user_identity.get('invokedBy') # Check if it's already set
         if not invoker_service and random.random() < 0.3:
             invoker_service = random.choice(["ec2.amazonaws.com", "lambda.amazonaws.com", "ecs-tasks.amazonaws.com"])

         if invoker_service:
            user_identity_block["invokedBy"] = invoker_service

    elif user_identity['type'] == 'FederatedUser' or user_identity['type'] == 'SAMLUser':
         # Simplified session context for federated users
         user_identity_block["sessionContext"] = {
             "attributes": {
                 "mfaAuthenticated": "false",
                 "creationDate": now.strftime('%Y-%m-%dT%H:%M:%SZ')
             },
             "sessionIssuer": { # Example Issuer (IdP)
                 "type": "IAM", # Could also be SAML Provider ARN
                 "principalId": f"AIDAF{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}", # Could be IdP User ID
                 "arn": f"arn:aws:iam::{account_id}:saml-provider/SimulatedIDP",
                 "accountId": account_id,
                 "userName": "SimulatedIDP"
             }
         }
    elif user_identity['type'] == 'Root':
        # Root user has specific session context attributes when using MFA
        if random.random() < 0.8: # Assume MFA is used often for Root
            user_identity_block["sessionContext"] = {
                 "attributes": {
                    "mfaAuthenticated": "true",
                    "creationDate": now.strftime('%Y-%m-%dT%H:%M:%SZ')
                 }
            }
        else:
             user_identity_block["sessionContext"] = {
                 "attributes": {
                    "mfaAuthenticated": "false",
                    "creationDate": now.strftime('%Y-%m-%dT%H:%M:%SZ')
                 }
            }


    aws_conf_for_ua = config.get(CONFIG_KEY, {})
    ua_list = aws_conf_for_ua.get('user_agents', _AWS_USER_AGENTS)
    user_agent_choice = random.choice(ua_list) if ua_list else "aws-cli/2.15.30 Python/3.11.8 Linux/5.15.0-113-generic exe/x86_64 prompt/off"

    # Determine managementEvent and eventCategory.
    # CloudTrail data events (data-plane API calls) require managementEvent=false and eventCategory="Data".
    # Management events (control-plane) are the default.
    _DATA_EVENTS = {
        "s3.amazonaws.com": {
            "GetObject", "PutObject", "DeleteObject", "CopyObject", "HeadObject", "DeleteObjects",
        },
        "dynamodb.amazonaws.com": {
            "GetItem", "PutItem", "UpdateItem", "DeleteItem",
            "Query", "Scan", "BatchGetItem", "BatchWriteItem",
            "ExecuteStatement", "BatchExecuteStatement",
        },
        "bedrock-runtime.amazonaws.com": {
            "InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream",
        },
        "bedrock-agent-runtime.amazonaws.com": {
            "Retrieve", "RetrieveAndGenerate", "InvokeAgent",
        },
        "lambda.amazonaws.com": {
            "Invoke", "InvokeWithResponseStream",
        },
        "logs.amazonaws.com": {
            "GetLogEvents", "FilterLogEvents",
        },
        "rds.amazonaws.com": {
            "DownloadDBLogFilePortion",
        },
    }
    management_event = True
    event_category = "Management"
    if event_name in _DATA_EVENTS.get(event_source, set()):
        management_event = False
        event_category = "Data"

    # Build TLS host header - service-specific endpoint
    if 'signin' in event_source:
        tls_host = f"us-east-1.signin.aws.amazon.com"
    elif 'iam' in event_source or region in ['us-east-1', 'global']:
        tls_host = event_source
    else:
        tls_host = event_source.replace("amazonaws.com", f"{region}.amazonaws.com")

    base_event = {
        "eventVersion": "1.11",                                           # -> xdm.observer.content_version
        "userIdentity": user_identity_block,
        "eventTime": now.strftime('%Y-%m-%dT%H:%M:%SZ'),                  # -> _time
        "eventSource": event_source,                                      # -> xdm.observer.name
        "eventName": event_name,                                          # -> xdm.event.operation_sub_type / xdm.event.type
        "awsRegion": region,                                              # -> xdm.target.cloud.region
        "sourceIPAddress": ip_address,                                    # -> xdm.source.ipv4 / xdm.source.ipv6 / xdm.source.host.fqdn / xdm.source.host.ipv4_public_addresses
        "userAgent": user_agent_choice,                                   # -> xdm.source.user_agent
        "requestID": str(uuid.uuid4()),                                   # -> xdm.network.session_id
        "eventID": str(uuid.uuid4()),                                     # -> xdm.event.id
        "readOnly": read_only,                                            # Set based on action
        "eventType": "AwsConsoleSignIn" if event_name == "ConsoleLogin" else "AwsApiCall", # -> xdm.event.original_event_type
        "managementEvent": management_event,                              # Set based on category
        "recipientAccountId": account_id,                                 # -> xdm.target.cloud.project_id (partially)
        "eventCategory": event_category,                                  # -> xdm.observer.type
        "tlsDetails": {                                                   # -> xdm.network.tls.*
            "tlsVersion": random.choice(["TLSv1.2", "TLSv1.3"]),
            "cipherSuite": random.choice([
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "TLS_AES_128_GCM_SHA256",  # TLSv1.3
                "TLS_AES_256_GCM_SHA384"   # TLSv1.3
                ]),
            "clientProvidedHostHeader": tls_host                         # -> xdm.target.host.fqdn / xdm.target.host.hostname
        },
    }

    # Add apiVersion if provided (not usually present for ConsoleLogin)
    if api_version and event_name != "ConsoleLogin":
        base_event["apiVersion"] = api_version

    # vpcEndpointId is only present when the call was made via a VPC Endpoint (~25% of calls)
    if random.random() < 0.25:
        vpc_endpoint_id = f"vpce-{''.join(random.choices('0123456789abcdef', k=17))}"
        base_event["vpcEndpointId"] = vpc_endpoint_id                    # -> xdm.source.host.device_id
        base_event["vpcEndpointAccountId"] = account_id

    # sharedEventID is only present for cross-account events that generate multiple CloudTrail records
    if random.random() < 0.05:
        base_event["sharedEventID"] = str(uuid.uuid4())                  # -> xdm.session_context_id

    # sessionCredentialFromConsole: string "true" for console-initiated sessions
    if event_name == 'ConsoleLogin' and user_identity['type'] != 'Root':
        base_event["sessionCredentialFromConsole"] = "true"

    return base_event

# --- Event Template Functions ---

# --- BENIGN SCENARIOS ---
# These functions simulate common, everyday read and write operations.
def _generate_s3_get_object(config, context=None):
    """(Benign) Generates a successful S3 GetObject event."""
    user_identity = None
    ip_address = None
    # FIX: Safely handle context
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')

    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    target_bucket = random.choice(s3_buckets)
    target_key = f"logs/server-log-{random.randint(1000, 9999)}.log"
    bucket_arn = f"arn:aws:s3:::{target_bucket}"
    object_arn = f"arn:aws:s3:::{target_bucket}/{target_key}"

    event = _get_base_event(config, user_identity, ip_address, region, "GetObject", "s3.amazonaws.com", api_version="2006-03-01", read_only=True) # Data event, but is read-only
    event.update({
        "managementEvent": False,
        "eventCategory": "Data",
        "requestParameters": {
            "bucketName": target_bucket,
            "key": target_key,
            "Host": f"{target_bucket}.s3.{region}.amazonaws.com"
            },
        "responseElements": {
            "x-amz-request-id": str(uuid.uuid4()),
             "x-amz-id-2": ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=76))
        },
        "resources": [
            {"type": "AWS::S3::Object", "ARN": object_arn, "accountId": account_id},
            {"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}
            ]
    })
    return [event]

def _generate_s3_make_public_acl(config, context=None):
    """(Threat) Simulates making an S3 bucket public via PutBucketAcl."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')

    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    target_bucket = random.choice(s3_buckets)
    bucket_arn = f"arn:aws:s3:::{target_bucket}"

    # Construct the ACL grant for public read
    acl_policy = {
        "AccessControlList": {
            "Grant": [{
                "Grantee": {
                    # URI for the "AllUsers" group
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    "Type": "Group"
                },
                "Permission": "READ" # Grant read permission
            }]
            # Note: A real PutBucketAcl would likely include the Owner grant too,
            # but for detection, the AllUsers grant is the critical part.
        }
        # Owner is implicitly the bucket owner
    }

    event = _get_base_event(config, user_identity, ip_address, region, "PutBucketAcl", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)
    event.update({
        "requestParameters": {
            "bucketName": target_bucket,
            "AccessControlPolicy": acl_policy,
            "Host": f"{target_bucket}.s3.{region}.amazonaws.com"
        },
        "responseElements": None, # Successful PutBucketAcl often has null responseElements
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
    })
    return [event]

def _generate_ec2_describe_instances(config, context=None):
    """(Benign) Generates a successful EC2 DescribeInstances event."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    ami_id = "ami-0abcdef1234567890"

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeInstances", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
    event.update({
        "requestParameters": {
            "filterSet": { # Simulate a common filter
                "items": [
                    {"name": "instance-state-name", "valueSet": {"items": [{"value": "running"}]}}
                ]
            }
        },
        "responseElements": {
            "reservationSet": {"items": [ # Simulate a single instance in the response
                {"reservationId": f"r-{''.join(random.choices('0123456789abcdef', k=17))}", "ownerId": account_id, "instancesSet": {"items": [
                    {"instanceId": instance_id, "imageId": ami_id, "instanceState": {"code": 16, "name": "running"}, "instanceType": "t3.micro"}
                ]}}
            ]},
            "requestId": str(uuid.uuid4())
        },
        "resources": [] # DescribeInstances does not target a specific resource ARN in the request
    })
    return [event]


def _generate_s3_list_buckets(config, context=None):
    """(Benign) Generates a successful S3 ListBuckets event."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # ListBuckets is a global action
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))
    
    # Simulate a partial list of buckets from config
    s3_buckets = config.get(CONFIG_KEY, {}).get("s3_buckets", ["default-sim-bucket-1"])
    bucket_list_sample = random.sample(s3_buckets, k=min(len(s3_buckets), 3))
    # Use timezone-aware datetime
    now = datetime.datetime.now(datetime.UTC)
    creation_time = (now - datetime.timedelta(days=random.randint(30, 365))).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z' # Format with millis
    bucket_response_items = [{"name": bucket, "creationDate": creation_time} for bucket in bucket_list_sample]


    event = _get_base_event(config, user_identity, ip_address, region, "ListBuckets", "s3.amazonaws.com", api_version="2006-03-01", read_only=True)
    event.update({
        "requestParameters": {"Host": "s3.amazonaws.com"},
        "responseElements": {
            "owner": {"id": f"{''.join(random.choices('0123456789abcdef', k=64))}", "displayName": user_identity.get('name', 'owner-name')},
            "buckets": {"bucket": bucket_response_items}
        },
        "resources": [] # ListBuckets is a global action, does not target a specific resource
    })
    return [event]

def _generate_cloudtrail_describe_trails(config, context=None):
    """(Benign) Simulates describing CloudTrail trails."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1') # DescribeTrails can be regional but often called in us-east-1 or home region
    event = _get_base_event(config, user_identity, ip_address, region, "DescribeTrails", "cloudtrail.amazonaws.com", api_version="2013-11-01", read_only=True)

    # Simulate describing one of the trails from config
    trail_name = random.choice(aws_conf.get("cloudtrails", ["management-events-trail"]))
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"
    s3_bucket = random.choice(aws_conf.get("s3_buckets", ["default-trail-bucket"]))

    event.update({
        "requestParameters": {}, # DescribeTrails often called without specific trail names
        "responseElements": {
             "trailList": [ # Simulate response for one trail
                {
                    "name": trail_name,
                    "s3BucketName": s3_bucket,
                    "includeGlobalServiceEvents": True,
                    "isMultiRegionTrail": True,
                    "trailARN": trail_arn,
                    "logFileValidationEnabled": True,
                    "isOrganizationTrail": False,
                    "homeRegion": region
                }
             ]
        },
        "resources": [] # DescribeTrails doesn't target specific resource ARNs in request
    })
    return [event]

def _generate_iam_list_roles(config, context=None):
    """(Benign) Simulates listing IAM roles."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # IAM is global
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))
    event = _get_base_event(config, user_identity, ip_address, region, "ListRoles", "iam.amazonaws.com", api_version="2010-05-08", read_only=True)

    # Simulate one role from the config in the response
    role_sample = random.choice(config.get(CONFIG_KEY, {}).get('users_and_roles', [{}]))
    if role_sample.get("type") not in ["Role", "AssumedRole"]:
        role_sample = {"name": "ecs-admin-role", "arn_suffix": "role/ecs-admin-role", "type": "Role"} # Fallback
    
    role_name = role_sample.get('name').split('/')[0] # Get base role name
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    role_id = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
    # Use timezone-aware datetime
    now = datetime.datetime.now(datetime.UTC)
    create_date = (now - datetime.timedelta(days=random.randint(30, 365))).strftime('%Y-%m-%dT%H:%M:%SZ')

    event.update({
        "requestParameters": {"pathPrefix": "/"},
        "responseElements": {
            "roles": [{
                "path": "/",
                "roleName": role_name,
                "roleId": role_id,
                "arn": role_arn,
                "createDate": create_date,
                "assumeRolePolicyDocument": "<URL-encoded-JSON-policy-document>"
            }],
            "isTruncated": False
        },
        "resources": [] # ListRoles is a global action
    })
    return [event]

def _generate_iam_list_users(config, context=None):
    """(Benign) Simulates listing IAM users."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # IAM is global
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))
    event = _get_base_event(config, user_identity, ip_address, region, "ListUsers", "iam.amazonaws.com", api_version="2010-05-08", read_only=True)

    # Simulate one user from the config in the response
    user_sample = random.choice(config.get(CONFIG_KEY, {}).get('users_and_roles', [{}]))
    if user_sample.get("type") != "IAMUser":
        user_sample = {"name": "Alice", "arn_suffix": "user/Alice", "type": "IAMUser"} # Fallback
    
    user_name = user_sample.get('name')
    user_arn = f"arn:aws:iam::{account_id}:user/{user_name}"
    user_id = f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
    # Use timezone-aware datetime
    now = datetime.datetime.now(datetime.UTC)
    create_date = (now - datetime.timedelta(days=random.randint(30, 365))).strftime('%Y-%m-%dT%H:%M:%SZ')

    event.update({
        "requestParameters": {"pathPrefix": "/"},
        "responseElements": {
            "users": [{
                "path": "/",
                "userName": user_name,
                "userId": user_id,
                "arn": user_arn,
                "createDate": create_date,
            }],
            "isTruncated": False
        },
        "resources": [] # ListUsers is a global action
    })
    return [event]

def _generate_ec2_describe_vpcs(config, context=None):
    """(Benign) Simulates describing VPCs."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    vpc_id = random.choice(aws_conf.get("vpcs", ["vpc-00000000000000000"]))
    
    event = _get_base_event(config, user_identity, ip_address, region, "DescribeVpcs", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "vpcSet": [{"vpcId": vpc_id, "ownerId": account_id, "state": "available", "cidrBlock": "10.0.0.0/16", "isDefault": True, "instanceTenancy": "default"}],
            "requestId": str(uuid.uuid4())
        },
        "resources": []
    })
    return [event]

def _generate_ec2_describe_subnets(config, context=None):
    """(Benign) Simulates describing Subnets."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    vpc_id = random.choice(aws_conf.get("vpcs", ["vpc-00000000000000000"]))
    subnet_id = f"subnet-{''.join(random.choices('0123456789abcdef', k=17))}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "DescribeSubnets", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "subnetSet": [{"subnetId": subnet_id, "ownerId": account_id, "state": "available", "cidrBlock": "10.0.1.0/24", "vpcId": vpc_id, "availabilityZone": f"{region}a", "availableIpAddressCount": 251, "defaultForAz": True, "mapPublicIpOnLaunch": True}],
            "requestId": str(uuid.uuid4())
        },
        "resources": []
    })
    return [event]

def _generate_ec2_describe_security_groups(config, context=None):
    """(Benign) Simulates describing Security Groups."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    sg_id = random.choice(aws_conf.get("security_groups", ["sg-00000000000000000"]))
    vpc_id = random.choice(aws_conf.get("vpcs", ["vpc-00000000000000000"]))

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeSecurityGroups", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "securityGroupInfo": [{"ownerId": account_id, "groupName": "default", "groupId": sg_id, "description": "default VPC security group", "vpcId": vpc_id, "ipPermissions": [
                { "ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "10.0.0.0/16"}]}} # Example of a common rule
            ], "ipPermissionsEgress": [
                { "ipProtocol": "-1", "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}} # Example of default egress
            ]}],
            "requestId": str(uuid.uuid4())
        },
        "resources": []
    })
    return [event]

def _generate_ec2_describe_route_tables(config, context=None):
    """(Benign) Simulates describing Route Tables."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    rtb_id = random.choice(aws_conf.get("route_tables", ["rtb-00000000000000000"]))
    vpc_id = random.choice(aws_conf.get("vpcs", ["vpc-00000000000000000"]))

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeRouteTables", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "routeTableSet": [{"routeTableId": rtb_id, "vpcId": vpc_id, "ownerId": account_id, "routeSet": [
                {"destinationCidrBlock": "10.0.0.0/16", "gatewayId": "local", "origin": "CreateRouteTable", "state": "active"},
                {"destinationCidrBlock": "0.0.0.0/0", "gatewayId": "igw-0123456789abcdef", "origin": "CreateRoute", "state": "active"}
            ], "associationSet": [
                {"routeTableAssociationId": f"rtbassoc-{''.join(random.choices('0123456789abcdef', k=17))}", "subnetId": f"subnet-{''.join(random.choices('0123456789abcdef', k=17))}", "main": True}
            ]}],
            "requestId": str(uuid.uuid4())
        },
        "resources": []
    })
    return [event]
    
def _generate_ec2_describe_network_acls(config, context=None):
    """(Benign) Simulates describing Network ACLs."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    nacl_id = f"acl-{''.join(random.choices('0123456789abcdef', k=17))}"
    vpc_id = random.choice(aws_conf.get("vpcs", ["vpc-00000000000000000"]))

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeNetworkAcls", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "networkAclSet": [{"networkAclId": nacl_id, "vpcId": vpc_id, "ownerId": account_id, "isDefault": True, "entrySet": [
                {"ruleNumber": 100, "protocol": "-1", "ruleAction": "allow", "egress": False, "cidrBlock": "0.0.0.0/0"},
                {"ruleNumber": 32767, "protocol": "-1", "ruleAction": "deny", "egress": False, "cidrBlock": "0.0.0.0/0"}
            ], "associationSet": [
                {"networkAclAssociationId": f"aclassoc-{''.join(random.choices('0123456789abcdef', k=17))}", "subnetId": f"subnet-{''.join(random.choices('0123456789abcdef', k=17))}"}
            ]}],
            "requestId": str(uuid.uuid4())
        },
        "resources": []
    })
    return [event]

def _generate_iam_get_user(config, context=None):
    """(Benign) Simulates GetUser for the acting user."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # IAM is global
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))
    
    # Can only be called by IAMUser or Root on itself (or on others if allowed)
    # AssumedRoles cannot call GetUser on themselves.
    # Let's simulate a user checking their own identity
    if user_identity['type'] not in ['IAMUser', 'Root']:
        # This event is invalid for this identity type, so let's generate a ListPolicies instead
        return _generate_iam_list_policies(config, context)
        
    user_name = user_identity.get('name')
    if user_identity['type'] == 'Root':
        user_name = "root"
    
    if not user_name: # Final fallback if name is missing from IAMUser
        user_name = "DefaultUser"


    event = _get_base_event(config, user_identity, ip_address, region, "GetUser", "iam.amazonaws.com", api_version="2010-05-08", read_only=True)
    
    # Use timezone-aware datetime
    now = datetime.datetime.now(datetime.UTC)
    create_date = (now - datetime.timedelta(days=random.randint(30, 365))).strftime('%Y-%m-%dT%H:%M:%SZ')

    event.update({
        "requestParameters": {}, # GetUser without params gets the caller
        "responseElements": {
            "user": {
                "path": "/",
                "userName": user_name,
                "userId": user_identity['principalId'],
                "arn": user_identity['arn'],
                "createDate": create_date
            }
        },
        "resources": [] # GetUser on self doesn't target a resource
    })
    return [event]

def _generate_iam_list_policies(config, context=None):
    """(Benign) Simulates listing IAM policies."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # IAM is global
    event = _get_base_event(config, user_identity, ip_address, region, "ListPolicies", "iam.amazonaws.com", api_version="2010-05-08", read_only=True)
    
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess" # Example policy
    policy_id = f"ANPA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
    # Use timezone-aware datetime
    now = datetime.datetime.now(datetime.UTC)
    create_date = (now - datetime.timedelta(days=random.randint(30, 730))).strftime('%Y-%m-%dT%H:%M:%SZ')
    update_date = (now - datetime.timedelta(days=random.randint(0, 29))).strftime('%Y-%m-%dT%H:%M:%SZ')


    event.update({
        "requestParameters": {"scope": "Local"}, # Common to list local policies
        "responseElements": {
            "policies": [{
                "policyName": "ReadOnlyAccess",
                "policyId": policy_id,
                "arn": policy_arn,
                "path": "/",
                "defaultVersionId": "v1",
                "attachmentCount": 1,
                "isAttachable": True,
                "createDate": create_date,
                "updateDate": update_date
            }],
            "isTruncated": False
        },
        "resources": [] # ListPolicies is a global action
    })
    return [event]

def _generate_s3_head_bucket(config, context=None):
    """(Benign) Simulates a HeadBucket request (checking if bucket exists)."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')
    
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    target_bucket = random.choice(s3_buckets)
    bucket_arn = f"arn:aws:s3:::{target_bucket}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "HeadBucket", "s3.amazonaws.com", api_version="2006-03-01", read_only=True)
    event.update({
        "requestParameters": {
            "bucketName": target_bucket,
            "Host": f"{target_bucket}.s3.{region}.amazonaws.com"
            },
        "responseElements": None, # HeadBucket returns 200 OK on success, no body
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
    })
    return [event]

def _generate_cloudwatch_describe_log_groups(config, context=None):
    """(Benign) Simulates describing CloudWatch Log Groups."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    log_group_name = random.choice(aws_conf.get("log_groups", ["/aws/lambda/default-function"]))
    log_group_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}:*"

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeLogGroups", "logs.amazonaws.com", api_version="2014-03-28", read_only=True)
    event.update({
        "requestParameters": {"logGroupNamePrefix": "/aws/"}, # Common prefix
        "responseElements": {
            "logGroups": [{
                "logGroupName": log_group_name,
                "creationTime": int(datetime.datetime.now(datetime.UTC).timestamp() * 1000) - 90*24*60*60*1000, # 90 days ago in ms
                "retentionInDays": 90,
                "metricFilterCount": 0,
                "arn": log_group_arn,
                "storedBytes": random.randint(100000, 50000000)
            }],
            "nextToken": None
        },
        "resources": [] # No resource ARN for the request itself
    })
    return [event]

def _generate_cloudwatch_get_log_events(config, context=None):
    """(Benign) Simulates getting log events from CloudWatch."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    log_group_name = random.choice(aws_conf.get("log_groups", ["/aws/lambda/default-function"]))
    log_stream_name = f"2023/10/24/[1]{''.join(random.choices('0123456789abcdef', k=32))}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "GetLogEvents", "logs.amazonaws.com", api_version="2014-03-28", read_only=True)
    
    # Use timezone-aware datetime and convert to milliseconds
    now_ms = int(datetime.datetime.now(datetime.UTC).timestamp() * 1000)
    
    event.update({
        "requestParameters": {
            "logGroupName": log_group_name,
            "logStreamName": log_stream_name,
            "startTime": now_ms - (60*60*1000), # 1 hour ago
            "endTime": now_ms,
            "startFromHead": True,
            "limit": 5
        },
        "responseElements": {
            "events": [
                {"timestamp": now_ms - (30*60*1000), "message": "START RequestId: ...", "ingestionTime": now_ms},
                {"timestamp": now_ms - (29*60*1000), "message": "INFO: Processing event...", "ingestionTime": now_ms}
            ],
            "nextForwardToken": "f/...",
            "nextBackwardToken": "b/..."
        },
        "resources": [] # This action does not have resource ARNs in the main 'resources' block
    })
    return [event]

def _generate_route53_list_hosted_zones(config, context=None):
    """(Benign) Simulates listing Route 53 Hosted Zones."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # Route 53 is global
    event = _get_base_event(config, user_identity, ip_address, region, "ListHostedZones", "route53.amazonaws.com", api_version="2013-04-01", read_only=True)
    
    zone_id = random.choice(config.get(CONFIG_KEY, {}).get("route53_zones", ["Z00000000000000000"]))
    domain_name = random.choice(config.get("benign_domains", ["example.com."]))

    event.update({
        "requestParameters": {},
        "responseElements": {
            "hostedZones": [{
                "id": f"/hostedzone/{zone_id}",
                "name": domain_name,
                "callerReference": str(uuid.uuid4()),
                "config": {"privateZone": False},
                "resourceRecordSetCount": 10
            }],
            "isTruncated": False,
            "maxItems": "100"
        },
        "resources": []
    })
    return [event]

def _generate_route53_list_resource_record_sets(config, context=None):
    """(Benign) Simulates listing resource record sets from Route 53."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # Route 53 is global
    aws_conf = config.get(CONFIG_KEY, {})
    zone_id = random.choice(aws_conf.get("route53_zones", ["Z00000000000000000"]))
    domain_name = random.choice(config.get("benign_domains", ["example.com."]))

    event = _get_base_event(config, user_identity, ip_address, region, "ListResourceRecordSets", "route53.amazonaws.com", api_version="2013-04-01", read_only=True)
    event.update({
        "requestParameters": {"hostedZoneId": zone_id},
        "responseElements": {
            "resourceRecordSets": [
                {"name": domain_name, "type": "A", "ttl": 300, "resourceRecords": [{"value": "192.0.2.1"}]},
                {"name": domain_name, "type": "NS", "ttl": 172800, "resourceRecords": [{"value": "ns-1.awsdns-01.com."}]}
            ],
            "isTruncated": False,
            "maxItems": "100"
        },
        "resources": [{"type": "AWS::Route53::HostedZone", "ARN": f"arn:aws:route53:::hostedzone/{zone_id}"}]
    })
    return [event]

def _generate_elb_describe_load_balancers(config, context=None):
    """(Benign) Simulates describing Elastic Load Balancers."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    lb_arn = random.choice(aws_conf.get("load_balancers", [f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/app/default-lb/0000000000000000"]))
    vpc_id = random.choice(aws_conf.get("vpcs", ["vpc-00000000000000000"]))

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeLoadBalancers", "elasticloadbalancing.amazonaws.com", api_version="2015-12-01", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "loadBalancers": [{
                "loadBalancerArn": lb_arn,
                "dNSName": "my-lb-1234567890.us-east-1.elb.amazonaws.com",
                "canonicalHostedZoneId": "Z35SXDOTRQ7X7K",
                "createdTime": "2020-01-01T00:00:00Z",
                "loadBalancerName": "my-app-lb",
                "scheme": "internet-facing",
                "vpcId": vpc_id,
                "state": {"code": "active"},
                "type": "application",
                "availabilityZones": [{"zoneName": f"{region}a", "subnetId": f"subnet-{''.join(random.choices('0123456789abcdef', k=17))}"}]
            }],
            "nextMarker": None
        },
        "resources": []
    })
    return [event]

def _generate_elb_describe_target_groups(config, context=None):
    """(Benign) Simulates describing ELB Target Groups."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    tg_arn = random.choice(aws_conf.get("target_groups", [f"arn:aws:elasticloadbalancing:{region}:{account_id}:targetgroup/default-tg/0000000000000000"]))
    vpc_id = random.choice(aws_conf.get("vpcs", ["vpc-00000000000000000"]))

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeTargetGroups", "elasticloadbalancing.amazonaws.com", api_version="2015-12-01", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "targetGroups": [{
                "targetGroupArn": tg_arn,
                "targetGroupName": "my-targets",
                "protocol": "HTTP",
                "port": 80,
                "vpcId": vpc_id,
                "healthCheckProtocol": "HTTP",
                "healthCheckPort": "traffic-port",
                "healthCheckEnabled": True,
                "targetType": "instance"
            }],
            "nextMarker": None
        },
        "resources": []
    })
    return [event]

def _generate_rds_describe_db_instances(config, context=None):
    """(Benign) Simulates describing RDS DB Instances."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    db_instance_id = random.choice(aws_conf.get("rds_instances", ["db-prod-instance"]))
    db_instance_arn = f"arn:aws:rds:{region}:{account_id}:db:{db_instance_id}"

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeDBInstances", "rds.amazonaws.com", api_version="2014-10-31", read_only=True)
    event.update({
    "requestParameters": {
        "dBInstanceIdentifier": db_instance_id # Request specific instance
    },
    "responseElements": {
        # Use "DescribeDBInstancesResult" wrapper based on AWS docs examples
        "DescribeDBInstancesResult": {
            "DBInstances": [{ # Use "DBInstances" list
                "DBInstanceIdentifier": db_instance_id, 
                "DBInstanceClass": "db.t3.micro",
                "Engine": "postgres",
                "DBInstanceStatus": "available",
                "MasterUsername": "admin",
                "DBName": "proddb",
                "Endpoint": {"Address": f"{db_instance_id}.{random.choice('abcdef1234')}.{region}.rds.amazonaws.com", "Port": 5432},
                "AllocatedStorage": 20,
                "InstanceCreateTime": "2020-01-01T00:00:00Z",
                "DBInstanceArn": db_instance_arn,
                "PubliclyAccessible": False
                # Add other relevant fields if needed by SIEM rules
            }]
        }
    },
    # Describe *Instance* doesn't usually list the instance ARN in resources block, often empty.
    "resources": []
    })
    return [event]

def _generate_rds_describe_db_snapshots(config, context=None):
    """(Benign) Simulates describing RDS DB Snapshots."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    db_snapshot_id = random.choice(aws_conf.get("rds_snapshots", ["rds:db-prod-snapshot-2023-10-21"]))
    db_instance_id = random.choice(aws_conf.get("rds_instances", ["db-prod-instance"]))
    db_snapshot_arn = f"arn:aws:rds:{region}:{account_id}:snapshot:{db_snapshot_id}"

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeDBSnapshots", "rds.amazonaws.com", api_version="2014-10-31", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "describeDBSnapshotsResult": {
                "dBSnapshots": [{
                    "dBSnapshotIdentifier": db_snapshot_id,
                    "dBInstanceIdentifier": db_instance_id,
                    "snapshotCreateTime": "2023-10-21T00:00:00Z",
                    "engine": "postgres",
                    "allocatedStorage": 20,
                    "status": "available",
                    "port": 5432,
                    "availabilityZone": f"{region}a",
                    "dBSnapshotArn": db_snapshot_arn
                }]
            }
        },
        "resources": []
    })
    return [event]

def _generate_ecr_describe_repositories(config, context=None):
    """(Benign) Simulates describing ECR repositories."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    repo_name = random.choice(aws_conf.get("ecr_repos", ["my-app-repo"]))
    repo_arn = f"arn:aws:ecr:{region}:{account_id}:repository/{repo_name}"

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeRepositories", "ecr.amazonaws.com", api_version="2015-09-21", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "repositories": [{
                "repositoryArn": repo_arn,
                "registryId": account_id,
                "repositoryName": repo_name,
                "repositoryUri": f"{account_id}.dkr.ecr.{region}.amazonaws.com/{repo_name}",
                "createdAt": "2020-01-01T00:00:00Z",
                "imageTagMutability": "MUTABLE"
            }],
            "nextToken": None
        },
        "resources": []
    })
    return [event]

def _generate_lambda_list_functions(config, context=None):
    """(Benign) Simulates listing Lambda functions."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    func_name = random.choice(aws_conf.get("lambda_functions", ["default-function"]))
    func_arn = f"arn:aws:lambda:{region}:{account_id}:function:{func_name}"
    role_arn = f"arn:aws:iam::{account_id}:role/lambda-exec-role"

    event = _get_base_event(config, user_identity, ip_address, region, "ListFunctions", "lambda.amazonaws.com", api_version="2015-03-31", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "functions": [{
                "functionName": func_name,
                "functionArn": func_arn,
                "runtime": "python3.9",
                "role": role_arn,
                "handler": "lambda_function.lambda_handler",
                "codeSize": 1024,
                "description": "My default function",
                "timeout": 3,
                "memorySize": 128,
                "lastModified": "2023-01-01T00:00:00.000+0000"
            }],
            "nextMarker": None
        },
        "resources": []
    })
    return [event]

def _generate_sts_get_caller_identity(config, context=None):
    """(Benign) Simulates GetCallerIdentity."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # STS is global but often logs here
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))
    
    event = _get_base_event(config, user_identity, ip_address, region, "GetCallerIdentity", "sts.amazonaws.com", api_version="2011-06-15", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {
            "account": account_id,
            "arn": user_identity['arn'],
            "userId": user_identity['principalId']
        },
        "resources": []
    })
    return [event]

def _generate_ec2_run_instances(config, context=None):
    """(Benign) Simulates successfully running (launching) an EC2 instance."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    ami_id = "ami-0abcdef1234567890" # Example default AMI
    instance_type = "t3.micro"
    new_instance_id = f"i-{''.join(random.choices('0123456789abcdef', k=17))}"
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{new_instance_id}"
    key_name = random.choice(aws_conf.get("key_pair_names", ["prod-key"]))
    sg_id = random.choice(aws_conf.get("security_groups", ["sg-00000000000000000"]))


    event = _get_base_event(config, user_identity, ip_address, region, "RunInstances", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {
            "instancesSet": {"items": [{"imageId": ami_id, "instanceType": instance_type, "minCount": 1, "maxCount": 1}]},
            "keyName": key_name,
            "securityGroupSet": {"items": [{"groupId": sg_id}]},
            "instanceInitiatedShutdownBehavior": "stop"
        },
        "responseElements": {
            "reservationId": f"r-{''.join(random.choices('0123456789abcdef', k=17))}",
            "ownerId": account_id,
            "instancesSet": {"items": [
                {"instanceId": new_instance_id, "imageId": ami_id, "instanceState": {"code": 0, "name": "pending"}, "instanceType": instance_type}
            ]}
        },
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_s3_put_object(config, context=None):
    """(Benign) Simulates successfully uploading an object to S3."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')

    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    target_bucket = random.choice(s3_buckets)
    target_key = f"uploads/document-{random.randint(1000, 9999)}.pdf"
    bucket_arn = f"arn:aws:s3:::{target_bucket}"
    object_arn = f"arn:aws:s3:::{target_bucket}/{target_key}"

    event = _get_base_event(config, user_identity, ip_address, region, "PutObject", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)
    event.update({
        "managementEvent": False,
        "eventCategory": "Data",
        "requestParameters": {
            "bucketName": target_bucket,
            "key": target_key,
            "Host": f"{target_bucket}.s3.{region}.amazonaws.com"
        },
        "responseElements": {
            "x-amz-request-id": str(uuid.uuid4()),
            "x-amz-id-2": ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=76)),
            "ETag": f"\"{''.join(random.choices('0123456789abcdef', k=32))}\""
        },
        "resources": [
            {"type": "AWS::S3::Object", "ARN": object_arn, "accountId": account_id},
            {"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}
        ]
    })
    return [event]
    
def _generate_ec2_stop_instances(config, context=None):
    """(Benign) Simulates successfully stopping an EC2 instance."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"

    event = _get_base_event(config, user_identity, ip_address, region, "StopInstances", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {"instancesSet": {"items": [{"instanceId": instance_id}]}},
        "responseElements": {
            "instancesSet": {"items": [
                {"instanceId": instance_id, "currentState": {"code": 64, "name": "stopping"}, "previousState": {"code": 16, "name": "running"}}
            ]},
            "requestId": str(uuid.uuid4())
        },
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    return [event]

def _generate_s3_create_bucket(config, context=None):
    """(Benign) Simulates successfully creating an S3 bucket."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    new_bucket_name = f"simulated-temp-bucket-{''.join(random.choices('0123456789abcdef', k=12))}"
    bucket_arn = f"arn:aws:s3:::{new_bucket_name}"

    event = _get_base_event(config, user_identity, ip_address, region, "CreateBucket", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)
    event.update({
        "requestParameters": {
            "bucketName": new_bucket_name,
            "Host": "s3.amazonaws.com",
            "createBucketConfiguration": {"locationConstraint": region}
        },
        "responseElements": {"Location": f"/{new_bucket_name}"},
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
    })
    return [event]

def _generate_s3_delete_bucket(config, context=None):
    """(Benign) Simulates successfully deleting an S3 bucket."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    target_bucket = random.choice(s3_buckets)
    bucket_arn = f"arn:aws:s3:::{target_bucket}"

    event = _get_base_event(config, user_identity, ip_address, region, "DeleteBucket", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)
    event.update({
        "requestParameters": {
            "bucketName": target_bucket,
            "Host": f"{target_bucket}.s3.{region}.amazonaws.com"
        },
        "responseElements": None, # Successful delete returns 204 No Content
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
    })
    return [event]

def _generate_cloudformation_create_stack(config, context=None):
    """(Benign) Simulates creating a CloudFormation stack."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    stack_name = f"my-dev-stack-{''.join(random.choices('0123456789abcdef', k=6))}"
    stack_id = f"arn:aws:cloudformation:{region}:{account_id}:stack/{stack_name}/{str(uuid.uuid4())}"

    event = _get_base_event(config, user_identity, ip_address, region, "CreateStack", "cloudformation.amazonaws.com", api_version="2010-05-15", read_only=False)
    event.update({
        "requestParameters": {
            "stackName": stack_name,
            "templateURL": "https://s3.amazonaws.com/my-templates/my-template.json",
            "parameters": [
                {"parameterKey": "InstanceType", "parameterValue": "t3.micro"}
            ],
            "capabilities": ["CAPABILITY_IAM"]
        },
        "responseElements": {"stackId": stack_id},
        "resources": [{"type": "AWS::CloudFormation::Stack", "ARN": stack_id, "accountId": account_id}]
    })
    return [event]

def _generate_cloudformation_delete_stack(config, context=None):
    """(Benign) Simulates deleting a CloudFormation stack."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    stack_name = f"my-dev-stack-{''.join(random.choices('0123456789abcdef', k=6))}"
    stack_id = f"arn:aws:cloudformation:{region}:{account_id}:stack/{stack_name}/{str(uuid.uuid4())}"

    event = _get_base_event(config, user_identity, ip_address, region, "DeleteStack", "cloudformation.amazonaws.com", api_version="2010-05-15", read_only=False)
    event.update({
        "requestParameters": {"stackName": stack_name},
        "responseElements": None,
        "resources": [{"type": "AWS::CloudFormation::Stack", "ARN": stack_id, "accountId": account_id}]
    })
    return [event]

def _generate_lambda_invoke(config, context=None):
    """(Benign) Simulates invoking a Lambda function."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    func_name = random.choice(aws_conf.get("lambda_functions", ["default-function"]))
    func_arn = f"arn:aws:lambda:{region}:{account_id}:function:{func_name}"

    event = _get_base_event(config, user_identity, ip_address, region, "Invoke", "lambda.amazonaws.com", api_version="2015-03-31", read_only=False)
    event.update({
        "requestParameters": {"functionName": func_name, "invocationType": "RequestResponse"},
        "responseElements": {"statusCode": 200, "executedVersion": "$LATEST"},
        "resources": [{"type": "AWS::Lambda::Function", "ARN": func_arn, "accountId": account_id}]
    })
    return [event]

def _generate_eks_describe_cluster(config, context=None):
    """(Benign) Simulates describing an EKS cluster."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    cluster_name = "prod-cluster"
    cluster_arn = f"arn:aws:eks:{region}:{account_id}:cluster/{cluster_name}"

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeCluster", "eks.amazonaws.com", api_version="2017-11-01", read_only=True)
    event.update({
        "requestParameters": {"name": cluster_name},
        "responseElements": {
            "cluster": {
                "name": cluster_name,
                "arn": cluster_arn,
                "createdAt": "2020-01-01T00:00:00Z",
                "version": "1.27",
                "endpoint": f"https://{random.choice('ABCDEF123456')}.gr7.{region}.eks.amazonaws.com",
                "roleArn": f"arn:aws:iam::{account_id}:role/eksClusterRole",
                "status": "ACTIVE"
            }
        },
        "resources": [{"type": "AWS::EKS::Cluster", "ARN": cluster_arn, "accountId": account_id}]
    })
    return [event]

def _generate_eks_list_clusters(config, context=None):
    """(Benign) Simulates listing EKS clusters."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    
    event = _get_base_event(config, user_identity, ip_address, region, "ListClusters", "eks.amazonaws.com", api_version="2017-11-01", read_only=True)
    event.update({
        "requestParameters": {},
        "responseElements": {"clusters": ["prod-cluster", "dev-cluster"], "nextToken": None},
        "resources": []
    })
    return [event]

def _generate_cloudformation_describe_stacks(config, context=None):
    """(Benign) Simulates describing CloudFormation stacks."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    stack_name = f"my-dev-stack-{''.join(random.choices('0123456789abcdef', k=6))}"
    stack_id = f"arn:aws:cloudformation:{region}:{account_id}:stack/{stack_name}/{str(uuid.uuid4())}"

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeStacks", "cloudformation.amazonaws.com", api_version="2010-05-15", read_only=True)
    event.update({
        "requestParameters": {"stackName": stack_name},
        "responseElements": {
            "stacks": [{
                "stackId": stack_id,
                "stackName": stack_name,
                "creationTime": "2020-01-01T00:00:00Z",
                "stackStatus": "CREATE_COMPLETE"
            }]
        },
        "resources": [{"type": "AWS::CloudFormation::Stack", "ARN": stack_id, "accountId": account_id}]
    })
    return [event]

def _generate_ecr_create_delete_repo(config, context=None):
    """(Benign) Simulates creating and then deleting an ECR repository."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    repo_name = f"temp-build-repo-{''.join(random.choices('0123456789abcdef', k=8))}"
    repo_arn = f"arn:aws:ecr:{region}:{account_id}:repository/{repo_name}"
    
    # Use timezone-aware datetime
    now = datetime.datetime.now(datetime.UTC)
    creation_time = int(now.timestamp()) # ECR uses epoch seconds

    create_event = _get_base_event(config, user_identity, ip_address, region, "CreateRepository", "ecr.amazonaws.com", api_version="2015-09-21", read_only=False)
    create_event.update({
        "requestParameters": {"repositoryName": repo_name, "imageTagMutability": "MUTABLE"},
        "responseElements": {
            "repository": {
                "repositoryArn": repo_arn,
                "registryId": account_id,
                "repositoryName": repo_name,
                "repositoryUri": f"{account_id}.dkr.ecr.{region}.amazonaws.com/{repo_name}",
                "createdAt": creation_time
            }
        },
        "resources": [{"type": "AWS::ECR::Repository", "ARN": repo_arn, "accountId": account_id}]
    })
    
    # Simulate a deletion event shortly after
    delete_event = _get_base_event(config, user_identity, ip_address, region, "DeleteRepository", "ecr.amazonaws.com", api_version="2015-09-21", read_only=False)
    delete_event["eventTime"] = (now + datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
    delete_event.update({
        "requestParameters": {"repositoryName": repo_name, "registryId": account_id},
        "responseElements": {
             "repository": {
                "repositoryArn": repo_arn,
                "registryId": account_id,
                "repositoryName": repo_name,
                "repositoryUri": f"{account_id}.dkr.ecr.{region}.amazonaws.com/{repo_name}",
                "createdAt": creation_time
            }
        },
        "resources": [{"type": "AWS::ECR::Repository", "ARN": repo_arn, "accountId": account_id}]
    })

    return [create_event, delete_event]

def _generate_lambda_create_function(config, context=None):
    """(Benign) Simulates creating a Lambda function with a standard runtime."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    func_name = f"my-standard-function-{''.join(random.choices('0123456789abcdef', k=6))}"
    func_arn = f"arn:aws:lambda:{region}:{account_id}:function:{func_name}"
    role_arn = f"arn:aws:iam::{account_id}:role/lambda-exec-role"
    runtime = random.choice(["python3.11", "nodejs18.x"])

    event = _get_base_event(config, user_identity, ip_address, region, "CreateFunction", "lambda.amazonaws.com", api_version="2015-03-31", read_only=False)
    event.update({
        "requestParameters": {
            "functionName": func_name,
            "runtime": runtime,
            "role": role_arn,
            "handler": "index.handler",
            "code": {"zipFile": "<SENSITIVE_REDACTED>"},
            "publish": True
        },
        "responseElements": {
            "functionName": func_name,
            "functionArn": func_arn,
            "runtime": runtime,
            "role": role_arn,
            "handler": "index.handler",
            "codeSize": 512,
            "timeout": 3,
            "memorySize": 128
        },
        "resources": [{"type": "AWS::Lambda::Function", "ARN": func_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_iam_create_role(config, context=None):
    """(Benign) Simulates creating an IAM role."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # IAM is global
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))
    
    role_name = f"MyNewRole-{''.join(random.choices('0123456789ABCDEF', k=6))}"
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    role_id = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "CreateRole", "iam.amazonaws.com", api_version="2010-05-08", read_only=False)
    event.update({
        "requestParameters": {
            "roleName": role_name,
            "path": "/",
            "assumeRolePolicyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
        },
        "responseElements": {
            "role": {
                "path": "/",
                "roleName": role_name,
                "roleId": role_id,
                "arn": role_arn,
                "createDate": datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "assumeRolePolicyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
            }
        },
        "resources": [{"type": "AWS::IAM::Role", "ARN": role_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_rds_restore_from_snapshot(config, context=None):
    """(Benign) Simulates restoring an RDS instance from a snapshot."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    snapshot_id = random.choice(aws_conf.get("rds_snapshots", ["rds:db-prod-snapshot-2023-10-21"]))
    new_db_instance_id = f"db-restored-{''.join(random.choices('0123456789abcdef', k=6))}"
    new_db_instance_arn = f"arn:aws:rds:{region}:{account_id}:db:{new_db_instance_id}"

    event = _get_base_event(config, user_identity, ip_address, region, "RestoreDBInstanceFromDBSnapshot", "rds.amazonaws.com", api_version="2014-10-31", read_only=False)
    event.update({
        "requestParameters": {
            "dBInstanceIdentifier": new_db_instance_id,
            "dBSnapshotIdentifier": snapshot_id,
            "dBInstanceClass": "db.t3.micro"
        },
        "responseElements": {
            "restoreDBInstanceFromDBSnapshotResult": {
                "dBInstance": {
                    "dBInstanceIdentifier": new_db_instance_id,
                    "dBInstanceStatus": "creating",
                    "engine": "postgres",
                    "dBInstanceArn": new_db_instance_arn
                }
            }
        },
        "resources": [{"type": "AWS::RDS::DBInstance", "ARN": new_db_instance_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_ec2_create_snapshot(config, context=None):
    """(Benign) Simulates creating an EBS snapshot."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    volume_id = random.choice(aws_conf.get("ebs_volumes", ["vol-00000000000000000"]))
    snapshot_id = f"snap-{''.join(random.choices('0123456789abcdef', k=17))}"
    snapshot_arn = f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot_id}"

    event = _get_base_event(config, user_identity, ip_address, region, "CreateSnapshot", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {"volumeId": volume_id, "description": "My scheduled backup"},
        "responseElements": {
            "snapshotId": snapshot_id,
            "volumeId": volume_id,
            "status": "pending",
            "startTime": int(datetime.datetime.now(datetime.UTC).timestamp() * 1000),
            "volumeSize": 20,
            "ownerId": account_id,
            "description": "My scheduled backup"
        },
        "resources": [
            {"type": "AWS::EC2::Volume", "ARN": f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}", "accountId": account_id},
            {"type": "AWS::EC2::Snapshot", "ARN": snapshot_arn, "accountId": account_id}
        ]
    })
    return [event]

def _generate_s3_get_bucket_policy(config, context=None):
    """(Benign) Simulates GetBucketPolicy."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    target_bucket = random.choice(aws_conf.get("s3_buckets", ["default-sim-bucket-1"]))
    bucket_arn = f"arn:aws:s3:::{target_bucket}"

    event = _get_base_event(config, user_identity, ip_address, region, "GetBucketPolicy", "s3.amazonaws.com", api_version="2006-03-01", read_only=True)
    event.update({
        "requestParameters": {"bucketName": target_bucket, "Host": f"{target_bucket}.s3.{region}.amazonaws.com"},
        "responseElements": {"policy": "{\"Version\":\"2012-10-17\",...}"}, # Simulated policy document
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_iam_get_role(config, context=None):
    """(Benign) Simulates GetRole."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    region = 'us-east-1' # IAM is global
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))
    
    role_sample = random.choice(config.get(CONFIG_KEY, {}).get('users_and_roles', [{}]))
    if role_sample.get("type") not in ["Role", "AssumedRole"]:
        role_sample = {"name": "ecs-admin-role", "arn_suffix": "role/ecs-admin-role", "type": "Role"}
    
    role_name = role_sample.get('name').split('/')[0]
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    role_id = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
    now = datetime.datetime.now(datetime.UTC)
    create_date = (now - datetime.timedelta(days=random.randint(30, 365))).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    event = _get_base_event(config, user_identity, ip_address, region, "GetRole", "iam.amazonaws.com", api_version="2010-05-08", read_only=True)
    event.update({
        "requestParameters": {"roleName": role_name},
        "responseElements": {
            "role": {
                "path": "/", "roleName": role_name, "roleId": role_id, "arn": role_arn, "createDate": create_date,
                "assumeRolePolicyDocument": "<URL-encoded-JSON-policy-document>"
            }
        },
        "resources": [{"type": "AWS::IAM::Role", "ARN": role_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_ec2_create_key_pair(config, context=None):
    """(Benign) Simulates creating a new EC2 Key Pair."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    
    key_name = f"new-key-{random.randint(1000,9999)}"
    key_fingerprint = ":".join(random.choices("0123456789abcdef", k=20))
    key_pair_id = f"key-{''.join(random.choices('0123456789abcdef', k=17))}"

    event = _get_base_event(config, user_identity, ip_address, region, "CreateKeyPair", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {"keyName": key_name, "keyType": "rsa"},
        "responseElements": {
            "keyPairId": key_pair_id,
            "keyFingerprint": key_fingerprint,
            "keyName": key_name,
            "keyMaterial": "<SENSITIVE_REDACTED>"
        },
        "resources": [] # CreateKeyPair response contains the new resource, request does not target one
    })
    return [event]

def _generate_ec2_delete_key_pair(config, context=None):
    """(Benign) Simulates deleting an EC2 Key Pair."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    
    key_name = random.choice(aws_conf.get("key_pair_names", ["prod-key"]))
    
    event = _get_base_event(config, user_identity, ip_address, region, "DeleteKeyPair", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {"keyName": key_name},
        "responseElements": {"return": True, "requestId": str(uuid.uuid4())},
        "resources": [] # No ARN for key pairs
    })
    return [event]

def _generate_rds_download_db_log_file(config, context=None):
    """(Benign) Simulates downloading RDS log files."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    db_instance_id = random.choice(aws_conf.get("rds_instances", ["db-prod-instance"]))
    log_file = random.choice(aws_conf.get("db_log_files", ["error/mysql-error-running.log"]))

    event = _get_base_event(config, user_identity, ip_address, region, "DownloadDBLogFilePortion", "rds.amazonaws.com", api_version="2014-10-31", read_only=True)
    event.update({
        "requestParameters": {"dBInstanceIdentifier": db_instance_id, "logFileName": log_file},
        "responseElements": {"logFileData": "...", "marker": "0", "additionalDataPending": False}, # Data is simulated as truncated
        "resources": [{"type": "AWS::RDS::DBInstance", "ARN": f"arn:aws:rds:{region}:{account_id}:db:{db_instance_id}", "accountId": account_id}]
    })
    return [event]

def _generate_ec2_describe_key_pairs(config, context=None):
    """(Benign) Simulates describing EC2 key pairs."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    
    key_name = random.choice(aws_conf.get("key_pair_names", ["prod-key"]))
    key_fingerprint = ":".join(random.choices("0123456789abcdef", k=20))
    key_pair_id = f"key-{''.join(random.choices('0123456789abcdef', k=17))}"

    event = _get_base_event(config, user_identity, ip_address, region, "DescribeKeyPairs", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
    event.update({
        "requestParameters": {"keyPairSet": {"items": [{"keyName": key_name}]}},
        "responseElements": {
            "keySet": [{"keyName": key_name, "keyPairId": key_pair_id, "keyFingerprint": key_fingerprint}]
        },
        "resources": []
    })
    return [event]
    
def _generate_ec2_describe_snapshots(config, context=None):
    """(Benign) Simulates describing EC2 snapshots."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    snapshot_id = random.choice(aws_conf.get("ec2_snapshots", ["snap-00000000000000000"]))
    snapshot_arn = f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot_id}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "DescribeSnapshots", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
    event.update({
        "requestParameters": {"snapshotSet": {"items": [{"snapshotId": snapshot_id}]}},
        "responseElements": {
            "snapshotSet": [{"snapshotId": snapshot_id, "status": "completed", "progress": "100%", "ownerId": account_id, "volumeSize": 20, "startTime": "2023-10-21T00:00:00Z"}]
        },
        "resources": [{"type": "AWS::EC2::Snapshot", "ARN": snapshot_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_ec2_describe_volumes(config, context=None):
    """(Benign) Simulates describing EBS volumes."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    volume_id = random.choice(aws_conf.get("ebs_volumes", ["vol-00000000000000000"]))
    volume_arn = f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "DescribeVolumes", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
    event.update({
        "requestParameters": {"volumeSet": {"items": [{"volumeId": volume_id}]}},
        "responseElements": {
            "volumeSet": [{"volumeId": volume_id, "status": "in-use", "size": 20, "createTime": "2023-01-01T00:00:00Z", "availabilityZone": f"{region}a", "volumeType": "gp3"}]
        },
        "resources": [{"type": "AWS::EC2::Volume", "ARN": volume_arn, "accountId": account_id}]
    })
    return [event]

# --- SUSPICIOUS SCENARIOS ---
# These functions simulate events that are not *always* malicious, but are often part of
# recon, persistence, or defense evasion. They are highly context-dependent.
def _generate_lambda_create_function_unusual_runtime(config, context=None):
    """(Suspicious) Simulates creating a Lambda function with an unusual runtime."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    func_name = f"my-custom-runtime-func-{''.join(random.choices('0123456789abcdef', k=6))}"
    func_arn = f"arn:aws:lambda:{region}:{account_id}:function:{func_name}"
    role_arn = f"arn:aws:iam::{account_id}:role/lambda-exec-role"
    # Pick a runtime that might be flagged as unusual (e.g., custom or deprecated)
    runtime = random.choice(aws_conf.get("unusual_lambda_runtimes", ["provided", "go1.x"]))

    event = _get_base_event(config, user_identity, ip_address, region, "CreateFunction", "lambda.amazonaws.com", api_version="2015-03-31", read_only=False)
    event.update({
        "requestParameters": {
            "functionName": func_name,
            "runtime": runtime,
            "role": role_arn,
            "handler": "bootstrap",
            "code": {"zipFile": "<SENSITIVE_REDACTED>"},
            "publish": True
        },
        "responseElements": {
            "functionName": func_name,
            "functionArn": func_arn,
            "runtime": runtime,
            "role": role_arn,
            "handler": "bootstrap",
            "codeSize": 512000,
            "timeout": 60,
            "memorySize": 256
        },
        "resources": [{"type": "AWS::Lambda::Function", "ARN": func_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_ebs_detach_volume(config, context=None):
    """(Suspicious) Simulates detaching an EBS volume from an instance."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    volume_id = random.choice(aws_conf.get("ebs_volumes", ["vol-00000000000000000"]))
    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    volume_arn = f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "DetachVolume", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {"volumeId": volume_id, "instanceId": instance_id, "device": "/dev/sdf", "force": False},
        "responseElements": {
            "volumeId": volume_id,
            "instanceId": instance_id,
            "device": "/dev/sdf",
            "status": "detaching",
            "attachTime": int(datetime.datetime.now(datetime.UTC).timestamp() * 1000) - 7*24*60*60*1000 # 7 days ago
        },
        "resources": [{"type": "AWS::EC2::Volume", "ARN": volume_arn, "accountId": account_id}]
    })
    return [event]

def _generate_ec2_modify_user_data(config, context=None):
    """(Suspicious) Simulates modifying EC2 instance user data, possible SSH key injection."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True) # Make it slightly more suspicious

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
    
    # Simulate a suspicious script (e.g., adding an SSH key)
    user_data_payload = "#!/bin/bash\necho 'ssh-rsa AAAAB3Nza...[REDACTED].../OqXj user@attacker' >> /home/ec2-user/.ssh/authorized_keys"
    user_data_b64 = base64.b64encode(user_data_payload.encode('utf-8')).decode('utf-8')

    event = _get_base_event(config, user_identity, ip_address, region, "ModifyInstanceAttribute", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {"instanceId": instance_id, "userData": {"value": user_data_b64}},
        "responseElements": {"return": True, "requestId": str(uuid.uuid4())},
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    return [event]

def _generate_ec2_export_to_s3(config, context=None):
    """(Suspicious) Simulates exporting an EC2 instance to an S3 bucket (exfil)."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
    s3_bucket = random.choice(aws_conf.get("s3_buckets", ["default-sim-bucket-1"]))
    
    export_task_id = f"export-i-{''.join(random.choices('0123456789abcdef', k=17))}"

    event = _get_base_event(config, user_identity, ip_address, region, "CreateInstanceExportTask", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {
            "instanceId": instance_id,
            "targetEnvironment": "vmware",
            "exportToS3Task": {
                "containerFormat": "ova",
                "diskImageFormat": "VMDK",
                "s3Bucket": s3_bucket,
                "s3Prefix": "exports/"
            },
            "description": "Exporting instance for backup"
        },
        "responseElements": {
            "exportTask": {
                "exportTaskId": export_task_id,
                "instanceExportDetails": {"instanceId": instance_id, "targetEnvironment": "vmware"},
                "state": "active",
                "statusMessage": "pending"
            }
        },
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    return [event]

def _generate_ec2_modify_route_table(config, context=None):
    """(Suspicious) Simulates modifying a route table (e.g., blackholing traffic or redirecting)."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    rtb_id = random.choice(aws_conf.get("route_tables", ["rtb-00000000000000000"]))
    rtb_arn = f"arn:aws:ec2:{region}:{account_id}:route-table/{rtb_id}"
    
    # Simulate replacing the default route to go to a specific instance (e.g., a sniffing instance)
    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))

    event = _get_base_event(config, user_identity, ip_address, region, "ReplaceRoute", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {
            "routeTableId": rtb_id,
            "destinationCidrBlock": "0.0.0.0/0",
            "instanceId": instance_id
        },
        "responseElements": {"return": True},
        "resources": [{"type": "AWS::EC2::RouteTable", "ARN": rtb_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_iam_create_access_key(config, context=None):
    """(Suspicious) Simulates creating a new access key for a user."""
    user_identity = None
    ip_address = None
    target_user_name = None
    
    # Get user/ip, falling back to random if not in context
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config) # <-- MOVED UP
    if not ip_address: ip_address = _get_random_ip(config)

    # Now safely determine target_user_name AFTER user_identity is guaranteed to be set
    if context:
        # If context provides a target, use it. Otherwise, user targets itself.
        target_user_name = ((context.get('target_user') or {}) or {}).get('name', user_identity.get('name'))
    else: # Handle case where context itself might be None (though unlikely now)
         target_user_name = user_identity.get('name')

    if not target_user_name:
        # Pick a random IAMUser if target couldn't be determined
        iam_users = [u for u in config.get(CONFIG_KEY, {}).get('users_and_roles', []) if u['type'] == 'IAMUser']
        if iam_users:
            target_user_name = random.choice(iam_users)['name']
        else:
            target_user_name = "Alice" # fallback

    # ... (rest of the code starting from region = 'us-east-1'...)

    region = 'us-east-1' # IAM is global
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))
    
    # Only IAMUsers can have access keys
    if user_identity['type'] not in ['IAMUser', 'Root', 'AssumedRole']: # AssumedRole can create keys for users
        return _generate_iam_list_roles(config, context) # Pick a different action
        
    target_arn = f"arn:aws:iam::{account_id}:user/{target_user_name}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "CreateAccessKey", "iam.amazonaws.com", api_version="2010-05-08", read_only=False)
    event.update({
        "requestParameters": {"userName": target_user_name},
        "responseElements": {
            "accessKey": {
                "userName": target_user_name,
                "accessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "status": "Active",
                "createDate": datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "secretAccessKey": "<SENSITIVE_REDACTED>"
            }
        },
        "resources": [{"type": "AWS::IAM::User", "ARN": target_arn, "accountId": account_id}]
    })
    return [event]

def _generate_iam_recon_list(config, context=None):
    """(Suspicious) Simulates a chain of IAM enumeration/recon commands."""
    user_identity = None
    ip_address = None
    
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True) # Make it from an external IP
    
    events = []
    
    # 1. List Users
    events.append(_generate_iam_list_users(config, context)[0])

    # 2. List Roles
    events.append(_generate_iam_list_roles(config, context)[0])

    # 3. List Policies
    events.append(_generate_iam_list_policies(config, context)[0])

    # 4. GetUser (on self)
    events.append(_generate_iam_get_user(config, context)[0])
    
    return events

def _generate_s3_set_replication(config, context=None):
    """(Suspicious) Simulates setting S3 replication to a foreign account."""
    user_identity = None
    ip_address = None
    
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')
    
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    target_bucket = random.choice(s3_buckets)
    bucket_arn = f"arn:aws:s3:::{target_bucket}"
    
    foreign_account = random.choice(aws_conf.get("foreign_account_ids", ["999988887777"]))
    foreign_bucket_arn = f"arn:aws:s3:::foreign-backup-bucket-{foreign_account}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "PutBucketReplication", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)
    event.update({
        "requestParameters": {
            "bucketName": target_bucket,
            "Host": f"{target_bucket}.s3.{region}.amazonaws.com",
            "replicationConfiguration": {
                "role": f"arn:aws:iam::{account_id}:role/s3-replication-role",
                "rules": [{
                    "id": "ExfilRule",
                    "status": "Enabled",
                    "priority": 1,
                    "destination": {"bucket": foreign_bucket_arn, "account": foreign_account},
                    "prefix": ""
                }]
            }
        },
        "responseElements": None,
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
    })
    return [event]
    
# --- THREAT SCENARIOS ---
# These functions simulate events that are almost always malicious or high-priority.
def _generate_multiple_denied_actions(config, context=None):
    """(Threat) Generates AccessDenied events for S3 and EC2."""
    events = []
    user_identity = None
    ip_address = None
    
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True) # Denials from external is more suspicious

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')

    # Ensure resource lists have fallbacks if missing from config
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    ec2_instances = aws_conf.get("ec2_instances", ["i-00000000000000000"])
    security_groups = aws_conf.get("security_groups", ["sg-00000000000000000"])

    actions_to_deny = [
        ("DeleteBucket", "s3.amazonaws.com", "2006-03-01", random.choice(s3_buckets), "AWS::S3::Bucket", "arn:aws:s3:::{}"),
        ("StopInstances", "ec2.amazonaws.com", "2016-11-15", random.choice(ec2_instances), "AWS::EC2::Instance", f"arn:aws:ec2:{region}:{account_id}:instance/{{}}"),
        ("TerminateInstances", "ec2.amazonaws.com", "2016-11-15", random.choice(ec2_instances), "AWS::EC2::Instance", f"arn:aws:ec2:{region}:{account_id}:instance/{{}}"),
        ("DeleteSecurityGroup", "ec2.amazonaws.com", "2016-11-15", random.choice(security_groups), "AWS::EC2::SecurityGroup", f"arn:aws:ec2:{region}:{account_id}:security-group/{{}}")
    ]

    for _ in range(random.randint(5, 10)): # Generate multiple denials
        action, source, api_version, resource_id, resource_type, arn_format = random.choice(actions_to_deny)
        base_event = _get_base_event(config, user_identity, ip_address, region, action, source, api_version, read_only=False)
        
        resource_arn = arn_format.format(resource_id)
        
        base_event.update({
            "errorCode": "AccessDenied",
            "errorMessage": f"User: {base_event['userIdentity']['arn']} is not authorized to perform: {action} on resource: {resource_arn}",
            # More realistic requestParameters
            "requestParameters": {
                "bucketName": resource_id if "Bucket" in action else None,
                "instanceIds": {"items": [{"instanceId": resource_id}]} if "Instances" in action else None,
                "groupId": resource_id if "SecurityGroup" in action else None
            },
            "responseElements": None,
            "resources": [{"type": resource_type, "ARN": resource_arn, "accountId": account_id}]
        })
        # Clean up nulls from requestParameters
        base_event["requestParameters"] = {k: v for k, v in base_event["requestParameters"].items() if v is not None}

        events.append(base_event)
    return events
def _get_random_user_from_template(config, user_template):
    """Takes a user template from config and returns a fully-fleshed identity object."""
    # Define CONFIG_KEY locally within this function for aws.py context
    CONFIG_KEY = "aws_config" 
    aws_conf = config.get(CONFIG_KEY, {})
    account_id = aws_conf.get('aws_account_id', '123456789012')

    final_identity = user_template.copy()
    final_identity['accountId'] = account_id

    # Build ARN if not present
    if 'arn' not in final_identity and 'arn_suffix' in final_identity:
        final_identity['arn'] = f"arn:aws:iam::{account_id}:{final_identity['arn_suffix']}"

    # Build PrincipalId if not present (simplified logic, matches _get_random_user)
    if 'principalId' not in final_identity:
        principal_id_prefix = ""
        principal_id_main = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=17))
        id_type = final_identity.get('type', 'IAMUser')

        if id_type == 'IAMUser':
            principal_id_prefix = "AIDA"
        elif id_type in ['AssumedRole', 'Role']:
             principal_id_prefix = "AROA"
        elif id_type == 'Root':
             final_identity['principalId'] = account_id
             return final_identity # Root is special case
        else: # FederatedUser, SAMLUser, etc.
             principal_id_prefix = "AIDAU" # Use a generic prefix

        # Handle AssumedRole/Role principalId structure :sessionName
        if id_type in ['AssumedRole', 'Role']:
             role_id_part = f"{principal_id_prefix}{principal_id_main}"
             session_name_part = final_identity.get('name', 'DefaultSession').split('/')[-1] if '/' in final_identity.get('name', 'DefaultSession') else 'DefaultSession'
             final_identity['principalId'] = f"{role_id_part}:{session_name_part}"
             # Store base role ID if needed for sessionIssuer later (optional here)
             # final_identity['_baseRoleId'] = role_id_part
        else:
            final_identity['principalId'] = f"{principal_id_prefix}{principal_id_main}"

    # Ensure essential fields like 'name' exist if possible
    if 'name' not in final_identity and 'arn_suffix' in final_identity:
         # Attempt to derive name from suffix
         parts = final_identity['arn_suffix'].split('/')
         if len(parts) > 1:
             final_identity['name'] = parts[-1]

    return final_identity

def _generate_api_call_with_pentest_ua(config, context=None):
    """(Threat) Simulates a common API call using a known pentest tool user agent."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    # Use an external IP, as pentest tools might be run from outside
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1') # Default, some calls might use other regions
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    # --- Select a known pentest User Agent ---
    pentest_user_agents = [
        "Nmap Scripting Engine",
        "sqlmap/1.6.x (https://sqlmap.org)", # Example versioned UA
        "Go-http-client/1.1", # Often used by custom Go tools like Pacu
        "curl/7.81.0", # Can be used manually for probing
        "python-requests/2.28.1", # Can be used by custom scripts
        "Cloudsploit by Aqua Security", # Example specific tool UA
        # Add more known tool UAs here if available
    ]
    chosen_ua = random.choice(pentest_user_agents)

    # --- Select a common API call for recon ---
    # Pick one: DescribeInstances, ListUsers, GetCallerIdentity
    action_choice = random.choice(["DescribeInstances", "ListUsers", "GetCallerIdentity"])

    event = None
    if action_choice == "DescribeInstances":
        event = _get_base_event(config, user_identity, ip_address, region, "DescribeInstances", "ec2.amazonaws.com", api_version="2016-11-15", read_only=True)
        event.update({
            "requestParameters": {}, # Simple request
            "responseElements": {"requestId": str(uuid.uuid4()), "reservationSet": {}}, # Simplified response
            "resources": []
        })
    elif action_choice == "ListUsers":
        region = 'us-east-1' # Force region for IAM
        event = _get_base_event(config, user_identity, ip_address, region, "ListUsers", "iam.amazonaws.com", api_version="2010-05-08", read_only=True)
        event.update({
            "requestParameters": None,
            "responseElements": {"users": [], "isTruncated": False},
            "resources": []
        })
    else: # GetCallerIdentity
        region = 'us-east-1' # Force region for STS
        event = _get_base_event(config, user_identity, ip_address, region, "GetCallerIdentity", "sts.amazonaws.com", api_version="2011-06-15", read_only=True)
        event.update({
            "requestParameters": None,
            "responseElements": {"account": account_id, "arn": user_identity['arn'], "userId": user_identity['principalId']},
            "resources": []
        })

    # --- Override the User Agent ---
    if event:
        event["userAgent"] = chosen_ua
        return [event]
    else:
        return None # Should not happen with current choices

def _generate_login_from_tor(config, context=None):
    """(Threat) Generates a successful ConsoleLogin event from a Tor IP."""
    user_identity = None
    ip_address = None

    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address') # Context might override Tor

    # --- FIX: Ensure user_identity is an IAMUser ---
    if not user_identity or user_identity.get('type') != 'IAMUser':
        aws_conf = config.get(CONFIG_KEY, {})
        iam_users = [u for u in aws_conf.get('users_and_roles', []) if u['type'] == 'IAMUser']
        if not iam_users:
             # Create a fallback IAMUser template if none in config
             user_template = {"type": "IAMUser", "name": "Alice", "arn_suffix": "user/Alice"}
        else:
             user_template = random.choice(iam_users)
        # Use helper to build the full identity object
        user_identity = _get_random_user_from_template(config, user_template) # Ensures structure is correct
   
    if not ip_address: ip_address = _get_random_ip(config, use_tor=True) # Force Tor IP

    region = 'us-east-1' # Login events often global or us-east-1
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))

    event = _get_base_event(config, user_identity, ip_address, region, "ConsoleLogin", "signin.amazonaws.com", api_version=None, read_only=False)

    # ConsoleLogin requestParameters is always null per AWS docs
    event["requestParameters"] = None

    # --- FIX: Match responseElements and additionalEventData exactly per AWS docs ---
    event.update({
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {
            "LoginTo": "https://console.aws.amazon.com/console/home?hashArgs=%23&isauthcode=true",
            "MobileVersion": "No",
            "MFAUsed": "No"
        },
    })
  
    # Resources should reflect the user logging in
    resource_type = "AWS::IAM::User" # Match example log
    event["resources"] = [{"type": resource_type, "ARN": event["userIdentity"]["arn"], "accountId": account_id}]

    return [event]

def _generate_iam_policy_change(config, context=None):
    """
    (Threat) Generates an event for attaching AdministratorAccess policy.
    Defaults to self-escalation if no target_user provided in context.
    ** THIS IS THE SPECIAL ONE THAT TRIGGERS THE XSIAM ALERT **
    """
    admin_user = None
    ip_address = None
    target_user_details = None

    # FIX: Safely handle context
    if context:
        admin_user = context.get('user_identity')
        ip_address = context.get('ip_address')
        target_user_details = context.get('target_user')
    
    if not admin_user: admin_user = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    if not target_user_details:
        # High probability of self-escalation in random mode
        if random.random() < 0.75:
            target_user_details = admin_user
            print("  [AWS Module] Simulating IAM self-escalation.") # Debug print
        else:
            # Otherwise, escalate a different random user/role
            target_user_details = _get_random_user(config)
            while target_user_details.get('principalId') == admin_user.get('principalId'): # Ensure it's different
                target_user_details = _get_random_user(config)
            print(f"  [AWS Module] Simulating IAM escalation targeting {target_user_details.get('name', 'Unknown')}.") # Debug print


    account_id = admin_user.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))
    region = 'us-east-1' # IAM is global
    policy_arn_to_attach = "arn:aws:iam::aws:policy/AdministratorAccess"

    target_name = target_user_details.get('name', 'DefaultTarget')
    target_type = target_user_details.get('type', 'IAMUser')
    target_arn = target_user_details.get('arn', f"arn:aws:iam::{account_id}:user/{target_name}") # Get full ARN
    
    event_name = "AttachUserPolicy"
    request_key = "userName"
    target_arn_type = "user"

    # --- SPECIAL HACK FOR XSIAM ANALYTIC ---
    # The alert "A cloud identity escalated its permissions" specifically looks for
    # an AssumedRole calling AttachUserPolicy on ITSELF.
    # We must force this specific combination.
    is_self_escalation = admin_user.get('principalId') == target_user_details.get('principalId')
    
    if is_self_escalation and admin_user['type'] == 'AssumedRole':
        print("  [AWS Module] Forcing AttachUserPolicy for AssumedRole self-escalation.")
        event_name = "AttachUserPolicy"
        request_key = "userName"
        # The requestParameter must be the *full* assumed role name (role/session)
        target_name = admin_user['name'] 
        target_arn_type = "user" # This is intentionally "wrong" to match the alert log
        # The resource ARN, however, is the ARN of the *role session*
        target_arn = admin_user['arn'] 
        
    elif target_type in ['AssumedRole', 'Role']:
        event_name = "AttachRolePolicy"
        request_key = "roleName"
        # Extract role name before any potential session suffix
        target_name = target_name.split('/')[0] if '/' in target_name else target_name
        target_arn_type = "role"
        target_arn = f"arn:aws:iam::{account_id}:role/{target_name}" # Use the base role ARN

    elif target_type == 'Group': 
        event_name = "AttachGroupPolicy"
        request_key = "groupName"
        target_arn_type = "group"
        target_arn = f"arn:aws:iam::{account_id}:group/{target_name}"
    # --- END SPECIAL HACK ---

    event = _get_base_event(config, admin_user, ip_address, region, event_name, "iam.amazonaws.com", api_version="2010-05-08", read_only=False)
    event.update({
        "requestParameters": {request_key: target_name, "policyArn": policy_arn_to_attach},
        "responseElements": None, # Successful attachment usually has null responseElements
        "resources": [{"type": f"AWS::IAM::{target_arn_type.title()}", "ARN": target_arn, "accountId": account_id}]
    })
    return [event]


def _generate_security_group_modified(config, context=None):
    """(Threat) Generates an event for a security group being modified to allow 0.0.0.0/0."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    sg_id = random.choice(aws_conf.get("security_groups", ["sg-00000000000000000"]))
    sg_arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
    
    port = random.choice([22, 3389, 23, 20, 21, 1433, 3306, 5900, 8080, 8443, 8389]) # SSH, RDP, Telnet, FTP , Custom Ports
    
    event_name = "AuthorizeSecurityGroupIngress"
    api_version = "2016-11-15"
    event_source = "ec2.amazonaws.com"
    
    event = _get_base_event(config, user_identity, ip_address, region, event_name, event_source, api_version=api_version, read_only=False)
    event.update({
        "requestParameters": {
            "groupId": sg_id,
            "ipPermissions": {
                "items": [{
                    "ipProtocol": "tcp",
                    "fromPort": port,
                    "toPort": port,
                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0", "description": "Allow all traffic"}]}
                }]
            }
        },
        "responseElements": {"_return": True},
        "resources": [{"type": "AWS::EC2::SecurityGroup", "ARN": sg_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_kms_key_disabled(config, context=None):
    """(Threat) Simulates disabling a KMS key, potentially cross-account."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config) # Actor from main account
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.4: # 40% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.7: # 30% chance Random External (non-TOR, non-benign list)
            ip_address = _get_random_ip(config, force_external=True)
        else: # 30% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')

    # --- FIX: Ensure target key is from a FOREIGN account ---
    foreign_account_id = random.choice(aws_conf.get("foreign_account_ids", ["123456789012"])) # Get foreign ID
    # Construct a plausible ARN for a key in the foreign account
    kms_key_arn = f"arn:aws:kms:{region}:{foreign_account_id}:key/mrk-{''.join(random.choices('abcdef0123456789', k=20))}"
    key_id = kms_key_arn.split('/')[-1]
    # --- END FIX ---

    event = _get_base_event(config, user_identity, ip_address, region, "DisableKey", "kms.amazonaws.com", api_version="2014-11-01", read_only=False)

    # --- FIX: Set recipientAccountId correctly ---
    event["recipientAccountId"] = foreign_account_id # Target account
    # --- END FIX ---

    event.update({
        "requestParameters": {"keyId": key_id}, # Use key ID (alias or ARN also possible)
        "responseElements": None, # Match raw log
         # --- FIX: Ensure resource accountId matches target ---
        "resources": [{"type": "AWS::KMS::Key", "ARN": kms_key_arn, "accountId": foreign_account_id}]
         # --- END FIX ---
    })
    return [event]

def _generate_root_user_activity(config, context=None):
    """(Threat/Suspicious) Simulates a simple API call (ListUsers) from the Root user."""
    ip_address = None
    if context:
        # Don't get user from context, we are forcing Root
        ip_address = context.get('ip_address')
    
    # Force the user to be Root
    user_identity = _get_random_user(config, allow_root=True)
    while user_identity['type'] != 'Root':
        user_identity = _get_random_user(config, allow_root=True)
        
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.1: # 10% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.4: # 30% chance Random External (non-TOR, non-benign list)
            ip_address = _get_random_ip(config, force_external=True)
        else: # 60% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    region = 'us-east-1' # IAM is global
    account_id = user_identity.get('accountId', config.get(CONFIG_KEY, {}).get('aws_account_id', '123456789012'))

    event = _get_base_event(config, user_identity, ip_address, region, "ListUsers", "iam.amazonaws.com", api_version="2010-05-08", read_only=True)
    event.update({
        "requestParameters": {"pathPrefix": "/"},
        "responseElements": {
            "users": [{"path": "/", "userName": "Alice", "userId": "AIDA...", "arn": f"arn:aws:iam::{account_id}:user/Alice", "createDate": "2020-01-01T00:00:00Z"}],
            "isTruncated": False
        },
        "resources": []
    })
    return [event]

def _generate_trail_deleted(config, context=None):
    """(Threat) Simulates deleting a CloudTrail trail."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.05: # 5% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.4: # 35% chance Random External
            ip_address = _get_random_ip(config, force_external=True)
        else: # 60% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    trail_name = random.choice(aws_conf.get("cloudtrails", ["management-events-trail"]))
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"

    event = _get_base_event(config, user_identity, ip_address, region, "DeleteTrail", "cloudtrail.amazonaws.com", api_version="2013-11-01", read_only=False)
    event.update({
        # --- FIX: Use trail name, not ARN ---
        "requestParameters": {"name": trail_name},
        # --- END FIX ---
        "responseElements": None,
        "resources": [{"type": "AWS::CloudTrail::Trail", "ARN": trail_arn, "accountId": account_id}]
    })
    return [event]

def _generate_multiple_deletes(config, context=None):
    """(Threat) Simulates rapid deletion of S3 bucket and EC2 instance."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.01: # 1% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.4: # 39% chance Random External
            ip_address = _get_random_ip(config, force_external=True)
        else: # 60% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    events = []
    
    # 1. Delete S3 Bucket
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    target_bucket = random.choice(s3_buckets)
    bucket_arn = f"arn:aws:s3:::{target_bucket}"
    
    s3_event = _get_base_event(config, user_identity, ip_address, region, "DeleteBucket", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)
    s3_event.update({
        "requestParameters": {"bucketName": target_bucket, "Host": f"{target_bucket}.s3.{region}.amazonaws.com"},
        "responseElements": None,
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
    })
    events.append(s3_event)

    # 2. Terminate EC2 Instance
    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
    
    ec2_event = _get_base_event(config, user_identity, ip_address, region, "TerminateInstances", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    ec2_event.update({
        "requestParameters": {"instancesSet": {"items": [{"instanceId": instance_id}]}},
        "responseElements": {
            "instancesSet": {"items": [
                {"instanceId": instance_id, "currentState": {"code": 32, "name": "shutting-down"}, "previousState": {"code": 16, "name": "running"}}
            ]}
        },
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    events.append(ec2_event)
    
    return events

def _generate_suspicious_iam_creation(config, context=None):
    """(Threat) Simulates a suspicious IAM user creation and permissioning chain."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config, allow_root=True) # Admin/Root action
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.1: # 10% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.7: # 60% chance Random External
            ip_address = _get_random_ip(config, force_external=True)
        else: # 30% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = 'us-east-1' # IAM is global
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    name_part1 = random.choice(["svc", "temp", "admin", "dev", "test", "service", "app"])
    name_part2 = random.choice(["acct", "user", "worker", "process", "key", "access"])
    random_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
    new_user_name = f"{name_part1}-{name_part2}-{random_suffix}"
    new_user_arn = f"arn:aws:iam::{account_id}:user/{new_user_name}"
    new_user_id = f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
    
    events = []
    
    # Use timezone-aware datetime
    now = datetime.datetime.now(datetime.UTC)

    # 1. Create User
    create_user_event = _get_base_event(config, user_identity, ip_address, region, "CreateUser", "iam.amazonaws.com", api_version="2010-05-08", read_only=False)
    create_user_event.update({
        "requestParameters": {"userName": new_user_name, "path": "/"},
        "responseElements": {
            "user": {"path": "/", "userName": new_user_name, "userId": new_user_id, "arn": new_user_arn, "createDate": now.strftime('%Y-%m-%dT%H:%M:%SZ')}
        },
        "resources": [{"type": "AWS::IAM::User", "ARN": new_user_arn, "accountId": account_id}]
    })
    events.append(create_user_event)

    # 2. Attach Admin Policy
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    attach_policy_event = _get_base_event(config, user_identity, ip_address, region, "AttachUserPolicy", "iam.amazonaws.com", api_version="2010-05-08", read_only=False)
    attach_policy_event["eventTime"] = (now + datetime.timedelta(seconds=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
    attach_policy_event.update({
        "requestParameters": {"userName": new_user_name, "policyArn": policy_arn},
        "responseElements": None,
        "resources": [{"type": "AWS::IAM::User", "ARN": new_user_arn, "accountId": account_id}]
    })
    events.append(attach_policy_event)

    # 3. Create Access Key
    create_key_event = _get_base_event(config, user_identity, ip_address, region, "CreateAccessKey", "iam.amazonaws.com", api_version="2010-05-08", read_only=False)
    create_key_event["eventTime"] = (now + datetime.timedelta(seconds=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
    create_key_event.update({
        "requestParameters": {"userName": new_user_name},
        "responseElements": {
            "accessKey": {
                "userName": new_user_name,
                "accessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "status": "Active",
                "createDate": (now + datetime.timedelta(seconds=10)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "secretAccessKey": "<SENSITIVE_REDACTED>"
            }
        },
        "resources": [{"type": "AWS::IAM::User", "ARN": new_user_arn, "accountId": account_id}]
    })
    events.append(create_key_event)
    
    return events
    
def _generate_cloudtrail_stop_logging(config, context=None):
    """(Threat) Simulates stopping logging for a CloudTrail trail."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.05: # 5% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.7: # 65% chance Random External
            ip_address = _get_random_ip(config, force_external=True)
        else: # 30% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    trail_name = random.choice(aws_conf.get("cloudtrails", ["management-events-trail"]))
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"

    event = _get_base_event(config, user_identity, ip_address, region, "StopLogging", "cloudtrail.amazonaws.com", api_version="2013-11-01", read_only=False)
    event.update({
        "requestParameters": {"name": trail_arn},
        "responseElements": None,
        "resources": [{"type": "AWS::CloudTrail::Trail", "ARN": trail_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_vpc_create_flow_log(config, context=None):
    """(Suspicious/Benign) Simulates creating a VPC Flow Log."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    vpc_id = random.choice(aws_conf.get("vpcs", ["vpc-00000000000000000"]))
    log_group_name = random.choice(aws_conf.get("log_groups", ["/aws/ec2/flow-logs"]))
    iam_role_arn = f"arn:aws:iam::{account_id}:role/flow-logs-role"
    flow_log_id = f"fl-{''.join(random.choices('0123456789abcdef', k=17))}"
    
    event = _get_base_event(config, user_identity, ip_address, region, "CreateFlowLogs", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {
            "resourceIds": [vpc_id],
            "resourceType": "VPC",
            "trafficType": "ALL",
            "logDestinationType": "cloud-watch-logs",
            "logGroupName": log_group_name,
            "deliverLogsPermissionArn": iam_role_arn
        },
        "responseElements": {
            "flowLogIdSet": {"items": [{"flowLogId": flow_log_id}]},
            "unsuccessful": [],
            "requestId": str(uuid.uuid4())
        },
        "resources": [
            {"type": "AWS::EC2::VPC", "ARN": f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}", "accountId": account_id},
            {"type": "AWS::Logs::LogGroup", "ARN": f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}", "accountId": account_id}
        ]
    })
    return [event]
    
def _generate_s3_suspicious_encryption(config, context=None):
    """(Threat) Simulates multiple S3 PutObject events using a specific KMS key."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True) # More suspicious

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')
    
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    kms_key_arn = random.choice(aws_conf.get("kms_keys", [f"arn:aws:kms:{region}:{account_id}:key/mrk-00000000000000000"]))
    target_bucket = random.choice(s3_buckets)
    bucket_arn = f"arn:aws:s3:::{target_bucket}"
    
    events = []
    for _ in range(random.randint(3, 7)):
        target_key = f"encrypted/file-{random.randint(1000, 9999)}.dat"
        object_arn = f"arn:aws:s3:::{target_bucket}/{target_key}"
        
        event = _get_base_event(config, user_identity, ip_address, region, "PutObject", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)
        event.update({
            "managementEvent": False,
            "eventCategory": "Data",
            "requestParameters": {
                "bucketName": target_bucket,
                "key": target_key,
                "Host": f"{target_bucket}.s3.{region}.amazonaws.com",
                "x-amz-server-side-encryption": "aws:kms",
                "x-amz-server-side-encryption-aws-kms-key-id": kms_key_arn
            },
            "responseElements": {
                "x-amz-request-id": str(uuid.uuid4()),
                "x-amz-id-2": ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=76)),
                "x-amz-server-side-encryption": "aws:kms",
                "x-amz-server-side-encryption-aws-kms-key-id": kms_key_arn
            },
            "resources": [
                {"type": "AWS::S3::Object", "ARN": object_arn, "accountId": account_id},
                {"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id},
                {"type": "AWS::KMS::Key", "ARN": kms_key_arn, "accountId": account_id}
            ]
        })
        events.append(event)

    return events


def _generate_s3_ransomware_encrypt(config, context=None):
    """(Threat) Simulates ransomware operator re-encrypting S3 objects with a foreign-account KMS key.
    Triggers XSIAM: 'Suspicious objects encryption in an AWS bucket'
    Detection signal: kms:GenerateDataKey from s3.amazonaws.com using a KMS key owned by a
    non-organization account, repeated across multiple objects in the same bucket.

    Full attack chain:
      GetCallerIdentity → ListBuckets → ListObjectsV2 →
      [CopyObject + GenerateDataKey] ×50-250 →
      DeleteObjects (batch) → PutObject (ransom note, no KMS)

    Each CopyObject (attacker IP) is immediately followed by a paired GenerateDataKey
    (kms.amazonaws.com, sourceIPAddress=s3.amazonaws.com) — S3 calls KMS internally
    to obtain the data key for each object it encrypts.
    """
    aws_conf = config.get(CONFIG_KEY, {})
    account_id = aws_conf.get('aws_account_id', '123456789012')
    region = aws_conf.get('aws_region', 'us-east-1')
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])

    # Stolen long-term IAM credentials — AKIA key from exfiltrated .env/config files.
    # Build a clean IAMUser identity from scratch so all fields are internally consistent:
    # AIDA principalId prefix, user ARN, AKIA access key, no sessionContext.
    # Coercing an AssumedRole identity to type=IAMUser leaves AROA/role fields intact,
    # which breaks XIF field extraction and potentially the detection query.
    _raw_user = _get_random_user(config)
    _user_name = _raw_user.get('name', _raw_user.get('userName', 'svc-backup-user'))
    account_id = _raw_user.get('accountId', account_id)
    user_identity = {
        "type": "IAMUser",
        "name": _user_name,
        "accountId": account_id,
        "arn_suffix": f"user/{_user_name}",
    }

    # VPN-only source IP — single consistent IP per run, rotates across runs.
    # Tor excluded: too slow/unreliable for bulk S3 throughput.
    ip_address = get_random_vpn_ip_ctx(config)["ip"]

    # Foreign-account KMS key — the primary cross-account detection signal
    foreign_account = random.choice(aws_conf.get("foreign_account_ids", ["999988887777"]))
    foreign_key_id = "mrk-" + "".join(random.choices("0123456789abcdef", k=32))
    foreign_kms_arn = f"arn:aws:kms:{region}:{foreign_account}:key/{foreign_key_id}"

    target_bucket = random.choice(s3_buckets)
    bucket_arn = f"arn:aws:s3:::{target_bucket}"

    # Generate object inventory once — shared across ListObjectsV2, CopyObject, DeleteObjects
    _prefixes = ["documents/", "data/", "backups/", "reports/", "exports/", "archives/", "db/", "configs/"]
    _exts = [".dat", ".bak", ".docx", ".xlsx", ".pdf", ".db", ".sql", ".csv", ".json", ".tar.gz"]
    num_files = random.randint(50, 250)
    objects = [
        {
            "key": f"{random.choice(_prefixes)}{random.randint(10000, 99999)}{random.choice(_exts)}",
            "size": random.randint(1024, 50 * 1024 * 1024),
            "eTag": '"' + ''.join(random.choices('0123456789abcdef', k=32)) + '"',
        }
        for _ in range(num_files)
    ]

    _cipher_suites = [
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "TLS_AES_128_GCM_SHA256",
    ]
    cipher_suite = random.choice(_cipher_suites)

    base_time = datetime.datetime.now(datetime.UTC)
    t_offset = 0.0
    events = []

    def _ts(offset):
        return (base_time + datetime.timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%SZ')

    def _ts_ms(offset):
        return (base_time + datetime.timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%S.000Z')

    def _strip_vpc(e):
        """External attacker traffic never arrives through a VPC endpoint."""
        e.pop("vpcEndpointId", None)
        e.pop("vpcEndpointAccountId", None)
        return e

    # ── Phase 1: GetCallerIdentity — verify stolen creds work ─────────────────
    e = _strip_vpc(_get_base_event(config, user_identity, ip_address, region, "GetCallerIdentity", "sts.amazonaws.com", api_version="2011-06-15", read_only=True))
    e["eventTime"] = _ts(t_offset)
    e.update({
        "requestParameters": None,
        "responseElements": {
            "account": account_id,
            "userId": user_identity.get('name', 'unknown'),
            "arn": user_identity.get('arn', f"arn:aws:iam::{account_id}:user/{user_identity.get('name', 'unknown')}")
        },
        "resources": []
    })
    events.append(e)
    t_offset += 5

    # ── Phase 2: ListBuckets — discover the target bucket ─────────────────────
    e = _strip_vpc(_get_base_event(config, user_identity, ip_address, region, "ListBuckets", "s3.amazonaws.com", api_version="2006-03-01", read_only=True))
    e["eventTime"] = _ts(t_offset)
    e.update({
        "requestParameters": None,
        "responseElements": {"buckets": [{"name": b} for b in s3_buckets[:5]]},
        "resources": []
    })
    events.append(e)
    t_offset += 8

    # ── Phase 3: ListObjectsV2 — enumerate bucket contents ────────────────────
    page_size = 1000
    pages = [objects[i:i + page_size] for i in range(0, len(objects), page_size)]
    next_token = None
    for page_idx, page_objects in enumerate(pages):
        is_last = (page_idx == len(pages) - 1)
        req_params = {"bucketName": target_bucket, "encoding-type": "url", "max-keys": page_size}
        if next_token:
            req_params["continuation-token"] = next_token
        next_token = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=32)) if not is_last else None

        resp = {
            "isTruncated": not is_last,
            "keyCount": len(page_objects),
            "maxKeys": page_size,
            "name": target_bucket,
            "prefix": ""
        }
        if next_token:
            resp["nextContinuationToken"] = next_token

        e = _strip_vpc(_get_base_event(config, user_identity, ip_address, region, "ListObjectsV2", "s3.amazonaws.com", api_version="2006-03-01", read_only=True))
        e["eventTime"] = _ts(t_offset)
        e.update({
            "requestParameters": req_params,
            "responseElements": resp,
            "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
        })
        events.append(e)
        t_offset += 3

    # ── Phase 4: CopyObject + GenerateDataKey pairs ────────────────────────────
    # Each CopyObject (attacker re-encrypts the object) is immediately followed by a
    # kms:GenerateDataKey event — S3 calls KMS synchronously to get the data key.
    # The KMS event carries:
    #   - userIdentity.type=AWSService / invokedBy=s3.amazonaws.com (service-to-service)
    #   - sourceIPAddress=s3.amazonaws.com (not the attacker IP)
    #   - resources[].accountId=foreign_account  ← the non-org-account signal XSIAM detects
    #   - encryptionContext links the KMS call back to the specific bucket and object key
    for obj in objects:
        object_arn = f"arn:aws:s3:::{target_bucket}/{obj['key']}"
        new_etag = '"' + ''.join(random.choices('0123456789abcdef', k=32)) + '"'
        copy_time = t_offset

        # CopyObject — S3 data event from the attacker's VPN IP
        # KMS key resource belongs in the KMS event only; S3 event has S3 resources only
        e = _strip_vpc(_get_base_event(config, user_identity, ip_address, region, "CopyObject", "s3.amazonaws.com", api_version="2006-03-01", read_only=False))
        e["eventTime"] = _ts(copy_time)
        e.update({
            "managementEvent": False,
            "eventCategory": "Data",
            "additionalEventData": {
                "AuthenticationMethod": "AuthHeader",
                "CipherSuite": cipher_suite,
                "SignatureVersion": "SigV4",
                "bytesTransferredIn": 0,
                "bytesTransferredOut": 0
            },
            "requestParameters": {
                "bucketName": target_bucket,
                "key": obj['key'],
                "copySource": f"{target_bucket}/{obj['key']}",
                "x-amz-metadata-directive": "REPLACE",
                "x-amz-server-side-encryption": "aws:kms",
                "x-amz-server-side-encryption-aws-kms-key-id": foreign_kms_arn
            },
            "responseElements": {
                "copyObjectResult": {
                    "eTag": new_etag,
                    "lastModified": _ts_ms(copy_time)
                }
            },
            "resources": [
                {"type": "AWS::S3::Object", "ARN": object_arn, "accountId": account_id},
                {"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id},
                # KMS key included in S3 event resources — cross-account accountId is the detection signal
                {"type": "AWS::KMS::Key", "ARN": foreign_kms_arn, "accountId": foreign_account}
            ]
        })
        events.append(e)

        # GenerateDataKey — KMS management event, S3 service calling KMS internally
        # Built from the same base to inherit requestID, eventID, recipientAccountId, tlsDetails, etc.
        # userIdentity and sourceIPAddress are then overridden to reflect the service call.
        kms_e = _strip_vpc(_get_base_event(config, user_identity, "s3.amazonaws.com", region, "GenerateDataKey", "kms.amazonaws.com", read_only=False))
        kms_e["eventTime"] = _ts(copy_time + 1)
        kms_e["sourceIPAddress"] = "s3.amazonaws.com"
        kms_e["recipientAccountId"] = account_id
        # AWSService identity — no principalId, accessKeyId, accountId, or sessionContext
        kms_e["userIdentity"] = {"type": "AWSService", "invokedBy": "s3.amazonaws.com"}
        # S3→KMS service calls show the calling service as the agent, not a CLI string.
        # Set explicitly so generate_log's defaults pass doesn't overwrite with a CLI agent.
        kms_e["userAgent"] = "s3.amazonaws.com"
        # sharedEventID is always present for cross-account KMS events — it marks that
        # this event involves a resource (KMS key) owned by a different AWS account.
        kms_e["sharedEventID"] = str(uuid.uuid4())
        kms_e.update({
            "requestParameters": {
                "keyId": foreign_kms_arn,
                "keySpec": "AES_256",
                "encryptionContext": {
                    "aws:s3:arn": object_arn,
                    "aws:s3:bucketName": target_bucket,
                    "aws:s3:x-amz-server-side-encryption-aws-kms-key-id": foreign_kms_arn
                }
            },
            "responseElements": None,  # KMS never logs key material in CloudTrail
            "resources": [
                # Foreign accountId here is the non-organization-account signal XSIAM detects
                {"type": "AWS::KMS::Key", "ARN": foreign_kms_arn, "accountId": foreign_account}
            ]
        })
        events.append(kms_e)

        t_offset += random.uniform(0.1, 0.5)  # Tight interval — rapid bulk operation

    # ── Phase 5: DeleteObjects — remove originals in batches of 500 ──────────
    batch_size = 500
    for i in range(0, len(objects), batch_size):
        batch = objects[i:i + batch_size]
        e = _strip_vpc(_get_base_event(config, user_identity, ip_address, region, "DeleteObjects", "s3.amazonaws.com", api_version="2006-03-01", read_only=False))
        e["eventTime"] = _ts(t_offset)
        e.update({
            "managementEvent": False,
            "eventCategory": "Data",
            "additionalEventData": {
                "AuthenticationMethod": "AuthHeader",
                "CipherSuite": cipher_suite,
                "SignatureVersion": "SigV4",
                "bytesTransferredIn": 0,
                "bytesTransferredOut": 0
            },
            "requestParameters": {
                "bucketName": target_bucket,
                "delete": {
                    "objects": [{"key": obj['key']} for obj in batch],
                    "quiet": False
                }
            },
            "responseElements": {
                "DeleteResult": {
                    "Deleted": [{"Key": obj['key']} for obj in batch]
                }
            },
            "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
        })
        events.append(e)
        t_offset += 5

    # ── Phase 6: PutObject ransom note — plain text, intentionally no KMS ─────
    # Victim must be able to read the note; encrypting it would defeat the purpose
    ransom_key = random.choice([
        "RANSOM_NOTE.txt", "README_DECRYPT.txt",
        "HOW_TO_RECOVER_FILES.txt", "YOUR_FILES_ARE_ENCRYPTED.txt"
    ])
    ransom_arn = f"arn:aws:s3:::{target_bucket}/{ransom_key}"
    e = _strip_vpc(_get_base_event(config, user_identity, ip_address, region, "PutObject", "s3.amazonaws.com", api_version="2006-03-01", read_only=False))
    e["eventTime"] = _ts(t_offset)
    e.update({
        "managementEvent": False,
        "eventCategory": "Data",
        "additionalEventData": {
            "AuthenticationMethod": "AuthHeader",
            "CipherSuite": cipher_suite,
            "SignatureVersion": "SigV4",
            "bytesTransferredIn": random.randint(512, 2048),
            "bytesTransferredOut": 0
        },
        "requestParameters": {
            "bucketName": target_bucket,
            "key": ransom_key,
            "Host": f"{target_bucket}.s3.{region}.amazonaws.com"
            # No x-amz-server-side-encryption — ransom note is deliberately unencrypted
        },
        "responseElements": {
            "x-amz-request-id": str(uuid.uuid4()),
            "x-amz-id-2": ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=76))
        },
        "resources": [
            {"type": "AWS::S3::Object", "ARN": ransom_arn, "accountId": account_id},
            {"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}
        ]
    })
    events.append(e)

    return events


def _generate_k8s_sa_outside_cluster(config, context=None):
    """(Threat) Simulates a K8s service account token being used from an external IP."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not ip_address: ip_address = _get_random_ip(config, force_external=True) # Force external IP
    
    aws_conf = config.get(CONFIG_KEY, {})
    account_id = aws_conf.get('aws_account_id', '123456789012')
    region = aws_conf.get('aws_region', 'us-east-1')
    
    # 1. Simulate the AssumeRoleWithWebIdentity call (this is the K8s SA authenticating)
    # This event is anonymous (no userIdentity) but has requestParameters
    # Use timezone-aware datetime
    now = datetime.datetime.now(datetime.UTC)
    
    # Generate realistic EKS IRSA (IAM Roles for Service Accounts) identifiers
    _irsa_role_names = [
        "prod-backend-api-irsa-role", "dev-worker-irsa-role", "staging-ingress-irsa-role",
        "eks-cluster-autoscaler-role", "fluentbit-log-forwarder-role", "external-secrets-role",
        "aws-load-balancer-controller-role", "cert-manager-irsa-role", "monitoring-prometheus-role",
        "datadog-agent-irsa-role",
    ]
    _k8s_namespaces = ["default", "kube-system", "monitoring", "logging", "ingress-nginx", "prod", "staging"]
    _k8s_sa_names = ["app-service-account", "backend-sa", "worker-sa", "api-sa", "default"]
    eks_role_name = random.choice(_irsa_role_names)
    k8s_namespace = random.choice(_k8s_namespaces)
    k8s_sa_name = random.choice(_k8s_sa_names)
    # Pod session name follows K8s naming: <deployment>-<replicaset-hash>-<pod-hash>
    _pod_prefix = random.choice(["backend-api", "worker", "api-server", "log-agent", "autoscaler"])
    _rs_hash = ''.join(random.choices('0123456789abcdef', k=8))
    _pod_hash = ''.join(random.choices('bcdfghjklmnpqrstvwxz2456789', k=5))
    pod_session_name = f"{_pod_prefix}-{_rs_hash}-{_pod_hash}"

    role_arn = f"arn:aws:iam::{account_id}:role/{eks_role_name}"
    role_id = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"

    event1 = {
        "eventVersion": "1.11",
        "userIdentity": None, # STS WebIdentity calls are initially anonymous
        "eventTime": now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRoleWithWebIdentity",
        "awsRegion": "us-east-1", # STS is global
        "sourceIPAddress": ip_address,
        "userAgent": "aws-sdk-go/1.44.180 (go1.20.4; linux; amd64)",
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "readOnly": True,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": account_id,
        "eventCategory": "Management",
        "tlsDetails": {
            "tlsVersion": "TLSv1.2",
            "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
            "clientProvidedHostHeader": "sts.amazonaws.com"
        },
        "sharedEventID": str(uuid.uuid4()),
        "vpcEndpointId": f"vpce-{''.join(random.choices('0123456789abcdef', k=17))}",
        "vpcEndpointAccountId": account_id,
        "apiVersion": "2011-06-15",
        "requestParameters": {
            "roleArn": role_arn,
            "roleSessionName": pod_session_name,
            "webIdentityToken": "eyJraWQiOi...[REDACTED]...GV9pbiI6MzYwMH0",
            "durationSeconds": 3600
        },
        "responseElements": {
            "credentials": {
                "accessKeyId": f"ASIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "expiration": (now + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "sessionToken": "Value hidden due to security reasons."
            },
            "assumedRoleUser": {
                "assumedRoleId": f"{role_id}:{pod_session_name}",
                "arn": f"arn:aws:sts::{account_id}:assumed-role/{eks_role_name}/{pod_session_name}"
            },
            "audience": "sts.amazonaws.com"
        },
        "resources": [{"type": "AWS::IAM::Role", "ARN": role_arn, "accountId": account_id}]
    }

    # 2. Create the identity that will be used for the *next* call
    assumed_role_identity = {
        "type": "AssumedRole",
        "principalId": event1["responseElements"]["assumedRoleUser"]["assumedRoleId"],
        "arn": event1["responseElements"]["assumedRoleUser"]["arn"],
        "accountId": account_id,
        "userName": f"{eks_role_name}/{pod_session_name}", # Add userName for base_event
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": role_id,
                "arn": role_arn,
                "accountId": account_id,
                "userName": eks_role_name
            },
            "attributes": {
                "mfaAuthenticated": "false",
                "creationDate": now.strftime('%Y-%m-%dT%H:%M:%SZ')
            },
            "webIdFederationData": { # This is key for K8s SA
                "federatedProvider": f"arn:aws:iam::{account_id}:oidc-provider/oidc.eks.{region}.amazonaws.com/id/{''.join(random.choices('0123456789ABCDEF', k=32))}",
                "attributes": {"aud": "sts.amazonaws.com", "sub": f"system:serviceaccount:{k8s_namespace}:{k8s_sa_name}"}
            }
        }
    }
    
    # 3. Simulate the suspicious API call (e.g., ListSecrets) using the new identity
    event2 = _get_base_event(config, assumed_role_identity, ip_address, region, "ListSecrets", "secretsmanager.amazonaws.com", api_version="2017-10-17", read_only=True)
    event2.update({
        "requestParameters": {"maxResults": 100},
        "responseElements": {
            "secretList": [{
                "ARN": f"arn:aws:secretsmanager:{region}:{account_id}:secret:prod/db/creds-123456",
                "name": "prod/db/creds"
            }],
            "nextToken": None
        },
        "resources": []
    })
    
    return [event1, event2]

def _generate_guardduty_detector_deleted(config, context=None):
    """(Threat) Simulates deleting a GuardDuty detector."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config, allow_root=True) # Admin/Root action
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    # Detector ID format is just hex chars, no 'gd-' prefix typically
    detector_id = f"{''.join(random.choices('0123456789abcdef', k=32))}" 
    # ARN is still useful internally but not put in resources
    # detector_arn = f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}" 

    event = _get_base_event(config, user_identity, ip_address, region, "DeleteDetector", "guardduty.amazonaws.com", api_version="2017-11-28", read_only=False)
    event.update({
        "requestParameters": {"detectorId": detector_id},
        "responseElements": None,
        # --- FIX: Empty resources list ---
        "resources": [] 
        # --- END FIX ---
    })
    return [event]
    
def _generate_pentest_instance_launch(config, context=None):
    """(Threat) Simulates launching a Kali Linux instance."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.1: # 10% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.4: # 30% chance Random External
            ip_address = _get_random_ip(config, force_external=True)
        else: # 60% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    # Use a known Kali AMI ID
    ami_id = random.choice(aws_conf.get("pentest_ami_ids", ["ami-01b4cff60c681b957"]))
    instance_type = "t3.medium" # Pentest tools might use a bit more RAM
    new_instance_id = f"i-{''.join(random.choices('0123456789abcdef', k=17))}"
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{new_instance_id}"
    key_name = random.choice(aws_conf.get("key_pair_names", ["prod-key"]))
    sg_id = random.choice(aws_conf.get("security_groups", ["sg-00000000000000000"]))
    
    event = _get_base_event(config, user_identity, ip_address, region, "RunInstances", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {
            "instancesSet": {"items": [{"imageId": ami_id, "instanceType": instance_type, "minCount": 1, "maxCount": 1}]},
            "keyName": key_name,
            "securityGroupSet": {"items": [{"groupId": sg_id}]},
            "instanceInitiatedShutdownBehavior": "stop"
        },
        "responseElements": {
            "reservationId": f"r-{''.join(random.choices('0123456789abcdef', k=17))}",
            "ownerId": account_id,
            "instancesSet": {"items": [
                {"instanceId": new_instance_id, "imageId": ami_id, "instanceState": {"code": 0, "name": "pending"}, "instanceType": instance_type}
            ]}
        },
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_ec2_instance_type_change(config, context=None):
    """(Threat) Simulates changing an instance type to a large, expensive one (crypto mining)."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.05: # 5% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.2: # 15% chance Random External
            ip_address = _get_random_ip(config, force_external=True)
        else: # 80% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
    
    # Pick a large instance type
    large_type = random.choice(aws_conf.get("large_instance_types", ["p4d.24xlarge"]))

    event = _get_base_event(config, user_identity, ip_address, region, "ModifyInstanceAttribute", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    event.update({
        "requestParameters": {
            "instanceId": instance_id,
            "instanceType": {"value": large_type}
        },
        "responseElements": {"return": True},
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_s3_copy_to_foreign_account(config, context=None):
    """(Threat) Simulates S3 CopyObject to a bucket in a foreign account."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    # --- Make user_identity more realistic (Role invoked by EC2) ---
    if not user_identity:
        user_identity = {}  # Initialize before assigning into it
        aws_conf = config.get(CONFIG_KEY, {})
        account_id_temp = aws_conf.get('aws_account_id', '123456789012')
        _roles = [u for u in aws_conf.get('users_and_roles', []) if u['type'] in ['Role', 'AssumedRole']]
        role_sample = random.choice(_roles) if _roles else {"name": "DevOpsRole", "arn_suffix": "role/DevOpsRole", "type": "Role"}
        user_identity['type'] = 'AssumedRole' # Overwrite type
        # --- FIX START ---
        role_base_name = role_sample['name'].split('/')[0]
        # Generate the instance ID part correctly using join
        instance_id_part = f"i-{''.join(random.choices('0123456789abcdef', k=17))}"
        session_name = instance_id_part # Use the instance ID as the session name part
        role_principal_id_base = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"

        user_identity['name'] = f"{role_base_name}/{session_name}"
        user_identity['arn'] = f"arn:aws:sts::{account_id_temp}:assumed-role/{role_base_name}/{session_name}"
        user_identity['principalId'] = f"{role_principal_id_base}:{session_name}"
    # --- FIX END ---
        # Add sessionContext if missing
        if 'sessionContext' not in user_identity:
             role_name_for_issuer = role_sample['name'].split('/')[0]
             role_arn_for_issuer = f"arn:aws:iam::{account_id_temp}:role/{role_name_for_issuer}"
             role_id_for_issuer = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
             user_identity['sessionContext'] = {
                "sessionIssuer": { "type": "Role", "principalId": role_id_for_issuer, "arn": role_arn_for_issuer, "accountId": account_id_temp, "userName": role_name_for_issuer },
                "attributes": { "mfaAuthenticated": "false", "creationDate": datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ') }
             }
        user_identity['invokedBy'] = "ec2.amazonaws.com" # Add invokedBy

    if not ip_address: ip_address = _get_random_ip(config, force_external=False) # Often internal if invoked by EC2

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')

    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    source_bucket = random.choice(s3_buckets)
    source_key = f"confidential/archive-{random.randint(10,99)}.zip"
    source_bucket_arn = f"arn:aws:s3:::{source_bucket}"
    source_object_arn = f"arn:aws:s3:::{source_bucket}/{source_key}"

    foreign_account = random.choice(aws_conf.get("foreign_account_ids", ["999988887777"]))
    foreign_bucket_name = f"foreign-backup-bucket-{random.randint(100,999)}"
    foreign_bucket_arn = f"arn:aws:s3:::{foreign_bucket_name}"

    event = _get_base_event(config, user_identity, ip_address, region, "CopyObject", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)

    # --- FIXES ---
    event["recipientAccountId"] = account_id # Set recipient to SOURCE account

    event.update({
        "managementEvent": False,
        "eventCategory": "Data",
        "requestParameters": {
            "bucketName": foreign_bucket_name, # Destination bucket
            "key": source_key,
            # Correct copy source format
            "x-amz-copy-source": f"{source_bucket}/{source_key}", 
            "Host": f"{foreign_bucket_name}.s3.{region}.amazonaws.com"
        },
        # Simulate SUCCESS response
        "responseElements": { 
            "copyObjectResult": {
                "eTag": f"\"{''.join(random.choices('0123456789abcdef', k=32))}\"",
                "lastModified": datetime.datetime.now(datetime.UTC).isoformat(timespec='microseconds') + "Z"
            }
        },
        # Remove error fields
        # "errorCode": "AccessDenied", 
        # "errorMessage": "Access Denied",
        # Add additionalEventData
        "additionalEventData": { 
             "SSEApplied": "Default_SSE_S3",
             "bytesTransferredOut": random.randint(1000000, 50000000) # Simulate bytes transferred
        },
        "resources": [
            {"type": "AWS::S3::Object", "ARN": source_object_arn, "accountId": account_id}, # Source Object (accountId added)
            {"type": "AWS::S3::Bucket", "ARN": source_bucket_arn, "accountId": account_id}, # Source Bucket
            # Destination bucket needs accountId
            {"type": "AWS::S3::Bucket", "ARN": foreign_bucket_arn, "accountId": foreign_account} 
        ]
    })
    # --- END FIXES ---
    return [event]
    
def _generate_s3_disable_bucket_logging(config, context=None):
    """(Threat) Simulates disabling S3 server access logging on a bucket."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.05: # 5% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.7: # 65% chance Random External
            ip_address = _get_random_ip(config, force_external=True)
        else: # 30% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')
    
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    target_bucket = random.choice(s3_buckets)
    bucket_arn = f"arn:aws:s3:::{target_bucket}"

    event = _get_base_event(config, user_identity, ip_address, region, "PutBucketLogging", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)
    event.update({
        "requestParameters": {
            "bucketName": target_bucket,
            "Host": f"{target_bucket}.s3.{region}.amazonaws.com",
            "bucketLoggingStatus": {} # Empty status block disables logging
        },
        "responseElements": None,
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
    })
    return [event]

def _generate_api_call_from_tor(config, context=None):
    """(Threat) Simulates a simple read API call (ListUsers) from a Tor IP."""
    user_identity = None
    ip_address = None

    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address') # Context might override Tor

    # --- Simulate an AssumedRole identity ---
    if not user_identity: 
        aws_conf = config.get(CONFIG_KEY, {})
        account_id_temp = aws_conf.get('aws_account_id', '123456789012')
        # Find or create a role template from config
        role_sample = next((u for u in aws_conf.get('users_and_roles', []) if u['type'] in ['Role', 'AssumedRole']), 
                           {"name": "ec2-instance-role", "type": "Role"}) # Default if none found

        user_identity = _get_random_user(config) # Get base structure
        user_identity['type'] = 'AssumedRole'
        # Use a realistic session name pattern
        session_name = f"i-{''.join(random.choices('0123456789abcdef', k=17))}" 
        role_base_name = role_sample['name'].split('/')[0]
        user_identity['name'] = f"{role_base_name}/{session_name}"
        user_identity['arn'] = f"arn:aws:sts::{account_id_temp}:assumed-role/{role_base_name}/{session_name}"
        # Generate matching principalId
        role_principal_id_base = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
        user_identity['principalId'] = f"{role_principal_id_base}:{session_name}"
        user_identity['userName'] = role_base_name # Base role name for userName field
        # Add sessionContext
        user_identity['sessionContext'] = {
            "sessionIssuer": { 
                "type": "Role", 
                "principalId": role_principal_id_base, 
                "arn": f"arn:aws:iam::{account_id_temp}:role/{role_base_name}", 
                "accountId": account_id_temp, 
                "userName": role_base_name 
            },
            "attributes": { 
                "mfaAuthenticated": "false", 
                "creationDate": datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ') 
            }
        }
    # --- End AssumedRole Simulation ---

    if not ip_address: ip_address = _get_random_ip(config, use_tor=True) # Force Tor IP

    region = 'us-east-1' # IAM is global

    # --- Generate ListUsers instead of DescribeInstances ---
    event = _get_base_event(config, user_identity, ip_address, region, "ListUsers", "iam.amazonaws.com", api_version="2010-05-08", read_only=True)
    event.update({
        "requestParameters": None, # Match raw log which shows null
        "responseElements": { # Match raw log structure
            "users": [], # Simulate empty response
            "isTruncated": False
        }, 
        "resources": []
    })
    # --- End ListUsers generation ---
    return [event]

def _generate_cloudwatch_delete_log_stream(config, context=None):
    """(Threat) Simulates deleting a CloudWatch Log Stream."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.1: # 10% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.7: # 60% chance Random External
            ip_address = _get_random_ip(config, force_external=True)
        else: # 30% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    log_group_name = random.choice(aws_conf.get("log_groups", ["/aws/ec2/flow-logs"]))
    log_stream_name = f"2023/10/24/[1]{''.join(random.choices('0123456789abcdef', k=32))}"
    log_group_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}:*"

    event = _get_base_event(config, user_identity, ip_address, region, "DeleteLogStream", "logs.amazonaws.com", api_version="2014-03-28", read_only=False)
    event.update({
        "requestParameters": {
            "logGroupName": log_group_name,
            "logStreamName": log_stream_name
        },
        "responseElements": None,
        "resources": [{"type": "AWS::Logs::LogGroup", "ARN": log_group_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_iam_remove_billing_admin(config, context=None):
    """(Threat) Simulates removing a billing admin policy from a role."""
    user_identity = None
    ip_address = None
    
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config, allow_root=True) # Admin action
    if not ip_address:
        ip_choice = random.random()
        if ip_choice < 0.01: # 1% chance TOR
            ip_address = _get_random_ip(config, use_anon=True)
        elif ip_choice < 0.7: # 60% chance Random External
            ip_address = _get_random_ip(config, force_external=True)
        else: # 30% chance Internal IP (Insider/Compromised Host)
            ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = 'us-east-1'

    # Find a role from config to target
    _roles = [u for u in aws_conf.get('users_and_roles', []) if u['type'] in ['Role', 'AssumedRole']]
    role_sample = random.choice(_roles) if _roles else {"name": "DevOpsRole", "arn_suffix": "role/DevOpsRole", "type": "Role"}

    role_name = role_sample.get('name').split('/')[0]
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    # This is the ARN for the AWS managed Billing policy
    billing_policy_arn = "arn:aws:iam::aws:policy/Billing"

    event = _get_base_event(config, user_identity, ip_address, region, "DetachRolePolicy", "iam.amazonaws.com", api_version="2010-05-08", read_only=False)
    event.update({
        "requestParameters": {"roleName": role_name, "policyArn": billing_policy_arn},
        "responseElements": None,
        "resources": [{"type": "AWS::IAM::Role", "ARN": role_arn, "accountId": account_id}]
    })
    return [event]

def _generate_s3_make_public(config, context=None):
    """(Threat) Simulates making an S3 bucket public via PutBucketPolicy."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = aws_conf.get('aws_region', 'us-east-1')
    
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])
    target_bucket = random.choice(s3_buckets)
    bucket_arn = f"arn:aws:s3:::{target_bucket}"
    
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:GetObject"],
            "Resource": f"arn:aws:s3:::{target_bucket}/*"
        }]
    }

    event = _get_base_event(config, user_identity, ip_address, region, "PutBucketPolicy", "s3.amazonaws.com", api_version="2006-03-01", read_only=False)
    event.update({
        "requestParameters": {
            "bucketName": target_bucket,
            "Host": f"{target_bucket}.s3.{region}.amazonaws.com",
            "policy": json.dumps(public_policy, separators=(',', ':')) # Compact JSON string
        },
        "responseElements": None,
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket_arn, "accountId": account_id}]
    })
    return [event]

def _generate_iam_delete_mfa_device(config, context=None):
    """(Threat) Simulates deleting a virtual MFA device for a user."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = 'us-east-1'
    
    # Pick a target user
    iam_users = [u for u in aws_conf.get('users_and_roles', []) if u['type'] == 'IAMUser']
    if not iam_users:
        target_user = {"name": "Alice", "arn_suffix": "user/Alice"} # Fallback
    else:
        target_user = random.choice(iam_users)
        
    target_user_name = target_user['name']
    # ARN of the virtual MFA device for the user
    mfa_arn = f"arn:aws:iam::{account_id}:mfa/{target_user_name}-mfa"

    event = _get_base_event(config, user_identity, ip_address, region, "DeleteVirtualMFADevice", "iam.amazonaws.com", api_version="2010-05-08", read_only=False)
    event.update({
        "requestParameters": {"serialNumber": mfa_arn},
        "responseElements": None,
        "resources": [{"type": "AWS::IAM::MFADevice", "ARN": mfa_arn, "accountId": account_id}]
    })
    return [event]
    
def _generate_ec2_create_and_share_snapshot(config, context=None):
    """(Threat) Simulates creating a snapshot and sharing it with a foreign account."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    
    volume_id = random.choice(aws_conf.get("ebs_volumes", ["vol-00000000000000000"]))
    snapshot_id = f"snap-{''.join(random.choices('0123456789abcdef', k=17))}"
    snapshot_arn = f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot_id}"
    foreign_account = random.choice(aws_conf.get("foreign_account_ids", ["999988887777"]))
    
    events = []
    
    # 1. Create Snapshot
    create_event = _get_base_event(config, user_identity, ip_address, region, "CreateSnapshot", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    create_event.update({
        "requestParameters": {"volumeId": volume_id, "description": "Temporary backup"},
        "responseElements": {
            "snapshotId": snapshot_id, "volumeId": volume_id, "status": "pending", 
            "startTime": int(datetime.datetime.now(datetime.UTC).timestamp() * 1000), 
            "volumeSize": 50, "ownerId": account_id, "description": "Temporary backup"
        },
        "resources": [
            {"type": "AWS::EC2::Volume", "ARN": f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}", "accountId": account_id},
            {"type": "AWS::EC2::Snapshot", "ARN": snapshot_arn, "accountId": account_id}
        ]
    })
    events.append(create_event)

    # 2. Modify Snapshot Attribute (Share it)
    share_event = _get_base_event(config, user_identity, ip_address, region, "ModifySnapshotAttribute", "ec2.amazonaws.com", api_version="2016-11-15", read_only=False)
    share_event["eventTime"] = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
    share_event.update({
        "requestParameters": {
            "snapshotId": snapshot_id,
            "attribute": "createVolumePermission",
            "operationType": "add",
            "createVolumePermission": {"add": {"items": [{"userId": foreign_account}]}}
        },
        "responseElements": {"return": True},
        "resources": [{"type": "AWS::EC2::Snapshot", "ARN": snapshot_arn, "accountId": account_id}]
    })
    events.append(share_event)
    
    return events
    
def _generate_iam_update_login_profile(config, context=None):
    """(Threat) Simulates updating a user's login profile (password change by admin)."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')
    
    # Actor Selection:
    if not user_identity:
        actor_choice = random.random()
        if actor_choice < 0.15: # 15% Root
            user_identity = _get_random_user(config, allow_root=True)
            while user_identity['type'] != 'Root': user_identity = _get_random_user(config, allow_root=True)
        elif actor_choice < 0.5: # 35% Assumed Role
            user_identity = _get_random_user(config)
            while user_identity['type'] not in ['AssumedRole', 'Role']: user_identity = _get_random_user(config)
        else: # 50% IAM User
            user_identity = _get_random_user(config)
            while user_identity['type'] != 'IAMUser': user_identity = _get_random_user(config)


    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    region = 'us-east-1'
    
   # Target Selection (already randomized, ensure pool is sufficient):
    iam_users = [u for u in aws_conf.get('users_and_roles', []) if u['type'] == 'IAMUser']
    if not iam_users:
       # Handle case where no IAM users are defined in config
       # Perhaps skip event or use a default target? For now, we'll proceed but log warning.
       print("Warning: No IAM users found in config to target for UpdateLoginProfile.")
       target_user = {"name": "DefaultTargetUser", "arn_suffix": "user/DefaultTargetUser"}
    else:
    # Ensure target is different from actor if possible
        target_user = random.choice(iam_users)
        while len(iam_users) > 1 and target_user.get('name') == user_identity.get('name'):
            target_user = random.choice(iam_users)

    target_user_name = target_user['name']
    target_user_arn = f"arn:aws:iam::{account_id}:user/{target_user_name}"

    event = _get_base_event(config, user_identity, ip_address, region, "UpdateLoginProfile", "iam.amazonaws.com", api_version="2010-05-08", read_only=False)
    event.update({
        "requestParameters": {
            "userName": target_user_name,
            "password": "<SENSITIVE_REDACTED>",
            "passwordResetRequired": True
        },
        "responseElements": None,
        "resources": [{"type": "AWS::IAM::User", "ARN": target_user_arn, "accountId": account_id}]
    })
    return [event]

# --- XSIAM BUILT-IN DETECTOR SCENARIOS ---

def _generate_ssm_start_session(config, context=None):
    """(Threat) Simulates an identity starting an AWS SSM Session Manager session.
    Triggers XSIAM: 'An identity started an AWS SSM session'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"

    # Session ID format per AWS docs: <username>-<hex-token>
    user_name = user_identity.get('name', user_identity.get('userName', 'user'))
    if '/' in user_name:
        user_name = user_name.split('/')[-1]
    session_id = f"{user_name}-{''.join(random.choices('0123456789abcdef', k=17))}"

    doc_name = random.choice(["SSM-SessionManagerRunShell", "AWS-StartInteractiveCommand"])

    event = _get_base_event(config, user_identity, ip_address, region, "StartSession", "ssm.amazonaws.com", api_version="2014-11-06", read_only=False)
    event.update({
        "requestParameters": {
            "target": instance_id,
            "documentName": doc_name,
            "parameters": {}
        },
        "responseElements": {
            "sessionId": session_id,
            "tokenValue": "Value hidden due to security reasons.",
            "streamUrl": f"wss://ssmmessages.{region}.amazonaws.com/v1/data-channel/{session_id}?role=publish_subscribe"
        },
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    return [event]


def _generate_ssm_send_command(config, context=None):
    """(Threat) Simulates command execution via AWS SSM SendCommand.
    Triggers XSIAM: 'Command execution via AWS SSM'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"

    # documentName reveals intent even though parameters are redacted in CloudTrail
    doc_name = random.choice(["AWS-RunShellScript", "AWS-RunPowerShellScript"])
    command_id = str(uuid.uuid4())

    now = datetime.datetime.now(datetime.UTC)
    expires_after = (now + datetime.timedelta(hours=1)).strftime("%b %d, %Y %I:%M:%S %p")
    requested_date = now.strftime("%b %d, %Y %I:%M:%S %p")

    event = _get_base_event(config, user_identity, ip_address, region, "SendCommand", "ssm.amazonaws.com", api_version="2014-11-06", read_only=False)
    event.update({
        "requestParameters": {
            "documentName": doc_name,
            "documentVersion": "$DEFAULT",
            "instanceIds": [instance_id],
            "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
            "timeoutSeconds": 3600,
            "comment": "",
            "outputS3BucketName": "",
            "outputS3KeyPrefix": "",
            "maxConcurrency": "50",
            "maxErrors": "0"
        },
        "responseElements": {
            "command": {
                "commandId": command_id,
                "documentName": doc_name,
                "documentVersion": "$DEFAULT",
                "comment": "",
                "expiresAfter": expires_after,
                "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
                "instanceIds": [instance_id],
                "targets": [],
                "requestedDateTime": requested_date,
                "status": "Pending",
                "statusDetails": "Pending",
                "outputS3BucketName": "",
                "outputS3KeyPrefix": "",
                "maxConcurrency": "50",
                "maxErrors": "0",
                "targetCount": 1,
                "completedCount": 0,
                "errorCount": 0,
                "deliveryTimedOutCount": 0,
                "timeoutSeconds": 3600,
                "serviceRole": "",
                "notificationConfig": {
                    "notificationArn": "",
                    "notificationEvents": [],
                    "notificationType": ""
                },
                "cloudWatchOutputConfig": {
                    "cloudWatchLogGroupName": "",
                    "cloudWatchOutputEnabled": False
                }
            }
        },
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    return [event]


def _generate_ssm_execution_chain(config, context=None):
    """(Threat) Simulates a recon-to-code-execution attack chain via AWS SSM.
    Triggers XSIAM: 'Command execution via AWS SSM' — with suspicious lead-up recon activity.
    Chain: DescribeInstanceInformation -> GetParameter (withDecryption) -> SendCommand
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, use_anon=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    instance_id = random.choice(aws_conf.get("ec2_instances", ["i-00000000000000000"]))
    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"

    sensitive_param = random.choice(aws_conf.get("sensitive_credential_paths", ["/prod/db/password"]))

    doc_name = random.choice(["AWS-RunShellScript", "AWS-RunPowerShellScript"])
    command_id = str(uuid.uuid4())

    base_time = datetime.datetime.now(datetime.UTC)
    now_fmt = base_time.strftime("%b %d, %Y %I:%M:%S %p")
    expires_fmt = (base_time + datetime.timedelta(hours=1)).strftime("%b %d, %Y %I:%M:%S %p")

    events = []

    # Event 1: DescribeInstanceInformation — attacker enumerates SSM-managed EC2 instances
    e1 = _get_base_event(config, user_identity, ip_address, region, "DescribeInstanceInformation", "ssm.amazonaws.com", api_version="2014-11-06", read_only=True)
    e1["eventTime"] = base_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    e1.update({
        "requestParameters": {
            "filters": [{"key": "PingStatus", "valueSet": ["Online"]}]
        },
        "responseElements": {
            "instanceInformationList": [{
                "instanceId": instance_id,
                "pingStatus": "Online",
                "platformType": "Linux"
            }]
        },
        "resources": []
    })
    events.append(e1)

    # Event 2: GetParameter — attacker reads a sensitive Parameter Store value with decryption
    e2 = _get_base_event(config, user_identity, ip_address, region, "GetParameter", "ssm.amazonaws.com", api_version="2014-11-06", read_only=True)
    e2["eventTime"] = (base_time + datetime.timedelta(seconds=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
    e2.update({
        "requestParameters": {
            "name": sensitive_param,
            "withDecryption": True
        },
        "responseElements": None,  # CloudTrail omits parameter value from responseElements
        "resources": []
    })
    events.append(e2)

    # Event 3: SendCommand — code execution on the instance found in event 1
    e3 = _get_base_event(config, user_identity, ip_address, region, "SendCommand", "ssm.amazonaws.com", api_version="2014-11-06", read_only=False)
    e3["eventTime"] = (base_time + datetime.timedelta(seconds=20)).strftime('%Y-%m-%dT%H:%M:%SZ')
    e3.update({
        "requestParameters": {
            "documentName": doc_name,
            "documentVersion": "$DEFAULT",
            "instanceIds": [instance_id],
            "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
            "timeoutSeconds": 3600,
            "comment": "",
            "outputS3BucketName": "",
            "outputS3KeyPrefix": "",
            "maxConcurrency": "50",
            "maxErrors": "0"
        },
        "responseElements": {
            "command": {
                "commandId": command_id,
                "documentName": doc_name,
                "documentVersion": "$DEFAULT",
                "comment": "",
                "expiresAfter": expires_fmt,
                "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
                "instanceIds": [instance_id],
                "targets": [],
                "requestedDateTime": now_fmt,
                "status": "Pending",
                "statusDetails": "Pending",
                "outputS3BucketName": "",
                "outputS3KeyPrefix": "",
                "maxConcurrency": "50",
                "maxErrors": "0",
                "targetCount": 1,
                "completedCount": 0,
                "errorCount": 0,
                "deliveryTimedOutCount": 0,
                "timeoutSeconds": 3600,
                "serviceRole": "",
                "notificationConfig": {
                    "notificationArn": "",
                    "notificationEvents": [],
                    "notificationType": ""
                },
                "cloudWatchOutputConfig": {
                    "cloudWatchLogGroupName": "",
                    "cloudWatchOutputEnabled": False
                }
            }
        },
        "resources": [{"type": "AWS::EC2::Instance", "ARN": instance_arn, "accountId": account_id}]
    })
    events.append(e3)

    return events


def _generate_rds_modify_db_snapshot_attribute(config, context=None):
    """(Threat) Simulates sharing an RDS snapshot with a foreign account.
    Triggers XSIAM: 'A cloud snapshot of AWS database or storage was modified or shared'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    snapshot_id = random.choice(aws_conf.get("rds_snapshots", ["rds:db-prod-snapshot-2023-10-21"]))
    snapshot_arn = f"arn:aws:rds:{region}:{account_id}:snapshot:{snapshot_id}"
    foreign_account = random.choice(aws_conf.get("foreign_account_ids", ["999988887777"]))

    event = _get_base_event(config, user_identity, ip_address, region, "ModifyDBSnapshotAttribute", "rds.amazonaws.com", api_version="2014-10-31", read_only=False)
    event.update({
        # attributeName must be "restore" for cross-account access - this is the detection indicator
        "requestParameters": {
            "dBSnapshotIdentifier": snapshot_id,
            "attributeName": "restore",
            "valuesToAdd": [foreign_account]
        },
        "responseElements": {
            "dBSnapshotAttributesResult": {
                "dBSnapshotIdentifier": snapshot_id,
                "dBSnapshotAttributes": [
                    {
                        "attributeName": "restore",
                        "attributeValues": [foreign_account]
                    }
                ]
            }
        },
        "resources": [{"type": "AWS::RDS::DBSnapshot", "ARN": snapshot_arn, "accountId": account_id}]
    })
    return [event]


def _generate_lambda_role_remote_usage(config, context=None):
    """(Threat) Simulates stolen Lambda execution-role credentials used from an external IP via CLI.
    Triggers XSIAM: 'Remote usage of AWS Lambda's role'
    Detection logic: AssumedRole with invokedBy=lambda.amazonaws.com + external sourceIPAddress.
    4-event CLI chain: GetCallerIdentity -> ListBuckets -> ListSecrets -> GetSecretValue
    """
    aws_conf = config.get(CONFIG_KEY, {})
    account_id = aws_conf.get('aws_account_id', '123456789012')
    region = aws_conf.get('aws_region', 'us-east-1')
    s3_buckets = aws_conf.get("s3_buckets", ["default-sim-bucket-1"])

    func_name = random.choice(aws_conf.get("lambda_functions", ["default-function"]))
    # Role name derived from the function — realistic naming convention
    role_name = f"{func_name}-exec-role"
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    role_id = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"

    # ASIA prefix = temporary STS credentials (from Lambda execution environment)
    temp_access_key = f"ASIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}"

    # Attacker using stolen creds via CLI from VPN/Tor — not from Lambda infrastructure
    ip_address = _get_random_ip(config, use_anon=True)

    # Force a CLI user agent — key signal that credentials are being used outside Lambda
    cli_agents = [ua for ua in _AWS_USER_AGENTS if ua.startswith("aws-cli/")]
    cli_ua = random.choice(cli_agents) if cli_agents else _AWS_USER_AGENTS[0]

    # Identity: AssumedRole with invokedBy=lambda.amazonaws.com is the key XSIAM detection signal
    assumed_role_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{func_name}"
    lambda_identity = {
        "type": "AssumedRole",
        "name": f"{role_name}/{func_name}",
        "arn": assumed_role_arn,
        "principalId": f"{role_id}:{func_name}",
        "accountId": account_id,
        "accessKeyId": temp_access_key,
        "invokedBy": "lambda.amazonaws.com",
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": role_id,
                "arn": role_arn,
                "accountId": account_id,
                "userName": role_name
            },
            "attributes": {
                "mfaAuthenticated": "false",
                "creationDate": datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
            }
        }
    }

    base_time = datetime.datetime.now(datetime.UTC)
    secret_arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:prod/db/creds-AbCdEf"
    events = []

    # Event 1: GetCallerIdentity — attacker verifies stolen creds are valid (first CLI step)
    e1 = _get_base_event(config, lambda_identity, ip_address, region, "GetCallerIdentity", "sts.amazonaws.com", api_version="2011-06-15", read_only=True)
    e1["eventTime"] = base_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    e1["userAgent"] = cli_ua
    e1.update({
        "requestParameters": None,
        "responseElements": {
            "account": account_id,
            "userId": f"{role_id}:{func_name}",
            "arn": assumed_role_arn
        },
        "resources": []
    })
    events.append(e1)

    # Event 2: ListBuckets — recon, discovers accessible S3 buckets
    e2 = _get_base_event(config, lambda_identity, ip_address, region, "ListBuckets", "s3.amazonaws.com", api_version="2006-03-01", read_only=True)
    e2["eventTime"] = (base_time + datetime.timedelta(seconds=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
    e2["userAgent"] = cli_ua
    e2.update({
        "requestParameters": None,
        "responseElements": {
            "buckets": [{"name": b} for b in s3_buckets[:5]]
        },
        "resources": []
    })
    events.append(e2)

    # Event 3: ListSecrets — recon, discovers secrets stored in Secrets Manager
    e3 = _get_base_event(config, lambda_identity, ip_address, region, "ListSecrets", "secretsmanager.amazonaws.com", api_version="2017-10-17", read_only=True)
    e3["eventTime"] = (base_time + datetime.timedelta(seconds=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
    e3["userAgent"] = cli_ua
    e3.update({
        "requestParameters": {"maxResults": 100},
        "responseElements": {
            "secretList": [{"ARN": secret_arn, "name": "prod/db/creds"}],
            "nextToken": None
        },
        "resources": []
    })
    events.append(e3)

    # Event 4: GetSecretValue — escalation, reads the discovered secret
    # Real CloudTrail omits secretString from responseElements — only metadata returned
    e4 = _get_base_event(config, lambda_identity, ip_address, region, "GetSecretValue", "secretsmanager.amazonaws.com", api_version="2017-10-17", read_only=True)
    e4["eventTime"] = (base_time + datetime.timedelta(seconds=15)).strftime('%Y-%m-%dT%H:%M:%SZ')
    e4["userAgent"] = cli_ua
    e4.update({
        "requestParameters": {"secretId": "prod/db/creds"},
        "responseElements": {
            "ARN": secret_arn,
            "name": "prod/db/creds",
            "versionId": ''.join(random.choices('abcdef0123456789-', k=36))
        },
        "resources": [{"type": "AWS::SecretsManager::Secret", "ARN": secret_arn, "accountId": account_id}]
    })
    events.append(e4)

    return events


def _generate_bedrock_delete_model_invocation_logging(config, context=None):
    """(Threat) Simulates deleting AWS Bedrock model invocation logging configuration.
    Triggers XSIAM: 'AWS Bedrock model invocation logging deletion'
    Per AWS API: requestParameters and responseElements are both null (DELETE with no body/response).
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')

    event = _get_base_event(config, user_identity, ip_address, region, "DeleteModelInvocationLoggingConfiguration", "bedrock.amazonaws.com", api_version="2023-04-20", read_only=False)
    event.update({
        "requestParameters": None,   # AWS API takes no request body (HTTP DELETE with no body)
        "responseElements": None,    # AWS API returns empty HTTP 200 on success
        "resources": []
    })
    return [event]


def _generate_cross_account_assume_role(config, context=None):
    """(Threat) Simulates a cross-account STS AssumeRole from a suspicious external account.

    The calling identity's accountId differs from the recipientAccountId — the
    canonical cross-account access signal that XSIAM analytics use to flag
    unexpected trust-boundary traversal.

    Triggers XSIAM: Cross-Account AssumeRole / unexpected trust boundary.
    """
    user_identity = None
    ip_address    = None
    if context:
        user_identity = context.get('user_identity')
        ip_address    = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address:    ip_address    = _get_random_ip(config, force_external=True)

    aws_conf      = config.get(CONFIG_KEY, {})
    region        = aws_conf.get('aws_region', 'us-east-1')
    account_id    = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    # The foreign account is a separate, suspicious AWS account ID
    foreign_account_id = str(random.randint(100_000_000_000, 999_999_999_999))
    while foreign_account_id == account_id:
        foreign_account_id = str(random.randint(100_000_000_000, 999_999_999_999))

    target_role_names = aws_conf.get("cross_account_role_names", [
        "OrganizationAccountAccessRole", "ReadOnlyAccess", "SecurityAudit",
        "AdministratorAccess", "DevOpsRole", "DeploymentRole",
    ])
    target_role   = random.choice(target_role_names)
    target_role_arn = f"arn:aws:iam::{account_id}:role/{target_role}"
    session_name  = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))}-session"
    assumed_role_id = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
    assumed_arn   = f"arn:aws:sts::{account_id}:assumed-role/{target_role}/{session_name}"
    credentials_expiry = (
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    event = _get_base_event(
        config, user_identity, ip_address, region,
        "AssumeRole", "sts.amazonaws.com",
        api_version="2011-06-15", read_only=False,
    )
    # Override: caller comes from the foreign account
    event["userIdentity"]["accountId"] = foreign_account_id
    event["recipientAccountId"] = account_id          # target account being accessed
    event.update({
        "requestParameters": {
            "roleArn": target_role_arn,
            "roleSessionName": session_name,
            "durationSeconds": 3600,
        },
        "responseElements": {
            "credentials": {
                "accessKeyId": f"ASIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "sessionToken": "Value hidden due to security reasons.",
                "expiration": credentials_expiry,
            },
            "assumedRoleUser": {
                "assumedRoleId": f"{assumed_role_id}:{session_name}",
                "arn": assumed_arn,
            },
        },
        "resources": [
            {"type": "AWS::IAM::Role", "ARN": target_role_arn, "accountId": account_id}
        ],
    })
    return [event]


def _generate_security_hub_disabled(config, context=None):
    """(Threat) Simulates disabling AWS Security Hub — a defense evasion action.

    Disabling Security Hub suppresses all cross-service security findings, hiding
    GuardDuty alerts, Config violations, and Inspector findings from the console.

    Triggers XSIAM: Defense Evasion / Security service disabled.
    """
    user_identity = None
    ip_address    = None
    if context:
        user_identity = context.get('user_identity')
        ip_address    = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config, allow_root=True)
    if not ip_address:    ip_address    = _get_random_ip(config, force_external=True)

    aws_conf   = config.get(CONFIG_KEY, {})
    region     = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))
    hub_arn    = f"arn:aws:securityhub:{region}:{account_id}:hub/default"

    event = _get_base_event(
        config, user_identity, ip_address, region,
        "DisableSecurityHub", "securityhub.amazonaws.com",
        api_version="2018-10-26", read_only=False,
    )
    event.update({
        "requestParameters": None,
        "responseElements": None,
        "resources": [
            {"type": "AWS::SecurityHub::Hub", "ARN": hub_arn, "accountId": account_id}
        ],
    })
    return [event]


def _generate_config_recorder_stopped(config, context=None):
    """(Threat) Simulates stopping the AWS Config configuration recorder.

    Stopping the recorder halts continuous resource change tracking, effectively
    creating a blind spot in configuration compliance monitoring.

    Triggers XSIAM: Defense Evasion / Config recorder stopped.
    """
    user_identity = None
    ip_address    = None
    if context:
        user_identity = context.get('user_identity')
        ip_address    = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config, allow_root=True)
    if not ip_address:    ip_address    = _get_random_ip(config, force_external=True)

    aws_conf   = config.get(CONFIG_KEY, {})
    region     = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    recorder_names = aws_conf.get("config_recorder_names", ["default", "aws-controltower-BaselineConfigRecorder"])
    recorder_name  = random.choice(recorder_names)

    event = _get_base_event(
        config, user_identity, ip_address, region,
        "StopConfigurationRecorder", "config.amazonaws.com",
        api_version="2014-11-12", read_only=False,
    )
    event.update({
        "requestParameters": {"configurationRecorderName": recorder_name},
        "responseElements": None,
        "resources": [],
    })
    return [event]


def _generate_waf_rule_deleted(config, context=None):
    """(Threat) Simulates deleting an AWS WAFv2 Web ACL or IP set — defense evasion.

    Removing a WAF rule or Web ACL exposes the protected resource to attack and
    eliminates rate-limiting and geo-blocking protections.

    Triggers XSIAM: Defense Evasion / WAF rule removed.
    """
    user_identity = None
    ip_address    = None
    if context:
        user_identity = context.get('user_identity')
        ip_address    = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config, allow_root=True)
    if not ip_address:    ip_address    = _get_random_ip(config, force_external=True)

    aws_conf   = config.get(CONFIG_KEY, {})
    region     = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    # Randomly choose between deleting a full WebACL vs just an IPSet
    action = random.choice(["DeleteWebACL", "DeleteIPSet"])
    scope  = random.choice(["REGIONAL", "CLOUDFRONT"])

    resource_id   = str(uuid.uuid4())
    lock_token    = str(uuid.uuid4())

    if action == "DeleteWebACL":
        web_acl_names = aws_conf.get("waf_web_acl_names", [
            "ProductionAPIProtection", "MainWebsiteACL",
            "CloudFrontProtection", "AdminPortalACL",
        ])
        resource_name = random.choice(web_acl_names)
        resource_arn  = (
            f"arn:aws:wafv2:{region}:{account_id}:regional/webacl/{resource_name}/{resource_id}"
            if scope == "REGIONAL"
            else f"arn:aws:wafv2:us-east-1:{account_id}:global/webacl/{resource_name}/{resource_id}"
        )
        resource_type = "AWS::WAFv2::WebACL"
    else:
        ipset_names = aws_conf.get("waf_ipset_names", [
            "BlockedCountriesIPSet", "MaliciousIPSet",
            "AllowListIPSet", "ThreatIntelIPSet",
        ])
        resource_name = random.choice(ipset_names)
        resource_arn  = (
            f"arn:aws:wafv2:{region}:{account_id}:regional/ipset/{resource_name}/{resource_id}"
            if scope == "REGIONAL"
            else f"arn:aws:wafv2:us-east-1:{account_id}:global/ipset/{resource_name}/{resource_id}"
        )
        resource_type = "AWS::WAFv2::IPSet"

    event = _get_base_event(
        config, user_identity, ip_address, region,
        action, "wafv2.amazonaws.com",
        api_version="2019-07-29", read_only=False,
    )
    event.update({
        "requestParameters": {
            "name": resource_name,
            "id":   resource_id,
            "scope": scope,
            "lockToken": lock_token,
        },
        "responseElements": None,
        "resources": [
            {"type": resource_type, "ARN": resource_arn, "accountId": account_id}
        ],
    })
    return [event]


# ─── Bedrock / SageMaker XSIAM detector generators ───────────────────────────

def _generate_bedrock_kb_modification(config, context=None):
    """(Threat) Simulates an unusual modification to a Bedrock Knowledge Base.
    Triggers XSIAM: 'Unusual AI Knowledge Base Modification' and
                    'Unusual AI RAG Knowledge Base Modification'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    kb_ids = aws_conf.get('bedrock_knowledge_bases', ['KBID1234AB', 'KBID5678CD', 'KBID9012EF'])
    kb_id = random.choice(kb_ids)
    kb_arn = f"arn:aws:bedrock:{region}:{account_id}:knowledge-base/{kb_id}"

    action = random.choice([
        "UpdateKnowledgeBase",
        "IngestKnowledgeBaseDocuments",
        "AssociateAgentKnowledgeBase",
        "DeleteKnowledgeBase",
    ])

    if action == "UpdateKnowledgeBase":
        req_params = {
            "knowledgeBaseId": kb_id,
            "name": f"kb-{kb_id.lower()}-updated",
            "description": "Updated knowledge base configuration",
            "roleArn": f"arn:aws:iam::{account_id}:role/AmazonBedrockExecutionRoleForKnowledgeBase",
            "knowledgeBaseConfiguration": {
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {
                    "embeddingModelArn": f"arn:aws:bedrock:{region}::foundation-model/amazon.titan-embed-text-v2:0"
                },
            },
        }
        resp = {"knowledgeBase": {"knowledgeBaseId": kb_id, "status": "UPDATING"}}
    elif action == "IngestKnowledgeBaseDocuments":
        data_source_id = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=10))
        req_params = {
            "knowledgeBaseId": kb_id,
            "dataSourceId": data_source_id,
            "documents": [
                {"s3Location": {"uri": f"s3://corp-kb-documents/{kb_id.lower()}/doc-{i}.pdf"}}
                for i in range(random.randint(1, 10))
            ],
        }
        resp = {"ingestedDocuments": [{"status": "INDEXED"}], "failedDocuments": []}
    elif action == "AssociateAgentKnowledgeBase":
        agent_id = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=10))
        req_params = {
            "agentId": agent_id,
            "agentVersion": "DRAFT",
            "knowledgeBaseId": kb_id,
            "description": "Associated knowledge base for agent",
            "knowledgeBaseState": "ENABLED",
        }
        resp = {"agentKnowledgeBase": {"agentId": agent_id, "knowledgeBaseId": kb_id, "knowledgeBaseState": "ENABLED"}}
    else:  # DeleteKnowledgeBase
        req_params = {"knowledgeBaseId": kb_id}
        resp = {"knowledgeBase": {"knowledgeBaseId": kb_id, "status": "DELETING"}}

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "bedrock-agent.amazonaws.com",
                            api_version="2023-06-05", read_only=False)
    event.update({
        "requestParameters": req_params,
        "responseElements": resp,
        "resources": [{"type": "AWS::Bedrock::KnowledgeBase", "ARN": kb_arn, "accountId": account_id}],
    })
    return [event]


def _generate_credential_file_access(config, context=None):
    """(Threat) Simulates suspicious access to cloud credential secrets via SSM Parameter Store or Secrets Manager.
    Triggers XSIAM: 'Suspicious access to cloud credential files'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    sensitive_paths = aws_conf.get('sensitive_credential_paths', [
        '/credentials/aws-access-key',
        '/corp/iam/service-account-key',
        '/prod/aws/access-key-id',
        '/prod/aws/secret-access-key',
        '/ec2/instance-credentials',
        '/ci/aws-deploy-credentials',
    ])
    secret_path = random.choice(sensitive_paths)

    use_secrets_manager = random.random() < 0.5
    if use_secrets_manager:
        suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
        secret_arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{secret_path.lstrip('/')}-{suffix}"
        event = _get_base_event(config, user_identity, ip_address, region,
                                "GetSecretValue", "secretsmanager.amazonaws.com",
                                api_version="2017-10-17", read_only=True)
        event.update({
            "requestParameters": {"secretId": secret_path},
            "responseElements": None,  # CloudTrail redacts secret values
            "resources": [{"type": "AWS::SecretsManager::Secret", "ARN": secret_arn, "accountId": account_id}],
        })
    else:
        param_arn = f"arn:aws:ssm:{region}:{account_id}:parameter{secret_path}"
        event = _get_base_event(config, user_identity, ip_address, region,
                                "GetParameter", "ssm.amazonaws.com",
                                api_version="2014-11-06", read_only=True)
        event.update({
            "requestParameters": {"name": secret_path, "withDecryption": True},
            "responseElements": None,  # CloudTrail redacts parameter values
            "resources": [{"type": "AWS::SSM::Parameter", "ARN": param_arn, "accountId": account_id}],
        })
    return [event]


def _generate_bedrock_guardrail_deleted(config, context=None):
    """(Threat) Simulates deletion of a Bedrock Guardrail (AI safety control).
    Triggers XSIAM: 'AI safeguards deletion attempt'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    guardrail_ids = aws_conf.get('bedrock_guardrail_ids', ['abc12345defg', 'xyz98765mnop', 'qrs55555tuvw'])
    guardrail_id = random.choice(guardrail_ids)
    guardrail_arn = f"arn:aws:bedrock:{region}:{account_id}:guardrail/{guardrail_id}"

    event = _get_base_event(config, user_identity, ip_address, region,
                            "DeleteGuardrail", "bedrock.amazonaws.com",
                            api_version="2023-04-20", read_only=False)
    event.update({
        "requestParameters": {
            "guardrailIdentifier": guardrail_id,
            "guardrailVersion": "DRAFT",
        },
        "responseElements": None,  # DELETE returns HTTP 202 with no body on success
        "resources": [{"type": "AWS::Bedrock::Guardrail", "ARN": guardrail_arn, "accountId": account_id}],
    })
    return [event]


def _generate_bedrock_denial_of_wallet(config, context=None):
    """(Threat) Simulates a sudden spike in Bedrock InvokeModel calls (denial-of-wallet attack).
    Triggers XSIAM: 'Potential denial of wallet abusing AI services'
    Returns multiple events representing the traffic burst.
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    model_ids = aws_conf.get('bedrock_model_ids', [
        'anthropic.claude-3-5-sonnet-20241022-v2:0',
        'anthropic.claude-3-haiku-20240307-v1:0',
        'amazon.nova-pro-v1:0',
        'amazon.titan-text-express-v1',
        'meta.llama3-70b-instruct-v1:0',
    ])
    # Spike targets a single expensive model
    model_id = random.choice(model_ids)
    model_arn = f"arn:aws:bedrock:{region}::foundation-model/{model_id}"

    spike_count = random.randint(20, 50)
    events = []
    for _ in range(spike_count):
        event = _get_base_event(config, user_identity, ip_address, region,
                                "InvokeModel", "bedrock-runtime.amazonaws.com",
                                api_version="2023-09-30", read_only=False)
        event.update({
            "requestParameters": {
                "modelId": model_id,
                "accept": "application/json",
                "contentType": "application/json",
            },
            "responseElements": None,
            "resources": [{"type": "AWS::Bedrock::FoundationModel", "ARN": model_arn, "accountId": account_id}],
        })
        events.append(event)
    return events


def _generate_sagemaker_dataset_modification(config, context=None):
    """(Threat) Simulates unusual modification of a SageMaker Feature Store feature group (training dataset).
    Triggers XSIAM: 'Unusual AI dataset modification'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    feature_groups = aws_conf.get('sagemaker_feature_groups', [
        'fraud-detection-features', 'customer-churn-features',
        'recommendation-engine-features', 'nlp-training-dataset',
    ])
    fg_name = random.choice(feature_groups)
    fg_arn = f"arn:aws:sagemaker:{region}:{account_id}:feature-group/{fg_name}"

    action = random.choice(["UpdateFeatureGroup", "DeleteFeatureGroup", "UpdateFeatureMetadata"])
    if action == "UpdateFeatureGroup":
        req_params = {
            "featureGroupName": fg_name,
            "featureAdditions": [
                {
                    "featureName": f"new_feature_{random.randint(1, 99)}",
                    "featureType": random.choice(["String", "Integral", "Fractional"]),
                }
            ],
        }
        resp = {"featureGroupArn": fg_arn}
    elif action == "DeleteFeatureGroup":
        req_params = {"featureGroupName": fg_name}
        resp = None
    else:  # UpdateFeatureMetadata
        req_params = {
            "featureGroupName": fg_name,
            "featureName": f"feature_{random.randint(1, 20)}",
            "description": "Modified feature description",
            "parameters": [{"key": "source", "value": "modified"}],
        }
        resp = {}

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "sagemaker.amazonaws.com",
                            api_version="2017-07-24", read_only=False)
    event.update({
        "requestParameters": req_params,
        "responseElements": resp,
        "resources": [{"type": "AWS::SageMaker::FeatureGroup", "ARN": fg_arn, "accountId": account_id}],
    })
    return [event]


def _generate_sagemaker_label_modification(config, context=None):
    """(Threat) Simulates suspicious creation/modification of a SageMaker Ground Truth labeling job (label poisoning).
    Triggers XSIAM: 'Suspicious AI Dataset Label Modification'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    labeling_jobs = aws_conf.get('sagemaker_labeling_jobs', [
        'fraud-label-job', 'sentiment-annotation-job',
        'image-classification-labels', 'ner-tagging-job',
    ])
    job_name = random.choice(labeling_jobs)
    new_job_name = f"{job_name}-relabel-{random.randint(1000, 9999)}"
    job_arn = f"arn:aws:sagemaker:{region}:{account_id}:labeling-job/{new_job_name}"
    region_acct = f"{region}:{account_id}"

    event = _get_base_event(config, user_identity, ip_address, region,
                            "CreateLabelingJob", "sagemaker.amazonaws.com",
                            api_version="2017-07-24", read_only=False)
    event.update({
        "requestParameters": {
            "labelingJobName": new_job_name,
            "labelAttributeName": "label",
            "inputConfig": {
                "dataSource": {
                    "s3DataSource": {
                        "manifestS3Uri": f"s3://sagemaker-datasets-{account_id}/{job_name}/input.manifest"
                    }
                },
            },
            "outputConfig": {"s3OutputPath": f"s3://sagemaker-output-{account_id}/{job_name}/"},
            "roleArn": f"arn:aws:iam::{account_id}:role/SageMakerLabelingRole",
            "labelCategoryConfigS3Uri": f"s3://sagemaker-ground-truth-{account_id}/{job_name}/label_categories.json",
            "humanTaskConfig": {
                "workteamArn": f"arn:aws:sagemaker:{region_acct}:workteam/private-crowd/default",
                "uiConfig": {
                    "uiTemplateS3Uri": f"s3://sagemaker-gt-{account_id}/templates/classification.html"
                },
                "preHumanTaskLambdaArn": f"arn:aws:lambda:{region}:432418664414:function:PRE-ImageMultiClass",
                "taskTitle": f"Relabeling task: {job_name}",
                "taskDescription": "Relabel existing annotations",
                "numberOfHumanWorkersPerDataObject": 1,
                "taskTimeLimitInSeconds": 3600,
                "annotationConsolidationConfig": {
                    "annotationConsolidationLambdaArn": f"arn:aws:lambda:{region}:432418664414:function:ACS-ImageMultiClass"
                },
            },
        },
        "responseElements": {"labelingJobArn": job_arn},
        "resources": [{"type": "AWS::SageMaker::LabelingJob", "ARN": job_arn, "accountId": account_id}],
    })
    return [event]


def _generate_bedrock_unusual_model_access(config, context=None):
    """(Threat) Simulates an unusual Bedrock model invocation from an unexpected identity.
    Triggers XSIAM: 'Unusual AWS Bedrock model access request'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    model_ids = aws_conf.get('bedrock_model_ids', [
        'anthropic.claude-3-5-sonnet-20241022-v2:0',
        'anthropic.claude-3-opus-20240229-v1:0',
        'amazon.nova-pro-v1:0',
        'meta.llama3-70b-instruct-v1:0',
        'mistral.mistral-large-2402-v1:0',
        'cohere.command-r-plus-v1:0',
    ])
    model_id = random.choice(model_ids)
    model_arn = f"arn:aws:bedrock:{region}::foundation-model/{model_id}"

    action = random.choice(["InvokeModel", "InvokeModelWithResponseStream"])
    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "bedrock-runtime.amazonaws.com",
                            api_version="2023-09-30", read_only=False)
    event.update({
        "requestParameters": {
            "modelId": model_id,
            "accept": "application/json",
            "contentType": "application/json",
        },
        "responseElements": None,
        "resources": [{"type": "AWS::Bedrock::FoundationModel", "ARN": model_arn, "accountId": account_id}],
    })
    return [event]


def _generate_bedrock_tor_model_usage(config, context=None):
    """(Threat) Simulates an AI model invocation from a Tor exit node.
    Triggers XSIAM: 'Suspicious AI model usage from a Tor exit node'
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, use_tor=True)  # Force Tor exit node

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    model_ids = aws_conf.get('bedrock_model_ids', [
        'anthropic.claude-3-5-sonnet-20241022-v2:0',
        'anthropic.claude-3-haiku-20240307-v1:0',
        'amazon.nova-pro-v1:0',
        'amazon.titan-text-express-v1',
    ])
    model_id = random.choice(model_ids)
    model_arn = f"arn:aws:bedrock:{region}::foundation-model/{model_id}"

    event = _get_base_event(config, user_identity, ip_address, region,
                            "InvokeModel", "bedrock-runtime.amazonaws.com",
                            api_version="2023-09-30", read_only=False)
    event.update({
        "requestParameters": {
            "modelId": model_id,
            "accept": "application/json",
            "contentType": "application/json",
        },
        "responseElements": None,
        "resources": [{"type": "AWS::Bedrock::FoundationModel", "ARN": model_arn, "accountId": account_id}],
    })
    return [event]


# ─── Bedrock / SageMaker benign generators ────────────────────────────────────

def _generate_bedrock_invoke_model(config, context=None):
    """(Benign) Routine Bedrock InvokeModel call — normal AI application usage."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    model_ids = aws_conf.get('bedrock_model_ids', [
        'anthropic.claude-3-5-sonnet-20241022-v2:0',
        'anthropic.claude-3-haiku-20240307-v1:0',
        'amazon.nova-pro-v1:0',
        'amazon.titan-text-express-v1',
    ])
    model_id = random.choice(model_ids)
    model_arn = f"arn:aws:bedrock:{region}::foundation-model/{model_id}"

    action = random.choice(["InvokeModel", "InvokeModelWithResponseStream"])
    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "bedrock-runtime.amazonaws.com",
                            api_version="2023-09-30", read_only=False)
    event.update({
        "requestParameters": {
            "modelId": model_id,
            "accept": "application/json",
            "contentType": "application/json",
        },
        "responseElements": None,
        "resources": [{"type": "AWS::Bedrock::FoundationModel", "ARN": model_arn, "accountId": account_id}],
    })
    return [event]


def _generate_bedrock_list_foundation_models(config, context=None):
    """(Benign) Read-only ListFoundationModels — developer or app checking available models."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')

    # Optionally filter by provider or output modality (common in automation scripts)
    providers = [None, "amazon", "anthropic", "meta", "cohere", "mistral"]
    by_provider = random.choice(providers)
    req_params = {}
    if by_provider:
        req_params["byProvider"] = by_provider

    event = _get_base_event(config, user_identity, ip_address, region,
                            "ListFoundationModels", "bedrock.amazonaws.com",
                            api_version="2023-04-20", read_only=True)
    event.update({
        "requestParameters": req_params if req_params else None,
        "responseElements": None,
        "resources": [],
    })
    return [event]


def _generate_bedrock_retrieve(config, context=None):
    """(Benign) Normal RAG Retrieve query against a Bedrock Knowledge Base."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    kb_ids = aws_conf.get('bedrock_knowledge_bases', ['KBPROD1234AB', 'KBPROD5678CD'])
    kb_id = random.choice(kb_ids)
    kb_arn = f"arn:aws:bedrock:{region}:{account_id}:knowledge-base/{kb_id}"

    # RetrieveAndGenerate is more common in real apps; Retrieve is used by custom orchestration
    action = random.choice(["Retrieve", "RetrieveAndGenerate"])
    service = "bedrock-agent-runtime.amazonaws.com"

    if action == "Retrieve":
        req_params = {
            "knowledgeBaseId": kb_id,
            "retrievalQuery": {"text": random.choice([
                "What is our refund policy?",
                "How do I reset my password?",
                "Summarize Q3 earnings report",
                "List security compliance requirements",
                "What are the product specifications?",
            ])},
            "retrievalConfiguration": {
                "vectorSearchConfiguration": {"numberOfResults": random.randint(3, 10)}
            },
        }
    else:  # RetrieveAndGenerate
        model_ids = aws_conf.get('bedrock_model_ids', ['anthropic.claude-3-haiku-20240307-v1:0'])
        model_id = random.choice(model_ids)
        req_params = {
            "input": {"text": random.choice([
                "Summarize the latest compliance requirements",
                "What are the steps for onboarding a new employee?",
                "Explain the incident response procedure",
            ])},
            "retrieveAndGenerateConfiguration": {
                "type": "KNOWLEDGE_BASE",
                "knowledgeBaseConfiguration": {
                    "knowledgeBaseId": kb_id,
                    "modelArn": f"arn:aws:bedrock:{region}::foundation-model/{model_id}",
                },
            },
        }

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, service, api_version="2023-07-26", read_only=True)
    event.update({
        "requestParameters": req_params,
        "responseElements": None,
        "resources": [{"type": "AWS::Bedrock::KnowledgeBase", "ARN": kb_arn, "accountId": account_id}],
    })
    return [event]


def _generate_sagemaker_list_training_jobs(config, context=None):
    """(Benign) Read-only SageMaker ListTrainingJobs — routine job monitoring."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')

    # Mix of list and describe calls — both are common in CI/CD and monitoring
    action = random.choice(["ListTrainingJobs", "DescribeTrainingJob", "ListModels", "DescribeModel"])

    if action == "DescribeTrainingJob":
        fg_list = aws_conf.get('sagemaker_feature_groups', ['fraud-detection-features'])
        job_name = f"training-{random.choice(fg_list)}-{random.randint(1000, 9999)}"
        req_params = {"trainingJobName": job_name}
    elif action == "DescribeModel":
        model_name = f"model-{random.randint(1000, 9999)}-prod"
        req_params = {"modelName": model_name}
    else:
        req_params = {
            "maxResults": random.randint(10, 100),
            "statusEquals": random.choice(["Completed", "InProgress", "Failed", None]),
        }
        req_params = {k: v for k, v in req_params.items() if v is not None}

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "sagemaker.amazonaws.com",
                            api_version="2017-07-24", read_only=True)
    event.update({
        "requestParameters": req_params,
        "responseElements": None,
        "resources": [],
    })
    return [event]


def _generate_secretsmanager_get_secret(config, context=None):
    """(Benign) Normal GetSecretValue for a non-credential application secret (DB password, API key)."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    # Non-credential secret paths — routine application usage
    benign_secrets = [
        '/prod/db/postgres-password',
        '/prod/db/mysql-password',
        '/prod/api/stripe-key',
        '/prod/api/sendgrid-key',
        '/prod/app/jwt-signing-secret',
        '/staging/db/password',
        '/prod/redis/auth-token',
        '/prod/smtp/password',
        '/prod/oauth/client-secret',
        '/corp/monitoring/pagerduty-token',
    ]
    secret_path = random.choice(benign_secrets)
    suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
    secret_arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{secret_path.lstrip('/')}-{suffix}"

    event = _get_base_event(config, user_identity, ip_address, region,
                            "GetSecretValue", "secretsmanager.amazonaws.com",
                            api_version="2017-10-17", read_only=True)
    event.update({
        "requestParameters": {"secretId": secret_path},
        "responseElements": None,
        "resources": [{"type": "AWS::SecretsManager::Secret", "ARN": secret_arn, "accountId": account_id}],
    })
    return [event]


# ─── Additional benign generators ─────────────────────────────────────────────

def _generate_dynamodb_read(config, context=None):
    """(Benign) Routine DynamoDB read — GetItem, Query, Scan, DescribeTable, ListTables."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    tables = aws_conf.get('dynamodb_tables', ['users', 'sessions', 'products', 'orders', 'events', 'config'])
    table_name = random.choice(tables)
    table_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"

    action = random.choice(["GetItem", "Query", "Scan", "DescribeTable", "ListTables"])

    if action == "GetItem":
        req_params = {"tableName": table_name, "key": {"id": {"S": str(uuid.uuid4())}}, "consistentRead": False}
    elif action == "Query":
        req_params = {
            "tableName": table_name,
            "keyConditionExpression": "#pk = :pkval",
            "expressionAttributeNames": {"#pk": "id"},
            "expressionAttributeValues": {":pkval": {"S": str(uuid.uuid4())}},
            "limit": random.randint(10, 100),
        }
    elif action == "Scan":
        req_params = {"tableName": table_name, "limit": random.randint(10, 50), "select": "ALL_ATTRIBUTES"}
    elif action == "DescribeTable":
        req_params = {"tableName": table_name}
    else:  # ListTables
        req_params = {"limit": 100}
        table_arn = None

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "dynamodb.amazonaws.com", api_version="2012-08-10", read_only=True)
    event.update({
        "requestParameters": req_params,
        "responseElements": None,
        "resources": [{"type": "AWS::DynamoDB::Table", "ARN": table_arn, "accountId": account_id}] if table_arn else [],
    })
    return [event]


def _generate_dynamodb_write(config, context=None):
    """(Benign) Routine DynamoDB write — PutItem, UpdateItem, DeleteItem."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    tables = aws_conf.get('dynamodb_tables', ['users', 'sessions', 'products', 'orders', 'events', 'config'])
    table_name = random.choice(tables)
    table_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"
    item_id = str(uuid.uuid4())
    ts = str(int(datetime.datetime.now(datetime.UTC).timestamp()))

    action = random.choice(["PutItem", "UpdateItem", "DeleteItem"])
    if action == "PutItem":
        req_params = {
            "tableName": table_name,
            "item": {"id": {"S": item_id}, "updatedAt": {"N": ts}},
            "returnValues": "NONE",
        }
    elif action == "UpdateItem":
        req_params = {
            "tableName": table_name,
            "key": {"id": {"S": item_id}},
            "updateExpression": "SET #ts = :ts",
            "expressionAttributeNames": {"#ts": "updatedAt"},
            "expressionAttributeValues": {":ts": {"N": ts}},
            "returnValues": "NONE",
        }
    else:  # DeleteItem
        req_params = {"tableName": table_name, "key": {"id": {"S": item_id}}, "returnValues": "NONE"}

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "dynamodb.amazonaws.com", api_version="2012-08-10", read_only=False)
    event.update({
        "requestParameters": req_params,
        "responseElements": None,
        "resources": [{"type": "AWS::DynamoDB::Table", "ARN": table_arn, "accountId": account_id}],
    })
    return [event]


def _generate_sts_assume_role_benign(config, context=None):
    """(Benign) Routine same-account STS AssumeRole — CI/CD pipelines, cross-service automation."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    service_roles = aws_conf.get('cross_account_role_names', [
        'LambdaExecutionRole', 'EC2InstanceRole', 'CodeDeployRole',
        'CodePipelineRole', 'CloudFormationDeployRole', 'ECSTaskExecutionRole',
    ])
    role_name = random.choice(service_roles)
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    session_name = random.choice([
        f"lambda-{random.randint(1000,9999)}",
        f"codepipeline-{random.randint(1000,9999)}",
        f"ecs-task-{str(uuid.uuid4())[:8]}",
        f"automation-{random.randint(100,999)}",
    ])
    assumed_role_id = f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
    expiry = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    event = _get_base_event(config, user_identity, ip_address, region,
                            "AssumeRole", "sts.amazonaws.com", api_version="2011-06-15", read_only=False)
    event.update({
        "requestParameters": {"roleArn": role_arn, "roleSessionName": session_name, "durationSeconds": 3600},
        "responseElements": {
            "credentials": {
                "accessKeyId": f"ASIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                "sessionToken": "Value hidden due to security reasons.",
                "expiration": expiry,
            },
            "assumedRoleUser": {
                "assumedRoleId": f"{assumed_role_id}:{session_name}",
                "arn": f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}",
            },
        },
        "resources": [{"type": "AWS::IAM::Role", "ARN": role_arn, "accountId": account_id}],
    })
    return [event]


def _generate_sqs_operations(config, context=None):
    """(Benign) Routine SQS operations — SendMessage, ReceiveMessage, GetQueueAttributes, ListQueues."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    queues = aws_conf.get('sqs_queues', [
        'order-processing', 'email-notifications', 'audit-events',
        'image-resize', 'data-pipeline', 'dlq-order-processing',
    ])
    queue_name = random.choice(queues)
    queue_url = f"https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"
    queue_arn = f"arn:aws:sqs:{region}:{account_id}:{queue_name}"

    action = random.choice(["SendMessage", "ReceiveMessage", "GetQueueAttributes", "ListQueues"])

    if action == "SendMessage":
        req_params = {"queueUrl": queue_url, "messageBody": "HIDDEN_DUE_TO_SECURITY_REASONS", "delaySeconds": 0}
        resp = {"sendMessageResponse": {"sendMessageResult": {
            "messageId": str(uuid.uuid4()),
            "mD5OfMessageBody": ''.join(random.choices('abcdef0123456789', k=32)),
        }}}
        resources = [{"type": "AWS::SQS::Queue", "ARN": queue_arn, "accountId": account_id}]
    elif action == "ReceiveMessage":
        req_params = {"queueUrl": queue_url, "maxNumberOfMessages": random.randint(1,10), "waitTimeSeconds": random.choice([0,5,10,20])}
        resp = None
        resources = [{"type": "AWS::SQS::Queue", "ARN": queue_arn, "accountId": account_id}]
    elif action == "GetQueueAttributes":
        req_params = {"queueUrl": queue_url, "attributeNames": ["All"]}
        resp = None
        resources = [{"type": "AWS::SQS::Queue", "ARN": queue_arn, "accountId": account_id}]
    else:  # ListQueues
        req_params = {"maxResults": 100}
        resp = None
        resources = []

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "sqs.amazonaws.com", api_version="2012-11-05",
                            read_only=(action != "SendMessage"))
    event.update({"requestParameters": req_params, "responseElements": resp, "resources": resources})
    return [event]


def _generate_sns_operations(config, context=None):
    """(Benign) Routine SNS operations — Publish, ListTopics, GetTopicAttributes."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    topics = aws_conf.get('sns_topics', [
        'order-alerts', 'security-notifications', 'infrastructure-alarms',
        'user-signups', 'payment-events', 'system-health',
    ])
    topic_name = random.choice(topics)
    topic_arn = f"arn:aws:sns:{region}:{account_id}:{topic_name}"

    action = random.choice(["Publish", "ListTopics", "GetTopicAttributes"])

    if action == "Publish":
        subject = random.choice(["Order Processed", "Alert: High CPU", "User Registration", "Payment Confirmed", None])
        req_params = {"topicArn": topic_arn, "message": "HIDDEN_DUE_TO_SECURITY_REASONS"}
        if subject:
            req_params["subject"] = subject
        resp = {"publishResponse": {"publishResult": {"messageId": str(uuid.uuid4())}}}
        resources = [{"type": "AWS::SNS::Topic", "ARN": topic_arn, "accountId": account_id}]
    elif action == "GetTopicAttributes":
        req_params = {"topicArn": topic_arn}
        resp = None
        resources = [{"type": "AWS::SNS::Topic", "ARN": topic_arn, "accountId": account_id}]
    else:  # ListTopics
        req_params = None
        resp = None
        resources = []

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "sns.amazonaws.com", api_version="2010-03-31",
                            read_only=(action != "Publish"))
    event.update({"requestParameters": req_params, "responseElements": resp, "resources": resources})
    return [event]


def _generate_ecs_describe(config, context=None):
    """(Benign) Routine ECS describe/list operations — cluster and task monitoring."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    clusters = aws_conf.get('ecs_clusters', ['prod-api-cluster', 'prod-workers-cluster', 'staging-cluster'])
    cluster_name = random.choice(clusters)
    cluster_arn = f"arn:aws:ecs:{region}:{account_id}:cluster/{cluster_name}"

    action = random.choice(["ListClusters", "DescribeClusters", "ListTasks", "DescribeTasks", "ListServices"])

    if action == "DescribeClusters":
        req_params = {"clusters": [cluster_name]}
        resources = [{"type": "AWS::ECS::Cluster", "ARN": cluster_arn, "accountId": account_id}]
    elif action in ("ListTasks", "ListServices"):
        req_params = {"cluster": cluster_name, "maxResults": 100}
        resources = [{"type": "AWS::ECS::Cluster", "ARN": cluster_arn, "accountId": account_id}]
    elif action == "DescribeTasks":
        task_id = str(uuid.uuid4())
        task_arn = f"arn:aws:ecs:{region}:{account_id}:task/{cluster_name}/{task_id}"
        req_params = {"cluster": cluster_name, "tasks": [task_arn]}
        resources = [{"type": "AWS::ECS::Task", "ARN": task_arn, "accountId": account_id}]
    else:  # ListClusters
        req_params = {"maxResults": 100}
        resources = []

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "ecs.amazonaws.com", api_version="2014-11-13", read_only=True)
    event.update({"requestParameters": req_params, "responseElements": None, "resources": resources})
    return [event]


def _generate_acm_list(config, context=None):
    """(Benign) Routine ACM certificate operations — ListCertificates, DescribeCertificate, GetCertificate."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    # Generate realistic-looking cert UUIDs as defaults
    cert_ids = aws_conf.get('acm_certificate_ids', [
        'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        'b2c3d4e5-f6a7-8901-bcde-f01234567891',
        'c3d4e5f6-a7b8-9012-cdef-012345678902',
    ])
    cert_id = random.choice(cert_ids)
    cert_arn = f"arn:aws:acm:{region}:{account_id}:certificate/{cert_id}"

    action = random.choice(["ListCertificates", "DescribeCertificate", "GetCertificate"])

    if action == "ListCertificates":
        req_params = {"maxItems": 100, "includes": {"keyTypes": ["RSA_2048", "EC_prime256v1"]}}
        resources = []
    else:
        req_params = {"certificateArn": cert_arn}
        resources = [{"type": "AWS::ACM::Certificate", "ARN": cert_arn, "accountId": account_id}]

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "acm.amazonaws.com", api_version="2015-12-08", read_only=True)
    event.update({"requestParameters": req_params, "responseElements": None, "resources": resources})
    return [event]


def _generate_ssm_get_parameter_benign(config, context=None):
    """(Benign) Routine SSM GetParameter/GetParametersByPath for non-credential application config values."""
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=False)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    config_params = aws_conf.get('ssm_config_parameters', [
        '/app/db-host', '/app/redis-endpoint', '/app/feature-flags/enable-new-checkout',
        '/infra/vpc-id', '/infra/subnet-ids', '/app/log-level',
        '/app/max-connections', '/shared/environment',
    ])
    param_path = random.choice(config_params)
    param_arn = f"arn:aws:ssm:{region}:{account_id}:parameter{param_path}"

    if random.random() < 0.3:
        action = "GetParametersByPath"
        path_prefix = '/'.join(param_path.split('/')[:3])
        req_params = {"path": path_prefix, "recursive": False, "withDecryption": False}
        param_arn = f"arn:aws:ssm:{region}:{account_id}:parameter{path_prefix}"
    else:
        action = "GetParameter"
        req_params = {"name": param_path, "withDecryption": False}

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "ssm.amazonaws.com", api_version="2014-11-06", read_only=True)
    event.update({
        "requestParameters": req_params,
        "responseElements": None,
        "resources": [{"type": "AWS::SSM::Parameter", "ARN": param_arn, "accountId": account_id}],
    })
    return [event]


# ─── Additional threat generators ─────────────────────────────────────────────

def _generate_iam_passrole_abuse(config, context=None):
    """(Threat) Simulates IAM PassRole privilege escalation.

    iam:PassRole is an IAM permission, not a CloudTrail event — it has no standalone
    CloudTrail record. The real evidence of PassRole abuse appears in the downstream
    action that consumes the role: an attacker calls CreateFunction on a Lambda they
    control, supplying a high-privilege role ARN as the execution role. AWS internally
    checks iam:PassRole at this point. The attacker then immediately Invokes the function
    to execute actions under the privileged role.

    Returns two events:
      1. CreateFunction (lambda.amazonaws.com) — role ARN contains privileged role
      2. Invoke (lambda.amazonaws.com) — attacker exercises the stolen permissions

    Triggers XSIAM: Privilege escalation via Lambda PassRole / unexpected IAM role attachment.
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    privileged_roles = [
        "AdministratorRole", "PowerUserRole", "SecurityAuditRole",
        "OrganizationAccountAccessRole", "CloudFormationExecutionRole",
        "AWSReservedSSO_AdministratorAccess",
    ]
    target_role = random.choice(privileged_roles)
    target_role_arn = f"arn:aws:iam::{account_id}:role/{target_role}"

    # Attacker-chosen function name — looks innocuous
    func_suffixes = ["helper", "worker", "sync", "monitor", "updater", "processor"]
    func_name = f"svc-{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=4))}-{random.choice(func_suffixes)}"
    func_arn = f"arn:aws:lambda:{region}:{account_id}:function:{func_name}"
    now = datetime.datetime.now(datetime.UTC)

    # Event 1: CreateFunction — supplies privileged role via iam:PassRole
    create_event = _get_base_event(config, user_identity, ip_address, region,
                                   "CreateFunction20150331", "lambda.amazonaws.com",
                                   api_version="2015-03-31", read_only=False)
    create_event.update({
        "requestParameters": {
            "functionName": func_name,
            "runtime": random.choice(["python3.12", "nodejs20.x"]),
            "role": target_role_arn,   # ← iam:PassRole is checked here
            "handler": "index.handler",
            "code": {"zipFile": "HIDDEN_DUE_TO_SECURITY_REASONS"},
            "timeout": 300,
            "memorySize": 512,
        },
        "responseElements": {
            "functionName": func_name,
            "functionArn": func_arn,
            "runtime": "python3.12",
            "role": target_role_arn,
            "lastModified": now.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "codeSize": random.randint(1024, 65536),
            "state": "Active",
        },
        "resources": [
            {"type": "AWS::Lambda::Function", "ARN": func_arn, "accountId": account_id},
            {"type": "AWS::IAM::Role", "ARN": target_role_arn, "accountId": account_id},
        ],
    })

    # Event 2: Invoke — attacker immediately uses the function to act under the privileged role
    invoke_event = _get_base_event(config, user_identity, ip_address, region,
                                   "Invoke", "lambda.amazonaws.com",
                                   api_version="2015-03-31", read_only=False)
    invoke_event["eventTime"] = (now + datetime.timedelta(seconds=random.randint(3, 15))).strftime('%Y-%m-%dT%H:%M:%SZ')
    invoke_event.update({
        "requestParameters": {
            "functionName": func_name,
            "invocationType": "RequestResponse",
        },
        "responseElements": {
            "statusCode": 200,
            "executedVersion": "$LATEST",
        },
        "resources": [{"type": "AWS::Lambda::Function", "ARN": func_arn, "accountId": account_id}],
    })

    return [create_event, invoke_event]


def _generate_lambda_update_function_code(config, context=None):
    """(Threat) Simulates backdoor injection via Lambda UpdateFunctionCode.
    Attacker replaces a legitimate function's code via S3 object or inline zip to add persistence
    or data exfiltration while the function continues operating normally.
    Triggers XSIAM: Suspicious Lambda function code modification.
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    functions = aws_conf.get('lambda_functions', [
        'api-handler', 'auth-service', 'payment-processor', 'data-exporter', 'webhook-handler',
    ])
    function_name = random.choice(functions)
    function_arn = f"arn:aws:lambda:{region}:{account_id}:function:{function_name}"

    if random.random() < 0.6:
        req_params = {
            "functionName": function_name,
            "s3Bucket": f"deployment-artifacts-{account_id}",
            "s3Key": f"backdoor/{function_name}-{random.randint(1000,9999)}.zip",
            "publish": True,
        }
    else:
        req_params = {"functionName": function_name, "zipFile": "HIDDEN_DUE_TO_SECURITY_REASONS", "publish": True}

    event = _get_base_event(config, user_identity, ip_address, region,
                            "UpdateFunctionCode20150331v2", "lambda.amazonaws.com",
                            api_version="2015-03-31", read_only=False)
    event.update({
        "requestParameters": req_params,
        "responseElements": {
            "functionName": function_name,
            "functionArn": function_arn,
            "runtime": random.choice(["python3.12", "nodejs20.x", "java21"]),
            "codeSize": random.randint(100000, 5000000),
            "lastModified": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "codeSha256": ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=43)) + '=',
        },
        "resources": [{"type": "AWS::Lambda::Function", "ARN": function_arn, "accountId": account_id}],
    })
    return [event]


def _generate_macie_disabled(config, context=None):
    """(Threat) Simulates disabling Amazon Macie (S3 sensitive data discovery and classification).
    Completes defense evasion set: GuardDuty + Security Hub + Config + CloudTrail + WAF + Macie.
    Triggers XSIAM: Defense evasion — disabling data security monitoring.
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')

    event = _get_base_event(config, user_identity, ip_address, region,
                            "DisableMacie", "macie2.amazonaws.com",
                            api_version="2020-01-01", read_only=False)
    event.update({"requestParameters": None, "responseElements": None, "resources": []})
    return [event]


def _generate_inspector_disabled(config, context=None):
    """(Threat) Simulates disabling Amazon Inspector v2 (EC2/ECR/Lambda vulnerability scanning).
    Triggers XSIAM: Defense evasion — disabling vulnerability scanning.
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    event = _get_base_event(config, user_identity, ip_address, region,
                            "Disable", "inspector2.amazonaws.com",
                            api_version="2020-06-08", read_only=False)
    event.update({
        "requestParameters": {"accountIds": [account_id], "resourceTypes": ["ECR", "EC2", "LAMBDA"]},
        "responseElements": {
            "accounts": [{"accountId": account_id, "status": "DISABLING"}],
            "failedAccounts": [],
        },
        "resources": [],
    })
    return [event]


def _generate_organizations_recon(config, context=None):
    """(Threat) Simulates AWS Organizations reconnaissance — listing all accounts to map blast radius
    before lateral movement across the org.
    Triggers XSIAM: Unusual Organizations API access / account enumeration.
    Returns multiple events: DescribeOrganization + ListAccounts + ListOrganizationalUnitsForParent.
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = 'us-east-1'  # Organizations API is always us-east-1
    root_id = f"r-{''.join(random.choices('abcdef0123456789', k=4))}"

    events = []
    for action, req_params in [
        ("DescribeOrganization", None),
        ("ListAccounts", {"maxResults": 20}),
        ("ListOrganizationalUnitsForParent", {"parentId": root_id, "maxResults": 20}),
    ]:
        event = _get_base_event(config, user_identity, ip_address, region,
                                action, "organizations.amazonaws.com",
                                api_version="2016-11-28", read_only=True)
        event.update({"requestParameters": req_params, "responseElements": None, "resources": []})
        events.append(event)
    return events


def _generate_eventbridge_rule_deleted(config, context=None):
    """(Threat) Simulates deletion or disabling of an EventBridge rule targeting security automation.
    Attackers remove rules that trigger Lambda IR functions or SNS security alerts.
    Triggers XSIAM: Defense evasion — disabling automated incident response.
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    rules = aws_conf.get('eventbridge_rules', [
        'security-alert-rule', 'guardduty-finding-handler', 'config-compliance-notifier',
        'cloudtrail-anomaly-responder', 'scheduled-security-scan', 'incident-response-trigger',
    ])
    rule_name = random.choice(rules)
    rule_arn = f"arn:aws:events:{region}:{account_id}:rule/{rule_name}"
    action = random.choice(["DeleteRule", "DisableRule"])

    event = _get_base_event(config, user_identity, ip_address, region,
                            action, "events.amazonaws.com", api_version="2015-10-07", read_only=False)
    event.update({
        "requestParameters": {"name": rule_name, **({"force": True} if action == "DeleteRule" else {})},
        "responseElements": None,
        "resources": [{"type": "AWS::Events::Rule", "ARN": rule_arn, "accountId": account_id}],
    })
    return [event]


def _generate_glue_job_exfil(config, context=None):
    """(Threat) Simulates Glue ETL job creation targeting an external S3 bucket for data exfiltration.
    Attacker creates a job reading from internal data catalog tables and writing to an attacker-controlled
    S3 bucket — bypasses S3 direct-copy controls, harder to detect than GetObject calls.
    Triggers XSIAM: Unusual Glue job creation / data exfiltration via ETL.
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    glue_dbs = aws_conf.get('glue_database_names', ['prod_data_catalog', 'analytics_db', 'data_lake', 'customer_data'])
    source_db = random.choice(glue_dbs)
    external_bucket = f"exfil-staging-{random.randint(10000, 99999)}"
    job_name = f"data-sync-{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=6))}"
    job_arn = f"arn:aws:glue:{region}:{account_id}:job/{job_name}"

    event = _get_base_event(config, user_identity, ip_address, region,
                            "CreateJob", "glue.amazonaws.com", api_version="2017-03-31", read_only=False)
    event.update({
        "requestParameters": {
            "name": job_name,
            "role": f"arn:aws:iam::{account_id}:role/GlueServiceRole",
            "command": {
                "name": "glueetl",
                "scriptLocation": f"s3://aws-glue-scripts-{account_id}/scripts/{job_name}.py",
                "pythonVersion": "3",
            },
            "defaultArguments": {
                "--source_database": source_db,
                "--output_path": f"s3://{external_bucket}/data/",
                "--TempDir": f"s3://aws-glue-temporary-{account_id}/temp/",
            },
            "connections": {"connections": [f"{source_db}-connection"]},
            "maxRetries": 0,
            "workerType": "G.2X",
            "numberOfWorkers": random.randint(5, 20),
            "glueVersion": "4.0",
        },
        "responseElements": {"name": job_name},
        "resources": [{"type": "AWS::Glue::Job", "ARN": job_arn, "accountId": account_id}],
    })
    return [event]


def _generate_athena_query_exfil(config, context=None):
    """(Threat) Simulates Athena exfiltration — SELECT * against a sensitive table with results
    written to an external S3 output location controlled by the attacker.
    Triggers XSIAM: Unusual Athena query / data exfiltration via SQL.
    """
    user_identity = None
    ip_address = None
    if context:
        user_identity = context.get('user_identity')
        ip_address = context.get('ip_address')

    if not user_identity: user_identity = _get_random_user(config)
    if not ip_address: ip_address = _get_random_ip(config, force_external=True)

    aws_conf = config.get(CONFIG_KEY, {})
    region = aws_conf.get('aws_region', 'us-east-1')
    account_id = user_identity.get('accountId', aws_conf.get('aws_account_id', '123456789012'))

    glue_dbs = aws_conf.get('glue_database_names', ['prod_data_catalog', 'analytics_db', 'data_lake', 'customer_data'])
    workgroups = aws_conf.get('athena_workgroups', ['primary', 'analytics-wg', 'data-team'])
    source_db = random.choice(glue_dbs)
    workgroup = random.choice(workgroups)
    table_name = random.choice(['customers', 'users', 'payments', 'transactions', 'pii_data', 'health_records'])
    external_bucket = f"query-results-{random.randint(10000, 99999)}"
    execution_id = str(uuid.uuid4())

    event = _get_base_event(config, user_identity, ip_address, region,
                            "StartQueryExecution", "athena.amazonaws.com",
                            api_version="2017-05-18", read_only=False)
    event.update({
        "requestParameters": {
            "queryString": f"SELECT * FROM {source_db}.{table_name} LIMIT 1000000",
            "queryExecutionContext": {"database": source_db, "catalog": "AwsDataCatalog"},
            "resultConfiguration": {
                "outputLocation": f"s3://{external_bucket}/results/",
                "encryptionConfiguration": {"encryptionOption": "SSE_S3"},
            },
            "workGroup": workgroup,
            "clientRequestToken": execution_id,
        },
        "responseElements": {"queryExecutionId": execution_id},
        "resources": [],
    })
    return [event]


# --- Scenario-specific functions map ---
# Maps scenario_event strings to the corresponding function
SCENARIO_FUNCTIONS = {
    "TOR_LOGIN": _generate_login_from_tor,
    "PENTEST_LAUNCH": _generate_pentest_instance_launch,
    "DISABLE_GUARDDUTY": _generate_guardduty_detector_deleted,
    "STOP_CLOUDTRAIL": _generate_cloudtrail_stop_logging,
    "MAKE_S3_PUBLIC": _generate_s3_make_public,
    "DISABLE_S3_LOGGING": _generate_s3_disable_bucket_logging,
    "ATTACH_ADMIN_POLICY": _generate_iam_policy_change,
    "CREATE_SUSPICIOUS_USER": _generate_suspicious_iam_creation,
    "SSM_START_SESSION": _generate_ssm_start_session,
    "SSM_SEND_COMMAND": _generate_ssm_send_command,
    "SSM_EXECUTION_CHAIN": _generate_ssm_execution_chain,
    "RDS_SHARE_SNAPSHOT": _generate_rds_modify_db_snapshot_attribute,
    "LAMBDA_ROLE_REMOTE": _generate_lambda_role_remote_usage,
    "S3_RANSOMWARE_ENCRYPT": _generate_s3_ransomware_encrypt,
    "BEDROCK_DELETE_LOGGING": _generate_bedrock_delete_model_invocation_logging,
    "CROSS_ACCOUNT_ASSUME_ROLE": _generate_cross_account_assume_role,
    "DISABLE_SECURITY_HUB": _generate_security_hub_disabled,
    "STOP_CONFIG_RECORDER": _generate_config_recorder_stopped,
    "DELETE_WAF_RULE": _generate_waf_rule_deleted,
    # Bedrock / SageMaker XSIAM detector scenarios
    "KB_MODIFICATION": _generate_bedrock_kb_modification,
    "BEDROCK_RAG_KB_MODIFICATION": _generate_bedrock_kb_modification,
    "CREDENTIAL_FILE_ACCESS": _generate_credential_file_access,
    "BEDROCK_GUARDRAIL_DELETED": _generate_bedrock_guardrail_deleted,
    "BEDROCK_DENIAL_OF_WALLET": _generate_bedrock_denial_of_wallet,
    "SAGEMAKER_DATASET_MODIFICATION": _generate_sagemaker_dataset_modification,
    "SAGEMAKER_LABEL_MODIFICATION": _generate_sagemaker_label_modification,
    "BEDROCK_UNUSUAL_MODEL_ACCESS": _generate_bedrock_unusual_model_access,
    "BEDROCK_TOR_USAGE": _generate_bedrock_tor_model_usage,
    # Additional threat scenarios
    "IAM_PASSROLE": _generate_iam_passrole_abuse,
    "LAMBDA_UPDATE_CODE": _generate_lambda_update_function_code,
    "DISABLE_MACIE": _generate_macie_disabled,
    "DISABLE_INSPECTOR": _generate_inspector_disabled,
    "ORGANIZATIONS_RECON": _generate_organizations_recon,
    "EVENTBRIDGE_RULE_DELETED": _generate_eventbridge_rule_deleted,
    "GLUE_JOB_EXFIL": _generate_glue_job_exfil,
    "ATHENA_QUERY_EXFIL": _generate_athena_query_exfil,
}


def get_threat_names():
    """Return available threat names dynamically from SCENARIO_FUNCTIONS.
    Adding a new entry to SCENARIO_FUNCTIONS automatically surfaces it here."""
    return list(SCENARIO_FUNCTIONS.keys())


# --- Categorized Scenario Dictionaries (Weights used for random mode) ---

BENIGN_SCENARIOS = {
    # Read Ops - Higher weights for common reads
    _generate_s3_get_object: 20,
    _generate_ec2_describe_instances: 15,
    _generate_s3_list_buckets: 10,
    _generate_cloudtrail_describe_trails: 5,
    _generate_iam_list_roles: 8,
    _generate_iam_list_users: 8,
    _generate_ec2_describe_vpcs: 8,
    _generate_ec2_describe_subnets: 8,
    _generate_ec2_describe_security_groups: 8,
    _generate_ec2_describe_route_tables: 5,
    _generate_ec2_describe_network_acls: 5,
    _generate_iam_get_user: 6,
    _generate_iam_list_policies: 6,
    _generate_s3_head_bucket: 7,
    _generate_cloudwatch_describe_log_groups: 5,
    _generate_cloudwatch_get_log_events: 4,
    _generate_route53_list_hosted_zones: 4,
    _generate_route53_list_resource_record_sets: 4,
    _generate_elb_describe_load_balancers: 4,
    _generate_elb_describe_target_groups: 4,
    _generate_rds_describe_db_instances: 4,
    _generate_rds_describe_db_snapshots: 4,
    _generate_ecr_describe_repositories: 3,
    _generate_lambda_list_functions: 3,
    _generate_sts_get_caller_identity: 5,
    _generate_eks_describe_cluster: 3,
    _generate_eks_list_clusters: 3,
    _generate_cloudformation_describe_stacks: 4,
    _generate_ec2_describe_key_pairs: 3,
    _generate_ec2_describe_snapshots: 3,
    _generate_ec2_describe_volumes: 3,
    _generate_s3_get_bucket_policy: 3,
    _generate_iam_get_role: 3,
    _generate_rds_download_db_log_file: 2,

    # Write/Lifecycle Ops - Lower weights for less frequent operations
    _generate_ec2_run_instances: 5,
    _generate_s3_put_object: 15,
    _generate_ec2_stop_instances: 4,
    _generate_s3_create_bucket: 2,
    _generate_s3_delete_bucket: 2,
    _generate_cloudformation_create_stack: 2,
    _generate_cloudformation_delete_stack: 2,
    _generate_lambda_invoke: 6,
    _generate_ecr_create_delete_repo: 2,
    _generate_lambda_create_function: 3,
    _generate_iam_create_role: 3,
    _generate_rds_restore_from_snapshot: 1,
    _generate_ec2_create_snapshot: 2,
    _generate_ec2_create_key_pair: 1,
    _generate_ec2_delete_key_pair: 1,

    # Bedrock / SageMaker / Secrets Manager benign ops
    _generate_bedrock_invoke_model: 8,         # High weight — routine AI workload
    _generate_bedrock_list_foundation_models: 4,
    _generate_bedrock_retrieve: 5,             # RAG queries are frequent in AI apps
    _generate_sagemaker_list_training_jobs: 3,
    _generate_secretsmanager_get_secret: 5,    # Routine app secret reads

    # Additional benign ops — DynamoDB, messaging, containers, certs, SSM config
    _generate_dynamodb_read: 12,               # DynamoDB is one of the highest-volume services
    _generate_dynamodb_write: 10,
    _generate_sts_assume_role_benign: 8,       # Constant in CI/CD and cross-service automation
    _generate_sqs_operations: 6,
    _generate_sns_operations: 5,
    _generate_ecs_describe: 4,
    _generate_acm_list: 3,
    _generate_ssm_get_parameter_benign: 6,     # Apps read config params constantly
}

SUSPICIOUS_SCENARIOS = {
    # Events that are context-dependent (could be admin work or malicious)
    _generate_lambda_create_function_unusual_runtime: 1,
    _generate_ebs_detach_volume: 1,
    _generate_ec2_modify_user_data: 2, # Often suspicious
    _generate_ec2_export_to_s3: 1,
    _generate_iam_remove_billing_admin: 1,
    _generate_vpc_create_flow_log: 0.5, # Very low weight, mostly benign
    _generate_ec2_modify_route_table: 1,
    _generate_iam_create_access_key: 2, # Can be normal, but also for persistence
    _generate_iam_recon_list: 1, # Multiple events, so lower weight
    _generate_s3_set_replication: 1,
}

THREAT_SCENARIOS = {
    # Events that are almost always high-priority/malicious
    _generate_multiple_denied_actions: 3,
    _generate_login_from_tor: 2,
    _generate_iam_policy_change: 1, # Includes self-escalation
    _generate_security_group_modified: 3, # Opening to 0.0.0.0 is significant
    _generate_kms_key_disabled: 2,
    _generate_root_user_activity: 1, # Should be rare
    _generate_trail_deleted: 2,
    _generate_multiple_deletes: 2,
    _generate_suspicious_iam_creation: 2,
    _generate_cloudtrail_stop_logging: 2,
    _generate_s3_suspicious_encryption: 1,
    _generate_k8s_sa_outside_cluster: 1,
    _generate_guardduty_detector_deleted: 2,
    _generate_pentest_instance_launch: 1,
    _generate_api_call_with_pentest_ua: 1,
    _generate_ec2_instance_type_change: 1,
    _generate_s3_copy_to_foreign_account: 1,
    _generate_s3_disable_bucket_logging: 2,
    _generate_api_call_from_tor: 1, # Lower weight than console login from tor
    _generate_cloudwatch_delete_log_stream: 1,
    _generate_s3_make_public: 2,
    _generate_iam_delete_mfa_device: 2,
    _generate_ec2_create_and_share_snapshot: 1, # Multiple events
    _generate_iam_update_login_profile: 2,
    _generate_s3_make_public_acl: 2,
    # XSIAM built-in detector scenarios
    _generate_ssm_start_session: 2,
    _generate_ssm_send_command: 2,
    _generate_ssm_execution_chain: 2,
    _generate_rds_modify_db_snapshot_attribute: 2,
    _generate_lambda_role_remote_usage: 2,
    _generate_s3_ransomware_encrypt: 2,
    _generate_bedrock_delete_model_invocation_logging: 2,
    # Defense evasion triad + cross-account lateral movement
    _generate_cross_account_assume_role: 2,
    _generate_security_hub_disabled: 2,
    _generate_config_recorder_stopped: 2,
    _generate_waf_rule_deleted: 2,
    # Bedrock / SageMaker XSIAM detector scenarios
    _generate_bedrock_kb_modification: 2,
    _generate_credential_file_access: 2,
    _generate_bedrock_guardrail_deleted: 2,
    _generate_bedrock_denial_of_wallet: 2,
    _generate_sagemaker_dataset_modification: 2,
    _generate_sagemaker_label_modification: 2,
    _generate_bedrock_unusual_model_access: 2,
    _generate_bedrock_tor_model_usage: 2,
    # Additional threat scenarios
    _generate_iam_passrole_abuse: 2,
    _generate_lambda_update_function_code: 2,
    _generate_macie_disabled: 2,
    _generate_inspector_disabled: 2,
    _generate_organizations_recon: 2,
    _generate_eventbridge_rule_deleted: 2,
    _generate_glue_job_exfil: 2,
    _generate_athena_query_exfil: 2,
}


# --- Main Module Function ---

def generate_log(config, context=None, threat_level="Benign", benign_only=False, scenario_event=None):
    """
    Patched generate_log with:
      - support for 'insane' level (combine all pools),
      - retry logic to avoid silent None returns,
      - normalization of weights,
      - event validation and defaults,
      - logging instead of prints.
    """
    # These imports are needed here
    import random, io, gzip, json, logging, traceback, time, datetime 
    
    # Extract session context — if provided, enrich IAM user pool with linked users
    session_context = (context or {}).get('session_context')
    if session_context and 'aws_config' in config:
        _linked_iam = [
            {"type": "IAMUser", "name": p.get('aws_iam_user'),
             "arn_suffix": f"user/{p.get('aws_iam_user')}"}
            for p in session_context.values()
            if p.get('aws_iam_user')
        ]
        if _linked_iam:
            existing = {u['name'] for u in config['aws_config'].get('users_and_roles', [])}
            for u in _linked_iam:
                if u['name'] not in existing:
                    config['aws_config'].setdefault('users_and_roles', []).append(u)

    logger = logging.getLogger('simulator.aws')
    logger.debug("generate_log called with threat_level=%s", threat_level)
    
    # Add this global declaration to modify the module-level variable
    global last_threat_event_time 

    events = None # Initialize events variable
    chosen_func = None # Initialize chosen_func

    # --- Handle scenario_event first ---
    if scenario_event:
        if scenario_event in SCENARIO_FUNCTIONS:
            logger.info("Generating scenario event: %s", scenario_event)
            try:
                # Directly call the scenario function
                result = SCENARIO_FUNCTIONS[scenario_event](config, context)
                if isinstance(result, list) and result:
                    events = result
                elif result: # Handle single event dict
                    events = [result]
                chosen_func = SCENARIO_FUNCTIONS[scenario_event] # Track for naming
            except Exception as e:
                logger.exception("Exception while running scenario generator %s: %s", scenario_event, e)
                return None # Exit if scenario function fails
        else:
            logger.warning("Unknown scenario_event: %s", scenario_event)
            return None
        
        if not events:
            logger.warning("Scenario generator %s returned no events.", scenario_event)
            return None # Exit if scenario returns no events
    # --- END SCENARIO BLOCK ---
    else:
        # --- START NORMAL (NON-SCENARIO) LOGIC ---
        # Normalize context to avoid errors
        if context is None:
            context = {}
        context.setdefault('user_identity', None)
        context.setdefault('target_user', None)
        context.setdefault('ip_address', None)
        context.setdefault('aws_region', None)

        # Choose pool based on threat level
        pool_name = "Benign" # For logging

        if benign_only:
            pool_to_use = BENIGN_SCENARIOS
            pool_name = "Benign (Forced)"
        elif threat_level == "Insane":
            # Combine all pools for Insane mode, summing weights for duplicates
            merged = {}
            for pool in (BENIGN_SCENARIOS, SUSPICIOUS_SCENARIOS, THREAT_SCENARIOS):
                for fn, w in pool.items():
                    merged[fn] = merged.get(fn, 0) + w
            pool_to_use = merged
            pool_name = "Insane (Combined)"
        else:
            # Time-based logic for Realistic, Elevated, etc.
            interval = _get_threat_interval(threat_level, config)
            current_time = time.time()

            if interval > 0 and (current_time - last_threat_event_time) > interval:
                # Time for a non-benign event
                last_threat_event_time = current_time
                # Combine suspicious and threat pools, summing weights for duplicates
                merged = {}
                for pool in (SUSPICIOUS_SCENARIOS, THREAT_SCENARIOS):
                    for fn, w in pool.items():
                        merged[fn] = merged.get(fn, 0) + w
                pool_to_use = merged
                pool_name = f"{threat_level} (Suspicious/Threat)"
            else:
                # Default to benign
                pool_to_use = BENIGN_SCENARIOS
                pool_name = f"{threat_level} (Benign)"

        if not pool_to_use:
            logger.warning("No scenarios available for selection: %s", pool_name)
            return None # Exit if no pool

        # Select the function using weights
        scenario_funcs = list(pool_to_use.keys())
        raw_weights = list(pool_to_use.values())
        norm_weights = [max(0.1, float(w)) for w in raw_weights] # Ensure positive weights

        # Try a few times to get a working function
        attempts = 5
        for i in range(attempts):
            chosen_func = random.choices(scenario_funcs, weights=norm_weights, k=1)[0]
            logger.debug("Attempt %d: Selected generator from %s pool: %s", i + 1, pool_name, getattr(chosen_func, "__name__", str(chosen_func)))
            
            try:
                result = chosen_func(config, context)
                if isinstance(result, list) and result:
                    events = result
                    break # Success! Exit the loop
                elif result: # Handle functions returning single event dict
                    events = [result]
                    break # Success! Exit the loop
                else:
                    logger.warning("Generator %s returned no events on attempt %d.", getattr(chosen_func, "__name__", str(chosen_func)), i + 1)
            except Exception as e:
                logger.exception("Exception while running generator %s on attempt %d: %s", getattr(chosen_func, "__name__", str(chosen_func)), i + 1, e)
                events = None # Ensure events is None if function fails
            
            # If loop finishes without break, events will be None or empty
        # --- END NORMAL (NON-SCENARIO) LOGIC ---

    # --- COMMON PROCESSING FOR BOTH SCENARIO AND NORMAL ---
    if not events:
        logger.warning("Failed to generate events after attempts (or scenario failed).")
        return None

    # Determine event name for return tuple — use scenario key if available
    _func_to_key = {fn: k for k, fn in SCENARIO_FUNCTIONS.items()}
    event_name_for_return = scenario_event if scenario_event else _func_to_key.get(chosen_func, getattr(chosen_func, "__name__", "unknown_generator"))

    logger.info("Generated events from: %s (count=%d)", event_name_for_return, len(events))

    # --- Inline validation function ---
    def _validate_event(evt, cfg, ctx):
        if not isinstance(evt, dict):
            return evt
        cfg = cfg if isinstance(cfg, dict) else {}
        ctx = ctx if isinstance(ctx, dict) else {}

        defaults = {
            "eventVersion": "1.11",
            "eventTime": datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "eventSource": evt.get("eventSource") or "aws.unknown",
            "eventName": evt.get("eventName") or evt.get("name") or "UnknownAction",
            "awsRegion": evt.get("awsRegion") or ctx.get("aws_region") or "us-east-1",
            "sourceIPAddress": evt.get("sourceIPAddress") or ctx.get("ip_address") or "0.0.0.0",
            "userAgent": evt.get("userAgent") or "aws-cli/2.15.30 Python/3.11.8 Linux/5.15.0-113-generic exe/x86_64 prompt/off",
            "userIdentity": evt.get("userIdentity") or {"type": "Unknown"},
            "requestParameters": evt.get("requestParameters") if evt.get("requestParameters") is not None else None,
            "responseElements": evt.get("responseElements") if evt.get("responseElements") is not None else None,
            "recipientAccountId": evt.get("recipientAccountId") or cfg.get('aws_config', {}).get('aws_account_id', '123456789012')
        }
        for k, v in defaults.items():
            if k not in evt or evt.get(k) is None:
                evt[k] = v
        if not isinstance(evt.get("eventTime"), str):
            evt["eventTime"] = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
        return evt
    # --- End _validate_event ---

    try:
        validated_events = [_validate_event(e, config, context) for e in events]
    except Exception as e:
        logger.exception("Error during event validation: %s", e)
        return None

    # Serialize + gzip
    log_file_content = {"Records": validated_events}
    try:
        json_str = json.dumps(log_file_content)
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=out, mode='w') as gz:
            gz.write(json_str.encode('utf-8'))
        gzipped_content = out.getvalue()
        logger.debug("Generated %d events (%d bytes gzipped)", len(validated_events), len(gzipped_content))
        
        # This is the final return
        return gzipped_content, event_name_for_return
    
    except Exception as e:
        logger.exception("Error during JSON serialization or Gzipping: %s", e)
        return None