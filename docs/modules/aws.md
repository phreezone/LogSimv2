# AWS CloudTrail Module

**Dataset:** `amazon_aws_raw`
**Transport:** AWS S3 (gzip-compressed JSON PUT)
**Format:** CloudTrail JSON array (schema 1.08), gzip-compressed, wrapped in `{"Records":[...]}` envelope

Simulates AWS CloudTrail management and data events for the XSIAM `amazon_aws_raw` dataset. The `AWSCloudTrail.xif` XIF pack filters on `_log_type = "Cloud Audit Log"` and maps `Records[]` array elements to XDM. Each simulated log file is written to S3 using the real CloudTrail path structure (`AWSLogs/<accountId>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/<accountId>_CloudTrail_<region>_<timestamp>_<uuid>.json.gz`), so the XSIAM S3 SQS-based collector picks it up identically to a live CloudTrail stream.

- **Schema:** CloudTrail 1.08 (functionally equivalent to 1.11 for all XDM-mapped fields)
- **Identity types:** `IAMUser`, `AssumedRole`, `Role`, `Root` — drawn from `aws_config.users_and_roles`
- **XIF:** `AWSCloudTrail.xif` — dataset filter `_log_type = "Cloud Audit Log"`

---

## Benign Events

Normal operational traffic establishing a clean baseline across all major AWS service areas.

### Compute & Containers

| Service | Events Generated |
|---|---|
| **EC2** | DescribeInstances, DescribeVPCs, DescribeSubnets, DescribeSecurityGroups, DescribeRouteTables, DescribeNetworkACLs, DescribeKeyPairs, DescribeSnapshots, DescribeVolumes, RunInstances, StopInstances, CreateSnapshot, CreateKeyPair, DeleteKeyPair |
| **ECS** | ListClusters, DescribeClusters, ListTasks, DescribeTasks, ListServices |
| **EKS** | ListClusters, DescribeCluster |
| **ECR** | DescribeRepositories, CreateRepository, DeleteRepository |
| **Lambda** | ListFunctions, Invoke, CreateFunction |

### Storage

| Service | Events Generated |
|---|---|
| **S3** | GetObject, ListBuckets, HeadBucket, GetBucketPolicy, PutObject, CreateBucket, DeleteBucket |

### Database & Analytics

| Service | Events Generated |
|---|---|
| **DynamoDB** | GetItem, Query, Scan, DescribeTable, ListTables, PutItem, UpdateItem, DeleteItem |
| **RDS** | DescribeDBInstances, DescribeDBSnapshots, DownloadDBLogFile, RestoreFromSnapshot |
| **Athena** | *(write path — see benign note below)* |

### Messaging & Eventing

| Service | Events Generated |
|---|---|
| **SQS** | SendMessage, ReceiveMessage, GetQueueAttributes, ListQueues |
| **SNS** | Publish, ListTopics, GetTopicAttributes |

### Identity & Access

| Service | Events Generated |
|---|---|
| **IAM** | ListRoles, ListUsers, GetUser, ListPolicies, GetRole, CreateRole |
| **STS** | GetCallerIdentity, AssumeRole (same-account, routine service automation) |

### Networking & Infrastructure

| Service | Events Generated |
|---|---|
| **ELB** | DescribeLoadBalancers, DescribeTargetGroups |
| **Route53** | ListHostedZones, ListResourceRecordSets |
| **CloudFormation** | DescribeStacks, CreateStack, DeleteStack |
| **VPC** | CreateFlowLog (low weight — also appears in Suspicious) |

### Security & Observability

| Service | Events Generated |
|---|---|
| **CloudTrail** | DescribeTrails |
| **CloudWatch** | DescribeLogGroups, GetLogEvents |
| **SSM** | GetParameter, GetParametersByPath (non-credential config paths) |
| **Secrets Manager** | GetSecretValue (non-credential app secrets: DB passwords, API keys) |
| **ACM** | ListCertificates, DescribeCertificate, GetCertificate |

### AI & ML

| Service | Events Generated |
|---|---|
| **Bedrock Runtime** | InvokeModel, InvokeModelWithResponseStream (routine AI usage) |
| **Bedrock** | ListFoundationModels |
| **Bedrock Agent Runtime** | Retrieve, RetrieveAndGenerate (RAG queries) |
| **SageMaker** | ListTrainingJobs, DescribeTrainingJob, ListModels, DescribeModel |

---

## Suspicious Events

Context-dependent events that are common in legitimate admin workflows but also appear in attacker playbooks. Included in Insane mode and generate lower-confidence alerts.

| Event | Signal |
|---|---|
| Lambda CreateFunction (unusual runtime) | Old/EOL runtime can indicate evasion or supply-chain staging |
| EBS DetachVolume | Disk detachment outside maintenance windows |
| EC2 ModifyInstanceAttribute (UserData) | Arbitrary code execution on next reboot |
| EC2 ExportToS3 | VM image export — could be legitimate DR or data theft |
| IAM RemoveBillingAdmin | Removing billing visibility — precedes financial abuse |
| EC2 ModifyRouteTable | Route manipulation — legitimate infra change or traffic interception |
| IAM CreateAccessKey | Credential provisioning — legitimate automation or persistence |
| IAM Recon (multi-event list) | Bulk list of users/roles/policies from one identity |
| S3 SetReplication | Cross-region replication — DR or exfiltration |

---

## Threat Scenarios

### Reconnaissance

* **`ORGANIZATIONS_RECON`** — Three-event burst: `DescribeOrganization` + `ListAccounts` + `ListOrganizationalUnitsForParent` via `organizations.amazonaws.com`. Attacker maps all accounts in the AWS Organization to identify high-value targets before lateral movement. *Signal: first-time or unusual Organizations API access from a non-management identity.*

### Identity & Privilege Escalation

* **`ATTACH_ADMIN_POLICY`** — `AttachUserPolicy` or `AttachRolePolicy` adding `AdministratorAccess` or a custom admin policy to an identity. Covers both self-escalation and third-party escalation.
* **`CREATE_SUSPICIOUS_USER`** — Creates an IAM user with a suspicious naming pattern, adds them to admin groups, and generates programmatic access keys in sequence.
* **`IAM_PASSROLE`** — `iam:PassRole` attaching a high-privilege role (e.g., `AdministratorRole`, `CloudFormationExecutionRole`) to a Lambda function or EC2 instance the attacker controls. No direct policy attachment needed — the compute resource runs as admin. *Signal: PassRole with a privileged target role from an unexpected identity.*
* **`IAM_UPDATE_LOGIN_PROFILE`** — `UpdateLoginProfile` resetting another user's console password — account takeover without creating new credentials.
* **`IAM_DELETE_MFA`** — `DeleteVirtualMFADevice` or `DeactivateMFADevice` removing MFA from an account to enable password-only access.
* **`CROSS_ACCOUNT_ASSUME_ROLE`** — `sts:AssumeRole` where the calling `userIdentity.accountId` differs from `recipientAccountId` — cross-account trust boundary traversal. *Signal: unexpected account ID in the caller identity.*

### Persistence

* **`TOR_LOGIN`** — Successful `ConsoleLogin` event from a known Tor exit node IP.
* **`API_CALL_FROM_TOR`** — Read API call (`ListUsers`) from a Tor exit node via an AssumedRole identity — lower confidence than console login.
* **`LAMBDA_UPDATE_CODE`** — `UpdateFunctionCode20150331v2` replacing a live function's deployment package via S3 or inline zip. Attacker injects a backdoor into an existing function that continues operating normally. *Signal: code update from an unusual identity or external IP.*
* **`LAMBDA_ROLE_REMOTE`** — Lambda execution using a remote or cross-account role — function running with an identity it was not originally configured with.
* **`IAM_CREATE_ACCESS_KEY`** — Programmatic access key creation for an existing user (also in Suspicious pool).

### Defense Evasion

* **`STOP_CLOUDTRAIL`** — `StopLogging` on a CloudTrail trail — disables audit logging.
* **`DISABLE_GUARDDUTY`** — `DeleteDetector` on a GuardDuty detector — removes threat detection.
* **`DISABLE_SECURITY_HUB`** — `DisableSecurityHub` — suppresses GuardDuty/Config/Inspector finding aggregation.
* **`STOP_CONFIG_RECORDER`** — `StopConfigurationRecorder` — halts AWS Config change tracking.
* **`DELETE_WAF_RULE`** — `DeleteWebACL` or `DeleteIPSet` via `wafv2.amazonaws.com` — removes perimeter filtering.
* **`DISABLE_MACIE`** — `DisableMacie` — stops S3 sensitive data discovery and classification scanning.
* **`DISABLE_INSPECTOR`** — `inspector2:Disable` for EC2, ECR, and Lambda — removes vulnerability scanning.
* **`BEDROCK_DELETE_LOGGING`** — `DeleteModelInvocationLoggingConfiguration` — removes the AI audit trail for all Bedrock model calls.
* **`EVENTBRIDGE_RULE_DELETED`** — `DeleteRule` or `DisableRule` on an EventBridge rule tied to security automation (GuardDuty finding handlers, scheduled scans, IR triggers). *Signal: security-named rule deleted or disabled.*

### Data Exfiltration — Storage

* **`MAKE_S3_PUBLIC`** — `PutBucketPolicy` setting a bucket policy that grants `s3:GetObject` to `*` (anonymous read).
* **`MAKE_S3_PUBLIC_ACL`** — `PutBucketAcl` or `PutObjectAcl` setting `public-read` or `public-read-write` via legacy ACL.
* **`S3_COPY_TO_FOREIGN_ACCOUNT`** — `CopyObject` with a destination bucket in a different AWS account ID.
* **`S3_SUSPICIOUS_ENCRYPTION`** — Overwrites S3 objects using a customer-managed KMS key from an external/attacker account — data becomes unreadable to the bucket owner (pseudo-ransomware).
* **`EC2_CREATE_SHARE_SNAPSHOT`** — Creates an EC2 EBS snapshot then modifies its attribute to share it with a foreign account ID — data exfiltration via snapshot copy.
* **`RDS_SHARE_SNAPSHOT`** — `ModifyDBSnapshotAttribute` sharing an RDS snapshot with a foreign account.
* **`GLUE_JOB_EXFIL`** — `glue:CreateJob` defining an ETL job that reads from an internal Glue data catalog database and writes output to an attacker-controlled S3 bucket. Bypasses S3 direct-copy detection; harder to attribute. *Signal: new Glue job with an external output path.*
* **`ATHENA_QUERY_EXFIL`** — `athena:StartQueryExecution` running `SELECT * FROM <sensitive_table> LIMIT 1000000` with results written to an external S3 output location. *Signal: large full-table query with non-standard output bucket.*

### Data Destruction

* **`MULTIPLE_DELETES`** — Rapid sequence of S3 DeleteObject and EC2/RDS resource deletion calls — ransomware or wiper pattern.
* **`TRAIL_DELETED`** — `DeleteTrail` permanently removing a CloudTrail trail.
* **`CLOUDWATCH_DELETE_LOG_STREAM`** — `DeleteLogStream` removing CloudWatch Logs streams — destroying audit evidence.
* **`KMS_KEY_DISABLED`** — `DisableKey` on a KMS CMK — renders all data encrypted with it inaccessible.

### Lateral Movement & Compute Abuse

* **`PENTEST_LAUNCH`** — `RunInstances` launching an EC2 instance from a known pentest AMI (Kali, Parrot, BlackArch, etc.).
* **`API_CALL_WITH_PENTEST_UA`** — Any API call carrying a pentest tool User-Agent (`nmap`, `sqlmap`, `Nikto`, `Burp`, etc.) in the `userAgent` field.
* **`EC2_INSTANCE_TYPE_CHANGE`** — `ModifyInstanceAttribute` changing an instance to a large GPU or compute-intensive type — cryptomining staging.
* **`LAMBDA_CREATE_FUNCTION_UNUSUAL_RUNTIME`** — Lambda function created with a deprecated or atypical runtime (Python 3.6, Node 10, Java 8, `provided`) — evasion or legacy exploit delivery.
* **`EC2_MODIFY_USER_DATA`** — `ModifyInstanceAttribute` changing the UserData script — arbitrary code execution on next reboot.
* **`K8S_SA_OUTSIDE_CLUSTER`** — EKS service account token used from a non-cluster IP — credential theft / token exfiltration.

### AI / ML Threats

* **`BEDROCK_DENIAL_OF_WALLET`** — Burst of 20–50 `bedrock-runtime:InvokeModel` calls against a single expensive model in rapid succession. *Signal: sudden spike in model invocations from one identity.*
* **`BEDROCK_UNUSUAL_MODEL_ACCESS`** — `InvokeModel` or `InvokeModelWithResponseStream` by an identity that does not normally call Bedrock, or calling an unusually expensive model. *Signal: first-time or out-of-baseline Bedrock access.*
* **`BEDROCK_TOR_USAGE`** — `bedrock-runtime:InvokeModel` from a Tor exit node IP. *Signal: anonymous LLM access.*
* **`BEDROCK_DELETE_LOGGING`** — See Defense Evasion above.
* **`BEDROCK_GUARDRAIL_DELETED`** — `bedrock:DeleteGuardrail` removing an AI safety guardrail. *Signal: AI safeguard removal.*
* **`KB_MODIFICATION`** / **`BEDROCK_RAG_KB_MODIFICATION`** — `bedrock-agent:UpdateKnowledgeBase`, `IngestKnowledgeBaseDocuments`, `AssociateAgentKnowledgeBase`, or `DeleteKnowledgeBase` by an identity not normally associated with knowledge base administration. *Signal: RAG corpus tampering.*
* **`SAGEMAKER_DATASET_MODIFICATION`** — `sagemaker:UpdateFeatureGroup`, `DeleteFeatureGroup`, or `UpdateFeatureMetadata` modifying a Feature Store feature group used for model training. *Signal: ML training data poisoning.*
* **`SAGEMAKER_LABEL_MODIFICATION`** — `sagemaker:CreateLabelingJob` re-labeling an existing Ground Truth dataset with a new job — label poisoning attack on supervised learning data. *Signal: unexpected labeling job on an established dataset.*
* **`CREDENTIAL_FILE_ACCESS`** — `secretsmanager:GetSecretValue` or `ssm:GetParameter` accessing a secret/parameter whose path contains sensitive naming patterns (`/credentials/`, `/aws/access-key`, `/aws/secret-access-key`). *Signal: accessing cloud credential material from an unusual identity.*

### SSM / Remote Execution

* **`SSM_START_SESSION`** — `ssm:StartSession` opening an interactive Session Manager shell to an EC2 instance. *Signal: interactive shell to production instance without change ticket.*
* **`SSM_SEND_COMMAND`** — `ssm:SendCommand` executing `AWS-RunShellScript` or `AWS-RunPowerShellScript` on a target instance. Parameters are redacted in CloudTrail but the document name is visible. *Signal: remote command execution.*

### Bedrock / SageMaker (additional)

* **`BEDROCK_DENIAL_OF_WALLET`** — See AI/ML Threats above.

---

## SCENARIO_FUNCTIONS Reference

The following scenario keys can be passed as `scenario_event` in coordinated simulator scenarios:

| Key | Generator | Trigger |
|---|---|---|
| `TOR_LOGIN` | ConsoleLogin from Tor IP | Identity attacks |
| `PENTEST_LAUNCH` | RunInstances with pentest AMI | Compute abuse |
| `DISABLE_GUARDDUTY` | DeleteDetector | Defense evasion |
| `STOP_CLOUDTRAIL` | StopLogging | Defense evasion |
| `MAKE_S3_PUBLIC` | PutBucketPolicy (public) | Data exposure |
| `DISABLE_S3_LOGGING` | PutBucketLogging (disabled) | Defense evasion |
| `ATTACH_ADMIN_POLICY` | AttachUserPolicy/AttachRolePolicy | Privilege escalation |
| `CREATE_SUSPICIOUS_USER` | CreateUser + AddUserToGroup + CreateAccessKey | Persistence |
| `SSM_START_SESSION` | StartSession | Remote access |
| `SSM_SEND_COMMAND` | SendCommand | Remote execution |
| `RDS_SHARE_SNAPSHOT` | ModifyDBSnapshotAttribute | Data exfiltration |
| `LAMBDA_ROLE_REMOTE` | Lambda invocation with remote role | Lateral movement |
| `BEDROCK_DELETE_LOGGING` | DeleteModelInvocationLoggingConfiguration | Defense evasion |
| `CROSS_ACCOUNT_ASSUME_ROLE` | AssumeRole (cross-account) | Lateral movement |
| `DISABLE_SECURITY_HUB` | DisableSecurityHub | Defense evasion |
| `STOP_CONFIG_RECORDER` | StopConfigurationRecorder | Defense evasion |
| `DELETE_WAF_RULE` | DeleteWebACL / DeleteIPSet | Defense evasion |
| `KB_MODIFICATION` | bedrock-agent KB write ops | AI tampering |
| `BEDROCK_RAG_KB_MODIFICATION` | bedrock-agent KB write ops | AI tampering |
| `CREDENTIAL_FILE_ACCESS` | GetSecretValue / GetParameter (credential path) | Credential theft |
| `BEDROCK_GUARDRAIL_DELETED` | DeleteGuardrail | AI safeguard removal |
| `BEDROCK_DENIAL_OF_WALLET` | InvokeModel ×20–50 burst | DoW attack |
| `SAGEMAKER_DATASET_MODIFICATION` | UpdateFeatureGroup / DeleteFeatureGroup | ML data poisoning |
| `SAGEMAKER_LABEL_MODIFICATION` | CreateLabelingJob (re-label) | Label poisoning |
| `BEDROCK_UNUSUAL_MODEL_ACCESS` | InvokeModel / InvokeModelWithResponseStream | Unusual AI access |
| `BEDROCK_TOR_USAGE` | InvokeModel from Tor IP | Anonymous AI abuse |
| `IAM_PASSROLE` | PassRole to privileged role | Privilege escalation |
| `LAMBDA_UPDATE_CODE` | UpdateFunctionCode20150331v2 | Backdoor injection |
| `DISABLE_MACIE` | DisableMacie | Defense evasion |
| `DISABLE_INSPECTOR` | inspector2:Disable | Defense evasion |
| `ORGANIZATIONS_RECON` | DescribeOrganization + ListAccounts + ListOUs | Reconnaissance |
| `EVENTBRIDGE_RULE_DELETED` | DeleteRule / DisableRule | Defense evasion |
| `GLUE_JOB_EXFIL` | glue:CreateJob (external output) | Data exfiltration |
| `ATHENA_QUERY_EXFIL` | StartQueryExecution (external output) | Data exfiltration |

---

## config.json Reference (`aws_config`)

| Key | Purpose |
|---|---|
| `users_and_roles` | Pool of IAM users and roles used as event identities |
| `aws_account_id` | Source account ID stamped into all events |
| `aws_region` | Default region for all events |
| `ec2_instances` | Instance IDs used in SSM and EC2 events |
| `rds_snapshots` | RDS snapshot identifiers for RDS share scenarios |
| `lambda_function_names` | Lambda functions targeted in Lambda scenarios |
| `lambda_role_names` | IAM roles used in Lambda remote-role scenarios |
| `foreign_account_ids` | External account IDs used in cross-account/exfil scenarios |
| `cross_account_role_names` | Role names used in AssumeRole (both benign and threat) |
| `dynamodb_tables` | Table names for DynamoDB read/write events |
| `sqs_queues` | Queue names for SQS events |
| `sns_topics` | Topic names for SNS events |
| `ecs_clusters` | ECS cluster names for container monitoring events |
| `acm_certificate_ids` | ACM certificate UUIDs for ACM list/describe events |
| `ssm_config_parameters` | Non-credential SSM parameter paths for benign reads |
| `sensitive_credential_paths` | SSM/Secrets Manager paths for `CREDENTIAL_FILE_ACCESS` |
| `eventbridge_rules` | Rule names targeted in `EVENTBRIDGE_RULE_DELETED` |
| `glue_database_names` | Glue catalog databases for Glue/Athena exfil scenarios |
| `athena_workgroups` | Athena workgroup names for query exfil events |
| `bedrock_knowledge_bases` | Bedrock KB IDs for knowledge base scenarios |
| `bedrock_guardrail_ids` | Guardrail IDs for `BEDROCK_GUARDRAIL_DELETED` |
| `bedrock_model_ids` | Foundation model IDs for Bedrock invocation scenarios |
| `sagemaker_feature_groups` | Feature Store group names for dataset modification |
| `sagemaker_labeling_jobs` | Ground Truth job names for label modification |
| `waf_web_acl_names` | WAF WebACL names for `DELETE_WAF_RULE` |
| `waf_ipset_names` | WAF IP set names for `DELETE_WAF_RULE` |
| `config_recorder_names` | AWS Config recorder names for `STOP_CONFIG_RECORDER` |
| `pentest_ami_ids` | AMI IDs recognised as pentest images |
| `large_instance_types` | Instance types used in cryptomining staging scenarios |
| `unusual_lambda_runtimes` | EOL runtimes used in unusual runtime scenarios |
| `tor_exit_nodes` | List of `{ip, country}` objects — shared with other modules |
