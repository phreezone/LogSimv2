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
| **STS** | GetCallerIdentity, AssumeRole (same-account: service roles — Lambda/ECS/EC2 — assumed only by their `AWSService` principal; deploy/CI roles assumed by people and pipelines) |

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

## Threat Scenarios (111 Types)

### Reconnaissance

* **`ORGANIZATIONS_RECON`** — Three-event burst: `DescribeOrganization` + `ListAccounts` + `ListOrganizationalUnitsForParent` via `organizations.amazonaws.com`. Attacker maps all accounts in the AWS Organization to identify high-value targets before lateral movement. *Signal: first-time or unusual Organizations API access from a non-management identity.*

### Identity & Privilege Escalation

* **`ATTACH_ADMIN_POLICY`** — `AttachUserPolicy` or `AttachRolePolicy` adding `AdministratorAccess` or a custom admin policy to an identity. Covers both self-escalation and third-party escalation.
* **`CREATE_SUSPICIOUS_USER`** — Creates an IAM user with a suspicious naming pattern, adds them to admin groups, and generates programmatic access keys in sequence.
* **`IAM_PASSROLE`** — `iam:PassRole` attaching a high-privilege role (e.g., `AdministratorRole`, `CloudFormationExecutionRole`) to a Lambda function or EC2 instance the attacker controls. No direct policy attachment needed — the compute resource runs as admin. *Signal: PassRole with a privileged target role from an unexpected identity.*
* **`IAM_UPDATE_LOGIN_PROFILE`** — `UpdateLoginProfile` resetting another user's console password — account takeover without creating new credentials.
* **`IAM_DELETE_MFA`** — `DeleteVirtualMFADevice` or `DeactivateMFADevice` removing MFA from an account to enable password-only access.
* **`CROSS_ACCOUNT_ASSUME_ROLE`** — `sts:AssumeRole` where the calling `userIdentity.accountId` differs from `recipientAccountId` — cross-account trust boundary traversal. *Signal: unexpected account ID in the caller identity.*
* **`ASSUME_ROLE_WITH_SAML`** — `sts:AssumeRoleWithSAML` — the CloudTrail footprint of a SAML/SSO federated login (Okta, Azure AD). The `roleSessionName` carries the IdP-asserted username; scenarios can pin it via `context['saml_user']` so the AWS session ties back to the same IdP identity (used by the Identity Attack → Cloud chain to pre-stage cross-identity linking). *Signal: federated role assumption from an unusual IdP user or source IP.*

### Persistence

* **`TOR_LOGIN`** — Successful `ConsoleLogin` event from a known Tor exit node IP.
* **`API_CALL_FROM_TOR`** — Read API call (`ListUsers`) from a Tor exit node via an AssumedRole identity — lower confidence than console login.
* **`LAMBDA_UPDATE_CODE`** — `UpdateFunctionCode20150331v2` replacing a live function's deployment package via S3 or inline zip. Attacker injects a backdoor into an existing function that continues operating normally. *Signal: code update from an unusual identity or external IP.*
* **`LAMBDA_ROLE_REMOTE`** — An IAM user assumes `LambdaExecutionRole` from a non-AWS IP with `aws-cli` and a Lambda-style session name (`lambda-NNNN`), then uses the issued `ASIA` credentials for GetCallerIdentity → ListBuckets → ListSecrets → GetSecretValue. *Signal: a role that only `lambda.amazonaws.com` assumes in the baseline, assumed by a person from outside the cloud.* Fires **Remote command line usage of AWS Lambda's role** [High].
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

* **`MAKE_S3_PUBLIC`** — `PutBucketAcl` granting the `AllUsers` group READ via legacy ACL. *This is the only form the built-in BIOC "AWS S3 bucket was exposed to public access" recognises.* The former `PutBucketPolicy` (`Principal:"*"`) variant was removed on 2026-08-02: it normalised identically in `cloud_audit_logs` but never fired the detector (0 alerts in 180 days; silent for 20min in a direct A/B where the ACL form alerted in 65s).
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
* **`KMS_KEY_DESTRUCTION`** — `DisableKey` → `ScheduleKeyDeletion` (7-day window) on a customer-managed KMS key — permanent, unrecoverable data destruction. The impact finale of the Cloud Ransomware chain. *Signal: ScheduleKeyDeletion on a CMK, especially paired with a preceding DisableKey.*

### Lateral Movement & Compute Abuse

* **`PENTEST_LAUNCH`** — `RunInstances` launching an EC2 instance from a known pentest AMI (Kali, Parrot, BlackArch, etc.).
* **`API_CALL_WITH_PENTEST_UA`** — Any API call carrying a pentest tool User-Agent (`nmap`, `sqlmap`, `Nikto`, `Burp`, etc.) in the `userAgent` field.
* **`EC2_INSTANCE_TYPE_CHANGE`** — `ModifyInstanceAttribute` changing an instance to a large GPU or compute-intensive type — cryptomining staging.
* **`LAMBDA_CREATE_FUNCTION_UNUSUAL_RUNTIME`** — Lambda function created with a deprecated or atypical runtime (Python 3.6, Node 10, Java 8, `provided`) — evasion or legacy exploit delivery.
* **`EC2_MODIFY_USER_DATA`** — `ModifyInstanceAttribute` changing the UserData script — arbitrary code execution on next reboot.
* **`K8S_SA_OUTSIDE_CLUSTER`** — EKS service account token used from a non-cluster IP — credential theft / token exfiltration.
* **`IMDS_CREDENTIAL_THEFT`** — EC2 instance-profile credentials stolen via SSRF/IMDSv1 and used from an **external** IP: `GetCallerIdentity` → `DescribeInstances` → `ListBuckets` → `ListAttachedRolePolicies`. `userIdentity.type` = AssumedRole (the instance role) but `sourceIPAddress` is the attacker's, not the instance's. The cloud-access stage of the Server Breach → Cloud chain. *Signal: instance-role temporary credentials used from a non-AWS source IP.*

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

## Analytics-Gap Batch (55 Scenarios, Added 2026-11-01)

These scenarios close Low-or-higher "AWS Audit Log" analytics that previously had no
producer. Each emits a real CloudTrail call with AWS-API-accurate
`requestParameters` / `responseElements` field names; the mapping from event shape to
detector is the published analytic description.

### Tenant verification (2026-11-03 and 2026-11-04)

**2026-11-03.** All 55 scenarios were fired in one run (`05:10:41Z`–`05:10:51Z`),
delivered as a single CloudTrail S3 object. The tenant raised **16 alerts**; **15 of the
55 scenarios** can be tied to one of them (`KMS_KEY_POLICY_FOREIGN` raised two).

**2026-11-04 (a).** The 39 scenarios that raised nothing on 11-03 were fired alone
(`01:26:42Z`–`01:26:49Z`, one object, 124 events). Five more scenarios raised an alert.

**2026-11-04 (b).** The remaining 34 scenarios were fired in 7 themed batches
(`03:42:55Z`–`03:49:20Z`), each flushed as its own S3 object 60 s apart, so an alert can
be matched to a batch — and usually to a single event — by timestamp. **Only 2 of the 34
raised an alert**; the other 32 stayed silent.

> **Attribution caveat:** within a single-object run, an alert is attributed by **event
> shape**, not one-scenario-per-alert. The batched run removes most of that ambiguity
> because each batch is isolated in time.

**2026-11-03 (16 alerts):**

| Key | Alert observed in the tenant | Status |
|---|---|---|
| `BACKUP_VAULT_POLICY` | A Backup vault policy was modified | ✅ primary |
| `BACKUP_VAULT_DELETED` | AWS Backup vault was deleted for the first time by this identity | ✅ Low+ variation |
| `ROUTE53_RESOLVER_LOGGING_DELETED` | Successful AWS Route53 DNS Resolver query logging configuration deletion by a non-admin identity | ✅ secondary |
| `DISABLE_ENCRYPTION` | Disable encryption operations | ✅ primary |
| `KMS_KEY_POLICY_FOREIGN` | KMS key policy was changed **and** Unusual KMS key policy modification | ✅ primary + secondary |
| `TRANSFER_FAMILY_SERVER` | Unusual cloud transfer service activity | ✅ secondary |
| `AI_SAFEGUARDS_MODIFIED` | Unusual modification of AI safeguards | ✅ secondary |
| `ML_MODEL_DOWNLOAD` | Suspicious First-Time AI Model Download by Identity | ✅ secondary |
| `EBS_SNAPSHOT_BLOCK_DOWNLOAD` | An unusual download of EBS snapshot block | ✅ secondary |
| `EC2_USER_DATA_READ` | Unusual Retrieval of cloud compute instance user data | ✅ secondary |
| `SES_ACTIVITY` | Unusual cloud email service activity | ✅ secondary |
| `SES_PRODUCTION_REQUEST` | SES Production Access Requested by an unusual identity | ✅ secondary |
| `MULTIPLE_UNUSUAL_ACTIVITIES` | Successful CloudTrail logging deletion by a non-admin identity | ⚠️ secondary; primary still unproven |
| `LOGGING_EXTERNAL_KMS` | AWS CloudTrail modification (not its stated external-key target) | ⚠️ secondary; target still unproven |
| `IAM_UNUSUAL_ACTIVITY` / `MULTIPLE_RISK_INDICATORS` | Potential creation of persistent cloud credentials | ⚠️ superseded — the same analytic is now pinned to `SSH_KEY_MODIFICATION` (see below); neither IAM primary promoted |

**2026-11-04 (a) — 5 scenarios:**

| Key | Alert observed in the tenant | Status |
|---|---|---|
| `SSM_INVENTORY_ASSOCIATION` | Unusual AWS SSM association created with inventory collection document | ✅ secondary |
| `BEDROCK_MODEL_SHARE` | Bedrock model shared with a foreign account | ✅ primary |
| `PUBLIC_SNAPSHOT_SHARE` | Cloud snapshot of a database or storage instance was publicly shared | ✅ primary (two alerts: the Medium base plus a Low variation) |
| `SES_SENDING_ENABLED` | Unusual cloud email service activity (not its sending-enabled target) | ⚠️ secondary; target still unproven |
| `SES_PHISHING_CHAIN` | Unusual cloud email service activity (not its phishing-chain target) | ⚠️ secondary; target still unproven |

**2026-11-04 (b) — batched run (2 of 34):**

| Key | Batch / event (UTC) | Alert observed in the tenant | Status |
|---|---|---|---|
| `SSH_KEY_MODIFICATION` | batch-6, `ImportKeyPair` `03:48:13Z` | Potential creation of persistent cloud credentials | ✅ secondary (none of the SSH-key targets fired) |
| `CONSOLE_FIRST_LOGIN_NONUSER` | batch-7, `ConsoleLogin` `03:49:17Z` | A non-user identity logged in to the AWS console for the first time | ✅ Medium variation (SecurityAuditorRole) |

"Potential creation of persistent cloud credentials" is deliberately generic — *"A cloud
identity invoked a credential-related persistence operation"* — and more than one shape
can raise it. The `ImportKeyPair` event pins it to `SSH_KEY_MODIFICATION`; because that
generator also fired in the 11-03 and 01:26 runs, those earlier alerts are now attributed
to it rather than to `IAM_UNUSUAL_ACTIVITY` / `MULTIPLE_RISK_INDICATORS`, which remain
unproven.

Across the three runs, **23 of the 55 scenarios** have been tied to at least one alert
(two of those, `IAM_UNUSUAL_ACTIVITY` and `MULTIPLE_RISK_INDICATORS`, are now superseded);
**32 have never raised anything**.

**Silent after three runs (32):**

| Batch | Keys |
|---|---|
| identity | `IAM_CROSS_ACCOUNT_ROLE`, `IAM_TRUST_POLICY_FOREIGN`, `LAMBDA_CROSS_ACCOUNT_PERMISSION`, `NEW_IAM_USER_RESOURCE_MOD`, `SG_REMOTE_ACCESS_UNKNOWN` |
| logging / storage / secrets | `LOG_ENUMERATION`, `LOGGING_BUCKET_DELETION`, `S3_FOREIGN_BUCKET_POLICY`, `BACKUP_STORAGE_ACCESS`, `SECRETS_MASS_DUMP`, `SSM_PARAMETERS_DUMP` |
| AI / ML / database | `AI_AGENT_MODIFIED`, `ML_ARTIFACT_DESTRUCTION`, `AI_DATASET_DOWNLOAD`, `RDS_MASTER_PASSWORD_CHANGE` |
| snapshots / volumes | `RDS_SNAPSHOT_EXPORT_UNKNOWN`, `MULTIPLE_SNAPSHOT_EXPORT`, `EBS_SNAPSHOT_DELETION`, `EBS_VOLUME_ATTACH`, `EBS_SNAPSHOT_CREATED` |
| compute / regions | `MULTI_REGION_COMPUTE`, `MULTI_REGION_DISCOVERY`, `COMPUTE_OUTSIDE_REGION`, `DORMANT_REGION_COMPUTE` |
| compute access | `SERIAL_CONSOLE_ACCESS`, `USER_DATA_MODIFY_REBOOT`, `EC2_BACKDOOR_PUBLIC`, `TRAFFIC_MIRRORING` |
| behaviour / console | `FAILED_ASSUME_ROLE`, `API_THROTTLING`, `UNUSUAL_COUNTRY_API`, `IMPOSSIBLE_TRAVEL_CLOUD` |

These emit real CloudTrail calls but do not match the analytic discriminators as written,
or the tenant has not accumulated the baseline they need (the catalog gives most of them a
30-day training period).

The primary name in `ANALYTIC_ALERTS` is the published base analytic; sibling Low+
variation names live in `ANALYTIC_ALERTS_SECONDARY`. A key not listed above is still
**NOT tenant-verified** — real AWS call shape, but whether it is the exact discriminator
the XSIAM analytic keys on is unproven until `_local_validation/aws_detector_sweep.py`
credits it.

### Shape audit (2026-11-05)

The 32 silent scenarios were re-read against the published CloudTrail record shapes, the
AWS API references, and the tenant's own `amazon_aws_raw` rows. These generator defects
were confirmed and fixed; none changes the event *name*, only the fields an analytic has
to parse.

| Area | Defect | Fix / source |
|---|---|---|
| `IAM_CROSS_ACCOUNT_ROLE` | trust policy was URL-encoded; `createDate` was localized (`Nov 05, 2026, 01:17:15 AM`) | plain JSON policy, `path: "/"`, ISO `createDate` — matches real tenant `CreateRole` and the AWS `CreateRole` example |
| `IAM_TRUST_POLICY_FOREIGN` | `policyDocument` URL-encoded | plain JSON (inferred from `CreateRole`; the tenant has no `UpdateAssumeRolePolicy` row — still unverified) |
| `LOGGING_BUCKET_DELETION` | could delete from `vpc-flow-logs-storage`; returned `{"requestCharged": null}` | targets a CloudTrail/access-log bucket; returns `{"DeleteResult": {"Deleted": [...]}}` |
| `EBS_SNAPSHOT_CREATED` | request and response `description` differed | one description echoed into both; `startTime` stays epoch-ms |
| `USER_DATA_MODIFY_REBOOT` | `ModifyInstanceAttribute.responseElements` was `null` | `{"return": true, "requestId": ...}` (real EC2 shape) |
| `SG_REMOTE_ACCESS_UNKNOWN`, `EC2_BACKDOOR_PUBLIC` | `AuthorizeSecurityGroupIngress` added a `requestId` | `{"_return": true}` only |
| `API_THROTTLING` | mixed `ThrottlingException` and `RequestLimitExceeded` | EC2's `RequestLimitExceeded` only |
| multi-event scenarios | every event shared one second | ordered, distinct `eventTime`s ending at "now" (spread over 10–240 s) |
| `NEW_IAM_USER_RESOURCE_MOD`, `IAM_UNUSUAL_ACTIVITY` | IAM `createDate` localized | ISO `createDate` |
| `SERIAL_CONSOLE_ACCESS` (and every generator reading `ec2_instances`) | config held non-hex IDs (`i-0webserverprod01`, `i-09h8g7f6e5d4c3f6`, …) | replaced with valid `i-` + 17 hex IDs |

**Still unverified, deliberately not changed:**

* `AI_AGENT_MODIFIED` uses `bedrock-agent.amazonaws.com`. AWS's
  `logging-using-cloudtrail` page documents `bedrock.amazonaws.com` for the Bedrock
  runtime (`InvokeModel`) but publishes no control-plane `UpdateAgent` sample; the
  Agents service prefix is `bedrock` in the service-authorization reference, so the
  event source is ambiguous. Flagged rather than guessed.
* `IAM_TRUST_POLICY_FOREIGN` policy encoding (see above).
* `EBS_VOLUME_ATTACH.attachTime` is emitted as ISO-8601. CloudTrail serializes some EC2
  timestamps as epoch-ms (`CreateSnapshot.startTime`), and no tenant `AttachVolume` row
  exists to settle it.
* `MULTI_REGION_*` / `DORMANT_REGION_COMPUTE` still depend on the tenant having
  baselined the account's home regions. More regions improve the chance; they do not
  prove the analytic.

### Identity, Trust & Cross-Account

| Key | Events | Target analytic |
|---|---|---|
| `IAM_CROSS_ACCOUNT_ROLE` | `CreateRole` with a foreign-account trust policy | AWS IAM Role Created with Cross-Account Access |
| `IAM_TRUST_POLICY_FOREIGN` | `UpdateAssumeRolePolicy` adding a foreign principal | AWS IAM Role's Trusted Policy Modification Allows Cross-Account Access |
| `LAMBDA_CROSS_ACCOUNT_PERMISSION` | `AddPermission` granting a foreign account or `*` | AWS Lambda Cross-Account sensitive permissions configured |
| `FAILED_ASSUME_ROLE` | 5–8 `AssumeRole` calls returning `AccessDenied` | Multiple failed AWS assume role attempts |

### Backup & Logging

| Key | Events | Target analytic |
|---|---|---|
| `BACKUP_VAULT_POLICY` | `PutBackupVaultAccessPolicy` granting a foreign account | A Backup vault policy was modified |
| `BACKUP_VAULT_DELETED` | `DeleteBackupVault` | AWS Backup vault was deleted |
| `BACKUP_STORAGE_ACCESS` | `GetObject` on backup/archive/config buckets | An identity accessed a backup cloud storage |
| `ROUTE53_RESOLVER_LOGGING_DELETED` | `DeleteResolverQueryLogConfig` | AWS Route53 DNS Resolver query logging configuration deletion |
| `LOG_ENUMERATION` | `DescribeTrails` + `DescribeLogGroups` + `ListTrails` + `DescribeConfigurationRecorders` | Log enumeration via cloud native logging service |
| `LOGGING_EXTERNAL_KMS` | `UpdateTrail` + `AssociateKmsKey` pointing at a foreign KMS key | Logging was impaired via external encryption key |
| `LOGGING_BUCKET_DELETION` | `DeleteObjects` against a CloudTrail/access-log bucket | Suspicious activity on logging bucket |

### Encryption & Resource Policy

| Key | Events | Target analytic |
|---|---|---|
| `DISABLE_ENCRYPTION` | `DisableEbsEncryptionByDefault` + `ModifyEbsDefaultKmsKeyId` | Disable encryption operations |
| `KMS_KEY_POLICY_FOREIGN` | `PutKeyPolicy` adding a foreign principal | KMS key policy was changed |
| `S3_FOREIGN_BUCKET_POLICY` | `PutBucketPolicy` granting a foreign account | Foreign account was granted permissions to S3 bucket via resource-based policy |
| `SG_REMOTE_ACCESS_UNKNOWN` | `AuthorizeSecurityGroupIngress` SSH/RDP from an unknown /32 | AWS Security Group remote access allowed from an unknown external IP address |
| `PUBLIC_SNAPSHOT_SHARE` | `ModifySnapshotAttribute` / `ModifyDBSnapshotAttribute` → `all` | Cloud snapshot of a database or storage instance was publicly shared |

### Snapshots, Volumes & Exfiltration

| Key | Events | Target analytic |
|---|---|---|
| `EBS_SNAPSHOT_BLOCK_DOWNLOAD` | `ListSnapshotBlocks` + `GetSnapshotBlock` ×3 | An EBS snapshot block was downloaded |
| `MULTIPLE_SNAPSHOT_EXPORT` | 3 × `StartExportTask` to unknown buckets | Multiple cloud snapshots export |
| `RDS_SNAPSHOT_EXPORT_UNKNOWN` | `StartExportTask` to an unknown bucket | An RDS snapshot was exported to an unknown S3 bucket |
| `EBS_SNAPSHOT_DELETION` | 4–6 × `DeleteSnapshot` | Suspicious EBS snapshots deletion |
| `EBS_VOLUME_ATTACH` | `AttachVolume` | EBS volume attachment attempt |
| `EBS_SNAPSHOT_CREATED` | 2–3 × `CreateSnapshot` from one volume | EBS snapshots were created from an EC2 instance |
| `SECRETS_MASS_DUMP` | 6 × `GetSecretValue` across two regions | An identity successfully extracted multiple secrets within the organization |
| `SSM_PARAMETERS_DUMP` | `GetParameters` (`withDecryption=true`) in batches | Suspicious AWS SSM parameters retrieval activity |
| `RDS_MASTER_PASSWORD_CHANGE` | `ModifyDBInstance` with `masterUserPassword=****` | An AWS database service master user password was changed |

### Compute & Discovery

| Key | Events | Target analytic |
|---|---|---|
| `MULTI_REGION_COMPUTE` | `RunInstances` with large/GPU types in 4 regions | Abnormal Allocation of compute resources in multiple regions |
| `MULTI_REGION_DISCOVERY` | Describe/List calls across 4 regions | Cloud infrastructure discovery across multiple regions |
| `COMPUTE_OUTSIDE_REGION` | EC2 instance-role credentials used from an external IP in another region | A compute-attached identity executed API calls outside the instance's region |
| `DORMANT_REGION_COMPUTE` | `RunInstances` in a region the account never uses | Compute activity in dormant cloud region |
| `SERIAL_CONSOLE_ACCESS` | `SendSerialConsoleSSHPublicKey` | Cloud compute serial console access |
| `EC2_USER_DATA_READ` | `DescribeInstanceAttribute(attribute=userData)` | Retrieval of cloud compute EC2 instance user data |
| `SSH_KEY_MODIFICATION` | `SendSSHPublicKey` + `ImportKeyPair` with attacker key material | Suspicious cloud compute instance SSH keys modification attempt |
| `USER_DATA_MODIFY_REBOOT` | `ModifyInstanceAttribute(userData)` → `RebootInstances` | Suspicious cloud user data modification attempt followed by VM restart |
| `EC2_BACKDOOR_PUBLIC` | `RunInstances` with admin profile + public IP, then open SSH/RDP to `0.0.0.0/0` | EC2 backdoor created with newly added external SSH or RDP access |
| `TRAFFIC_MIRRORING` | `CreateTrafficMirrorFilter` + `Target` + `Session` | Network sniffing detected in Cloud environment |
| `API_THROTTLING` | 12–18 calls returning `ThrottlingException`/`RequestLimitExceeded` | Cloud identity reached a throttling API rate |

### AI / ML

| Key | Events | Target analytic |
|---|---|---|
| `BEDROCK_MODEL_SHARE` | RAM `CreateResourceShare` with `allowExternalPrincipals=true` | Bedrock model shared with a foreign account |
| `AI_AGENT_MODIFIED` | `UpdateAgent` changing model/instructions | Cloud AI agent was modified |
| `AI_SAFEGUARDS_MODIFIED` | `UpdateGuardrail` setting filters to `NONE` | AI safeguards were modified |
| `ML_ARTIFACT_DESTRUCTION` | `DeleteEndpoint` + `DeleteModel` + `DeleteFeatureGroup` + `DeleteModelPackage` | ML artifacts destruction |
| `AI_DATASET_DOWNLOAD` | 3–5 × `GetObject` of training-data shards | Suspicious AI Dataset Download |
| `ML_MODEL_DOWNLOAD` | 2–4 × `GetObject` of model weight shards | Suspicious ML Model Download |

### Email (SES), SSM & Transfer

| Key | Events | Target analytic |
|---|---|---|
| `SES_SENDING_ENABLED` | `UpdateAccountSendingEnabled(true)` | Cloud email sending was enabled |
| `SES_ACTIVITY` | `VerifyEmailIdentity` + `CreateConfigurationSet` + `SendEmail` | Cloud email service activity |
| `SES_PRODUCTION_REQUEST` | `PutAccountDetails` requesting production access | SES Production Access Requested |
| `SES_PHISHING_CHAIN` | identity verify → permissive identity policy → bulk send | Suspicious activity indicating a potential abuse of a cloud-native email service |
| `SSM_INVENTORY_ASSOCIATION` | `CreateAssociation` with `AWS-GatherSoftwareInventory` | AWS SSM association created with inventory collection document |
| `TRANSFER_FAMILY_SERVER` | `CreateServer` + `CreateUser` (SFTP, PUBLIC endpoint) | AWS Transfer Family server created |
| `IAM_UNUSUAL_ACTIVITY` | EC2-role `CreateUser` + `AttachUserPolicy(AdministratorAccess)` + `CreateAccessKey` from an external IP | Unusual Identity and Access Management (IAM) activity — **generator only; claim withheld**, see below |

### Behavioural & Geographic Aggregates

These four are not single API shapes. They emit the burst a per-identity baseline or
org-scoped aggregate would eventually classify, and are the least certain in the batch.

| Key | Events | Target analytic |
|---|---|---|
| `UNUSUAL_COUNTRY_API` | 3 read calls from an ambient attacker-pool country the identity has not used | A cloud identity executed an API call from an unusual country |
| `IMPOSSIBLE_TRAVEL_CLOUD` | Same identity, home country then a far-pair country 8 minutes later | Impossible travel by a cloud identity |
| `MULTIPLE_UNUSUAL_ACTIVITIES` | 6 distinct uncommon calls (credential, policy, ingress, secret, log, recon) in one burst | A cloud identity performed multiple unusual activities |
| `MULTIPLE_RISK_INDICATORS` | Anonymizer IP + novel country + `CreateUser`/`AttachUserPolicy`/`CreateAccessKey` | Multiple risk indicators for a cloud identity |

Country selection for these four uses `config['external_traffic_sources']`, never
`config['vpn_novel_country_pool']`. The reserve pool exists so the org-scoped
"First successful VPN access from a country in organization" analytic keeps its
70-day novelty cycle; spending it on cloud API calls would re-saturate the org
baseline and silence that detector.

### Residual AWS Gaps (No Generator)

Four Low+ targets still have no producer, for the reasons given:

| Target | Why no generator |
|---|---|
| An operation was performed by an identity from a domain that was not seen in the tenant | CloudTrail carries no identity-provider **domain** field; this is an Entra/Okta concept that happens to list AWS Audit Log as an alternative source |
| Cloud impersonation attempt by unusual identity type | Tried 2026-10-08 and dropped: Informational base + 14-day activation, never fired in 90 days of tenant history |
| Unusual cloud identity impersonation | Same 2026-10-08 decision as above |
| Unusual Identity and Access Management (IAM) activity | Generator exists (`IAM_UNUSUAL_ACTIVITY`) but the claim is withheld for the same 90-day evidence; re-add the primary and secondary together if a sweep credits the "Internet facing instance" variation |

---

## SCENARIO_FUNCTIONS Reference

The following scenario keys can be passed as `scenario_event` in coordinated simulator scenarios:

| Key | Generator | Trigger |
|---|---|---|
| `TOR_LOGIN` | ConsoleLogin from Tor IP | Identity attacks |
| `PENTEST_LAUNCH` | RunInstances with pentest AMI | Compute abuse |
| `DISABLE_GUARDDUTY` | DeleteDetector | Defense evasion |
| `STOP_CLOUDTRAIL` | StopLogging | Defense evasion |
| `MAKE_S3_PUBLIC` | PutBucketAcl (AllUsers grant) | Data exposure |
| `DISABLE_S3_LOGGING` | PutBucketLogging (disabled) | Defense evasion |
| `ATTACH_ADMIN_POLICY` | AttachUserPolicy/AttachRolePolicy | Privilege escalation |
| `CREATE_SUSPICIOUS_USER` | CreateUser + AddUserToGroup + CreateAccessKey | Persistence |
| `SSM_START_SESSION` | StartSession | Remote access |
| `SSM_SEND_COMMAND` | SendCommand | Remote execution |
| `RDS_SHARE_SNAPSHOT` | ModifyDBSnapshotAttribute | Data exfiltration |
| `LAMBDA_ROLE_REMOTE` | AssumeRole of the Lambda role via CLI from outside AWS + CLI chain | Credential access |
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
| `IAM_CROSS_ACCOUNT_ROLE` | CreateRole (foreign trust) | Cross-account access |
| `IAM_TRUST_POLICY_FOREIGN` | UpdateAssumeRolePolicy (foreign principal) | Cross-account access |
| `LAMBDA_CROSS_ACCOUNT_PERMISSION` | AddPermission (foreign or public) | Cross-account access |
| `FAILED_ASSUME_ROLE` | AssumeRole ×5–8 (AccessDenied) | Credential probing |
| `BACKUP_VAULT_POLICY` | PutBackupVaultAccessPolicy | Backup tampering |
| `BACKUP_VAULT_DELETED` | DeleteBackupVault | Backup destruction |
| `BACKUP_STORAGE_ACCESS` | GetObject on backup bucket | Data access |
| `ROUTE53_RESOLVER_LOGGING_DELETED` | DeleteResolverQueryLogConfig | Defense evasion |
| `LOG_ENUMERATION` | DescribeTrails/LogGroups/ConfigRecorders | Reconnaissance |
| `LOGGING_EXTERNAL_KMS` | UpdateTrail + AssociateKmsKey (foreign key) | Logging impairment |
| `LOGGING_BUCKET_DELETION` | DeleteObjects on logging bucket | Defense evasion |
| `DISABLE_ENCRYPTION` | DisableEbsEncryptionByDefault | Defense evasion |
| `KMS_KEY_POLICY_FOREIGN` | PutKeyPolicy (foreign principal) | Data exposure |
| `S3_FOREIGN_BUCKET_POLICY` | PutBucketPolicy (foreign account) | Data exposure |
| `SG_REMOTE_ACCESS_UNKNOWN` | AuthorizeSecurityGroupIngress (/32) | Network exposure |
| `PUBLIC_SNAPSHOT_SHARE` | ModifySnapshotAttribute / ModifyDBSnapshotAttribute | Data exposure |
| `EBS_SNAPSHOT_BLOCK_DOWNLOAD` | ListSnapshotBlocks + GetSnapshotBlock | Data exfiltration |
| `MULTIPLE_SNAPSHOT_EXPORT` | StartExportTask ×3 | Data exfiltration |
| `RDS_SNAPSHOT_EXPORT_UNKNOWN` | StartExportTask (unknown bucket) | Data exfiltration |
| `EBS_SNAPSHOT_DELETION` | DeleteSnapshot ×4–6 | Data destruction |
| `EBS_VOLUME_ATTACH` | AttachVolume | Lateral movement |
| `EBS_SNAPSHOT_CREATED` | CreateSnapshot ×2–3 | Data staging |
| `SECRETS_MASS_DUMP` | GetSecretValue ×6 | Credential theft |
| `SSM_PARAMETERS_DUMP` | GetParameters (decrypt) | Credential theft |
| `RDS_MASTER_PASSWORD_CHANGE` | ModifyDBInstance (master password) | Persistence |
| `MULTI_REGION_COMPUTE` | RunInstances (GPU) ×4 regions | Compute abuse |
| `MULTI_REGION_DISCOVERY` | Describe/List ×4 regions | Reconnaissance |
| `COMPUTE_OUTSIDE_REGION` | Instance-role calls from external IP | Credential abuse |
| `DORMANT_REGION_COMPUTE` | RunInstances in dormant region | Compute abuse |
| `SERIAL_CONSOLE_ACCESS` | SendSerialConsoleSSHPublicKey | Persistence |
| `EC2_USER_DATA_READ` | DescribeInstanceAttribute(userData) | Credential access |
| `SSH_KEY_MODIFICATION` | SendSSHPublicKey + ImportKeyPair | Persistence |
| `USER_DATA_MODIFY_REBOOT` | ModifyInstanceAttribute(userData) + Reboot | Persistence |
| `EC2_BACKDOOR_PUBLIC` | RunInstances + open SSH/RDP | Persistence |
| `TRAFFIC_MIRRORING` | CreateTrafficMirrorFilter/Target/Session | Collection |
| `API_THROTTLING` | DescribeInstances ×12–18 (throttled) | Discovery |
| `BEDROCK_MODEL_SHARE` | RAM CreateResourceShare | AI exfiltration |
| `AI_AGENT_MODIFIED` | UpdateAgent | AI tampering |
| `AI_SAFEGUARDS_MODIFIED` | UpdateGuardrail | AI tampering |
| `ML_ARTIFACT_DESTRUCTION` | SageMaker Delete* | AI destruction |
| `AI_DATASET_DOWNLOAD` | GetObject (dataset shards) | AI exfiltration |
| `ML_MODEL_DOWNLOAD` | GetObject (model shards) | AI exfiltration |
| `SES_SENDING_ENABLED` | UpdateAccountSendingEnabled | Email abuse |
| `SES_ACTIVITY` | VerifyEmailIdentity + SendEmail | Email abuse |
| `SES_PRODUCTION_REQUEST` | PutAccountDetails | Email abuse |
| `SES_PHISHING_CHAIN` | Verify + PutIdentityPolicy + SendEmail | Email abuse |
| `SSM_INVENTORY_ASSOCIATION` | CreateAssociation (inventory doc) | Discovery |
| `TRANSFER_FAMILY_SERVER` | CreateServer + CreateUser | Exfiltration staging |
| `IAM_UNUSUAL_ACTIVITY` | EC2-role CreateUser + admin policy + key | Privilege escalation |
| `UNUSUAL_COUNTRY_API` | Read calls from a novel country | Geo anomaly |
| `IMPOSSIBLE_TRAVEL_CLOUD` | Home then far country in 8 minutes | Geo anomaly |
| `MULTIPLE_UNUSUAL_ACTIVITIES` | 6 uncommon calls in one burst | Behavioural anomaly |
| `MULTIPLE_RISK_INDICATORS` | Anonymizer + novel country + IAM abuse | Risk aggregation |

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
| `cross_account_role_names` | Role names used in AssumeRole: the human/CI pool of the benign AssumeRole (service roles are filtered out) and the cross-account threat |
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

## Generated Identifiers

`modules/cloud_ids.py` generates correctly-shaped AWS identifiers and grows the
`aws_config` pools once at startup, before any module reads one. Full rationale in
[value-cardinality.md](../value-cardinality.md).

| Pool | Before | After |
|---|---|---|
| `ec2_snapshots` | 26 | 900 |
| `ebs_volumes` | 26 | 600 |
| `ec2_instances` | 26 | 400 |
| `log_groups` | 26 | 250 |
| `s3_buckets` | 26 | 200 |
| `foreign_account_ids` | 26 | 150 |
| `vpcs` | 26 | **26** (a real estate has few) |

Growing the pools is more faithful than generating per event for anything that persists: a
real account genuinely keeps a stable set of instances that get started, stopped and
snapshotted for months. The defect was never recurrence — it was having 26 of them for
an estate of ~250 users.

Formats are the documented ones, because these get pivoted on: `i-` + **17** hex (AWS left
the 8-hex form behind in 2016), `AKIA` + 16 for a long-lived key, `ASIA` + 16 for STS
temporary credentials, 12-digit accounts, DNS-compliant bucket names.

**Your own account ID never changes** — it is your identity, appears in every ARN, and
is read from `.env`. Only *foreign* account IDs vary, which is the field a cross-account
AssumeRole rule keys on.

Three additions worth knowing:

- **Secret names.** `sensitive_credential_paths` is seeded with the six leaf names the
  "Secret or Parameter Retrieval Targeting Credentials" rule matches —
  `rootCredentials`, `MasterKey`, `SuperUser`, `service_account_key`, `encryption_key`,
  `BreakGlass`. That rule previously had **one** live alternative, and only via a
  case-insensitive match.
- **S3 canned ACLs.** A quarter of `PutBucketAcl` events now use the
  `x-amz-acl: public-read` form instead of the `AllUsers` grant URI, because CloudTrail
  carries one or the other and both are real. The grant-URI form stays dominant
  deliberately: it is the only one the built-in BIOC recognises.
- **Automation principals.** Service-linked roles (`AWSServiceRoleForAmazonEKS`) and
  instance profiles are now in `users_and_roles`, so the four rules that *exclude* AWS's
  own automation finally have something to exclude.
  `sessionContext.sessionIssuer.arn` reports the real
  `role/aws-service-role/<service>.amazonaws.com/<name>` path.

`aws_config.pentest_ami_ids` is deliberately **not** generated over — those ids encode
distro names the Kali-AMI rule matches.
