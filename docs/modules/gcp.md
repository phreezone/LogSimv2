# GCP Cloud Audit Logs

**Dataset:** `google_cloud_logging_raw`
**Transport:** Google Cloud Pub/Sub (`google-cloud-pubsub` library; `send_pubsub_message()` in log_simulator.py)
**Format:** Single GCP LogEntry JSON per Pub/Sub message (NOT gzip-compressed, unlike AWS)

Simulates Google Cloud Audit Log events for the XSIAM `google_cloud_logging_raw` dataset. The GoogleCloudLogging XIF pack (`GCP_MAP_COMMON_FIELDS` + `GCP_MAP_AUDIT_LOGS` rules) maps LogEntry fields to XDM. Each message is a complete Cloud Audit Log `LogEntry` JSON object published as a single Pub/Sub message. Log routing matches real GCP: operations that create or modify resources land in the Admin Activity log (`cloudaudit.googleapis.com%2Factivity`); read/list operations land in the Data Access log (`cloudaudit.googleapis.com%2Fdata_access`).

- **XIF:** GoogleCloudLogging pack — `GCP_MAP_COMMON_FIELDS` + `GCP_MAP_AUDIT_LOGS`
- **Key XDM fields:** `insertId`, `logName`, `severity`, `resource.labels.project_id`, `resource.type`, `protoPayload.authenticationInfo.principalEmail`, `protoPayload.requestMetadata.callerIp`, `protoPayload.methodName`, `protoPayload.status.code`
- **Identity:** uses `session_context[user].email` or `gcp_config.service_accounts`; optional per-user override via `gcp_iam_user` in user_profiles

---

## Benign Events (38 Types)

Normal operational traffic establishing a clean baseline across all major GCP services:

| Service Area | Events Generated |
|---|---|
| **Cloud Storage** | List objects, get object, put/upload object |
| **Compute Engine** | List instances, get instance details, list disk images |
| **IAM** | Get IAM policy, list service accounts |
| **BigQuery** | List datasets, run query job |
| **GKE** | List clusters |
| **Cloud Run** | List services |
| **Pub/Sub** | List topics |
| **Secret Manager** | Access non-sensitive secret versions |
| **Cloud Logging** | List log sinks |
| **Cloud Monitoring** | List metric descriptors |
| **Cloud DNS** | List managed zones |
| **Vertex AI** | List models, run predictions, generate content, list training jobs, batch predict |
| **Cloud SQL** | List instances, connect to instance |
| **Cloud KMS** | List key rings, encrypt data |
| **Artifact Registry** | List repositories |
| **Cloud Build** | List builds |
| **Cloud Armor** | List security policies |
| **Spanner** | List instances |
| **Dataflow** | List jobs |
| **Service Account lifecycle** | Create service account (routine provisioning) |

## Threat Scenarios (71 Types)

---

### Defense Evasion / Audit Tampering

* **`DISABLE_AUDIT_LOGGING`** — Delete or update a Cloud Logging sink (`google.logging.v2.ConfigServiceV2.DeleteSink` / `UpdateSink`) to stop audit log export to SIEM. *Signal: mutating op on log export pipeline.*
* **`LOGGING_SINK_DELETE`** — Delete a named log export sink. Lower weight than DISABLE_AUDIT_LOGGING; complements it as a distinct detection target.
* **`LOGGING_SINK_MODIFY`** — Update a log sink's filter or destination URI to redirect or suppress log export without full deletion.
* **`LOGGING_BUCKET_DELETE`** — Delete a Cloud Logging log storage bucket (`google.logging.v2.ConfigServiceV2.DeleteBucket`), targeting `_Default` or `_Required` system buckets to destroy stored audit logs. *Distinct from sink deletion — this is the storage backend.*
* **`DISABLE_SCC`** — Delete a Security Command Center notification config (`securitycenter.notificationConfigs.delete`) to suppress SCC findings and alerts.
* **`DISABLE_VPC_FLOW_LOGS`** — Patch a VPC subnetwork (`v1.compute.subnetworks.patch`) to set `enableFlowLogs: false`, removing network visibility.

---

### IAM / Privilege Escalation

* **`IAM_PRIVILEGE_ESCALATION`** — `SetIamPolicy` on the project adding `roles/owner` or `roles/editor` to an unexpected principal (user or service account).
* **`ADMIN_ROLE_GRANTED`** — `SetIamPolicy` on the project granting a highly privileged admin role (`roles/resourcemanager.organizationAdmin`, `roles/iam.securityAdmin`, etc.) to a cloud identity user or group.
* **`IAM_ROLE_CREATE`** — `google.iam.admin.v1.CreateRole` — custom IAM role created with suspicious permissions (`iam.serviceAccounts.actAs`, `resourcemanager.projects.setIamPolicy`, `secretmanager.versions.access`, etc.). *Signal: shadow admin role staging.*
* **`IAM_DENY_POLICY_CREATE`** — `google.iam.admin.v1beta.CreatePolicy` — IAM Deny policy created with `deniedPrincipals` targeting other service accounts while the attacker exempts themselves via `exceptionPrincipals`.
* **`EXTERNAL_USER_ADDED`** — `SetIamPolicy` binding an external Gmail account (`@gmail.com`) or personal email to a project role. *Signal: unauthorized external identity granted access.*
* **`SENSITIVE_ROLE_TO_GROUP`** — `SetIamPolicy` granting `roles/owner`, `roles/editor`, or another sensitive role to a broad group alias (`all-employees@`, `dev-team@`, etc.). *Signal: over-permissive bulk grant.*
* **`CROSS_PROJECT_SA_GRANT`** — `SetIamPolicy` adding a service account from an external or unknown project as a project-level binding. *Signal: cross-project lateral movement.*
* **`SECRETMANAGER_SELF_GRANT`** — `SetIamPolicy` on Secret Manager granting the caller `roles/secretmanager.secretAccessor` on a secret they do not already have access to. *Signal: privilege self-elevation on sensitive resource.*
* **`DEPLOYMENTMANAGER_SELF_GRANT`** — `SetIamPolicy` on Deployment Manager granting the caller `roles/deploymentmanager.editor`. Deployment Manager runs as a service account with broad project permissions — self-grant enables indirect privilege escalation.

---

### Service Account Credential Abuse

* **`CREATE_SA_KEY`** — `google.iam.admin.v1.CreateServiceAccountKey` — creates a long-lived JSON key for a service account, enabling offline credential exfiltration.
* **`DELETE_SA_KEY`** — `google.iam.admin.v1.DeleteServiceAccountKey` — deletes a service account key after use to cover tracks.
* **`SERVICE_ACCOUNT_IMPERSONATION`** — Two-event sequence: (1) `google.iam.admin.v1.ServiceAccounts.GetIamPolicy` (ACTIVITY) scoping a target SA, then (2) `google.iam.credentials.v1.IAMCredentials.GenerateAccessToken` (DATA_ACCESS) minting a token for that SA. Caller and target are always distinct identities. *Signal: token theft / lateral movement via SA impersonation.*
* **`SA_IMPERSONATION_FAILED`** — `google.iam.credentials.v1.IAMCredentials.GenerateAccessToken` returning `PERMISSION_DENIED` (status code 7) — attacker lacks `iam.serviceAccounts.getAccessToken` on the target. Routes to DATA_ACCESS log (`%2Fdata_access`). *Signal: failed privilege escalation attempt.*
* **`CREATE_SERVICE_ACCOUNT`** — `google.iam.admin.v1.CreateServiceAccount` — creates a new service account, often a staging step before key creation or role grant.
* **`DELETE_SERVICE_ACCOUNT`** — `google.iam.admin.v1.DeleteServiceAccount` — deletes a service account to disrupt dependent workloads or cover tracks. Caller and target are always distinct identities.
* **`DISABLE_SERVICE_ACCOUNT`** — `google.iam.admin.v1.DisableServiceAccount` — disables a SA, preventing its tokens from being accepted by GCP APIs. Caller and target are always distinct identities.
* **`FUNCTIONS_SENSITIVE_ROLE`** — `google.cloud.functions.v2.FunctionService.SetIamPolicy` at the function resource level, binding `roles/cloudfunctions.admin` or `roles/run.admin` to a service account or external user. *Signal: function-scoped privilege grant.*

---

### Data Exposure & Exfiltration — Storage

* **`MAKE_GCS_PUBLIC`** — `storage.setIamPolicy` on a GCS bucket binding `allUsers` as `roles/storage.objectViewer`. Resource labels: `{bucket_name, project_id}` — no spurious location field. *Signal: public data exposure.*
* **`GCS_BUCKET_CONFIG_MODIFY`** — `storage.buckets.patch` weakening a GCS bucket's security posture: disabling uniform bucket-level access, removing public access prevention, disabling versioning, removing retention policy, or adding a permissive default object ACL.
* **`GCS_BUCKET_DELETE`** — `storage.buckets.delete` — destroys the bucket and all its objects.
* **`GCS_LIFECYCLE_TAMPER`** — `storage.buckets.update` adding a lifecycle rule with `action.type: Delete` and `condition.age: 1–3 days` — time-delayed data destruction. The attacker sets this once and walks away; GCS automation silently deletes all objects after the TTL expires.
* **`SNAPSHOT_EXFIL`** — Two-event sequence: (1) `v1.compute.disks.createSnapshot` creating a disk snapshot, then (2) `v1.compute.snapshots.setIamPolicy` sharing it to an attacker-controlled external project. *Signal: data exfiltration via compute disk clone.*
* **`COMPUTE_IMAGE_EXFIL`** — Two-event sequence: (1) `v1.compute.images.insert` creating a disk image from an instance, then (2) `v1.compute.images.setIamPolicy` sharing it to an external project. Consistent `image_id` across both events for XSIAM correlation.
* **`SECRET_MASS_ACCESS`** — Burst of 15–40 `google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion` calls against sensitive secrets in rapid succession. Multi-event. *Signal: credential harvesting sweep.*

---

### Data Exposure & Exfiltration — Databases & Analytics

* **`BIGQUERY_DATA_EXFIL`** — Two-event sequence: (1) `JobService.InsertJob` with a `SELECT *` query against a sensitive table, then (2) `JobService.InsertJob` with an `extract` configuration writing to an attacker-controlled GCS bucket. Shared `operation_id` for XSIAM correlation.
* **`BIGQUERY_TABLE_DELETE`** — `google.cloud.bigquery.v2.TableService.DeleteTable` — 3–8 tables deleted in rapid succession from the same dataset by the same identity. *Signal: data destruction / ransomware targeting analytics infrastructure.*
* **`BIGQUERY_PUBLIC_DATASET`** — `google.cloud.bigquery.v2.DatasetService.Update` modifying the dataset `access` list to add `allAuthenticatedUsers` as `READER`. *Signal: analytics data exposure to any Google account.*
* **`CLOUDSQL_EXPORT_EXTERNAL`** — `google.cloud.sql.v1.SqlInstancesService.Export` exporting a SQL database (`fileType: SQL`) to a URI in an attacker-controlled GCS bucket (different project). *Signal: SQL-layer data exfiltration.*
* **`CLOUDSQL_BACKUP_DELETE`** — `google.cloud.sql.v1.SqlBackupRunsService.Delete` — 3–8 automated backup runs deleted in rapid succession. *Signal: eliminating recovery options before ransomware or sabotage.*
* **`SQL_INSTANCE_PUBLIC`** — `google.cloud.sql.v1.SqlInstancesService.Patch` enabling `ipv4Enabled: true` and adding `authorizedNetworks: [{value: "0.0.0.0/0"}]` — exposes database to the internet.

---

### Container & GKE Threats

* **`GKE_EXEC_INTO_POD`** — `io.k8s.core.v1.pods.exec` or `io.k8s.core.v1.pods.portforward` — interactive shell (`/bin/sh`, `stdin: true`, `tty: true`) into a running container. *Signal: lateral movement / hands-on-keyboard activity inside cluster.*
* **`GKE_PRIVILEGED_POD_CREATED`** — `io.k8s.core.v1.pods.create` with `securityContext.privileged: true`, `hostPID: true`, `hostNetwork: true`, capabilities `SYS_ADMIN/SYS_PTRACE/NET_ADMIN`, and a host filesystem volume mount. The pod command uses `nsenter -t 1 -m -u -i -n` to escape the container namespace into the node OS. *Signal: container breakout / host takeover.*
* **`GKE_CLUSTER_ADMIN_BINDING`** — `io.k8s.rbac.v1.clusterrolebindings.create` binding `cluster-admin` ClusterRole to an external user, external service account, or broad group subject. *Signal: full Kubernetes API server compromise.*
* **`GKE_PUBLIC_ENDPOINT_ENABLED`** — `google.container.v1.ClusterManager.UpdateCluster` setting `desiredMasterAuthorizedNetworksConfig.cidrBlocks: [{cidrBlock: "0.0.0.0/0"}]` — exposes the K8s API server to the public internet. *Signal: cluster perimeter removal.*

---

### Serverless & CI/CD Threats

* **`CLOUD_FUNCTION_MALICIOUS_DEPLOY`** — `google.cloud.functions.v2.FunctionService.CreateFunction` or `UpdateFunction` deploying a Cloud Function with `C2_ENDPOINT` in environment variables. *Signal: persistence via serverless backdoor.*
* **`CLOUDRUN_PUBLIC_DEPLOY`** — `google.iam.v1.IAMPolicy.SetIamPolicy` on a Cloud Run service binding `allUsers` to `roles/run.invoker` — makes the service publicly invocable without authentication. Includes `policyDelta.bindingDeltas` for XSIAM detection. *Signal: unauthenticated public API exposure.*
* **`CLI_FROM_SERVERLESS`** — Any GCP API call where `callerSuppliedUserAgent` contains `command/gcloud` and `callerIp` is an RFC-1918 / GCP-internal address and `principalEmail` is a service account. Legitimate serverless code uses client libraries, not the gcloud CLI. Five API variants: IAM list (DATA_ACCESS), GCS list (DATA_ACCESS), Secret Manager access (DATA_ACCESS), SA key creation (ACTIVITY), GCS object delete (ACTIVITY). *Signal: attacker interactive shell inside serverless container.*
* **`CLOUDBUILD_TRIGGER_MODIFY`** — `google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger` modifying a Cloud Build trigger to inject a malicious build step: either a `curl` exfiltrating `/workspace` env files, a `docker run` downloading and executing a remote init script, or a `gsutil cp` copying the entire build workspace to an attacker bucket. Resource labels: `{build_trigger_id, project_id}`. *Signal: CI/CD pipeline poisoning.*

---

### Network & Perimeter

* **`FIREWALL_EXPOSE_ALL`** — `v1.compute.firewalls.insert` creating a firewall rule with `allowed: [{IPProtocol: all}]` and `sourceRanges: ["0.0.0.0/0"]` on a high priority. *Signal: perimeter destruction.*
* **`FIREWALL_RULE_DELETE`** — `v1.compute.firewalls.delete` removing an existing protective firewall rule. *Signal: removing network controls.*
* **`FIREWALL_RULE_MODIFY`** — `v1.compute.firewalls.patch` modifying a firewall rule to expand allowed traffic (wider IP range or additional protocols).
* **`VPC_NETWORK_DELETE`** — `v1.compute.networks.delete` — deletes a VPC network, disrupting all resources attached to it. Resource labels: `{network_id: <numeric>}`.
* **`VPC_ROUTE_DELETE`** — `v1.compute.routes.delete` — removes a VPC route, disrupting routing for attached resources. Resource labels: `{route_id: <numeric>}`.
* **`VPC_PEERING_BACKDOOR`** — `v1.compute.networks.addPeering` creating a VPC peering connection to an unknown external project, establishing private RFC-1918 connectivity to an attacker-controlled VPC.
* **`VPN_ROUTE_CREATE`** — Creates a Cloud VPN route to an external/suspicious CIDR. *Signal: covert network tunnel.*

---

### Compute & Infrastructure

* **`VM_METADATA_MODIFY`** — `v1.compute.instances.setMetadata` setting a `startup-script` or `windows-startup-script-ps1` metadata key — enables arbitrary code execution on next VM restart. *Signal: persistence via instance metadata.*
* **`PROJECT_DELETE`** — `cloudresourcemanager.projects.delete` — deletes the entire GCP project and all resources within it after the 30-day lien period.
* **`CLOUD_ARMOR_DELETE`** — `networksecurity.securityPolicies.delete` or equivalent — removes the Cloud Armor WAF policy, exposing backend services to unfiltered traffic.
* **`ORG_POLICY_MODIFY`** — `orgpolicy.googleapis.com` — modify an org-level policy constraint (e.g., remove `constraints/iam.disableServiceAccountKeyCreation` or `constraints/compute.requireShieldedVm`). *Signal: removing preventive security guardrails.*

---

### KMS / Cryptographic Destruction

* **`KMS_KEY_DESTROY`** — `google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion` — hard-schedules a key version for destruction after the 30-day grace period, making all data encrypted with it permanently unreadable.
* **`KMS_KEY_VERSION_DISABLE`** — `google.cloud.kms.v1.KeyManagementService.UpdateCryptoKeyVersion` with `updateMask: state` and `state: DISABLED` — immediately prevents all encrypt/decrypt operations without the 30-day grace window. Harder to attribute than a hard destroy. Response includes `state: DISABLED` and algorithm details.

---

### Pub/Sub

* **`PUBSUB_SUBSCRIPTION_DELETE`** — `google.pubsub.v1.Subscriber.DeleteSubscription` — deletes a Pub/Sub subscription, dropping all pending messages and severing the consumer. *Signal: disrupting event pipelines.*
* **`PUBSUB_TOPIC_DELETE`** — `google.pubsub.v1.Publisher.DeleteTopic` — deletes a Pub/Sub topic along with all its subscriptions.

---

### Artifact Registry

* **`ARTIFACT_REGISTRY_PUBLIC`** — `google.devtools.artifactregistry.v1.ArtifactRegistry.SetIamPolicy` binding `allUsers` to `roles/artifactregistry.reader` on a repository. Includes `policyDelta.bindingDeltas` for XSIAM detection. *Signal: container image exposure enabling supply-chain reconnaissance.*

---

### IAM Reconnaissance

* **`IAM_RECON_TESTPERMISSIONS`** — Burst of 5–15 `TestIamPermissions` calls (DATA_ACCESS) across multiple services — `cloudresourcemanager`, `iam`, `storage`, `bigquery`, `secretmanager`, `compute`, `cloudkms`. Each call returns a partial list of granted permissions in the response body, simulating post-compromise privilege mapping. *Signal: attacker enumerating what the compromised credential can do before choosing next pivot.*

---

### Vertex AI / ML Security

* **`VERTEX_DATASET_DELETE`** — Delete a Vertex AI managed dataset — analogous to SageMaker dataset deletion.
* **`VERTEX_DENIAL_OF_WALLET`** — Burst of 20–50 `InvokeModel` / `predict` calls against Gemini endpoints in rapid succession. Multi-event. *Signal: LLM abuse / financial exhaustion.*
* **`VERTEX_MODEL_EXFIL`** — Export a Vertex AI model artifact to an external storage bucket.
* **`VERTEX_TRAINING_MALICIOUS`** — Submit a training job using a suspicious or external container image URI (not from `us-docker.pkg.dev/vertex-ai/`).
* **`VERTEX_DATASET_POISON`** — Modify training dataset metadata or labels — ML data poisoning.
* **`VERTEX_RAG_CORPUS_MODIFY`** — Modify or delete a Vertex AI RAG corpus — corrupts grounding data for Gemini-backed applications.
* **`VERTEX_TOR_PREDICT`** — `predict` or `InvokeModel` call originating from a Tor exit node IP. *Signal: anonymous LLM abuse.*
* **`VERTEX_MODEL_ARMOR_DELETE`** — Delete a Model Armor safety template (`projects.locations.templates.delete`) — removes LLM safety guardrails.
* **`VERTEX_DISABLE_MODEL_LOGGING`** — Disable model prediction logging (`UpdateModel` setting `predictSchemataUri` or logging config to null) — removes AI audit trail.

---

### Identity — Tor

* **`TOR_API_ACCESS`** — Any GCP Cloud API call where `callerIp` is a known Tor exit node. The event type varies per run (IAM, GCS, Compute, BigQuery, etc.). *Signal: anonymous API access from anonymization network.*

---

### Impossible Travel / Account Compromise

* **`CROSS_PROJECT_SA_GRANT`** — `SetIamPolicy` binding a service account from an external project as a member, establishing a cross-project foothold.

---

### Pub/Sub Infrastructure

* **`PUBSUB_SUBSCRIPTION_DELETE`** / **`PUBSUB_TOPIC_DELETE`** — See Pub/Sub section above.
