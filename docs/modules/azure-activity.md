# Azure Activity log

`modules/azure_activity.py` simulates the Azure Activity log of a mid-size enterprise estate as
Azure Monitor diagnostic settings stream it to an event hub, plus the AKS API-server audit log
(`kube-audit`) from the estate's clusters.

| Module | Feed (record shape) | XSIAM dataset | Source-Identifier |
|---|---|---|---|
| `azure_activity` | Activity log, event-hub resource-log schema; AKS `kube-audit` | `msft_azure_raw` | `fce13a1d51294f84bae4a37851503060` |

Transport is the Cribl receiver (`"azure_activity_config": {"transport": "cribl"}`), as for the
Entra feeds. See [microsoft-entra.md](microsoft-entra.md#transport-the-cribl-receiver-no-cribl-instance-needed).
XSIAM files the records in `cloud_audit_logs` as `log_name = azure_audit_logs`, the input of
the Cloud analytics (verified with a canary on 2026-10-21).

## Record shape

Microsoft's "schema from storage account and event hubs" (Activity log schema, 2026-10-13):
`time`, `resourceId` and `operationName` (upper-cased, as streamed), `category`, `resultType`
(`Start` / `Accept` / `Success` / `Failure`), `resultSignature` (`Started.`, `Succeeded.OK`,
`Succeeded.Created`, `Failed.Forbidden`, ...), `durationMs` (always 0), `callerIpAddress`,
`correlationId`, `identity` and `level`. Also `location` (`global`) and `properties`
(`statusCode`, `serviceRequestId`, `eventCategory`, `entity`, `message`, `hierarchy`, plus
`requestbody` / `responseBody` / `statusMessage`).

Each write, delete or action is a **Started** record followed by **Succeeded** or **Failed**
under one `correlationId`, ending at or before now.

`identity.authorization` carries the scope, action and RBAC evidence: role, assignment scope,
the built-in role definition id and principal type. `identity.claims` carries the full ARM-token
claim set from Microsoft's sample: `objectidentifier`, the xmlsoap `name` and `upn`, `puid`,
`tenantid`, `scope`, `appid`, `idtyp`, and `onprem_sid` when the CIE identity map supplies one.
A canary carrying only `upn`/`name`/`appid` was attributed to the app id, not the user. With
the full set (canary 2026-10-22) the user record came back fully enriched: `identity_name` is
the UPN, username and domain are filled, and the asset type is `AZURE_ACTIVE_DIRECTORY_USER`.
A service principal shows as `Application` / `ServicePrincipal` by object id. Started
normalises to `PENDING` and Succeeded to `Success`.

The `msft_azure_raw` modeling rule deliberately leaves `xdm.source.user` empty for streamed
Administrative/Policy/Alert records. The Cloud analytics read the identity from
`cloud_audit_logs`, not from XDM.

## The estate (`modules/azure_estate.py`)

Deterministic, so resources recur as in a real tenant:

- Four subscriptions: `examplecorp-prod`, `-nonprod`, `-shared-services` and `-data`, under a
  management-group tree that `properties.hierarchy` reflects.
- Named resource groups per workload (`rg-web-prod`, `rg-network-shared`, ...).
- A stable pool of each resource type with CAF-style names (`vm-web-prod-01`,
  `stdataprod85403`, `kv-security-prod-02`, `aks-aks-prod-01`).
- Regions per subscription, plus regions the estate never uses (for a dormant-region case).

## Callers

- **People** come from the shared identity model, by role: cloud/platform, network,
  security and data teams. Each uses the Azure Portal or CLI.
  - A caller with a live session on the activity bus acts from that session's egress IP, so an
    ARM change lines up with the same person's Entra sign-in, logon and firewall traffic.
  - Otherwise they act from their stable egress (`azure_common.egress`).
  - Human changes follow business hours.
- **Automation** runs around the clock:
  - Service principals: IaC deployments, pipelines, backup and monitoring integrations,
    egressing from Microsoft AS8075 blocks.
  - User-assigned managed identities: automation jobs and the AKS agent pool.

## Benign traffic

Administrative, Policy, ServiceHealth, ResourceHealth, Alert, Autoscale and Recommendation
records, plus kube-audit. The mix:

- **Curated recurring operations** (about 40), each run by the team that owns it:
  deployments, tags, VM start/restart, App Service config and slot swaps, node-pool scaling,
  monitoring components and alert rules, private endpoints and private DNS, policy
  assignments, SQL firewall rules and databases, Data Factory pipelines, ML compute.
- **The long tail:** any of the 3,575 benign operations in `azure_activity_catalog`
  (Microsoft's documented write/delete/action operations for 38 providers).
- **Automation** service-principal and managed-identity operations.
- **Policy evaluations:** compliance scans by Policy Insights and deployment-time evaluations.
  Audit is `Warning`; Deny is `Error`/`Failure`.
- **Platform events:**
  - Service Health incidents, maintenance, advisories.
  - Resource Health activated/resolved.
  - Metric alerts activated/resolved.
  - Autoscale up/down.
  - Advisor recommendations.
- **Data-plane resource logs** (`modules/azure_dataplane.py`), modeled on Microsoft's documented
  event-hub schemas:
  - **Storage blob access** (`StorageRead` / `StorageWrite` / `StorageDelete`): apps and managed
    identities reading and writing their own blobs, a little admin access, read-heavy. OAuth is the
    benign baseline; targeted scenarios also model `AccountKey` and `SAS` authentication and expose
    `AuthenticationType` for detections that distinguish those modes.
  - **Key Vault** (`AuditEvent`): secret/key gets and lists, sign/wrap/unwrap, by app and managed
    identities. The bulk retrieval scenario uses a nonstandard identity so rare-identity and volume
    detections can be exercised; benign traffic has no bulk enumeration.
  - **Azure AI / Cognitive Services** (`RequestResponse`): model invocations
    (`ChatCompletions_Create`, `Embeddings_Create`, ...) by application identities against known
    deployments. No model discovery, no abnormal volume. `Models_List` is the documented Azure
    OpenAI model-enumeration operation and is emitted under the `Audit` category.
- **AKS audit** (`modules/aks_audit.py`): controllers, the scheduler, kubelets and workloads
  reading and watching, lease renewals, node status patches, events, CI rolling deployments by
  patch, and platform engineers' read-only kubectl.
  The same canary confirmed these reach `cloud_audit_logs`, parsed from the inner audit event:
  `event_id` is the `auditID`, the operation is the request URI, and the identity is the
  Kubernetes user. User agent, source IP and the cluster (as referenced resource) come through
  too. `log_name` is empty for them.

Targeted vendor-compatibility scenarios include AKS secret reads with a Python HTTP client user
agent, five denied API list requests by one service account across distinct Kubernetes resource
types, and an explicit Azure Firewall rule-collection-group delete operation. These are separate
from the benign baseline. `wip_storage_shared_key_access` and `wip_storage_sas_access` emit the
respective Storage authentication type without fabricating an OAuth RBAC decision.

About 6% of benign human changes fail (authorization denied, conflict, bad request, not found,
locked scope), with Azure-style error messages. Forced ARM threat scenarios are successful
mutations and emit `Started` plus a correlated terminal success record.

Operations an XSIAM analytic raises on by itself (`azure_activity_catalog.ALERTING_PREFIXES`:
NSG/firewall/VNet/VPN/DNS-zone changes, Key Vault, storage account settings, VM
create/stop/delete/run-command/extensions, snapshots, role assignments, locks, diagnostic
settings, automation runbooks, and so on) never appear in benign traffic. Kubernetes creates of
secrets, configmaps, workloads, RBAC, namespaces and service accounts, exec, ephemeral
containers and permission self-reviews stay out of the kube-audit baseline for the same reason.
The data-plane baselines likewise leave out what their detectors key on: first-time or backup
storage access, foreign-account copy, anonymous access (Storage); bulk secret enumeration (Key
Vault); model discovery and denial-of-wallet volume (AI).

## Ingestion note

Storage, Key Vault and AI records are resource logs in categories outside the Entra set, so the
`msft_azure_raw` modeling rule maps them through its generic resource-log path (caller IP,
resource id, operation, outcome). A 3-record canary (2026-10-23) confirmed all three reach
`cloud_audit_logs` as `azure_audit_logs`: Storage normalises to `resource_type` CloudStorage
(operation GetData), Key Vault to KMS/VAULTS, and AI to MachineLearning with `service_type`
"AI/ML Audit". Caller IP comes through. Azure OpenAI Entra identity is represented by
`properties.objectId` in published samples, rather than a top-level identity object.

## Schema review (2026-10-23)

The review compared Event Hub wire records with Microsoft's service-specific schemas, rather than
using normalized XSIAM column types as a proxy for the original JSON. The following corrections are
now in the generators:

| Feed | Corrections |
|---|---|
| Activity Log | Event Hub resource-log severity uses `Informational`; RBAC authorization evidence keeps canonical hyphenated UUIDs for assignment, definition, and principal IDs. The resource-log common schema allows `Informational`, `Warning`, `Error`, or `Critical`. |
| Storage Blob | Inner `identity.type` uses `OAuth`, `Account Key`, or `SAS Key`; `tokenHash` is synthetic SHA-256 in the documented format; role IDs are canonical UUID strings; single-request `operationCount` is `0`; list/service/container/block-list operations use matching request URIs; response type/status text follow the result class. |
| Key Vault | Request URI and returned object ID match the operation family (vault, secret, key, or certificate); `VaultGet` uses the documented 2015-06-01 control endpoint form, while data-plane operations use version 7.4; failed requests report `Failure`. `durationMs` remains a string because Microsoft's Key Vault sample encodes it that way. |
| Microsoft Graph Activity Logs | `durationMs` is numeric, `operationVersion` follows `/v1.0/` or `/beta/`, daemon auth method is client-secret by default (with an explicit certificate override), and `signInActivityId` links to the sign-in's `uniqueTokenIdentifier` when available. |
| Entra Audit Event Hub copy | The envelope includes a mapped `resultType` (`Success`, `Failure`, or `Timeout`) from the directory audit result. |
| AKS audit | JSON Patch request bodies remain arrays, while the successful response is a Kubernetes resource object; the builder no longer treats a patch array as a mutable response object. |

Primary references: [Azure Activity Log schema](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log-schema), [resource-log common schema](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-schema), [Storage Blob schema](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference), [StorageBlobLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs), [Key Vault logging schema](https://learn.microsoft.com/en-us/azure/key-vault/general/logging), [Microsoft Graph Activity Logs](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview), [Entra activity-log schemas](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas), [AKS monitoring/audit policy](https://learn.microsoft.com/en-us/azure/aks/monitor-aks?tabs=cilium), and [Kubernetes Audit Event API](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/).

Remaining schema boundary: Azure AI diagnostic properties vary by resource/API version and are not
specified in one Microsoft Event Hub sample as fully as Storage or Key Vault. The builder matches
the published Azure OpenAI diagnostic field family and the previously ingested canary; validate it
against the tenant's configured Cognitive Services category before widening the event set. Event
Hub wrappers also differ from Log Analytics table rows, so wire types must be reviewed before
interpreting XSIAM's normalized types. No new tenant records were sent during this review.

## Threat scenarios and Cortex detector coverage

`modules/azure_activity.py` now exposes 143 forced scenarios covering Azure Activity ARM operations, AKS kube-audit, Storage Blob, Key Vault, and Azure AI resource logs. Related detectors that require Entra `AuditLogs`, `SignInLogs`, Microsoft Graph activity, or Microsoft 365 SharePoint/OneDrive Graph activity use their owning generators in `azuread_audit.py`, `azuread_signin.py`, and `o365_sharepoint.py`. Across those modules, All 186 Cortex Azure Audit Log index entries now have a same-title scenario mapping, including the AD FS Hybrid Health server-registration operation. Other mappings remain provisional pending alert attribution and detector-profile prerequisites.

The row-by-row inventory is in [azure-audit-detector-inventory.md](azure-audit-detector-inventory.md). It records each detector's source requirements, activation and training windows, test window, severity, event family, inferred prerequisites, scenario key, and synopsis. The transport and remaining attribution gaps are summarized in [azure-detector-delivery-gaps.md](azure-detector-delivery-gaps.md). Detector pages expose descriptions and prerequisites, not the full analytic query; same-title mappings therefore do not establish exact query compatibility. Profiling alerts also need the stated activation/training history, and multi-event alerts need all events within the detector's window.

Coverage spans:

- Azure Activity Log categories and ARM operations, including network/security changes, RBAC, compute, storage configuration, logging/diagnostics, automation, Event Hubs, SQL, Key Vault configuration, Azure AI safeguards, packet capture, and backup-policy changes.
- AKS kube-audit objects and API behaviors, including RBAC, secrets, workloads, privileged pod settings, enumeration, denied requests, external service accounts, and cluster lifecycle.
- Storage Blob access, copy, enumeration, bulk downloads, protection settings, and dataset-object changes; Key Vault AuditEvent operations; Azure AI model/file requests.
- Entra directory and sign-in events plus Microsoft Graph request records, including identities, app permissions, unusual sign-ins, Graph enumeration, throttling, denied requests, mailbox enumeration and inbox-rule creation. M365 Graph storage events are covered by the SharePoint/OneDrive module.

The only index entry without a scenario mapping is **“A New Server was Added to an Azure Active Directory Hybrid Health ADFS Environment.”** It describes Azure AD Hybrid Health/AD FS server telemetry; the current Azure Activity and Entra audit generators do not have a documented event shape for that source. The inventory marks this row as blocked rather than substituting an unrelated ARM or directory event. Other source-specific detectors such as Exchange mailbox telemetry are mapped only where the existing Graph request logs can express the operation; detector query or profile behavior may still require additional sources.

No new live events were sent during this inventory/build pass. Existing prior canary records are not evidence that these scenario-specific alerts fired. A limited live verification still needs an approved canary batch, followed by read-only checks in `msft_azure_raw`, `cloud_audit_logs`, and the alerts dataset.

## Validation

Earlier validation established that the module imported, scenario functions returned records,
and representative canaries reached the tenant. It did not compare every field to an authoritative
service sample or establish that each threat scenario fires its named analytic. Earlier canaries covered representative Activity, AKS, Storage, Key Vault, and AI ingestion. Earlier review exercised registered scenario-to-alert paths across Azure Activity, Entra Audit, Entra SignIn, and SharePoint/Graph with transport routing stubbed. That confirms local record generation only; it does not prove detector firing.

The 2026-10-23 schema pass additionally passed `py_compile`, the 45-scenario/10-case AKS shape
check, the 143 Azure on-demand catalog checks, training determinism (60/70/963/1,376 events),
threat-level alignment across all 20 modules, the 49-case API contract, and cardinality-pool
guards. The detection compatibility scan still reports its three documented Cisco-only baseline
failures; it reports no Azure rule as unsatisfiable. These offline checks do not replace a
field-by-field inspection of a fresh tenant raw record or an alert-firing test.

The benign Activity Log category mix now includes all eight documented categories: Administrative, Security, ServiceHealth, ResourceHealth, Alert, Autoscale, Recommendation, and Policy. The Security builder follows Microsoft’s Defender for Cloud Activity Log example fields (Security category, Activate Alert operation, active status, severity, compromised entity, and remediation steps); it is a schema fixture, not a claim that Defender generated the alert.

### AKS kube-audit fidelity

AKS diagnostic `kube-audit` events use the Event Hub envelope (`operationName` for
`Microsoft.ContainerService/managedClusters/diagnosticLogs/Read`, `category: kube-audit`, cluster
`resourceId`, and `properties.log` containing a JSON-serialized `audit.k8s.io/v1` Event). The inner
event carries `auditID`, stage and timestamps, request URI, user/groups, source IPs, user agent,
object reference, response status, and authorization annotations. This shape follows the Microsoft
[AKS monitoring example](https://learn.microsoft.com/en-us/azure/aks/monitor-aks?tabs=cilium) and
the Kubernetes [Audit Event API](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/).

The generator applies the relevant exceptions from AKS's documented Microsoft-managed audit
policy: secret, ConfigMap, service-account and token-review records are `Metadata`; event writes are
logged at `Metadata` only in `default` and `kube-system`, while event `delete` and `list` are
metadata-only elsewhere; other event operations are suppressed. Kubelet/node `get` requests for
nodes are suppressed, ordinary API reads are `Request`, and configured API writes generally use
`RequestResponse`; node/pod status updates by node identities use `Request`. Body fields are omitted
at `Metadata`, response bodies are omitted at `Request`, and failed authorization records have a
403 response with `authorization.k8s.io/decision=forbid`. Exec uses the streaming
`ResponseStarted` stage, HTTP 101, a `pods/exec` subresource URI and its command/TTY query fields.
Ephemeral container updates target `pods/ephemeralcontainers`; SelfSubjectRulesReview is a
cluster-scoped API path whose target namespace belongs in its request body. These details matter
because Cortex and third-party rules inspect the serialized Kubernetes event, not only the Azure
wrapper. Microsoft-managed policy exceptions may change over time and are not user-configurable in
AKS, so the levels are an explicit approximation rather than proof of byte-for-byte parity.

Offline shape validation checks all 45 AKS Cortex inventory mappings and focused cases for event
schema, URI/object-reference consistency, policy-level body presence, policy-suppressed operations,
denials, exec/ephemeral/RBAC request paths, and timestamp ordering. This does not establish that a
tenant's Cortex analytic emitted an alert.

The operation-specific threat builders also emit account-level Storage network ACL changes that
allow public network access, a batch of five distinct VM allocations by one identity, correlated
cross-subscription blob-copy records (`CopyBlobSource` and `CopyBlob`), and AI file-content downloads
using `Files_GetFileContent`. AI request-spike records now hold the account, caller, and deployment
constant across the burst. These shapes match the documented operation and fields; detector firing
remains unverified without a tenant-side alert and profile history.

This source review cross-checks the Event Hub envelope and key service-specific fields against
Microsoft's resource-log schema, Activity Log schema, Storage Blob log reference, Key Vault
AuditEvent example, Foundry diagnostic logging guide, and AKS monitoring reference. Elastic's
Activity Logs integration independently documents Event Hub ingestion and parses authorization
evidence and claims. Splunk's Azure ingestion documentation corroborates the streamed Activity
fields and search mappings. Vendor parsers establish broad compatibility expectations, but do not
guarantee each synthetic event matches this tenant's exact detections.

Checks run for this review:

- Python compilation and module import, including catalog assertions for benign operations.
- All registered scenario-to-alert generation paths in Azure Activity, Entra Audit, Entra SignIn, and SharePoint/Graph were exercised locally with transport routing stubbed (dry run).
- Shape assertions for correlated ARM `Started`/terminal pairs, Storage OAuth principal and RBAC
  authorization fields, Shared Key/SAS authentication fields, distinct Key Vault secret URIs, AI category fields, suspicious AKS user-agent and denied-enumeration audit JSON.
- Repository deterministic-training, threat-level alignment, on-demand catalog, API contract, and
  cardinality-pool validators.

Limitations: Activity `durationMs=0` and the streamed Administrative envelope follow Microsoft's
Activity Log mapping. Storage uses the documented `identity.authorization.principals` shape and
data-plane Blob roles. Key Vault uses documented ObjectVerb operations and the sample's identity,
URI, and property structure. AI `Audit` and `RequestResponse` categories and common resource-log
fields are documented. A public Azure OpenAI example confirms `Models_List`, result signature,
caller IP, `properties.objectId`, API version, model deployment/name/version, and request/response
length and times. The generator now follows those fields. The example is a Log Analytics view of
the event and does not prove every Event Hub raw-field detail or XSIAM mapping. `wip_` marks
detector-level matching as unconfirmed.

**Confirmed firing (promoted out of `wip_`, 2026-10-23/24 fire-all).** These ten scenarios were
observed raising their alert on this feed's data, so they carry plain keys and their
`ANALYTIC_ALERTS` value is the tenant's observed name; the old `wip_` names still resolve on
demand via `_RENAMED_THREATS`:
`firewall_policy_delete` (An Azure Firewall policy deletion), `network_watcher_delete` (Azure
Network Watcher Deletion), `alert_rule_delete` (Unusual Azure Monitor alert rule deletion),
`eventhub_delete` (Azure Event Hub Deletion), `vm_command` (Unusual Azure VM remote command
execution), `ai_safeguard_delete` (AI safeguards were successfully deleted), `ai_safeguard_modify`
(Unusual modification of AI safeguards), `kube_anonymous` (A Kubernetes API operation was
successfully invoked by an anonymous user), `kube_node_external` and `kube_dashboard_external`
(the Kubernetes service-account-outside-cluster detections). Everything else stays `wip_` until
its own alert is observed.

Sources:

- [Microsoft Azure Activity Log event schema](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log-schema)
- [Microsoft Azure resource logs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-schema)
- [Microsoft Storage Blob monitoring reference](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference)
- [Microsoft StorageBlobLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs)
- [Microsoft cross-account blob copy logging](https://learn.microsoft.com/en-us/azure/storage/common/security-restrict-copy-operations)
- [Microsoft Files - Get Content REST API](https://learn.microsoft.com/en-us/rest/api/azureopenai/files/get-content?view=rest-azureopenai-2024-10-21)
- [Microsoft Defender for Cloud alert schema](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-schemas)
- [Microsoft Key Vault logging](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)
- [Microsoft Foundry diagnostic logging](https://learn.microsoft.com/en-us/azure/foundry/how-to/diagnostic-logging)
- [Microsoft AKS monitoring reference](https://learn.microsoft.com/en-us/azure/aks/monitor-aks-reference)
- [Zscaler: monitoring Azure OpenAI abuse (example events and detector queries)](https://www.zscaler.com/blogs/cybersecurity-best-practices/azure-openai-abuse)
- [Elastic Azure OpenAI integration](https://www.elastic.co/docs/reference/integrations/azure_openai)
- [Elastic Azure Activity Logs integration](https://www.elastic.co/docs/reference/integrations/azure/activitylogs)
- [Splunk Azure source types and sample events](https://help.splunk.com/en/data-management/ingest-data-from-cloud-sources/use-data-inputs/1.17/getting-data-in-gdi/overview-of-source-types-for-data-inputs)
