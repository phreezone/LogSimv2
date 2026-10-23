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
    identities reading and writing their own blobs, a little admin access, read-heavy. OAuth only,
    known accounts.
  - **Key Vault** (`AuditEvent`): secret/key gets and lists, sign/wrap/unwrap, by app and managed
    identities. No bulk enumeration of distinct secrets (the dump pattern).
  - **Azure AI / Cognitive Services** (`RequestResponse`): model invocations
    (`ChatCompletions_Create`, `Embeddings_Create`, ...) by application identities against known
    deployments. No model discovery, no abnormal volume.
- **AKS audit** (`modules/aks_audit.py`): controllers, the scheduler, kubelets and workloads
  reading and watching, lease renewals, node status patches, events, CI rolling deployments by
  patch, and platform engineers' read-only kubectl.
  The same canary confirmed these reach `cloud_audit_logs`, parsed from the inner audit event:
  `event_id` is the `auditID`, the operation is the request URI, and the identity is the
  Kubernetes user. User agent, source IP and the cluster (as referenced resource) come through
  too. `log_name` is empty for them.

About 6% of human changes fail (authorization denied, conflict, bad request, not found,
locked scope), with Azure's own error messages.

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
"AI/ML Audit". Caller identity and IP come through (the app's Microsoft egress).

## Threat scenarios

`azure_activity` now has 64 forced threat scenarios, each with a Cortex Azure Audit Log target
in `ANALYTIC_ALERTS`. All scenario keys use the `wip_` prefix because the published target is
identified but a corresponding synthetic alert has not yet been confirmed in this tenant. The
usual threat gate controls ambient generation; a specific scenario can be forced by its key.
Nothing in this module sends automatically to the tenant unless the simulator is configured for
live Cribl transport.

Coverage in this first scenario set:

- 43 ARM control-plane targets: network and firewall changes, diagnostic/logging changes, RBAC,
  compute lifecycle and execution, storage configuration, Event Hub, SQL export, AKS, Key Vault,
  automation, and related operations. Mutations emit correlated `Started` plus terminal records;
  denied variants emit the single Azure `Failed` record.
- 13 AKS audit targets: anonymous access, secrets/configmaps, workloads, RBAC, namespace and
  service-account changes, job/controller creation, exec, and ephemeral containers.
- 8 Storage, Key Vault, and Azure AI targets using the resource-log builders in
  `modules/azure_dataplane.py`.

The Cortex Azure Audit Log index currently lists 186 alert names. This 64-scenario set is a
partial mapping, not complete coverage. Profiling and multi-event detections still need suitable
history or sequences; Entra directory/Graph and Microsoft 365 detections need their corresponding
feeds; additional single-event targets need exact operation and field matching before they are
registered. `wip_` indicates the emitted shape still needs tenant alert verification.

## Validation

`python -c "from modules import azure_activity"` asserts at import that every curated and
automation operation exists in the catalog and is not an alerting operation. The standard
`_local_validation` suite covers the module through the module loader.
