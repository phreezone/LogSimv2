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
A canary carrying only `upn`/`name`/`appid` was attributed to the app id, not the user.

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
- **AKS audit** (`modules/aks_audit.py`): controllers, the scheduler, kubelets and workloads
  reading and watching, lease renewals, node status patches, events, CI rolling deployments by
  patch, and platform engineers' read-only kubectl.

About 6% of human changes fail (authorization denied, conflict, bad request, not found,
locked scope), with Azure's own error messages.

Operations an XSIAM analytic raises on by itself (`azure_activity_catalog.ALERTING_PREFIXES`:
NSG/firewall/VNet/VPN/DNS-zone changes, Key Vault, storage account settings, VM
create/stop/delete/run-command/extensions, snapshots, role assignments, locks, diagnostic
settings, automation runbooks, and so on) never appear in benign traffic. Kubernetes creates of
secrets, configmaps, workloads, RBAC, namespaces and service accounts, exec, ephemeral
containers and permission self-reviews stay out of the kube-audit baseline for the same reason.

## Threats

None yet: `SCENARIOS` and `ANALYTIC_ALERTS` are empty, so every threat level emits benign
traffic and nothing is offered on demand. The target detectors (the Cortex "Azure Audit Log"
list) and the operations each keys on are mapped in the session notes. New scenarios should
use the `wip_` key prefix until their analytic is seen firing.

## Validation

`python -c "from modules import azure_activity"` asserts at import that every curated and
automation operation exists in the catalog and is not an alerting operation. The standard
`_local_validation` suite covers the module through the module loader.
