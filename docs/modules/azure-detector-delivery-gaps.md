# Azure detector delivery and remaining gaps

Updated 2026-10-23 after the 198-path low-rate smoke batch. This note separates event generation and routing from Cortex alert evaluation: HTTP acceptance and ingestion prove delivery, while named-alert attribution proves only the specific tested detector path.

## Source routing already implemented

| Event family | Generator | Destination path | Smoke evidence |
|---|---|---|---|
| Azure Activity ARM Administrative and platform categories | `modules/azure_activity.py` | Azure Event Hubs Source-Identifier `fce13a1d51294f84bae4a37851503060` -> `msft_azure_raw` -> `cloud_audit_logs` / `azure_audit_logs` | The Firewall policy deletion alert matched the generated operation and caller. |
| AKS API-server audit | `modules/aks_audit.py`, called by `azure_activity` | `kube-audit` category in the same Event Hub feed | Anonymous API activity generated a matching alert. |
| Storage Blob data plane | `modules/azure_dataplane.py` | `StorageRead` / `StorageWrite` / `StorageDelete`, routed to the same Event Hub source | Records were accepted; this run did not attribute an alert to a Storage scenario. |
| Key Vault data plane | `modules/azure_dataplane.py` | `AuditEvent` with Key/Secret/Certificate ObjectVerb operations, routed to Event Hub | Records were accepted; no Key Vault target alert was observed. |
| Azure AI data plane | `modules/azure_dataplane.py` | `Audit` / `RequestResponse`, routed to Event Hub | Records were accepted; no AI target alert was observed in this run. |
| Entra directory audit and sign-ins | `modules/azuread_audit.py`, `modules/azuread_signin.py` | Native datasets plus Event Hub diagnostic copies; `eventhub_copies` is enabled | The unverified-domain alert appeared during the run. |
| Graph activity | `modules/graph_activity.py`, attached by Entra/SharePoint generators | `MicrosoftGraphActivityLogs` Event Hub records | Ingested as Microsoft Graph Activity logs; no other target name was attributed in this window. |
| SharePoint Online audit | `modules/o365_sharepoint.py` | SharePoint native dataset plus Graph companions for mapped scenarios | Ingested; no SharePoint detector name was observed in the window. |

Azure Activity ARM rows do not need an additional Event Hub copy flag: their module's default source identifier is already the Azure Event Hubs source. `eventhub_routed` in the smoke report counts records with an explicit cross-destination route marker; zero for an ARM record does not mean it bypassed Event Hubs.

## Changes from the audit

- Added the previously unmapped `A New Server was Added to an Azure Active Directory Hybrid Health AD FS Environment` scenario. It emits `Microsoft.ADHybridHealthService/services/servicemembers/action` with an `AdFederationService` resource path. The operation and resource predicate are corroborated by Microsoft's Azure Activity analytic rule and the RBAC operation catalog. This is synthetic event construction only; no AD FS or Azure control-plane operation is performed.
- Corrected the detector inventory labels for AKS, Storage Blob, Key Vault, and AI scenarios so the documented event family matches the actual generator. Some storage/key-vault detections use ARM configuration events; the data-plane-specific scenarios use service diagnostic categories.
- Updated module and README coverage to 140 Azure Activity scenarios and 186/186 inventory entries mapped across Azure Activity plus adjacent Entra/Graph/M365 modules.

## Remaining gaps

1. **Alert attribution is sparse.** The smoke batch produced two Azure Activity target names and one adjacent Entra target name. The other 189 distinct target names in the run were not observed. This is not proof that each event was malformed: most Cortex pages specify 14-day activation and 30-day training periods, and several require 10-minute/1-hour sequences or identity/resource history. The API's alert list does not establish that an absent target is a shape failure.
2. **Data-plane ingestion needs field-level confirmation.** HTTP 200 and row presence in the raw feed do not prove that each Storage/Key Vault/AI event normalized to the exact fields its analytic reads. A dedicated read-only query should check category, operation, caller identity, resource ID, result, and service-specific properties per event marker before attempting more alert tuning.
3. **Event Hub vs. native-source eligibility is detector-specific.** Entra copies and Graph companions are already enabled. Some Microsoft 365 detections need the SharePoint/Exchange/DLP feed itself; a Graph companion cannot stand in for that workload audit record. Other detectors explicitly require kube-audit or resource data-plane categories. Do not duplicate every event to every source identifier.
4. **Some Cortex query predicates are not public.** The inventory notes where the public alert description does not expose exact operation filters. Those mappings need a controlled one-scenario-at-a-time alert check after the destination dataset/fields and profile prerequisites are confirmed.
5. **External/system event domains remain outside this generator.** Events whose semantics require actual AD FS server telemetry, external partner/cloud audit feeds, or Cortex-trained identity/resource baselines cannot be made equivalent by renaming an Azure Activity record. They require the appropriate synthetic source event family or tenant history.

## Source references

- [Azure Activity log schema](https://learn.microsoft.com/azure/azure-monitor/fundamentals/activity-log-schema)
- [Microsoft Sentinel AD FS Hybrid Health new-server analytic](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Activity/Analytic%20Rules/NRT-AADHybridHealthADFSNewServer.yaml)
- [Microsoft Azure RBAC control-plane operation catalog](https://learn.microsoft.com/azure/role-based-access-control/permissions/identity)
- [Cortex AD FS Hybrid Health detector](https://cortex-docs.paloaltonetworks.com/analytics-alerts/alerts-by-name/a-new-server-was-added-to-an-azure-active-directory-hybrid-health-adfs-environment)
- [Row-by-row detector inventory](azure-audit-detector-inventory.md)
