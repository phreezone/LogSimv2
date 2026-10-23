"""Azure Activity log (Azure Monitor diagnostic settings -> Event Hubs) -> msft_azure_raw, via the
cribl_direct transport under the Azure Event Hubs Source-Identifier.

Records follow the resource-log schema Microsoft documents for an Activity log streamed to an event
hub: time, resourceId, operationName, category, resultType, resultSignature, durationMs (always
0), callerIpAddress, correlationId, identity{authorization, claims}, level, location ("global"),
properties{statusCode, serviceRequestId, eventCategory, entity, message, hierarchy, ...}.
resourceId and operationName are upper-cased as the streamed records carry them. XSIAM files them
in cloud_audit_logs as log_name azure_audit_logs (verified with a canary on 2026-10-21).

  * Administrative: write/delete/action operations on a stable estate (modules/azure_estate.py)
    -- a curated set of the operations a real platform team runs every day, plus the long tail of
    Microsoft's documented operations (azure_activity_catalog). Each emits Started then
    Succeeded/Failed under one correlationId, as Azure does; a realistic minority fail.
  * Policy, ServiceHealth, ResourceHealth, Alert, Autoscale and Recommendation events with the
    operation names and value sets of Microsoft's Activity log schema.
  * kube-audit: AKS API-server audit records streamed from the clusters' diagnostic settings
    (modules/aks_audit.py).

Operations an XSIAM analytic raises on by itself (azure_activity_catalog.ALERTING_PREFIXES) never
appear in benign traffic; the threat scenarios emit them. Callers are the Azure-operating roles
of the shared identity model, correlated with the activity bus; automation runs as service
principals and managed identities around the clock. Human activity follows business hours.
"""
import datetime
import json
import random
import time
import uuid

from modules import azure_common as ac
from modules import aks_audit as aks
from modules import azure_activity_catalog as cat
from modules import azure_dataplane as dp
from modules import azure_estate as ae

NAME = "Azure Activity"
DESCRIPTION = ("Simulates the Azure Activity log (Event Hubs resource-log schema) and AKS kube-audit "
               "for msft_azure_raw via the cribl_direct transport.")
CONFIG_KEY = "azure_activity_config"
SOURCE_IDENTIFIER = "fce13a1d51294f84bae4a37851503060"
INTEGRATION_IDENTIFIER = "logsim:azure_activity"
DATASET = "msft_azure_raw"


def _ts(offset_s=0.0):
    d = datetime.datetime.fromtimestamp(time.time() + min(0.0, offset_s), datetime.timezone.utc)
    return f"{d:%Y-%m-%dT%H:%M:%S}.{d.microsecond:06d}{random.randint(0, 9)}Z"


# ── resource ids for any documented operation ──────────────────────────────────────────
# Providers whose resources live at subscription scope rather than in a resource group.
_SUB_SCOPED = {"microsoft.authorization", "microsoft.security", "microsoft.advisor",
               "microsoft.policyinsights", "microsoft.costmanagement", "microsoft.support",
               "microsoft.features"}
# Child resources whose name Azure fixes.
_FIXED_CHILD = {"blobservices": "default", "fileservices": "default", "queueservices": "default",
                "tableservices": "default", "config": "web", "managementpolicies": "default",
                "advancedthreatprotectionsettings": "current", "auditingsettings": "default",
                "securityalertpolicies": "default", "backupshorttermretentionpolicies": "default",
                "transparentdataencryption": "current", "providers": "Microsoft.Insights"}


def split_op(op):
    """'Microsoft.Web/sites/slots/slotsswap/action' -> ('Microsoft.Web', ['sites', 'slots'], 'action', 'slotsswap')."""
    parts = op.split("/")
    provider, verb = parts[0], parts[-1].lower()
    if verb == "action" and len(parts) > 2:
        return provider, parts[1:-2], verb, parts[-2]
    return provider, parts[1:-1], verb, None


def resource_for(op, sub, rnd=None):
    """A resource id on the estate for an operation, and its top-level type."""
    r = rnd or random
    provider, types, _verb, _action = split_op(op)
    pl = provider.lower()
    if pl == "microsoft.resources":
        rg = r.choice(ae.resource_groups(sub))
        if types[:1] == ["subscriptions"] or not types:
            return f"/subscriptions/{sub['id']}/resourceGroups/{rg}", "resourceGroups"
        name = "default" if types[0].lower() == "tags" else f"{rg}-{types[0][:6].lower()}-{r.randint(1, 40):02d}"
        return f"/subscriptions/{sub['id']}/resourceGroups/{rg}/providers/{provider}/{types[0]}/{name}", types[0]
    if pl == "microsoft.management":
        return f"/providers/Microsoft.Management/managementGroups/{r.choice(sub['mgs'])}", "managementGroups"
    if not types:
        return ae.sub_rid(sub), "subscriptions"
    chain = []
    for i, t in enumerate(types):
        if t.lower() == "locations":
            name = ae.region(sub, r)
        elif i == 0:
            name = ae.pick_name(sub, t, r)
        else:
            name = _FIXED_CHILD.get(t.lower()) or f"{ae.abbr(t)}-{r.randint(1, 6):02d}"
        chain += [t, name]
    if pl in _SUB_SCOPED:
        return ae.sub_rid(sub, provider, *chain), types[0]
    return ae.rid(sub, provider, *chain), types[0]


# ── record builders ────────────────────────────────────────────────────────────────────
_RESULT_TYPE = {"Started": "Start", "Accepted": "Accept", "Succeeded": "Success", "Failed": "Failure"}


def _evidence(caller, sub, role):
    who = caller.get("upn") or caller.get("name")
    return {"role": role, "roleAssignmentScope": f"/subscriptions/{sub['id']}",
            "roleAssignmentId": ae.hex32(f"ra:{who}:{role}:{sub['id']}"),
            "roleDefinitionId": ae.ROLES.get(role, ae.ROLES["Contributor"]).replace("-", ""),
            "principalId": caller["oid"].replace("-", ""),
            "principalType": "User" if caller["kind"] == "User" else "ServicePrincipal"}


def record(op, resource_id, caller, sub, *, status="Succeeded", code="OK", role="Contributor",
           offset_s=0.0, corr=None, request_body=None, response_body=None, error=None,
           level=None, extra_props=None):
    """One Administrative Activity record in the event-hub resource-log shape."""
    props = {"eventCategory": "Administrative", "entity": resource_id, "message": op,
             "hierarchy": ae.hierarchy(sub)}
    if status != "Started":
        props = dict({"statusCode": code, "serviceRequestId": str(uuid.uuid4())}, **props)
    if request_body is not None:
        props["requestbody"] = json.dumps(request_body)
    if response_body is not None:
        props["responseBody"] = json.dumps(response_body)
    if error:
        props["statusMessage"] = json.dumps({"error": error})
    if extra_props:
        props.update(extra_props)
    sig = "Started." if status == "Started" else f"{status}.{code}"
    return {
        "time": _ts(offset_s), "resourceId": resource_id.upper(), "operationName": op.upper(),
        "category": "Administrative", "resultType": _RESULT_TYPE.get(status, status),
        "resultSignature": sig, "durationMs": 0, "callerIpAddress": caller.get("ip") or "",
        "correlationId": corr or str(uuid.uuid4()),
        "identity": {"authorization": {"scope": resource_id, "action": op,
                                       "evidence": _evidence(caller, sub, role)},
                     "claims": caller["claims"]},
        "level": level or ("Error" if status == "Failed" else "Information"),
        "location": "global", "properties": props}


# Write/delete/action outcome codes: PUT creates (Created) or updates (OK); long-running actions
# are accepted first (Accepted, then OK); deletes answer OK or NoContent.
def _success_code(op):
    verb = op.rsplit("/", 1)[-1].lower()
    if verb == "write":
        return random.choice(("OK", "OK", "Created"))
    if verb == "delete":
        return random.choice(("OK", "NoContent"))
    return "OK"


_FAILURES = [  # (weight, http code name, error code, message template)
    (5, "Forbidden", "AuthorizationFailed",
     "The client '{who}' with object id '{oid}' does not have authorization to perform action '{op}' "
     "over scope '{scope}' or the scope is invalid. If access was recently granted, please refresh "
     "your credentials."),
    (2, "Conflict", "Conflict", "Operation cannot be performed because another operation is in progress on the resource."),
    (2, "BadRequest", "InvalidRequestContent", "The request content was invalid and could not be deserialized."),
    (1, "NotFound", "ResourceNotFound", "The Resource '{scope}' under resource group was not found."),
    (1, "Conflict", "ScopeLocked", "The scope '{scope}' cannot perform write operation because it is locked."),
]


def _error(caller, op, scope, kind=None):
    pick = kind or random.choices(_FAILURES, weights=[f[0] for f in _FAILURES])[0]
    _w, code, ecode, msg = pick
    who = caller.get("upn") or caller.get("appid")
    return code, {"code": ecode, "message": msg.format(who=who, oid=caller["oid"], op=op, scope=scope)}


def operation(op, resource_id, caller, sub, *, role="Contributor", request_body=None,
              response_body=None, fail=False, fail_kind=None, offset_s=0.0, duration_s=None):
    """Started then Succeeded (or Failed) for one write/delete/action, as Azure logs it. The pair
    shares a correlationId and ends at offset_s (<= now)."""
    corr = str(uuid.uuid4())
    dur = duration_s if duration_s is not None else random.uniform(0.4, 25.0)
    start = record(op, resource_id, caller, sub, status="Started", role=role, corr=corr,
                   offset_s=offset_s - dur, request_body=request_body)
    if fail:
        code, err = _error(caller, op, resource_id, fail_kind)
        end = record(op, resource_id, caller, sub, status="Failed", code=code, role=role, corr=corr,
                     offset_s=offset_s, error=err)
    else:
        end = record(op, resource_id, caller, sub, status="Succeeded", code=_success_code(op),
                     role=role, corr=corr, offset_s=offset_s, response_body=response_body)
    return [start, end]


def denied(op, resource_id, caller, sub, *, offset_s=0.0):
    """An ARM call refused by RBAC: Azure logs only the failure (no Started record)."""
    code, err = _error(caller, op, resource_id, _FAILURES[0])
    return [record(op, resource_id, caller, sub, status="Failed", code=code, role="Reader",
                   offset_s=offset_s, error=err)]


# ── benign: curated recurring operations ───────────────────────────────────────────────
# What a platform team runs every day, by who runs it: (weight, operation, team, RBAC role).
# Every entry is a documented operation that no analytic raises on by itself (checked at import).
_TEAM_ROLES = {"cloud": ae.CLOUD_OPS, "net": ae.NET_OPS, "sec": ae.SEC_OPS, "data": ae.DATA_OPS}
_CURATED = [
    (8, "Microsoft.Resources/deployments/write", "cloud", "Contributor"),
    (3, "Microsoft.Resources/deployments/validate/action", "cloud", "Contributor"),
    (4, "Microsoft.Resources/tags/write", "cloud", "Contributor"),
    (3, "Microsoft.Compute/virtualMachines/start/action", "cloud", "Virtual Machine Contributor"),
    (3, "Microsoft.Compute/virtualMachines/restart/action", "cloud", "Virtual Machine Contributor"),
    (2, "Microsoft.Compute/disks/write", "cloud", "Virtual Machine Contributor"),
    (4, "Microsoft.Web/sites/restart/action", "cloud", "Website Contributor"),
    (4, "Microsoft.Web/sites/config/write", "cloud", "Website Contributor"),
    (2, "Microsoft.Web/sites/slots/slotsswap/action", "cloud", "Website Contributor"),
    (1, "Microsoft.Web/serverfarms/write", "cloud", "Website Contributor"),
    (2, "Microsoft.ContainerService/managedClusters/agentPools/write", "cloud", "Contributor"),
    (2, "Microsoft.Insights/components/write", "cloud", "Monitoring Contributor"),
    (1, "Microsoft.Insights/actionGroups/write", "cloud", "Monitoring Contributor"),
    (2, "Microsoft.Insights/metricAlerts/write", "cloud", "Monitoring Contributor"),
    (1, "Microsoft.Insights/autoscalesettings/write", "cloud", "Monitoring Contributor"),
    (1, "Microsoft.OperationalInsights/workspaces/savedSearches/write", "cloud", "Contributor"),
    (1, "Microsoft.Cache/redis/write", "cloud", "Contributor"),
    (1, "Microsoft.ServiceBus/namespaces/queues/write", "cloud", "Contributor"),
    (1, "Microsoft.EventHub/namespaces/eventhubs/write", "cloud", "Contributor"),
    (1, "Microsoft.Logic/workflows/write", "cloud", "Contributor"),
    (1, "Microsoft.ManagedIdentity/userAssignedIdentities/write", "cloud", "Contributor"),
    (0.5, "Microsoft.Support/supportTickets/write", "cloud", "Contributor"),
    (1, "Microsoft.Network/publicIPAddresses/write", "net", "Network Contributor"),
    (1, "Microsoft.Network/loadBalancers/write", "net", "Network Contributor"),
    (2, "Microsoft.Network/privateEndpoints/write", "net", "Network Contributor"),
    (2, "Microsoft.Network/privateDnsZones/A/write", "net", "Network Contributor"),
    (1, "Microsoft.Network/networkInterfaces/join/action", "net", "Network Contributor"),
    (1, "Microsoft.Security/pricings/write", "sec", "Security Admin"),
    (2, "Microsoft.Authorization/policyAssignments/write", "sec", "Security Admin"),
    (1, "Microsoft.Authorization/policyExemptions/write", "sec", "Security Admin"),
    (0.5, "Microsoft.Security/securityContacts/write", "sec", "Security Admin"),
    (2, "Microsoft.Sql/servers/firewallRules/write", "data", "SQL DB Contributor"),
    (2, "Microsoft.Sql/servers/databases/write", "data", "SQL DB Contributor"),
    (1, "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/write", "data", "Contributor"),
    (2, "Microsoft.DataFactory/factories/pipelines/write", "data", "Contributor"),
    (2, "Microsoft.DataFactory/factories/pipelines/createrun/action", "data", "Contributor"),
    (1, "Microsoft.MachineLearningServices/workspaces/computes/write", "data", "Contributor"),
    (1, "Microsoft.MachineLearningServices/workspaces/jobs/write", "data", "Contributor"),
]
# Automation identities and the operations they run on a schedule, around the clock.
_AUTOMATION = {
    "sp-terraform-platform": ("ServicePrincipal", ["Microsoft.Resources/deployments/write",
                              "Microsoft.Resources/deployments/validate/action", "Microsoft.Resources/tags/write"]),
    "sp-azdo-pipelines": ("ServicePrincipal", ["Microsoft.Web/sites/slots/slotsswap/action",
                          "Microsoft.Web/sites/config/write", "Microsoft.Web/sites/restart/action",
                          "Microsoft.ContainerRegistry/registries/importImage/action"]),
    "sp-backup-orchestrator": ("ServicePrincipal", [
        "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/backup/action"]),
    "sp-monitoring-integration": ("ServicePrincipal", ["Microsoft.Insights/metricAlerts/write",
                                  "Microsoft.Insights/actionGroups/write"]),
    "id-automation-ops": ("ManagedIdentity", ["Microsoft.Automation/automationAccounts/jobs/write",
                          "Microsoft.Compute/virtualMachines/start/action"]),
    "id-aks-prod-agentpool": ("ManagedIdentity", ["Microsoft.Network/loadBalancers/write",
                              "Microsoft.Network/publicIPAddresses/write"]),
    "id-func-data-ingest": ("ManagedIdentity", ["Microsoft.DataFactory/factories/pipelines/createrun/action"]),
}
_CANON = {o.lower(): o for ops in cat.OPERATIONS.values() for o in ops}
for _w, _op, _t, _r in _CURATED:
    assert _op.lower() in _CANON and not cat.is_alerting(_op), _op
for _n, (_k, _ops) in _AUTOMATION.items():
    for _op in _ops:
        assert _op.lower() in _CANON and not cat.is_alerting(_op), _op
_CURATED_W = [c[0] for c in _CURATED]

# Long-tail catalog draws, weighted toward the providers a platform team touches most.
_TAIL_PROVIDERS = {p: ops for p, ops in cat.BENIGN_OPERATIONS.items() if ops}
_TAIL_WEIGHT = {"Microsoft.Network": 6, "Microsoft.Web": 6, "Microsoft.Compute": 5, "Microsoft.Storage": 3,
                "Microsoft.Sql": 3, "Microsoft.Insights": 3, "Microsoft.ContainerService": 2,
                "Microsoft.Resources": 3, "Microsoft.Authorization": 1, "Microsoft.KeyVault": 1}
_TAIL_NAMES = sorted(_TAIL_PROVIDERS)
_TAIL_W = [_TAIL_WEIGHT.get(p, 1) for p in _TAIL_NAMES]
_DATA_PROVIDERS = {"Microsoft.Sql", "Microsoft.DataFactory", "Microsoft.MachineLearningServices",
                   "Microsoft.DocumentDB", "Microsoft.DBforPostgreSQL"}

_FAIL_RATE = 0.06


def _body(op, sub, rnd=None):
    """A small realistic request body for a PUT (location + tags), else None."""
    if not op.lower().endswith("/write"):
        return None
    r = rnd or random
    return {"location": ae.region(sub, r), "tags": {"env": sub["env"], "owner": "platform",
                                                    "costCenter": f"CC-{r.randint(100, 999)}"}}


def _human(config, context, op, team, role, sub=None):
    sub = sub or ae.pick_sub()
    caller = ae.pick_admin(config, _TEAM_ROLES[team], context)
    res, _t = resource_for(op, sub)
    return operation(_CANON[op.lower()], res, caller, sub, role=role, request_body=_body(op, sub),
                     fail=random.random() < _FAIL_RATE)


def _b_curated(config, context):
    _w, op, team, role = random.choices(_CURATED, weights=_CURATED_W)[0]
    return _human(config, context, op, team, role)


def _b_tail(config, context):
    prov = random.choices(_TAIL_NAMES, weights=_TAIL_W)[0]
    op = random.choice(_TAIL_PROVIDERS[prov])
    if prov == "Microsoft.Network" and random.random() < 0.6:
        team = "net"
    elif prov in _DATA_PROVIDERS:
        team = "data"
    else:
        team = "cloud"
    return _human(config, context, op, team, "Contributor")


def _b_automation(config, context):
    name = random.choice(list(_AUTOMATION))
    kind, ops = _AUTOMATION[name]
    sub = ae.pick_sub()
    caller = ae.app_caller(name, kind)
    op = random.choice(ops)
    res, _t = resource_for(op, sub)
    role = (ae.SERVICE_PRINCIPALS.get(name) or ae.MANAGED_IDENTITIES.get(name))["role"]
    return operation(_CANON[op.lower()], res, caller, sub, role=role, request_body=_body(op, sub),
                     fail=random.random() < 0.01)


# ── benign: the other Activity log categories ──────────────────────────────────────────
_POLICY_DEFS = [  # (display name, effect)
    ("Storage accounts should restrict network access", "audit"),
    ("Audit VMs that do not use managed disks", "audit"),
    ("Require a tag on resources", "deny"),
    ("Allowed locations", "deny"),
    ("Deploy Log Analytics agent for Linux VMs", "deployIfNotExists"),
    ("Configure diagnostic settings for Key Vaults to Log Analytics workspace", "deployIfNotExists"),
    ("Azure SQL Database should have Azure AD-only authentication enabled", "auditIfNotExists"),
    ("Add a tag to resources", "modify"),
    ("App Service apps should only be accessible over HTTPS", "audit"),
    ("Key vaults should have deletion protection enabled", "audit"),
]
_PI_APPID = "1d78a85d-813d-46f0-b496-dd72f50a3ec0"   # Microsoft Azure Policy Insights
_POLICY_INSIGHTS = {
    "kind": "ServicePrincipal", "name": "Microsoft Azure Policy Insights",
    "oid": ae.guid("policyinsights"), "appid": _PI_APPID, "ip": "",
    "claims": {"aud": "https://management.azure.com/", "iss": f"https://sts.windows.net/{ae.TENANT_ID}/",
               "appid": _PI_APPID, "appidacr": "2",
               "http://schemas.microsoft.com/identity/claims/identityprovider": f"https://sts.windows.net/{ae.TENANT_ID}/",
               "http://schemas.microsoft.com/identity/claims/objectidentifier": ae.guid("policyinsights"),
               "http://schemas.microsoft.com/identity/claims/tenantid": ae.TENANT_ID,
               "idtyp": "app", "ver": "1.0"}}


def _platform(sub, category, op, resource_id, result_type, level, props, claims=None, offset_s=0.0):
    """A non-Administrative Activity record (same envelope; category-specific properties)."""
    rec = {"time": _ts(offset_s), "resourceId": resource_id.upper(), "operationName": op.upper(),
           "category": category, "resultType": result_type, "resultSignature": "",
           "durationMs": 0, "callerIpAddress": "", "correlationId": str(uuid.uuid4()),
           "level": level, "location": "global",
           "properties": dict({"eventCategory": category, "entity": resource_id, "message": op,
                               "hierarchy": ae.hierarchy(sub)}, **props)}
    if claims is not None:
        rec["identity"] = {"claims": claims}
    return rec


def _b_policy(config, context):
    """An Azure Policy evaluation: a compliance scan by Policy Insights, or the evaluation riding on
    a deployment. Audit = Warning, Deny = Error/Failure, the rest Informational."""
    sub = ae.pick_sub()
    name, effect = random.choice(_POLICY_DEFS)
    op = random.choice(cat.BENIGN_OPERATIONS["Microsoft.Storage"] + cat.BENIGN_OPERATIONS["Microsoft.Web"]
                       + cat.BENIGN_OPERATIONS["Microsoft.Compute"])
    res, _t = resource_for(op, sub)
    scan = random.random() < 0.7
    caller = _POLICY_INSIGHTS if scan else ae.pick_admin(config, ae.CLOUD_OPS, context)
    if effect == "deny" and scan:
        effect = "audit"
    pdid = ae.guid("policydef:" + name)
    pa = ae.hex32("pa:" + name)[:24]
    policies = [{"policyDefinitionId": f"/providers/Microsoft.Authorization/policyDefinitions/{pdid}/",
                 "policyDefinitionName": pdid, "policyDefinitionDisplayName": name,
                 "policyDefinitionEffect": effect[:1].upper() + effect[1:],
                 "policyAssignmentId": f"/subscriptions/{sub['id']}/providers/Microsoft.Authorization/policyAssignments/{pa}/",
                 "policyAssignmentName": pa, "policyAssignmentScope": f"/subscriptions/{sub['id']}",
                 "policyAssignmentParameters": {}}]
    level = {"audit": "Warning", "auditIfNotExists": "Warning", "deny": "Error"}.get(effect, "Information")
    rt = "Failure" if effect == "deny" else "Success"
    props = {"isComplianceCheck": "True" if scan else "False", "resourceLocation": ae.region(sub),
             "ancestors": ",".join(reversed(sub["mgs"])) + "," + ae.TENANT_ID,
             "policies": json.dumps(policies)}
    rec = _platform(sub, "Policy", f"Microsoft.Authorization/policies/{effect}/action", res, rt, level,
                    props, caller["claims"])
    rec["callerIpAddress"] = caller.get("ip") or ""
    rec["resultSignature"] = "Failed." if rt == "Failure" else "Succeeded."
    rec["identity"]["authorization"] = {
        "scope": res, "action": "Microsoft.Resources/checkPolicyCompliance/read" if scan else op}
    return [rec]


_SVC_HEALTH = [  # (incidentType, operation, level, title template)
    ("Incident", "Microsoft.ServiceHealth/incident/action", "Warning", "{svc} - {region} - degraded performance"),
    ("Maintenance", "Microsoft.ServiceHealth/maintenance/action", "Informational", "Planned maintenance: {svc} - {region}"),
    ("Information", "Microsoft.ServiceHealth/info/action", "Informational", "{svc}: upcoming change notification"),
    ("ActionRequired", "Microsoft.ServiceHealth/actionrequired/action", "Warning", "Action required: migrate {svc} resources before retirement"),
    ("Security", "Microsoft.ServiceHealth/security/action", "Warning", "Security advisory: {svc}"),
]
_SVCS = ["Virtual Machines", "App Service", "SQL Database", "Storage", "Azure Kubernetes Service",
         "Key Vault", "Event Hubs", "Azure Monitor", "Azure Front Door", "Cosmos DB"]


def _b_service_health(config, context):
    sub = ae.pick_sub()
    itype, op, level, title = random.choice(_SVC_HEALTH)
    svc, reg = random.choice(_SVCS), ae.region(sub)
    t = title.format(svc=svc, region=reg)
    stage = random.choice(["Active", "Active", "Resolved"])
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    tracking = f"{random.choice(letters)}{random.randint(10, 99)}{random.choice(letters)}-{random.choice(letters)}{random.randint(10, 99)}"
    props = {"title": t, "service": svc, "region": reg, "incidentType": itype, "trackingId": tracking,
             "communication": f"{t}. Engineers are engaged; the next update will be provided in 60 minutes.",
             "impactStartTime": _ts(-random.randint(600, 7200)),
             "impactedServices": json.dumps([{"ImpactedRegions": [{"RegionName": reg}], "ServiceName": svc}]),
             "defaultLanguageTitle": t, "stage": stage, "communicationId": str(random.randint(10 ** 17, 10 ** 18)),
             "version": "0.1.1"}
    return [_platform(sub, "ServiceHealth", op, f"/subscriptions/{sub['id']}", stage, level, props)]


_HEALTH_TYPES = [("virtualMachines", "Microsoft.Compute"), ("servers", "Microsoft.Sql"),
                 ("sites", "Microsoft.Web"), ("storageAccounts", "Microsoft.Storage"),
                 ("managedClusters", "Microsoft.ContainerService")]


def _b_resource_health(config, context):
    sub = ae.pick_sub()
    rtype, prov = random.choice(_HEALTH_TYPES)
    res = ae.rid(sub, prov, rtype, ae.pick_name(sub, rtype))
    stage, prev, cur, level = random.choice([
        ("Activated", "Available", "Unavailable", "Critical"), ("Activated", "Available", "Degraded", "Warning"),
        ("Resolved", "Unavailable", "Available", "Informational"), ("Resolved", "Degraded", "Available", "Informational"),
        ("Updated", "Unavailable", "Unavailable", "Critical"), ("InProgress", "Unknown", "Unknown", "Warning")])
    cause = random.choice(["PlatformInitiated", "PlatformInitiated", "UserInitiated"])
    props = {"title": f"{rtype[:-1]} health status changed to {cur.lower()}",
             "details": ("The resource was restarted by its owner" if cause == "UserInitiated"
                         else "The resource has experienced an unexpected event"),
             "currentHealthStatus": cur, "previousHealthStatus": prev, "type": "Downtime",
             "cause": cause, "stage": stage}
    rt = {"Activated": "Active", "InProgress": "In Progress"}.get(stage, stage)
    return [_platform(sub, "ResourceHealth", f"Microsoft.Resourcehealth/healthevent/{stage}/action", res,
                      rt, level, props)]


def _b_alert(config, context):
    sub = ae.pick_sub()
    rule = ae.pick_name(sub, "metricAlerts")
    rtype, prov = random.choice(_HEALTH_TYPES[:3])
    target = ae.rid(sub, prov, rtype, ae.pick_name(sub, rtype))
    metric, unit, thr = random.choice([("Percentage CPU", "Percent", "80"),
                                       ("Available Memory Bytes", "Bytes", "524288000"),
                                       ("Http5xx", "Count", "10"), ("DTU Consumption Percentage", "Percent", "90")])
    state = random.choice(["Activated", "Resolved"])
    props = {"RuleUri": ae.rid(sub, "microsoft.insights", "alertrules", rule), "RuleName": rule,
             "RuleDescription": "", "Threshold": thr, "WindowSizeInMinutes": "5", "Aggregation": "Average",
             "Operator": "GreaterThan", "MetricName": metric, "MetricUnit": unit, "resourceId": target}
    claims = {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/spn": "Microsoft.Insights/alertRules"}
    return [_platform(sub, "Alert", f"Microsoft.Insights/AlertRules/{state}/Action", target,
                      "Active" if state == "Activated" else "Resolved",
                      "Warning" if state == "Activated" else "Informational", props, claims)]


def _b_autoscale(config, context):
    sub = ae.pick_sub()
    setting = ae.pick_name(sub, "autoscaleSettings")
    target = ae.rid(sub, "Microsoft.Web", "serverfarms", ae.pick_name(sub, "serverfarms"))
    old = random.randint(2, 8)
    up = random.random() < 0.5
    new = old + 1 if up else max(1, old - 1)
    act = "Scaleup" if up else "Scaledown"
    desc = (f"The autoscale engine attempting to scale resource {target} from {old} instances count "
            f"to {new} instances count.")
    props = {"Description": desc, "ResourceName": target, "OldInstancesCount": str(old),
             "NewInstancesCount": str(new),
             "LastScaleActionTime": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}
    res = ae.rid(sub, "microsoft.insights", "autoscalesettings", setting)
    claims = {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/spn": "Microsoft.Insights/autoscaleSettings"}
    op = f"Microsoft.Insights/AutoscaleSettings/{act}/Action"
    return [_platform(sub, "Autoscale", op, res, "Started", "Informational", props, claims, offset_s=-30),
            _platform(sub, "Autoscale", op, res, "Succeeded", "Informational", props, claims)]


def _b_recommendation(config, context):
    sub = ae.pick_sub()
    rtype, prov = random.choice(_HEALTH_TYPES)
    res = ae.rid(sub, prov, rtype, ae.pick_name(sub, rtype))
    props = {"recommendationSchemaVersion": "1.0",
             "recommendationCategory": random.choice(["HighAvailability", "Performance", "Security", "Cost"]),
             "recommendationImpact": random.choice(["High", "Medium", "Low"]),
             "recommendationRisk": random.choice(["Error", "Warning", "None"]),
             "recommendationType": ae.guid("advisor:" + rtype + str(random.randint(1, 12)))}
    return [_platform(sub, "Recommendation", "Microsoft.Advisor/generateRecommendations/action", res,
                      "Active", "Informational", props)]


_PLATFORM = [(3, _b_service_health), (4, _b_resource_health), (4, _b_alert), (3, _b_autoscale),
             (2, _b_recommendation)]


def _b_platform(config, context):
    return random.choices([f for _w, f in _PLATFORM], weights=[w for w, _f in _PLATFORM])[0](config, context)


def _b_kube(config, context):
    admin = ae.pick_admin(config, ae.CLOUD_OPS, context)["upn"] if random.random() < 0.3 else None
    return aks.benign(admin)


# Data-plane resource logs (Storage access, Key Vault, AI). High-volume machine traffic that runs
# around the clock, so it is part of both the off-hours and business-hours mix.
def _b_dataplane(config, context):
    return random.choices([dp.benign_storage, dp.benign_keyvault, dp.benign_ai],
                          weights=[6, 3, 2])[0](config, context)


def generate_benign(config=None, context=None):
    """One routine Activity event (or Started/Succeeded pair), an AKS audit record, or a data-plane
    resource log. Off hours, automation, policy, platform events, cluster chatter and data-plane
    traffic continue; human changes follow the business day."""
    if random.random() > ac.activity_weight():
        f = random.choices([_b_automation, _b_policy, _b_platform, aks_benign_quiet, _b_dataplane],
                           weights=[38, 14, 16, 14, 18])[0]
        return f(config, context)
    f = random.choices([_b_curated, _b_tail, _b_automation, _b_policy, _b_platform, _b_kube, _b_dataplane],
                       weights=[34, 14, 13, 9, 6, 10, 14])[0]
    return f(config, context)


def aks_benign_quiet(config, context):
    """Off-hours cluster chatter: control plane and workloads only, no humans."""
    return aks.benign(None)


# ── threat events ────────────────────────────────────────────────────────────────────
# Scenario keys are prefixed wip_ because the shapes and published Cortex targets are
# documented, but no alert has yet been attributed to these synthetic events in the tenant.
# On-demand callers can pass the scenario key directly; mappings expose the corresponding
# published target while preserving that qualification in the event name.
def _arm_event(config, op, *, roles=None, role="Contributor", actor=None, sub=None,
               fail=False, body=None, offset_s=0.0):
    sub = sub or ae.pick_sub()
    caller = actor or ae.pick_admin(config, roles or ae.CLOUD_OPS)
    rid, _rtype = resource_for(op, sub)
    return operation(op, rid, caller, sub, role=role, request_body=body, fail=fail,
                     offset_s=offset_s)


def _arm_one(config, op, **kwargs):
    return _arm_event(config, op, **kwargs)


_ARM_TARGETS = {
    # Network/security configuration and logging controls
    "wip_nsg_rule_change": ("An Azure Network Security Group was modified", "Microsoft.Network/networkSecurityGroups/securityRules/write", "net", "Network Contributor"),
    "wip_firewall_change": ("An Azure Firewall was modified", "Microsoft.Network/azureFirewalls/write", "net", "Network Contributor"),
    "wip_firewall_policy_delete": ("An Azure Firewall policy deletion", "Microsoft.Network/firewallPolicies/delete", "net", "Network Contributor"),
    "wip_firewall_rule_collection": ("An Azure Firewall rule collection group was modified or deleted", "Microsoft.Network/firewallPolicies/ruleCollectionGroups/write", "net", "Network Contributor"),
    "wip_firewall_rule_group": ("An Azure firewall rule group was modified", "Microsoft.Network/firewallPolicies/ruleCollectionGroups/write", "net", "Network Contributor"),
    "wip_dns_zone_change": ("An Azure DNS Zone was modified", "Microsoft.Network/dnsZones/write", "net", "Network Contributor"),
    "wip_vnet_change": ("An Azure virtual network was modified", "Microsoft.Network/virtualNetworks/write", "net", "Network Contributor"),
    "wip_vnet_device_change": ("An Azure virtual network Device was modified", "Microsoft.Network/networkVirtualAppliances/write", "net", "Network Contributor"),
    "wip_vpn_connection_change": ("An Azure VPN Connection was modified", "Microsoft.Network/connections/write", "net", "Network Contributor"),
    "wip_p2s_vpn_change": ("An Azure Point-to-Site VPN was modified", "Microsoft.Network/p2sVpnGateways/write", "net", "Network Contributor"),
    "wip_diagnostic_settings_delete": ("Azure diagnostic configuration deletion", "Microsoft.Insights/diagnosticSettings/delete", "sec", "Monitoring Contributor"),
    "wip_alert_rule_delete": ("Azure Monitor alert rule deleted", "Microsoft.Insights/metricAlerts/delete", "sec", "Monitoring Contributor"),
    "wip_logging_disabled": ("Cloud resource logging was disabled", "Microsoft.Insights/diagnosticSettings/delete", "sec", "Monitoring Contributor"),
    "wip_suppression_rule_create": ("An Azure Suppression Rule was created", "Microsoft.Security/alertsSuppressionRules/write", "sec", "Security Admin"),
    # IAM and persistence
    "wip_role_assignment": ("An identity was granted permissions to manage user access to Azure resources", "Microsoft.Authorization/roleAssignments/write", "sec", "User Access Administrator"),
    "wip_group_write": ("A cloud identity created or modified a security group", "Microsoft.Network/networkSecurityGroups/securityRules/write", "net", "Network Contributor"),
    "wip_automation_account_create": ("Azure Automation Account Creation", "Microsoft.Automation/automationAccounts/write", "cloud", "Contributor"),
    "wip_runbook_write": ("Azure Automation Runbook Creation/Modification", "Microsoft.Automation/automationAccounts/runbooks/write", "cloud", "Automation Contributor"),
    "wip_runbook_delete": ("Azure Automation Runbook Deletion", "Microsoft.Automation/automationAccounts/runbooks/delete", "cloud", "Automation Contributor"),
    "wip_webhook_create": ("Azure Automation Webhook creation", "Microsoft.Automation/automationAccounts/webhooks/write", "cloud", "Automation Contributor"),
    "wip_vmss_command": ("Azure virtual machine commands execution", "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action", "cloud", "Virtual Machine Contributor"),
    # Compute, storage, messaging and data resources
    "wip_vm_create": ("Cloud instance creation attempt", "Microsoft.Compute/virtualMachines/write", "cloud", "Virtual Machine Contributor"),
    "wip_vm_stop": ("A cloud instance was stopped", "Microsoft.Compute/virtualMachines/powerOff/action", "cloud", "Virtual Machine Contributor"),
    "wip_vm_command": ("Azure virtual machine commands execution", "Microsoft.Compute/virtualMachines/runCommand/action", "cloud", "Virtual Machine Contributor"),
    "wip_vm_extension": ("Azure VM extension abuse attempt", "Microsoft.Compute/virtualMachines/extensions/write", "cloud", "Virtual Machine Contributor"),
    "wip_snapshot_sas": ("An Azure VM snapshot SAS URL was generated", "Microsoft.Compute/snapshots/beginGetAccess/action", "cloud", "Backup Contributor"),
    "wip_resource_group_delete": ("Azure Resource Group Deletion", "Microsoft.Resources/subscriptions/resourceGroups/delete", "cloud", "Owner"),
    "wip_storage_config": ("A cloud storage configuration was modified", "Microsoft.Storage/storageAccounts/write", "data", "Storage Account Contributor"),
    "wip_storage_public": ("Azure storage account was publicly shared", "Microsoft.Storage/storageAccounts/blobServices/containers/write", "data", "Storage Account Contributor"),
    "wip_storage_key": ("Azure Storage Account key generated", "Microsoft.Storage/storageAccounts/listKeys/action", "data", "Storage Account Contributor"),
    "wip_storage_replication": ("Azure storage account cross-tenant object replication was enabled", "Microsoft.Storage/storageAccounts/objectReplicationPolicies/write", "data", "Storage Account Contributor"),
    "wip_blob_public_access": ("Azure Blob Container Access Level Modification", "Microsoft.Storage/storageAccounts/blobServices/containers/write", "data", "Storage Account Contributor"),
    "wip_eventhub_auth_rule": ("Azure Event Hub Authorization rule creation/modification", "Microsoft.EventHub/namespaces/authorizationRules/write", "cloud", "Contributor"),
    "wip_eventhub_delete": ("Azure Event Hub Deletion", "Microsoft.EventHub/namespaces/eventhubs/delete", "cloud", "Contributor"),
    "wip_sql_export": ("An Azure SQL database was exported from a production subscription", "Microsoft.Sql/servers/databases/export/action", "data", "SQL DB Contributor"),
    "wip_compute_allocation": ("Allocation of multiple cloud compute resources", "Microsoft.Compute/virtualMachines/write", "cloud", "Contributor"),
    "wip_container_registry": ("A container registry was created or deleted", "Microsoft.ContainerRegistry/registries/write", "cloud", "Contributor"),
    "wip_aks_cluster_change": ("An Azure Kubernetes Cluster was created or deleted", "Microsoft.ContainerService/managedClusters/write", "cloud", "Contributor"),
    "wip_keyvault_config": ("An Azure Key Vault was modified", "Microsoft.KeyVault/vaults/write", "sec", "Key Vault Administrator"),
    "wip_cosmos_key_read": ("Uncommon Azure Cosmos DB master key read by identity", "Microsoft.DocumentDB/databaseAccounts/listKeys/action", "data", "Contributor"),
    "wip_app_gateway_change": ("Modification or Deletion of an Azure Application Gateway Detected", "Microsoft.Network/applicationGateways/write", "net", "Network Contributor"),
    "wip_network_watcher_delete": ("Azure Network Watcher Deletion", "Microsoft.Network/networkWatchers/delete", "net", "Network Contributor"),
}


def _request_body(op, sub):
    """Operation-specific ARM request content for operations whose details matter to triage."""
    op_l = op.lower()
    if "networksecuritygroups/securityrules/" in op_l:
        return {"properties": {"protocol": "Tcp", "sourcePortRange": "*", "destinationPortRange": "443",
                "sourceAddressPrefix": "10.20.0.0/16", "destinationAddressPrefix": "10.30.0.0/16",
                "access": "Allow", "priority": 4096, "direction": "Inbound", "description": "LogSim test rule"}}
    if "virtualmachines/runcommand/action" in op_l:
        return {"commandId": "RunPowerShellScript", "script": ["Get-Date"], "parameters": []}
    if "virtualmachinescalesets/virtualmachines/runcommand/action" in op_l:
        return {"commandId": "RunShellScript", "script": ["date"], "parameters": []}
    if "virtualmachines/extensions/write" in op_l:
        return {"location": ae.region(sub), "properties": {"publisher": "Microsoft.Compute",
                "type": "CustomScriptExtension", "typeHandlerVersion": "1.10",
                "settings": {"commandToExecute": "echo LogSim"}}}
    if "roleassignments/write" in op_l:
        principal = ae.app_caller(random.choice(list(ae.SERVICE_PRINCIPALS)))
        return {"properties": {"principalId": principal["oid"], "principalType": "ServicePrincipal",
                "roleDefinitionId": ae.sub_rid(sub, "Microsoft.Authorization", "roleDefinitions",
                                                ae.ROLES["Contributor"]),
                "description": "Simulated role assignment"}}
    if "containers/write" in op_l and "microsoft.storage" in op_l:
        return {"properties": {"publicAccess": "Blob"}}
    if "objectreplicationpolicies/write" in op_l:
        return {"properties": {"sourceAccount": "stdataprod85403", "destinationAccount": "starchiveprod30211",
                "rules": [{"ruleId": "replication-policy-01", "sourceContainer": "exports",
                           "destinationContainer": "archive"}]}}
    if "snapshots/begingetaccess/action" in op_l:
        return {"access": "Read", "durationInSeconds": 3600}
    if "runbooks/" in op_l:
        return {"properties": {"runbookType": "PowerShell", "description": "Routine maintenance runbook",
                                "logProgress": True, "logVerbose": False}}
    if "webhooks/write" in op_l:
        return {"properties": {"runbook": {"name": "maintenance-check"}, "isEnabled": True}}
    if "databases/export/action" in op_l:
        return {"storageKeyType": "SharedAccessKey", "administratorLogin": "sql-export",
                "authenticationType": "Sql"}
    return {"change": "simulated configuration update", "source": "LogSim"}


def _make_arm_scenario(op, team, role):
    roles = _TEAM_ROLES[team]
    def scenario(config=None):
        # A newly observed non-platform identity and a denied path are useful analytic variants.
        actor = ae.pick_nonstandard(config) if random.random() < 0.18 else None
        sub = ae.pick_sub()
        kwargs = {"roles": roles, "role": role, "actor": actor, "sub": sub,
                  "body": _request_body(op, sub)}
        return _arm_event(config, op, **kwargs)
    return scenario


def _kube_threat(config, kind):
    cluster = random.choice(aks.CLUSTERS)
    if kind == "anonymous":
        user, groups, src, ua = "system:anonymous", ["system:unauthenticated"], "198.51.100.24", "kubectl/v1.30.4"
        return [aks.record(cluster, aks.event("get", "secrets", ns="payments", name="db-credentials", user=user,
                    groups=groups, src=src, ua=ua, code=200, reason="RBAC: allowed by permissive binding"))]
    service_user, groups = aks.sa("payments", "payments-api")
    payloads = {
        "secret": ("create", "secrets", "db-credentials", "", {"apiVersion":"v1","kind":"Secret","metadata":{"name":"db-credentials","namespace":"payments"},"type":"Opaque","data":{"password":"<redacted>"}}),
        "configmap": ("create", "configmaps", "runtime-config", "", {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"runtime-config","namespace":"payments"},"data":{"LOG_LEVEL":"debug"}}),
        "deployment": ("create", "deployments", "payments-debug", "apps", {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"payments-debug","namespace":"payments"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"debug","image":"mcr.microsoft.com/azure-cli:latest"}]}}}}),
        "rolebinding": ("create", "rolebindings", "payments-admin", "rbac.authorization.k8s.io", {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"payments-admin","namespace":"payments"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin","apiGroup":"rbac.authorization.k8s.io"},"subjects":[{"kind":"ServiceAccount","name":"payments-api","namespace":"payments"}]}),
        "clusterrole": ("create", "clusterroles", "node-reader", "rbac.authorization.k8s.io", {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"node-reader"},"rules":[{"apiGroups":[""],"resources":["secrets","nodes"],"verbs":["get","list"]}]}),
        "namespace": ("create", "namespaces", "staging-tools", "", {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"staging-tools"}}),
        "serviceaccount": ("create", "serviceaccounts", "backup-runner", "", {"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"backup-runner","namespace":"payments"}}),
        "cronjob": ("create", "cronjobs", "nightly-export", "batch", {"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"nightly-export","namespace":"payments"},"spec":{"schedule":"0 2 * * *","jobTemplate":{"spec":{"template":{"spec":{"containers":[{"name":"export","image":"mcr.microsoft.com/azure-cli:latest"}],"restartPolicy":"Never"}}}}}}),
        "daemonset": ("create", "daemonsets", "node-observer", "apps", {"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"node-observer","namespace":"monitoring"},"spec":{"selector":{"matchLabels":{"app":"node-observer"}},"template":{"metadata":{"labels":{"app":"node-observer"}},"spec":{"containers":[{"name":"observer","image":"mcr.microsoft.com/oss/kubernetes/pause:3.9"}]}}}}),
        "statefulset": ("create", "statefulsets", "cache-replica", "apps", {"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"cache-replica","namespace":"catalog"},"spec":{"serviceName":"cache","replicas":1,"selector":{"matchLabels":{"app":"cache"}},"template":{"metadata":{"labels":{"app":"cache"}},"spec":{"containers":[{"name":"cache","image":"redis:7"}]}}}}),
        "exec": ("create", "pods", "payments-api-7f94d6c8bf-x2m4p", "", None),
        "ephemeral": ("update", "pods", "payments-api-7f94d6c8bf-x2m4p", "", {"apiVersion":"v1","kind":"Pod","metadata":{"name":"payments-api-7f94d6c8bf-x2m4p","namespace":"payments"},"spec":{"ephemeralContainers":[{"name":"debugger","image":"busybox:1.36","targetContainerName":"payments-api"}]}}),
    }
    action, res, name, group, body = payloads[kind]
    subres = "exec" if kind == "exec" else None
    event = aks.event(action, res, ns=None if res in ("clusterroles", "namespaces") else "payments",
                      name=name, subresource=subres, user=service_user, groups=groups,
                      src="10.244.12.17", ua="kubectl/v1.30.4", api_group=group,
                      request_object=body, code=200)
    return [aks.record(cluster, event)]


_KUBE_TARGETS = {
    "wip_kube_anonymous": ("A Kubernetes API operation was successfully invoked by an anonymous user", "anonymous"),
    "wip_kube_secret": ("A Kubernetes secret was created or deleted", "secret"),
    "wip_kube_configmap": ("A Kubernetes ConfigMap was created or deleted", "configmap"),
    "wip_kube_deployment": ("A Kubernetes deployment was created", "deployment"),
    "wip_kube_rolebinding": ("An Azure Kubernetes Role-Binding or Cluster-Role-Binding was modified or deleted", "rolebinding"),
    "wip_kube_clusterrole": ("An Azure Kubernetes Role or Cluster-Role was modified", "clusterrole"),
    "wip_kube_namespace": ("A Kubernetes namespace was created or deleted", "namespace"),
    "wip_kube_serviceaccount": ("An Azure Kubernetes Service Account was modified or deleted", "serviceaccount"),
    "wip_kube_cronjob": ("A Kubernetes Cronjob was created", "cronjob"),
    "wip_kube_daemonset": ("A Kubernetes DaemonSet was created", "daemonset"),
    "wip_kube_statefulset": ("A Kubernetes StatefulSet was created", "statefulset"),
    "wip_kube_exec": ("Unusual exec into a Kubernetes Pod", "exec"),
    "wip_kube_ephemeral": ("A Kubernetes ephemeral container was created", "ephemeral"),
}


def _storage_threat(config=None, *, mode="first", count=1):
    sub = ae.pick_sub()
    account = ae.pick_name(sub, "storageAccounts")
    caller = ae.pick_nonstandard(config) if mode == "first" else ae.pick_admin(config, ae.DATA_OPS)
    out = []
    for i in range(count):
        container = "backups" if mode == "backup" else None
        blob = f"backup-{i:04d}.bak" if mode == "backup" else f"download-{uuid.uuid4().hex[:12]}.parquet"
        out.append(dp.storage_record(account, sub, caller, "GetBlob", "StorageRead", container=container,
                                     blob=blob, offset_s=-i * 2.0))
    return out


def _keyvault_threat(config=None, op="SecretList", *, count=1):
    sub = ae.pick_sub()
    caller = ae.pick_admin(config, ae.SEC_OPS)
    vault = ae.pick_name(sub, "vaults")
    return [dp.keyvault_record(vault, sub, caller, op, object_name=f"service-{i:02d}", offset_s=-i * 3.0)
            for i in range(count)]


def _ai_threat(config=None, count=1, status=200, op="ChatCompletions_Create"):
    sub = ae.PROD
    caller = ae.app_caller(random.choice(list(ae.SERVICE_PRINCIPALS)), "ServicePrincipal")
    account = ae.pick_name(sub, "accounts")
    return [dp.ai_record(account, sub, caller, op, status=status,
                         offset_s=-i * 3.0) for i in range(count)]


SCENARIOS = {
    key: _make_arm_scenario(op, team, role)
    for key, (_alert, op, team, role) in _ARM_TARGETS.items()
}
SCENARIOS.update({key: (lambda config=None, kind=kind: _kube_threat(config, kind))
                  for key, (_alert, kind) in _KUBE_TARGETS.items()})
SCENARIOS.update({
    "wip_storage_first_access": _storage_threat,
    "wip_storage_backup_access": lambda config=None: _storage_threat(config, mode="backup"),
    "wip_storage_multiple_downloads": lambda config=None: _storage_threat(config, mode="bulk", count=16),
    "wip_keyvault_key_change": lambda config=None: _keyvault_threat(config, "KeyRotate"),
    "wip_keyvault_secret_dump": lambda config=None: _keyvault_threat(config, "SecretGet", count=12),
    "wip_keyvault_key_management": lambda config=None: _keyvault_threat(config, "KeyRotate"),
    "wip_ai_model_discovery": lambda config=None: _ai_threat(config, count=6, op="Models_List"),
    "wip_ai_denial_of_wallet": lambda config=None: _ai_threat(config, count=24),
    "wip_ai_dataset_download": lambda config=None: _ai_threat(config, count=8),
})

# Published Cortex targets. These are intentionally unconfirmed scenario mappings; the wip_
# key makes that status visible in the on-demand catalog until a real alert validates the shape.
ANALYTIC_ALERTS = {key: alert for key, (alert, *_rest) in {**_ARM_TARGETS, **_KUBE_TARGETS}.items()}
ANALYTIC_ALERTS.update({
    "wip_storage_first_access": "An identity accessed a cloud storage for the first time",
    "wip_storage_backup_access": "An identity accessed a backup cloud storage",
    "wip_storage_multiple_downloads": "An identity initiated a download of multiple cloud objects",
    "wip_keyvault_key_change": "Unusual key management activity",
    "wip_keyvault_secret_dump": "Suspicious secrets dump activity",
    "wip_keyvault_key_management": "Unusual key management activity",
    "wip_ai_model_discovery": "AI model discovery",
    "wip_ai_denial_of_wallet": "Potential denial of wallet abusing AI services",
    "wip_ai_dataset_download": "Suspicious AI Dataset Download",
})


_GATE = ac.ThreatGate(SCENARIOS)


def get_threat_names():
    return list(SCENARIOS)


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    if scenario_event:
        key = scenario_event if scenario_event in SCENARIOS else str(scenario_event).lower()
        if key in SCENARIOS:
            return (SCENARIOS[key](config), key)
        return None
    if benign_only or threat_level == "Benign Traffic Only":
        return generate_benign(config, context)
    if _GATE.fire(threat_level, config):
        key = random.choice(list(SCENARIOS))
        return (SCENARIOS[key](config), key)
    return generate_benign(config, context)
