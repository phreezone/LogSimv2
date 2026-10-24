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
EVENT_INTERVAL = 0.5   # default relative benign volume: ARM + data-plane + kube control-plane activity, moderate


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
            "roleAssignmentId": ae.guid(f"ra:{who}:{role}:{sub['id']}"),
            "roleDefinitionId": ae.ROLES.get(role, ae.ROLES["Contributor"]),
            "principalId": caller["oid"],
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
        "level": level or ("Error" if status == "Failed" else "Informational"),
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
    level = {"audit": "Warning", "auditIfNotExists": "Warning", "deny": "Error"}.get(effect, "Informational")
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


def _b_security(config, context):
    """A Defender for Cloud alert using Microsoft's documented Activity Log Security shape."""
    sub = ae.pick_sub()
    region = ae.region(sub)
    resource = ae.rid(sub, "Microsoft.Compute", "virtualMachines", ae.pick_name(sub, "virtualMachines"))
    alert_id = str(uuid.uuid4())
    alert_name = random.choice([
        "Suspicious double extension file executed",
        "PREVIEW - Role binding to the cluster-admin role detected",
        "Suspicious activity detected on a virtual machine",
    ])
    severity = random.choice(["Low", "Medium"])
    props = {
        "eventName": alert_name,
        "Severity": severity,
        "compromisedEntity": resource.rsplit("/", 1)[-1],
        "remediationSteps": ["Review the affected resource and validate the alert."],
        "intent": random.choice(["Execution", "PrivilegeEscalation", "Discovery"]),
        "description": f"Synthetic Defender for Cloud alert: {alert_name}.",
        "eventDataId": alert_id,
        "eventCategory": "Security",
        "operationId": alert_id,
    }
    rec = _platform(sub, "Security", "Microsoft.Security/locations/alerts/activate/action",
                    f"/subscriptions/{sub['id']}/resourceGroups/{ae.rg_for(sub, 'virtualMachines')}"
                    f"/providers/Microsoft.Security/locations/{region}/alerts/{alert_id}",
                    "Active", "Informational", props)
    rec["correlationId"] = alert_id
    return [rec]


_PLATFORM = [(3, _b_service_health), (4, _b_resource_health), (4, _b_alert), (3, _b_autoscale),
             (2, _b_recommendation), (0.5, _b_security)]


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
    "firewall_policy_delete": ("An Azure Firewall policy deletion", "Microsoft.Network/firewallPolicies/delete", "net", "Network Contributor"),
    "wip_firewall_rule_collection_delete": ("An Azure Firewall rule collection group was modified or deleted", "Microsoft.Network/firewallPolicies/ruleCollectionGroups/delete", "net", "Network Contributor"),
    "wip_firewall_rule_collection": ("An Azure Firewall rule collection group was modified or deleted", "Microsoft.Network/firewallPolicies/ruleCollectionGroups/write", "net", "Network Contributor"),
    "wip_firewall_rule_group": ("An Azure firewall rule group was modified", "Microsoft.Network/firewallPolicies/ruleCollectionGroups/write", "net", "Network Contributor"),
    "wip_dns_zone_change": ("An Azure DNS Zone was modified", "Microsoft.Network/dnsZones/write", "net", "Network Contributor"),
    "wip_vnet_change": ("An Azure virtual network was modified", "Microsoft.Network/virtualNetworks/write", "net", "Network Contributor"),
    "wip_vnet_device_change": ("An Azure virtual network Device was modified", "Microsoft.Network/networkVirtualAppliances/write", "net", "Network Contributor"),
    "wip_vpn_connection_change": ("An Azure VPN Connection was modified", "Microsoft.Network/connections/write", "net", "Network Contributor"),
    "wip_p2s_vpn_change": ("An Azure Point-to-Site VPN was modified", "Microsoft.Network/p2sVpnGateways/write", "net", "Network Contributor"),
    "wip_diagnostic_settings_delete": ("Azure diagnostic configuration deletion", "Microsoft.Insights/diagnosticSettings/delete", "sec", "Monitoring Contributor"),
    "alert_rule_delete": ("Unusual Azure Monitor alert rule deletion", "Microsoft.Insights/metricAlerts/delete", "sec", "Monitoring Contributor"),
    "wip_logging_disabled": ("Cloud resource logging was disabled", "Microsoft.Insights/diagnosticSettings/delete", "sec", "Monitoring Contributor"),
    "wip_suppression_rule_create": ("An Azure Suppression Rule was created", "Microsoft.Security/alertsSuppressionRules/write", "sec", "Security Admin"),
    # IAM and persistence
    "wip_role_assignment": ("An identity was granted permissions to manage user access to Azure resources", "Microsoft.Authorization/roleAssignments/write", "sec", "User Access Administrator"),
    "wip_cloud_permission_escalation": ("A cloud identity had escalated its permissions", "Microsoft.Authorization/roleAssignments/write", "sec", "User Access Administrator"),
    "wip_iam_persistence": ("A cloud identity invoked IAM related persistence operations", "Microsoft.Authorization/roleAssignments/write", "sec", "User Access Administrator"),
    "wip_route_table_change": ("Azure route table creation or modification", "Microsoft.Network/routeTables/write", "net", "Network Contributor"),
    "wip_billing_role_removed": ("Billing admin role was removed", "Microsoft.Authorization/roleAssignments/delete", "sec", "User Access Administrator"),
    "wip_automation_account_create": ("Azure Automation Account Creation", "Microsoft.Automation/automationAccounts/write", "cloud", "Contributor"),
    "wip_runbook_write": ("Azure Automation Runbook Creation/Modification", "Microsoft.Automation/automationAccounts/runbooks/write", "cloud", "Automation Contributor"),
    "wip_runbook_delete": ("Azure Automation Runbook Deletion", "Microsoft.Automation/automationAccounts/runbooks/delete", "cloud", "Automation Contributor"),
    "wip_webhook_create": ("Azure Automation Webhook creation", "Microsoft.Automation/automationAccounts/webhooks/write", "cloud", "Automation Contributor"),
    "wip_vmss_command": ("Azure virtual machine commands execution", "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action", "cloud", "Virtual Machine Contributor"),
    # Compute, storage, messaging and data resources
    "wip_vm_create": ("Cloud instance creation attempt", "Microsoft.Compute/virtualMachines/write", "cloud", "Virtual Machine Contributor"),
    "wip_vm_delete": ("Cloud instance deletion attempt", "Microsoft.Compute/virtualMachines/delete", "cloud", "Virtual Machine Contributor"),
    "wip_vm_stop": ("A cloud instance was stopped", "Microsoft.Compute/virtualMachines/powerOff/action", "cloud", "Virtual Machine Contributor"),
    "vm_command": ("Unusual Azure VM remote command execution", "Microsoft.Compute/virtualMachines/runCommand/action", "cloud", "Virtual Machine Contributor"),
    "wip_vm_extension": ("Azure VM extension abuse attempt", "Microsoft.Compute/virtualMachines/extensions/write", "cloud", "Virtual Machine Contributor"),
    "wip_snapshot_sas": ("An Azure VM snapshot SAS URL was generated", "Microsoft.Compute/snapshots/beginGetAccess/action", "cloud", "Backup Contributor"),
    "wip_snapshot_create": ("Cloud snapshot created or modified", "Microsoft.Compute/snapshots/write", "cloud", "Backup Contributor"),
    "wip_resource_group_delete": ("Azure Resource Group Deletion", "Microsoft.Resources/subscriptions/resourceGroups/delete", "cloud", "Owner"),
    "wip_storage_config": ("A cloud storage configuration was modified", "Microsoft.Storage/storageAccounts/write", "data", "Storage Account Contributor"),
    "wip_storage_versioning_disabled": ("Object versioning was disabled", "Microsoft.Storage/storageAccounts/blobServices/write", "data", "Storage Account Contributor"),
    "wip_storage_soft_delete_disabled": ("Soft delete of cloud storage configuration was disabled", "Microsoft.Storage/storageAccounts/blobServices/write", "data", "Storage Account Contributor"),
    "wip_storage_public": ("Azure storage account was publicly shared", "Microsoft.Storage/storageAccounts/write", "data", "Storage Account Contributor"),
    "wip_storage_key": ("Azure Storage Account key generated", "Microsoft.Storage/storageAccounts/listKeys/action", "data", "Storage Account Contributor"),
    "wip_storage_replication": ("Azure storage account cross-tenant object replication was enabled", "Microsoft.Storage/storageAccounts/objectReplicationPolicies/write", "data", "Storage Account Contributor"),
    "wip_blob_public_access": ("Azure Blob Container Access Level Modification", "Microsoft.Storage/storageAccounts/blobServices/containers/write", "data", "Storage Account Contributor"),
    "wip_eventhub_auth_rule": ("Azure Event Hub Authorization rule creation/modification", "Microsoft.EventHub/namespaces/authorizationRules/write", "cloud", "Contributor"),
    "eventhub_delete": ("Azure Event Hub Deletion", "Microsoft.EventHub/namespaces/eventhubs/delete", "cloud", "Contributor"),
    "wip_sql_export": ("An Azure SQL database was exported from a production subscription", "Microsoft.Sql/servers/databases/export/action", "data", "SQL DB Contributor"),
    "wip_compute_allocation": ("Allocation of multiple cloud compute resources", "Microsoft.Compute/virtualMachines/write", "cloud", "Contributor"),
    "wip_vm_serial_console": ("Cloud compute serial console access", "Microsoft.SerialConsole/serialPorts/connect/action", "cloud", "Virtual Machine Contributor"),
    "wip_dormant_region_compute": ("Compute activity in dormant cloud region", "Microsoft.Compute/virtualMachines/write", "cloud", "Contributor"),
    "wip_snapshot_sas_prod": ("An Azure VM snapshot SAS URL was generated for export from a production subscription", "Microsoft.Compute/snapshots/beginGetAccess/action", "cloud", "Backup Contributor"),
    "wip_container_registry": ("A container registry was created or deleted", "Microsoft.ContainerRegistry/registries/write", "cloud", "Contributor"),
    "wip_aks_cluster_change": ("An Azure Kubernetes Cluster was created or deleted", "Microsoft.ContainerService/managedClusters/write", "cloud", "Contributor"),
    "wip_keyvault_config": ("An Azure Key Vault was modified", "Microsoft.KeyVault/vaults/write", "sec", "Key Vault Administrator"),
    "wip_cosmos_key_read": ("Uncommon Azure Cosmos DB master key read by identity", "Microsoft.DocumentDB/databaseAccounts/listKeys/action", "data", "Contributor"),
    "wip_app_gateway_change": ("Modification or Deletion of an Azure Application Gateway Detected", "Microsoft.Network/applicationGateways/write", "net", "Network Contributor"),
    "network_watcher_delete": ("Azure Network Watcher Deletion", "Microsoft.Network/networkWatchers/delete", "net", "Network Contributor"),
    "ai_safeguard_delete": ("AI safeguards were successfully deleted", "Microsoft.CognitiveServices/accounts/raiPolicies/delete", "data", "Cognitive Services Contributor"),
    "ai_safeguard_modify": ("Unusual modification of AI safeguards", "Microsoft.CognitiveServices/accounts/raiPolicies/write", "data", "Cognitive Services Contributor"),
    "wip_backup_policy_change": ("Cloud storage automatic backup disabled", "Microsoft.RecoveryServices/vaults/backupPolicies/write", "data", "Backup Contributor"),
    "wip_database_export": ("Data exfiltration from cloud database", "Microsoft.Sql/servers/databases/export/action", "data", "SQL DB Contributor"),
    "wip_network_packet_capture": ("Network sniffing detected in Cloud environment", "Microsoft.Network/networkWatchers/packetCaptures/write", "net", "Network Contributor"),
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
    if "microsoft.storage/storageaccounts/write" in op_l:
        return {"properties": {"publicNetworkAccess": "Enabled",
                "networkAcls": {"defaultAction": "Allow", "bypass": "None",
                                "ipRules": [], "virtualNetworkRules": []}}}
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


def _adfs_health_server_added(config=None):
    """Azure AD Hybrid Health AD FS server registration Activity Log event.

    The detector's public companion rule keys on this exact Administrative operation and a
    resourceId containing AdFederationService. Keep that resource name explicit; the generic
    resource inventory cannot express the service-name predicate.
    """
    sub = ae.pick_sub()
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    service = "AdFederationService-sts.examplecorp.com"
    member = f"adfs-{random.randint(2, 9):02d}.examplecorp.com"
    resource_id = (f"/subscriptions/{sub['id']}/providers/Microsoft.ADHybridHealthService/"
                   f"services/{service}/servicemembers/{member}")
    return operation("Microsoft.ADHybridHealthService/services/servicemembers/action",
                     resource_id, caller, sub, role="Contributor",
                     request_body={"properties": {"machineName": member,
                                   "serviceName": service, "machineRole": "AdfsServer"}})


def _compute_allocation(config=None, count=5):
    """Several distinct VM allocations by one actor/subscription in a short window."""
    sub = ae.pick_sub()
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    base_id, _ = resource_for("Microsoft.Compute/virtualMachines/write", sub)
    prefix = base_id.rsplit("/", 1)[0]
    records = []
    for i in range(count):
        rid = f"{prefix}/vm-batch-{uuid.uuid4().hex[:8]}"
        records.extend(operation("Microsoft.Compute/virtualMachines/write", rid, caller, sub,
            role="Contributor", request_body={"location": ae.region(sub), "properties": {
                "hardwareProfile": {"vmSize": random.choice(["Standard_D2s_v5", "Standard_D4s_v5", "Standard_E4s_v5"])},
                "storageProfile": {"imageReference": {"publisher": "Canonical", "offer": "0001-com-ubuntu-server-jammy",
                                  "sku": "22_04-lts-gen2", "version": "latest"}},
                "osProfile": {"computerName": rid.rsplit("/", 1)[-1], "adminUsername": "azureuser"},
                "networkProfile": {"networkInterfaces": []}}, "tags": {"environment": "simulated"}},
            offset_s=-i * 90.0))
    return records


def _multi_snapshot_export(config=None, count=4):
    sub = ae.PROD
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    records = []
    for i in range(count):
        rid = ae.rid(sub, "Microsoft.Compute", "snapshots", f"snapshot-export-{uuid.uuid4().hex[:8]}")
        records.extend(operation("Microsoft.Compute/snapshots/beginGetAccess/action", rid, caller, sub,
            role="Backup Contributor", request_body={"access": "Read", "durationInSeconds": 3600},
            offset_s=-i * 120.0))
    return records


def _multi_resource_deletion(config=None, count=4):
    sub = ae.pick_sub()
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    operations = ["Microsoft.Compute/virtualMachines/delete", "Microsoft.Storage/storageAccounts/delete",
                  "Microsoft.KeyVault/vaults/delete", "Microsoft.Network/networkInterfaces/delete"]
    out = []
    for i in range(count):
        op = operations[i % len(operations)]
        rid, _ = resource_for(op, sub)
        rid = rid.rsplit("/", 1)[0] + f"/sim-delete-{uuid.uuid4().hex[:8]}"
        out.extend(operation(op, rid, caller, sub, role="Contributor", offset_s=-i * 90.0))
    return out


def _multi_denied_actions(config=None, count=4):
    sub = ae.pick_sub()
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    operations = ["Microsoft.Compute/virtualMachines/delete", "Microsoft.Storage/storageAccounts/listKeys/action",
                  "Microsoft.Authorization/roleAssignments/write", "Microsoft.KeyVault/vaults/delete"]
    out = []
    for i in range(count):
        op = operations[i % len(operations)]
        rid, _ = resource_for(op, sub)
        out.extend(denied(op, rid, caller, sub, offset_s=-i * 90.0))
    return out


def _heavy_compute_allocation(config=None):
    sub = ae.pick_sub()
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    base_id, _ = resource_for("Microsoft.Compute/virtualMachines/write", sub)
    prefix = base_id.rsplit("/", 1)[0]
    vm_sizes = ["Standard_NC24ads_A100_v4", "Standard_NC48ads_A100_v4", "Standard_ND96amsr_A100_v4"]
    out = []
    for i, size in enumerate(vm_sizes):
        name = f"gpu-batch-{uuid.uuid4().hex[:8]}"
        out.extend(operation("Microsoft.Compute/virtualMachines/write", f"{prefix}/{name}", caller, sub,
            role="Contributor", request_body={"location": ae.region(sub), "properties": {
                "hardwareProfile": {"vmSize": size}, "storageProfile": {"imageReference": {
                    "publisher": "Canonical", "offer": "0001-com-ubuntu-server-jammy",
                    "sku": "22_04-lts-gen2", "version": "latest"}},
                "osProfile": {"computerName": name, "adminUsername": "azureuser"},
                "networkProfile": {"networkInterfaces": []}}, "tags": {"purpose": "simulated"}},
            offset_s=-i * 120.0))
    return out


def _dormant_region_compute(config=None):
    sub = ae.pick_sub()
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    rid, _ = resource_for("Microsoft.Compute/virtualMachines/write", sub)
    rid = rid.rsplit("/", 1)[0] + f"/vm-dormant-{uuid.uuid4().hex[:8]}"
    return operation("Microsoft.Compute/virtualMachines/write", rid, caller, sub, role="Contributor",
        request_body={"location": ae.DORMANT_REGIONS[0], "properties": {
            "hardwareProfile": {"vmSize": "Standard_D2s_v5"}, "tags": {"purpose": "simulated"}}})


def _storage_protection_change(config=None, *, versioning=True):
    op = "Microsoft.Storage/storageAccounts/blobServices/write"
    team, role = _TEAM_ROLES["data"], "Storage Account Contributor"
    sub = ae.pick_sub()
    actor = ae.pick_admin(config, team)
    body = {"properties": {"isVersioningEnabled": False,
            "deleteRetentionPolicy": {"enabled": False, "days": 7},
            "containerDeleteRetentionPolicy": {"enabled": False, "days": 7}}}
    if versioning:
        body["properties"].pop("deleteRetentionPolicy")
        body["properties"].pop("containerDeleteRetentionPolicy")
    return _arm_event(config, op, roles=team, role=role, actor=actor, sub=sub, body=body)


def _multi_unusual_activities(config=None):
    sub = ae.pick_sub()
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    ops = ["Microsoft.Compute/virtualMachines/write", "Microsoft.Authorization/roleAssignments/write",
           "Microsoft.Storage/storageAccounts/write", "Microsoft.Insights/diagnosticSettings/delete"]
    out = []
    for i, op in enumerate(ops):
        rid, _ = resource_for(op, sub)
        out.extend(operation(op, rid, caller, sub, role="Contributor",
                             request_body=_request_body(op, sub), offset_s=-i * 120.0))
    return out


def _cross_project_activity(config=None):
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    op = "Microsoft.Compute/virtualMachines/write"
    out = []
    for i, sub in enumerate(ae.SUBSCRIPTIONS[:3]):
        rid, _ = resource_for(op, sub)
        out.extend(operation(op, rid, caller, sub, role="Contributor",
                             request_body={"location": ae.region(sub)}, offset_s=-i * 180.0))
    return out


def _multi_region_enumeration(config=None):
    """One identity performs the same resource discovery across distinct Azure regions."""
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    op = "Microsoft.Compute/virtualMachines/read"
    out = []
    for i, region in enumerate(("eastus", "westus2", "northeurope", "uksouth")):
        sub = ae.SUBSCRIPTIONS[i % len(ae.SUBSCRIPTIONS)]
        rid, _ = resource_for(op, sub)
        out.extend(operation(op, rid, caller, sub, role="Reader", offset_s=-i * 45.0,
                             request_body={"location": region}))
    return out


def _vm_ssh_key_change(config=None):
    sub = ae.pick_sub()
    op = "Microsoft.Compute/virtualMachines/write"
    rid, _ = resource_for(op, sub)
    caller = ae.pick_admin(config, _TEAM_ROLES["cloud"])
    body = {"location": ae.region(sub), "properties": {"hardwareProfile": {"vmSize": "Standard_D2s_v5"},
             "osProfile": {"computerName": rid.rsplit("/", 1)[-1], "adminUsername": "azureuser",
                           "linuxConfiguration": {"disablePasswordAuthentication": True,
                             "ssh": {"publicKeys": [{"path": "/home/azureuser/.ssh/authorized_keys",
                                                        "keyData": "ssh-rsa AAAA...LogSimSyntheticKey"}]}}}}}
    return operation(op, rid, caller, sub, role="Virtual Machine Contributor", request_body=body)


def _newly_seen_resource_change(config=None):
    sub = ae.pick_sub()
    caller = ae.pick_nonstandard(config)
    op = "Microsoft.Storage/storageAccounts/write"
    return _arm_event(config, op, roles=_TEAM_ROLES["data"], role="Storage Account Contributor",
                      actor=caller, sub=sub, body=_request_body(op, sub))


def _new_domain_activity(config=None):
    sub = ae.pick_sub()
    actor = dict(ae.pick_admin(config, _TEAM_ROLES["cloud"]))
    domain = ac.rare_domain()
    local = actor.get("username", "cloud.operator").split("@", 1)[0]
    actor["username"] = f"{local}@{domain}"
    actor["upn"] = actor["username"]
    actor["email"] = actor["username"]
    return _arm_event(config, "Microsoft.Compute/virtualMachines/read", roles=_TEAM_ROLES["cloud"],
                      role="Reader", actor=actor, sub=sub)


def _kube_threat(config, kind):
    cluster = random.choice(aks.CLUSTERS)
    if kind == "denied_enumeration":
        user, groups = aks.sa("payments", "payments-api")
        probes = [("pods", "", "payments"), ("secrets", "", "payments"),
                  ("deployments", "apps", "payments"), ("roles", "rbac.authorization.k8s.io", "payments"),
                  ("nodes", "", None)]
        return [aks.record(cluster, aks.event("list", resource, ns=namespace, user=user, groups=groups,
                    src="10.244.12.17", ua="python-requests/2.32.3", code=403, decision="forbid",
                    reason="RBAC: forbidden by RoleBinding", api_group=group,
                    offset_s=-(len(probes)-i-1)*2.0))
                for i, (resource, group, namespace) in enumerate(probes)]
    if kind == "anonymous":
        user, groups, src, ua = "system:anonymous", ["system:unauthenticated"], "198.51.100.24", "kubectl/v1.30.4"
        return [aks.record(cluster, aks.event("get", "secrets", ns="payments", name="db-credentials", user=user,
                    groups=groups, src=src, ua=ua, code=200, reason="RBAC: allowed by permissive binding"))]
    if kind in _KUBE_EXTRA:
        verb, resource, ns, name, group, body = _KUBE_EXTRA[kind]
        user, groups = aks.sa("payments", "payments-api")
        src = "10.244.12.17"
        ua = "kubectl/v1.30.4"
        code, decision, reason = None, "allow", ""
        if kind in ("dashboard_external", "service_account_external", "node_external"):
            src = ac.rare_asn_loc().get("ip", "45.155.205.233")
        if kind == "dashboard_external":
            user, groups = "system:serviceaccount:kubernetes-dashboard:kubernetes-dashboard", ["system:serviceaccounts", "system:serviceaccounts:kubernetes-dashboard", "system:authenticated"]
        elif kind == "node_external":
            user, groups = f"system:node:{aks.node(cluster, 1)}", ["system:nodes", "system:authenticated"]
        elif kind == "scan_tool":
            ua = "trivy-operator/0.24.1 (kubernetes security scanner)"
        elif kind == "denied_api":
            code, decision, reason = 403, "forbid", "RBAC: forbidden by RoleBinding"
        elif kind == "suspicious_secret_ua":
            ua = "python-requests/2.32.3"
        event = aks.event(verb, resource,
                          ns=None if resource == "selfsubjectrulesreviews" else ns,
                          name=name, user=user, groups=groups, src=src, ua=ua,
                          api_group=group, request_object=body, code=code, decision=decision, reason=reason)
        return [aks.record(cluster, event)]
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
    subres = "exec" if kind == "exec" else "ephemeralcontainers" if kind == "ephemeral" else None
    event = aks.event(action, res, ns=None if res in ("clusterroles", "namespaces") else "payments",
                      name=name, subresource=subres, user=service_user, groups=groups,
                      src="10.244.12.17", ua="kubectl/v1.30.4", api_group=group,
                      request_object=body, code=101 if kind == "exec" else 201 if action == "create" else None,
                      stage="ResponseStarted" if kind == "exec" else None,
                      request_query="command=sh&container=payments-api&stdin=true&stdout=true&tty=true"
                      if kind == "exec" else None)
    return [aks.record(cluster, event)]


_KUBE_EXTRA = {
    "clusterrolebinding": ("create", "clusterrolebindings", None, "simulated-admin-binding", "rbac.authorization.k8s.io", {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"simulated-admin-binding"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"payments-api","namespace":"payments"}]}),
    "dashboard_external": ("get", "secrets", "kubernetes-dashboard", "dashboard-token", "", None),
    "node_external": ("list", "pods", None, None, "", None),
    "sidecar_pod": ("create", "pods", "payments", "metrics-sidecar", "", {"apiVersion":"v1","kind":"Pod","metadata":{"name":"metrics-sidecar","namespace":"payments"},"spec":{"containers":[{"name":"app","image":"mcr.microsoft.com/oss/kubernetes/pause:3.9"},{"name":"sidecar","image":"mcr.microsoft.com/oss/kubernetes/pause:3.9"}]}}),
    "pod_delete": ("delete", "pods", "payments", "payments-api-old", "", None),
    "replicaset": ("create", "replicasets", "payments", "payments-api-rs", "apps", {"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"name":"payments-api-rs","namespace":"payments"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"payments-api"}},"template":{"metadata":{"labels":{"app":"payments-api"}},"spec":{"containers":[{"name":"api","image":"mcr.microsoft.com/oss/kubernetes/pause:3.9"}]}}}}),
    "service": ("create", "services", "payments", "payments-api-public", "", {"apiVersion":"v1","kind":"Service","metadata":{"name":"payments-api-public","namespace":"payments"},"spec":{"type":"LoadBalancer","selector":{"app":"payments-api"},"ports":[{"port":443,"targetPort":8443}]}}),
    "network_policy": ("create", "networkpolicies", "payments", "allow-all-egress", "networking.k8s.io", {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"allow-all-egress","namespace":"payments"},"spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[{}]}}),
    "host_ipc": ("create", "pods", "payments", "host-ipc-debug", "", {"apiVersion":"v1","kind":"Pod","metadata":{"name":"host-ipc-debug","namespace":"payments"},"spec":{"hostIPC":True,"containers":[{"name":"debug","image":"mcr.microsoft.com/oss/kubernetes/pause:3.9"}]}}),
    "host_pid": ("create", "pods", "payments", "host-pid-debug", "", {"apiVersion":"v1","kind":"Pod","metadata":{"name":"host-pid-debug","namespace":"payments"},"spec":{"hostPID":True,"containers":[{"name":"debug","image":"mcr.microsoft.com/oss/kubernetes/pause:3.9"}]}}),
    "sensitive_volume": ("create", "pods", "payments", "host-path-debug", "", {"apiVersion":"v1","kind":"Pod","metadata":{"name":"host-path-debug","namespace":"payments"},"spec":{"containers":[{"name":"debug","image":"mcr.microsoft.com/oss/kubernetes/pause:3.9","volumeMounts":[{"name":"host","mountPath":"/host"}]}],"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}),
    "unknown_registry": ("create", "pods", "payments", "external-image", "", {"apiVersion":"v1","kind":"Pod","metadata":{"name":"external-image","namespace":"payments"},"spec":{"containers":[{"name":"app","image":"registry.example.invalid/untrusted/tool:1.0"}]}}),
    "host_network": ("create", "pods", "payments", "host-network-debug", "", {"apiVersion":"v1","kind":"Pod","metadata":{"name":"host-network-debug","namespace":"payments"},"spec":{"hostNetwork":True,"containers":[{"name":"debug","image":"mcr.microsoft.com/oss/kubernetes/pause:3.9"}]}}),
    "privileged_pod": ("create", "pods", "payments", "privileged-debug", "", {"apiVersion":"v1","kind":"Pod","metadata":{"name":"privileged-debug","namespace":"payments"},"spec":{"containers":[{"name":"debug","image":"mcr.microsoft.com/oss/kubernetes/pause:3.9","securityContext":{"privileged":True}}]}}),
    "admission_controller": ("create", "mutatingwebhookconfigurations", None, "simulated-mutating-webhook", "admissionregistration.k8s.io", {"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingWebhookConfiguration","metadata":{"name":"simulated-mutating-webhook"},"webhooks":[{"name":"mutate.example.invalid","clientConfig":{"url":"https://webhook.example.invalid"},"rules":[]}] }),
    "events_delete": ("delete", "events", "payments", "payments-api.2bd5", "", None),
    "enumeration": ("list", "namespaces", None, None, "", None),
    "rbac_enumeration": ("create", "selfsubjectrulesreviews", None, None, "authorization.k8s.io", {"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"payments"}}),
    "secret_enumeration": ("list", "secrets", "payments", None, "", None),
    "secret_access": ("get", "secrets", "payments", "db-credentials", "", None),
    "service_account_external": ("get", "secrets", "payments", "db-credentials", "", None),
    "scan_tool": ("list", "pods", "payments", None, "", None),
    "denied_api": ("get", "secrets", "payments", "db-credentials", "", None),
    "suspicious_secret_ua": ("get", "secrets", "payments", "db-credentials", "", None),
    "unusual_sa_api": ("create", "clusterrolebindings", None, "unusual-sa-binding", "rbac.authorization.k8s.io", {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"unusual-sa-binding"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"payments-api","namespace":"payments"}]}),
}


_KUBE_TARGETS = {
    "kube_anonymous": ("A Kubernetes API operation was successfully invoked by an anonymous user", "anonymous"),
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
    "wip_kube_clusterrolebinding": ("A Kubernetes cluster role binding was created or deleted", "clusterrolebinding"),
    "kube_dashboard_external": ("A Kubernetes dashboard service account was used outside the cluster", "dashboard_external"),
    "kube_node_external": ("A Kubernetes node service account was used outside the cluster", "node_external"),
    "wip_kube_sidecar_pod": ("A Kubernetes Pod was created with a sidecar container", "sidecar_pod"),
    "wip_kube_pod_delete": ("A Kubernetes Pod was deleted", "pod_delete"),
    "wip_kube_replicaset": ("A Kubernetes ReplicaSet was created", "replicaset"),
    "wip_kube_service": ("A Kubernetes service was created or deleted", "service"),
    "wip_kube_network_policy": ("Kubernetes network policy modification", "network_policy"),
    "wip_kube_host_ipc": ("Kubernetes Pod Created with host Inter Process Communications (IPC) namespace", "host_ipc"),
    "wip_kube_host_pid": ("Kubernetes Pod created with host process ID (PID) namespace", "host_pid"),
    "wip_kube_sensitive_volume": ("Kubernetes Pod Created With Sensitive Volume", "sensitive_volume"),
    "wip_kube_unknown_registry": ("Kubernetes pod creation from unknown container image registry", "unknown_registry"),
    "wip_kube_host_network": ("Kubernetes pod creation with host network", "host_network"),
    "wip_kube_privileged_pod": ("Kubernetes Privileged Pod Creation", "privileged_pod"),
    "wip_kube_admission_controller": ("Kubernetes admission controller activity", "admission_controller"),
    "wip_kube_events_delete": ("Kubernetes cluster events deletion", "events_delete"),
    "wip_kube_enumeration": ("Kubernetes enumeration activity", "enumeration"),
    "wip_kube_rbac_enumeration": ("Kubernetes RBAC enumeration", "rbac_enumeration"),
    "wip_kube_secret_enumeration": ("Kubernetes secrets enumeration for the first time", "secret_enumeration"),
    "wip_kube_service_account_external": ("Kubernetes service account activity outside the cluster", "service_account_external"),
    "wip_kube_scan_tool": ("Kubernetes vulnerability scanning tool usage", "scan_tool"),
    "wip_kube_denied_api": ("Denied API call by a Kubernetes service account", "denied_api"),
    "wip_kube_denied_enumeration": ("Kubernetes API enumeration denied across resource types", "denied_enumeration"),
    "wip_kube_unusual_sa_api": ("A Kubernetes service account executed an unusual API call", "unusual_sa_api"),
    "wip_kube_secret_access": ("An identity accessed Azure Kubernetes Secrets", "secret_access"),
    "wip_kube_secret_access_suspicious_ua": ("AKS secret access with a suspicious user agent", "suspicious_secret_ua"),
    "wip_kube_clusterrole_created": ("A Kubernetes cluster role was created", "clusterrole"),
    "wip_kube_rolebinding_create_delete": ("A Kubernetes role binding was created or deleted", "rolebinding"),
    "wip_kube_permission_enumeration": ("A Kubernetes service account has enumerated its permissions", "rbac_enumeration"),
    "wip_kube_serviceaccount_create_delete": ("A Kubernetes service account was created or deleted", "serviceaccount"),
    "wip_kube_events_removed": ("Azure Kubernetes events were deleted", "events_delete"),
    "wip_kube_unusual_secret_access": ("Unusual Kubernetes secret access", "secret_access"),
}


def _storage_threat(config=None, *, mode="first", count=1):
    sub = ae.pick_sub()
    account = ae.pick_name(sub, "storageAccounts")
    caller = ae.pick_nonstandard(config) if mode == "first" else ae.pick_admin(config, ae.DATA_OPS)
    out = []
    if mode == "copy":
        # Stable external subscription/account: the detector describes an unmonitored destination.
        dest_sub = dict(ae.PROD, id=ae.guid("foreign-storage-subscription"), name="external-archive", env="prod")
        destination = "stforeignarchive0042"
        return dp.storage_copy_records(account, sub, destination, dest_sub, caller)
    if mode == "model":
        caller = ae.pick_nonstandard(config)
        return [dp.storage_record(account, sub, caller, "GetBlob", "StorageRead", container="models",
                                  blob="vision-encoder-v3.onnx")]
    if mode == "enumerate":
        caller = ae.pick_admin(config, ae.DATA_OPS)
        return [dp.storage_record(account, sub, caller, "ListBlobs", "StorageRead", container=c,
                                  offset_s=-i * 4.0)
                for i, c in enumerate(["exports", "datasets", "backups", "logs", "artifacts", "uploads",
                                       "bronze", "silver", "gold", "diagnostics"])]
    if mode == "object_read":
        caller = ae.pick_nonstandard(config)
        return [dp.storage_record(account, sub, caller, "GetBlob", "StorageRead", container="datasets",
                                  blob="research-cohort.parquet")]
    if mode == "dataset_modify":
        caller = ae.pick_nonstandard(config)
        return [dp.storage_record(account, sub, caller, "SetBlobMetadata", "StorageWrite", container="datasets",
                                  blob="labels/quality-review.csv")]
    if mode in ("shared_key", "sas"):
        caller = ae.pick_admin(config, ae.DATA_OPS)
        auth_type = "AccountKey" if mode == "shared_key" else "SAS"
        op = "GetBlob" if mode == "shared_key" else "ListBlobs"
        return [dp.storage_record(account, sub, caller, op, "StorageRead", container="exports",
                                  blob="quarterly-report.parquet", authentication_type=auth_type)]
    for i in range(count):
        container = "backups" if mode == "backup" else None
        blob = f"backup-{i:04d}.bak" if mode == "backup" else f"download-{uuid.uuid4().hex[:12]}.parquet"
        out.append(dp.storage_record(account, sub, caller, "GetBlob", "StorageRead", container=container,
                                     blob=blob, offset_s=-i * 2.0))
    return out


def _keyvault_threat(config=None, op="SecretList", *, count=1):
    sub = ae.pick_sub()
    caller = ae.pick_nonstandard(config) if op == "SecretGet" and count >= 12 else ae.pick_admin(config, ae.SEC_OPS)
    vault = ae.pick_name(sub, "vaults")
    return [dp.keyvault_record(vault, sub, caller, op, object_name=f"service-{i:02d}", offset_s=-i * 3.0)
            for i in range(count)]


def _ai_threat(config=None, count=1, status=200, op="ChatCompletions_Create"):
    sub = ae.PROD
    caller = ae.app_caller(random.choice(list(ae.SERVICE_PRINCIPALS)), "ServicePrincipal")
    account = ae.pick_name(sub, "accounts")
    deployment, model = random.choice(dp._AI_DEPLOYMENTS)
    return [dp.ai_record(account, sub, caller, op, status=status,
                         offset_s=-i * 3.0, deployment=deployment, model=model,
                         file_id=f"file-{uuid.uuid4().hex[:32]}" if op == "Files_GetFileContent" else None)
            for i in range(count)]


def _public_storage(config=None):
    return _make_arm_scenario("Microsoft.Storage/storageAccounts/write", "data",
                              "Storage Account Contributor")(config)


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
    "wip_storage_enumeration": lambda config=None: _storage_threat(config, mode="enumerate"),
    "wip_unusual_cloud_object_read": lambda config=None: _storage_threat(config, mode="object_read"),
    "wip_ai_dataset_label_modify": lambda config=None: _storage_threat(config, mode="dataset_modify"),
    "wip_storage_cross_account_copy": lambda config=None: _storage_threat(config, mode="copy"),
    "wip_storage_shared_key_access": lambda config=None: _storage_threat(config, mode="shared_key"),
    "wip_storage_sas_access": lambda config=None: _storage_threat(config, mode="sas"),
    "wip_ml_model_download": lambda config=None: _storage_threat(config, mode="model"),
    "wip_keyvault_key_change": lambda config=None: _keyvault_threat(config, "KeyRotate"),
    "wip_keyvault_secret_dump": lambda config=None: _keyvault_threat(config, "SecretGet", count=12),
    "wip_keyvault_key_management": lambda config=None: _keyvault_threat(config, "KeyRotate"),
    "wip_ai_model_discovery": lambda config=None: _ai_threat(config, count=6, op="Models_List"),
    "wip_ai_denial_of_wallet": lambda config=None: _ai_threat(config, count=24),
    "wip_ai_dataset_download": lambda config=None: _ai_threat(config, count=8, op="Files_GetFileContent"),
    "wip_keyvault_key_modified": lambda config=None: _keyvault_threat(config, "KeyUpdate"),
    "wip_keyvault_secret_modified": lambda config=None: _keyvault_threat(config, "SecretSet"),
    "wip_keyvault_secret_deleted": lambda config=None: _keyvault_threat(config, "SecretDelete"),
    "wip_keyvault_certificate_create": lambda config=None: _keyvault_threat(config, "CertificateCreate"),
    "wip_multiple_snapshot_exports": _multi_snapshot_export,
    "wip_multiple_resource_deletions": _multi_resource_deletion,
    "wip_multiple_denied_actions": _multi_denied_actions,
    "wip_heavy_compute_allocation": _heavy_compute_allocation,
    "wip_dormant_region_compute": _dormant_region_compute,
    "wip_multiple_unusual_activities": _multi_unusual_activities,
    "wip_cross_project_activity": _cross_project_activity,
    "wip_newly_seen_resource_change": _newly_seen_resource_change,
    "wip_storage_versioning_disabled": lambda config=None: _storage_protection_change(config, versioning=True),
    "wip_storage_soft_delete_disabled": lambda config=None: _storage_protection_change(config, versioning=False),
})
SCENARIOS["wip_adfs_health_server_added"] = _adfs_health_server_added
SCENARIOS["wip_storage_public"] = _public_storage
SCENARIOS["wip_compute_allocation"] = _compute_allocation
SCENARIOS["wip_kube_cluster_created_deleted"] = SCENARIOS["wip_aks_cluster_change"]
SCENARIOS.update({
    "wip_multi_region_enumeration": _multi_region_enumeration,
    "wip_vm_ssh_key_modification": _vm_ssh_key_change,
    "wip_granting_access_account": SCENARIOS["wip_role_assignment"],
    "wip_backup_delete_protection_disabled": SCENARIOS["wip_backup_policy_change"],
    "wip_database_export_exfiltration": SCENARIOS["wip_sql_export"],
    "wip_new_domain_activity": lambda config=None: _new_domain_activity(config),
    "wip_keyvault_modified_exact": SCENARIOS["wip_keyvault_config"],
    "wip_permission_delegation_granted": SCENARIOS["wip_role_assignment"],
    "wip_blob_anonymous_access": SCENARIOS["wip_blob_public_access"],
    "wip_storage_suspicious_bulk_download": lambda config=None: _storage_threat(config, mode="bulk", count=16),
    "wip_storage_multiple_objects_suspicious": lambda config=None: _storage_threat(config, mode="bulk", count=16),
    "wip_keyvault_modification_exact": SCENARIOS["wip_keyvault_config"],
    "wip_unusual_ai_dataset_modification": lambda config=None: _storage_threat(config, mode="dataset_modify"),
})

# Published Cortex targets. These are intentionally unconfirmed scenario mappings; the wip_
# key makes that status visible in the on-demand catalog until a real alert validates the shape.
ANALYTIC_ALERTS = {key: alert for key, (alert, *_rest) in {**_ARM_TARGETS, **_KUBE_TARGETS}.items()}
ANALYTIC_ALERTS.update({
    "wip_adfs_health_server_added": "A New Server was Added to an Azure Active Directory Hybrid Health ADFS Environment",
    "wip_multi_region_enumeration": "Multi region enumeration activity",
    "wip_vm_ssh_key_modification": "Suspicious cloud compute instance SSH keys modification attempt",
    "wip_storage_multiple_downloads": "An identity performed a suspicious download of multiple cloud storage objects",
    "wip_keyvault_config": "Azure Key Vault modification",
    "wip_role_assignment": "Azure permission delegation granted",
    "wip_blob_public_access": "Azure storage account blob anonymous access is enabled",
    "wip_multiple_resource_deletions": "Deletion of multiple cloud resources",
    "wip_unusual_cloud_object_read": "Suspicious identity downloaded multiple objects from a bucket",
    "wip_keyvault_config": "An Azure Key Vault was modified",
    "wip_role_assignment": "An identity was granted permissions to manage user access to Azure resources",
    "wip_blob_public_access": "Azure Blob Container Access Level Modification",
    "wip_storage_multiple_downloads": "An identity performed a suspicious download of multiple cloud storage objects",
    "wip_vm_ssh_key_modification": "Suspicious cloud compute instance SSH keys modification attempt",
    "wip_backup_policy_change": "Cloud storage automatic backup disabled",
    "wip_backup_delete_protection_disabled": "Cloud storage delete protection disabled",
    "wip_database_export": "Data exfiltration from cloud database",
    "wip_network_packet_capture": "Network sniffing detected in Cloud environment",
    "wip_granting_access_account": "Granting Access to an Account",
    "wip_database_export_exfiltration": "Data exfiltration from cloud database",
    "wip_kube_cluster_created_deleted": "A Kubernetes cluster was created or deleted",
    "wip_storage_first_access": "An identity accessed a cloud storage for the first time",
    "wip_storage_backup_access": "An identity accessed a backup cloud storage",
    "wip_storage_multiple_downloads": "An identity initiated a download of multiple cloud objects",
    "wip_storage_enumeration": "Storage enumeration activity",
    "wip_unusual_cloud_object_read": "An unusual read activity of cloud object",
    "wip_storage_cross_account_copy": "A cloud storage object was copied to a foreign cloud account",
    "wip_ml_model_download": "Suspicious ML Model Download",
    "wip_keyvault_key_change": "Unusual key management activity",
    "wip_keyvault_secret_dump": "Suspicious secrets dump activity",
    "wip_keyvault_key_management": "Unusual key management activity",
    "wip_ai_model_discovery": "AI model discovery",
    "wip_ai_denial_of_wallet": "Potential denial of wallet abusing AI services",
    "wip_ai_dataset_download": "Suspicious AI Dataset Download",
    "wip_keyvault_key_modified": "An Azure Key Vault key was modified",
    "wip_keyvault_secret_modified": "Azure Key Vault Secrets were modified",
    "wip_keyvault_secret_deleted": "Unusual secret management activity",
    "wip_keyvault_certificate_create": "Unusual certificate management activity",
    "wip_multiple_snapshot_exports": "Multiple cloud snapshots export",
    "wip_multiple_resource_deletions": "Deletion of multiple cloud resources",
    "wip_multiple_denied_actions": "Cloud user performed multiple actions that were denied",
    "wip_heavy_compute_allocation": "Suspicious heavy allocation of compute resources - possible mining activity",
    "wip_dormant_region_compute": "Compute activity in dormant cloud region",
    "wip_multiple_unusual_activities": "A cloud identity performed multiple unusual activities",
    "wip_cross_project_activity": "Unusual cross projects activity",
    "wip_newly_seen_resource_change": "Unusual resource modification by newly seen IAM user",
    "wip_storage_versioning_disabled": "Object versioning was disabled",
    "wip_storage_soft_delete_disabled": "Soft delete of cloud storage configuration was disabled",
    "wip_keyvault_modified_exact": "An Azure Key Vault was modified",
    "wip_permission_delegation_granted": "Azure permission delegation granted",
    "wip_blob_anonymous_access": "Azure storage account blob anonymous access is enabled",
    "wip_storage_suspicious_bulk_download": "An identity performed a suspicious download of multiple cloud storage objects",
    "wip_storage_multiple_objects_suspicious": "Suspicious identity downloaded multiple objects from a bucket",
    "wip_new_domain_activity": "An operation was performed by an identity from a domain that was not seen in the organization",
    "wip_ai_dataset_label_modify": "Suspicious AI Dataset Label Modification",
    "wip_keyvault_modification_exact": "Azure Key Vault modification",
    "wip_unusual_ai_dataset_modification": "Unusual AI dataset modification",
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

# Scenarios promoted out of wip_ once their alert was observed firing on this feed's data
# (2026-10-23/24 fire-all). Old wip_ names still resolve on demand via this table.
_RENAMED_THREATS = {
    "WIP_AI_SAFEGUARD_DELETE": "ai_safeguard_delete",
    "WIP_AI_SAFEGUARD_MODIFY": "ai_safeguard_modify",
    "WIP_ALERT_RULE_DELETE": "alert_rule_delete",
    "WIP_EVENTHUB_DELETE": "eventhub_delete",
    "WIP_FIREWALL_POLICY_DELETE": "firewall_policy_delete",
    "WIP_KUBE_ANONYMOUS": "kube_anonymous",
    "WIP_KUBE_DASHBOARD_EXTERNAL": "kube_dashboard_external",
    "WIP_KUBE_NODE_EXTERNAL": "kube_node_external",
    "WIP_NETWORK_WATCHER_DELETE": "network_watcher_delete",
    "WIP_VM_COMMAND": "vm_command",
}
