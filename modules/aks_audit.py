"""AKS API-server audit logs (diagnostic category kube-audit) streamed to an event hub, for
modules/azure_activity.py (helper, not a generator).

Each record is the event-hub envelope AKS diagnostic settings emit -- operationName
Microsoft.ContainerService/managedClusters/diagnosticLogs/Read, category kube-audit, the cluster's
resourceId -- with properties.log holding one Kubernetes audit.k8s.io/v1 Event as a JSON string
(verb, requestURI, user, sourceIPs, userAgent, objectRef, responseStatus, annotations).

The benign baseline is what a cluster's own control plane and workloads do all day: controllers,
the scheduler and kubelets reading and watching, leases renewed, node status patched, events
recorded, CI rolling deployments by patch. Creating or deleting the objects the Kubernetes
detectors key on (secrets, configmaps, workloads, RBAC, namespaces, service accounts), exec,
ephemeral containers and permission self-reviews are left to the threat scenarios.
"""
import datetime
import hashlib
import json
import random
import time
import uuid

from modules import azure_estate as ae

OPERATION = "Microsoft.ContainerService/managedClusters/diagnosticLogs/Read"


def _ts(offset_s=0.0):
    d = datetime.datetime.fromtimestamp(time.time() + min(0.0, offset_s), datetime.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond:06d}Z"


def _h(s):
    return hashlib.sha256(str(s).encode()).hexdigest()


# The estate's clusters: prod and nonprod, each with a stable node pool and pod CIDR.
CLUSTERS = []
for _sub in (ae.PROD, ae.SUBSCRIPTIONS[1]):
    _name = ae.resource_name(_sub, "managedClusters", 0)
    CLUSTERS.append({"sub": _sub, "name": _name,
                     "id": ae.rid(_sub, "Microsoft.ContainerService", "managedClusters", _name),
                     "ccp": _h("ccp:" + _name)[:24], "pool": f"aks-nodepool1-{int(_h('pool:' + _name)[:8], 16) % 10 ** 8}",
                     "pod_cidr": "10.244", "node_cidr": "10.224.0"})

NAMESPACES = ["default", "payments", "orders", "catalog", "web", "monitoring", "ingress-nginx", "cert-manager"]
APPS = {"payments": ["payments-api", "ledger-worker"], "orders": ["orders-api", "orders-sync"],
        "catalog": ["catalog-api", "search-indexer"], "web": ["storefront", "bff"],
        "monitoring": ["prometheus", "grafana"], "ingress-nginx": ["ingress-nginx-controller"],
        "cert-manager": ["cert-manager"], "default": ["toolbox"]}
_KUBECTL_UA = "kubectl/v1.30.4 (linux/amd64) kubernetes/a51b3b7"
_K8S_UA = "{comp}/v1.30.4 (linux/amd64) kubernetes/a51b3b7"


def node(cluster, i=None):
    return f"{cluster['pool']}-vmss{(i if i is not None else random.randrange(4)):06d}"


def record(cluster, event, offset_s=0.0):
    """Wrap one audit Event in the kube-audit event-hub envelope."""
    return {"operationName": OPERATION, "category": "kube-audit", "ccpNamespace": cluster["ccp"],
            "resourceId": cluster["id"].upper(), "time": event["stageTimestamp"],
            "properties": {"log": json.dumps(event, separators=(",", ":")), "stream": "stdout",
                           "pod": f"kube-apiserver-{_h('apis:' + cluster['name'])[:10]}-{_h('apis2:' + cluster['name'])[:5]}",
                           "containerID": _h("cid:" + cluster["name"])}}


def event(verb, resource, *, ns=None, name=None, subresource=None, user, groups=None, src="10.224.0.4",
          ua=None, code=200, api_group="", api_version="v1", request_object=None, decision="allow",
          reason="", offset_s=0.0, level="Metadata"):
    """One audit.k8s.io/v1 Event (stage ResponseComplete)."""
    path = f"/apis/{api_group}/{api_version}" if api_group else f"/api/{api_version}"
    if ns:
        path += f"/namespaces/{ns}"
    path += f"/{resource}"
    if name:
        path += f"/{name}"
    if subresource:
        path += f"/{subresource}"
    if verb in ("list", "watch") and not name:
        path += "?watch=true" if verb == "watch" else "?limit=500"
    t_end = _ts(offset_s)
    t_start = _ts(offset_s - random.uniform(0.002, 0.3))
    obj = {"resource": resource, "apiVersion": api_version}
    if api_group:
        obj["apiGroup"] = api_group
    if ns:
        obj["namespace"] = ns
    if name:
        obj["name"] = name
    if subresource:
        obj["subresource"] = subresource
    ev = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": level,
          "auditID": str(uuid.uuid4()), "stage": "ResponseComplete", "requestURI": path,
          "verb": verb, "user": {"username": user, "groups": groups or ["system:authenticated"]},
          "sourceIPs": [src], "userAgent": ua or _KUBECTL_UA, "objectRef": obj,
          "responseStatus": {"metadata": {}, "code": code},
          "requestReceivedTimestamp": t_start, "stageTimestamp": t_end,
          "annotations": {"authorization.k8s.io/decision": decision,
                          "authorization.k8s.io/reason": reason or (
                              "" if decision == "forbid" else 'RBAC: allowed by ClusterRoleBinding "system:basic-user"')}}
    if code >= 400:
        ev["responseStatus"].update({"status": "Failure", "reason": "Forbidden" if code == 403 else "NotFound"})
    if request_object is not None:
        ev["requestObject"] = request_object
        ev["level"] = "RequestResponse"
    return ev


def sa(ns, name):
    return f"system:serviceaccount:{ns}:{name}", ["system:serviceaccounts", f"system:serviceaccounts:{ns}",
                                                  "system:authenticated"]


def human(upn):
    """An Entra user signing in to the cluster through kubelogin (AKS-managed Entra integration)."""
    return upn, ["system:authenticated", ae.guid("aks-admins")]


# ── benign control-plane chatter ──────────────────────────────────────────────────────
def _b_controller(c):
    comp = random.choice(["kube-controller-manager", "kube-scheduler"])
    res, grp = random.choice([("pods", ""), ("nodes", ""), ("endpoints", ""), ("replicasets", "apps"),
                              ("deployments", "apps"), ("leases", "coordination.k8s.io"),
                              ("endpointslices", "discovery.k8s.io")])
    verb = "update" if res == "leases" else random.choice(["list", "watch", "get"])
    ns = "kube-system" if res == "leases" else (None if res == "nodes" or verb != "get" else random.choice(NAMESPACES))
    name = comp if res == "leases" else None
    return event(verb, res, ns=ns, name=name, user=f"system:{comp}", groups=["system:authenticated"],
                 ua=_K8S_UA.format(comp=comp), api_group=grp, src="10.224.0.4")


def _b_kubelet(c):
    i = random.randrange(4)
    nd = node(c, i)
    res, verb, sub, grp = random.choice([("nodes", "patch", "status", ""), ("leases", "update", None, "coordination.k8s.io"),
                                         ("pods", "get", None, ""), ("pods", "patch", "status", ""),
                                         ("configmaps", "watch", None, ""), ("secrets", "watch", None, "")])
    ns = {"leases": "kube-node-lease", "nodes": None}.get(res, random.choice(NAMESPACES))
    name = nd if res in ("nodes", "leases") else None
    return event(verb, res, ns=ns, name=name, subresource=sub, user=f"system:node:{nd}",
                 groups=["system:nodes", "system:authenticated"], ua=_K8S_UA.format(comp="kubelet"),
                 api_group=grp, src=f"{c['node_cidr']}.{4 + i}")


def _b_workload(c):
    ns = random.choice([n for n in NAMESPACES if n != "default"])
    app = random.choice(APPS[ns])
    user, groups = sa(ns, app)
    res, verb = random.choice([("configmaps", "get"), ("endpoints", "list"), ("pods", "list"),
                               ("leases", "update"), ("events", "create")])
    grp = "coordination.k8s.io" if res == "leases" else ""
    return event(verb, res, ns=ns, name=app if verb in ("get", "update") else None, user=user, groups=groups,
                 ua=f"{app}/1.0 (linux/amd64) kubernetes/client-go", api_group=grp,
                 src=f"{c['pod_cidr']}.{random.randint(0, 3)}.{random.randint(2, 250)}", code=201 if verb == "create" else 200)


def _b_ci_rollout(c):
    """The CI service account rolls a new image by patching an existing deployment."""
    ns = random.choice([n for n in NAMESPACES if n in ("payments", "orders", "catalog", "web")])
    user, groups = sa("ci", "azdo-deployer")
    return event("patch", "deployments", ns=ns, name=random.choice(APPS[ns]), user=user, groups=groups,
                 ua="kubectl/v1.30.4 (linux/amd64) kubernetes/a51b3b7", api_group="apps", api_version="v1",
                 src="52.252.0.45")


def _b_admin_read(c, admin_upn):
    """A platform engineer inspecting the cluster with kubectl (read-only)."""
    user, groups = human(admin_upn)
    res, grp = random.choice([("pods", ""), ("deployments", "apps"), ("services", ""), ("nodes", ""),
                              ("events", ""), ("ingresses", "networking.k8s.io")])
    ns = None if res == "nodes" else random.choice(NAMESPACES)
    return event(random.choice(["get", "list"]), res, ns=ns, user=user, groups=groups, api_group=grp,
                 src=f"{c['node_cidr']}.{random.randint(30, 60)}")


def benign(admin_upn=None):
    """One routine audit record from one of the clusters."""
    c = random.choices(CLUSTERS, weights=(3, 1))[0]
    fns = [(_b_controller, 30), (_b_kubelet, 35), (_b_workload, 25), (_b_ci_rollout, 3)]
    if admin_upn:
        fns.append((lambda cl: _b_admin_read(cl, admin_upn), 7))
    f = random.choices([x for x, _w in fns], weights=[w for _x, w in fns])[0]
    return [record(c, f(c))]
