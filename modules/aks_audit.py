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
import copy
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
    if event is None:
        return None
    return {"operationName": OPERATION, "category": "kube-audit", "ccpNamespace": cluster["ccp"],
            "resourceId": cluster["id"].upper(), "time": event["stageTimestamp"],
            "properties": {"log": json.dumps(event, separators=(",", ":")), "stream": "stdout",
                           "pod": f"kube-apiserver-{_h('apis:' + cluster['name'])[:10]}-{_h('apis2:' + cluster['name'])[:5]}",
                           "containerID": _h("cid:" + cluster["name"])}}


def _audit_level(verb, resource, api_group, subresource=None, *, user="", groups=(), namespace=None,
                 name=None):
    """Apply the relevant rules from Microsoft's documented managed AKS audit policy."""
    resource = resource.lower()
    verb = verb.lower()
    groups = set(groups)
    if user == "aksService" and verb in {"get", "list"}:
        return "None"
    if user == "system:kube-proxy" and verb == "watch" and resource in {"endpoints", "services"}:
        return "None"
    if (user == "kubelet" or "system:nodes" in groups) and verb == "get" \
            and resource == "nodes" and subresource in (None, "status"):
        return "None"
    if user == "system:apiserver" and verb == "get" and resource == "namespaces" \
            and subresource in (None, "status", "finalize"):
        return "None"
    if api_group == "metrics.k8s.io" and user == "aksService" and verb in {"get", "list"}:
        return "None"
    if resource == "events":
        if verb in {"delete", "list"}:
            return "Metadata"
        if verb in {"create", "update", "patch"} and namespace in {"default", "kube-system"}:
            return "Metadata"
        return "None"
    if resource in {"secrets", "configmaps", "serviceaccounts", "serviceaccounts/token",
                    "tokenreviews"}:
        return "Metadata"
    if resource in {"nodes", "pods"} and subresource == "status" \
            and verb in {"update", "patch"} \
            and ("system:nodes" in groups or user in {"client", "kubelet",
                "system:node-problem-detector", "system:serviceaccount:kube-system:node-problem-detector",
                "system:serviceaccount:kube-system:aci-connector-linux"}):
        return "Request"
    if verb == "deletecollection" and user == "system:serviceaccount:kube-system:namespace-controller":
        return "Request"
    if api_group == "apiextensions.k8s.io" and resource == "customresourcedefinitions" \
            and name in {"volumesnapshotcontents.snapshot.storage.k8s.io",
                         "volumesnapshots.snapshot.storage.k8s.io"} \
            and verb in {"update", "patch"}:
        return "Request"
    if api_group == "apiextensions.k8s.io" and resource == "customresourcedefinitions" \
            and name == "installations.operator.tigera.io":
        return "Metadata"
    if resource == "configmaps" and name == "coredns-custom" and namespace == "kube-system" \
            and verb in {"update", "patch"}:
        return "RequestResponse"
    known_groups = {"", "admissionregistration.k8s.io", "apiextensions.k8s.io",
                    "apiregistration.k8s.io", "apps", "authentication.k8s.io",
                    "authorization.k8s.io", "autoscaling", "batch", "certificates.k8s.io",
                    "extensions", "metrics.k8s.io", "networking.k8s.io", "policy",
                    "rbac.authorization.k8s.io", "scheduling.k8s.io", "settings.k8s.io",
                    "storage.k8s.io"}
    if verb in {"get", "list", "watch"}:
        return "Request" if api_group in known_groups else "Metadata"
    return "RequestResponse" if api_group in known_groups else "Metadata"


def event(verb, resource, *, ns=None, name=None, subresource=None, user, groups=None, src="10.224.0.4",
          ua=None, code=None, api_group="", api_version="v1", request_object=None,
          response_object=None, decision="allow", reason="", offset_s=0.0, stage=None,
          request_query=None):
    """One audit.k8s.io/v1 Event with a level matching AKS's managed audit policy."""
    path = f"/apis/{api_group}/{api_version}" if api_group else f"/api/{api_version}"
    if ns:
        path += f"/namespaces/{ns}"
    path += f"/{resource}"
    if name:
        path += f"/{name}"
    if subresource:
        path += f"/{subresource}"
    if request_query:
        path += "?" + request_query
    elif verb in ("list", "watch") and not name:
        path += "?watch=true" if verb == "watch" else "?limit=500"
    stage = stage or ("ResponseStarted" if verb == "watch" else "ResponseComplete")
    if code is None:
        code = 201 if verb == "create" else 200
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
    level = _audit_level(verb, resource, api_group, subresource, user=user, groups=groups or (),
                         namespace=ns, name=name)
    if level == "None":
        return None
    ev = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": level,
          "auditID": str(uuid.uuid4()), "stage": stage, "requestURI": path,
          "verb": verb, "user": {"username": user, "groups": groups or ["system:authenticated"]},
          "sourceIPs": [src], "userAgent": ua or _KUBECTL_UA, "objectRef": obj,
          "responseStatus": {"metadata": {}, "code": code,
                             "status": "Failure" if code >= 400 else "Success"},
          "requestReceivedTimestamp": t_start, "stageTimestamp": t_end,
          "annotations": {"authorization.k8s.io/decision": decision,
                          "authorization.k8s.io/reason": reason or (
                              "RBAC: no RBAC policy matched" if decision == "forbid" else
                              'RBAC: allowed by ClusterRoleBinding "payments-workload-access"')}}
    if code >= 400:
        ev["responseStatus"].update({"status": "Failure", "reason": "Forbidden" if code == 403 else "NotFound"})
    if level in ("Request", "RequestResponse") and request_object is not None:
        ev["requestObject"] = request_object
    if level == "RequestResponse" and code < 400:
        response = response_object
        if response is None and isinstance(request_object, dict):
            response = copy.deepcopy(request_object)
            metadata = response.setdefault("metadata", {})
            metadata.setdefault("uid", str(uuid.uuid4()))
            metadata.setdefault("resourceVersion", str(random.randint(100000, 999999)))
            metadata.setdefault("creationTimestamp", _ts(offset_s))
        elif response is None and request_object is not None:
            # JSON Patch and merge-patch request bodies can be arrays/scalars. The API server
            # responds with the resulting resource object, never by mutating the patch document.
            response = {"apiVersion": f"{api_group}/{api_version}" if api_group else api_version,
                        "kind": "Status", "status": "Success", "code": code}
        elif response is None and verb in {"delete", "deletecollection"} and 200 <= code < 300:
            response = {"apiVersion": "v1", "kind": "Status", "status": "Success", "code": code}
            if name:
                response["details"] = {"name": name, "kind": resource.rstrip("s").capitalize()}
        elif response is None and name and 200 <= code < 300:
            kinds = {"pods": "Pod", "namespaces": "Namespace", "deployments": "Deployment",
                     "replicasets": "ReplicaSet", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet",
                     "cronjobs": "CronJob", "services": "Service", "networkpolicies": "NetworkPolicy",
                     "roles": "Role", "clusterroles": "ClusterRole", "rolebindings": "RoleBinding",
                     "clusterrolebindings": "ClusterRoleBinding", "ingresses": "Ingress"}
            metadata = {"name": name, "uid": str(uuid.uuid4()),
                        "resourceVersion": str(random.randint(100000, 999999)),
                        "creationTimestamp": _ts(offset_s)}
            if ns:
                metadata["namespace"] = ns
            response = {"apiVersion": f"{api_group}/{api_version}" if api_group else api_version,
                        "kind": kinds.get(resource, resource.rstrip("s").capitalize()),
                        "metadata": metadata}
        if response is not None:
            ev["responseObject"] = response
    return ev


def sa(ns, name):
    return f"system:serviceaccount:{ns}:{name}", ["system:serviceaccounts", f"system:serviceaccounts:{ns}",
                                                  "system:authenticated"]


def human(upn):
    """An Entra user signing in to the cluster through kubelogin (AKS-managed Entra integration)."""
    return upn, ["system:authenticated", ae.guid("aks-admins")]


def _read_name(resource, namespace, cluster):
    if resource == "nodes":
        return node(cluster)
    app = random.choice(APPS.get(namespace, APPS["default"]))
    if resource == "pods":
        return f"{app}-{_h('pod:' + app)[:10]}"
    if resource == "events":
        return f"{app}.{_h('event:' + app)[:8]}"
    if resource == "services":
        return f"{app}-service"
    return app


# ── benign control-plane chatter ──────────────────────────────────────────────────────
def _b_controller(c):
    comp = random.choice(["kube-controller-manager", "kube-scheduler"])
    res, grp = random.choice([("pods", ""), ("nodes", ""), ("endpoints", ""), ("replicasets", "apps"),
                              ("deployments", "apps"), ("leases", "coordination.k8s.io"),
                              ("endpointslices", "discovery.k8s.io")])
    verb = "update" if res == "leases" else random.choice(["list", "watch", "get"])
    ns = "kube-system" if res == "leases" else (None if res == "nodes" or verb != "get" else random.choice(NAMESPACES))
    name = comp if res == "leases" else _read_name(res, ns, c) if verb == "get" else None
    return event(verb, res, ns=ns, name=name, user=f"system:{comp}", groups=["system:authenticated"],
                 ua=_K8S_UA.format(comp=comp), api_group=grp, src="10.224.0.4")


def _b_kubelet(c):
    i = random.randrange(4)
    nd = node(c, i)
    res, verb, sub, grp = random.choice([("nodes", "patch", "status", ""), ("leases", "update", None, "coordination.k8s.io"),
                                         ("pods", "get", None, ""), ("pods", "patch", "status", ""),
                                         ("configmaps", "watch", None, ""), ("secrets", "watch", None, "")])
    ns = {"leases": "kube-node-lease", "nodes": None}.get(res, random.choice(NAMESPACES))
    name = nd if res in ("nodes", "leases") else _read_name(res, ns, c) if verb == "get" else None
    return event(verb, res, ns=ns, name=name, subresource=sub, user=f"system:node:{nd}",
                 groups=["system:nodes", "system:authenticated"], ua=_K8S_UA.format(comp="kubelet"),
                 api_group=grp, src=f"{c['node_cidr']}.{4 + i}")


def _b_workload(c):
    ns = random.choice([n for n in NAMESPACES if n != "default"])
    res, verb = random.choice([("configmaps", "get"), ("endpoints", "list"), ("pods", "list"),
                               ("leases", "update"), ("events", "create")])
    if res == "events":
        ns = "default"  # AKS logs event writes only in default and kube-system.
    app = random.choice(APPS[ns])
    user, groups = sa(ns, app)
    grp = "coordination.k8s.io" if res == "leases" else ""
    return event(verb, res, ns=ns, name=app if verb in ("get", "update") else None, user=user, groups=groups,
                 ua=f"{app}/1.0 (linux/amd64) kubernetes/client-go", api_group=grp,
                 src=f"{c['pod_cidr']}.{random.randint(0, 3)}.{random.randint(2, 250)}", code=201 if verb == "create" else 200)


def _b_ci_rollout(c):
    """The CI service account rolls a new image by patching an existing deployment."""
    ns = random.choice([n for n in NAMESPACES if n in ("payments", "orders", "catalog", "web")])
    user, groups = sa("ci", "azdo-deployer")
    deployment = random.choice(APPS[ns])
    patch = [{"op": "replace", "path": "/spec/template/spec/containers/0/image",
              "value": f"logsim.azurecr.io/{deployment}:v20261023"}]
    return event("patch", "deployments", ns=ns, name=deployment, user=user, groups=groups,
                 ua="kubectl/v1.30.4 (linux/amd64) kubernetes/a51b3b7", api_group="apps", api_version="v1",
                 request_object=patch,
                 response_object={"apiVersion": "apps/v1", "kind": "Deployment",
                                  "metadata": {"name": deployment, "namespace": ns,
                                               "uid": _h("deployment:" + deployment)[:32],
                                               "resourceVersion": str(random.randint(100000, 999999)),
                                               "creationTimestamp": _ts()}},
                 src="52.252.0.45")


def _b_admin_read(c, admin_upn):
    """A platform engineer inspecting the cluster with kubectl (read-only)."""
    user, groups = human(admin_upn)
    res, grp = random.choice([("pods", ""), ("deployments", "apps"), ("services", ""), ("nodes", ""),
                              ("events", ""), ("ingresses", "networking.k8s.io")])
    ns = None if res == "nodes" else random.choice(NAMESPACES)
    verb = random.choice(["get", "list"])
    name = _read_name(res, ns, c) if verb == "get" else None
    return event(verb, res, ns=ns, name=name, user=user, groups=groups, api_group=grp,
                 src=f"{c['node_cidr']}.{random.randint(30, 60)}")


def benign(admin_upn=None):
    """One routine audit record from one of the clusters."""
    c = random.choices(CLUSTERS, weights=(3, 1))[0]
    fns = [(_b_controller, 30), (_b_kubelet, 35), (_b_workload, 25), (_b_ci_rollout, 3)]
    if admin_upn:
        fns.append((lambda cl: _b_admin_read(cl, admin_upn), 7))
    f = random.choices([x for x, _w in fns], weights=[w for _x, w in fns])[0]
    return [record(c, f(c))]
