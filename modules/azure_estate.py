"""The synthetic Azure estate behind modules/azure_activity.py: subscriptions, resource groups,
named resources, and the identities that act on them (helper, not a generator).

Everything here is deterministic, so resources recur the way they do in a real tenant: the same
storage accounts, vaults and VMs appear day after day, and a never-seen resource or region is
genuinely new. Identities come from LogSim's shared user model (azure_common), so the admin who
changes an NSG is the same person who signed in to Entra and logged on to Windows.

Caller identity is the `identity.claims` object of an Activity record. XSIAM's cloud normaliser
reads the user from it; a canary carrying only upn/name/appid was attributed to the appid, so
callers carry the full claim set of Microsoft's documented event-hub sample (objectidentifier,
xmlsoap name and upn, puid, tenantid, scope, ...).
"""
import hashlib
import random
import time

from modules import azure_common as ac

TENANT_ID = ac.HOME_TENANT_ID


def _h(s):
    return int(hashlib.sha256(str(s).encode()).hexdigest(), 16)


def guid(seed):
    return ac._stable_guid("azest:" + str(seed))


def hex32(seed):
    return guid(seed).replace("-", "")


# ── subscriptions and resource groups ─────────────────────────────────────────────────
# The prod subscription id is the one the 2026-10-21 canary used, so its resources stay part
# of the same estate.
SUBSCRIPTIONS = [
    {"name": "examplecorp-prod", "id": "7d1f0a4e-2b6c-4c8e-9a51-3e0f6b2d9c14", "env": "prod",
     "mgs": ("mg-examplecorp", "mg-landingzones", "mg-prod"), "regions": ("eastus", "eastus2")},
    {"name": "examplecorp-nonprod", "id": guid("sub:nonprod"), "env": "dev",
     "mgs": ("mg-examplecorp", "mg-landingzones", "mg-nonprod"), "regions": ("eastus", "centralus")},
    {"name": "examplecorp-shared-services", "id": guid("sub:shared"), "env": "shared",
     "mgs": ("mg-examplecorp", "mg-platform"), "regions": ("eastus", "westus2")},
    {"name": "examplecorp-data", "id": guid("sub:data"), "env": "dp",
     "mgs": ("mg-examplecorp", "mg-landingzones", "mg-prod"), "regions": ("eastus2",)},
]
PROD = SUBSCRIPTIONS[0]
SUB_WEIGHTS = (5, 3, 2, 2)    # prod is the busiest
# Regions the estate never deploys to: compute there reads as a dormant region.
DORMANT_REGIONS = ("brazilsouth", "southafricanorth", "koreacentral", "australiacentral2",
                   "uaenorth", "norwayeast", "japanwest", "southindia", "switzerlandwest")

_WORKLOADS = {
    "prod": ("web", "api", "network", "data", "aks", "identity", "monitoring", "backup", "integration", "security"),
    "dev": ("web", "api", "network", "aks", "sandbox", "ml"),
    "shared": ("network", "monitoring", "automation", "identity", "security", "backup", "dns"),
    "dp": ("data", "ml", "analytics", "integration"),     # data platform
}


def pick_sub(rnd=None):
    return (rnd or random).choices(SUBSCRIPTIONS, weights=SUB_WEIGHTS)[0]


def resource_groups(sub):
    return [f"rg-{w}-{sub['env']}" for w in _WORKLOADS[sub["env"]]]


def hierarchy(sub):
    """properties.hierarchy: tenant root, management groups, subscription."""
    return "/".join((TENANT_ID,) + sub["mgs"] + (sub["id"],))


# ── named resources ───────────────────────────────────────────────────────────────────
# lower-cased resource type -> (preferred workload, Azure CAF abbreviation, instances per subscription)
TYPES = {
    "virtualmachines": ("web", "vm", 6), "virtualmachinescalesets": ("aks", "vmss", 2),
    "disks": ("web", "disk", 6), "snapshots": ("backup", "snap", 4), "sshpublickeys": ("identity", "sshkey", 3),
    "networksecuritygroups": ("network", "nsg", 5), "virtualnetworks": ("network", "vnet", 2),
    "networkinterfaces": ("web", "nic", 6), "publicipaddresses": ("network", "pip", 4),
    "loadbalancers": ("network", "lb", 2), "applicationgateways": ("network", "agw", 1),
    "azurefirewalls": ("network", "afw", 1), "firewallpolicies": ("network", "afwp", 1),
    "routetables": ("network", "rt", 3), "dnszones": ("dns", "dnsz", 2), "privatednszones": ("dns", "pdnsz", 3),
    "privateendpoints": ("network", "pep", 4), "virtualnetworkgateways": ("network", "vgw", 1),
    "connections": ("network", "con", 2), "p2svpngateways": ("network", "p2s", 1),
    "networkwatchers": ("network", "nw", 1), "natgateways": ("network", "ng", 1),
    "bastionhosts": ("network", "bas", 1), "storageaccounts": ("data", "st", 4), "vaults": ("security", "kv", 3),
    "managedclusters": ("aks", "aks", 1), "registries": ("aks", "cr", 1), "sites": ("web", "app", 4),
    "serverfarms": ("web", "asp", 2), "servers": ("data", "sql", 2), "databases": ("data", "sqldb", 3),
    "automationaccounts": ("automation", "aa", 1), "runbooks": ("automation", "rb", 4),
    "namespaces": ("integration", "evhns", 2), "eventhubs": ("integration", "evh", 4),
    "workspaces": ("monitoring", "log", 1), "components": ("monitoring", "appi", 3),
    "actiongroups": ("monitoring", "ag", 2), "metricalerts": ("monitoring", "ma", 4),
    "activitylogalerts": ("monitoring", "ala", 2), "scheduledqueryrules": ("monitoring", "sqr", 2),
    "autoscalesettings": ("web", "as", 2), "databaseaccounts": ("data", "cosmos", 1),
    "redis": ("api", "redis", 1), "service": ("api", "apim", 1), "workflows": ("integration", "logic", 3),
    "accounts": ("ml", "oai", 1), "factories": ("integration", "adf", 1),
    "userassignedidentities": ("identity", "id", 3), "flexibleservers": ("data", "psql", 1),
    "emailservices": ("integration", "acs-email", 1), "communicationservices": ("integration", "acs", 1),
}
_ALNUM_TYPES = {"storageaccounts", "registries"}   # Azure forbids dashes in these names


def abbr(rtype):
    t = rtype.lower()
    if t in TYPES:
        return TYPES[t][1]
    caps = "".join(ch for ch in rtype if ch.isupper()).lower()
    return (rtype[:1].lower() + caps)[:5] or t[:4]


def _workload(sub, rtype):
    wl = TYPES.get(rtype.lower(), ("app",))[0]
    wls = _WORKLOADS[sub["env"]]
    return wl if wl in wls else wls[_h(sub["id"] + rtype.lower()) % len(wls)]


def rg_for(sub, rtype):
    return f"rg-{_workload(sub, rtype)}-{sub['env']}"


def resource_name(sub, rtype, idx):
    wl = _workload(sub, rtype)
    if rtype.lower() in _ALNUM_TYPES:
        return f"{abbr(rtype)}{wl}{sub['env']}{_h(sub['id'] + rtype.lower()) % 900 + 100}{idx + 1:02d}"[:24]
    return f"{abbr(rtype)}-{wl}-{sub['env']}-{idx + 1:02d}"


def count(rtype):
    return TYPES.get(rtype.lower(), (None, None, 2))[2]


def pick_name(sub, rtype, rnd=None):
    return resource_name(sub, rtype, (rnd or random).randrange(count(rtype)))


def rid(sub, provider, *chain, rg=None):
    """Resource id. chain alternates type, name: rid(sub, 'Microsoft.Compute', 'virtualMachines', 'vm-web-prod-01')."""
    rg = rg or rg_for(sub, chain[0])
    return f"/subscriptions/{sub['id']}/resourceGroups/{rg}/providers/{provider}/" + "/".join(chain)


def sub_rid(sub, provider=None, *chain):
    """Subscription-scoped id (role assignments, policy, Defender settings, ...)."""
    base = f"/subscriptions/{sub['id']}"
    return base if not provider else f"{base}/providers/{provider}/" + "/".join(chain)


def region(sub, rnd=None):
    return (rnd or random).choice(sub["regions"])


# ── Azure RBAC ─────────────────────────────────────────────────────────────────────────
# Built-in role definition ids (Microsoft's published, stable ids).
ROLES = {
    "Owner": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "User Access Administrator": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    "Network Contributor": "4d97b98b-1d4f-4787-a291-c67834d212e7",
    "Virtual Machine Contributor": "9980e02c-c2be-4d73-94e8-173b1dc7cf3c",
    "Storage Account Contributor": "17d1049b-9a84-46fb-8f53-869881c3d3ab",
    "Key Vault Administrator": "00482a5a-887f-4fb3-b363-3b7fe8e74483",
    "Security Admin": "fb1c8493-542b-48eb-b624-b4c8fea62acd",
    "Monitoring Contributor": "749f88d5-cbae-40b8-bcfc-e573ddc772fa",
    "SQL DB Contributor": "9b7fa17d-e63e-47b0-bb0a-15c516ac86ec",
    "Website Contributor": "de139f84-1756-47ae-9be6-808fbbe84772",
    "Automation Contributor": "f353d9bd-d4a6-484e-a77a-8050b599b867",
    "Azure Kubernetes Service Cluster Admin Role": "0ab0b1a8-8aac-4efd-b8c2-3ee1fb270be8",
    "AcrPush": "8311e382-0749-4cb8-b61a-304f252e45ec",
    "Backup Contributor": "5e467623-bb1f-42f4-a55d-6e525e11384b",
}
# Roles that hand out control of the subscription (assignment of one reads as escalation).
PRIVILEGED_ROLES = ("Owner", "User Access Administrator", "Contributor")


# ── callers ──────────────────────────────────────────────────────────────────────────
# Who normally operates Azure: the cloud/platform team does most changes, network engineers own
# the network plane, security engineers own Defender/Key Vault/policy, data engineers own
# data/ML. Anyone else making an ARM change reads as a non-standard identity.
CLOUD_OPS = ("Cloud Administrator", "Cloud Architect", "Cloud Engineer", "Platform Engineer",
             "Infrastructure Engineer", "Infrastructure Lead", "DevOps Engineer", "Senior DevOps Engineer",
             "SRE", "Site Reliability Engineer", "Systems Engineer", "Systems Administrator", "IT Administrator")
NET_OPS = ("Network Engineer",)
SEC_OPS = ("Senior Security Engineer", "Security Engineer", "Security Architect")
DATA_OPS = ("Data Engineer", "ML Engineer", "Machine Learning Engineer", "Data Scientist")
_ALL_AZURE_ROLES = frozenset(CLOUD_OPS + NET_OPS + SEC_OPS + DATA_OPS)

# First-party client apps humans use against ARM (real appIds).
CLIENTS = {"Azure Portal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
           "Azure CLI": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
           "Azure PowerShell": "1950a258-227b-4e31-a9cf-717495945fc2"}


def _token_times(now=None):
    t = int(now or time.time())
    iat = t - random.randint(300, 3000)
    return str(iat), str(iat), str(iat + 3600 + random.randint(0, 1800))


def user_caller(user, ip=None, client=None):
    """A human caller: their UPN/object id, the client they use, and the ARM token claims."""
    un = user["username"]
    client = client or ("Azure Portal" if _h("cli:" + un) % 3 else "Azure CLI")
    first, _, last = (user.get("display_name") or un).partition(" ")
    iat, nbf, exp = _token_times()
    oid = ac.user_oid(un)
    claims = {
        "aud": "https://management.core.windows.net/", "iss": f"https://sts.windows.net/{TENANT_ID}/",
        "iat": iat, "nbf": nbf, "exp": exp,
        "http://schemas.microsoft.com/claims/authnclassreference": "1",
        "aio": hex32("aio:" + un + iat)[:44],
        "http://schemas.microsoft.com/claims/authnmethodsreferences": "pwd,mfa",
        "appid": CLIENTS[client], "appidacr": "0",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": last or first,
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": first,
        "groups": ",".join(guid(f"grp:{un}:{i}") for i in range(2)),
        "idtyp": "user", "ipaddr": ip or "",
        "name": user.get("display_name") or un,
        "http://schemas.microsoft.com/identity/claims/objectidentifier": oid,
        "puid": f"1003{_h('puid:' + un) % 16 ** 12:012X}",
        "rh": "0.A" + hex32("rh:" + un)[:30],
        "http://schemas.microsoft.com/identity/claims/scope": "user_impersonation",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": hex32("nid:" + un)[:43],
        "http://schemas.microsoft.com/identity/claims/tenantid": TENANT_ID,
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": user["upn"],
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": user["upn"],
        "uti": hex32("uti:" + str(random.random()))[:22], "ver": "1.0",
    }
    sid = ac.on_prem_sid(un)
    if sid:
        claims["onprem_sid"] = sid
    return {"kind": "User", "user": user, "upn": user["upn"], "oid": oid, "ip": ip,
            "client": client, "claims": claims}


# Automation identities: service principals (pipelines, IaC, integrations) and user-assigned
# managed identities. Each is a stable entity with a stable role and normal egress.
SERVICE_PRINCIPALS = {
    "sp-terraform-platform": {"role": "Contributor", "egress": "azure"},
    "sp-azdo-pipelines": {"role": "Website Contributor", "egress": "azure"},
    "sp-backup-orchestrator": {"role": "Backup Contributor", "egress": "azure"},
    "sp-monitoring-integration": {"role": "Monitoring Contributor", "egress": "azure"},
}
MANAGED_IDENTITIES = {
    "id-automation-ops": {"role": "Automation Contributor"},
    "id-aks-prod-agentpool": {"role": "Network Contributor"},
    "id-func-data-ingest": {"role": "Storage Account Contributor"},
}


def _azure_egress(seed):
    from modules import graph_activity as ga   # the verified Microsoft AS8075 blocks
    return ga._azure_ip(seed)


def app_caller(name, kind="ServicePrincipal", ip=None, tenant_id=None):
    """A service principal or managed identity caller. MI tokens carry xms_mirid, the identity's
    own resource id."""
    appid = ac.app_id(name)
    oid = ac.user_oid(("mi:" if kind == "ManagedIdentity" else "sp:") + name)
    iat, nbf, exp = _token_times()
    tid = tenant_id or TENANT_ID
    claims = {
        "aud": "https://management.core.windows.net/", "iss": f"https://sts.windows.net/{tid}/",
        "iat": iat, "nbf": nbf, "exp": exp, "aio": hex32("aio:" + name + iat)[:44],
        "appid": appid, "appidacr": "1" if kind == "ServicePrincipal" else "2",   # 1 secret, 2 cert/MI
        "http://schemas.microsoft.com/identity/claims/identityprovider": f"https://sts.windows.net/{tid}/",
        "idtyp": "app",
        "http://schemas.microsoft.com/identity/claims/objectidentifier": oid,
        "rh": "0.A" + hex32("rh:" + name)[:30],
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": oid,
        "http://schemas.microsoft.com/identity/claims/tenantid": tid,
        "uti": hex32("uti:" + str(random.random()))[:22], "ver": "1.0",
    }
    if kind == "ManagedIdentity":
        sub = SUBSCRIPTIONS[2]
        claims["xms_mirid"] = rid(sub, "Microsoft.ManagedIdentity", "userAssignedIdentities", name, rg="rg-identity-shared")
    return {"kind": kind, "name": name, "oid": oid, "appid": appid,
            "ip": ip if ip is not None else ("" if kind == "ManagedIdentity" else _azure_egress(name)),
            "claims": claims}


def pick_admin(config, roles=CLOUD_OPS, context=None):
    """A caller from an Azure-operating role. Prefers someone with a live session on the activity
    bus (their ARM change then lines up with their sign-in and network traffic) and uses that
    session's egress IP; otherwise the user's own stable egress."""
    pool = _role_pool(config, roles)
    sess = None
    if pool and _active_sessions is not None and random.random() < ac.CORRELATE_PROB:
        live = [s for s in (_active_sessions() or []) if s.get("username") in pool]
        if live:
            sess = random.choice(live)
    if sess:
        user = ac._user_info(sess["username"], config, context)
        ip = sess.get("egress_ip") or ac.egress(user)["ip"]
    elif pool:
        un = random.choice(pool)
        user = ac._norm(un, (config or {}).get("user_profiles", {})[un])
        ip = ac.egress(user)["ip"]
    else:
        user = ac.pick_user(config, context)
        ip = ac.egress(user)["ip"]
    return user_caller(user, ip)


def pick_nonstandard(config, context=None):
    """An active identity whose role never touches Azure (finance, sales, HR, ...)."""
    profiles = (config or {}).get("user_profiles") or {}
    pool = [u for u, p in profiles.items()
            if p.get("role") not in _ALL_AZURE_ROLES and p.get("department") not in ("IT", "DevOps", "Security")
            and ac.lifecycle_cohort(u) == "active"]
    if pool:
        un = random.choice(pool)
        user = ac._norm(un, profiles[un])
    else:
        user = ac.pick_user(config, context)
    return user_caller(user, ac.egress(user)["ip"])


_POOLS = {}


def _role_pool(config, roles):
    profiles = (config or {}).get("user_profiles") or {}
    key = (id(profiles), roles)
    if key not in _POOLS:
        _POOLS[key] = sorted(u for u, p in profiles.items()
                             if p.get("role") in roles and ac.lifecycle_cohort(u) == "active")
    return _POOLS[key]


try:
    from modules.session_utils import active_sessions as _active_sessions
except Exception:  # pragma: no cover
    _active_sessions = None
