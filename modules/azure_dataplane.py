"""Azure data-plane resource logs for modules/azure_activity.py (helper, not a generator):
Storage blob access (StorageRead/Write/Delete), Key Vault AuditEvent, and Azure AI / Cognitive
Services RequestResponse. All three stream through diagnostic settings to an event hub ->
msft_azure_raw, and are the data behind the storage-access, Key Vault and AI detectors.

Record shapes follow Microsoft's documented event-hub schemas verbatim:
  - Storage: monitor-blob-storage-reference "schema from storage account and event hubs" -- top
    level time/resourceId/category/operationName/statusCode/callerIpAddress(ip:port)/uri, nested
    identity{type,requester{...},authorization[]} and properties{accountName,userAgentHeader,...}.
  - Key Vault: key-vault/general/logging -- operationName in ObjectVerb form (VaultGet, SecretGet,
    KeyList, ...), category AuditEvent, identity{claim{objectidentifier,upn,appid}},
    properties{clientInfo,requestUri,id,httpStatusCode}.
  - AI: ai-services diagnostic logging -- resource log, categories Audit / RequestResponse,
    Microsoft.CognitiveServices/accounts, operationName like ChatCompletions_Create.

Benign baseline only: the normal machine traffic these services produce (apps and managed
identities reading their own blobs, secrets and models, with a little admin access). The patterns
the detectors key on -- first-time/backup access, foreign-account copy, secret dumps, model
discovery, denial-of-wallet volume -- are left out, so routine traffic does not raise them.
"""
import datetime
import random
import time
import uuid

from modules import azure_common as ac
from modules import azure_estate as ae

TENANT_ID = ae.TENANT_ID


def _ts(offset_s=0.0):
    d = datetime.datetime.fromtimestamp(time.time() + min(0.0, offset_s), datetime.timezone.utc)
    return f"{d:%Y-%m-%dT%H:%M:%S}.{d.microsecond:07d}"[:-1] + "Z"


def _dotnet_ticks(offset_s=0.0):
    """Azure OpenAI diagnostic properties use .NET ticks for request/response times."""
    d = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset_s)
    return ((d.toordinal() - 1) * 86400 + d.hour * 3600 + d.minute * 60 + d.second) * 10_000_000 + d.microsecond * 10


# ── Storage blob access (StorageBlobLogs) ──────────────────────────────────────────────
_BLOB_READ = ["GetBlob", "GetBlobProperties", "GetBlobMetadata", "ListBlobs", "GetContainerProperties",
              "GetBlockList", "GetBlobServiceProperties"]
_BLOB_WRITE = ["PutBlob", "PutBlock", "PutBlockList", "SetBlobMetadata", "SetBlobProperties",
               "SetBlobTier", "AppendBlock"]
_BLOB_DELETE = ["DeleteBlob"]
_CONTAINERS = ["backups", "artifacts", "images", "logs", "exports", "datasets", "uploads",
               "terraform-state", "diagnostics", "bronze", "silver", "gold"]
_BLOB_EXT = [("vhd", "PageBlob"), ("bak", "BlockBlob"), ("parquet", "BlockBlob"), ("json", "BlockBlob"),
             ("csv", "BlockBlob"), ("png", "BlockBlob"), ("zip", "BlockBlob"), ("log", "BlockBlob"),
             ("tfstate", "BlockBlob"), ("bin", "BlockBlob")]


def _blob_path(rnd, container=None, blob=None):
    c = container or rnd.choice(_CONTAINERS)
    ext, _bt = rnd.choice(_BLOB_EXT)
    return c, blob or f"{rnd.choice(['data','part','obj','blob','file','snap'])}-{rnd.randint(0, 9999):04d}.{ext}"


def storage_record(account, sub, caller, op, category, *, ip=None, status=200, offset_s=0.0,
                   container=None, blob=None, rnd=None):
    r = rnd or random
    container, blob = _blob_path(r, container, blob)
    host = f"{account}.blob.core.windows.net"
    acct_id = ae.rid(sub, "Microsoft.Storage", "storageAccounts", account, "blobServices", "default",
                     rg=ae.rg_for(sub, "storageAccounts"))
    ua = "azsdk-python-storage-blob/12.19.0 Python/3.11.8 (Linux-5.15)" if caller["kind"] != "User" \
        else ac.user_agent(caller["user"])
    access = {"StorageRead": ("read", "Storage Blob Data Reader", "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"),
              "StorageWrite": ("write", "Storage Blob Data Contributor", "ba92f5b4-2d11-453d-a403-e96b0029c9fe"),
              "StorageDelete": ("delete", "Storage Blob Data Contributor", "ba92f5b4-2d11-453d-a403-e96b0029c9fe")}
    action, role, role_id = access[category]
    principal_type = "User" if caller["kind"] == "User" else "ServicePrincipal"
    ident = {"type": "OAuth",
             "authorization": [{"action": f"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/{action}",
                                "result": "Granted", "reason": "Policy", "type": "RBAC",
                                "roleAssignmentId": ae.hex32("ra:" + caller["oid"] + account),
                                "roleDefinitionId": role_id.replace("-", ""),
                                "principals": [{"id": caller["oid"], "type": principal_type}]}],
             "properties": {"metricResponseType": "Success", "objectKey": f"/{account}/{container}/{blob}"},
        "requester": {"appId": caller.get("appid") or ae.CLIENTS.get(caller.get("client"))
                       or ac.app_id("sp:" + str(caller.get("name", ""))),
                           "audience": "https://storage.azure.com/", "objectId": caller["oid"],
                           "tenantId": TENANT_ID, "tokenIssuer": f"https://sts.windows.net/{TENANT_ID}/"}}
    if caller["kind"] == "User":
        ident["requester"]["upn"] = caller["upn"]
        ident["requester"]["uniqueName"] = caller["upn"]
    rec = {
        "time": _ts(offset_s), "resourceId": acct_id.upper(), "category": category,
        "operationName": op, "operationVersion": "2021-08-06", "schemaVersion": "1.0",
        "statusCode": status, "statusText": "Success" if status < 400 else "AuthorizationPermissionMismatch",
        "durationMs": r.randint(2, 180), "callerIpAddress": f"{(caller.get('ip') or ip or '20.0.0.1')}:{r.randint(1024, 65000)}",
        "correlationId": str(uuid.uuid4()), "location": ae.region(sub, r),
        "uri": f"https://{host}/{container}/{blob}", "protocol": "HTTPS",
        "identity": ident,
        "properties": {"accountName": account, "requestUrl": f"https://{host}/{container}/{blob}",
                       "userAgentHeader": ua, "clientRequestId": str(uuid.uuid4()), "serviceType": "blob",
                       "operationCount": 1, "requestHeaderSize": r.randint(300, 1200),
                       "requestBodySize": r.randint(0, 65536) if category == "StorageWrite" else 0,
                       "responseHeaderSize": r.randint(150, 400),
                       "responseBodySize": r.randint(200, 4194304) if category == "StorageRead" else 0,
                       "tlsVersion": "TLS 1.2", "accessTier": r.choice(["Hot", "Hot", "Cool"])}}
    return ac.route_eventhub(rec)


def benign_storage(config, context=None):
    """A read-heavy blob access by an app/managed identity (or occasionally an admin) on a known
    account. No anonymous auth, no cross-tenant, no first-time account."""
    sub = ae.pick_sub()
    account = ae.pick_name(sub, "storageAccounts")
    if random.random() < 0.85:
        name = random.choice(list(ae.SERVICE_PRINCIPALS) + list(ae.MANAGED_IDENTITIES))
        caller = ae.app_caller(name, "ManagedIdentity" if name in ae.MANAGED_IDENTITIES else "ServicePrincipal")
    else:
        caller = ae.pick_admin(config, ae.DATA_OPS + ae.CLOUD_OPS, context)
    r = random.random()
    op_cat = (random.choice(_BLOB_READ), "StorageRead") if r < 0.75 else \
        (random.choice(_BLOB_WRITE), "StorageWrite") if r < 0.95 else (random.choice(_BLOB_DELETE), "StorageDelete")
    return [storage_record(account, sub, caller, op_cat[0], op_cat[1])]


# ── Key Vault AuditEvent ───────────────────────────────────────────────────────────────
_KV_READ = ["VaultGet", "SecretGet", "SecretList", "SecretListVersions", "KeyGet", "KeyList",
            "CertificateGet", "CertificateList"]
_KV_USE = ["KeySign", "KeyVerify", "KeyWrap", "KeyUnwrap", "KeyDecrypt", "KeyEncrypt"]
_KV_WRITE = ["SecretSet", "KeyCreate", "CertificateCreate", "KeyRotate"]


def keyvault_record(vault, sub, caller, op, *, status=200, offset_s=0.0, object_name=None, rnd=None):
    r = rnd or random
    host = f"{vault}.vault.azure.net"
    claim = {"http://schemas.microsoft.com/identity/claims/objectidentifier": caller["oid"],
             "appid": caller.get("appid") or ac.app_id("sp:" + str(caller.get("name", "")))}
    if caller["kind"] == "User":
        claim["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"] = caller["upn"]
    obj = {"VaultGet": "", "SecretGet": "secrets/" + (object_name or "db-conn"), "SecretList": "secrets",
           "KeyGet": "keys/data-key", "KeyList": "keys", "KeyRotate": "keys/data-key/rotate"}.get(
               op, "secrets/app-secret")
    rec = {
        "time": _ts(offset_s),
        "resourceId": ae.rid(sub, "Microsoft.KeyVault", "vaults", vault, rg=ae.rg_for(sub, "vaults")).upper(),
        "operationName": op, "operationVersion": "7.4", "category": "AuditEvent",
        "resultType": "Success" if status < 400 else "Unauthorized",
        "resultSignature": "OK" if status < 400 else "Forbidden", "resultDescription": "",
        "durationMs": str(r.randint(5, 220)), "callerIpAddress": caller.get("ip") or "20.0.0.1",
        "correlationId": str(uuid.uuid4()), "identity": {"claim": claim},
        "properties": {"clientInfo": "azsdk-python-keyvault-secrets/4.8.0" if caller["kind"] != "User"
                       else "AzurePowerShell/12.1.0", "requestUri": f"https://{host}/{obj}?api-version=7.4",
                       "id": f"https://{host}/{obj}", "httpStatusCode": status}}
    return ac.route_eventhub(rec)


def benign_keyvault(config, context=None):
    """A secret/key read by an app or managed identity, or a signing/wrap op, on a known vault.
    No bulk enumeration of many distinct secrets (that is the secrets-dump pattern)."""
    sub = ae.pick_sub()
    vault = ae.pick_name(sub, "vaults")
    if random.random() < 0.9:
        name = random.choice(list(ae.SERVICE_PRINCIPALS) + list(ae.MANAGED_IDENTITIES))
        caller = ae.app_caller(name, "ManagedIdentity" if name in ae.MANAGED_IDENTITIES else "ServicePrincipal")
    else:
        caller = ae.pick_admin(config, ae.SEC_OPS + ae.CLOUD_OPS, context)
    r = random.random()
    op = random.choice(_KV_READ) if r < 0.7 else random.choice(_KV_USE) if r < 0.95 else random.choice(_KV_WRITE)
    return [keyvault_record(vault, sub, caller, op)]


# ── Azure AI / Cognitive Services (RequestResponse, Audit) ─────────────────────────────
_AI_OPS = {  # operationName -> (apiName, category)
    "ChatCompletions_Create": ("Chat Completions", "RequestResponse"),
    "Completions_Create": ("Completions", "RequestResponse"),
    "Embeddings_Create": ("Embeddings", "RequestResponse"),
    "Transcriptions_Create": ("Audio Transcriptions", "RequestResponse"),
    # Audit-category model catalog lookup. The operation name is also present in the public
    # Azure OpenAI logging sample used by the Cortex model-discovery analytic.
    "Models_List": ("Models", "Audit"),
}
_AI_DEPLOYMENTS = [("gpt-4o", "gpt-4o"), ("gpt-4o-mini", "gpt-4o-mini"), ("gpt-35-turbo", "gpt-35-turbo"),
                   ("text-embedding-3-large", "text-embedding-3-large"), ("o3-mini", "o3-mini")]


def ai_record(account, sub, caller, op, *, status=200, offset_s=0.0, rnd=None):
    r = rnd or random
    api, category = _AI_OPS[op]
    dep, model = r.choice(_AI_DEPLOYMENTS)
    request_time = _dotnet_ticks(offset_s - r.uniform(0.1, 3.0))
    duration_ms = r.randint(120, 9000)
    props = {"apiName": f"Azure OpenAI API version {'2023-12-01-preview' if op == 'Models_List' else '2023-05-15'}",
             "requestTime": request_time, "responseTime": request_time + duration_ms * 10_000,
             "statusCode": status, "objectId": caller["oid"]}
    if category == "RequestResponse":
        props.update({"requestLength": r.randint(200, 24000),
                      "responseLength": r.randint(100, 16000) if status < 400 else 0,
                      "modelDeploymentName": dep, "modelName": model, "modelVersion": "2024-08-06",
                      "streamType": r.choice(["Non-Streaming", "Streaming"]),
                      "apimRequestId": str(uuid.uuid4())})
    rec = {
        "time": _ts(offset_s),
        "resourceId": ae.rid(sub, "Microsoft.CognitiveServices", "accounts", account,
                             rg=ae.rg_for(sub, "accounts")).upper(),
        "operationName": op, "category": category,
        "resultType": "Success" if status < 400 else "ClientError",
        "resultSignature": str(status), "durationMs": duration_ms,
        "callerIpAddress": caller.get("ip") or "20.0.0.1", "correlationId": str(uuid.uuid4()),
        "level": "Informational", "location": ae.region(sub, r),
        "properties": props}
    return ac.route_eventhub(rec)


def benign_ai(config, context=None):
    """A normal model invocation by an application identity against a known deployment. No model
    enumeration and no abnormal request volume (those are the discovery / denial-of-wallet
    patterns)."""
    sub = random.choice([ae.PROD, ae.SUBSCRIPTIONS[3]])   # prod + data platform host the AI accounts
    account = ae.pick_name(sub, "accounts")
    name = random.choice(list(ae.SERVICE_PRINCIPALS))
    caller = ae.app_caller(name, "ServicePrincipal")
    op = random.choices(["ChatCompletions_Create", "Completions_Create",
                         "Embeddings_Create", "Transcriptions_Create"],
                        weights=[6, 1, 4, 1])[0]
    return [ai_record(account, sub, caller, op)]
