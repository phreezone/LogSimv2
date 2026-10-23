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
import hashlib
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
                   container=None, blob=None, rnd=None, correlation_id=None, extra_properties=None,
                   authentication_type="OAuth"):
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
    # StorageBlobLogs uses compact AuthenticationType values at the top level, while the
    # Event Hub identity.type value is the display form documented in the event schema.
    identity_type = {"AccountKey": "Account Key", "SAS": "SAS Key"}.get(authentication_type,
                                                                            authentication_type)
    ident = {"type": identity_type,
             "authorization": [{"action": f"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/{action}",
                                "result": "Granted", "reason": "Policy", "type": "RBAC",
                                "roleAssignmentId": str(uuid.uuid5(uuid.NAMESPACE_URL,
                                    "ra:" + caller["oid"] + account)),
                                "roleDefinitionId": role_id,
                                "principals": [{"id": caller["oid"], "type": principal_type}]}],
             "properties": {"metricResponseType": "Success", "objectKey": f"/{account}/{container}/{blob}"},
        "requester": {"appId": caller.get("appid") or ae.CLIENTS.get(caller.get("client"))
                       or ac.app_id("sp:" + str(caller.get("name", ""))),
                           "audience": "https://storage.azure.com/", "objectId": caller["oid"],
                           "tenantId": TENANT_ID, "tokenIssuer": f"https://sts.windows.net/{TENANT_ID}/"}}
    if caller["kind"] == "User":
        ident["requester"]["upn"] = caller["upn"]
        ident["requester"]["uniqueName"] = caller["upn"]
    if authentication_type != "OAuth":
        # Key/SAS authenticated requests do not carry the OAuth RBAC decision details.
        ident.pop("authorization", None)
        ident.pop("requester", None)
    token_digest = hashlib.sha256(
        ("synthetic-storage-token:" + caller["oid"] + account).encode()).hexdigest().upper()
    if authentication_type == "OAuth":
        ident["tokenHash"] = token_digest
    elif authentication_type == "AccountKey":
        ident["tokenHash"] = f"key1({token_digest})"
    elif authentication_type == "SAS":
        sig_digest = hashlib.sha256(("synthetic-sas-signature:" + caller["oid"] + account).encode()).hexdigest().upper()
        ident["tokenHash"] = f"key1({token_digest}),SasSignature({sig_digest})"
    ident["properties"]["metricResponseType"] = "Success" if status < 400 else \
        "ClientOtherError" if status < 500 else "ServerOtherError"
    if op == "GetBlobServiceProperties":
        request_uri = f"https://{host}/?restype=service&comp=properties"
    elif op == "ListBlobs":
        request_uri = f"https://{host}/{container}?restype=container&comp=list"
    elif op == "GetContainerProperties":
        request_uri = f"https://{host}/{container}?restype=container"
    elif op == "GetBlockList":
        request_uri = f"https://{host}/{container}/{blob}?comp=blocklist"
    else:
        request_uri = f"https://{host}/{container}/{blob}"
    status_text = "Success" if status < 400 else ("AuthorizationPermissionMismatch" if status == 403
                  else "BlobNotFound" if status == 404 else "ServerBusy" if status >= 500 else "Conflict")
    rec = {
        "time": _ts(offset_s), "resourceId": acct_id.upper(), "category": category,
        "operationName": op, "operationVersion": "2021-08-06", "schemaVersion": "1.0",
        "authenticationType": authentication_type,
        "statusCode": status, "statusText": status_text,
        "durationMs": r.randint(2, 180), "callerIpAddress": f"{(caller.get('ip') or ip or '20.0.0.1')}:{r.randint(1024, 65000)}",
        "correlationId": correlation_id or str(uuid.uuid4()), "location": ae.region(sub, r),
        "uri": request_uri, "protocol": "HTTPS",
        "identity": ident,
        "properties": {"accountName": account, "requestUrl": request_uri,
                       "userAgentHeader": ua, "clientRequestId": str(uuid.uuid4()), "serviceType": "blob",
                       "operationCount": 0, "requestHeaderSize": r.randint(300, 1200),
                       "requestBodySize": r.randint(0, 65536) if category == "StorageWrite" else 0,
                       "responseHeaderSize": r.randint(150, 400),
                       "responseBodySize": r.randint(200, 4194304) if category == "StorageRead" else 0,
                       "tlsVersion": "TLS 1.2", "accessTier": r.choice(["Hot", "Hot", "Cool"])}}
    if extra_properties:
        rec["properties"].update(extra_properties)
    return ac.route_eventhub(rec)


def storage_copy_records(source_account, source_sub, destination_account, destination_sub, caller,
                         *, container="exports", blob="quarterly-report.parquet", offset_s=0.0):
    """Build correlated StorageBlobLogs-style records for a cross-account Copy Blob."""
    corr = str(uuid.uuid4())
    dst_container, dst_blob = "imports", f"received-{uuid.uuid4().hex[:10]}.parquet"
    destination_uri = f"https://{destination_account}.blob.core.windows.net/{dst_container}/{dst_blob}"
    source_uri = f"https://{source_account}.blob.core.windows.net/{container}/{blob}"
    destination_rid = ae.rid(destination_sub, "Microsoft.Storage", "storageAccounts", destination_account,
                             "blobServices", "default", rg=ae.rg_for(destination_sub, "storageAccounts"))
    source_event = storage_record(source_account, source_sub, caller, "CopyBlobSource", "StorageRead",
        container=container, blob=blob, offset_s=offset_s, correlation_id=corr,
        extra_properties={"destinationUri": destination_uri, "copyDestinationArmId": destination_rid,
                          "operationCount": 2})
    source_event["destinationUri"] = destination_uri
    source_event["copyDestinationArmId"] = destination_rid
    source_event["DestinationUri"] = destination_uri
    source_event["CopyDestinationArmId"] = destination_rid
    destination_event = storage_record(destination_account, destination_sub, caller, "CopyBlob", "StorageWrite",
        container=dst_container, blob=dst_blob, offset_s=offset_s, correlation_id=corr,
        extra_properties={"sourceUri": source_uri, "copySource": source_uri, "operationCount": 2})
    destination_event["sourceUri"] = source_uri
    destination_event["SourceUri"] = source_uri
    return [source_event, destination_event]


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


def _keyvault_object_path(op, object_name=None):
    """Return the REST resource/action path corresponding to a Key Vault operation."""
    name = object_name or "app-secret"
    if op == "VaultGet":
        return "", "2015-06-01", True
    if op in ("SecretList",):
        return "secrets", "7.4", None
    if op in ("KeyList",):
        return "keys", "7.4", None
    if op in ("CertificateList",):
        return "certificates", "7.4", None
    if op.startswith("Secret"):
        suffix = "/versions" if op == "SecretListVersions" else ""
        return f"secrets/{name}{suffix}", "7.4", None
    if op.startswith("Key"):
        action = {"KeySign": "sign", "KeyVerify": "verify", "KeyWrap": "wrapkey",
                  "KeyUnwrap": "unwrapkey", "KeyDecrypt": "decrypt", "KeyEncrypt": "encrypt",
                  "KeyRotate": "rotate"}.get(op)
        suffix = "/versions" if op == "KeyListVersions" else f"/{action}" if action else ""
        key = object_name or "data-key"
        return f"keys/{key}{suffix}", "7.4", None
    if op.startswith("Certificate"):
        suffix = "/versions" if op == "CertificateListVersions" else ""
        return f"certificates/{name}{suffix}", "7.4", None
    return f"secrets/{name}", "7.4", None


def keyvault_record(vault, sub, caller, op, *, status=200, offset_s=0.0, object_name=None, rnd=None):
    r = rnd or random
    host = f"{vault}.vault.azure.net"
    claim = {"http://schemas.microsoft.com/identity/claims/objectidentifier": caller["oid"],
             "appid": caller.get("appid") or ac.app_id("sp:" + str(caller.get("name", "")))}
    if caller["kind"] == "User":
        claim["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"] = caller["upn"]
    obj, version, is_vault_control = _keyvault_object_path(op, object_name or
        ("db-conn" if op.startswith("Secret") else "data-key" if op.startswith("Key") else "tls-cert"))
    region = ae.region(sub, r)
    region_code = {"eastus": "eus", "eastus2": "eus2", "centralus": "cus",
                   "westus2": "wus2"}.get(region.lower(), "eus")
    endpoint = f"https://control-prod-{region_code}.vaultcore.azure.net" if is_vault_control else None
    host = f"{vault}.vault.azure.net"
    request_uri = (f"{endpoint}/subscriptions/{sub}/resourcegroups/{ae.rg_for(sub, 'vaults')}"
                   f"/providers/Microsoft.KeyVault/vaults/{vault}?api-version={version}" if op == "VaultGet"
                   else f"https://{host}/{obj}?api-version={version}")
    object_path = obj.rsplit("/", 1)[0] if op in {"KeySign", "KeyVerify", "KeyWrap", "KeyUnwrap",
        "KeyDecrypt", "KeyEncrypt", "KeyRotate"} else obj
    object_uri = f"https://{host}/" if op == "VaultGet" else f"https://{host}/{object_path}"
    signature = ("OK" if status < 400 else "Unauthorized" if status == 401 else
                 "Forbidden" if status == 403 else "Not Found" if status == 404 else
                 "Conflict" if status == 409 else "Internal Server Error" if status >= 500 else "Bad Request")
    rec = {
        "time": _ts(offset_s),
        "resourceId": ae.rid(sub, "Microsoft.KeyVault", "vaults", vault, rg=ae.rg_for(sub, "vaults")).upper(),
        "operationName": op, "operationVersion": version, "category": "AuditEvent",
        "resultType": "Success" if status < 400 else "Failure",
        "resultSignature": signature, "resultDescription": "",
        "durationMs": str(r.randint(5, 220)), "callerIpAddress": caller.get("ip") or "20.0.0.1",
        "correlationId": str(uuid.uuid4()), "identity": {"claim": claim},
        "properties": {"clientInfo": "azsdk-python-keyvault-secrets/4.8.0" if caller["kind"] != "User"
                       else "AzurePowerShell/12.1.0", "requestUri": request_uri,
                       "id": object_uri, "httpStatusCode": status}}
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
    "Files_List": ("Files", "Audit"),
    "Files_GetFileContent": ("Files - Get Content", "Audit"),
}
_AI_DEPLOYMENTS = [("gpt-4o", "gpt-4o"), ("gpt-4o-mini", "gpt-4o-mini"), ("gpt-35-turbo", "gpt-35-turbo"),
                   ("text-embedding-3-large", "text-embedding-3-large"), ("o3-mini", "o3-mini")]


def ai_record(account, sub, caller, op, *, status=200, offset_s=0.0, rnd=None,
              deployment=None, model=None, file_id=None):
    r = rnd or random
    api, category = _AI_OPS[op]
    dep, model_name = (deployment, model) if deployment and model else r.choice(_AI_DEPLOYMENTS)
    request_time = _dotnet_ticks(offset_s - r.uniform(0.1, 3.0))
    duration_ms = r.randint(120, 9000)
    version = "2023-12-01-preview" if op in ("Models_List", "Files_List", "Files_GetFileContent") else "2023-05-15"
    props = {"apiName": f"Azure OpenAI API version {version}",
             "requestTime": request_time, "responseTime": request_time + duration_ms * 10_000,
             "statusCode": status, "objectId": caller["oid"]}
    if op == "Files_GetFileContent":
        props["fileId"] = file_id or f"file-{uuid.uuid4().hex[:32]}"
    if category == "RequestResponse":
        props.update({"requestLength": r.randint(200, 24000),
                      "responseLength": r.randint(100, 16000) if status < 400 else 0,
                      "modelDeploymentName": dep, "modelName": model_name, "modelVersion": "2024-08-06",
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
