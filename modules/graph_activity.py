"""Microsoft Graph activity logs (Entra diagnostic category MicrosoftGraphActivityLogs), streamed
to an event hub -> msft_azure_raw -> cloud_audit_logs as log_name microsoft_graph_activity_logs.

One record per Graph API request, in the schema Microsoft documents for the
MicrosoftGraphActivityLogs table (requestMethod, requestUri, responseStatusCode, appId, userId /
servicePrincipalId, scopes / roles, wids, ipAddress, userAgent, responseSizeBytes, ...), inside
the event-hub resource-log envelope. The record carries no request body, exactly like the real
log, so an operation is identified by method + URI + status.

Not a generator (no NAME): the Entra/O365 modules call these builders to attach the Graph request
behind an operation they already emit (the audit record says WHAT changed, this says which API
call made the change), and to add a benign baseline of everyday Graph traffic. The baseline
never contains a request one of the "Microsoft Graph Activity Logs" detectors raises on by itself
(creating users/groups/apps/invitations/mailbox rules, adding credentials/owners/auth methods,
downloading or uploading drive content); only scenarios emit those.
"""
import random
import time
import uuid

from modules import azure_common as ac

GRAPH = "https://graph.microsoft.com"

# First-party client apps (real Microsoft appIds) that call Graph on a user's behalf.
CLIENT_APPS = {
    "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "Microsoft Office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "OneDrive SyncEngine": "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "OfficeHome": "4765445b-32c6-49b0-83e6-1d93765276ca",
    "Outlook Mobile": "27922004-5251-4030-b22d-91ecd9a37ea4",
    "Microsoft Graph Command Line Tools": "14d82eec-204b-4c2f-b7e8-296a70dab67e",
    "Graph Explorer": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
    "Azure Portal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
}
# Directory role template ids (wids claim) for admins acting through Graph.
WID_GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
WID_USER_ADMIN = "fe930be7-5e62-47db-91af-98c3a49a38b1"
WID_APP_ADMIN = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
WID_SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
WID_MEMBER = "b79fbf4d-3ef9-4689-8143-76b194e85509"   # default "User" role every member carries

_POWERSHELL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/7.4.5 Microsoft.Graph/2.25.0"
_DAEMON_UA = "Microsoft.Graph.Core/3.1.15 (Microsoft.Graph/5.62.0) .NET/8.0.10"

# Daemon / integration apps that call Graph with application permissions, each with its stable
# app roles and the requests it routinely makes (its baseline).
DAEMON_APPS = {
    "LogSim Reporting App": {
        "roles": "Reports.Read.All User.Read.All",
        "calls": [("GET", "/v1.0/reports/getOffice365ActiveUserDetail(period='D7')", 200, 48000),
                  ("GET", "/v1.0/users?$select=id,displayName,userPrincipalName&$top=999", 200, 92000)]},
    "HR Provisioning Connector": {
        "roles": "User.ReadWrite.All",
        "calls": [("GET", "/v1.0/users/delta", 200, 12000),
                  ("PATCH", "/v1.0/users/{user}", 204, 0)]},
    "SIEM Graph Connector": {
        "roles": "AuditLog.Read.All Directory.Read.All SecurityEvents.Read.All",
        "calls": [("GET", "/v1.0/auditLogs/directoryAudits?$top=500", 200, 210000),
                  ("GET", "/v1.0/security/alerts_v2?$top=100", 200, 34000)]},
    "Backup Sync Service": {
        "roles": "Files.Read.All Sites.Read.All",
        "calls": [("GET", "/v1.0/users/{user}/drive/root/delta", 200, 26000),
                  ("GET", "/v1.0/sites/{site}/drive/root/delta", 200, 31000)]},
}


def _ts(offset_s=0.0):
    t = time.time() + min(0.0, offset_s)
    frac = int((t % 1) * 10_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{frac:07d}Z"


def app_identity(name, tenant_id=None):
    """Stable identity for an application (appId + its service principal object id)."""
    return {"name": name, "app_id": ac.app_id(name), "sp_id": ac.user_oid("sp:" + name),
            "tenant_id": tenant_id or ac.HOME_TENANT_ID}


def _record(*, method, uri, status, ip, app_id, user_id="", sp_id="", scopes="", roles="",
            wids="", ua="", size=None, offset_s=0.0, token_tenant=None, duration=None):
    ts = _ts(offset_s)
    req = str(uuid.uuid4())
    dur = duration if duration is not None else random.randint(40, 900)
    if size is None:
        size = 0 if status in (204, 302) else random.randint(400, 6000)
    idp = f"https://sts.windows.net/{token_tenant or ac.HOME_TENANT_ID}/"
    path = uri if uri.startswith("http") else GRAPH + uri
    rec = {
        "time": ts, "resourceId": ac.EVENTHUB_RESOURCE, "operationName": "Microsoft Graph Activity",
        "operationVersion": "beta", "category": "MicrosoftGraphActivityLogs",
        "resultSignature": str(status), "durationMs": str(dur), "callerIpAddress": ip,
        "correlationId": req, "level": "Informational", "location": "East US",
        "properties": {
            "timeGenerated": ts, "location": "East US", "requestId": req, "operationId": req,
            "clientRequestId": str(uuid.uuid4()), "apiVersion": path.split("/")[3] if path.count("/") > 3 else "v1.0",
            "requestMethod": method, "responseStatusCode": status, "tenantId": ac.HOME_TENANT_ID,
            "durationMs": dur, "responseSizeBytes": size,
            "signInActivityId": uuid.uuid4().hex[:22], "roles": roles, "tokenIssuedAt": _ts(offset_s - 600),
            "appId": app_id, "userId": user_id, "servicePrincipalId": sp_id, "scopes": scopes,
            "identityProvider": idp, "clientAuthMethod": 2 if sp_id and not user_id else 0,
            "wids": wids, "ipAddress": ip, "userAgent": ua, "requestUri": path,
            "deviceId": None, "sessionId": str(uuid.uuid4()) if user_id else "", "atContent": ""}}
    return ac.route_eventhub(rec)


def user_request(user, method, uri, status=200, *, client="Microsoft Graph Command Line Tools",
                 scopes="User.Read openid profile", wids=WID_MEMBER, ip=None, ua=None, size=None,
                 offset_s=0.0):
    """A delegated Graph request made by a user through a client app."""
    return _record(method=method, uri=uri, status=status,
                   ip=ip or ac.egress(user)["ip"],
                   app_id=CLIENT_APPS.get(client, ac.app_id(client)),
                   user_id=ac.user_oid(user["username"]), scopes=scopes, wids=wids,
                   ua=ua or (_POWERSHELL_UA if client == "Microsoft Graph Command Line Tools"
                             else ac.user_agent(user)),
                   size=size, offset_s=offset_s)


def app_request(app, method, uri, status=200, *, roles="", ip=None, ua=_DAEMON_UA, size=None,
                offset_s=0.0):
    """An app-only Graph request made by a service principal (application permissions).
    `app` is app_identity(); a foreign tenant_id there makes it a cross-tenant caller."""
    return _record(method=method, uri=uri, status=status, ip=ip or _azure_ip(app["name"]),
                   app_id=app["app_id"], sp_id=app["sp_id"], roles=roles, ua=ua, size=size,
                   offset_s=offset_s, token_tenant=app.get("tenant_id"))


def _azure_ip(seed):
    """Stable Azure-datacenter egress for a cloud-hosted daemon (20.x / 40.x / 52.x)."""
    n = ac._h("gaip:" + seed)
    return f"{(20, 40, 52)[n % 3]}.{(n >> 8) % 200 + 20}.{(n >> 16) % 254 + 1}.{(n >> 24) % 250 + 2}"


def _fill(uri, user=None, site=None):
    return (uri.replace("{user}", ac.user_oid(user["username"]) if user else str(uuid.uuid4()))
               .replace("{site}", site or ac._stable_guid("site:" + str(random.randint(1, 40)))))


# ── benign baseline ───────────────────────────────────────────────────────────────────
# What a user's Office/Teams/Outlook clients ask Graph for after a sign-in. Read-only, own data.
_USER_CALLS = [
    ("Microsoft Teams", "GET", "/v1.0/me/joinedTeams", 200),
    ("Microsoft Teams", "GET", "/beta/me/presence", 200),
    ("Microsoft Teams", "GET", "/v1.0/me/chats?$top=50", 200),
    ("Microsoft Office", "GET", "/v1.0/me", 200),
    ("Microsoft Office", "GET", "/v1.0/me/photo/$value", 200),
    ("Microsoft Office", "GET", "/v1.0/me/mailFolders/inbox/messages/delta", 200),
    ("Microsoft Office", "GET", "/v1.0/me/events?$top=25", 200),
    ("Microsoft Office", "GET", "/v1.0/me/people?$top=10", 200),
    ("OneDrive SyncEngine", "GET", "/v1.0/me/drive", 200),
    ("OneDrive SyncEngine", "GET", "/v1.0/me/drive/root/delta", 200),
    ("OfficeHome", "GET", "/v1.0/me/insights/used?$top=20", 200),
    ("OfficeHome", "GET", "/v1.0/me/memberOf?$select=id,displayName", 200),
    ("Outlook Mobile", "GET", "/v1.0/me/mailboxSettings", 200),
    ("Microsoft Office", "GET", "/v1.0/me/mailFolders/inbox/messages/delta", 304),
]
_DELEGATED_SCOPES = {
    "Microsoft Teams": "Chat.ReadWrite Presence.Read.All Team.ReadBasic.All User.Read",
    "Microsoft Office": "Mail.ReadWrite Calendars.ReadWrite People.Read User.Read",
    "OneDrive SyncEngine": "Files.ReadWrite.All Sites.ReadWrite.All User.Read",
    "OfficeHome": "User.Read Sites.Read.All GroupMember.Read.All",
    "Outlook Mobile": "Mail.ReadWrite MailboxSettings.Read User.Read",
}


def benign_user_calls(user, loc=None, n=None, offset_s=0.0):
    """1-3 everyday Graph requests from a user's clients, from the sign-in's egress."""
    ip = (loc or {}).get("ip") or ac.egress(user)["ip"]
    out = []
    for i in range(n or random.randint(1, 3)):
        client, method, uri, status = random.choice(_USER_CALLS)
        out.append(_record(method=method, uri=uri, status=status, ip=ip, app_id=CLIENT_APPS[client],
                           user_id=ac.user_oid(user["username"]), scopes=_DELEGATED_SCOPES.get(client, ""),
                           wids=WID_MEMBER, ua=ac.user_agent(user), offset_s=offset_s + i * 0.4))
    return out


def benign_app_calls(name=None, user=None, offset_s=0.0):
    """One routine request from a daemon app, drawn from that app's own baseline. `user` is the
    roster identity a per-user call (drive delta, profile sync) is about."""
    name = name or random.choice(list(DAEMON_APPS))
    spec = DAEMON_APPS[name]
    method, uri, status, size = random.choice(spec["calls"])
    return [app_request(app_identity(name), method, _fill(uri, user), status, roles=spec["roles"],
                        size=size + random.randint(0, size // 4 + 1), offset_s=offset_s)]


# ── request sequences behind scenario operations ─────────────────────────────────────
def admin_change(admin, method, uri, status, *, wids=WID_USER_ADMIN,
                 scopes="Directory.AccessAsUser.All User.ReadWrite.All", ip=None, offset_s=-2.0):
    """The Graph call an admin made (PowerShell SDK) for a directory change the audit log records."""
    return [user_request(admin, method, uri, status, scopes=scopes, wids=wids, ip=ip,
                         offset_s=offset_s)]


def burst(identity, calls, *, ip=None, roles="", scopes="", wids=WID_MEMBER, client=None,
          span_s=240.0, end_offset_s=-5.0):
    """Many requests from one identity within span_s seconds, ending at end_offset_s (<= now).
    identity is a user dict (delegated) or app_identity() (app-only). calls: [(method, uri, status, size)]."""
    out = []
    n = len(calls)
    for i, (method, uri, status, size) in enumerate(calls):
        off = end_offset_s - span_s * (n - 1 - i) / max(1, n - 1)
        if "app_id" in identity:
            out.append(app_request(identity, method, uri, status, roles=roles, ip=ip, size=size,
                                   offset_s=off))
        else:
            out.append(user_request(identity, method, uri, status, client=client or "Microsoft Graph Command Line Tools",
                                    scopes=scopes or "Directory.Read.All User.Read.All", wids=wids,
                                    ip=ip, size=size, offset_s=off))
    return out
