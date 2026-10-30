"""Office 365 Exchange Online audit (O365 Management Activity, Workload=Exchange)
-> msft_o365_exchange_online_raw, via the cribl_direct transport (dedicated UUID).

Record shapes verified against the Management Activity API schema (ExchangeAdmin /
ExchangeMailbox) and real tenant rows:
  - RecordType 1  ExchangeAdmin  : cmdlet audit — Parameters [{Name,Value}], ObjectId path,
                                    ResultStatus "True"/"False", ExternalAccess, OriginatingServer
  - RecordType 2  ExchangeItem   : mailbox action — LogonType (0 Owner/2 Delegated), MailboxOwnerUPN,
                                    MailboxGuid, ClientInfoString, ClientIPAddress, Item/Folders
  - RecordType 50 MailItemsAccessed : OperationProperties [{Name:MailAccessType,Value:Bind}], OperationCount

Benign baseline = routine mailbox activity (MailItemsAccessed dominant, Send, Move, benign
rules, logins) + light admin. Threat scenarios target the Exchange BEC detections:
inbox forwarding rule, email-hiding rule, mailbox SMTP forwarding, mailbox delegation,
SendAs grant, transport (mail-flow) forwarding rule, folder-permission modification, and
mailbox audit bypass.
"""
import base64
import random
import time
import uuid

from modules import azure_common as ac
from modules import graph_activity as ga

NAME = "Office 365 Exchange Online"
DESCRIPTION = "Simulates Office 365 Exchange Online mailbox/admin audit records for msft_o365_exchange_online_raw via the cribl_direct transport."
CONFIG_KEY = "o365_exchange_config"
SOURCE_IDENTIFIER = "dee8e85ce7db4573a8bc21b807e1d73a"
INTEGRATION_IDENTIFIER = "logsim:o365_exchange"
DATASET = "msft_o365_exchange_online_raw"
EVENT_INTERVAL = 0.3   # default relative benign volume: mailbox access (MailItemsAccessed) is very high volume
ORG_ID = "09febfec-25f3-48fa-bd8c-9b4a44f896ec"
ORG_NAME = ac.UPN_DOMAIN

ADMIN_ROLES = ("IT Administrator", "IT Director", "Systems Engineer")
_EXT_DOMAINS = ["gmail.com", "proton.me", "mailrelay-xyz.com", "outlook.com", "secure-fwd.net"]
_SERVERS = ["SA1PR22MB4272 (15.21.0496.000)", "CH2PR22MB1863 (15.20.4200.000)",
            "BN9PR22MB3421 (15.20.4200.012)"]
# Threat rate governed centrally by ac.ThreatGate / ac.THREAT_EPISODES_PER_HOUR (see _GATE below).


def _g():
    return str(uuid.uuid4())


def _now(offset_s=0):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + offset_s))


def _sid(username):
    n = ac._h("sid:" + username)
    return f"S-1-5-21-{n % 4294967295}-{(n >> 32) % 4294967295}-{(n >> 64) % 4294967295}-{n % 90000 + 10000}"


_MBX_HOST = "NAMPR22A009.PROD.OUTLOOK.COM"
_POOL_OWA = "Microsoft.Exchange.Clients.Owa2.Server.NetCore"   # user-created rules (OWA/Outlook)
_POOL_ADMIN = "MSExchangeAdminApiNetCore"                      # Set-Mailbox / transport (EAC/admin API)


def _mbx_path(u):
    return (f"{_MBX_HOST}/Microsoft Exchange Hosted Organizations/"
            f"{ORG_NAME}/{u['display_name']}")


def _mbx_oid_path(u):
    # Real O365 rows address the mailbox by its directory object GUID, not the display name.
    return (f"{_MBX_HOST}/Microsoft Exchange Hosted Organizations/"
            f"{ORG_NAME}/{ac.user_oid(u['username'])}")


def _ip_port(ip):
    # RecordType 1 admin-cmdlet ClientIP carries the source port (e.g. "72.147.250.56:24410").
    return f"{ip}:{random.randint(1024, 65535)}"


def _utoken():
    # 22-char URL-safe token id, matching AppAccessContext.UniqueTokenId (e.g. "CfFaVFHZ20Cw_hYdx2XRAA").
    import base64
    return base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")


def _param(**kv):
    return [{"Name": k, "Value": v} for k, v in kv.items()]


# OWA first-party app + API ids that real MailItemsAccessed / ExchangeItemGroup rows carry.
_OWA_APP = "9199bf20-a13f-4107-85dc-02114787ef48"
_API_ID = "774A8455-3122-4FD5-90F1-C4D1A062AD91"


def _userkey(username):
    # Mailbox-activity rows (RecordType 2/3/50) carry a 16-hex UserKey, not a GUID.
    return f"{ac._h('ukey:' + username) & 0xFFFFFFFFFFFFFFFF:016X}"


def _b64id(nbytes=48):
    return base64.b64encode(bytes(random.getrandbits(8) for _ in range(nbytes))).decode().rstrip("=")


def _app_access_context(offset_s=0):
    return {"AADSessionId": _g(), "APIId": _API_ID, "ClientAppId": _OWA_APP,
            "IssuedAtTime": _now(offset_s), "UniqueTokenId": _utoken()}


def _common(operation, actor, record_type, result, offset_s=0):
    return {"CreationTime": _now(offset_s), "Id": _g(), "Operation": operation,
            "OrganizationId": ORG_ID, "RecordType": record_type, "ResultStatus": result,
            "UserKey": ac.user_oid(actor["username"]), "Version": 1, "Workload": "Exchange",
            "UserId": actor["upn"], "OrganizationName": ORG_NAME,
            "OriginatingServer": random.choice(_SERVERS)}


def admin_cmdlet(operation, actor, params, target_user=None, result="True",
                 external=False, offset_s=0):
    """RecordType 1 — Exchange admin cmdlet audit record. Field shapes (UserKey=UPN, ClientIP
    with port, per-cmdlet ObjectId, AppAccessContext with AADSessionId/UniqueTokenId) match real
    msft_o365_exchange_online_raw rows captured from a live .onmicrosoft.com tenant."""
    r = _common(operation, actor, 1, result, offset_s)
    tgt = target_user or actor
    sess = _g()
    issued = _now(offset_s)
    # ObjectId shape follows the real O365 audit rows per cmdlet family.
    if operation in ("New-InboxRule", "Set-InboxRule"):
        rule = next((p["Value"] for p in params if p["Name"] == "Name"), "")
        obj = f"{_mbx_oid_path(tgt)}\\{rule}"
        pool = _POOL_OWA
    elif operation in ("New-TransportRule", "Set-TransportRule", "Remove-TransportRule"):
        obj = ""                                  # transport rules are org-scoped, no mailbox ObjectId
        pool = _POOL_ADMIN
    elif operation.startswith("Set-Mailbox") or operation in ("Set-CASMailbox", "Enable-Mailbox"):
        obj = ac.user_oid(tgt["username"])        # bare mailbox directory GUID
        pool = _POOL_ADMIN
    else:
        obj = _mbx_path(tgt)
        pool = _POOL_ADMIN
    r.update({"UserType": 2, "UserKey": actor["upn"], "ExternalAccess": external,
              "ClientIP": _ip_port(ac.egress(actor)["ip"]), "ObjectId": obj, "Parameters": params,
              "AppPoolName": pool, "RequestId": _g(), "SessionId": sess,
              "TokenObjectId": ac.user_oid(actor["username"]), "TokenTenantId": ORG_ID,
              "AppAccessContext": {"AADSessionId": sess, "IssuedAtTime": issued,
                                   "UniqueTokenId": _utoken()}})
    if target_user:
        r["ModifiedObjectResolvedName"] = target_user["display_name"]
    return r


def mailbox_action(operation, owner, actor=None, logon_type=0, client="OWA",
                   item=None, extra=None, offset_s=0, result="Succeeded"):
    """RecordType 2 — mailbox action (owner or delegate access)."""
    actor = actor or owner
    r = _common(operation, actor, 2, result, offset_s)
    r.update({"UserType": 0, "ExternalAccess": (actor["username"] != owner["username"]),
              "LogonType": logon_type, "InternalLogonType": 0,
              "MailboxOwnerUPN": owner["upn"], "MailboxOwnerSid": _sid(owner["username"]),
              "MailboxGuid": ac.user_oid("mbx:" + owner["username"]),
              "LogonUserSid": _sid(actor["username"]),
              "ClientIPAddress": ac.egress(actor)["ip"], "ClientIP": ac.egress(actor)["ip"],
              "ClientInfoString": ("Client=OWA;Action=ViaProxy" if client == "OWA"
                                   else "Client=REST;Client=RESTSystem;;"),
              "AppId": "00000002-0000-0ff1-ce00-000000000000",
              "ClientAppId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
              "TokenTenantId": ORG_ID, "SessionId": _g()})
    if item is not None:
        r["Item"] = item
    if extra:
        r.update(extra)
    return r


def mail_items_accessed(owner, count=1, offset_s=0, throttled=False):
    """RecordType 50 — MailItemsAccessed. throttled=True emits a sync-level throttled access
    (IsThrottled True) — Microsoft stops logging per-item binds under heavy access, which is itself
    a documented mass-mailbox-access / compromise indicator.

    WIP/prerequisite-gated (verified 2026-10-30, no alert from a synthetic burst): the mass-mailbox-
    access analytics are Identity Analytics / behavioral detectors that need a per-mailbox baseline
    plus volume over a test window, which a one-shot synthetic burst cannot satisfy. The record shape
    is field-correct (matches real rows); the gap is the analytics prerequisite, not the data."""
    # Field shapes verified against real msft_o365_exchange_online_raw MailItemsAccessed rows:
    # UserType 0, OWA app/client ids, a 16-hex UserKey, AppAccessContext + TokenObjectId, and
    # OperationProperties that are just MailAccessType (no IsThrottled) on an ordinary Bind.
    r = _common("MailItemsAccessed", owner, 50, "Succeeded", offset_s)
    r["UserKey"] = _userkey(owner["username"])
    r.update({"UserType": 0, "ExternalAccess": False, "LogonType": 0, "InternalLogonType": 0,
              "MailboxOwnerUPN": owner["upn"], "MailboxOwnerSid": _sid(owner["username"]),
              "MailboxGuid": ac.user_oid("mbx:" + owner["username"]),
              "LogonUserSid": _sid(owner["username"]),
              "ClientIPAddress": ac.egress(owner)["ip"],
              "ClientInfoString": "Client=OWA;Action=ViaProxy",
              "AppId": _OWA_APP, "ClientAppId": _OWA_APP,
              "AppAccessContext": _app_access_context(offset_s),
              "TokenObjectId": ac.user_oid(owner["username"]),
              "OperationCount": count, "TokenTenantId": ORG_ID})
    if throttled:
        # Microsoft stops per-item binds under heavy access (a documented mass-access indicator).
        r["OperationProperties"] = [{"Name": "MailAccessType", "Value": "Sync"},
                                    {"Name": "IsThrottled", "Value": "True"}]
    else:
        r["OperationProperties"] = [{"Name": "MailAccessType", "Value": "Bind"}]
        r["Folders"] = [{"FolderItems": [{"CreationTime": _now(offset_s), "Id": _b64id(),
                                          "ImmutableId": _b64id(), "InternetMessageId": f"<{_g()}@{ORG_NAME}>",
                                          "SizeInBytes": random.randint(1500, 90000)}
                                         for _ in range(count)],
                         "Path": "\\Inbox"}]
    return r


def item_group_action(operation, owner, actor=None, folder_path="\\Deleted Items", count=1, offset_s=0):
    """RecordType 3 — ExchangeItemGroup (bulk move/soft-delete). Real SoftDelete/HardDelete rows
    carry AffectedItems + a Folder object, Bearer auth and the OWA app ids."""
    actor = actor or owner
    r = _common(operation, actor, 3, "Succeeded", offset_s)
    r["UserKey"] = _userkey(actor["username"])
    folder = {"Id": _b64id(), "Path": folder_path}
    r.update({"UserType": 0, "ExternalAccess": (actor["username"] != owner["username"]),
              "CrossMailboxOperation": False, "LogonType": 0, "InternalLogonType": 0,
              "AuthType": "Bearer", "TokenType": "V1AppActAs", "HostAppId": _API_ID,
              "MailboxOwnerUPN": owner["upn"], "MailboxOwnerSid": _sid(owner["username"]),
              "MailboxGuid": ac.user_oid("mbx:" + owner["username"]),
              "LogonUserSid": _sid(actor["username"]),
              "ClientIPAddress": ac.egress(actor)["ip"], "ClientIP": ac.egress(actor)["ip"],
              "ClientInfoString": "Client=OWA;Action=ViaProxy",
              "AppId": _OWA_APP, "ClientAppId": _OWA_APP,
              "TokenObjectId": ac.user_oid(actor["username"]), "TokenTenantId": ORG_ID,
              "AppAccessContext": _app_access_context(offset_s), "Folder": folder,
              "AffectedItems": [{"Id": _b64id(), "InternetMessageId": f"<{_g()}@{ORG_NAME}>",
                                 "ParentFolder": folder, "Subject": ac.email_subject()}
                                for _ in range(count)]})
    return r


def dlp_rule_match(sender, offset_s=0):
    """RecordType 13 — DlpRuleMatch: a sent message matched a DLP policy. Real rows carry
    ExchangeMetaData + PolicyDetails and no ResultStatus/OriginatingServer.

    WIP/prerequisite-gated (verified 2026-10-30, no alert): DLP alerts are raised by the tenant's own
    DLP policy engine evaluating mail, so injecting a match record for a policy that is not configured
    in the tenant will not raise the DLP analytic. The record shape is field-correct; firing needs a
    real DLP policy in the tenant."""
    r = _common("DlpRuleMatch", sender, 13, "", offset_s)
    for k in ("ResultStatus", "OriginatingServer", "OrganizationName"):
        r.pop(k, None)
    r["UserKey"] = ac.user_oid(sender["username"])
    server = random.choice(_SERVERS).split()[0]
    msg_id = f"<{_g().replace('-', '')}@{server}.namprd22.prod.outlook.com>"
    r.update({"UserType": 0, "ObjectId": msg_id, "IncidentId": _g(),
              "SensitiveInfoDetectionIsIncluded": False,
              "ExchangeMetaData": {"BCC": [], "CC": [], "FileSize": random.randint(2000, 200000),
                  "From": sender["upn"], "IsViewableByExternalUsers": True, "MessageID": msg_id,
                  "RecipientCount": 1, "SensitivityLabelIds": [], "SensitivityLabelNames": [],
                  "Sent": _now(offset_s)},
              "PolicyDetails": [{"PolicyId": _g(),
                  "PolicyName": "Default HR & Privacy Info Protection Policy",
                  "Rules": [{"ActionParameters": ["GenerateAlert:true"],
                             "Actions": ["NotifyUser", "GenerateAlert"],
                             "AlertProperties": [{"Name": "GenerateAlertCutTime", "Value": _now(offset_s)}],
                             "RuleId": _g(), "RuleName": random.choice(["U.S. PII", "Credit Card Number",
                                                                        "U.S. Social Security Number (SSN)"])}]}]})
    return r


# ── benign baseline ─────────────────────────────────────────────────────────────────

def _b_mail_accessed(cfg):
    # ~4% of heavy benign access sessions get throttled (large mailboxes, migrations, busy users).
    if random.random() < 0.04:
        return mail_items_accessed(ac.pick_user(cfg), throttled=True)
    return mail_items_accessed(ac.pick_user(cfg), count=random.randint(1, 8))


def _b_send(cfg):
    return mailbox_action("Send", ac.pick_user(cfg), client="OWA")


def _b_move(cfg):
    u = ac.pick_user(cfg)
    op = random.choice(["MoveToDeletedItems", "Move", "SoftDelete", "HardDelete"])
    # SoftDelete/HardDelete are logged as RecordType 3 (ExchangeItemGroup) with AffectedItems;
    # Move/MoveToDeletedItems stay RecordType 2 single-item actions.
    if op in ("SoftDelete", "HardDelete"):
        return item_group_action(op, u, count=random.randint(1, 5))
    return mailbox_action(op, u, item={"Subject": ac.email_subject(), "ParentFolder": {"Path": "\\Inbox"}})


def _b_dlp_match(cfg):
    return dlp_rule_match(ac.pick_user(cfg))


def _b_benign_rule(cfg):
    u = ac.pick_user(cfg)
    folder = random.choice(["Newsletters", "Projects", "Receipts", "Team"])
    return mailbox_action("UpdateInboxRules", u, extra={"OperationProperties":
        [{"Name": "RuleOperation", "Value": "AddMailboxRule"},
         {"Name": "RuleName", "Value": f"Move {folder}"},
         {"Name": "RuleActions", "Value": f"[MoveToFolder={folder}]"}]})


def _b_login(cfg):
    return mailbox_action("MailboxLogin", ac.pick_user(cfg))


def _b_new_mailbox(cfg):
    admin = ac.pick_by_role(cfg, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(cfg)
    return admin_cmdlet("New-Mailbox", admin, _param(Name=tgt["display_name"],
                        UserPrincipalName=tgt["upn"]), target_user=tgt, external=True)


# Full mailbox-audit operation set (Exchange mailbox auditing — owner/delegate/admin actions).
_MAILBOX_OPS = ["Create", "Update", "Move", "MoveToDeletedItems", "SoftDelete", "HardDelete",
                "Copy", "FolderBind", "Send", "SendAs", "SendOnBehalf", "MailboxLogin",
                "UpdateInboxRules", "UpdateCalendarDelegation", "AddFolderPermissions",
                "UpdateFolderPermissions", "RemoveFolderPermissions", "ApplyRecord",
                "RecordDelete", "SearchQueryInitiated"]
_ITEM_OPS = {"Create", "Update", "Move", "MoveToDeletedItems", "SoftDelete", "HardDelete",
             "Copy", "FolderBind"}
# Common benign admin cmdlets (mailbox configuration housekeeping).
_ADMIN_BENIGN = ["Set-Mailbox", "Set-CASMailbox", "Set-MailboxRegionalConfiguration",
                 "Set-MailboxCalendarConfiguration", "Enable-Mailbox", "Set-OwaMailboxPolicy",
                 "Set-MailboxMessageConfiguration", "Add-MailboxFolderPermission",
                 "Set-Clutter", "Set-FocusedInbox"]


def _b_mailbox_op(cfg):
    u = ac.pick_user(cfg)
    op = random.choice(_MAILBOX_OPS)
    lt = 0 if random.random() < 0.85 else 2   # mostly owner, some delegate access
    item = ({"Subject": ac.email_subject(), "ParentFolder": {"Path": "\\Inbox"}}
            if op in _ITEM_OPS else None)
    return mailbox_action(op, u, logon_type=lt, item=item)


def _b_admin_benign(cfg):
    admin = ac.pick_by_role(cfg, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(cfg)
    return admin_cmdlet(random.choice(_ADMIN_BENIGN), admin, _param(Identity=tgt["upn"]),
                        target_user=tgt)


_BENIGN = [(8, _b_mail_accessed), (7, _b_mailbox_op), (3, _b_move), (2, _b_benign_rule),
           (2, _b_login), (1, _b_new_mailbox), (1, _b_admin_benign), (1, _b_dlp_match)]
_B_POOL = [fn for w, fn in _BENIGN for _ in range(w)]
_HUMAN = {_b_mailbox_op, _b_benign_rule, _b_login, _b_new_mailbox, _b_admin_benign}


# A realistic minority of benign Exchange operations fail: admin cmdlets rejected for insufficient
# permissions / bad parameters (ResultStatus "False"), and mailbox actions that error (ResultStatus
# "Failed"). Background MailItemsAccessed (RT50) is left as success.
_FAIL_RATE = 0.08


def _maybe_fail(rec):
    if random.random() >= _FAIL_RATE:
        return rec
    rt = rec.get("RecordType")
    if rt == 1:                      # admin cmdlet: mostly hard-fail, sometimes partial
        rec["ResultStatus"] = "PartiallySucceeded" if random.random() < 0.25 else "False"
    elif rt == 2:                    # mailbox action
        rec["ResultStatus"] = "Failed"
    return rec


def generate_benign(config=None, context=None):
    fn = random.choice(_B_POOL)
    if fn in _HUMAN and random.random() > ac.activity_weight():
        fn = _b_mail_accessed   # off-hours: background mail sync still runs
    return [_maybe_fail(fn(config))]


# ── Exchange BEC detection scenarios ────────────────────────────────────────────────

def scenario_inbox_forwarding_rule(config=None):
    """New-InboxRule that forwards the whole inbox to an external public mailbox (gmail) ->
    'Exchange inbox forwarding rule configured' (public domain -> 'External ...' Low variant).
    No filter condition, so the rule carries every incoming message out to the external account."""
    u = ac.pick_user(config)
    ext = f"{u['username'].replace('.', '')}@gmail.com"
    return [admin_cmdlet("New-InboxRule", u, _param(Name="Invoices", ForwardTo=ext,
                         StopProcessingRules="True"), target_user=u)]


def scenario_inbox_forwarding_delegate(config=None):
    """New-InboxRule with external forwarding set by a DELEGATE on another user's mailbox ->
    'Exchange inbox forwarding rule configured by a delegate user' variant."""
    delegate = ac.pick_user(config); victim = ac.pick_user(config)
    ext = f"{victim['username'].replace('.', '')}@{random.choice(_EXT_DOMAINS)}"
    return [admin_cmdlet("New-InboxRule", delegate, _param(Name="Archive", ForwardTo=ext,
                         StopProcessingRules="True"), target_user=victim, external=True)]


def scenario_inbox_forwarding_suspicious(config=None):
    """New-InboxRule forwarding externally AND filtering on sensitive keywords -> 'Suspicious
    Exchange inbox forwarding rule configured' variant (Medium)."""
    u = ac.pick_user(config)
    ext = f"{u['username'].replace('.', '')}@{random.choice(_EXT_DOMAINS)}"
    return [admin_cmdlet("New-InboxRule", u, _param(Name=".", ForwardTo=ext,
                         SubjectOrBodyContainsWords="invoice;payment;wire transfer;password;confidential",
                         DeleteMessage="True", StopProcessingRules="True"), target_user=u)]


def scenario_transport_forwarding_delegate(config=None):
    """A mail-flow (transport) forwarding rule configured by a delegate -> 'Exchange transport
    forwarding rule configured' delegate variant."""
    delegate = ac.pick_user(config)
    ext = f"collector@{random.choice(_EXT_DOMAINS)}"
    return [admin_cmdlet("New-TransportRule", delegate, _param(Name="External Archive",
                         BlindCopyTo=ext, Enabled="True"), external=True)]


def scenario_mailbox_smtp_forwarding_delegate(config=None):
    """Set-Mailbox SMTP forwarding set by a DELEGATE on another user's mailbox -> 'Exchange user
    mailbox forwarding' delegate variant."""
    delegate = ac.pick_user(config); victim = ac.pick_user(config)
    ext = f"{victim['username'].replace('.', '')}@{random.choice(_EXT_DOMAINS)}"
    return [admin_cmdlet("Set-Mailbox", delegate, _param(Identity=victim["upn"],
                         ForwardingSmtpAddress=f"smtp:{ext}", DeliverToMailboxAndForward="False"),
                         target_user=victim, external=True)]


def scenario_email_hiding_rule(config=None):
    """New-InboxRule that deletes/hides incoming mail -> 'Exchange email-hiding inbox rule'."""
    u = ac.pick_user(config)
    return [admin_cmdlet("New-InboxRule", u, _param(Name=".", MoveToFolder="Deleted Items",
                         MarkAsRead="True", DeleteMessage="True", StopProcessingRules="True"),
                         target_user=u)]


def scenario_catch_all_hiding_rule(config=None):
    """New-InboxRule with NO filtering condition (applies to ALL incoming mail) that moves to an
    obscure folder, marks read and stops processing -> 'Suspicious catch-all inbox rule for email
    hiding'. The absence of any From/Subject condition is the catch-all signal."""
    u = ac.pick_user(config)
    return [admin_cmdlet("New-InboxRule", u, _param(Name="...", MoveToFolder="RSS Feeds",
                         MarkAsRead="True", DeleteMessage="False", StopProcessingRules="True"),
                         target_user=u)]


def scenario_mailbox_smtp_forwarding(config=None):
    """Set-Mailbox with external SMTP forwarding -> 'Exchange user mailbox forwarding'."""
    u = ac.pick_user(config)
    ext = f"{u['username'].replace('.', '')}@{random.choice(_EXT_DOMAINS)}"
    return [admin_cmdlet("Set-Mailbox", u, _param(Identity=u["upn"],
                         ForwardingSmtpAddress=f"smtp:{ext}", DeliverToMailboxAndForward="False"),
                         target_user=u)]


def scenario_mailbox_delegation(config=None):
    """Add-MailboxPermission FullAccess to another user -> 'Exchange mailbox delegation permissions added'."""
    victim = ac.pick_user(config); grantee = ac.pick_user(config)
    return [admin_cmdlet("Add-MailboxPermission", grantee, _param(Identity=victim["upn"],
                         User=grantee["upn"], AccessRights="FullAccess", InheritanceType="All"),
                         target_user=victim)]


def scenario_send_as_permission(config=None):
    """Add-RecipientPermission SendAs -> impersonation setup."""
    victim = ac.pick_user(config); grantee = ac.pick_user(config)
    return [admin_cmdlet("Add-RecipientPermission", grantee, _param(Identity=victim["upn"],
                         Trustee=grantee["upn"], AccessRights="SendAs"), target_user=victim)]


def scenario_transport_forwarding_rule(config=None):
    """New-TransportRule that BCCs all mail externally -> 'Exchange transport forwarding rule configured'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    ext = f"collector@{random.choice(_EXT_DOMAINS)}"
    return [admin_cmdlet("New-TransportRule", admin, _param(Name="External Archive",
                         BlindCopyTo=ext, Enabled="True"))]


def scenario_folder_permission_mod(config=None):
    """ModifyFolderPermissions granting the Default user access -> 'Exchange mailbox folder permission modification'."""
    u = ac.pick_user(config)
    item = {"Id": _g(), "ParentFolder": {"Path": "\\Inbox", "MemberRights": "ReadAny",
            "MemberUpn": "Default", "MemberSid": "S-1-1-0"}}
    return [mailbox_action("ModifyFolderPermissions", u, item=item, result="Succeeded")]


def scenario_mail_accessed_multi_ip_subnet(config=None):
    """One mailbox accessed from MULTIPLE rotating IPs in the same /16 subnet (per the detector
    'User mail items accessed from multiple IPs in the same subnet'), where the caller IPs are
    anomalous for the user (risky ASN/country vs their baseline). Rotating within one /16 evades
    per-IP rate limits (T1090.003)."""
    owner = ac.pick_user(config)
    # A hosting/VPS /16 that is NOT this user's normal egress -> anomalous ASN/country signal.
    net16 = random.choice(["45.148", "193.218", "185.220", "146.70"])
    out = []
    for i in range(8):
        r = mail_items_accessed(owner, count=random.randint(2, 6), offset_s=-(i * 15))
        ip = f"{net16}.{random.randint(0, 255)}.{random.randint(2, 250)}"   # rotate across the /16
        r["ClientIPAddress"] = ip
        r["ClientInfoString"] = "Client=REST;Client=RESTSystem;;"   # unmanaged automated access
        out.append(r)
    return out


def scenario_sent_to_deleted_scripted(config=None):
    """A burst of Sent Items -> Deleted Items moves via a REST/scripting client from an unusual
    source -> 'User moved Exchange Sent items to Deleted Items (possible scripting)' (anti-forensics)."""
    u = ac.pick_user(config)
    bad = random.choice(["45.148.10.92", "193.218.118.158", "171.25.193.78"])
    out = []
    for i in range(12):
        r = mailbox_action("Move", u, client="REST",
                           item={"Subject": ac.email_subject(), "ParentFolder": {"Path": "\\Sent Items"}},
                           extra={"DestFolderPathName": "\\Deleted Items"}, offset_s=-(i * 5))
        r["ClientIPAddress"] = bad
        r["ClientIP"] = bad
        out.append(r)
    return out


def scenario_anti_phish_policy_disabled(config=None):
    """Anti-phishing policy disabled/removed -> 'Exchange anti-phish policy disabled or removed'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [admin_cmdlet(random.choice(["Disable-AntiPhishRule", "Remove-AntiPhishPolicy"]), admin,
                         _param(Identity="Office365 AntiPhish Default"))]


def scenario_exchange_audit_log_disabled(config=None):
    """Per-mailbox audit logging turned off -> 'Exchange audit log disabled'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [admin_cmdlet("Set-Mailbox", admin, _param(Identity=tgt["upn"], AuditEnabled="False"),
                         target_user=tgt)]


def scenario_cas_mailbox_changed(config=None):
    """Client Access settings on a mailbox are changed to re-enable legacy protocols (IMAP/POP/
    ActiveSync) that bypass modern-auth controls -> 'Mailbox Client Access Setting (CAS) changed'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [admin_cmdlet("Set-CASMailbox", admin, _param(Identity=tgt["upn"],
                         ImapEnabled="True", PopEnabled="True", ActiveSyncEnabled="True"),
                         target_user=tgt)]


def scenario_compliance_search_created(config=None):
    """eDiscovery/content search created -> 'Exchange compliance search created'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    return [admin_cmdlet("New-ComplianceSearch", admin,
                         _param(Name=f"Search-{random.randint(1000,9999)}",
                                ContentMatchQuery="(password OR confidential OR wire transfer)",
                                ExchangeLocation="All"))]


def scenario_dkim_disabled(config=None):
    """DKIM signing disabled for a domain -> 'Exchange DKIM signing configuration disabled'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [admin_cmdlet("Set-DkimSigningConfig", admin, _param(Identity=ORG_NAME, Enabled="False"))]


def scenario_malware_filter_removed(config=None):
    """Malware filter policy removed -> 'Exchange malware filter policy removed'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [admin_cmdlet("Remove-MalwareFilterPolicy", admin, _param(Identity="Default"))]


def scenario_safe_attachment_disabled(config=None):
    """Safe Attachments policy disabled/removed -> 'Exchange Safe Attachment policy disabled or removed'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [admin_cmdlet(random.choice(["Disable-SafeAttachmentRule", "Remove-SafeAttachmentPolicy"]),
                         admin, _param(Identity="Default SafeAttachment Policy"))]


def scenario_safe_link_disabled(config=None):
    """Safe Links policy disabled/removed -> 'Exchange Safe Link policy disabled or removed'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [admin_cmdlet(random.choice(["Disable-SafeLinksRule", "Remove-SafeLinksPolicy"]),
                         admin, _param(Identity="Default SafeLinks Policy"))]


def scenario_email_hiding_transport_rule(config=None):
    """Transport (mail-flow) rule that silently deletes/redirects mail -> 'Exchange email-hiding
    transport rule'."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [admin_cmdlet("New-TransportRule", admin,
                         _param(Name="Compliance Journaling", DeleteMessage="True",
                                SubjectOrBodyContainsWords="invoice;payment;breach", Enabled="True"))]


def scenario_single_ip_multi_mailbox(config=None):
    """One caller IP reads mail items from MANY different mailboxes -> 'Single IP accessed mail
    items of multiple users'."""
    ip = random.choice(["45.148.10.92", "193.218.118.158", "185.220.101.34"])
    out = []
    for i in range(8):
        owner = ac.pick_user(config)
        r = mail_items_accessed(owner, count=random.randint(2, 5), offset_s=-(i * 15))
        r["ClientIPAddress"] = ip
        r["ClientInfoString"] = "Client=REST;Client=RESTSystem;;"
        out.append(r)
    return out


def scenario_mailbox_enumeration(config=None):
    """An Azure application uses the Graph API to enumerate/read many distinct mailboxes in a short
    window -> 'Mailbox enumeration activity by Azure application' (Cloud Service Discovery T1526,
    Informational)."""
    out = []
    for i in range(10):
        owner = ac.pick_user(config)
        r = mail_items_accessed(owner, count=1, offset_s=-(i * 6))
        r["ClientInfoString"] = "Client=REST;Client=RESTSystem;;"   # Graph app, not interactive
        r["AppId"] = "00000003-0000-0000-c000-000000000000"         # Microsoft Graph
        out.append(r)
    return out


def scenario_sensitive_mail_external(config=None):
    """Sensitive mail sent to an external recipient -> 'Sensitive Exchange mail sent to external
    users'."""
    u = ac.pick_user(config)
    ext = f"{u['username'].replace('.', '')}@{random.choice(_EXT_DOMAINS)}"
    return [mailbox_action("Send", u, client="OWA",
                           item={"Subject": "Wire transfer instructions - CONFIDENTIAL",
                                 "ParentFolder": {"Path": "\\Sent Items"}},
                           extra={"Recipients": [ext], "ExternalAccess": True})]


def scenario_dlp_policy_disabled(config=None):
    """A Microsoft 365 DLP compliance policy is disabled or removed -> 'Microsoft 365 DLP policy
    disabled or removed' (compliance-cmdlet audit record)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    return [admin_cmdlet(random.choice(["Set-DlpCompliancePolicy", "Remove-DlpCompliancePolicy"]),
                         admin, _param(Identity=random.choice(["U.S. PII", "PCI DSS", "Financial Data"]),
                                       Mode="Disable"))]


def scenario_audit_bypass(config=None):
    """Set-MailboxAuditBypassAssociation enabling audit bypass -> defense evasion (Exchange audit bypass)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [admin_cmdlet("Set-MailboxAuditBypassAssociation", admin,
                         _param(Identity=tgt["upn"], AuditBypassEnabled="True"), target_user=tgt)]


SCENARIOS = {
    "inbox_forwarding_rule": scenario_inbox_forwarding_rule,
    "inbox_forwarding_delegate": scenario_inbox_forwarding_delegate,
    "inbox_forwarding_suspicious": scenario_inbox_forwarding_suspicious,
    "mailbox_smtp_forwarding_delegate": scenario_mailbox_smtp_forwarding_delegate,
    "transport_forwarding_delegate": scenario_transport_forwarding_delegate,
    "email_hiding_rule": scenario_email_hiding_rule,
    "catch_all_hiding_rule": scenario_catch_all_hiding_rule,
    "mailbox_smtp_forwarding": scenario_mailbox_smtp_forwarding,
    "mailbox_delegation": scenario_mailbox_delegation,
    "send_as_permission": scenario_send_as_permission,
    "transport_forwarding_rule": scenario_transport_forwarding_rule,
    "folder_permission_mod": scenario_folder_permission_mod,
    "mail_accessed_multi_ip_subnet": scenario_mail_accessed_multi_ip_subnet,
    "sent_to_deleted_scripted": scenario_sent_to_deleted_scripted,
    "single_ip_multi_mailbox": scenario_single_ip_multi_mailbox,
    "anti_phish_policy_disabled": scenario_anti_phish_policy_disabled,
    "exchange_audit_log_disabled": scenario_exchange_audit_log_disabled,
    "cas_mailbox_changed": scenario_cas_mailbox_changed,
    "compliance_search_created": scenario_compliance_search_created,
    "dkim_disabled": scenario_dkim_disabled,
    "malware_filter_removed": scenario_malware_filter_removed,
    "safe_attachment_disabled": scenario_safe_attachment_disabled,
    "safe_link_disabled": scenario_safe_link_disabled,
    "email_hiding_transport_rule": scenario_email_hiding_transport_rule,
    "sensitive_mail_external": scenario_sensitive_mail_external,
    "mailbox_enumeration": scenario_mailbox_enumeration,
    "dlp_policy_disabled": scenario_dlp_policy_disabled,
    "audit_bypass": scenario_audit_bypass,
}


# Maps each scenario to the Cortex analytics alert its O365 Audit (RecordType 1) record is built to
# raise, so threat_catalog can offer them on demand. The three forwarding detectors
# (confirmed on the Cortex "alerts-by-name" pages) all read Office 365 Audit and carry a 14-day
# activation + 30-day training window, so a freshly started feed sits in activation before firing.
# Delegate / suspicious / external shapes roll up under the base detector name as documented variations.
ANALYTIC_ALERTS = {
    "inbox_forwarding_rule": "Exchange inbox forwarding rule configured",
    "inbox_forwarding_delegate": "Exchange inbox forwarding rule configured",
    "inbox_forwarding_suspicious": "Exchange inbox forwarding rule configured",
    "mailbox_smtp_forwarding": "Exchange user mailbox forwarding",
    "mailbox_smtp_forwarding_delegate": "Exchange user mailbox forwarding",
    "transport_forwarding_rule": "Exchange transport forwarding rule configured",
    "transport_forwarding_delegate": "Exchange transport forwarding rule configured",
    "email_hiding_rule": "Exchange email-hiding inbox rule",
    "catch_all_hiding_rule": "Exchange email-hiding inbox rule",
    "email_hiding_transport_rule": "Exchange email-hiding transport rule",
    "mailbox_delegation": "Exchange mailbox delegation permissions added",
    "folder_permission_mod": "Exchange mailbox folder permission modification",
    "mail_accessed_multi_ip_subnet": "User mail items accessed from multiple IPs",
    "single_ip_multi_mailbox": "Single IP accessed mail items of multiple users",
    "mailbox_enumeration": "Mailbox enumeration activity by Azure application",
    "sent_to_deleted_scripted": "User moved sent items to deleted items",
    "anti_phish_policy_disabled": "Exchange anti-phish policy disabled or removed",
    "exchange_audit_log_disabled": "Exchange audit log disabled",
    "compliance_search_created": "Exchange compliance search created",
    "dkim_disabled": "Exchange DKIM signing configuration disabled",
    "malware_filter_removed": "Exchange malware filter policy removed",
    "safe_attachment_disabled": "Exchange Safe Attachment policy disabled or removed",
    "safe_link_disabled": "Exchange Safe Link policy disabled or removed",
    "sensitive_mail_external": "Sensitive Exchange mail sent to external users",
    "dlp_policy_disabled": "Microsoft 365 DLP policy disabled or removed",
}


# ── Graph activity companions ────────────────────────────────────────────────────────
# "Azure mailbox rule creation" and "Mailbox enumeration activity by Azure application" read Graph
# API request logs (MicrosoftGraphActivityLogs, routed to msft_azure_raw), so these scenarios also
# emit the Graph calls behind their Exchange records. Benign Exchange traffic carries none.
_RULE_SCENARIOS = {"inbox_forwarding_rule", "inbox_forwarding_delegate", "inbox_forwarding_suspicious",
                   "email_hiding_rule", "catch_all_hiding_rule"}


def _graph_companions(key, records):
    if key in _RULE_SCENARIOS:
        out = []
        for r in records:
            upn = r.get("UserId") or ""
            actor = {"username": upn.split("@")[0], "upn": upn}
            if r.get("ExternalAccess"):        # a delegate writing into another user's mailbox
                uri = (f"/v1.0/users/{ac._stable_guid('mbx:' + str(r.get('ObjectId')))}"
                       "/mailFolders/inbox/messageRules")
            else:
                uri = "/v1.0/me/mailFolders/inbox/messageRules"
            out.append(ga.user_request(actor, "POST", uri, 201, client="Microsoft Graph Command Line Tools",
                                       scopes="MailboxSettings.ReadWrite Mail.ReadWrite",
                                       ip=r.get("ClientIP"), offset_s=-2.0))
        return out
    if key == "mailbox_enumeration":
        app = ga.app_identity(ac.rare_app_name())
        calls = [("GET", f"/v1.0/users/{ac.user_oid((r.get('MailboxOwnerUPN') or 'x').split('@')[0])}"
                         "/messages?$top=50", 200, random.randint(30000, 90000)) for r in records]
        return ga.burst(app, calls, ip=ac.rare_asn_loc()["ip"], roles="Mail.Read", span_s=60)
    return []


def _with_graph(config, key, records):
    if ac.eventhub_enabled(config, CONFIG_KEY):
        return _graph_companions(key, records) + records
    return records


_GATE = ac.ThreatGate(SCENARIOS)


def get_threat_names():
    return list(SCENARIOS.keys())


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    if scenario_event:
        key = scenario_event if scenario_event in SCENARIOS else scenario_event.lower()
        if key in SCENARIOS:
            return (_with_graph(config, key, SCENARIOS[key](config)), key)
        return None
    if benign_only or threat_level == "Benign Traffic Only":
        return generate_benign(config, context)
    if _GATE.fire(threat_level, config):
        key = random.choice(list(SCENARIOS))
        return (_with_graph(config, key, SCENARIOS[key](config)), key)
    return generate_benign(config, context)
