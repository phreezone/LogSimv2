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

NAME = "Office 365 Exchange Online"
DESCRIPTION = "Simulates Office 365 Exchange Online mailbox/admin audit records for msft_o365_exchange_online_raw via the cribl_direct transport."
CONFIG_KEY = "o365_exchange_config"
SOURCE_IDENTIFIER = "dee8e85ce7db4573a8bc21b807e1d73a"
INTEGRATION_IDENTIFIER = "logsim:o365_exchange"
DATASET = "msft_o365_exchange_online_raw"
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


def _mbx_path(u):
    return (f"NAMPR22A009.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/"
            f"{ORG_NAME}/{u['display_name']}")


def _store_id(seed):
    """Exchange store identifier — 'AAMk' + base64 blob, the real Item/Folder Id shape
    seen in mailbox audit records (Item.Id, ParentFolder.Id, DestFolder.Id, Folders[].Id).
    https://learn.microsoft.com/en-us/purview/audit-log-exchange-properties"""
    # Mask explicitly to 256 bits (32 bytes) BEFORE to_bytes: the raw XOR of h1 with
    # (h2 << 64) can span up to 320 bits, and int.to_bytes() raises OverflowError for any
    # value >= 1 << 256. The paste-order mask guarantees no seed can ever overflow.
    n = (ac._h("store:" + seed) ^ (ac._h("store2:" + seed) << 64)) & ((1 << 256) - 1)
    return "AAMk" + base64.b64encode(n.to_bytes(32, "big")).decode().rstrip("=")


_OWA_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/131.0.0.0 Safari/537.36")


def _param(**kv):
    return [{"Name": k, "Value": v} for k, v in kv.items()]


def _common(operation, actor, record_type, result, offset_s=0):
    return {"CreationTime": _now(offset_s), "Id": _g(), "Operation": operation,
            "OrganizationId": ORG_ID, "RecordType": record_type, "ResultStatus": result,
            "UserKey": ac.user_oid(actor["username"]), "Version": 1, "Workload": "Exchange",
            "UserId": actor["upn"], "OrganizationName": ORG_NAME,
            "OriginatingServer": random.choice(_SERVERS)}


def _folder_name(path):
    # "\\Inbox" -> "Inbox"; "\\Inbox\\Old Mail" -> "Old Mail"
    return path.strip("\\").split("\\")[-1]


def _item_shape(item):
    """Normalize an Item dict to the ExchangeItem complex type: Id (store id, 'AAMk...' —
    mandatory), Subject, ParentFolder {Id, Path (+'\\\\'+Name)}, InternetMessageId,
    Attachments (string of names+sizes) — https://learn.microsoft.com/en-us/office/
    office-365-management-api/office-365-management-activity-api-schema#exchangeitem"""
    out = {"Id": _store_id("item:" + item.get("Subject", _g()))}
    if "Subject" in item:
        out["Subject"] = item["Subject"]
    pf = item.get("ParentFolder")
    if pf:
        path = pf.get("Path", "\\Inbox")
        pf = dict(pf)
        pf.setdefault("Id", _store_id("folder:" + path))
        pf.setdefault("Name", _folder_name(path))
        out["ParentFolder"] = pf
    out["InternetMessageId"] = f"<{_g()}@{ORG_NAME}>"
    if "Attachments" in item:
        out["Attachments"] = item["Attachments"]
    return out


def admin_cmdlet(operation, actor, params, target_user=None, result="True",
                 external=False, offset_s=0):
    """RecordType 1 — Exchange admin cmdlet audit record.
    Exchange Admin schema (ManagedProperties/Parameters/ExternalAccess/OriginatingServer/
    OrganizationName/Token{ObjectId,TenantId}) — https://learn.microsoft.com/en-us/office/
    office-365-management-api/office-365-management-activity-api-schema#exchange-admin-schema
    ClientInfoString for management-tool cmdlets: "Client=WebServices;ExchangeWebServices"
    (documented example). AppPoolName/RequestId are NOT in the schema and were dropped."""
    r = _common(operation, actor, 1, result, offset_s)
    r.update({"UserType": 2, "ExternalAccess": external, "ClientIP": ac.egress(actor)["ip"],
              "ObjectId": _mbx_path(target_user or actor), "Parameters": params,
              "ClientInfoString": "Client=WebServices;ExchangeWebServices",
              "TokenObjectId": ac.user_oid(actor["username"]),
              "TokenTenantId": ORG_ID,
              "AppAccessContext": {"IssuedAtTime": _now(offset_s)}})
    if target_user:
        r["ModifiedObjectResolvedName"] = target_user["display_name"]
    return r


def _client_info(client):
    """Real ClientInfoString values (Exchange mailbox + admin audit records):
    - "Client=OWA;<browser UA>"            — doc example
    - "Client=REST;A3883EBA-FBE9-48BD-9ED3-DCA3E0E84250;;" — Outlook desktop REST client
    - "Client=REST;Client=RESTSystem;;"    — server-side/system REST access
    - "Client=ActiveSync;Apple-iPhone/1309.63" — doc example
    - "Client=WebServices;ExchangeWebServices" — doc example (EWS)
    https://learn.microsoft.com/en-us/purview/audit-log-exchange-properties
    ({Client=Out of Office | Client=Scheduled Processing} values relate to OOF/scheduled
    server workflows; not emitted by this schedule.)"""
    parts = {
        "OWA": f"Client=OWA;{_OWA_UA}",
        "REST": "Client=REST;A3883EBA-FBE9-48BD-9ED3-DCA3E0E84250;;",   # Outlook desktop REST
        "RESTSystem": "Client=REST;Client=RESTSystem;;",               # system/Graph REST
        "ActiveSync": "Client=ActiveSync;Apple-iPhone/1309.63",
        "EWS": "Client=WebServices;ExchangeWebServices",
    }
    return parts.get(client, parts["OWA"])


def mailbox_action(operation, owner, actor=None, logon_type=0, client="OWA",
                   item=None, extra=None, offset_s=0, result="Succeeded"):
    """RecordType 2 — mailbox action (owner or delegate access).
    Exchange Mailbox schema — LogonType/InternalLogonType share the enum (InternalLogonType
    mirrors LogonType in real records)."""
    actor = actor or owner
    r = _common(operation, actor, 2, result, offset_s)
    r.update({"UserType": 0, "ExternalAccess": False,   # True = out-of-tenant/delegated-admin logon
              "LogonType": logon_type, "InternalLogonType": logon_type,
              "MailboxOwnerUPN": owner["upn"], "MailboxOwnerSid": _sid(owner["username"]),
              "MailboxGuid": ac.user_oid("mbx:" + owner["username"]),
              "LogonUserSid": _sid(actor["username"]),
              "ClientIPAddress": ac.egress(actor)["ip"], "ClientIP": ac.egress(actor)["ip"],
              "ClientInfoString": _client_info(client),
              "AppId": "00000002-0000-0ff1-ce00-000000000000",
              "TokenTenantId": ORG_ID, "SessionId": _g()})
    if client == "OWA":
        r["ClientAppId"] = "d3590ed6-52b3-4102-aeff-aad2292ab01c"   # Office/OWA web client GUID
    if item is not None:
        r["Item"] = _item_shape(item)
    if extra:
        r.update(extra)
    return r


def mail_items_accessed(owner, count=1, offset_s=0, throttled=False):
    """RecordType 50 — MailItemsAccessed. throttled=True emits a sync-level access
    (MailAccessType=Sync, no per-item binds logged) — heavy mass-mailbox-access pattern."""
    r = _common("MailItemsAccessed", owner, 50, "Succeeded", offset_s)
    r.update({"UserType": 5, "ExternalAccess": False, "LogonType": 0, "InternalLogonType": 0,
              "MailboxOwnerUPN": owner["upn"], "MailboxOwnerSid": _sid(owner["username"]),
              "MailboxGuid": ac.user_oid("mbx:" + owner["username"]),
              "LogonUserSid": _sid(owner["username"]),
              "ClientIPAddress": ac.egress(owner)["ip"],
              "ClientInfoString": "Client=REST;Client=RESTSystem;;",
              "AppId": "00000003-0000-0000-c000-000000000000",  # Microsoft Graph app id
              "OperationCount": count, "TokenTenantId": ORG_ID})
    # Real RT50 records carry ClientAppId only as a known client-app GUID (or not at all);
    # a random app GUID is invalid, so it is omitted.
    if throttled:
        r["OperationProperties"] = [{"Name": "MailAccessType", "Value": "Sync"}]
    else:
        r["OperationProperties"] = [{"Name": "MailAccessType", "Value": "Bind"}]
        # ExchangeAggregatedFolder: Id mandatory, Path, FolderItems = ExchangeFolderItem
        r["Folders"] = [{"Id": _store_id("access-folder:" + owner["username"]),
                         "Path": "\\Inbox",
                         "FolderItems": [{"InternetMessageId": f"<{_g()}@{ORG_NAME}>"}
                                         for _ in range(count)]}]
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
    return mailbox_action(random.choice(["MoveToDeletedItems", "Move", "SoftDelete"]), u,
                          item={"Subject": ac.email_subject(), "ParentFolder": {"Path": "\\Inbox"}})


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
                        UserPrincipalName=tgt["upn"]), target_user=tgt)   # admin's own action, not ExternalAccess


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


_BENIGN = [(8, _b_mail_accessed), (7, _b_mailbox_op), (2, _b_benign_rule),
           (2, _b_login), (1, _b_new_mailbox), (1, _b_admin_benign)]
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
    """New-InboxRule that forwards mail to an external address -> 'Exchange inbox forwarding rule configured'."""
    u = ac.pick_user(config)
    ext = f"{u['username'].replace('.', '')}@{random.choice(_EXT_DOMAINS)}"
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
    """AddFolderPermissions granting the Default user access -> 'Exchange mailbox folder
    permission modification'. Permission info lives on the Folders (ExchangeFolder) complex —
    real schema: Id/Path/Name + MemberUpn/MemberSid/MemberRights; no FolderId/Permissions
    nested sub-objects in the Management Activity schema."""
    u = ac.pick_user(config)
    folder = {"Id": _store_id("folder:\\\\Inbox:" + u["username"]), "Path": "\\Inbox",
              "Name": "Inbox", "MemberUpn": "Default", "MemberSid": "S-1-1-0",
              "MemberRights": "ReadAny"}
    return [mailbox_action("ModifyFolderPermissions", u, extra={"Folders": [folder]},
                           result="Succeeded")]


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
                           extra={"DestFolder": {"Id": _store_id("destfolder:Deleted Items:"
                                                                + u["username"]),
                                                 "Path": "\\Deleted Items", "Name": "Deleted Items"}},
                           offset_s=-(i * 5))
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
        r["LogonType"] = 5      # BestAccess: client app acting on the mailbox, not the owner
        r["InternalLogonType"] = 5
        r["UserType"] = 0
        out.append(r)
    return out


def scenario_sensitive_mail_external(config=None):
    """Sensitive (AIP-labelled) mail sent to an external recipient -> 'Sensitive Exchange mail
    sent to external users'. Real schema: SensitivityLabel is a top-level property (label GUID
    assigned to the mail item — detailed-properties reference); recipientList is a Collection
    (EmailAddress) of {Address, Name}; recipientCount is Int64."""
    u = ac.pick_user(config)
    ext = f"{u['username'].replace('.', '')}@{random.choice(_EXT_DOMAINS)}"
    return [mailbox_action("Send", u, client="OWA",
                           item={"Subject": "Wire transfer instructions - CONFIDENTIAL",
                                 "ParentFolder": {"Path": "\\Sent Items"}},
                           extra={"recipientList": [{"Address": ext, "Name": ext}],
                                  "recipientCount": 1,
                                  "SensitivityLabel": ac.user_oid("label:confidential")})]


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


def scenario_compliance_search_purge_action(config=None):
    """New-ComplianceSearchAction with a Purge action on an existing search -> mass soft/
    hard-delete of mailbox content from within a compliance search (T1070.002 email
    anti-forensics). Mirrors scenario_compliance_search_created's record shape.
    Wording verified as an Exchange admin cmdlet: the admin audit log records changes made
    by running cmdlets in Exchange Online PowerShell — 'The audit log doesn't record cmdlets
    that begin with the verbs Get-, Search-, or Test-' (audit-log-activities, 'Exchange admin
    activities'). Original ComplianceSearchAction op: New-ComplianceSearchAction."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT", "Security"))
    search = f"Search-{random.randint(1000, 9999)}"
    return [admin_cmdlet("New-ComplianceSearchAction", admin,
                         _param(SearchName=search, Purge=random.choice(["SoftDelete", "HardDelete"]),
                                Confirm="False"))]


def scenario_mailbox_permission_removed(config=None):
    """Remove-MailboxPermission FullAccess from a victim -> 'removed delegate mailbox
    permissions'; an attacker who finished with a delegate path deletes the trail.
    Verified: 'Removed delegate mailbox permissions | Remove-MailboxPermission' in the
    Exchange mailbox activities table (audit-log-activities)."""
    attacker = ac.pick_user(config); victim = ac.pick_user(config)
    return [admin_cmdlet("Remove-MailboxPermission", attacker, _param(Identity=victim["upn"],
                          User=attacker["upn"], AccessRights="FullAccess"), target_user=victim)]


def scenario_inbox_rule_modified(config=None):
    """Set-InboxRule that adds external forwarding to an EXISTING rule -> 'modified inbox
    rule' variant of the classic forwarding-down detector. Verified: 'Modified inbox rule
    from Outlook web app | Set-InboxRule' in the Exchange mailbox activities table."""
    u = ac.pick_user(config)
    ext = f"{u['username'].replace('.', '')}@{random.choice(_EXT_DOMAINS)}"
    return [admin_cmdlet("Set-InboxRule", u, _param(Name="Invoices", ForwardTo=ext,
                          StopProcessingRules="True"), target_user=u)]


def scenario_transport_rule_disabled(config=None):
    """Existing transport (mail-flow) rule disabled or edited off by a delegate -> mail-flow
    protection removed. Real Exchange cmdlets (Disable-TransportRule / disabling via
    Set-TransportRule Enabled=False): cmdlet-run records per the Exchange admin audit rules
    noted in scenario_compliance_search_purge_action."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",))
    return [admin_cmdlet(random.choice(["Disable-TransportRule", "Set-TransportRule"]), admin,
                         _param(Identity=random.choice(["Junk Filter", "Vendor Domains Valid"]),
                                Enabled="False", ExceptIfFrom=ORG_NAME),
                         result="True")]


def scenario_recoverable_items_purge(config=None):
    """Purged messages from the mailbox (HardDelete — permanently removed from Recoverable
    Items) in a short burst from OWA -> anti-forensic permanent deletion.
    Verified: 'Purged messages from the mailbox | HardDelete' in the Exchange mailbox
    activities table (audit-log-activities)."""
    u = ac.pick_user(config)
    return [mailbox_action("HardDelete", u, client="OWA",
                           item={"Subject": random.choice(["Invoice overdue", "Wire transfer confirmation",
                                                           "Password reset instructions"]),
                                 "ParentFolder": {"Path": "\\Deleted Items"}},
                           offset_s=-i * 7)
            for i in range(random.randint(3, 6))]


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
    "compliance_search_purge_action": scenario_compliance_search_purge_action,
    "mailbox_permission_removed": scenario_mailbox_permission_removed,
    "inbox_rule_modified": scenario_inbox_rule_modified,
    "transport_rule_disabled": scenario_transport_rule_disabled,
    "recoverable_items_purge": scenario_recoverable_items_purge,
}


_GATE = ac.ThreatGate(SCENARIOS)


def get_threat_names():
    return list(SCENARIOS.keys())


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    if scenario_event:
        key = scenario_event if scenario_event in SCENARIOS else scenario_event.lower()
        if key in SCENARIOS:
            return (SCENARIOS[key](config), key)
        return None
    if benign_only or threat_level == "Benign Traffic Only":
        return generate_benign(config, context)
    if _GATE.fire(threat_level, config):
        key = random.choice(list(SCENARIOS))
        return (SCENARIOS[key](config), key)
    return generate_benign(config, context)
