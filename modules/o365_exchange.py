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
_THREAT_PROB = {"Benign Traffic Only": 0.0, "Low": 0.02, "Realistic": 0.05,
                "Medium": 0.08, "High": 0.12, "Insane": 0.30}


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


def _param(**kv):
    return [{"Name": k, "Value": v} for k, v in kv.items()]


def _common(operation, actor, record_type, result, offset_s=0):
    return {"CreationTime": _now(offset_s), "Id": _g(), "Operation": operation,
            "OrganizationId": ORG_ID, "RecordType": record_type, "ResultStatus": result,
            "UserKey": ac.user_oid(actor["username"]), "Version": 1, "Workload": "Exchange",
            "UserId": actor["upn"], "OrganizationName": ORG_NAME,
            "OriginatingServer": random.choice(_SERVERS)}


def admin_cmdlet(operation, actor, params, target_user=None, result="True",
                 external=False, offset_s=0):
    """RecordType 1 — Exchange admin cmdlet audit record."""
    r = _common(operation, actor, 1, result, offset_s)
    r.update({"UserType": 2, "ExternalAccess": external, "ClientIP": ac.egress(actor)["ip"],
              "ObjectId": _mbx_path(target_user or actor), "Parameters": params,
              "AppPoolName": "MSExchangePowerShellAppPool", "RequestId": _g(),
              "TokenTenantId": ORG_ID,
              "AppAccessContext": {"IssuedAtTime": _now(offset_s)}})
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


def mail_items_accessed(owner, count=1, offset_s=0):
    """RecordType 50 — MailItemsAccessed."""
    r = _common("MailItemsAccessed", owner, 50, "Succeeded", offset_s)
    r.update({"UserType": 5, "ExternalAccess": False, "LogonType": 0, "InternalLogonType": 0,
              "MailboxOwnerUPN": owner["upn"], "MailboxOwnerSid": _sid(owner["username"]),
              "MailboxGuid": ac.user_oid("mbx:" + owner["username"]),
              "LogonUserSid": _sid(owner["username"]),
              "ClientIPAddress": ac.egress(owner)["ip"],
              "ClientInfoString": "Client=REST;Client=RESTSystem;;",
              "AppId": "00000003-0000-0000-c000-000000000000", "ClientAppId": _g(),
              "OperationCount": count, "TokenTenantId": ORG_ID,
              "OperationProperties": [{"Name": "MailAccessType", "Value": "Bind"}],
              "Folders": [{"Path": "\\Inbox", "FolderItems": [{"InternetMessageId": f"<{_g()}@{ORG_NAME}>"}
                                                              for _ in range(count)]}]})
    return r


# ── benign baseline ─────────────────────────────────────────────────────────────────

def _b_mail_accessed(cfg):
    return mail_items_accessed(ac.pick_user(cfg), count=random.randint(1, 8))


def _b_send(cfg):
    return mailbox_action("Send", ac.pick_user(cfg), client="OWA")


def _b_move(cfg):
    u = ac.pick_user(cfg)
    return mailbox_action(random.choice(["MoveToDeletedItems", "Move", "SoftDelete"]), u,
                          item={"Subject": random.choice(["Re: Q3 numbers", "Lunch?", "Newsletter",
                                "Ticket update", "Meeting notes"]), "ParentFolder": {"Path": "\\Inbox"}})


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


_BENIGN = [(8, _b_mail_accessed), (4, _b_send), (4, _b_move), (2, _b_benign_rule),
           (2, _b_login), (1, _b_new_mailbox)]
_B_POOL = [fn for w, fn in _BENIGN for _ in range(w)]
_HUMAN = {_b_send, _b_move, _b_benign_rule, _b_login, _b_new_mailbox}


def generate_benign(config=None, context=None):
    fn = random.choice(_B_POOL)
    if fn in _HUMAN and random.random() > ac.activity_weight():
        fn = _b_mail_accessed   # off-hours: background mail sync still runs
    return [fn(config)]


# ── Exchange BEC detection scenarios ────────────────────────────────────────────────

def scenario_inbox_forwarding_rule(config=None):
    """New-InboxRule that forwards mail to an external address -> 'Exchange inbox forwarding rule configured'."""
    u = ac.pick_user(config)
    ext = f"{u['username'].replace('.', '')}@{random.choice(_EXT_DOMAINS)}"
    return [admin_cmdlet("New-InboxRule", u, _param(Name="Invoices", ForwardTo=ext,
                         StopProcessingRules="True"), target_user=u)]


def scenario_email_hiding_rule(config=None):
    """New-InboxRule that deletes/hides incoming mail -> 'Exchange email-hiding inbox rule'."""
    u = ac.pick_user(config)
    return [admin_cmdlet("New-InboxRule", u, _param(Name=".", MoveToFolder="Deleted Items",
                         MarkAsRead="True", DeleteMessage="True", StopProcessingRules="True"),
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


def scenario_audit_bypass(config=None):
    """Set-MailboxAuditBypassAssociation enabling audit bypass -> defense evasion (Exchange audit bypass)."""
    admin = ac.pick_by_role(config, ADMIN_ROLES, ("IT",)); tgt = ac.pick_user(config)
    return [admin_cmdlet("Set-MailboxAuditBypassAssociation", admin,
                         _param(Identity=tgt["upn"], AuditBypassEnabled="True"), target_user=tgt)]


SCENARIOS = {
    "inbox_forwarding_rule": scenario_inbox_forwarding_rule,
    "email_hiding_rule": scenario_email_hiding_rule,
    "mailbox_smtp_forwarding": scenario_mailbox_smtp_forwarding,
    "mailbox_delegation": scenario_mailbox_delegation,
    "send_as_permission": scenario_send_as_permission,
    "transport_forwarding_rule": scenario_transport_forwarding_rule,
    "folder_permission_mod": scenario_folder_permission_mod,
    "audit_bypass": scenario_audit_bypass,
}


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
    if random.random() < _THREAT_PROB.get(threat_level, 0.05):
        key = random.choice(list(SCENARIOS))
        return (SCENARIOS[key](config), key)
    return generate_benign(config, context)
