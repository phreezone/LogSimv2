# modules/mgmt_plane.py
# Shared management-plane identity for the firewall modules: who administers the
# devices, from where, which host backs their configuration up, which host polls them
# over SNMP, and the "logging suppressed" window a device is currently in.
#
# Every firewall module draws admin sessions from here so the BASELINE is one coherent
# operations team (same admins, same jump hosts, same backup and monitoring hosts on
# every vendor) and a THREAT stands out against it only by the property its detection
# pattern keys on: a source outside the admin subnet, an unusual command, a burst of
# config reads, an SNMP query from anything but the poller.
#
# Detection patterns these feed (gocortexio advisory corpus, MANAGEMENT locus):
#   device-admin-from-unexpected-source        admin login from outside admin_subnet
#   network-device-config-or-route-change      route / ACL / tunnel edits + write mem
#   network-device-logging-suppressed-for-a-window   no logging enable ... logging enable
#   scripted-device-config-harvesting          one source, many devices, show run / export
#   snmp-from-unexpected-source                UDP/161 to devices from a non-poller
#
# Overridable through config["management_plane"]; the defaults sit inside
# config["internal_networks"] so the hosts are ordinary internal endpoints.

import random
import time
from ipaddress import ip_address, ip_network

try:
    from modules.session_utils import rare_external_ip, rand_ip_from_network
except ImportError:
    from session_utils import rare_external_ip, rand_ip_from_network

_DEFAULTS = {
    # NOC / jump-host subnet: the only place device administration should come from.
    "admin_subnet":    "10.0.30.0/24",
    "jump_hosts":      ["10.0.30.30", "10.0.30.31"],
    # Named network-team accounts plus the config-backup service account.
    "admins":          ["netadmin.jlee", "netadmin.pkhan", "netadmin.rortiz", "fw_ops"],
    "backup_account":  "svc_netbackup",
    "backup_host":     "10.0.20.11",
    "snmp_pollers":    ["10.0.20.10"],
    "snmp_community":  "n0c-r3ad",
    # Infrastructure behind the firewall that the poller reads over SNMP.
    "network_devices": ["10.0.10.254", "10.1.255.254", "172.16.255.254", "192.168.10.1",
                        "10.0.20.1", "10.0.30.1", "192.168.1.1", "192.168.2.1"],
}


def conf(config):
    """config["management_plane"] merged over the defaults."""
    out = dict(_DEFAULTS)
    out.update((config or {}).get("management_plane", {}) or {})
    return out


def admin_user(config):
    return random.choice(conf(config)["admins"])


def admin_source(config):
    """A source inside the admin subnet: mostly a jump host, sometimes a NOC desk."""
    c = conf(config)
    if random.random() < 0.8:
        return random.choice(c["jump_hosts"])
    return rand_ip_from_network(ip_network(c["admin_subnet"], strict=False))


def in_admin_subnet(config, ip):
    try:
        return ip_address(ip) in ip_network(conf(config)["admin_subnet"], strict=False)
    except ValueError:
        return False


def backup(config):
    """(host, account) of the scheduled configuration-backup job."""
    c = conf(config)
    return c["backup_host"], c["backup_account"]


def snmp_poller(config):
    return random.choice(conf(config)["snmp_pollers"])


def network_devices(config):
    return list(conf(config)["network_devices"])


def unexpected_source(config, session_context=None):
    """(ip, label) for an admin session from OUTSIDE the admin subnet.

    External sources come from the shared rare pool (never the ambient pool, so they
    stay rare); internal ones are an ordinary user workstation, the shape of a
    compromised endpoint pivoting onto the device. These are management sessions,
    not VPN logins, so they do not feed the VPN new-country baseline.
    """
    if session_context and random.random() < 0.35:
        try:
            from modules.session_utils import get_random_user
        except ImportError:
            from session_utils import get_random_user
        ui = get_random_user(session_context, preferred_device_type="workstation")
        if ui and ui.get("ip") and not in_admin_subnet(config, ui["ip"]):
            return ui["ip"], "internal-non-admin"
    return rare_external_ip(), "external"


def sibling_hostnames(hostname, n):
    """Peer devices of one estate for multi-device patterns: ASA-FW-01 -> ASA-FW-02..."""
    head, _, tail = hostname.rpartition("-")
    if tail.isdigit():
        width = len(tail)
        return [f"{head}-{int(tail) + i:0{width}d}" for i in range(n)]
    return [hostname] + [f"{hostname}-{i:02d}" for i in range(2, n + 1)]


# ── Cisco CLI admin session (ASA and FTD share the message catalog) ─────────────────
# 113015 AAA reject (local db) / 113004 AAA success / 605005 login permitted /
# 111009 show-command / 111010 config command (carries the source IP) /
# 111008 write memory / 611103 logout. `prefix` is "ASA" or "FTD".

def cisco_cmd(prefix, user, src_ip, command):
    if command.startswith(("show ", "more ", "dir")):
        return f"%{prefix}-7-111009: User '{user}' executed cmd: {command}"
    return f"%{prefix}-5-111010: User '{user}', running 'CLI' from IP {src_ip}, executed '{command}'"


def is_private(ip):
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False


def cisco_admin_session(prefix, user, src_ip, commands, *, aaa_server, mgmt_ip, outside_ip,
                        proto="ssh", iface=None, start=None, aaa_failures=0, gap=(2, 25),
                        write_mem=False, logout=True):
    """[(datetime, message)] for one CLI session. Ends now unless `start` is given."""
    from datetime import datetime, timedelta, timezone
    if iface is None:
        iface = "management" if is_private(src_ip) else "outside"
    dev_ip = outside_ip if iface == "outside" else mgmt_ip
    t = start or datetime.now(timezone.utc) - timedelta(seconds=(len(commands) + 3) * gap[1])
    out = []

    def emit(msg, step):
        nonlocal t
        out.append((t, msg))
        t = t + timedelta(seconds=step)

    for _ in range(aaa_failures):
        emit(f"%{prefix}-6-113015: AAA user authentication Rejected : reason = Invalid password : "
             f"local database : user = {user} : user IP = {src_ip}", random.randint(2, 6))
    emit(f"%{prefix}-6-113004: AAA user authentication Successful : server = {aaa_server} : "
         f"user = {user}", 0)
    emit(f'%{prefix}-6-605005: Login permitted from {src_ip}/{random.randint(49152, 65535)} '
         f'to {iface}:{dev_ip}/{proto} for user "{user}"', random.randint(*gap))
    for cmd in commands:
        emit(cisco_cmd(prefix, user, src_ip, cmd), random.randint(*gap))
    if write_mem:
        emit(f"%{prefix}-5-111008: User '{user}' executed the 'write memory' command.",
             random.randint(1, 4))
    if logout:
        emit(f"%{prefix}-5-611103: User logged out: Uname: {user}", 0)
    return out


CISCO_SHOW_COMMANDS = [
    "show interface ip brief", "show conn count", "show vpn-sessiondb summary",
    "show failover", "show cpu usage", "show xlate count", "show route",
    "show access-list OUTSIDE_IN", "show logging", "show version",
]
# Routine change-window edits: objects, ACL remarks, NAT for a new server.
CISCO_ROUTINE_CHANGES = [
    ["object network OBJ-WEB-{n}", "host 10.0.10.{n}"],
    ["access-list INSIDE_OUT remark CHG{n} allow patch repo"],
    ["object-group network GRP-PATCH-SRV", "network-object host 10.0.20.{n}"],
    ["access-list OUTSIDE_IN extended permit tcp any object OBJ-WEB-{n} eq https"],
]
CISCO_HARVEST_COMMANDS = ["show running-config", "more system:running-config",
                          "show crypto ca certificates", "show running-config username"]


def cisco_route_change_commands(rogue):
    """Traffic redirection: a static route via an attacker next hop, a permit-any ACE
    for it and a packet capture toward it."""
    return ["show route", "show running-config route",
            f"route outside 10.0.10.0 255.255.255.0 {rogue} 1",
            f"access-list OUTSIDE_IN extended permit ip host {rogue} any",
            f"capture CAP1 interface inside match ip any host {rogue}"]


# ── scheduled config backup ──────────────────────────────────────────────────────────
# The backup job runs once per UTC day at 02:00, not on a weighted draw: its value as a
# baseline is that it is REGULAR (same host, same account, same time every day).
_BACKUP_HOUR_UTC = 2
_last_backup_day = {}   # module key -> UTC day number


def backup_due(key, now=None):
    """True once per UTC day, on the first call at or after 02:00 UTC."""
    now = now or time.time()
    day, hour = int(now // 86400), int(now % 86400 // 3600)
    if hour >= _BACKUP_HOUR_UTC and _last_backup_day.get(key) != day:
        _last_backup_day[key] = day
        return True
    return False


# ── logging-suppressed window ────────────────────────────────────────────────────────
# An attacker disables the device's logging, works, then re-enables it. The detection
# is the GAP, so while a window is open the owning module emits nothing at all; the
# re-enable is emitted by the first generate_log call after the window closes.
_suppressed = {}   # module key -> {"until", "user", "src", "since"}


def open_suppression(key, seconds, user, src, now=None):
    now = now or time.time()
    _suppressed[key] = {"until": now + seconds, "since": now, "user": user, "src": src}


def suppression_state(key, now=None):
    """'active' while the window is open, the state dict once it has expired (the
    caller emits the re-enable and the window is cleared), else None."""
    st = _suppressed.get(key)
    if not st:
        return None
    if (now or time.time()) < st["until"]:
        return "active"
    return _suppressed.pop(key)


def suppression_window_seconds():
    """10-40 minutes: long enough to stand out against a device that reports every
    few seconds, short enough to look like a hands-on-keyboard session."""
    return random.randint(600, 2400)
