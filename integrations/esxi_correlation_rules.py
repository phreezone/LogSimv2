"""Build the VMware ESXi correlation rules (one per modules/vmware_esxi.py threat).

    python integrations/esxi_correlation_rules.py            # write XSIAM imports/esxi_*.json + bundle
    python integrations/esxi_correlation_rules.py --check [--minutes N]   # run each rule's query on tenant data
    python integrations/esxi_correlation_rules.py --apply    # create missing rules, update ones whose description changed

XSIAM ships only the two uncommon-command rarity analytics for ESXi syslog, so every other
threat in the module needs a custom rule. The rules read vmware_esxi_raw directly: the
content pack's parsing rule leaves only hostname/process/msg, and its modeling rule puts
the host and user in different XDM fields depending on the event, so each rule extracts
its own fields from _raw_log. Every rule ends in the same column set, so every rule maps
the same alert fields (_ALERT_FIELDS).
"""

import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_IMPORTS = os.path.join(_ROOT, "XSIAM imports")
_PREFIX = "VMware ESXi — "

_PRIVATE = ('incidr({f}, "10.0.0.0/8") or incidr({f}, "172.16.0.0/12") or '
            'incidr({f}, "192.168.0.0/16") or incidr({f}, "127.0.0.0/8")')


def _public(field):
    return f"{field} != null and not ({_PRIVATE.format(f=field)})"


# Fields every rule extracts. The country lookup only matters for public sources, so
# geo_ip is the source IP when it is public and a 0.0.0.0 placeholder otherwise (iploc
# drops rows whose IP is null, so the placeholder also keeps events with no source). Rules override the per-rule columns (event_action,
# target_account, command_or_path, target_object, external_target) in their own alter.
_COMMON = r'''| alter esxi_host = arrayindex(regextract(_raw_log, "^<\d+>\S+\s+(\S+)\s"), 0),
        process_name = lowercase(arrayindex(regextract(_raw_log, "^<\d+>\S+\s+\S+\s+([A-Za-z_-]+)"), 0)),
        process_id = arrayindex(regextract(_raw_log, "^<\d+>\S+\s+\S+\s+[^\[]*?\[(\d+)\]"), 0),
        event_id = arrayindex(regextract(_raw_log, "Event (\d+) :"), 0),
        host_ip = _final_reporting_device_ip,
        message = arrayindex(regextract(_raw_log, "^<\d+>\S+\s+\S+\s+(.*)$"), 0)
| alter actor_user = coalesce(
            arrayindex(regextract(_raw_log, "\suser=([^\s\]]+)"), 0),
            arrayindex(regextract(_raw_log, "shell\[\d+\]: \[([^\]]+)\]: "), 0),
            arrayindex(regextract(_raw_log, " by ([^\s@]+)@\d"), 0),
            arrayindex(regextract(_raw_log, "Accepted \S+ for (?:user )?(\S+) from"), 0),
            arrayindex(regextract(_raw_log, "USER (\S+) pid \d+ cmd"), 0)),
        src_ip = coalesce(
            arrayindex(regextract(_raw_log, "@(\d+\.\d+\.\d+\.\d+)"), 0),
            arrayindex(regextract(_raw_log, "from (\d+\.\d+\.\d+\.\d+)"), 0),
            arrayindex(regextract(_raw_log, "rhost=(\d+\.\d+\.\d+\.\d+)"), 0),
            arrayindex(regextract(_raw_log, "envoy-access\[\d+\]: .*? (\d+\.\d+\.\d+\.\d+):\d+ HTTP/"), 0)),
        src_port = coalesce(
            arrayindex(regextract(_raw_log, "from \S+ port (\d+)"), 0),
            arrayindex(regextract(_raw_log, "envoy-access\[\d+\]: .*? \d+\.\d+\.\d+\.\d+:(\d+) HTTP/"), 0))
| alter app_protocol = if(process_name = "sshd-session", "ssh",
                       if(process_name in ("hostd", "envoy-access"), "https",
                       if(process_name = "shell", "esxi-shell", null))),
        host_service_port = if(process_name = "sshd-session", "22",
                            if(process_name in ("hostd", "envoy-access"), "443", null)),
        event_action = null, target_account = null, command_or_path = null,
        target_object = null, external_target = null
| alter geo_ip = if(''' + _public("src_ip") + ''', src_ip, "0.0.0.0")
| iploc geo_ip loc_country as src_country
'''

_COMP = '''| bin _time span = {span}
| comp count() as event_count,
       values(actor_user) as actor_users,
       values(src_ip) as src_ips,
       values(src_country) as src_countries,
       values(src_port) as src_ports,
       values(process_name) as process_names,
       values(process_id) as process_ids,
       values(event_id) as event_ids,
       values(event_action) as event_actions,
       values(target_account) as target_accounts,
       values(command_or_path) as commands_paths,
       values(target_object) as target_objects,
       values(external_target) as external_targets,
       values(app_protocol) as app_protocols,
       values(host_service_port) as host_service_ports,
       values(message) as events_seen{extra}
       by esxi_host, host_ip, _time{by}
'''

_FIELDS = ("| fields esxi_host, host_ip, actor_users, src_ips, src_countries, src_ports, "
           "host_service_ports, process_names, process_ids, event_ids, event_actions, "
           "target_accounts, commands_paths, target_objects, external_targets, app_protocols, "
           "events_seen, event_count\n")

# Alert field -> output column. Identical for every rule, so each alert carries the host,
# actor, source, process, event, target and evidence fields the module populates.
_ALERT_FIELDS = {
    "agent_hostname": "esxi_host",
    "action_local_ip": "host_ip",
    "action_local_port": "host_service_ports",
    "actor_effective_username": "actor_users",
    "action_remote_ip": "src_ips",
    "action_remote_port": "src_ports",
    "src_geo_country_name": "src_countries",
    "actor_process_image_name": "process_names",
    "processid": "process_ids",
    "eventid": "event_ids",
    "eventaction": "event_actions",
    "usersdetails": "target_accounts",
    "applicationpath": "commands_paths",
    "action_file_name": "target_objects",
    "action_external_hostname": "external_targets",
    "action_app_protocol": "app_protocols",
    "action_evtlog_message": "events_seen",
}

# ESXi 8 interactive shell command:  shell[pid]: [root]: esxcli system account list
_SHELL = r'_raw_log ~= "shell\[\d+\]: \[[^\]]+\]: "'
_CMD = r'arrayindex(regextract(_raw_log, "shell\[\d+\]: \[[^\]]+\]: (.+)$"), 0)'

# event, title, category, tactic, technique, span, filter, alter, extra comp, by, threshold,
# what fired, why it matters
RULES = [
    dict(
        event="uncommon_host_command",
        title="Ransomware-Precursor Command Run in Host Shell",
        category="EXECUTION", tactic="TA0002 - Execution",
        techniques=["T1059.012 - Command and Scripting Interpreter: Hypervisor CLI",
                    "T1675 - ESXi Administration Command"],
        filter=_SHELL + r''' and _raw_log ~= "\]: .*(system account (add|remove|set)|system permission (set|unset)|network firewall (set --enabled false|unload)|hostsvc/lockdown_disable|syslog config set --loghost=''|auditrecords (remote|local) disable|acceptance set --level CommunitySupported|--no-sig-check|encryption set --require|coredump file set --unconfigure|maintenanceMode set -e true|python -c|wget http|curl http|dd if=/dev/zero of=/vmfs|/tmp/\.|authorized_keys|crontabs/root|vib remove)"''',
        alter=f'''| alter command_or_path = {_CMD},
        event_action = "shell command",
        external_target = arrayindex(regextract(_raw_log, "https?://([^/\\s']+)"), 0)''',
        threshold="event_count >= 1", span="1h",
        what="An ESXi host shell ran a command from the ESXi-ransomware playbook: local "
             "account or permission changes, firewall or lockdown disable, audit/syslog "
             "disable, unsigned VIB install, secure-boot/encryption downgrade, downloaded "
             "tooling, SSH-key or cron implants.",
        why="These commands are almost never part of routine host administration and are "
            "the staging steps seen before ESXi ransomware encrypts datastores.",
    ),
    dict(
        event="ssh_brute_force",
        title="SSH Brute Force Against Host",
        category="CREDENTIAL_ACCESS", tactic="TA0006 - Credential Access",
        techniques=["T1110.001 - Brute Force: Password Guessing"],
        filter=r'_raw_log ~= "sshd-session\[\d+\]: (error: PAM: Authentication failure for|Invalid user|Accepted \S+ for)"',
        alter=r'''| alter target_account = arrayindex(regextract(_raw_log, "(?:Authentication failure for (?:illegal user )?|Invalid user |Accepted \S+ for )(\S+) from"), 0),
        event_action = if(_raw_log contains "Accepted ", "ssh login succeeded",
                       if(_raw_log contains "Invalid user", "ssh unknown user", "ssh login failed")),
        failed = if(_raw_log contains "Authentication failure", 1, 0),
        succeeded = if(_raw_log ~= "Accepted \S+ for", 1, 0)''',
        # Benign console/stale-credential failures come from loopback and the admin LAN.
        post_filter=_public("src_ip"),
        extra=",\n       sum(failed) as failures, sum(succeeded) as successes",
        by=", src_ip", threshold="failures >= 10", span="1h",
        what="One source made 10 or more failed SSH logins against the host within an hour "
             "(the alert's event actions show whether a login then succeeded).",
        why="SSH password guessing against root is the most common initial access to ESXi "
            "before ransomware deployment.",
    ),
    dict(
        event="vuln_scan",
        title="External Scan of Host Management Services",
        category="RECONNAISSANCE", tactic="TA0043 - Reconnaissance",
        techniques=["T1595.002 - Active Scanning: Vulnerability Scanning"],
        filter=r'_raw_log ~= "(envoy-access\[\d+\]: |Did not receive identification string|\[preauth\]|Unable to negotiate with|banner exchange|Cannot login \S+@\d|Invalid user \S+ from|Authentication failure for)"',
        alter=r'''| alter event_action = if(_raw_log contains "envoy-access", "http endpoint probe",
                       if(_raw_log contains "Cannot login", "api login probe",
                       if(_raw_log ~= "Invalid user|Authentication failure", "ssh login probe", "ssh preauth probe"))),
        target_object = arrayindex(regextract(_raw_log, "envoy-access\[\d+\]: \S+ (\S+) \d{3} "), 0),
        target_account = arrayindex(regextract(_raw_log, "(?:Cannot login |Invalid user |Authentication failure for (?:illegal user )?)([^@\s]+)"), 0)''',
        post_filter=_public("src_ip"),
        extra=",\n       count_distinct(event_action) as probe_types",
        by=", src_ip", threshold="event_count >= 10 and probe_types >= 3", span="1h",
        what="One external address probed three or more of the host's management services "
             "(HTTPS/envoy endpoints, SSH pre-auth, SSH logins, SOAP API logins) at least 10 "
             "times in an hour.",
        why="Scanning the ESXi management plane from the internet precedes exploitation of "
            "exposed hypervisors (OpenSLP, hostd/vCenter CVEs, default credentials).",
    ),
    dict(
        event="root_login_rare_source",
        title="Root Login From External Address",
        category="INFILTRATION", tactic="TA0001 - Initial Access",
        techniques=["T1078.003 - Valid Accounts: Local Accounts"],
        filter=r'_raw_log ~= "(Accepted \S+ for (user )?root from|User root@\S+ logged in as)"',
        alter='''| alter event_action = "root login", target_account = "root"''',
        post_filter=_public("src_ip"),
        by=", src_ip", threshold="event_count >= 1", span="1h",
        what="The host accepted a root login from a public (non-RFC1918) address.",
        why="ESXi management should only be reachable from the admin network; a root login "
            "from the internet means exposed management and likely stolen credentials.",
    ),
    dict(
        event="ssh_service_enabled",
        title="SSH Enabled Then Used From External Address",
        category="LATERAL_MOVEMENT", tactic="TA0008 - Lateral Movement",
        techniques=["T1021.004 - Remote Services: SSH"],
        # Admins toggle SSH routinely from the admin network, so an enable alone is not
        # the signal: the rule needs SSH (or the ESXi Shell) switched on AND an SSH
        # session opened from a public address on the same host in the same hour.
        filter=r'_raw_log ~= "((SSH|ESXi Shell) for the host \S+ has been enabled|SSH session was opened for|sshd-session\[\d+\]: Accepted \S+ for)"',
        alter=r'''| alter event_action = if(_raw_log contains "has been enabled", "ssh/shell enabled", "ssh session opened"),
        target_account = arrayindex(regextract(_raw_log, "(?:SSH session was opened for '|Accepted \S+ for )([^@'\s]+)"), 0),
        enabled = if(_raw_log contains "has been enabled", 1, 0)''',
        post_filter="enabled = 1 or (" + _public("src_ip") + ")",
        extra=",\n       sum(enabled) as enables, sum(if(enabled = 0, 1, 0)) as external_sessions",
        threshold="enables >= 1 and external_sessions >= 1", span="1h",
        what="SSH or the ESXi Shell was switched on for the host and an SSH session was opened "
             "from a public address within the same hour.",
        why="Opening SSH and then logging in from the internet is a near-universal step in "
            "ESXi ransomware intrusions; routine maintenance enables SSH from the admin "
            "network only.",
    ),
    dict(
        event="local_account_created",
        title="Local Account Created and Granted Admin",
        category="PERSISTENCE", tactic="TA0003 - Persistence",
        techniques=["T1136.001 - Create Account: Local Account",
                    "T1098 - Account Manipulation"],
        filter=r'_raw_log ~= "(Account \S+ was created on host|Permission created for \S+ on root, role is Administrator)"',
        alter=r'''| alter target_account = coalesce(arrayindex(regextract(_raw_log, "Account (\S+) was created on host"), 0),
                                 arrayindex(regextract(_raw_log, "Permission created for (\S+) on root"), 0)),
        event_action = if(_raw_log contains "role is Administrator", "admin role granted", "account created"),
        created = if(_raw_log contains "was created on host", 1, 0),
        admin = if(_raw_log contains "role is Administrator", 1, 0)''',
        extra=",\n       sum(created) as creations, sum(admin) as admin_grants",
        # Same actor for both steps: benign onboarding creates accounts and grants Admin
        # separately, often by different people.
        by=", target_account, actor_user", threshold="creations >= 1 and admin_grants >= 1", span="1h",
        what="One user created a new local account on the host and gave it the Admin role "
             "within the same hour.",
        why="A fresh local admin is a classic ESXi persistence foothold that survives "
            "password resets of the existing accounts.",
    ),
    dict(
        event="mass_vm_power_off",
        title="Mass VM Power-Off on Host",
        category="TAMPERING", tactic="TA0040 - Impact",
        techniques=["T1529 - System Shutdown/Reboot",
                    "T1490 - Inhibit System Recovery"],
        # ESXi 8: the operator's tag is on '<vm> on  <host> in ha-datacenter is stopping';
        # the 'is powered off' that follows is system-logged with no user.
        filter=r'_raw_log ~= "(in ha-datacenter is stopping|VirtualMachine\.removeAllSnapshots)" and _raw_log contains " user="',
        alter=r'''| alter target_object = coalesce(arrayindex(regextract(_raw_log, "Event \d+ : (.+?) on\s+\S+ in ha-datacenter is stopping"), 0),
                                arrayindex(regextract(_raw_log, "(haTask-\S+removeAllSnapshots\S*)"), 0)),
        event_action = if(_raw_log contains "is stopping", "vm powered off", "all snapshots removed")
| alter powered_vm = if(event_action = "vm powered off", target_object, null)''',
        # vCenter-driven operations arrive as vpxuser (DRS, scheduled tasks); the person
        # behind them is only visible in vCenter, so this rule watches host-level users.
        post_filter='actor_user != "vpxuser"',
        extra=",\n       count_distinct(powered_vm) as vms_powered_off",
        by=", actor_user", threshold="vms_powered_off >= 3", span="1h",
        what="One user powered off three or more VMs on one host within an hour, often with "
             "all their snapshots removed.",
        why="ESXi ransomware powers VMs off and deletes snapshots so the VMDKs can be "
            "encrypted and cannot be rolled back.",
    ),
    dict(
        event="remote_syslog_disabled",
        title="Remote Syslog Forwarding Disabled",
        category="EVASION", tactic="TA0005 - Defense Evasion",
        techniques=["T1562.006 - Impair Defenses: Indicator Blocking"],
        filter=r'''_raw_log ~= "(Syslog\.global\.logHost., value ..\s*$|syslog config set --loghost=(''|..)\s*$)"''',
        alter='''| alter event_action = "remote syslog disabled", target_object = "Syslog.global.logHost"''',
        threshold="event_count >= 1", span="1h",
        what="Syslog.global.logHost was set to empty, so the host stopped forwarding logs.",
        why="Cutting log forwarding blinds the SIEM to everything the attacker does next on "
            "the host.",
    ),
    dict(
        event="vm_disk_export",
        title="VM Disk Downloaded Outside the Backup Proxy",
        category="COLLECTION", tactic="TA0009 - Collection",
        techniques=["T1005 - Data from Local System"],
        # ESXi 8: the download event names the client ('<agent>@<ip>'), the /folder GET
        # that precedes it names the user.
        filter=r'_raw_log ~= "(File download from path|Got HTTP GET request for /folder/)"',
        alter=r'''| alter command_or_path = coalesce(arrayindex(regextract(_raw_log, "File download from path '([^']+)'"), 0),
                                   arrayindex(regextract(_raw_log, "request for /folder/([^?\s]+)"), 0)),
        target_object = arrayindex(regextract(_raw_log, "(?:File download from path '[^']*/|request for /folder/(?:[^?\s]*/)?)([^/?'\s]+)"), 0),
        event_action = if(_raw_log contains "File download", "datastore file download", "datastore GET")''',
        post_filter='not (src_ip = "10.0.20.15" or actor_user = "svc_vmbackup")',
        extra=",\n       sum(if(event_action = \"datastore file download\", 1, 0)) as downloads",
        threshold="downloads >= 1", span="1h",
        what="VM disk or config files were downloaded off a datastore by someone other than "
             "the backup proxy (svc_vmbackup from 10.0.20.15).",
        why="Pulling -flat.vmdk files through the datastore browser steals whole servers "
            "(domain controllers, databases) for offline credential and data extraction.",
    ),
    dict(
        event="guest_ops_exec",
        title="Guest Operations API Used to Run Code in VMs",
        category="EXECUTION", tactic="TA0002 - Execution",
        techniques=["T1675 - ESXi Administration Command"],
        filter=r'_raw_log ~= "Guest operation (StartProgramInGuest|InitiateFileTransferToGuest|ListProcessesInGuest)"',
        alter=r'''| alter event_action = arrayindex(regextract(_raw_log, "Guest operation (\w+)"), 0),
        command_or_path = coalesce(arrayindex(regextract(_raw_log, "program='([^']+)'"), 0),
                                   arrayindex(regextract(_raw_log, "path='([^']+)'"), 0)),
        target_object = arrayindex(regextract(_raw_log, "on vm=(\S+)"), 0),
        target_account = arrayindex(regextract(_raw_log, "guestAuth=(\S+)"), 0),
        external_target = arrayindex(regextract(_raw_log, "https?://([^/\s']+)"), 0)''',
        by=", actor_user", threshold="event_count >= 1", span="1h",
        what="The vSphere Guest Operations (VIX) API was used to start programs, push files, "
             "or list processes inside guest VMs from the host.",
        why="Guest operations run code in a VM without touching its network, a "
            "hypervisor-to-guest lateral movement path that bypasses guest EDR network "
            "visibility.",
    ),
    dict(
        event="datastore_upload",
        title="Suspicious File Uploaded to Datastore",
        category="INFILTRATION", tactic="TA0011 - Command and Control",
        techniques=["T1105 - Ingress Tool Transfer"],
        filter=r'_raw_log ~= "(File upload to path|Got HTTP PUT request for /folder/)"',
        alter=r'''| alter command_or_path = coalesce(arrayindex(regextract(_raw_log, "File upload to path '([^']+)'"), 0),
                                   arrayindex(regextract(_raw_log, "request for /folder/([^?\s]+)"), 0)),
        target_object = arrayindex(regextract(_raw_log, "(?:File upload to path '[^']*/|request for /folder/(?:[^?\s]*/)?)([^/?'\s]+)"), 0),
        event_action = if(_raw_log contains "File upload", "datastore file upload", "datastore PUT")''',
        # The vCenter service account loading ISOs / templates into the library is routine.
        post_filter=r'not (actor_user = "svc_vcenter" and command_or_path ~= "^ISO/[^/]+\.(iso|ovf)$")',
        extra=",\n       sum(if(event_action = \"datastore PUT\", 1, 0)) as uploads",
        by=", actor_user", threshold="uploads >= 1", span="1h",
        what="A file was uploaded to a datastore by an account other than the vCenter "
             "service, or outside the ISO library.",
        why="Datastores are shared by every host in the cluster, so staging scripts, "
            "binaries, or boot images there spreads tooling to every hypervisor.",
    ),
    dict(
        event="vm_disk_attach",
        title="Another VM's Disk Attached to a VM",
        category="COLLECTION", tactic="TA0009 - Collection",
        techniques=["T1006 - Direct Volume Access"],
        filter='_raw_log contains "added existing disk"',
        alter=r'''| alter target_object = arrayindex(regextract(_raw_log, "Reconfigured (\S+) on"), 0),
        command_or_path = arrayindex(regextract(_raw_log, "added existing disk (\S+)"), 0),
        disk_vm = arrayindex(regextract(_raw_log, "added existing disk /vmfs/volumes/[^/]+/([^/]+)/"), 0),
        event_action = "existing disk attached"''',
        post_filter="disk_vm != null and disk_vm != target_object",
        threshold="event_count >= 1", span="1h",
        what="A VM was reconfigured to mount a virtual disk that belongs to a different VM.",
        why="Mounting a domain controller or database disk on a scratch VM reads it raw, "
            "bypassing the guest OS and its controls (e.g. NTDS.dit theft).",
    ),
    dict(
        event="kernel_module_load",
        title="Unsigned Kernel Module Loaded",
        category="PERSISTENCE", tactic="TA0003 - Persistence",
        techniques=["T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions"],
        filter=r'_raw_log ~= "(esxcli system module load|not in VMware signed set)"',
        alter=r'''| alter target_object = coalesce(arrayindex(regextract(_raw_log, "module load -m (\S+)"), 0),
                                arrayindex(regextract(_raw_log, "Loaded module (\S+) from"), 0)),
        command_or_path = coalesce(arrayindex(regextract(_raw_log, "Loaded module \S+ from (\S+)"), 0),
                                   ''' + _CMD + r'''),
        event_action = if(_raw_log contains "not in VMware signed set", "unsigned module loaded", "module load command")''',
        threshold="event_count >= 1", span="1h",
        what="A kernel module was loaded on the host by hand, or vmkernel reported a module "
             "outside the VMware signed set.",
        why="Malicious VMkernel modules and VIBs (VIRTUALPITA/VIRTUALPIE) give persistent, "
            "hard-to-see backdoors on the hypervisor.",
    ),
    dict(
        event="promiscuous_mode",
        title="Port Group Security Policy Opened",
        category="CREDENTIAL_ACCESS", tactic="TA0006 - Credential Access",
        techniques=["T1040 - Network Sniffing"],
        # ESXi 8 logs no event for a port-group policy change; the esxcli command is the record.
        filter=_SHELL + r''' and _raw_log ~= "portgroup policy security set .*--allow-(promiscuous|forged-transmits|mac-change)=(true|1|yes)"''',
        alter=r'''| alter target_object = arrayindex(regextract(_raw_log, "-p .([^\x22]+)."), 0),
        command_or_path = ''' + _CMD + r''',
        event_action = arrayindex(regextract(_raw_log, "--(allow-[a-z-]+)=(?:true|1|yes)"), 0)''',
        threshold="event_count >= 1", span="1h",
        what="A port group's promiscuous mode, forged transmits, or MAC address changes "
             "policy was set to allow from the host shell.",
        why="Allowing promiscuous mode lets any VM on the port group sniff all traffic on "
            "it; forged transmits allow spoofing. Hardened hosts keep all three off.",
    ),
    dict(
        event="unplanned_reboot",
        title="Host Shut Down Outside Maintenance Mode",
        category="TAMPERING", tactic="TA0040 - Impact",
        techniques=["T1529 - System Shutdown/Reboot"],
        filter=r'_raw_log ~= "(being shut down by .*not in maintenance mode|running VMs were not cleanly powered off)"',
        alter=r'''| alter event_action = if(_raw_log contains "not cleanly", "vms not cleanly powered off", "host shutdown outside maintenance"),
        target_object = arrayindex(regextract(_raw_log, "(\d+) running VMs"), 0)''',
        threshold="event_count >= 1", span="1h",
        what="The host was shut down or rebooted while not in maintenance mode, with VMs "
             "still running.",
        why="Planned reboots happen inside maintenance mode with VMs evacuated; a hard "
            "shutdown with running VMs is destructive and can mask or finish an attack.",
    ),
    dict(
        event="snmp_external_target",
        title="SNMP Trap Target Set to External Address",
        category="EXFILTRATION", tactic="TA0010 - Exfiltration",
        techniques=["T1048 - Exfiltration Over Alternative Protocol"],
        filter=r'_raw_log ~= "(esxcli system snmp set .*-t |SNMP agent enabled with trap target)"',
        alter=r'''| alter external_target = coalesce(arrayindex(regextract(_raw_log, "-t (\d+\.\d+\.\d+\.\d+)@"), 0),
                                  arrayindex(regextract(_raw_log, "trap target (\d+\.\d+\.\d+\.\d+)"), 0)),
        command_or_path = ''' + _CMD + r''',
        event_action = "snmp trap target set"''',
        post_filter=_public("external_target"),
        threshold="event_count >= 1", span="1h",
        what="The host's SNMP agent was enabled with a trap target on a public address.",
        why="SNMP traps to the internet leak host inventory and state, and a public "
            "community string exposes the agent to outside queries.",
    ),
    dict(
        event="log_rotation_disabled",
        title="Host Log Rotation or Log Directory Tampered",
        category="EVASION", tactic="TA0005 - Defense Evasion",
        techniques=["T1562.006 - Impair Defenses: Indicator Blocking",
                    "T1070 - Indicator Removal"],
        filter=r'_raw_log ~= "(syslog config logger set .*--rotate 0|syslog config set .*--logdir=/tmp|Syslog\.global\.logDir., value ./tmp)"',
        alter=r'''| alter command_or_path = coalesce(''' + _CMD + r''',
                                   arrayindex(regextract(_raw_log, "(Syslog\.global\.logDir\S*, value \S+)"), 0)),
        event_action = if(_raw_log ~= "logDir|logdir", "log directory moved to tmp",
                       if(_raw_log contains "--rotate 0", "log rotation disabled", "syslog config changed"))''',
        threshold="event_count >= 1", span="1h",
        what="Host log rotation was set to size 0 / rotate 0, or the log directory was moved "
             "to /tmp.",
        why="On ESXi /tmp is a ramdisk wiped at reboot; together with disabled rotation the "
            "host's local log evidence is lost.",
    ),
    dict(
        event="config_harvest",
        title="Burst of Host Configuration Discovery Commands",
        category="DISCOVERY", tactic="TA0007 - Discovery",
        techniques=["T1082 - System Information Discovery",
                    "T1087.001 - Account Discovery: Local Account"],
        filter=_SHELL + r''' and _raw_log ~= "\]: (esxcli system settings advanced list|esxcli network firewall ruleset list|esxcli system account list|esxcli system permission list|vim-cmd vmsvc/getallvms|esxcli storage filesystem list|esxcli network ip interface list|esxcli system snmp get|vim-cmd hostsvc/hostsummary|esxcli software vib list)\s*$"''',
        alter=f'''| alter command_or_path = {_CMD}, event_action = "discovery command"''',
        extra=",\n       count_distinct(command_or_path) as distinct_commands",
        threshold="distinct_commands >= 6", span="10m",
        what="Six or more different host configuration discovery commands (accounts, "
             "permissions, firewall, network, storage, SNMP, VIBs) ran within 10 minutes.",
        why="Scripted harvesting of the whole host configuration is reconnaissance before "
            "privilege abuse or encryption; monitoring runs only a few of these.",
    ),
    dict(
        event="permission_denied_burst",
        title="Repeated Permission Denied for One User",
        category="DISCOVERY", tactic="TA0007 - Discovery",
        techniques=["T1069.001 - Permission Groups Discovery: Local Groups"],
        filter='_raw_log contains "Permission to perform this operation was denied for user"',
        alter=r'''| alter actor_user = arrayindex(regextract(_raw_log, "denied for user ([^@\s]+)@"), 0),
        target_object = arrayindex(regextract(_raw_log, "denied for user \S+ on (\S+)"), 0),
        event_action = "permission denied"''',
        by=", actor_user", threshold="event_count >= 5", span="1h",
        what="One user was denied permission five or more times within an hour across host "
             "management operations.",
        why="A burst of denials means an account is probing what it is allowed to do, "
            "typical of a stolen low-privilege credential.",
    ),
]


def _query(r):
    q = f"dataset = vmware_esxi_raw\n| filter {r['filter']}\n" + _COMMON + r["alter"] + "\n"
    if r.get("post_filter"):
        q += f"| filter {r['post_filter']}\n"
    q += _COMP.format(span=r["span"], extra=r.get("extra", ""), by=r.get("by", ""))
    # Grouping keys beyond esxi_host are suppression fields. A suppression field missing
    # from the output fails every run on the tenant ("suppression fields references field
    # that no longer exists" / "server error while generating the alert").
    keys = "".join(f", {k}" for k in _key(r)[1:])
    q += f"| filter {r['threshold']}\n" + _FIELDS.replace("| fields esxi_host,", f"| fields esxi_host{keys},", 1)
    return q


def _key(r):
    return ["esxi_host"] + [b.strip() for b in r.get("by", "").split(",") if b.strip()]


def build(r):
    name = _PREFIX + r["title"]
    key = _key(r)
    mitre = "; ".join(r["techniques"])
    return {
        "name": name,
        "severity": "SEV_020_LOW",
        "xql_query": _query(r),
        "is_enabled": True,
        "description": r["what"],
        "alert_name": f"{name} on $esxi_host",
        "alert_category": r["category"],
        "alert_type": None,
        "alert_description": (
            f"What fired: {r['what']}\n\n"
            f"Why it matters: {r['why']} Assessed severity: Low.\n\n"
            f"MITRE ATT&CK: {mitre} ({r['tactic']}).\n\n"
            "Investigate:\n"
            "  - Read events_seen for the exact host log lines and the acting user / source.\n"
            "  - Confirm with the ESXi owner whether the change or access was planned "
            "(change ticket, maintenance window).\n"
            f"  - Pivot on the alert's key ({', '.join(key)}) and the source IP to firewall, "
            "VPN, and identity activity in the same window.\n"
            "  - Check the same host for other ESXi alerts (shell enabled, uncommon commands, "
            "syslog changes, VM power-offs) that would make this part of a ransomware chain."
        ),
        "alert_domain": "DOMAIN_SECURITY",
        "alert_fields": dict(_ALERT_FIELDS),
        "execution_mode": "SCHEDULED",
        "search_window": "1 hours",
        "simple_schedule": "10 minutes",
        "timezone": "America/New_York",
        "crontab": "*/10 * * * *",
        "suppression_enabled": True,
        "suppression_duration": "1 hours",
        "suppression_fields": key,
        "dataset": "alerts",
        "user_defined_severity": None,
        "user_defined_category": None,
        "mitre_defs": {r["tactic"]: list(r["techniques"])},
        "investigation_query_link": "",
        "drilldown_query_timeframe": "ALERT",
        "mapping_strategy": "CUSTOM",   # raw-dataset query + explicit alert_fields
        "action": "ALERTS",
        "lookup_mapping": [],
    }


def _bundle_path():
    return os.path.join(_IMPORTS, "bundle.json")


def write():
    rules = [build(r) for r in RULES]
    for r, rule in zip(RULES, rules):
        with open(os.path.join(_IMPORTS, f"esxi_{r['event']}.json"), "w", encoding="utf-8") as f:
            json.dump([rule], f, indent=2)
            f.write("\n")
    with open(_bundle_path(), encoding="utf-8") as f:
        bundle = json.load(f)
    names = {r["name"] for r in rules}
    bundle = [b for b in bundle if b.get("name") not in names] + rules
    with open(_bundle_path(), "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
        f.write("\n")
    print(f"wrote {len(rules)} rule files + bundle.json ({len(bundle)} rules)")


def check(minutes):
    from integrations.xsiam_client import XsiamClient
    c = XsiamClient()
    bad = 0
    for r in RULES:
        try:
            rows = c.xql_query(_query(r), minutes_back=minutes, limit=50)
            print(f"  {len(rows):>3} hit window(s)  {r['event']}")
            for row in rows[:2]:
                print("        ", {k: row.get(k) for k in ("esxi_host", "actor_users", "src_ips", "event_count")})
        except Exception as e:  # noqa: BLE001 - report every failing query, keep going
            bad += 1
            print(f"  ERROR  {r['event']}: {str(e)[:600]}")
    return 1 if bad else 0


def apply():
    from integrations.xsiam_client import XsiamClient
    c = XsiamClient()
    live = {r["name"]: r for r in c.get_correlation_rules()}
    failed = 0
    for rule in (build(r) for r in RULES):
        cur = live.get(rule["name"])
        if cur is not None:
            if all(cur.get(k) == rule[k] for k in ("description", "xql_query", "suppression_fields")):
                print(f"  exists   {rule['name']}")
                continue
            rep = c.insert_correlation_rules([dict(rule, rule_id=cur["rule_id"])])
            rep = rep.get("reply", rep) or {}
            now = {r["name"]: r for r in c.get_correlation_rules()}.get(rule["name"]) or {}
            ok = all(now.get(k) == rule[k] for k in ("description", "xql_query", "suppression_fields"))
            failed += not ok
            print(f"  {'updated' if ok else 'FAILED '}  {rule['name']}  {'' if ok else rep}")
            if not ok:
                break
            continue
        rep = c.insert_correlation_rules([rule])
        rep = rep.get("reply", rep) or {}
        ok = rule["name"] in {r["name"] for r in c.get_correlation_rules()}
        failed += not ok
        print(f"  {'created' if ok else 'FAILED '}  {rule['name']}  {'' if ok else rep}")
        if not ok:
            break
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--minutes", type=int, default=7 * 1440, help="--check window (default 7 days)")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    if args.check:
        return check(args.minutes)
    if args.apply:
        return apply()
    write()
    return 0


if __name__ == "__main__":
    sys.exit(main())
