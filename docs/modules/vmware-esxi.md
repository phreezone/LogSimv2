# VMware ESXi

**Dataset:** `vmware_esxi_raw`
**Transport:** Syslog (TCP) to the Broker VM — `vmware_esxi_config.syslog_port` (default **1518**). Plain syslog is the default transport, so no `transport` key is set.
**Format:** Native ESXi `vmsyslogd` lines (RFC 5424-style header with an ISO 8601-UTC timestamp), **Raw** — *not* CEF.
**Default rate:** ~**0.01 events/s** (one every 100 s). A real ESXi host is quiet — outside the ambient `vpxa` poll it changes state rarely — so this source defaults far below the usual 1/s. The default comes from the module's `DEFAULT_EVENT_INTERVAL` (100 s) and can be overridden with `vmware_esxi_config.event_interval`; operators can still raise the rate per run from the dashboard.

Simulates VMware ESXi host syslog for the XSIAM `vmware_esxi_raw` dataset. ESXi forwards host logs (`hostd`, `vpxa`, `vobd`, `sshd`/`pam_unix`, `vmkernel`, `crond`, shell) to a remote collector. In XSIAM the Broker VM Syslog applet is configured **Protocol = TCP, Format = Raw, Vendor = VMware, Product = ESXi** on a dedicated port; the Marketplace **VMware ESXi** content pack supplies the parsing rule (`regexcapture` → `parsed_fields`) and the modeling rule that maps those fields to XDM and the **Virtualization Stories**.

## Routing: why a dedicated port

Plain syslog carries **no in-body routing key** (unlike the CEF `__firewall_type` used by PANW NGFW). The collector therefore tells ESXi apart from the other syslog sources **by listening port**, exactly as the existing syslog sources are separated — Cisco ASA `1514`, Apache `1515`, Infoblox `1516`. ESXi uses **`1518`**. Stand up a Broker VM Syslog collector on that port with Vendor = VMware, Product = ESXi, Format = Raw.

## Format

```
<30>2026-10-29T19:26:35.684Z esxi02.corp.examplecorp.local Hostd: info hostd[2423828] [Originator@6876 sub=Vimsvc.ha-eventmgr opID=esxui-76a5-c4db user=vmadmin] Event 992789 : User vmadmin@127.0.0.1 logged in as VMware-client/8.0.0
<86>2026-10-29T19:26:35.684Z esxi01.corp.examplecorp.local sshd[2138731]: Invalid user administrator from 104.168.77.66 port 41105
<30>2026-10-29T19:26:35.684Z esxi01.corp.examplecorp.local vobd: [GenericCorrelator] 6752482815us: [vob.user.ssh.session.failed] SSH login has failed for 'administrator@104.168.77.66'.
```

- **PRI** is `facility × 8 + severity`: `hostd`/`vpxa`/`vobd`/`vmkernel` under `daemon` (3), `sshd`/`pam_unix` under `authpriv` (10).
- **Timestamp** is ISO 8601-UTC with milliseconds and `Z` — the format modern ESXi (6.5+) emits and the pack parses for `_time`. The legacy ESXi 6.0 BSD `Mmm dd HH:MM:SS` stamp (no year/zone) would leave `_time` unset and break every time-windowed analytic, so it is never emitted.
- The `[Originator@6876 sub=… opID=… user=…]` tag sits in the **message body** (not RFC 5424 structured data), matching real ESXi and the pack's `regexcapture`.

**Key normalized XDM** (from the pack changelog, not yet confirmed by an in-tenant parse here): `xdm.source.user.username`, `xdm.*.identity.*` (pack ≥ 1.0.20), `xdm.source.ipv4`, `xdm.event.outcome`, target process name/path/command_line for `vmkernel` process-lifecycle events (≥ 1.0.21), and the Virtualization Stories (≥ 1.0.10).

**Identity:** when a session context is present the human operator is a correlated `session_utils` user, so ESXi auth stitches to the same identity seen on the cloud / Windows feeds; otherwise it falls back to a local ESXi account (`root`, `svc_vcenter`, `vmadmin`).

---

## Benign events

Routine day-to-day ESX operations that build a clean per-host baseline. Each is its own weighted generator (`_BENIGN_MIX`), so the activities an ESX environment must always show are first-class and reliably present. The mix is **time-of-day weighted** (shared `azure_common.activity_weight`): admin/config/login events (`human`) cluster in business hours, while machine events (vpxa poll, vCenter sync, vmkernel, backup, cron) run around the clock and dominate off-hours. Remote admin sources come from the shared ops-team jump hosts (`mgmt_plane`), so ESXi administration correlates with the firewall feeds.

| Event | Detail |
|---|---|
| `vpxa` status poll | The dominant ambient event — periodic `PollQuickStatsLoop`, `verbose` |
| **Shell command** | Common `esxcli` / `vim-cmd` / probe commands — the baseline the uncommon-command analytics train against |
| **Shell login / logout (success + failure)** | **SSH** success (`Accepted password` / `publickey` / `keyboard-interactive`, with `pam_unix` session + `hostd`/`vob` open-close) and failure (`Failed password` / `keyboard-interactive`, `Invalid user`, `pam_unix(sshd:auth)` failure, `vob.user.ssh.session.failed`); **ESXi Shell** and **DCUI** console logins/logouts (`logged in/out as …`) and failures (`Cannot login …`) |
| **Account lifecycle (benign)** | **Create** (`+ vob.user.account.created`), **disable** (role `NoAccess`), **delete/remove** (`+ vob.user.account.removed`), **lockout** after failed attempts (`+ vob.user.account.locked`), password change, role assign/remove, account review |
| **Stale-account login attempts** | Login attempt against a **disabled** account (`pam_unix(sshd:account): account … is disabled` / console `Cannot login … (account disabled)`) or a **deleted/offboarded** account (SSH `Invalid user …` + `pam_unix(sshd:auth): check pass; user unknown` / console `Cannot login … (no such user)`). Names come from `vmware_esxi_config.disabled_accounts` / `former_accounts`. |
| **SSH / ESXi Shell enable + disable** | Routine maintenance toggles — admin turns SSH or the ESXi Shell on, and off again — as a `hostd` config event + the matching `vob.user.esxshell[.ssh].{enabled,disabled}` correlator event |
| **VM power** | `powered on` / `powered off` / `suspended` / `reset` / guest-OS `shut down` / `reboot` / `standby` |
| VM lifecycle | Create, clone, reconfigure, vMotion migration, snapshot remove/consolidate |
| vSphere session | vSphere Client / API login + logout (`hostd` `Vimsvc.ha-eventmgr`, with client IP + user) |
| **vmkernel** | Storage path state / SCSI sense / APD / PDL, `vmnic` link up/down, hardware-sensor (fan/PSU/temp), memory admission — `vmkernel.log` / `vmkwarning.log` |
| **vCenter sync (runtime)** | The bulk of a managed host's authenticated activity: `vpxuser` login/logout from vCenter, `vpxa` inventory/task syncs, heartbeats, and connect / disconnect / reconnect |
| **Policy / config change** | Advanced settings (`Set called with key "…"` + the changed-option event: shell timeouts, password/lockout policy, log level, DCUI banner), lockdown-mode toggle, NTP/DNS config, port-group security policy, firewall allowed-IP lists, role create/modify |
| **Service policy** | Service startup policy (SSH / ESXi Shell / NTP / CIM / SNMP → on/off/automatic) and service start/stop/restart |
| **Backup job (runtime)** | Scheduled VM backup: snapshot create → NFC `File download` read → snapshot remove, by the backup proxy IP + service account (the benign baseline `vm_disk_export` stands against) |
| **Patch activity** | Signed VIB install and image-profile compliance scan via `esxupdate` (benign counterpart to the VIB-bypass threat) |
| **Datastore ops** | HBA rescan, NFS mount, capacity, VMFS grow |
| **HA / DRS** | vSphere HA (`fdm`) heartbeats, master election, host-isolation checks, and DRS load-balancing migrations |
| **Service control** | `hostd`/`vpxa`/`ntpd` restarts, SSL certificate renewal, NTP sync, firewall-ruleset enable/refresh |
| Snapshot create | Backup-job snapshot, quiesced |
| Maintenance mode | Host enters / exits maintenance mode (patching, vMotion) |
| Storage / datastore | NFS/VMFS volume state, device latency warnings |
| `crond` | `hostd-probe.sh` scheduled job |
| Service health | VMFS heartbeat, sensor health green, NTP sync |

The SSH/ESXi-Shell enable↔disable and VM power on↔off events are deliberately **benign here** — routine operations, emitted on both state transitions — distinct from the actor-driven threat generators below (which fire enablement from the shell as an *uncommon command*, the analytic path).

## Analytics

Per the Cortex **[alerts by data source: VMware virtualization servers syslogs](https://cortex-docs.paloaltonetworks.com/analytics-alerts/alerts-by-data-source/vmware-virtualization-servers-syslogs)** catalog, this data source drives **exactly two** shipped analytics — both **behavioral-rarity over the command executed on the host**:

| Alert | ATT&CK | Model |
|---|---|---|
| Uncommon command executed on a virtualization host | Execution T1059.012 (Hypervisor CLI) | Train 30d · activate 14d · single-event · dedup 1d, keyed on command + host |
| Uncommon command was executed on a device *(+ "…sensitive command…" variation)* | Execution T1059 | Same model, device-level |

There is **no** published auth/identity/VM-lifecycle analytic for this data source. Because the model is a rarity detector, a stable **common-command baseline** is what makes a rare command stand out — the benign `shell_command` and `crond` events supply it.

## Threats

Only the **analytic** event is offered on demand (dashboard Fire panel / MCP `fire_event` / CLI). The rest run in long-running sessions as realistic ESXi attacker TTPs — background baseline plus hunting/correlation fuel — and are **not** offered on demand (though the account-manipulation / evasion ones also surface as uncommon commands when run from the shell, which *is* the analytic path).

| Event | Analytic | Target | Notes |
|---|---|---|---|
| `uncommon_host_command` | ✅ | Uncommon command executed on a virtualization host | Interactive shell running uncommon admin / discovery / evasion / destructive commands (`esxcli` account add, firewall disable, syslog clear, downloaded tooling, encryptor staging) from the **rare** pool. |
| `ssh_brute_force` | — | *(hunt / correlation)* | SSH credential-guessing burst — many `sshd` failures + `vob.user.ssh.session.failed` from one external IP, usually ending in a `root` success. |
| `vuln_scan` | — | *(hunt / correlation)* | A vulnerability scanner / recon tool probing the management surface from one IP: `rhttpproxy` connections to `/sdk` `/mob` `/ui` `/folder`, SSL-handshake failures, CIM probes, `sshd` pre-auth noise (no identification string, `[preauth]` closes, no matching cipher/kex), and default-credential SSH + SOAP/API login attempts. Same IP correlates to the firewall feed. |
| `root_login_rare_source` | — | *(hunt / correlation)* | Successful `root` logon from a rare external source. |
| `ssh_service_enabled` | — | *(hunt / correlation)* | ESXi Shell / SSH turned on — the near-universal ESXi-ransomware precursor. |
| `local_account_created` | — | *(hunt / correlation)* | New local account + Admin role — persistence / privilege. |
| `mass_vm_power_off` | — | *(hunt / correlation)* | Many VMs powered off / snapshots removed — the destructive stage. |
| `remote_syslog_disabled` | — | *(hunt / correlation)* | `Syslog.global.logHost` cleared — anti-forensics (emits the `Set called with key "Syslog.global.logHost"` form SIEM content keys on). |
| `vm_disk_export` | — | *(hunt / correlation)* | VM disks/config downloaded off the datastore over NFC — VM theft (`File download from path … was initiated from`). |

The `uncommon_host_command` rare pool mirrors the ESXi-ransomware command catalog SIEM vendors detect on: `esxcli system account add` / `permission set … role Admin`, `network firewall set --enabled false` / `unload`, `vim-cmd hostsvc/lockdown_disable`, `system auditrecords remote|local disable`, `software acceptance set --level CommunitySupported`, `software vib install --force --no-sig-check`, `system settings encryption set --require-secure-boot=false` / `--require-exec-installed-only=false`, `syslog config set --loghost=''`, SSH-key and crontab **persistence** implants (`authorized_keys`, `/var/spool/cron/crontabs/root`), `software vib remove`, plus downloaded-tooling and encryptor staging. `ssh_service_enabled` also emits "Administrator access to the host has been enabled".

> **Still unverified in-tenant.** `uncommon_host_command` targets the real catalog analytic and emits the command-line the modeling rule reads, but no live fire has confirmed it here — every other module earned its "confirmed" status only after a fire → ingest → detect pass (`_local_validation/threat_harness.py`). The rarity model also needs the baseline to have trained (30 days of the common commands), so validation is not instantaneous. Run that pass before upgrading the claim.

## Configuration (`vmware_esxi_config`)

| Key | Default | Purpose |
|---|---|---|
| `syslog_port` | `1518` | Broker VM collector port for this source (Vendor = VMware, Product = ESXi, Format = Raw) |
| `hosts` | 3 `esxiNN.corp.examplecorp.local` | Cluster hostnames — stable so each host is a real entity for host-baselined analytics |
| `mgmt_ip` | `127.0.0.1` | What `hostd` records for local/console (DCUI/esxcli) auth; remote logons carry the client IP |
| `admins` | `root`, `svc_vcenter`, `vmadmin` | Local/service ESXi identities (fallback when no session context) |
| `datastores` | `datastore1`, `ds-prod-nfs01`, `ds-vsan-01` | Datastore names for storage + snapshot events |
| `vms` | `DC01`…`BACKUP01` | Guest VM names for power/snapshot events |

---

## ESXi host vs vCenter — what this module emits

This module emits an **ESXi host** profile — specifically a **vCenter-managed** host — not vCenter Server output. The two are distinct syslog sources:

| | ESXi host (this module → `vmware_esxi_raw`) | vCenter Server (VCSA, a separate source) |
|---|---|---|
| Programs / idents | `hostd`, `vpxa`, `vobd`, `vmkernel`/`vmkwarning`, `sshd`/`pam_unix`, `shell`, `crond` | `vpxd`, `vpxd-main`, `vsphere_client`, `vmware-sso` (SSO/STS), `vapi`, `vmware-vpostgres` |
| Log files | `/var/log/{hostd,vpxa,vobd,vmkernel,auth,shell,syslog}.log` + per-VM `vmware.log` | `/var/log/vmware/vpxd/*`, `…/sso/*`, `…/vsphere-ui/*` on the appliance |

Why this reads as an ESXi host and not vCenter:
- The programs emitted (`hostd`/`vpxa`/`vobd`/`sshd`/`shell`/`vmkernel`) are exactly the host-side set; **no `vpxd`/`vpxd-main`/SSO/vSphere-UI lines are produced**, which is the vCenter fingerprint (Microsoft's Sentinel parser even uses `vpxd-main` as a vCenter host-discovery hint).
- **`vpxa` is present**, and per Broadcom the `vpxa` agent (and its log) exists **only when the host is managed by vCenter** — so the output models the common managed-host deployment rather than a standalone host.
- Per Broadcom, **`hostd.log` itself records** VM Task/Events, vSphere Client / SDK logins, and comms with the `vpxa` agent — so the vSphere-Client logins and VM power/Task events this module emits from `hostd` are genuine **host** output, not borrowed vCenter content.

If a dedicated **vCenter** (`vpxd`) source is wanted later, that is a separate module (different programs, different dataset) — say the word and it can be added alongside this one.

## External references (reviewed for event coverage)

The event set was cross-checked against VMware/Broadcom and the major SIEM vendors so the generated logs match what real ESXi emits and what detection content expects:

- **Broadcom / VMware** — [ESXi log file locations & contents](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/9-0/vsphere-security/securing-esxi-hosts/managing-esxi-log-files/esxi-log-file-locations.html) (the authoritative host log-file catalog; confirms `vpxa` = vCenter-managed only, and `hostd` contents).
- **Microsoft Sentinel** — [VMware ESXi parser `VMwareESXi.yaml`](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/VMWareESXi/Parsers/VMwareESXi.yaml) — extracts `sub=`, `opID=`, `user=` from the `[Originator@6876 …]` tag and the `process[id]` prefix; this module's wire format matches those regexes exactly.
- **Google SecOps (Chronicle)** — [`VMWARE_ESX` parser](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/vmware-esx) — maps `program`, `event_type`, `USER`/`pid`/`cmd`, `srcip`, `opID`, `severity`, `filepath`; the `USER root pid N cmd …` shell form maps to `PROCESS_LAUNCH`.
- **Splunk** — [Add-on for VMware ESXi Logs](https://docs.splunk.com/Documentation/AddOns/released/VMWesxilogs/SourceTypes) (per-service sourcetypes: `hostd`, `Vpxa`, `vobd`, `vmkernel`, `Fdm`) and [Detecting ESXi ransomware](https://www.splunk.com/en_us/blog/security/detecting-esxi-ransomware-activity-splunk.html) (the attacker-command catalog folded into the rare-command pool).
