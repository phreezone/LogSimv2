# Firewall & VPN management plane

Until 2026-10-19 the firewall modules emitted only data-plane traffic and VPN sessions.
Management-plane attacks (admin access to the device itself, config and route edits,
turning logging off, harvesting configs, SNMP abuse) are a large share of the
gocortexio advisory corpus (`network.firewall` 73 patterns, `vpn_gateway` 58). This
adds a coherent admin baseline and five threats, taken from the corpus's MANAGEMENT
patterns, to all four firewall modules. The corpus is AGPL-3.0, so it was used as
reference only and none of its code was copied.

Shared identity lives in `modules/mgmt_plane.py`. It can be overridden with
`config["management_plane"]`.

| Role | Default |
|---|---|
| Admin subnet (NOC / jump hosts) | `10.0.30.0/24`; jump hosts `10.0.30.30`, `.31` |
| Admin accounts | `netadmin.jlee`, `netadmin.pkhan`, `netadmin.rortiz`, `fw_ops` |
| Config-backup job | `svc_netbackup` from `10.0.20.11`, once per UTC day at 02:00 |
| SNMP poller | `10.0.20.10` → 8 infrastructure devices behind the firewalls |

## Baseline (benign)

| Event | Rate at 1 call/s | ASA / FTD | FortiGate | Check Point |
|---|---|---|---|---|
| Admin session (`mgmt_admin_session`) | ~40/day; 1 in 5 makes a routine change and saves it | 113004 → 605005 → 111009 show / 111010 config → 111008 → 611103 | 32001 → [44547 object edit] → 32003 | SmartConsole audit: Log In → View → [Create/Modify → Publish → Install Policy] → Log Out |
| Config backup | 1/day (clock-keyed) | `show running-config` by `svc_netbackup` | 32143 backup by SCP | audit `Export` via Web API |
| SNMP poll (`snmp_poll`) | ~800/day | 302015/302016 UDP/161 | traffic 13, UDP/161, app SNMP | FW-1 connection, UDP/161 |

FortiGate's existing `admin_event` now also comes from the admin subnet and the shared
team. Before this change it came from any user workstation, which made "admin from an
unexpected source" part of the baseline.

## Threats

All five sit on each module's existing threat throttle (`threat_generation_levels`), at
weight 1 in `config.json` and in each module's defaults. None has a shipped Cortex
analytic, so they are marked non-analytic. They run in long sessions and in the
harness, and they are not offered for on-demand firing.

| Threat key | Corpus pattern | What is emitted |
|---|---|---|
| `mgmt_admin_unexpected_source` | device-admin-from-unexpected-source | A valid admin logs in from outside the admin subnet: a rare external IP on the outside interface, or a user workstation. Sometimes 1-2 AAA failures come first. |
| `mgmt_config_route_change` | network-device-config-or-route-change | A static route via an attacker next hop, a permit-any rule, and a capture or IPsec tunnel to it, then write mem / publish + install. |
| `mgmt_logging_suppressed` | network-device-logging-suppressed-for-a-window | `no logging enable` (FortiGate `log.syslogd.setting status[enable->disable]`; Check Point "send logs ... disabled"). The module then emits **nothing** for 10-40 min (`generate_log` returns None) and finally re-enables logging from the same session. |
| `mgmt_config_harvest` | scripted-device-config-harvesting | One source logs into 3-5 peer devices (`<host>-01..05`) with no auth failures, spends seconds on each, runs the same config-dump commands, and copies the config to an outside TFTP server. |
| `snmp_unexpected_source` | snmp-from-unexpected-source | A user workstation walks every infrastructure device on UDP/161 (FortiGate adds 29021 SNMP query failures against itself). |

The logging-suppressed gap needs a later `generate_log` call to close it. An on-demand
fire from outside the worker passes `context["mgmt_backdate"] = True`, which emits both
halves at once, with the disable stamped one window in the past. The harness does this.

## Where each message lands

Checked against the official content packs (demisto/content, `*_2_11.xif`):

* **Cisco ASA** (`cisco_asa_raw`, CiscoASA modeling rule). Every message goes through
  `parse_cisco()`, and the rule maps `generalCiscoLog.user` / `.command` / `.src_ip` /
  `.operation` / `.outcome`. `xdm.event.description` and `xdm.observer.name` populate
  for every ID. Cortex's analytics list only 302013-16 and the AnyConnect IDs, so none
  of the admin IDs can drive an analytic.
* **Cisco Firepower** (`cisco_firepower_raw`). FTD sends device administration as
  Cisco syslog (`%FTD-…`), not CEF, and the rule's `cefVersion = null` branch is the
  same parse_cisco model as ASA. SNMP is CEF CONNECTION.
* **FortiGate** (`fortinet_fortigate_raw`, FortiGate modeling rule). The FortiOS 7.4.4
  IDs used are 0100032001/2/3 (login, fail, logout), 0100044546/7/8 (config attribute,
  object attribute, execute), 0100032143 (backup by SCP) and 0100029021 (SNMP query
  failed). `cfgpath` maps to `xdm.target.resource.type`, `cfgattr` to `.resource.name`,
  `cfgobj` to `.resource.value`, and `logid` to `xdm.event.id`. The admin is `duser`,
  which maps to `xdm.target.user.username`, matching the existing admin_event.
* **Check Point**. Audit records carry Device Product `SmartConsole`, so XSIAM routes
  them out of `check_point_vpn_1_firewall_1_raw`. The CheckpointFirewall pack models
  only FireWall-1, URL Filtering, SmartDefense, Application Control and Identity
  Awareness, so the audit records are raw-only (useful for hunts and correlation
  rules). SNMP stays in FW-1 and is modeled.

Tenant verification: `_local_validation/mgmt_plane_probe.py send|read` drives every
generator with a marker admin account and marker SNMP device IPs, then reports the
dataset, the parsed `_json` and the XDM fields each event produced. End-to-end:
`_local_validation/threat_harness.py fire net:<asa|fgt|cp|ftd>:<threat>`.
