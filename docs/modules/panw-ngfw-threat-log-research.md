# PAN NGFW threat logs — how the other threat types look

Research notes (2026-11-15) for extending `modules/panw_ngfw.py` beyond the eight
`vulnerability` signatures the tenant's real pa440 carries. Three kinds of evidence are kept
apart: **documented** (Palo Alto's field reference), **observed** (Elastic's open test data and
the tenant's own alerts) and **unconfirmed** (needs a real row to settle).

## 1. Threat log layout (documented)

Palo Alto's *Threat Log Fields* page (PAN-OS 12.x) gives the CSV order:

`FUTURE_USE, Receive Time, Serial, Type, Threat/Content Type, FUTURE_USE, Generated Time,
Source, Destination, NAT src, NAT dst, Rule, Source User, Dest User, Application, Vsys,
Source Zone, Dest Zone, Inbound IF, Outbound IF, Log Action, FUTURE_USE, Session ID, Repeat
Count, Sport, Dport, NAT sport, NAT dport, Flags, Protocol, Action, URL/Filename, Threat ID,
Category, Severity, Direction, Sequence, Action Flags, Src Location, Dst Location, FUTURE_USE,
Content Type, PCAP ID, File Digest, Cloud, URL Index, User Agent, File Type, X-Forwarded-For,
Referer, Sender, Subject, Recipient, Report ID, …, Threat Category, Content Version, …`

The Cortex Syslog Collector's custom format carries the same data as named keys (`misc`,
`threat_id`, `threat_name`, `threat_category`, `direction`, `user_agent`, `xff`, `severity`
as `$number-of-severity`). Which fields each subtype uses:

| Subtype | Meaning | `misc` holds | Subtype-only fields |
|---|---|---|---|
| `vulnerability` | exploit detected by a Vulnerability Protection profile | URL or file name, if any | — |
| `spyware` | Anti-Spyware profile: phone-home / C2, DNS signatures, sinkhole | domain, URL or file | — |
| `virus` | Antivirus profile | file name | — |
| `wildfire-virus` | virus detected via an Antivirus profile from the WildFire signature feed | file name | — |
| `wildfire` | WildFire verdict after the firewall submitted a file | file name | `filedigest`, `cloud`, `filetype`, `reportid`, `url_idx` |
| `ml-virus` | WildFire Inline ML verdict via an Antivirus profile | file name | `partial_hash` |
| `file` | File Blocking profile match | file name or file type | — |
| `data` | Data Filtering profile match | file name | `reportid` |
| `scan` / `flood` / `packet` | Zone Protection profile | — | — |
| `url` | URL filtering (carried in the URL log) | the URI | `user_agent`, `referer`, `http_method`, `content_type`, `xff` |

Documented value sets:

- **action**: alert, allow, deny, drop, drop-all-packets, reset-client, reset-server,
  reset-both, block-url, block-ip, random-drop, sinkhole, syncookie-sent, block-continue,
  continue, block-override, override-lockout, override, and `block` (WildFire only: file
  blocked and uploaded).
- **severity**: informational, low, medium, high, critical.
- **category** (the `category` column, not the threat category): URL category for `url`; for
  `wildfire` it is the verdict `malware` / `phishing` / `grayware` / `benign`; `any` otherwise.
- **direction**: client-to-server or server-to-client. Documented as `0` / `1` in some
  releases; the live rows and the Cortex format use the words.
- **Threat ID ranges**: 8000–8099 scan, 8500–8599 flood, 9999 URL filtering, 10000–19999
  spyware phone-home, 20000–29999 spyware download, 30000–44999 vulnerability exploit,
  52000–52999 file type, 60000–69999 data filtering. Virus, WildFire-feed and DNS-C2
  signatures no longer use a range: they have permanent, globally unique IDs (hence the
  9-digit IDs below). Filter by subtype and `threat_category` instead of ID ranges.
- **Flags** bit `0x20000000` = file submitted to WildFire.
- In the default CSV `Threat ID` is `name(id)` for most subtypes; the Cortex format splits it
  into `threat_name` and `threat_id` (the live rows carry both).

## 2. What each subtype looks like (observed, Elastic's public test data)

323 threat rows from Elastic's `panw` integration test fixtures, parsed with the documented
field order. Signature names are Palo Alto's published names. No WildFire row is in the set.

| Subtype | Shapes seen |
|---|---|
| `spyware` (112 rows) | Mostly **DNS**: app `dns`/`dns-base`, udp/53, actions `drop`, `drop-packet`, `sinkhole`, `drop-all-packets`; severity mostly medium; `thr_category` `dns-malware`, `domain-edl`, `dns-proxy`. Names look like `generic:<domain>(327891564)`, `Proxy:<domain>(109010004)`, `Suspicious Domain(12000000)`; `misc` is the queried domain. Classic phone-home: `Bredolab.Gen Command and Control Traffic(13024)`, `misc` a file/URI. |
| `virus` (5) | server-to-client, app `web-browsing`, actions `reset-both` / `reset-server`, severity medium; `thr_category` `elf` or `script-av`; name `Virus/Linux.<name>(419149938)`; `misc` the file name; content version `Antivirus-<n>-<n>`. |
| `file` (10) | server-to-client `web-browsing`, actions `deny` / `alert`, severity low; threat `Windows Executable (EXE)(52020)`; `misc` the file name; threat ID in the 52000 range. |
| `data` (34) | `PII(60000)`, severity informational, actions `reset-both` / `alert`, mostly server-to-client; `misc` a page name. |
| `scan` (1) | `SCAN: Host Sweep(8002)`, medium, action alert, app `not-applicable`, `thr_category` `scan`. |
| `vulnerability` (2) | `Potential HTML Evasion Technique Detected in HTTP Response(91883)`, low, alert, `thr_category` `protocol-anomaly`. |
| `url` (159) | threat ID 9999; actions `block-url` / `alert`; categories include `malware-sites`, `not-resolved`, `private-ip-addresses`. (Covered by the module's URL log.) |

The content-version string looks like `AppThreat-<n>-<n>` (vulnerability, file) or
`Antivirus-<n>-<n>` (virus).

## 3. WildFire (documented; no sample line found)

- A `wildfire` threat row is a **verdict** on a file the firewall submitted: `category` is
  `malware`, `phishing` (links), `grayware` or `benign`; `filedigest` is the file's hash,
  `cloud` the WildFire cloud FQDN, `filetype` the file kind (PE, PDF, APK, ELF, MS Office,
  archive, script, …), `reportid` the analysis ID, `misc` the file name, `url_idx` links it to
  the URL log of the download. Action `block` appears only here.
- WildFire Submissions severity (documented, version-dependent): grayware with any action is
  **low**; benign is **informational**; a submission blocked and forwarded is
  **informational**; in 10.2, malicious + allow is **high**. Threat-log entries for a malicious
  verdict with block/alert, from the WildFire signature feed, are **medium**.
- Palo Alto publishes harmless WildFire test files (PE, APK, macOS, ELF) whose verdict is
  always malware; they are for checking forwarding, and no antivirus signature exists for the
  PE test file, so it is logged as a submission, not blocked.
- **Unconfirmed**: an exact `wildfire` row (threat name format, `cloud` value, `filetype`
  spelling, which `action`) is not in any source I found. The tenant's own `panw_ngfw_threat_raw`
  has none yet, so a real row is needed before building it.

## 4. How XSIAM turns a threat log into an alert (observed, the tenant's `PAN_NGFW` alerts)

The Cortex docs describe no subtype/severity matrix. The tenant's own alerts from the pa440
show the mapping (read-only query, 2026-11-15):

| Alert field | Comes from |
|---|---|
| `alert_name` | `threat_name` |
| `alert_source` | `PAN_NGFW` (tag `DS:PANW/NGFW`) |
| `category` | the subtype, capitalised (`Vulnerability`) |
| `severity` | the threat's severity, upper-cased (MEDIUM / HIGH / CRITICAL) |
| `description` | `<Threat category> (<misc>)` when `misc` exists (`Hacktool (host:port/path)`), otherwise the category text (`Code-Execution`, `Vulnerability Exploit Detection`) |
| `action` | from the firewall action: `drop` → `PREVENTED__DROPPED_THE_SESSION_`; `alert` → `DETECTED__RAISED_AN_ALERT_` |
| `misc`, `app_category`, `app_subcategory`, `app_technology`, zones, `fw_rule_name`, `fw_serial_number`, `ngfw_vsys_name` | the corresponding threat-log columns |
| `original_tags` | `DS:PANW/NGFW`, plus `R:<...>` tags such as `R:Vulnerability Scanners` (scanner signatures) |

Two documented Cortex analytics read threat logs: *Analytics enhanced NGFW – Rare Internal
Firewall Vulnerability Threat Alert* (Informational; needs threat logs and an XDR Agent) and
*Massive upload to a rare storage or mail domain* / *Recurring access to rare domain* (these
also need the XDR Agent). So on a firewall-only feed the alerts that appear are the native
`PAN_NGFW` ones.

Not yet shown by the tenant: whether `spyware`, `virus`, `wildfire` and `file` threat rows
raise native alerts, and at which severity. Informational-severity rows may not.

## 5. What this means for the generator

Buildable now, with shapes from section 2:

- **Spyware (DNS)**: udp/53 from an internal host to the resolver, `sinkhole` / `drop`,
  `thr_category` `dns-malware`, `misc` the domain. Needs real signature names and IDs.
- **Spyware (phone-home)**: a classic C2 callback to a rare external host, severity high or
  critical, `drop` / `reset-both`.
- **Virus**: server-to-client download of a file, `reset-both`, `thr_category` `elf` /
  `script-av`.
- **File / data / scan**: low-severity, mostly noise; the scan and flood signatures belong
  with the traffic detectors (`SCAN: Host Sweep(8002)` matches a port sweep).

Every one needs **real Threat IDs and names from the tenant**: the generator never invents
IDs. The scheduled 12-hour job reads them from `panw_ngfw_threat_raw` after the user's own
threat generation, and builds what the rows prove.

## Sources

- PAN-OS *Threat Log Fields* (syslog field descriptions):
  https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields
- PAN-OS *Log Types and Severity Levels* and *View WildFire Logs and Analysis Reports*:
  https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/view-and-manage-logs/log-types-and-severity-levels
  https://docs.paloaltonetworks.com/advanced-wildfire/administration/monitor-wildfire-activity/view-wildfire-logs-and-analysis-reports/view-wildfire-logs-and-analysis-reports-pan-os
- WildFire test files: https://docs.paloaltonetworks.com/wildfire/10-1/wildfire-admin/submit-files-for-wildfire-analysis/verify-wildfire-submissions/test-a-sample-malware-file
- Cortex *Ingest NGFW logs using the Syslog collector* (custom format) and *Palo Alto Networks
  Firewall threat Logs* analytics:
  https://cortex-docs.paloaltonetworks.com/analytics-alerts/alerts-by-data-source/palo-alto-networks-firewall-threat-logs
- Elastic `panw` integration test fixtures (open source):
  https://github.com/elastic/integrations/tree/main/packages/panw/data_stream/panos/_dev/test/pipeline
