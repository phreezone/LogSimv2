# ExampleCorp Environment Knowledge for the XSIAM Agentic Assistant

<!--
HOW TO USE THIS FILE
- Upload at: Agentic Assistant Hub > Knowledge Center > + New Source > File. Limit 5 MB; MD/JSON/JSONL/CSV/DOC/DOCX.
- Share the source with the agents that should use it.
- Retrieval is search-based: every section is self-contained, every row names its site/team/system, and
  each section ends with a "How to use this" line.
- NEVER put secrets here: no API keys, passwords, tokens, or real personal data.
- Provenance: most values were derived from the LogSim simulator's config.json and modules (the
  simulated ExampleCorp estate that feeds this tenant). Values supplied by the owner (working hours,
  holidays, change freeze, backup schedule, authorized upload sites) are marked [owner].
  Dataset names in section 9 were read from the XSIAM tenant on 2026-11-15.
  Anything marked TODO is still unknown. Anything marked (assumption) should be confirmed.
- Where this file conflicts with built-in Cortex knowledge, the agent prefers this file and flags the conflict.
-->

| Field | Value |
|---|---|
| Organization | ExampleCorp |
| Owner (team / contact) | TODO |
| Last reviewed | 2026-11-15 |
| Industry / compliance regimes | TODO |
| Corporate email domain | examplecorp.com |
| Active Directory domain | EXAMPLECORP (DNS: examplecorp.local) |
| Public website | www.examplecorp.com |
| Headcount (directory) | 501 user accounts in 15 departments |
| Countries with offices | United States (7 offices), Canada (Toronto), Ireland (Dublin), United Kingdom (London) |
| Countries with NO business presence | Everything else. No office or Zscaler location exists outside the ten sites in section 1. |

**How to use this:** Treat sign-ins or traffic that originate from a country with no business presence as unexpected unless section 1a (VPN/SASE ranges) or the user's recorded travel explains them.

---

## 1. Sites and egress addresses

Public NAT/egress addresses per office. Many users share a few addresses, so an IP alone does not identify a person.

| Site | Country | ISP (ASN) | Public egress IPs | Shared NAT? | Notes |
|---|---|---|---|---|---|
| Columbus, OH | US | AT&T Services (7018) | 75.23.197.10-15 | Yes | TODO: role (HQ?) |
| Austin, TX | US | AT&T Services (7018) | 209.30.75.10-15 | Yes | |
| Seattle, WA | US | Lumen / CenturyLink (209) | 97.126.30.10-15 | Yes | |
| New York, NY | US | Verizon Business (701) | 173.52.219.10-15 | Yes | |
| Chicago, IL | US | AT&T Services (7018) | 70.241.99.10-14 | Yes | |
| Fremont, CA | US | Hurricane Electric (6939) | 74.82.60.10-14 | Yes | |
| Atlanta, GA | US | AT&T Services (7018) | 75.46.159.10-13 | Yes | |
| Dublin | IE | Eir (5466) | 51.171.78.10-13 | Yes | |
| London | GB | BT (2856) | 83.245.18.10-13 | Yes | |
| Toronto, ON | CA | Rogers Communications (812) | 99.221.22.10-13 | Yes | |

Each user is assigned to one office and normally appears from that office's pool.

**How to use this:** Sign-ins and web traffic from these addresses are corporate. Do not attribute an event to one user from a shared egress IP alone; correlate on user, device or session. A user appearing from an office other than their own is notable but not by itself malicious.

### 1a. Remote, mobile, VPN and proxy ranges

| Item | Value |
|---|---|
| Home / remote work | Permitted (modeled). Users sign in from a residential ISP in their own office's metro (for example Spectrum, Comcast, AT&T Internet, Verizon Fios, Virgin Media, Bell). Each user keeps one home /24 and one address in it. Home devices are named `<DEPT>-HM-nnn` and sit in 172.16.100.0/24. |
| Mobile sign-ins | Permitted (modeled). Carrier LTE/5G addresses (T-Mobile, Verizon Wireless, AT&T Mobility, Vodafone, Three, Rogers, Bell) in the user's own metro. Mobile devices are in 10.10.50.0/24. |
| Corporate VPN gateways | Cisco ASA AnyConnect; FortiGate SSL VPN at 203.0.113.20; Check Point gateway 203.0.113.10 |
| Firewall NAT pools | 203.0.113.0/27 (Palo Alto PA-VM-01), 203.0.113.0/28 (Cisco ASA-FW-01) |
| Zscaler (web proxy) egress IPs | 198.51.100.10, 198.51.100.11, 198.51.100.12 (users behind Zscaler appear from these addresses) |
| Zscaler VPN gateway (internal) | 10.0.10.1 |
| Zscaler locations | One per office site: Columbus_OH_USA, Austin_TX_USA, Seattle_WA_USA, NewYork_NY_USA, Chicago_IL_USA, Fremont_CA_USA, Atlanta_GA_USA, Dublin_IE, London_UK, Toronto_ON_CA |
| Consumer VPN / anonymizers (Mullvad, NordVPN, ProtonVPN and similar) | Not sanctioned (assumption) |
| Tor | Not sanctioned (assumption) |
| Partner / B2B ranges | TODO |

**How to use this:** A sign-in that geolocates away from the user's office is explained only by a corporate VPN/proxy range above, a home or mobile address in the user's own metro, or recorded travel. Anything else, especially a consumer VPN or Tor address, should be treated as unexpected.

---

## 2. Internal networks, segments and zones

All offices appear to share one logical internal address plan; per-site subnets are not distinguished in the telemetry.

| Segment | CIDR | Zone | Purpose | Key hosts / notes |
|---|---|---|---|---|
| Sales endpoints | 192.168.10.0/24 | LAN (user) | Laptops, Sales dept. | `SALES-LT-nnn` |
| Engineering endpoints | 192.168.20.0/24 | LAN (user) | Laptops and workstations | `ENG-WS-nnn` |
| Marketing endpoints | 192.168.30.0/24 | LAN (user) | Laptops | |
| HR endpoints | 192.168.40.0/24 | LAN (user) | Laptops | |
| Finance endpoints | 192.168.50.0/24 | LAN (user) | Workstations | Sensitive: payroll, AP/AR |
| IT endpoints | 192.168.60.0/24 | LAN (user) | Laptops and workstations | IT staff are privileged |
| Operations endpoints | 192.168.70.0/24 | LAN (user) | Laptops | |
| Legal endpoints | 192.168.80.0/24 | LAN (user) | Laptops | Sensitive: contracts |
| Security endpoints | 192.168.90.0/24 | LAN (user) | Laptops and workstations | SOC / IR staff |
| DevOps endpoints | 192.168.100.0/24 | LAN (user) | Laptops and workstations | Privileged cloud access |
| Data Science endpoints | 192.168.110.0/24 | LAN (user) | Laptops and workstations | |
| Customer Success endpoints | 192.168.120.0/24 | LAN (user) | Laptops | |
| Product endpoints | 192.168.130.0/24 | LAN (user) | Laptops | |
| Support endpoints | 192.168.140.0/24 | LAN (user) | Workstations | |
| Procurement endpoints | 192.168.150.0/24 | LAN (user) | Laptops | |
| Mobile devices | 10.10.50.0/24 | Mobile | Phones (iPhone, Pixel, Galaxy) named `<USER>-<MODEL>` | |
| Home / remote devices | 172.16.100.0/24 | Remote | Home-office devices | `<DEPT>-HM-nnn` |
| Web / public services | 10.0.10.0/24 | DMZ / servers | www.examplecorp.com web farm | 10.0.10.50-52 (public web farm only), 10.0.10.1 (Zscaler VPN gw), 10.0.10.254 (network device), 10.0.10.10 (DC01) |
| Server / data infrastructure | 10.0.20.0/24 | Server | Databases, backup, vCenter, monitoring | 10.0.20.10 DC02, 10.0.20.11-14 databases, 10.0.20.15 VM backup proxy, 10.0.20.16 APP01, 10.0.20.20 vCenter, 10.0.20.30-32 file servers FS01/FS02/FILE01, 10.0.20.40 Exchange, 10.0.20.41 SharePoint, 10.0.20.50 print server, 10.0.20.1 gateway |
| Management / admin | 10.0.30.0/24 | Management | NOC and firewall administration | Jump hosts 10.0.30.30 and 10.0.30.31; 10.0.30.40 SNMP poller; 10.0.30.5 Check Point management server; 10.0.30.11-14 firewall management (see 2c); 10.0.30.1 gateway |
| Infrastructure services | 10.1.0.0/16 | Server | DNS/DHCP and application servers | 10.1.1.2 Infoblox DC1, 10.1.5.20-21 servers, 10.1.100.10-11 databases, 10.1.255.254 network device |
| Data center B | 10.100.0.0/16 | Server | Servers and databases | 10.100.1.1-2, 10.100.10.10-11 |
| Legacy / other servers | 192.168.1.0/24, 192.168.2.0/24 | LAN | Early demo users and servers | 192.168.1.100/.101/.200 servers; 192.168.1.1 and 192.168.2.1 network devices; 192.168.2.50 server |
| Server ranges | 172.16.0.0/16, 172.17.0.0/16, 172.18.0.0/16, 172.31.0.0/16 | Server | Application and database servers | 172.16.10.5-6, 172.16.50.5-7 (databases), 172.16.255.254 (network device), 172.17.5.5, 172.18.100.100, 172.31.10.10 |
| Guest Wi-Fi | TODO | Guest | Infoblox network view `guest-wifi` | CIDR unknown |
| Infoblox DC2 | 10.1.1.3 | Server | Second DNS server | Inside the infrastructure-services range with DC1 |

**How to use this:** An endpoint subnet identifies the owning department (for example a 192.168.50.x source is Finance). Servers should not initiate connections to the internet from the Server or DMZ zones except for known update and backup destinations. Admin protocols (SSH, RDP, WinRM, SNMP, firewall management) should originate from 10.0.30.0/24.

### 2a. DMZ and exposed services

| Service | Host / IP | Port(s) | Exposed to internet? | Expected inbound sources |
|---|---|---|---|---|
| Public website (Apache) | www.examplecorp.com, 10.0.10.50, 10.0.10.51, 10.0.10.52 | 443 | Yes | Any internet source |
| Palo Alto DMZ interface | PA-VM-01 ethernet1/3 | n/a | n/a | n/a |
| Infoblox `dmz-services` DNS view | TODO | 53 | TODO | TODO |

Probing of paths such as `/admin.php`, `/wp-login.php`, `/.env`, `/.git/config`, `/phpinfo.php` and `/backup.sql` against the website is reconnaissance, not legitimate use; none of these paths are part of the real site.

### 2b. Infrastructure services

| Service | Host / IP | Notes |
|---|---|---|
| DNS / DHCP (Infoblox NIOS 9.0.3) | infoblox-dc1-01 (10.1.1.2), infoblox-dc2-01 (10.1.1.3) | DNS views `internal-lan`, `dmz-services`; network views `default`, `guest-wifi`; RPZ zones `rpz.infoblox.internal`, `bloxone-rpz-malware`, `rpz.threat-intel.corp` |
| Internal DNS names | examplecorp.local, ad.examplecorp.local, dc01/dc02, fileserver, exchange, sharepoint, vcenter (all `.examplecorp.local`) | |
| Domain controllers | DC01.examplecorp.local (10.0.10.10), DC02.examplecorp.local (10.0.20.10) | Windows events arrive through Windows Event Collector. See section 6a-1 for further DC names. |
| VMware vCenter | vcenter.corp.examplecorp.local, 10.0.20.20 | Manages three ESXi hosts |
| Network-config backup host | 10.1.5.20 (BACKUP01) | Account `svc_netbackup` |
| VM backup proxy | 10.0.20.15 | Account `svc_vmbackup` |
| SNMP poller | 10.0.30.40 | Polls 8 network devices |
| Admin jump hosts | 10.0.30.30, 10.0.30.31 | Only these should originate admin protocols |
| Firewalls | ASA-FW-01, DC1-FTD-01, PA-VM-01, CP-FW-1 (with CP-MGMT-01), FG-FW-01 | Management interface IPs are in section 2c |
| Network devices (SNMP/admin) | 10.0.10.254, 10.1.255.254, 172.16.255.254, 192.168.10.1, 10.0.20.1, 10.0.30.1, 192.168.1.1, 192.168.2.1 | |

**How to use this:** Use this table to name a host's role when an event cites only an IP.

### 2c. Firewalls and their management interface IPs

| Firewall | Hostname | Platform | Management interface IP | Other addresses | Notes |
|---|---|---|---|---|---|
| Cisco ASA | ASA-FW-01 | Cisco ASA, AnyConnect VPN (group `TunnelGroup_AnyConnect`) | **10.0.30.11** | Outside 203.0.113.1; NAT pool 203.0.113.0/28; AAA server 10.0.10.200 | Set in config.json (`cisco_asa_config.management_ip`). Simulator assignment, not owner-confirmed. |
| Cisco Firepower | DC1-FTD-01 | Cisco FTD (device ID ftd-9a8b7c6d-5e4f-3a2b-1c0d), interfaces `inside` / `outside`, policy `Default_Access_Control_Policy` | **10.0.30.12** | Outside 203.0.113.30 | Set in config.json (`firepower_config.management_ip`). Simulator assignment, not owner-confirmed. |
| Check Point | Gateway CP-FW-1; management server CP-MGMT-01 | Check Point gateway plus SmartConsole management server | **10.0.30.5** (management server CP-MGMT-01) | Gateway CP-FW-1 / VPN gateway 203.0.113.10 | No separate gateway management IP is defined. Admin audit records are `SmartConsole` events with `origin` and `dst` 10.0.30.5. Set in config.json (`checkpoint_config.management_server_ip`). |
| Palo Alto | PA-VM-01 | PAN-OS 11.1.4, serial 007051000012345, vsys1 | **10.0.30.13** | ethernet1/1 WAN, ethernet1/2 LAN, ethernet1/3 DMZ; NAT pool 203.0.113.0/27 | Set in config.json (`panw_ngfw_config.mgmt_ip`). Simulator assignment, not owner-confirmed. |
| Fortinet | FG-FW-01 | FortiGate, serial FGVM08TM21000001, vdom `root` | **10.0.30.14** | VPN gateway 203.0.113.20; port1 WAN, port10 LAN | Set in config.json (`fortinet_config.management_ip`). Simulator assignment, not owner-confirmed. |

**How to use this:** Administration of a firewall (SSH, HTTPS, SmartConsole, SNMP) should reach these management addresses from the admin subnet 10.0.30.0/24, in practice the jump hosts 10.0.30.30 and 10.0.30.31. A connection to a management IP from a user workstation or the internet is unexpected. The ASA, FTD and Check Point management addresses are all in 10.0.30.0/24.

---

## 3. Sanctioned applications and destinations

### 3a. Authorized file upload / sharing sites [owner]

| Service | Domain(s) | Who may use it | Upload allowed? | Notes |
|---|---|---|---|---|
| Box | box.com | All employees | Yes | Corporate use |
| Box (ExampleCorp tenant) | examplecorp.box.com | All employees | Yes | The preferred, tenant-controlled Box instance |
| Microsoft OneDrive (corporate) | `<tenant>-my.sharepoint.com` (OneDrive for Business), onedrive.com, api.onedrive.com, graph.microsoft.com; TODO exact tenant name | All employees | Yes | Corporate tenant only (assumption). Personal OneDrive (onedrive.live.com, 1drv.ms, *.files.1drv.com) is not authorized unless the owner says otherwise. |

All other file-sharing and storage services are unauthorized for uploads, including Dropbox, Google Drive, WeTransfer, Mega, MediaFire, pCloud, Proton Drive, iCloud Drive, ShareFile, GoFile and paste sites (Pastebin, Rentry, JustPaste.it, etc.).

Dropbox Business and Egnyte are integrated with Okta SSO and appear in the corporate application list, but they are not listed as authorized upload destinations. TODO: confirm.

**How to use this:** An upload to a destination outside this table is unsanctioned and should be reported with the user, device, destination and byte count. An upload to an authorized destination is not automatically benign: still weigh volume, sensitivity of the data, off-hours timing, and whether the account is a personal rather than corporate one.

### 3b. Single sign-on applications (Okta)

About 100 applications are integrated with Okta SSO and are treated as sanctioned:
Microsoft Office 365, Google Workspace, Microsoft Teams, Slack, Zoom, RingCentral, Webex, Loom, Calendly, Salesforce, HubSpot, Pipedrive, Outreach, Salesloft, Gong, Clari, ZoomInfo, LinkedIn Sales Navigator, Workday, BambooHR, Rippling, ADP Workforce Now, Greenhouse, Lever, Lattice, Culture Amp, 15Five, Leapsome, Jira, Confluence, Asana, Monday.com, Notion, Airtable, Smartsheet, ClickUp, Trello, Linear, ServiceNow, Freshservice, PagerDuty, GitHub, GitLab, CircleCI, Harness, LaunchDarkly, Retool, Postman, Sentry, Datadog, New Relic, Grafana Cloud, Splunk Cloud, Figma, Miro, Adobe Creative Cloud, Lucidchart, Canva, Box, Dropbox Business, Egnyte, Contentful, Tableau, Looker, Power BI, Domo, Amplitude, Mixpanel, Heap, Segment, Snowflake, Databricks, NetSuite, Concur, Expensify, Coupa, Bill.com, Brex, Zuora, Anaplan, DocuSign, PandaDoc, Ironclad, Drata, Vanta, OneTrust, Zendesk, Freshdesk, Intercom, Front, Marketo, Drift, Sprout Social, Hootsuite, Udemy Business, Pluralsight, Coursera for Business, Cornerstone OnDemand, Qualtrics, SurveyMonkey and Claude.

### 3c. Approved remote-access, RMM and admin tools

| Tool | Approved users/hosts | Notes |
|---|---|---|
| Cisco AnyConnect VPN | All employees | Corporate remote access |
| SSH / RDP / WinRM to servers | Administrators from the jump hosts only | See section 5a |
| TODO (RMM, remote-support tools) | TODO | |

### 3d. Approved external email senders

Known-good bulk senders seen in Proofpoint: microsoft.com, linkedin.com, dropbox.com, github.com, atlassian.com, zoom.us, salesforce.com, docusign.net, adobe.com, slack.com, hubspot.com, servicenow.com, workday.com, concur.com.

Lookalike domains (for example `micros0ft-support.com`, `docusign-notify.net`, `sharepoint-online.net`, `onedrive-share.xyz`, `zoom-meeting-invite.com`) are phishing, not approved senders.

| Item | Value |
|---|---|
| Internal mail domain | examplecorp.com |
| Proofpoint cluster | examplecorp_hosted |
| Approved external sharing partners | TODO |

**How to use this:** Compare a sender or destination domain with the lists above and look for lookalikes before judging it.

---

## 4. Working hours and schedules

### 4a. Working hours [owner]

All teams work the same schedule.

| Team | Time zone | Core hours | Days | Out-of-hours activity normal? |
|---|---|---|---|---|
| All departments (Engineering, Sales, IT, DevOps, Marketing, Finance, Operations, Customer Success, Support, Procurement, Security, Data Science, Product, HR, Legal) | US Eastern (America/New_York) | 07:00-18:00 | Monday-Friday | No, except where listed in 4d |

UTC equivalents of 07:00-18:00 Eastern: 12:00-23:00 UTC during Eastern Standard Time (early November to mid-March, UTC-5) and 11:00-22:00 UTC during Eastern Daylight Time (mid-March to early November, UTC-4). DST ends 2026-11-01 and 2027-11-07; it starts 2027-03-14.

Offices in other time zones (Seattle, Fremont, Dublin, London) are assumed to follow the same Eastern schedule. TODO: refine if local hours differ.

### 4b. US holidays (no normal activity expected) [owner]

Follows the US federal calendar. Observed dates are shown when the holiday falls on a weekend.

| Holiday | 2026 | 2027 |
|---|---|---|
| New Year's Day | Thu 2026-01-01 | Fri 2027-01-01 |
| Martin Luther King Jr. Day | Mon 2026-01-19 | Mon 2027-01-18 |
| Presidents' Day | Mon 2026-02-16 | Mon 2027-02-15 |
| Memorial Day | Mon 2026-05-25 | Mon 2027-05-31 |
| Juneteenth | Fri 2026-06-19 | Fri 2027-06-18 (observed) |
| Independence Day | Fri 2026-07-03 (observed) | Mon 2027-07-05 (observed) |
| Labor Day | Mon 2026-09-07 | Mon 2027-09-06 |
| Columbus / Indigenous Peoples' Day | Mon 2026-10-12 | Mon 2027-10-11 |
| Veterans Day | Wed 2026-11-11 | Thu 2027-11-11 |
| Thanksgiving | Thu 2026-11-26 | Thu 2027-11-25 |
| Christmas Day | Fri 2026-12-25 | Fri 2027-12-24 (observed) |

Dates for the day after Thanksgiving and Christmas Eve are commonly quiet but are not designated holidays (assumption). Ireland, the UK and Canada observe different public holidays; TODO if needed.

### 4c. Change freeze [owner]

Change freeze applies to the **last weekend of each month**: from Saturday 00:00 to Sunday 23:59 Eastern, starting on the last Saturday of the month (assumption on exact boundaries).

| Month | Freeze weekend (Saturday - Sunday) |
|---|---|
| Nov 2026 | 2026-11-28 - 2026-11-29 |
| Dec 2026 | 2026-12-26 - 2026-12-27 |
| Jan 2027 | 2027-01-30 - 2027-01-31 |
| Feb 2027 | 2027-02-27 - 2027-02-28 |
| Mar 2027 | 2027-03-27 - 2027-03-28 |
| Apr 2027 | 2027-04-24 - 2027-04-25 |
| May 2027 | 2027-05-29 - 2027-05-30 |
| Jun 2027 | 2027-06-26 - 2027-06-27 |
| Jul 2027 | 2027-07-31 - 2027-08-01 |
| Aug 2027 | 2027-08-28 - 2027-08-29 |
| Sep 2027 | 2027-09-25 - 2027-09-26 |
| Oct 2027 | 2027-10-30 - 2027-10-31 |
| Nov 2027 | 2027-11-27 - 2027-11-28 |
| Dec 2027 | 2027-12-25 - 2027-12-26 |

### 4d. Scheduled jobs and maintenance [owner]

| Job | Schedule | Hosts / accounts | Expected activity |
|---|---|---|---|
| Backup jobs | Nightly at 02:00 UTC (21:00 Eastern the previous evening in EST, 22:00 in EDT) | Backup servers: BACKUP01 VM; VM backup proxy 10.0.20.15 (`svc_vmbackup`) | VM snapshot create and remove, bulk reads of whole VM disks from the ESXi hosts, large transfers, service-account logons |
| Network-config backup | Nightly at 02:00 UTC | `svc_netbackup` from 10.1.5.20 (BACKUP01) | `show running-config` or config export on firewalls |
| SNMP polling | Continuous | 10.0.30.40 to 8 network devices over UDP/161 | Constant low-volume SNMP |
| Patching / maintenance windows | TODO | TODO | TODO |
| On-call rotation | TODO | TODO | TODO |

Backups run every night, including freeze weekends and holidays, and are expected then; configuration changes are not. The 02:00 UTC start falls in the evening Eastern time, outside working hours, so backup activity is the main expected off-hours activity on the backup hosts.

**How to use this:** Convert event time to US Eastern before judging whether it is "off hours". Activity outside 07:00-18:00 Eastern on weekdays, on weekends, or on a holiday is unexpected unless it belongs to a job in 4d or an on-call response. Any configuration change on a freeze weekend should be reported with who made it and whether an emergency change was approved (TODO: emergency change process).

---

## 5. Identity and accounts

| Item | Value |
|---|---|
| Corporate email / UPN domain | examplecorp.com (assumption for UPN) |
| AD domain | EXAMPLECORP / examplecorp.local |
| Okta org / Entra tenant names | TODO |
| Username format | `<first initial>.<lastname>`, for example `a.tucker`; a numeric suffix resolves collisions (`a.cox2`, `w.shah2`); apostrophes are kept (`j.o'brien`). Email is `<username>@examplecorp.com`. |
| Demo / legacy usernames | Some modules use a smaller set of short usernames such as `jsmith`, `mjohnson`, `alee`, `bwilliams`, `cbrown`, `dtaylor`, `ewhite`, `fmartin`, `gjackson`, `hthompson`, `j.doe`, `a.smith`, `b.jones`. Treat them as employees. |
| Device hostname format | `<DEPT>-LT-nnn` (laptop), `<DEPT>-WS-nnn` (workstation), `<DEPT>-HM-nnn` (home/remote device), `<FIRST INITIAL><SURNAME>-<MODEL>` (mobile). The department prefix identifies the owning team; see section 5e for every prefix. |
| Admin account naming | Network admins `netadmin.<user>`; shared team account `fw_ops` |
| Service account naming | `svc_<purpose>`, for example `svc_netbackup`, `svc_vmbackup`, `svc_vcenter` |
| Devices modeled | 303 laptops, 263 workstations, 362 mobile, 156 home devices |
| Contractor / vendor policy | TODO |
| Dormant account definition | TODO |
| Leaver process | TODO |

### 5a. Departments and roles

| Department | Users | Subnet | Representative roles |
|---|---|---|---|
| Engineering | 75 | 192.168.20.0/24 | Software Engineer, Staff Engineer, Principal Engineer, Engineering Manager, Intern SWE |
| Sales | 50 | 192.168.10.0/24 | Account Executive, BDR, Sales Engineer, Regional Manager |
| IT | 37 | 192.168.60.0/24 | IT Administrator, Systems Administrator, Cloud Administrator, Network Engineer, Systems Engineer, Help Desk, IT Director |
| DevOps | 33 | 192.168.100.0/24 | DevOps Engineer, SRE, Cloud Architect, Platform Engineer, Infrastructure Lead |
| Marketing | 31 | 192.168.30.0/24 | Marketing Manager, Content Strategist, Brand Designer |
| Finance | 31 | 192.168.50.0/24 | Controller, Finance Director, Accounts Payable, Financial Analyst |
| Operations | 31 | 192.168.70.0/24 | Operations Manager, Process Engineer, Supply Chain Lead |
| Customer Success | 31 | 192.168.120.0/24 | Customer Success Manager, Renewal Manager, CS Director |
| Support | 31 | 192.168.140.0/24 | Support Engineer, Tier 2 Support, Technical Writer |
| Procurement | 31 | 192.168.150.0/24 | Procurement Director, Vendor Manager, Purchasing Manager |
| Security | 28 | 192.168.90.0/24 | CISO, SOC Analyst, Incident Responder, Threat Hunter, Security Engineer, GRC Analyst |
| Data Science | 28 | 192.168.110.0/24 | Data Scientist, ML Engineer, Data Engineer |
| Product | 27 | 192.168.130.0/24 | Product Manager, Product Director, UX Researcher |
| HR | 22 | 192.168.40.0/24 | HR Director, Recruiter, Compensation Analyst, HRIS Analyst |
| Legal | 15 | 192.168.80.0/24 | Senior Counsel, Corporate Counsel, Legal Director, Paralegal |

Behavior is correlated by department: users in one department tend to visit similar destinations and move similar volumes, so a user who deviates from their department peers is more notable than one who matches them.

### 5b. VIP and privileged accounts

**VIP by title (executive / leadership / sensitive roles):**

| Title | Department | Accounts |
|---|---|---|
| CISO | Security | g.strand, k.freeman, s.kwon, j.mcdonald, l.coleman |
| IT Director | IT | a.reed, s.ferreira, j.ahmed2 |
| Controller | Finance | x.hayashi, w.shah2, r.park, j.mcintosh, s.green, f.grant |
| Finance Director | Finance | i.nielsen, e.shin, d.magnusson |
| HR Director | HR | d.greco, j.perez, p.griffin |
| Legal Director / Counsel | Legal | k.christensen, n.hughes, w.dubois, k.jung, p.gray, w.appiah, s.morgan, i.turner, s.klein, y.castillo |
| Procurement Director | Procurement | d.snyder, j.kwon, m.mcdonald, b.alves, d.lambert, m.watanabe, r.omar |
| Customer Success Director | CustomerSuccess | c.reed, e.ahmed, s.young, y.perry |
| Product Director | Product | g.cruz, m.butler, d.warren |

**Privileged by role (IT infrastructure):**

| Role | Accounts |
|---|---|
| IT Administrator | a.leroy, c.kato, m.eriksson, e.rivera |
| Systems Administrator | j.howard |
| Systems Engineer | a.reyes, r.wells, s.russo, c.ford, e.oh |
| Cloud Administrator | i.mensah, b.sanders, j.thomas |
| Network Engineer | a.cox2, m.bennett, h.roberts, r.marino, d.howard, a.petit, j.fox, b.lawson |

**Network and firewall administrators:** `netadmin.jlee`, `netadmin.pkhan`, `netadmin.rortiz`, `fw_ops` (expected only from 10.0.30.0/24). FortiGate admins: `admin`, `f_admin_01`, `sec_ops`, `root`, `netops_svc`. Infoblox admins: `infoadmin`, `noc-user`, `soc-analyst`. ESXi administrators: `root`, `svc_vcenter`, `vmadmin`.

**Cloud access:** 167 of 501 users have an AWS IAM user. By department: Engineering 55, Security 27, DevOps 23, IT 21, Data Science 17, Product 7, Sales 4, Marketing 3, Operations 3, Support 3, Customer Success 2, HR 1, Procurement 1. No users are mapped to Google Cloud IAM users.

### 5c. Service accounts

| Account | Purpose | Expected source | Expected targets | Interactive logon expected? |
|---|---|---|---|---|
| svc_netbackup | Network device config backup | 10.1.5.20 | Firewalls (show running-config / config export) | No |
| svc_vmbackup | VM backup | 10.0.20.15 | ESXi hosts (snapshots, NFC disk reads) | No |
| svc_vcenter | vCenter management of ESXi | vcenter 10.0.20.20 | ESXi hosts | No |
| vpxuser | vCenter's built-in account on ESXi hosts | vCenter | ESXi hosts | No |
| netops_svc | Network operations | TODO | FortiGate | No |
| svc_app_01 | Application service account | TODO | Okta-protected apps | No |
| Google Cloud service accounts | terraform-runner, gke-node-sa, ci-cd-deployer, data-pipeline-sa, monitoring-agent | Cloud | GCP project | No |

### 5d. Disabled, former and break-glass accounts

| Account | State | Meaning of a logon attempt |
|---|---|---|
| svc_legacy | Disabled (ESXi) | Attempt against a disabled account; investigate |
| auditor | Disabled (ESXi) | Attempt against a disabled account; investigate |
| jdoe | Deleted / offboarded | Attempt looks like an unknown user; likely stale credentials or probing |
| contractor1 | Deleted / offboarded | As above |
| tempadmin | Deleted / offboarded | As above |
| Break-glass accounts | TODO | Any use should be reviewed |

**How to use this:** A VIP or privileged account acting from outside its normal source, a service account with an interactive logon, or any use of a disabled, former or break-glass account warrants escalation. Administrative protocols should originate from the jump hosts.

### 5e. Device naming by department

Every employee device is named after the department that owns it, so a hostname tells you the team, the device class and the expected subnet. Hostnames are upper case and unique (except one mobile-name collision, below). Windows events show them as fully qualified names, for example `MKT-LT-001.examplecorp.local`.

**Format**

| Device class | Hostname pattern | Example | Where it connects from |
|---|---|---|---|
| Office laptop | `<PREFIX>-LT-nnn` | `MKT-LT-001`, `HR-LT-014` | Its department's office subnet (section 5a), through the office NAT pool |
| Office workstation | `<PREFIX>-WS-nnn` | `ENG-WS-038`, `SUP-WS-004` | Its department's office subnet |
| Home / remote device | `<PREFIX>-HM-nnn` | `SALES-HM-012`, `HR-HM-003` | Home subnet 172.16.100.0/24 (home ISP addresses, VPN or Zscaler) |
| Mobile phone | `<FIRST INITIAL><SURNAME up to 8 characters>[2]-<MODEL>` | `AGREEN-PIXEL7`, `CDOYLE2-GALAXYS24`, `LO'BRIEN-PIXEL8` | Mobile subnet 10.10.50.0/24 |

- `nnn` is a three-digit sequence number starting at 001 and counted separately for each prefix and class (`MKT-LT-001` to `MKT-LT-031`; `MKT-HM-001` to `MKT-HM-008`). There are no gaps.
- Each user has one primary office device (a laptop, or a workstation in the technical departments). 84 of the 501 users have only that device; the others also have a mobile phone, a home device, or both. Technical departments (Data Science, DevOps, Engineering, IT, Security) give some users both a workstation and a laptop.
- Mobile names are built from the username: first initial plus the surname cut to 8 characters (`JHAMILTO` for j.hamilton). Apostrophes are kept (`LO'BRIEN`, `AO'BRIEN`). A trailing `2` marks the second user with the same name (`WSHAH2`, `ACOX2`). The model is `IPHONE` (optionally 12, 13, 13PRO, 14, 15, 15PRO), `PIXEL` (PIXEL8), `PIXELFOLD`, `GALAXYS` (GALAXYS24), `GALAXYULTRA` or `ONEPLUS` (ONEPLUS12). iPhones run iOS; every other model runs Android.
- Counts: 303 laptops, 263 workstations, 156 home devices, 362 mobile (180 iOS, 182 Android). Home devices run Windows (74), macOS (62) and Ubuntu (20).
- Ubuntu endpoints exist only in Data Science, DevOps, Engineering and Security. Every other department uses Windows and macOS only.
- Collision: `LHANSEN-IPHONE12` is the mobile name of both l.hansen (Support) and la.hansen (Finance).

**Prefixes by department**

| Department | Prefix | Users | Laptops `<P>-LT-nnn` | Workstations `<P>-WS-nnn` | Home `<P>-HM-nnn` | Mobile | Endpoint OS mix (laptops + workstations) | Endpoint subnet |
|---|---|---|---|---|---|---|---|---|
| Customer Success | `CS-` | 31 | 31 | - | 11 | 20 | Windows 21, macOS 10 | 192.168.120.0/24 |
| Data Science | `DS-` | 28 | 9 | 28 | 5 | 23 | Ubuntu 17, macOS 13, Windows 7 | 192.168.110.0/24 |
| DevOps | `DEVOPS-` | 33 | 13 | 33 | 7 | 27 | Ubuntu 19, Windows 15, macOS 12 | 192.168.100.0/24 |
| Engineering | `ENG-` | 75 | 24 | 75 | 25 | 52 | Windows 36, macOS 34, Ubuntu 29 | 192.168.20.0/24 |
| Finance | `FIN-` | 31 | - | 31 | 10 | 23 | Windows 22, macOS 9 | 192.168.50.0/24 |
| HR | `HR-` | 22 | 22 | - | 8 | 14 | Windows 15, macOS 7 | 192.168.40.0/24 |
| IT | `IT-` | 37 | 9 | 37 | 5 | 25 | Windows 32, macOS 14 | 192.168.60.0/24 |
| Legal | `LEG-` | 15 | 15 | - | 5 | 11 | Windows 9, macOS 6 | 192.168.80.0/24 |
| Marketing | `MKT-` | 31 | 31 | - | 8 | 19 | Windows 19, macOS 12 | 192.168.30.0/24 |
| Operations | `OPS-` | 31 | 31 | - | 9 | 26 | Windows 24, macOS 7 | 192.168.70.0/24 |
| Procurement | `PROC-` | 31 | 31 | - | 11 | 22 | Windows 21, macOS 10 | 192.168.150.0/24 |
| Product | `PROD-` | 27 | 27 | - | 8 | 20 | Windows 17, macOS 10 | 192.168.130.0/24 |
| Sales | `SALES-` | 50 | 50 | - | 27 | 34 | macOS 27, Windows 23 | 192.168.10.0/24 |
| Security | `SEC-` | 28 | 10 | 28 | 12 | 21 | macOS 17, Windows 11, Ubuntu 10 | 192.168.90.0/24 |
| Support | `SUP-` | 31 | - | 31 | 5 | 25 | Windows 26, macOS 5 | 192.168.140.0/24 |

**How to use this:** Read the prefix to find the owning department, then compare the department with the connection. A `HR-` or `FIN-` device that appears on another department's subnet, an office device on the home or mobile subnet, or a device used by someone other than its department's staff deserves a closer look. Servers do not follow this pattern (section 6).

---

## 6. Assets and hostnames

### 6a. Servers and roles

| Host | Role | Address | Notes |
|---|---|---|---|
| DC01.examplecorp.local | Domain controller | 10.0.10.10 | Also an ESXi VM named DC01 |
| DC02.examplecorp.local | Domain controller | 10.0.20.10 | Domain controller only (the SNMP poller moved to 10.0.30.40; no longer listed as a database server) |
| fileserver.examplecorp.local | File server (DNS name) | 10.0.20.30 | Alias for FS01; no longer shares an address with the web farm |
| FS01 / FS02 (also written FS-01, FS-02) | File servers named in Windows events | 10.0.20.30 / 10.0.20.31 (simulator assignment, owner to confirm) | SMB shares and Kerberos service names `cifs/fs01` and `cifs/fs02.examplecorp.local`; see the share list below |
| FILE01 | File server | 10.0.20.32 (simulator assignment, owner to confirm) | ESXi VM |
| SQL01 | SQL Server | 192.168.1.101 (DNS) | ESXi VM; see 6a-1 |
| WEB01 | Web server | TODO | ESXi VM |
| APP01 | Application server | 10.0.20.16 (DNS) | ESXi VM; see 6a-1 |
| EXCH01 | Exchange server | 10.0.20.40 (DNS name `exchange`) | ESXi VM; see 6a-1 |
| BACKUP01 | Backup server | 10.1.5.20 (DNS) | ESXi VM; backup jobs run nightly at 02:00 UTC |
| esxi01 / esxi02 / esxi03 .corp.examplecorp.local | VMware ESXi hosts | TODO | Managed by vCenter 10.0.20.20; datastores `datastore1`, `ds-prod-nfs01`, `ds-vsan-01` |
| vcenter.corp.examplecorp.local | vCenter Server | 10.0.20.20 | |
| www.examplecorp.com | Public web farm | 10.0.10.50, .51, .52 | Apache, TCP 443; these addresses answer no internal DNS name |
| Database servers | Application databases | 10.0.20.11-14, 172.16.50.5-7, 192.168.5.10-11, 10.1.100.10-11, 10.100.10.10-11, 172.17.20.20, 172.18.30.30, 192.168.50.50, 10.0.100.100-101, 172.31.50.50 | Plus names such as prod-rds-instance-1, dev-mysql-server, analytics-redshift, legacy-oracle-db, finance-postgres-db |

**File server shares.** Named in Windows events: `\\FS-01\Finance` (Budgets, Payroll), `\\FS-01\HR\Personnel`, `\\FS-01\Legal\Contracts`, `\\FS-02\Engineering\Designs`. The generic shares on each file server are `Shared`, `Departments` and `Home$` (data on D:), and `Backups` on the backup server (E:). Access to Finance, HR and Legal shares is expected only from those departments' endpoint subnets (section 2).

**File-server traffic as the firewalls see it.** The firewalls (ASA, Firepower, FortiGate, Check Point, Palo Alto) record routine workstation SMB (TCP 445) and FTP to the three file servers only: FS01 10.0.20.30, FS02 10.0.20.31 and FILE01 10.0.20.32. Palo Alto also sends about 30% of its routine SMB to the domain controllers (SYSVOL/NETLOGON). SMB to any other server, to a workstation, or to a file server the user has never used, is the signal.

**ESXi hosts: expected administrators and commands.** Administrative logons to ESXi come from `svc_vcenter`/`vpxuser` (vCenter), `svc_vmbackup` (backup proxy), the ops jump hosts, and the local console (127.0.0.1). Routine shell commands are common `esxcli` and `vim-cmd` queries (listing, status, get). Turning SSH or the ESXi Shell on and off for maintenance is routine and is normally followed by turning it off again. Uncommon commands are anything that adds accounts, disables the firewall, clears or redirects syslog, loads kernel modules, installs unsigned VIBs, or stages tooling or an encryptor on the host. TODO: list the named people who administer ESXi.

### 6a-1. Server names in internal DNS (Infoblox, examplecorp.local)

| DNS name | Address | Notes |
|---|---|---|
| dc01 | 10.0.10.10 | Domain controller |
| dc02 | 10.0.20.10 | Domain controller |
| dc03 | 10.1.5.10 | Additional DC name in the zone |
| dc04 | 192.168.1.10 | Additional DC name in the zone |
| dc05 | 172.16.10.10 | Additional DC name in the zone |
| ad | 10.0.10.10, 10.0.20.10 | `ad.examplecorp.local`, an alias for the first two DCs |
| fs01 / fileserver | 10.0.20.30 | File server; `fileserver` is an alias |
| fs02 | 10.0.20.31 | File server |
| file01 | 10.0.20.32 | File server |
| exchange | 10.0.20.40 | |
| sharepoint | 10.0.20.41 | |
| vcenter | 10.0.20.20 | Matches the ESXi configuration |
| sql01 | 192.168.1.101 | |
| print01 | 10.0.20.50 | |
| app01 | 10.0.20.16 | |
| backup01 | 10.1.5.20 | |
| radius | 10.1.5.21 | |
| infoblox-dc1-01 / infoblox-dc2-01 | 10.1.1.2 / 10.1.1.3 | DNS grid members |
| any other internal server | `srv-<a>-<b>-<c>-<d>.examplecorp.local` | For example `srv-172-31-10-10` for 172.31.10.10 |

**How to use this:** When a log names a host such as `fileserver` or `sql01`, this table gives the address the internal DNS returns for it.

### 6b. Security and scanning tooling

| Tool | Source IP / host | Schedule | Notes |
|---|---|---|---|
| Vulnerability scanner | TODO | TODO | Scan-like traffic is expected only from here |
| Authorized pentest / red team | TODO | TODO | Kali, Tor-like and scanning activity inside these windows is expected |
| EDR / agent management | TODO | TODO | |
| Security Operations team | Security department (SOC Analyst, Incident Responder, Threat Hunter) | Business hours (section 4a) | |

**How to use this:** Use host names and roles to judge criticality. Treat DC01, DC02, SQL01, FILE01, EXCH01, BACKUP01, the ESXi hosts, vCenter and the finance databases as critical.

---

## 7. Cloud estate

### 7a. AWS

| Item | Value |
|---|---|
| Account ID | TODO (not recorded in this file) |
| Primary region | us-east-1 |
| Allowed regions | us-east-1 (assumption); TODO others |
| Trusted cross-account IDs | TODO. Any other account ID assuming a role is unexpected. |
| IAM roles in routine use | EC2FullAccessRole, S3ReadOnlyRole, LambdaExecRole and similar |
| Service roles | Assumed only by AWS services (for example Lambda), never by a person's CLI session |
| Audit/security tooling | CloudTrail (for example `org-management-events-trail`, `security-audit-trail-central`), GuardDuty, Config, Security Hub. Owned by Security and IT; stopping or disabling any of them is unexpected. |
| Example sensitive resources | `finance-reports-q4-2025`, `prod-customer-data-us-east-1` (S3); `finance-db-secure`, `hr-db-encrypted`, `prod-db-main-instance` (RDS) |
| Buckets allowed to be public | TODO. `web-static-content-cdn` and `marketing-assets-prod` look intended for public content; confirm. |

### 7b. Google Cloud

| Item | Value |
|---|---|
| Project ID | TODO (placeholder in telemetry) |
| Organization ID | 123456789012 |
| Allowed regions | us-central1, us-east1, us-west1, europe-west1, asia-east1 |
| Service accounts | terraform-runner, gke-node-sa, ci-cd-deployer, data-pipeline-sa, monitoring-agent |
| Compute | prod-web-01, prod-web-02, prod-api-01, dev-workstation-01, bastion-host-01, db-replica-01 |
| GKE clusters | prod-cluster-us-central1, dev-cluster-us-central1 |
| Buckets | `<project>-backups`, `<project>-artifacts`, `<project>-logs`, `<project>-public-assets` (the last looks intended to be public) |
| BigQuery datasets | analytics_prod, data_warehouse, ml_features, audit_logs |
| Log sinks | export-to-bq-audit, export-to-storage-compliance, pubsub-siem-export (feeds XSIAM) |
| Who may modify sinks / Security Command Center / IAM policy | TODO |

### 7c. Microsoft Entra / Microsoft 365 / Azure

| Item | Value |
|---|---|
| Tenant name / ID | TODO |
| Subscriptions and purpose | TODO |
| Office-based sign-ins | From the user's own office pool (section 1) |
| Identity data path | Reaches XSIAM through Event Hub and Graph activity |

**How to use this:** An AssumeRole from an unlisted account, activity in an unlisted region, creation of a public bucket other than the allowed ones, or a change to audit or security tooling by someone not responsible for it is unexpected. Changes to the `pubsub-siem-export` sink also affect XSIAM's own visibility.

---

## 8. Data sensitivity

| Data class | Examples | Where it lives | Who handles it | Allowed to leave via |
|---|---|---|---|---|
| Financial | Finance reports, payroll, AP/AR | Finance databases, `finance-reports-*` bucket, Finance endpoints (192.168.50.0/24) | Finance | Authorized upload sites only (section 3a) |
| HR / personnel | Employee records, compensation | `hr-db-encrypted`, HR endpoints (192.168.40.0/24) | HR | Authorized upload sites only |
| Customer data | Customer records and portal data | `prod-customer-data-us-east-1`, customer databases | Engineering, Customer Success, Support | TODO |
| Legal / contracts | Contracts and counsel work product | Legal endpoints (192.168.80.0/24), SharePoint | Legal | Authorized upload sites only |
| Source code / secrets | Repositories, credentials, keys | GitHub / GitLab, secret stores | Engineering, DevOps | TODO |

| Item | Value |
|---|---|
| DLP policy names | TODO |
| Sensitive SharePoint sites | TODO |
| Classification scheme | TODO |

**How to use this:** Weigh the sensitivity of the data class heavily when judging an upload, download or share, and treat anything outside the "Allowed to leave via" column as a finding.

---

## 9. Log sources and detection notes

### 9a. Log source map

Dataset names were read from the tenant. The `_vendor` / `_product` columns on each row identify the feed. "Raw" datasets hold the feed as ingested; XSIAM's modeling rules map them into XDM.

| Source | Dataset(s) | `_vendor` / `_product` | Ingest path | Notes |
|---|---|---|---|---|
| Cisco ASA (ASA-FW-01) | `cisco_asa_raw` | Cisco / ASA | Broker syslog, TCP 1514 | The ASA never sets a Deny action in the action field. Management-plane messages (admin login, config, SNMP) are in the same dataset. |
| Cisco Firepower (DC1-FTD-01) | `cisco_firepower_raw` | Cisco / Firepower | CEF | Event name is carried in `cefName`. Device administration arrives as Cisco syslog (`%FTD-...`), not CEF. |
| Palo Alto NGFW (PA-VM-01) | Traffic: `panw_ngfw_traffic_raw`; URL: `panw_ngfw_url_raw`; threat: `panw_ngfw_threat_raw`; files: `panw_ngfw_filedata_raw`; system: `panw_ngfw_system_raw`; config: `panw_ngfw_config_raw`; CEF: `panw_ngfw_cef_raw` | PANW / `NGFW_CEF` for CEF-format events; PANW / `NGFW` for rows from a non-CEF PAN-OS source | CEF to the Broker Syslog Collector, port 514 | Routing depends on `__firewall_type`; timestamps cannot be back-dated. Both products appear in the traffic and URL datasets. |
| Check Point (CP-FW-1) | Firewall and SNMP: `check_point_vpn_1_firewall_1_raw`; identity: `check_point_identity_awareness_raw`; admin audit (SmartConsole): `check_point_smartconsole_raw`; IPS: `check_point_smartdefense_raw`; URL: `check_point_url_filtering_raw`; app control: `check_point_application_control_raw` | Check Point / (FireWall-1, Identity Awareness, SmartConsole, SmartDefense, URL Filtering, Application Control) | TODO | SmartConsole audit records are raw-only: no modeling rule, so use them for hunts and correlation rules, not XDM queries. |
| Fortinet FortiGate (FG-FW-01) | `fortinet_fortigate_raw` | Fortinet / Fortigate | CEF syslog through the Broker | Admin events use FortiOS log IDs such as 0100032001 (login) and 0100032143 (backup by SCP). |
| Zscaler web gateway | Web: `zscaler_nssweblog_raw`; firewall: `zscaler_nssfwlog_raw` | Zscaler / `NSSWeblog`, `NSSFWlog` | NSS CEF | |
| Proofpoint email | `proofpoint_tap_raw` | proofpoint / tap | HTTP collector | Message and click events. Mailbox content records are in `msft_o365_emails_raw` (msft / o365_emails). |
| Infoblox NIOS (dc1/dc2) | `infoblox_infoblox_raw` | infoblox / infoblox | Broker syslog, port 1516 | One dataset holds all DNS, DHCP, audit, RPZ and Threat Protect events. There are no separate DNS or DHCP datasets. `infoblox_nios_raw` exists but is essentially unused. |
| Apache (www.examplecorp.com) | `apache_httpd_raw` | apache / httpd | Broker syslog, port 1515 | Access and error logs. |
| VMware ESXi (3 hosts) | `vmware_esxi_raw`; Virtualization Stories: `virtualization_data` | Vmware / Esxi | Broker syslog, Raw format, port 1518 | Plain syslog, not CEF. The Marketplace pack supplies parsing. Only uncommon-command analytics apply. A host is quiet; routine events are sparse. |
| Okta SSO | `okta_sso_raw` | Okta / Sso | HTTP collector | |
| Windows event logs | `microsoft_windows_raw`; normalized copy in `xdr_data` | microsoft / windows | Windows Event Collector (WEC) | Domain EXAMPLECORP. `_raw_log` is Windows event XML, so extract fields with `regextract(_raw_log, "Name='<Field>'>([^<]+)<")`. Cloud and on-premises identity are separate planes. |
| AWS | `amazon_aws_raw` | Amazon / AWS | S3 | CloudTrail and related audit logs. |
| Google Cloud | `google_cloud_logging_raw` | Google / Cloud Logging | Pub/Sub, topic `xsiam-audit-logs` | |
| Entra sign-ins | `msft_azure_ad_raw` | msft / Azure AD | Cribl (Graph `auditLogs/signIns`) | Never reaches `cloud_audit_logs`. |
| Entra directory audit | `msft_azure_ad_audit_raw` | msft / Azure AD | Cribl (Graph `auditLogs/directoryAudits`) | |
| Entra via Office 365 | `msft_o365_azure_ad_raw` | msft / O365 Azure AD | Office 365 Management Activity (`Audit.AzureActiveDirectory`) | Sign-ins (record type 15) and directory operations. |
| Azure Event Hub | `msft_azure_raw` | MSFT / Azure | Event Hub | Azure Activity log, Microsoft Graph activity logs, and Entra diagnostics (provisioning, risk events). This is the path that feeds `cloud_audit_logs`. |
| Azure Kubernetes Service | `msft_azure_aks_raw` | MSFT / Azure | Event Hub (assumption) | AKS audit logs. |
| Exchange Online | `msft_o365_exchange_online_raw` | msft / O365 Exchange Online | Office 365 Management Activity | Mailbox audit and admin events. |
| SharePoint / OneDrive | `msft_o365_sharepoint_online_raw` | msft / O365 Sharepoint Online | Office 365 Management Activity | File operations and sharing. This is where uploads to corporate OneDrive appear. |
| Microsoft 365 DLP | `msft_o365_dlp_raw` | msft / O365 DLP | Office 365 Management Activity | DLP rule matches. |
| Microsoft 365 general | `msft_o365_general_raw` | msft / O365 General | Office 365 Management Activity | Copilot and Power BI. |

**How to use this:** Pick the dataset from this table before writing a query. For example, an upload to corporate OneDrive is in `msft_o365_sharepoint_online_raw`, a web proxy upload is in `zscaler_nssweblog_raw`, and a firewall byte count is in the firewall's own dataset. Use `_vendor` and `_product` to separate the CEF PAN source from other PAN-OS rows.

---

## 10. Response process

| Item | Value |
|---|---|
| Security Operations staffing | Security department: SOC Analyst, Incident Responder, Threat Hunter, Security Analyst, Security Engineer, Threat Intelligence Analyst, GRC Analyst; led by a CISO |
| Severity definitions | TODO |
| SLAs per severity | TODO |
| Escalation contacts by system | TODO |
| Ticketing system | TODO. ServiceNow, Freshservice, Jira and PagerDuty are integrated with Okta. |
| Approved automated response actions | TODO |
| Actions needing approval first | TODO (for example isolating a VIP endpoint or disabling an executive account) |
| Auto-close criteria | TODO |

**How to use this:** Recommend only approved response actions; name the approver for any action that needs approval.

---

## 11. Decision rules

- Convert event time to US Eastern. Weekday activity between 07:00 and 18:00 Eastern is normal; weekends, US holidays and nights are not, unless a scheduled job in 4d or an on-call response explains them.
- Nightly backup activity at about 02:00 UTC (VM snapshots, whole-disk reads, large service-account transfers on the backup hosts, config exports by `svc_netbackup`) is expected. The same activity from any other host or account, or at another time, is not.
- Any configuration change during the last weekend of the month is unexpected unless it is an approved emergency change.
- A source in section 1 is corporate. A source geolocated outside the countries with offices, or from Tor or a consumer VPN, is unexpected for an employee.
- An upload to a destination outside section 3a is unsanctioned. An upload to Box, examplecorp.box.com or corporate OneDrive is permitted, but large volumes of sensitive data (section 8) or personal-account use still need review.
- Administrative protocols (SSH, RDP, WinRM, SNMP, firewall management) from outside 10.0.30.0/24, or from a host other than the jump hosts, are unexpected.
- A service account with an interactive logon, or any use of a disabled, former or break-glass account, is unexpected.
- Scanning or tooling activity that matches a scheduled authorized scan or pentest (section 6b) is likely sanctioned; confirm with the owner.
- When the evidence cites only an IP, look it up in sections 1, 2 and 6 before drawing conclusions about the user, department or host role.
- When a fact is marked TODO, say that the file does not cover it instead of assuming.
