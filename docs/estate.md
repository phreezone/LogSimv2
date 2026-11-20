# The simulated estate (5,000 users)

`config.json` describes one company, ExampleCorp: its people, their devices, its offices and
its servers. Until 2026-11-19 it held 501 users. A one-off estate generator expanded it to
5,000 people with the department sizes, servers and applications a company of that size
would have. This page covers what the generator wrote, the config keys it added, and the
behaviour that depends on them.

The site and address details (subnets, DCs, server addresses, device counts) are tabled in
[xsiam-byok-knowledge.md](xsiam-byok-knowledge.md), sections 2, 5 and 6.

## What was kept stable

The tenant's analytics have weeks of baselines learned against the 501 original users, so
the expansion leaves them where they were:

- **Usernames, devices and device subnets** of the 501 are unchanged. New devices go into
  new /24s only, never into an existing one. That matters because a device's sticky IP is
  hashed modulo its subnet's size (`session_utils._sticky_ip`), so widening a /24 to a /21
  would have moved every address in it.
- **SIDs** are unchanged except for 18 users: 11 whose RID was already taken by another
  user (the old `1100 + hash % 8,900` scheme collides), and 7 whose RID sat in the
  training-student range 5000-5099. Those moved to RIDs 11000 and up. RIDs are now stored
  per user (`user_profiles.*.sid_rid`); new hires get sequential RIDs from 12000 in hire
  order.
- **Offices** are unchanged: each base user keeps the site the old department hash gave
  them, now written out as `user_profiles.*.office`.
- **Recurring and "stable" selections** (`recurring_host`, `stable_subset`,
  `stable_beacon_pairs`) draw from base users only, so the recurring pairs the tenant
  learned stay the same people.
- **Firewall destinations for base users** are unchanged: their SMB/FTP still goes to
  FS01/FS02/FILE01 and their LDAP/Kerberos to the five DC addresses the firewall modules
  always used.
- **Okta habitual apps** for base users are the same 3-5 apps as before (see Applications).

Changed on purpose:

- Three usernames contained an apostrophe and were renamed: `j.o'brien`, `l.o'brien` and
  `a.o'brien` became `j.obrien`, `l.obrien` and `a.obrien`. Their emails, device names and
  AWS IAM name changed with them. In the tenant they look like three new people.
- Every base user was re-titled onto a realistic ladder. The base had five CISOs, seven
  Procurement Directors and six Controllers; it now has one of each. A title change moves
  no IP or SID.
- `la.hansen`'s phone was renamed `LHANSEN2-IPHONE12`. It had shared `LHANSEN-IPHONE12`
  with `l.hansen`.

## People

| Department | Users | AWS | GCP |
|---|---|---|---|
| Engineering | 1,400 | 1,027 | 28 |
| Sales | 750 | 60 | 0 |
| Support | 500 | 48 | 0 |
| Customer Success | 450 | 29 | 0 |
| Operations | 350 | 34 | 0 |
| Marketing | 330 | 32 | 0 |
| Product | 230 | 60 | 0 |
| DevOps | 175 | 122 | 105 |
| IT | 175 | 99 | 61 |
| Finance | 175 | 0 | 0 |
| Data Science | 150 | 91 | 15 |
| HR | 140 | 6 | 0 |
| Security | 65 | 63 | 10 |
| Procurement | 60 | 2 | 0 |
| Legal | 50 | 0 | 0 |

- **Roles.** Each department has a fixed ladder (`LADDERS` in the generator): one head,
  about one manager per eight people, few senior titles, and interns only in Engineering,
  Data Science and Marketing. Titles that modules key on are kept verbatim: IT
  Administrator, IT Director, Systems Engineer, Security Engineer, Security Analyst, and
  the Azure operator titles in `azure_estate`. "Help Desk" is now "Help Desk Analyst" in
  both the data and the code.
- **Names.** First names come from Social Security Administration birth rankings for
  1980-2010, summed across the years. 70% come from the top 500 for the person's sex and
  30% from ranks 501-1000, weighted by popularity but capped at 10 people per name.
  Surnames come from the 2010 Census list: about 12% from the 150 most common (repeats
  capped at 3-8), the rest used once each. Everything is A-Z only. Irish O'- surnames,
  which the Census stores without the apostrophe ("Obrien"), are left out. A blocklist
  screens first names, surnames and the composed username, email and display name for
  vulgarity. The result has about 1,700 distinct first names and 4,400 distinct surnames.
- **Usernames** follow the base pattern: `f.lastname`, then `f.lastname2` on a collision.
- **Cloud access.** AWS: each department keeps the share of IAM users it had in the base
  estate. GCP: new on 2026-11-19, mainly IT and DevOps (`gcp_iam_user` = the user's email).
  GCP audit logs now name only these users as human principals; before, any roster user
  could appear, HR and Legal included.

## Devices

New hires get the same mix per department as the base users: the department's primary
device type and OS split, its second-laptop rate and its home-device rate. They get **no
phones**. A new hire therefore never shows a mobile device, a mobile Entra sign-in or
carrier egress (`azure_common.has_phone`). Base users keep their phones, mobile sign-ins
included.

Office devices go into the department's block `192.168.D0.0/24` to `192.168.D9.0/24`,
skipping `192.168.12-15.0/24`, which `zscaler._RDP_RARE_SERVER_NETS` keeps quiet. Home
devices go into `172.20.0.0/21`, outside `internal_networks`.

`internal_networks` does not list the user subnets, and should not. Every module uses it
as the pool for *random* "other internal host" addresses (rare destinations, sweep targets,
DHCP filler). A user subnet in it would let those random picks land on real people's
sticky IPs.

## Onboarding: new hires join over 90 days

`user_profiles.*.start_date` marks a pre-provisioned new hire. Before that date the account
exists in the directory and in `config.json`, but nothing draws it for activity:

- `session_utils.pickable_users()` (behind `get_random_user`) skips it.
- `azure_common.lifecycle_cohort()` returns `pending`, so `pick_user`, `pick_by_role` and
  the cohort pools skip it.
- The Windows module gives its workstation no events.

The 4,499 hires start about 50 a day from 2026-11-21 to 2027-02-18, so the estate keeps
gaining genuinely first-seen users, hosts and app pairs for three months. The caches behind
these checks refresh each UTC day, so a long-running simulator picks up each day's hires
without a restart.

To make everyone active at once, set `user_behavior.onboarding.enabled` to `false`.

## Sites and servers

- **Offices.** New hires are spread across the ten sites by size (Columbus 25%, Austin and
  New York 12% each, ... Dublin and Toronto 5% each); see `sites` in the config.
- **Domain controllers.** `domain_controller_hosts` lists DC01-DC16 with their sites.
  `domain_controllers` still lists only the five original addresses, so base-estate
  firewall traffic is unchanged. A new hire's Windows DC events name their site's DC
  (`session_utils.site_dc`; the workstation worker sets it per host). Their LDAP/Kerberos
  in the firewall modules goes to their site's DC addresses
  (`resolver.domain_controllers_for`).
- **File servers.** `file_servers` is still FS01/FS02/FILE01. `file_server_sites` adds
  FS03-FS14 by site. A new hire's SMB/FTP goes to their own site's servers
  (`resolver.file_servers(config, src_ip)`).
- **Other servers.** The generator added 104 servers: 11 new DCs (DC06-DC16) and 93
  member servers, among them AD FS and its proxies, Entra Connect,
  a PKI, NPS, DHCP, WSUS and SCCM with a distribution point per site, SQL, Exchange and
  SharePoint nodes, application and web servers, backup, a second vCenter, KMS and
  monitoring. It also added 21 more ESXi hosts, 24 in total. Every new server is
  appended to `internal_servers` (earlier indices stay stable) and named in
  `server_roles`, so DNS and firewall names agree.

## Applications

`okta_config.okta_sso_apps` grew from 101 to 350 apps. `okta_config.app_entitlements` maps
apps to people: every user gets `core`, their department's list and 1-3 `optional` picks,
fixed per user (`okta_sso.user_apps`). Benign SSO picks one of the user's 3-5 habitual apps
80% of the time and another assigned app the rest of the time.

Before entitlements, that remaining 20% was any app in the tenant. Over a week every user
reached every app, so "first access to an application" had nothing to find. An app outside
a user's assignments is now genuinely new for them. Base users' habitual apps are computed
over the first `legacy_app_count` apps exactly as before, so their baselines carry over.

`okta_sso._RARE_SSO_APPS`, the decommissioned and sandbox apps that threats reach for,
grew from 8 to 40.

## Windows endpoint cap

At 5,000 users there are about 2,600 Windows workstations. With one always-on worker each,
the module's events/s were spread so thin that no host built a baseline, at a cost of one
thread per machine. `windows_events_config.endpoint_cap` bounds this:

```json
"endpoint_cap": {"active": 800, "core": 500}
```

- **Core.** The first 500 hosts generate every day: all 265 base-estate workstations,
  then new hires' machines in start-date order. Each core host is idle until its user
  starts.
- **Rotation.** The other 300 worker slots take a different deterministic draw each UTC
  day from the remaining hosts whose users have started. A machine outside today's draw
  is simply off, as real machines are, and comes back on a later day.
- **Disabling.** `active: 0` turns the cap off: one worker per host, as before.

Total Windows volume is still set by the dashboard rate (`_BENIGN_RATE`) and
`wks_interval_multiplier`. The cap only decides how many hosts share it.

## Re-running the generator

The generator is a local tool and is not in the repository. It lives in the git-ignored
`_local_validation/estate_generator.py`, alongside the other local validation scripts.
It refuses to run on an expanded config: it checks for the `_estate_generator` marker and
exactly 501 users. To rebuild, restore the 501-user `config.json` from git history and run:

```bash
python _local_validation/estate_generator.py --names-dir <dir> --report estate_report.md
```

`<dir>` must hold `ssa_1980_2010_male.txt`, `ssa_1980_2010_female.txt` and
`Names_2010Census.csv`; the generator's docstring says where each comes from. Neither is
committed. The output is deterministic for a given seed and name files.
