# Value cardinality: why pools are generated, and what may never change

## The problem

Every value the simulator draws from a fixed list in `config.json` stops being rare
the moment the run is long enough. A 25-entry pool can make a domain rarely
*picked*; it cannot make it *rare*. Over a week every entry accumulates thousands
of hits and UEBA learns it as normal, so the detections that depend on novelty --
"never-seen host", "rare destination", "file-name cardinality", "new C2
infrastructure" -- have nothing left to fire on.

Rarity has to come from **cardinality**, not from weighting. That principle already
drove `modules/domain_corpus.py` for benign browsing; these two modules apply it to
the threat half and to file names.

| Pool | Before | After |
|---|---|---|
| `infoblox_threats.malicious_domains` | 25 fixed | generated, ~850 distinct per 1,000 draws |
| `infoblox_threats.dga_domains` | 25 fixed | generated, >99% distinct |
| `firepower_config.malicious_dns_domains` | **3 fixed** | generated (`malware_distro` / `c2`) |
| `firepower_config.malicious_files` | 6 fixed dicts | generated, with matching AV detection names |
| `checkpoint_firewall` C2 list | 5 hard-coded in the function | generated per source |
| `fortinet_config.dga_beacon_domains` | 8 fixed | generated DGA per source |
| `exfiltration_destinations` (file sharing) | 25 real services | **74 real services** (not generated -- rule literals) |
| Firepower large upload / download destinations | **4 fixed** | shared pool, ~130 distinct per 300 |
| `zscaler._UPLOAD_FILES` | 20 fixed, no placeholders | generated, ~99% distinct |
| Proofpoint attachment templates | 8 + 8, varying only by `{num}` | generated |
| QR phishing attachment | `AuthCode.png`, always | generated |

### Coverage by module

| Module | Threat domains | File names |
|---|---|---|
| `infoblox_dns` | `threat_domains` | n/a |
| `cisco_firepower` | `threat_domains` | `threat_files` |
| `checkpoint_firewall` | `threat_domains` | n/a |
| `fortinet_fortigate` | `threat_domains` (DGA) | n/a |
| `zscaler` | already unbounded via `session_utils.rare_domain()` | `threat_files` |
| `proofpoint_email` | uses its own URL pool | `threat_files` |
| `cisco_asa` | **not applicable** | **not applicable** |

Cisco ASA is the one deliberate gap: ASA syslog is layer 3/4 and carries no domain
or file field at all, which is documented at length in that module (it is also why
the ASA SMTP and volume detections cannot be analytic). There is nothing to
generate.

Zscaler's C2 domains were already generated before this work, by
`session_utils.rare_domain()` -- syllable-composed names with an optional number, so
cardinality was never the problem there. They carry no family token, which is
correct: no Zscaler rule matches a domain substring. Its rules match category
fields (`cs1`, `reason`), which are a fixed vocabulary by design.

### Two things deliberately NOT generated

* `exfiltration_destinations` -- the shared file-sharing pool. These are real services,
  and the "Infoblox - DNS Resolution of Unsanctioned Cloud Storage" rule matches them as
  literals, so generating over them would break that rule. It is **grown by adding more
  genuine services instead** -- 25 to 60, then a second wave (letsupload.io, turbobit.net,
  rapidgator.net, Backblaze B2 and 10 more) to 74 -- which also put three of that rule's
  literals
  (`filebin`, `transfer.sh`, `send.now`) into the project for the first time. Cardinality
  here comes from the number of distinct services plus the 30% long-tail share; a single
  service correctly keeps its one real domain (`pastebin.com` is always `pastebin.com`).
  Every URL a service emits uses that service's real link shape -- turbobit/hitfile
  short links (`/<id>.html`), rapidgator `<hash>.html`, filestore `?d=<id>`, Backblaze's
  `b2_download_file_by_id` API -- so URL-shaped detectors can key on per-service format.
* Per-source C2 stability. Check Point, FortiGate and Zscaler each keep a
  `_beacon_target_map` so one source keeps calling the same host across runs -- that
  recurrence IS the "recurring rare domain" detection signal. The generator is
  therefore called once, when a source is first seeded, never per event. FortiGate
  still varies the DGA subdomain per beacon under a stable base, which is what a
  real implant does.

## The constraint that makes this delicate

138 of the 186 correlation rules match **literal substrings**. Nine of those literals
are substrings of threat domain names, matched across 5 rules (they overlap -- one rule often ORs over several tokens):

| Token | Rules referencing it | Family |
|---|---|---|
| `command-control` | 5 | `c2` |
| `c2-infra` | 3 | `c2_infra` |
| `credential-stealer` | 2 | `credential_stealer` |
| `exploit-kit` | 2 | `exploit_kit` |
| `malware-distro` | 2 | `malware_distro` |
| `new-c2` | 2 | `new_c2` |
| `phishing-kit` | 2 | `phishing_kit` |
| `phishing-login` | 2 | `phishing_login` |
| `ransomware-payload` | 2 | `ransomware` |

These are a **contract**, not decoration. Randomise a pool without them and the
rules go quiet with no error anywhere. So the token leads and everything else
varies: `modules/threat_domains.py` reproduces the token verbatim and composes an
optional subdomain, a role word, an optional short discriminator and an abused TLD
around it.

    command-control  ->  cdn.command-control-relay.top
                         command-control-node-7f2.icu
                         panel.command-control-proxy-get.sbs

Two of those tokens did not exist anywhere in the project before this work. The
shipped pool had `phish-kit-host.ru` while the rules match `phishing-kit`, and
`ransomware-payment-page.biz` while the rules match `ransomware-payload`. Near
misses, each silencing two rules. Generating from the tokens the rules actually use
fixed four detections as a side effect.

## Head and tail

`infoblox_threats.generated_share` (default `0.75`) sets how much of the threat
traffic is generated. It is deliberately not 1.0:

* the **curated pools are the head** -- an operator hunting by hand needs a handful
  of names they can remember and type, and the scenario walkthroughs quote them;
* **generated domains are the tail**, which is where the cardinality that defeats a
  novelty baseline comes from.

Same division of labour as `domain_corpus` for benign traffic, with the proportions
inverted: there the curated pool is the dominant head and the tail is a thin 5%
slice, because benign traffic needs a stable head for affinity baselines. Here the
tail dominates, because a threat domain that recurs is the failure mode.

Set it to `0` to pin everything back to the curated pools.

## The dependency that nearly broke silently

`infoblox_dns.generate_dns_pair` decides NXDOMAIN vs NOERROR by asking whether the
domain is malicious. It used to answer by testing membership of the config pool:

```python
bad_domains  = set(threat_cfg['malicious_domains'] + threat_cfg['dga_domains'])
is_malicious = domain in bad_domains
```

Generate domains without telling that test and it answers `False` for every one of
them, so every C2 lookup starts resolving successfully -- quietly breaking both the
NXDOMAIN storm rule and the "C2 domain resolves NOERROR" rule. It now calls
`threat_domains.is_threat(domain, config)`, which recognises a generated domain by
its family token and by an issue registry, and still honours the config pools.

Anything else that needs to know "is this one of ours" must use the same call, never
a pool membership test.

## File names

`modules/threat_files.py`. Two things there are also contracts:

* **Content types.** "Proofpoint - Image-Based (QR) Phishing" matches
  `messageParts contains "image/png"`, so the MIME string has to be the real one for
  the extension. `_CONTENT_TYPE` is the single source of truth, keyed by extension,
  and the generator never emits a mismatched pair.
* **The malicious extension set.** "Proofpoint - Malware Attachment Delivered" ORs
  over `.docm/.exe/.iso/.js/.lnk/.xlsm/.zip`. The old templates covered three of
  those and never produced `.lnk`, `.iso`, `.docm` or `.js`, so four branches had
  never been exercised. All seven now appear, which is also simply more current:
  once Office blocked macros by default, `.lnk` and `.iso`/`.img` container delivery
  became the dominant pattern, and a corpus stuck on macro documents is modelling
  2021.

Malware families are tied to the delivery format rather than picked at random --
IcedID really did ship `.iso`/`.lnk`, QakBot `.xlsm` -- because an analyst who reads
"Emotet delivered via .lnk" in an alert stops trusting the data.

## Cloud identifiers

`modules/cloud_ids.py`. `aws_config` shipped ~20 pools of 25-26 resource identifiers,
so the same 26 EC2 instances were started, stopped and snapshotted all month, and an
analyst pivoting on `i-01a2b3c4d5e6f7a1` found a month of unrelated history.

Formats are the documented ones, because these are parsed and pivoted on rather than
merely displayed -- `i-` + **17** hex (AWS moved off the 8-hex form in 2016), `AKIA`
+ 16 for a long-lived key, `ASIA` + 16 for STS temporary credentials, 12-digit
account ids, DNS-compliant bucket names.

### Pools are grown, not replaced

`cloud_ids.expand_pools(config)` runs once at startup, after the `PLACEHOLDER_*`
substitution so generated ARNs carry the real account id, and before the modules
load. That avoids touching ~100 `random.choice(conf[pool])` call sites, and it is
also the more faithful model: a real account **does** keep a stable set of instances
and buckets that recur for months. The defect was never recurrence, it was having 26
of them for an estate of ~250 users. Pool sizes therefore reflect the shape of a real
estate rather than one flat number:

| Pool | Before | After | Why |
|---|---|---|---|
| `ec2_snapshots` | 26 | 900 | snapshots accumulate |
| `ebs_volumes` | 26 | 600 | one or more per instance |
| `ec2_instances` | 26 | 400 | |
| `log_groups` | 26 | 250 | one per function/cluster |
| `s3_buckets` | 26 | 200 | |
| `vpcs` | 26 | **26** | a real estate has few VPCs |
| `gcp_config.service_accounts` | **5** | 60 | tightest pool in the project |

Two things stay fixed on purpose:

* **The org's own AWS account id.** It is the tenant's identity and appears in every
  ARN. Only *foreign* account ids are generated -- which is precisely the field a
  cross-account AssumeRole rule keys on.
* **`pentest_ami_ids`.** Those ids encode distro names (`ami-kali-linux-official`,
  `ami-parrot-sec-os`) and "AWS - Kali / Penetration-Testing AMI Launched" matches
  them. Random `ami-0<hex>` entries would dilute the signal.

### Cloud literals the rules match

* **Secret names.** `rootCredentials`, `MasterKey`, `SuperUser`,
  `service_account_key`, `encryption_key`, `BreakGlass` are force-seeded into
  `sensitive_credential_paths`, and ~55% of generated secrets carry one. Before this,
  "AWS - Secret or Parameter Retrieval Targeting Credentials" was held up by a single
  alternative, and only through a **case-insensitive** match on
  `emergency-breakglass-key` -- had the tenant's XQL case sensitivity ever been
  switched on, the rule would have died outright. Note `service_account_key` is spelt
  with underscores; the shipped pool had `/corp/iam/service-account-key` with
  hyphens, which the rule never matched.
* **S3 canned ACLs.** `put-bucket-acl --acl public-read` logs `x-amz-acl` with no
  `AccessControlPolicy`; the `--grant-read uri=...AllUsers` form logs the grant URI.
  CloudTrail carries one or the other, never both, so 25% of events take the canned
  form. The grant-URI form stays dominant deliberately: per the 2026-08-02 note in
  `aws.py`, only that form fires the built-in BIOC (65s, versus a policy form silent
  for 20 minutes and 0 alerts in 180 days).
* **`roles/iam.serviceAccountUser`**, added to GCP's `_ADMIN_ROLES`. It is the classic
  impersonation-escalation role and was missing from the project entirely.
* **Automation principals.** `AWSServiceRoleFor...` and `...InstanceProfile` appear
  only in NEGATED clauses -- four rules exclude them so AWS's own automation does not
  alert -- and the account contained none, so the exclusions were never exercised.
  Added to `users_and_roles`, with the **real** role names: capitalising the service
  prefix would give `AWSServiceRoleForEks` and `AWSServiceRoleForRds`, which do not
  exist. `/aws-service-role/` required a second fix: CloudTrail reports the full role
  path in `sessionContext.sessionIssuer.arn`, and `_normalize_role_identity` was
  discarding it when rewriting a Role into an AssumedRole.

### Deliberately not done

* **`PublicReadGetObject`** is a bucket-*policy* Sid. The only place to put it would
  be a `PutBucketPolicy` event, which was removed on 2026-08-02 with evidence, and
  putting a policy Sid inside an ACL event would fabricate a field shape CloudTrail
  never emits. The rule fires on `AllUsers` regardless.
* **`iam:*`** needs an inline policy document, i.e. a `PutUserPolicy` event this
  module does not have. The rule already fires on `AdministratorAccess` /
  `PowerUserAccess`. Adding inline-policy escalation is worthwhile on its own merits
  (it is a real and stealthier technique) but it is a new event type, not an id fix.

## Guards

Run both before and after touching any pool:

```bash
python _local_validation/threat_generator_check.py
```

Asserts the generator invariants directly and fast: every family's token survives
100% of its draws, the tokens it claims as rule-bearing really are literals the
rules in `XSIAM imports` match, cardinality holds at realistic volumes,
`is_threat()` recognises generated domains and rejects benign ones, MIME matches
extension, and the malware rule's whole OR-chain is exercised.

```bash
python _local_validation/detection_compat_check.py
```

The broader guard: builds a corpus from every module and scenario and checks each
rule's literals against the corpus of the dataset that rule reads. It fails on
unsatisfiable clauses, not absent literals. Judge on the full run -- `--fast`
over-reports, because some literals only the scenarios produce.

```bash
python _local_validation/cloud_ids_check.py
```

Asserts the identifier formats against the documented AWS/GCP shapes, the rule
literals above, and the pool expansion (including that it is idempotent, since
startup may load config more than once).

Measured effect across the three steps, on the full run:

| | Start | Domains + files | + cloud ids |
|---|---|---|---|
| literals present | 143 | 153 | **166** |
| literals absent | 41 | 36 | **23** |
| unsatisfiable rules | 3 | 3 | **3** |

The three unsatisfiable rules are the same ones throughout -- the two Cisco Firepower
`cefName` rules and the Cisco ASA `106023` rule, all three replaced in the tenant and
awaiting deletion of the originals. No literal regressed at any step.

Note the test's `_THREAT_REPS` was raised from 12 to 30 once the sleep stub brought
the run to ~20s. At 12, rarely-drawn values flipped between runs (the pentest AMI
names traded places; `roles/iam.serviceAccountUser` came and went), which made the
coverage list impossible to read and invited chasing non-problems.
