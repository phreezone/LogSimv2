# Correlation rule fixes — 2026-10-21

An audit of all 127 correlation rules in the lab tenant, made with read-only API calls.
Each enabled rule was run over 30 days of tenant data. Its real output columns were
checked against its `alert_fields` and `suppression_fields`. One issue per rule was then
read back from the `alerts` dataset to see which mapped fields actually arrive.

53 rules changed. The fixes were built from the **live** definitions, not the repo copies,
because 11 rules had been edited in the tenant since they were last exported.

## Where they are now

**Applied to the lab tenant on 2026-10-22.** All 53 were updated in place through
`correlations/insert`, which overwrites the rule with a matching `rule_id`. Every rule
read back identical and no copies were created.

The 2026-11-02 review then synced `XSIAM imports/` from the tenant, which carried these
fixes into the repo, and deleted and reloaded every rule. On 2026-11-02 all 53 fixes were
still live: 46 unchanged, and 7 with further query edits from that review (see
[`XSIAM imports/REVIEW-2026-11-02.md`](../XSIAM%20imports/REVIEW-2026-11-02.md)).

**The rule numbers on this page are the IDs from before that reload.** Every rule has a
new ID now; look up the current one by name in `XSIAM imports/rule_ids.json`. To change
a rule, edit `XSIAM imports/` and use `integrations/correlation_rules_deploy.py`, then
check with `integrations/correlation_rules_sync.py`.

One fix is not a rule edit: **DNS Rebinding** needs `_generate_dns_rebinding` in
`modules/infoblox_dns.py` to emit a public answer and then a private one for the same
domain (see below).

API notes:
- `correlations/delete` cannot filter on `rule_id`. Delete by exact `name` AND exact
  `xql_query`, and check first that the pair matches only one rule.
- `XsiamClient._post` already wraps the body in `request_data`. Pass the list or filter
  object itself, not another `request_data`.

Tenant cleanup, also done on 2026-10-22:

| Rule | Action (done) | Why |
|---|---|---|
| 1586 DNS C2 Kill Chain — NXDOMAIN Storm + Outbound Firewall Activity | deleted | Raised 68 "suppression field no longer exists" HEALTH errors; replaced by 1679 (v2) |
| 1607 GCP — API Access From External / Non-Corporate IP | deleted | Same error, 68 times; replaced by 1680 (v2) |
| 1566 Cisco ASA — High Volume of Denied Inbound Connections | disabled | Unsatisfiable (`observer.action = "Deny"` is never set); replaced by 1676 (v2) |

## What was wrong

### The issue's URL field was never filled — 32 rules

`xdm_url` does not reach the issue's URL field: across 88 sampled issues it filled `url`
on none of them. `fw_url_domain` does fill it. Every rule that put its URL or domain only
in `xdm_url` now also maps it to `fw_url_domain`. URL is a case-grouping artifact, so
these issues could not group by URL before.

Rules: 121, 123, 1567, 1569, 1571, 1572, 1573, 1574, 1575, 1576, 1583, 1598, 1602, 1605,
1614, 1615, 1616, 1634, 1636, 1639, 1640, 1644, 1646, 1649, 1650, 1668–1673, 1675.

### ASA connection direction inverted — 12 rules

Cortex's `parse_cisco()` files the `for` clause as `src`. LogSim therefore puts the
connection's initiator first (see `modules/cisco_asa.py`, `_generate_connection_session`),
so `generalCiscoLog.src_*` and `xdm.source.*` are always the side that opened the
connection. These rules assumed genuine Cisco ordering instead (server or destination
first). They fired on the wrong traffic, or never fired at all.

| Rule | Was | Now |
|---|---|---|
| 1599 Large Outbound C2 Callback Post-Click | `dst_interface = "inside"`, internal host = `dst_ip`: selected inbound and internal flows (its "external" hosts were 192.168.x on port 445) | inside → outside, src is the host |
| 1606 Large Outbound TCP Egress (≥50MB) | same | same |
| 1632 Large Outbound Egress (Pre-Encryption Exfil) | same | same |
| 1617 Internal Web Server Initiating Outbound Connection | same; also counted Built and Teardown twice | same; 302014 only |
| 1637 Outbound C2 Connection Allowed (Post DNS Resolve) | same; its "external" host was 192.168.30.231 | same |
| 1588 SMB Share Enumeration | `xdm.source.port = 445`, so it never fired | target port 445, scanner = source, internal only |
| 1620 SMB Lateral Movement to Unseen Hosts | same | same |
| 1629 Large SMB Session (Data Staging) | `src_port = 445` | `dst_port = 445` |
| 1585 Ransomware Precursor | both halves inverted; the ransomware host was mapped as the *remote* IP | scanner = source; egress inside → outside |
| 1589 Outbound SMTP Spam Bot | source port 25/587 with target inside, i.e. inbound mail | inside source → outside port 25/587; window 15m → 1h, ≥34 → ≥20 distinct MX (LogSim spreads 60–150 servers over 1–3 h) |
| 1590 SSH Proxy / Tunnel-Like Activity | `src_port = 22`, proxy = `dst_ip` | `dst_port = 22`, proxy = source; ≥6 → ≥5 targets (generator: 5–10) |
| 1578 Internal Port Scan | counted distinct *source* ports, which are ephemeral, so any busy host pair crossed 168 | distinct destination ports ≥100 (generator: 100–200); scanned ports mapped as the victim's port |

All 12 rewrites were run against the tenant over 30 days. Each returns rows, and every
mapped and suppression column is present.

### Private-IP tests were substring matches — 7 rules

`ip contains "10."` also matches `84.210.20.3`, and `contains "172."` matches
`1.172.x.x`. As a result:
- **Okta 1600, 1621, 1627, 1645** dropped real external logins.
- **529** labelled public IPs as "internal".
- **1570 (DNS Rebinding)** labelled public answers as private.

All now use `incidr()` on the RFC1918 ranges.

1570 had a second problem. It required at least two distinct *private* answers for one
domain, which neither real rebinding nor LogSim produces. Its only alert in 30 days was
`31.210.77.235`, a public IP. The rule now fires when one domain answers both a public
and an RFC1918 address within 10 minutes. `_generate_dns_rebinding` now emits that
public → private pair; it previously emitted one private answer per random domain.

### Fields mapped to nothing, or to the wrong thing — 9 rules

| Rule | Problem | Fix |
|---|---|---|
| 119 Proofpoint / Okta, 122 Proofpoint / Zscaler | every alert field was `None`, so issues carried no user, IP or URL | mapped to the query's own columns |
| 121 Threat Hunting — Proofpoint click then Okta login | `action_local_ip` held an email address; `agent_ip_addresses` mapped to nothing | removed both |
| 529 Okta — Internal Network Login | mapped `ip` and `displayMessage`, which its `comp` drops, so both were always null | `ip` carried through the aggregation |
| 1583, 1614, 1615, 1616 (Apache) | user-agent strings in `actor_process_image_name` | moved to `user_agent` |
| 1659 Apache — High Volume of Server Errors | client IPs in `action_external_hostname` | moved to `action_remote_ip` |

## Checked and fine

- **List values** in IP and username fields arrive intact: `remote_ip` and `user_name`
  are arrays on the issue.
- **Mapping names are matched case-insensitively.** 1651 maps `senderIP` while the
  column is `senderip`, and `remote_ip` is still filled.
- **Every other enabled rule** outputs every column it maps or suppresses on.

## Still not firing — needs a generator or threshold decision

These parse and map correctly but match nothing in 30 days:

- **GCP (9 rules):** `google_cloud_logging_raw` is empty, because Pub/Sub delivery is
  failing.
- **1572 Fast Flux:** needs ≥50 distinct IPs per domain in 15 minutes; the generator
  rotates 3–6.
- **1583 / 1614 Apache 4xx recon:** need ≥50 recon-path 4xx responses across ≥15 paths
  in 30 minutes.
- **1602 AWS Secret Retrieval:** looks for `service_account_key`, `rootCredentials` and
  similar names. The generator uses paths like `service-account-key`, and emits one
  event per fire where the rule needs ≥5.
- **1581 AWS Insider Threat:** needs ≥3 distinct operations from one IP and user within
  4 hours.
- **1664 Proofpoint — Malware accidentally delivered:** LogSim only sends high
  `malwareScore` messages as `message-blocked`.
- **1584 VPN Compromise Confirmed:** needs ASA 109006 failures plus a 113039 login for
  the same user.
