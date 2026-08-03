# FortiGate CEF → XSIAM Field Map & Genuineness Reference

Authoritative per-subtype map of what a **genuine** FortiGate CEF log looks like, what
**XSIAM** does with each field, and the **module's** current status. Use this as the spec
when adding or fixing `modules/fortinet_fortigate.py` generators.

## Sources (all verified)
- **Genuine CEF fields per subtype** — FortiOS 7.4.4 Log Reference, "CEF support" section
  (each subtype shows the on-disk log *and* its exact CEF/`FTNTFGT` form).
- **XDM mapping** — XSIAM content pack `demisto/content` → `Packs/FortiGate`
  `ModelingRules/FortiGate_1_3.xif` + `_schema.json` (176 raw fields) and
  `ParsingRules/FortiGate/FortiGate.xif`.
- **Module status** — direct-call dump of every generator in `fortinet_fortigate.py`.

## Ingestion contract
- Transport: **CEF syslog** → Broker VM → dataset **`fortinet_fortigate_raw`**.
- Fortinet-proprietary fields use the **`FTNTFGT`** prefix (e.g. `FTNTFGTvirus`). Standard
  CEF keys are unprefixed (`src`, `dst`, `spt`, `dpt`, `act`, `app`, `in`, `out`, `request`,
  `fname`, `fsize`, `duser`, `suser`, `dhost`, `dvchost`, `deviceExternalId`,
  `deviceInboundInterface`/`deviceOutboundInterface`, `deviceDirection`).
- **`FTNTFGTeventtime`** (nanosecond epoch) is **required** — the parsing rule derives `_time`
  from it (`_time = eventtime − duration`). The module emits it correctly.
- CEF header (genuine): `CEF:0|Fortinet|Fortigate|v{ver}|{logid}|{type}:{subtype} {eventtype} {action}|{sev}|`
  — note the **Name field includes `eventtime`/eventtype and action**, e.g. `utm:virus infected blocked`.

## Genuine CEF field-name mapping (easy to get wrong)
| On-disk field | Genuine CEF key | Notes |
|---|---|---|
| `filename` | **`fname`** | NOT `FTNTFGTfilename` |
| `filesize` | **`fsize`** | NOT `FTNTFGTfilesize` |
| `url` | **`request`** | NOT `FTNTFGTurl` |
| `agent` | **`requestClientApplication`** | user-agent |
| `hostname` | **`dhost`** | |
| `catdesc` | **`requestContext`** | web/dns category description |
| `count` | **`cnt`** | anomaly/DoS |
| `direction` | **`deviceDirection`** | incoming/outgoing → 0/1 |
| `from` / `to` | **`suser`** / **`duser`** | email |
| `status` | **`outcome`** | |
| `virus` | **`FTNTFGTvirus`** | NOT `FTNTFGTvirusname` |

---

## Summary status by subtype

| Subtype | Module produces | Header correct | Status |
|---|---|---|---|
| `virus` (antivirus) | ✅ `virus` (fixed) | ✅ (fixed) | fixed: subtype/eventtype/field-names |
| `ips` | ✅ | ✅ | good; genuine also has `crscore`/`craction`/`crlevel` |
| `app-ctrl` | ✅ | ✅ (fixed) | fixed: added `eventtype=app-ctrl-all`, `incidentserialno` |
| `waf` | ✅ | ✅ | good; optional `rawdata`, `direction=request` |
| `webfilter` | ✅ | ✅ | good; emits `requestContext`+`FTNTFGTcatdesc` |
| `dns` | ✅ `dns:dns-query` (fixed) | ✅ (fixed) | fixed: `type=dns subtype=dns-query` |
| `anomaly` (DoS) | ✅ added | ✅ | `_simulate_dos_anomaly` |
| `dlp` | ✅ added | ✅ | `_simulate_dlp_block` — 3-log exfil chain [dns, traffic:forward, utm:dlp], shared session id |
| `forward`,`ssl`,`vpn`,`system` | ✅ | ✅ | good |

---

## Per-subtype detail

### `utm:virus` (antivirus)  — genuine logid `0211008192`, eventtype `infected`
Genuine CEF keys: `FTNTFGTsubtype=virus FTNTFGTeventtype=infected` `msg act app externalId src dst spt dpt`
`deviceInboundInterface FTNTFGTsrcintfrole deviceOutboundInterface FTNTFGTdstintfrole FTNTFGTpolicyid proto deviceDirection`
**`fname`** **`FTNTFGTquarskip`** **`FTNTFGTvirus`** **`FTNTFGTdtype=Virus`** **`FTNTFGTref`** **`FTNTFGTvirusid`**
`request FTNTFGTprofile duser requestClientApplication` **`FTNTFGTanalyticscksum`** **`FTNTFGTanalyticssubmit`** **`FTNTFGTcrscore`** **`FTNTFGTcrlevel`**.

XDM: `FTNTFGTvirus`→`alert.original_threat_name`, `FTNTFGTviruscat`→`alert.category`,
`FTNTFGTfilehash`→`target.file.md5/sha256` (by length), `fname`→`target.file.filename`,
`fsize`→`target.file.size`, `FTNTFGTvirusid`→`alert.original_threat_id`, `FTNTFGTCRlevel`→`alert.severity`.

Module status:
- `_simulate_antivirus` — **subtype=`antivirus`** (→`virus`), **eventtype=`virus`** (→`infected`). Fields `fname/fsize/FTNTFGTvirus/virusid/viruscat/filehash/filetype/ref` present ✅. Missing genuine `FTNTFGTdtype`, `FTNTFGTquarskip`, `FTNTFGTanalyticscksum/submit`, `FTNTFGTcrscore`.
- `_generate_antivirus_allow` — **invented keys** `FTNTFGTfilename FTNTFGTfilesize FTNTFGTurl FTNTFGTvirusname FTNTFGTvirusstatus` → must be `fname fsize request FTNTFGTvirus` (+ drop `virusstatus` or map to `FTNTFGTanalyticssubmit`). These are dropped by XSIAM today.

### `utm:ips`  — genuine logid `0419016384`, eventtype `signature`
Genuine: `FTNTFGTsubtype=ips FTNTFGTeventtype=signature FTNTFGTseverity FTNTFGTattack FTNTFGTattackid`
`FTNTFGTprofile FTNTFGTref FTNTFGTincidentserialno` `dhost(hostname) request(url) act(reset/dropped) proto app`
`crscore craction crlevel`. XDM: `FTNTFGTattack`→`alert.original_threat_name`, `FTNTFGTattackid`→`alert.original_threat_id`, `FTNTFGTseverity`→`alert.severity`, `FTNTFGTref`→`alert.description`, `FTNTFGTincidentserialno`→`alert.original_alert_id`.
Module: ✅ complete for the core fields. Enhancement: add `FTNTFGTcrscore/craction/crlevel`, `dhost`.

### `utm:app-ctrl`  — genuine logid `1059028704`, eventtype `app-ctrl-all`
Genuine: `FTNTFGTeventtype=app-ctrl-all FTNTFGTappid FTNTFGTapplist FTNTFGTappcat FTNTFGTapp FTNTFGTapprisk FTNTFGTincidentserialno dhost request msg`.
XDM: `FTNTFGTapp(+appid)`→`target.application.name`, `FTNTFGTappcat`→`application_protocol_category`, `FTNTFGTapprisk`→`alert.severity` (coalesce).
Module: has app/appid/appcat/apprisk/applist ✅. **Missing `FTNTFGTeventtype=app-ctrl-all` and `FTNTFGTincidentserialno`.**

### `utm:waf`  — genuine logid `1203030258`, eventtype `waf-http-constraint`
Genuine: `FTNTFGTeventtype=waf-http-constraint FTNTFGTseverity FTNTFGTconstraint FTNTFGTrawdata request requestClientApplication act(passthrough)`. Constraint logs have **no `attack`** (only signature-detection WAF does) — so the module omitting `attack` is correct.
Module: ✅ good. Missing `FTNTFGTrawdata`, `direction=request`. (Optional: add a signature-detection WAF variant with `attack`/`attackid`.)

### `utm:webfilter`  — genuine logid `0316013056`, eventtype `ftgd_blk`
Genuine: `FTNTFGTeventtype=ftgd_blk dhost(hostname) act request(url) out(sentbyte) in(rcvdbyte) FTNTFGTmethod FTNTFGTreqtype` **`FTNTFGTcat=26`** **`requestContext=Malicious Websites`** `FTNTFGTcrscore FTNTFGTcrlevel`. XDM: `url_category = coalesce(requestContext, FTNTFGTcatdesc)`; `cat`→`observer.type` (numeric FortiGuard category enum).
Module: ✅ produces webfilter with `eventtype`, `requestContext`, `FTNTFGTcatdesc`. Note genuine puts the **number** in `FTNTFGTcat` and the description in `requestContext`; keep both. Add `FTNTFGTmethod`, `FTNTFGTreqtype`, `FTNTFGTcrscore/crlevel`.

### `dns` (NOT utm)  — genuine logid `1501054802`, `type=dns subtype=dns-response`
Genuine header: **`type="dns" subtype="dns-response"`** (or `dns-query`). Fields: `FTNTFGTqname FTNTFGTqtype FTNTFGTqtypeval FTNTFGTqclass FTNTFGTipaddr FTNTFGTxid cat FTNTFGTcatdesc FTNTFGTprofile FTNTFGTsrcmac act msg`. XDM: `FTNTFGTqname`→`dns.dns_question.name`, `FTNTFGTqtype`→type enum, `FTNTFGTeventtype`(`dns-response`/`dns-query`)→`is_response`, `FTNTFGTipaddr`→`dns_resource_record.value`.
Module: emits **`type=utm subtype=dns`** ❌ — should be `type=dns` and `subtype=dns-response`/`dns-query`. Has qname/qtype/qclass/ipaddr/catdesc ✅. Missing `FTNTFGTqtypeval`, `FTNTFGTxid`, `FTNTFGTeventtype` set to the dns-query/response value.

### `utm:anomaly` (DoS)  — genuine logid `0720018433`, eventtype `anomaly`  — **TO ADD**
Genuine: `FTNTFGTsubtype=anomaly FTNTFGTeventtype=anomaly FTNTFGTseverity=critical FTNTFGTattack(icmp_flood) FTNTFGTattackid FTNTFGTicmpid FTNTFGTicmptype FTNTFGTicmpcode FTNTFGTpolicyid FTNTFGTpolicytype=DoS-policy FTNTFGTref cnt(count) act(clear_session) proto app(service) FTNTFGTcrscore FTNTFGTcrlevel`.
XDM: `FTNTFGTattack`→`alert.original_threat_name`, `FTNTFGTattackid`→id, `FTNTFGTseverity`→severity, `cnt`? (not mapped), icmp fields → `network.icmp.type/code`.

### `utm:dlp`  — genuine logid `0954024576`, eventtype `dlp`  — **missing generator**
Genuine: `FTNTFGTfilteridx FTNTFGTdlpextra FTNTFGTfiltertype FTNTFGTfiltercat FTNTFGTseverity FTNTFGTepoch FTNTFGTeventid FTNTFGTfiletype fname fsize FTNTFGTprofile dhost request act`. (Optional add.)

### `traffic:forward`, `utm:ssl`, `event:vpn`, `event:system`
Structurally correct and richly populated. Notes: forward/ssl carry TLS fields
(`FTNTFGTcipher/tlsver/scertcname/scertissuer`) ✅; vpn carries `FTNTFGTtunnelip/assignip/xauthuser/vpntunnel` ✅; system carries `FTNTFGTmethod`, `duser`, `sproc` ✅.

---

## Correctness issues — FIXED 2026-07-22

1. ✅ **`_generate_antivirus_allow` invented CEF keys** — now `fname`/`fsize`/`request`, virus-specific keys dropped for the clean verdict (eventtype `analytics`, `FTNTFGTanalyticscksum`/`analyticssubmit`).
2. ✅ **Antivirus subtype/eventtype** — both generators now `subtype=virus`; block=`eventtype=infected` (+`FTNTFGTdtype`/`quarskip`/`crscore`), clean=`analytics`. logid `0211008192`.
3. ✅ **DNS type/subtype** — all 4 DNS generators now emit `type=dns subtype=dns-query`.
4. ✅ **`FTNTFGTsessduration`** — removed from `_base_traffic_fields`.
5. ✅ **app-ctrl** — added `FTNTFGTeventtype=app-ctrl-all` + `FTNTFGTincidentserialno`.
6. ✅ **CEF Name field** — `_format_fortinet_cef` now emits `{type}:{subtype} {eventtype} {action}`.
7. ✅ **`utm:anomaly` (DoS) generator added** — `_simulate_dos_anomaly` (icmp/syn/udp/session floods with `attack`/`attackid`/`severity`/`policytype=DoS-policy`/`cnt`/icmp fields).
8. ✅ **`utm:dlp` generator added** — `_simulate_dlp_block` returns a **3-log exfil chain** `[dns:dns-query, traffic:forward accept, utm:dlp block]` sharing one `externalId` (session): host resolves the file-sharing domain, opens an outbound HTTPS upload, then the DLP sensor blocks it (`dlpextra`/`filtertype`/`filtercat`/`severity`/`epoch`/`eventid`/`filetype`/`fname`/`fsize`, logid `0954024576`). Scenario-ready via `forced_event='dlp_block'`. Uses `config.exfiltration_destinations`.

Both new events registered in `_DEFAULT_THREAT_EVENTS` **and** `config.json` → `fortinet_config.event_mix.threat` (weight 4 each) so they appear in normal rotation — note the config's threat list overrides the module defaults, so new events must be added in both places.

**Deliberately left (hunt-only raw columns, pending genuine-CEF verification, non-breaking):**
`FTNTFGTservice` (genuine maps service→`app`), `FTNTFGTremotegw`, `FTNTFGTtunneltype`, `FTNTFGTtz`.
These are dropped by XSIAM's modeling (not in schema) but harmless; revisit if exact FortiOS CEF key names are confirmed.

Genuine-but-not-XDM-mapped hunt fields the module correctly emits (keep): `FTNTFGTsrcintfrole`,
`FTNTFGTdstintfrole`, `FTNTFGTpolicytype`, `FTNTFGTpoluuid`, `FTNTFGTdtype`, `FTNTFGTconstraint`.
