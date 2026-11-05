# Transports: Native Pipes and the Cribl Fallback

Every module reaches XSIAM the way the real product does: its **native pipe**. When that
pipe is not set up, or fails in a way retrying will not fix, the module sends to XSIAM's
integrated **Cribl receiver** instead, under its data source's Source-Identifier from the
Cortex catalog. With only `CRIBL_COLLECTOR_URL` and `CRIBL_TOKEN` set, every module runs.

The routing lives in `integrations/transport.py`; the Cribl wire format and catalog live in
`integrations/cribl_direct.py`.

## Native pipes

| Pipe | Modules | Set up when |
|---|---|---|
| `syslog` (Broker VM Syslog Collector) | Cisco ASA, Firepower, PAN NGFW, FortiGate, Check Point, Zscaler, Infoblox, Apache, VMware ESXi | `SYSLOG_HOST` is set (port from the module's `syslog_port`) |
| `http` (XSIAM HTTP Log Collector) | Okta, Proofpoint | the collector's URL (`*_COLLECTOR_URL` or `HTTP_COLLECTOR_URL`) and key are set |
| `s3` | AWS CloudTrail | `S3_BUCKET_NAME` and AWS credentials (`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`, or `AWS_PROFILE`) |
| `pubsub` | GCP | `GCP_PROJECT_ID`, `GCP_PUBSUB_TOPIC`, credentials, and `google-cloud-pubsub` installed |
| `wec` (Broker VM WEC) | Windows Event Log | `WEC_BROKER_URL` and `WEC_PFX_PATH` |
| `cribl` | the Microsoft / Entra / O365 / Azure modules | `CRIBL_COLLECTOR_URL` and `CRIBL_TOKEN` (Cribl is their native pipe) |

A module's config section names its pipe in `transport`; `"auto"` or no value means the
module's own `NATIVE_TRANSPORT`, else syslog. `"tcp"` means syslog.

## When a send goes to Cribl

1. **Not set up.** The pipe is missing a setting from the table above. The first send logs
   one line, for example
   `Okta SSO: http unavailable (no URL for HTTP collector 'okta_collector') -> Cribl receiver (okta_sso_raw)`.
2. **Failed.** A send fails with an error retrying will not fix:

   | Pipe | Errors that switch to Cribl |
   |---|---|
   | syslog | connection refused / reset, unknown host, any write that fails after one reconnect |
   | http | connection error, HTTP 401 / 403 / 404, or the circuit breaker opening |
   | s3 | AccessDenied, bad or missing credentials, NoSuchBucket, and similar |
   | pubsub | PermissionDenied, Unauthenticated, NotFound, bad credentials |
   | wec | the client cannot connect, or the WEC circuit breaker opens |

   The payload that failed is resent via Cribl, and that pipe's later sends go straight to
   Cribl for `transport_retry_s` seconds (default 300). Then the pipe is tried again. A
   syslog failure is scoped to its port and an HTTP failure to its collector, so one
   broken applet does not move every module.

   Other HTTP failures (5xx, 429) resend that request via Cribl without switching the
   pipe. A timed-out HTTP request is not resent, because the collector may have taken it.

The dashboard's **Transport routing** health group shows each module's pipe, whether it is
set up, and where it is sending now.

The **Cribl** health group is always shown, because Cribl is every module's fallback even
when nothing is using it:

| Check | Fails when |
|---|---|
| `CRIBL_COLLECTOR_URL defined` | unset, still the `.env.example` placeholder, or not an `https://…/logs/v1/integrated/cribl/data` URL (e.g. the HTTP collector URL pasted by mistake) |
| `CRIBL_TOKEN defined` | unset, a placeholder, or starts with `Bearer ` (LogSim adds that itself) |
| `receiver accepts the token` | the receiver answers 401/403 (token rejected), 404 (wrong URL) or not at all |
| `source UUIDs recognised` | the receiver refuses a module's Source-Identifier, or a generic route's vendor/product (re-checked every 15 minutes) |

The last two POST an **empty** batch, which the receiver validates but which ingests
nothing. A failure is an **error** when some source is on Cribl now (the Microsoft feeds,
or a module whose native pipe is down) and a **warning** otherwise: nothing is lost yet,
but a native pipe that fails would have nowhere to fall back to.

## Turning it off

```json
{ "cribl_fallback": false }                          // top level: no module falls back
{ "okta_config": { "cribl_fallback": false } }       // one module stays on its pipe
```

Without `CRIBL_COLLECTOR_URL` / `CRIBL_TOKEN` nothing falls back; each pipe reports its own
errors as before.

## Cribl routes

Each module's `SOURCE_IDENTIFIER` is a UUID from the Cortex catalog
([Data source UUIDs](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/configure-cortex-xsiam/cortex-xsiam-data-sources/vendor-specific-data-sources-and-connectors/cribl/ingest-data-from-cribl/data-souce-uuids)),
copied into `cribl_direct.CATALOG`.

| Module | Catalog source | Dataset | Record |
|---|---|---|---|
| Okta SSO | Okta SSO `5faf4c1f…` | `okta_sso_raw` | System Log event (JSON) |
| Proofpoint | Proofpoint TAP `3eefce0f…` | `proofpoint_tap_raw` | TAP event (JSON) |
| AWS | AWS audit logs `c19f87b6…` | `amazon_aws_raw` | one CloudTrail record per line |
| GCP | Cloud Logging `00a8322c…` | `google_cloud_logging_raw` | LogEntry (JSON) |
| Windows Event Log | Windows Event Logs `63b0fbeb…` | `microsoft_windows_raw` | `<Event>` XML, as a Cribl WEF source carries it |
| Microsoft modules | their own UUIDs (unchanged) | `msft_*_raw` | vendor API record (JSON) |
| Syslog modules | **Generic** `af012929…` + vendor/product | `<vendor>_<product>_raw` | the syslog line (`Format: raw`) |

The syslog sources have no dedicated catalog UUID, so they use the generic one. The vendor
and product come from each CEF line's header (so Check Point's products and Zscaler's web
and firewall logs each reach their own dataset), else from the module's `XSIAM_VENDOR` /
`XSIAM_PRODUCT`: Cisco/ASA, Cisco/Firepower, infoblox/infoblox, apache/httpd, VMware/ESXi.

### Caveats

- **Generic-UUID data gets no OOTB analytics.** Per the Cortex catalog page, out-of-the-box
  analytics only run on dedicated-UUID sources. Parsing rules, modeling rules and
  correlation rules still apply. For the firewall analytics, keep the Broker syslog pipe.
- **PAN NGFW** over the Broker is split into `panw_ngfw_*_raw` datasets by
  `__firewall_type`; over Cribl it lands in one CEF dataset.
- **Generic UUID vendor/product:** the receiver requires both, as `Vendor` / `Product`
  headers (without them: 400 "must signal both vendor and product").
