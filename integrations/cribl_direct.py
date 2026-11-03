"""Direct-to-XSIAM "Cribl receiver" transport — push synthetic events into the native
dataset + Fusion analytics pipeline WITHOUT a Cribl instance at runtime.

Reverse-engineered from a real Cribl Cortex XSIAM destination's outbound request
(2026-10-10). The integrated receiver (/logs/v1/integrated/cribl/data) only columns data
that arrives in the exact wire shape the Cribl destination emits:

  POST <CRIBL_COLLECTOR_URL>
  Authorization:          Bearer <CRIBL_TOKEN>      # the "Bearer " prefix is required
  Content-Type:           application/json
  Content-Encoding:       gzip
  Format:                 json
  Source-Identifier:      <dedicated catalog UUID>  # selects dataset + parser; must be exact
  Integration-Identifier: <any non-empty string>    # free-form; not validated
  body = gzip( NDJSON )  where each line = {"data": <vendor record>, "collector_ms": <ms>}

A bare record (no {"data":...} envelope), or a non-gzip body, or a bare (non-Bearer)
token, all return HTTP 200 but land in _raw_log and never parse — that cost us a month of
"lands raw" results. Only every piece above together yields parsed, analytics-eligible rows.

Portability: a user needs only the FREE XSIAM Cribl integration (Settings -> Data Sources
-> add Cribl -> generate token). No Entra account, no Cribl Stream instance.

The generic UUID's vendor and product go in Vendor / Product headers: without both the
receiver answers 400 "must signal both vendor and product for non-xsiam integrations",
with them 200 (measured 2026-11-02; header names are case-insensitive).

Catalog Source-Identifier UUIDs are per data source; see CATALOG below, copied from the
Cortex XSIAM "Data source UUIDs" page.

Sources with no dedicated UUID (the syslog firewalls, Infoblox, Apache, ESXi) go under
GENERIC_UUID with a Vendor and Product, which XSIAM turns into <vendor>_<product>_raw.
Per that page, OOTB analytics only run on dedicated-UUID data; parsing and modeling rules
still apply to generic data. Their records are text lines, sent as Format: raw.
"""
import gzip
import json
import os
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:  # pragma: no cover
    raise SystemExit("The 'requests' package is required: pip install -r requirements.txt")

# The Cortex XSIAM Cribl catalog ("Data source UUIDs", read 2026-11-02):
# name -> (Source-Identifier, dataset). Only use GENERIC_UUID for a source not listed.
GENERIC_UUID = "af01292940d7426594d3d3e55ae17ee0"   # -> <vendor>_<product>_raw
CATALOG = {
    "aws_audit":              ("c19f87b6262f48259b3d5d2a2c691802", "amazon_aws_raw"),
    "aws_eks":                ("fb8a9d4922cb4095b76d71e921d2d999", "amazon_eks_raw"),
    "aws_flow":               ("667083aa68544eee8b67cdd2d4cc327b", "amazon_aws_raw"),
    "aws_generic":            ("0498f8a24de04b3e85102e742f6783f8", "amazon_aws_raw"),
    "aws_prompt":             ("a53edad7ef0c46ffb5037fb2e21520cb", "amazon_aws_raw"),
    "aws_route53":            ("0a7544038b444998a20e698669817e3d", "amazon_route53_raw"),
    "box":                    ("3ef05d14ae9349f8bbd48c8a4797334a", "box_admin_logs_raw"),
    "crowdstrike_incident":   ("230b2b0233bf4327806af72e6e5769f3", "crowdstrike_falcon_incident_raw"),
    "crowdstrike_hosts":      ("8b673ac8e2f34b4a8dc14c22f0e6063b", "crowdstrike_hosts_raw"),
    "dropbox_directory":      ("e8d2c52bc9594621924fab0507264586", "dropbox_users_raw"),
    "dropbox_events":         ("a6322b2fd9e545e0a4223ba754c48fb9", "dropbox_events_raw"),
    "gcp_cloud_logging":      ("00a8322c85e14beabfa7ad5f3d62db73", "google_cloud_logging_raw"),
    "google_gmail":           ("8607490288d1407ba82b5c5ad9dc64a0", "google_gmail_raw"),
    "gws_alerts":             ("4f263650cd29475c81f2ff953cf19827", "google_workspace_alerts_raw"),
    "gws_chromeos":           ("e82ae276e6b9442fa80920a03d2a38d6", "google_workspace_chrome_raw"),
    "gws_groups":             ("689ae8ef14e848e3855b81e91d8af9bc", "google_workspace_enterprise_groups_raw"),
    "gws_rules":              ("2621aaf3334a4147ae727afe84db31a9", "google_workspace_rules_raw"),
    "gws_users":              ("359ecd845fa54caab6ddb4b7c7a2764d", "google_workspace_user_acounts_raw"),
    "azure_event_hub":        ("fce13a1d51294f84bae4a37851503060", "msft_azure_raw"),
    "azure_ad":               ("c00d6d52e5b141a8baa8db9d9345423d", "msft_azure_ad_raw"),
    "azure_ad_audit":         ("0e076d5abe864bf78e8145ea9e0d749e", "msft_azure_ad_audit_raw"),
    "azure_ad_signin":        ("f56dcfdf6bca43e793a4b6e9290e7b12", "msft_azure_ad_raw"),
    "msft_defender":          ("ce9e8cf36e0742c38aa89787a256855f", "msft_defender_raw"),
    "msft_dhcp":              ("b55819e8959c49728d5d98a6d87eafb6", "msft_dhcp_raw"),
    "graph_security_alerts":  ("5619f2f691fc46c4b202587fdaa031c3", "msft_graph_security_alerts_raw"),
    "o365_azure_ad":          ("e1f109f886ea42fbb96be6ec0cc597a9", "msft_o365_azure_ad_raw"),
    "o365_dlp":               ("8f052782739d4b8389644cca23b994ac", "msft_o365_dlp_raw"),
    "o365_domains":           ("cae29fd87b554bd9a5694afb225e8dc9", "msft_o365_domains_raw"),
    "o365_exchange":          ("dee8e85ce7db4573a8bc21b807e1d73a", "msft_o365_exchange_online_raw"),
    "o365_general":           ("c7655e83805b4a058e66043a6715156c", "msft_o365_general_raw"),
    "o365_sharepoint":        ("3a37f519e9094a3f8c4185fa572cd111", "msft_o365_sharepoint_online_raw"),
    "o365_contacts":          ("de1b694a6c8341958bc08c4b7c140874", "msft_o365_contacts_raw"),
    "o365_devices":           ("de229685f708413fad46289657ea09de", "msft_o365_devices_raw"),
    "o365_groups":            ("0b0499ac0d984145b201c6d674771dbf", "msft_o365_groups_raw"),
    "o365_mailboxes":         ("9855a03559ce4263b568671e695d1fa8", "msft_o365_mailboxes_raw"),
    "o365_rules":             ("6b925df8923d4038bf78998d1ffde77c", "msft_o365_rules_raw"),
    "o365_users":             ("dcfb7a412e654efd868de0b8cf81766a", "msft_o365_users_raw"),
    "windows_event_logs":     ("63b0fbeb501e4650896e7064d3412e14", "microsoft_windows_raw"),
    "okta_sso":               ("5faf4c1fdb8443d9920d6a54815432c1", "okta_sso_raw"),
    "onelogin_events":        ("22b23a3f9f1e49998645b683d5dc3a6f", "onelogin_events_raw"),
    "onelogin":               ("88cfbd3e7b974d999b10edac83995b8a", "onelogin_users_raw"),
    "pingone":                ("924951a8394b4605b1725f943292ab4f", "pingid_pingone_raw"),
    "proofpoint_tap":         ("3eefce0f791e4391a3643b8cf860a361", "proofpoint_tap_raw"),
    "salesforce_logs":        ("ab109687acd24978aabcb7ad8b5742e3", "salesforce_login_raw"),
    "salesforce_snapshots":   ("addbf31a6372491e88d45934dff5b5b0", None),
    "sentinelone_dv":         ("b9fa55e6fa564c709358425ce0f61517", "sentinelone_deep_visibility_raw"),
    "servicenow_cmdb":        ("8b3e767247e44471a95e563378d0b9be", None),
    "workday":                ("00d4e740702d4eb2939a87c2318513dd", "workday_workday_raw"),
}
DEDICATED_UUIDS = {name: uuid for name, (uuid, _dataset) in CATALOG.items()}
KNOWN_UUIDS = set(DEDICATED_UUIDS.values()) | {GENERIC_UUID}


def is_catalog_uuid(source_identifier: str) -> bool:
    """True for a dedicated catalog UUID or the generic one."""
    return source_identifier in KNOWN_UUIDS

# A record may name a different destination than the module that produced it, e.g. the
# Event Hub copy of a Graph sign-in (msft_azure_raw rather than msft_azure_ad_raw):
# record[ROUTE_KEY] = [source_identifier, integration_identifier]. split_routes() groups a
# batch by destination; the key never goes on the wire.
ROUTE_KEY = "__cribl_route__"


def split_routes(records: Sequence[Any], source_identifier: str,
                 integration_identifier: str) -> Dict[Tuple[str, str], List[Any]]:
    """{(source_identifier, integration_identifier): [records]} with ROUTE_KEY removed.
    Records without a route go to the given defaults; insertion order is kept."""
    groups: Dict[Tuple[str, str], List[Any]] = {}
    for r in records:
        dest = (source_identifier, integration_identifier)
        if isinstance(r, dict) and ROUTE_KEY in r:
            r = dict(r)
            route = r.pop(ROUTE_KEY) or ()
            dest = (route[0] if len(route) > 0 and route[0] else source_identifier,
                    route[1] if len(route) > 1 and route[1] else integration_identifier)
        groups.setdefault(dest, []).append(r)
    return groups


class CriblDirectSender:
    """POSTs synthetic events straight into XSIAM's integrated Cribl receiver."""

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None,
                 verify_tls: bool = False, timeout: float = 30.0):
        self.url = url or os.getenv("CRIBL_COLLECTOR_URL")
        self.token = token or os.getenv("CRIBL_TOKEN")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._session = requests.Session()
        if not self.url or not self.token:
            raise ValueError("CRIBL_COLLECTOR_URL and CRIBL_TOKEN must be set (env or args).")

    def send(self, records: Sequence[Any], source_identifier: str,
             integration_identifier: str = "logsim:synthetic",
             vendor: Optional[str] = None, product: Optional[str] = None,
             fmt: Optional[str] = None) -> Tuple[int, str, int]:
        """Send a batch of vendor records under one Source-Identifier.

        Returns (http_status, response_text, num_records_sent). Records go under the given
        Source-Identifier unless they name their own (ROUTE_KEY); those are posted in a
        separate request to their destination. Batches freely — the real destination sends
        many NDJSON lines per POST.

        A record is a dict (JSON vendor record) or a str (a raw text line, e.g. syslog).
        *vendor*/*product* are required with GENERIC_UUID; *fmt* defaults to "json" for
        dict records and "raw" for text.
        """
        if vendor or product or fmt:
            return self._post(list(records), source_identifier, integration_identifier,
                              vendor, product, fmt)
        groups = split_routes(list(records), source_identifier, integration_identifier)
        if len(groups) > 1:
            # Records bound for other destinations (ROUTE_KEY) go in their own requests, so a
            # direct caller cannot misroute them; the worst status is reported.
            results = [self._post(recs, src, integ) for (src, integ), recs in groups.items()]
            bad = [r for r in results if r[0] not in (200, 201, 202, 204)]
            code, text, _ = (bad or results)[0]
            return code, text, sum(r[2] for r in results)
        records = next(iter(groups.values()), [])
        if groups:
            source_identifier, integration_identifier = next(iter(groups))
        return self._post(records, source_identifier, integration_identifier)

    def _post(self, records, source_identifier, integration_identifier,
              vendor=None, product=None, fmt=None):
        if not records:
            return 0, "no records", 0
        now_ms = int(time.time() * 1000)
        ndjson = "\n".join(
            json.dumps({"data": r, "collector_ms": now_ms}, default=str) for r in records
        ) + "\n"
        body = gzip.compress(ndjson.encode("utf-8"))
        if fmt is None:
            fmt = "raw" if all(isinstance(r, str) for r in records) else "json"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Format": fmt,
            "Source-Identifier": source_identifier,
            "Integration-Identifier": integration_identifier,
        }
        # The generic UUID names its dataset by vendor/product (the Cribl destination's
        # __vendor/__product fields); a dedicated UUID already implies them.
        if vendor:
            headers["Vendor"] = vendor
        if product:
            headers["Product"] = product
        resp = self._session.post(self.url, headers=headers, data=body,
                                  verify=self.verify_tls, timeout=self.timeout)
        return resp.status_code, resp.text[:200], len(records)


def probe(source_identifier: str, vendor: Optional[str] = None, product: Optional[str] = None,
          url: Optional[str] = None, token: Optional[str] = None,
          timeout: float = 10.0) -> Tuple[int, str]:
    """POST an empty batch: checks the URL, token and Source-Identifier while ingesting
    nothing. Returns (http_status, response_text); status 0 means no response.

    What the receiver answers (measured 2026-11-02):
      200 {"num_records":0}  URL, token and UUID (+ vendor/product for the generic) good
      401                    token missing or rejected
      404                    wrong URL path
      400 "missing or unknown UUID ..."     Source-Identifier not in the tenant catalog
      400 "must signal both vendor and product ..."  generic UUID without Vendor/Product
    """
    url = url or os.getenv("CRIBL_COLLECTOR_URL")
    token = token or os.getenv("CRIBL_TOKEN")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "Format": "json",
        "Source-Identifier": source_identifier,
        "Integration-Identifier": "logsim:healthcheck",
    }
    if vendor:
        headers["Vendor"] = vendor
    if product:
        headers["Product"] = product
    try:
        resp = requests.post(url, headers=headers, data=gzip.compress(b""),
                             verify=False, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        return 0, f"{type(exc).__name__}: {exc}"
    return resp.status_code, resp.text[:200]


def send_batch(records: Sequence[Dict[str, Any]], source_identifier: str,
               integration_identifier: str = "logsim:synthetic") -> Tuple[int, str, int]:
    """One-shot convenience wrapper around CriblDirectSender.send()."""
    return CriblDirectSender().send(records, source_identifier, integration_identifier)
