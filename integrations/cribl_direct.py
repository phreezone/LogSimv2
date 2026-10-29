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

Catalog Source-Identifier UUIDs are per data source; see DEDICATED_UUIDS below and the
XSIAM "Data source UUIDs" doc for the full list.
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

# Dedicated catalog UUIDs, one per LogSim source, checked against the Cortex "Data source
# UUIDs" catalog (Cribl). A module's SOURCE_IDENTIFIER must be one of these, or its records
# land in the wrong dataset (or raw) and never reach the source's OOTB analytics.
DEDICATED_UUIDS = {
    # Cribl is the module's transport (or its "auto" fallback).
    "o365_azure_ad":     "e1f109f886ea42fbb96be6ec0cc597a9",  # -> msft_o365_azure_ad_raw
    "azure_ad_signin":   "f56dcfdf6bca43e793a4b6e9290e7b12",  # -> msft_azure_ad_raw
    "azure_ad_audit":    "0e076d5abe864bf78e8145ea9e0d749e",  # -> msft_azure_ad_audit_raw
    "o365_exchange":     "dee8e85ce7db4573a8bc21b807e1d73a",  # -> msft_o365_exchange_online_raw
    "o365_sharepoint":   "3a37f519e9094a3f8c4185fa572cd111",  # -> msft_o365_sharepoint_online_raw
    "o365_dlp":          "8f052782739d4b8389644cca23b994ac",  # -> msft_o365_dlp_raw
    "o365_general":      "c7655e83805b4a058e66043a6715156c",  # -> msft_o365_general_raw
    "gcp_cloud_logging": "00a8322c85e14beabfa7ad5f3d62db73",  # -> google_cloud_logging_raw
    "aws_cloudtrail":    "c19f87b6262f48259b3d5d2a2c691802",  # -> amazon_aws_raw (AWS audit logs)
    # Catalog entries for sources LogSim sends another way today (HTTP collector / WEC).
    "okta_sso":          "5faf4c1fdb8443d9920d6a54815432c1",  # -> okta_sso_raw
    "proofpoint_tap":    "3eefce0f791e4391a3643b8cf860a361",  # -> proofpoint_tap_raw
    "windows_events":    "63b0fbeb501e4650896e7064d3412e14",  # -> microsoft_windows_raw
}
GENERIC_UUID = "af01292940d7426594d3d3e55ae17ee0"   # <vendor>_<product>_raw, no OOTB analytics


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

    def send(self, records: Sequence[Dict[str, Any]], source_identifier: str,
             integration_identifier: str = "logsim:synthetic") -> Tuple[int, str, int]:
        """Send a batch of vendor records under one dedicated Source-Identifier.

        Returns (http_status, response_text, num_records_sent). All records in a call must
        belong to the same source (same Source-Identifier). Batches freely — the real
        destination sends many NDJSON lines per POST.
        """
        records = list(records)
        if not records:
            return 0, "no records", 0
        now_ms = int(time.time() * 1000)
        ndjson = "\n".join(
            json.dumps({"data": r, "collector_ms": now_ms}, default=str) for r in records
        ) + "\n"
        body = gzip.compress(ndjson.encode("utf-8"))
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Format": "json",
            "Source-Identifier": source_identifier,
            "Integration-Identifier": integration_identifier,
        }
        resp = self._session.post(self.url, headers=headers, data=body,
                                  verify=self.verify_tls, timeout=self.timeout)
        return resp.status_code, resp.text[:200], len(records)


def send_batch(records: Sequence[Dict[str, Any]], source_identifier: str,
               integration_identifier: str = "logsim:synthetic") -> Tuple[int, str, int]:
    """One-shot convenience wrapper around CriblDirectSender.send()."""
    return CriblDirectSender().send(records, source_identifier, integration_identifier)
