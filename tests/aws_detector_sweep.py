"""Tenant-side sweep: fire every named AWS threat and read back what XSIAM did.

The companion to tests/aws_event_smoke.py. That one proves events are well-formed;
this one proves what the tenant actually does with them — the only evidence that
counts, because on 2026-08-02 two S3 generators normalised *identically* in
cloud_audit_logs and only one fired its detector.

Everything is uploaded as ONE {"Records":[...]} S3 object so the whole sweep
rides a single collector pull. The pull is bimodal (~9s when healthy, 25min+
when not) and per-object, so batching is what makes a full sweep practical.

Events are correlated back by CloudTrail eventID -> cloud_provider_event_id,
so attribution is exact and no marker has to be injected into the payloads.

usage:  python tests/aws_detector_sweep.py [--wait-minutes N] [--threat NAME]
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

import log_simulator  # noqa: E402
from modules import aws  # noqa: E402
from integrations.xsiam_client import XsiamClient  # noqa: E402


def load_config():
    cs = open("config.json", encoding="utf-8").read()
    for ph, envvar in (("PLACEHOLDER_GCP_PROJECT_ID", "GCP_PROJECT_ID"),
                       ("PLACEHOLDER_GCP_PROJECT_NUMBER", "GCP_PROJECT_NUMBER"),
                       ("PLACEHOLDER_AWS_ACCOUNT_ID", "AWS_ACCOUNT_ID")):
        val = os.getenv(envvar, "")
        assert val, f"{envvar} missing from .env"
        cs = cs.replace(ph, val)
    return json.loads(cs)


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wait-minutes", type=int, default=45)
    ap.add_argument("--threat", action="append",
                    help="limit to specific threat name(s); default = all")
    args = ap.parse_args()

    config = load_config()
    threats = args.threat or list(aws.SCENARIO_FUNCTIONS)

    # --- generate ------------------------------------------------------------
    records = []
    by_threat = {}      # threat -> [eventID, ...]
    gen_errors = {}
    for t in threats:
        try:
            out = aws.SCENARIO_FUNCTIONS[t](config, context=None)
        except Exception as e:
            gen_errors[t] = repr(e)[:160]
            continue
        events = [e for e in (out if isinstance(out, list) else [out])
                  if isinstance(e, dict)]
        by_threat[t] = [e.get("eventID") for e in events if e.get("eventID")]
        records.extend(events)

    log(f"generated {len(records)} events across {len(by_threat)} threats "
        f"({len(gen_errors)} generator errors)")
    for t, e in gen_errors.items():
        log(f"   GENERATOR ERROR {t}: {e}")
    if not records:
        return 1

    # --- upload as one object ------------------------------------------------
    body = json.dumps({"Records": records}, default=str)
    log_simulator.send_s3_message(gzip.compress(body.encode("utf-8")), aws, config,
                                  f"detector sweep: {len(records)} events")
    log(f"uploaded one object, {len(body)} bytes uncompressed")

    all_ids = {i for ids in by_threat.values() for i in ids}
    c = XsiamClient()
    uploaded_at = time.time()

    # --- wait for ingestion --------------------------------------------------
    log(f"waiting up to {args.wait_minutes}min for ingestion ...")
    seen = {}
    deadline = uploaded_at + args.wait_minutes * 60
    while time.time() < deadline:
        # Read back only as far as this run. Filtering to AWS is necessary but not
        # sufficient: cloud_audit_logs is shared with GCP, and once AWS ingestion is
        # healthy the tenant alone produces enough rows that a fixed 180-minute
        # window exceeds the inline result limit — the query then returns a
        # stream_id instead of rows and the sweep dies for a reason that has nothing
        # to do with ingestion. Scoping the window to the time since upload keeps it
        # small no matter how long the sweep waits.
        window = max(15, int((time.time() - uploaded_at) / 60) + 6)
        rows = c.xql_query(
            'dataset = cloud_audit_logs | filter cloud_provider = "AWS" '
            '| fields _time, cloud_provider_event_id, operation_name_orig, '
            'identity_name, identity_type, identity_sub_type, referenced_resource',
            minutes_back=window, limit=3000)
        seen = {r.get("cloud_provider_event_id"): r for r in rows
                if r.get("cloud_provider_event_id") in all_ids}
        if len(seen) >= len(all_ids) * 0.9:
            break
        log(f"   ingested {len(seen)}/{len(all_ids)} ...")
        time.sleep(60)

    log(f"ingested {len(seen)}/{len(all_ids)} events")

    # --- report per threat ---------------------------------------------------
    print(f"\n{'threat':<34} {'ingest':<8} {'identity':<10} operations")
    print("-" * 92)
    unresolved = []
    missing = []
    for t in sorted(by_threat):
        ids = by_threat[t]
        rows = [seen[i] for i in ids if i in seen]
        ing = f"{len(rows)}/{len(ids)}"
        if not rows:
            missing.append(t)
            print(f"{t:<34} {ing:<8} {'-':<10} NOT INGESTED")
            continue
        resolved = sum(1 for r in rows if r.get("identity_type"))
        idflag = f"{resolved}/{len(rows)}"
        if resolved < len(rows):
            unresolved.append(t)
        ops = ",".join(sorted({str(r.get("operation_name_orig")) for r in rows}))
        print(f"{t:<34} {ing:<8} {idflag:<10} {ops[:44]}")

    # --- alerts --------------------------------------------------------------
    log("\nchecking which detectors fired (5min settle) ...")
    time.sleep(300)
    alerts = c.xql_query(
        'dataset = alerts | filter alert_source contains "ANALYTICS" '
        '| fields _time, alert_name, alert_source, description | sort desc _time',
        minutes_back=60, limit=200)
    byname = defaultdict(int)
    for a in alerts:
        byname[a.get("alert_name")] += 1
    print(f"\n--- native analytics alerts in the last hour: {len(alerts)} ---")
    for n, k in sorted(byname.items(), key=lambda x: -x[1]):
        print(f"  {k:4}  {n}")

    print("\n=== SUMMARY ===")
    print(f"  threats fired      : {len(by_threat)}")
    print(f"  not ingested       : {len(missing)}  {missing if missing else ''}")
    print(f"  identity unresolved: {len(unresolved)}  {unresolved if unresolved else ''}")
    print("\nNOTE: alert counts above are tenant-wide for the window and include "
          "ambient traffic — they indicate which detectors are alive, not a "
          "per-threat mapping. Confirm a specific threat with --threat NAME.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
