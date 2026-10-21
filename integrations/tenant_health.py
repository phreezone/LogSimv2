"""Read the tenant's own HEALTH alerts for problems with what LogSim sends.

Cortex raises an alert (alert_domain DOMAIN_HEALTH) when a parsing rule throws on
ingested data, when a correlation rule fails to run, when a collector goes quiet, and
when a Broker VM collector cannot forward. The alert's description names the dataset,
rule or collector instance and the reason -- usually the exact defect -- yet it lands
in the alert list where nobody debugging a generator thinks to look. This module turns
those alerts into findings (idea taken from the ayman-m/phantom XDM-validation skill).

Read-only: one XQL query over the `alerts` dataset. Used by the dashboard Health tab
(cached, refreshed in the background) and from the command line:

    python -m integrations.tenant_health [--hours 24] [--json]

Exit status 1 when a parsing-rule or correlation-rule error is found.
"""
import argparse
import json
import os
import re
import sys
import time

# Datasets LogSim writes to, matched as substrings of the dataset/product a parsing
# error names. Parsing errors elsewhere in the tenant are reported as "other".
LOGSIM_DATASET_HINTS = (
    "cisco_asa", "cisco_firepower", "fortinet", "check_point", "checkpoint", "zscaler",
    "infoblox", "apache", "httpd", "okta", "proofpoint", "amazon_aws", "aws", "gcp",
    "google", "msft", "microsoft_windows", "windows",
)

_QUERY = ('dataset = alerts | filter alert_domain = "DOMAIN_HEALTH" '
          '| comp count() as n, max(_time) as last_seen, first(description) as sample '
          'by alert_name | sort desc n')

# category -> (dashboard check name, severity when present)
CATEGORIES = {
    "parsing":     ("parsing-rule errors on LogSim data", "error"),
    "correlation": ("correlation-rule errors", "error"),
    "collector":   ("LogSim collectors gone quiet", "warn"),
    "broker":      ("Broker VM collector errors", "warn"),
}


def classify(name, description):
    """(category, detail) for one HEALTH alert, or (None, None) when it is not about
    LogSim's data (threat-intel feed collection errors, indicator housekeeping...)."""
    name = name or ""
    desc = description or ""
    low = f"{name} {desc}".lower()
    if "parsing rule" in low:
        m = re.search(r"dataset (\S+)", desc)
        ds = m.group(1) if m else ""
        reason = desc.split("Error description:")[-1].strip(" .:") if "Error description" in desc else desc
        if ds and not any(h in ds.lower() for h in LOGSIM_DATASET_HINTS):
            return None, None
        return "parsing", f"{ds or 'dataset ?'}: {reason[:160]}"
    if name.startswith("Correlation rule error in"):
        rule = name[len("Correlation rule error in"):].strip()
        reason = desc.split("The reason for this failure was:")[-1].strip()
        return "correlation", f"{rule}: {reason[:160]}"
    if "not collected for an abnormally long time" in low:
        m = re.search(r"collector instance is (\S+?)\.?(\s|$)", desc)
        inst = m.group(1) if m else ""
        if inst.startswith("logsim:") or "windows event collector" in low:
            dur = re.search(r"Duration: ([^.]+)", desc)
            return "collector", f"{inst or name.split(' were not')[0]} ({dur.group(1) if dur else '?'})"
        return None, None
    m = re.match(r"An error occurred in a (syslog collector|windows event collector) on the (\S+)", name)
    if m:
        reason = desc.split("Description message:")[-1].strip(" .:")
        return "broker", f"{m.group(1)} on {m.group(2)}: {reason[:120]}"
    return None, None


def scan(client=None, hours=24, limit=500):
    """{"findings": {category: [{name, count, last_seen, detail}]}, "ignored": n, "hours": h}."""
    if client is None:
        from integrations.xsiam_client import XsiamClient
        client = XsiamClient()
    rows = client.xql_query(_QUERY, minutes_back=int(hours * 60), limit=limit, timeout=150)
    findings = {c: [] for c in CATEGORIES}
    ignored = 0
    for r in rows:
        cat, detail = classify(r.get("alert_name"), r.get("sample"))
        if cat is None:
            ignored += int(r.get("n") or 0)
            continue
        findings[cat].append({"name": r.get("alert_name"), "count": int(r.get("n") or 0),
                              "last_seen": (r.get("last_seen") or 0) / 1000, "detail": detail})
    return {"findings": findings, "ignored": ignored, "hours": hours, "checked_at": time.time()}


def check_rows(result):
    """Dashboard health rows (group / check / status / detail), one per category."""
    rows = []
    for cat, (check, severity) in CATEGORIES.items():
        items = result["findings"].get(cat, [])
        if items:
            total = sum(i["count"] for i in items)
            detail = f"{total} in {result['hours']} h -- " + "; ".join(
                f"{i['detail']} (x{i['count']})" for i in items[:3])
            if len(items) > 3:
                detail += f"; +{len(items) - 3} more"
            rows.append({"group": "XSIAM tenant", "check": check, "status": severity,
                         "detail": detail})
        else:
            rows.append({"group": "XSIAM tenant", "check": check, "status": "ok",
                         "detail": f"none in the last {result['hours']} h"})
    return rows


def _load_env():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    _load_env()
    result = scan(hours=args.hours)
    if args.json:
        print(json.dumps(result, indent=1, default=str))
    else:
        for row in check_rows(result):
            mark = {"ok": "OK  ", "warn": "WARN", "error": "FAIL"}[row["status"]]
            print(f"  {mark} {row['check']}: {row['detail']}")
        print(f"  ({result['ignored']} unrelated HEALTH alerts ignored)")
    bad = result["findings"]["parsing"] or result["findings"]["correlation"]
    return 1 if bad else 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
