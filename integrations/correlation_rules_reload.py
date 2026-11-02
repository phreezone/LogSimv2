"""Delete every correlation rule from the tenant, then recreate all of them from an export.

    python integrations/correlation_rules_reload.py <export.json> <ledger.json>

Written 2026-11-02 to clear a wedged correlation scheduler (zero alerts since
2026-10-14, XQL refusing queries on the parallel-query cap). The export is what
correlations/get returned, every field included.

Safety, in order:
  1. Every live rule must equal its export entry field-for-field, and the two sets
     must match exactly, or nothing is touched.
  2. Deletes go one rule at a time by exact name (the API has no rule_id filter).
     Each must report exactly the expected rule_id, or the run stops.
  3. Inserts drop rule_id (a create, not an update). The tenant then has to match
     the export field-for-field, apart from the new ids.
The ledger records old id -> deleted -> new id after every step, and a rerun
resumes from it, so an interrupted run never loses track of a rule.
"""

import json
import os
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from integrations.xsiam_client import XsiamClient, XsiamError  # noqa: E402

INSERT_BATCH = 20
PROBE_MINUTES = 5


def _strip(rule):
    return {k: v for k, v in rule.items() if k != "rule_id"}


def _save(path, ledger):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(ledger, fh, indent=2)


def _probe_xql(c):
    try:
        c.xql_query("dataset = okta_sso_raw | fields _time | limit 1", minutes_back=10, timeout=120)
        return "OK"
    except XsiamError as e:
        return "parallel-cap" if "parallel running queries" in str(e) else f"ERR {str(e)[:120]}"


def main():
    export_path, ledger_path = sys.argv[1], sys.argv[2]
    export = json.load(open(export_path, encoding="utf-8"))
    by_name = {r["name"]: r for r in export}
    c = XsiamClient()
    ledger = json.load(open(ledger_path, encoding="utf-8")) if os.path.exists(ledger_path) else {
        r["name"]: {"old_id": r["rule_id"], "deleted": False, "new_id": None} for r in export}

    # 1. Verify the export is a complete, exact copy of what is live (fresh runs only).
    live = {r["name"]: r for r in c.get_correlation_rules()}
    if not any(e["deleted"] for e in ledger.values()):
        missing = set(live) ^ set(by_name)
        differ = [n for n in live if n in by_name and live[n] != by_name[n]]
        if missing or differ:
            sys.exit(f"ABORT: export does not match tenant. set-diff={sorted(missing)} differ={differ}")
        print(f"verified: all {len(live)} live rules match the export exactly")

    # 2. Delete.
    for name, e in ledger.items():
        if e["deleted"]:
            continue
        if name not in live:
            sys.exit(f"ABORT: {name!r} not live but not marked deleted -- investigate before continuing")
        got = c.delete_correlation_rule(name)
        if got != [e["old_id"]]:
            _save(ledger_path, ledger)
            sys.exit(f"ABORT: deleting {name!r} removed {got}, expected [{e['old_id']}]")
        e["deleted"] = True
        _save(ledger_path, ledger)
        print(f"  deleted {e['old_id']:>5}  {name}")

    left = [r for r in c.get_correlation_rules() if r["name"] in by_name]
    if left and not any(e["new_id"] for e in ledger.values()):
        sys.exit(f"ABORT: {len(left)} rules still present after deletes")
    print(f"tenant holds 0 of the {len(by_name)} rules")

    # 3. With no rules scheduled, does XQL free up?
    if not any(e["new_id"] for e in ledger.values()):
        for i in range(PROBE_MINUTES):
            print(f"  xql probe {i + 1}/{PROBE_MINUTES}: {_probe_xql(c)}")
            if i < PROBE_MINUTES - 1:
                time.sleep(60)

    # 4. Recreate.
    todo = [n for n, e in ledger.items() if not e["new_id"]]
    present = {r["name"]: r["rule_id"] for r in c.get_correlation_rules()}
    for n in list(todo):              # an insert that landed before an interruption
        if n in present:
            ledger[n]["new_id"] = present[n]
            todo.remove(n)
    for i in range(0, len(todo), INSERT_BATCH):
        batch = todo[i:i + INSERT_BATCH]
        rep = c.insert_correlation_rules([_strip(by_name[n]) for n in batch])
        errs = (rep.get("reply", rep) or {}).get("errors") or []
        present = {r["name"]: r["rule_id"] for r in c.get_correlation_rules()}
        for n in batch:
            if n in present:
                ledger[n]["new_id"] = present[n]
        _save(ledger_path, ledger)
        print(f"  inserted batch {i // INSERT_BATCH + 1}: "
              f"{sum(1 for n in batch if ledger[n]['new_id'])}/{len(batch)} created, errors={errs}")

    # 5. Verify.
    live = {r["name"]: r for r in c.get_correlation_rules()}
    missing = [n for n in by_name if n not in live]
    differ = [n for n in by_name if n in live and _strip(live[n]) != _strip(by_name[n])]
    print(f"restored {len(by_name) - len(missing)}/{len(by_name)}; missing={missing}; field-diffs={differ}")
    return 1 if (missing or differ) else 0


if __name__ == "__main__":
    sys.exit(main())
