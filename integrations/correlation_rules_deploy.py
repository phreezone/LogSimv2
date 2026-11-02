"""Push repo rule definitions to the tenant as in-place updates, for rules that drifted.

    python integrations/correlation_rules_deploy.py                 # dry run: list what differs
    python integrations/correlation_rules_deploy.py --apply [NAME]  # update all drifted, or one

The repo is the source here (the reverse of correlation_rules_sync.py --write). Each rule
is sent with its live rule_id, so the tenant updates it rather than creating a copy, and
is read back and compared field-for-field before the next one is sent.
"""

import argparse
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from integrations.xsiam_client import XsiamClient  # noqa: E402
from integrations.correlation_rules_sync import _load_repo, _same  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("name", nargs="?", help="deploy only this rule")
    args = ap.parse_args()

    c = XsiamClient()
    live = {r["name"]: r for r in c.get_correlation_rules()}
    repo = {}
    for doc, _ in _load_repo().values():
        for it in (doc if isinstance(doc, list) else [doc]):
            if isinstance(it, dict) and it.get("name") in live:
                repo.setdefault(it["name"], it)
    todo = [n for n in sorted(repo) if not _same(repo[n], live[n])
            and (args.name is None or n == args.name)]
    print(f"{len(todo)} rule(s) differ from the tenant")
    failed = 0
    for n in todo:
        rid = live[n]["rule_id"]
        if not args.apply:
            print(f"  would update {rid:>5}  {n}")
            continue
        payload = {**{k: v for k, v in repo[n].items() if k != "rule_id"}, "rule_id": rid}
        rep = c.insert_correlation_rules([payload])
        rep = rep.get("reply", rep) or {}
        got = {r["name"]: r for r in c.get_correlation_rules()}.get(n)
        ok = bool(got) and got["rule_id"] == rid and _same(repo[n], got)
        failed += not ok
        print(f"  {'updated' if ok else 'FAILED '} {rid:>5}  {n}  "
              f"{'' if ok else rep.get('errors') or rep}")
        if not ok:
            break
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
