#!/usr/bin/env python
"""Validate the XDR executor without firing an attack.

Default (live) mode runs only NON-EXECUTING Atomic actions against the box —
`-ShowDetailsBrief` and `-CheckPrereqs` — to prove the WinRM->Atomic invocation
path end to end. It never runs a technique unless you pass --execute with an
explicit --technique/--test, so the harness is safe to run casually.

    python tests/xdr_executor_check.py                 # dry-run + live non-exec checks
    python tests/xdr_executor_check.py --dry-run-only   # no box needed
    python tests/xdr_executor_check.py --technique T1082 --test 1 --execute   # FIRES it (opt-in)
"""
import argparse
import json
import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from dotenv import load_dotenv  # noqa: E402
from modules.xdr_orchestration import (  # noqa: E402
    WorkstationConnection, ConnectionError,
    WinRMAtomicExecutor, DryRunExecutor,
)
from modules.xdr_orchestration.executor import _input_args_to_ps_hashtable  # noqa: E402


def _load_config():
    with open(os.path.join(_REPO, "config.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def _p(r):
    mark = "OK " if r.ok else "ERR"
    print(f"  [{mark}] {r.action} {r.technique_id} rc={r.rc} — {r.detail}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--technique", default="T1082", help="ATT&CK technique id (default T1082)")
    ap.add_argument("--test", default="1", help="Atomic test number(s), e.g. 1 or 1,2 (default 1)")
    ap.add_argument("--dry-run-only", action="store_true", help="skip the live box entirely")
    ap.add_argument("--execute", action="store_true",
                    help="OPT-IN: actually FIRE the technique on the box (and clean up after)")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    load_dotenv(os.path.join(_REPO, ".env"))

    # 1) DryRun — no box. Exercises every action + the input-args renderer.
    print("== DryRunExecutor (no box) ==")
    dry = DryRunExecutor()
    _p(dry.show_details(args.technique, args.test))
    _p(dry.check_prereqs(args.technique, args.test))
    _p(dry.execute(args.technique, args.test, input_args={"output_file": r"C:\t.txt", "port": 443}))
    _p(dry.cleanup(args.technique, args.test, input_args={"output_file": r"C:\t.txt"}))
    print("  input-args PS hashtable render:",
          _input_args_to_ps_hashtable({"c2": "evil.test", "port": 443}))

    if args.dry_run_only:
        return 0

    # 2) Live — NON-EXECUTING probes against the real box.
    print("\n== WinRMAtomicExecutor (live box, non-executing) ==")
    try:
        conn = WorkstationConnection.from_config(_load_config())
    except ConnectionError as e:
        print(f"  CONFIG ERROR: {e}", file=sys.stderr)
        return 2
    ex = WinRMAtomicExecutor(conn)
    print(f"  atomic module: {ex.atomic_psd1}")
    d = ex.show_details(args.technique, args.test); _p(d)
    c = ex.check_prereqs(args.technique, args.test); _p(c)

    ok = d.ok  # show_details resolving the technique proves the invocation path
    if not d.ok:
        print("  NOTE: show_details failed — see detail above (EDR prevent mode? module path?)")

    # 3) OPT-IN execution.
    if args.execute:
        print(f"\n== FIRING {args.technique} test {args.test} (opt-in) ==")
        r = ex.execute(args.technique, args.test); _p(r)
        print("  --- running cleanup ---")
        _p(ex.cleanup(args.technique, args.test))
        ok = ok and r.ok

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
