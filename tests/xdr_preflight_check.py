#!/usr/bin/env python
"""Standalone preflight + identity-discovery harness for the XDR orchestration
module's WorkstationConnection.

This is the fastest feedback loop for the P1 foundation: it builds the connection
from config.json + .env exactly the way the orchestrator will, runs the fail-closed
preflight against the live box, and prints the human-readable report (including the
discovered user/host/IP the synthetic logs would carry).

Usage (from repo root):
    python tests/xdr_preflight_check.py            # live box per config.json
    python tests/xdr_preflight_check.py --stub     # no-box: exercise the stub path
    python tests/xdr_preflight_check.py --json      # machine-readable report

Exit code is 0 only when preflight is GREEN, so this doubles as a CI/gate check.
"""
import argparse
import json
import os
import sys

# Make the repo root importable when run from anywhere.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from dotenv import load_dotenv  # noqa: E402
from modules.xdr_orchestration import WorkstationConnection, ConnectionError  # noqa: E402


def _load_config():
    with open(os.path.join(_REPO, "config.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stub", action="store_true",
                    help="force transport='stub' (no live box) to exercise the seed path")
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    ap.add_argument("--require-xsiam", action="store_true",
                    help="also check XSIAM management-API reachability (not yet wired — will FAIL until xsiam_client exists)")
    args = ap.parse_args()

    # The preflight banner uses ✓/✗ glyphs; a Windows console defaults to cp1252
    # and would raise UnicodeEncodeError. Force UTF-8 so the report prints anywhere.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    load_dotenv(os.path.join(_REPO, ".env"))
    config = _load_config()

    if args.stub:
        # Override transport in-memory so we don't have to edit config.json.
        config.setdefault("xdr_orchestration", {}).setdefault("connection", {})["transport"] = "stub"

    try:
        conn = WorkstationConnection.from_config(config)
    except ConnectionError as e:
        print(f"CONFIG ERROR: {e}", file=sys.stderr)
        return 2

    if not args.json:
        print("Target:", json.dumps(conn.describe(), indent=2))
        print("-" * 60)

    report = conn.preflight(require_xsiam=args.require_xsiam, force=True)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render())

    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
