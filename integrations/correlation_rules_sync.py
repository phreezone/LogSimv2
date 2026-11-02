"""Keep `XSIAM imports/` in step with the correlation rules actually live in the tenant.

Rules get edited in the XSIAM console far more often than they get exported back,
so the repo copy drifts: on 2026-11-02, 27 rules had tenant-side query edits the
repo never saw and 26 rules existed only in the tenant. A review run against the
repo files would have been reviewing queries that no longer run.

    python integrations/correlation_rules_sync.py            # report drift, exit 1 if any
    python integrations/correlation_rules_sync.py --write    # pull tenant state into the repo

--write rewrites every repo rule whose name matches a live rule (in bundle.json and in
its own file -- the same rule ships in both), creates a file for each tenant-only rule,
and records name -> rule_id in rule_ids.json. Rule ids live there rather than in the
rule files because a rule_id in an import file turns a create into an update, and an
id the tenant does not know fails the import. Rules that exist only in the repo are
reported and left alone: they are usually originals a v2 replaced, and deleting
them is a decision, not a sync.
"""

import argparse
import glob
import io
import json
import os
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from integrations.xsiam_client import XsiamClient  # noqa: E402

RULES_DIR = os.path.join(_ROOT, "XSIAM imports")
IDS_FILE = os.path.join(RULES_DIR, "rule_ids.json")
_UNSAFE = re.compile(r'[<>:"/\\|?*\[\]]')


def _norm(q):
    return re.sub(r"\s+", " ", q or "").strip()


def _same(a, b):
    """Equal for review purposes: whitespace-insensitive query, everything else exact."""
    keys = (set(a) | set(b)) - {"rule_id", "xql_query"}
    return _norm(a.get("xql_query")) == _norm(b.get("xql_query")) and \
        all(a.get(k) == b.get(k) for k in keys)


def _load_repo():
    """{path: (doc, compact)} for every JSON file holding correlation rules."""
    out = {}
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.json"))):
        if path == IDS_FILE:
            continue
        with io.open(path, encoding="utf-8") as fh:
            text = fh.read()
        try:
            doc = json.loads(text)
        except ValueError:
            continue
        items = doc if isinstance(doc, list) else [doc]
        if any(isinstance(i, dict) and "xql_query" in i for i in items):
            # UI exports are one line; hand-written files are indented. Keep each as found.
            out[path] = (doc, "\n" not in text.strip())
    return out


def _dump(path, doc, compact):
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        if compact:
            json.dump(doc, fh)
        else:
            json.dump(doc, fh, indent=2)
            fh.write("\n")


def _as_file_item(live, had_id):
    item = dict(live)
    if not had_id:
        item.pop("rule_id", None)
    return item


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--write", action="store_true", help="pull tenant state into the repo")
    args = ap.parse_args()

    live = {r["name"]: r for r in XsiamClient().get_correlation_rules()}
    repo = _load_repo()

    seen, drifted = set(), []
    for path, (doc, compact) in repo.items():
        items = doc if isinstance(doc, list) else [doc]
        changed = False
        for i, it in enumerate(items):
            if not isinstance(it, dict) or it.get("name") not in live:
                continue
            seen.add(it["name"])
            if _same(it, live[it["name"]]):
                continue
            drifted.append((os.path.basename(path), it["name"]))
            items[i] = _as_file_item(live[it["name"]], "rule_id" in it)
            changed = True
        if changed and args.write:
            _dump(path, items if isinstance(doc, list) else items[0], compact)

    tenant_only = sorted(set(live) - seen)
    repo_names = {it.get("name") for doc, _ in repo.values()
                  for it in (doc if isinstance(doc, list) else [doc]) if isinstance(it, dict)}
    repo_only = sorted(n for n in repo_names - set(live) if n)

    print(f"{len(live)} live rules, {len(drifted)} drifted, "
          f"{len(tenant_only)} tenant-only, {len(repo_only)} repo-only")
    for f, n in drifted:
        print(f"  drift      {n}  [{f}]")
    for n in tenant_only:
        print(f"  tenant-only {live[n]['rule_id']:>5}  {n}")
    for n in repo_only:
        print(f"  repo-only  {n}")

    if args.write:
        for n in tenant_only:
            fname = _UNSAFE.sub("", n.replace("—", "-").replace("≥", ">=")).strip()
            _dump(os.path.join(RULES_DIR, fname + ".json"), [_as_file_item(live[n], False)], False)
        ids = {n: live[n]["rule_id"] for n in sorted(live)}
        _dump(IDS_FILE, ids, False)
        print("written")
        return 0
    return 1 if (drifted or tenant_only) else 0


if __name__ == "__main__":
    sys.exit(main())
