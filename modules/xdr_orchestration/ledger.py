# modules/xdr_orchestration/ledger.py
#
# Persistent run ledger (Tier-1 #3). The console's in-memory _ATTACK_SUMMARIES is
# capped and lost on restart, so there is no durable record of what fired, where,
# and whether it detected. This writes one compact JSON object per run to an
# append-only JSONL file, so the console (and the user) can show history and trend
# — "did rule X fire on the last N runs?" — across restarts.
#
# JSONL, not SQLite: append-only, dependency-free, trivially greppable, and safe to
# tail. Writes are best-effort and NEVER fatal to a run (a ledger failure must not
# abort a purple-team run). Entries carry only non-secret summary data — identity
# triad, options, per-step outcome, emitted counts, and the scorecard summary —
# never credentials and never full stdout/stderr.

import json
import os
import time
from typing import List, Optional

# Default location: a gitignored folder at the repo root. Override with XDR_LEDGER_PATH.
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_PKG_DIR, "..", ".."))
DEFAULT_LEDGER_PATH = os.path.join(_REPO_ROOT, "xdr_runs", "ledger.jsonl")


def ledger_path(explicit: Optional[str] = None) -> str:
    """Resolve the ledger path: explicit arg, else XDR_LEDGER_PATH, else default."""
    return explicit or os.getenv("XDR_LEDGER_PATH") or DEFAULT_LEDGER_PATH


def _trim(s, n=400):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + "…"


def summarize_run(summary: dict, *, story_id: Optional[str] = None,
                  options: Optional[dict] = None) -> dict:
    """Project a full orchestrator run summary down to the compact ledger entry.
    Keeps the identity triad, options, scorecard summary, and a one-line-per-step
    outcome — drops bulky stdout/stderr."""
    ident = summary.get("identity") or {}
    steps = []
    for res in summary.get("results", []):
        if res.get("action") != "execute":
            continue
        steps.append({
            "technique_id": res.get("technique_id"),
            "test_numbers": res.get("test_numbers"),
            "ok": res.get("ok"),
            "rc": res.get("rc"),
            "detail": _trim(res.get("detail"), 160),
        })
    sc = summary.get("scorecard") or {}
    sc_small = None
    if sc:
        sc_small = {
            "available": sc.get("available"),
            "score": sc.get("score"),
            "matched": len(sc.get("matched") or []),
            "missing": len(sc.get("missing") or []),
            "incidents": len(sc.get("incidents") or []),
            "coalesced": sc.get("coalesced"),
        }
    return {
        "ts": time.time(),
        "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "story": summary.get("story"),
        "story_id": story_id,
        "ok": summary.get("ok"),
        "aborted": summary.get("aborted"),
        "identity": {"user": ident.get("username"), "host": ident.get("hostname"),
                     "ip": ident.get("ip"), "source": ident.get("source")},
        "options": options or {},
        "emitted": summary.get("emitted"),
        "selected_steps": summary.get("selected_steps"),
        "timing": summary.get("timing"),
        "techniques": steps,
        "scorecard": sc_small,
    }


def record_run(entry: dict, *, path: Optional[str] = None, verbose: bool = True) -> Optional[str]:
    """Append one entry as a JSON line. Best-effort: returns the path on success,
    None on any failure (logged, never raised)."""
    p = ledger_path(path)
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        if verbose:
            print(f"[XDR] ledger += {entry.get('story_id') or entry.get('story')} -> {p}")
        return p
    except Exception as e:
        if verbose:
            print(f"[XDR] ledger write skipped (non-fatal): {e}")
        return None


def read_runs(limit: int = 50, *, path: Optional[str] = None) -> List[dict]:
    """Return the most recent `limit` entries, newest first. Empty on any failure."""
    p = ledger_path(path)
    try:
        with open(p, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return []
    except Exception:
        return []
    out = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
        if len(out) >= limit:
            break
    return out
