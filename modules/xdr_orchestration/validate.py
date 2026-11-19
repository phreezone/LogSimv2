# modules/xdr_orchestration/validate.py
#
# Offline story validator. A story (especially a hand-written YAML one) can name a
# module that doesn't exist, an event its module never emits, or an unvalidated
# technique, and nothing noticed until the run: _emit() quietly logged "module not
# loaded" and the scorecard counted the step as untracked or missed. This checks a
# story against the repo itself -- no tenant, no box, no imports of generator
# modules -- so a bad story is caught at load time and refused before it fires.
#
# Problems are {level, step, message}:
#   error   -- the run would be wrong (unknown module/event, no technique id). The
#              orchestrator refuses to fire; a YAML file with errors is not registered.
#   warning -- the run works but something is off (technique outside the validated
#              palette, a correlation rule name that no longer exists in the catalog).
# Network events nothing is built to detect are NOT problems here -- the scorecard
# already lists them as untracked.

import json
import os
import re
from functools import lru_cache
from typing import List

from .expectations import (_MODULES_DIR, CORRELATION_ALERTS, RULE_PREFIX,
                           _module_index)

_REPO_ROOT = os.path.dirname(_MODULES_DIR)
RULE_CATALOG = os.path.join(_REPO_ROOT, "XSIAM imports", "rule_ids.json")
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_TESTS_RE = re.compile(r"^\d+(\s*,\s*\d+)*$")


@lru_cache(maxsize=None)
def _module_source(base: str) -> str:
    try:
        with open(os.path.join(_MODULES_DIR, base + ".py"), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def module_emits(module_name: str, event: str) -> bool:
    """True when the module's source names `event` as a quoted literal -- every
    generator dispatches scenario_event on string literals, so an event that never
    appears quoted cannot be produced."""
    base = _module_index().get(module_name)
    if not base:
        return False
    return re.search(r"[\"']" + re.escape(event) + r"[\"']", _module_source(base)) is not None


@lru_cache(maxsize=1)
def _rule_names() -> tuple:
    try:
        with open(RULE_CATALOG, encoding="utf-8") as fh:
            return tuple(json.load(fh).keys())
    except Exception:
        return ()


def _p(level, step, message):
    return {"level": level, "step": step, "message": message}


def validate_story(story) -> List[dict]:
    """Every problem with `story`, in step order. Empty list = clean."""
    from .stories import TECHNIQUE_CATALOG
    out = []
    if not getattr(story, "id", None):
        out.append(_p("error", None, "story has no id"))
    if not story.steps:
        out.append(_p("error", None, "story has no steps"))
    index = _module_index()
    rules = _rule_names()
    for i, step in enumerate(story.steps, 1):
        tech = step.technique or {}
        tid = tech.get("id")
        if not tid:
            out.append(_p("error", i, "step has no technique id"))
        elif not _TECH_RE.match(str(tid)):
            out.append(_p("error", i, f"'{tid}' is not an ATT&CK technique id (T####[.###])"))
        elif tid not in TECHNIQUE_CATALOG:
            out.append(_p("warning", i, f"{tid} is outside the validated technique palette "
                                        "(no ATT&CK mapping or endpoint expectation; the "
                                        "box may lack its prereqs)"))
        if tech.get("executor") == "builtin":
            from .payloads import PAYLOADS
            if tech.get("payload") not in PAYLOADS:
                out.append(_p("error", i, f"builtin step needs a known payload "
                                          f"(got '{tech.get('payload')}'; known: "
                                          + ", ".join(sorted(PAYLOADS)) + ")"))
            if step.prereqs:
                out.append(_p("warning", i, "prereqs is ignored for builtin payload steps"))
        elif tech.get("executor") not in (None, "winrm_atomic"):
            out.append(_p("error", i, f"unknown executor '{tech.get('executor')}' "
                                      "(winrm_atomic or builtin)"))
        tn = tech.get("test_numbers")
        if tn is not None and not _TESTS_RE.match(str(tn)):
            out.append(_p("error", i, f"test_numbers '{tn}' must be digits, comma-separated"))
        for ne in step.network or []:
            if ne.module not in index:
                out.append(_p("error", i, f"unknown module '{ne.module}' (module NAMEs: "
                                          + ", ".join(sorted(index)) + ")"))
                continue
            if not module_emits(ne.module, ne.event):
                out.append(_p("error", i, f"{ne.module} never emits event '{ne.event}'"))
                continue
            if rules:
                vendor = RULE_PREFIX.get(ne.module, ne.module)
                for key in ((ne.module, ne.event), ("*", ne.event)):
                    for name in CORRELATION_ALERTS.get(key, []):
                        name = name.format(vendor=vendor)
                        if not any(r.startswith(name) for r in rules):
                            out.append(_p("warning", i,
                                          f"{ne.module}/{ne.event}: no rule named '{name}…' in "
                                          "rule_ids.json -- the scorecard will count it as a miss "
                                          "(vendor not imported?)"))
    return out


def errors(problems) -> list:
    return [p for p in problems if p["level"] == "error"]


def format_problems(problems) -> str:
    return "\n".join(
        f"  {p['level'].upper():7} {('step ' + str(p['step'])) if p['step'] else 'story'}: {p['message']}"
        for p in problems)
