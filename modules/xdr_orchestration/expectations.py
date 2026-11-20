# modules/xdr_orchestration/expectations.py
#
# What should each emitted network event trigger? Answered from the EMITTER, not
# from hand-written guesses in the story.
#
# The scorecard used to match network steps against hand-maintained needle lists
# ("Share Enumeration", "Command and Control", ...). Those drifted from the real
# alert names, so a detection that fired read as a miss (2026-11-17: the SMB
# share-enumeration event alerts as "Rare SMB session to a remote host").
#
# The generator modules already declare which native XSIAM analytic each event is
# built to trip (get_threat_info()/ANALYTIC_ALERTS, read via threat_catalog). This
# module reads that declaration, and adds the shipped CORRELATION rule an event is
# built for where there is one (Infoblox and the scenario-only events declare no
# native analytic -- their alerts are correlation rules in "XSIAM imports/").
#
# Result: one detection per distinct alert, with its alternates, plus the list of
# emitted events nothing is expected to detect (shown, not scored).

import importlib
import os
import re
from functools import lru_cache
from typing import Iterable, List, Tuple

_MODULES_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Correlation-rule names prefix the vendor differently from the module NAME.
RULE_PREFIX = {
    "Check Point Firewall": "Check Point",
    "Cisco ASA Firewall":   "Cisco ASA",
    "Infoblox NIOS":        "Infoblox",
    "Zscaler Web Gateway":  "Zscaler",
}

# Correlation rules an event is built to trip. Keys are (module NAME, event); "*"
# matches any module, and "{vendor}" is the rule's vendor prefix (RULE_PREFIX).
# Every name is a prefix of a rule in "XSIAM imports/rule_ids.json":
#   C2_BEACON  -> "Infoblox — DNS C2 Beacon (Recurring Domain Queries)"
#   DNS_TUNNEL -> "Infoblox — DNS Tunneling (TXT Query Burst)"
#   web_c2_beacon / C2_EGRESS -> "<vendor> — Web C2 Beacon (entity-mapped v2)"
#     (C2_EGRESS sends 10-16 callbacks; the rule fires at >= 8 per 15 min)
CORRELATION_ALERTS = {
    ("Infoblox NIOS", "C2_BEACON"):           ["Infoblox — DNS C2 Beacon"],
    ("Infoblox NIOS", "DNS_TUNNEL"):          ["Infoblox — DNS Tunneling"],
    ("Zscaler Web Gateway", "web_c2_beacon"): ["Zscaler — Web C2 Beacon"],
    ("*", "C2_EGRESS"):                       ["{vendor} — Web C2 Beacon"],
}

_NAME_RE = re.compile(r'^NAME\s*=\s*["\'](.+?)["\']', re.MULTILINE)


@lru_cache(maxsize=1)
def _module_index() -> dict:
    """{module NAME: python module basename}, read from the source text so building
    it imports nothing."""
    index = {}
    for fn in os.listdir(_MODULES_DIR):
        if not fn.endswith(".py") or fn.startswith("_"):
            continue
        try:
            with open(os.path.join(_MODULES_DIR, fn), encoding="utf-8") as fh:
                m = _NAME_RE.search(fh.read())
        except OSError:
            continue
        if m:
            index.setdefault(m.group(1), fn[:-3])
    return index


@lru_cache(maxsize=None)
def native_alerts(module_name: str) -> dict:
    """{event: native analytic name} the module declares. {} when the module is
    unknown, fails to import, or declares none (Infoblox, for one)."""
    base = _module_index().get(module_name)
    if not base:
        return {}
    try:
        from modules import threat_catalog
        mod = importlib.import_module(f"modules.{base}")
        return {t["event"]: t["alert"] for t in threat_catalog.analytic_threats(mod)}
    except Exception:
        return {}


def expected_for_event(module_name: str, event: str) -> List[str]:
    """Alert names (alternates of ONE detection) this event should trip: the
    module's native analytic first, then the correlation rule built for it."""
    out = []
    native = native_alerts(module_name).get(event)
    if native:
        out.append(native)
    vendor = RULE_PREFIX.get(module_name, module_name)
    for key in ((module_name, event), ("*", event)):
        for name in CORRELATION_ALERTS.get(key, []):
            name = name.format(vendor=vendor)
            if name not in out:
                out.append(name)
    return out


def network_detections(network: Iterable) -> Tuple[list, list]:
    """Group a step's NetworkEvents into detections.

    Returns (detections, untracked):
      detections  [{label, needles, emitted}] -- one per distinct alert. Events that
                  trip the same alert (three SMB events -> "Rare SMB session to a remote
                  host") collapse into one detection listing every emitter.
      untracked   ["module/event"] emitted with no known detection (shown, not scored).
    """
    groups, untracked = {}, []
    for ne in network or []:
        tag = f"{ne.module}/{ne.event}"
        needles = expected_for_event(ne.module, ne.event)
        if not needles:
            if tag not in untracked:
                untracked.append(tag)
            continue
        g = groups.setdefault(tuple(needles), {"label": needles[0],
                                               "needles": list(needles), "emitted": []})
        if tag not in g["emitted"]:
            g["emitted"].append(tag)
    return list(groups.values()), untracked
