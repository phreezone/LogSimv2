# modules/xdr_orchestration/scorecard.py
#
# Closed-loop detection scorecard (Tier-1 #1). The orchestrator fires a story and
# emits aligned network logs; this closes the loop — it pulls the alerts/incidents
# the run actually produced from XSIAM and scores them against the DETECTIONS the run
# should produce: network ones derived from each emitting module (expectations.py),
# endpoint ones from Step.expected_alerts. Every row says which kind it is, so a miss
# reads as "sent, not detected" vs "endpoint-only, agent didn't alert".
#
# It answers the three questions a purple-team run exists to answer:
#   1. Which expected detections actually fired? (coverage)
#   2. Did endpoint + network coalesce into ONE incident, or split? (stitch)
#   3. What else fired that we didn't expect? (noise / surprises)
#
# Design: NEVER fatal. No XSIAM creds, an API error, or the integration not being
# importable all return {available: False, reason}, exactly like the orchestrator's
# incident-cleanup. An alert counts only if it is tied to the run (box user, host,
# internal IP, or a run domain -- run_markers); endpoint rows then match on the
# step's MITRE technique id, network rows on the alert names derived from the
# emitting module. get_alerts has no server-side name/host filter, so the whole
# window is fetched (sized by alert_fetch_limit) and filtered here. A fake client
# can be injected for offline testing.

import math
import os
import re
import time
from typing import List, Optional

# The alert sources a run can produce. The analytics/correlation three are what the
# synthetic network events trip; the agent sources are where the Cortex agent's own
# detections of the REAL techniques land (2026-11-18: the box's alerts arrive as
# "XDR Agent" -- without it no endpoint expectation could ever match). Vulnerability
# and posture sources are left out: they never come from a fired event.
_DEFAULT_SOURCES = ("XDR Analytics", "XDR Analytics BIOC", "Correlation",
                    "XDR Agent", "XDR BIOC", "XDR IOC")

# get_alerts pages 100 at a time, newest first, so a cap that is too small drops the
# run's EARLIEST alerts. Size it from the window (the tenant runs ~13 alerts/min
# across these sources; 30/min leaves headroom) and report when it was hit.
ALERT_FETCH_MIN = 300
ALERT_FETCH_PER_MIN = 30
ALERT_FETCH_CAP = 3000


def alert_fetch_limit(minutes_back: int) -> int:
    return min(ALERT_FETCH_CAP, max(ALERT_FETCH_MIN, int(minutes_back) * ALERT_FETCH_PER_MIN))


def _lower(s):
    return (s or "").lower()


def _selected(story, selected_steps):
    keep = set(selected_steps) if selected_steps else None
    return [(i, s) for i, s in enumerate(story.steps, 1) if keep is None or i in keep]


def _sent(network, vendors):
    """The step's network events whose vendor was sent (vendors None = all, for
    summaries from before vendor selection existed)."""
    if vendors is None:
        return network
    return [ne for ne in (network or []) if ne.module in vendors]


def _emitted(network, idx, emitted_map):
    """The step's network events ACTUALLY emitted this run (orchestrator's
    summary["network_emitted"]). When emitted_map is None (summaries from before it
    was recorded, or a static manifest with no run) fall back to all of them, so the
    old vendor-only path is unchanged. JSON round-trips int keys to str, so accept
    both. A conditional event gated off (only_if_output) is absent here, so it is
    neither an expectation nor a miss."""
    if emitted_map is None:
        return network
    allowed = set(emitted_map.get(idx) or emitted_map.get(str(idx)) or [])
    return [ne for ne in (network or []) if f"{ne.module}/{ne.event}" in allowed]


def collect_expectations(story, selected_steps: Optional[List[int]] = None,
                         vendors=None, emitted_map=None) -> list:
    """The DETECTIONS this run should produce -- one row per distinct alert, not per
    alert-name guess, so the score counts detections rather than needles.

    Each row: {step, narrative, technique_id, mitre, source, label, needles, emitted}.
      source   "network"  -- we emitted a synthetic event built to trip this alert;
                             a miss means the detector didn't fire on what we sent.
               "endpoint" -- no synthetic signal; it rests on the Cortex agent seeing
                             the real technique. A miss is an endpoint-detection gap.
      needles  alternates of the ONE alert (any match counts the detection once).
      emitted  for network rows, the "module/event"s that carry the signal.
    Network rows are derived from each step's emitting modules (expectations.py);
    endpoint rows come from step.expected_alerts (TECHNIQUE_CATALOG by default).
    Limited to `selected_steps` (1-based) so a partial run is scored on what it fired."""
    from .expectations import network_detections
    out = []
    for idx, step in _selected(story, selected_steps):
        tech = (step.technique or {}).get("id")
        mitre = getattr(step, "mitre", None) or {}
        base = {"step": idx, "narrative": step.narrative,
                "technique_id": tech, "mitre": mitre}
        endpoint = list(getattr(step, "expected_alerts", None) or [])
        if endpoint:
            out.append({**base, "source": "endpoint",
                        "label": mitre.get("technique") or tech or endpoint[0],
                        "needles": endpoint, "emitted": []})
        net = _emitted(_sent(getattr(step, "network", None), vendors), idx, emitted_map)
        detections, _ = network_detections(net)
        for d in detections:
            out.append({**base, "source": "network", **d})
    return out


def untracked_emissions(story, selected_steps: Optional[List[int]] = None,
                        vendors=None, emitted_map=None) -> list:
    """Network events the run emits that no known analytic or rule is built to detect
    (e.g. Zscaler large_download). Shown for transparency; never scored."""
    from .expectations import network_detections
    out = []
    for idx, step in _selected(story, selected_steps):
        net = _emitted(_sent(getattr(step, "network", None), vendors), idx, emitted_map)
        for tag in network_detections(net)[1]:
            out.append({"step": idx, "emitted": tag})
    return out


WINDOW_FLOOR_MIN = 15     # never look back less than this
WINDOW_BUFFER_MIN = 5     # slack before the run start (clock skew, anchor events)


def run_window_minutes(summary: dict, now: Optional[float] = None) -> int:
    """Lookback (minutes) that covers the whole run: from `summary["started_at"]`
    (minus a buffer) to now, floored at WINDOW_FLOOR_MIN. Called at scoring time, so
    a scorecard pulled after a settle wait, or a Re-score clicked an hour later,
    still reaches back to the run's first alert. Summaries from before started_at was
    recorded fall back to the floor."""
    started = (summary or {}).get("started_at")
    if not started:
        return WINDOW_FLOOR_MIN
    age_min = ((now or time.time()) - float(started)) / 60.0
    return max(WINDOW_FLOOR_MIN, int(math.ceil(age_min)) + WINDOW_BUFFER_MIN)


def _mitre_ids(a: dict) -> set:
    """Technique ids an alert is tagged with. XSIAM sends
    mitre_technique_id_and_name as ["T1059.001 - Command and Scripting ...", ...]."""
    out = set()
    for s in _flat(a.get("mitre_technique_id_and_name")):
        tid = s.split(" ", 1)[0].strip().upper()
        if tid.startswith("T"):
            out.add(tid)
    return out


def technique_hit(tid: Optional[str], a: dict) -> bool:
    """True when the alert is tagged with the step's technique: the same id, its
    parent (alert says T1547, step is T1547.001), or a sub-technique of it (alert
    says T1003.001, step is T1003). Sibling sub-techniques do NOT match."""
    if not tid:
        return False
    tid = tid.upper()
    base = tid.split(".")[0]
    for t in _mitre_ids(a):
        if t == tid or t == base or (t.split(".")[0] == base and "." not in tid):
            return True
    return False


def find_detection(exp: dict, alerts: list, attrs: dict, used=None) -> dict:
    """Find the alert that satisfies one expectation. Only alerts tied to the run
    (attrs[id(alert)] is a marker name) count -- a same-named alert from background
    traffic or another host is NOT this run's detection.

    Endpoint rows try the step's MITRE technique id first (exact, independent of
    alert naming), then the name alternates. Network rows use the names derived
    from the emitting module.

    Returns {"alert", "needle", "matched_by": "mitre"|"name", "via"} on a hit, else
    {"unattributed": alert-or-None} -- the first same-named alert that fired but
    carries none of the run's markers, so a miss can say "it fired, not for us".

    `used` holds ids of alerts already credited to another row: one alert is one
    detection, so it cannot satisfy two rows (e.g. "Suspicious port scan" contains
    both PAN's needle and Zscaler's "Port Scan")."""
    used = used if used is not None else set()
    if exp.get("source") == "endpoint" and exp.get("technique_id"):
        for a in alerts:
            if id(a) in used:
                continue
            if attrs.get(id(a)) and technique_hit(exp["technique_id"], a):
                return {"alert": a, "needle": exp["technique_id"],
                        "matched_by": "mitre", "via": attrs[id(a)]}
    stray = None
    for needle in exp.get("needles") or []:
        n = _lower(needle)
        for a in alerts:
            if n not in _lower(a.get("name")):
                continue
            if attrs.get(id(a)) and id(a) not in used:
                return {"alert": a, "needle": needle, "matched_by": "name",
                        "via": attrs[id(a)]}
            stray = stray or a
    return {"unattributed": stray}


def _alert_id(a: dict):
    return a.get("alert_id") or a.get("internal_id") or a.get("id")


def _alert_brief(a: dict) -> dict:
    # case_id: XSIAM's get_alerts_multi_events carries the grouping case on every
    # alert (`incident_id` is null there). Unset = the alert was never grouped into a
    # case; on this tenant that is low-severity alerts only.
    return {"name": a.get("name"),
            "severity": a.get("severity"),
            "id": _alert_id(a),
            "source": a.get("source") or a.get("alert_source"),
            "case_id": a.get("case_id") or a.get("incident_id")}


# ── Run attribution ──────────────────────────────────────────────────────────
# get_alerts returns the whole tenant (thousands of alerts/day, many from LogSim's
# own background traffic tripping the same detectors), so an alert only counts for
# the run -- expected or unexpected -- if it carries one of the run's own markers.
# Identity sits at the top level for agent alerts and inside events[] for
# correlation alerts, whose field names vary by rule, so every event value is
# checked (exact comparisons, so breadth doesn't cost precision).
_TOP_FIELDS = ("host_name", "host_ip", "user_name", "agent_fqdn")


def _flat(v):
    if v is None or v == "":
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if x not in (None, "")]
    return [str(v)]


def run_markers(story, summary: dict, identity: dict) -> dict:
    """The values that tie an alert to THIS run: the box user/host, its internal IP,
    and every domain the run's network steps used. The egress IP is deliberately left
    out: it is the office's shared NAT address, so LogSim's background traffic carries
    it too and matching on it would pull unrelated alerts in. Run alerts keyed on the
    egress IP (Zscaler, perimeter firewalls) still attribute through the run domain."""
    ident = identity or {}
    domains = set()
    if summary.get("domain_override"):
        domains.add(_lower(summary["domain_override"]))
    # The domains the run actually used (fresh per-run tags). A Re-score rebuilds
    # the story with its original domains, so these come from the summary.
    for d in (summary.get("run_domains") or {}).values():
        if d:
            domains.add(_lower(d))
    for _idx, step in _selected(story, summary.get("selected_steps")):
        for ne in getattr(step, "network", None) or []:
            d = (getattr(ne, "context", None) or {}).get("domain")
            if d:
                domains.add(_lower(d))
    return {"user": _lower(ident.get("username")),
            "host": _lower(ident.get("hostname")).split(".")[0],
            "ips": {ip for ip in (ident.get("ip"),) if ip},
            "domains": domains}


def _attribution(a: dict, m: dict) -> Optional[str]:
    """Which run marker this alert carries ('user', 'host', 'ip', 'domain'), else None."""
    vals = []
    for f in _TOP_FIELDS:
        vals += _flat(a.get(f))
    for ev in a.get("events") or []:
        for v in (ev or {}).values():
            if isinstance(v, (str, list, tuple)):
                vals += _flat(v)
    for v in vals:
        lv = v.lower()
        if m["user"] and (lv == m["user"] or lv.endswith("\\" + m["user"])
                          or lv.startswith(m["user"] + "@")):
            return "user"
        if m["host"] and lv.split(".")[0] == m["host"]:
            return "host"
        if v in m["ips"]:
            return "ip"
        if any(lv == d or lv.endswith("." + d) for d in m["domains"]):
            return "domain"
    return None


# Console deep links, both taken from the tenant console on 2026-11-19:
#   https://<tenant>.xdr.us.paloaltonetworks.com/issue-view/<alert id>
#   https://<tenant>.xdr.us.paloaltonetworks.com/case?caseid=<case id>
ISSUE_VIEW_PATH = "/issue-view/{id}"
CASE_VIEW_PATH = "/case?caseid={id}"


def console_base(api_base: Optional[str] = None) -> Optional[str]:
    """The tenant's web console origin. XSIAM_CONSOLE_URL wins; otherwise it is the
    API base with the leading 'api-' dropped (api-<tenant>.xdr... -> <tenant>.xdr...).
    None when neither is known, and the UI then shows plain ids."""
    explicit = (os.getenv("XSIAM_CONSOLE_URL") or "").strip().rstrip("/")
    if explicit:
        return explicit
    if not isinstance(api_base, str):
        api_base = None
    base = (api_base or os.getenv("XSIAM_API_BASE") or "").strip().rstrip("/")
    m = re.match(r"^(https?://)api-([^/]+)", base)
    return (m.group(1) + m.group(2)) if m else None


def console_links(api_base: Optional[str] = None) -> Optional[dict]:
    """URL templates the console UI fills with an id ({id}), or None."""
    root = console_base(api_base)
    if not root:
        return None
    return {"base": root, "issue": root + ISSUE_VIEW_PATH, "case": root + CASE_VIEW_PATH}


def unexpected_alerts(alerts, matched_ids, markers, limit: int = 25, attrs=None) -> list:
    """Alerts attributed to this run (by marker) that no expectation claimed, grouped
    by name: [{name, count, severity, source, via, mitre, case_ids}]. These are the
    'what else fired?' answer: a real extra detection, or a needle that has drifted."""
    groups = {}
    for a in alerts:
        if _alert_id(a) in matched_ids:
            continue
        via = attrs.get(id(a)) if attrs is not None else _attribution(a, markers)
        if not via:
            continue
        g = groups.setdefault(a.get("name"), {
            "name": a.get("name"), "count": 0, "severity": a.get("severity"),
            "source": a.get("source") or a.get("alert_source"), "via": via,
            "mitre": sorted(_mitre_ids(a)), "case_ids": [], "alert_ids": []})
        g["count"] += 1
        aid = _alert_id(a)
        if aid and len(g["alert_ids"]) < 10:
            g["alert_ids"].append(aid)
        cid = a.get("case_id") or a.get("incident_id")
        if cid and cid not in g["case_ids"]:
            g["case_ids"].append(cid)
    return sorted(groups.values(), key=lambda g: -g["count"])[:limit]


def build_scorecard(story, summary: dict, identity: dict, *, client=None,
                    minutes_back: Optional[int] = None, wait_seconds: float = 0,
                    sources=_DEFAULT_SOURCES, verbose: bool = True) -> dict:
    """Pull the run's detections from XSIAM and score them against the story's
    expectations. Returns a scorecard dict (see module docstring). Best-effort.

    `client` may be injected (tests / reuse); otherwise an XsiamClient is built from
    the environment. `wait_seconds` lets the caller give detectors time to fire
    before pulling (the tenant's detector SLA is ~10 min). `minutes_back` defaults to
    run_window_minutes(summary): run start (minus a buffer) to now, floor 15 min.
    """
    user = (identity or {}).get("username")
    host = (identity or {}).get("hostname")
    vendors = summary.get("network_vendors")      # None: older run, all vendors sent
    emitted_map = summary.get("network_emitted")  # None: older run, score all sent
    expectations = collect_expectations(story, summary.get("selected_steps"), vendors,
                                        emitted_map)

    # Build/resolve the client — any failure is reported, never raised.
    if client is None:
        try:
            from integrations.xsiam_client import XsiamClient
        except Exception as e:
            return {"available": False, "reason": f"XSIAM client unavailable: {e}",
                    "expected_total": len(expectations)}
        try:
            client = XsiamClient()
        except Exception as e:
            return {"available": False, "reason": f"no XSIAM API credentials: {e}",
                    "expected_total": len(expectations)}

    if wait_seconds and wait_seconds > 0:
        if verbose:
            print(f"[XDR] scorecard — waiting {wait_seconds:.0f}s for detectors to settle…")
        time.sleep(wait_seconds)

    if minutes_back is None:
        minutes_back = run_window_minutes(summary)

    fetch_limit = alert_fetch_limit(minutes_back)
    try:
        try:
            alerts = client.get_alerts(minutes_back=minutes_back, limit=fetch_limit,
                                       sources=list(sources))
        except TypeError:          # older/fake clients without `limit`
            alerts = client.get_alerts(minutes_back=minutes_back, sources=list(sources))
    except Exception as e:
        return {"available": False, "reason": f"could not list alerts: {e}",
                "expected_total": len(expectations)}
    # Newest-first paging: hitting the cap means the OLDEST alerts in the window --
    # the run's first steps -- may be cut off, so misses there are unreliable.
    truncated = len(alerts) >= fetch_limit

    markers = run_markers(story, summary, identity)
    attrs = {id(a): _attribution(a, markers) for a in alerts}

    matched, missing = [], []
    by_source = {"network": {"matched": 0, "total": 0},
                 "endpoint": {"matched": 0, "total": 0}}
    # Credit each alert to at most one row, most specific row first (longest needle),
    # then report rows in story order.
    used, hits = set(), {}
    for k in sorted(range(len(expectations)),
                    key=lambda k: -max((len(x) for x in expectations[k]["needles"]), default=0)):
        hits[k] = find_detection(expectations[k], alerts, attrs, used)
        if hits[k].get("alert"):
            used.add(id(hits[k]["alert"]))
    for k, exp in enumerate(expectations):
        hit = hits[k]
        row = {k: exp[k] for k in ("step", "source", "label", "needles", "emitted",
                                   "technique_id", "mitre")}
        bucket = by_source.setdefault(exp["source"], {"matched": 0, "total": 0})
        bucket["total"] += 1
        if hit.get("alert"):
            row["needle"] = hit["needle"]
            row["matched_by"] = hit["matched_by"]
            row["via"] = hit["via"]
            row["alert"] = _alert_brief(hit["alert"])
            matched.append(row)
            bucket["matched"] += 1
        else:
            if hit.get("unattributed"):
                row["unattributed"] = _alert_brief(hit["unattributed"])
            missing.append(row)

    matched_ids = {r["alert"]["id"] for r in matched if r["alert"].get("id")}
    unexpected = unexpected_alerts(alerts, matched_ids, markers, attrs=attrs)
    # Cases the run's own alerts were grouped into, straight from each alert's
    # case_id: a stricter coalescence read than the incident lookup below, which can
    # only find cases whose entity lists name the box user/host.
    alert_cases = sorted({c for c in
                          [r["alert"].get("case_id") for r in matched] +
                          [cid for u in unexpected for cid in u["case_ids"]] if c},
                         key=str)

    # Incident coalescence for the box identity.
    incidents = []
    coalesced = None
    try:
        incs = client.get_open_incidents(minutes_back=max(minutes_back, 60),
                                         user=user, host=host)
        for inc in incs:
            incidents.append({
                "id": inc.get("incident_id"),
                "alert_count": inc.get("alert_count"),
                "status": inc.get("status"),
                "users": inc.get("users"), "hosts": inc.get("hosts"),
            })
    except Exception as e:
        if verbose:
            print(f"[XDR] scorecard — incident lookup skipped: {e}")

    # Coalescence, tri-state: None = no case yet, True = one case, False = split.
    # Prefer the run's own alerts' case_ids: they are exact. The incident lookup only
    # finds cases whose entity lists name the box user/host, so a case built from
    # IP-keyed network alerts is invisible to it; it is the fallback when no run alert
    # carries a case_id yet.
    if alert_cases:
        coalesced, coalesced_basis = len(alert_cases) == 1, "alert_cases"
    elif incidents:
        coalesced, coalesced_basis = len(incidents) == 1, "incident_lookup"
    else:
        coalesced, coalesced_basis = None, None
    # Matched alerts XSIAM never grouped into a case (low severity on this tenant):
    # they can't coalesce with anything, whatever the grouping rules.
    uncased = [r["alert"]["name"] for r in matched if not r["alert"].get("case_id")]

    score = (round(len(matched) / len(expectations), 3)
             if expectations else None)

    card = {
        "available": True,
        "window_minutes": minutes_back,
        "waited_seconds": wait_seconds or 0,
        "identity": {"user": user, "host": host},
        "expected_total": len(expectations),     # detections, not needles
        "by_source": by_source,
        "matched": matched,
        "missing": missing,
        "untracked": untracked_emissions(story, summary.get("selected_steps"), vendors,
                                          emitted_map),
        "network_vendors": vendors,
        "unexpected": unexpected,
        "alert_cases": alert_cases,
        "observed_alert_count": len(alerts),
        "fetch_limit": fetch_limit,
        "truncated": truncated,
        "run_alert_count": sum(1 for v in attrs.values() if v),
        "observed_sample": [a.get("name") for a in alerts[:12]],
        "incidents": incidents,
        "coalesced": coalesced,
        "coalesced_basis": coalesced_basis,
        "uncased": uncased,
        "score": score,
        "console": console_links(getattr(client, "base", None)),
    }
    if verbose:
        pct = f"{score*100:.0f}%" if score is not None else "n/a"
        state = "none yet" if coalesced is None else (
            ("coalesced" if coalesced else "SPLIT") + f" by {coalesced_basis}")
        net, ep = by_source["network"], by_source["endpoint"]
        print(f"[XDR] scorecard — detected {len(matched)}/{len(expectations)} ({pct}): "
              f"network {net['matched']}/{net['total']}, endpoint {ep['matched']}/{ep['total']}; "
              f"observed {len(alerts)} alerts{' (TRUNCATED at ' + str(fetch_limit) + ')' if truncated else ''}, "
              f"{card['run_alert_count']} tied to the run; unexpected={len(unexpected)}; "
              f"cases from alerts={alert_cases or 'none'}; "
              f"incidents={len(incidents)} ({state})")
    return card
