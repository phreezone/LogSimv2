# modules/xdr_orchestration/scorecard.py
#
# Closed-loop detection scorecard (Tier-1 #1). The orchestrator fires a story and
# emits aligned network logs; this closes the loop — it pulls the alerts/incidents
# the run actually produced from XSIAM and scores them against what each step SAID
# it should trigger (Step.expected_alerts / Step.mitre, Tier-1 #2).
#
# It answers the three questions a purple-team run exists to answer:
#   1. Which expected detections actually fired? (coverage)
#   2. Did endpoint + network coalesce into ONE incident, or split? (stitch)
#   3. What else fired that we didn't expect? (noise / surprises)
#
# Design: NEVER fatal. No XSIAM creds, an API error, or the integration not being
# importable all return {available: False, reason}, exactly like the orchestrator's
# incident-cleanup. Matching is by alert-name substring within the run's time window
# (get_alerts has no server-side name filter and alert host/user fields vary), which
# mirrors how the existing threat harness attributes detections. A fake client can
# be injected for offline testing.

import time
from typing import List, Optional

# The alert sources a fired event can produce (shared with the XSIAM client).
_DEFAULT_SOURCES = ("XDR Analytics", "XDR Analytics BIOC", "Correlation")


def _lower(s):
    return (s or "").lower()


def collect_expectations(story, selected_steps: Optional[List[int]] = None) -> list:
    """Flatten the story's per-step detection expectations into a match list.

    Each expectation: {step, narrative, technique_id, mitre, needle}. `needle` is one
    alert-name substring from a step's expected_alerts. Limited to `selected_steps`
    (1-based) when given, so a partial run is scored only on what it fired."""
    keep = set(selected_steps) if selected_steps else None
    out = []
    for idx, step in enumerate(story.steps, 1):
        if keep is not None and idx not in keep:
            continue
        needles = getattr(step, "expected_alerts", None) or []
        tech = (step.technique or {}).get("id")
        mitre = getattr(step, "mitre", None) or {}
        for needle in needles:
            out.append({"step": idx, "narrative": step.narrative,
                        "technique_id": tech, "mitre": mitre, "needle": needle})
    return out


def _match_alert(needle, alerts):
    """First alert whose name contains `needle` (case-insensitive), else None."""
    n = _lower(needle)
    for a in alerts:
        if n in _lower(a.get("name")):
            return a
    return None


def _alert_brief(a: dict) -> dict:
    return {"name": a.get("name"),
            "severity": a.get("severity"),
            "id": a.get("alert_id") or a.get("internal_id") or a.get("id"),
            "source": a.get("source") or a.get("alert_source")}


def build_scorecard(story, summary: dict, identity: dict, *, client=None,
                    minutes_back: Optional[int] = None, wait_seconds: float = 0,
                    sources=_DEFAULT_SOURCES, verbose: bool = True) -> dict:
    """Pull the run's detections from XSIAM and score them against the story's
    expectations. Returns a scorecard dict (see module docstring). Best-effort.

    `client` may be injected (tests / reuse); otherwise an XsiamClient is built from
    the environment. `wait_seconds` lets the caller give detectors time to fire
    before pulling (the tenant's detector SLA is ~10 min). `minutes_back` defaults to
    a window that covers the whole run with a buffer.
    """
    user = (identity or {}).get("username")
    host = (identity or {}).get("hostname")
    expectations = collect_expectations(story, summary.get("selected_steps"))

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

    # Window: cover the run plus a buffer; floor at 15 minutes.
    if minutes_back is None:
        minutes_back = 15

    try:
        alerts = client.get_alerts(minutes_back=minutes_back, sources=list(sources))
    except Exception as e:
        return {"available": False, "reason": f"could not list alerts: {e}",
                "expected_total": len(expectations)}

    matched, missing = [], []
    for exp in expectations:
        a = _match_alert(exp["needle"], alerts)
        row = {"needle": exp["needle"], "step": exp["step"],
               "technique_id": exp["technique_id"], "mitre": exp["mitre"]}
        if a:
            row["alert"] = _alert_brief(a)
            matched.append(row)
        else:
            missing.append(row)

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
        # Tri-state: None = no incident yet (nothing stitched / detectors not fired),
        # True = one incident (endpoint + network coalesced), False = split across >1.
        coalesced = None if len(incidents) == 0 else (len(incidents) == 1)
    except Exception as e:
        if verbose:
            print(f"[XDR] scorecard — incident lookup skipped: {e}")

    score = (round(len(matched) / len(expectations), 3)
             if expectations else None)

    card = {
        "available": True,
        "window_minutes": minutes_back,
        "waited_seconds": wait_seconds or 0,
        "identity": {"user": user, "host": host},
        "expected_total": len(expectations),
        "matched": matched,
        "missing": missing,
        "observed_alert_count": len(alerts),
        "observed_sample": [a.get("name") for a in alerts[:12]],
        "incidents": incidents,
        "coalesced": coalesced,
        "score": score,
    }
    if verbose:
        pct = f"{score*100:.0f}%" if score is not None else "n/a"
        state = "none yet" if coalesced is None else ("coalesced" if coalesced else "SPLIT")
        print(f"[XDR] scorecard — matched {len(matched)}/{len(expectations)} expected "
              f"({pct}); observed {len(alerts)} alerts; incidents={len(incidents)} ({state})")
    return card
