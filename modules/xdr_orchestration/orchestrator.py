# modules/xdr_orchestration/orchestrator.py
#
# The coordinator: runs a STORY end to end. Per step it fires the real technique
# on the box (executor) AND emits the step's synthetic network logs pinned to the
# box's discovered identity, right around the same wall-clock — so XSIAM stitches
# endpoint + network into one incident.
#
# Fail-closed: nothing fires unless connection.preflight() passes (a live box that
# can't receive commands, a down agent, etc. aborts the run with the reason).
#
# Registered as a scenario in log_simulator.get_scenarios() via run_reference_story
# so it flows through the existing driver, run-tracking, and transports unchanged.

import sys
import time
from typing import Optional

from .connection import WorkstationConnection, ConnectionError
from .executor import build_executor
from .stories import Story, get_reference_story, get_intrusion_story, get_story


def _emit(all_modules, module_key, event, context, config, verbose=True):
    """Emit one synthetic network log via the named module, mirroring the proven
    scenario pattern (module.generate_log(...) -> process_and_send). process_and_send
    is imported lazily to avoid a circular import at get_scenarios() load time."""
    module = all_modules.get(module_key)
    if module is None:
        if verbose:
            print(f"    - skip {module_key}/{event}: module not loaded")
        return 0
    try:
        from log_simulator import process_and_send  # lazy: avoids circular import
        result = module.generate_log(config, scenario_event=event, context=context)
        if not result:
            return 0
        content, name = result if isinstance(result, tuple) else (result, event)
        if content:
            process_and_send(content, module, config, name)
            if verbose:
                print(f"    - emitted {module_key}/{event} (src_ip={context.get('src_ip')})")
            return 1
    except Exception as e:
        print(f"    - ERROR emitting {module_key}/{event}: {e}")
    return 0


def _resolve_prior_incidents(identity, verbose=True):
    """Best-effort: resolve prior OPEN XSIAM incidents for the box identity so the
    upcoming run's fresh case is the only grouping target for its network alerts.

    XSIAM folds a correlation (network) alert into any open incident sharing its
    user/host entity. With several stale box-cases open, a run's network alerts can
    group into an OLDER case while its endpoint alerts form a NEW one — splitting the
    story. Resolving the priors makes the stitch deterministic (this automates the
    manual case-closing that was the difference between a stitched and a split run).

    NEVER fatal: any failure (no XSIAM creds, API error) logs and returns 0 so the
    run proceeds. Only ever targets incidents matching the box user/host; uses the
    reversible `resolved_security_testing` status. Returns the count resolved.
    """
    user = identity.get("username")
    host = identity.get("hostname")
    try:
        from integrations.xsiam_client import XsiamClient, XsiamError
    except Exception as e:
        if verbose:
            print(f"[XDR] cleanup skipped — XSIAM client unavailable: {e}")
        return 0
    try:
        client = XsiamClient()
    except Exception as e:
        if verbose:
            print(f"[XDR] cleanup skipped — no XSIAM API credentials: {e}")
        return 0
    try:
        # Match on user OR host: query each and union by incident_id so a case keyed
        # on only one of the two entities is still caught.
        found = {}
        for kw in ({"user": user} if user else {}), ({"host": host} if host else {}):
            if not kw:
                continue
            for inc in client.get_open_incidents(minutes_back=1440, **kw):
                found[inc.get("incident_id")] = inc
    except XsiamError as e:
        if verbose:
            print(f"[XDR] cleanup skipped — could not list incidents: {e}")
        return 0
    if not found:
        if verbose:
            print(f"[XDR] cleanup — no prior open incidents for user={user} host={host}")
        return 0
    resolved = 0
    for inc_id, inc in found.items():
        try:
            client.resolve_incident(
                inc_id,
                comment=f"LogSim XDR pre-run cleanup: resolving prior open box-case so "
                        f"this run's network alerts stitch into a single fresh incident.")
            resolved += 1
            if verbose:
                print(f"[XDR] cleanup — resolved prior incident {inc_id} "
                      f"(alerts={inc.get('alert_count')}, users={inc.get('users')})")
        except XsiamError as e:
            print(f"[XDR] cleanup — FAILED to resolve incident {inc_id}: {e}")
    return resolved


def run_story(all_modules, config, story: Optional[Story] = None, *,
              connection: Optional[WorkstationConnection] = None,
              dry_run: Optional[bool] = None, verbose: bool = True,
              cleanup_prior_incidents: bool = False) -> dict:
    """Run one story. Returns a summary dict {ok, identity, steps:[...], emitted, results}.

    Fail-closed on preflight. `dry_run` forces the DryRun executor (no technique
    fires); by default a stub-transport connection implies dry-run.

    `cleanup_prior_incidents` (default OFF): when True, resolve prior OPEN XSIAM
    incidents for the box identity before firing, so this run's network alerts and
    endpoint alerts reliably coalesce into a single fresh incident (see
    _resolve_prior_incidents). Best-effort — never aborts the run. Opt-in because it
    closes incidents on the tenant.
    """
    story = story or get_reference_story()
    summary = {"story": story.name, "ok": False, "identity": None,
               "results": [], "emitted": 0, "aborted": None}

    # The preflight banner uses ✓/✗ glyphs; a cp1252-encoded stream (piped output,
    # some Windows consoles) would raise UnicodeEncodeError. Make output UTF-8 safe.
    for _stream in (getattr(sys, "stdout", None), getattr(sys, "stderr", None)):
        try:
            _stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    # 1) Connection.
    if connection is None:
        try:
            connection = WorkstationConnection.from_config(config)
        except ConnectionError as e:
            summary["aborted"] = f"connection config error: {e}"
            print(f"[XDR] ABORT — {summary['aborted']}")
            return summary

    # 2) Preflight — fail-closed.
    print(f"\n=== XDR Orchestration: {story.name} ===")
    report = connection.preflight(force=True)
    print(report.render())
    if not report.ok:
        summary["aborted"] = "preflight failed — orchestrator refuses to fire"
        print(f"[XDR] ABORT — {summary['aborted']}")
        return summary

    # 3) Identity seed (from the preflight report, else discover).
    identity = report.identity or connection.discover_identity()
    summary["identity"] = identity
    host_ip  = identity.get("ip")
    egress_ip = identity.get("egress_ip") or host_ip
    host_name = identity.get("hostname")
    user      = identity.get("username")
    host_mac  = identity.get("mac") or "00:50:56:%02x:%02x:%02x" % (
        hash(host_name or "") & 0xff, (hash(host_name or "") >> 8) & 0xff,
        (hash(host_name or "") >> 16) & 0xff)

    # 4) Executor.
    executor = build_executor(connection, dry_run=dry_run)
    print(f"[XDR] executor={executor.name}  identity: user={user} host={host_name} "
          f"ip={host_ip} egress={egress_ip}")

    # 4.5) Optional pre-run incident cleanup (opt-in) — resolve prior open box-cases
    #      so this run's network + endpoint alerts stitch into ONE fresh incident.
    if cleanup_prior_incidents:
        summary["cleanup_resolved"] = _resolve_prior_incidents(identity, verbose=verbose)

    # 5) Identity anchors — bind the synthetic network IP to the real host/user so
    #    IP-keyed network alerts resolve to the same identity the endpoint case uses.
    if story.anchor_dhcp:
        # IP <-> host (DHCP lease).
        summary["emitted"] += _emit(
            all_modules, "Infoblox NIOS", "DHCP_ACK",
            {"src_ip": host_ip, "client_mac": host_mac, "hostname": host_name},
            config, verbose)
        time.sleep(1)
    if story.anchor_logon:
        # IP <-> user (4624 type-3 network logon): "user logged on from host_ip".
        summary["emitted"] += _emit(
            all_modules, "Windows Event Log", "NETWORK_LOGON",
            {"user": user, "hostname": host_name, "src_ip": host_ip},
            config, verbose)
        time.sleep(1)

    # 6) Steps.
    for i, step in enumerate(story.steps, 1):
        print(f"\n[XDR] STEP {i}: {step.narrative}")
        if step.pre_delay:
            time.sleep(step.pre_delay)

        # 6a) Fire the real technique.
        tech = step.technique
        input_args = tech.get("input_args") or step.params.get("input_args")
        # Some tests need a target file/tool staged first (e.g. file deletion).
        if step.prereqs:
            pr = executor.get_prereqs(tech["id"], tech.get("test_numbers"))
            print(f"    - prereqs {tech['id']}: {'OK' if pr.ok else 'FAIL'} — {pr.detail}")
            summary["results"].append(pr.to_dict())
        r = executor.execute(tech["id"], tech.get("test_numbers"), input_args=input_args)
        print(f"    - technique {tech['id']} test {tech.get('test_numbers')}: "
              f"{'OK' if r.ok else 'FAIL'} — {r.detail}")
        summary["results"].append(r.to_dict())

        # 6b) Emit the aligned synthetic network events, pinned to identity
        #     (src_ip + hostname + the real user; egress IP for external modules).
        #     `ip` mirrors `src_ip` for modules that read `ip` (e.g. Okta client IP).
        for ne in step.network:
            _ip = egress_ip if ne.external else host_ip
            base = {"src_ip": _ip, "ip": _ip, "hostname": host_name, "user": user}
            ctx = {**base, **ne.context}
            summary["emitted"] += _emit(all_modules, ne.module, ne.event, ctx, config, verbose)

        # 6c) Cleanup the technique's artifacts (persistence etc.) so nothing is left
        #     behind — the creation telemetry already fired during execute().
        if step.cleanup:
            cr = executor.cleanup(tech["id"], tech.get("test_numbers"), input_args=input_args)
            print(f"    - cleanup {tech['id']}: {'OK' if cr.ok else 'FAIL'} — {cr.detail}")
            summary["results"].append(cr.to_dict())

        if step.post_delay:
            time.sleep(step.post_delay)

    _execs = [res for res in summary["results"] if res["action"] == "execute"]
    summary["ok"] = all(res["ok"] for res in _execs) if _execs else True
    print(f"\n[XDR] done — technique_ok={summary['ok']} "
          f"techniques={len(_execs)} synthetic_events_emitted={summary['emitted']}")
    return summary


# ── Scenario entry (registered in get_scenarios) ──────────────────────────────

def run_reference_story(all_modules, config):
    """Scenario-registry entry point: run the full reference story against the
    configured target. Signature matches every other scenario func(all_modules,
    config). Dry-run is auto-selected when transport='stub'."""
    return run_story(all_modules, config, get_reference_story())


def run_quick_story(all_modules, config):
    """Scenario-registry entry point: run the short 'quick' story (small run)."""
    return run_story(all_modules, config, get_story("xdr_quick"))


def run_intrusion_story(all_modules, config):
    """Scenario-registry entry point: run the credential-theft 'smash-and-grab'
    story — a different tactic spread (credential access / evasion / staging /
    exfil) so XDR sees more than discovery noise."""
    return run_story(all_modules, config, get_intrusion_story())


def run_story_id(all_modules, config, story_id, *, dry_run=None,
                 cleanup_prior_incidents=False):
    """Run a story by id (used by the console /api/attack/run route). Falls back to
    the reference story when the id is unknown."""
    story = get_story(story_id) or get_reference_story()
    return run_story(all_modules, config, story, dry_run=dry_run,
                     cleanup_prior_incidents=cleanup_prior_incidents)
