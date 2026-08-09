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
from .stories import Story, get_reference_story


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


def run_story(all_modules, config, story: Optional[Story] = None, *,
              connection: Optional[WorkstationConnection] = None,
              dry_run: Optional[bool] = None, verbose: bool = True) -> dict:
    """Run one story. Returns a summary dict {ok, identity, steps:[...], emitted, results}.

    Fail-closed on preflight. `dry_run` forces the DryRun executor (no technique
    fires); by default a stub-transport connection implies dry-run.
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

    # 5) Identity anchor — bind the synthetic network IP to the real host/user.
    if story.anchor_dhcp:
        summary["emitted"] += _emit(
            all_modules, "Infoblox NIOS", "DHCP_ACK",
            {"src_ip": host_ip, "client_mac": host_mac, "hostname": host_name},
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
        r = executor.execute(tech["id"], tech.get("test_numbers"), input_args=input_args)
        print(f"    - technique {tech['id']} test {tech.get('test_numbers')}: "
              f"{'OK' if r.ok else 'FAIL'} — {r.detail}")
        summary["results"].append(r.to_dict())

        # 6b) Emit the aligned synthetic network events, pinned to identity
        #     (src_ip + hostname + the real user; egress IP for external modules).
        for ne in step.network:
            base = {"src_ip": egress_ip if ne.external else host_ip,
                    "hostname": host_name, "user": user}
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
    """Scenario-registry entry point: run the P1 reference story against the
    configured target. Signature matches every other scenario func(all_modules,
    config). Dry-run is auto-selected when transport='stub'."""
    return run_story(all_modules, config, get_reference_story())
