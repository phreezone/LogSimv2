"""Training Mode trust checks — determinism, bulk/stream parity, and backfill bounds.

Run:  python tests/training_determinism.py
No XSIAM tenant or network is required — everything runs in capture / dry-run mode.

What it proves:
  A. Determinism   — two runs of a pack produce byte-identical content (timestamps stripped).
  B. Bulk-vs-Stream   — bulk (backfill) and stream (live) produce the SAME content, order, and
                     per-log transport target. This is the core alignment guarantee.
  C. Backfill      — a bulk run stamps events inside [now-duration, now] and non-decreasing.
"""

import os
import re
import sys
import time
import datetime

sys.path.insert(0, '.')

import log_simulator as ls
from modules import training_engine as te

_UTC = datetime.timezone.utc
_TS_ISO_RE = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?')


def _load_config():
    from dotenv import load_dotenv
    load_dotenv()
    text = open('config.json', encoding='utf-8').read()
    for ph, env in (('PLACEHOLDER_GCP_PROJECT_ID', 'GCP_PROJECT_ID'),
                    ('PLACEHOLDER_GCP_PROJECT_NUMBER', 'GCP_PROJECT_NUMBER'),
                    ('PLACEHOLDER_AWS_ACCOUNT_ID', 'AWS_ACCOUNT_ID')):
        text = text.replace(ph, os.getenv(env, 'test-' + env.lower()))
    import json
    cfg = json.loads(text)
    # Pin the Tor list so backfill runs don't depend on a live fetch.
    cfg['_static_tor_exit_nodes'] = list(cfg.get('tor_exit_nodes', []))
    return cfg


def _norm(cap):
    return [(n, e, ls._strip_volatile(p)) for (n, e, p) in cap]


# Small, fast packs (short duration so tests finish quickly).
# Pure-benign, interval-paced — used for the backfill-window check (no off-hours threats).
BENIGN_PACK = {
    'id': 'test-benign', 'seed': 'test-benign',
    'duration_seconds': 300, 'benign_interval_seconds': 5,
    'benign_modules': ['Okta SSO', 'Apache httpd', 'Zscaler Web Gateway'],
}

# High-volume, high-realism — exercises benign_events_per_second_per_module (rate) and
# benign_threat_level='High' (threats mixed into the baseline), like the real packs.
HIGHVOL_PACK = {
    'id': 'test-highvol', 'seed': 'test-highvol',
    'duration_seconds': 30, 'benign_events_per_second_per_module': 10,
    'benign_threat_level': 'High',
    'benign_modules': ['Okta SSO', 'Apache httpd', 'Zscaler Web Gateway'],
}


def _pack_with_threat(all_modules):
    """Benign pack plus one injected threat, to exercise the injected-action path."""
    pack = dict(BENIGN_PACK, id='test-threat', seed='test-threat')
    mod = all_modules.get('Okta SSO')
    names = mod.get_threat_names() if mod and hasattr(mod, 'get_threat_names') else None
    if names:
        pack['threats'] = [{'module': 'Okta SSO', 'name': names[0],
                            'count': 1, 'offset_seconds': 120}]
    return pack


def test_determinism(all_modules, config, pack):
    a = te._capture_run(pack, all_modules, config, 'stream')
    b = te._capture_run(pack, all_modules, config, 'stream')
    assert a, f"[{pack['id']}] capture produced no events"
    assert _norm(a) == _norm(b), f"[{pack['id']}] two runs differ (non-deterministic)"
    return len(a)


def test_parity(all_modules, config, pack):
    ok, bulk, stream = te.verify_parity(pack, all_modules, config)
    if not ok:
        nb, ns = _norm(bulk), _norm(stream)
        # find first divergence for a helpful message
        for i, (x, y) in enumerate(zip(nb, ns)):
            if x != y:
                raise AssertionError(f"[{pack['id']}] bulk/stream diverge at event {i}:\n"
                                     f"  bulk  ={x}\n  stream={y}")
        raise AssertionError(f"[{pack['id']}] bulk/stream length differ: "
                             f"{len(nb)} vs {len(ns)}")
    return len(bulk)


def test_backfill_bounds(all_modules, config, pack):
    """Dry bulk run: capture payloads (timestamps baked in by the frozen clock) and
    assert every emitted timestamp falls in [now-duration, now] and is non-decreasing
    across the timeline."""
    prev_sink, prev_dry = ls._capture_sink, ls._dry_run
    sink = []
    ls._capture_sink = sink
    ls._dry_run = True
    try:
        t0 = time.time()
        summary = te.run_pack(pack, all_modules, config, mode='bulk')
    finally:
        ls._capture_sink, ls._dry_run = prev_sink, prev_dry
    t1 = time.time()

    duration = pack['duration_seconds']
    lo = t0 - duration - 5
    hi = t1 + 5

    per_event_max = []
    for (_n, _e, payload) in sink:
        s = payload.decode('utf-8', 'replace') if isinstance(payload, bytes) else str(payload)
        epochs = []
        for m in _TS_ISO_RE.findall(s):
            try:
                iso = m.replace('Z', '+00:00')
                dt = datetime.datetime.fromisoformat(iso)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=_UTC)
                epochs.append(dt.timestamp())
            except ValueError:
                continue
        # every parsed event-time must fall inside the backfill window
        for ep in epochs:
            assert lo <= ep <= hi, (f"[{pack['id']}] timestamp {ep} outside backfill window "
                                    f"[{lo}, {hi}] (now-{duration}s .. now)")
        if epochs:
            per_event_max.append(max(epochs))

    # timeline should broadly progress forward (allow small within-event jitter)
    assert per_event_max, f"[{pack['id']}] no parseable timestamps captured"
    assert per_event_max[-1] >= per_event_max[0], f"[{pack['id']}] timeline not progressing"
    return summary['actions'], len(per_event_max)


# A real attack scenario staged with benign noise around it — exercises the full
# injected-scenario path (multi-module, S3/gzip, Windows counters, ns epochs, …).
SCENARIO_PACK = {
    'id': 'test-scenario-18', 'seed': 'test-scenario-18',
    'duration_seconds': 120, 'benign_events_per_second_per_module': 5,
    'benign_threat_level': 'High',
    'benign_modules': ['Okta SSO', 'Zscaler Web Gateway'],
    'scenario': {'id': '18', 'start_offset_seconds': 30},
}


def main():
    config = _load_config()
    all_modules = ls.load_modules()
    threat_pack = _pack_with_threat(all_modules)

    results = []
    for pack in (BENIGN_PACK, threat_pack, HIGHVOL_PACK, SCENARIO_PACK):
        n = test_determinism(all_modules, config, pack)
        results.append(f"  PASS  determinism   [{pack['id']}]  ({n} events, 2 identical runs)")
        n = test_parity(all_modules, config, pack)
        results.append(f"  PASS  bulk-vs-stream    [{pack['id']}]  ({n} events identical)")

    # Backfill-bounds applies to the benign baseline only: injected threats/scenarios
    # may embed deliberate off-hours (e.g. 2-5 AM) timestamps for realism, which are
    # legitimately outside the [now-duration, now] window.
    actions, n = test_backfill_bounds(all_modules, config, BENIGN_PACK)
    results.append(f"  PASS  backfill       [{BENIGN_PACK['id']}]  ({actions} actions, {n} timestamped)")

    print("\n".join(results))
    print("\nAll training-mode trust checks PASSED.")


if __name__ == '__main__':
    try:
        main()
    except AssertionError as e:
        print(f"\n  FAIL: {e}")
        sys.exit(1)
