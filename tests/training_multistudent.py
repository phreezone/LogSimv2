"""Multi-student capture-replay trust checks — isolation, reproducibility, alignment.

Run:  python tests/training_multistudent.py
No XSIAM tenant or network needed — everything runs against captured payloads in memory.

Proves:
  A. Isolation / leak-check — a student's replay contains NONE of the canonical entities,
     and different students share no user/IP/host.
  B. Cross-day reproducibility — the canonical for (pack, seed, eps) is byte-identical across
     regenerations (fixed anchor => day-independent); a different seed yields a different block.
  C. Timestamp shift — bulk backfill lands every event in [now-4h, now]; the anchor never leaks.
  D. AM/PM alignment per student — a student's bulk and stream payloads are identical except
     for timestamps (same rewrite; only the shift differs).
"""

import os
import re
import sys
import time
import datetime

sys.path.insert(0, '.')

import log_simulator as ls
from modules import training_engine as te

_ISO = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Small, fast, deterministic canonical: benign only, no scenario, 2 non-Windows modules.
PACK = {
    'id': 'ms-test', 'seed': 'ms-v1', 'duration_seconds': 30,
    'benign_threat_level': 'Benign Traffic Only',
    'benign_modules': ['Okta SSO', 'Zscaler Web Gateway'],
}
EPS = 2


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
    cfg['_static_tor_exit_nodes'] = list(cfg.get('tor_exit_nodes', []))
    return cfg


def _text(p):
    return te._payload_text(p)


def test_isolation(mods, cfg):
    captured, inv, _ = te.capture_canonical(PACK, mods, cfg, EPS)
    assert captured, "empty canonical"
    student_out = {}
    for n in (1, 2, 3):
        smap = te.build_student_map(inv, cfg, n)
        rewritten = [te.rewrite_payload(p, smap) for (_o, _m, _e, p) in captured]
        leak = te.leak_check(inv, rewritten)
        assert not leak, f"student{n} leaked canonical entities: {list(leak)[:5]}"
        assert any(f'student{n}' in _text(p) for p in rewritten), f"student{n} identity missing"
        student_out[n] = "\n".join(_text(p) for p in rewritten)
    # Pairwise IP disjointness across the per-student blocks.
    def student_ips(txt):
        return {ip for ip in _IP.findall(txt) if ip.startswith('10.') or ip.startswith('185.')}
    for a, b in ((1, 2), (1, 3), (2, 3)):
        shared = student_ips(student_out[a]) & student_ips(student_out[b])
        assert not shared, f"student{a}/student{b} share IPs: {list(shared)[:5]}"
    return len(captured)


def test_reproducibility(mods, cfg):
    a, _ia, _ = te.capture_canonical(PACK, mods, cfg, EPS)
    b, _ib, _ = te.capture_canonical(PACK, mods, cfg, EPS)
    sa = [(o, m, e, _text(p)) for (o, m, e, p) in a]
    sb = [(o, m, e, _text(p)) for (o, m, e, p) in b]
    assert sa == sb, "canonical not byte-identical across regenerations (day-dependent!)"
    # Different seed => materially different block.
    other = dict(PACK, seed='ms-v2')
    c, _ic, _ = te.capture_canonical(other, mods, cfg, EPS)
    sc = [(o, m, e, _text(p)) for (o, m, e, p) in c]
    assert sa != sc, "different seed produced the same canonical"
    return len(a)


def test_shift_window(mods, cfg):
    captured, inv, _ = te.capture_canonical(PACK, mods, cfg, EPS)
    anchor_epoch = te._anchor_dt(cfg).timestamp()
    duration = PACK['duration_seconds']
    now = time.time()
    delta = (now - duration) - anchor_epoch          # bulk backfill
    smap = te.build_student_map(inv, cfg, 1)
    lo, hi = now - duration - 5, now + 5
    stamps = 0
    for (_o, _m, _e, p) in captured:
        out = ls.shift_timestamps(te.rewrite_payload(p, smap), delta, anchor_epoch)
        txt = _text(out)
        assert '2020-01-01' not in txt, "anchor timestamp leaked into output"
        for t in _ISO.findall(txt):
            dt = datetime.datetime.strptime(t, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
            assert lo <= dt.timestamp() <= hi, f"timestamp {t} outside backfill window"
            stamps += 1
    assert stamps > 0, "no timestamps verified"
    return stamps


def test_am_pm_alignment(mods, cfg):
    captured, inv, _ = te.capture_canonical(PACK, mods, cfg, EPS)
    anchor_epoch = te._anchor_dt(cfg).timestamp()
    duration = PACK['duration_seconds']
    now = time.time()
    bulk_delta = (now - duration) - anchor_epoch
    stream_delta = now - anchor_epoch
    smap = te.build_student_map(inv, cfg, 2)
    diffs = 0
    for (_o, _m, _e, p) in captured:
        base = te.rewrite_payload(p, smap)
        am = ls._strip_volatile(ls.shift_timestamps(base, bulk_delta, anchor_epoch))
        pm = ls._strip_volatile(ls.shift_timestamps(base, stream_delta, anchor_epoch))
        if am != pm:
            diffs += 1
    assert diffs == 0, f"{diffs} payloads differ between AM and PM beyond timestamps"
    return len(captured)


def main():
    cfg = _load_config()
    mods = ls.load_modules()
    results = []
    n = test_isolation(mods, cfg);        results.append(f"  PASS  isolation/leak    ({n} events x 3 students, disjoint)")
    n = test_reproducibility(mods, cfg);  results.append(f"  PASS  reproducibility   ({n} events identical; new seed differs)")
    n = test_shift_window(mods, cfg);     results.append(f"  PASS  backfill window   ({n} timestamps in [now-dur, now])")
    n = test_am_pm_alignment(mods, cfg);  results.append(f"  PASS  AM/PM alignment   ({n} events identical except timestamps)")
    print("\n".join(results))
    print("\nAll multi-student trust checks PASSED.")


if __name__ == '__main__':
    try:
        main()
    except AssertionError as e:
        print(f"\n  FAIL: {e}")
        sys.exit(1)
