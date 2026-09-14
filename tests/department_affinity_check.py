"""Departmental behavioural affinity: does peer-group analytics have a signal?

XSIAM already knows each user's department from the simulated AD, but the label
is only useful if departments actually behave differently.  This asserts the
property that makes peer grouping work:

    inter-department distance  >  intra-department spread

and the property that keeps it honest:

    a Finance user hitting an Engineering domain must be RARE, not IMPOSSIBLE

A hard partition would score perfectly on the first test and be wrong: it turns
"unusual for their peer group" into "cannot happen", which is a different
dataset and would silently change which existing rules fire.

Run:  python tests/department_affinity_check.py
"""

import collections
import json
import math
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import modules.session_utils as su                                # noqa: E402
from modules.session_utils import (build_session_context,          # noqa: E402
                                   weighted_dns_domain,
                                   weighted_destination,
                                   get_byte_volume_band,
                                   department_of, _norm_user)

_fails, _checks = [], []


def check(name, cond, detail=""):
    _checks.append(name)
    if not cond:
        _fails.append(f"{name}: {detail}")


def profile(user, domains, n=4000):
    """Normalised domain-frequency vector for one user."""
    c = collections.Counter(weighted_dns_domain(user, domains) for _ in range(n))
    return [c.get(d, 0) / n for d in domains]


def cosine_distance(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return 1.0 - (dot / (na * nb)) if na and nb else 1.0


def main():
    cfg = json.load(open(os.path.join(_ROOT, "config.json"), encoding="utf-8"))
    sess = build_session_context(cfg)
    domains = cfg["benign_domains"]

    by_dept = collections.defaultdict(list)
    for u, p in cfg.get("user_profiles", {}).items():
        if p.get("department"):
            by_dept[p["department"]].append(u)
    depts = [d for d, us in sorted(by_dept.items()) if len(us) >= 4][:8]
    check("enough departments to compare", len(depts) >= 4, f"{len(depts)}")
    print(f"departments compared: {len(depts)}  "
          f"(affinity strength {su._DEPT_AFFINITY_STRENGTH})")

    # --- the core property -------------------------------------------------
    profiles = {d: [profile(u, domains) for u in by_dept[d][:4]] for d in depts}

    intra = []
    for d in depts:
        ps = profiles[d]
        for i in range(len(ps)):
            for j in range(i + 1, len(ps)):
                intra.append(cosine_distance(ps[i], ps[j]))
    inter = []
    for i, d1 in enumerate(depts):
        for d2 in depts[i + 1:]:
            for p1 in profiles[d1]:
                for p2 in profiles[d2]:
                    inter.append(cosine_distance(p1, p2))

    mi, mx = sum(intra) / len(intra), sum(inter) / len(inter)
    print(f"  mean intra-department distance: {mi:.3f}")
    print(f"  mean inter-department distance: {mx:.3f}")
    print(f"  separation ratio              : {mx / mi:.2f}x")
    check("departments separate (inter > intra)", mx > mi, f"{mx:.3f} vs {mi:.3f}")
    check("separation is meaningful (>1.3x)", mx / mi > 1.3, f"{mx / mi:.2f}x")

    # --- rare, not impossible ----------------------------------------------
    # Every domain must remain reachable for every department, or we have built
    # a partition rather than a bias.
    unreachable = 0
    for d in depts:
        seen = set()
        for u in by_dept[d][:3]:
            seen |= {weighted_dns_domain(u, domains) for _ in range(6000)}
        missing = set(domains) - seen
        unreachable += len(missing)
    check("every domain still reachable by every department", unreachable == 0,
          f"{unreachable} domain/department pairs unreachable")

    # --- department shifts volume tiers, users still vary inside them -------
    tiers = {}
    for d in depts:
        bands = [get_byte_volume_band(u) for u in by_dept[d][:12]]
        tiers[d] = collections.Counter(bands)
    distinct_modal = {max(c.items(), key=lambda kv: kv[1])[0] for c in tiers.values()}
    check("departments differ in modal volume tier", len(distinct_modal) >= 2,
          f"{len(distinct_modal)} distinct modal tiers")
    spread = sum(1 for c in tiers.values() if len(c) > 1)
    check("users still vary within a department", spread >= max(1, len(depts) // 2),
          f"{spread}/{len(depts)} departments show >1 tier")
    print(f"  modal volume tiers across departments: {len(distinct_modal)} distinct; "
          f"{spread}/{len(depts)} departments internally varied")

    # --- destinations get the same treatment --------------------------------
    dests = cfg.get("zscaler_config", {}).get("benign_egress_destinations") or []
    if len(dests) >= 8:
        dv = {}
        for d in depts[:4]:
            c = collections.Counter()
            for u in by_dept[d][:3]:
                for _ in range(2000):
                    c[weighted_destination(u, dests).get("name")] += 1
            dv[d] = c.most_common(1)[0][0]
        check("departments favour different destinations",
              len(set(dv.values())) >= 2, f"{dv}")
        print(f"  favourite destination by department: "
              f"{ {k: v[:22] for k, v in dv.items()} }")

    # --- deliberately-rare destinations must stay rare ----------------------
    if len(dests) >= 8:
        rare = [d for d in dests if su._is_rare_destination(d)]
        if rare:
            c = collections.Counter()
            for u in [u for d in depts for u in by_dept[d][:4]]:
                for _ in range(400):
                    c[weighted_destination(u, dests).get("name")] += 1
            tot = sum(c.values())
            for r in rare:
                share = c.get(r.get("name"), 0) / tot
                uniform = 1.0 / len(dests)
                check(f"rare destination stays below uniform share: {r.get('name')}",
                      share < uniform, f"{share:.2%} vs uniform {uniform:.2%}")
                check(f"rare destination still reachable: {r.get('name')}",
                      c.get(r.get("name"), 0) > 0)
            print(f"  rare destinations held below uniform share ({len(rare)} checked)")

    # --- strength 0 must reproduce the old pure per-user behaviour ----------
    saved = su._DEPT_AFFINITY_STRENGTH
    su._DEPT_AFFINITY_STRENGTH = 0.0
    su._USER_DOMAIN_WEIGHTS.clear()
    off_users = {su._affinity_offset(u, len(domains), "dns") for u in by_dept[depts[0]][:8]}
    su._DEPT_AFFINITY_STRENGTH = saved
    su._USER_DOMAIN_WEIGHTS.clear()
    check("strength 0 disables clustering (offsets scatter)", len(off_users) >= 4,
          f"{len(off_users)} distinct offsets among 8 same-department users")

    # --- identity forms all resolve to one department -----------------------
    u0 = by_dept[depts[0]][0]
    forms = [u0, f"{u0}@examplecorp.com", "EXAMPLECORP" + chr(92) + u0, u0.upper()]
    resolved = {department_of(f) for f in forms}
    check("all wire username forms resolve to one department", len(resolved) == 1,
          f"{resolved}")

    print()
    print("=" * 70)
    if _fails:
        print(f"FAILED {len(_fails)}/{len(_checks)}")
        for f in _fails:
            print("  x", f)
        return 1
    print(f"ALL {len(_checks)} CHECKS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
