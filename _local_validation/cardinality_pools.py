"""Guard the baseline-vs-rare cardinality design for the Azure/O365 generators.

Rarity detectors ("first seen", "unusual app/resource/tenant/domain") only work if the benign
baseline NEVER emits a rare-pool entity and the rare pools are effectively unbounded. This test
exercises the baseline heavily and asserts no rare-pool value leaks into it, and that the rare
pools stay disjoint from the baseline and barely repeat over a large draw.

Run:  python _local_validation/cardinality_pools.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import azure_common as ac           # noqa: E402
from modules import azuread_signin as aadsi       # noqa: E402
from modules import azuread_audit as aaud         # noqa: E402
from modules import o365_azuread as o365a         # noqa: E402

CFG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")
CFG = json.load(open(CFG_PATH, encoding="utf-8"))

N_BASELINE = 20000      # baseline events per feed (at 1 log/s this is ~5.5 hours of traffic)
N_RARE = 50000          # rare draws (far more than months of real firing)
_FAILS = []


def check(cond, msg):
    print(("  OK  " if cond else " FAIL ") + msg)
    if not cond:
        _FAILS.append(msg)


def _blob(recs):
    return json.dumps(recs, default=str)


def test_rare_pools_unbounded_and_disjoint():
    print("[rare pools: scale + disjointness]")
    base_apps = set(ac.SAAS_CORE) | set(ac.ADMIN_CONSENT_APPS)
    apps = {ac.rare_app_name() for _ in range(N_RARE)}
    check(len(apps & base_apps) == 0, f"rare_app_name disjoint from baseline apps (overlap={len(apps & base_apps)})")
    check(len(apps) / N_RARE > 0.99, f"rare_app_name near-unique ({len(apps)}/{N_RARE})")

    tenants = {ac.rare_tenant()["tenant_id"] for _ in range(N_RARE)}
    check(len(tenants) == N_RARE, f"rare_tenant ids all unique ({len(tenants)}/{N_RARE})")

    ips = {ac.rare_asn_loc()["ip"] for _ in range(N_RARE)}
    check(len(ips) / N_RARE > 0.99, f"rare_asn_loc IPs near-unique ({len(ips)}/{N_RARE})")

    emails = {ac.rare_ext_email() for _ in range(N_RARE)}
    check(len(emails) / N_RARE > 0.99, f"rare_ext_email near-unique ({len(emails)}/{N_RARE})")


def test_baseline_never_emits_rare():
    print("[baseline never emits a rare-pool entity]")
    # Build quick membership predicates. Rare apps always carry a trailing digit-run from a huge
    # space; the cleanest universal check is: no baseline value may equal a freshly-generated rare
    # sample set, and known rare markers (rare ASNs, onmicrosoft rogue domains) must be absent.
    rare_asn_numbers = {a for a, _i, _o in ac._RARE_ASNS}

    feeds = {
        "signin": lambda: aadsi.generate_benign(CFG, {}),
        "audit": lambda: aaud.generate_benign(CFG, {}),
        "o365_aad": lambda: o365a.generate_benign(CFG, {}),
    }
    for name, gen in feeds.items():
        leaked_asn = 0
        leaked_rogue_dom = 0
        for _ in range(N_BASELINE):
            recs = gen()
            b = _blob(recs)
            if ".onmicrosoft.com" in b and "evilcorp" not in b:
                # any onmicrosoft vanity domain in a benign record would be a rogue-tenant leak
                leaked_rogue_dom += 1
            for r in recs:
                asn = r.get("autonomousSystemNumber")
                if asn in rare_asn_numbers:
                    leaked_asn += 1
        check(leaked_asn == 0, f"{name}: no benign sign-in from a rare/hosting ASN ({leaked_asn})")
        check(leaked_rogue_dom == 0, f"{name}: no benign record referencing a rogue onmicrosoft tenant ({leaked_rogue_dom})")


def test_baseline_subsets_are_narrow_and_stable():
    print("[per-entity baseline subsets narrow + stable]")
    u = {"username": "pat.lee", "department": "Sales"}
    a1 = ac.baseline_apps_for(u, interactive=True)
    a2 = ac.baseline_apps_for(u, interactive=True)
    check(a1 == a2, "baseline_apps_for stable across calls")
    check(len(a1) < len(ac.APPS_INTERACTIVE), f"baseline app subset narrower than full pool ({len(a1)}<{len(ac.APPS_INTERACTIVE)})")
    r1 = ac.baseline_resources_for(u)
    check(ac.rare_resource_for(u) not in set(r1), "rare_resource_for falls outside the entity baseline")


def test_onboarding_grows_slowly():
    print("[onboarding drift is gradual]")
    t0 = ac._RUN_T0
    n0 = len(ac.onboarded_apps(t0))
    n_day = len(ac.onboarded_apps(t0 + 24 * 3600))
    n_month = len(ac.onboarded_apps(t0 + 30 * 24 * 3600))
    check(n0 == ac.ONBOARDING_BASE_APPS, f"starts at base ({n0})")
    check(n_day - n0 <= 2, f"<=2 new apps/day ({n_day - n0})")
    check(n_month > n0, f"estate grows over a month ({n0}->{n_month})")
    check(n_month < len(ac.ADMIN_CONSENT_APPS), "estate not fully baked in after a month")


def test_lifecycle_cohorts():
    print("[identity lifecycle cohorts]")
    roster = list(CFG["user_profiles"])
    cohorts = {u: ac.lifecycle_cohort(u) for u in roster}
    n_dormant = sum(1 for c in cohorts.values() if c == "dormant")
    n_departed = sum(1 for c in cohorts.values() if c == "departed")
    check(n_dormant > 0 and n_departed > 0, f"roster has dormant ({n_dormant}) and departed ({n_departed}) cohorts")
    check(ac.lifecycle_cohort("some.user") == ac.lifecycle_cohort("some.user"), "cohort assignment stable")

    reserved = {u for u, c in cohorts.items() if c != "active"}
    # Benign signin/audit/o365 must never emit a reserved-cohort ROSTER identity.
    feeds = {"signin": aadsi, "audit": aaud, "o365_aad": o365a}
    for name, mod in feeds.items():
        leaked = 0
        for _ in range(15000):
            for rec in mod.generate_benign(CFG, {}):
                upn = rec.get("userPrincipalName") or rec.get("UserId") or ""
                un = str(upn).split("@")[0]
                if un in reserved:
                    leaked += 1
        check(leaked == 0, f"{name}: benign never signs in a dormant/departed roster account ({leaked})")

    # The state scenarios draw the right cohort.
    dis = {aadsi.SCENARIOS["disabled_user_signin"](CFG)[0]["userPrincipalName"].split("@")[0] for _ in range(100)}
    check(all(ac.lifecycle_cohort(u) == "departed" for u in dis), "disabled_user_signin draws departed cohort")
    dor = {aadsi.SCENARIOS["dormant_account_signin"](CFG)[0]["userPrincipalName"].split("@")[0] for _ in range(100)}
    check(all(ac.lifecycle_cohort(u) == "dormant" for u in dor), "dormant_account_signin draws dormant cohort")


if __name__ == "__main__":
    test_rare_pools_unbounded_and_disjoint()
    test_baseline_never_emits_rare()
    test_baseline_subsets_are_narrow_and_stable()
    test_onboarding_grows_slowly()
    test_lifecycle_cohorts()
    print()
    if _FAILS:
        print(f"FAILED ({len(_FAILS)}):")
        for f in _FAILS:
            print("  - " + f)
        sys.exit(1)
    print("ALL CARDINALITY GUARDS PASSED")
