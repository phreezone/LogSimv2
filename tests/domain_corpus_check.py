"""Long-tail domain corpus: is "rare" actually rare, and does it fail safe?

The problem this guards against: with a ~26-domain pool, a "rare" domain is only
a low WEIGHT. Over a long run it is still seen thousands of times and UEBA learns
it as normal. Rarity has to come from CARDINALITY. This asserts:

    offline  the filters keep what they should and drop what they should
    live     the Tranco list loads, and reloads from cache
    rarity   ~tail_share of benign lookups hit the tail, and they almost never repeat
    honesty  no adult/gambling domain reaches an ALLOWED event; Zscaler tail hits
             are not labelled as a named SaaS app
    safety   with no corpus the helpers draw nothing -- not even a random number --
             so offline runs are byte-identical to before the corpus existed
    repro    a seeded run draws the same tail twice

Needs network on the first run (tranco-list.eu); later runs use domain_cache/.

Run:  python tests/domain_corpus_check.py
"""

import collections
import importlib
import json
import os
import random
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from modules import domain_corpus as dc                            # noqa: E402
import modules.session_utils as su                                 # noqa: E402
import modules.zscaler as zs                                       # noqa: E402

_fails, _checks = [], []


def check(name, cond, detail=""):
    _checks.append(name)
    status = "ok  " if cond else "FAIL"
    print(f"  [{status}] {name}" + (f"  -- {detail}" if detail else ""))
    if not cond:
        _fails.append(f"{name}: {detail}")


def offline_filters():
    print("offline filters")
    ranked = (["head.com"] * 5 + [
        "essex.ac.uk", "sussex.gov.uk", "middlesex.edu", "judicial.gov",
        "alphabet.com", "wissen.de",                       # must survive
        "6107.casino", "tubeporndot.com", "tototogel00.net", "sbobet88.com",
        "judibola.id", "sexmovies-ok.com",                 # unsafe
        "58.in-addr.arpa",                                 # arpa: both views
        "awsdns-cn-08.com", "rocket-cdn3.com", "ns2.pl",   # infra: dns only
        "tail-end.com",
    ])
    dns, web, unsafe = dc.build_views(ranked, 6, len(ranked) - 1)
    keep = {"essex.ac.uk", "sussex.gov.uk", "middlesex.edu", "judicial.gov",
            "alphabet.com", "wissen.de"}
    check("safe look-alikes kept", keep <= set(web), sorted(keep - set(web)))
    check("unsafe dropped from both views", unsafe == 6 and not
          any(dc._UNSAFE_RE.search(d) for d in dns), f"unsafe={unsafe}")
    check("reverse-DNS zones dropped", "58.in-addr.arpa" not in dns)
    infra = {"awsdns-cn-08.com", "rocket-cdn3.com", "ns2.pl"}
    check("infra kept for DNS", infra <= set(dns))
    check("infra removed from web", not infra & set(web))
    check("web is a subset of dns", set(web) <= set(dns))
    check("rank window respected",
          "head.com" not in dns and "tail-end.com" not in dns)
    _, _, unfiltered = dc.build_views(ranked, 6, len(ranked), filter_unsafe=False)
    check("filter_unsafe=False keeps them", unfiltered == 0)


def fallback_consumes_no_randomness():
    print("fallback")
    dc.load({"domain_corpus": {"enabled": False}})
    check("disabled -> not ok", not dc.CORPUS_STATE["ok"] and not dc.available(),
          dc.CORPUS_STATE.get("error"))
    random.seed(7)
    before = random.getstate()
    got = [su.long_tail_domain("dns") for _ in range(100)]
    check("helper returns None", got == [None] * 100)
    check("helper draws no random numbers", random.getstate() == before)


def live_and_cache(cfg):
    print("live load + cache")
    t = time.time()
    state = dict(dc.load(cfg))
    first = time.time() - t
    check("corpus loads", state["ok"], state.get("error"))
    if not state["ok"]:
        return False
    check("DNS tail is wide", state["dns"] > 400_000, f"{state['dns']:,}")
    check("web tail is wide", state["web"] > 400_000, f"{state['web']:,}")
    print(f"    Tranco {state['list_id']} ({state['source']}) in {first:.1f}s, "
          f"{state['unsafe_filtered']:,} unsafe filtered")
    t = time.time()
    same = dc.load(cfg)
    check("repeat load with same settings is a no-op",
          time.time() - t < 0.1 and same.get("list_id") == state["list_id"])
    t = time.time()
    again = dict(dc.load(cfg, force=True))
    check("forced reload comes from cache", again.get("source") == "cache",
          f"{again.get('source')} in {time.time() - t:.1f}s")
    check("cache returns the same list", again.get("list_id") == state["list_id"])
    check("cache reload yields identical tails", again["dns"] == state["dns"]
          and again["web"] == state["web"])
    # Both module loaders importlib.reload() every file in modules/ AFTER the
    # startup load -- a corpus that does not survive that is never used.
    importlib.reload(dc)
    check("loaded corpus survives importlib.reload",
          dc.available() and dc.CORPUS_STATE.get("list_id") == state["list_id"],
          f"available={dc.available()} state={dc.CORPUS_STATE.get('error')}")
    pinned = dict(dc.load({"domain_corpus": {**cfg.get("domain_corpus", {}),
                                             "pinned_list_id": state["list_id"]}}))
    check("pinned list id loads", pinned.get("ok") and pinned.get("pinned")
          and pinned.get("list_id") == state["list_id"], pinned.get("error"))
    dc.load(cfg)
    return True


def rarity(cfg):
    print("rarity through weighted_dns_domain")
    su.build_session_context(cfg)
    pool = cfg["benign_domains"]
    users = list(cfg["user_profiles"])[:200]
    n = 60_000
    picks = [su.weighted_dns_domain(random.choice(users), pool) for _ in range(n)]
    tail = [d for d in picks if d not in pool]
    share = len(tail) / n
    check("tail share ~= configured", abs(share - dc.TAIL_SHARE) < 0.01,
          f"{share:.2%} vs {dc.TAIL_SHARE:.0%}")
    counts = collections.Counter(tail)
    repeated = sum(c for c in counts.values() if c > 1) / max(1, len(tail))
    check("tail domains essentially never repeat", repeated < 0.02,
          f"{len(counts):,} distinct of {len(tail):,}; {repeated:.2%} in repeats")
    check("no unsafe domain reached a lookup",
          not any(dc._UNSAFE_RE.search(d) for d in tail))
    # The old failure mode, for contrast: the rarest curated domain's hit count.
    pool_counts = collections.Counter(d for d in picks if d in pool)
    rarest = min(pool_counts.values())
    print(f"    rarest curated domain: {rarest:,} hits  vs  "
          f"busiest tail domain: {max(counts.values())} hits")


def zscaler_web(cfg):
    print("zscaler web")
    captured = []
    orig = zs._format_nss_log_as_cef
    zs._format_nss_log_as_cef = lambda fields, *a, **k: captured.append(fields) or ""
    try:
        dev = {"hostname": "WKS-1", "owner": "a.tucker", "os_type": "Windows",
               "os_version": "10", "user_agent": "Mozilla/5.0"}
        for _ in range(8000):
            zs._generate_benign_web_traffic(cfg, "a.tucker", "Finance", "10.0.0.5", dev)
    finally:
        zs._format_nss_log_as_cef = orig
    named = {d.get("name", "").replace(" ", "").lower()
             for d in cfg["zscaler_config"]["benign_egress_destinations"]}
    tail = [f for f in captured if f["ehost"] not in named]
    share = len(tail) / len(captured)
    check("zscaler tail share ~= configured", abs(share - dc.TAIL_SHARE) < 0.015,
          f"{share:.2%}")
    check("tail hits labelled General Browsing",
          all(f["appname"] == "General Browsing" for f in tail))
    check("tail hosts come from the web view (no infra)",
          not any(dc._INFRA_RE.search(f["ehost"]) for f in tail))
    check("tail hits carry a public IP",
          all(not f["sip"].startswith(("10.", "192.168.", "172.")) for f in tail))


def determinism(cfg):
    print("determinism")
    su.build_session_context(cfg)
    pool = cfg["benign_domains"]

    def run():
        random.seed(12345)
        return [su.weighted_dns_domain(f"u{i % 40}", pool) for i in range(5000)]
    check("seeded runs draw an identical tail", run() == run())


def main():
    cfg = json.load(open(os.path.join(_ROOT, "config.json"), encoding="utf-8"))
    offline_filters()
    fallback_consumes_no_randomness()
    if live_and_cache(cfg):
        rarity(cfg)
        zscaler_web(cfg)
        determinism(cfg)
    print(f"\n{len(_checks) - len(_fails)}/{len(_checks)} checks passed")
    if _fails:
        print("FAILURES:\n  " + "\n  ".join(_fails))
        sys.exit(1)


if __name__ == "__main__":
    main()
