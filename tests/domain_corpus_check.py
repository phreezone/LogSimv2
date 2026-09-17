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


def _capture_zscaler(cfg, generator, n):
    """Run a Zscaler generator n times, returning its NSSWeblog field dicts.

    These generators emit a DNS precursor and an NSSFWlog alongside the web log
    and all three go through _format_nss_log_as_cef, so keep only the web ones.
    """
    captured = []
    orig = zs._format_nss_log_as_cef
    zs._format_nss_log_as_cef = lambda fields, *a, **k: captured.append(fields) or ""
    try:
        dev = {"hostname": "WKS-1", "owner": "a.tucker", "os_type": "Windows",
               "os_version": "10", "user_agent": "Mozilla/5.0"}
        for _ in range(n):
            generator(cfg, "a.tucker", "Finance", "10.0.0.5", dev)
    finally:
        zs._format_nss_log_as_cef = orig
    return [f for f in captured if "ehost" in f]


def exfil_tail(cfg):
    """Large uploads must reach BOTH archetypes: the curated file-sharing sites
    (pastebin/mega/wetransfer -- famous domain, anomalous volume) and the long
    tail (a host nothing else in the run resolves). Losing either one silently
    removes a whole class of detection content from the training data."""
    print("exfil destinations")
    curated = {(d.get("domain") or "") for d in cfg["exfiltration_destinations"]}
    share_cfg = cfg["domain_corpus"]["exfil_tail_share"]

    def is_curated(host):
        # Wildcard entries ("*.digitaloceanspaces.com") reach the log as a
        # concrete FQDN, so an exact-membership test would miscount them as tail.
        return host in curated or any(
            d.startswith("*.") and host.endswith(d[1:]) for d in curated)

    fields = _capture_zscaler(cfg, zs._generate_data_exfil_web_traffic, 6000)
    tail = [f for f in fields if not is_curated(f["ehost"])]
    hit  = [f for f in fields if is_curated(f["ehost"])]
    share = len(tail) / len(fields)
    check("exfil tail share ~= configured", abs(share - share_cfg) < 0.02,
          f"{share:.2%} vs {share_cfg:.0%}")
    check("curated file-sharing sites still dominate", len(hit) > len(tail),
          f"{len(hit):,} curated vs {len(tail):,} tail")

    # The user-visible guarantee: uploads still go to pastebin and friends.
    # Direction is curated per entry and defaults to "both" -- it used to be an
    # alphabetical split that left anonfiles, gist, gofile, dropbox, drive.google
    # and box unreachable for uploads.
    upload_pool = {(d.get("domain") or "") for d in cfg["exfiltration_destinations"]
                   if d.get("direction", "both") in ("upload", "both")}
    seen = {f["ehost"] for f in hit}
    missed = {d for d in upload_pool
              if not (d in seen or (d.startswith("*.")
                                    and any(h.endswith(d[1:]) for h in seen)))}
    check("every curated upload destination still receives uploads",
          not missed, sorted(missed))
    check("pastebin specifically still receives uploads", "pastebin.com" in seen)
    check("the formerly unreachable upload targets are reachable",
          {"anonfiles.com", "gist.github.com", "gofile.io", "dropbox.com",
           "drive.google.com", "box.com"} <= seen,
          sorted({"anonfiles.com", "gist.github.com", "gofile.io", "dropbox.com",
                  "drive.google.com", "box.com"} - seen))

    counts = collections.Counter(f["ehost"] for f in tail)
    repeated = sum(c for c in counts.values() if c > 1) / max(1, len(tail))
    check("exfil tail hosts essentially never repeat", repeated < 0.02,
          f"{len(counts):,} distinct of {len(tail):,}; {repeated:.2%} in repeats")
    check("no unsafe domain reached an exfil upload",
          not any(dc._UNSAFE_RE.search(f["ehost"]) for f in tail))
    check("exfil tail hosts come from the web view (no infra)",
          not any(dc._INFRA_RE.search(f["ehost"]) for f in tail))

    # A tail host is not a named SaaS app. Mislabelling it as cloud storage makes
    # the event fire the wrong detection and hide from the right one.
    check("tail exfil is labelled uncategorised, not Online Storage",
          all(f["urlcat"] == "Miscellaneous or Unknown"
              and f["appname"] == "General Browsing" for f in tail))
    check("curated exfil keeps its Online Storage labelling",
          all(f["urlcat"] == "Online Storage"
              and f["appname"] == "File Transfer" for f in hit))
    check("tail exfil still carries the large upload volume",
          all(f["bytesout"] > 300_000_000 for f in tail))

    # Per-object URLs: a fixed "/upload" collapses every exfil event onto one URL.
    urls = [f["eurl"] for f in fields]
    check("exfil URLs are unique per event",
          len(set(urls)) / len(urls) > 0.99, f"{len(set(urls)):,} of {len(urls):,}")
    pastebin = [u for u in urls if u.startswith("https://pastebin.com/")]
    check("service URL shapes are realistic",
          bool(pastebin) and all(u.startswith("https://pastebin.com/raw/")
                                 for u in pastebin), pastebin[:1])

    # Downloads honour the curated direction tag. Uploads and downloads now
    # OVERLAP by design -- a host you upload to is a host someone downloads from,
    # and the firewall modules already drew both directions from the whole pool.
    upload_only = {(d.get("domain") or "") for d in cfg["exfiltration_destinations"]
                   if d.get("direction", "both") == "upload"}
    dl = _capture_zscaler(cfg, zs._generate_large_download, 3000)
    dl_hosts = {f["ehost"] for f in dl if is_curated(f["ehost"])}
    check("upload-only destinations never serve a download",
          not dl_hosts & upload_only, sorted(dl_hosts & upload_only))
    eligible = {d for d in curated if d not in upload_only}
    covered = {d for d in eligible
               if d in dl_hosts or (d.startswith("*.")
                                    and any(h.endswith(d[1:]) for h in dl_hosts))}
    check("both-direction destinations do serve downloads",
          covered == eligible, f"missing {sorted(eligible - covered)}")

    # DLP blocks share the picker, so they inherit both archetypes too.
    dlp = _capture_zscaler(cfg, zs._generate_dlp_web_traffic, 2000)
    dlp_tail = [f for f in dlp if not is_curated(f["ehost"])]
    check("DLP blocks reach the tail as well",
          bool(dlp_tail) and all(f["urlcat"] == "Miscellaneous or Unknown"
                                 for f in dlp_tail), f"{len(dlp_tail):,} tail blocks")


def exfil_fallback_consumes_no_randomness(cfg):
    """With no corpus the tail gate must not draw a random number, so an offline
    run picks the same curated destination it would have picked before."""
    print("exfil fallback")
    dc.load({"domain_corpus": {"enabled": False}})
    random.seed(11)
    a = [su.exfil_destination(cfg, "upload")[0] for _ in range(200)]
    random.seed(11)
    b = [su.exfil_destination({**cfg, "domain_corpus": {"exfil_tail_share": 0}},
                              "upload")[0] for _ in range(200)]
    check("no corpus -> every draw is curated",
          all(not t for t in [su.exfil_destination(cfg, "upload")[3]
                              for _ in range(200)]))
    check("tail gate draws no random numbers when unavailable", a == b)
    dc.load(cfg)


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
        exfil_tail(cfg)
        exfil_fallback_consumes_no_randomness(cfg)
        determinism(cfg)
    print(f"\n{len(_checks) - len(_fails)}/{len(_checks)} checks passed")
    if _fails:
        print("FAILURES:\n  " + "\n  ".join(_fails))
        sys.exit(1)


if __name__ == "__main__":
    main()
