"""Long-tail domain corpus: real registrable domains for the "rare" tail.

The benign pools in config.json are ~26 curated domains. Weighting can make one
of them *rarely picked*, but over a long run every entry accumulates thousands of
hits and UEBA learns it as normal -- with a pool that small, rarity is only a
weight. Rarity has to come from CARDINALITY: a tail so wide that any one domain
is seen roughly once. This module supplies that tail; the curated pool stays the
per-user head, so the affinity baselines built on it are untouched.

Source: Tranco (https://tranco-list.eu), a research aggregate of CrUX, Farsight,
Majestic, Radar and Umbrella, pay-level domains only. Chosen over Umbrella for
its permissive terms and because every daily list has a permanent ID, which is
what makes a snapshot pinnable for reproducible Training runs.

Measured against the live list GQNVK (2026-09-14):
    download        9.7 MB zipped / 1M rows            0.7 s
    labels          2: 87.7%   3: 10.1%   4: 0.2%      (already registrable)
    unsafe tail     2.34% adult / gambling / warez     (.casino and togel spam)
    infra tail      ~0.5% DNS hosting, CDN, ad-tech, reverse-DNS zones

Two views, because DNS and web proxies see different things:
    dns  -- resolver-realistic: keeps nameserver/CDN/ad-tech PLDs a real
            resolver is asked about.  Infoblox, Check Point DNS.
    web  -- browsing destinations only: infrastructure removed.  Zscaler.

Degradation is soft: with no corpus the callers fall back to the config pool,
and /api/health reports rarity as degraded. Unlike the Tor list (where a missing
list makes events WRONG), a missing corpus only makes the tail narrower.
"""

import gzip
import io
import json
import os
import random
import re
import time
import urllib.request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(PROJECT_ROOT, "domain_cache")

_API_LATEST = "https://tranco-list.eu/api/lists/date/latest"
_DOWNLOAD_BY_ID = "https://tranco-list.eu/download/{list_id}/1000000"
_UA = "LogSim/2.0 (+domain-corpus)"

_DEFAULTS = {
    "enabled": True,
    # Ranks below this are the popular head -- well-known enough that UEBA
    # baselines would treat them as common. Above the end rank the list is
    # dominated by parked and spam registrations, and dropping it halves memory.
    "tail_start_rank": 20_000,
    "tail_end_rank": 500_000,
    # Fraction of benign DNS queries / web requests drawn from the tail.
    "tail_share": 0.05,
    "filter_unsafe": True,
    "cache_ttl_hours": 24,
    # Tranco list ID (e.g. "GQNVK") to load instead of the latest daily list.
    "pinned_list_id": None,
}

# Loaded state must survive importlib.reload(): both the dashboard's
# _load_modules() and log_simulator.load_modules() reload every file in modules/,
# and both run AFTER the startup load(). reload() re-executes this file in the
# same module __dict__, so plain assignments here would silently discard a
# loaded corpus -- measured: health reported "not attempted" and every tail draw
# fell back to the config pool. globals().get() keeps the existing objects.
# Outcome of the last load(), surfaced by /api/health.
CORPUS_STATE: dict = globals().get("CORPUS_STATE") or {"ok": False,
                                                       "error": "not attempted"}
TAIL_SHARE = globals().get("TAIL_SHARE", _DEFAULTS["tail_share"])
_LOADED_KEY = globals().get("_LOADED_KEY")
_DNS_TAIL: list = globals().get("_DNS_TAIL", [])
_WEB_TAIL: list = globals().get("_WEB_TAIL", [])

# Adult / gambling / warez / pharma spam. In a corporate baseline these look
# wrong as ALLOWED traffic. Heuristic, tuned against the measured tail: the
# look-behinds keep essex/sussex/middlesex, and judi(?!c) keeps judicial.
_UNSAFE_RE = re.compile(
    r"porn|xxx|xvideo|xnxx|hentai|nsfw|onlyfans|escort|nude|camgirl|milf"
    r"|(?<![aeiu]s)(?<!middle)sex(?!ton|tant)"
    r"|casino|poker|gambl|betting|bet365|sbobet|\bslots?\b|slotgacor|togel"
    r"|judi(?!c)|dewa\d|torrent|warez|keygen|crack(?:ed|s)?\b"
    r"|viagra|cialis|tadalaf"
)

# Reverse-DNS zones are never a query name on their own (PTR queries have their
# own generator), so they leave both views.
_ARPA_RE = re.compile(r"\.arpa$")

# Infrastructure a resolver sees but a user never browses to.
_INFRA_RE = re.compile(
    r"dns|cdn|akadns|akamai|edgekey|edgesuite|cloudfront|trafficmanager"
    r"|azure-api|azureedge|doubleclick|adnxs|adsrvr|adservice|telemetry"
    r"|tracking|analytics|metrics|nameserver"
    r"|(?:^|[.-])(?:ns|mx)\d|(?:^|[.-])ntp"
)


def build_views(domains, tail_start_rank, tail_end_rank, filter_unsafe=True):
    """Split a rank-ordered domain list into (dns_tail, web_tail, unsafe_count).

    `domains[i]` is the domain at rank i+1. Pure, so tests need no network.
    """
    lo = max(0, int(tail_start_rank) - 1)
    hi = min(len(domains), int(tail_end_rank))
    dns, web, unsafe = [], [], 0
    for d in domains[lo:hi]:
        if _ARPA_RE.search(d):
            continue
        if filter_unsafe and _UNSAFE_RE.search(d):
            unsafe += 1
            continue
        dns.append(d)
        if not _INFRA_RE.search(d):
            web.append(d)   # same string object -- a reference, not a copy
    return dns, web, unsafe


# ── Fetch + cache ─────────────────────────────────────────────────────────────

def _get(url, timeout):
    req = urllib.request.Request(
        url, headers={"Accept-Encoding": "gzip", "User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
    return raw


def _cache_path(list_id):
    return os.path.join(CACHE_DIR, f"tranco_{list_id}.csv.gz")


def _pointer_path():
    return os.path.join(CACHE_DIR, "latest.json")


def _parse_lines(lines, limit):
    """Rank-ordered domains from Tranco `rank,domain` lines, stopping at `limit`.

    Streams and stops early: materialising all 1M rows peaked at 180 MB to
    retain the 36 MB actually used.
    """
    domains = []
    for line in lines:
        if len(domains) >= limit:
            break
        rank, sep, domain = line.strip().partition(",")
        if sep and domain:
            domains.append(domain)
    return domains


def _download(list_id, limit):
    raw = _get(_DOWNLOAD_BY_ID.format(list_id=list_id), timeout=90)
    # A truncated or HTML error body must not become the cached corpus.
    rows = raw.count(b"\n")
    if rows < 100_000 or not raw.startswith(b"1,"):
        raise ValueError(f"Tranco list {list_id} looks malformed ({rows} rows)")
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = _cache_path(list_id) + ".tmp"
    with gzip.open(tmp, "wb") as fh:
        fh.write(raw)
    os.replace(tmp, _cache_path(list_id))
    return _parse_lines(io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8"), limit)


def _read_cached(list_id, limit):
    with gzip.open(_cache_path(list_id), "rt", encoding="utf-8") as fh:
        return _parse_lines(fh, limit)


def _prune(keep):
    """Drop cached lists other than `keep`, oldest first, retaining three."""
    try:
        files = sorted((os.path.join(CACHE_DIR, f) for f in os.listdir(CACHE_DIR)
                        if f.startswith("tranco_") and f.endswith(".csv.gz")),
                       key=os.path.getmtime)
    except OSError:
        return
    keep_paths = {_cache_path(k) for k in keep if k}
    for path in [p for p in files if p not in keep_paths][:-2]:
        try:
            os.remove(path)
        except OSError:
            pass


def _obtain(cfg, fetch):
    """Return (list_id, domains, source) where source is live/cache/stale-cache."""
    limit = int(cfg["tail_end_rank"])
    pinned = cfg.get("pinned_list_id")
    if pinned:
        if os.path.exists(_cache_path(pinned)):
            return pinned, _read_cached(pinned, limit), "cache"
        if not fetch:
            raise RuntimeError(f"pinned list {pinned} is not cached")
        return pinned, _download(pinned, limit), "live"

    pointer = None
    try:
        with open(_pointer_path(), encoding="utf-8") as fh:
            pointer = json.load(fh)
    except (OSError, ValueError):
        pass
    cached = bool(pointer and os.path.exists(_cache_path(pointer.get("list_id"))))
    ttl = float(cfg.get("cache_ttl_hours", _DEFAULTS["cache_ttl_hours"])) * 3600
    if cached and (not fetch or time.time() - pointer.get("fetched_at", 0) < ttl):
        return pointer["list_id"], _read_cached(pointer["list_id"], limit), "cache"
    if not fetch:
        raise RuntimeError("no cached corpus and fetching is disabled")

    try:
        meta = json.loads(_get(_API_LATEST, timeout=15).decode("utf-8"))
        list_id = meta["list_id"]
        if os.path.exists(_cache_path(list_id)):
            domains = _read_cached(list_id, limit)
        else:
            domains = _download(list_id, limit)
        with open(_pointer_path(), "w", encoding="utf-8") as fh:
            json.dump({"list_id": list_id, "created_on": meta.get("created_on"),
                       "fetched_at": time.time()}, fh)
        _prune([list_id])
        return list_id, domains, "live"
    except Exception:
        # Yesterday's tail is still a million times wider than the config pool.
        if cached:
            return (pointer["list_id"], _read_cached(pointer["list_id"], limit),
                    "stale-cache")
        raise


def load(config, fetch=True, force=False):
    """Load the corpus into memory once, at startup. Never raises.

    Loaded once per process and never refreshed underneath a running simulator,
    so a morning Training Bulk stage and an afternoon Live stream in the same
    process draw from an identical tail. Set `pinned_list_id` for the same tail
    across restarts.

    A repeat call with the same settings is a no-op: the CLI loads the corpus and
    then starts the dashboard, whose import would otherwise load it again.
    """
    global TAIL_SHARE, _LOADED_KEY
    cfg = {**_DEFAULTS, **(config.get("domain_corpus") or {})}
    key = json.dumps({k: cfg[k] for k in _DEFAULTS}, sort_keys=True, default=str)
    if not force and CORPUS_STATE.get("ok") and key == _LOADED_KEY:
        return CORPUS_STATE
    _LOADED_KEY = None
    TAIL_SHARE = float(cfg["tail_share"])
    started = time.time()
    try:
        if not cfg["enabled"]:
            raise RuntimeError("disabled in config (domain_corpus.enabled)")
        list_id, domains, source = _obtain(cfg, fetch)
        dns, web, unsafe = build_views(domains, cfg["tail_start_rank"],
                                       cfg["tail_end_rank"], cfg["filter_unsafe"])
        if not dns or not web:
            raise ValueError("tail rank window selected no domains")
        _DNS_TAIL[:] = dns
        _WEB_TAIL[:] = web
        CORPUS_STATE.clear()
        CORPUS_STATE.update(
            ok=True, error=None, source=source, list_id=list_id,
            dns=len(dns), web=len(web), unsafe_filtered=unsafe,
            tail_share=TAIL_SHARE, pinned=bool(cfg["pinned_list_id"]),
            load_seconds=round(time.time() - started, 2))
        _LOADED_KEY = key
        print(f"[domain-corpus] Tranco {list_id} ({source}): {len(dns):,} DNS / "
              f"{len(web):,} web tail domains, {unsafe:,} unsafe filtered, "
              f"tail share {TAIL_SHARE:.0%}")
    except Exception as exc:
        _DNS_TAIL.clear()
        _WEB_TAIL.clear()
        CORPUS_STATE.clear()
        CORPUS_STATE.update(ok=False, error=str(exc), dns=0, web=0,
                            tail_share=TAIL_SHARE)
        print(f"[domain-corpus] WARNING: long-tail corpus unavailable ({exc}). "
              "Rare domains fall back to the config pool, which UEBA will "
              "eventually learn as normal.")
    return CORPUS_STATE


def available():
    return bool(_DNS_TAIL)


def tail_domain(view="dns"):
    """One uniformly-drawn tail domain from the given view, or None if unloaded."""
    pool = _WEB_TAIL if view == "web" else _DNS_TAIL
    return random.choice(pool) if pool else None
