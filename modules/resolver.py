"""Authoritative name->address resolution shared by every module.

WHY THIS EXISTS
Before this module each generator invented its own destination address. Infoblox
answered DNS queries with a random public IP, while the firewalls independently
picked a destination from config['benign_egress_destinations']. Measured in-tenant
2026-09-18 over 7 days, the two never agreed:

    Infoblox  zoom.us -> 45.25.97.136, 213.199.25.93, 142.254.180.140 ...
    FortiGate zoom.us -> 13.107.4.50
    intersection: EMPTY

so a DNS-to-connection network story could not be built at all, and `ups.com`
returned 3,009 distinct answers over 3,009 queries. One resolver removes the
disagreement by construction: Infoblox answers with resolve(), the firewalls take
their destination from resolve(), so the DNS answer IS the connection target.

DESIGN -- three zones, only one of which is ever looked up live:

  1. INTERNAL  synthetic and authoritative. examplecorp.local and every internal
               server/DC name. These addresses are RFC1918 and do not exist in
               public DNS, so they can never be resolved -- they are assigned
               deterministically from config['internal_servers'] / DC lists.

  2. CURATED    the ~30 real SaaS domains in benign_egress_destinations. Resolved
               live ONCE at startup, pinned for the life of the process, cached to
               disk with a TTL. Falls back to the configured CIDR when offline.

  3. SYNTHETIC  every threat destination: the rare-destination pool, DGA/C2 and
               dynamic-DNS names, Tor exits, the novel-country pool. NEVER looked
               up. Resolving them would be meaningless (most do not exist), would
               leak the simulator's activity to public resolvers, and would break
               the disjointness the rare pools depend on.

WHY NOT LIVE PER EVENT
Real DNS is far more volatile than the detectors tolerate. salesforce.com returns
eight rotating Akamai addresses; resolving per event would recreate the exact
"3,009 answers" instability this module exists to remove, and CDN anycast spans
dozens of countries, which is what silenced the org-scoped VPN new-country
detector at a 210-country footprint. So: resolve once, PIN for the run.

Degradation is soft, like domain_corpus: with no network the curated zone falls
back to the configured CIDR per domain and stays internally consistent, so the
DNS/firewall join still holds -- only the addresses are synthetic rather than real.
"""

import ipaddress
import json
import os
import random
import socket
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(PROJECT_ROOT, "domain_cache")
_CACHE_FILE = os.path.join(CACHE_DIR, "resolver.json")

_DEFAULTS = {
    # Live lookup of the curated public domains at startup. Off -> pure synthetic
    # (deterministic from the configured CIDRs); the join still holds.
    "live": True,
    "cache_ttl_hours": 24,
    "timeout_seconds": 3.0,
    # Cap on addresses pinned per domain. Real DNS hands back large rotating sets
    # (salesforce.com: 8 Akamai IPs); a handful is enough to look real while
    # keeping a destination stable enough for rarity/recurrence baselines.
    "max_ips_per_domain": 3,
    # Reject a live answer whose address is not inside the domain's configured
    # CIDR *and* would introduce a country the curated policy does not already
    # cover. The country footprint is load-bearing -- see session_utils.
    "restrict_to_configured_cidr": False,
}

# Survives importlib.reload(): both dashboards and log_simulator.load_modules()
# reload modules/ AFTER startup load(). Plain assignment would silently drop the
# pinned table -- the same trap domain_corpus documents.
RESOLVER_STATE: dict = globals().get("RESOLVER_STATE") or {"ok": False,
                                                           "error": "not attempted"}
_FORWARD: dict = globals().get("_FORWARD", {})   # domain -> [ip, ...]
_REVERSE: dict = globals().get("_REVERSE", {})   # ip -> domain
_LOADED_KEY = globals().get("_LOADED_KEY")


# ── helpers ───────────────────────────────────────────────────────────────────

def _stable_host(cidr, key):
    """A deterministic address inside `cidr`, derived from `key`.

    Deterministic so the same name maps to the same address across restarts --
    a fresh address every run would defeat the recurrence detectors the same way
    a fresh address per query defeats them.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return None
    import hashlib
    digest = int(hashlib.sha256(str(key).encode()).hexdigest(), 16)
    # /31 and /32 have no network/broadcast pair to skip; using the +1 offset on a
    # /32 walked one address PAST the range (13.107.4.50/32 -> .51), which
    # _local_validation/resolver_check.py caught as an answer outside its configured CIDR.
    if net.prefixlen >= 31:
        return str(ipaddress.ip_address(int(net.network_address)
                                        + digest % net.num_addresses))
    span = net.num_addresses - 2
    return str(ipaddress.ip_address(int(net.network_address) + 1 + digest % span))


def _live_lookup(domain, timeout):
    """Real A-record lookup. Returns [] on any failure -- never raises."""
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []
    finally:
        socket.setdefaulttimeout(None)


def _read_cache(ttl_seconds):
    try:
        with open(_CACHE_FILE, encoding="utf-8") as fh:
            blob = json.load(fh)
    except (OSError, ValueError):
        return None, None
    age = time.time() - blob.get("fetched_at", 0)
    return blob.get("forward") or {}, (age < ttl_seconds)


def _write_cache(forward):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = _CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"fetched_at": time.time(), "forward": forward}, fh, indent=2)
        os.replace(tmp, _CACHE_FILE)
    except OSError:
        pass


# ── zone builders ─────────────────────────────────────────────────────────────

def _internal_zone(config):
    """examplecorp.local names -> real internal addresses. Always synthetic.

    The internal estate is RFC1918 and exists only in this simulation, so these
    are assigned from the same pools the firewall modules target: a query for
    fileserver.<domain> resolves to an address the firewalls actually connect to.
    """
    ib = config.get("infoblox_config", {}) or {}
    ad_domain = (ib.get("ad_domain")
                 or config.get("ad_domain")
                 or "examplecorp.local")
    servers = list(config.get("internal_servers") or [])
    dcs = list(ib.get("domain_controllers") or config.get("domain_controllers") or [])
    if not dcs:
        dcs = ["10.0.10.10", "10.0.20.10", "10.1.5.10", "192.168.1.10", "172.16.10.10"]

    zone = {ad_domain: list(dcs[:2]) or servers[:1]}
    # Domain controllers: dc01..dcNN
    for i, ip in enumerate(dcs, start=1):
        zone[f"dc{i:02d}.{ad_domain}"] = [ip]
    zone[f"ad.{ad_domain}"] = list(dcs[:2])

    # Member servers, pinned deterministically to real internal_servers entries so
    # a name always resolves to the same host the firewalls target.
    roles = ["fileserver", "exchange", "sharepoint", "vcenter", "sql01",
             "print01", "app01", "backup01", "radius"]
    if servers:
        for i, role in enumerate(roles):
            zone[f"{role}.{ad_domain}"] = [servers[i % len(servers)]]

    # The Infoblox grid members themselves, so every module that names the DNS
    # server a client talks to uses the name the grid answers for.
    for name, ip in grid_members(config):
        zone[f"{name}.{ad_domain}"] = [ip]

    # Every remaining internal server gets a host name too, so a firewall that
    # names a server and Infoblox answering a PTR for it agree.
    named = {ip for ips in zone.values() for ip in ips}
    for ip in servers:
        if ip not in named:
            zone[_srv_name(ip, ad_domain)] = [ip]
    return ad_domain, zone


def _srv_name(ip, ad_domain):
    return f"srv-{str(ip).replace('.', '-')}.{ad_domain}"


def _curated_zone(config, cfg, fetch):
    """The ~30 real SaaS domains. Live once, pinned, cached; CIDR fallback."""
    dests = []
    for d in (config.get("benign_egress_destinations") or []):
        dom = d.get("domain")
        if dom and d.get("ip_range"):
            dests.append((dom, d["ip_range"]))
    for d in ((config.get("zscaler_config") or {}).get("benign_egress_destinations") or []):
        dom = d.get("domain")
        if dom and d.get("ip_range") and dom not in dict(dests):
            dests.append((dom, d["ip_range"]))

    ttl = float(cfg["cache_ttl_hours"]) * 3600
    cached, fresh = _read_cache(ttl)
    if cached and fresh:
        source = "cache"
        forward = {dom: ips for dom, ips in cached.items()
                   if dom in dict(dests) and ips}
        missing = [(d, c) for d, c in dests if d not in forward]
    else:
        source = "cache" if cached else "synthetic"
        forward, missing = {}, list(dests)

    live_hits = 0
    if missing and fetch and cfg["live"]:
        for dom, cidr in missing:
            ips = _live_lookup(dom, cfg["timeout_seconds"])
            if cfg["restrict_to_configured_cidr"] and ips:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    ips = [i for i in ips if ipaddress.ip_address(i) in net]
                except (ValueError, TypeError):
                    pass
            if ips:
                forward[dom] = ips[: int(cfg["max_ips_per_domain"])]
                live_hits += 1
        if live_hits:
            source = "live" if not cached else "live+cache"
            _write_cache(forward)

    # Anything still unresolved falls back to a deterministic host in its CIDR.
    # This keeps the DNS answer and the firewall destination identical offline.
    synth = 0
    for dom, cidr in dests:
        if not forward.get(dom):
            host = _stable_host(cidr, dom)
            if host:
                forward[dom] = [host]
                synth += 1
    return forward, source, live_hits, synth, len(dests)


# ── public API ────────────────────────────────────────────────────────────────

def load(config, fetch=True, force=False):
    """Build the resolution table once, at startup. Never raises.

    Repeat calls with unchanged settings are a no-op, because the CLI loads and
    then starts the dashboard, whose import would otherwise load again.
    """
    global _LOADED_KEY
    cfg = {**_DEFAULTS, **(config.get("resolver") or {})}
    key = json.dumps({k: cfg[k] for k in _DEFAULTS}, sort_keys=True, default=str)
    if not force and RESOLVER_STATE.get("ok") and key == _LOADED_KEY:
        return RESOLVER_STATE
    _LOADED_KEY = None
    started = time.time()
    try:
        ad_domain, internal = _internal_zone(config)
        curated, source, live_hits, synth, total = _curated_zone(config, cfg, fetch)

        _FORWARD.clear()
        _FORWARD.update(internal)
        _FORWARD.update(curated)
        for dom, cidr in list(_PINS.items()):
            if dom not in _FORWARD:
                host = _stable_host(cidr, dom)
                if host:
                    _FORWARD[dom] = [host]
        _REVERSE.clear()
        # The zone apex and ad.<domain> are aliases for the DCs, not their host
        # names; a PTR for a DC must say dc01, not examplecorp.local.
        aliases = {ad_domain, f"ad.{ad_domain}"}
        for dom, ips in _FORWARD.items():
            if dom in aliases:
                continue
            for ip in ips:
                _REVERSE.setdefault(ip, dom)

        RESOLVER_STATE.clear()
        RESOLVER_STATE.update(
            ok=True, error=None, source=source, ad_domain=ad_domain,
            internal=len(internal), curated=len(curated), curated_total=total,
            live=live_hits, synthetic=synth,
            load_seconds=round(time.time() - started, 2))
        _LOADED_KEY = key
        print(f"[resolver] {len(internal)} internal ({ad_domain}) + {len(curated)} "
              f"curated names ({source}: {live_hits} live, {synth} synthetic)")
    except Exception as exc:
        _FORWARD.clear()
        _REVERSE.clear()
        RESOLVER_STATE.clear()
        RESOLVER_STATE.update(ok=False, error=str(exc), internal=0, curated=0)
        print(f"[resolver] WARNING: resolution table unavailable ({exc}). "
              "Generators fall back to per-module address choice, and the "
              "DNS-to-connection join will not hold.")
    return RESOLVER_STATE


def available():
    return bool(_FORWARD)


def resolve(domain, default=None):
    """All addresses for `domain`, or [] when unknown (threat/synthetic names)."""
    if not domain:
        return []
    ips = _FORWARD.get(domain.lower().rstrip("."))
    if ips:
        return list(ips)
    return [default] if default else []


def resolve_one(domain, default=None):
    """One address for `domain` -- the answer a client would connect to.

    Stable per domain: picks from the pinned set, so repeated lookups agree and
    the firewall destination matches the DNS answer.
    """
    ips = resolve(domain)
    if not ips:
        return default
    return ips[0] if len(ips) == 1 else random.choice(ips)


def reverse(ip):
    """Domain that owns `ip`, for PTR answers and enrichment. None when unknown."""
    return _REVERSE.get(ip)


def known_domains():
    return sorted(_FORWARD)


# ── DNS topology shared by Infoblox and every network module ─────────────────
#
# Clients resolve through the Infoblox grid, not public resolvers. Every module
# that logs a client's DNS traffic must name the SAME grid member Infoblox logs
# the query on, so the member choice lives here, not in any one module. The
# network modules used to send benign client DNS straight to 8.8.8.8/1.1.1.1,
# which in an Infoblox estate is itself a policy-bypass signal -- and it meant no
# firewall DNS flow ever lined up with an Infoblox query.

def grid_members(config):
    """[(hostname, ipv4)] of the Infoblox grid: hostnames[i] serves dns_server_ips[i]."""
    ib    = (config or {}).get("infoblox_config", {}) or {}
    names = ib.get("hostnames") or ["infoblox-dc1-01"]
    ips   = ib.get("dns_server_ips") or ib.get("server_ip") or ["10.1.1.2"]
    if not isinstance(ips, list):
        ips = [ips]
    n = max(len(names), len(ips))
    return [(names[i % len(names)], ips[i % len(ips)]) for i in range(n)]


def dns_server_for(config, key):
    """(hostname, ip) of the grid member that serves `key` (a client IP or MAC).

    Deterministic, so the Infoblox module and every firewall agree on which
    member a given client talks to.
    """
    import hashlib
    members = grid_members(config)
    if key is None:
        return random.choice(members)
    return members[int(hashlib.sha256(str(key).encode()).hexdigest(), 16) % len(members)]


def dns_forwarders(config):
    """Upstream resolvers the grid forwards recursion to -- the only DNS that
    leaves the estate in normal operation."""
    ib = (config or {}).get("infoblox_config", {}) or {}
    return list(ib.get("forwarders") or ["8.8.8.8", "8.8.4.4"])


_PINS: dict = globals().get("_PINS", {})   # domain -> cidr, registered by modules


def pin(domain, cidr):
    """Register a module's own well-known name (a vendor update host, the
    company's VPN gateway) with a stable address inside its real range, so
    Infoblox answers it the same way the module connects to it. Idempotent;
    an existing table entry wins. Survives load(), which re-applies pins."""
    d = str(domain).lower().rstrip(".")
    _PINS.setdefault(d, cidr)
    if d not in _FORWARD:
        host = _stable_host(cidr, d)
        if host:
            _FORWARD[d] = [host]
            _REVERSE.setdefault(host, d)
    return (_FORWARD.get(d) or [None])[0]


def answer_for(domain, config=None):
    """The address `domain` resolves to, for ANY name, identical in every module.

    Curated and internal names come from the table. Everything else (long-tail
    corpus names, one-off hosts) gets a STABLE address from the ambient external
    pool keyed by the name -- stable so the Infoblox answer and the firewall
    destination agree, ambient so it carries the same geolocation as all other
    benign external traffic. Threat infrastructure passes its own address
    explicitly and never reaches this fallback.
    """
    ip = resolve_one(domain)
    if ip:
        return ip
    try:
        from modules.session_utils import stable_external_ip
    except ImportError:
        from session_utils import stable_external_ip
    return stable_external_ip(str(domain).lower().rstrip("."), config)


def benign_target(config, dest):
    """(domain, ip) for a benign_egress_destinations entry, where the ip is what
    the NAME resolves to. Replaces each module's own random host in the entry's
    CIDR, which never matched the Infoblox answer for the same name."""
    dest = dest or {}
    domain = dest.get("domain") or str(dest.get("name", "example.com")).lower().replace(" ", "")
    ip = resolve_one(domain)
    if not ip and dest.get("ip_range"):
        ip = _stable_host(dest["ip_range"], domain)
    return domain, ip or answer_for(domain, config)


def internal_fqdn(config, ip, prefix="srv"):
    """The name the grid holds for an internal address; a stable srv-N name on
    the AD suffix when the address has no role name."""
    name = reverse(ip)
    if name:
        return name
    return _srv_name(ip, internal_domain(config))


def internal_domain(config=None):
    """The AD/DNS suffix the whole simulation shares (examplecorp.local)."""
    if RESOLVER_STATE.get("ad_domain"):
        return RESOLVER_STATE["ad_domain"]
    ib = (config or {}).get("infoblox_config", {}) or {}
    return ib.get("ad_domain") or (config or {}).get("ad_domain") or "examplecorp.local"
