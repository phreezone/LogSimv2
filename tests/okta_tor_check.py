"""Okta anonymizer-fidelity check: Tor/VPN markers, geo consistency, enrichment.

Guards the fixes made after the 2026-09 vendor-conformance research:

  * Tor is reported the way Okta reports it -- debugContext.debugData.proxyType
    and request.ipChain[].ipDetails.ipServiceCategories -- not by securityContext
    alone, which carries only a generic isProxy bit.
  * geographicalContext.geolocation is never (0, 0).  Null Island is a real
    coordinate, so an unplaceable address that lands there hands geo-velocity a
    huge, perfectly repeatable distance from every genuine login.  Okta emits a
    null geolocation instead, and so do we.
  * Exit nodes carry the real country and hosting AS from Onionoo rather than
    country="Unknown" / isp="TOR Exit Node" / AS0, none of which any GeoIP-backed
    vendor would ever return.
  * The private _ipCtx key _build_client() uses to thread the source context
    never reaches the wire.

Run:  python tests/okta_tor_check.py
Needs network for the live Tor list; skips (exit 0) if it cannot be reached.
"""

import collections
import json
import os
import random
import sys
import urllib.request

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from modules.tor_enrichment import enrich_tor_nodes          # noqa: E402
import modules.okta_sso as okta                               # noqa: E402
from modules.session_utils import get_random_anon_ip_ctx      # noqa: E402

_BULK = "https://check.torproject.org/torbulkexitlist"

_fails, _checks = [], []


def check(name, cond, detail=""):
    _checks.append(name)
    if not cond:
        _fails.append(f"{name}: {detail}")


def haversine(a, b):
    """Great-circle km between (lat, lon) pairs.

    Delegates to the module's own _get_location_distance() rather than carrying a
    second copy of the formula -- if the module's geo maths is wrong, this test
    should be wrong the same way and say so.
    """
    return okta._get_location_distance({"lat": a[0], "lon": a[1]},
                                       {"lat": b[0], "lon": b[1]})


def flatten(x):
    """Generators return a str, a list, or a (list, extra) tuple."""
    if isinstance(x, str):
        yield x
    elif isinstance(x, (list, tuple)):
        for item in x:
            yield from flatten(item)


def main():
    cfg = json.load(open(os.path.join(_ROOT, "config.json"), encoding="utf-8"))

    try:
        raw = urllib.request.urlopen(_BULK, timeout=30).read().decode("utf-8")
    except Exception as exc:
        print(f"SKIP: cannot reach {_BULK} ({exc})")
        return 0
    ips = [l.strip() for l in raw.splitlines() if l.strip()]
    nodes, stats = enrich_tor_nodes([{"ip": i} for i in ips])
    cfg["tor_exit_nodes"] = nodes
    print(f"Tor list: {stats['total']} nodes, Onionoo resolved "
          f"{stats['resolved']} ({stats['join_rate']}%)")
    # The bulk exit list and Onionoo's relay set refresh on different cadences,
    # so their overlap genuinely drifts through the day -- 98.2% and 87.9% both
    # observed within hours. The floor is set to catch enrichment actually
    # breaking (which lands near 0%), not normal churn.
    check("onionoo join rate >=75%", stats["join_rate"] >= 75.0, f"{stats['join_rate']}%")

    # --- Tor-path events ----------------------------------------------------
    random.seed(1234)
    user = {"username": "j.smith@examplecorp.com", "full_name": "John Smith"}
    actor = okta._build_actor(user["username"], user["full_name"])
    events = []
    for _ in range(150):
        ctx = okta._get_random_ip_and_context(cfg, "tor_exit_nodes")
        events.append(json.loads(okta._assemble(
            "user.session.start", actor, okta._build_client(ctx, cfg),
            {"result": "SUCCESS", "reason": None},
            security_context=okta._build_security_context(ctx),
            debug_context=okta._build_debug_context("PASSWORD", include_auth_signals=True))))

    check("no _ipCtx on the wire",
          not any("_ipCtx" in json.dumps(e) for e in events))
    check("proxyType == 'tor'",
          all(e["debugContext"]["debugData"].get("proxyType") == "tor" for e in events),
          str(collections.Counter(e["debugContext"]["debugData"].get("proxyType")
                                  for e in events)))
    cats = [(e["request"]["ipChain"][0].get("ipDetails") or {}).get("ipServiceCategories")
            for e in events]
    check("ipServiceCategories present", all(cats))
    check("category is Tor/ANONYMIZER_TOR",
          all(c and c[0]["type"] == "Tor" and c[0]["category"] == "ANONYMIZER_TOR"
              for c in cats))
    check("isAnonymous true", all(c and c[0]["isAnonymous"] is True for c in cats))
    check("isProxy true", all(e["securityContext"]["isProxy"] is True for e in events))
    check("asNumber int or null",
          all(e["securityContext"]["asNumber"] is None
              or isinstance(e["securityContext"]["asNumber"], int) for e in events))
    check("no AS0", not any(e["securityContext"]["asNumber"] == 0 for e in events))
    check("no placeholder ISP",
          not any(e["securityContext"]["isp"] == "TOR Exit Node" for e in events))
    check("zone is the string 'null'", all(e["client"]["zone"] == "null" for e in events))
    check("country never 'Unknown'",
          not any(e["client"]["geographicalContext"]["country"] == "Unknown"
                  for e in events))

    resolved = [e for e in events if e["securityContext"]["asNumber"] is not None]
    check("asNumber populated >=75%", len(resolved) / len(events) >= 0.75,
          f"{len(resolved)}/{len(events)} — tracks the Onionoo join rate above")
    # Onionoo returns as_name for ~99.5% of relays, so a few events legitimately
    # carry an asNumber with a null asOrg.  Assert the rate, not perfection --
    # fabricating an org name would be a fresh divergence.
    org_rate = sum(1 for e in resolved if e["securityContext"]["asOrg"]) / len(resolved)
    check("asOrg populated >=95% of resolved", org_rate >= 0.95, f"{org_rate:.1%}")
    check("asOrg == isp",
          all(e["securityContext"]["asOrg"] == e["securityContext"]["isp"]
              for e in resolved))

    island = outside = geo_null = 0
    for e in events:
        g = e["client"]["geographicalContext"]
        loc = g.get("geolocation")
        if loc is None:
            geo_null += 1
            check("null geolocation implies null country", g["country"] is None,
                  f"country={g['country']}")
            continue
        if abs(loc["lat"]) < 0.01 and abs(loc["lon"]) < 0.01:
            island += 1
        cc = next((k for k, v in okta._COUNTRY_NAMES.items() if v == g["country"]), None)
        centroid = okta._COUNTRY_CENTROIDS.get(cc) if cc else None
        if centroid and haversine((loc["lat"], loc["lon"]), centroid) > 400:
            outside += 1
    check("no Null Island coordinates", island == 0, f"{island} events at (0,0)")
    check("coordinates inside the named country", outside == 0,
          f"{outside} events >400km from centroid")
    print(f"  countries: {collections.Counter(e['client']['geographicalContext']['country'] for e in events).most_common(6)}")
    print(f"  null geolocation (unresolved exit): {geo_null}/{len(events)}")

    # --- degraded paths ------------------------------------------------------
    fb = okta._get_random_ip_and_context(dict(cfg, tor_exit_nodes=[]), "tor_exit_nodes")
    check("empty-list fallback is not the RFC5737 doc address",
          fb["ip"] != "203.0.113.1", fb["ip"])
    check("empty-list fallback keeps anonymizer markers",
          fb["is_proxy"] and fb["proxy_type"] == "tor")
    check("empty-list fallback invents no geo",
          fb["city"] is None and fb["country"] is None)

    unres = okta._get_random_ip_and_context(
        dict(cfg, tor_exit_nodes=[{"ip": "203.0.113.77", "country": "Unknown"}]),
        "tor_exit_nodes")
    check("unresolved node -> null country", unres["country"] is None)
    check("unresolved node -> null geolocation",
          okta._build_client(unres, cfg)["geographicalContext"]["geolocation"] is None)

    # --- benign path must be untouched --------------------------------------
    random.seed(99)
    ben = [okta._get_random_ip_and_context(cfg, "benign_ingress_sources") for _ in range(60)]
    check("benign sources still enriched",
          all(b["city"] and b["isp"] and b["asn"] for b in ben))
    check("benign sources not marked proxy", not any(b.get("proxy_type") for b in ben))
    bev = json.loads(okta._assemble(
        "user.session.start", actor, okta._build_client(ben[0], cfg),
        {"result": "SUCCESS", "reason": None},
        security_context=okta._build_security_context(ben[0]),
        debug_context=okta._build_debug_context("PASSWORD", include_auth_signals=True)))
    check("benign has no proxyType", "proxyType" not in bev["debugContext"]["debugData"])
    check("benign has no ipDetails", "ipDetails" not in bev["request"]["ipChain"][0])
    check("benign isProxy false", bev["securityContext"]["isProxy"] is False)
    check("benign threatSuspected false",
          bev["debugContext"]["debugData"].get("threatSuspected") == "false")
    check("benign has coordinates",
          bev["client"]["geographicalContext"]["geolocation"] is not None)

    # --- anonymizer ctx shared with the other modules ------------------------
    random.seed(7)
    anon = [get_random_anon_ip_ctx(cfg) for _ in range(80)]
    check("anon ctx always flags proxy", all(a["is_proxy"] for a in anon))
    check("anon ctx always types the proxy",
          all(a.get("proxy_type") in ("tor", "vpn") for a in anon))
    tor_anon = [a for a in anon if a["proxy_type"] == "tor"]
    check("anon tor drops the placeholder ISP",
          not any(a["isp"] == "TOR Exit Node" for a in tor_anon))
    check("anon tor never AS0", not any(a["asn"] == 0 for a in tor_anon))

    # --- whole-module sweep --------------------------------------------------
    random.seed(11)
    total = leaked = islands = 0
    for level in ("Realistic", "Elevated", "High", "Extreme"):
        for _ in range(250):
            for line in flatten(okta.generate_log(cfg, threat_level=level)):
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                total += 1
                if "_ipCtx" in line:
                    leaked += 1
                loc = (e.get("client", {}).get("geographicalContext") or {}).get("geolocation")
                if loc and abs(loc.get("lat", 9)) < 0.01 and abs(loc.get("lon", 9)) < 0.01:
                    islands += 1
    check("sweep: no private key leak", leaked == 0, f"{leaked} events")
    check("sweep: no Null Island", islands == 0, f"{islands} events")
    print(f"  module sweep: {total} events")

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
