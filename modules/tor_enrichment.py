"""Geo/ASN enrichment for the live Tor exit node list.

`check.torproject.org/torbulkexitlist` returns bare IPs and nothing else, so
every Tor-sourced event used to carry country="Unknown" and a null ISP/ASN.
That is not what a real IdP reports: Okta (and every other GeoIP-backed vendor)
resolves a Tor exit through a MaxMind-class database, and exit nodes are
ordinary hosting addresses that resolve perfectly well to a country and an AS.
An "Unknown" country is a LogSim artefact, not vendor behaviour -- and it fed
_city_geolocation() a country it could not place, which is how Tor events ended
up at (0.0, 0.0).

The Tor Project's own Onionoo service publishes country + AS for every running
relay, so the enrichment comes from the same authority as the exit list itself:
no extra vendor, no API key, no GeoIP database to ship or keep current.

Measured against the live services (2026-09-09):
    torbulkexitlist   1,340 IPs                       0.5 s
    onionoo details   3,173 relays / 519 KB gzipped   0.8 s
    join rate         1,300 / 1,340 = 97.0%
    country 100%   as 100%   as_name 99.5%

Onionoo exposes `city_name` and `region_name` in its schema but returns them
for 0% of relays, so city/state stay null -- which is itself accurate, since
Okta emits null for those whenever its provider cannot place the address.
"""

import gzip
import json
import urllib.request

# Only running exits, and only the fields we consume -- the unfiltered document
# is several MB, this one is ~519 KB.
_ONIONOO_URL = (
    "https://onionoo.torproject.org/details"
    "?flag=Exit&running=true"
    "&fields=or_addresses,exit_addresses,country,as,as_name"
)

_UA = "LogSim/2.0 (+tor-exit-enrichment)"


def _get(url, timeout):
    req = urllib.request.Request(
        url, headers={"Accept-Encoding": "gzip", "User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
    return raw


def fetch_onionoo_exit_map(timeout=30):
    """Return {ip: {country, asn, isp}} for every running Tor exit relay.

    Returns an empty dict on any failure -- enrichment is best-effort and must
    never take down the exit-list fetch it decorates.
    """
    try:
        doc = json.loads(_get(_ONIONOO_URL, timeout).decode("utf-8"))
    except Exception:
        return {}

    out = {}
    for relay in doc.get("relays", []):
        # `as` is "AS197540"; Okta's securityContext.asNumber is an integer.
        asn = None
        as_field = relay.get("as")
        if isinstance(as_field, str) and as_field.upper().startswith("AS"):
            try:
                asn = int(as_field[2:])
            except ValueError:
                asn = None

        # Onionoo gives a lowercase ISO-3166-1 alpha-2; the module country tables
        # are keyed uppercase.  Deliberately NOT using Onionoo's `country_name`:
        # it says "United States of America" where Okta says "United States", so
        # the ISO code is joined against the existing per-module country table.
        # Onionoo uses "??" when it cannot place a relay.  Passing that through
        # would put the literal string "??" in geographicalContext.country, which
        # no GeoIP-backed vendor would ever emit -- treat it as unknown so the
        # geolocation guard renders a null coordinate instead.
        cc = (relay.get("country") or "").upper()
        if len(cc) != 2 or not cc.isalpha():
            cc = None
        info = {
            "country": cc,
            "asn":     asn,
            "isp":     relay.get("as_name") or None,
        }

        # An exit relay is reachable on its OR address and exits from its
        # exit_addresses; the bulk list can name either, so index both.
        addrs = list(relay.get("exit_addresses") or [])
        for or_addr in (relay.get("or_addresses") or []):
            # "1.2.3.4:9001" or "[2001:db8::1]:9001"
            addrs.append(or_addr.rsplit(":", 1)[0].strip("[]"))
        for addr in addrs:
            if addr:
                out[addr] = info
    return out


def enrich_tor_nodes(nodes, timeout=30, onionoo_map=None):
    """Attach country/asn/isp and the anonymizer markers to bulk-list nodes.

    `nodes` is the [{"ip": ...}, ...] list from torbulkexitlist.  Returns
    (enriched_nodes, stats) where stats reports the join rate so the caller can
    surface it in a health check.  Nodes Onionoo cannot resolve keep country
    None rather than a fabricated one -- a null country is honest and the
    geolocation guard renders it as a null coordinate instead of (0, 0).
    """
    if onionoo_map is None:
        onionoo_map = fetch_onionoo_exit_map(timeout=timeout)

    resolved = 0
    enriched = []
    for node in nodes:
        node = dict(node) if isinstance(node, dict) else {"ip": str(node)}
        info = onionoo_map.get(node.get("ip"))
        if info:
            resolved += 1
            # Normalise here too: callers may supply their own map.
            cc = (info.get("country") or "")
            node["country"] = cc.upper() if len(cc) == 2 and cc.isalpha() else None
            node["asn"]     = info["asn"]
            node["isp"]     = info["isp"]
        else:
            # Never leave the literal "Unknown" behind -- _country_name() would
            # echo it straight into geographicalContext.country as a country.
            if not node.get("country") or node.get("country") == "Unknown":
                node["country"] = None
            node.setdefault("asn", None)
            node.setdefault("isp", None)
        # Markers every anonymizer-aware generator keys on.  Okta reports Tor via
        # debugContext.debugData.proxyType and ipChain[].ipDetails, not via
        # securityContext alone, so carry the type as well as the flag.
        node["is_proxy"]   = True
        node["proxy_type"] = "tor"
        node["domain"]     = None
        enriched.append(node)

    stats = {
        "total":      len(enriched),
        "resolved":   resolved,
        "onionoo":    len(onionoo_map),
        "join_rate":  round(100.0 * resolved / len(enriched), 1) if enriched else 0.0,
    }
    return enriched, stats
