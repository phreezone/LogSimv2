"""Composed browser user-agents: realistic shapes, realistic spread.

Measured before this module: 31 distinct user-agent strings across 64,541 events, a
2,082x reuse. `session_utils.get_user_agent` is already correct in making the value
STICKY per device -- a device's UA really is stable -- so the limit was purely the
size of the pool it drew from: about 13 browser strings in `config.json`.

## How much cardinality is actually realistic

Less than it first appears, and it is worth being precise so this does not
over-generate. Chrome's UA Reduction (2022-23) freezes the minor, build and patch to
zero on desktop, so a modern desktop Chrome sends

    Chrome/124.0.0.0            not  Chrome/124.0.6367.60

Firefox likewise sends only the major (`Firefox/124.0`), and Safari a short
`Version/17.3`. So desktop cardinality is bounded by

    family x major version in use x platform

which for a managed fleet is perhaps 40-80 values, not thousands. The genuine long
tail is MOBILE: Chrome on Android still carries the full build, and the device model
is in the string, so a fleet with a normal spread of Samsung/Pixel/OnePlus handsets
contributes most of the variety.

Target here is therefore a few hundred distinct values, with the shape of a real
fleet: most devices on a current major, a thinning tail on older ones (patch lag is
real, and it is what makes an "outdated browser" detection work at all).

## A correctness fix found while auditing the old pool

Three entries used `Windows NT 11.0`. That string does not exist: Windows 11 reports
`Windows NT 10.0` in its UA, and Microsoft deliberately did not bump it. Any analyst
who greps for it finds nothing in the real world, so it was a tell. Only
`Windows NT 10.0` is emitted here.

Scanner and bot agents are deliberately absent. Those are not device fingerprints --
`session_utils._is_enduser_ua` exists to keep them from becoming one -- and the
generators that model scanners set their own agent.
"""

import random

# --- desktop platforms ------------------------------------------------------
#
# Windows 11 reports NT 10.0, same as Windows 10 -- there is no NT 11.0.
_WIN = "Windows NT 10.0; Win64; x64"
# macOS in a Chrome/Safari UA freezes at 10_15_7 for Chrome, while Safari reports the
# real version. Both forms are real; which one appears depends on the browser.
_MAC_CHROME = "Macintosh; Intel Mac OS X 10_15_7"
# Safari's version and the macOS it runs on are NOT independent: Sequoia (15) ships
# Safari 18, Sonoma (14) ships 17, Ventura (13) ships 16. Drawing them separately
# produced "Version/17.3 ... Mac OS X 15_3", a pairing that cannot exist and is
# exactly the kind of detail that tells an analyst the log is synthetic.
_MAC_SAFARI_PAIRS = (
    ("Macintosh; Intel Mac OS X 15_3", (18, 3)),
    ("Macintosh; Intel Mac OS X 15_1", (18, 1)),
    ("Macintosh; Intel Mac OS X 14_6", (17, 6)),
    ("Macintosh; Intel Mac OS X 14_5", (17, 5)),
    ("Macintosh; Intel Mac OS X 14_4", (17, 4)),
    ("Macintosh; Intel Mac OS X 14_3", (17, 3)),
    ("Macintosh; Intel Mac OS X 13_6", (16, 6)),
)
_LINUX = "X11; Linux x86_64"

# Chromium majors currently plausible in a fleet, weighted so most devices sit on a
# recent one and a thinning tail lags behind.
_CHROME_MAJORS = ((133, 26), (132, 20), (131, 14), (130, 9), (129, 6),
                  (128, 4), (127, 3), (126, 2), (124, 2), (118, 1))
_FIREFOX_MAJORS = ((135, 24), (134, 18), (133, 12), (132, 8), (128, 6), (118, 2))
# Safari's Version/ token and the macOS string move together in reality.

_DESKTOP_PLATFORM_WEIGHTS = ((_WIN, 68), (_MAC_CHROME, 24), (_LINUX, 8))


def _weighted(pairs, rng=random):
    return rng.choices([p[0] for p in pairs], weights=[p[1] for p in pairs], k=1)[0]


def seeded(seed):
    """A private RNG for a caller that needs a REPRODUCIBLE agent.

    session_utils assigns each device a sticky UA derived from a hash of
    username+device_type, so the fingerprint survives a restart. If it did not, every
    restart would look like a new browser on every device and "new user agent for this
    user" would fire across the estate. Passing a seeded RNG keeps that guarantee
    while drawing from the full composed space instead of a fixed list.
    """
    return random.Random(seed)


def _chrome_major(rng=random):
    return _weighted(_CHROME_MAJORS, rng)


def chrome_desktop(rng=random):
    """Desktop Chrome. Reduced version per Chrome UA Reduction."""
    return (f"Mozilla/5.0 ({_weighted(_DESKTOP_PLATFORM_WEIGHTS, rng)}) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_chrome_major(rng)}.0.0.0 Safari/537.36")


def edge_desktop(rng=random):
    """Desktop Edge. Edge trails Chrome's major by 0-1 and appends its own token."""
    major = _chrome_major(rng)
    edge = major - rng.choice((0, 0, 1))
    platform = _weighted(((_WIN, 88), (_MAC_CHROME, 12)), rng)   # Edge is mostly Windows
    return (f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 Safari/537.36 Edg/{edge}.0.0.0")


def firefox_desktop(rng=random):
    """Desktop Firefox. rv: tracks the major, except for the long-lived rv:109 ESR."""
    major = _weighted(_FIREFOX_MAJORS, rng)
    rv = 109 if rng.random() < 0.18 else major      # rv:109 stuck around for ESR
    platform = _weighted(((_WIN, 62), ("Macintosh; Intel Mac OS X 14.4", 20),
                          (_LINUX, 18)), rng)
    return (f"Mozilla/5.0 ({platform}; rv:{rv}.0) Gecko/20100101 "
            f"Firefox/{major}.0")


def safari_desktop(rng=random):
    """Desktop Safari on macOS, with the OS and Safari version kept consistent."""
    platform, (major, minor) = rng.choice(_MAC_SAFARI_PAIRS)
    return (f"Mozilla/5.0 ({platform}) "
            f"AppleWebKit/605.1.15 (KHTML, like Gecko) "
            f"Version/{major}.{minor} Safari/605.1.15")


# --- mobile -----------------------------------------------------------------
#
# Where the real tail lives: Chrome on Android still carries the full build number,
# and the handset model is in the string. A normal corporate fleet spans a lot of
# models, which is most of this module's cardinality.
_ANDROID_MODELS = (
    # Samsung
    "SM-S938U", "SM-S931B", "SM-S928B", "SM-S921U", "SM-S918B", "SM-A546B",
    "SM-A356B", "SM-G998B", "SM-F956B", "SM-X710",
    # Pixel
    "Pixel 9 Pro", "Pixel 9", "Pixel 8 Pro", "Pixel 8a", "Pixel 7", "Pixel 6a",
    # OnePlus / Oppo / Xiaomi / Motorola
    "CPH2557", "CPH2581", "PJD110", "2312DRA50C", "23127PN0CC",
    "motorola edge 50 pro", "moto g84 5G",
    # Nokia / Sony / Honor
    "Nokia G60 5G", "XQ-DQ54", "FNE-NX9", "LLY-LX1",
)
_ANDROID_VERSIONS = ((15, 34), (14, 30), (13, 18), (12, 10), (11, 5), (10, 3))
_IOS_VERSIONS = ("18_3", "18_2", "18_1", "17_6", "17_5", "17_4", "16_7")
# Full Chromium build numbers, paired with the major they belong to.
_CHROME_BUILDS = {133: ("6943.98", "6943.121", "6943.49"),
                  132: ("6834.163", "6834.122", "6834.83"),
                  131: ("6778.200", "6778.135", "6778.81"),
                  130: ("6723.107", "6723.86"),
                  129: ("6668.101", "6668.70"),
                  128: ("6613.146", "6613.88")}


def _chrome_build(major, rng=random):
    return rng.choice(_CHROME_BUILDS.get(major, ("6943.98",)))


def chrome_android(rng=random):
    major = _weighted(_CHROME_MAJORS[:6], rng)          # phones update briskly
    android = _weighted(_ANDROID_VERSIONS, rng)
    return (f"Mozilla/5.0 (Linux; Android {android}; {rng.choice(_ANDROID_MODELS)}) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.{_chrome_build(major, rng)} Mobile Safari/537.36")


def safari_ios(rng=random):
    ios = rng.choice(_IOS_VERSIONS)
    version = ios.split("_")[0] + "." + ios.split("_")[1]
    return (f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios} like Mac OS X) "
            f"AppleWebKit/605.1.15 (KHTML, like Gecko) "
            f"Version/{version} Mobile/15E148 Safari/604.1")


def chrome_ios(rng=random):
    """Chrome on iOS is CriOS and still rides the WebKit engine."""
    ios = rng.choice(_IOS_VERSIONS)
    major = _weighted(_CHROME_MAJORS[:5], rng)
    return (f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios} like Mac OS X) "
            f"AppleWebKit/605.1.15 (KHTML, like Gecko) "
            f"CriOS/{major}.0.{_chrome_build(major, rng)} Mobile/15E148 Safari/604.1")


def ipad_safari(rng=random):
    ios = rng.choice(_IOS_VERSIONS)
    version = ios.split("_")[0] + "." + ios.split("_")[1]
    return (f"Mozilla/5.0 (iPad; CPU OS {ios} like Mac OS X) "
            f"AppleWebKit/605.1.15 (KHTML, like Gecko) "
            f"Version/{version} Mobile/15E148 Safari/604.1")


# Desktop browser share, roughly enterprise-shaped: Chrome and Edge dominate, Edge
# higher than consumer numbers because it ships with Windows and is often policy-set.
_DESKTOP_MIX = ((chrome_desktop, 46), (edge_desktop, 30),
                (firefox_desktop, 12), (safari_desktop, 12))
_MOBILE_MIX = ((chrome_android, 48), (safari_ios, 34),
               (chrome_ios, 10), (ipad_safari, 8))


def desktop_agent(rng=random):
    """One desktop browser UA."""
    return _weighted(_DESKTOP_MIX, rng)(rng)


def mobile_agent(rng=random):
    """One mobile browser UA."""
    return _weighted(_MOBILE_MIX, rng)(rng)


def agent_for(device_type=None, rng=random):
    """A browser UA appropriate to the device type.

    device_type is the session-context kind ("workstation", "laptop", "mobile",
    "tablet", ...); anything phone-shaped gets a mobile agent.
    """
    kind = (device_type or "").lower().split("_")[0]
    if kind in ("mobile", "phone", "tablet", "ipad", "iphone", "android"):
        return mobile_agent(rng)
    return desktop_agent(rng)


def agent_pool(n=240, device_type=None):
    """`n` distinct UAs, for callers that want a pool rather than a single draw.

    Used to widen the sticky-fingerprint pool that session_utils assigns from, which
    is why it returns DISTINCT values: duplicates there would waste pool slots.
    """
    out, guard = set(), 0
    while len(out) < n and guard < n * 60:
        if device_type:
            out.add(agent_for(device_type))
        else:
            # With no device type, span BOTH form factors. Desktop saturates around
            # 136 values because of UA reduction, so a desktop-only pool silently
            # caps there; the mobile side is what carries the tail.
            out.add(mobile_agent() if random.random() < 0.5 else desktop_agent())
        guard += 1
    return sorted(out)
