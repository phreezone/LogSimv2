# modules/session_utils.py
# Shared helpers for user/device session context across all simulator modules.
# Called once at startup by log_simulator.py to build a stable identity map for
# the duration of the run, then passed into every module's generate_log() via
# context={'session_context': session_context}.

import random
import hashlib
from ipaddress import ip_address, ip_network


# ---------------------------------------------------------------------------
# Session builder – called once in log_simulator.py main()
# ---------------------------------------------------------------------------

def build_session_context(config):
    """
    Build a stable user→device→IP mapping for this simulator run.

    For each user in config['user_profiles']:
      - The primary device is ALWAYS activated and gets a randomly assigned IP
        from its configured subnet.  The IP stays fixed for the entire run.
      - Each secondary device (mobile, home, extra laptop …) has a 40% chance
        of being activated.  If activated it also gets a stable IP for the run.
      - A user can be simultaneously active on their primary workstation/laptop
        AND a mobile/home device — that's intentional (phone + desk machine).
      - IPs do NOT jump during a run.  To simulate a different day, restart
        the script and new IPs will be assigned.

    Returns a dict keyed by username, ready to pass to any module.
    """
    session_context = {}

    for username, profile in config.get('user_profiles', {}).items():
        devices = profile.get('devices', [])
        primary_devices   = [d for d in devices if d.get('is_primary')]
        secondary_devices = [d for d in devices if not d.get('is_primary')]

        active_devices = {}

        # Always activate every primary device
        for device in primary_devices:
            ip = _pick_ip(device['subnet'])
            active_devices[device['type']] = {**device, 'ip': ip}

        # Activate secondary devices with type-based affinity weights.
        # Real users predominantly use their primary device; secondary
        # devices are used much less frequently.
        _SECONDARY_ACTIVATION = {
            'laptop': 0.50, 'home': 0.20, 'mobile': 0.15,
        }
        for device in secondary_devices:
            chance = _SECONDARY_ACTIVATION.get(device.get('type'), 0.25)
            if random.random() < chance:
                ip = _pick_ip(device['subnet'])
                # If a device of this type is already active (e.g. two laptops),
                # suffix the type so both are preserved.
                dtype = device['type']
                if dtype in active_devices:
                    dtype = f"{dtype}_{device['device_id']}"
                active_devices[dtype] = {**device, 'ip': ip}

        # Assign a sticky user-agent to each device for the run.
        # Real users keep the same browser/OS fingerprint for days or weeks.
        user_agents = config.get('user_agents', _DEFAULT_USER_AGENTS)
        for dtype, dev in active_devices.items():
            # Deterministic UA from hash of username+device_type so it's stable
            # across restarts with the same config (but still looks random).
            digest = hashlib.sha256(f"{username}:{dtype}".encode()).digest()
            ua_idx = digest[0] % len(user_agents)
            dev['user_agent'] = user_agents[ua_idx]

        # Derive the convenience primary_* shortcuts from the first primary device
        first_primary = primary_devices[0] if primary_devices else None
        primary_type  = first_primary['type'] if first_primary else None
        primary_dev   = active_devices.get(primary_type, {}) if primary_type else {}

        session_context[username] = {
            'username':         username,
            'display_name':     profile.get('display_name', username),
            'department':       profile.get('department', 'Unknown'),
            'role':             profile.get('role', ''),
            'email':            profile.get('email', f"{username}@examplecorp.com"),
            'aws_iam_user':     profile.get('aws_iam_user'),
            'active_devices':   active_devices,
            # Shortcuts – modules can use these directly for the common case
            'primary_ip':       primary_dev.get('ip'),
            'primary_hostname': primary_dev.get('hostname'),
            'primary_os_type':  primary_dev.get('os_type'),
            'primary_os_version': primary_dev.get('os_version'),
            'primary_user_agent': primary_dev.get('user_agent'),
        }

    return session_context


def rand_ip_from_network(network):
    """Pick a random host IP from a network in O(1) memory and time.

    Accepts an ip_network object or a CIDR string.  Never materialises the full
    host list, so it is safe on large subnets (e.g. /8, /11, /13) that would
    otherwise allocate millions of objects per call.

    /31 and /32 prefixes have no conventional host range; the full address space
    is used so the function always returns a valid address.
    """
    if isinstance(network, str):
        network = ip_network(network, strict=False)
    if network.prefixlen >= 31:
        first = int(network.network_address)
        last  = int(network.broadcast_address)
    else:
        first = int(network.network_address) + 1
        last  = int(network.broadcast_address) - 1
    return str(ip_address(random.randint(first, last)))


def _pick_ip(subnet_cidr):
    """Pick a random host IP from a CIDR subnet string."""
    try:
        return rand_ip_from_network(subnet_cidr)
    except Exception:
        return '127.0.0.1'


# ---------------------------------------------------------------------------
# Per-call helpers – called inside each module's generate_log()
# ---------------------------------------------------------------------------

def get_random_user(session_context, preferred_device_type=None):
    """
    Pick a random active user and return a flat info dict.

    preferred_device_type – if supplied and the user has that device type active,
                            that device's IP/hostname will be used instead of primary.

    Returns a dict with keys:
        username, ip, hostname, os_type, os_version, device_type,
        department, email, display_name, aws_iam_user
    Returns None if session_context is empty.
    """
    if not session_context:
        return None
    username = random.choice(list(session_context.keys()))
    return get_user_by_name(session_context, username, preferred_device_type)


def get_user_by_name(session_context, username, preferred_device_type=None):
    """
    Return the info dict for a specific user.
    Follows the same device selection logic as get_random_user().
    Returns None if the user is not in session_context.
    """
    if not session_context or username not in session_context:
        return None

    profile = session_context[username]
    devices = profile.get('active_devices', {})

    device = _select_device(devices, preferred_device_type)
    if device is None:
        # Fallback to primary shortcuts
        return {
            'username':     username,
            'ip':           profile.get('primary_ip'),
            'hostname':     profile.get('primary_hostname'),
            'os_type':      profile.get('primary_os_type'),
            'os_version':   profile.get('primary_os_version'),
            'device_type':  None,
            'department':   profile.get('department'),
            'email':        profile.get('email'),
            'display_name': profile.get('display_name'),
            'aws_iam_user': profile.get('aws_iam_user'),
        }

    return {
        'username':     username,
        'ip':           device.get('ip'),
        'hostname':     device.get('hostname'),
        'os_type':      device.get('os_type'),
        'os_version':   device.get('os_version'),
        'device_type':  device.get('type'),
        'department':   profile.get('department'),
        'email':        profile.get('email'),
        'display_name': profile.get('display_name'),
        'aws_iam_user': profile.get('aws_iam_user'),
    }


def get_all_active_ips(session_context):
    """Return every active IP across all users (useful for server-side lookups)."""
    ips = []
    for profile in session_context.values():
        for device in profile.get('active_devices', {}).values():
            if device.get('ip'):
                ips.append(device['ip'])
    return ips


def get_all_emails(session_context):
    """Return every user's email address."""
    return [p.get('email') for p in session_context.values() if p.get('email')]


def find_user_by_ip(session_context, ip):
    """
    Given an IP address, find which user and device it belongs to.
    Returns (username, profile_dict) or (None, None).
    """
    for username, profile in session_context.items():
        for device in profile.get('active_devices', {}).values():
            if device.get('ip') == ip:
                return username, profile
    return None, None


def get_zscaler_device_info(user_info):
    """
    Convert a user_info dict (from get_random_user) into the device_info dict
    format that zscaler.py uses internally, for backward compatibility.
    """
    if not user_info:
        return {
            'hostname': 'UNKNOWN-HOST',
            'owner': 'unknown_owner',
            'os_type': 'Windows',
            'os_version': '11',
        }
    return {
        'hostname':   user_info.get('hostname', 'UNKNOWN-HOST'),
        'owner':      user_info.get('display_name', user_info.get('username', 'Unknown')),
        'os_type':    user_info.get('os_type', 'Windows'),
        'os_version': user_info.get('os_version', '11'),
    }


# ---------------------------------------------------------------------------
# Anonymizer IP helpers – shared across all modules
# ---------------------------------------------------------------------------

# Fallback VPN provider pool used when config.json has no "vpn_providers" key.
# Keep this in sync with the config.json "vpn_providers" array.
_FALLBACK_VPN_PROVIDERS = [
    {"isp": "Mullvad VPN",             "asn": 39351,  "domain": "mullvad.net",               "country": "NL", "ip_prefix": "45.83",   "ip_range": [220, 223]},
    {"isp": "Mullvad VPN",             "asn": 39351,  "domain": "mullvad.net",               "country": "SE", "ip_prefix": "194.165", "ip_range": [16, 17]},
    {"isp": "NordVPN",                 "asn": 207049, "domain": "nordvpn.com",               "country": "NL", "ip_prefix": "195.206", "ip_range": [105, 106]},
    {"isp": "NordVPN",                 "asn": 207049, "domain": "nordvpn.com",               "country": "DE", "ip_prefix": "37.120",  "ip_range": [210, 215]},
    {"isp": "ProtonVPN AG",            "asn": 62597,  "domain": "protonvpn.com",             "country": "CH", "ip_prefix": "185.159", "ip_range": [157, 158]},
    {"isp": "ExpressVPN",              "asn": 20278,  "domain": "expressvpn.com",            "country": "GB", "ip_prefix": "217.138", "ip_range": [128, 220]},
    {"isp": "Surfshark B.V.",          "asn": 9009,   "domain": "surfshark.com",             "country": "NL", "ip_prefix": "156.146", "ip_range": [60, 80]},
    {"isp": "IPVanish",                "asn": 32748,  "domain": "ipvanish.com",              "country": "US", "ip_prefix": "66.181",  "ip_range": [1, 100]},
    {"isp": "Private Internet Access", "asn": 11260,  "domain": "privateinternetaccess.com", "country": "US", "ip_prefix": "104.244", "ip_range": [72, 79]},
    {"isp": "CyberGhost S.A.",         "asn": 40065,  "domain": "cyberghost.com",            "country": "RO", "ip_prefix": "77.68",   "ip_range": [1, 100]},
    {"isp": "Windscribe",              "asn": 14061,  "domain": "windscribe.com",            "country": "CA", "ip_prefix": "64.44",   "ip_range": [40, 50]},
    {"isp": "Hide.me VPN",             "asn": 9009,   "domain": "hide.me",                   "country": "MY", "ip_prefix": "185.225", "ip_range": [56, 63]},
]


def get_random_vpn_ip_ctx(config):
    """Pick a random commercial VPN provider from config and return an ip_ctx dict.

    Reads 'vpn_providers' from the top-level config; falls back to the built-in
    list if the key is absent.  Each call generates a fresh IP from the provider's
    address range so consecutive calls land on different subnets.

    Returned dict keys: ip, city, state, isp, asn, domain, country, is_proxy.
    """
    providers = config.get("vpn_providers") or _FALLBACK_VPN_PROVIDERS
    p = random.choice(providers)
    lo, hi = p["ip_range"][0], p["ip_range"][1]
    ip = f"{p['ip_prefix']}.{random.randint(lo, hi)}.{random.randint(1, 254)}"
    return {
        "ip":       ip,
        "city":     None,
        "state":    None,
        "isp":      p["isp"],
        "asn":      p["asn"],
        "domain":   p["domain"],
        "country":  p["country"],
        "is_proxy": True,
    }


def get_random_anon_ip_ctx(config):
    """Return an anonymizer ip_ctx drawn from the live Tor list or a commercial VPN.

    Mix: 70% commercial VPN (typically MEDIUM-priority XSIAM alert),
         30% live Tor exit node (HIGH-priority XSIAM alert).

    The wide provider pool ensures XSIAM UEBA sees a different subnet on
    each event rather than normalising repeated connections from a /13 block.
    """
    tor_nodes = config.get("tor_exit_nodes", [])
    if tor_nodes and random.random() < 0.30:
        node = random.choice(tor_nodes)
        if isinstance(node, dict):
            ip      = node.get("ip", "185.220.101.1")
            country = node.get("country", "Unknown")
        else:
            ip, country = str(node), "Unknown"
        return {
            "ip":       ip,
            "city":     None,
            "state":    None,
            "isp":      "TOR Exit Node",
            "asn":      0,
            "domain":   None,
            "country":  country,
            "is_proxy": True,
        }
    return get_random_vpn_ip_ctx(config)


# ---------------------------------------------------------------------------
# UEBA behavioral helpers – shared across all firewall modules
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Geographic source-IP policy
# ---------------------------------------------------------------------------
# DO NOT "FIX" THIS BACK to a wide random first-octet pool.
#
# The XSIAM analytic "First successful VPN access from a country in organization"
# is a FIRST-SEEN, ORG-SCOPED detector: it fires only when a successful VPN login
# arrives from a country that has NOT been seen anywhere in the org for 30 days.
#
# Measured over a 30-day window:
#   * xdm.source.location.country across cisco_asa_raw, check_point_vpn_1_firewall_1_raw,
#     fortinet_fortigate_raw, cisco_firepower_raw, zscaler_nssfwlog_raw, okta_sso_raw
#     = 210 DISTINCT COUNTRIES — essentially every country on Earth. Nothing could
#     ever be novel, so the analytic was permanently silent (and stayed silent).
#   * ASA AnyConnect session-start (113039) events alone = 70 distinct countries.
#   * check_point_vpn_1_firewall_1_raw alone = 168 distinct countries.
#
# The old stable_vpn_ip() below picked `random host inside one of 20 different /8
# blocks` (11, 23, 31, 45, 46, 52, 63, 72, 91, 104, 108, 128, 142, 155, 168, 176,
# 184, 198, 203, 212).  A /8 spans dozens of countries, so this ONE function —
# which is the benign VPN-login source IP for Check Point, FortiGate, Firepower
# and Zscaler — was on its own scattering VPN logins across most of the planet.
#
# XSIAM geo-resolves the ACTUAL IP and IGNORES any "country" label we attach, so
# the only safe construction is precise, individually PROBED CIDRs. Every range
# referenced here was emitted to the tenant as an ASA 113039 event and its
# xdm.source.location.country read back before being committed to config.json.
#
# The policy is SCARCITY + ROTATION, with three mutually exclusive country sets:
#   config['benign_ingress_sources']   5 countries (US/GB/DE/CA/AU) — ambient VPN
#   config['external_traffic_sources'] 35 countries — non-VPN attacker/internet noise
#   config['vpn_novel_country_pool']   70 countries — RESERVE, touched ONLY by the
#                                      deliberate "first access from a new country"
#                                      event, one per day => 70-day recurrence,
#                                      comfortably past the detector's 30-day window.
# ---------------------------------------------------------------------------

# Fallback home ranges, used when no config is threaded through to the caller.
# These are the XSIAM-verified /24s that also populate config['benign_ingress_sources'].
_VPN_HOME_RANGES = [
    "68.86.113.0/24",    # Comcast, United States
    "71.163.116.0/24",   # Verizon FiOS, United States
    "99.36.12.0/24",     # AT&T, United States
    "97.85.44.0/24",     # Charter Spectrum, United States
    "70.176.220.0/24",   # Cox, United States
    "81.152.44.0/24",    # BT, United Kingdom
    "90.207.60.0/24",    # Sky Broadband, United Kingdom
    "80.130.44.0/24",    # Deutsche Telekom, Germany
    "92.208.44.0/24",    # Vodafone Kabel, Germany
    "64.231.44.0/24",    # Rogers, Canada
    "70.24.140.0/24",    # Bell Canada, Canada
    "1.126.44.0/24",     # Telstra, Australia
    "49.176.44.0/24",    # Optus, Australia
]

_USER_HOME_IPS = {}


def _home_ranges(config=None):
    """Home-country CIDRs for ambient VPN logins (config first, constant fallback)."""
    if config:
        ranges = [s.get("ip_range") for s in config.get("benign_ingress_sources", [])
                  if s.get("ip_range")]
        if ranges:
            return ranges
    return _VPN_HOME_RANGES


def stable_vpn_ip(user, config=None):
    """Return a deterministic 'home' external IP for a given user.

    Each user gets a primary (80%) and secondary (20%) home IP derived from a
    SHA-256 hash of their username, so UEBA sees a stable per-user baseline.

    Both IPs are drawn from the SMALL, PROBED home-country pool (US/GB/DE/CA/AU)
    — see the geographic source-IP policy note above.  Selecting a wider pool
    here re-saturates the org-wide country baseline and silences the
    "First successful VPN access from a country in organization" analytic.
    """
    if user not in _USER_HOME_IPS:
        digest = hashlib.sha256(user.encode()).digest()
        ranges = _home_ranges(config)
        def _pick(a, b, c):
            net = ip_network(ranges[digest[a] % len(ranges)], strict=False)
            base = int(net.network_address)
            size = net.num_addresses
            # keep off .0 / broadcast
            off = (digest[b] * 256 + digest[c]) % max(size - 2, 1) + 1
            return str(ip_address(base + off))
        _USER_HOME_IPS[user] = [_pick(0, 1, 2), _pick(4, 5, 6)]
    ips = _USER_HOME_IPS[user]
    return ips[0] if random.random() < 0.80 else ips[1]


# ---------------------------------------------------------------------------
# Reserve-country VPN source IPs — drives the "First successful VPN access from
# a country in organization" analytic.
# ---------------------------------------------------------------------------

def _novel_pool(config):
    return [e for e in (config or {}).get("vpn_novel_country_pool", []) if e.get("ip_range")]


def novel_country_vpn_ip(config, offset=0):
    """Return (ip, country_code, country_name, isp_name) from the RESERVE country pool.

    country_name is the country as XSIAM ACTUALLY RESOLVED IT when the range was
    probed (config key "resolved_country").  Vendor formats that carry a country
    STRING in the log line (FortiGate FTNTFGTsrccountry, Zscaler geo field) must be
    labelled with it, so the text field and the IP geo-lookup agree no matter which
    of the two the vendor's XIF maps to xdm.source.location.country.

    Rotation is keyed on the day number so that every VPN-capable module picks
    the SAME country on the same day.  That is deliberate: the analytic is
    org-scoped, so if ASA, Check Point, FortiGate, Firepower and Zscaler each
    picked a different country on the same day they would burn five reserve
    countries per day (a 14-day cycle) instead of one (a 70-day cycle), and the
    30-day novelty window would never be satisfied.  One country per day, all
    sources agreeing, gives a 70-day recurrence per country.

    `offset` shifts the rotation; the caller passes a non-zero value only when it
    deliberately wants a second, different country (e.g. impossible travel).

    Returns (None, None, None, None) when the pool is missing from config.
    """
    pool = _novel_pool(config)
    if not pool:
        return None, None, None, None
    import time as _time
    day = int(_time.time() // 86400)
    entry = pool[(day + offset) % len(pool)]
    try:
        ip = rand_ip_from_network(ip_network(entry["ip_range"], strict=False))
    except Exception:
        ip = entry["ip_range"].split("/")[0]
    return ip, entry.get("country"), entry.get("resolved_country"), entry.get("name")


# ---------------------------------------------------------------------------
# Tor exit nodes for VPN logins — country-filtered.
# ---------------------------------------------------------------------------

def tor_vpn_ips(config):
    """Live Tor exit-node IPs restricted to the genuine Tor-heavy countries.

    DO NOT "FIX" THIS BACK to `config['tor_exit_nodes']` unfiltered.
    Probing the full live exit-node list through the tenant
    resolved them to 55 DISTINCT COUNTRIES, with a long random tail (Seychelles,
    Belize, Nicaragua, Panama, Peru …) that rotates daily as nodes churn.  Left
    unfiltered, vpn_tor_login alone keeps burning reserve countries and silences
    the "First successful VPN access from a country" analytic.

    Real Tor exit capacity is heavily concentrated: the same probe put 75% of all
    exit nodes in just United States / Germany / Netherlands / France / Romania.
    config['tor_vpn_prefix_allowlist'] holds the 182 /16 prefixes that resolved
    EXCLUSIVELY to those five countries — 930 of the 1,380 live nodes (67%), so
    the pool stays large and every IP is still a genuine, currently-live exit node.
    That keeps the HIGH-severity "A Successful VPN connection from TOR" analytic
    firing while capping Tor's geographic footprint at five countries, none of
    which appear in vpn_novel_country_pool.

    Falls back to the unfiltered list if the allowlist matches nothing — breaking
    the Tor analytic is worse than briefly widening the country set.
    """
    nodes = config.get("tor_exit_nodes", []) or []
    ips = [n.get("ip") if isinstance(n, dict) else str(n) for n in nodes]
    ips = [i for i in ips if i]
    allow = set(config.get("tor_vpn_prefix_allowlist", []) or [])
    if not allow:
        return ips
    filtered = [i for i in ips if ".".join(i.split(".")[:2]) in allow]
    return filtered or ips


def tor_vpn_ip(config, default=None):
    """Single country-filtered Tor exit node IP (see tor_vpn_ips)."""
    ips = tor_vpn_ips(config)
    return random.choice(ips) if ips else default


# ---------------------------------------------------------------------------
# Ambient external ("rest of the internet") source IPs
# ---------------------------------------------------------------------------
# DO NOT "FIX" THIS BACK to `random.choice(first_octets) + 3 random octets`.
#
# Every module used to carry its own _random_external_ip() picking a random host
# inside one of 14 /8 blocks (45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193,
# 194, 212, 213).  A /8 spans dozens of countries, so scanners, C2 callbacks and
# generic inbound noise alone reached several hundred countries and were a
# primary driver of the 210-country org baseline.
#
# These 35 PROBED /24s keep external traffic looking like it comes from all over
# the world (35 countries, all six populated continents) while guaranteeing it
# can never touch a country in config['vpn_novel_country_pool'].  The three sets
# are disjoint by construction — that disjointness is the whole mechanism.
_EXTERNAL_TRAFFIC_RANGES = [
    "213.33.20.0/24",        # A1 Telekom Austria, Austria
    "187.10.20.0/24",        # Vivo Sao Paulo, Brazil
    "95.42.20.0/24",         # Vivacom Sofia, Bulgaria
    "61.135.20.0/24",        # China Unicom Beijing, China
    "88.100.20.0/24",        # O2 Czech Prague, Czechia
    "80.62.20.0/24",         # TDC Copenhagen, Denmark
    "91.153.20.0/24",        # Elisa Helsinki, Finland
    "90.10.20.0/24",         # Orange France Paris, France
    "79.130.20.0/24",        # OTE Athens, Greece
    "219.76.20.0/24",        # PCCW Hong Kong, Hong Kong
    "81.182.20.0/24",        # Magyar Telekom Budapest, Hungary
    "49.36.20.0/24",         # Reliance Jio Mumbai, India
    "114.5.20.0/24",         # Telkomsel Jakarta, Indonesia
    "79.178.20.0/24",        # Bezeq Tel Aviv, Israel
    "79.20.20.0/24",         # Telecom Italia Rome, Italy
    "210.150.20.0/24",       # NTT Tokyo, Japan
    "175.138.20.0/24",       # TM Kuala Lumpur, Malaysia
    "189.130.20.0/24",       # Telmex Mexico City, Mexico
    "84.26.20.0/24",         # Ziggo Amsterdam, Netherlands
    "84.210.20.0/24",        # Telenor Oslo, Norway
    "83.5.20.0/24",          # Orange Polska Warsaw, Poland
    "85.242.20.0/24",        # MEO Lisbon, Portugal
    "79.114.20.0/24",        # RCS RDS Bucharest, Romania
    "116.87.20.0/24",        # Singtel Singapore, Singapore
    "41.134.20.0/24",        # Telkom SA Johannesburg, South Africa
    "175.200.20.0/24",       # KT Seoul, South Korea
    "88.2.20.0/24",          # Telefonica Madrid, Spain
    "78.69.20.0/24",         # Telia Stockholm, Sweden
    "85.2.20.0/24",          # Swisscom Zurich, Switzerland
    "61.217.20.0/24",        # HiNet Taipei, Taiwan
    "171.98.20.0/24",        # TrueOnline Bangkok, Thailand
    "88.226.20.0/24",        # Turk Telekom Istanbul, Turkiye
    "46.211.20.0/24",        # Kyivstar Kyiv, Ukraine
    "94.200.20.0/24",        # Etisalat Dubai, United Arab Emirates
    "113.162.20.0/24",       # VNPT Hanoi, Vietnam
]


def random_external_ip(config=None):
    """A public, non-RFC-1918 IP from the ambient external-traffic country pool.

    Shared replacement for every module's private _random_external_ip().
    See _EXTERNAL_TRAFFIC_RANGES above for why this is a curated list and not a
    random host inside a /8.
    """
    ranges = None
    if config:
        ranges = [s.get("ip_range") for s in config.get("external_traffic_sources", [])
                  if s.get("ip_range")]
    if not ranges:
        ranges = _EXTERNAL_TRAFFIC_RANGES
    try:
        return rand_ip_from_network(ip_network(random.choice(ranges), strict=False))
    except Exception:
        return "203.0.113.%d" % random.randint(1, 254)


# Corporate mail relay IPs — small fixed pool that every module's benign email
# generator draws from.  Real enterprises route all outbound email through 2-3
# relays; a user connecting to dozens of distinct SMTP servers is exactly the
# spam-bot signal XSIAM detects.  Threat smtp_spray generators deliberately
# connect to 30-50 distinct IPs to create contrast against this tight baseline.
CORPORATE_MAIL_SERVERS = [
    "74.125.200.27",    # Google Workspace SMTP relay
    "40.107.22.100",    # Microsoft 365 SMTP relay
    "207.46.163.218",   # Microsoft Exchange Online Protection relay
]


_USER_MAIL_SERVERS = {}

def stable_mail_servers(user):
    """Return 2-3 deterministic corporate mail relay IPs for a given user.

    Each user is assigned a primary mail server (70%) and 1-2 alternates (30%)
    from CORPORATE_MAIL_SERVERS, derived from a SHA-256 hash of their username.
    This keeps the per-user unique-server count to 2-3 over any time window,
    preventing XSIAM from flagging normal email as spam-bot traffic.
    """
    if user not in _USER_MAIL_SERVERS:
        digest = hashlib.sha256(user.encode()).digest()
        n = len(CORPORATE_MAIL_SERVERS)
        primary_idx = digest[8] % n
        # 1-2 alternates (always includes primary, plus 1 or 2 others)
        alt_count = 1 + (digest[9] % 2)   # 1 or 2 alternates
        servers = [CORPORATE_MAIL_SERVERS[primary_idx]]
        for i in range(1, alt_count + 1):
            idx = (primary_idx + i) % n
            servers.append(CORPORATE_MAIL_SERVERS[idx])
        _USER_MAIL_SERVERS[user] = servers
    servers = _USER_MAIL_SERVERS[user]
    # Primary 70%, alternates share remaining 30%
    if random.random() < 0.70 or len(servers) == 1:
        return servers[0]
    return random.choice(servers[1:])


_USER_DEST_WEIGHTS = {}

def weighted_destination(user, destinations):
    """Pick a destination with per-user Zipf-like affinity.

    70% of the time, destinations are chosen via a user-specific weighting
    (so alice tends to visit the same top sites). 30% of the time, a uniform
    random pick adds variety. This creates the browsing-pattern baselines
    that UEBA platforms need for 'Rare X' / 'Uncommon X' detections.
    """
    if not destinations:
        return {} if isinstance(destinations, dict) else destinations
    n = len(destinations)
    cache_key = (user, n)
    if cache_key not in _USER_DEST_WEIGHTS:
        digest = hashlib.sha256(user.encode()).digest()
        offset = digest[0] % n
        weights = []
        for i in range(n):
            pos = (i - offset) % n
            weights.append(1.0 / (1 + pos))
        _USER_DEST_WEIGHTS[cache_key] = weights
    if random.random() < 0.70:
        return random.choices(destinations, weights=_USER_DEST_WEIGHTS[cache_key], k=1)[0]
    return random.choice(destinations)


# Per-user byte volume bands: deterministic daily-transfer ranges so UEBA
# can build a "user X typically transfers Y MB/day" baseline.
_USER_BYTE_BANDS = {}

def get_byte_volume_band(user):
    """Return a (low, high) byte-count tuple for this user's typical daily web traffic.

    The band is deterministic per-user: some users are heavy (200-500 MB),
    some medium (50-200 MB), some light (10-50 MB). Within a single session
    each event should draw from this band to build a consistent volume profile.
    """
    if user not in _USER_BYTE_BANDS:
        digest = hashlib.sha256(user.encode()).digest()
        # 3 tiers: light (40%), medium (40%), heavy (20%)
        tier = digest[0] % 10
        if tier < 4:        # light
            lo, hi = 5_000, 50_000
        elif tier < 8:      # medium
            lo, hi = 20_000, 200_000
        else:               # heavy
            lo, hi = 100_000, 500_000
        _USER_BYTE_BANDS[user] = (lo, hi)
    return _USER_BYTE_BANDS[user]


# DNS domain affinity: each user resolves the same ~50 domains repeatedly.
_DEFAULT_BENIGN_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "office365.com",
    "slack.com", "zoom.us", "salesforce.com", "aws.amazon.com",
    "teams.microsoft.com", "linkedin.com", "stackoverflow.com",
    "jira.atlassian.com", "confluence.atlassian.com", "drive.google.com",
    "outlook.office.com", "portal.azure.com", "app.box.com",
    "dropbox.com", "youtube.com", "wikipedia.org", "cloudflare.com",
    "fastly.net", "akamai.com", "cdn.jsdelivr.net", "npmjs.com",
    "pypi.org", "docker.io", "grafana.com", "datadog.com", "splunk.com",
]

_USER_DOMAIN_WEIGHTS = {}

def weighted_dns_domain(user, domains=None):
    """Pick a DNS domain with per-user affinity.

    Each user has a stable top-5 most-queried domains (60% of queries),
    a mid-tier of ~10 domains (25%), and the rest as tail (15%).
    This creates the domain-frequency baselines UEBA needs for
    'Rare Domain' / 'New Domain' detections.
    """
    if domains is None:
        domains = _DEFAULT_BENIGN_DOMAINS
    n = len(domains)
    cache_key = (user, "dns", n)
    if cache_key not in _USER_DOMAIN_WEIGHTS:
        digest = hashlib.sha256(f"{user}:dns".encode()).digest()
        offset = digest[0] % n
        weights = []
        for i in range(n):
            pos = (i - offset) % n
            weights.append(1.0 / (1 + pos) ** 1.5)  # steeper than destination affinity
        _USER_DOMAIN_WEIGHTS[cache_key] = weights
    if random.random() < 0.85:
        return random.choices(domains, weights=_USER_DOMAIN_WEIGHTS[cache_key], k=1)[0]
    return random.choice(domains)


def reset_caches():
    """Clear all per-user memoization caches for a hermetic start.

    These module-level dicts memoize per-user picks (home IPs, mail servers,
    destination/byte/domain weightings) the first time each user is seen, so
    subsequent picks stay stable within a run. Deterministic Training Mode calls
    this before a seeded run so the very first pick for each user is reproducible
    instead of depending on whatever an earlier run left cached.
    """
    _USER_HOME_IPS.clear()
    _USER_MAIL_SERVERS.clear()
    _USER_DEST_WEIGHTS.clear()
    _USER_BYTE_BANDS.clear()
    _USER_DOMAIN_WEIGHTS.clear()


def get_users_by_department(session_context):
    """Return users grouped by department for the Bad User picker.

    Returns {department: [{username, display_name, department, has_aws, has_gcp}, ...]}
    sorted by department name, users sorted by display_name within each group.
    """
    groups = {}
    for username, profile in (session_context or {}).items():
        dept = profile.get('department', 'Unknown')
        entry = {
            'username':     username,
            'display_name': profile.get('display_name', username),
            'department':   dept,
            'has_aws':      bool(profile.get('aws_iam_user')),
            'primary_os':   profile.get('primary_os_type', ''),
        }
        groups.setdefault(dept, []).append(entry)
    # Sort departments alphabetically, users by display_name within each
    return {dept: sorted(users, key=lambda u: u['display_name'])
            for dept, users in sorted(groups.items())}


def get_user_agent(session_context, username, device_type=None):
    """Return the sticky user-agent for a user's device.

    Falls back to a deterministic pick from the default pool if no
    session_context is available.
    """
    if session_context and username in session_context:
        devices = session_context[username].get('active_devices', {})
        if device_type and device_type in devices:
            ua = devices[device_type].get('user_agent')
            if ua:
                return ua
        # Try primary
        ua = session_context[username].get('primary_user_agent')
        if ua:
            return ua
    # Deterministic fallback
    digest = hashlib.sha256(f"{username}:ua".encode()).digest()
    return _DEFAULT_USER_AGENTS[digest[0] % len(_DEFAULT_USER_AGENTS)]


def pick_ephemeral_port():
    """Pick a random ephemeral source port (49152-65535)."""
    return random.randint(49152, 65535)


# Default user-agent pool (used when config has no 'user_agents' key)
_DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _select_device(devices, preferred_type):
    """Pick the best available device from the active_devices dict."""
    if not devices:
        return None
    if preferred_type and preferred_type in devices:
        return devices[preferred_type]
    # Preference order for network-visible devices
    for dtype in ('workstation', 'laptop', 'home', 'mobile'):
        if dtype in devices:
            return devices[dtype]
    # Fall back to whatever is first
    return next(iter(devices.values()))
