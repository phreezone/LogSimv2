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

# Realistic external IP first octets used by stable_vpn_ip
_EXT_FIRST_OCTETS = [11, 23, 31, 45, 46, 52, 63, 72, 91, 104,
                     108, 128, 142, 155, 168, 176, 184, 198, 203, 212]

_USER_HOME_IPS = {}

def stable_vpn_ip(user):
    """Return a deterministic 'home' external IP for a given user.

    Each user gets a primary (80%) and secondary (20%) home IP derived from
    a SHA-256 hash of their username. This lets UEBA platforms build a stable
    baseline of where each user typically logs in from, so that logins from
    novel locations (like Tor) stand out.
    """
    if user not in _USER_HOME_IPS:
        digest = hashlib.sha256(user.encode()).digest()
        o1 = _EXT_FIRST_OCTETS[digest[0] % len(_EXT_FIRST_OCTETS)]
        primary = f"{o1}.{digest[1] % 254 + 1}.{digest[2] % 254 + 1}.{digest[3] % 254 + 1}"
        o1b = _EXT_FIRST_OCTETS[digest[4] % len(_EXT_FIRST_OCTETS)]
        secondary = f"{o1b}.{digest[5] % 254 + 1}.{digest[6] % 254 + 1}.{digest[7] % 254 + 1}"
        _USER_HOME_IPS[user] = [primary, secondary]
    ips = _USER_HOME_IPS[user]
    return ips[0] if random.random() < 0.80 else ips[1]


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
