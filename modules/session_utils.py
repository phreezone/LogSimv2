# modules/session_utils.py
# Shared helpers for user/device session context across all simulator modules.
# Called once at startup by log_simulator.py to build a stable identity map for
# the duration of the run, then passed into every module's generate_log() via
# context={'session_context': session_context}.

import random
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

        # Randomly activate secondary devices (40% each)
        for device in secondary_devices:
            if random.random() < 0.40:
                ip = _pick_ip(device['subnet'])
                # If a device of this type is already active (e.g. two laptops),
                # suffix the type so both are preserved.
                dtype = device['type']
                if dtype in active_devices:
                    dtype = f"{dtype}_{device['device_id']}"
                active_devices[dtype] = {**device, 'ip': ip}

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
