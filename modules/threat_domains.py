"""Generated threat domains: unlimited cardinality, detection tokens preserved.

The problem is the one domain_corpus.py solves for benign traffic, in the threat
half. `infoblox_threats.malicious_domains` is 25 fixed strings, so on a long run
every one of them accumulates thousands of hits: "malware-distro-site.ru" stops
being a rare never-seen host and becomes part of the furniture. Rarity cannot come
from weighting a 25-entry pool, only from CARDINALITY.

But threat domains cannot simply be randomised, because nine of the literals the
correlation rules match are SUBSTRINGS of these names (five distinct rules, which
overlap heavily -- one rule ORs over several tokens):

    command-control      4 rules      malware-distro       2 rules
    credential-stealer   2 rules      phishing-login       2 rules
    exploit-kit          2 rules      phishing-kit         2 rules
    ransomware-payload   2 rules

Those substrings are a CONTRACT. Randomise the pool without them and the rules go
quiet with no error -- which is exactly what _local_validation/detection_compat_check.py exists
to catch.

So the token leads and everything else varies. Each family owns one mandatory
token, reproduced verbatim, and the generator composes a realistic domain around
it: an optional subdomain, a role word, an optional short discriminator, and a TLD
drawn from the ones abuse actually concentrates in.

    command-control  ->  cdn.command-control-relay.top
                         command-control-node-7f2.icu
                         command-control-gateway.cyou

Two of those tokens did not exist anywhere before this module. The pool shipped
`phish-kit-host.ru` while the rules match "phishing-kit", and
`ransomware-payment-page.biz` while the rules match "ransomware-payload" -- near
misses, each silencing two rules. Generating from the tokens the rules actually use
fixes four detections as a side effect.

Realism note: the discriminator is deliberately short and often absent. A malicious
domain a human registered for a campaign reads like words, not like output of a
DGA -- that is what dga_domain() below is for, and conflating the two would make
every threat domain look algorithmic.
"""

import random
import string

# Second component after the token. These read as infrastructure roles, which is
# how campaign domains are actually named.
_ROLES = ("server", "node", "relay", "gateway", "panel", "hub", "endpoint",
          "host", "portal", "cdn", "api", "svc", "proxy", "edge", "cloud")

# Subdomain prefixes a real resolver sees in front of campaign infrastructure.
_PREFIXES = ("cdn", "api", "static", "update", "telemetry", "secure", "login",
             "www", "mail", "ns1", "panel", "admin", "cfg", "check-in", "gate")

# TLDs weighted towards where domain abuse actually concentrates: cheap new gTLDs
# and a few ccTLDs, not .com. Kept in the same spirit as the curated pool this
# replaces, which already used .ru/.top/.xyz/.icu/.cyou/.buzz/.monster/.cfd.
_TLDS = (
    ("top", 10), ("xyz", 9), ("icu", 7), ("cyou", 6), ("buzz", 6), ("monster", 5),
    ("cfd", 5), ("sbs", 5), ("click", 4), ("link", 4), ("live", 4), ("online", 4),
    ("site", 4), ("shop", 3), ("store", 3), ("website", 3), ("space", 3),
    ("fun", 3), ("press", 2), ("wiki", 2), ("blog", 2), ("uno", 2), ("host", 2),
    ("tech", 2), ("ru", 6), ("su", 2), ("cn", 2), ("tk", 3), ("ml", 2),
)
_TLD_NAMES = tuple(t for t, _ in _TLDS)
_TLD_WEIGHTS = tuple(w for _, w in _TLDS)

# family -> (token that MUST survive verbatim, threat category)
#
# The token is the contract with the detection content; the category feeds vendor
# category fields (Zscaler urlcat, Firepower secIntelCategory). Families marked
# RULE carry a token a correlation rule matches -- never rename those.
_FAMILIES = {
    # --- RULE-BEARING: renaming any token below silences live detections --------
    "c2":                 ("command-control",    "Command and Control"),
    "credential_stealer": ("credential-stealer", "Spyware"),
    "exploit_kit":        ("exploit-kit",        "Exploit"),
    "malware_distro":     ("malware-distro",     "Malware"),
    "phishing_login":     ("phishing-login",     "Phishing"),
    # These two tokens were absent from the whole project: the shipped pool had
    # "phish-kit-host" and "ransomware-payment-page" while the rules match
    # "phishing-kit" and "ransomware-payload". Four rules could never fire.
    "phishing_kit":       ("phishing-kit",       "Phishing"),
    "ransomware":         ("ransomware-payload", "Ransomware"),
    # --- scenario-bearing: log_simulator matches these in its hunt queries -----
    "c2_infra":           ("c2-infra",           "Command and Control"),
    "new_c2":             ("new-c2",             "Command and Control"),
    # --- no rule depends on these; they keep the pool's original variety -------
    "keylogger":          ("keylogger-data",     "Spyware"),
    "trojan":             ("trojan-download",    "Malware"),
    "spam":               ("spam-campaign",      "Spam"),
    "fake_support":       ("fake-tech-support",  "Scam"),
    "driveby":            ("driveby-download",   "Malware"),
    "coinminer":          ("coinminer-pool",     "Cryptomining"),
    "adware":             ("adware-injector",    "Adware"),
    "malvertising":       ("malvertising-redir", "Adware"),
    "fake_av":            ("fake-antivirus",     "Scam"),
    "backdoor":           ("backdoor-listener",  "Malware"),
    "scam_survey":        ("scam-survey",        "Scam"),
    "info_stealer":       ("info-stealer",       "Spyware"),
    "form_grabber":       ("form-grabber",       "Spyware"),
    "browser_locker":     ("browser-locker",     "Scam"),
    "mobile_malware":     ("mobile-malware",     "Malware"),
    "smishing":           ("smishing-link",      "Phishing"),
    "darkweb":            ("darkweb-market",     "Illegal"),
    "cryptojacking":      ("cryptojacking",      "Cryptomining"),
    "fake_invoice":       ("fake-invoice",       "Phishing"),
}

# Tokens no rule matches may still be renamed freely; these may not.
RULE_TOKENS = frozenset((
    "command-control", "credential-stealer", "exploit-kit", "malware-distro",
    "phishing-login", "phishing-kit", "ransomware-payload", "c2-infra", "new-c2",
))

_DISCRIMINATOR_ALPHABET = string.ascii_lowercase + string.digits
# How often a domain carries a short discriminator. Kept below half on purpose:
# always-on makes every campaign domain look machine-generated.
_DISCRIMINATOR_SHARE = 0.40
_PREFIX_SHARE = 0.35


# Every domain this module has handed out, so is_threat() can be exact rather than
# a guess. Reload-safe, like resolver._PINS: a module reload must not forget which
# names are already in flight.
#
# This registry is not decoration. infoblox_dns.generate_dns_pair decides NXDOMAIN
# vs NOERROR by asking whether the domain is malicious, and it used to answer that
# by testing membership of the config pool. Generate domains without telling anyone
# and that test silently returns False, so every C2 lookup starts resolving
# successfully -- quietly breaking both the NXDOMAIN storm rule and the "C2 domain
# resolves NOERROR" rule. A token match covers the families intrinsically; the
# registry is what covers DGA labels, which carry no token by design.
_ISSUED = globals().get("_ISSUED") or set()


def families():
    """Every family name, for callers that want to pick one explicitly."""
    return tuple(_FAMILIES)


def is_threat(domain, config=None):
    """Is this a domain the simulator treats as malicious?

    True for anything this module issued, anything carrying a family token, and --
    so behaviour does not change for callers still reading config -- anything in the
    config threat pools.
    """
    if not domain:
        return False
    if domain in _ISSUED:
        return True
    if any(token in domain for token, _ in _FAMILIES.values()):
        return True
    if config:
        threat_cfg = config.get("infoblox_threats", {}) or {}
        for key in ("malicious_domains", "dga_domains"):
            if domain in (threat_cfg.get(key) or ()):
                return True
    return False


def issued():
    """How many domains have been handed out this process (diagnostics)."""
    return len(_ISSUED)


def token_for(family):
    """The literal substring this family guarantees, or None if unknown."""
    entry = _FAMILIES.get(family)
    return entry[0] if entry else None


def category_for(family):
    """Vendor-facing threat category for this family, or None if unknown."""
    entry = _FAMILIES.get(family)
    return entry[1] if entry else None


def family_of(domain):
    """Which family a generated domain belongs to, by its token. None if no match."""
    for name, (token, _) in _FAMILIES.items():
        if token in domain:
            return name
    return None


def _discriminator():
    """A short campaign-ish suffix: 3 lowercase/digit chars, or a 2-3 digit number."""
    if random.random() < 0.5:
        return "".join(random.choice(_DISCRIMINATOR_ALPHABET) for _ in range(3))
    return str(random.randint(10, 999))


def threat_domain(family=None):
    """One generated threat domain whose family token is present verbatim.

    With no family, one is chosen uniformly. The token always survives, so a
    correlation rule matching it fires regardless of how the rest varies.
    """
    if family is None or family not in _FAMILIES:
        family = random.choice(tuple(_FAMILIES))
    token, _ = _FAMILIES[family]

    label = f"{token}-{random.choice(_ROLES)}"
    if random.random() < _DISCRIMINATOR_SHARE:
        label = f"{label}-{_discriminator()}"
    tld = random.choices(_TLD_NAMES, weights=_TLD_WEIGHTS, k=1)[0]
    domain = f"{label}.{tld}"
    if random.random() < _PREFIX_SHARE:
        domain = f"{random.choice(_PREFIXES)}.{domain}"
    _ISSUED.add(domain)
    return domain


# How much of the threat traffic draws a GENERATED domain rather than a curated
# one from config. Deliberately not 100%.
#
# The curated pool is the head and has a job: an operator hunting by hand needs a
# handful of names they can actually remember and type, and the scenario
# walkthroughs quote them. Generated domains are the tail, which is where the
# cardinality that defeats a "never-seen host" baseline comes from. Same split of
# responsibilities as domain_corpus for benign traffic, in the other direction --
# there the curated pool is the dominant head and the tail is a thin 5% slice;
# here the tail dominates, because a threat domain that recurs is the failure mode.
#
# Override per deployment with infoblox_threats.generated_share in config.json.
_DEFAULT_GENERATED_SHARE = 0.75


def generated_share(config=None):
    """Fraction of threat-domain draws that should be generated."""
    if not config:
        return _DEFAULT_GENERATED_SHARE
    threat_cfg = config.get("infoblox_threats", {}) or {}
    share = threat_cfg.get("generated_share", _DEFAULT_GENERATED_SHARE)
    try:
        return min(1.0, max(0.0, float(share)))
    except (TypeError, ValueError):
        return _DEFAULT_GENERATED_SHARE


def pick(config=None, family=None, pool_key="malicious_domains",
         section="infoblox_threats"):
    """A threat domain: generated most of the time, curated the rest.

    Drop-in for `random.choice(config[section][pool_key])`. Keeps the curated names
    in circulation for manual hunting while making the long run's domain set
    effectively unbounded.

    `section` matters: each vendor keeps its threat pools in its own config block
    (firepower_config.malicious_dns_domains, fortinet_config.dga_beacon_domains),
    so defaulting every caller to infoblox_threats would silently find no pool and
    drop the curated head those modules are supposed to keep.
    """
    pool = ()
    if config:
        pool = (config.get(section, {}) or {}).get(pool_key) or ()
    if pool and random.random() >= generated_share(config):
        return random.choice(pool)
    # DGA pools hold algorithmic labels, which carry no token to preserve.
    return dga_domain() if "dga" in pool_key else threat_domain(family)


def threat_domains(n, family=None):
    """n distinct generated threat domains."""
    out = set()
    guard = 0
    while len(out) < n and guard < n * 40:
        out.add(threat_domain(family))
        guard += 1
    return sorted(out)


# --- DGA -------------------------------------------------------------------
#
# Algorithmic domains are the opposite case: no token to preserve (no rule matches
# a DGA label -- they are detected by NXDOMAIN volume and entropy, which is what
# the Infoblox NXDOMAIN storm rule keys on), so these are free to be pure noise.
# The shipped infoblox_threats.dga_domains pool was 25 fixed strings, which makes a
# "storm" of 232 lookups revisit the same 25 names ~9 times each and leaves an
# entropy or cardinality detector nothing to see.

_DGA_TLDS = ("com", "net", "info", "org", "biz", "top", "xyz", "ru", "cc", "su")
_VOWELS = "aeiou"
_CONSONANTS = "bcdfghjklmnpqrstvwxyz"


def dga_domain(style=None):
    """One algorithmic domain.

    Two styles, because real DGA families split roughly this way and a detector
    tuned on only one of them is not really tested:
      "random"      -- uniform consonant/digit soup (Conficker, Necurs)
      "pronounce"   -- alternating consonant/vowel, longer (Suppobox, Matsnu)
    """
    if style is None:
        style = "pronounce" if random.random() < 0.35 else "random"
    if style == "pronounce":
        label = "".join(random.choice(_CONSONANTS) + random.choice(_VOWELS)
                        for _ in range(random.randint(5, 9)))
    else:
        alphabet = string.ascii_lowercase + string.digits
        label = "".join(random.choice(alphabet)
                        for _ in range(random.randint(10, 18)))
    domain = f"{label}.{random.choice(_DGA_TLDS)}"
    _ISSUED.add(domain)
    return domain


def dga_domains(n, style=None):
    """n distinct algorithmic domains -- enough for a storm without repeats."""
    out = set()
    guard = 0
    while len(out) < n and guard < n * 40:
        out.add(dga_domain(style))
        guard += 1
    return sorted(out)
