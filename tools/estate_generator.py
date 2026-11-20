#!/usr/bin/env python3
"""Expand the LogSim estate in config.json from the 501-user base to a 5,000-person company.

Deterministic (fixed seed), and it keeps every existing user's identity stable. Each of the
501 base users keeps their username, devices and device subnets, so their sticky device IPs
are unchanged, and keeps their SID wherever it was already unique. Two exceptions, by
decision on 2026-11-19:
  * the three usernames containing an apostrophe are renamed (j.o'brien -> j.obrien), and
  * every role is re-titled to a realistic ladder (one CISO, one Controller, ...).

What it writes, all in config.json:
  user_profiles        4,499 new users (no phones), plus office, start_date, sid_rid and
                       gcp_iam_user on everyone
  sites / domain_controllers / domain_controller_hosts / server_roles / internal_servers /
  file_servers / database_servers / vmware_esxi_config hosts+vms / management_plane devices
  okta_config          about 250 SaaS apps and a department entitlement map
  aws_config           users_and_roles lists every profile IAM user
  service_accounts     wider app/db name pools

Name sources. Neither file is committed; fetch both into a directory and pass --names-dir:
  ssa_1980_2010_male.txt / ssa_1980_2010_female.txt
      Comma-separated first names, ranked by total births 1980-2010, summed from SSA's
      "Popular Names by Birth Year" top-1000 tables (https://www.ssa.gov/oact/babynames/).
  Names_2010Census.csv
      2010 Census surname file (www2.census.gov/topics/genealogy/2010surnames/names.zip).

Usage:
  python tools/estate_generator.py --names-dir <dir> [--config config.json] [--report out.md]
"""
import argparse
import collections
import csv
import datetime as _dt
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import sys

SEED = "logsim-estate-5000-v1"
BASE_USER_COUNT = 501
MARKER_KEY = "_estate_generator"
DOMAIN = "examplecorp.com"

# ── headcount ────────────────────────────────────────────────────────────────────────────
# 5,000-person SaaS company. Security ~1.3%, IT ~1:29, HR ~1:36 are in line with published
# staffing ratios for software companies of this size.
TARGETS = {
    "Engineering": 1400, "Sales": 750, "Support": 500, "CustomerSuccess": 450,
    "Operations": 350, "Marketing": 330, "Product": 230, "DevOps": 175, "IT": 175,
    "Finance": 175, "DataScience": 150, "HR": 140, "Security": 65, "Procurement": 60,
    "Legal": 50,
}

# Role ladders: (title, headcount). Titles that modules key on are kept verbatim:
#   azure_common/_ADMIN_ROLE_NAMES, azuread_audit ADMIN/HELPDESK/LIFECYCLE_ROLES,
#   o365_* ADMIN_ROLES, azure_estate CLOUD_OPS/NET_OPS/SEC_OPS/DATA_OPS.
LADDERS = {
    "Engineering": [
        ("VP of Engineering", 1), ("Director of Engineering", 8),
        ("Senior Engineering Manager", 20), ("Engineering Manager", 120),
        ("Principal Engineer", 25), ("Staff Software Engineer", 70),
        ("Senior Software Engineer", 370), ("Software Engineer", 400),
        ("Associate Software Engineer", 110), ("Frontend Engineer", 96),
        ("Mobile Engineer", 45), ("QA Engineer", 50), ("Software Engineer in Test", 30),
        ("Technical Program Manager", 30), ("Software Engineering Intern", 25),
    ],
    "Sales": [
        ("VP of Sales", 1), ("Regional Sales Director", 8), ("Sales Manager", 60),
        ("Enterprise Account Executive", 90), ("Senior Account Executive", 110),
        ("Account Executive", 170), ("Sales Development Representative", 120),
        ("Business Development Representative", 60), ("Sales Engineer", 80),
        ("Senior Sales Engineer", 20), ("Sales Operations Analyst", 20),
        ("Sales Operations Manager", 5), ("Sales Enablement Manager", 6),
    ],
    "Support": [
        ("Director of Support", 1), ("Support Manager", 25), ("Support Team Lead", 35),
        ("Senior Support Engineer", 60), ("Support Engineer", 140),
        ("Technical Support Specialist", 120), ("Support Analyst", 60),
        ("Escalation Engineer", 20), ("Technical Writer", 20),
        ("Knowledge Base Specialist", 10), ("Support Operations Analyst", 9),
    ],
    "CustomerSuccess": [
        ("VP of Customer Success", 1), ("Customer Success Director", 5),
        ("Customer Success Team Manager", 30), ("Senior Customer Success Manager", 70),
        ("Customer Success Manager", 160), ("Technical Account Manager", 60),
        ("Renewal Manager", 40), ("Onboarding Specialist", 40),
        ("Implementation Specialist", 30), ("Customer Success Operations Analyst", 14),
    ],
    "Operations": [
        ("VP of Operations", 1), ("Operations Director", 4), ("Operations Manager", 30),
        ("Supply Chain Manager", 10), ("Senior Operations Analyst", 30),
        ("Operations Analyst", 80), ("Supply Chain Analyst", 40),
        ("Process Improvement Manager", 8), ("Process Engineer", 25),
        ("Business Operations Specialist", 50), ("Operations Coordinator", 50),
        ("Facilities Manager", 10), ("Facilities Coordinator", 12),
    ],
    "Marketing": [
        ("Chief Marketing Officer", 1), ("Marketing Director", 6), ("Marketing Manager", 30),
        ("Product Marketing Manager", 35), ("Demand Generation Manager", 25),
        ("Content Strategist", 30), ("Content Writer", 25), ("SEO Specialist", 12),
        ("Digital Marketing Specialist", 35), ("Marketing Analyst", 25),
        ("Growth Analyst", 15), ("Brand Designer", 20), ("Social Media Manager", 10),
        ("Events Manager", 12), ("Marketing Operations Specialist", 20),
        ("Marketing Coordinator", 23), ("Marketing Intern", 6),
    ],
    "Product": [
        ("VP of Product", 1), ("Product Director", 6), ("Group Product Manager", 15),
        ("Principal Product Manager", 8), ("Senior Product Manager", 50),
        ("Product Manager", 75), ("Associate Product Manager", 20),
        ("Product Analyst", 20), ("Product Designer", 20), ("UX Researcher", 10),
        ("Product Operations Manager", 5),
    ],
    "DevOps": [
        ("Director of Infrastructure", 1), ("Infrastructure Lead", 8), ("Cloud Architect", 8),
        ("Senior DevOps Engineer", 30), ("DevOps Engineer", 40),
        ("Site Reliability Engineer", 35), ("Platform Engineer", 25),
        ("Infrastructure Engineer", 15), ("Cloud Engineer", 13),
    ],
    "IT": [
        ("Chief Information Officer", 1), ("IT Director", 1), ("IT Manager", 7),
        ("IT Administrator", 10), ("Systems Engineer", 12), ("Systems Administrator", 12),
        ("Network Engineer", 14), ("Cloud Administrator", 8), ("Endpoint Engineer", 10),
        ("Identity and Access Engineer", 6), ("Help Desk Analyst", 35),
        ("Desktop Support Technician", 30), ("IT Support Specialist", 15),
        ("IT Asset Analyst", 6), ("IT Business Analyst", 8),
    ],
    "Security": [
        ("CISO", 1), ("Director of Security Operations", 1), ("Director of GRC", 1),
        ("Security Manager", 4), ("SOC Analyst", 12), ("Senior Security Analyst", 6),
        ("Security Analyst", 6), ("Incident Responder", 5), ("Threat Hunter", 3),
        ("Threat Intelligence Analyst", 3), ("Security Engineer", 9),
        ("Senior Security Engineer", 4), ("Application Security Engineer", 2),
        ("Security Architect", 3), ("GRC Analyst", 5),
    ],
    "Finance": [
        ("CFO", 1), ("VP of Finance", 1), ("Controller", 1), ("Assistant Controller", 2),
        ("Finance Director", 3), ("FP&A Manager", 4), ("Finance Manager", 8),
        ("Senior Financial Analyst", 15), ("Financial Analyst", 25), ("FP&A Analyst", 15),
        ("Senior Accountant", 20), ("Staff Accountant", 25),
        ("Accounts Payable Specialist", 15), ("Accounts Receivable Specialist", 12),
        ("Payroll Specialist", 8), ("Tax Manager", 2), ("Tax Analyst", 5),
        ("Treasury Analyst", 4), ("Internal Auditor", 4), ("Billing Specialist", 5),
    ],
    "DataScience": [
        ("Director of Data Science", 1), ("Data Science Manager", 8),
        ("Principal Data Scientist", 3), ("Senior Data Scientist", 18),
        ("Data Scientist", 30), ("Machine Learning Engineer", 22), ("Data Engineer", 30),
        ("Analytics Engineer", 12), ("Data Analyst", 18), ("Research Scientist", 5),
        ("Data Science Intern", 3),
    ],
    "HR": [
        ("Chief People Officer", 1), ("HR Director", 2), ("HR Manager", 6),
        ("HR Business Partner", 18), ("Talent Acquisition Manager", 3),
        ("Senior Recruiter", 12), ("Recruiter", 25), ("Recruiting Coordinator", 12),
        ("Compensation Analyst", 6), ("Benefits Specialist", 8), ("HRIS Analyst", 8),
        ("HR Generalist", 18), ("HR Coordinator", 12),
        ("Learning and Development Specialist", 6), ("People Operations Specialist", 3),
    ],
    "Procurement": [
        ("Procurement Director", 1), ("Procurement Manager", 4),
        ("Senior Procurement Analyst", 6), ("Procurement Analyst", 10),
        ("Strategic Sourcing Analyst", 8), ("Purchasing Specialist", 12),
        ("Vendor Manager", 8), ("Contract Manager", 5), ("Procurement Coordinator", 6),
    ],
    "Legal": [
        ("General Counsel", 1), ("Deputy General Counsel", 1), ("Legal Director", 2),
        ("Senior Corporate Counsel", 6), ("Corporate Counsel", 10), ("Privacy Counsel", 3),
        ("Paralegal", 10), ("Contracts Manager", 6), ("Contract Specialist", 6),
        ("Legal Operations Analyst", 3), ("Compliance Manager", 2),
    ],
}

# Abbreviations in the old titles, expanded before matching old -> new titles.
_ABBREV = {"swe": "software engineer", "ae": "account executive", "pm": "product manager",
           "sre": "site reliability engineer", "bdr": "business development representative",
           "cs": "customer success", "ml": "machine learning", "ap": "accounts payable",
           "ar": "accounts receivable", "hr": "hr", "it": "it"}

# Per-department AWS share, measured on the 501 base users (kept as instructed).
# GCP share: none in the base estate; added 2026-11-19, mainly IT and DevOps.
GCP_RATE = {"DevOps": 0.60, "IT": 0.35, "Security": 0.15, "DataScience": 0.10,
            "Engineering": 0.02}
GCP_PREFERRED = {  # titles that get GCP first inside each department
    "IT": ("Cloud Administrator", "Systems Engineer", "IT Administrator", "Network Engineer",
           "Systems Administrator", "Identity and Access Engineer", "IT Director", "IT Manager"),
    "Security": ("Security Engineer", "Senior Security Engineer", "Security Architect",
                 "Application Security Engineer", "Incident Responder", "Threat Hunter"),
    "DataScience": ("Data Engineer", "Machine Learning Engineer", "Analytics Engineer",
                    "Data Science Manager", "Principal Data Scientist"),
    "Engineering": ("Principal Engineer", "Staff Software Engineer", "Engineering Manager"),
}
_TECH_WORDS = ("engineer", "architect", "administrator", "developer", "data", "cloud",
               "analyst", "operations", "sre", "devops", "scientist", "technical")

# ── sites ────────────────────────────────────────────────────────────────────────────────
# Same order as modules/azure_common.OFFICES. Weight = share of NEW hires per site.
SITES = [
    # city, code, weight, server /24
    ("Columbus", "CMH", 25, "10.0.20.0/24"),
    ("Austin", "AUS", 12, "10.0.21.0/24"),
    ("Seattle", "SEA", 10, "10.0.22.0/24"),
    ("New York", "NYC", 12, "10.0.23.0/24"),
    ("Chicago", "CHI", 9, "10.0.24.0/24"),
    ("Fremont", "FRE", 8, "10.0.25.0/24"),
    ("Atlanta", "ATL", 7, "10.0.26.0/24"),
    ("Dublin", "DUB", 5, "10.0.27.0/24"),
    ("London", "LON", 7, "10.0.28.0/24"),
    ("Toronto", "TOR", 5, "10.0.29.0/24"),
]

DEPT_BLOCK_BASE = {  # third octet of each department's original /24 in 192.168.0.0/16
    "Sales": 10, "Engineering": 20, "Marketing": 30, "HR": 40, "Finance": 50, "IT": 60,
    "Operations": 70, "Legal": 80, "Security": 90, "DevOps": 100, "DataScience": 110,
    "CustomerSuccess": 120, "Product": 130, "Support": 140, "Procurement": 150,
}
DEVICES_PER_SUBNET = 200        # of 235 sticky-assignable addresses (.20-.254)
# /24s inside the department blocks that modules already use for something else:
# zscaler._RDP_RARE_SERVER_NETS are "quiet" RDP targets that must stay unpopulated.
RESERVED_SUBNETS = {"192.168.12.0/24", "192.168.13.0/24", "192.168.14.0/24", "192.168.15.0/24"}
# New home/VPN devices: 172.20.0.0/21. The base pool 172.16.100.0/24 sits inside the
# internal_networks entry 172.16.0.0/16, which modules draw random "other internal host"
# addresses from; a new pool there would put ~1,500 real devices in that random draw.
HOME_BLOCK = "172.20.{}.0/24"
HOME_BLOCK_SIZE = 8
ONBOARDING_DAYS = 90

# ── profanity screen ─────────────────────────────────────────────────────────────────────
# Substrings checked against the separator-free username, display name and email local part.
_BLOCK_SUBSTR = ("shit", "fuck", "cunt", "cock", "dick", "porn", "slut", "whore", "twat",
                 "piss", "nazi", "nigg", "fag", "wank", "tits", "boob", "penis", "vagin",
                 "pussy", "bitch", "bastard", "rapist", "dildo", "jizz", "spunk", "crap",
                 "damn", "kkk", "hitler", "satan", "nude", "sexy", "horny", "butt")
# Prefixes checked against the surname / first name alone.
_BLOCK_PREFIX = ("anal", "anus", "ass", "cum", "sex", "hore", "rape", "kill", "dyke", "fart",
                 "poop", "turd", "suck", "lick", "hell", "drug", "gay", "kock", "kok", "phuc",
                 "fuk", "dong", "wang", "weiner", "wiener", "schlong", "hooker", "pimp")
_BLOCK_EXACT = {"baby", "infant", "unknown", "male", "female", "boy", "girl", "god", "jesus",
                "christ", "satan", "lucifer", "sin", "nazi", "hitler", "ho", "hoe", "slaughter",
                "coffin", "grave", "death", "killer", "butcher", "hore", "pee", "poo",
                "rich", "money", "cash", "dollar", "sex", "gay", "fear"}
# Irish O'- surnames lose the apostrophe in the Census file (OBRIEN); they read badly
# without it, so they are left out rather than respelled.
_O_PREFIX_RE = re.compile(r"^O(BRIEN|CONN|NEAL|NEIL|NEILL|DONN|HAR|KEEF|MALLEY|ROURKE|"
                          r"SULLIVAN|LEARY|GRADY|QUINN|SHEA|BANNON|KANE|DONOGHUE|TOOLE|MEAR|"
                          r"MARA|CALLAGHAN|HALLORAN|FARRELL|FLAHERTY|BRYANT|DANIEL|HAIR|"
                          r"GORMAN|LOUGHLIN|BOYLE|DWYER|REILLY|HAGAN|KELLY|CONNELL|NEAL|DAY|"
                          r"BERRY|BRYAN|CAIN|DONNELL|FALLON|HARE|HERN|KEEFE|LEARY|NEILL|ROUKE)$")


def _rng(*parts):
    return random.Random(hashlib.sha256("|".join((SEED,) + tuple(map(str, parts))).encode()).digest())


def _sha_int(s, nbytes=None):
    d = hashlib.sha256(str(s).encode()).digest()
    return int.from_bytes(d[:nbytes] if nbytes else d, "big")


def _clean(s):
    return re.sub(r"[^a-z]", "", s.lower())


def is_vulgar(*strings):
    for s in strings:
        c = _clean(s)
        if not c:
            continue
        if c in _BLOCK_EXACT or any(b in c for b in _BLOCK_SUBSTR):
            return True
    return False


def _name_part_blocked(name):
    n = name.lower()
    return (n in _BLOCK_EXACT or n.startswith(_BLOCK_PREFIX)
            or any(b in n for b in _BLOCK_SUBSTR))


def _cap_surname(raw):
    s = raw.capitalize()
    if raw.startswith("MC") and len(raw) > 3:
        s = "Mc" + raw[2:].capitalize()
    return s


# ── config text surgery ──────────────────────────────────────────────────────────────────
# config.json has mixed line endings and hand formatting; only the sections this tool owns
# are rewritten, in place, so the diff stays reviewable.
def _top_level_span(text, key):
    m = re.search(r'(\r?\n)  "' + re.escape(key) + r'": ', text)
    if not m:
        return None
    start = m.end()
    _, end = json.JSONDecoder().raw_decode(text, start)
    return m.start(), start, end, m.group(1)


def _dump(value, eol):
    s = json.dumps(value, indent=2, ensure_ascii=False)
    s = s.replace("\n", "\n  ")              # nest one level under the top object
    return s.replace("\n", eol)


def set_top_level(text, key, value, after=None):
    span = _top_level_span(text, key)
    if span:
        _, vstart, vend, eol = span
        return text[:vstart] + _dump(value, eol) + text[vend:]
    # insert a new key after `after` (or before the closing brace)
    if after and _top_level_span(text, after):
        _, _, aend, eol = _top_level_span(text, after)
        return text[:aend] + "," + eol + f'  "{key}": ' + _dump(value, eol) + text[aend:]
    raise KeyError(key)


# ── names ────────────────────────────────────────────────────────────────────────────────
def load_first_names(names_dir):
    lists = {}
    for sex, fn in (("M", "ssa_1980_2010_male.txt"), ("F", "ssa_1980_2010_female.txt")):
        with open(os.path.join(names_dir, fn), encoding="utf-8") as fh:
            lists[sex] = [n.strip() for n in fh.read().split(",") if n.strip()]
    rank = {s: {n: i for i, n in enumerate(l)} for s, l in lists.items()}
    out = {}
    for sex, other in (("M", "F"), ("F", "M")):
        keep = []
        for n in lists[sex]:
            # a name in both lists stays only with the sex it ranks higher for
            if n in rank[other] and rank[other][n] < rank[sex][n]:
                continue
            if not re.fullmatch(r"[A-Za-z]+", n) or _name_part_blocked(n):
                continue
            keep.append(n)
        out[sex] = keep
    return out


def load_surnames(names_dir, limit=25000):
    rows = []
    with open(os.path.join(names_dir, "Names_2010Census.csv"), encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            n = r["name"]
            if not re.fullmatch(r"[A-Z]{2,}", n) or n == "ALL":
                continue
            if _O_PREFIX_RE.match(n) or _name_part_blocked(n):
                continue
            rows.append((_cap_surname(n), int(r["count"])))
            if len(rows) >= limit:
                break
    return rows


class NamePicker:
    """70% of first names from the combined 1980-2010 top 500 of that sex, 30% from ranks
    501-1000; popularity-weighted but flattened (1/sqrt(rank)) and capped per name.
    Surnames: ~12% from the 150 most common (repeatable, capped), the rest each used once."""

    FIRST_CAP = 10

    def __init__(self, first, surnames, existing_profiles, rng):
        self.rng = rng
        self.first = first
        self.first_used = collections.Counter(p["display_name"].split()[0]
                                              for p in existing_profiles.values())
        self.sur_used = collections.Counter(p["display_name"].split()[-1]
                                            for p in existing_profiles.values())
        self.full_used = {p["display_name"].lower() for p in existing_profiles.values()}
        self.common = surnames[:150]
        self.unique_pool = [(n, c) for n, c in surnames[150:]]
        self.rng.shuffle(self.unique_pool)
        # weight within the unique tier: sqrt(count), sampled without replacement via keys
        keyed = [(self.rng.random() ** (1.0 / math.sqrt(c)), n) for n, c in self.unique_pool]
        keyed.sort(reverse=True)
        self.unique_order = [n for _, n in keyed if n not in self.sur_used]
        self.unique_idx = 0

    def _first(self, sex):
        names = self.first[sex]
        top, rest = names[:500], names[500:1000]
        if rest and self.rng.random() >= 0.70:
            tier, offset = rest, 500
        else:
            tier, offset = top, 0
        weights = [1.0 / math.sqrt(i + 1 + offset) for i in range(len(tier))]
        for _ in range(50):
            n = self.rng.choices(tier, weights=weights, k=1)[0]
            if self.first_used[n] < self.FIRST_CAP:
                return n
        return n

    def _surname(self):
        if self.rng.random() < 0.12:
            for _ in range(50):
                idx = min(int(self.rng.expovariate(1 / 30.0)), len(self.common) - 1)
                n = self.common[idx][0]
                cap = 8 if idx < 25 else 3
                if self.sur_used[n] < cap:
                    return n
        n = self.unique_order[self.unique_idx]
        self.unique_idx += 1
        return n

    def next(self, sex):
        for _ in range(200):
            f, l = self._first(sex), self._surname()
            if f"{f} {l}".lower() in self.full_used:
                continue
            if is_vulgar(f + l, f[0] + l, f"{f}.{l}"):
                continue
            self.first_used[f] += 1
            self.sur_used[l] += 1
            self.full_used.add(f"{f} {l}".lower())
            return f, l
        raise RuntimeError("name space exhausted")


# ── roles ────────────────────────────────────────────────────────────────────────────────
# Old title -> the new title it should land on while that title has room.
PREFERRED = {
    "Controller": "Controller", "Intern SWE": "Software Engineering Intern",
    "Staff Engineer": "Staff Software Engineer", "Full Stack Engineer": "Software Engineer",
    "Senior PM": "Senior Product Manager", "Regional Manager": "Sales Manager",
    "Talent Acquisition Specialist": "Recruiter", "HR Specialist": "HR Generalist",
    "ML Researcher": "Research Scientist", "Purchasing Manager": "Procurement Manager",
    "Customer Support Lead": "Support Team Lead", "Tier 2 Support": "Senior Support Engineer",
    "Tier 2 Support Engineer": "Senior Support Engineer", "IT Analyst": "IT Business Analyst",
    "Help Desk": "Help Desk Analyst", "Help Desk Technician": "Desktop Support Technician",
}
# "... Manager" titles that are individual contributors, not people managers.
_IC_MANAGER = ("product manager", "program manager", "account manager", "success manager",
               "renewal manager", "vendor manager", "contract manager", "contracts manager",
               "marketing manager", "media manager", "events manager", "generation manager",
               "enablement manager", "operations manager")


def _level(title):
    t = title.lower()
    if re.search(r"\b(ciso|cfo|cio|chief|vp\b|vp of|general counsel)", t) or t.startswith("head of"):
        return 0
    if "director" in t or t in ("controller", "deputy general counsel"):
        return 1
    if t.startswith("group ") or (re.search(r"\b(manager|lead|deputy)\b", t)
                                  and not any(p in t for p in _IC_MANAGER)):
        return 2
    if re.search(r"\b(principal|staff)\b", t):
        return 3
    if re.search(r"\b(senior|sr)\b", t):
        return 4
    if re.search(r"\b(intern|associate|coordinator|tier 1|junior)\b", t):
        return 6
    return 5


def _tokens(title):
    words = re.findall(r"[a-z&]+", title.lower())
    out = []
    for w in words:
        out.extend(_ABBREV.get(w, w).split())
    stop = {"senior", "sr", "staff", "principal", "of", "and", "the", "director", "manager",
            "lead", "head", "vp", "associate", "intern", "junior", "chief"}
    return {w for w in out if w not in stop}


def assign_roles(profiles, rng):
    """Re-title the base users onto the ladders, then return the open slots per department."""
    slots = {d: collections.Counter(dict(l)) for d, l in LADDERS.items()}
    for d, l in LADDERS.items():
        assert sum(c for _, c in l) == TARGETS[d], (d, sum(c for _, c in l))
    changes = collections.Counter()
    by_dept = collections.defaultdict(list)
    for u in sorted(profiles):
        by_dept[profiles[u]["department"]].append(u)
    for dept, users in by_dept.items():
        # most senior old titles claim slots first
        users.sort(key=lambda u: (_level(profiles[u]["role"]), u))
        for u in users:
            old = profiles[u]["role"]
            lv, tok = _level(old), _tokens(old)
            best, best_score = None, None
            for title, left in slots[dept].items():
                if left <= 0:
                    continue
                tl = _level(title)
                overlap = len(tok & _tokens(title))
                score = (overlap * 3 - abs(tl - lv) * 2 - (5 if tl < lv else 0)
                         + (10 if title in (old, PREFERRED.get(old)) else 0))
                # ties go to the roomier (more generic) title, then alphabetically
                key = (score, left, [-ord(c) for c in title])
                if best_score is None or key > best_score:
                    best, best_score = title, key
            slots[dept][best] -= 1
            if best != old:
                changes[(old, best)] += 1
            profiles[u]["role"] = best
    return slots, changes


# ── main build ───────────────────────────────────────────────────────────────────────────
def legacy_rid(username):
    """modules/windows_events._stable_user_sid before 2026-11-19: 1100 + sha1 % 8900."""
    h = hashlib.sha1(username.encode()).digest()
    return 1100 + (int.from_bytes(h[:4], "big") % 8_900)


def legacy_office(department):
    """modules/azure_common.office_for before 2026-11-19 (site by department hash)."""
    return SITES[int(hashlib.sha256(f"site:{department}".encode()).hexdigest(), 16) % len(SITES)][0]


def build(config, names_dir, anchor):
    profiles = config["user_profiles"]
    if config.get(MARKER_KEY) or len(profiles) != BASE_USER_COUNT:
        raise SystemExit(f"expected the {BASE_USER_COUNT}-user base config without "
                         f"'{MARKER_KEY}'; got {len(profiles)} users")
    report = collections.OrderedDict()

    # 1. renames (apostrophes)
    renames = {}
    for u in sorted(profiles):
        if "'" in u:
            renames[u] = u.replace("'", "")
    for old, new in renames.items():
        assert new not in profiles, new
        p = profiles.pop(old)
        p["display_name"] = p["display_name"].replace("O'B", "Ob").replace("'", "")
        p["email"] = p["email"].replace("'", "")
        if p.get("aws_iam_user"):
            p["aws_iam_user"] = p["aws_iam_user"].replace("O'B", "Ob").replace("'", "")
        for dv in p["devices"]:
            dv["device_id"] = dv["device_id"].replace("'", "")
            dv["hostname"] = dv["hostname"].replace("'", "")
        profiles[new] = p
    report["renamed"] = renames

    # 1b. the base has one hostname on two people's phones (LHANSEN-IPHONE12): the later
    # owner gets the numeric suffix the other phone names already use (CDOYLE2-GALAXYS24).
    seen_hosts, host_fixes = set(), []
    for u in sorted(profiles):
        for dv in profiles[u]["devices"]:
            h = dv["hostname"].upper()
            if h in seen_hosts:
                stem, _, model = h.partition("-")
                k = 2
                while f"{stem}{k}-{model}" in seen_hosts:
                    k += 1
                dv["hostname"] = dv["device_id"] = f"{stem}{k}-{model}"
                host_fixes.append((u, h, dv["hostname"]))
                h = dv["hostname"]
            seen_hosts.add(h)
    report["hostname_fixes"] = host_fixes

    # 2. offices for the base users = what office_for() computed for them
    for u, p in profiles.items():
        p["office"] = legacy_office(p["department"])

    # 3. re-title roles
    rng = _rng("roles")
    open_slots, role_changes = assign_roles(profiles, rng)
    report["role_changes"] = role_changes

    # 4. device model measured on the base
    base_by_dept = collections.defaultdict(list)
    for u, p in profiles.items():
        base_by_dept[p["department"]].append(p)
    dept_prefix, dept_primary_type, dept_primary_os = {}, {}, {}
    dept_home_rate, dept_second_rate, dept_home_os, dept_second_os = {}, {}, {}, {}
    os_versions = collections.defaultdict(collections.Counter)
    counters = collections.Counter()
    for dept, ps in base_by_dept.items():
        prim = [dv for p in ps for dv in p["devices"] if dv["is_primary"]]
        dept_prefix[dept] = prim[0]["device_id"].split("-")[0]
        dept_primary_type[dept] = collections.Counter(dv["type"] for dv in prim).most_common(1)[0][0]
        dept_primary_os[dept] = collections.Counter(dv["os_type"] for dv in prim)
        homes = [dv for p in ps for dv in p["devices"] if dv["type"] == "home"]
        seconds = [dv for p in ps for dv in p["devices"]
                   if not dv["is_primary"] and dv["type"] in ("laptop", "workstation")]
        dept_home_rate[dept] = sum(1 for p in ps if any(d["type"] == "home" for d in p["devices"])) / len(ps)
        dept_second_rate[dept] = len(seconds) / len(ps)
        dept_home_os[dept] = collections.Counter(dv["os_type"] for dv in homes)
        dept_second_os[dept] = collections.Counter(dv["os_type"] for dv in seconds)
    for p in profiles.values():
        for dv in p["devices"]:
            if dv["type"] != "mobile":
                os_versions[dv["os_type"]][dv["os_version"]] += 1
            m = re.fullmatch(r"([A-Z]+)-(WS|LT|HM)-(\d+)", dv["device_id"])
            if m:
                counters[(m.group(1), m.group(2))] = max(counters[(m.group(1), m.group(2))], int(m.group(3)))
    global_home_os = sum(dept_home_os.values(), collections.Counter())
    global_second_os = sum(dept_second_os.values(), collections.Counter())

    def pick(counter, r):
        keys = sorted(counter)
        return r.choices(keys, weights=[counter[k] for k in keys], k=1)[0]

    # 5. new users
    first, surnames = load_first_names(names_dir), load_surnames(names_dir)
    picker = NamePicker(first, surnames, profiles, _rng("names"))
    nrng = _rng("people")
    site_names = [s[0] for s in SITES]
    site_weights = [s[2] for s in SITES]
    new_users = []
    for dept in TARGETS:
        titles = [t for t, c in sorted(open_slots[dept].items()) for _ in range(c)]
        nrng.shuffle(titles)
        for title in titles:
            sex = "M" if nrng.random() < 0.5 else "F"
            f, l = picker.next(sex)
            new_users.append({"first": f, "last": l, "department": dept, "role": title,
                              "office": nrng.choices(site_names, weights=site_weights, k=1)[0]})
    nrng.shuffle(new_users)                       # hire order across departments

    taken = set(profiles)
    aws_taken = {p["aws_iam_user"].lower() for p in profiles.values() if p.get("aws_iam_user")}
    office_subnets = {d: [] for d in TARGETS}     # [(cidr, used)]
    home_subnets = []
    subnet_fill = collections.Counter()

    def next_subnet(dept):
        base = DEPT_BLOCK_BASE[dept]
        for i in range(1, 10):
            cidr = f"192.168.{base + i}.0/24"
            if cidr in RESERVED_SUBNETS:
                continue
            if subnet_fill[cidr] < DEVICES_PER_SUBNET:
                subnet_fill[cidr] += 1
                return cidr
        raise RuntimeError(f"{dept}: department block 192.168.{base}-{base + 9} is full")

    def next_home():
        for i in range(HOME_BLOCK_SIZE):
            cidr = HOME_BLOCK.format(i)
            if subnet_fill[cidr] < DEVICES_PER_SUBNET:
                subnet_fill[cidr] += 1
                return cidr
        raise RuntimeError("home block 172.20.0.0/21 is full")

    def device(dept, code, dtype, os_type, subnet, primary, r):
        prefix = dept_prefix[dept]
        counters[(prefix, code)] += 1
        did = f"{prefix}-{code}-{counters[(prefix, code)]:03d}"
        return {"type": dtype, "device_id": did, "hostname": did, "os_type": os_type,
                "os_version": pick(os_versions[os_type], r), "subnet": subnet,
                "is_primary": primary}

    anchor_d = _dt.date.fromisoformat(anchor)
    for i, nu in enumerate(new_users):
        f, l, dept = nu["first"], nu["last"], nu["department"]
        base_un = f"{f[0].lower()}.{l.lower()}"
        un, k = base_un, 1
        while un in taken:
            k += 1
            un = f"{base_un}{k}"
        assert not is_vulgar(un), un
        taken.add(un)
        r = _rng("devices", un)
        pt = dept_primary_type[dept]
        devs = [device(dept, "WS" if pt == "workstation" else "LT", pt,
                       pick(dept_primary_os[dept], r), next_subnet(dept), True, r)]
        if r.random() < dept_second_rate[dept]:
            os2 = pick(dept_second_os[dept] or global_second_os, r)
            devs.append(device(dept, "LT", "laptop", os2, next_subnet(dept), False, r))
        if r.random() < dept_home_rate[dept]:
            devs.append(device(dept, "HM", "home", pick(dept_home_os[dept] or global_home_os, r),
                               next_home(), False, r))
        start = anchor_d + _dt.timedelta(days=1 + (i * ONBOARDING_DAYS) // len(new_users))
        profiles[un] = {
            "display_name": f"{f} {l}", "department": dept, "role": nu["role"],
            "email": f"{un}@{DOMAIN}", "aws_iam_user": None, "gcp_iam_user": None,
            "office": nu["office"], "start_date": start.isoformat(), "devices": devs,
        }

    # 6. cloud access
    def tech_score(p, preferred=()):
        t = p["role"]
        if t in preferred:
            return 0
        return 1 if any(w in t.lower() for w in _TECH_WORDS) else 2

    crng = _rng("cloud")
    aws_rate = {}
    for dept, ps in base_by_dept.items():
        aws_rate[dept] = sum(1 for p in ps if p.get("aws_iam_user")) / len(ps)
    for dept in TARGETS:
        members = sorted(u for u, p in profiles.items() if p["department"] == dept)
        want = round(aws_rate[dept] * TARGETS[dept])
        have = sum(1 for u in members if profiles[u].get("aws_iam_user"))
        cands = [u for u in members if not profiles[u].get("aws_iam_user") and "start_date" in profiles[u]]
        crng.shuffle(cands)
        cands.sort(key=lambda u: tech_score(profiles[u]))
        for u in cands[:max(0, want - have)]:
            f, l = profiles[u]["display_name"].split(" ", 1)
            name, k = f"{f}.{l}", 1
            while name.lower() in aws_taken:
                k += 1
                name = f"{f}.{l}{k}"
            aws_taken.add(name.lower())
            profiles[u]["aws_iam_user"] = name
        rate = GCP_RATE.get(dept, 0)
        want = round(rate * TARGETS[dept])
        cands = list(members)
        crng.shuffle(cands)
        cands.sort(key=lambda u: (tech_score(profiles[u], GCP_PREFERRED.get(dept, ())),
                                  0 if profiles[u].get("aws_iam_user") else 1))
        for u in cands[:want]:
            profiles[u]["gcp_iam_user"] = profiles[u]["email"]
    report["aws_rate"] = aws_rate

    # 7. SIDs: base users keep the RID they had wherever it is unique and clear of the
    # training-student range; everyone else gets a sequential RID in hire order.
    reserved = set(range(5000, 5100))             # training_config student sid_rid_base
    used, moved = set(), []
    next_fix = 11000
    for u in sorted(u for u in profiles if "start_date" not in profiles[u]):
        rid = legacy_rid(u)
        if rid in used or rid in reserved:
            moved.append((u, rid, next_fix))
            rid, next_fix = next_fix, next_fix + 1
        used.add(rid)
        profiles[u]["sid_rid"] = rid
    rr = _rng("rids")
    rid = 12000
    for u in sorted((u for u in profiles if "start_date" in profiles[u]),
                    key=lambda u: (profiles[u]["start_date"], u)):
        rid += rr.randint(1, 6)                   # computers and groups take RIDs too
        profiles[u]["sid_rid"] = rid
    report["sid_moved"] = moved

    # 8. reorder profile keys for readability
    order = ["display_name", "department", "role", "email", "aws_iam_user", "gcp_iam_user",
             "office", "start_date", "sid_rid", "devices"]
    for u in list(profiles):
        p = profiles[u]
        profiles[u] = {k: p[k] for k in order if k in p}
    report["subnet_fill"] = dict(sorted(subnet_fill.items()))
    return report


# ── infrastructure ───────────────────────────────────────────────────────────────────────
def build_infrastructure(config):
    sites = [{"city": c, "code": code, "server_subnet": net, "new_hire_weight": w}
             for c, code, w, net in SITES]
    site_net = {c: net for c, _, _, net in SITES}

    def ip(city, host):
        return str(ipaddress.ip_network(site_net[city]).network_address + host)

    # Domain controllers: DC01-DC05 keep the five addresses every firewall module already
    # uses as its DC fallback; DC06-DC16 sit in the site server subnets.
    dcs = [("DC01", "10.0.10.10", "Columbus"), ("DC02", "10.0.20.10", "Columbus"),
           ("DC03", "10.1.5.10", "Columbus"), ("DC04", "192.168.1.10", "New York"),
           ("DC05", "172.16.10.10", "Austin"),
           ("DC06", ip("New York", 10), "New York"), ("DC07", ip("Austin", 10), "Austin"),
           ("DC08", ip("Seattle", 10), "Seattle"), ("DC09", ip("Seattle", 11), "Seattle"),
           ("DC10", ip("Chicago", 10), "Chicago"), ("DC11", ip("Fremont", 10), "Fremont"),
           ("DC12", ip("Atlanta", 10), "Atlanta"), ("DC13", ip("London", 10), "London"),
           ("DC14", ip("London", 11), "London"), ("DC15", ip("Dublin", 10), "Dublin"),
           ("DC16", ip("Toronto", 10), "Toronto")]

    servers = []      # (name, ip, role, site)

    def add(name, addr, role, site):
        servers.append((name, addr, role, site))

    # file servers: FS01/FS02/FILE01 unchanged; one or two per site after that
    fs = [("FS03", ip("Columbus", 33), "Columbus"), ("FS04", ip("Austin", 30), "Austin"),
          ("FS05", ip("Seattle", 30), "Seattle"), ("FS06", ip("New York", 30), "New York"),
          ("FS07", ip("New York", 31), "New York"), ("FS08", ip("Chicago", 30), "Chicago"),
          ("FS09", ip("Fremont", 30), "Fremont"), ("FS10", ip("Atlanta", 30), "Atlanta"),
          ("FS11", ip("Dublin", 30), "Dublin"), ("FS12", ip("London", 30), "London"),
          ("FS13", ip("London", 31), "London"), ("FS14", ip("Toronto", 30), "Toronto")]
    for n, a, s in fs:
        add(n, a, "file", s)
    for i, (c, *_rest) in enumerate(SITES[1:], start=2):
        add(f"PRINT{i:02d}", ip(c, 50), "print", c)
    for i in range(2, 9):
        add(f"SQL{i:02d}", ip("Columbus", 58 + i), "sql", "Columbus")
    for i, (c, h) in enumerate([("New York", 60), ("New York", 61), ("London", 60),
                                 ("London", 61)], start=9):
        add(f"SQL{i:02d}", ip(c, h), "sql", c)
    add("EXCH02", ip("Columbus", 42), "exchange", "Columbus")
    add("SP02", ip("Columbus", 43), "sharepoint", "Columbus")
    add("SP03", ip("Columbus", 44), "sharepoint", "Columbus")
    add("ADFS01", ip("Columbus", 70), "adfs", "Columbus")
    add("ADFS02", ip("Columbus", 71), "adfs", "Columbus")
    add("WAP01", "10.0.10.70", "adfs-proxy", "Columbus")
    add("WAP02", "10.0.10.71", "adfs-proxy", "Columbus")
    add("AADC01", ip("Columbus", 72), "entra-connect", "Columbus")
    add("AADC02", ip("Columbus", 73), "entra-connect", "Columbus")
    add("ROOTCA01", ip("Columbus", 80), "pki", "Columbus")
    add("CA01", ip("Columbus", 81), "pki", "Columbus")
    add("CA02", ip("Columbus", 82), "pki", "Columbus")
    add("NPS02", "10.1.5.22", "radius", "Columbus")
    add("DHCP01", ip("Columbus", 90), "dhcp", "Columbus")
    add("DHCP02", ip("Columbus", 91), "dhcp", "Columbus")
    add("DHCP03", ip("New York", 90), "dhcp", "New York")
    add("DHCP04", ip("London", 90), "dhcp", "London")
    add("WSUS01", ip("Columbus", 92), "patching", "Columbus")
    add("SCCM01", ip("Columbus", 93), "patching", "Columbus")
    for i, (c, *_rest) in enumerate(SITES[1:], start=1):
        add(f"SCCMDP{i:02d}", ip(c, 93), "patching", c)
    add("BACKUP02", "10.1.5.23", "backup", "Columbus")
    add("BACKUP03", "10.1.5.24", "backup", "Columbus")
    add("BACKUP04", ip("London", 25), "backup", "London")
    add("VCENTER02", ip("London", 20), "vcenter", "London")
    for i in range(2, 21):
        add(f"APP{i:02d}", ip("Columbus", 98 + i), "app", "Columbus")
    for i in range(1, 9):
        add(f"WEB{i:02d}", f"10.0.10.{79 + i}", "web", "Columbus")
    add("KMS01", ip("Columbus", 95), "kms", "Columbus")
    add("MON02", "10.0.30.41", "monitoring", "Columbus")

    # sanity: no address twice, none in a user subnet
    taken = [a for _, a, _ in dcs] + [a for _, a, _, _ in servers]
    dup = [a for a, c in collections.Counter(taken).items() if c > 1]
    assert not dup, dup
    old_servers = list(config["internal_servers"])
    clash = set(a for _, a, _, _ in servers) & (set(old_servers) | set(config["database_servers"]))
    assert not clash, clash
    user_nets = [ipaddress.ip_network(dv["subnet"]) for p in config["user_profiles"].values()
                 for dv in p["devices"]]
    for a in taken[5:]:
        assert not any(ipaddress.ip_address(a) in n for n in user_nets), a

    dc_hosts = {n: {"ip": a, "site": s} for n, a, s in dcs}
    # append only: earlier internal_servers indices stay where resolver expects them
    internal_servers = old_servers + [a for _, a, _ in dcs[5:]] + \
        [a for _, a, _, _ in servers if a not in old_servers]
    roles = dict(config["server_roles"])
    for n, a, _, _ in servers:
        roles.setdefault(n.lower(), a)
    roles.setdefault("fs01", "10.0.20.30")
    # file_servers stays the base three (every firewall module's SMB/FTP destination for
    # base users); new hires reach their own site's servers via file_server_sites.
    file_servers = list(config["file_servers"])
    file_server_sites = {"FS01": {"ip": "10.0.20.30", "site": "Columbus"},
                         "FS02": {"ip": "10.0.20.31", "site": "Columbus"},
                         "FILE01": {"ip": "10.0.20.32", "site": "Columbus"}}
    file_server_sites.update({n: {"ip": a, "site": s} for n, a, r, s in servers if r == "file"})

    # "192.168.1.db1" is not an address; everything else stays where it was
    db = [x for x in config["database_servers"]
          if not re.fullmatch(r"\d+\.\d+\.\d+\.[a-z]\w*", x)]
    db += [a for n, a, r, _ in servers if r == "sql"]

    esxi = dict(config["vmware_esxi_config"])
    hosts = list(esxi["hosts"])
    for i in range(len(hosts) + 1, 25):
        hosts.append(f"esxi{i:02d}.corp.examplecorp.local")
    vms = list(esxi["vms"])
    for n, *_ in dcs[1:]:
        vms.append(n)
    for n, _, r, _ in servers:
        if r not in ("adfs-proxy",) and n not in vms:
            vms.append(n)
    datastores = list(esxi["datastores"])
    for d in ("ds-prod-nfs02", "ds-vsan-02", "ds-vsan-nyc01", "ds-vsan-lon01", "ds-backup-01"):
        if d not in datastores:
            datastores.append(d)

    mgmt = dict(config["management_plane"])
    nd = list(mgmt["network_devices"])
    for c, _, _, net in SITES[1:]:
        gw = str(ipaddress.ip_network(net).network_address + 1)
        if gw not in nd:
            nd.append(gw)
    mgmt["network_devices"] = nd

    return {
        # domain_controllers: the five addresses the firewall modules already fell back
        # to, unchanged; the per-site DCs live in domain_controller_hosts.
        "sites": sites, "domain_controllers": [a for _, a, _ in dcs[:5]],
        "domain_controller_hosts": dc_hosts, "internal_servers": internal_servers,
        "server_roles": roles, "file_servers": file_servers,
        "file_server_sites": file_server_sites, "database_servers": db,
        "esxi": (hosts, vms, datastores), "management_plane": mgmt,
        "server_list": [(n, a, "dc", s) for n, a, s in dcs] + servers,
    }


# ── applications ─────────────────────────────────────────────────────────────────────────
NEW_OKTA_APPS = {
    "core": ["Microsoft Office 365", "Microsoft Teams", "Slack", "Zoom", "Workday", "Confluence",
             "Jira", "DocuSign", "Concur", "Culture Amp", "Udemy Business", "Lucidchart",
             "1Password", "KnowBe4", "Okta Dashboard", "ServiceNow"],
    "Sales": ["Salesforce", "Outreach", "Salesloft", "Gong", "Clari", "ZoomInfo",
              "LinkedIn Sales Navigator", "Highspot", "Seismic", "Chorus", "Apollo.io",
              "Vidyard", "DealHub", "PandaDoc", "Calendly", "Crossbeam", "Demandbase",
              "6sense", "Bombora", "Lusha"],
    "Marketing": ["HubSpot", "Marketo", "Drift", "Sprout Social", "Hootsuite", "Canva",
                  "Adobe Creative Cloud", "Figma", "Contentful", "WordPress VIP", "Semrush",
                  "Ahrefs", "Hotjar", "Optimizely", "Unbounce", "Cvent", "ON24", "Bynder",
                  "Brandwatch", "Mailchimp", "Iterable", "Braze", "Wistia", "Vimeo"],
    "Engineering": ["GitHub", "GitLab", "CircleCI", "Harness", "LaunchDarkly", "Sentry",
                    "Datadog", "New Relic", "Grafana Cloud", "PagerDuty", "Postman",
                    "Retool", "Linear", "Buildkite", "SonarCloud", "Snyk", "JFrog Artifactory",
                    "Docker Hub", "Vercel", "Netlify", "BrowserStack", "Sauce Labs",
                    "Codecov", "Mend", "Figma", "Miro", "Statsig", "Honeycomb",
                    "Lightstep", "Chromatic"],
    "DevOps": ["GitHub", "GitLab", "Terraform Cloud", "HashiCorp Vault", "Datadog",
               "PagerDuty", "Grafana Cloud", "Splunk Cloud", "AWS IAM Identity Center",
               "Google Cloud Console", "Azure Portal", "Cloudflare", "Fastly", "Akamai Control Center",
               "Kubernetes Dashboard", "Argo CD", "Spacelift", "env0", "Rootly",
               "incident.io", "Opsgenie", "Statuspage", "Teleport", "Tailscale",
               "Wiz", "Lacework", "Harness", "Buildkite"],
    "IT": ["ServiceNow", "Freshservice", "Jamf Pro", "Microsoft Intune", "Kandji",
           "Google Workspace Admin", "Okta Admin Console", "Zoom Admin", "Slack Admin",
           "Lansweeper", "Snipe-IT", "TeamViewer", "BeyondTrust Remote Support",
           "Splashtop", "Meraki Dashboard", "Zscaler Admin Portal", "Palo Alto Networks Strata",
           "Cisco Umbrella", "Backupify", "Druva", "Keeper Admin", "Azure Portal",
           "AWS IAM Identity Center", "Google Cloud Console", "SolarWinds", "Auvik"],
    "Security": ["CrowdStrike Falcon", "Cortex XSIAM", "Splunk Cloud", "Wiz", "Lacework",
                 "Tenable.io", "Rapid7 InsightVM", "Proofpoint TAP", "KnowBe4 Admin",
                 "Abnormal Security", "Recorded Future", "VirusTotal Enterprise",
                 "HackerOne", "Bugcrowd", "Snyk", "Vanta", "Drata", "OneTrust",
                 "Netskope", "Zscaler Admin Portal", "1Password Business", "Varonis",
                 "SentinelOne", "Okta Admin Console", "AWS IAM Identity Center",
                 "Google Cloud Console", "ThreatConnect", "Expel Workbench"],
    "Finance": ["NetSuite", "Concur", "Expensify", "Coupa", "Bill.com", "Brex", "Ramp",
                "Zuora", "Anaplan", "Adaptive Planning", "BlackLine", "FloQast",
                "Avalara", "Carta", "Stripe Dashboard", "Chargebee", "Tipalti",
                "Kyriba", "Navan", "Pigment", "Mosaic", "Ironclad"],
    "HR": ["Workday", "BambooHR", "Rippling", "ADP Workforce Now", "Greenhouse", "Lever",
           "Lattice", "Culture Amp", "15Five", "Leapsome", "Gusto", "Paylocity",
           "Checkr", "HireRight", "LinkedIn Recruiter", "Indeed Employer", "Glassdoor Employer",
           "Docebo", "Cornerstone OnDemand", "Benefitfocus", "Justworks", "Deel",
           "Remote.com", "SmartRecruiters", "Gem", "Textio"],
    "Legal": ["Ironclad", "DocuSign CLM", "Clio", "LexisNexis", "Westlaw", "OneTrust",
              "Juro", "ContractPodAi", "Relativity", "Everlaw", "Diligent Boards",
              "NetDocuments", "iManage", "Logikcull", "Thomson Reuters Practical Law"],
    "Procurement": ["Coupa", "Zip", "Tropic", "Vendr", "SAP Ariba", "Jaggaer", "Ivalua",
                    "Ironclad", "Graphite Connect", "Vanta", "Bonfire", "Precoro"],
    "Operations": ["Smartsheet", "Monday.com", "Asana", "Airtable", "ClickUp", "Notion",
                   "Trello", "Envoy", "Robin", "OfficeSpace", "Eptura", "Tableau", "Looker",
                   "ShipStation", "Flexport", "Kinaxis", "o9 Solutions", "Coupa", "Celonis",
                   "Process Street", "Lucidchart", "Loom"],
    "CustomerSuccess": ["Gainsight", "ChurnZero", "Totango", "Vitally", "Salesforce",
                        "Zendesk", "Intercom", "Front", "Gong", "Catalyst", "Planhat",
                        "Loom", "Calendly", "Pendo", "WalkMe", "Rocketlane", "Guru",
                        "Highspot", "DocuSign", "Zoom Webinars"],
    "Support": ["Zendesk", "Freshdesk", "Intercom", "Front", "Kustomer", "Help Scout",
                "Salesforce Service Cloud", "Guru", "Confluence", "Jira Service Management",
                "Statuspage", "PagerDuty", "Loom", "Talkdesk", "Five9", "Aircall",
                "MaestroQA", "Klaus", "Stonly", "Document360", "Shelf"],
    "Product": ["Productboard", "Aha!", "Pendo", "Amplitude", "Mixpanel", "Heap",
                "FullStory", "LogRocket", "Figma", "Miro", "Dovetail", "UserTesting",
                "Maze", "Lookback", "Hotjar", "Linear", "Jira Product Discovery",
                "Notion", "Loom", "Statsig", "LaunchDarkly", "Optimizely"],
    "DataScience": ["Snowflake", "Databricks", "dbt Cloud", "Fivetran", "Airbyte Cloud",
                    "Tableau", "Looker", "Power BI", "Mode", "Hex", "Sigma Computing",
                    "Amplitude", "Segment", "Hightouch", "Census", "Monte Carlo",
                    "Weights & Biases", "Hugging Face", "Domino Data Lab", "DataRobot",
                    "Dataiku", "Atlan", "Alation", "Google Cloud Console",
                    "AWS IAM Identity Center", "Jupyter Hub"],
    "optional": ["Dropbox Business", "Box", "Egnyte", "Evernote Teams", "Grammarly Business",
                 "Otter.ai", "Fireflies.ai", "Claude", "ChatGPT Enterprise", "Perplexity Enterprise",
                 "Coursera for Business", "Pluralsight", "LinkedIn Learning", "O'Reilly Learning",
                 "Qualtrics", "SurveyMonkey", "Typeform", "Google Workspace", "Webex",
                 "RingCentral", "Dialpad", "Slido", "Mentimeter", "Mural", "Whimsical",
                 "Coda", "Quip", "Workplace from Meta", "Bonusly", "Kudos", "Benevity",
                 "TravelPerk", "Egencia", "Expensify", "Carta", "Fidelity NetBenefits",
                 "Guideline", "Lucid", "Prezi", "Pitch", "Gamma", "Descript", "Camtasia",
                 "Snagit", "Calendly", "Doodle", "Clockwise", "Reclaim.ai", "Krisp",
                 "Zoom Whiteboard", "Tango", "Scribe"],
}


def build_okta(config):
    okta = dict(config["okta_config"])
    apps = list(okta["okta_sso_apps"])
    legacy_n = len(apps)
    seen = set(apps)
    for group in NEW_OKTA_APPS.values():
        for a in group:
            if a not in seen:
                apps.append(a)
                seen.add(a)
    okta["okta_sso_apps"] = apps
    okta["_comment_app_entitlements"] = (
        "Which SSO apps a user is assigned (modules/okta_sso.user_apps): every user gets "
        "'core' plus their department's list plus 1-3 picks from 'optional', fixed per user. "
        "Benign sign-ins draw from that set, so a user reaching an app outside it is a "
        "genuinely new app for them. Apps in okta_sso_apps that no list names are still "
        "valid targets for threat scenarios.")
    okta["app_entitlements"] = {
        "core": NEW_OKTA_APPS["core"],
        "departments": {d: NEW_OKTA_APPS[d] for d in TARGETS},
        "optional": NEW_OKTA_APPS["optional"],
        "optional_per_user": [1, 3],
        # base users keep their habitual apps from the first legacy_app_count apps
        "legacy_app_count": legacy_n,
    }
    return okta


NEW_SVC_APP = ["SSO_BRIDGE", "HRIS_SYNC", "PAYROLL_EXPORT", "CRM_SYNC", "ERP_CONNECTOR",
               "SEARCH_INDEXER", "EMAIL_RELAY", "PRINT_SPOOLER", "SCAN_TO_EMAIL", "VPN_RADIUS",
               "PKI_ENROLL", "SCCM_CLIENT_PUSH", "WSUS_SYNC", "VEEAM_PROXY", "SQL_AGENT",
               "SHAREPOINT_FARM", "EXCHANGE_HYBRID", "ADFS_SVC", "AADC_SYNC", "DFS_REPL",
               "TABLEAU_EXTRACT", "SNOWFLAKE_LOADER", "KAFKA_CONNECT", "AIRFLOW_WORKER",
               "JENKINS_AGENT", "GITLAB_RUNNER", "ARTIFACTORY", "SONAR_SCANNER", "NESSUS_SCAN",
               "SIEM_FORWARDER", "EDR_UPDATER", "MDM_CONNECTOR", "BADGE_SYSTEM", "HVAC_BMS",
               "VOIP_GATEWAY", "CONFERENCE_ROOM", "KIOSK", "WIFI_GUEST_PORTAL"]
NEW_SVC_DB = ["PAYROLL_APP", "CRM_APP", "ERP_APP", "BILLING_APP", "SUPPORT_APP",
              "MARKETING_APP", "SEARCH_APP", "SSO_APP", "CMDB_APP", "ASSET_APP", "BI_EXTRACT",
              "DWH_ETL", "SHAREPOINT_CONTENT", "SCCM_SITE", "WSUS_DB", "VEEAM_CATALOG",
              "PKI_DB", "BADGE_DB", "HELPDESK_APP", "TIMECARD_APP"]


def build_service_accounts(config):
    sa = dict(config["service_accounts"])
    sa["app_names"] = list(dict.fromkeys(list(sa["app_names"]) + NEW_SVC_APP))
    sa["db_names"] = list(dict.fromkeys(list(sa["db_names"]) + NEW_SVC_DB))
    return sa


# ── entry point ──────────────────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "..", "config.json"))
    ap.add_argument("--names-dir", required=True)
    ap.add_argument("--anchor", default="2026-11-20",
                    help="onboarding starts the day after this date (new hires: 90 days)")
    ap.add_argument("--report", default=None, help="write a markdown summary here")
    args = ap.parse_args(argv)

    with open(args.config, encoding="utf-8", newline="") as fh:
        text = fh.read()
    config = json.loads(text)

    report = build(config, args.names_dir, args.anchor)
    infra = build_infrastructure(config)
    profiles = config["user_profiles"]

    # aws_config.users_and_roles lists every profile IAM user (the module also merges
    # them at runtime; the list is what the docs and the dashboard read).
    aws = dict(config["aws_config"])
    uar = list(aws["users_and_roles"])
    for e in uar:
        if e.get("type") == "IAMUser" and "'" in e.get("name", ""):
            e["name"] = e["name"].replace("O'B", "Ob").replace("'", "")
            e["arn_suffix"] = "user/" + e["name"]
    have = {e["name"] for e in uar}
    for u in sorted(profiles):
        n = profiles[u].get("aws_iam_user")
        if n and n not in have:
            uar.append({"type": "IAMUser", "name": n, "arn_suffix": f"user/{n}"})
            have.add(n)
    aws["users_and_roles"] = uar

    esxi = dict(config["vmware_esxi_config"])
    esxi["hosts"], esxi["vms"], esxi["datastores"] = infra["esxi"]

    win = dict(config["windows_events_config"])
    win["endpoint_cap"] = {
        "_comment": ("At most `active` Windows workstations generate events on a given day: "
                     "the `core` hosts every day (all base-estate workstations come first), "
                     "the rest a different deterministic draw each UTC day from the remaining "
                     "onboarded hosts. Keeps per-host density and thread count bounded at "
                     "5,000 users while hosts keep (re)appearing. active: 0 disables the cap."),
        "active": 800, "core": 500,
    }

    ub = dict(config["user_behavior"])
    ub["onboarding"] = {
        "_comment": ("Profiles with a start_date are pre-provisioned new hires: they exist in "
                     "the directory but generate no activity before that date (UTC), so the "
                     "estate grows ~50 genuinely first-seen users a day. enabled: false makes "
                     "everyone active at once."),
        "enabled": True,
    }

    config[MARKER_KEY] = {
        "_comment": "Estate expanded by tools/estate_generator.py; do not run it on this file again.",
        "seed": SEED, "base_users": BASE_USER_COUNT, "users": len(profiles),
        "onboarding_anchor": args.anchor,
    }

    infra_comment = (
        "domain_controllers: the five DC addresses the firewall modules always fell back to "
        "(DC01-DC05), unchanged so base-estate traffic keeps its baseline. "
        "domain_controller_hosts: every DC with its site; DC06-DC16 sit in the site server "
        "subnets under 'sites'. New hires' Windows DC events and SMB/LDAP traffic go to "
        "their own site (session_utils.site_dc / site_dc_ip / site_file_servers).")

    out = text
    out = set_top_level(out, "user_profiles", profiles)
    out = set_top_level(out, "aws_config", aws)
    out = set_top_level(out, "okta_config", build_okta(config))
    out = set_top_level(out, "service_accounts", build_service_accounts(config))
    out = set_top_level(out, "internal_servers", infra["internal_servers"])
    out = set_top_level(out, "file_servers", infra["file_servers"])
    out = set_top_level(out, "server_roles", infra["server_roles"])
    out = set_top_level(out, "database_servers", infra["database_servers"])
    out = set_top_level(out, "management_plane", infra["management_plane"])
    out = set_top_level(out, "vmware_esxi_config", esxi)
    out = set_top_level(out, "windows_events_config", win)
    out = set_top_level(out, "user_behavior", ub)
    out = set_top_level(out, "file_server_sites", infra["file_server_sites"], after="file_servers")
    out = set_top_level(out, "_comment_domain_controllers", infra_comment, after="server_roles")
    out = set_top_level(out, "domain_controllers", infra["domain_controllers"],
                        after="_comment_domain_controllers")
    out = set_top_level(out, "domain_controller_hosts", infra["domain_controller_hosts"],
                        after="domain_controllers")
    out = set_top_level(out, "sites", infra["sites"], after="domain_controller_hosts")
    out = set_top_level(out, MARKER_KEY, config[MARKER_KEY], after="sites")
    json.loads(out)                                   # must still parse

    with open(args.config, "w", encoding="utf-8", newline="") as fh:
        fh.write(out)

    if args.report:
        write_report(args.report, config, report, infra)
    print(f"users: {len(profiles)}  servers added: {len(infra['server_list'])}  "
          f"renamed: {len(report['renamed'])}  SIDs moved: {len(report['sid_moved'])}")


def write_report(path, config, report, infra):
    p = config["user_profiles"]
    L = ["# Estate expansion report", ""]
    dept = collections.Counter(x["department"] for x in p.values())
    L += ["| Department | Users | AWS | GCP | Devices |", "|---|---|---|---|---|"]
    for d in TARGETS:
        us = [x for x in p.values() if x["department"] == d]
        L.append(f"| {d} | {len(us)} | {sum(1 for x in us if x['aws_iam_user'])} | "
                 f"{sum(1 for x in us if x['gcp_iam_user'])} | {sum(len(x['devices']) for x in us)} |")
    L += ["", f"Total users: {len(p)}; devices: {sum(len(x['devices']) for x in p.values())}", ""]
    L += ["## Renamed", ""] + [f"- `{a}` -> `{b}`" for a, b in report["renamed"].items()] + [""]
    L += ["## Duplicate hostnames fixed", ""]
    L += [f"- {u}: {a} -> {b}" for u, a, b in report["hostname_fixes"]] + [""]
    L += ["## Role changes on base users", ""]
    for (a, b), c in sorted(report["role_changes"].items()):
        L.append(f"- {a} -> {b} ({c})")
    L += ["", "## SIDs moved (collision or training range)", ""]
    L += [f"- {u}: {a} -> {b}" for u, a, b in report["sid_moved"]]
    L += ["", "## Subnet fill", ""] + [f"- {k}: {v}" for k, v in report["subnet_fill"].items()]
    first = collections.Counter(x["display_name"].split()[0] for x in p.values())
    last = collections.Counter(x["display_name"].split()[-1] for x in p.values())
    L += ["", f"Distinct first names: {len(first)}; top: {first.most_common(10)}",
          f"Distinct surnames: {len(last)}; top: {last.most_common(10)}", ""]
    L += ["## Servers", ""] + [f"- {n} {a} ({r}, {s})" for n, a, r, s in infra["server_list"]]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


if __name__ == "__main__":
    sys.exit(main())
