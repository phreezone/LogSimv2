"""Shared helpers for the Azure AD / O365 generators.

Sources identities from LogSim's canonical user model (config['user_profiles'] /
session_context, same as every other module) and models realistic sign-in content:
stable corporate-egress and home public IPs per user (so the ML analytics build a
coherent per-user baseline), plus catalogs of the apps, resources and status codes that
dominate a real Microsoft Entra tenant.

Research basis (Microsoft Entra sign-in / audit schema + typical tenant volume):
- Non-interactive sign-ins (silent token refresh by Outlook/Teams/OneDrive/mobile) are by
  far the highest volume, then interactive user sign-ins, then benign failures, then
  directory-audit activity. generate-side weighting reflects that.
"""
import functools
import hashlib
import ipaddress
import json
import math
import os
import random
import time

try:
    from modules.session_utils import (get_random_user, get_user_by_name,
                                        pick_active_session, publish_activity as _publish_activity,
                                        CORRELATE_PROB)
except Exception:  # pragma: no cover
    get_random_user = None
    get_user_by_name = None
    pick_active_session = None
    _publish_activity = None
    CORRELATE_PROB = 0.6


def publish_signin(user, loc=None):
    """Publish a cloud interactive sign-in as an active session (so on-prem/network follow-on for the
    same user correlates). No-op if the activity bus is unavailable."""
    if _publish_activity is None or not isinstance(user, dict):
        return
    _publish_activity(user.get("username"), egress_ip=(loc or {}).get("ip"),
                      department=user.get("department"), email=user.get("upn"),
                      display_name=user.get("display_name"))

UPN_DOMAIN = "examplecorp.com"   # match LogSim's identity model (user emails are @examplecorp.com)
HOME_TENANT_ID = "09febfec-25f3-48fa-bd8c-9b4a44f896ec"

# Egress is geolocated by XSIAM against real IP data, so every block below is one the declared
# network really announces and that GeoLite places in the declared city. Each /24 was checked on
# 2026-10-22 against RIPEstat: origin ASN (prefix-overview) and MaxMind GeoLite city covering
# >= 90% of the /24 (maxmind-geo-lite). The previous hand-picked blocks belonged to AWS, Microsoft,
# a hospital network and a Luxembourg ISP, so XSIAM saw offices in the wrong organisation or
# country. Re-run the check after changing any block.

# Corporate office sites. Each site is a geo + ISP/ASN + a NAT egress pool of several public IPs,
# so users at a site share a realistic small pool (many users behind a few office IPs) while the
# population as a whole spreads across ~60 office IPs across 10 sites instead of collapsing onto 3.
def _pool(block, first=10, n=6):
    base = block.rsplit(".", 1)[0]
    return [f"{base}.{first + i}" for i in range(n)]


OFFICES = [
    {"city": "Columbus", "state": "Ohio",       "countryOrRegion": "US", "lat": 39.96, "lon": -82.99,  "asn": 7018, "isp": "AT&T Services",       "ips": _pool("75.23.197.0")},
    {"city": "Austin",   "state": "Texas",      "countryOrRegion": "US", "lat": 30.27, "lon": -97.74,  "asn": 7018, "isp": "AT&T Services",       "ips": _pool("209.30.75.0")},
    {"city": "Seattle",  "state": "Washington", "countryOrRegion": "US", "lat": 47.60, "lon": -122.33, "asn": 209,  "isp": "Lumen (CenturyLink)", "ips": _pool("97.126.30.0")},
    {"city": "New York", "state": "New York",   "countryOrRegion": "US", "lat": 40.71, "lon": -74.01,  "asn": 701,  "isp": "Verizon Business",    "ips": _pool("173.52.219.0")},
    {"city": "Chicago",  "state": "Illinois",   "countryOrRegion": "US", "lat": 41.88, "lon": -87.63,  "asn": 7018, "isp": "AT&T Services",       "ips": _pool("70.241.99.0", n=5)},
    {"city": "Fremont",  "state": "California", "countryOrRegion": "US", "lat": 37.55, "lon": -121.99, "asn": 6939, "isp": "Hurricane Electric",  "ips": _pool("74.82.60.0", n=5)},
    {"city": "Atlanta",  "state": "Georgia",    "countryOrRegion": "US", "lat": 33.75, "lon": -84.39,  "asn": 7018, "isp": "AT&T Services",       "ips": _pool("75.46.159.0", n=4)},
    {"city": "Dublin",   "state": "Leinster",   "countryOrRegion": "IE", "lat": 53.35, "lon": -6.26,   "asn": 5466, "isp": "Eir",                 "ips": _pool("51.171.78.0", n=4)},
    {"city": "London",   "state": "England",    "countryOrRegion": "GB", "lat": 51.51, "lon": -0.13,   "asn": 2856, "isp": "BT",                  "ips": _pool("83.245.18.0", n=4)},
    {"city": "Toronto",  "state": "Ontario",    "countryOrRegion": "CA", "lat": 43.65, "lon": -79.38,  "asn": 812,  "isp": "Rogers Communications", "ips": _pool("99.221.22.0", n=4)},
]
# Kept for back-compat (a flat list of the primary office IPs).
OFFICE_EGRESS = [{"ip": o["ips"][0], "city": o["city"], "state": o["state"],
                  "countryOrRegion": o["countryOrRegion"], "lat": o["lat"], "lon": o["lon"]} for o in OFFICES]

# Residential ISP egress for remote/home days, per office metro: (isp, asn, /24, city, state, lat, lon).
# A user keeps one home block and one host in it (stable per user).
HOME_POOLS = {
    "Columbus": [("Spectrum", 10796, "75.185.237.0", "Hilliard", "Ohio", 40.03, -83.16),
                 ("AT&T Internet", 7018, "76.210.127.0", "Columbus", "Ohio", 39.96, -82.99)],
    "Austin":   [("Spectrum", 11427, "70.124.245.0", "Austin", "Texas", 30.27, -97.74),
                 ("AT&T Internet", 7018, "76.210.162.0", "Austin", "Texas", 30.27, -97.74)],
    "Seattle":  [("Comcast Cable", 7922, "216.122.114.0", "Seattle", "Washington", 47.60, -122.33),
                 ("CenturyLink", 209, "71.212.187.0", "Seattle", "Washington", 47.60, -122.33)],
    "New York": [("Spectrum", 12271, "74.71.58.0", "New York", "New York", 40.71, -74.01),
                 ("Verizon Fios", 701, "199.222.10.0", "Brooklyn", "New York", 40.68, -73.94)],
    "Chicago":  [("Comcast Cable", 7922, "50.73.116.0", "Chicago", "Illinois", 41.88, -87.63),
                 ("AT&T Internet", 7018, "99.180.199.0", "Chicago", "Illinois", 41.88, -87.63)],
    "Fremont":  [("AT&T Internet", 7018, "71.140.76.0", "San Francisco", "California", 37.77, -122.42),
                 ("Sonic", 46375, "135.180.117.0", "Oakland", "California", 37.80, -122.27)],
    "Atlanta":  [("Comcast Cable", 7922, "50.73.90.0", "Atlanta", "Georgia", 33.75, -84.39),
                 ("AT&T Internet", 7018, "75.46.152.0", "Atlanta", "Georgia", 33.75, -84.39)],
    "Dublin":   [("Virgin Media Ireland", 6830, "109.255.234.0", "Dublin", "Leinster", 53.35, -6.26)],
    "London":   [("Virgin Media", 5089, "139.190.228.0", "London", "England", 51.51, -0.13),
                 ("BT", 2856, "31.118.227.0", "London", "England", 51.51, -0.13)],
    "Toronto":  [("Bell Canada", 577, "74.13.228.0", "Toronto", "Ontario", 43.65, -79.38)],
}
# Mobile carrier egress (LTE/5G) per office metro, for occasional phone sign-ins: (isp, asn, /24).
# Carrier blocks geolocate to the metro, so a phone sign-in never "travels" away from the office.
MOBILE_POOLS = {
    "Columbus": [("T-Mobile USA", 21928, "172.59.244.0"), ("Verizon Wireless", 6167, "63.45.79.0")],
    "Austin":   [("Verizon Wireless", 6167, "97.155.229.0")],
    "Seattle":  [("T-Mobile USA", 21928, "162.187.202.0"), ("Verizon Wireless", 6167, "75.253.34.0"),
                 ("AT&T Mobility", 20057, "12.72.243.0")],
    "New York": [("Verizon Wireless", 6167, "166.145.69.0"), ("AT&T Mobility", 20057, "166.137.229.0")],
    "Chicago":  [("T-Mobile USA", 21928, "162.186.86.0"), ("Verizon Wireless", 6167, "97.242.87.0")],
    "Fremont":  [("T-Mobile USA", 21928, "172.59.174.0"), ("Verizon Wireless", 6167, "97.206.73.0"),
                 ("AT&T Mobility", 20057, "12.72.210.0")],
    "Atlanta":  [("T-Mobile USA", 21928, "172.56.69.0")],
    "Dublin":   [("Vodafone Ireland", 15502, "109.77.255.0"), ("Three Ireland", 13280, "92.251.244.0")],
    "London":   [("Three UK", 206067, "188.31.115.0")],
    "Toronto":  [("Rogers Wireless", 812, "72.138.229.0"), ("Bell Mobility", 36522, "207.236.216.0")],
}

# Apps/resources that dominate real Entra sign-in telemetry.
APPS_INTERACTIVE = ["Microsoft Office 365 Portal", "Office365 Shell WCSS-Client", "OfficeHome",
                    "Microsoft Teams", "My Apps", "Microsoft Office", "Outlook Web App",
                    "Microsoft 365 Security and Compliance Center", "Azure Portal",
                    "Microsoft App Access Panel", "Power BI", "Microsoft Power Apps",
                    "Microsoft Forms", "SharePoint Online Client", "Microsoft Stream",
                    "Microsoft Intune Company Portal", "Microsoft Bookings", "Yammer"]
APPS_NONINTERACTIVE = ["Microsoft Authentication Broker", "Microsoft Office", "OneDrive SyncEngine",
                       "Microsoft Teams", "Outlook Mobile", "Windows Sign In",
                       "Office365 Shell WCSS-Client", "Microsoft Account Controls V2",
                       "Microsoft Edge", "Microsoft Intune Web Company Portal",
                       "Microsoft Device Registration Client", "OfficeClientService",
                       "Microsoft Teams Web Client", "Enterprise Roaming and Backup"]
RESOURCES = ["Microsoft Graph", "Office 365 Exchange Online", "Office 365 SharePoint Online",
             "Windows Azure Active Directory", "Microsoft.Azure.SyncFabric", "Windows Azure Service Management API",
             "Microsoft Teams Services", "Azure Key Vault", "Microsoft Information Protection Sync Service",
             "Office 365 Management APIs", "Microsoft Graph Change Tracking", "Azure Storage"]
# Benign sign-in failures that happen routinely (mistyped password, expired password, MFA needed).
BENIGN_FAIL = [
    (50126, "Error validating credentials due to invalid username or password."),
    (50055, "The password is expired."),
    (50074, "Strong Authentication is required."),
    (50058, "Session information is not sufficient for single-sign-on."),
    (50072, "User needs to enroll for second factor authentication."),
    (50076, "Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication."),
    (50140, "This occurred due to 'Keep me signed in' interrupt when the user was signing in."),
    (50173, "The provided grant has expired due to it being revoked; the user must sign in again."),
    (65001, "The user or administrator has not consented to use the application."),
    (16000, "Either multiple user identities are available for the current request or none are selected."),
]


# Conditional Access policies a tenant typically has (displayName -> grant controls).
CA_POLICIES = [
    ("Require MFA for All Users", ["Mfa"]),
    ("Block Legacy Authentication", ["Block"]),
    ("Require Compliant or Hybrid Joined Device", ["CompliantDevice", "DomainJoinedDevice"]),
    ("Require MFA for Admins", ["Mfa"]),
    ("Require Approved Client App", ["ApprovedApplication"]),
]
# MFA / authentication methods (Entra authenticationMethod values).
MFA_METHODS = ["Mobile app notification", "Mobile app verification code", "Text message",
               "Windows Hello for Business", "FIDO2 security key", "Password"]
# Benign directory-audit Operations by category (O365 Management Activity naming — trailing period).
AUDIT_OPS = {
    "UserManagement": ["Update user.", "Change user password.", "Reset user password.",
                       "Update PasswordProfile.", "Add user.", "Update StsRefreshTokenValidFrom Timestamp."],
    "GroupManagement": ["Add member to group.", "Remove member from group.", "Update group."],
    "AuthMethod": ["User registered security info.", "User started security info registration.",
                   "User deleted security info.", "Admin registered security info."],
    "DeviceManagement": ["Add registered device.", "Add registered owner to device.", "Update device."],
    "ApplicationManagement": ["Consent to application.", "Add app role assignment grant to user."],
}


# ── programmatic business-entity generators ──────────────────────────────────────────
# Shared across the O365/Entra modules. Two kinds:
#   * UNBOUNDED, non-entity text (email subjects, external recipients) — fine to be unique per
#     event, since the record's own id (MessageId/InternetMessageId) is the entity key.
#   * BOUNDED, deterministic catalogs for things that ARE entities with stable ids (security/
#     distribution groups, Power BI reports/workspaces) — a real tenant has many but a finite,
#     recurring set, so detectors can baseline them. Seeded -> identical across runs/machines.

_SUBJECT_PREFIX = ["", "", "", "Re: ", "Re: ", "RE: ", "Fwd: ", "FW: ", "[EXTERNAL] "]
_SUBJECT_TOPIC = [
    "Q{q} forecast", "budget review", "invoice {n}", "PO {n}", "contract draft", "renewal quote",
    "meeting notes", "weekly status", "project update", "design review", "sprint planning",
    "incident {n}", "ticket #{n}", "customer escalation", "onboarding", "offer letter",
    "performance review", "payroll", "expense report", "travel approval", "security review",
    "access request", "password reset", "deployment window", "release notes", "roadmap",
    "pricing proposal", "partnership", "NDA for signature", "SOW attached", "data request",
    "board deck", "all-hands", "team lunch", "office closure", "benefits enrollment",
    "policy update", "compliance attestation", "audit follow-up", "vendor review", "QBR prep"]
_SUBJECT_SUFFIX = ["", "", "", "", " - action required", " (FYI)", " [URGENT]", " - please review",
                   " - EOD", " 2025", " 2026", " v2", " - final", " (no reply needed)"]
_EXT_FIRST = ["john", "sarah", "mike", "priya", "chen", "maria", "david", "anna", "raj", "emma",
              "carlos", "yuki", "tom", "laura", "sam", "nina", "omar", "lena", "paul", "zoe",
              "accounts", "billing", "sales", "support", "info", "procurement", "legal", "hr",
              "noreply", "notifications", "team", "contact", "admin", "orders"]
_EXT_DOMAINS_WIDE = ["gmail.com", "outlook.com", "proton.me", "yahoo.com", "icloud.com",
                     "partner-co.com", "acmecorp.com", "globex.com", "initech.com", "contoso.com",
                     "fabrikam.com", "northwind.com", "vendor.io", "consulting-grp.com",
                     "law-firm.net", "bank-corp.com", "logistics-llc.com", "supplier.co"]


def email_subject(rnd=None, q=None, external=False):
    r = rnd or random
    topic = r.choice(_SUBJECT_TOPIC).replace("{q}", str(q or r.randint(1, 4))).replace(
        "{n}", str(r.randint(1000, 99999)))
    pfx = r.choice(_SUBJECT_PREFIX)
    if external and not pfx.startswith("[EXTERNAL]") and r.random() < 0.5:
        pfx = "[EXTERNAL] " + pfx
    return f"{pfx}{topic[0].upper()}{topic[1:]}{r.choice(_SUBJECT_SUFFIX)}"


def external_email(rnd=None):
    r = rnd or random
    first = r.choice(_EXT_FIRST)
    dom = r.choice(_EXT_DOMAINS_WIDE)
    style = r.random()
    if style < 0.45:
        return f"{first}.{r.choice(_EXT_FIRST)}@{dom}"
    if style < 0.7:
        return f"{first}{r.randint(1, 999)}@{dom}"
    return f"{first}@{dom}"


def _build_catalog(seed, n, genfn):
    rnd = random.Random(seed)
    seen, out = set(), []
    while len(out) < n:
        v = genfn(rnd)
        if v not in seen:
            seen.add(v); out.append(v)
    return out


# Security / distribution / M365 groups — bounded deterministic catalog (entities w/ stable ids).
_GROUP_DEPTS = ["Sales", "Marketing", "Engineering", "Finance", "HR", "Legal", "IT", "Operations",
                "Support", "Product", "Security", "DevOps", "Data", "Procurement", "Facilities",
                "Customer Success", "Research", "Design", "QA", "Compliance"]
_GROUP_FUNC = ["Team", "Managers", "Admins", "Leads", "All", "Users", "Owners", "Members",
               "Approvers", "Readers", "Contributors", "On-Call", "Interns", "Contractors"]
_GROUP_REGION = ["", "", "", "AMER", "EMEA", "APAC", "LATAM", "US", "EU", "UK", "Global"]
_GROUP_PREFIX = ["", "", "DL-", "SG-", "M365-", "GRP-", "sec-", "dist-"]


def _gen_group(rnd):
    style = rnd.random()
    if style < 0.2:
        return rnd.choice(["All Employees", "All Company", "VPN Users", "Everyone",
                           "Licensed Users", "Guest Users", "External Collaborators"])
    pfx = rnd.choice(_GROUP_PREFIX); dept = rnd.choice(_GROUP_DEPTS)
    func = rnd.choice(_GROUP_FUNC); region = rnd.choice(_GROUP_REGION)
    name = f"{dept} {func}"
    if region:
        name = f"{name} - {region}"
    if rnd.random() < 0.15:
        name = f"Project {rnd.choice(['Apollo','Zephyr','Helios','Orion','Atlas','Titan','Nova'])} {func}"
    return f"{pfx}{name}"


_GROUPS_CATALOG = _build_catalog("logsim-groups-v1", 400, _gen_group)


def group_name(rnd=None):
    return (rnd or random).choice(_GROUPS_CATALOG)


# Power BI workspaces & reports — bounded deterministic catalogs (entities w/ stable ids).
_PBI_TOPIC = ["Sales Pipeline", "Revenue", "Customer 360", "Exec KPIs", "Support Metrics",
              "Finance Actuals", "Churn", "Marketing Funnel", "Product Usage", "Headcount",
              "Forecast", "Bookings", "Pipeline Health", "Renewals", "NPS", "Cost Analysis",
              "Inventory", "Logistics", "Compliance", "Security Posture", "SLA", "Adoption",
              "Cohort", "Attribution", "Budget vs Actual", "Cash Flow", "Utilization"]
_PBI_KIND = ["Dashboard", "Report", "Analysis", "Scorecard", "Summary", "Trends", "Overview",
             "Deep Dive", "Weekly", "Monthly", "QBR", "Executive"]
_PBI_WS_SUFFIX = ["Analytics", "Reporting", "BI", "Insights", "Data", "Metrics"]


def _gen_report(rnd):
    return f"{rnd.choice(_PBI_TOPIC)} {rnd.choice(_PBI_KIND)}"


def _gen_workspace(rnd):
    return f"{rnd.choice(_GROUP_DEPTS)} {rnd.choice(_PBI_WS_SUFFIX)}"


_PBI_REPORTS_CATALOG = _build_catalog("logsim-pbi-reports-v1", 300, _gen_report)
_PBI_WS_CATALOG = _build_catalog("logsim-pbi-ws-v1", 60, _gen_workspace)


def report_name(rnd=None):
    return (rnd or random).choice(_PBI_REPORTS_CATALOG)


def workspace_name(rnd=None):
    return (rnd or random).choice(_PBI_WS_CATALOG)


# ══ cardinality: baseline vs. reserved-rare pools ════════════════════════════════════════
# Rarity detectors ("first seen", "unusual app/resource/tenant/domain for this entity/org") only
# work if the thing that is supposed to be rare is NEVER produced by the benign baseline and almost
# never repeats. We keep THREE disjoint tiers:
#
#   1. BASELINE   — small, recurring pools the benign baseline draws from. Each entity (user, SP)
#                   gets a stable, narrow SUBSET (its "normal" apps/resources), so a draw outside
#                   that subset reads anomalous. These are what the ML learns as "normal".
#   2. ONBOARDING — a slowly growing set (wall-clock schedule) the benign baseline is allowed to add
#                   to over time, so "first seen app/consent" fires organically without baking the
#                   whole roster in within hours at 1 log/sec (~86k events/day per generator).
#   3. RARE       — effectively unbounded combinatorial spaces (>1e9) that ONLY threat scenarios
#                   draw from, disjoint from tiers 1-2 by construction + an explicit membership
#                   filter. Random draw from a space this large makes repeats negligible over months
#                   of runtime, so no persisted "already used" counter is needed (same approach as
#                   the SharePoint cold-tail). This guarantees a rare scenario ALWAYS has a genuinely
#                   never-before-seen entity available, no matter how long the sim runs.

# ── SaaS application catalogs (shared by the Graph + O365 directory feeds) ─────────────
# Common apps that recur in everyday delegated consent / app-role events — the hot core that
# forms the baseline (familiar, always-present apps).
SAAS_CORE = ["Salesforce", "ServiceNow", "Zoom", "Slack", "Workday", "DocuSign", "Atlassian Cloud",
              "GitHub Enterprise", "Adobe Acrobat Sign", "Box", "Tableau Online", "Power BI",
              "Microsoft Graph Command Line Tools"]

# Enterprise integrations that realistically receive tenant-wide admin consent. A large, varied
# roster: each app is a stable entity (deterministic appId + SP objectId). Benign consent onboards
# these GRADUALLY (see onboarding schedule) rather than all at once.
ADMIN_CONSENT_APPS = [
    # Collaboration / productivity
    "Slack", "Zoom", "Webex", "Google Workspace", "Dropbox Business", "Box", "Egnyte",
    "Citrix ShareFile", "Notion", "Confluence", "Atlassian Cloud", "Asana", "Monday.com", "Trello",
    "Smartsheet", "Miro", "Mural", "Lucidchart", "Figma", "Airtable", "ClickUp", "Basecamp", "Wrike",
    "Coda", "Evernote Business", "Calendly", "Loom", "Grammarly Business", "Zapier", "Workato",
    "Tray.io", "Make", "Doodle",
    # E-signature / documents / content
    "DocuSign", "Adobe Acrobat Sign", "PandaDoc", "Dropbox Sign", "Adobe Creative Cloud", "Canva",
    "Contentful", "Webflow", "Wistia", "Vimeo", "Brightcove", "DocuWare", "M-Files", "Nintex",
    # CRM / sales / marketing
    "Salesforce", "HubSpot", "Zoho CRM", "Pipedrive", "Microsoft Dynamics 365", "Marketo",
    "Salesforce Pardot", "Outreach", "Salesloft", "Gong", "ZoomInfo", "Clearbit", "Drift",
    "Intercom", "Mailchimp", "SendGrid", "Constant Contact", "Braze", "Iterable", "Segment",
    "Amplitude", "Mixpanel", "Pendo", "Heap", "Marqeta", "Apollo.io", "6sense", "Demandbase",
    # Support / ITSM / customer success
    "ServiceNow", "Jira Service Management", "Freshservice", "Freshdesk", "Zendesk", "Help Scout",
    "Front", "Gainsight", "Totango", "ChurnZero", "Vitally", "ServiceTitan",
    # Observability / IT ops
    "PagerDuty", "Opsgenie", "Splunk Cloud", "Datadog", "New Relic", "Dynatrace", "AppDynamics",
    "Grafana Cloud", "Sumo Logic", "Elastic Cloud", "LogicMonitor", "SolarWinds", "ManageEngine",
    "NinjaOne", "Automox", "ConnectWise", "Jamf Pro", "Kandji", "Rippling", "JumpCloud",
    # Security / identity
    "Okta", "Ping Identity", "OneLogin", "Duo Security", "CyberArk", "SailPoint IdentityNow",
    "BeyondTrust", "CrowdStrike Falcon", "SentinelOne", "Proofpoint", "Mimecast", "Abnormal Security",
    "KnowBe4", "Netskope", "Zscaler", "Cloudflare", "Palo Alto Prisma Access", "Tenable.io", "Qualys",
    "Rapid7 InsightVM", "Wiz", "Lacework", "Snyk", "Veracode", "Checkmarx", "1Password Business",
    "LastPass", "Dashlane", "Keeper Security", "HashiCorp Vault", "Twingate", "Tailscale",
    "Vanta", "Drata", "Secureframe", "OneTrust", "LogicGate", "AuditBoard",
    # HR / recruiting / people
    "Workday", "BambooHR", "Gusto", "ADP Workforce Now", "UKG Pro", "Paylocity", "Paycom", "Namely",
    "Greenhouse", "Lever", "SmartRecruiters", "Workable", "Culture Amp", "Lattice", "15Five", "Deel",
    "Remote", "Cornerstone OnDemand", "Docebo", "LinkedIn Learning", "Udemy Business", "Pluralsight",
    "Coursera for Business", "Degreed", "WalkMe",
    # Finance / ERP / procurement
    "SAP Concur", "Coupa", "Bill.com", "Ramp", "Brex", "NetSuite", "Sage Intacct", "QuickBooks Online",
    "Xero", "Stripe", "Avalara", "Navan", "Airbase", "Tipalti", "Expensify", "Divvy", "Anaplan",
    "Workiva", "BlackLine",
    # Dev / engineering / CI-CD
    "GitHub Enterprise", "GitLab", "Bitbucket", "CircleCI", "Jenkins", "Harness", "Octopus Deploy",
    "JFrog Artifactory", "SonarCloud", "Sentry", "Rollbar", "Bugsnag", "LaunchDarkly", "Split.io",
    "Postman", "SwaggerHub", "Terraform Cloud", "Pulumi", "Docker Hub", "Databricks",
    # Data / analytics / BI
    "Snowflake", "dbt Cloud", "Fivetran", "Airbyte", "Looker", "Tableau Online", "Power BI",
    "Qlik Sense", "Mode Analytics", "Sisense", "ThoughtSpot", "Metabase", "Hex", "Alteryx",
    "Celonis", "Collibra", "Monte Carlo",
    # Automation / RPA / misc platform
    "UiPath", "Automation Anywhere", "Blue Prism", "MuleSoft", "Boomi", "BetterCloud", "Torii",
    "Productiv", "Zluri",
    # Storage / backup / DR
    "Druva", "Rubrik", "Cohesity", "Veeam", "Backblaze",
    # Comms / telephony
    "Twilio", "RingCentral", "Dialpad", "Aircall", "8x8", "Five9", "Talkdesk", "Genesys Cloud",
    "Vonage",
    # Microsoft first-party admin tooling
    "Microsoft Graph Command Line Tools", "Microsoft Graph PowerShell", "Azure CLI",
    # Design / construction / vertical
    "Autodesk Construction Cloud", "Procore", "Bluebeam", "Qualtrics", "SurveyMonkey", "Typeform",
]

# Vendor/product tokens used to synthesize app-registration names for the unbounded RARE app space.
APP_VENDORS = [
    "Asana", "Monday", "Notion", "Airtable", "Smartsheet", "Miro", "Figma", "Lucidchart", "Calendly",
    "Dropbox", "Egnyte", "Mural", "Coda", "ClickUp", "Wrike", "Basecamp", "Trello", "Jira",
    "Confluence", "Bitbucket", "GitLab", "CircleCI", "Datadog", "Grafana", "Splunk", "PagerDuty",
    "Opsgenie", "New Relic", "Sumo Logic", "Okta", "Ping Identity", "OneLogin", "Duo", "CyberArk",
    "SailPoint", "CrowdStrike", "SentinelOne", "Proofpoint", "Mimecast", "Netskope", "Zscaler",
    "Cloudflare", "Snyk", "Veracode", "1Password", "LastPass", "HashiCorp", "Twilio", "SendGrid",
    "Mailchimp", "HubSpot", "Marketo", "Segment", "Amplitude", "Mixpanel", "Pendo", "Intercom",
    "Drift", "Gong", "Outreach", "Salesloft", "Gainsight", "Totango", "Greenhouse", "Lever",
    "BambooHR", "Gusto", "Rippling", "Deel", "Expensify", "Coupa", "Ramp", "Brex", "Bill.com",
    "NetSuite", "Xero", "Stripe", "Snowflake", "Databricks", "Fivetran", "Looker", "Qlik",
    "ThoughtSpot", "Metabase", "Alteryx", "UiPath", "Workato", "Zapier", "Boomi", "MuleSoft",
    "Celonis", "Vanta", "Drata", "OneTrust", "AuditBoard", "Procore", "Qualtrics", "SurveyMonkey",
    "Typeform", "Loom", "Grammarly", "Webex", "RingCentral", "Twingate", "Tailscale", "JumpCloud"]

APP_PRODUCTS = [
    "Connector", "for Microsoft 365", "SSO", "Integration", "Sync", "Cloud", "Enterprise",
    "Analytics", "API", "Automation", "Add-in", "Teams App", "Reporting", "Gateway", "Provisioning",
    "SCIM", "for Outlook", "for Teams", "for SharePoint", "Insights", "Workspace", "Platform",
    "Admin", "Service", "Bot"]


# ── onboarding drift: benign app estate grows on a wall-clock schedule ─────────────────
# At 1 log/sec a generator emits ~86k events/day, so uniformly sampling the whole 258-app consent
# roster in the baseline would let XSIAM "see" every app within hours and the "first seen" detectors
# would saturate. Instead the consented estate grows a few apps per week (wall-clock), so new apps
# keep appearing for ~a year of runtime. Order is seeded (stable across restarts); the admitted
# count is a pure function of elapsed time, so no state file is needed.
_RUN_T0 = time.time()
ONBOARDING_BASE_APPS = 40            # apps already consented when the tenant "starts"
ONBOARDING_HOURS_PER_APP = 36.0      # ~4-5 newly consented apps per week

_ONBOARD_ORDER = None


def _onboard_order():
    global _ONBOARD_ORDER
    if _ONBOARD_ORDER is None:
        order = list(dict.fromkeys(ADMIN_CONSENT_APPS))      # dedup, stable
        random.Random("logsim-onboard-order-v1").shuffle(order)
        _ONBOARD_ORDER = order
    return _ONBOARD_ORDER


def onboarded_apps(now=None):
    """The subset of the consent roster the tenant has onboarded by `now` (grows with wall-clock)."""
    order = _onboard_order()
    hrs = max(0.0, ((now if now is not None else time.time()) - _RUN_T0) / 3600.0)
    n = min(len(order), ONBOARDING_BASE_APPS + int(hrs / ONBOARDING_HOURS_PER_APP))
    return order[:n]


def baseline_saas_app(now=None):
    """Benign app pick: the recurring core plus apps onboarded so far (never a rare/unseen app)."""
    return random.choice(SAAS_CORE + onboarded_apps(now))


def admin_consent_app(now=None):
    """Benign admin-consent target: an app from the onboarded estate (the newest is the organic
    'first seen admin consent')."""
    ob = onboarded_apps(now)
    return random.choice(ob) if ob else random.choice(SAAS_CORE)


# ── per-entity baseline subsets (stable, narrow) ──────────────────────────────────────
# A user/SP does not touch every app and resource — it has a small habitual set. Benign draws from
# that set so the ML learns a tight per-entity baseline; a draw outside it (rare pool) is anomalous.
def _stable_subset(seed, pool, k):
    """Deterministic k-element subset of pool for a given seed (stable across runs)."""
    k = max(1, min(k, len(pool)))
    return random.Random(seed).sample(sorted(pool), k)


def baseline_apps_for(user, interactive=True, k=None):
    pool = APPS_INTERACTIVE if interactive else APPS_NONINTERACTIVE
    un = user["username"] if isinstance(user, dict) else str(user)
    k = k or (7 if interactive else 6)
    return _stable_subset(f"appset:{interactive}:{un}", pool, k)


def pick_baseline_app(user, interactive=True):
    return random.choice(baseline_apps_for(user, interactive))


def baseline_resources_for(entity, k=4):
    """Stable subset of RESOURCES this user/SP normally accesses (entity may be a user dict or a
    string key like 'sp:<name>')."""
    key = entity["username"] if isinstance(entity, dict) else str(entity)
    return _stable_subset(f"resset:{key}", RESOURCES, k)


def pick_baseline_resource(entity):
    return random.choice(baseline_resources_for(entity))


def rare_resource_for(entity, rnd=None):
    """A resource OUTSIDE this entity's baseline set (an 'unusual resource for this app/user')."""
    r = rnd or random
    base = set(baseline_resources_for(entity))
    outside = [x for x in RESOURCES if x not in base]
    return r.choice(outside) if outside else r.choice(RESOURCES)


# ── reserved RARE pools (unbounded, disjoint from baseline) ────────────────────────────
_RARE_APP_EDITIONS = ["", "", "Pro", "Enterprise", "Cloud", "EU", "US", "Global", "Partner",
                      "Dev", "Sandbox", "Beta", "Labs", "Premium", "Team", "Online", "X"]
# Baseline app name set — rare app names are filtered against this so the spaces can never overlap.
_BASELINE_APP_SET = frozenset(SAAS_CORE) | frozenset(ADMIN_CONSENT_APPS)


def rare_app_name(rnd=None):
    """A never-before-seen application-registration name from an unbounded space (>1e9), guaranteed
    disjoint from every baseline/onboarded app. For first-seen app / illicit-consent scenarios."""
    r = rnd or random
    for _ in range(8):
        name = (f"{r.choice(APP_VENDORS)} {r.choice(APP_PRODUCTS)} "
                f"{r.choice(_RARE_APP_EDITIONS)}{r.randint(1000, 999999)}").replace("  ", " ").strip()
        if name not in _BASELINE_APP_SET:
            return name
    return name  # astronomically unlikely to loop out; name already carries a unique number


# Hosting / VPS / anonymizer networks -- sign-ins from these never occur in the benign baseline
# (which uses corporate office / residential / mobile egress), so any is anomalous. Each entry is a
# prefix the ASN really originates whose whole extent GeoLite places in one country (RIPEstat
# announced-prefixes + prefix-overview + maxmind-geo-lite, 2026-10-22), so XSIAM's own enrichment
# agrees with the record. ~21M addresses, drawn in proportion to block size, keep attacker IPs
# effectively unique (an unbounded rare pool); the few /24s are providers with no large
# single-country prefix.
_RARE_ASNS = [  # (asn, isp, prefix, country)
    (14061, "DigitalOcean, LLC", "188.226.128.0/17", "NL"),
    (14061, "DigitalOcean, LLC", "107.170.0.0/17", "US"),
    (14061, "DigitalOcean, LLC", "46.101.128.0/17", "DE"),
    (14061, "DigitalOcean, LLC", "162.243.0.0/17", "US"),
    (16509, "Amazon.com, Inc.", "184.192.0.0/10", "US"),
    (16509, "Amazon.com, Inc.", "3.128.0.0/10", "US"),
    (16509, "Amazon.com, Inc.", "44.224.0.0/11", "US"),
    (14618, "Amazon.com, Inc.", "44.192.0.0/11", "US"),
    (14618, "Amazon.com, Inc.", "3.224.0.0/12", "US"),
    (14618, "Amazon.com, Inc.", "34.224.0.0/12", "US"),
    (14618, "Amazon.com, Inc.", "34.192.0.0/12", "US"),
    (20473, "The Constant Company (Vultr)", "44.33.0.0/16", "US"),
    (20473, "The Constant Company (Vultr)", "167.179.64.0/18", "JP"),
    (20473, "The Constant Company (Vultr)", "158.247.192.0/18", "KR"),
    (20473, "The Constant Company (Vultr)", "108.61.0.0/18", "US"),
    (63949, "Akamai Connected Cloud (Linode)", "178.79.128.0/18", "GB"),
    (63949, "Akamai Connected Cloud (Linode)", "45.79.128.0/18", "US"),
    (63949, "Akamai Connected Cloud (Linode)", "172.104.64.0/19", "JP"),
    (63949, "Akamai Connected Cloud (Linode)", "172.232.32.0/19", "FR"),
    (24940, "Hetzner Online GmbH", "78.46.0.0/15", "DE"),
    (24940, "Hetzner Online GmbH", "178.104.0.0/15", "DE"),
    (24940, "Hetzner Online GmbH", "91.99.0.0/16", "DE"),
    (24940, "Hetzner Online GmbH", "2.31.0.0/16", "DE"),
    (16276, "OVH SAS", "57.130.0.0/16", "FR"),
    (51167, "Contabo GmbH", "169.58.128.0/17", "FR"),
    (51167, "Contabo GmbH", "169.58.0.0/17", "FR"),
    (51167, "Contabo GmbH", "194.163.128.0/18", "FR"),
    (51167, "Contabo GmbH", "13.140.128.0/18", "FR"),
    (9009, "M247 Europe SRL", "106.48.160.0/20", "IT"),
    (9009, "M247 Europe SRL", "106.49.144.0/20", "BR"),
    (9009, "M247 Europe SRL", "106.49.224.0/20", "DE"),
    (9009, "M247 Europe SRL", "106.49.0.0/20", "FR"),
    (49505, "Selectel", "95.213.128.0/17", "RU"),
    (49505, "Selectel", "87.228.0.0/17", "RU"),
    (49505, "Selectel", "178.72.128.0/18", "RU"),
    (49505, "Selectel", "82.202.192.0/18", "RU"),
    (200019, "Alexhost SRL", "80.97.128.0/20", "MD"),
    (396982, "Google LLC", "136.110.38.0/24", "SG"),
    (396982, "Google LLC", "35.234.92.0/24", "DE"),
    (60068, "Datacamp Limited (CDN77)", "89.187.179.0/24", "US"),
    (3214, "xTom", "78.142.192.0/24", "NL"),
    (14061, "DigitalOcean, LLC", "128.199.116.0/24", "SG"),
    (16276, "OVH SAS", "167.114.188.0/24", "CA"),
]
_RARE_SIZES = [ipaddress.ip_network(p).num_addresses for _a, _i, p, _c in _RARE_ASNS]


def rare_asn_loc(rnd=None, country=None):
    """Egress from a hosting/VPS/anonymizer network (never seen in the benign baseline). Returns the
    same shape as egress(): {ip, city, state, countryOrRegion, geoCoordinates, asn, isp}, in the
    country the block really sits in. `country` narrows the draw to blocks there when any exist."""
    r = rnd or random
    idx = [i for i, x in enumerate(_RARE_ASNS) if not country or x[3] == country] or list(range(len(_RARE_ASNS)))
    # Provider first, weighted by the square root of its space (so AWS's /10s do not crowd out the
    # VPS hosts), then a block within it by size: diverse infrastructure, still ~99% unique IPs.
    groups = {}
    for i in idx:
        groups.setdefault(_RARE_ASNS[i][1], []).append(i)
    names = list(groups)
    isp = r.choices(names, weights=[sum(_RARE_SIZES[i] for i in groups[n]) ** 0.5 for n in names])[0]
    i = r.choices(groups[isp], weights=[_RARE_SIZES[j] for j in groups[isp]])[0]
    asn, isp, prefix, cc = _RARE_ASNS[i]
    net = ipaddress.ip_network(prefix)
    ip = str(net.network_address + r.randrange(1, net.num_addresses - 1))
    return {"ip": ip, "city": "", "state": "", "countryOrRegion": cc,
            "geoCoordinates": {"latitude": 0, "longitude": 0}, "asn": asn, "isp": isp}


# Combinatorial pieces for rogue tenants / backdoor domains (unbounded).
_RARE_ORG_WORDS = ["corp", "cloud", "sync", "secure", "global", "services", "systems", "tenant",
                   "identity", "federation", "partner", "group", "holdings", "digital", "online",
                   "mail", "connect", "access", "verify", "portal", "office", "msft", "entra",
                   "admin", "gateway", "trust", "data", "net", "hub", "soft", "tech", "labs"]
_RARE_TLDS = ["com", "net", "org", "io", "co", "cloud", "app", "info", "biz", "xyz", "online",
              "site", "live", "pro", "email", "link"]


def _rare_label(rnd):
    r = rnd
    a, b = r.choice(_RARE_ORG_WORDS), r.choice(_RARE_ORG_WORDS)
    sep = r.choice(["", "", "-"])
    tail = r.choice(["", "", "", str(r.randint(1, 999)), r.choice(["hq", "intl", "grp", "co"])])
    return f"{a}{sep}{b}{tail}"


def rare_domain(rnd=None, kind="generic"):
    """A never-seen external domain from an unbounded space. kind: 'generic', 'federation'
    (IdP/backdoor flavored), or 'onmicrosoft' (a fake external tenant vanity domain)."""
    r = rnd or random
    label = _rare_label(r)
    if kind == "onmicrosoft":
        return f"{label}.onmicrosoft.com"
    if kind == "federation":
        label = r.choice(["login", "sts", "adfs", "auth", "sso", "idp", "secure"]) + \
            r.choice(["-", ""]) + label
    return f"{label}.{r.choice(_RARE_TLDS)}"


def rare_tenant(rnd=None):
    """A never-seen external Entra tenant: returns {domain, tenant_id} (both unbounded/unique)."""
    r = rnd or random
    dom = rare_domain(r, kind="onmicrosoft")
    return {"domain": dom, "tenant_id": _stable_guid("rtenant:" + dom + ":" + str(r.random()))}


def rare_ext_email(rnd=None):
    """A never-seen external recipient address on a rare domain (for exfil/forwarding targets)."""
    r = rnd or random
    first = r.choice(_EXT_FIRST)
    return f"{first}{r.randint(1, 9999)}@{rare_domain(r)}"


# Actors who are NOT part of any admin baseline — a 'non-standard account' for admin-type operations.
_ADMIN_ROLE_NAMES = frozenset({"IT Administrator", "IT Director", "Systems Engineer", "Help Desk",
                               "Security Engineer", "Security Analyst"})


def pick_nonstandard_actor(config=None, context=None):
    """Pick an identity whose directory role is NOT an admin/helpdesk/security role, so an
    admin-type action by them reads as 'performed by a non-standard account'. Falls back to
    pick_user() if no role metadata is available."""
    profiles = (config or {}).get("user_profiles") or {}
    if profiles:
        non_admin = [u for u, p in profiles.items()
                     if p.get("role") not in _ADMIN_ROLE_NAMES and lifecycle_cohort(u) == "active"]
        if non_admin:
            u = random.choice(non_admin)
            return _norm(u, profiles[u])
    return pick_user(config, context)


# ── identity lifecycle (active / dormant / departed cohorts) ──────────────────────────
# Every identity is deterministically assigned a lifecycle cohort. The benign baseline draws ONLY
# from 'active' identities (pick_user excludes the reserved cohorts by default), so dormant and
# departed accounts have NO recent activity in the training window — exactly what the state-based
# detectors key on:
#   active    — the normal working population; appears throughout the baseline.
#   dormant   — exists in the directory but is never signed in by the baseline (stale/service/leave
#               accounts). A sign-in by one reads as 'login/auth by a dormant account'.
#   departed  — a former employee / decommissioned account, also never active in the baseline. A
#               sign-in attempt reads as a disabled/leaver account trying to authenticate.
# Cohorts are a pure hash of the username, so they're stable across runs and independent of the
# roster source (session_context or config['user_profiles']).
_LIFECYCLE_DORMANT_PCT = 6
_LIFECYCLE_DEPARTED_PCT = 6


@functools.lru_cache(maxsize=None)
def lifecycle_cohort(username):
    """Deterministic lifecycle cohort for an identity: 'active' | 'dormant' | 'departed'.

    Memoised: it is a pure hash of the username, and the roster filters call it for every
    user on every event -- uncached that was ~500 SHA-256s per Exchange event (~90% of the
    module's generation time)."""
    b = _h("lifecycle:v1:" + str(username)) % 100
    if b < _LIFECYCLE_DORMANT_PCT:
        return "dormant"
    if b < _LIFECYCLE_DORMANT_PCT + _LIFECYCLE_DEPARTED_PCT:
        return "departed"
    return "active"


def _session_ctx(context):
    return (context or {}).get("session_context") if isinstance(context, dict) else None


def _roster(config=None, context=None):
    """Usernames available this run: session_context roster if present, else config profiles."""
    sc = _session_ctx(context)
    if sc:
        return list(sc.keys())
    return list(((config or {}).get("user_profiles") or {}).keys())


def _user_info(uname, config, context):
    """Build a normalized identity dict for a specific username from whichever roster is live."""
    sc = _session_ctx(context)
    if sc and get_user_by_name and uname in sc:
        u = get_user_by_name(sc, uname)
        if u:
            return {"username": uname, "upn": u.get("email") or f"{uname}@{UPN_DOMAIN}",
                    "display_name": u.get("display_name", uname),
                    "department": u.get("department", "Unknown"),
                    "os_type": u.get("os_type", "Windows"), "os_version": u.get("os_version", "10")}
    profiles = (config or {}).get("user_profiles") or {}
    if uname in profiles:
        return _norm(uname, profiles[uname])
    return {"username": uname, "upn": f"{uname}@{UPN_DOMAIN}", "display_name": uname,
            "department": "Unknown", "os_type": "Windows", "os_version": "10"}


def _pick_cohort_user(config, context, cohort):
    """Pick an identity in a specific lifecycle cohort (dormant/departed). Returns a normalized
    identity dict, or falls back to pick_user() if the roster has no member of that cohort."""
    roster = [u for u in _roster(config, context) if lifecycle_cohort(u) == cohort]
    if roster:
        return _user_info(random.choice(roster), config, context)
    return pick_user(config, context)


def pick_dormant_user(config=None, context=None):
    """A dormant identity (exists, but never active in the baseline) — for dormant-account scenarios."""
    return _pick_cohort_user(config, context, "dormant")


def pick_departed_user(config=None, context=None):
    """A departed/decommissioned identity — for disabled/leaver sign-in scenarios."""
    return _pick_cohort_user(config, context, "departed")


# ── threat gating ────────────────────────────────────────────────────────────────────
# Threats are modeled as wall-clock EPISODES, not a per-log percentage. A detection fires on an
# episode (a burst/sequence: a spray, a mass-download, an impossible-travel pair), once per episode,
# so the realistic knob is "how many malicious episodes happen per hour" — independent of log volume
# and burst size. In a real low-incident tenant genuine malicious activity is a needle in a haystack
# (well under 0.01% of logs; most days zero). Rates below are PER MODULE; tenant-wide totals (×7
# feeds) are noted. The gate uses a Poisson process over elapsed real time, so episodes occur at the
# target wall-clock rate however often the module is polled. A benign warmup still withholds all
# threats until a baseline has accrued.
# Keyed by EXACTLY the six levels every other module uses (config.json
# threat_generation_levels): the Microsoft feeds differ only in HOW a level paces threats
# (Poisson episodes rather than a minimum interval), never in WHICH levels exist. This table
# used to carry two private levels (Low, Medium) that nothing could select, and lacked
# Elevated and Extreme, which therefore fell back to Realistic.
THREAT_EPISODES_PER_HOUR = {
    "Benign Traffic Only": 0.0,
    "Realistic": 0.03,   # ~5/day tenant-wide — a handful, like a real low-incident tenant
    "Elevated":  0.15,   # ~25/day tenant-wide (the former "Medium" rate)
    "High":      0.6,    # ~100/day tenant-wide
    "Extreme":   2.0,    # ~340/day tenant-wide
    "Insane":    6.0,    # stress/demo — ~1000/day tenant-wide
}
THREAT_WARMUP_EVENTS = 500   # benign records per module before any threat may fire
_THREAT_MAX_DT = 600.0       # cap elapsed-time per call so a long idle gap can't dump an episode


class ThreatGate:
    """Decides when a module should emit a threat scenario vs. benign. Fires episodes as a Poisson
    process at THREAT_EPISODES_PER_HOUR (wall-clock), independent of how often the module is polled
    or how large each scenario burst is, and withholds all threats during a benign warmup so
    baselines form first. `scenarios` is accepted for call-site compatibility and not required."""

    def __init__(self, scenarios=None, warmup=THREAT_WARMUP_EVENTS, max_dt=_THREAT_MAX_DT,
                 rate_scale=1.0):
        self._scenarios = scenarios
        self._warmup = warmup
        self._max_dt = max_dt
        self._rate_scale = rate_scale   # <1 makes this source rarer (e.g. multi-step campaigns)
        self.count = 0
        self._last = None

    def fire(self, threat_level, config=None, now=None):
        """True if a threat scenario should fire on this call."""
        self.count += 1
        t = now if now is not None else time.time()
        last, self._last = self._last, t
        if self.count <= self._warmup:                  # still accruing baseline
            return False
        rate_hr = THREAT_EPISODES_PER_HOUR.get(threat_level, THREAT_EPISODES_PER_HOUR["Realistic"]) * self._rate_scale
        if rate_hr <= 0 or last is None:
            return False
        dt = min(max(0.0, t - last), self._max_dt)      # seconds since last call (capped)
        if dt <= 0:
            return False
        p = 1.0 - math.exp(-(rate_hr / 3600.0) * dt)    # Poisson: P(>=1 episode in dt)
        return random.random() < p


def _h(s):
    return int(hashlib.sha256(str(s).encode()).hexdigest(), 16)


def applied_ca(result="success", n=1):
    """Return an appliedConditionalAccessPolicies list (Graph appliedConditionalAccessPolicy)."""
    picks = random.sample(CA_POLICIES, min(n, len(CA_POLICIES)))
    out = []
    for name, grants in picks:
        out.append({"id": str(_h(name) % 10**32).zfill(8)[:8] + "-ca",  # stable-ish id
                    "displayName": name, "enforcedGrantControls": grants,
                    "enforcedSessionControls": [], "result": result})
    return out


def auth_details(method="Password", succeeded=True, step_ts=None):
    """Return an authenticationDetails list entry (Graph signIn authenticationDetail)."""
    return [{"authenticationStepDateTime": step_ts,
             "authenticationMethod": method,
             "authenticationMethodDetail": "",
             "succeeded": succeeded,
             "authenticationStepResultDetail": ("MFA completed in Azure AD" if method != "Password"
                                                else "Correct password"),
             "authenticationStepRequirement": ""}]


_ACTIVE_NAMES = {}   # id(profiles) -> (profiles, len, active names)


def _active_profile_names(profiles):
    """ACTIVE-cohort usernames of a user_profiles dict (all names if none are active),
    cached per roster -- this ran a cohort check over every profile on every event. The
    dict itself is kept in the entry so its id cannot be reused by another object."""
    hit = _ACTIVE_NAMES.get(id(profiles))
    if hit is not None and hit[0] is profiles and hit[1] == len(profiles):
        return hit[2]
    names = [n for n in profiles if lifecycle_cohort(n) == "active"] or list(profiles)
    _ACTIVE_NAMES[id(profiles)] = (profiles, len(profiles), names)
    return names


def pick_user(config=None, context=None, include_reserved=False):
    """Return a normalized identity from LogSim's user model.

    Prefers the run's session_context; falls back to config['user_profiles']; last resort a
    stub. Keys: username, upn, display_name, department, os_type, os_version.

    By default only ACTIVE-cohort identities are returned, so the benign baseline (and ordinary
    threat scenarios, which also call this) never touch the reserved dormant/departed accounts —
    those stay absent from the baseline until a dormant/leaver scenario explicitly summons one via
    pick_dormant_user()/pick_departed_user(). include_reserved=True disables the filter.
    """
    sc = (context or {}).get("session_context") if isinstance(context, dict) else None
    if sc and get_random_user:
        # Correlation: prefer a currently-active session user (someone who just logged on elsewhere),
        # so cloud activity clusters with the on-prem/network activity for the same identity.
        if not include_reserved and pick_active_session and random.random() < CORRELATE_PROB:
            s = pick_active_session()
            if s and s["username"] in sc and lifecycle_cohort(s["username"]) == "active":
                info = get_user_by_name(sc, s["username"]) if get_user_by_name else None
                if info:
                    return {"username": s["username"],
                            "upn": info.get("email") or f'{s["username"]}@{UPN_DOMAIN}',
                            "display_name": info.get("display_name", s["username"]),
                            "department": info.get("department", "Unknown"),
                            "os_type": info.get("os_type", "Windows"),
                            "os_version": info.get("os_version", "10")}
        for _ in range(12):
            u = get_random_user(sc)
            if not u:
                break
            uname = u["username"]
            if include_reserved or lifecycle_cohort(uname) == "active":
                return {"username": uname,
                        "upn": u.get("email") or f"{uname}@{UPN_DOMAIN}",
                        "display_name": u.get("display_name", uname),
                        "department": u.get("department", "Unknown"),
                        "os_type": u.get("os_type", "Windows"),
                        "os_version": u.get("os_version", "10")}
    profiles = (config or {}).get("user_profiles") or {}
    if profiles:
        names = list(profiles) if include_reserved else _active_profile_names(profiles)
        uname = random.choice(names)
        p = profiles[uname]
        dev = (p.get("devices") or [{}])[0]
        return {"username": uname,
                "upn": p.get("email") or f"{uname}@{UPN_DOMAIN}",
                "display_name": p.get("display_name", uname),
                "department": p.get("department", "Unknown"),
                "os_type": dev.get("os_type", "Windows"),
                "os_version": dev.get("os_version", "10")}
    return {"username": "a.user", "upn": f"a.user@{UPN_DOMAIN}", "display_name": "A User",
            "department": "Unknown", "os_type": "Windows", "os_version": "10"}


def _norm(uname, p):
    dev = (p.get("devices") or [{}])[0]
    return {"username": uname, "upn": p.get("email") or f"{uname}@{UPN_DOMAIN}",
            "display_name": p.get("display_name", uname),
            "department": p.get("department", "Unknown"), "role": p.get("role", ""),
            "os_type": dev.get("os_type", "Windows"), "os_version": dev.get("os_version", "10")}


_ROLE_POOLS = {}


def pick_by_role(config, roles, departments=None):
    """Pick an actor whose profile role is in `roles` (e.g. Help Desk, IT Administrator).

    Admin actions in a real tenant come from a small, stable set of admins — the analytics
    baseline 'who normally does this', so a non-admin doing it reads as anomalous. Falls back
    to IT-department users, then to pick_user()."""
    profiles = (config or {}).get("user_profiles") or {}
    key = (tuple(roles), tuple(departments or ()))
    if key not in _ROLE_POOLS:
        # Admins who "do the work" are active by definition — never draw a reserved (dormant/
        # departed) account for a baseline admin action.
        pool = [u for u, p in profiles.items()
                if p.get("role") in roles and lifecycle_cohort(u) == "active"]
        if not pool and departments:
            pool = [u for u, p in profiles.items()
                    if p.get("department") in departments and lifecycle_cohort(u) == "active"]
        _ROLE_POOLS[key] = sorted(pool)
    pool = _ROLE_POOLS[key]
    if not pool:
        return pick_user(config)
    u = random.choice(pool)
    return _norm(u, profiles[u])


# Business-hours activity profile (US Eastern, fixed offset). Interactive/admin activity
# follows the workday; token refreshes continue overnight. Gives 'unusual time' detectors a
# real diurnal baseline to judge against.
TZ_OFFSET_HOURS = -5


def activity_weight(now_ts=None):
    """0..1 likelihood that a human-driven event happens right now."""
    import time as _t
    t = _t.gmtime((now_ts or _t.time()) + TZ_OFFSET_HOURS * 3600)
    h, weekday = t.tm_hour, t.tm_wday < 5
    if weekday:
        if 8 <= h < 18:
            return 1.0
        if h == 7 or 18 <= h < 21:
            return 0.35
        return 0.06
    return 0.15 if 9 <= h < 17 else 0.04


def _stable_guid(seed):
    h = hashlib.sha256(str(seed).encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# Browser/user-agent matrix keyed by OS family. Each entry: (browser label, full UA string).
# A user sticks to one profile (stable per user) so their device baseline is coherent.
_UA_CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Safari/537.36"
_UA_EDGE_WIN   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Safari/537.36 Edg/{v}"
_UA_FF_WIN     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{fv}) Gecko/20100101 Firefox/{fv}"
_UA_SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{sv} Safari/605.1.15"
_UA_CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Safari/537.36"
_UA_SAFARI_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
_UA_CHROME_AND = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Mobile Safari/537.36"

_BROWSER_PROFILES = {
    "Windows": [("Chrome 154.0.0", "Chrome", "154.0.0.0", "Windows10", _UA_CHROME_WIN.format(v="154.0.0.0")),
                ("Chrome 153.0.0", "Chrome", "153.0.0.0", "Windows10", _UA_CHROME_WIN.format(v="153.0.0.0")),
                ("Edge 154.0.0",   "Edge",   "154.0.0.0", "Windows10", _UA_EDGE_WIN.format(v="154.0.0.0")),
                ("Edge 153.0.0",   "Edge",   "153.0.0.0", "Windows10", _UA_EDGE_WIN.format(v="153.0.0.0")),
                ("Firefox 131.0",  "Firefox","131.0",     "Windows10", _UA_FF_WIN.format(fv="131.0"))],
    "macOS":   [("Safari 17.4",    "Safari", "17.4",      "MacOsX",    _UA_SAFARI_MAC.format(sv="17.4")),
                ("Safari 17.3",    "Safari", "17.3",      "MacOsX",    _UA_SAFARI_MAC.format(sv="17.3")),
                ("Chrome 154.0.0", "Chrome", "154.0.0.0", "MacOsX",    _UA_CHROME_MAC.format(v="154.0.0.0"))],
    "iOS":     [("Mobile Safari 17.4", "Safari", "17.4", "IPhone",     _UA_SAFARI_IOS)],
    "Android": [("Chrome Mobile 154", "Chrome", "154.0.0.0", "Android", _UA_CHROME_AND.format(v="154.0.0.0"))],
}


def _profile(user, mobile=False):
    """Stable (browser_label, browser_name, browser_version, platform, user_agent) for a user."""
    if mobile:
        fam = "iOS" if _h("mobfam:" + user["username"]) % 2 else "Android"
    else:
        fam = user.get("os_type", "Windows")
        if fam not in _BROWSER_PROFILES:
            fam = "Windows"
    opts = _BROWSER_PROFILES[fam]
    return opts[_h("brow:" + user["username"]) % len(opts)]


def _browser(os_type, user=None):
    if user is None:
        return "Safari 17.4" if os_type == "macOS" else "Chrome 154.0.0"
    return _profile(user)[0]


def user_agent(user, mobile=False):
    """Stable, realistic User-Agent string for a user (desktop by default)."""
    return _profile(user, mobile=mobile)[4]


# ── CIE identity alignment (ITDR asset enrichment) ────────────────────────────────────
# XSIAM's ITDR enriches events with identity-asset context (User Risk View, asset-role, risk
# scoring) only when an event's identity key matches an identity the Cloud Identity Engine synced.
# For this tenant CIE is connected to a directory whose users were replicated from our roster, but
# the synthetic Entra object GUID (hash-derived) does NOT match the real objectGUID there, so
# enrichment does not attach (contains_featured_user = NO). To fix that WITHOUT hard-coding anyone's
# real IDs, we load an OPTIONAL identity map: when present, user_oid()/on_prem_sid() return the real
# objectId / on-prem SID from the map so every emitted event joins to the CIE identity; when absent,
# they fall back to the deterministic hash (current behavior). Drop the file in and enrichment
# attaches with no code change. Map format (JSON), keyed by username and/or UPN:
#   { "a.tucker": {"object_id": "<entra objectGUID>", "on_prem_sid": "S-1-5-21-...", "sam": "a.tucker"} }
# Path: $LOGSIM_CIE_IDENTITY_MAP, else config['cie_identity_map_path'], else state/cie_identity_map.json.
_IDENTITY_MAP = None
_IDENTITY_MAP_LOADED = False


def _identity_map_path(config=None):
    p = os.environ.get("LOGSIM_CIE_IDENTITY_MAP") or (config or {}).get("cie_identity_map_path")
    if p:
        return p
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "state", "cie_identity_map.json")


def load_identity_map(config=None, force=False):
    """Load (once) the optional CIE identity map. Returns {} when no file is present."""
    global _IDENTITY_MAP, _IDENTITY_MAP_LOADED
    if _IDENTITY_MAP_LOADED and not force:
        return _IDENTITY_MAP
    path = _identity_map_path(config)
    data = {}
    try:
        if os.path.exists(path):
            raw = json.load(open(path, encoding="utf-8"))
            if isinstance(raw, dict):
                # index by both username and upn local-part for flexible lookup
                for key, val in raw.items():
                    if not isinstance(val, dict):
                        continue
                    data[key] = val
                    data[key.split("@")[0]] = val
                    if val.get("upn"):
                        data[val["upn"]] = val
                        data[val["upn"].split("@")[0]] = val
    except Exception:
        data = {}
    _IDENTITY_MAP = data
    _IDENTITY_MAP_LOADED = True
    return data


def _identity_entry(username):
    m = _IDENTITY_MAP if _IDENTITY_MAP_LOADED else load_identity_map()
    return m.get(str(username)) if m else None


def write_identity_map_template(config, path=None):
    """Write a fill-in CIE identity-map template for every roster user (blank object_id/on_prem_sid),
    so the real values can be exported from the CIE-connected directory and dropped straight in.
    Returns the path written."""
    profiles = (config or {}).get("user_profiles") or {}
    tmpl = {}
    for uname, p in profiles.items():
        tmpl[uname] = {"upn": p.get("email") or f"{uname}@{UPN_DOMAIN}",
                       "object_id": "", "on_prem_sid": "", "sam": uname}
    path = path or _identity_map_path(config)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(tmpl, open(path, "w", encoding="utf-8"), indent=2)
    return path


def on_prem_sid(username):
    """Real on-premises SID for a user when the CIE identity map supplies one, else None."""
    e = _identity_entry(username)
    return e.get("on_prem_sid") if e else None


def cie_identity_overrides(user):
    """Optional on-prem identity fields (onPremisesSecurityIdentifier / sAMAccountName) to merge into
    a sign-in record, populated only when the CIE identity map covers this user."""
    e = _identity_entry(user["username"] if isinstance(user, dict) else user)
    if not e:
        return {}
    out = {}
    if e.get("on_prem_sid"):
        out["onPremisesSecurityIdentifier"] = e["on_prem_sid"]
    if e.get("sam"):
        out["onPremisesSamAccountName"] = e["sam"]
    return out


# ── stable-per-entity identifiers (cardinality) ──────────────────────────────────────
# These MUST be stable per entity, not random per event, or the analytics see every
# sign-in as a brand-new user/app (infinite cardinality) and the baseline never forms and
# "first seen"/"new app" detectors misfire. IDs that MUST stay unique per event
# (id/Id, correlationId, InterSystemsId, IntraSystemId, sessionId) are left random.

def user_oid(username):
    """Stable directory object id for a user (Graph userId / O365 UserKey).

    If a CIE identity map is loaded and covers this user, returns the directory's REAL objectId so
    the event joins to the ITDR identity asset; otherwise a deterministic hash (stable per user)."""
    e = _identity_entry(username)
    if e and e.get("object_id"):
        return e["object_id"]
    return _stable_guid("oid:" + str(username))


def app_id(name):
    """Stable application id for an app display name (Graph appId / O365 ApplicationId)."""
    return _stable_guid("app:" + str(name))


def resource_id(name):
    """Stable resource id for a resource display name (Graph resourceId)."""
    return _stable_guid("res:" + str(name))


# Device trust posture, stable per user. Most corporate endpoints are AADJ/Hybrid + managed/
# compliant; a realistic minority are Azure AD registered or Workplace joined (BYOD) and not managed.
_TRUST_TYPES = [
    ("Azure AD joined",        True,  True),
    ("Azure AD joined",        True,  True),
    ("Hybrid Azure AD joined", True,  True),
    ("Hybrid Azure AD joined", True,  True),
    ("Azure AD registered",    False, False),
    ("Workplace joined",       False, False),
]


def device_for(user, new=False, mobile=False):
    """deviceDetail for a sign-in. Stable per user by default (coherent device baseline); a
    brand-new unmanaged device when new=True -> feeds 'new device seen' anomaly detectors.
    mobile=True returns the user's phone profile."""
    os_type = user.get("os_type", "Windows")
    os_str = f'{os_type} {user.get("os_version", "")}'.strip()
    if new:
        return {"deviceId": "", "displayName": "", "browser": _browser(os_type, user),
                "operatingSystem": os_str, "isCompliant": False, "isManaged": False, "trustType": ""}
    if mobile:
        label, bname, _bv, _plat, _ua = _profile(user, mobile=True)
        mos = "iOS 17.4" if "iOS" in _plat or _plat == "IPhone" else "Android 14.0"
        return {"deviceId": _stable_guid("mdev:" + user["username"]),
                "displayName": f'{user["username"].split(".")[0].capitalize()}-Phone',
                "browser": label, "operatingSystem": mos,
                "isCompliant": True, "isManaged": True, "trustType": "Azure AD registered"}
    trust, managed, compliant = _TRUST_TYPES[_h("trust:" + user["username"]) % len(_TRUST_TYPES)]
    return {"deviceId": _stable_guid("dev:" + user["username"]),
            "displayName": f'{user["username"].upper().replace(".", "")}-PC',
            "browser": _browser(os_type, user), "operatingSystem": os_str,
            "isCompliant": compliant, "isManaged": managed, "trustType": trust}


def office_for(user):
    """The stable office site a user belongs to (by department)."""
    return OFFICES[_h("site:" + str(user.get("department", "Unknown"))) % len(OFFICES)]


def _loc(city, state, country, lat, lon, ip, asn, isp):
    return {"ip": ip, "city": city, "state": state, "countryOrRegion": country,
            "geoCoordinates": {"latitude": lat, "longitude": lon}, "asn": asn, "isp": isp}


def egress(user, remote_prob=0.25, mobile_prob=0.08):
    """Stable public egress for a user: mostly their dept office NAT (a stable IP within the
    site's pool), sometimes a residential/home IP, occasionally a mobile-carrier IP.

    Returns {ip, city, state, countryOrRegion, geoCoordinates, asn, isp}. Deterministic per user
    so each user keeps a coherent IP/ASN/geo baseline (anomaly detectors judge against it), while
    the population spreads across ~50 office IPs + per-user home + carrier IPs. Home and mobile
    blocks are in the user's office metro (HOME_POOLS / MOBILE_POOLS), so a day at home or on a
    phone never looks like travel.
    """
    un = user["username"]
    site = office_for(user)
    r = random.random()
    if r < mobile_prob:                                   # phone on cellular (carrier block in the metro)
        n = _h("mob:" + un)
        isp, asn, block = MOBILE_POOLS[site["city"]][n % len(MOBILE_POOLS[site["city"]])]
        ip = f'{block.rsplit(".", 1)[0]}.{(n >> 8) % 250 + 3}'
        return _loc(site["city"], site["state"], site["countryOrRegion"],
                    site["lat"], site["lon"], ip, asn, isp)
    if r < mobile_prob + remote_prob:                     # working from home (residential, same metro)
        n = _h("home:" + un)
        isp, asn, block, city, state, lat, lon = HOME_POOLS[site["city"]][n % len(HOME_POOLS[site["city"]])]
        ip = f'{block.rsplit(".", 1)[0]}.{(n >> 8) % 250 + 3}'
        return _loc(city, state, site["countryOrRegion"], lat, lon, ip, asn, isp)
    # at the office (stable IP in the site's NAT pool)
    ip = site["ips"][_h("deskip:" + un) % len(site["ips"])]
    return _loc(site["city"], site["state"], site["countryOrRegion"],
                site["lat"], site["lon"], ip, site["asn"], site["isp"])


# ── Event Hub copies (msft_azure_raw) ─────────────────────────────────────────────────
# XSIAM's Cloud analytics read cloud_audit_logs. The Graph signIns feed (msft_azure_ad_raw)
# never reaches it; the same objects streamed through Entra diagnostic settings to an event hub
# do, as log_name azure_ad_signin_logs, and Graph API request logs (MicrosoftGraphActivityLogs)
# arrive as microsoft_graph_activity_logs -- the data the "Microsoft Graph Activity Logs"
# detectors need (verified by a canary on 2026-10-22). Modules emit those copies alongside their
# native records; the cribl transport routes each to the Azure Event Hubs Source-Identifier
# via the record's route key (integrations.cribl_direct.ROUTE_KEY, stripped before sending).
EVENTHUB_SOURCE = "fce13a1d51294f84bae4a37851503060"
EVENTHUB_INTEGRATION = "logsim:entra_eventhub"
ROUTE_KEY = "__cribl_route__"
EVENTHUB_RESOURCE = f"/tenants/{HOME_TENANT_ID}/providers/Microsoft.aadiam"


def eventhub_enabled(config, config_key):
    """Whether a module emits Event Hub copies (config[<key>]['eventhub_copies'], default on)."""
    mc = (config or {}).get(config_key) if isinstance(config, dict) else None
    return bool(mc.get("eventhub_copies", True)) if isinstance(mc, dict) else True


def route_eventhub(record):
    """Mark a record for the Azure Event Hubs Source-Identifier (msft_azure_raw)."""
    record[ROUTE_KEY] = [EVENTHUB_SOURCE, EVENTHUB_INTEGRATION]
    return record


def is_eventhub_copy(record):
    return isinstance(record, dict) and ROUTE_KEY in record


def _signin_category(signin):
    types = signin.get("signInEventTypes") or []
    if "servicePrincipal" in types:
        return "ServicePrincipalSignInLogs"
    if "managedIdentity" in types:
        return "ManagedIdentitySignInLogs"
    return "SignInLogs" if signin.get("isInteractive", True) else "NonInteractiveUserSignInLogs"


def eventhub_signin(signin):
    """The Event Hub diagnostic-settings record for a Graph signIn object (same object as
    properties; envelope fields follow Microsoft's sign-in log schema for event hubs)."""
    status = signin.get("status") or {}
    code = status.get("errorCode", 0) or 0
    loc = signin.get("location") or {}
    who = (signin.get("userDisplayName") or signin.get("servicePrincipalName")
           or signin.get("appDisplayName") or "")
    rec = {"time": signin.get("createdDateTime"), "resourceId": EVENTHUB_RESOURCE,
           "operationName": "Sign-in activity", "operationVersion": "1.0",
           "category": _signin_category(signin), "tenantId": HOME_TENANT_ID,
           "resultType": str(code), "resultSignature": "None",
           "resultDescription": "" if not code else (status.get("failureReason") or ""),
           "durationMs": 0, "callerIpAddress": signin.get("ipAddress"),
           "correlationId": signin.get("correlationId"), "identity": who, "Level": 4,
           "location": loc.get("countryOrRegion", ""), "properties": signin}
    return route_eventhub(rec)


def with_eventhub_signins(records):
    """records + an Event Hub copy of every Graph signIn object among them (order kept: each
    copy follows its original)."""
    out = []
    for r in records or []:
        out.append(r)
        if isinstance(r, dict) and "signInEventTypes" in r and not is_eventhub_copy(r):
            out.append(eventhub_signin(r))
    return out
