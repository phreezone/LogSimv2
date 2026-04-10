# modules/okta_sso.py
# Simulates Okta System Log events in exact REST API format (/api/v1/logs).
# Output is a structural match to the real Okta API so that Cribl can forward
# it to XSIAM and have it parsed identically to native Okta data.

import random
import time
import json
from datetime import datetime, timezone
from ipaddress import ip_network
import uuid
import re
import math

NAME = "Okta SSO"
DESCRIPTION = "Simulates Okta System Log events in exact Okta REST API format."
XSIAM_VENDOR = "Okta"
XSIAM_PRODUCT = "Sso"
CONFIG_KEY = "okta_config"

last_threat_event_time = 0

# authenticationProvider string values per Okta API spec
# PASSWORD logins → None; MFA factor events → "FACTOR_PROVIDER"
_AUTH_PROVIDER_FOR_CRED = {
    "PASSWORD":             None,
    "OIE_OKTA_VERIFY_PUSH": "FACTOR_PROVIDER",
    "PUSH":                 "FACTOR_PROVIDER",
    "SIGNED_NONCE":         "FACTOR_PROVIDER",
    "SMS":                  "FACTOR_PROVIDER",
    "EMAIL":                "FACTOR_PROVIDER",
    "TOTP":                 "FACTOR_PROVIDER",
}

_MFA_FACTOR_MAP = {
    "PASSWORD":             ("OKTA_CREDENTIAL_PROVIDER",   "PASSWORD",             "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"),
    "OIE_OKTA_VERIFY_PUSH": ("OKTA_CREDENTIAL_PROVIDER",   "OKTA_VERIFY_PUSH",     "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"),
    "PUSH":                 ("OKTA_CREDENTIAL_PROVIDER",   "OKTA_VERIFY_PUSH",     "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"),
    "SIGNED_NONCE":         ("OKTA_CREDENTIAL_PROVIDER",   "SIGNED_NONCE",         "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"),
    "SMS":                  ("OKTA_CREDENTIAL_PROVIDER",   "SMS",                  "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"),
    "EMAIL":                ("OKTA_CREDENTIAL_PROVIDER",   "EMAIL",                "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"),
    "TOTP":                 ("GOOGLE_CREDENTIAL_PROVIDER", "TOKEN:SOFTWARE:TOTP",  "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"),
}

# Realistic Okta request URIs — mix of IDX/OAuth endpoints (with ?) and SAML paths
_SAML_URLS = [
    # IDX authentication flow endpoints (always have query params in real logs)
    "/idp/idx/identify?",
    "/idp/idx/challenge?",
    "/idp/idx/challenge/answer?",
    "/idp/idx/authenticators/poll?",
    "/idp/idx/credential/enroll?",
    # OAuth 2.0 / token endpoints
    "/oauth2/v1/token?",
    "/oauth2/v1/authorize?",
    "/oauth2/v1/userinfo?",
    # Internal API endpoints
    "/api/internal/v1/mappings?",
    "/api/v1/authn?",
    # SAML SSO app endpoints (no query params)
    "/app/salesforce/sso/saml",
    "/app/microsoft_office_365/sso/saml",
    "/app/servicenow/sso/saml",
    "/app/workday/sso/saml",
    "/app/slack/sso/saml",
    "/login/login.htm",
]



import hashlib

try:
    from modules.session_utils import get_random_user, get_user_by_name, get_all_emails
except ImportError:
    from session_utils import get_random_user, get_user_by_name, get_all_emails

# Stable alphanumeric Okta user ID: 00u + 17 base-62 chars, deterministic per username.
# SHA-1 of the username is used as the seed so the same user always gets the same ID,
# even across restarts — matching how real Okta assigns permanent user IDs.
_ALPHANUM_62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def _stable_user_id(username):
    """Return a stable Okta-format user ID (00u + 17 alphanumeric chars) for a username."""
    n = int(hashlib.sha1(username.encode()).hexdigest(), 16)
    chars = []
    for _ in range(17):
        n, r = divmod(n, 62)
        chars.append(_ALPHANUM_62[r])
    return "00u" + "".join(chars)

# ISO-3166-1 alpha-2 → full country name (as Okta geographicalContext returns it)
_COUNTRY_NAMES = {
    "US": "United States",  "GB": "United Kingdom", "CA": "Canada",
    "AU": "Australia",      "DE": "Germany",         "FR": "France",
    "JP": "Japan",          "CN": "China",           "RU": "Russia",
    "IN": "India",          "BR": "Brazil",          "NL": "Netherlands",
    "SE": "Sweden",         "IT": "Italy",           "ES": "Spain",
    "CH": "Switzerland",    "CZ": "Czech Republic",  "FI": "Finland",
    "KR": "South Korea",    "KP": "North Korea",     "RO": "Romania",
    "AR": "Argentina",      "IR": "Iran",            "NG": "Nigeria",
    "PH": "Philippines",    "UA": "Ukraine",         "VN": "Vietnam",
    "ZA": "South Africa",   "MX": "Mexico",          "SG": "Singapore",
    "HK": "Hong Kong",      "PK": "Pakistan",        "EG": "Egypt",
    "SA": "Saudi Arabia",   "TH": "Thailand",        "ID": "Indonesia",
}

def _country_name(code):
    """Convert ISO-2 country code to full name. Falls back to code if unknown."""
    return _COUNTRY_NAMES.get(str(code).upper(), code)

# --- UTILITY ---

def _get_threat_interval(threat_level, config):
    return config.get("threat_generation_levels", {}).get(threat_level, 7200)


def _get_random_ip_and_context(config, source_list_key="benign_ingress_sources"):
    source_list = config.get(source_list_key, [{}])
    if not source_list:
        return {"ip": "203.0.113.1", "city": "New York", "country": "US",
                "state": "New York", "isp": "ExampleISP", "asn": 65500, "domain": "examplecorp.com", "is_proxy": False}
    source = random.choice(source_list)
    ip_range = source.get("ip_range")
    ip = source.get("ip")
    if ip_range:
        network = ip_network(ip_range, strict=False)
        # Safe for all subnet sizes including /31 and /32
        max_idx = network.num_addresses - 1
        ip = str(network[random.randint(0, max_idx)])
    # Fallback if source entry had no ip/ip_range defined
    if not ip:
        ip = "203.0.113." + str(random.randint(1, 254))
    return {"ip": ip, **source}


def _get_random_user_info(config, session_context=None):
    if session_context:
        user = get_random_user(session_context)
        if user:
            return {"username": user["username"], "full_name": user["display_name"]}
    # Legacy fallback
    users = config.get("zscaler_config", {}).get("device_map", {})
    if not users:
        return {"username": "default.user", "full_name": "Default User"}
    username, user_details = random.choice(list(users.items()))
    return {"username": username, "full_name": user_details.get("owner", "Unknown User")}


# --- BLOCK BUILDERS ---

def _build_actor(username, full_name):
    return {
        "id":          _stable_user_id(username),
        "type":        "User",
        "alternateId": username if "@" in username else f"{username}@examplecorp.com",
        "displayName": full_name,
        "detailEntry": None,
    }


def _build_admin_actor(config, session_context=None):
    if session_context:
        user = get_random_user(session_context, preferred_device_type="workstation")
        if user:
            username  = user["username"]
            full_name = user["display_name"]
            return {
                "id":          _stable_user_id(username),
                "type":        "User",
                "alternateId": username if "@" in username else f"{username}@examplecorp.com",
                "displayName": full_name,
                "detailEntry": None,
            }
    # Legacy fallback
    users = config.get("zscaler_config", {}).get("device_map", {})
    if users:
        username, details = random.choice(list(users.items()))
        full_name = details.get("owner", "Admin User")
    else:
        username, full_name = "admin.user", "Admin User"
    return {
        "id":          _stable_user_id(username),
        "type":        "User",
        "alternateId": username if "@" in username else f"{username}@examplecorp.com",
        "displayName": full_name,
        "detailEntry": None,
    }


def _build_client(ip_context, config, interactive_only=False):
    _default_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
    ]
    # Filter out None/empty entries; fall back to defaults if list is empty or missing
    all_uas = [ua for ua in config.get("user_agents", []) if ua and isinstance(ua, str)]
    if not all_uas:
        all_uas = _default_uas

    # UAs that should never appear on interactive login events
    _BOT_MARKERS = ("Googlebot", "Bingbot", "bot", "crawler", "spider")

    if interactive_only:
        # Must be a real browser UA — exclude bots/crawlers even if they contain "Mozilla"
        browser_agents = [
            ua for ua in all_uas
            if "Mozilla" in ua and not any(m.lower() in ua.lower() for m in _BOT_MARKERS)
        ]
        ua_string = random.choice(browser_agents) if browser_agents else _default_uas[0]
    else:
        # Weight real browsers 3:1 over tools/bots so Unknown OS stays rare
        browser_agents = [
            ua for ua in all_uas
            if "Mozilla" in ua and not any(m.lower() in ua.lower() for m in _BOT_MARKERS)
        ]
        other_agents = [ua for ua in all_uas if ua not in browser_agents]
        weighted_pool = browser_agents * 3 + other_agents
        ua_string = random.choice(weighted_pool) if weighted_pool else all_uas[0]

    # Parse OS with version — matches what Okta's UA parser returns
    def _parse_os(ua):
        if "Windows NT 10.0" in ua: return "Windows 10"
        if "Windows NT 11.0" in ua: return "Windows 11"
        if "Windows NT 6.3"  in ua: return "Windows 8.1"
        if "Windows NT 6.2"  in ua: return "Windows 8"
        if "Windows NT 6.1"  in ua: return "Windows 7"
        if "Windows NT"      in ua: return "Windows"
        if "Macintosh"       in ua: return "Mac OS X"
        m = re.search(r"iPhone OS ([\d_]+)", ua)
        if m: return "iOS " + m.group(1).replace("_", ".")
        m = re.search(r"Android ([\d.]+)", ua)
        if m: return "Android " + m.group(1)
        if "Linux"           in ua: return "Linux"
        return "Unknown"

    # Browser — Okta returns uppercase strings
    def _parse_browser(ua):
        if "Edg/" in ua or "Edge/" in ua: return "CHROMIUM_EDGE"
        if "Chrome"   in ua: return "CHROME"
        if "Firefox"  in ua: return "FIREFOX"
        if "Safari"   in ua and "Chrome" not in ua: return "SAFARI"
        if "curl"     in ua or "Boto" in ua or "python" in ua.lower(): return "UNKNOWN"
        return "UNKNOWN"

    os_name  = _parse_os(ua_string)
    device   = "Mobile" if ("iPhone" in ua_string or "Android" in ua_string) else "Computer"
    browser_match = True  # placeholder — using _parse_browser directly below
    ip       = ip_context.get("ip")

    return {
        "id":     None,
        "device": device,
        "userAgent": {
            "rawUserAgent": ua_string,
            "os":           os_name,
            "browser":      _parse_browser(ua_string),
        },
        "ipAddress": ip,
        "geographicalContext": {
            "city":        ip_context.get("city"),
            "country":     _country_name(ip_context.get("country", "")),  # full name per Okta API
            "state":       ip_context.get("state"),
            "postalCode":  None,
            "geolocation": {
                "lat": round(random.uniform(-90, 90),   4),
                "lon": round(random.uniform(-180, 180), 4),
            },
        },
        "zone": "null",  # Okta returns the string "null" when no named zone matches
    }


def _build_authentication_context(credential_type="PASSWORD"):
    cred_provider, _, authn_ref = _MFA_FACTOR_MAP.get(
        credential_type,
        ("OKTA_CREDENTIAL_PROVIDER", "password_as_factor", "urn:oasis:names:tc:SAML:2.0:ac:classes:Password")
    )
    return {
        "authenticationProvider": _AUTH_PROVIDER_FOR_CRED.get(credential_type),
        "credentialProvider":     cred_provider,
        "credentialType":         credential_type,
        "externalSessionId":      f"ext-session-{uuid.uuid4()}",
        "authnContextClassRef":   authn_ref,
        "issuer":                 None,
        "interface":              None,
        "authenticationStep":     0,
    }


def _build_security_context(ip_context):
    return {
        "asNumber": ip_context.get("asn"),
        "asOrg":    ip_context.get("isp"),
        "domain":   ip_context.get("domain", "examplecorp.com"),
        "isProxy":  ip_context.get("is_proxy", False),
        "isp":      ip_context.get("isp"),
    }


def _build_request(client_block):
    geo = client_block.get("geographicalContext", {})
    return {
        "ipChain": [{
            "ip":  client_block.get("ipAddress"),
            "geographicalContext": {
                "city":       geo.get("city"),
                "country":    _country_name(geo.get("country", "")),  # full name
                "state":      geo.get("state"),
                "postalCode": geo.get("postalCode"),
                "geolocation": geo.get("geolocation", {}),
            },
            "version": "V4",
            "source":  None,
        }]
    }


# --- THREAT / BEHAVIOR FORMATTERS ---



# Okta Behavior Detection Engine only runs during user authentication flows.
# behaviors and risk are ONLY present in debugData for these event types:
#   user.session.start, user.authentication.auth_via_mfa, user.authentication.verify
# All other events (lifecycle, admin, policy, OAuth, SSO) have no behaviors field.
_AUTH_BEHAVIORS_NEGATIVE = (
    "{New Geo-Location=NEGATIVE, New Device=NEGATIVE, "
    "New IP=NEGATIVE, New State=NEGATIVE, New Country=NEGATIVE, "
    "Velocity Behavior=NEGATIVE, New City=NEGATIVE}"
)
_AUTH_DEBUG_DEFAULTS = {
    "risk":            "{level=LOW}",
    "behaviors":       _AUTH_BEHAVIORS_NEGATIVE,
    "threatSuspected": "false",
}


def _build_debug_context(credential_type="PASSWORD", extra=None, include_auth_signals=False,
                         okta_domain="https://examplecorp.okta.com"):
    """
    Build debugContext block.

    include_auth_signals=True  ->  add behaviors + risk + origin (only for auth events:
                                   user.session.start, user.authentication.auth_via_mfa,
                                   user.authentication.verify).
    include_auth_signals=False ->  no behaviors/risk/origin (correct for lifecycle, admin,
                                   policy, OAuth, SSO, and all non-auth events).
    """
    _, factor_value, _ = _MFA_FACTOR_MAP.get(
        credential_type,
        ("OKTA_CREDENTIAL_PROVIDER", "password_as_factor", "urn:oasis:names:tc:SAML:2.0:ac:classes:Password")
    )
    url_path = random.choice(_SAML_URLS)
    # requestUri is the path without query string; url includes trailing ?
    request_uri = url_path.rstrip("?")
    is_mfa = credential_type not in ("PASSWORD", None)
    data = {
        "requestId":         uuid.uuid4().hex,
        "dtHash":            uuid.uuid4().hex + uuid.uuid4().hex,  # 64-char hex like real Okta dtHash
        "deviceFingerprint": uuid.uuid4().hex[:32],
        "requestUri":        request_uri,
        "url":               url_path,
    }
    if is_mfa:
        data["factor"] = factor_value
    if include_auth_signals:
        data.update(_AUTH_DEBUG_DEFAULTS)
        data["origin"] = okta_domain  # present on interactive login events
    if extra:
        data.update(extra)
    return {"debugData": data}


def _build_transaction():
    return {
        "type":   "WEB",
        "id":     uuid.uuid4().hex,
        "detail": {},
    }


def _build_transaction_api():
    """Transaction block for API token events — includes requestApiTokenId."""
    return {
        "type":   "WEB",
        "id":     uuid.uuid4().hex,
        "detail": {"requestApiTokenId": uuid.uuid4().hex},
    }


def _build_target_user(actor):
    return [{"id": actor["id"], "type": "User",
             "alternateId": actor["alternateId"],
             "displayName": actor["displayName"],
             "detailEntry": None}]


# --- CORE ASSEMBLER ---

# Maps modern eventType → legacy eventType string (from real Okta System Log samples).
# Events not in this dict have legacyEventType=None.
# user.session.start is outcome-dependent: handled inline in _assemble.
_LEGACY_EVENT_TYPES = {
    "user.authentication.auth_via_mfa":                       "core.user.factor.attempt_success",
    "user.authentication.sso":                                "app.auth.sso",
    "user.mfa.factor.activate":                               "core.user.factor.activate",
    "user.mfa.factor.reset_all":                              "core.user.factor.reset_all",
    "user.account.privilege.grant":                           "core.user.admin_privilege.granted",
    "user.account.lock":                                      "core.user_auth.account_locked",
    "user.account.update_password":                           "core.user.config.password_update.success",
    "group.user_membership.add":                              "core.user_group_member.user_add",
    "group.user_membership.remove":                           "core.user_group_member.user_remove",
    "system.api_token.create":                                "api.token.create",
    "system.api_token.revoke":                                "api.token.revoke",
    "user.authentication.auth_via_radius":                    "core.user_auth.radius.login_success",
    "user.session.impersonation.grant":                       "core.user.impersonation.grant.enabled",
    "user.session.end":                                       "core.user_auth.logout_success",
    "security.threat.detected":                               "security.threat.detected",
    "user.account.report_suspicious_activity_by_enduser":     "core.user.account.report_suspicious_activity_by_enduser",
}


def _assemble(event_type, actor, client, outcome,
              severity="INFO", display_message="",
              authentication_context=None, security_context=None,
              debug_context=None, target=None, legacy_event_type=None,
              transaction=None):
    if authentication_context is None:
        authentication_context = _build_authentication_context()
    if security_context is None:
        security_context = {"asNumber": None, "asOrg": None,
                            "domain": "examplecorp.com", "isProxy": False, "isp": None}
    if debug_context is None:
        debug_context = _build_debug_context()

    # Resolve legacyEventType from lookup; caller may override explicitly.
    if legacy_event_type is None:
        if event_type == "user.session.start":
            legacy_event_type = (
                "core.user_auth.login_success"
                if outcome.get("result") == "SUCCESS"
                else "core.user.factor.attempt_fail"
            )
        else:
            legacy_event_type = _LEGACY_EVENT_TYPES.get(event_type)

    # For SSO events, append an AppUser target entry (matches real Okta logs).
    if event_type == "user.authentication.sso" and target:
        if not any(t.get("type") == "AppUser" for t in target):
            target = list(target) + [{
                "id":          f"0ua{uuid.uuid4().hex[:17]}",
                "type":        "AppUser",
                "displayName": actor.get("displayName", ""),
                "alternateId": actor.get("alternateId", "unknown"),
                "detailEntry": None,
            }]

    event = {
        "uuid":             str(uuid.uuid4()),
        "published":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "eventType":        event_type,
        "legacyEventType":  legacy_event_type,
        "version":          "0",
        "severity":         severity,
        "displayMessage":   display_message,
        "actor":            actor,
        "client":           client,
        "outcome":          outcome,
        "target":           target or [],
        "device":           None,
        "request":          _build_request(client),
        "transaction":      transaction if transaction is not None else _build_transaction(),
        "authenticationContext": authentication_context,
        "securityContext":  security_context,
        "debugContext":     debug_context,
    }
    return json.dumps(event, default=str)


# --- BACKGROUND EVENTS ---

# Authenticator display names for user.session.start AuthenticatorEnrollment targets
_AUTHN_ENROLL_NAMES = {
    "PASSWORD":             "Password",
    "OIE_OKTA_VERIFY_PUSH": "Okta Verify",
    "PUSH":                 "Okta Verify",
    "TOTP":                 "Google Authenticator",
    "SMS":                  "Okta SMS",
    "EMAIL":                "Okta Email",
    "SIGNED_NONCE":         "Okta FastPass",
}

def _session_start_targets(credential_type="PASSWORD"):
    """
    Real Okta user.session.start events include two target entries:
    1. AuthenticatorEnrollment — the factor used (e.g. Password, Okta Verify)
    2. AppInstance — the app the session was established for (Okta Dashboard on direct login)
    """
    factor_name = _AUTHN_ENROLL_NAMES.get(credential_type, "Password")
    return [
        {
            "id":          f"lae{uuid.uuid4().hex[:17]}",
            "type":        "AuthenticatorEnrollment",
            "displayName": factor_name,
            "alternateId": "unknown",
            "detailEntry": None,
        },
        {
            "id":          _app_instance_id("Okta Dashboard"),
            "type":        "AppInstance",
            "displayName": "Okta Dashboard",
            "alternateId": "Okta Dashboard",
            "detailEntry": {"signOnModeType": "SAML_2_0"},
        },
    ]


def _generate_successful_login(config, user_info, session_context=None, ip_ctx=None):
    ip_ctx  = ip_ctx or _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.session.start", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", include_auth_signals=True),
        target=_session_start_targets("PASSWORD"),
    )


def _generate_sso_access(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Microsoft Office 365"]))
    target = [{"id": _app_instance_id(app), "type": "AppInstance",
               "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}]
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="User single sign on to app",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=target,
    )


def _generate_mfa_verify(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    cred   = random.choice(["OIE_OKTA_VERIFY_PUSH", "TOTP", "SMS", "EMAIL"])
    return _assemble(
        "user.authentication.auth_via_mfa", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Authentication of user via MFA",
        authentication_context=_build_authentication_context(cred),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context(cred, include_auth_signals=True),
    )


def _generate_password_reset(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.account.update_password", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Update password for user",
        target=_build_target_user(actor),
    )


# --- ACCOUNT UNLOCK EVENTS ---

def _generate_account_unlock_self(config, user_info, session_context=None):
    """user.account.unlock — user self-unlocks (feeds 'Okta account unlock' detection)."""
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.account.unlock", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Unlock user account",
        authentication_context=_build_authentication_context("EMAIL"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("EMAIL"),
        target=_build_target_user(actor),
    )


def _generate_account_unlock_by_admin(config, user_info, session_context=None):
    """user.account.unlock_by_admin — admin unlocks user (feeds 'Okta account unlock by admin' detection)."""
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    return _assemble(
        "user.account.unlock_by_admin", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Admin-initiated user unlock for Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_build_target_user(target_user),
    )


def _generate_account_lock(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    return _assemble(
        "user.account.lock", actor, client,
        outcome={"result": "FAILURE", "reason": "LOCKED_OUT"},
        severity="WARN", display_message="Max sign in attempts exceeded",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={"loginResult": "LOCKED_OUT"}),
        target=_build_target_user(actor),
    )


def _generate_account_unlock_token(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.account.unlock_token", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Generate user unlock token",
        target=_build_target_user(actor),
    )


# --- THREAT EVENTS ---

def _generate_failed_login(config, user_info, ip_ctx=None, session_context=None):
    if ip_ctx is None:
        ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    reason = random.choice(["INVALID_CREDENTIALS", "LOCKED_OUT", "ACCOUNT_SUSPENDED"])
    return _assemble(
        "user.session.start", actor, client,
        outcome={"result": "FAILURE", "reason": reason},
        severity="WARN", display_message=f"User login to Okta failed: {reason}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={"loginResult": reason}, include_auth_signals=True),
    )


def _generate_brute_force_sequence(config, user_info, session_context=None):
    """Failed logins -> account lock -> admin unlock."""
    print("    - Okta Module generating brute force + lockout + unlock sequence...")
    logs = []
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    for _ in range(random.randint(3, 7)):
        logs.append(_generate_failed_login(config, user_info, ip_ctx=ip_ctx))
    logs.append(_generate_account_lock(config, user_info))
    logs.append(_generate_account_unlock_by_admin(config, user_info))
    return logs


def _generate_benign_retry(config, user_info, session_context=None):
    """
    Normal user mistyping their password once or twice then successfully logging in.
    Generates 1-2 INVALID_CREDENTIALS failures from the same IP, followed by a SUCCESS
    from that same IP for the same user.

    Added to the background multi pool so it appears naturally in baseline traffic.
    Also in the threat pool as 'benign_retry' so UEBA signature writers can trigger
    it explicitly to verify their rules correctly handle low-failure noise.
    """
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(ip_ctx)
    logs = []

    # 1-2 failed attempts — INVALID_CREDENTIALS only (not LOCKED_OUT, that needs repeated failures)
    for _ in range(random.randint(1, 2)):
        logs.append(_assemble(
            "user.session.start", actor, client,
            outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            severity="WARN", display_message="User login to Okta failed: INVALID_CREDENTIALS",
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD",
                extra={"loginResult": "INVALID_CREDENTIALS"}, include_auth_signals=True),
        ))

    # Successful login — same IP, same user
    logs.append(_assemble(
        "user.session.start", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", include_auth_signals=True),
        target=_session_start_targets("PASSWORD"),
    ))
    return logs


def _generate_tor_login(config, user_info, session_context=None):
    print("    - Okta Module generating TOR login event...")
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    return [_assemble(
        "user.session.start", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}",
            "behaviors": "{New Geo-Location=POSITIVE, New Device=NEGATIVE, New IP=POSITIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity Behavior=NEGATIVE, New City=NEGATIVE}",
            "threatSuspected": "true",
            "proxyType": "TOR",
            "threatDetections": json.dumps({"TOR Exit Node": "HIGH"}),
        }),
        target=_session_start_targets("PASSWORD"),
    )]


def _generate_policy_deny(config, user_info, session_context=None):
    print("    - Okta Module generating policy deny event...")
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=False)
    reason  = random.choice(config.get("okta_threat_events", {}).get("policy_deny_reasons", ["RISK_LEVEL_HIGH"]))
    return [_assemble(
        "policy.evaluate_sign_on", actor, client,
        outcome={"result": "FAILURE", "reason": reason},
        severity="WARN", display_message=f"Sign-on policy evaluation failed: {reason}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={"risk": "{level=MEDIUM}"}),
    )]


def _generate_mfa_bombing_sequence(config, user_info, session_context=None):
    print("    - Okta Module generating MFA bombing (fatigue) sequence...")
    logs    = []
    ip_ctx  = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=False)
    sec_ctx = _build_security_context(ip_ctx)
    auth_ctx = _build_authentication_context("OIE_OKTA_VERIFY_PUSH")

    logs.append(_assemble(
        "user.authentication.verify", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Verify user identity",
        authentication_context=auth_ctx, security_context=sec_ctx,
    ))
    num_bombs = random.randint(10, 20)
    print(f"      -> Sending {num_bombs} MFA push notifications...")
    for _ in range(num_bombs):
        logs.append(_assemble(
            "system.push.send_factor_verify_push", actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="INFO", display_message="MFA push challenge sent",
            authentication_context=auth_ctx, security_context=sec_ctx,
        ))
        logs.append(_assemble(
            "user.mfa.okta_verify.deny_push", actor, client,
            outcome={"result": "FAILURE", "reason": "USER_REJECTED_OKTA_VERIFY_PUSH"},
            severity="WARN", display_message="User rejected Okta Verify push notification",
            authentication_context=auth_ctx, security_context=sec_ctx,
            debug_context=_build_debug_context("OIE_OKTA_VERIFY_PUSH", extra={
                "risk": "{level=HIGH}"
            }),
        ))
    return logs


# ---------------------------------------------------------------------------
# NEW DETECTION GENERATORS — 19 additional XSIAM/XDR Okta detections
# ---------------------------------------------------------------------------

# --- USER LIFECYCLE ---

def _generate_user_suspended(config, user_info, session_context=None):
    """user.lifecycle.suspend — admin suspends a user account."""
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    return _assemble(
        "user.lifecycle.suspend", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Suspend Okta user",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_build_target_user(target_user),
    )


def _generate_user_deactivated(config, user_info, session_context=None):
    """user.lifecycle.deactivate — admin deactivates (offboards) a user."""
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    return _assemble(
        "user.lifecycle.deactivate", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Deactivate Okta user",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_build_target_user(target_user),
    )


def _generate_password_reset_by_admin(config, user_info, session_context=None):
    """user.account.reset_password — admin resets a user's password."""
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    return _assemble(
        "user.account.reset_password", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Reset password for user",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_build_target_user(target_user),
    )


# --- MFA / DEVICE ---

def _generate_mfa_factor_enrolled(config, user_info, session_context=None):
    """user.mfa.factor.activate — user enrolls a new MFA factor."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    cred   = random.choice(["OIE_OKTA_VERIFY_PUSH", "TOTP", "SMS", "EMAIL", "SIGNED_NONCE"])
    factor_names = {
        "OIE_OKTA_VERIFY_PUSH": "Okta Verify",
        "TOTP":                 "Google Authenticator",
        "SMS":                  "SMS",
        "EMAIL":                "Email",
        "SIGNED_NONCE":         "Okta FastPass",
    }
    factor_name = factor_names.get(cred, "Unknown Factor")
    target = [{
        "id":          f"mfa-{uuid.uuid4()}",
        "type":        "AuthenticatorEnrollment",
        "displayName": factor_name,
        "alternateId": cred,
        "detailEntry": None,
    }]
    return _assemble(
        "user.mfa.factor.activate", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"User activated {factor_name}",
        authentication_context=_build_authentication_context(cred),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context(cred),
        target=target,
    )


def _generate_mfa_factor_reset_by_admin(config, user_info, session_context=None):
    """user.mfa.factor.reset_all — admin resets all MFA factors for a user."""
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    return _assemble(
        "user.mfa.factor.reset_all", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="Reset all factors for user",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_build_target_user(target_user),
    )


def _generate_mfa_bypass_attempt(config, user_info, session_context=None):
    """
    user.mfa.attempt_bypass — user attempts to skip MFA.
    Feeds 'A user attempted to bypass Okta MFA' detection.
    """
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    sec_ctx = _build_security_context(ip_ctx)
    dbg_ctx = _build_debug_context("PASSWORD", extra={
        "risk":            "{level=HIGH}",
        "behaviors":       "{New Geo-Location=NEGATIVE, New Device=NEGATIVE, New IP=NEGATIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity Behavior=NEGATIVE, New City=NEGATIVE}",
        "threatSuspected": "false",
    })
    return _assemble(
        "user.mfa.attempt_bypass", actor, client,
        outcome={"result": "FAILURE", "reason": "MFA_ENROLLMENT_REQUIRED"},
        severity="WARN", display_message="User attempted to bypass MFA",
        security_context=sec_ctx,
        debug_context=dbg_ctx,
    )


def _generate_new_device_enrolled(config, user_info, session_context=None):
    """
    device.enrollment.create + user.mfa.factor.activate sequence.
    Feeds 'User added a new device to Okta Verify instance' detection.
    """
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(ip_ctx)

    device_id = f"guuid{uuid.uuid4().hex[:20]}"
    os_types  = ["Windows", "macOS", "iOS", "Android"]
    os_choice = random.choice(os_types)
    device_target = [{
        "id":          device_id,
        "type":        "Device",
        "displayName": f"{user_info['full_name']}'s {os_choice} Device",
        "alternateId": f"serial-{uuid.uuid4().hex[:12].upper()}",
        "detailEntry": {
            "platform":  os_choice,
            "osVersion": "latest",
            "managed":   False,
            "registered": True,
        },
    }]

    logs = []
    logs.append(_assemble(
        "device.enrollment.create", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Enroll new device",
        security_context=sec_ctx,
        debug_context=_build_debug_context("SIGNED_NONCE"),
        target=device_target,
    ))
    logs.append(_assemble(
        "user.mfa.factor.activate", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="User activated Okta Verify",
        authentication_context=_build_authentication_context("OIE_OKTA_VERIFY_PUSH"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("OIE_OKTA_VERIFY_PUSH"),
        target=[{
            "id":          f"mfa-{uuid.uuid4()}",
            "type":        "AuthenticatorEnrollment",
            "displayName": "Okta Verify",
            "alternateId": "OIE_OKTA_VERIFY_PUSH",
            "detailEntry": None,
        }],
    ))
    return logs


def _generate_device_assigned(config, user_info, session_context=None):
    """device.user.add — device assigned to a user. Feeds 'Okta device assignment' detection."""
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    os_types    = ["Windows", "macOS", "iOS", "Android"]
    os_choice   = random.choice(os_types)
    targets = [
        {
            "id":          f"guuid{uuid.uuid4().hex[:20]}",
            "type":        "Device",
            "displayName": f"{user_info['full_name']}'s {os_choice} Device",
            "alternateId": f"serial-{uuid.uuid4().hex[:12].upper()}",
            "detailEntry": None,
        },
        _build_target_user(target_user)[0],
    ]
    return _assemble(
        "device.user.add", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Add device to user",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=targets,
    )


# --- GROUP MEMBERSHIP ---

def _generate_group_membership_add(config, user_info, session_context=None):
    """group.user_membership.add — user added to a group. Feeds group membership detection."""
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    groups = [
        "Everyone", "IT Admins", "Finance Team", "Engineering", "Sales",
        "HR", "Executives", "VPN Users", "Security Team", "Contractors",
        "Temp MFA Bypass", "Super Admins", "Cloud Access",
    ]
    group = random.choice(groups)
    targets = [
        _build_target_user(target_user)[0],
        {
            "id":          f"grp{uuid.uuid4().hex[:20]}",
            "type":        "UserGroup",
            "displayName": group,
            "alternateId": group,
            "detailEntry": None,
        },
    ]
    return _assemble(
        "group.user_membership.add", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Add user to group membership",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=targets,
    )


def _generate_group_membership_remove(config, user_info, session_context=None):
    """group.user_membership.remove — user removed from a group."""
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    groups = ["IT Admins", "VPN Users", "Temp MFA Bypass", "Super Admins", "Contractors"]
    group  = random.choice(groups)
    targets = [
        _build_target_user(target_user)[0],
        {
            "id":          f"grp{uuid.uuid4().hex[:20]}",
            "type":        "UserGroup",
            "displayName": group,
            "alternateId": group,
            "detailEntry": None,
        },
    ]
    return _assemble(
        "group.user_membership.remove", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Remove user from group membership",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=targets,
    )


# --- PRIVILEGE & ADMIN ACCESS ---

def _generate_admin_privilege_grant(config, user_info, session_context=None):
    """
    user.account.privilege.grant — admin role granted to user.
    Feeds 'Okta admin privilege assignment' detection.
    """
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    _ROLE_DISPLAY = {
        "SUPER_ADMIN":      "Super administrator",
        "ORG_ADMIN":        "Organization administrator",
        "APP_ADMIN":        "Application administrator",
        "USER_ADMIN":       "User administrator",
        "GROUP_ADMIN":      "Group administrator",
        "HELP_DESK_ADMIN":  "Help desk administrator",
    }
    role = random.choice(list(_ROLE_DISPLAY))
    return _assemble(
        "user.account.privilege.grant", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="Grant user privilege",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={"privilegeGranted": _ROLE_DISPLAY[role]}),
        target=[_build_target_user(target_user)[0]],
    )


def _generate_admin_app_access(config, user_info, session_context=None):
    """
    user.authentication.sso to Okta Admin Console.
    Feeds 'A user accessed Okta admin application' detection.
    """
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    target = [{
        "id":          _app_instance_id("Okta Admin Console"),
        "type":        "AppInstance",
        "displayName": "Okta Admin Console",
        "alternateId": "Okta Admin Console",
        "detailEntry": {"signOnModeType": "SAML_2_0"},
    }]
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User single sign on to app",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=target,
    )


# --- API & RATE LIMITS ---

def _generate_api_token_created(config, user_info, session_context=None):
    """
    system.api_token.create — new API token created.
    Feeds 'Okta API Token Created' detection.
    """
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=True)
    token_name = random.choice([
        "CI/CD Pipeline Token", "SIEM Integration", "Automation Token",
        "Monitoring Service", "Backup Integration", "Custom App Token",
    ])
    target = [{
        "id":          f"token-{uuid.uuid4().hex[:20]}",
        "type":        "Token",
        "displayName": token_name,
        "alternateId": token_name,
        "detailEntry": None,
    }]
    return _assemble(
        "system.api_token.create", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Create API token",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=target,
    )


def _generate_rate_limit_breach(config, user_info, session_context=None):
    """
    system.api.rate_limit.violation — API rate limit hit.
    Feeds 'Potential Okta access limit breach' detection.
    """
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    endpoints = [
        "/api/v1/users", "/api/v1/sessions", "/api/v1/authn",
        "/api/v1/logs", "/api/v1/apps",
    ]
    endpoint = random.choice(endpoints)
    dbg_ctx = _build_debug_context("PASSWORD", extra={
        "rateLimitWarning":   "true",
        "rateLimitEndpoint":  endpoint,
        "rateLimitMultiplier": str(random.randint(2, 10)),
        "remainingRequests":  str(random.randint(0, 10)),
    })
    return _assemble(
        "system.api.rate_limit.violation", actor, client,
        outcome={"result": "FAILURE", "reason": "RATE_LIMIT_EXCEEDED"},
        severity="WARN", display_message=f"Rate limit violation on {endpoint}",
        security_context=_build_security_context(ip_ctx),
        debug_context=dbg_ctx,
    )


# --- SUSPICIOUS / REPORTED ACTIVITY ---

def _generate_fastpass_phishing_detected(config, user_info, session_context=None):
    """
    user.authentication.auth_via_mfa with outcome.reason = 'FastPass declined phishing attempt'

    Fired when a user enrolled in Okta FastPass hits an AiTM (Adversary-in-the-Middle)
    phishing proxy. FastPass detects the origin mismatch between the device and the
    proxy and blocks the attempt. The client IP is the proxy, not the user's real IP.

    The debugContext.debugData.logOnlySecurityData field contains the phishing URL and
    the mismatched origin header — key forensic details for hunting the phishing infra.

    Documented detection query (Okta Security, 2022):
      eventType eq "user.authentication.auth_via_mfa"
      AND outcome.result eq "FAILURE"
      AND outcome.reason eq "FastPass declined phishing attempt"

    Referenced in: Splunk Security Content, Azure Sentinel, Elastic SIEM, Okta sec.okta.com
    """
    # AiTM proxy IPs — attacker's reverse proxy sitting between victim and Okta
    _AITM_PROXY_IPS = [
        {"ip": "91.108.4.1",    "city": None, "country": "NL", "asn": 62041,  "isp": "Telegram Messenger", "domain": "telegram.org",   "is_proxy": True},
        {"ip": "185.220.101.5", "city": None, "country": "DE", "asn": 60729,  "isp": "Zwiebeldienst e.V.",  "domain": "tor-exit.de",     "is_proxy": True},
        {"ip": "94.232.43.12",  "city": None, "country": "RU", "asn": 197695, "isp": "RegRu Hosting",       "domain": "reg.ru",          "is_proxy": True},
        {"ip": "162.247.74.27", "city": None, "country": "US", "asn": 396507, "isp": "Quintex Alliance",    "domain": "torproject.org",  "is_proxy": True},
        {"ip": "45.142.212.100","city": None, "country": "NL", "asn": 210644, "isp": "Aeza International",  "domain": "aeza.net",        "is_proxy": True},
        {"ip": "45.227.255.4",  "city": None, "country": "BR", "asn": 267784, "isp": "Flyservers S.A.",     "domain": "flyservers.com",  "is_proxy": True},
    ]

    # Realistic phishing domain/URL patterns mimicking Okta login pages
    _PHISHING_DOMAINS = [
        "okta-secure-login.{tld}",
        "login-okta-verify.{tld}",
        "okta-sso-portal.{tld}",
        "verify-okta-account.{tld}",
        "okta-workforce-login.{tld}",
    ]
    _PHISHING_TLDS = ["com", "net", "co", "xyz", "io", "online"]

    import random as _r
    proxy_ctx = _r.choice(_AITM_PROXY_IPS)
    domain = _r.choice(_PHISHING_DOMAINS).format(tld=_r.choice(_PHISHING_TLDS))
    phishing_url = f"https://{domain}/login/login.htm?fromURI=%2Fapp%2FuserHome"

    actor  = _build_actor(user_info["username"], user_info["full_name"])
    # FastPass is device-bound — user is on a managed desktop/laptop
    fp_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    ]
    ua_str = _r.choice(fp_uas)
    # The client block uses the proxy IP — that's what Okta sees at the origin check
    client = _build_client(proxy_ctx, config, interactive_only=False)
    client["userAgent"]["rawUserAgent"] = ua_str

    # logOnlySecurityData contains the phishing URL + mismatched origin (Okta OIE 2022)
    log_only = (
        f'{{"behaviors":{{}},"phishingUrl":"{phishing_url}",'
        f'"originCheckResult":"MISMATCH",'
        f'"requestedUri":"/idp/idx/challenge/answer?"}}'
    )

    return _assemble(
        "user.authentication.auth_via_mfa", actor, client,
        outcome={"result": "FAILURE", "reason": "FastPass declined phishing attempt"},
        severity="WARN",
        display_message="FastPass declined phishing attempt",
        authentication_context=_build_authentication_context("SIGNED_NONCE"),
        security_context={
            "asNumber": proxy_ctx.get("asn"),
            "asOrg":    proxy_ctx.get("isp"),
            "domain":   proxy_ctx.get("domain"),
            "isProxy":  True,
            "isp":      proxy_ctx.get("isp"),
        },
        debug_context=_build_debug_context("SIGNED_NONCE", extra={
            "risk":              "{level=HIGH}",
            "behaviors":         "{New Geo-Location=POSITIVE, New Device=NEGATIVE, New IP=POSITIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity Behavior=NEGATIVE, New City=NEGATIVE}",
            "threatSuspected":   "true",
            "logOnlySecurityData": log_only,
            "threatDetections":  json.dumps({"Phishing Attempt Blocked": "HIGH"}),
        }),
    )


def _generate_user_reported_suspicious(config, user_info, session_context=None):
    """
    user.account.report_suspicious_activity_by_enduser — user flags unexpected activity.
    Feeds 'A user observed and reported unusual activity in Okta' detection.
    """
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.account.report_suspicious_activity_by_enduser", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User report suspicious activity",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("OIE_OKTA_VERIFY_PUSH", extra={
            "risk": "{level=HIGH}",
            "threatSuspected":  "true",
            "reportedActivity": "unexpected_push_notification",
        }),
    )


def _generate_okta_threat_detected(config, user_info, session_context=None):
    """
    security.threat.detected — Okta ThreatInsight fires on a known-malicious IP.
    Feeds 'Okta Reported Threat Detected' and 'Okta Reported Attack Suspected' detections.

    Real Okta logs: actor is the source IP address (type="IP address"), not a User.
    outcome.reason is comma-separated human-readable threat names.
    threatDetections is a JSON-encoded string (not a nested object).
    """
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    ip     = ip_ctx.get("ip", "1.2.3.4")
    # Real Okta ThreatInsight actor is the suspicious IP, not a user
    actor  = {
        "id":          ip,
        "type":        "IP address",
        "alternateId": "unknown",
        "displayName": ip,
        "detailEntry": None,
    }
    client = _build_client(ip_ctx, config, interactive_only=False)

    # Real Okta threat combinations — comma-separated in outcome.reason
    _THREAT_COMBOS = [
        {
            "reason":     "Password Spray, Login Failures",
            "detections": {"Password Spray": "HIGH", "Login Failures": "MEDIUM"},
        },
        {
            "reason":     "Login failures with high unknown users count, Password Spray, Login Failures",
            "detections": {"Login failures with high unknown users count": "HIGH",
                           "Password Spray": "HIGH", "Login Failures": "MEDIUM"},
        },
        {
            "reason":     "Credential Stuffing",
            "detections": {"Credential Stuffing": "HIGH"},
        },
        {
            "reason":     "Brute Force Attacks",
            "detections": {"Brute Force Attacks": "HIGH"},
        },
    ]
    combo   = random.choice(_THREAT_COMBOS)
    sec_ctx = _build_security_context(ip_ctx)
    dbg_ctx = _build_debug_context("PASSWORD", extra={
        "threatSuspected": "true",
        "threatDetections": json.dumps(combo["detections"]),
    })
    return _assemble(
        "security.threat.detected", actor, client,
        outcome={"result": "DENY", "reason": combo["reason"]},
        severity="WARN", display_message="Request from suspicious actor",
        security_context=sec_ctx,
        debug_context=dbg_ctx,
    )


# --- SESSION IMPERSONATION ---

def _generate_session_impersonation(config, user_info, session_context=None):
    """
    user.session.impersonation.* sequence — admin impersonates a user.
    Feeds 'Okta User Session Impersonation' detection.
    """
    print("    - Okta Module generating session impersonation sequence...")
    logs        = []
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx     = _build_security_context(ip_ctx)
    target      = _build_target_user(target_user)

    for event_type, message in [
        ("user.session.impersonation.grant",    "Grant user session impersonation"),
        ("user.session.impersonation.initiate", "Initiate user session impersonation"),
        ("user.session.impersonation.extend",   "Extend user session impersonation"),
        ("user.session.impersonation.revoke",   "Revoke user session impersonation"),
    ]:
        logs.append(_assemble(
            event_type, admin_actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="WARN", display_message=message,
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD"),
            target=target,
        ))
    return logs


# --- IMPOSSIBLE TRAVEL ---

def _generate_impossible_travel_sequence(config, user_info, session_context=None):
    """
    Two user.session.start events from geographically impossible locations in short succession.
    Feeds 'Impossible travel' detection.
    """
    print("    - Okta Module generating impossible travel sequence...")
    logs = []

    # Location 1: benign home country
    ip_ctx1 = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client1 = _build_client(ip_ctx1, config, interactive_only=True)
    logs.append(_assemble(
        "user.session.start", actor, client1,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx1),
        debug_context=_build_debug_context("PASSWORD", include_auth_signals=True),
        target=_session_start_targets("PASSWORD"),
    ))

    # Location 2: attacker from TOR / foreign IP — minutes later, same user
    ip_ctx2 = _get_random_ip_and_context(config, "tor_exit_nodes")
    client2 = _build_client(ip_ctx2, config, interactive_only=False)
    sec_ctx2 = _build_security_context(ip_ctx2)
    dbg_ctx2 = _build_debug_context("PASSWORD", extra={
        "risk": "{level=HIGH}",
        "behaviors": "{New Geo-Location=POSITIVE, New Device=NEGATIVE, New IP=NEGATIVE, New State=NEGATIVE, New Country=POSITIVE, Velocity Behavior=NEGATIVE, New City=NEGATIVE}",
        "threatSuspected":  "true",
    }, include_auth_signals=False)
    logs.append(_assemble(
        "user.session.start", actor, client2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx2,
        debug_context=dbg_ctx2,
        target=_session_start_targets("PASSWORD"),
    ))
    return logs


# --- PASSWORD SPRAY ---

def _generate_password_spray(config, session_context=None):
    """
    Many failed user.session.start from same IP, different usernames.
    Feeds 'Okta password spray detected' detection.
    """
    print("    - Okta Module generating password spray sequence...")
    logs   = []
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    sec_ctx = _build_security_context(ip_ctx)
    dbg_ctx = _build_debug_context("PASSWORD", extra={
        "loginResult":     "INVALID_CREDENTIALS",
        "threatSuspected": "true",
        "risk": "{level=HIGH}",
    })
    # Hit many different users from the same IP — that's the spray pattern
    if session_context:
        targets = [(u, {"owner": p["display_name"]}) for u, p in session_context.items()]
    else:
        users = config.get("zscaler_config", {}).get("device_map", {})
        targets = list(users.items()) if users else [("user1", {"owner": "User One"}), ("user2", {"owner": "User Two"})]
    for username, details in targets:
        actor  = _build_actor(username, details.get("owner", username))
        client = _build_client(ip_ctx, config, interactive_only=False)
        # Force same IP across all attempts — the defining characteristic
        client["ipAddress"] = ip_ctx.get("ip")
        logs.append(_assemble(
            "user.session.start", actor, client,
            outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            severity="WARN", display_message="User login to Okta failed: INVALID_CREDENTIALS",
            security_context=sec_ctx,
            debug_context=dbg_ctx,
        ))
    return logs


# --- APP PROVISIONING ---

def _generate_app_assigned_to_user(config, user_info, session_context=None):
    """app.generic.provision.assign_user_to_app — app provisioned to user."""
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    app         = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    targets = [
        _build_target_user(target_user)[0],
        {
            "id":          _app_instance_id(app),
            "type":        "AppInstance",
            "displayName": app,
            "alternateId": app,
            "detailEntry": {"signOnModeType": _app_sign_on_mode(app)},
        },
    ]
    return _assemble(
        "app.generic.provision.assign_user_to_app", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Provision user to app {app}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=targets,
    )


# ---------------------------------------------------------------------------
# SSO-SPECIFIC DETECTION GENERATORS (26 new detections)
# ---------------------------------------------------------------------------

# Shared data for geo/ASN anomalies
_HIGH_RISK_COUNTRIES = [
    {"country": "RU", "city": "Moscow",    "state": None, "asn": 12389, "isp": "Rostelecom",      "domain": "rt.ru",        "is_proxy": False},
    {"country": "CN", "city": "Beijing",   "state": None, "asn": 4134,  "isp": "Chinanet",        "domain": "chinanet.cn",  "is_proxy": False},
    {"country": "KP", "city": "Pyongyang", "state": None, "asn": 131072,"isp": "Star JV",         "domain": None,           "is_proxy": False},
    {"country": "IR", "city": "Tehran",    "state": None, "asn": 31549, "isp": "Shatel",          "domain": "shatel.ir",    "is_proxy": False},
    {"country": "NG", "city": "Lagos",     "state": None, "asn": 37148, "isp": "MainOne",         "domain": "mainone.net",  "is_proxy": False},
    {"country": "BR", "city": "Sao Paulo", "state": None, "asn": 28573, "isp": "Claro",           "domain": "claro.com.br", "is_proxy": False},
    {"country": "UA", "city": "Kyiv",      "state": None, "asn": 15895, "isp": "Kyivstar",        "domain": "kyivstar.net", "is_proxy": False},
    {"country": "VN", "city": "Hanoi",     "state": None, "asn": 45899, "isp": "VNPT",            "domain": "vnpt.vn",      "is_proxy": False},
]

_NEW_ASNS = [
    {"asn": 394711, "isp": "Hetzner Online",   "domain": "hetzner.com",  "is_proxy": False},
    {"asn": 14061,  "isp": "DigitalOcean",     "domain": "digitalocean.com","is_proxy": False},
    {"asn": 16509,  "isp": "Amazon AWS",       "domain": "amazonaws.com","is_proxy": False},
    {"asn": 8075,   "isp": "Microsoft Azure",  "domain": "microsoft.com","is_proxy": False},
    {"asn": 15169,  "isp": "Google Cloud",     "domain": "google.com",   "is_proxy": False},
    {"asn": 8100,   "isp": "QuadraNet",        "domain": "quadranet.com","is_proxy": False},
    {"asn": 209,    "isp": "Qwest/CenturyLink","domain": "centurylink.com","is_proxy": False},
]

_MACHINE_USER_AGENTS = [
    "python-requests/2.31.0",
    "python-requests/2.28.2",
    "Go-http-client/1.1",
    "curl/8.1.2",
    "curl/7.88.1",
    "okta-sdk-python/2.6.0",
    "node-fetch/2.6.9",
    "Axios/1.4.0",
    "Java/17.0.5",
    "okta-aws-cli/2.0.0",
    "PostmanRuntime/7.32.3",
    "okta-signin-widget/7.11.0",
]

_UNUSUAL_OS_LIST = ["ChromeOS", "FreeBSD", "Ubuntu", "Fedora", "Kali Linux", "Tails"]

_SUSPICIOUS_COUNTRIES = ["RU", "CN", "KP", "IR", "SY", "BY", "CU", "MM"]

_NEW_COUNTRY_POOL = [
    {"country": "JP", "city": "Tokyo",     "state": None, "asn": 2497, "isp": "IIJ",       "domain": "iij.net",    "is_proxy": False},
    {"country": "AU", "city": "Sydney",    "state": "NSW","asn": 1221, "isp": "Telstra",   "domain": "telstra.com","is_proxy": False},
    {"country": "DE", "city": "Berlin",    "state": None, "asn": 3320, "isp": "Telekom",   "domain": "telekom.de", "is_proxy": False},
    {"country": "ZA", "city": "Cape Town", "state": None, "asn": 36937,"isp": "Liquid",    "domain": "liquid.tech","is_proxy": False},
    {"country": "IN", "city": "Mumbai",    "state": None, "asn": 9498, "isp": "Airtel",    "domain": "airtel.in",  "is_proxy": False},
    {"country": "AR", "city": "Buenos Aires","state": None,"asn": 10318,"isp": "Cablevision","domain": "cablevision.com.ar","is_proxy": False},
    {"country": "PH", "city": "Manila",    "state": None, "asn": 9299, "isp": "PLDT",      "domain": "pldt.net",   "is_proxy": False},
]

_RARE_SSO_APPS = [
    "Legacy HR Portal", "Old Payroll System", "Dev Environment SSO",
    "Staging ServiceNow", "Internal Wiki", "Finance Archive",
    "Backup Identity Provider", "Shadow IT App",
]


def _make_sso_target(app_name):
    return [{
        "id":          _app_instance_id(app_name),
        "type":        "AppInstance",
        "displayName": app_name,
        "alternateId": app_name,
        "detailEntry": {"signOnModeType": _app_sign_on_mode(app_name)},
    }]


def _make_ip_ctx_from(base, overrides):
    """Merge base ip_ctx with overrides dict."""
    ctx = {"ip": "203.0.113.1", "city": None, "country": None,
           "state": None, "isp": None, "asn": None, "domain": None, "is_proxy": False}
    ctx.update(base)
    ctx.update(overrides)
    return ctx


# --- SSO FAILURE PATTERNS ---

def _generate_sso_brute_force(config, user_info, session_context=None):
    """Many failed user.authentication.sso, same user — SSO Brute Force."""
    print("    - Okta Module generating SSO brute force sequence...")
    logs   = []
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    sec_ctx = _build_security_context(ip_ctx)
    dbg_ctx = _build_debug_context("PASSWORD", extra={
        "risk": "{level=HIGH}",
    })
    for _ in range(random.randint(8, 15)):
        client = _build_client(ip_ctx, config, interactive_only=False)
        logs.append(_assemble(
            "user.authentication.sso", actor, client,
            outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            severity="WARN", display_message=f"SSO authentication to {app} failed",
            security_context=sec_ctx, debug_context=dbg_ctx,
            target=_make_sso_target(app),
        ))
    return logs


def _generate_intense_sso_failures(config, session_context=None):
    """High volume failed SSO across multiple users — Intense SSO failures."""
    print("    - Okta Module generating intense SSO failures sequence...")
    logs   = []
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    if session_context:
        targets = [(u, {"owner": p["display_name"]}) for u, p in session_context.items()]
    else:
        users  = config.get("zscaler_config", {}).get("device_map", {})
        targets = list(users.items()) if users else [("u1", {"owner": "User One"}), ("u2", {"owner": "User Two"})]
    apps   = config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"])
    sec_ctx = _build_security_context(ip_ctx)
    for username, details in targets:
        actor = _build_actor(username, details.get("owner", username))
        for _ in range(random.randint(2, 4)):
            app    = random.choice(apps)
            client = _build_client(ip_ctx, config, interactive_only=False)
            logs.append(_assemble(
                "user.authentication.sso", actor, client,
                outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
                severity="WARN", display_message=f"SSO authentication to {app} failed",
                security_context=sec_ctx,
                debug_context=_build_debug_context("PASSWORD"),
                target=_make_sso_target(app),
            ))
    return logs


def _generate_sso_password_spray(config, session_context=None):
    """Failed SSO, same IP, many users — SSO Password Spray."""
    print("    - Okta Module generating SSO password spray sequence...")
    logs   = []
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    if session_context:
        targets = [(u, {"owner": p["display_name"]}) for u, p in session_context.items()]
    else:
        users  = config.get("zscaler_config", {}).get("device_map", {})
        targets = list(users.items()) if users else [("u1", {"owner": "User One"}), ("u2", {"owner": "User Two"})]
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    sec_ctx = _build_security_context(ip_ctx)
    dbg_ctx = _build_debug_context("PASSWORD", extra={
        "threatSuspected": "true",
        "risk": "{level=HIGH}",
    })
    for username, details in targets:
        actor  = _build_actor(username, details.get("owner", username))
        client = _build_client(ip_ctx, config, interactive_only=False)
        client["ipAddress"] = ip_ctx.get("ip")   # lock same IP
        logs.append(_assemble(
            "user.authentication.sso", actor, client,
            outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            severity="WARN", display_message=f"SSO authentication to {app} failed",
            security_context=sec_ctx, debug_context=dbg_ctx,
            target=_make_sso_target(app),
        ))
    return logs


def _generate_ip_rotation_sso_spray(config, user_info, session_context=None):
    """Same user, many different IPs, all fail SSO — IP Rotation Pattern in SSO Spray."""
    print("    - Okta Module generating IP rotation SSO spray sequence...")
    logs  = []
    actor = _build_actor(user_info["username"], user_info["full_name"])
    app   = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    # Build a pool of distinct IPs
    ip_pool = [
        {"ip": f"185.220.{random.randint(100,110)}.{random.randint(1,254)}", "city": None, "country": "NL",
         "state": None, "asn": 208323, "isp": "TOR Exit", "domain": None, "is_proxy": True},
        {"ip": f"45.33.{random.randint(1,254)}.{random.randint(1,254)}", "city": "Dallas", "country": "US",
         "state": "TX", "asn": 63949, "isp": "Linode", "domain": "linode.com", "is_proxy": False},
        {"ip": f"104.244.{random.randint(70,80)}.{random.randint(1,254)}", "city": None, "country": "SE",
         "state": None, "asn": 395954, "isp": "Mullvad VPN", "domain": "mullvad.net", "is_proxy": True},
    ]
    for ip_ctx in ip_pool:
        client = _build_client(ip_ctx, config, interactive_only=False)
        client["ipAddress"] = ip_ctx["ip"]
        logs.append(_assemble(
            "user.authentication.sso", actor, client,
            outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            severity="WARN", display_message=f"SSO authentication to {app} failed",
            security_context=_build_security_context(ip_ctx),
            debug_context=_build_debug_context("PASSWORD", extra={
                "threatSuspected": "true",
                "risk": "{level=HIGH}",
            }),
            target=_make_sso_target(app),
        ))
    return logs


# --- GEO / COUNTRY ANOMALIES ---

def _generate_sso_rejected_unusual_country(config, user_info, session_context=None):
    """User rejects MFA push during SSO from unusual country — A user rejected SSO from unusual country."""
    ip_ctx = _make_ip_ctx_from(random.choice(_HIGH_RISK_COUNTRIES),
                               {"ip": f"185.220.{random.randint(100,110)}.{random.randint(1,254)}"})
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    logs   = []
    # Push sent
    logs.append(_assemble(
        "system.push.send_factor_verify_push", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="MFA push challenge sent",
        authentication_context=_build_authentication_context("OIE_OKTA_VERIFY_PUSH"),
        security_context=_build_security_context(ip_ctx),
    ))
    # User denies — they didn't initiate it
    logs.append(_assemble(
        "user.mfa.okta_verify.deny_push", actor, client,
        outcome={"result": "FAILURE", "reason": "USER_REJECTED_OKTA_VERIFY_PUSH"},
        severity="WARN", display_message="User rejected Okta Verify push — unusual country",
        authentication_context=_build_authentication_context("OIE_OKTA_VERIFY_PUSH"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("OIE_OKTA_VERIFY_PUSH", extra={
            "risk": "{level=HIGH}",
            "behaviors": "{New Geo-Location=POSITIVE, New Device=NEGATIVE, New IP=NEGATIVE, New State=NEGATIVE, New Country=POSITIVE, Velocity Behavior=NEGATIVE, New City=NEGATIVE}",
            "threatSuspected": "true",
        }),
        target=_make_sso_target(app),
    ))
    return logs


def _generate_sso_impossible_travel(config, user_info, session_context=None):
    """SSO from two geographically impossible countries — Impossible traveler SSO."""
    print("    - Okta Module generating SSO impossible travel sequence...")
    logs  = []
    actor = _build_actor(user_info["username"], user_info["full_name"])
    app   = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))

    # First SSO — home country
    ip_ctx1 = _get_random_ip_and_context(config, "benign_ingress_sources")
    client1 = _build_client(ip_ctx1, config, interactive_only=True)
    logs.append(_assemble(
        "user.authentication.sso", actor, client1,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="User single sign on to app",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx1),
        debug_context=_build_debug_context("PASSWORD"),
        target=_make_sso_target(app),
    ))

    # Second SSO — impossible foreign location minutes later
    ip_ctx2 = _make_ip_ctx_from(random.choice(_HIGH_RISK_COUNTRIES),
                                {"ip": f"185.220.{random.randint(100,110)}.{random.randint(1,254)}"})
    client2 = _build_client(ip_ctx2, config, interactive_only=False)
    logs.append(_assemble(
        "user.authentication.sso", actor, client2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"User SSO from impossible travel location",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx2),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}",
            "threatSuspected": "true",
        }),
        target=_make_sso_target(app),
    ))
    return logs


def _generate_sso_possible_impossible_travel(config, user_info, session_context=None):
    """SSO from two different countries, plausible but unusual — Possible Impossible Travel Pattern SSO."""
    logs  = []
    actor = _build_actor(user_info["username"], user_info["full_name"])
    app   = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))

    ip_ctx1 = _get_random_ip_and_context(config, "benign_ingress_sources")
    client1 = _build_client(ip_ctx1, config, interactive_only=True)
    logs.append(_assemble(
        "user.authentication.sso", actor, client1,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="User single sign on to app",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx1),
        debug_context=_build_debug_context("PASSWORD"),
        target=_make_sso_target(app),
    ))

    ip_ctx2 = _make_ip_ctx_from(random.choice(_NEW_COUNTRY_POOL),
                                {"ip": f"203.{random.randint(100,200)}.{random.randint(1,254)}.{random.randint(1,254)}"})
    client2 = _build_client(ip_ctx2, config, interactive_only=True)
    logs.append(_assemble(
        "user.authentication.sso", actor, client2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"User SSO from new country — possible impossible travel",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx2),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    ))
    return logs


def _generate_sso_new_country(config, user_info, session_context=None):
    """SSO from a country the user has never used — A user connected from a new country."""
    ip_ctx = _make_ip_ctx_from(random.choice(_NEW_COUNTRY_POOL),
                               {"ip": f"203.{random.randint(100,200)}.{random.randint(1,254)}.{random.randint(1,254)}"})
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"User SSO from new country {ip_ctx['country']}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_suspicious_country(config, user_info, session_context=None):
    """SSO from a high-risk country — User attempted to connect from suspicious country."""
    country_code = random.choice(_SUSPICIOUS_COUNTRIES)
    country_data = next((c for c in _HIGH_RISK_COUNTRIES if c["country"] == country_code),
                        _HIGH_RISK_COUNTRIES[0])
    ip_ctx = _make_ip_ctx_from(country_data,
                               {"ip": f"185.220.{random.randint(100,110)}.{random.randint(1,254)}"})
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "FAILURE", "reason": "ACCESS_DENIED"},
        severity="WARN", display_message=f"SSO attempt from suspicious country {country_code}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}",
            "threatSuspected": "true",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_new_country_org(config, user_info, session_context=None):
    """SSO from a country no one in the org has ever used — First connection from country in org."""
    ip_ctx = _make_ip_ctx_from(random.choice(_NEW_COUNTRY_POOL),
                               {"ip": f"203.{random.randint(100,200)}.{random.randint(1,254)}.{random.randint(1,254)}"})
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"First SSO from country {ip_ctx['country']} in organization",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_from_tor(config, user_info, session_context=None):
    """Successful SSO from TOR exit node — A successful SSO sign-in from TOR."""
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"Successful SSO from TOR exit node to {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "proxyType": "TOR",
            "threatDetections": json.dumps({"TOR Exit Node": "HIGH"}),
            "threatSuspected": "true",
            "risk": "{level=HIGH}",
        }),
        target=_make_sso_target(app),
    )


# --- ASN ANOMALIES ---

def _generate_sso_new_asn_user(config, user_info, session_context=None):
    """SSO from ASN user has never used — First SSO access from ASN for user."""
    asn_data = random.choice(_NEW_ASNS)
    ip_ctx   = {"ip": f"45.33.{random.randint(1,254)}.{random.randint(1,254)}",
                "city": "Ashburn", "country": "US", "state": "VA", **asn_data}
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"First SSO from new ASN {asn_data['asn']} for user",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_new_asn_org(config, user_info, session_context=None):
    """SSO from ASN org has never seen — First SSO access from ASN in organization."""
    asn_data = random.choice(_NEW_ASNS)
    ip_ctx   = {"ip": f"45.33.{random.randint(1,254)}.{random.randint(1,254)}",
                "city": "Frankfurt", "country": "DE", "state": None, **asn_data}
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"First SSO from new ASN {asn_data['asn']} in org",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_suspicious_asn(config, user_info, session_context=None):
    """SSO from known-bad/anonymizer ASN — Suspicious SSO access from ASN."""
    suspicious_asns = [
        {"asn": 209854, "isp": "Surfshark VPN",  "domain": "surfshark.com", "is_proxy": True},
        {"asn": 395954, "isp": "Mullvad VPN",    "domain": "mullvad.net",   "is_proxy": True},
        {"asn": 209,    "isp": "M247",            "domain": "m247.com",      "is_proxy": True},
        {"asn": 60068,  "isp": "Datacamp Limited","domain": "datacamp.co.uk","is_proxy": True},
    ]
    asn_data = random.choice(suspicious_asns)
    ip_ctx   = {"ip": f"104.{random.randint(200,250)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "city": None, "country": "NL", "state": None, **asn_data}
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO from suspicious anonymizer ASN {asn_data['asn']}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
            "proxyType": "VPN",
        }),
        target=_make_sso_target(app),
    )


# --- USER AGENT / OS ANOMALIES ---

def _generate_sso_abnormal_os(config, user_info, session_context=None):
    """SSO with OS user has never used — SSO with abnormal operating system."""
    unusual_os   = random.choice(_UNUSUAL_OS_LIST)
    ua_map       = {
        "ChromeOS":  "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "FreeBSD":   "Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Ubuntu":    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Fedora":    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Kali Linux":"Mozilla/5.0 (X11; Linux x86_64; Kali) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Tails":     "Mozilla/5.0 (X11; Linux x86_64; Tails) Gecko/20100101 Firefox/117.0",
    }
    ua_str = ua_map.get(unusual_os, ua_map["Ubuntu"])
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    client["userAgent"]["rawUserAgent"] = ua_str
    client["userAgent"]["os"]           = unusual_os
    app = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO with abnormal OS: {unusual_os}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_new_os(config, user_info, session_context=None):
    """SSO with OS the user has never used before — SSO with new operating system."""
    new_os_options = [
        ("Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118 Safari/537.36"),
        ("Macintosh", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/604.1"),
        ("iPhone",  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"),
        ("Android", "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.98 Mobile Safari/537.36"),
    ]
    os_name, ua_str = random.choice(new_os_options)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    client["userAgent"]["rawUserAgent"] = ua_str
    client["userAgent"]["os"]           = os_name
    app = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO with new OS: {os_name}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=LOW}",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_abnormal_user_agent(config, user_info, session_context=None):
    """SSO with suspicious/scripted user agent — SSO with abnormal user agent."""
    ua_str = random.choice(_MACHINE_USER_AGENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    client["userAgent"]["rawUserAgent"] = ua_str
    client["userAgent"]["os"]           = "Unknown"
    client["userAgent"]["browser"]      = "UNKNOWN"
    app = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO with abnormal user agent",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_machine_account(config, user_info, session_context=None):
    """SSO from a machine/automation user agent — SSO authentication by a machine account."""
    ua_str = random.choice(_MACHINE_USER_AGENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    client["userAgent"]["rawUserAgent"] = ua_str
    client["userAgent"]["os"]           = "Unknown"
    client["userAgent"]["browser"]      = "UNKNOWN"
    client["device"]                    = "Unknown"
    app = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO by machine account",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_service_account(config, user_info, session_context=None):
    """SSO by a service account — SSO authentication by a service account."""
    svc_names = [
        ("svc-datadog",       "DataDog Service"),
        ("svc-jenkins",       "Jenkins CI Service"),
        ("svc-terraform",     "Terraform Automation"),
        ("svc-backup",        "Backup Service"),
        ("svc-monitoring",    "Monitoring Service"),
        ("svc-github-actions","GitHub Actions"),
    ]
    svc_username, svc_fullname = random.choice(svc_names)
    # Service accounts use machine-style actors
    svc_actor = {
        "id":          _stable_user_id(svc_username),
        "type":        "User",
        "alternateId": f"{svc_username}@examplecorp.com",
        "displayName": svc_fullname,
        "detailEntry": None,
    }
    ua_str = random.choice(_MACHINE_USER_AGENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    client = _build_client(ip_ctx, config, interactive_only=False)
    client["userAgent"]["rawUserAgent"] = ua_str
    client["userAgent"]["os"]           = "Unknown"
    client["userAgent"]["browser"]      = "UNKNOWN"
    client["device"]                    = "Unknown"
    app = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", svc_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO by service account {svc_username}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=LOW}",
        }),
        target=_make_sso_target(app),
    )


# --- HONEY ACCOUNTS ---

def _generate_honey_user_auth(config, session_context=None):
    """Login attempt by a canary/honey account — Authentication attempt by honey user."""
    honey_accounts = [
        ("honey.user",       "Honey User"),
        ("canary.admin",     "Canary Admin"),
        ("test.account",     "Test Account"),
        ("honeypot.user",    "Honeypot User"),
        ("decoy.admin",      "Decoy Admin"),
    ]
    username, fullname = random.choice(honey_accounts)
    honey_actor = _build_actor(username, fullname)
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    client = _build_client(ip_ctx, config, interactive_only=False)
    return _assemble(
        "user.session.start", honey_actor, client,
        outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
        severity="WARN", display_message="Authentication attempt by honey user — ALERT",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}",
            "threatSuspected": "true",
            "honeyUser": "true",
        }),
    )


def _generate_honey_user_sso(config, session_context=None):
    """SSO attempt by a canary account — SSO authentication attempt by honey user."""
    honey_accounts = [
        ("honey.user",       "Honey User"),
        ("canary.admin",     "Canary Admin"),
        ("test.account",     "Test Account"),
        ("honeypot.user",    "Honeypot User"),
    ]
    username, fullname = random.choice(honey_accounts)
    honey_actor = _build_actor(username, fullname)
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    client = _build_client(ip_ctx, config, interactive_only=False)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", honey_actor, client,
        outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
        severity="WARN", display_message="SSO attempt by honey user — ALERT",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}",
            "threatSuspected": "true",
            "honeyUser": "true",
        }),
        target=_make_sso_target(app),
    )


# --- MISC BEHAVIOURAL ---

def _generate_sso_multiple_unusual_resources(config, user_info, session_context=None):
    """Burst of SSO to rare/unusual apps — A user accessed multiple unusual resources via SSO."""
    print("    - Okta Module generating multiple unusual SSO resources sequence...")
    actor = _build_actor(user_info["username"], user_info["full_name"])
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    logs  = []
    unusual_apps = _RARE_SSO_APPS.copy()
    random.shuffle(unusual_apps)
    for app in unusual_apps[:random.randint(4, 6)]:
        client = _build_client(ip_ctx, config, interactive_only=True)
        logs.append(_assemble(
            "user.authentication.sso", actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="WARN", display_message=f"User SSO to unusual resource: {app}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=_build_security_context(ip_ctx),
            debug_context=_build_debug_context("PASSWORD", extra={
                "risk": "{level=MEDIUM}",
            }),
            target=_make_sso_target(app),
        ))
    return logs


def _generate_sso_unusual_time(config, user_info, session_context=None):
    """SSO at 2-5 AM local time — A user logged in at unusual time via SSO."""
    from datetime import datetime, timedelta
    # Override published timestamp to 2-5 AM
    odd_hour   = random.randint(2, 4)
    odd_minute = random.randint(0, 59)
    ts = datetime.utcnow().replace(hour=odd_hour, minute=odd_minute, second=0, microsecond=0)
    published  = ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    event  = json.loads(_assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO at unusual time {odd_hour:02d}:{odd_minute:02d} UTC",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    ))
    event["published"]       = published
    event["legacyEventType"] = event["eventType"]
    return json.dumps(event)


def _generate_sso_suspicious_auth(config, user_info, session_context=None):
    """SSO with multiple risk signals combined — Suspicious SSO authentication."""
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    client["userAgent"]["rawUserAgent"] = random.choice(_MACHINE_USER_AGENTS)
    client["userAgent"]["os"]           = "Unknown"
    app = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="Suspicious SSO authentication",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}",
            "threatSuspected": "true",
        }),
        target=_make_sso_target(app),
    )


def _generate_sso_first_resource_org(config, user_info, session_context=None):
    """SSO to an app no one in the org has ever accessed — First SSO Resource Access in Organization."""
    # Use a rare app not in the standard list
    rare_app = random.choice(_RARE_SSO_APPS)
    ip_ctx   = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor    = _build_actor(user_info["username"], user_info["full_name"])
    client   = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"First ever SSO access to {rare_app} in organization",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(rare_app),
    )


def _generate_disabled_user_sso(config, user_info, session_context=None):
    """Disabled user tries to authenticate via SSO — A disabled user attempted to authenticate."""
    # Use a deactivated user pattern
    deactivated_actor = _build_actor(user_info["username"], user_info["full_name"])
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))
    return _assemble(
        "user.authentication.sso", deactivated_actor, client,
        outcome={"result": "FAILURE", "reason": "USER_DISABLED"},
        severity="WARN", display_message="SSO attempt by disabled/deactivated user",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "loginResult": "USER_DISABLED",
            "risk": "{level=MEDIUM}",
        }),
        target=_make_sso_target(app),
    )


# ===========================================================================
# EXTENDED EVENT TYPE COVERAGE — 121 new event types from Okta docs CSV
# ===========================================================================

# Shared helpers for admin-initiated events
def _admin_event(config, event_type, display_message, target=None, severity="INFO",
                 outcome_result="SUCCESS", outcome_reason=None, extra_debug=None,
                 session_context=None):
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx     = _build_security_context(ip_ctx)
    dbg_ctx     = _build_debug_context("PASSWORD", extra=extra_debug or {})
    return _assemble(event_type, admin_actor, client,
                     outcome={"result": outcome_result, "reason": outcome_reason},
                     severity=severity, display_message=display_message,
                     security_context=sec_ctx, debug_context=dbg_ctx, target=target)

def _user_event(config, user_info, event_type, display_message, target=None, severity="INFO",
                outcome_result="SUCCESS", outcome_reason=None, extra_debug=None, admin=False,
                session_context=None):
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_admin_actor(config, session_context) if admin else _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(ip_ctx)
    dbg_ctx = _build_debug_context("PASSWORD", extra=extra_debug or {})
    return _assemble(event_type, actor, client,
                     outcome={"result": outcome_result, "reason": outcome_reason},
                     severity=severity, display_message=display_message,
                     security_context=sec_ctx, debug_context=dbg_ctx, target=target)

def _target_user(user_info):
    actor = _build_actor(user_info["username"], user_info["full_name"])
    return _build_target_user(actor)

def _target_group(name):
    return [{"id": f"grp{uuid.uuid4().hex[:20]}", "type": "UserGroup",
             "displayName": name, "alternateId": name, "detailEntry": None}]

def _target_app(name):
    return [{"id": _app_instance_id(name), "type": "AppInstance",
             "displayName": name, "alternateId": name,
             "detailEntry": {"signOnModeType": _app_sign_on_mode(name)}}]

def _target_policy(name, ptype="Policy"):
    return [{"id": f"pol-{uuid.uuid4()}", "type": ptype,
             "displayName": name, "alternateId": name, "detailEntry": None}]

def _target_rule(name):
    return [{"id": f"rule-{uuid.uuid4()}", "type": "Rule",
             "displayName": name, "alternateId": name, "detailEntry": None}]

def _target_zone(name):
    return [{"id": f"zone-{uuid.uuid4()}", "type": "NetworkZone",
             "displayName": name, "alternateId": name, "detailEntry": None}]

def _target_idp(name):
    return [{"id": f"idp-{uuid.uuid4()}", "type": "IdentityProvider",
             "displayName": name, "alternateId": name, "detailEntry": None}]

def _target_role(name):
    return [{"id": f"role-{uuid.uuid4()}", "type": "Role",
             "displayName": name, "alternateId": name, "detailEntry": None}]


_OIDC_APPS = {
    "GitHub", "GitLab", "Google Workspace", "Slack", "Zoom", "Datadog",
    "PagerDuty", "Notion", "Amplitude", "Snowflake", "Databricks", "Figma",
    "Miro", "Linear", "Webex", "Loom", "Claude", "CircleCI", "Sentry",
    "LaunchDarkly", "New Relic", "Grafana Cloud", "Mixpanel", "Heap",
    "Segment", "Greenhouse", "Lattice", "BambooHR",
}

def _app_instance_id(name: str) -> str:
    """Return a deterministic Okta-style app instance ID (0oa + 18 chars) for *name*."""
    import hashlib
    h   = hashlib.sha256(name.encode()).hexdigest()
    _ch = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    out = "0oa"
    for i in range(0, 54, 3):
        out += _ch[int(h[i:i+3], 16) % len(_ch)]
    return out[:21]

def _app_sign_on_mode(name: str) -> str:
    return "OPENID_CONNECT" if name in _OIDC_APPS else "SAML_2_0"

def _rand_app(config):
    return random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Salesforce"]))

_POLICY_NAMES   = ["Global Session Policy","Default Policy","MFA Enrollment","Password Policy",
                   "App Sign-On Policy","Risk-Based Access","Authenticator Enrollment Policy"]
_RULE_NAMES     = ["Default Rule","Allow from Corp IP","Block TOR","Require MFA","Time-Based Access",
                   "High-Risk Deny","New Device MFA","Password Expiry Rule"]
_ZONE_NAMES     = ["Corporate Network","VPN Zone","US Offices","Blocked Countries",
                   "TOR Exit Nodes","Cloud IPs","Partner Network"]
_IDP_NAMES      = ["Google Workspace","Okta","Azure AD","Ping Identity","ADFS",
                   "Duo Security","JumpCloud","OneLogin"]
_IAM_ROLES      = ["Super Admin","Org Admin","App Admin","User Admin","Group Admin",
                   "Help Desk Admin","Read-Only Admin","Custom Security Role"]
_SOCIAL_IDPS    = ["Google","Apple","LinkedIn","GitHub","Microsoft","Facebook"]
_AUTH_FACTORS   = ["Okta Verify","Google Authenticator","SMS","Email","YubiKey","WebAuthn","Phone Call"]
_OAUTH_CLIENTS  = ["Salesforce SSO","Workday Integration","Internal Dashboard",
                   "Mobile App","CI/CD Pipeline","Analytics Service"]
_BREACH_REASONS = ["CREDENTIAL_STUFFING","KNOWN_BREACH","DARK_WEB_EXPOSURE","PASSWORD_REUSE"]
_RISK_LEVELS    = ["HIGH","MEDIUM","LOW"]
_RISK_REASONS   = ["NEW_COUNTRY","NEW_DEVICE","ANOMALOUS_LOCATION","IMPOSSIBLE_TRAVEL",
                   "VELOCITY_EXCEEDED","KNOWN_THREAT_IP","SUSPICIOUS_BROWSER"]
_WEBAUTHN_FACTORS   = ["YubiKey", "Touch ID", "Windows Hello", "Passkey", "Security Key"]
_KERBEROS_APPS      = ["Active Directory SSO", "Windows Desktop SSO", "Kerberos SSO"]
_RADIUS_APPS        = ["Corporate WiFi", "VPN Gateway", "Network Access Control"]
_SCIM_BACKDOOR_PFXS = ["svc-", "api-", "sync-", "backup-", "test-", "temp-"]
_HOOK_ENDPOINTS    = ["Slack Notification Hook", "SIEM Event Hook",
                      "ServiceNow Incident Hook", "PagerDuty Alert Hook"]
_OAUTH2_DENY_REASONS = ["ACCESS_DENIED", "SCOPE_NOT_ALLOWED", "REDIRECT_URI_MISMATCH"]
_OKTA_ADMIN_SCOPES   = [
    "okta.users.manage", "okta.groups.manage", "okta.apps.manage",
    "okta.policies.manage", "okta.roles.manage", "okta.logs.read",
    "okta.authorizationServers.manage", "okta.trustedOrigins.manage",
]
_AD_AGENT_NAMES = ["Okta AD Agent", "AD Connector", "Directory Sync Agent"]


# ---------------------------------------------------------------------------
# user.lifecycle — full lifecycle coverage
# ---------------------------------------------------------------------------

def _gen_user_lifecycle_create(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.lifecycle.create",
        "Create Okta user", target=_target_user(user_info), admin=True, session_context=session_context)

def _gen_user_lifecycle_activate(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.lifecycle.activate",
        "Activate Okta user", target=_target_user(user_info), admin=True, session_context=session_context)

def _gen_user_lifecycle_reactivate(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.lifecycle.reactivate",
        "Reactivate Okta user", target=_target_user(user_info), admin=True,
        severity="WARN", session_context=session_context)

def _gen_user_lifecycle_unsuspend(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.lifecycle.unsuspend",
        "Unsuspend Okta user", target=_target_user(user_info), admin=True, session_context=session_context)

def _gen_user_lifecycle_delete_initiated(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.lifecycle.delete.initiated",
        "Delete Okta user initiated", target=_target_user(user_info), admin=True,
        severity="WARN", session_context=session_context)

def _gen_user_lifecycle_delete_completed(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.lifecycle.delete.completed",
        "Delete Okta user completed", target=_target_user(user_info), admin=True,
        severity="WARN", session_context=session_context)


# ---------------------------------------------------------------------------
# user.account — profile & privilege events
# ---------------------------------------------------------------------------

def _gen_user_account_update_profile(config, user_info, session_context=None):
    fields = random.choice(["firstName","lastName","email","title","department","mobilePhone","manager"])
    return _user_event(config, user_info, "user.account.update_profile",
        f"Update user profile for Okta ({fields})",
        target=_target_user(user_info),
        extra_debug={"changedAttribute": fields, "previousValue": "old_value", "newValue": "new_value"}, session_context=session_context)

def _gen_user_account_privilege_revoke(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.account.privilege.revoke",
        "All of user's admin privilege revoked",
        target=_target_user(user_info), admin=True, severity="WARN", session_context=session_context)

def _gen_user_account_expire_password(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.account.expire_password",
        "User's Okta password is expired",
        target=_target_user(user_info), admin=True, session_context=session_context)

def _gen_user_account_lock_limit(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.account.lock.limit",
        "User account reached lockout limit — will not auto-unlock",
        target=_target_user(user_info), severity="WARN",
        outcome_result="FAILURE", outcome_reason="LOCKED_OUT", session_context=session_context)

def _gen_user_account_update_primary_email(config, user_info, session_context=None):
    new_email = f"new.{user_info['username']}@examplecorp.com"
    return _user_event(config, user_info, "user.account.update_primary_email",
        "User primary email updated",
        target=_target_user(user_info),
        extra_debug={"newEmail": new_email}, session_context=session_context)


# ---------------------------------------------------------------------------
# user.session — session events
# ---------------------------------------------------------------------------

def _gen_user_session_end(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.session.end",
        "User logout from Okta", session_context=session_context)

def _gen_user_session_clear(config, user_info, session_context=None):
    """Admin clears all sessions for user — force logout."""
    return _user_event(config, user_info, "user.session.clear",
        "Clear user sessions", target=_target_user(user_info), admin=True,
        severity="WARN", session_context=session_context)

def _gen_user_session_access_admin_app(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.session.access_admin_app",
        "User accessing Okta admin app", severity="WARN",
        target=_target_app("Okta Admin Console"))

def _gen_user_session_context_change(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.session.context.change",
        "User session context changed",
        extra_debug={"reason": "IP_ADDRESS_CHANGED", "behaviors": "{New Geo-Location=NEGATIVE, New Device=NEGATIVE, New IP=POSITIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity Behavior=NEGATIVE, New City=NEGATIVE}"}, session_context=session_context)

def _gen_user_session_expire(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.session.expire",
        "Expire user session", session_context=session_context)


# ---------------------------------------------------------------------------
# user.mfa — MFA factor management
# ---------------------------------------------------------------------------

def _gen_user_mfa_factor_deactivate(config, user_info, session_context=None):
    factor = random.choice(_AUTH_FACTORS)
    return _user_event(config, user_info, "user.mfa.factor.deactivate",
        f"Reset factor enrollment: {factor}",
        target=[{"id": f"mfa-{uuid.uuid4()}", "type": "AuthenticatorEnrollment",
                 "displayName": factor, "alternateId": factor, "detailEntry": None}],
        admin=True, severity="WARN", session_context=session_context)

def _gen_user_mfa_factor_suspend(config, user_info, session_context=None):
    factor = random.choice(_AUTH_FACTORS)
    return _user_event(config, user_info, "user.mfa.factor.suspend",
        f"Suspend factor enrollment: {factor}",
        target=[{"id": f"mfa-{uuid.uuid4()}", "type": "AuthenticatorEnrollment",
                 "displayName": factor, "alternateId": factor, "detailEntry": None}],
        admin=True, session_context=session_context)

def _gen_user_mfa_factor_update(config, user_info, session_context=None):
    factor = random.choice(_AUTH_FACTORS)
    return _user_event(config, user_info, "user.mfa.factor.update",
        f"Update factor: {factor}",
        target=[{"id": f"mfa-{uuid.uuid4()}", "type": "AuthenticatorEnrollment",
                 "displayName": factor, "alternateId": factor, "detailEntry": None}])

def _gen_user_mfa_okta_verify(config, user_info, session_context=None):
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("user.mfa.okta_verify", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Verify user with Okta Verify",
        authentication_context=_build_authentication_context("OIE_OKTA_VERIFY_PUSH"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("OIE_OKTA_VERIFY_PUSH"))


# ---------------------------------------------------------------------------
# push / RADIUS / provisioning / extended auth — high-volume benign noise
# ---------------------------------------------------------------------------

def _gen_push_send_verify(config, user_info, session_context=None):
    """system.push.send_factor_verify_push — Okta sends a push to user's device.
    Very high volume; fires for every Okta Verify push attempt."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "system.push.send_factor_verify_push", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Send push verify factor challenge",
        authentication_context=_build_authentication_context("OIE_OKTA_VERIFY_PUSH"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("OIE_OKTA_VERIFY_PUSH"),
    )


def _gen_mfa_push_deny(config, user_info, session_context=None):
    """user.mfa.okta_verify.deny_push — user accidentally denies a push notification.
    Common noise; distinct from MFA bombing (single isolated deny)."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.mfa.okta_verify.deny_push", actor, client,
        outcome={"result": "FAILURE", "reason": "USER_REJECTED_OKTA_VERIFY_PUSH"},
        severity="WARN", display_message="User rejected Okta Verify push notification",
        authentication_context=_build_authentication_context("OIE_OKTA_VERIFY_PUSH"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("OIE_OKTA_VERIFY_PUSH"),
    )


def _gen_radius_auth_success(config, user_info, session_context=None):
    """user.authentication.auth_via_radius — Okta RADIUS agent auth for WiFi/VPN."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    app    = random.choice(_RADIUS_APPS)
    return _assemble(
        "user.authentication.auth_via_radius", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Authentication of user via RADIUS: {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": _app_instance_id(app), "type": "AppInstance",
                 "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
    )


def _gen_policy_sign_on_eval(config, user_info, session_context=None):
    """policy.evaluate_sign_on — sign-on policy evaluation (fires on every auth in OIE).
    Outcome ACCESS_ALLOWED for benign; includes policy + rule targets."""
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    policy  = random.choice(_POLICY_NAMES)
    rule    = random.choice(_RULE_NAMES)
    targets = _target_policy(policy) + _target_rule(rule)
    return _assemble(
        "policy.evaluate_sign_on", actor, client,
        outcome={"result": "ALLOW", "reason": None},
        severity="INFO", display_message="Evaluate user sign on policy",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=targets,
    )


def _gen_fastpass_session_start(config, user_info, session_context=None):
    """user.session.start via Okta FastPass (passwordless, device-bound SIGNED_NONCE)."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.session.start", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="User login to Okta",
        authentication_context=_build_authentication_context("SIGNED_NONCE"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("SIGNED_NONCE", include_auth_signals=True),
        target=_session_start_targets("SIGNED_NONCE"),
    )


def _gen_webauthn_factor_enroll(config, user_info, session_context=None):
    """user.mfa.factor.activate for WebAuthn/FIDO2 hardware key or passkey.
    Covers YubiKey, Touch ID, Windows Hello, passkeys — distinct from Okta Verify."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    factor = random.choice(_WEBAUTHN_FACTORS)
    target = [{"id": f"mfa-{uuid.uuid4()}", "type": "AuthenticatorEnrollment",
               "displayName": factor, "alternateId": "FIDO2_WEBAUTHN", "detailEntry": None}]
    return _assemble(
        "user.mfa.factor.activate", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"User activated {factor}",
        authentication_context=_build_authentication_context("SIGNED_NONCE"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("SIGNED_NONCE"),
        target=target,
    )


def _gen_auth_via_webauthn(config, user_info, session_context=None):
    """user.authentication.auth_via_webauthn — FIDO2/WebAuthn hardware key or passkey authentication.
    Distinct from enrollment (user.mfa.factor.activate); fires on every WebAuthn-based login."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    factor = random.choice(_WEBAUTHN_FACTORS)
    target = [{"id": f"mfa-{uuid.uuid4()}", "type": "AuthenticatorEnrollment",
               "displayName": factor, "alternateId": "FIDO2_WEBAUTHN", "detailEntry": None}]
    return _assemble(
        "user.authentication.auth_via_webauthn", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Authentication of user via WebAuthn: {factor}",
        authentication_context=_build_authentication_context("SIGNED_NONCE"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("SIGNED_NONCE", include_auth_signals=True),
        target=target,
    )


def _gen_app_push_password_success(config, user_info, session_context=None):
    """app.user_management.push_password_update.success — AD sync password push to app.
    Very common in enterprise hybrid deployments (Okta AD agent)."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = _rand_app(config)
    target = [
        {"id": _app_instance_id(app), "type": "AppInstance",
         "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}},
        _build_target_user(_build_actor(user_info["username"], user_info["full_name"]))[0],
    ]
    return _assemble(
        "app.user_management.push_password_update.success", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Push password update to app: {app}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=target,
    )


def _gen_app_push_profile_success(config, user_info, session_context=None):
    """app.user_management.push_profile_update.success — profile attribute sync push."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = _rand_app(config)
    target = [
        {"id": _app_instance_id(app), "type": "AppInstance",
         "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}},
        _build_target_user(_build_actor(user_info["username"], user_info["full_name"]))[0],
    ]
    return _assemble(
        "app.user_management.push_profile_update.success", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Push profile update to app: {app}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=target,
    )


def _gen_app_push_password_failure(config, user_info, session_context=None):
    """app.user_management.push_password_update.failure — sync failure (realistic noise)."""
    ip_ctx   = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor    = _build_admin_actor(config, session_context)
    client   = _build_client(ip_ctx, config, interactive_only=True)
    app      = _rand_app(config)
    reasons  = ["INVALID_CREDENTIALS", "APP_UNAVAILABLE", "PUSH_FAILED", "LOCKED_OUT"]
    target   = [
        {"id": _app_instance_id(app), "type": "AppInstance",
         "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}},
        _build_target_user(_build_actor(user_info["username"], user_info["full_name"]))[0],
    ]
    return _assemble(
        "app.user_management.push_password_update.failure", actor, client,
        outcome={"result": "FAILURE", "reason": random.choice(reasons)},
        severity="WARN", display_message=f"Failed to push password update to app: {app}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=target,
    )


def _gen_user_account_update_secondary_email(config, user_info, session_context=None):
    """user.account.update_secondary_email — user updates recovery/secondary email."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.account.update_secondary_email", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Update secondary email address for user",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_build_target_user(actor),
    )


def _gen_user_account_update_phone(config, user_info, session_context=None):
    """user.account.update_phone — user updates their SMS/voice phone number."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.account.update_phone", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Update user phone number",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_build_target_user(actor),
    )


def _gen_app_push_new_user(config, user_info, session_context=None):
    """app.user_management.push_new_user — SCIM/provisioning push creates account in downstream app."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = _rand_app(config)
    target = [
        {"id": _app_instance_id(app), "type": "AppInstance",
         "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}},
        _build_target_user(_build_actor(user_info["username"], user_info["full_name"]))[0],
    ]
    return _assemble(
        "app.user_management.push_new_user", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Push new user to app: {app}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=target,
    )


def _gen_app_push_user_deactivation(config, user_info, session_context=None):
    """app.user_management.push_user_deactivation — SCIM push deactivates account in downstream app."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = _rand_app(config)
    target = [
        {"id": _app_instance_id(app), "type": "AppInstance",
         "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}},
        _build_target_user(_build_actor(user_info["username"], user_info["full_name"]))[0],
    ]
    return _assemble(
        "app.user_management.push_user_deactivation", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Push user deactivation to app: {app}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=target,
    )


def _gen_system_agent_ad_push_password(config, user_info, session_context=None):
    """system.agent.ad.push_password_update — AD agent syncs a password change from on-prem AD.
    Actor is SystemPrincipal (the AD agent process, not a human); very high volume in hybrid orgs."""
    ip_ctx     = _get_random_ip_and_context(config, "benign_ingress_sources")
    agent_name = random.choice(_AD_AGENT_NAMES)
    ad_actor   = {"id": "SYSTEM", "type": "SystemPrincipal", "alternateId": "system@okta.com",
                  "displayName": agent_name, "detailEntry": None}
    client     = _build_client(ip_ctx, config, interactive_only=False)
    return _assemble(
        "system.agent.ad.push_password_update", ad_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Active Directory push password update for user",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_build_target_user(_build_actor(user_info["username"], user_info["full_name"])),
        transaction={"type": "JOB", "id": uuid.uuid4().hex, "detail": {}},
    )


def _gen_kerberos_auth(config, user_info, session_context=None):
    """user.authentication.auth_via_kerberos — Kerberos via Okta Desktop SSO / AD-joined machine."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=False)
    app    = random.choice(_KERBEROS_APPS)
    return _assemble(
        "user.authentication.auth_via_kerberos", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Authentication of user via Kerberos: {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": _app_instance_id(app), "type": "AppInstance",
                 "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
    )


def _gen_mfa_factor_challenge(config, user_info, session_context=None):
    """user.mfa.factor.challenge — Okta presents MFA challenge (pre-verify step).
    Fires before user.authentication.auth_via_mfa in the full OIE auth flow."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    cred   = random.choice(["OIE_OKTA_VERIFY_PUSH", "TOTP", "SMS", "EMAIL"])
    return _assemble(
        "user.mfa.factor.challenge", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Send MFA challenge to user",
        authentication_context=_build_authentication_context(cred),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context(cred),
    )


def _gen_auth_verify(config, user_info, session_context=None):
    """user.authentication.verify — password accepted, MFA step now required.
    Very high volume; fires on every password+MFA login. Standalone benign version
    (currently only generated inside _generate_mfa_bombing_sequence)."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.authentication.verify", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Verify user identity",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", include_auth_signals=True),
    )


def _gen_app_import_started(config, user_info, session_context=None):
    """app.generic.import.started.incremental_import — AD/LDAP incremental sync job starts.
    Very common in enterprise hybrid deployments; fires on every scheduled sync."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = _rand_app(config)
    return _assemble(
        "app.generic.import.started.incremental_import", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Start import: Incremental import",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": _app_instance_id(app), "type": "AppInstance",
                 "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
    )


def _gen_app_import_success(config, user_info, session_context=None):
    """app.generic.import.success — AD/LDAP sync job completed successfully."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=True)
    app    = _rand_app(config)
    return _assemble(
        "app.generic.import.success", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Finish import: Success",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": _app_instance_id(app), "type": "AppInstance",
                 "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
    )


def _gen_oauth2_authorize_success(config, user_info, session_context=None):
    """app.oauth2.as.authorize — OAuth2 authorization code request granted.
    Fires on every OAuth2 authorization flow. Only scope_denied variant existed before."""
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    app     = random.choice(_OAUTH_CLIENTS)
    return _assemble(
        "app.oauth2.as.authorize", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="OAuth2 authorization code request granted",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": _app_instance_id(app), "type": "AppInstance",
                 "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": "OPENID_CONNECT"}}],
    )


def _gen_oauth2_authorize_denied(config, user_info, session_context=None):
    """app.oauth2.as.authorize — OAuth2 authorization denied (bad redirect, missing scope)."""
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    app     = random.choice(_OAUTH_CLIENTS)
    return _assemble(
        "app.oauth2.as.authorize", actor, client,
        outcome={"result": "FAILURE", "reason": random.choice(_OAUTH2_DENY_REASONS)},
        severity="WARN", display_message="OAuth2 authorization request denied",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": _app_instance_id(app), "type": "AppInstance",
                 "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": "OPENID_CONNECT"}}],
    )


def _gen_hook_outbound_sent(config, user_info, session_context=None):
    """hook.outbound.request.sent — Okta fires an outbound event hook (Workflows / Events API).
    Actor is SystemPrincipal; target is the hook endpoint."""
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    system_actor = {"id": "SYSTEM", "type": "SystemPrincipal", "alternateId": "system@okta.com",
                    "displayName": "Okta System", "detailEntry": None}
    client  = _build_client(ip_ctx, config, interactive_only=False)
    hook    = random.choice(_HOOK_ENDPOINTS)
    return _assemble(
        "hook.outbound.request.sent", system_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Send outbound hook request",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": f"hook-{uuid.uuid4().hex[:20]}", "type": "HookType",
                 "displayName": hook, "alternateId": hook, "detailEntry": None}],
        transaction={"type": "JOB", "id": uuid.uuid4().hex, "detail": {}},
    )


def _gen_device_assurance_pass(config, user_info, session_context=None):
    """device.assurance.policy.evaluate — device meets assurance requirements (compliant)."""
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    policy  = random.choice(_POLICY_NAMES)
    os_types = ["Windows", "macOS", "iOS", "Android"]
    os_choice = random.choice(os_types)
    targets = [
        {"id": f"guuid{uuid.uuid4().hex[:20]}", "type": "Device",
         "displayName": f"Managed {os_choice} Device",
         "alternateId": f"serial-{uuid.uuid4().hex[:12].upper()}",
         "detailEntry": {"platform": os_choice, "managed": True, "registered": True}},
        {"id": f"pol-{uuid.uuid4()}", "type": "Policy",
         "displayName": policy, "alternateId": policy, "detailEntry": None},
    ]
    return _assemble(
        "device.assurance.policy.evaluate", actor, client,
        outcome={"result": "ALLOW", "reason": None},
        severity="INFO", display_message="Evaluate device assurance policy",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("SIGNED_NONCE"),
        target=targets,
    )


def _gen_device_assurance_fail(config, user_info, session_context=None):
    """device.assurance.policy.evaluate — device fails assurance check (unmanaged/non-compliant)."""
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    policy  = random.choice(_POLICY_NAMES)
    os_types = ["Windows", "macOS", "iOS", "Android"]
    os_choice = random.choice(os_types)
    targets = [
        {"id": f"guuid{uuid.uuid4().hex[:20]}", "type": "Device",
         "displayName": f"Unmanaged {os_choice} Device",
         "alternateId": f"serial-{uuid.uuid4().hex[:12].upper()}",
         "detailEntry": {"platform": os_choice, "managed": False, "registered": False}},
        {"id": f"pol-{uuid.uuid4()}", "type": "Policy",
         "displayName": policy, "alternateId": policy, "detailEntry": None},
    ]
    return _assemble(
        "device.assurance.policy.evaluate", actor, client,
        outcome={"result": "DENY", "reason": "DEVICE_NOT_COMPLIANT"},
        severity="WARN", display_message="Evaluate device assurance policy",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=targets,
    )


def _gen_user_registration_create(config, user_info, session_context=None):
    """user.registration.create — user self-registers via Okta CIAM self-service registration.
    Actor is the new user themselves (no admin actor)."""
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble(
        "user.registration.create", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Registration of new user",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_build_target_user(actor),
    )


# ---------------------------------------------------------------------------
# user.authentication — extended auth methods
# ---------------------------------------------------------------------------

def _gen_user_auth_via_idp(config, user_info, session_context=None):
    idp = random.choice(_IDP_NAMES)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("user.authentication.auth_via_IDP", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Authenticate user via IDP: {idp}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_target_idp(idp))

def _gen_user_auth_via_saml(config, user_info, session_context=None):
    app = _rand_app(config)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("user.authentication.auth_via_inbound_SAML", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Authenticate user via inbound SAML: {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_target_app(app))

def _gen_user_slo(config, user_info, session_context=None):
    app = _rand_app(config)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("user.authentication.slo", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"User single logout from app: {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_target_app(app))

def _gen_user_universal_logout(config, user_info, session_context=None):
    return _user_event(config, user_info, "user.authentication.universal_logout",
        "Universal Logout triggered for user",
        target=_target_user(user_info), admin=True, severity="WARN", session_context=session_context)

def _gen_user_auth_via_social(config, user_info, session_context=None):
    provider = random.choice(_SOCIAL_IDPS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("user.authentication.auth_via_social", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Authenticate user with social login: {provider}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_target_idp(provider))


# ---------------------------------------------------------------------------
# user.risk — risk level changes
# ---------------------------------------------------------------------------

def _gen_user_risk_change(config, user_info, session_context=None):
    old_level = random.choice(["LOW","MEDIUM","HIGH"])
    new_level = random.choice([l for l in ["LOW","MEDIUM","HIGH"] if l != old_level])
    return _user_event(config, user_info, "user.risk.change",
        f"User risk level changed: {old_level} → {new_level}",
        target=_target_user(user_info),
        severity="WARN" if new_level=="HIGH" else "WARN",
        extra_debug={"previousRiskLevel": old_level, "newRiskLevel": new_level,
                     "reasons": random.sample(_RISK_REASONS, 2)})

def _gen_user_risk_detect(config, user_info, session_context=None):
    reason = random.choice(_RISK_REASONS)
    return _user_event(config, user_info, "user.risk.detect",
        f"User risk detected: {reason}",
        target=_target_user(user_info),
        severity="WARN",
        extra_debug={"riskLevel": random.choice(["MEDIUM","HIGH"]),
                     "riskReason": reason,
                     "threatSuspected": "true"})


# ---------------------------------------------------------------------------
# group — lifecycle, privilege, app assignment
# ---------------------------------------------------------------------------

def _gen_group_lifecycle_create(config, user_info, session_context=None):
    name = random.choice(["Security Team","Contractors","Temp Access","Dev Team","Data Analysts"])
    return _admin_event(config, "group.lifecycle.create",
        f"Create Okta group: {name}", target=_target_group(name), session_context=session_context)

def _gen_group_lifecycle_delete(config, user_info, session_context=None):
    name = random.choice(["Old Team","Temp Contractors","Legacy Group","Archived"])
    return _admin_event(config, "group.lifecycle.delete",
        f"Delete Okta group: {name}", target=_target_group(name), severity="WARN", session_context=session_context)

def _gen_group_profile_update(config, user_info, session_context=None):
    name = random.choice(["IT Admins","Everyone","Finance","Security Team"])
    return _admin_event(config, "group.profile.update",
        f"Update Okta group profile: {name}", target=_target_group(name), session_context=session_context)

def _gen_group_privilege_grant(config, user_info, session_context=None):
    name  = random.choice(["IT Admins","Security Team","Help Desk"])
    role  = random.choice(_IAM_ROLES)
    return _admin_event(config, "group.privilege.grant",
        f"Grant admin privilege to group {name}: {role}",
        target=_target_group(name) + _target_role(role), severity="WARN", session_context=session_context)

def _gen_group_privilege_revoke(config, user_info, session_context=None):
    name = random.choice(["IT Admins","Security Team","Help Desk"])
    return _admin_event(config, "group.privilege.revoke",
        f"Revoke admin privilege from group: {name}",
        target=_target_group(name), severity="WARN", session_context=session_context)

def _gen_group_app_assignment_add(config, user_info, session_context=None):
    app  = _rand_app(config)
    name = random.choice(["Everyone","Engineering","Sales","Finance"])
    return _admin_event(config, "group.application_assignment.add",
        f"Add app {app} to group {name}",
        target=_target_group(name) + _target_app(app), session_context=session_context)

def _gen_group_app_assignment_remove(config, user_info, session_context=None):
    app  = _rand_app(config)
    name = random.choice(["Contractors","Temp Access","Old Team"])
    return _admin_event(config, "group.application_assignment.remove",
        f"Remove app {app} from group {name}",
        target=_target_group(name) + _target_app(app), severity="WARN", session_context=session_context)


# ---------------------------------------------------------------------------
# application.lifecycle & user_membership
# ---------------------------------------------------------------------------

def _gen_app_lifecycle(event_type, config, user_info, severity="INFO", session_context=None):
    app = _rand_app(config)
    verbs = {
        "application.lifecycle.create":     "Create application",
        "application.lifecycle.activate":   "Activate application",
        "application.lifecycle.deactivate": "Deactivate application",
        "application.lifecycle.delete":     "Delete application",
        "application.lifecycle.update":     "Update application",
    }
    return _admin_event(config, event_type, f"{verbs.get(event_type,'App event')}: {app}",
        target=_target_app(app), severity=severity, session_context=session_context)

def _gen_application_lifecycle_create(config, user_info, session_context=None):
    return _gen_app_lifecycle("application.lifecycle.create", config, user_info, session_context=session_context)
def _gen_application_lifecycle_activate(config, user_info, session_context=None):
    return _gen_app_lifecycle("application.lifecycle.activate", config, user_info, session_context=session_context)
def _gen_application_lifecycle_deactivate(config, user_info, session_context=None):
    return _gen_app_lifecycle("application.lifecycle.deactivate", config, user_info, severity="WARN", session_context=session_context)
def _gen_application_lifecycle_delete(config, user_info, session_context=None):
    return _gen_app_lifecycle("application.lifecycle.delete", config, user_info, severity="WARN", session_context=session_context)
def _gen_application_lifecycle_update(config, user_info, session_context=None):
    return _gen_app_lifecycle("application.lifecycle.update", config, user_info, session_context=session_context)

def _gen_application_user_membership_add(config, user_info, session_context=None):
    app = _rand_app(config)
    return _user_event(config, user_info, "application.user_membership.add",
        f"Add user to application: {app}", target=_target_user(user_info) + _target_app(app), admin=True, session_context=session_context)

def _gen_application_user_membership_remove(config, user_info, session_context=None):
    app = _rand_app(config)
    return _user_event(config, user_info, "application.user_membership.remove",
        f"Remove user from application: {app}", target=_target_user(user_info) + _target_app(app),
        admin=True, severity="WARN", session_context=session_context)

def _gen_application_user_membership_provision(config, user_info, session_context=None):
    app = _rand_app(config)
    return _user_event(config, user_info, "application.user_membership.provision",
        f"User provisioned to application: {app}", target=_target_user(user_info) + _target_app(app),
        admin=True, session_context=session_context)

def _gen_application_user_membership_deprovision(config, user_info, session_context=None):
    app = _rand_app(config)
    return _user_event(config, user_info, "application.user_membership.deprovision",
        f"User deprovisioned from application: {app}", target=_target_user(user_info) + _target_app(app),
        admin=True, severity="WARN", session_context=session_context)

def _gen_application_policy_sign_on_deny(config, user_info, session_context=None):
    app = _rand_app(config)
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("application.policy.sign_on.deny_access", actor, client,
        outcome={"result": "DENY", "reason": "SIGN_ON_POLICY"},
        severity="WARN", display_message=f"Deny user access to {app} due to sign-on policy",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_target_app(app))


# ---------------------------------------------------------------------------
# policy — lifecycle and rules
# ---------------------------------------------------------------------------

def _gen_policy_lifecycle(event_type, config, user_info, severity="INFO", session_context=None):
    name  = random.choice(_POLICY_NAMES)
    ptype = random.choice(["OKTA_SIGN_ON","PASSWORD","MFA_ENROLL","IDP_DISCOVERY","ACCESS_POLICY"])
    verbs = {"policy.lifecycle.create":"Create","policy.lifecycle.update":"Update",
             "policy.lifecycle.delete":"Delete","policy.lifecycle.activate":"Activate",
             "policy.lifecycle.deactivate":"Deactivate","policy.lifecycle.overwrite":"Overwrite"}
    return _admin_event(config, event_type,
        f"{verbs.get(event_type,'Policy action')} policy: {name}",
        target=_target_policy(name, ptype), severity=severity, session_context=session_context)

def _gen_policy_lifecycle_create(config, u, session_context=None):
    return _gen_policy_lifecycle("policy.lifecycle.create", config, u, session_context=session_context)
def _gen_policy_lifecycle_update(config, u, session_context=None):
    return _gen_policy_lifecycle("policy.lifecycle.update", config, u, session_context=session_context)
def _gen_policy_lifecycle_delete(config, u, session_context=None):
    return _gen_policy_lifecycle("policy.lifecycle.delete", config, u, severity="WARN", session_context=session_context)
def _gen_policy_lifecycle_activate(config, u, session_context=None):
    return _gen_policy_lifecycle("policy.lifecycle.activate", config, u, session_context=session_context)
def _gen_policy_lifecycle_deactivate(config, u, session_context=None):
    return _gen_policy_lifecycle("policy.lifecycle.deactivate", config, u, severity="WARN", session_context=session_context)

def _gen_policy_rule(event_type, config, user_info, severity="INFO", session_context=None):
    rule = random.choice(_RULE_NAMES)
    policy = random.choice(_POLICY_NAMES)
    verbs = {"policy.rule.add":"Add","policy.rule.update":"Update",
             "policy.rule.delete":"Delete","policy.rule.activate":"Activate",
             "policy.rule.deactivate":"Deactivate"}
    return _admin_event(config, event_type,
        f"{verbs.get(event_type,'Rule action')} policy rule: {rule}",
        target=_target_rule(rule) + _target_policy(policy), severity=severity, session_context=session_context)

def _gen_policy_rule_add(config, u, session_context=None):        return _gen_policy_rule("policy.rule.add", config, u, session_context=session_context)
def _gen_policy_rule_update(config, u, session_context=None):     return _gen_policy_rule("policy.rule.update", config, u, session_context=session_context)
def _gen_policy_rule_delete(config, u, session_context=None):     return _gen_policy_rule("policy.rule.delete", config, u, severity="WARN", session_context=session_context)
def _gen_policy_rule_activate(config, u, session_context=None):   return _gen_policy_rule("policy.rule.activate", config, u, session_context=session_context)
def _gen_policy_rule_deactivate(config, u, session_context=None): return _gen_policy_rule("policy.rule.deactivate", config, u, severity="WARN", session_context=session_context)

def _gen_policy_auth_reevaluate_fail(config, user_info, session_context=None):
    return _user_event(config, user_info, "policy.auth_reevaluate.fail",
        "Auth policy re-evaluation resulted in policy violation",
        severity="WARN", outcome_result="FAILURE", outcome_reason="POLICY_VIOLATION",
        extra_debug={"risk": "{level=HIGH}"}, session_context=session_context)

def _gen_policy_entity_risk_evaluate(config, user_info, session_context=None):
    level = random.choice(_RISK_LEVELS)
    return _user_event(config, user_info, "policy.entity_risk.evaluate",
        f"Evaluation of Entity Risk Policy: level={level}",
        extra_debug={"riskLevel": level, "reasons": random.sample(_RISK_REASONS, 2)}, session_context=session_context)

def _gen_policy_entity_risk_action(config, user_info, session_context=None):
    actions = ["BLOCK","STEP_UP_AUTH","NOTIFY","LOG_ONLY"]
    action  = random.choice(actions)
    return _user_event(config, user_info, "policy.entity_risk.action",
        f"Entity Risk Policy action invoked: {action}",
        severity="WARN",
        extra_debug={"action": action, "riskLevel": random.choice(["MEDIUM","HIGH"])}, session_context=session_context)


# ---------------------------------------------------------------------------
# security — attacks, breach, session, trusted origins, authenticators
# ---------------------------------------------------------------------------

def _gen_security_attack_start(config, user_info, session_context=None):
    attack_types = ["CREDENTIAL_STUFFING","PASSWORD_SPRAY","BRUTE_FORCE","BOT_ACTIVITY"]
    attack = random.choice(attack_types)
    ip_ctx  = _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=False)
    return _assemble("security.attack.start", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"ThreatInsight: org under {attack} attack",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "attackType": attack, "threatSuspected": "true",
            "risk": "{level=HIGH}"}))

def _gen_security_attack_end(config, user_info, session_context=None):
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=False)
    return _assemble("security.attack.end", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="ThreatInsight: attack on org has ended",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"))

def _gen_security_breached_credential(config, user_info, session_context=None):
    reason = random.choice(_BREACH_REASONS)
    return _user_event(config, user_info, "security.breached_credential.detected",
        f"Breached credential detected: {reason}",
        target=_target_user(user_info), severity="WARN",
        extra_debug={"breachReason": reason, "threatSuspected": "true",
                     "risk": "{level=HIGH}"})

def _gen_security_session_roaming(config, user_info, session_context=None):
    return _user_event(config, user_info, "security.session.detect_client_roaming",
        "Roaming session detected — IP changed mid-session",
        severity="WARN",
        extra_debug={"behaviors": "{New Geo-Location=NEGATIVE, New Device=NEGATIVE, New IP=POSITIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity Behavior=POSITIVE, New City=NEGATIVE}",
                     "risk": "{level=MEDIUM}"})

def _gen_security_trusted_origin_create(config, user_info, session_context=None):
    origins = ["https://app.examplecorp.com","https://internal.corp.net","https://dev.examplecorp.com"]
    origin  = random.choice(origins)
    return _admin_event(config, "security.trusted_origin.create",
        f"Create trusted origin: {origin}",
        target=[{"id": f"tos-{uuid.uuid4()}", "type": "TrustedOrigin",
                 "displayName": origin, "alternateId": origin, "detailEntry": None}])

def _gen_security_trusted_origin_delete(config, user_info, session_context=None):
    return _admin_event(config, "security.trusted_origin.delete",
        "Delete trusted origin", severity="WARN",
        target=[{"id": f"tos-{uuid.uuid4()}", "type": "TrustedOrigin",
                 "displayName": "https://old.examplecorp.com",
                 "alternateId": "https://old.examplecorp.com", "detailEntry": None}])

def _gen_security_trusted_origin_update(config, user_info, session_context=None):
    return _admin_event(config, "security.trusted_origin.update",
        "Update trusted origin configuration",
        target=[{"id": f"tos-{uuid.uuid4()}", "type": "TrustedOrigin",
                 "displayName": "https://app.examplecorp.com",
                 "alternateId": "https://app.examplecorp.com", "detailEntry": None}])

def _gen_security_events_provider(config, user_info, session_context=None):
    providers = ["CrowdStrike","SentinelOne","Zscaler","Palo Alto Networks","Microsoft Defender"]
    provider  = random.choice(providers)
    detections = ["RISKY_USER","MALWARE_DETECTED","PHISHING_ATTEMPT","ANOMALOUS_BEHAVIOR"]
    detection  = random.choice(detections)
    ip_ctx  = _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=False)
    return _assemble("security.events.provider.receive_event", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"Security event from {provider}: {detection}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "provider": provider, "detectionType": detection,
            "risk": "{level=HIGH}"}))

def _gen_security_authenticator_activate(config, user_info, session_context=None):
    factor = random.choice(_AUTH_FACTORS)
    return _admin_event(config, "security.authenticator.lifecycle.activate",
        f"Admin activated authenticator: {factor}",
        target=[{"id": f"auth-{uuid.uuid4()}", "type": "Authenticator",
                 "displayName": factor, "alternateId": factor, "detailEntry": None}])

def _gen_security_authenticator_deactivate(config, user_info, session_context=None):
    factor = random.choice(_AUTH_FACTORS)
    return _admin_event(config, "security.authenticator.lifecycle.deactivate",
        f"Admin deactivated authenticator: {factor}",
        target=[{"id": f"auth-{uuid.uuid4()}", "type": "Authenticator",
                 "displayName": factor, "alternateId": factor, "detailEntry": None}],
        severity="WARN", session_context=session_context)


# ---------------------------------------------------------------------------
# zone — network zone management
# ---------------------------------------------------------------------------

def _gen_zone_event(event_type, config, user_info, severity="INFO", session_context=None):
    name = random.choice(_ZONE_NAMES)
    verbs = {"zone.create":"Create","zone.update":"Update","zone.delete":"Delete",
             "zone.activate":"Activate","zone.deactivate":"Deactivate",
             "zone.make_blacklist":"Mark as blacklist","zone.remove_blacklist":"Unmark blacklist"}
    return _admin_event(config, event_type,
        f"{verbs.get(event_type,'Zone action')} network zone: {name}",
        target=_target_zone(name), severity=severity, session_context=session_context)

def _gen_zone_create(c, u, session_context=None):         return _gen_zone_event("zone.create", c, u, session_context=session_context)
def _gen_zone_update(c, u, session_context=None):         return _gen_zone_event("zone.update", c, u, session_context=session_context)
def _gen_zone_delete(c, u, session_context=None):         return _gen_zone_event("zone.delete", c, u, "WARN", session_context=session_context)
def _gen_zone_activate(c, u, session_context=None):       return _gen_zone_event("zone.activate", c, u, session_context=session_context)
def _gen_zone_deactivate(c, u, session_context=None):     return _gen_zone_event("zone.deactivate", c, u, "WARN", session_context=session_context)
def _gen_zone_make_blacklist(c, u, session_context=None):  return _gen_zone_event("zone.make_blacklist", c, u, "WARN", session_context=session_context)
def _gen_zone_remove_blacklist(c, u, session_context=None):return _gen_zone_event("zone.remove_blacklist", c, u, session_context=session_context)


# ---------------------------------------------------------------------------
# system — API tokens, email, SMS, voice, IDP, org rate limits, log stream
# ---------------------------------------------------------------------------

def _gen_system_api_token_revoke(config, user_info, session_context=None):
    return _admin_event(config, "system.api_token.revoke",
        "Revoke API token", severity="WARN",
        target=[{"id": f"token-{uuid.uuid4().hex[:20]}", "type": "Token",
                 "displayName": "Revoked Token", "alternateId": "Revoked Token", "detailEntry": None}])

def _gen_system_api_token_update(config, user_info, session_context=None):
    return _admin_event(config, "system.api_token.update",
        "Update API token",
        target=[{"id": f"token-{uuid.uuid4().hex[:20]}", "type": "Token",
                 "displayName": "Updated Token", "alternateId": "Updated Token", "detailEntry": None}])

def _gen_system_api_token_enable(config, user_info, session_context=None):
    return _admin_event(config, "system.api_token.enable",
        "Enable API token",
        target=[{"id": f"token-{uuid.uuid4().hex[:20]}", "type": "Token",
                 "displayName": "Enabled Token", "alternateId": "Enabled Token", "detailEntry": None}])

def _gen_system_email_factor_verify(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("system.email.send_factor_verify_message", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Email verification sent to user",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("EMAIL"))

def _gen_system_email_password_reset(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("system.email.password_reset.sent_message", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Password reset email sent",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("EMAIL"))

def _gen_system_email_new_device(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("system.email.new_device_notification.sent_message", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="New device sign-in notification email sent",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("EMAIL"))

def _gen_system_sms_factor_verify(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("system.sms.send_factor_verify_message", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="SMS factor verification sent",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("SMS"))

def _gen_system_sms_password_reset(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("system.sms.send_password_reset_message", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Password reset SMS sent",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("SMS"))

def _gen_system_voice_mfa_challenge(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("system.voice.send_mfa_challenge_call", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Voice MFA challenge call sent",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("VOICE_CALL"))

def _gen_system_voice_password_reset(config, user_info, session_context=None):
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("system.voice.send_password_reset_call", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message="Password reset voice call sent",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("VOICE_CALL"))

def _gen_system_idp_event(event_type, config, user_info, severity="INFO", session_context=None):
    idp   = random.choice(_IDP_NAMES)
    verbs = {"system.idp.lifecycle.create":"Create","system.idp.lifecycle.update":"Update",
             "system.idp.lifecycle.delete":"Delete","system.idp.lifecycle.activate":"Activate",
             "system.idp.lifecycle.deactivate":"Deactivate"}
    return _admin_event(config, event_type,
        f"{verbs.get(event_type,'IDP action')} identity provider: {idp}",
        target=_target_idp(idp), severity=severity, session_context=session_context)

def _gen_system_idp_create(c, u, session_context=None):      return _gen_system_idp_event("system.idp.lifecycle.create", c, u, session_context=session_context)
def _gen_system_idp_update(c, u, session_context=None):      return _gen_system_idp_event("system.idp.lifecycle.update", c, u, session_context=session_context)
def _gen_system_idp_delete(c, u, session_context=None):      return _gen_system_idp_event("system.idp.lifecycle.delete", c, u, "WARN", session_context=session_context)
def _gen_system_idp_activate(c, u, session_context=None):    return _gen_system_idp_event("system.idp.lifecycle.activate", c, u, session_context=session_context)
def _gen_system_idp_deactivate(c, u, session_context=None):  return _gen_system_idp_event("system.idp.lifecycle.deactivate", c, u, "WARN", session_context=session_context)

def _gen_system_org_rate_limit_violation(config, user_info, session_context=None):
    endpoint = random.choice(["/api/v1/users","/api/v1/sessions","/oauth2/v1/token","/api/v1/logs"])
    return _admin_event(config, "system.org.rate_limit.violation",
        f"Org rate limit violation: {endpoint}", severity="WARN",
        extra_debug={"endpoint": endpoint, "remainingRequests": "0"}, session_context=session_context)

def _gen_system_org_rate_limit_warning(config, user_info, session_context=None):
    endpoint = random.choice(["/api/v1/users","/api/v1/sessions","/oauth2/v1/token"])
    return _admin_event(config, "system.org.rate_limit.warning",
        f"Org rate limit warning: {endpoint}",
        extra_debug={"endpoint": endpoint, "remainingRequests": str(random.randint(5, 50))}, session_context=session_context)

def _gen_system_org_rate_limit_burst(config, user_info, session_context=None):
    return _admin_event(config, "system.org.rate_limit.burst",
        "Burst rate limit capacity activated", severity="WARN", session_context=session_context)

def _gen_system_log_stream_create(config, user_info, session_context=None):
    sinks = ["Splunk","AWS S3","Azure Event Hubs","Google Pub/Sub","Sumo Logic","Datadog"]
    sink  = random.choice(sinks)
    return _admin_event(config, "system.log_stream.lifecycle.create",
        f"Create log stream: {sink}",
        target=[{"id": f"ls-{uuid.uuid4()}", "type": "LogStream",
                 "displayName": sink, "alternateId": sink, "detailEntry": None}])

def _gen_system_log_stream_delete(config, user_info, session_context=None):
    return _admin_event(config, "system.log_stream.lifecycle.delete",
        "Delete log stream", severity="WARN",
        target=[{"id": f"ls-{uuid.uuid4()}", "type": "LogStream",
                 "displayName": "Deleted Stream", "alternateId": "Deleted Stream", "detailEntry": None}])

def _gen_system_mfa_factor_activate(config, user_info, session_context=None):
    factor = random.choice(_AUTH_FACTORS)
    return _admin_event(config, "system.mfa.factor.activate",
        f"Admin activated org-wide MFA factor: {factor}",
        target=[{"id": f"mfa-{uuid.uuid4()}", "type": "AuthenticatorEnrollment",
                 "displayName": factor, "alternateId": factor, "detailEntry": None}])

def _gen_system_mfa_factor_deactivate(config, user_info, session_context=None):
    factor = random.choice(_AUTH_FACTORS)
    return _admin_event(config, "system.mfa.factor.deactivate",
        f"Admin deactivated org-wide MFA factor: {factor}",
        target=[{"id": f"mfa-{uuid.uuid4()}", "type": "AuthenticatorEnrollment",
                 "displayName": factor, "alternateId": factor, "detailEntry": None}],
        severity="WARN", session_context=session_context)


# ---------------------------------------------------------------------------
# app.oauth2 — token grants, revocations, OIDC sign-on, client management
# ---------------------------------------------------------------------------

def _oauth2_target(client_name):
    return [{"id": _app_instance_id(client_name), "type": "AppInstance",
             "displayName": client_name, "alternateId": client_name,
             "detailEntry": {"signOnModeType": "OPENID_CONNECT"}}]

def _gen_oauth2_token_grant_access(config, user_info, session_context=None):
    client = random.choice(_OAUTH_CLIENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.oauth2.as.token.grant.access_token", actor, c,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"OAuth2 access token granted: {client}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD",
            extra={"grantType": "authorization_code", "scope": "openid profile email",
                   "tokenLifetime": "3600"}),
        target=_oauth2_target(client))

def _gen_oauth2_token_grant_refresh(config, user_info, session_context=None):
    client = random.choice(_OAUTH_CLIENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.oauth2.as.token.grant.refresh_token", actor, c,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"OAuth2 refresh token granted: {client}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_oauth2_target(client))

def _gen_oauth2_token_grant_id_token(config, user_info, session_context=None):
    """app.oauth2.as.token.grant.id_token — OIDC id_token issued as part of authorization code flow.
    Fires alongside access_token on every OIDC login; very high volume in OIDC-heavy environments."""
    client = random.choice(_OAUTH_CLIENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.oauth2.as.token.grant.id_token", actor, c,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"OAuth2 id token granted: {client}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD",
            extra={"grantType": "authorization_code", "scope": "openid profile email",
                   "tokenLifetime": "3600"}),
        target=_oauth2_target(client))


def _gen_oauth2_introspect(config, user_info, session_context=None):
    """app.oauth2.as.introspect — token introspection call from an API/service validating a bearer token.
    Very common in microservice architectures; fires on every inbound API request that validates tokens."""
    client = random.choice(_OAUTH_CLIENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=False)
    return _assemble("app.oauth2.as.introspect", actor, c,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"OAuth2 token introspection: {client}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_oauth2_target(client))


def _gen_oauth2_token_revoke(config, user_info, session_context=None):
    client = random.choice(_OAUTH_CLIENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.oauth2.as.token.revoke", actor, c,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"OAuth2 token revoked: {client}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_oauth2_target(client))

def _gen_oauth2_token_detect_reuse(config, user_info, session_context=None):
    """Token reuse = potential session hijack."""
    client = random.choice(_OAUTH_CLIENTS)
    ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=False)
    return _assemble("app.oauth2.as.token.detect_reuse", actor, c,
        outcome={"result": "FAILURE", "reason": "TOKEN_REUSE_DETECTED"},
        severity="WARN", display_message=f"One-time refresh token reuse detected: {client}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}",
            "threatSuspected": "true"}),
        target=_oauth2_target(client))

def _gen_oauth2_signon(config, user_info, session_context=None):
    client = random.choice(_OAUTH_CLIENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.oauth2.signon", actor, c,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"User performed OIDC SSO to app: {client}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_oauth2_target(client))

def _gen_oauth2_client_create(config, user_info, session_context=None):
    client = random.choice(_OAUTH_CLIENTS)
    return _admin_event(config, "app.oauth2.client.lifecycle.create",
        f"Create OAuth client: {client}", target=_oauth2_target(client), session_context=session_context)

def _gen_oauth2_client_delete(config, user_info, session_context=None):
    client = random.choice(_OAUTH_CLIENTS)
    return _admin_event(config, "app.oauth2.client.lifecycle.delete",
        f"Delete OAuth client: {client}", target=_oauth2_target(client), severity="WARN", session_context=session_context)

def _gen_oauth2_scope_denied(config, user_info, session_context=None):
    client = random.choice(_OAUTH_CLIENTS)
    scopes = ["admin:org","write:users","delete:apps","manage:policies"]
    scope  = random.choice(scopes)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.oauth2.as.authorize.scope_denied", actor, c,
        outcome={"result": "FAILURE", "reason": "SCOPE_DENIED_BY_POLICY"},
        severity="WARN", display_message=f"OAuth2 scope denied: {scope}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={"deniedScope": scope}),
        target=_oauth2_target(client))

def _gen_oauth2_consent_grant(config, user_info, session_context=None):
    client = random.choice(_OAUTH_CLIENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.oauth2.as.consent.grant", actor, c,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"User granted consent to app: {client}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", extra={"scope": "openid profile email"}),
        target=_oauth2_target(client))

def _gen_oauth2_consent_revoke(config, user_info, session_context=None):
    client = random.choice(_OAUTH_CLIENTS)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    c      = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.oauth2.as.consent.revoke", actor, c,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"Consent revoked for app: {client}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_oauth2_target(client))


# ---------------------------------------------------------------------------
# iam — roles and resource sets
# ---------------------------------------------------------------------------

def _gen_iam_role_create(config, user_info, session_context=None):
    role = f"Custom {random.choice(['Security','Compliance','Audit','Provisioning'])} Role"
    return _admin_event(config, "iam.role.create",
        f"Create custom admin role: {role}", target=_target_role(role), session_context=session_context)

def _gen_iam_role_delete(config, user_info, session_context=None):
    role = random.choice(_IAM_ROLES)
    return _admin_event(config, "iam.role.delete",
        f"Delete custom admin role: {role}", target=_target_role(role), severity="WARN", session_context=session_context)

def _gen_iam_role_update(config, user_info, session_context=None):
    role = random.choice(_IAM_ROLES)
    return _admin_event(config, "iam.role.update",
        f"Update custom admin role: {role}", target=_target_role(role), session_context=session_context)

def _gen_iam_resourceset_bindings_add(config, user_info, session_context=None):
    role = random.choice(_IAM_ROLES)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    return _admin_event(config, "iam.resourceset.bindings.add",
        f"Admin role assignment created: {role}",
        target=_build_target_user(target_user) + _target_role(role),
        severity="WARN", session_context=session_context)

def _gen_iam_resourceset_bindings_delete(config, user_info, session_context=None):
    role = random.choice(_IAM_ROLES)
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    return _admin_event(config, "iam.resourceset.bindings.delete",
        f"Admin role assignment deleted: {role}",
        target=_build_target_user(target_user) + _target_role(role), session_context=session_context)


# ---------------------------------------------------------------------------
# device.lifecycle — full lifecycle coverage
# ---------------------------------------------------------------------------

def _device_target(os_type=None):
    os_choice = os_type or random.choice(["Windows","macOS","iOS","Android","ChromeOS"])
    return [{"id": f"guuid{uuid.uuid4().hex[:20]}", "type": "Device",
             "displayName": f"{os_choice} Device",
             "alternateId": f"serial-{uuid.uuid4().hex[:12].upper()}",
             "detailEntry": {"platform": os_choice, "managed": True, "registered": True}}]

def _gen_device_lifecycle(event_type, config, user_info, severity="INFO", session_context=None):
    verbs = {"device.lifecycle.activate":"Activate","device.lifecycle.deactivate":"Deactivate",
             "device.lifecycle.delete":"Delete","device.lifecycle.suspend":"Suspend",
             "device.lifecycle.unsuspend":"Unsuspend"}
    return _admin_event(config, event_type,
        f"{verbs.get(event_type,'Device action')} device",
        target=_device_target(), severity=severity, session_context=session_context)

def _gen_device_lifecycle_activate(c, u, session_context=None):    return _gen_device_lifecycle("device.lifecycle.activate", c, u, session_context=session_context)
def _gen_device_lifecycle_deactivate(c, u, session_context=None):  return _gen_device_lifecycle("device.lifecycle.deactivate", c, u, "WARN", session_context=session_context)
def _gen_device_lifecycle_delete(c, u, session_context=None):      return _gen_device_lifecycle("device.lifecycle.delete", c, u, "WARN", session_context=session_context)
def _gen_device_lifecycle_suspend(c, u, session_context=None):     return _gen_device_lifecycle("device.lifecycle.suspend", c, u, "WARN", session_context=session_context)
def _gen_device_lifecycle_unsuspend(c, u, session_context=None):   return _gen_device_lifecycle("device.lifecycle.unsuspend", c, u, session_context=session_context)

def _gen_device_user_remove(config, user_info, session_context=None):
    target_user = _build_actor(user_info["username"], user_info["full_name"])
    return _admin_event(config, "device.user.remove",
        "Remove device from user",
        target=_device_target() + _build_target_user(target_user),
        severity="WARN", session_context=session_context)


# ---------------------------------------------------------------------------
# app.access_request & app.generic
# ---------------------------------------------------------------------------

def _gen_app_access_request(config, user_info, session_context=None):
    app = _rand_app(config)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.access_request.request", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO", display_message=f"User requested access to app: {app}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_target_app(app))

def _gen_app_access_grant(config, user_info, session_context=None):
    app = _rand_app(config)
    return _admin_event(config, "app.access_request.grant",
        f"App access request granted: {app}", target=_target_app(app), session_context=session_context)

def _gen_app_access_deny(config, user_info, session_context=None):
    app = _rand_app(config)
    return _admin_event(config, "app.access_request.deny",
        f"App access request denied: {app}", target=_target_app(app),
        outcome_result="FAILURE", outcome_reason="REQUEST_DENIED", severity="WARN", session_context=session_context)

def _gen_app_unauth_access_attempt(config, user_info, session_context=None):
    app = _rand_app(config)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    return _assemble("app.generic.unauth_app_access_attempt", actor, client,
        outcome={"result": "FAILURE", "reason": "UNAUTHORIZED"},
        severity="WARN", display_message=f"User attempted unauthorized access to: {app}",
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=_target_app(app))


# ===========================================================================
# CORRELATED THREAT SEQUENCES
# ===========================================================================

def _generate_rogue_admin_creation(config, user_info, session_context=None):
    """user.lifecycle.create + user.account.privilege.grant — rogue admin account."""
    print("    - Okta Module generating rogue admin creation sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(ip_ctx)
    new_username = f"svc.{uuid.uuid4().hex[:8]}@examplecorp.com"
    new_user_id = _stable_user_id(new_username)
    t_new = [{"id": new_user_id, "type": "User", "alternateId": new_username,
              "displayName": "New Service Account", "detailEntry": None}]
    logs.append(_assemble("user.lifecycle.create", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None}, severity="INFO",
        display_message=f"Create Okta user: {new_username}",
        security_context=sec_ctx, debug_context=_build_debug_context("PASSWORD"), target=t_new))
    role = random.choice(["SUPER_ADMIN","ORG_ADMIN","APP_ADMIN"])
    logs.append(_assemble("user.account.privilege.grant", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Admin role {role} granted to newly created user",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "privilegeGranted": role,
            "risk": "{level=HIGH}"}),
        target=t_new))
    return logs


def _generate_breached_credential_login(config, user_info, session_context=None):
    """security.breached_credential.detected + user.session.start SUCCESS."""
    print("    - Okta Module generating breached credential login sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    c1 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("security.breached_credential.detected", actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Breached credential detected for {user_info["username"]}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "breachReason": "CREDENTIAL_STUFFING", "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_build_target_user(actor)))
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    c2["ipAddress"] = ip_ctx.get("ip")
    logs.append(_assemble("user.session.start", actor, c2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_session_start_targets("PASSWORD")))
    return logs


def _generate_risk_policy_bypass(config, user_info, session_context=None):
    """user.risk.detect + policy.auth_reevaluate.fail + user.authentication.sso SUCCESS."""
    print("    - Okta Module generating risk policy bypass sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    app = random.choice(config.get("okta_config",{}).get("okta_sso_apps",["Salesforce"]))
    reason = random.choice(_RISK_REASONS)
    c1 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("user.risk.detect", actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"User risk detected: {reason}", security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "riskLevel": "HIGH", "riskReason": reason, "threatSuspected": "true"}),
        target=_build_target_user(actor)))
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("policy.auth_reevaluate.fail", actor, c2,
        outcome={"result": "FAILURE", "reason": "POLICY_VIOLATION"}, severity="WARN",
        display_message="Auth policy re-evaluation violation — user should be blocked",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}"})))
    c3 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("user.authentication.sso", actor, c3,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"SSO succeeded despite risk policy violation — {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_make_sso_target(app)))
    return logs


def _generate_shadow_idp_attack(config, user_info, session_context=None):
    """system.idp.lifecycle.create + user.authentication.auth_via_IDP (new IDP)."""
    print("    - Okta Module generating shadow IDP attack sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    rogue = f"corp-auth-{uuid.uuid4().hex[:6]}.attacker.io"
    t_idp = [{"id": f"idp-{uuid.uuid4()}", "type": "IdentityProvider",
               "displayName": rogue, "alternateId": rogue, "detailEntry": None}]
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("system.idp.lifecycle.create", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"New identity provider created: {rogue}", security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}"}),
        target=t_idp))
    c2 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("user.authentication.auth_via_IDP", actor, c2,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"User authed via newly created IDP: {rogue}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=t_idp))
    return logs


def _generate_universal_logout_bypass(config, user_info, session_context=None):
    """user.authentication.universal_logout + user.session.start SUCCESS (same IP)."""
    print("    - Okta Module generating universal logout bypass sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    t_user = _build_target_user(actor)
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("user.authentication.universal_logout", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Universal Logout triggered for {user_info["username"]}",
        security_context=sec_ctx, debug_context=_build_debug_context("PASSWORD"), target=t_user))
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    c2["ipAddress"] = ip_ctx.get("ip")
    logs.append(_assemble("user.session.start", actor, c2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_session_start_targets("PASSWORD")))
    return logs


def _generate_defense_evasion(config, user_info, session_context=None):
    """system.log_stream.lifecycle.delete + policy.lifecycle.deactivate + user.authentication.sso."""
    print("    - Okta Module generating defense evasion sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    app = random.choice(config.get("okta_config",{}).get("okta_sso_apps",["Salesforce"]))
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("system.log_stream.lifecycle.delete", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message="Log stream deleted — SIEM telemetry removed", security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}"}),
        target=[{"id": f"ls-{uuid.uuid4()}", "type": "LogStream",
                 "displayName": "SIEM Stream", "alternateId": "SIEM Stream", "detailEntry": None}]))
    policy_name = random.choice(["Global Session Policy","MFA Enforcement Policy","Risk-Based Access"])
    c2 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("policy.lifecycle.deactivate", admin_actor, c2,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Security policy deactivated: {policy_name}", security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}"}),
        target=[{"id": f"pol-{uuid.uuid4()}", "type": "Policy",
                 "displayName": policy_name, "alternateId": policy_name, "detailEntry": None}]))
    c3 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("user.authentication.sso", actor, c3,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"SSO access after defense evasion: {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_make_sso_target(app)))
    return logs


def _generate_third_party_signal_access(config, user_info, session_context=None):
    """security.events.provider.receive_event (RISKY_USER) + user.authentication.sso SUCCESS."""
    print("    - Okta Module generating third-party signal + continued access sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "benign_ingress_sources")
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    app = random.choice(config.get("okta_config",{}).get("okta_sso_apps",["Salesforce"]))
    provider = random.choice(["CrowdStrike","SentinelOne","Zscaler","Microsoft Defender"])
    detection = random.choice(["RISKY_USER","MALWARE_DETECTED","DEVICE_COMPROMISED","LATERAL_MOVEMENT"])
    admin_actor = _build_admin_actor(config, session_context)
    c1 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("security.events.provider.receive_event", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Security event from {provider}: {detection} for {user_info["username"]}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "provider": provider, "detectionType": detection,
            "affectedUser": user_info["username"],
            "risk": "{level=HIGH}"}),
        target=_build_target_user(actor)))
    c2 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("user.authentication.sso", actor, c2,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"SSO succeeded on compromised account: {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_make_sso_target(app)))
    return logs


def _generate_dormant_account_reactivation(config, user_info, session_context=None):
    """user.lifecycle.reactivate + burst of user.authentication.sso to sensitive apps."""
    print("    - Okta Module generating dormant account reactivation sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    t_user = _build_target_user(actor)
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("user.lifecycle.reactivate", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Dormant account reactivated: {user_info["username"]}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}"}),
        target=t_user))
    sensitive_apps = ["AWS Console","Azure Portal","GCP Console","Okta Admin Console","Snowflake","Databricks"]
    for app in random.sample(sensitive_apps, 3):
        c = _build_client(ip_ctx, config, interactive_only=False)
        c["ipAddress"] = ip_ctx.get("ip")
        logs.append(_assemble("user.authentication.sso", actor, c,
            outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
            display_message=f"Reactivated account accessing sensitive app: {app}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD", extra={
                "threatSuspected": "true",
                "risk": "{level=HIGH}"}),
            target=_make_sso_target(app)))
    return logs


def _generate_oauth_consent_abuse(config, user_info, session_context=None):
    """app.oauth2.as.consent.grant (broad scope) + burst of app.oauth2.as.token.grant.access_token."""
    print("    - Okta Module generating OAuth consent abuse sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "benign_ingress_sources")
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    rogue_client = random.choice(["BudgetApproval Tool","HR Sync Service","Analytics Connector","Data Export Utility"])
    t_client = [{"id": _app_instance_id(rogue_client), "type": "AppInstance",
                 "displayName": rogue_client, "alternateId": rogue_client, "detailEntry": {"signOnModeType": "OPENID_CONNECT"}}]
    broad_scopes = ["okta.users.manage","okta.apps.manage","okta.groups.manage","okta.policies.manage"]
    admin_actor = _build_admin_actor(config, session_context)
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("app.oauth2.as.consent.grant", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Admin granted broad OAuth consent: {rogue_client}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "scope": " ".join(random.sample(broad_scopes, 3)), "grantType": "admin_consent",
            "risk": "{level=MEDIUM}"}),
        target=t_client))
    for _ in range(random.randint(4, 7)):
        c = _build_client(ip_ctx, config, interactive_only=True)
        logs.append(_assemble("app.oauth2.as.token.grant.access_token", actor, c,
            outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
            display_message=f"Access token granted to over-permissioned app: {rogue_client}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD", extra={
                "grantType": "client_credentials", "scope": random.choice(broad_scopes),
                "risk": "{level=HIGH}"}),
            target=t_client))
    return logs


def _generate_session_clear_bypass(config, user_info, session_context=None):
    """user.session.clear + user.session.start SUCCESS (same suspicious IP)."""
    print("    - Okta Module generating session clear bypass sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    t_user = _build_target_user(actor)
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("user.session.clear", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Admin cleared all sessions for {user_info["username"]}",
        security_context=sec_ctx, debug_context=_build_debug_context("PASSWORD"), target=t_user))
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    c2["ipAddress"] = ip_ctx.get("ip")
    logs.append(_assemble("user.session.start", actor, c2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_session_start_targets("PASSWORD")))
    return logs


def _generate_device_swap_enrollment(config, user_info, session_context=None):
    """device.lifecycle.delete + device.enrollment.create + user.authentication.sso."""
    print("    - Okta Module generating device swap enrollment sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    app = random.choice(config.get("okta_config",{}).get("okta_sso_apps",["Salesforce"]))
    old_dev = [{"id": f"guuid{uuid.uuid4().hex[:20]}", "type": "Device",
                "displayName": "Corporate Laptop (Managed)",
                "alternateId": f"serial-{uuid.uuid4().hex[:12].upper()}",
                "detailEntry": {"platform": "Windows", "managed": True, "registered": True}}]
    new_dev = [{"id": f"guuid{uuid.uuid4().hex[:20]}", "type": "Device",
                "displayName": "Unknown Device",
                "alternateId": f"serial-{uuid.uuid4().hex[:12].upper()}",
                "detailEntry": {"platform": "Unknown", "managed": False, "registered": False}}]
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("device.lifecycle.delete", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message="Managed device deleted", security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD"), target=old_dev))
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("device.enrollment.create", actor, c2,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message="New unmanaged device enrolled", security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}"}),
        target=new_dev + _build_target_user(actor)))
    c3 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("user.authentication.sso", actor, c3,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"SSO from newly enrolled unmanaged device: {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_make_sso_target(app)))
    return logs


def _generate_iam_privilege_escalation(config, user_info, session_context=None):
    """iam.role.create + iam.resourceset.bindings.add + user.account.privilege.grant."""
    print("    - Okta Module generating IAM privilege escalation sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    t_user = _build_target_user(actor)
    role_name = f"Escalated-{random.choice(["Security","Compliance","Billing","Platform"])}-Role"
    t_role = [{"id": f"role-{uuid.uuid4()}", "type": "Role",
               "displayName": role_name, "alternateId": role_name, "detailEntry": None}]
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("iam.role.create", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Custom admin role created: {role_name}", security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}"}), target=t_role))
    c2 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("iam.resourceset.bindings.add", admin_actor, c2,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Role bound to user: {role_name}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}"}),
        target=t_user + t_role))
    c3 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("user.account.privilege.grant", admin_actor, c3,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Admin privilege granted after IAM escalation: {user_info["username"]}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "privilegeGranted": "SUPER_ADMIN",
            "risk": "{level=HIGH}",
            "threatSuspected": "true"}),
        target=t_user))
    return logs



def _generate_mfa_downgrade_access(config, user_info, session_context=None):
    """
    user.mfa.factor.deactivate (admin removes factor) + user.session.start SUCCESS from new IP.
    Detection: MFA removed for user who then logs in without it — account takeover assist.
    """
    print("    - Okta Module generating MFA downgrade + account access sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    factor = random.choice(_AUTH_FACTORS)
    t_factor = [{"id": f"mfa-{uuid.uuid4()}", "type": "AuthenticatorEnrollment",
                 "displayName": factor, "alternateId": factor, "detailEntry": None}]
    t_user = _build_target_user(actor)

    # Step 1 — admin deactivates MFA factor for the user
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("user.mfa.factor.deactivate", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Admin removed MFA factor {factor} for {user_info["username"]}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}"}),
        target=t_factor + t_user))

    # Step 2 — user logs in without MFA from suspicious IP (same session window)
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    c2["ipAddress"] = ip_ctx.get("ip")
    logs.append(_assemble("user.session.start", actor, c2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN",
        display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_session_start_targets("PASSWORD")))
    return logs


def _generate_authenticator_downgrade(config, user_info, session_context=None):
    """
    system.mfa.factor.deactivate (strong org-wide auth disabled) +
    user.authentication.auth_via_mfa (weak remaining factor) + user.authentication.sso SUCCESS.
    Detection: Attacker degrades org authentication strength then accesses apps.
    """
    print("    - Okta Module generating authenticator downgrade sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    app = random.choice(config.get("okta_config",{}).get("okta_sso_apps",["Salesforce"]))
    strong_factor = random.choice(["YubiKey", "WebAuthn", "Okta Verify"])
    weak_factor   = random.choice(["SMS", "Email", "Phone Call"])
    t_auth = [{"id": f"auth-{uuid.uuid4()}", "type": "Authenticator",
               "displayName": strong_factor, "alternateId": strong_factor, "detailEntry": None}]

    # Step 1 — org-wide strong authenticator deactivated
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("system.mfa.factor.deactivate", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Org-wide authenticator deactivated: {strong_factor}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}"}),
        target=t_auth))

    # Step 2 — user authenticates with weaker remaining factor
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("user.authentication.auth_via_mfa", actor, c2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"User authenticated with weak factor: {weak_factor}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "factor": weak_factor,
            "risk": "{level=HIGH}"})))

    # Step 3 — SSO succeeds with downgraded auth bar
    c3 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("user.authentication.sso", actor, c3,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO after authenticator downgrade: {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_make_sso_target(app)))
    return logs


def _generate_api_token_abuse(config, user_info, session_context=None):
    """
    system.api_token.create + system.org.rate_limit.violation (same actor, same session).
    Detection: Token created then immediately used to hammer the API — data exfiltration attempt.
    """
    print("    - Okta Module generating API token abuse sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    sec_ctx = _build_security_context(ip_ctx)
    endpoints = ["/api/v1/users", "/api/v1/groups", "/api/v1/apps",
                 "/api/v1/logs", "/api/v1/events", "/api/v1/authorizationServers"]
    endpoint = random.choice(endpoints)
    token_name = f"automation-{uuid.uuid4().hex[:8]}"
    t_token = [{"id": f"token-{uuid.uuid4().hex[:20]}", "type": "Token",
                "displayName": token_name, "alternateId": token_name, "detailEntry": None}]

    # Step 1 — API token created
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("system.api_token.create", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"API token created: {token_name}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}"}),
        target=t_token))

    # Step 2 — rate limit violation from same IP (token being hammered)
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    c2["ipAddress"] = ip_ctx.get("ip")
    logs.append(_assemble("system.org.rate_limit.violation", admin_actor, c2,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Rate limit violated — possible API enumeration: {endpoint}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "endpoint": endpoint, "remainingRequests": "0",
            "threatSuspected": "true",
            "risk": "{level=HIGH}"})))
    return logs


def _generate_zone_bypass_access(config, user_info, session_context=None):
    """
    zone.delete (corporate zone removed) + user.authentication.sso SUCCESS from that IP range.
    Detection: Admin deletes a network restriction zone, then SSO succeeds from previously blocked IP.
    """
    print("    - Okta Module generating zone bypass access sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    app = random.choice(config.get("okta_config",{}).get("okta_sso_apps",["Salesforce"]))
    zone_name = random.choice(["Corporate Network", "Blocked Countries", "TOR Exit Nodes",
                               "VPN-Required Zone", "Geo-Restricted Zone"])
    t_zone = [{"id": f"zone-{uuid.uuid4()}", "type": "NetworkZone",
               "displayName": zone_name, "alternateId": zone_name, "detailEntry": None}]

    # Step 1 — corporate/blocking zone deleted
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("zone.delete", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"Network zone deleted: {zone_name}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}"}),
        target=t_zone))

    # Step 2 — SSO now succeeds from IP that would have been restricted
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    c2["ipAddress"] = ip_ctx.get("ip")
    logs.append(_assemble("user.authentication.sso", actor, c2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO from previously restricted IP after zone deletion: {app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_make_sso_target(app)))
    return logs


def _generate_admin_app_after_compromise(config, user_info, session_context=None):
    """
    user.authentication.sso SUCCESS + user.session.access_admin_app (immediate pivot).
    Detection: User SSOs from suspicious location then immediately pivots to Okta admin console.
    """
    print("    - Okta Module generating admin app pivot after compromise sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "tor_exit_nodes")
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)
    initial_app = random.choice(config.get("okta_config",{}).get("okta_sso_apps",["Salesforce"]))

    # Step 1 — SSO to a normal app from suspicious IP (initial foothold)
    c1 = _build_client(ip_ctx, config, interactive_only=False)
    logs.append(_assemble("user.authentication.sso", actor, c1,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"SSO from suspicious IP: {initial_app}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}"}),
        target=_make_sso_target(initial_app)))

    # Step 2 — immediately accesses Okta admin console (privilege escalation)
    c2 = _build_client(ip_ctx, config, interactive_only=False)
    c2["ipAddress"] = ip_ctx.get("ip")
    logs.append(_assemble("user.session.access_admin_app", actor, c2,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="Admin console accessed immediately after suspicious SSO",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "threatSuspected": "true",
            "risk": "{level=HIGH}"}),
        target=_target_app("Okta Admin Console")))
    return logs


def _generate_rogue_oauth_client_spray(config, user_info, session_context=None):
    """
    app.oauth2.client.lifecycle.create + burst of app.oauth2.as.token.grant.access_token.
    Detection: New OAuth client registered and immediately starts harvesting access tokens.
    """
    print("    - Okta Module generating rogue OAuth client token spray sequence...")
    logs, ip_ctx = [], _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    actor = _build_actor(user_info["username"], user_info["full_name"])
    sec_ctx = _build_security_context(ip_ctx)

    rogue_client = f"data-sync-{uuid.uuid4().hex[:8]}"
    t_client = [{"id": _app_instance_id(rogue_client), "type": "AppInstance",
                 "displayName": rogue_client, "alternateId": rogue_client, "detailEntry": {"signOnModeType": "OPENID_CONNECT"}}]
    scopes = ["okta.users.read", "okta.groups.read", "okta.apps.read",
              "okta.logs.read", "okta.policies.read"]

    # Step 1 — rogue OAuth client created
    c1 = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble("app.oauth2.client.lifecycle.create", admin_actor, c1,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message=f"New OAuth client registered: {rogue_client}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=MEDIUM}"}),
        target=t_client))

    # Step 2 — immediate token spray from new client
    for _ in range(random.randint(5, 9)):
        c = _build_client(ip_ctx, config, interactive_only=True)
        logs.append(_assemble("app.oauth2.as.token.grant.access_token", actor, c,
            outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
            display_message=f"Token harvested by newly registered OAuth client: {rogue_client}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD", extra={
                "grantType": "client_credentials",
                "scope": random.choice(scopes),
                "threatSuspected": "true",
                "risk": "{level=HIGH}"}),
            target=t_client))
    return logs



def _generate_sms_otp_bombing(config, user_info, session_context=None):
    """SMS OTP bombing — attacker triggers rapid burst of SMS verify messages to exhaust the victim.
    Same concept as MFA push bombing but via SMS channel; volume signal (20-40 messages) is the indicator.
    Hunt: system.sms.send_factor_verify_message burst from same target user within a short window."""
    print("    - Okta Module simulating: SMS OTP bombing...")
    count = random.randint(20, 40)
    logs  = [_gen_system_sms_factor_verify(config, user_info, session_context) for _ in range(count)]
    return logs


def _generate_sign_on_policy_downgrade(config, user_info, session_context=None):
    """Admin weakens a sign-on policy rule (removes MFA requirement), then auth succeeds without MFA.
    Hunt: policy.rule.update by admin actor followed immediately by user.session.start with no MFA factor,
    then SSO to a sensitive app — the policy change and the no-MFA login are temporally linked."""
    print("    - Okta Module simulating: Sign-on policy downgrade + no-MFA login...")
    logs = []
    # Step 1: admin updates policy rule (drops MFA requirement)
    logs.append(_gen_policy_rule_update(config, user_info, session_context))
    # Step 2: login succeeds with only PASSWORD — no MFA factor in the auth chain
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor  = _build_actor(user_info["username"], user_info["full_name"])
    client = _build_client(ip_ctx, config, interactive_only=True)
    logs.append(_assemble(
        "user.session.start", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD", include_auth_signals=True),
        target=_session_start_targets("PASSWORD"),
    ))
    # Step 3: immediate SSO to a sensitive app (attacker pivoting)
    app = _rand_app(config)
    logs.append(_assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User single sign on to app",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=_build_security_context(ip_ctx),
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": _app_instance_id(app), "type": "AppInstance",
                 "displayName": app, "alternateId": app,
                 "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
    ))
    return logs


def _generate_aitm_phishing(config, user_info, session_context=None):
    """AiTM (Adversary-in-the-Middle) phishing — attacker proxies the Okta login page, relays
    credentials in real-time, and steals the resulting session token.

    Signal chain:
      1. user.session.start SUCCESS from a high-risk/Tor IP (phishing proxy)
      2. Immediate burst of user.authentication.sso to multiple sensitive apps (attacker pivoting)
      3. security.session.detect_client_roaming — token reused from a second IP

    Hunt: session.start from anomalous IP + SSO burst to sensitive apps within 60s + session roaming."""
    print("    - Okta Module simulating: AiTM phishing attack (session token theft)...")
    logs = []
    # Step 1: session.start via phishing proxy IP (high-risk country)
    phishing_ip = f"185.220.{random.randint(100, 110)}.{random.randint(1, 254)}"
    ip_ctx  = _make_ip_ctx_from(random.choice(_HIGH_RISK_COUNTRIES), {"ip": phishing_ip})
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(ip_ctx)
    logs.append(_assemble(
        "user.session.start", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", include_auth_signals=True,
            extra={"risk": "{level=HIGH}", "threatSuspected": "true"}),
        target=_session_start_targets("PASSWORD"),
    ))
    # Step 2: rapid SSO to several sensitive apps from the same stolen session
    sensitive_apps = ["AWS Console", "Azure Portal", "Salesforce", "GitHub Enterprise",
                      "Okta Admin Console", "Snowflake"]
    for app in random.sample(sensitive_apps, random.randint(3, 5)):
        logs.append(_assemble(
            "user.authentication.sso", actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="WARN", display_message="User single sign on to app",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD",
                extra={"risk": "{level=HIGH}", "threatSuspected": "true"}),
            target=[{"id": _app_instance_id(app), "type": "AppInstance",
                     "displayName": app, "alternateId": app,
                     "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
        ))
    # Step 3: session roaming alert fires when token is replayed from a different IP
    logs.append(_gen_security_session_roaming(config, user_info, session_context))
    return logs


def _generate_event_hook_deletion(config, user_info, session_context=None):
    """Defense evasion via event hook deletion — attacker removes outbound event hooks to blind the SIEM.

    Signal chain:
      1. system.event_hook.lifecycle.delete — hook deleted (SIEM/Slack/SOC notification silenced)
      2. user.authentication.sso continues to fire — activity goes unnoticed

    Hunt: hook deletion by a user account (not SystemPrincipal) followed by privilege changes or
    sensitive app access within the same session."""
    print("    - Okta Module simulating: Event hook deletion (defense evasion)...")
    logs = []
    # Step 1: delete the outbound event hook
    admin_actor = _build_admin_actor(config, session_context)
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    client  = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(ip_ctx)
    hook    = random.choice(_HOOK_ENDPOINTS)
    hook_id = f"who{uuid.uuid4().hex[:22]}"
    logs.append(_assemble(
        "system.event_hook.lifecycle.delete", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"Delete event hook: {hook}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": hook_id, "type": "EventHook",
                 "displayName": hook, "alternateId": hook, "detailEntry": None}],
    ))
    # Step 2: attacker continues activity — SSO to an admin-adjacent app, now unlogged externally
    app = "Okta Admin Console"
    logs.append(_assemble(
        "user.authentication.sso", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User single sign on to app",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": _app_instance_id(app), "type": "AppInstance",
                 "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": "SAML_2_0"}}],
    ))
    return logs


def _generate_malicious_oauth_app_registration(config, user_info, session_context=None):
    """Malicious OAuth app registered with broad okta.* admin scopes, then used to harvest tokens.

    Signal chain:
      1. app.oauth2.client.lifecycle.create — rogue OAuth client registered
      2. app.oauth2.as.consent.grant — user (or admin) grants consent to the broad scopes
      3. app.oauth2.as.token.grant.access_token × 3-6 — token issued and reused for API access

    Hunt: OAuth client creation where scope contains 'okta.' admin prefixes; consent grant to same
    client immediately after creation; burst of token grants from that client."""
    print("    - Okta Module simulating: Malicious OAuth app registration with admin scopes...")
    logs = []
    admin_actor = _build_admin_actor(config, session_context)
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    client  = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(ip_ctx)
    rogue_client = f"corp-{random.choice(['sync','backup','monitor','audit'])}-{uuid.uuid4().hex[:6]}"
    rogue_target = [{"id": _app_instance_id(rogue_client), "type": "AppInstance",
                     "displayName": rogue_client, "alternateId": rogue_client,
                     "detailEntry": {"signOnModeType": "OPENID_CONNECT"}}]
    # Pick 2-3 broad admin scopes — the signal that makes this suspicious
    bad_scopes = " ".join(random.sample(_OKTA_ADMIN_SCOPES, random.randint(2, 3)))
    # Step 1: register the rogue OAuth client
    logs.append(_assemble(
        "app.oauth2.client.lifecycle.create", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"Create OAuth client: {rogue_client}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={"requestedScopes": bad_scopes}),
        target=rogue_target,
    ))
    # Step 2: consent granted (admin self-consents or victim approves the consent screen)
    logs.append(_assemble(
        "app.oauth2.as.consent.grant", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"User granted consent to app: {rogue_client}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={"scope": bad_scopes}),
        target=rogue_target,
    ))
    # Step 3: burst of access_token grants — attacker using the token to call Okta APIs
    for _ in range(random.randint(3, 6)):
        logs.append(_assemble(
            "app.oauth2.as.token.grant.access_token", admin_actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="WARN", display_message=f"OAuth2 access token granted: {rogue_client}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD",
                extra={"grantType": "client_credentials", "scope": bad_scopes, "tokenLifetime": "3600"}),
            target=rogue_target,
        ))
    return logs


# --- BACKGROUND NOISE ---

# All _gen_* functions return a single JSON string. Wrap with [x] when adding to lists.
# All _generate_* multi-event functions return a list already.

def _generate_background_log(config, session_context=None):
    user_info = _get_random_user_info(config, session_context)

    # Single-event generators — each returns one JSON string
    single = [
        # Core auth — weighted 3x to keep realistic baseline
        _generate_successful_login, _generate_successful_login, _generate_successful_login,
        _generate_sso_access, _generate_sso_access, _generate_sso_access,
        _generate_mfa_verify, _generate_mfa_verify,
        # Account management (legacy _generate_* helpers)
        _generate_password_reset, _generate_account_unlock_self,
        _generate_account_unlock_by_admin, _generate_account_unlock_token,
        _generate_user_suspended, _generate_user_deactivated,
        _generate_password_reset_by_admin, _generate_mfa_factor_enrolled,
        _generate_device_assigned, _generate_group_membership_add,
        _generate_group_membership_remove, _generate_admin_privilege_grant,
        _generate_admin_app_access, _generate_api_token_created,
        _generate_app_assigned_to_user,
        # SSO baseline noise
        _generate_sso_new_country, _generate_sso_new_asn_user, _generate_sso_new_asn_org,
        _generate_sso_new_country_org, _generate_sso_machine_account,
        _generate_sso_service_account, _generate_sso_abnormal_os, _generate_sso_new_os,
        _generate_sso_unusual_time, _generate_sso_first_resource_org,
        _generate_disabled_user_sso,
        # --- NEW: user.lifecycle ---
        _gen_user_lifecycle_create, _gen_user_lifecycle_activate,
        _gen_user_lifecycle_reactivate, _gen_user_lifecycle_unsuspend,
        _gen_user_lifecycle_delete_initiated, _gen_user_lifecycle_delete_completed,
        # --- NEW: user.account ---
        _gen_user_account_update_profile, _gen_user_account_privilege_revoke,
        _gen_user_account_expire_password, _gen_user_account_lock_limit,
        _gen_user_account_update_primary_email, _gen_user_account_update_phone,
        # --- NEW: user.session ---
        _gen_user_session_end, _gen_user_session_clear,
        _gen_user_session_access_admin_app, _gen_user_session_context_change,
        _gen_user_session_expire,
        # --- NEW: user.mfa ---
        _gen_user_mfa_factor_deactivate, _gen_user_mfa_factor_suspend,
        _gen_user_mfa_factor_update, _gen_user_mfa_okta_verify,
        # --- NEW: push / provisioning / radius ---
        _gen_push_send_verify, _gen_mfa_push_deny, _gen_radius_auth_success,
        _gen_policy_sign_on_eval, _gen_fastpass_session_start, _gen_webauthn_factor_enroll,
        _gen_auth_via_webauthn,
        _gen_app_push_password_success, _gen_app_push_profile_success,
        _gen_app_push_password_failure, _gen_app_push_new_user,
        _gen_app_push_user_deactivation, _gen_system_agent_ad_push_password,
        _gen_user_account_update_secondary_email,
        _gen_kerberos_auth, _gen_mfa_factor_challenge,
        _gen_auth_verify, _gen_app_import_started, _gen_app_import_success,
        _gen_oauth2_authorize_success, _gen_oauth2_authorize_denied,
        _gen_hook_outbound_sent, _gen_device_assurance_pass, _gen_device_assurance_fail,
        _gen_user_registration_create,
        # --- NEW: user.authentication ---
        _gen_user_auth_via_idp, _gen_user_auth_via_saml, _gen_user_slo,
        _gen_user_universal_logout, _gen_user_auth_via_social,
        # --- NEW: user.risk ---
        _gen_user_risk_change, _gen_user_risk_detect,
        # --- NEW: group ---
        _gen_group_lifecycle_create, _gen_group_lifecycle_delete,
        _gen_group_profile_update, _gen_group_privilege_grant,
        _gen_group_privilege_revoke, _gen_group_app_assignment_add,
        _gen_group_app_assignment_remove,
        # --- NEW: application lifecycle & membership ---
        _gen_application_lifecycle_create, _gen_application_lifecycle_activate,
        _gen_application_lifecycle_deactivate, _gen_application_lifecycle_delete,
        _gen_application_lifecycle_update,
        _gen_application_user_membership_add, _gen_application_user_membership_remove,
        _gen_application_user_membership_provision, _gen_application_user_membership_deprovision,
        _gen_application_policy_sign_on_deny,
        # --- NEW: policy lifecycle & rules ---
        _gen_policy_lifecycle_create, _gen_policy_lifecycle_update,
        _gen_policy_lifecycle_delete, _gen_policy_lifecycle_activate,
        _gen_policy_lifecycle_deactivate,
        _gen_policy_rule_add, _gen_policy_rule_update, _gen_policy_rule_delete,
        _gen_policy_rule_activate, _gen_policy_rule_deactivate,
        _gen_policy_auth_reevaluate_fail, _gen_policy_entity_risk_evaluate,
        _gen_policy_entity_risk_action,
        # --- NEW: security ---
        _gen_security_attack_start, _gen_security_attack_end,
        _gen_security_breached_credential, _gen_security_session_roaming,
        _gen_security_trusted_origin_create, _gen_security_trusted_origin_delete,
        _gen_security_trusted_origin_update, _gen_security_events_provider,
        _gen_security_authenticator_activate, _gen_security_authenticator_deactivate,
        # --- NEW: zone ---
        _gen_zone_create, _gen_zone_update, _gen_zone_delete,
        _gen_zone_activate, _gen_zone_deactivate,
        _gen_zone_make_blacklist, _gen_zone_remove_blacklist,
        # --- NEW: system ---
        _gen_system_api_token_revoke, _gen_system_api_token_update,
        _gen_system_api_token_enable,
        _gen_system_email_factor_verify, _gen_system_email_password_reset,
        _gen_system_email_new_device,
        _gen_system_sms_factor_verify, _gen_system_sms_password_reset,
        _gen_system_voice_mfa_challenge, _gen_system_voice_password_reset,
        _gen_system_idp_create, _gen_system_idp_update, _gen_system_idp_delete,
        _gen_system_idp_activate, _gen_system_idp_deactivate,
        _gen_system_org_rate_limit_violation, _gen_system_org_rate_limit_warning,
        _gen_system_org_rate_limit_burst,
        _gen_system_log_stream_create, _gen_system_log_stream_delete,
        _gen_system_mfa_factor_activate, _gen_system_mfa_factor_deactivate,
        # --- NEW: app.oauth2 ---
        _gen_oauth2_token_grant_access, _gen_oauth2_token_grant_refresh,
        _gen_oauth2_token_grant_id_token, _gen_oauth2_introspect,
        _gen_oauth2_token_revoke, _gen_oauth2_token_detect_reuse,
        _gen_oauth2_signon, _gen_oauth2_client_create, _gen_oauth2_client_delete,
        _gen_oauth2_scope_denied, _gen_oauth2_consent_grant, _gen_oauth2_consent_revoke,
        # --- NEW: iam ---
        _gen_iam_role_create, _gen_iam_role_delete, _gen_iam_role_update,
        _gen_iam_resourceset_bindings_add, _gen_iam_resourceset_bindings_delete,
        # --- NEW: device lifecycle ---
        _gen_device_lifecycle_activate, _gen_device_lifecycle_deactivate,
        _gen_device_lifecycle_delete, _gen_device_lifecycle_suspend,
        _gen_device_lifecycle_unsuspend, _gen_device_user_remove,
        # --- NEW: app access requests ---
        _gen_app_access_request, _gen_app_access_grant, _gen_app_access_deny,
        _gen_app_unauth_access_attempt,
        # --- NEW: mfa reset (low-freq benign admin op) ---
        _generate_mfa_factor_reset_by_admin,
    ]

    # Multi-event generators — each returns a list
    multi = [
        _generate_new_device_enrolled,   # [device.enrollment.create, user.mfa.factor.activate]
        _generate_benign_retry,          # 1-2 INVALID_CREDENTIALS failures then SUCCESS (same user/IP)
    ]

    # Pick from combined pool (weight single 10:1 over multi to avoid huge bursts)
    pool = single * 1 + [None] * (len(single) // 10)
    pick = random.choice(single + multi)
    result = pick(config, user_info, session_context)
    if isinstance(result, list):
        return result
    return [result]


def _generate_ephemeral_account(config, user_info, session_context=None):
    """
    Admin creates a user account and deletes it less than a minute later.
    The rapid create→activate→deactivate→delete sequence is a high-fidelity signal for:
      - Service/backdoor account creation to avoid detection
      - Privilege escalation staging (create, act, destroy evidence)
      - Insider threat testing access then cleaning up

    UEBA signal: user.lifecycle.create and user.lifecycle.delete within a 60-second window
    for the same target user, both performed by the same admin actor.
    """
    print("    - Okta Module simulating: Ephemeral account (created + deleted < 1 min)")
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx     = _build_security_context(ip_ctx)
    dbg_ctx     = _build_debug_context("PASSWORD")

    # Generate a synthetic target user — not a real session user, just an account being created
    fake_username = f"svc-temp-{uuid.uuid4().hex[:6]}@examplecorp.com"
    fake_fullname = f"Temp Service Account {uuid.uuid4().hex[:4].upper()}"
    target_actor  = _build_actor(fake_username, fake_fullname)
    target        = _build_target_user(target_actor)

    logs = []
    for event_type, message, severity in [
        ("user.lifecycle.create",            f"Create Okta user: {fake_username}",     "WARN"),
        ("user.lifecycle.activate",          f"Activate Okta user: {fake_username}",   "WARN"),
        ("user.lifecycle.deactivate",        f"Deactivate Okta user: {fake_username}", "WARN"),
        ("user.lifecycle.delete.initiated",  f"Initiate delete Okta user: {fake_username}", "WARN"),
        ("user.lifecycle.delete.completed",  f"Delete Okta user: {fake_username}",     "WARN"),
    ]:
        logs.append(_assemble(
            event_type, admin_actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity=severity, display_message=message,
            security_context=sec_ctx, debug_context=dbg_ctx, target=target,
        ))
    return logs


def _generate_lateral_sso_attempts(config, user_info, session_context=None):
    """
    Compromised or insider user attempts SSO to multiple apps they have never accessed,
    failing on each one — the Okta equivalent of walking around trying unknown computers.

    Generates 5-10 user.authentication.sso FAILURE events across different apps, each
    denied by policy (ACCESS_DENIED) or invalid credentials, spread across 1-2 minutes
    of simulated time. All events share the same user and originating IP.

    UEBA signal: high volume of SSO failures to distinct apps never previously accessed
    by this user in a short window. Correlates with lateral movement or credential testing.
    """
    print("    - Okta Module simulating: Lateral SSO attempts (failed logins to multiple unknown apps)")
    ip_ctx  = _get_random_ip_and_context(config, "benign_ingress_sources")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(ip_ctx)

    all_apps = config.get("okta_config", {}).get("okta_sso_apps", [
        "Salesforce", "ServiceNow", "Workday", "GitHub Enterprise", "AWS Console",
        "Jira", "Confluence", "Zoom", "Slack", "Microsoft Teams",
        "Greenhouse", "Netsuite", "Tableau", "Splunk", "PagerDuty",
    ])
    # Pick 5-10 distinct apps — use the full list if configured apps < 5
    n = random.randint(5, min(10, max(5, len(all_apps))))
    apps = random.sample(all_apps, min(n, len(all_apps)))

    deny_reasons = ["ACCESS_DENIED", "INVALID_CREDENTIALS", "SIGN_ON_POLICY"]

    logs = []
    for app in apps:
        reason = random.choice(deny_reasons)
        logs.append(_assemble(
            "user.authentication.sso", actor, client,
            outcome={"result": "FAILURE", "reason": reason},
            severity="WARN",
            display_message=f"SSO to {app} denied: {reason}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD", extra={
                "risk": "{level=MEDIUM}",
                "behaviors": "{New Geo-Location=NEGATIVE, New Device=NEGATIVE, New IP=NEGATIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity Behavior=POSITIVE, New City=NEGATIVE}",
            }),
            target=_make_sso_target(app),
        ))
    return logs


# ---------------------------------------------------------------------------
# NEW THREAT SEQUENCES — cross-platform IDP attack patterns
# ---------------------------------------------------------------------------

def _generate_mfa_factor_enroll_attack(config, user_info, session_context=None):
    """
    Attacker uses a stolen session to enroll their own MFA factor (persistence).
    Pattern: session admin access → self-enroll attacker's authenticator → auth with it.
    Signal: MFA enrollment from external/TOR IP immediately followed by successful MFA auth.
    """
    print("    - Okta Module generating MFA factor self-enroll attack...")
    logs    = []
    ip_ctx  = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=False)
    sec_ctx = _build_security_context(ip_ctx)
    factor  = random.choice(_WEBAUTHN_FACTORS + ["OIE_OKTA_VERIFY_PUSH", "TOTP"])

    # Step 1: attacker opens user settings via stolen session
    logs.append(_assemble(
        "user.session.access_admin_app", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User accessing Okta administration app",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}", "threatSuspected": "true",
        }),
    ))
    # Step 2: attacker enrolls their own authenticator on the victim account
    logs.append(_assemble(
        "user.mfa.factor.activate", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"User activated {factor}",
        authentication_context=_build_authentication_context("SIGNED_NONCE"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("SIGNED_NONCE", extra={
            "risk": "{level=HIGH}", "threatSuspected": "true",
        }),
        target=[{"id": f"mfa-{uuid.uuid4()}", "type": "AuthenticatorEnrollment",
                 "displayName": factor, "alternateId": "ATTACKER_ENROLLED", "detailEntry": None}],
    ))
    # Step 3: attacker authenticates successfully with the newly enrolled factor
    logs.append(_assemble(
        "user.authentication.auth_via_mfa", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="Authentication of user via MFA",
        authentication_context=_build_authentication_context("OIE_OKTA_VERIFY_PUSH"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("OIE_OKTA_VERIFY_PUSH", extra={
            "risk": "{level=HIGH}", "threatSuspected": "true",
        }, include_auth_signals=True),
    ))
    return logs


def _generate_log_stream_evasion(config, user_info, session_context=None):
    """
    Attacker deletes audit log stream to blind SIEM (defense evasion).
    Signal: log stream deletion is high-fidelity; very rare in normal ops.
    """
    print("    - Okta Module generating log stream defense evasion...")
    logs    = []
    ip_ctx  = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=False)
    sec_ctx = _build_security_context(ip_ctx)

    # Step 1: admin console access (using stolen/escalated session)
    logs.append(_assemble(
        "user.session.access_admin_app", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User accessing Okta administration app",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD"),
    ))
    # Step 2: delete audit log stream — blinds SIEM
    logs.append(_assemble(
        "system.log_stream.lifecycle.delete", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="Delete log stream",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}", "threatSuspected": "true",
        }),
        target=[{"id": f"ls-{uuid.uuid4().hex[:20]}", "type": "LogStream",
                 "displayName": "SIEM Log Stream", "alternateId": "SIEM Log Stream",
                 "detailEntry": None}],
    ))
    # Step 3: self-grant admin privilege (optional escalation before cleanup)
    if random.random() < 0.5:
        logs.append(_assemble(
            "user.account.privilege.grant", actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="WARN", display_message="Grant user privilege",
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD"),
            target=_build_target_user(actor),
        ))
    return logs


def _generate_radius_brute_force(config, user_info, session_context=None):
    """
    Attacker brute-forces RADIUS auth for VPN access from same external IP.
    Signal: high-volume RADIUS failures from one IP in a short window.
    Returns a list.
    """
    print("    - Okta Module generating RADIUS VPN brute force...")
    logs      = []
    # Use a random external IP for all attempts (same attacker source)
    first_octets = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 212]
    attacker_ip  = f"{random.choice(first_octets)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    attacker_ctx = {"ip": attacker_ip, "city": None, "country": "RU",
                    "asn": 60729, "isp": "External Attacker", "domain": None, "is_proxy": False}
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(attacker_ctx, config, interactive_only=False)
    client["ipAddress"] = attacker_ip
    sec_ctx = _build_security_context(attacker_ctx)
    app     = random.choice(_RADIUS_APPS)

    num_attempts = random.randint(20, 50)
    for _ in range(num_attempts):
        logs.append(_assemble(
            "user.authentication.auth_via_radius", actor, client,
            outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            severity="WARN", display_message=f"Authentication of user via RADIUS: {app}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD", extra={
                "risk": "{level=HIGH}", "threatSuspected": "true",
            }),
            target=[{"id": _app_instance_id(app), "type": "AppInstance",
                     "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
        ))
    # Optional final success (attacker found correct credentials)
    if random.random() < 0.3:
        logs.append(_assemble(
            "user.authentication.auth_via_radius", actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="WARN", display_message=f"Authentication of user via RADIUS: {app}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD", extra={
                "risk": "{level=HIGH}", "threatSuspected": "true",
            }),
            target=[{"id": _app_instance_id(app), "type": "AppInstance",
                     "displayName": app, "alternateId": app, "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
        ))
    return logs


def _generate_cross_idp_hijack(config, user_info, session_context=None):
    """
    Attacker adds a rogue identity provider to redirect auth traffic.
    Signal: new IDP created and immediately used for authentication.
    """
    print("    - Okta Module generating cross-IDP hijack attack...")
    logs    = []
    ip_ctx  = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=False)
    sec_ctx = _build_security_context(ip_ctx)

    rogue_idp_tlds  = ["attacker.com", "evil-corp.net", "rogue-idp.io",
                       "fakesso.xyz", "malicious-idp.ru"]
    rogue_idp_name  = f"External IDP ({random.choice(rogue_idp_tlds)})"
    rogue_target    = [{"id": f"idp-{uuid.uuid4()}", "type": "IdentityProvider",
                        "displayName": rogue_idp_name, "alternateId": rogue_idp_name,
                        "detailEntry": None}]

    # Step 1: create rogue IDP
    logs.append(_assemble(
        "system.idp.lifecycle.create", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"Create identity provider: {rogue_idp_name}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}", "threatSuspected": "true",
        }),
        target=rogue_target,
    ))
    # Step 2: activate rogue IDP
    logs.append(_assemble(
        "system.idp.lifecycle.activate", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"Activate identity provider: {rogue_idp_name}",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD"),
        target=rogue_target,
    ))
    # Step 3: auth via the rogue IDP
    logs.append(_assemble(
        "user.authentication.auth_via_IDP", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message=f"Authenticate user via IDP: {rogue_idp_name}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}", "threatSuspected": "true",
        }, include_auth_signals=True),
        target=rogue_target,
    ))
    return logs


def _generate_scim_bulk_create(config, user_info, session_context=None):
    """
    SCIM API abused to bulk-create backdoor user accounts in rapid succession.
    Actor is a SystemPrincipal (API token), not a human admin.
    Signal: multiple account creations in seconds from API principal.
    Returns a list.
    """
    print("    - Okta Module generating SCIM bulk backdoor account creation...")
    logs = []
    # System/API actor — not a human; common pattern for SCIM provisioning abuse
    scim_actor = {
        "id":          "SYSTEM",
        "type":        "SystemPrincipal",
        "alternateId": "system",
        "displayName": "SCIM Provisioning Agent",
        "detailEntry": None,
    }
    # Use a minimal client block (API calls have no real browser/geo context)
    ip_ctx = _get_random_ip_and_context(config, "benign_ingress_sources")
    client = _build_client(ip_ctx, config, interactive_only=False)

    num_accounts = random.randint(3, 8)
    for i in range(num_accounts):
        prefix   = random.choice(_SCIM_BACKDOOR_PFXS)
        suffix   = uuid.uuid4().hex[:6]
        username = f"{prefix}{suffix}@examplecorp.com"
        backdoor_actor = _build_actor(username, f"Service Account {suffix}")
        logs.append(_assemble(
            "user.lifecycle.create", scim_actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="INFO", display_message="Create Okta user",
            security_context=_build_security_context(ip_ctx),
            debug_context=_build_debug_context("PASSWORD", extra={
                "risk": "{level=HIGH}", "threatSuspected": "true",
            }),
            target=_build_target_user(backdoor_actor),
        ))
    return logs


def _generate_device_assurance_bypass(config, user_info, session_context=None):
    """
    Attacker's non-compliant device fails device assurance, then bypasses via unprotected app path.
    Signal: device assurance DENY followed immediately by SSO success on a different app.
    """
    print("    - Okta Module generating device assurance bypass attack...")
    logs    = []
    ip_ctx  = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor   = _build_actor(user_info["username"], user_info["full_name"])
    client  = _build_client(ip_ctx, config, interactive_only=False)
    sec_ctx = _build_security_context(ip_ctx)
    policy  = random.choice(_POLICY_NAMES)
    os_type = random.choice(["Windows", "macOS"])
    # Attacker's unmanaged device
    device_target = [
        {"id": f"guuid{uuid.uuid4().hex[:20]}", "type": "Device",
         "displayName": f"Unmanaged {os_type} Device",
         "alternateId": f"serial-{uuid.uuid4().hex[:12].upper()}",
         "detailEntry": {"platform": os_type, "managed": False, "registered": False}},
        {"id": f"pol-{uuid.uuid4()}", "type": "Policy",
         "displayName": policy, "alternateId": policy, "detailEntry": None},
    ]
    # Step 1: device assurance check fails
    logs.append(_assemble(
        "device.assurance.policy.evaluate", actor, client,
        outcome={"result": "DENY", "reason": "DEVICE_NOT_COMPLIANT"},
        severity="WARN", display_message="Evaluate device assurance policy",
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}", "threatSuspected": "true",
        }),
        target=device_target,
    ))
    # Step 2: attacker finds an unprotected app and authenticates via SSO
    fallback_app = random.choice(config.get("okta_config", {}).get("okta_sso_apps", ["Legacy App"]))
    logs.append(_assemble(
        "user.authentication.sso", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="User single sign on to app",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}", "threatSuspected": "true",
        }),
        target=[{"id": _app_instance_id(fallback_app), "type": "AppInstance",
                 "displayName": fallback_app, "alternateId": fallback_app, "detailEntry": {"signOnModeType": _app_sign_on_mode(fallback_app)}}],
    ))
    # Step 3: attacker acquires OAuth2 token via less-protected app
    oauth_client = random.choice(_OAUTH_CLIENTS)
    logs.append(_assemble(
        "app.oauth2.as.authorize", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN", display_message="OAuth2 authorization code request granted",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}", "threatSuspected": "true",
        }),
        target=[{"id": _app_instance_id(oauth_client), "type": "AppInstance",
                 "displayName": oauth_client, "alternateId": oauth_client, "detailEntry": {"signOnModeType": "OPENID_CONNECT"}}],
    ))
    return logs


def _generate_oauth2_token_farm(config, user_info, session_context=None):
    """
    Rogue OAuth client or attacker makes excessive authorization code requests (token farming).
    Signal: volume pattern — many authorizations from same client in a short window.
    Returns a list.
    """
    print("    - Okta Module generating OAuth2 token farming attack...")
    logs       = []
    ip_ctx     = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor      = _build_actor(user_info["username"], user_info["full_name"])
    client     = _build_client(ip_ctx, config, interactive_only=False)
    sec_ctx    = _build_security_context(ip_ctx)
    oauth_app  = random.choice(_OAUTH_CLIENTS)
    app_target = [{"id": _app_instance_id(oauth_app), "type": "AppInstance",
                   "displayName": oauth_app, "alternateId": oauth_app, "detailEntry": {"signOnModeType": "OPENID_CONNECT"}}]

    num_requests = random.randint(15, 30)
    for _ in range(num_requests):
        logs.append(_assemble(
            "app.oauth2.as.authorize", actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="INFO", display_message="OAuth2 authorization code request granted",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD", extra={
                "risk": "{level=HIGH}", "threatSuspected": "true",
            }),
            target=app_target,
        ))
    return logs


def _generate_registration_abuse(config, user_info, session_context=None):
    """
    Attacker exploits open self-registration to bulk-create accounts from same external IP.
    Signal: multiple user.registration.create events from same IP in a short window.
    Returns a list.
    """
    print("    - Okta Module generating self-registration abuse...")
    logs    = []
    # All registrations come from the same external attacker IP
    first_octets = [45, 52, 54, 62, 80, 91, 104, 142, 176, 185, 193, 212]
    attacker_ip  = f"{random.choice(first_octets)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    attacker_ctx = {"ip": attacker_ip, "city": None, "country": "RU",
                    "asn": 60729, "isp": "External Attacker", "domain": None, "is_proxy": False}
    client  = _build_client(attacker_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(attacker_ctx)

    num_accounts = random.randint(4, 8)
    for i in range(num_accounts):
        suffix   = uuid.uuid4().hex[:8]
        username = f"user{suffix}@external.com"
        new_actor = _build_actor(username, f"New User {i+1}")
        logs.append(_assemble(
            "user.registration.create", new_actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="INFO", display_message="Registration of new user",
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD", extra={
                "risk": "{level=HIGH}", "threatSuspected": "true",
            }),
            target=_build_target_user(new_actor),
        ))
    return logs


_SVC_ACCOUNTS = [
    ("svc-datadog",        "DataDog Service"),
    ("svc-jenkins",        "Jenkins CI Service"),
    ("svc-terraform",      "Terraform Automation"),
    ("svc-backup",         "Backup Service"),
    ("svc-monitoring",     "Monitoring Service"),
    ("svc-github-actions", "GitHub Actions"),
    ("svc-splunk",         "Splunk Forwarder"),
    ("svc-qualys",         "Qualys Scanner"),
    ("svc-servicenow",     "ServiceNow Integration"),
    ("svc-workday",        "Workday Integration"),
]

_PRIVILEGED_GROUPS = [
    "Super Administrators", "IT Admins", "Global Admins",
    "Okta Administrators", "Security Admins", "Executive Users",
]


def _generate_service_account_login_abuse(config, user_info, session_context=None):
    """
    Service account authenticates interactively via browser (should never happen —
    service accounts must use API tokens or machine credentials, not password sessions).
    Signal for XQL: actor_alternateId starts with 'svc-' + credentialType = PASSWORD +
    interactive client (browser user agent).
    Followed by SSO to sensitive apps — attacker using a stolen service account credential.
    """
    print("    - Okta Module generating service account interactive login abuse...")
    svc_username, svc_fullname = random.choice(_SVC_ACCOUNTS)
    svc_email = f"{svc_username}@examplecorp.com"
    svc_actor = {
        "id":          _stable_user_id(svc_username),
        "type":        "User",
        "alternateId": svc_email,
        "displayName": svc_fullname,
        "detailEntry": None,
    }
    # Attacker uses a browser (not machine UA) — that's the anomaly
    ip_ctx  = _get_random_ip_and_context(config, "tor_exit_nodes")
    client  = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx = _build_security_context(ip_ctx)

    logs = []
    # Step 1: Interactive session start with password (svc accounts never do this)
    logs.append(_assemble(
        "user.session.start", svc_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN",
        display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", include_auth_signals=True),
        target=_session_start_targets("PASSWORD"),
    ))
    # Step 2: SSO to 2-3 sensitive apps
    sensitive_apps = random.sample(
        ["Salesforce", "ServiceNow", "Workday", "NetSuite", "GitHub", "Datadog"],
        k=random.randint(2, 3),
    )
    for app in sensitive_apps:
        logs.append(_assemble(
            "user.authentication.sso", svc_actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="WARN",
            display_message=f"Service account SSO to {app}: {svc_email}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD"),
            target=[{"id": _app_instance_id(app), "type": "AppInstance",
                     "displayName": app, "alternateId": app,
                     "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
        ))
    return logs


def _generate_bulk_mfa_reset(config, user_info, session_context=None):
    """
    Compromised admin account resets MFA factors for 5-10 users in rapid succession.
    Attacker removes existing MFA to prepare those accounts for takeover.
    Signal for XQL: multiple user.mfa.factor.reset_all events from same actor in short window.
    """
    print("    - Okta Module generating bulk MFA reset attack...")
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx     = _build_security_context(ip_ctx)
    dbg_ctx     = _build_debug_context("PASSWORD")

    logs = []
    # Step 1: admin accesses console
    logs.append(_assemble(
        "user.session.access_admin_app", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN",
        display_message="User accessing Okta Admin Console",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx, debug_context=dbg_ctx,
        target=[{"id": _app_instance_id("Okta Admin Console"), "type": "AppInstance",
                 "displayName": "Okta Admin Console", "alternateId": "Okta Admin Console",
                 "detailEntry": {"signOnModeType": "SAML_2_0"}}],
    ))
    # Step 2: batch of MFA resets against different target users
    victims = _get_random_users_from_config(config, count=random.randint(5, 10))
    for victim in victims:
        v_actor = _build_actor(victim["username"], victim["full_name"])
        logs.append(_assemble(
            "user.mfa.factor.reset_all", admin_actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="WARN",
            display_message=f"Admin reset all MFA factors for {victim['username']}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx, debug_context=dbg_ctx,
            target=_build_target_user(v_actor),
        ))
    return logs


def _generate_group_privilege_escalation(config, user_info, session_context=None):
    """
    Attacker (or insider) adds an existing user to a privileged admin group,
    then immediately leverages the new privileges to access sensitive resources.
    Different from rogue_admin_creation: no new user created — existing account escalated.
    Signal for XQL: group.user_membership.add to privileged group → admin console access
    by the same user within minutes.
    """
    print("    - Okta Module generating group-based privilege escalation...")
    ip_ctx      = _get_random_ip_and_context(config, "benign_ingress_sources")
    admin_actor = _build_admin_actor(config, session_context)
    victim_actor = _build_actor(user_info["username"], user_info["full_name"])
    client      = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx     = _build_security_context(ip_ctx)
    dbg_ctx     = _build_debug_context("PASSWORD")

    priv_group = random.choice(_PRIVILEGED_GROUPS)
    logs = []

    # Step 1: victim (or compromised admin) adds user to privileged group
    logs.append(_assemble(
        "group.user_membership.add", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN",
        display_message=f"Added {user_info['username']} to privileged group {priv_group}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx, debug_context=dbg_ctx,
        target=[
            {"id": f"grp{uuid.uuid4().hex[:20]}", "type": "UserGroup",
             "displayName": priv_group, "alternateId": priv_group, "detailEntry": None},
            _build_target_user(victim_actor)[0],
        ],
    ))
    # Step 2: privilege inheritance materialises
    logs.append(_assemble(
        "user.account.privilege.grant", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN",
        display_message=f"Admin privilege granted to {user_info['username']} via group {priv_group}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx, debug_context=dbg_ctx,
        target=_build_target_user(victim_actor),
    ))
    # Step 3: newly privileged user immediately accesses admin console
    ext_ip_ctx = _get_random_ip_and_context(config, "tor_exit_nodes")
    victim_client = _build_client(ext_ip_ctx, config, interactive_only=True)
    victim_sec    = _build_security_context(ext_ip_ctx)
    logs.append(_assemble(
        "user.session.access_admin_app", victim_actor, victim_client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="WARN",
        display_message=f"Newly privileged user accessing Okta Admin Console",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=victim_sec,
        debug_context=_build_debug_context("PASSWORD", extra={"threatSuspected": "true"}),
        target=[{"id": _app_instance_id("Okta Admin Console"), "type": "AppInstance",
                 "displayName": "Okta Admin Console", "alternateId": "Okta Admin Console",
                 "detailEntry": {"signOnModeType": "SAML_2_0"}}],
    ))
    # Step 4: pivot to 2 sensitive apps
    for app in random.sample(["Salesforce", "ServiceNow", "NetSuite", "Workday", "GitHub"], k=2):
        logs.append(_assemble(
            "user.authentication.sso", victim_actor, victim_client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="WARN",
            display_message=f"Post-escalation SSO to {app}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=victim_sec,
            debug_context=_build_debug_context("PASSWORD", extra={"threatSuspected": "true"}),
            target=[{"id": _app_instance_id(app), "type": "AppInstance",
                     "displayName": app, "alternateId": app,
                     "detailEntry": {"signOnModeType": _app_sign_on_mode(app)}}],
        ))
    return logs


def _generate_refresh_token_persistence(config, user_info, session_context=None):
    """
    Attacker maintains long-term persistent access via OAuth2 refresh tokens.
    After initial auth, chains 15-25 refresh token grants over simulated extended window.
    Signal for XQL: high volume app.oauth2.as.token.grant.refresh_token from single actor/client.
    Legitimate apps refresh tokens but rarely more than a few times per session.
    """
    print("    - Okta Module generating OAuth2 refresh token persistence...")
    ip_ctx   = _get_random_ip_and_context(config, "tor_exit_nodes")
    actor    = _build_actor(user_info["username"], user_info["full_name"])
    client   = _build_client(ip_ctx, config, interactive_only=False)
    sec_ctx  = _build_security_context(ip_ctx)
    oauth_client = random.choice(_OAUTH_CLIENTS)
    app_tgt  = [{"id": _app_instance_id(oauth_client), "type": "AppInstance",
                 "displayName": oauth_client, "alternateId": oauth_client,
                 "detailEntry": {"signOnModeType": "OPENID_CONNECT"}}]

    logs = []
    # Step 1: initial authentication
    logs.append(_assemble(
        "user.session.start", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO",
        display_message="User login to Okta",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD", include_auth_signals=True),
        target=_session_start_targets("PASSWORD"),
    ))
    # Step 2: initial access token
    logs.append(_assemble(
        "app.oauth2.as.token.grant.access_token", actor, client,
        outcome={"result": "SUCCESS", "reason": None},
        severity="INFO",
        display_message=f"OAuth2 access token granted to {oauth_client}",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx,
        debug_context=_build_debug_context("PASSWORD"),
        target=app_tgt,
    ))
    # Step 3: sustained refresh token cycling (persistence pattern)
    num_refreshes = random.randint(15, 25)
    for _ in range(num_refreshes):
        logs.append(_assemble(
            "app.oauth2.as.token.grant.refresh_token", actor, client,
            outcome={"result": "SUCCESS", "reason": None},
            severity="INFO",
            display_message=f"OAuth2 refresh token cycled for {oauth_client}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx,
            debug_context=_build_debug_context("PASSWORD"),
            target=app_tgt,
        ))
    return logs


def _generate_admin_role_enumeration(config, user_info, session_context=None):
    """
    Attacker with admin access performs systematic IAM reconnaissance:
    enumerates roles and resource set bindings, then escalates privilege.
    Signal for XQL: burst of iam.role.* and iam.resourceset.bindings.* events
    from same actor in short window — reconnaissance before escalation.
    """
    print("    - Okta Module generating admin IAM role enumeration...")
    ip_ctx      = _get_random_ip_and_context(config, "tor_exit_nodes")
    admin_actor = _build_admin_actor(config, session_context)
    client      = _build_client(ip_ctx, config, interactive_only=True)
    sec_ctx     = _build_security_context(ip_ctx)
    dbg_ctx     = _build_debug_context("PASSWORD", extra={"threatSuspected": "true"})

    logs = []
    # Step 1: admin console access
    logs.append(_assemble(
        "user.session.access_admin_app", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message="Admin console access from external IP",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx, debug_context=_build_debug_context("PASSWORD"),
        target=[{"id": _app_instance_id("Okta Admin Console"), "type": "AppInstance",
                 "displayName": "Okta Admin Console", "alternateId": "Okta Admin Console",
                 "detailEntry": {"signOnModeType": "SAML_2_0"}}],
    ))
    # Step 2: rapid IAM role reads/updates (enumeration)
    role_names = ["Help Desk Admin", "Read-Only Admin", "App Admin",
                  "Group Admin", "Report Admin", "User Admin"]
    for role in random.sample(role_names, k=random.randint(4, 6)):
        logs.append(_assemble(
            "iam.role.update", admin_actor, client,
            outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
            display_message=f"IAM role enumerated/modified: {role}",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx, debug_context=dbg_ctx,
            target=[{"id": f"role-{uuid.uuid4()}", "type": "Role",
                     "displayName": role, "alternateId": role, "detailEntry": None}],
        ))
    # Step 3: resource set binding inspection (who has what)
    for _ in range(random.randint(3, 5)):
        logs.append(_assemble(
            "iam.resourceset.bindings.add", admin_actor, client,
            outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
            display_message="IAM resource set binding added (recon + escalation)",
            authentication_context=_build_authentication_context("PASSWORD"),
            security_context=sec_ctx, debug_context=dbg_ctx,
            target=[{"id": f"rs-{uuid.uuid4()}", "type": "ResourceSet",
                     "displayName": "All Users Resource Set", "alternateId": "ALL_USERS",
                     "detailEntry": None}],
        ))
    # Step 4: grant themselves broader role
    logs.append(_assemble(
        "user.account.privilege.grant", admin_actor, client,
        outcome={"result": "SUCCESS", "reason": None}, severity="WARN",
        display_message="Privilege escalation after IAM enumeration",
        authentication_context=_build_authentication_context("PASSWORD"),
        security_context=sec_ctx, debug_context=dbg_ctx,
        target=_build_target_user(admin_actor),
    ))
    return logs


def _get_random_users_from_config(config, count=5):
    """Helper: pick N random users from config.user_profiles."""
    profiles = config.get("user_profiles", {})
    if not profiles:
        return [{"username": f"user{i}@examplecorp.com", "full_name": f"User {i}"}
                for i in range(count)]
    keys = random.sample(list(profiles.keys()), k=min(count, len(profiles)))
    result = []
    for k in keys:
        v = profiles[k]
        result.append({"username": k, "full_name": v.get("display_name", k)})
    return result


def _make_threat_dict(config, user_info, session_context):
    """Build and return the full threat dispatch dict.

    Lambdas are lazy — calling this function with stub objects (as get_threat_names() does)
    only creates the dict and does NOT execute any generator.  Adding a new threat entry here
    is the single change required for it to appear in the Specific Threat menu automatically.
    """
    return {
        # Legacy multi-event attack sequences
        "brute_force":            lambda: _generate_brute_force_sequence(config, user_info, session_context),
        "tor_login":              lambda: _generate_tor_login(config, user_info, session_context),
        "policy_deny":            lambda: _generate_policy_deny(config, user_info, session_context),
        "mfa_bombing":            lambda: _generate_mfa_bombing_sequence(config, user_info, session_context),
        "mfa_bypass":             lambda: [_generate_mfa_bypass_attempt(config, user_info, session_context)],
        "impersonation":          lambda: _generate_session_impersonation(config, user_info, session_context),
        "impossible_travel":      lambda: _generate_impossible_travel_sequence(config, user_info, session_context),
        "password_spray":         lambda: _generate_password_spray(config, session_context),
        "fastpass_phishing":       lambda: [_generate_fastpass_phishing_detected(config, user_info, session_context)],
        "reported_suspicious":    lambda: [_generate_user_reported_suspicious(config, user_info, session_context)],
        "threat_detected":        lambda: [_generate_okta_threat_detected(config, user_info, session_context)],
        "mfa_reset":              lambda: [_generate_mfa_factor_reset_by_admin(config, user_info, session_context)],
        # SSO attack sequences
        "sso_brute_force":        lambda: _generate_sso_brute_force(config, user_info, session_context),
        "intense_sso_failures":   lambda: _generate_intense_sso_failures(config, session_context),
        "sso_password_spray":     lambda: _generate_sso_password_spray(config, session_context),
        "ip_rotation_sso":        lambda: _generate_ip_rotation_sso_spray(config, user_info, session_context),
        "sso_rejected_country":   lambda: _generate_sso_rejected_unusual_country(config, user_info, session_context),
        "sso_impossible_travel":  lambda: _generate_sso_impossible_travel(config, user_info, session_context),
        "sso_possible_imp_travel":lambda: _generate_sso_possible_impossible_travel(config, user_info, session_context),
        "sso_tor":                lambda: [_generate_sso_from_tor(config, user_info, session_context)],
        "sso_suspicious_country": lambda: [_generate_sso_suspicious_country(config, user_info, session_context)],
        "sso_suspicious_asn":     lambda: [_generate_sso_suspicious_asn(config, user_info, session_context)],
        "sso_abnormal_ua":        lambda: [_generate_sso_abnormal_user_agent(config, user_info, session_context)],
        "sso_suspicious_auth":    lambda: [_generate_sso_suspicious_auth(config, user_info, session_context)],
        "sso_multi_unusual":      lambda: _generate_sso_multiple_unusual_resources(config, user_info, session_context),
        "honey_auth":             lambda: [_generate_honey_user_auth(config)],
        "honey_sso":              lambda: [_generate_honey_user_sso(config)],
        # High-signal single events promoted to threat tier
        "attack_start":           lambda: [_gen_security_attack_start(config, user_info, session_context)],
        "breached_credential":    lambda: [_gen_security_breached_credential(config, user_info, session_context)],
        "session_roaming":        lambda: [_gen_security_session_roaming(config, user_info, session_context)],
        "token_reuse":            lambda: [_gen_oauth2_token_detect_reuse(config, user_info, session_context)],
        "risk_detect":            lambda: [_gen_user_risk_detect(config, user_info, session_context)],
        "risk_change":            lambda: [_gen_user_risk_change(config, user_info, session_context)],
        "policy_risk_action":     lambda: [_gen_policy_entity_risk_action(config, user_info, session_context)],
        "policy_reeval_fail":     lambda: [_gen_policy_auth_reevaluate_fail(config, user_info, session_context)],
        "account_lock_limit":     lambda: [_gen_user_account_lock_limit(config, user_info, session_context)],
        "unauth_app_access":      lambda: [_gen_app_unauth_access_attempt(config, user_info, session_context)],
        "oauth2_scope_denied":    lambda: [_gen_oauth2_scope_denied(config, user_info, session_context)],
        "app_sign_on_deny":       lambda: [_gen_application_policy_sign_on_deny(config, user_info, session_context)],
        "security_events_provider": lambda: [_gen_security_events_provider(config, user_info, session_context)],
        "zone_blacklist":         lambda: [_gen_zone_make_blacklist(config, user_info, session_context)],
        "idp_delete":             lambda: [_gen_system_idp_delete(config, user_info, session_context)],
        "admin_privilege_revoke": lambda: [_gen_user_account_privilege_revoke(config, user_info, session_context)],
        "iam_binding_add":        lambda: [_gen_iam_resourceset_bindings_add(config, user_info, session_context)],
        # --- NEW: 12 correlated multi-event sequences ---
        "rogue_admin_creation":        lambda: _generate_rogue_admin_creation(config, user_info, session_context),
        "breached_credential_login":   lambda: _generate_breached_credential_login(config, user_info, session_context),
        "risk_policy_bypass":          lambda: _generate_risk_policy_bypass(config, user_info, session_context),
        "shadow_idp_attack":           lambda: _generate_shadow_idp_attack(config, user_info, session_context),
        "universal_logout_bypass":     lambda: _generate_universal_logout_bypass(config, user_info, session_context),
        "defense_evasion":             lambda: _generate_defense_evasion(config, user_info, session_context),
        "third_party_signal_access":   lambda: _generate_third_party_signal_access(config, user_info, session_context),
        "dormant_account_reactivation":lambda: _generate_dormant_account_reactivation(config, user_info, session_context),
        "oauth_consent_abuse":         lambda: _generate_oauth_consent_abuse(config, user_info, session_context),
        "session_clear_bypass":        lambda: _generate_session_clear_bypass(config, user_info, session_context),
        "device_swap_enrollment":      lambda: _generate_device_swap_enrollment(config, user_info, session_context),
        "iam_privilege_escalation":    lambda: _generate_iam_privilege_escalation(config, user_info, session_context),
        # --- NEW: 6 sequences covering remaining background-only high-value events ---
        "mfa_downgrade_access":        lambda: _generate_mfa_downgrade_access(config, user_info, session_context),
        "authenticator_downgrade":     lambda: _generate_authenticator_downgrade(config, user_info, session_context),
        "api_token_abuse":             lambda: _generate_api_token_abuse(config, user_info, session_context),
        "zone_bypass_access":          lambda: _generate_zone_bypass_access(config, user_info, session_context),
        "admin_app_pivot":             lambda: _generate_admin_app_after_compromise(config, user_info, session_context),
        "rogue_oauth_client_spray":    lambda: _generate_rogue_oauth_client_spray(config, user_info, session_context),
        # --- NEW: UEBA baseline and lifecycle attack scenarios ---
        "benign_retry":                lambda: _generate_benign_retry(config, user_info, session_context),
        "ephemeral_account":           lambda: _generate_ephemeral_account(config, user_info, session_context),
        "lateral_sso_attempts":        lambda: _generate_lateral_sso_attempts(config, user_info, session_context),
        # --- Okta Audit analytics detections ---
        "mfa_factor_update":      lambda: [_gen_user_mfa_factor_update(config, user_info, session_context)],
        "policy_rule_update":     lambda: [_gen_policy_rule_update(config, user_info, session_context)],
        "device_assigned":        lambda: [_generate_device_assigned(config, user_info, session_context)],
        "new_device_enrolled":    lambda: _generate_new_device_enrolled(config, user_info, session_context),
        "zone_update":            lambda: [_gen_zone_update(config, user_info, session_context)],
        # --- NEW: cross-platform IDP attack patterns ---
        "mfa_enroll_attack":      lambda: _generate_mfa_factor_enroll_attack(config, user_info, session_context),
        "log_stream_evasion":     lambda: _generate_log_stream_evasion(config, user_info, session_context),
        "radius_brute_force":     lambda: _generate_radius_brute_force(config, user_info, session_context),
        "cross_idp_hijack":       lambda: _generate_cross_idp_hijack(config, user_info, session_context),
        "scim_bulk_create":       lambda: _generate_scim_bulk_create(config, user_info, session_context),
        # --- NEW: device trust / OAuth2 / self-registration attacks ---
        "device_assurance_bypass":      lambda: _generate_device_assurance_bypass(config, user_info, session_context),
        "oauth2_token_farm":            lambda: _generate_oauth2_token_farm(config, user_info, session_context),
        "registration_abuse":           lambda: _generate_registration_abuse(config, user_info, session_context),
        # --- NEW: XQL hunt coverage gaps ---
        "service_account_login_abuse":  lambda: _generate_service_account_login_abuse(config, user_info, session_context),
        "bulk_mfa_reset":               lambda: _generate_bulk_mfa_reset(config, user_info, session_context),
        "group_privilege_escalation":   lambda: _generate_group_privilege_escalation(config, user_info, session_context),
        "refresh_token_persistence":    lambda: _generate_refresh_token_persistence(config, user_info, session_context),
        "admin_role_enumeration":       lambda: _generate_admin_role_enumeration(config, user_info, session_context),
        # --- NEW: additional threat scenarios ---
        "sms_otp_bombing":              lambda: _generate_sms_otp_bombing(config, user_info, session_context),
        "sign_on_policy_downgrade":     lambda: _generate_sign_on_policy_downgrade(config, user_info, session_context),
        "aitm_phishing":                lambda: _generate_aitm_phishing(config, user_info, session_context),
        "event_hook_deletion":          lambda: _generate_event_hook_deletion(config, user_info, session_context),
        "malicious_oauth_app":          lambda: _generate_malicious_oauth_app_registration(config, user_info, session_context),
    }


def get_threat_names():
    """Return available threat names dynamically from _make_threat_dict.
    Adding a new entry to _make_threat_dict automatically surfaces it here."""
    return list(_make_threat_dict({}, {"username": "", "full_name": ""}, None).keys())


def _generate_threat_log(config, session_context=None, override=None):
    """Return a list of threat-level JSON event strings.
    If override is a known threat key, that specific threat is generated instead of a random one.
    """
    user_info = _get_random_user_info(config, session_context)
    threats   = _make_threat_dict(config, user_info, session_context)
    label = override if (override and override in threats) else random.choice(list(threats.keys()))
    return (threats[label](), label)


# --- SCENARIO SUPPORT ---

def _get_location_distance(loc1, loc2):
    R = 6371
    lat1, lon1 = math.radians(loc1.get("lat", 0)), math.radians(loc1.get("lon", 0))
    lat2, lon2 = math.radians(loc2.get("lat", 0)), math.radians(loc2.get("lon", 0))
    dlon, dlat = lon2 - lon1, lat2 - lat1
    a = math.sin(dlat/2)**2 + math.cos(lat1)*math.cos(lat2)*math.sin(dlon/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


def _generate_scenario_log(config, scenario):
    if scenario.get("name") != "impossible_travel":
        return []
    user_info = {"username": scenario["user"], "full_name": scenario["user_full_name"]}
    actor = _build_actor(user_info["username"], user_info["full_name"])

    if scenario.get("step") == "benign_success":
        ip_ctx = scenario["benign_location"]
        client = _build_client(ip_ctx, config, interactive_only=True)
        return [_assemble("user.session.start", actor, client,
                          outcome={"result": "SUCCESS", "reason": None},
                          severity="INFO", display_message="User login to Okta",
                          authentication_context=_build_authentication_context("PASSWORD"),
                          security_context=_build_security_context(ip_ctx),
                          debug_context=_build_debug_context("PASSWORD", include_auth_signals=True),
                          target=_session_start_targets("PASSWORD"))]

    elif scenario.get("step") == "suspicious_success":
        ip_ctx  = scenario["suspicious_location"]
        client  = _build_client(ip_ctx, config, interactive_only=False)
        sec_ctx = _build_security_context(ip_ctx)
        dbg_ctx = _build_debug_context("PASSWORD", extra={
            "risk": "{level=HIGH}",
            "behaviors": "{New Geo-Location=POSITIVE, New Device=NEGATIVE, New IP=NEGATIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity Behavior=NEGATIVE, New City=NEGATIVE}", "threatSuspected": "true",
        })
        return [_assemble("user.session.start", actor, client,
                          outcome={"result": "SUCCESS", "reason": None},
                          severity="WARN", display_message="User login to Okta",
                          authentication_context=_build_authentication_context("PASSWORD"),
                          security_context=sec_ctx, debug_context=dbg_ctx,
                          target=_session_start_targets("PASSWORD"))]
    return []


# --- MAIN ENTRY POINT ---

def generate_log(config, scenario=None, threat_level="Realistic",
                 scenario_event=None, context=None, benign_only=False):
    global last_threat_event_time

    # Extract session_context from the context dict passed by log_simulator.py
    session_context = (context or {}).get("session_context")

    if scenario:
        return _generate_scenario_log(config, scenario)

    if scenario_event:
        user_info = _get_random_user_info(config, session_context)
        if context and "user" in context:
            parts = context["user"].split(".")
            user_info = {"username": context["user"],
                         "full_name": " ".join(p.capitalize() for p in parts)}
        if scenario_event == "LOGIN":
            override_ip = (context or {}).get("ip")
            ip_ctx = None
            if override_ip:
                ip_ctx = {"ip": override_ip, "city": None, "country": "Unknown",
                          "state": None, "isp": "Unknown", "asn": None,
                          "domain": None, "is_proxy": False}
            return [_generate_successful_login(config, user_info, session_context, ip_ctx=ip_ctx)]
        elif scenario_event == "UNLOCK":
            return [_generate_account_unlock_self(config, user_info, session_context)]
        elif scenario_event == "ADMIN_UNLOCK":
            return [_generate_account_unlock_by_admin(config, user_info, session_context)]
        else:
            # Treat any other scenario_event as a named internal threat
            return _generate_threat_log(config, session_context, override=scenario_event)

    if benign_only:
        result = _generate_background_log(config, session_context)
        return result if isinstance(result, list) else [result]

    if threat_level == "Insane":
        if random.random() < 0.5:
            return _generate_threat_log(config, session_context)
        result = _generate_background_log(config, session_context)
        return result if isinstance(result, list) else [result]

    interval     = _get_threat_interval(threat_level, config)
    current_time = time.time()

    if (current_time - last_threat_event_time) > interval:
        last_threat_event_time = current_time
        result = _generate_threat_log(config, session_context)
        return result if isinstance(result, list) else [result]

    result = _generate_background_log(config)
    return result if isinstance(result, list) else [result]
