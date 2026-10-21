"""Live cross-feed campaign coordinator.

The multi-stage identity campaigns in `azuread_threat_sequences` (BEC, ransomware, OAuth app
abuse, stale-account reactivation, hybrid on-prem->cloud, RT->PRT) span several datasets and two
transports (Cribl for cloud, WEC for on-prem Windows), so they can't ride a single module's
return->dispatch path. This module makes them fire during a LIVE run instead of only via the
validation harness: on each tick its ThreatGate decides (Poisson, wall-clock) whether to launch a
campaign, and if so it builds and SELF-SENDS the whole chain through the proven dual-transport
`seqs.fire()` path, then returns None (nothing for the normal dispatcher).

Design / safety:
- OPT-IN: loaded like any module (has NAME) but only runs when selected. Not in any default set.
- Benign-only safe: returns None in Benign Traffic Only mode -> zero effect on a baseline run.
- Rarer than single-scenario episodes (rate_scale below): a campaign is one high-signal incident,
  not per-feed noise, so it shouldn't match the per-module scenario rate.
- Campaigns self-send via integrations.cribl_direct (+ WEC), the same transport the harness uses;
  WEC steps no-op cleanly when WEC_BROKER_URL/WEC_PFX_PATH aren't set.
"""
import random

from modules import azure_common as ac
from modules import azuread_threat_sequences as seqs

NAME = "Identity Threat Campaigns"
DESCRIPTION = ("Fires multi-stage cross-feed identity campaigns (BEC, ransomware, OAuth abuse, "
               "hybrid on-prem/cloud, RT->PRT) during a live run, self-sending via cribl_direct + WEC.")
CONFIG_KEY = "azuread_campaigns_config"

# A campaign is a whole incident, rarer than a single-feed scenario episode. 0.5 => campaigns fire at
# half the per-module episode rate for the selected threat level.
_CAMPAIGN_RATE_SCALE = 0.5
_GATE = ac.ThreatGate(rate_scale=_CAMPAIGN_RATE_SCALE)

# The dashboard lists each campaign under Threats & Scenarios -> Run Attack Scenario
# (run_campaign below) instead of showing this coordinator as a module card; the CLI
# still loads it as a module.
DASHBOARD_MODULE = False

# Dashboard titles, in the order the campaigns are listed there.
CAMPAIGN_TITLES = {
    "hybrid_onprem_cloud":              "Hybrid On-Prem → Cloud (workstation logon → Kerberos → AiTM sign-in → MFA persistence → mail exfil)",
    "bec_campaign":                     "Business Email Compromise (TOR takeover → MFA added → inbox hiding rule → mail forwarding)",
    "ransomware_campaign":              "Cloud Ransomware (compromised sign-in → SharePoint mass download → mass delete → DLP)",
    "oauth_app_abuse":                  "OAuth App Abuse (never-seen app consent → SP credential → app sign-in → mailbox access)",
    "illicit_oauth_consent":            "Illicit OAuth Consent (user consents risky scopes → app reads mail/files)",
    "aitm_token_theft":                 "AiTM Token Theft (TOR sign-in → attacker MFA registration → token reset)",
    "rt_to_prt_transition":             "Refresh Token → PRT Transition (broker RT → unmanaged-device PRT sign-in)",
    "spray_compromise_persist":         "Password Spray → Compromise → MFA Persistence",
    "golden_saml_federation":           "Golden SAML Federation Backdoor (admin → set federation → add domain)",
    "privesc_global_admin":             "Privilege Escalation to Global Admin (role grant → PIM MFA requirement removed)",
    "mfa_tamper_takeover":              "MFA Tamper Takeover (MFA disabled → password reset → sign-in as victim)",
    "backdoor_user":                    "Backdoor User (admin creates a user → privileged role → it signs in)",
    "sp_credential_abuse":              "Service Principal Credential Abuse (credential added → SP signs in from new IP)",
    "stale_account_reactivation":       "Stale Account Reactivation (departed account → sign-in → audit → SharePoint)",
    "insider_threat":                   "Insider Threat (employee bulk SharePoint download + Exchange exfil)",
    "impossible_travel_risky":          "Impossible Travel + Risky Sign-in (US success → high-risk success abroad)",
    "legacy_auth_bypass":               "Legacy Auth MFA Bypass (repeated legacy-protocol sign-ins to Exchange)",
    "rogue_tenant_cross_tenant_sync":   "Rogue Tenant Trust (cross-tenant access + inbound sync from an attacker tenant)",
    "delegated_admin_partner_takeover": "Delegated Admin Partner Takeover (external partner added and promoted)",
    "multitenant_org_join":             "Multi-Tenant Org Join (tenant folded into an attacker-run org)",
    "cross_tenant_sync_outbound":       "Outbound Cross-Tenant Sync (users synced to a rogue tenant)",
}


def run_campaign(name, config=None, context=None):
    """Send one campaign now (dashboard Run Attack Scenario). Raises if any cloud batch
    was rejected, so the run shows as failed instead of silently 'done'. Windows steps
    are skipped, not failed, when WEC isn't configured."""
    results = seqs.fire(name, config, context=context)
    failed = []
    for _name, res in results:
        code, text = res[0], res[1]
        if code == "__wec__":
            print(f"[{NAME}] {name}: Windows steps {text}")
        elif not (isinstance(code, int) and 200 <= code < 300):
            failed.append(f"HTTP {code}: {str(text)[:120]}")
        else:
            print(f"[{NAME}] {name}: sent {res[2]} record(s)")
    if failed:
        raise RuntimeError(f"campaign '{name}' rejected: " + "; ".join(failed))
    return results


def get_threat_names():
    """Campaign names, so the 'specific threat' menu can launch one on demand."""
    return list(seqs.SEQUENCES.keys())


def _fire(name, config, context):
    try:
        seqs.fire(name, config, context=context)   # self-sends cloud (Cribl) + on-prem (WEC)
        return (seqs.build, name)
    except Exception as e:   # never let a campaign error kill the module loop
        print(f"[{NAME}] campaign '{name}' error: {str(e)[:160]}")
        return None


def generate_log(config=None, threat_level="Realistic", benign_only=False,
                 scenario=None, scenario_event=None, context=None):
    # On-demand (menu / harness-style): launch a named campaign.
    if scenario_event:
        name = scenario_event if scenario_event in seqs.SEQUENCES else scenario_event.lower()
        if name in seqs.SEQUENCES:
            _fire(name, config, context)
        return None
    # No campaigns during baseline / benign-only runs.
    if benign_only or threat_level == "Benign Traffic Only":
        return None
    # Poisson gate: occasionally launch a random campaign for this threat level.
    if _GATE.fire(threat_level, config):
        _fire(random.choice(list(seqs.SEQUENCES)), config, context)
    # This module self-sends; nothing goes through the normal dispatcher.
    return None
