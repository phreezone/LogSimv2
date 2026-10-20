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
