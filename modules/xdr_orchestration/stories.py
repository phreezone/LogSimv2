# modules/xdr_orchestration/stories.py
#
# A STORY is the unit of work (per plan): a coherent, ordered narrative where each
# step blends a REAL endpoint technique (fired by an executor) with ALIGNED
# synthetic network events, so XSIAM reads the whole run as one incident with a
# beginning, middle, and end — not a scatter of isolated alerts.
#
# Stories are pure DATA here; orchestrator.py sequences them. Each step declares
# its network artifacts once in `params`; the orchestrator threads `params` into
# BOTH the executor (as Atomic input args) AND the synthetic network `context`, so
# the endpoint and the network agree on dest/port/app. (v1 also lets a NetworkEvent
# carry explicit context for module-specific field names; the shared identity —
# src_ip/hostname — is injected by the orchestrator, mirroring the proven
# run_beaconing_implant_scenario pattern.)

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class NetworkEvent:
    """One synthetic network log to emit alongside a step's real technique.
    `module` is the all_modules key (e.g. "Infoblox NIOS"); `event` is the
    module's scenario_event; `context` adds module-specific keys (the orchestrator
    injects the shared identity — src_ip/hostname — automatically)."""
    module: str
    event: str
    context: dict = field(default_factory=dict)
    external: bool = False   # True => use the egress/public IP as src_ip (Zscaler, perimeter FW)


@dataclass
class Step:
    narrative: str
    technique: dict                       # {"id","test_numbers","executor"?, "input_args"?}
    params: dict = field(default_factory=dict)      # shared per-step vars (dest/port/app/domain/url)
    network: List[NetworkEvent] = field(default_factory=list)
    pre_delay: float = 0.0
    post_delay: float = 2.0


@dataclass
class Story:
    id: str
    name: str
    steps: List[Step]
    # Identity anchor: emit an Infoblox DHCP lease binding the box's IP<->hostname
    # before firing, so XSIAM's identity graph ties the synthetic network IP to the
    # same host the Cortex agent reports (see reference_ip_user_binding). Off unless
    # the Infoblox module is present.
    anchor_dhcp: bool = True


# ── Reference story (P1) ──────────────────────────────────────────────────────

def get_reference_story() -> Story:
    """A short, safe, complete arc used to validate the stitch: recon on the real
    endpoint + a synthetic DNS/web C2 beacon pinned to the same host identity.

    Uses only T1082-1 (System Information Discovery) — benign, non-destructive,
    cleanup-capable, and already proven to fire + land in xdr_data. The network
    events reuse the known-good Infoblox/Zscaler beacon events from the beaconing
    scenario, keyed to the discovered host so endpoint + network share identity."""
    c2_domain = "cdn-sync-telemetry.net"     # single source of truth for this step
    return Story(
        id="xdr_reference",
        name="XDR Reference: real recon + aligned synthetic C2 beacon",
        anchor_dhcp=True,
        steps=[
            Step(
                narrative="Discovery — real System Information Discovery on the endpoint, "
                          "paired with a synthetic DNS + web C2 beacon from the same host.",
                technique={"id": "T1082", "test_numbers": "1", "executor": "winrm_atomic"},
                params={"domain": c2_domain, "protocol": "https", "port": 443},
                network=[
                    NetworkEvent("Infoblox NIOS", "C2_BEACON",
                                 context={"domain": c2_domain}),
                    NetworkEvent("Zscaler Web Gateway", "web_c2_beacon",
                                 context={"domain": c2_domain}, external=True),
                ],
                post_delay=2.0,
            ),
        ],
    )


def get_story(story_id: str) -> Optional[Story]:
    """Resolve a story by id. P1 has one; Phase 2 externalizes these to files."""
    return {get_reference_story().id: get_reference_story()}.get(story_id)
