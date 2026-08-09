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
    cleanup: bool = False                 # run the atomic's -Cleanup after the step (persistence etc.)
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
    # Identity anchor: emit a Windows 4624 type-3 network logon binding the box's
    # IP<->user, so XSIAM can resolve IP-keyed network alerts (e.g. the DNS C2
    # beacon, which lands with host_ip but NO_HOST/no user) to the same user the
    # endpoint case is keyed on — the prerequisite for the network alert to merge
    # into the endpoint incident. Requires the Windows Event Log module (WEC).
    anchor_logon: bool = True


# ── Reference story (P1) ──────────────────────────────────────────────────────

def get_reference_story() -> Story:
    """A coherent, safe kill-chain arc: real endpoint recon → C2 beacon → persistence
    on the box, with synthetic DNS/web C2 logs pinned to the SAME discovered identity
    (host, IP, AND user) so endpoint + network read as one incident.

    Every technique is non-destructive and cleanup-capable; the persistence step
    runs -Cleanup so no artifact is left behind. Network events reuse the known-good
    Infoblox/Zscaler beacon events, now carrying the real user + the step's C2 domain
    (see the module identity/domain overrides), not module defaults."""
    c2_domain = "cdn-sync-telemetry.net"     # single source of truth for the C2 step
    return Story(
        id="xdr_reference",
        name="XDR Reference: real recon → C2 beacon → persistence + aligned synthetic C2",
        anchor_dhcp=True,
        steps=[
            Step(
                narrative="Discovery — System Information Discovery (systeminfo / reg).",
                technique={"id": "T1082", "test_numbers": "1", "executor": "winrm_atomic"},
            ),
            Step(
                narrative="Discovery — System Network Configuration Discovery (ipconfig / arp / route).",
                technique={"id": "T1016", "test_numbers": "1", "executor": "winrm_atomic"},
            ),
            Step(
                narrative="Discovery — System Owner/User Discovery (whoami).",
                technique={"id": "T1033", "test_numbers": "1", "executor": "winrm_atomic"},
            ),
            Step(
                narrative="Discovery — Process Discovery (tasklist).",
                technique={"id": "T1057", "test_numbers": "1", "executor": "winrm_atomic"},
            ),
            Step(
                narrative="Command & Control — endpoint recon paired with a synthetic DNS + web "
                          "C2 beacon to the same C2 domain, from the same host and user.",
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
            Step(
                narrative="Persistence — Registry Run Key (HKCU ...\\Run); cleaned up after.",
                technique={"id": "T1547.001", "test_numbers": "1", "executor": "winrm_atomic"},
                cleanup=True,
            ),
        ],
    )


def get_story(story_id: str) -> Optional[Story]:
    """Resolve a story by id. P1 has one; Phase 2 externalizes these to files."""
    return {get_reference_story().id: get_reference_story()}.get(story_id)
