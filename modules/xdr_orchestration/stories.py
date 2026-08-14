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
    prereqs: bool = False                 # run the atomic's -GetPrereqs before firing (tests that
                                          # need a target file/tool staged first, e.g. file deletion)
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

def _wa(tid, tn="1"):
    """Shorthand for a winrm_atomic technique step spec."""
    return {"id": tid, "test_numbers": tn, "executor": "winrm_atomic"}


def get_reference_story() -> Story:
    """The full kill-chain arc: a broad real-endpoint recon sweep → C2 beacon (DNS +
    DNS-tunnel + web) → collection → persistence (two techniques), with synthetic
    network logs pinned to the SAME discovered identity (host, IP, user) so endpoint
    + network read as one incident.

    Every technique is non-destructive and cleanup-capable; persistence steps run
    -Cleanup so no artifact is left behind. This is the richest event mix — use the
    'quick' story for fast isolated runs."""
    c2_domain = "cdn-sync-telemetry.net"     # single source of truth for the C2 step
    return Story(
        id="xdr_reference",
        name="XDR Full Kill-Chain: recon sweep → C2 (DNS/tunnel/web) → persistence x2",
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            # ── Discovery sweep (TA0007) — many distinct endpoint detections ──────
            Step("Discovery — System Information (systeminfo / reg).", _wa("T1082")),
            Step("Discovery — System Network Configuration (ipconfig / arp / route).", _wa("T1016")),
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Discovery — Process Discovery (tasklist).", _wa("T1057")),
            Step("Discovery — System Network Connections (netstat).", _wa("T1049")),
            Step("Discovery — Local Account enumeration (net user).", _wa("T1087.001")),
            Step("Discovery — Security Software Discovery (find AV/EDR).", _wa("T1518.001")),
            # ── Command & Control (TA0011) — real recon + aligned synthetic C2 ────
            Step(
                "Command & Control — endpoint activity paired with a synthetic DNS beacon, "
                "DNS tunnel, and web C2 to the same domain, from the same host and user.",
                _wa("T1082"),
                params={"domain": c2_domain, "protocol": "https", "port": 443},
                network=[
                    NetworkEvent("Infoblox NIOS", "C2_BEACON", context={"domain": c2_domain}),
                    NetworkEvent("Infoblox NIOS", "DNS_TUNNEL"),
                    NetworkEvent("Zscaler Web Gateway", "web_c2_beacon",
                                 context={"domain": c2_domain}, external=True),
                    # Perimeter firewall egress — whichever vendor is onboarded logs the
                    # same beacon from the box, carrying the bare box user (stitches).
                    NetworkEvent("Cisco Firepower", "C2_EGRESS", context={"domain": c2_domain}),
                    NetworkEvent("Check Point Firewall", "C2_EGRESS", context={"domain": c2_domain}),
                    NetworkEvent("Fortinet FortiGate", "C2_EGRESS", context={"domain": c2_domain}),
                ],
                post_delay=2.0,
            ),
            # ── Persistence (TA0003) — two techniques, both cleaned up ───────────
            Step("Persistence — Registry Run Key (HKCU ...\\Run); cleaned up after.",
                 _wa("T1547.001"), cleanup=True),
            Step("Persistence — Scheduled Task (schtasks); cleaned up after.",
                 _wa("T1053.005"), cleanup=True),
        ],
    )


def get_quick_story() -> Story:
    """A short, fast arc for small isolated runs from the console: one recon
    technique + a single identity-aligned DNS/web C2 beacon. Minimal footprint,
    exercises the full endpoint→network→stitch path end to end."""
    c2_domain = "sync-metrics-cdn.net"
    return Story(
        id="xdr_quick",
        name="XDR Quick: recon + aligned C2 beacon (fast, small run)",
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step(
                "Command & Control — recon + synthetic DNS + web C2 beacon, same host/user.",
                _wa("T1082"),
                params={"domain": c2_domain},
                network=[
                    NetworkEvent("Infoblox NIOS", "C2_BEACON", context={"domain": c2_domain}),
                    NetworkEvent("Zscaler Web Gateway", "web_c2_beacon",
                                 context={"domain": c2_domain}, external=True),
                ],
            ),
        ],
    )


# ── Credential-theft story (P2) ───────────────────────────────────────────────

def get_intrusion_story() -> Story:
    """A hands-on-keyboard 'smash-and-grab' arc that deliberately AVOIDS the
    recon-heavy techniques of the reference story, so the Cortex agent produces a
    completely different set of endpoint detections: LOLBin ingress → OS credential
    dumping (LSASS) → credentials-in-files → indicator removal → local data staging
    → exfiltration over HTTP. This broadens XDR's view from 'discovery noise' to the
    high-severity credential-theft/exfil detections that anchor real incidents.

    Every test is validated non-destructive against the live box (2026-08-14):
      • T1105-13   MpCmdRun.exe LOLBin download   (cmd; cleanup deletes temp file)
      • T1003.001-2 comsvcs.dll LSASS MiniDump     (ps, elevated; cleanup deletes dmp)
      • T1552.001-4 findstr passwords in files     (ps; read-only)
      • T1070.004-6 file deletion / indicator removal (ps; prereq creates the target)
      • T1074.001-3 Compress-Archive data staging  (ps; cleanup deletes the zip)
      • T1048.003-4 exfil over HTTP                (ps; POSTs to the C2 domain)

    Network artifacts are pinned to the same discovered identity so the download and
    exfil beats stitch into the endpoint incident: a large web download on ingress,
    and web-exfil + DNS-tunnel + perimeter-firewall egress on exfil.
    """
    exfil_domain = "sync-backup-store.net"     # single source of truth for the exfil step
    return Story(
        id="xdr_intrusion",
        name="XDR Credential-Theft: LOLBin ingress → LSASS dump → creds-in-files → "
             "evasion → staging → HTTP exfil",
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            # ── Execution / Ingress Tool Transfer (TA0011/TA0002) ────────────────
            Step(
                "Ingress Tool Transfer — a Living-off-the-Land download via Windows "
                "Defender's own MpCmdRun.exe, paired with a synthetic large web "
                "download from the same host.",
                _wa("T1105", "13"),
                network=[
                    NetworkEvent("Zscaler Web Gateway", "large_download", external=True),
                ],
            ),
            # ── Credential Access (TA0006) — the high-severity core ──────────────
            Step("OS Credential Dumping — dump LSASS memory via comsvcs.dll MiniDump "
                 "(native rundll32); the dump file is cleaned up after.",
                 _wa("T1003.001", "2"), cleanup=True),
            Step("Unsecured Credentials — search local files for passwords with findstr.",
                 _wa("T1552.001", "4")),
            # ── Defense Evasion (TA0005) — anti-forensics ────────────────────────
            Step("Indicator Removal — delete a file from disk (prereq stages the "
                 "target file first so the deletion is self-contained).",
                 _wa("T1070.004", "6"), prereqs=True),
            # ── Collection / Local Data Staging (TA0009) ─────────────────────────
            Step("Data Staged — archive collected data into a zip in the temp folder "
                 "for later exfiltration; the staged archive is cleaned up after.",
                 _wa("T1074.001", "3"), cleanup=True),
            # ── Exfiltration (TA0010) — real endpoint POST + aligned synthetic net ─
            Step(
                "Exfiltration Over Alternative Protocol — the endpoint POSTs data over "
                "HTTP to the exfil domain, paired with a synthetic web upload, DNS "
                "tunnel, and perimeter-firewall egress from the same host and user.",
                _wa("T1048.003", "4"),
                params={"domain": exfil_domain, "protocol": "https", "port": 443,
                        "input_args": {"input_file": r"C:\Windows\win.ini",
                                       "ip_address": f"http://{exfil_domain}/upload"}},
                network=[
                    NetworkEvent("Zscaler Web Gateway", "data_exfil",
                                 context={"domain": exfil_domain}, external=True),
                    NetworkEvent("Infoblox NIOS", "DNS_TUNNEL"),
                    NetworkEvent("Cisco Firepower", "C2_EGRESS", context={"domain": exfil_domain}),
                    NetworkEvent("Check Point Firewall", "C2_EGRESS", context={"domain": exfil_domain}),
                    NetworkEvent("Fortinet FortiGate", "C2_EGRESS", context={"domain": exfil_domain}),
                ],
                post_delay=2.0,
            ),
        ],
    )


# ── Registry ──────────────────────────────────────────────────────────────────

_STORY_BUILDERS = {
    "xdr_quick":     get_quick_story,
    "xdr_reference": get_reference_story,
    "xdr_intrusion": get_intrusion_story,
}


def list_stories() -> list:
    """[{id, name, steps, techniques}] for the console story picker."""
    out = []
    for sid, build in _STORY_BUILDERS.items():
        s = build()
        out.append({
            "id": s.id,
            "name": s.name,
            "steps": len(s.steps),
            "techniques": [st.technique["id"] for st in s.steps],
        })
    return out


def all_technique_ids() -> list:
    """Every distinct technique id across all stories — used by the Kickstarter to
    install exactly the prereqs any story might need."""
    ids = []
    for build in _STORY_BUILDERS.values():
        for st in build().steps:
            if st.technique["id"] not in ids:
                ids.append(st.technique["id"])
    return ids


def get_story(story_id: str) -> Optional[Story]:
    """Resolve a story by id (defaults handled by the caller)."""
    build = _STORY_BUILDERS.get(story_id)
    return build() if build else None
