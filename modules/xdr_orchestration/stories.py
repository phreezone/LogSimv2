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

import os
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
    # CONDITIONAL emission: when set, this event is emitted ONLY if the step's real
    # technique produced a truthy output under this key (ExecResult.outputs[<key>]).
    # Lets a step carry a synthetic network half that pairs with an OPTIONAL behaviour
    # (e.g. the cradle's egress half, emitted only when a real http(s) url was fetched
    # -> outputs["remote"] is True). The scorecard scores only what was emitted
    # (orchestrator records summary["network_emitted"]), so a run that didn't take the
    # conditional path never reads as a network miss.
    only_if_output: Optional[str] = None


@dataclass
class Step:
    narrative: str
    technique: dict                       # {"id","test_numbers","executor"?, "input_args"?}
    params: dict = field(default_factory=dict)      # shared per-step vars (dest/port/app/domain/url)
    network: List[NetworkEvent] = field(default_factory=list)
    # ENDPOINT detection expectation: alert-name substrings that are ALTERNATES of the
    # one detection the technique itself should raise on the Cortex agent. Left empty,
    # _annotate() fills it from TECHNIQUE_CATALOG. Network expectations are NOT set
    # here -- the scorecard derives them from each NetworkEvent's emitting module
    # (expectations.py), so they always match what the generator was built to trip.
    expected_alerts: List[str] = field(default_factory=list)
    mitre: dict = field(default_factory=dict)        # {"tactic","technique_id","technique"}
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
    # ATT&CK tactics this story exercises (display-only, for the console picker).
    tactics: List[str] = field(default_factory=list)
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


# ── Shared synthetic-network building blocks ───────────────────────────────────
# Reused across stories so the egress/recon/lateral stitches stay consistent. Every
# event name here is one the orchestrator path already proved against the modules.

def _fw_egress(domain=None) -> List["NetworkEvent"]:
    """Perimeter-firewall egress fan-out: whichever vendor is onboarded logs the same
    beacon from the box (the others skip). Optionally pinned to a destination domain."""
    ctx = {"domain": domain} if domain else {}
    return [
        NetworkEvent("Cisco Firepower", "C2_EGRESS", context=dict(ctx)),
        NetworkEvent("Check Point Firewall", "C2_EGRESS", context=dict(ctx)),
        NetworkEvent("Fortinet FortiGate", "C2_EGRESS", context=dict(ctx)),
    ]


def _internal_recon_net() -> List["NetworkEvent"]:
    """Synthetic INTERNAL network recon from the box — SMB share enumeration + a port
    scan. Internal (not external), so the source is the box's LAN IP and the events
    stitch to the same host the endpoint recon runs on."""
    return [
        NetworkEvent("Zscaler Web Gateway", "smb_share_enumeration"),
        NetworkEvent("Zscaler Web Gateway", "port_scan"),
    ]


def _internal_lateral_net() -> List["NetworkEvent"]:
    """Synthetic INTERNAL lateral movement from the box to other hosts: SMB to a new
    host, an RDP pivot, and a rare SMB file transfer — the network half of a pivot."""
    return [
        NetworkEvent("Zscaler Web Gateway", "smb_new_host_lateral"),
        NetworkEvent("Zscaler Web Gateway", "rdp_lateral"),
        NetworkEvent("Zscaler Web Gateway", "smb_rare_file_transfer"),
    ]


def _remote_fetch_egress(gate="remote") -> List["NetworkEvent"]:
    """The perimeter half of an outbound tool/script fetch, emitted ONLY when the step
    really reached out (outputs[gate] truthy). A web-proxy record that names the exact
    URL/host/hash the box fetched (Zscaler `sandbox_threat` consumes the run artifact),
    plus the firewall egress fan-out. The orchestrator pins the destination from the
    run artifact (the fetched host -> `domain`), so the fired URL and the perimeter
    egress agree. Used by the cradle's optional http(s)-url mode; a file:// run emits
    none of it."""
    evs = [NetworkEvent("Zscaler Web Gateway", "sandbox_threat")]
    evs += _fw_egress()                    # C2_EGRESS; domain pinned at emit time
    for e in evs:
        e.only_if_output = gate
    return evs


# ── Detection / ATT&CK catalog ─────────────────────────────────────────────────
# Maps each validated technique id to its ATT&CK (tactic, technique name) and a
# best-effort set of alert-name substrings it should trigger. _annotate() fills any
# Step that didn't set these explicitly. The expected_alerts are EXPECTATIONS the
# user tunes against their own tenant's analytic names — a miss on the scorecard
# means "not observed", which is itself the signal worth seeing. Low-signal recon
# techniques intentionally carry no expected_alerts (they rarely alert alone) but
# still carry their ATT&CK mapping for the coverage map.
TECHNIQUE_CATALOG = {
    "T1082":     {"tactic": "Discovery", "technique": "System Information Discovery", "expected_alerts": []},
    "T1016":     {"tactic": "Discovery", "technique": "System Network Configuration Discovery", "expected_alerts": []},
    "T1033":     {"tactic": "Discovery", "technique": "System Owner/User Discovery", "expected_alerts": []},
    "T1057":     {"tactic": "Discovery", "technique": "Process Discovery", "expected_alerts": []},
    "T1049":     {"tactic": "Discovery", "technique": "System Network Connections Discovery", "expected_alerts": []},
    "T1087.001": {"tactic": "Discovery", "technique": "Account Discovery: Local Account", "expected_alerts": []},
    "T1518.001": {"tactic": "Discovery", "technique": "Security Software Discovery", "expected_alerts": ["Security Software"]},
    "T1105":     {"tactic": "Command and Control", "technique": "Ingress Tool Transfer", "expected_alerts": ["Ingress Tool", "LOLBin", "Download"]},
    # Builtin download_cradle payload. Cortex keys on the deobfuscated script block
    # (WebClient + DownloadString + Invoke-Expression); best-effort names, tune per tenant.
    "T1059.001": {"tactic": "Execution", "technique": "Command and Scripting Interpreter: PowerShell",
                  "expected_alerts": ["Suspicious PowerShell", "PowerShell", "DownloadString", "Invoke-Expression", "Download Cradle", "WebClient", "Encoded"]},
    # Builtin encoded_command payload. powershell.exe -EncodedCommand <base64>; the
    # detector keys on the encoded-command flag + blob. Best-effort names, tune per tenant.
    "T1027.010": {"tactic": "Defense Evasion", "technique": "Obfuscated Files or Information: Command Obfuscation",
                  "expected_alerts": ["Encoded", "Obfuscat", "Suspicious PowerShell", "PowerShell", "EncodedCommand", "Base64", "enc"]},
    # Names the agent actually raised on 2026-11-18 (XDR Agent, box-tied):
    # "Credential Gathering Protection - <id>" (many ids, one per rule hit) and
    # "Memory dumping with comsvcs.dll". Matching is case-insensitive substring.
    "T1003.001": {"tactic": "Credential Access", "technique": "OS Credential Dumping: LSASS Memory", "expected_alerts": ["Credential Gathering Protection", "Memory dumping", "LSASS", "Credential Dump", "comsvcs", "MiniDump"]},
    "T1552.001": {"tactic": "Credential Access", "technique": "Unsecured Credentials: Credentials In Files", "expected_alerts": ["Unsecured Credential", "Credentials In Files", "password"]},
    "T1070.004": {"tactic": "Defense Evasion", "technique": "Indicator Removal: File Deletion", "expected_alerts": ["Indicator Removal", "File Deletion"]},
    "T1074.001": {"tactic": "Collection", "technique": "Data Staged: Local Data Staging", "expected_alerts": ["Data Staged", "Staging", "Archive"]},
    "T1048.003": {"tactic": "Exfiltration", "technique": "Exfiltration Over Unencrypted Non-C2 Protocol", "expected_alerts": ["Exfiltration", "Exfil"]},
    "T1547.001": {"tactic": "Persistence", "technique": "Boot/Logon Autostart: Registry Run Keys", "expected_alerts": ["Run Key", "Registry Run", "Autostart"]},
    # Matches the analytics alert "Uncommon local scheduled task created" (2026-11-18).
    "T1053.005": {"tactic": "Persistence", "technique": "Scheduled Task/Job: Scheduled Task", "expected_alerts": ["Scheduled Task"]},
    # Builtin wildfire_pe payload. Confirmed 2026-11-18: "WildFire Malware", source
    # XDR Agent, high, action "Detected (Post Detected)", ~10 min after the run (the
    # file stays on disk so the agent can upload it for the verdict).
    "T1204.002": {"tactic": "Execution", "technique": "User Execution: Malicious File", "expected_alerts": ["WildFire Malware"]},
    # Builtin squiblydoo payload. Best-effort names (BTP / LOLBin regsvr32 abuse);
    # confirm against the tenant on the first run and tune these substrings.
    "T1218.010": {"tactic": "Defense Evasion", "technique": "System Binary Proxy Execution: Regsvr32",
                  "expected_alerts": ["Regsvr32", "Squiblydoo", "scrobj", "Signed Binary Proxy", "LOLBIN"]},
    # Builtin vss_shadow_delete payload. Best-effort names (ransomware / inhibit-
    # recovery); confirm against the tenant on the first run and tune these.
    "T1490":     {"tactic": "Impact", "technique": "Inhibit System Recovery",
                  "expected_alerts": ["Shadow Cop", "Volume Shadow", "Inhibit System Recovery", "vssadmin", "Ransomware"]},
    # ── P4 scenario techniques (builtin payloads). expected_alerts are best-effort
    # ── Cortex names; tune against the tenant after the first run.
    "T1486":     {"tactic": "Impact", "technique": "Data Encrypted for Impact",
                  "expected_alerts": ["Ransomware", "Encrypt", "Mass", "File Modification", "Behavioral Threat"]},
    "T1003.002": {"tactic": "Credential Access", "technique": "OS Credential Dumping: Security Account Manager",
                  "expected_alerts": ["SAM", "Registry Hive", "reg save", "Credential Gathering", "Credential Dump"]},
    "T1555":     {"tactic": "Credential Access", "technique": "Credentials from Password Stores",
                  "expected_alerts": ["LaZagne", "Credential", "Password Store", "Hacktool", "Credential Gathering"]},
    "T1218.005": {"tactic": "Defense Evasion", "technique": "System Binary Proxy Execution: Mshta",
                  "expected_alerts": ["Mshta", "mshta", "Signed Binary Proxy", "LOLBIN", "Suspicious"]},
    "T1127.001": {"tactic": "Defense Evasion", "technique": "Trusted Developer Utilities Proxy Execution: MSBuild",
                  "expected_alerts": ["MSBuild", "Trusted Developer", "LOLBIN", "Code Execution", "Suspicious"]},
    "T1562.001": {"tactic": "Defense Evasion", "technique": "Impair Defenses: Disable or Modify Tools",
                  "expected_alerts": ["Impair", "Defender", "Tamper", "Real-time", "Disable", "Exclusion"]},
    "T1070.001": {"tactic": "Defense Evasion", "technique": "Indicator Removal: Clear Windows Event Logs",
                  "expected_alerts": ["Clear", "Event Log", "wevtutil", "Indicator Removal", "Log Clear"]},
    "T1543.003": {"tactic": "Persistence", "technique": "Create or Modify System Process: Windows Service",
                  "expected_alerts": ["Service", "New Service", "sc.exe", "Service Creation", "Persistence"]},
    "T1546.003": {"tactic": "Persistence", "technique": "Event Triggered Execution: WMI Event Subscription",
                  "expected_alerts": ["WMI", "Event Subscription", "Event Consumer", "Persistence", "CommandLineEventConsumer"]},
    # ── Atomic-test-backed stages (vetted Red Canary tests run by test number via the
    # ── executor -- no bespoke offensive payloads). Best-effort names; tune per tenant.
    "T1548.002": {"tactic": "Privilege Escalation", "technique": "Abuse Elevation Control Mechanism: Bypass UAC",
                  "expected_alerts": ["UAC", "Bypass User Account", "Fodhelper", "fodhelper", "Elevation", "Auto-elevate"]},
    "T1036.003": {"tactic": "Defense Evasion", "technique": "Masquerading: Rename System Utilities",
                  "expected_alerts": ["Masquerad", "Rename", "svchost", "LOLBIN", "Suspicious Process Name"]},
    "T1136.001": {"tactic": "Persistence", "technique": "Create Account: Local Account",
                  "expected_alerts": ["Account Creation", "New Local Account", "net user", "Create Account", "User Account"]},
    "T1047":     {"tactic": "Execution", "technique": "Windows Management Instrumentation",
                  "expected_alerts": ["WMI", "wmic", "Win32_Process", "WMI Process", "Process Creation"]},
    "T1197":     {"tactic": "Defense Evasion", "technique": "BITS Jobs",
                  "expected_alerts": ["BITS", "bitsadmin", "Background Intelligent", "Transfer Job"]},
}


# Network-signal expectations are derived, not written here: the scorecard asks each
# NetworkEvent's emitting module which analytic / correlation rule that event is built
# to trip (expectations.py). A step can therefore never expect an alert it doesn't
# emit, and a network miss always means "sent, the detector didn't fire".


# ── Palo Alto NGFW as the default network vendor ──────────────────────────────
# Every step's network signal also gets a PAN NGFW rendering, derived from the vendor
# events it already declares (so YAML stories get it too). PAN is the one network
# vendor sent by default; the others are opt-in per run (orchestrator network_vendors).
PANW_MODULE = "Palo Alto Networks NGFW"
DEFAULT_NETWORK_VENDORS = (PANW_MODULE,)

# other-vendor event -> PAN NGFW event (panw_ngfw._THREAT_DISPATCH / _XDR_EVENTS)
PANW_EQUIVALENT = {
    "C2_BEACON": "xdr_c2_beacon", "web_c2_beacon": "xdr_c2_beacon", "C2_EGRESS": "xdr_c2_beacon",
    "DNS_TUNNEL": "dns_tunnel_pattern",
    "port_scan": "port_scan",
    "smb_share_enumeration": "rare_smb", "smb_new_host_lateral": "rare_smb",
    "smb_rare_file_transfer": "rare_smb",
    "rdp_lateral": "rare_rdp",
    "data_exfil": "large_upload_https",
    "large_download": "xdr_web_download", "sandbox_threat": "xdr_web_download",
    "reverse_ssh_tunnel": "unusual_ssh_external",
}


def panw_equivalents(network) -> List["NetworkEvent"]:
    """The PAN NGFW events matching a step's other-vendor events, one per distinct
    (event, domain). Internal source (the box's LAN IP): the firewall logs the
    pre-NAT client, as PAN does."""
    out, seen = [], set()
    for ne in network or []:
        if ne.module == PANW_MODULE:
            continue
        ev = PANW_EQUIVALENT.get(ne.event)
        if not ev:
            continue
        dom = ne.context.get("domain") if ev == "xdr_c2_beacon" else None
        # A conditional source event mirrors to a conditional PAN event on the SAME
        # gate, so the default-vendor PAN rendering isn't emitted when the source half
        # was gated off (e.g. the cradle's egress on a file:// run).
        gate = getattr(ne, "only_if_output", None)
        if (ev, dom, gate) in seen:
            continue
        seen.add((ev, dom, gate))
        out.append(NetworkEvent(PANW_MODULE, ev, context={"domain": dom} if dom else {},
                                external=ne.external, only_if_output=gate))
    return out


def _annotate(story: "Story") -> "Story":
    """Fill each step's mitre + expected_alerts from TECHNIQUE_CATALOG where the step
    didn't set them explicitly, and add the step's PAN NGFW network events (unless it
    already lists some). Idempotent; returns the same story. Every consumer
    (run_story, list_stories, mitre_coverage) annotates, so steps always carry their
    ATT&CK mapping without the builders having to repeat it."""
    for step in story.steps:
        if step.network and not any(ne.module == PANW_MODULE for ne in step.network):
            step.network = list(step.network) + panw_equivalents(step.network)
        tid = (step.technique or {}).get("id")
        cat = TECHNIQUE_CATALOG.get(tid, {})
        if not step.mitre:
            step.mitre = {"tactic": cat.get("tactic"), "technique_id": tid,
                          "technique": cat.get("technique")}
        if not step.expected_alerts:
            step.expected_alerts = list(cat.get("expected_alerts") or [])
    return story


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
        tactics=["Discovery", "Command & Control", "Persistence"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            # ── Discovery sweep (TA0007) — many distinct endpoint detections ──────
            Step("Discovery — System Information (systeminfo / reg).", _wa("T1082")),
            Step("Discovery — System Network Configuration (ipconfig / arp / route).", _wa("T1016")),
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Discovery — Process Discovery (tasklist).", _wa("T1057")),
            Step("Discovery — System Network Connections (netstat), paired with synthetic "
                 "internal SMB share enumeration and a port scan from the box.",
                 _wa("T1049"), network=_internal_recon_net()),
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
        tactics=["Discovery", "Command & Control"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step(
                "Command & Control — recon + synthetic DNS + web C2 beacon + perimeter "
                "egress, same host/user.",
                _wa("T1082"),
                params={"domain": c2_domain},
                network=[
                    NetworkEvent("Infoblox NIOS", "C2_BEACON", context={"domain": c2_domain}),
                    NetworkEvent("Zscaler Web Gateway", "web_c2_beacon",
                                 context={"domain": c2_domain}, external=True),
                    *_fw_egress(c2_domain),
                ],
            ),
        ],
    )


def get_recon_story() -> Story:
    """Discovery/Recon sweep (TA0007) as a one-shot, fire-on-demand stage — the seven
    low-signal host-recon techniques the reference kill-chain opens with, broken out so
    the recon arc can be fired on its own. Every step is a read-only Atomic (systeminfo,
    ipconfig/arp/route, whoami, tasklist, netstat, net user, AV/EDR discovery); the
    netstat step is paired with a synthetic internal SMB share enumeration + port scan
    from the box, so the on-box recon and the network recon stitch to one identity.
    Non-destructive and nothing to clean up. These rarely alert alone (hence no
    expected_alerts), but they build the behavioural picture and the correlation volume
    the analytics key on."""
    return Story(
        id="xdr_recon",
        name="XDR Recon Sweep: system / network / account / security discovery",
        tactics=["Discovery"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Information (systeminfo / reg).", _wa("T1082")),
            Step("Discovery — System Network Configuration (ipconfig / arp / route).", _wa("T1016")),
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Discovery — Process Discovery (tasklist).", _wa("T1057")),
            Step("Discovery — System Network Connections (netstat), paired with synthetic "
                 "internal SMB share enumeration and a port scan from the box.",
                 _wa("T1049"), network=_internal_recon_net()),
            Step("Discovery — Local Account enumeration (net user).", _wa("T1087.001")),
            Step("Discovery — Security Software Discovery (find AV/EDR).", _wa("T1518.001"),
                 post_delay=3.0),
        ],
    )


# ── WildFire malware-delivery story ───────────────────────────────────────────

def _builtin(tid: str, payload: str) -> dict:
    """Builtin payload step spec (payloads.py), run by the executor over the same
    channel as the Atomic tests but with no Atomic dependency."""
    return {"id": tid, "executor": "builtin", "payload": payload}


def _wildfire_pe() -> dict:
    """Builtin payload step spec: download + run Palo Alto's WildFire test PE
    (payloads.py). T1204.002 = User Execution: Malicious File."""
    return _builtin("T1204.002", "wildfire_pe")


def get_wildfire_story() -> Story:
    """Malware delivery that the Cortex agent judges with a REAL WildFire verdict.

    The Atomic techniques exercise behaviour; this exercises the agent's malware
    module. Palo Alto's WildFire test PE (fresh SHA-256 on every download, verdict
    always malware) is fetched over plain HTTP to C:\\Users\\Public\\Downloads -- outside
    the Atomic allow-list paths -- and executed, so the agent queries WildFire on a
    never-seen hash and raises its WildFire malware alert (allow ~5 min for the
    verdict). The paired Zscaler sandbox record names the same file, hash and URL.
    The file stays until the next WildFire run removes it: deleting it right away
    stopped the agent's WildFire upload (no verdict, no alert)."""
    return Story(
        id="xdr_wildfire",
        name="XDR WildFire: malware test file delivered and run (real WildFire verdict)",
        tactics=["Discovery", "Execution"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami), the operator orienting first.",
                 _wa("T1033")),
            Step(
                "Execution — download Palo Alto's WildFire test PE over HTTP and run it; "
                "Zscaler records the same file with a malicious sandbox verdict.",
                _wildfire_pe(),
                network=[NetworkEvent("Zscaler Web Gateway", "sandbox_threat")],
                # No cleanup: the agent needs the file on disk to upload it for the
                # WildFire verdict. The next run removes it (payloads.py).
                cleanup=False,
                post_delay=5.0,
            ),
        ],
    )


# ── Builtin-payload behaviour stories (self-contained, no Atomic prereqs) ──────
# Each pairs a light orient step with ONE high-signal builtin payload (payloads.py).
# All are endpoint-only: the detection is the behaviour on the box, so there is no
# synthetic network half. The payloads drop their files outside the Atomic allow-list
# paths (like wildfire_pe) so the agent actually examines them.

def get_shadow_delete_story() -> Story:
    """Inhibit System Recovery (T1490) — the ransomware-prep move the Cortex agent
    flags and usually PREVENTS: a process invoking vssadmin to delete volume shadow
    copies. NON-DESTRUCTIVE by design — the payload targets a random, non-existent
    shadow id, so no real shadow copy is removed while the command line the detector
    keys on is still produced (payloads.py). Endpoint-only."""
    return Story(
        id="xdr_shadow_delete",
        name="XDR Inhibit Recovery: vssadmin shadow-copy deletion (ransomware-prep)",
        tactics=["Discovery", "Impact"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami), the operator orienting first.",
                 _wa("T1033")),
            Step("Impact — Inhibit System Recovery: invoke vssadmin to delete volume "
                 "shadow copies (non-destructive — a non-existent shadow id).",
                 _builtin("T1490", "vss_shadow_delete"),
                 cleanup=False, post_delay=3.0),
        ],
    )


def get_procdump_story() -> Story:
    """OS Credential Dumping: LSASS Memory (T1003.001) with a SIGNED tool. Downloads
    Sysinternals ProcDump to C:\\Users\\Public\\Downloads (outside the Atomic allow-list)
    and runs `procdump -ma lsass.exe`, so the agent's Credential Gathering / LSASS-
    access detection fires on a legitimately-signed binary — a complement to the
    comsvcs.dll MiniDump path in the intrusion/lateral stories. The dump (LSASS
    memory) is deleted immediately; the tool is cleaned up after. Endpoint-only."""
    return Story(
        id="xdr_procdump",
        name="XDR Credential Dumping: ProcDump LSASS memory dump (signed tool)",
        tactics=["Discovery", "Credential Access"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Credential Access — download Sysinternals ProcDump and dump LSASS "
                 "memory; the dump is deleted at once, the tool cleaned up after.",
                 _builtin("T1003.001", "procdump_lsass"),
                 cleanup=True, post_delay=3.0),
        ],
    )


def get_squiblydoo_story() -> Story:
    """Signed Binary Proxy Execution: Regsvr32 / Squiblydoo (T1218.010). Stages a
    benign COM scriptlet and runs `regsvr32 /s /n /u /i:<sct> scrobj.dll`, so regsvr32
    proxy-executes script and spawns a child process — the behaviour the Cortex
    agent's BTP flags. The scriptlet only writes a marker (no real payload); scriptlet
    and marker are cleaned up after. Endpoint-only (local scriptlet, no fetch)."""
    return Story(
        id="xdr_squiblydoo",
        name="XDR Squiblydoo: regsvr32 scrobj.dll proxy execution (LOLBin)",
        tactics=["Discovery", "Defense Evasion"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Defense Evasion — Squiblydoo: regsvr32 proxy-executes a local COM "
                 "scriptlet via scrobj.dll; scriptlet + marker cleaned up after.",
                 _builtin("T1218.010", "squiblydoo"),
                 cleanup=True, post_delay=3.0),
        ],
    )


def get_cradle_story() -> Story:
    """Command and Scripting Interpreter: PowerShell (T1059.001) — the classic
    `IEX (New-Object Net.WebClient).DownloadString(<url>)` download cradle. Cortex's
    behavioral / command-line analytics key on the deobfuscated script block
    (WebClient + DownloadString + Invoke-Expression), so the detection fires on the
    command-line SHAPE, not on what runs. Benign + self-contained by default: the
    payload stages a tiny LOCAL marker-writing script and points the cradle at it over
    a file:// URL, so no bytes leave the box and IEX only ever runs our own marker
    write (payloads.py). The cradle runs as a real CHILD powershell.exe with the literal
    on its command line (deliberately NOT via the base64/certutil delivery that hides
    legit scripts) so the agent sees exactly the artifact. Script + marker cleaned up
    after. Endpoint-only by default. An http(s) url can be passed per run for a true-
    egress test; in THAT mode the step also emits a synthetic perimeter half (web-proxy
    record naming the fetched URL + firewall egress), pinned to the same host, so the
    scorecard shows a network-sourced detection too. A file:// run emits none of it."""
    return Story(
        id="xdr_cradle",
        name="XDR Download Cradle: IEX WebClient.DownloadString (PowerShell)",
        tactics=["Discovery", "Execution"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Execution — PowerShell download cradle: a child powershell.exe runs "
                 "`IEX (New-Object Net.WebClient).DownloadString(<url>)` (benign local "
                 "file:// script by default); script + marker cleaned up after. With an "
                 "http(s) url, a synthetic perimeter egress half is emitted too.",
                 _builtin("T1059.001", "download_cradle"),
                 network=_remote_fetch_egress(),
                 cleanup=True, post_delay=3.0),
        ],
    )


def get_encoded_story() -> Story:
    """Obfuscated Files or Information: Command Obfuscation (T1027.010) — the
    `powershell.exe -EncodedCommand <base64>` pattern. A near-universal "suspicious
    PowerShell" heuristic keys on the -EncodedCommand/-enc flag carrying a base64
    UTF-16LE blob on a powershell command line. Benign: the decoded command only
    writes a marker and prints a line (payloads.py). Run as a real CHILD
    powershell.exe with the encoded blob on ITS command line — deliberately NOT via
    the base64/certutil delivery that hides legit scripts (that delivery exists to
    AVOID this very alert), so the agent sees exactly the artifact. Marker cleaned up
    after. Endpoint-only."""
    return Story(
        id="xdr_encoded",
        name="XDR Encoded Command: powershell.exe -EncodedCommand (base64)",
        tactics=["Discovery", "Defense Evasion"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Defense Evasion — Command Obfuscation: a child powershell.exe runs a "
                 "base64 `-EncodedCommand` of a benign marker write; marker cleaned up after.",
                 _builtin("T1027.010", "encoded_command"),
                 cleanup=True, post_delay=3.0),
        ],
    )


def get_tamper_story() -> Story:
    """Impair Defenses: Disable or Modify Tools (T1562.001) — a REVERSIBLE tamper.
    Reuses the `disable_defender` builtin (payloads.py): disable Defender real-time
    protection and add a benign exclusion path, then revert BOTH immediately (the
    detection fires on the attempt; protection is left ON). Cleanup re-asserts the
    revert as a belt-and-suspenders. This is the same payload the `xdr_evasion` chain
    uses, broken out as a one-shot so the tamper trigger can be fired on its own.
    Endpoint-only. If Tamper Protection is on, the disable is blocked — itself the
    detection."""
    return Story(
        id="xdr_tamper",
        name="XDR Impair Defenses: disable Defender real-time protection (reverted)",
        tactics=["Discovery", "Defense Evasion"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Defense Evasion — Impair Defenses: disable Defender real-time "
                 "protection and add an exclusion, then revert both immediately.",
                 _builtin("T1562.001", "disable_defender"),
                 cleanup=True, post_delay=3.0),
        ],
    )


# ── P4 scenario stories (recombine builtins + validated Atomic steps) ──────────

def get_ransomware_story() -> Story:
    """A ransomware kill-chain — Cortex's flagship behavioural detection. Recon →
    LSASS credential dump (comsvcs) → shadow-copy deletion (inhibit recovery) → a
    NON-DESTRUCTIVE mass-encryption simulation in a scratch dir with a ransom note.
    The shadow-delete + mass file rewrite/rename + note is the classic ransomware
    behaviour the agent flags."""
    return Story(
        id="xdr_ransomware",
        name="XDR Ransomware: recon -> LSASS dump -> shadow-copy deletion -> mass-encryption sim",
        tactics=["Discovery", "Credential Access", "Impact"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery - System Owner/User (whoami).", _wa("T1033")),
            Step("Credential Access - LSASS MiniDump via comsvcs.dll; cleaned up after.",
                 _wa("T1003.001", "2"), cleanup=True),
            Step("Impact - Inhibit System Recovery: vssadmin shadow-copy deletion "
                 "(non-destructive; a non-existent shadow id).",
                 _builtin("T1490", "vss_shadow_delete"), post_delay=2.0),
            Step("Impact - Data Encrypted for Impact: simulate mass file encryption in a "
                 "scratch dir and drop a ransom note (scratch dir only, cleaned up after).",
                 _builtin("T1486", "ransomware_sim"), cleanup=True, post_delay=3.0),
        ],
    )


def get_cred_theft_story() -> Story:
    """Hands-on-keyboard credential theft with real tooling: LOLBin ingress -> Mimikatz
    (staged) -> SAM/SYSTEM/SECURITY hive dump via reg.exe -> LaZagne (staged) -> HTTP
    exfil with aligned synthetic network. Mimikatz/LaZagne are staged by the Kickstarter;
    if the agent blocked their download, those steps report 'not staged' (itself a
    signal) and the LOLBin SAM dump still fires."""
    exfil_domain = "cred-dropbox-sync.net"
    return Story(
        id="xdr_cred_theft",
        name="XDR Credential Theft: ingress -> Mimikatz -> SAM dump -> LaZagne -> exfil",
        tactics=["Command & Control", "Credential Access", "Exfiltration"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Ingress Tool Transfer - LOLBin download via MpCmdRun.exe, paired with a "
                 "synthetic large web download.",
                 _wa("T1105", "13"),
                 network=[NetworkEvent("Zscaler Web Gateway", "large_download", external=True)]),
            Step("Credential Access - run Mimikatz (sekurlsa::logonpasswords) from the "
                 "staged copy.", _builtin("T1003.001", "mimikatz"), post_delay=2.0),
            Step("Credential Access - dump the SAM/SYSTEM/SECURITY registry hives via "
                 "reg.exe; the hives are deleted at once.",
                 _builtin("T1003.002", "sam_hive_dump"), cleanup=True),
            Step("Credential Access - run the LaZagne harvester from the staged copy.",
                 _builtin("T1555", "lazagne"), post_delay=2.0),
            Step("Exfiltration Over Alternative Protocol - the endpoint POSTs over HTTP to "
                 "the exfil domain, paired with synthetic web upload + DNS tunnel + egress.",
                 _wa("T1048.003", "4"),
                 params={"domain": exfil_domain, "protocol": "https", "port": 443,
                         "input_args": {"input_file": r"C:\Windows\win.ini",
                                        "ip_address": f"http://{exfil_domain}/upload"}},
                 network=[
                     NetworkEvent("Zscaler Web Gateway", "data_exfil",
                                  context={"domain": exfil_domain}, external=True),
                     NetworkEvent("Infoblox NIOS", "DNS_TUNNEL"),
                     *_fw_egress(exfil_domain),
                 ], post_delay=2.0),
        ],
    )


def get_evasion_story() -> Story:
    """A LOLBin / defense-evasion chain: two signed-binary proxy executions (Squiblydoo
    regsvr32, then mshta), a trusted-developer-utility proxy (MSBuild inline task),
    disabling Defender real-time protection (reverted), and clearing an event log. All
    endpoint-only Behavioral Threat Protection triggers; artifacts cleaned up / reverted."""
    return Story(
        id="xdr_evasion",
        name="XDR Defense Evasion: Squiblydoo -> mshta -> MSBuild -> disable Defender -> clear log",
        tactics=["Discovery", "Defense Evasion"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery - System Owner/User (whoami).", _wa("T1033")),
            Step("Defense Evasion - Squiblydoo: regsvr32 proxy-executes a local scriptlet.",
                 _builtin("T1218.010", "squiblydoo"), cleanup=True),
            Step("Defense Evasion - mshta proxy-executes a local scriptlet.",
                 _builtin("T1218.005", "mshta_proxy"), cleanup=True),
            Step("Defense Evasion - MSBuild compiles and runs an inline C# task.",
                 _builtin("T1127.001", "msbuild_inline"), cleanup=True),
            Step("Defense Evasion - Impair Defenses: disable Defender real-time protection "
                 "and add an exclusion, then revert.",
                 _builtin("T1562.001", "disable_defender"), cleanup=True),
            Step("Defense Evasion - Indicator Removal: clear an event log via wevtutil "
                 "(an own custom log; non-destructive).",
                 _builtin("T1070.001", "clear_event_log"), cleanup=True, post_delay=2.0),
        ],
    )


def get_persistence_sweep_story() -> Story:
    """A persistence sweep: Registry Run key and a Scheduled Task (Atomic), then a new
    Windows service, a WMI permanent event subscription, and a Startup-folder shortcut
    (builtins). Every foothold is removed in cleanup, so the box is left clean while the
    agent still sees five distinct persistence techniques."""
    return Story(
        id="xdr_persistence_sweep",
        name="XDR Persistence Sweep: Run key -> scheduled task -> service -> WMI sub -> startup",
        tactics=["Discovery", "Persistence"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery - System Owner/User (whoami).", _wa("T1033")),
            Step("Persistence - Registry Run Key (HKCU ...\\Run); cleaned up after.",
                 _wa("T1547.001"), cleanup=True),
            Step("Persistence - Scheduled Task (schtasks); cleaned up after.",
                 _wa("T1053.005"), cleanup=True),
            Step("Persistence - create a Windows service via sc.exe; deleted after.",
                 _builtin("T1543.003", "new_service"), cleanup=True),
            Step("Persistence - WMI permanent event subscription; removed after.",
                 _builtin("T1546.003", "wmi_subscription"), cleanup=True),
            Step("Persistence - drop a .lnk in the common Startup folder; removed after.",
                 _builtin("T1547.001", "startup_folder"), cleanup=True, post_delay=2.0),
        ],
    )


def get_privesc_story() -> Story:
    """Privilege escalation -> evasion -> foothold, built entirely from VETTED Atomic
    Red Team tests (run by pinned test number via the executor -- no bespoke offensive
    payloads). Each pinned test is non-destructive, self-contained (no remote
    download), and has Atomic cleanup, which the step runs:
      * T1548.002-4  Bypass UAC via Fodhelper (PowerShell); HKCU ms-settings hijack.
      * T1036.003-7  Rename a built-in exe (cmd.exe -> svchost.exe in %TEMP%) and run it.
      * T1136.001-4  Create a local user with net.exe; cleanup deletes it.
    This fills Privilege Escalation, which no other story covered."""
    return Story(
        id="xdr_privesc",
        name="XDR Privilege Escalation & Foothold: UAC bypass -> masquerade -> local account",
        tactics=["Discovery", "Privilege Escalation", "Defense Evasion", "Persistence"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery - System Owner/User (whoami).", _wa("T1033")),
            Step("Privilege Escalation - Bypass UAC via Fodhelper (HKCU ms-settings hijack); "
                 "cleaned up after.", _wa("T1548.002", "4"), cleanup=True),
            Step("Defense Evasion - Masquerading: copy a built-in exe to a trusted name "
                 "(svchost.exe) and run it; cleaned up after.", _wa("T1036.003", "7"), cleanup=True),
            Step("Persistence - Create Account: add a local user via net.exe; the account "
                 "is deleted after.", _wa("T1136.001", "4"), cleanup=True, post_delay=2.0),
        ],
    )


def get_lolbin_story() -> Story:
    """LOLBin execution + transfer, from VETTED Atomic Red Team tests (run by pinned
    test number -- no bespoke payloads). Both are Windows, non-destructive, self-
    contained enough for a lab, and cleanup-capable:
      * T1047-5    WMI Execute Local Process: wmic process call create notepad.exe;
                   cleanup ends the process.
      * T1197-1    Bitsadmin Download: bitsadmin /transfer creates a BITS job that
                   fetches a benign Atomic-repo markdown (not executed); cleanup
                   deletes the file. The BITS job creation is the detection; a failed
                   download is non-fatal."""
    return Story(
        id="xdr_lolbin",
        name="XDR LOLBin: WMI process execution -> BITS transfer job",
        tactics=["Discovery", "Execution", "Defense Evasion"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery - System Owner/User (whoami).", _wa("T1033")),
            Step("Execution - WMI: create a process via wmic (Win32_Process Create); "
                 "the process is ended after.", _wa("T1047", "5"), cleanup=True),
            Step("Defense Evasion - BITS Jobs: create a BITS transfer job via bitsadmin; "
                 "the downloaded file is deleted after.", _wa("T1197", "1"),
                 cleanup=True, post_delay=2.0),
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
        tactics=["Execution", "Credential Access", "Defense Evasion",
                 "Collection", "Exfiltration"],
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
                    NetworkEvent("Zscaler Web Gateway", "reverse_ssh_tunnel", external=True),
                    NetworkEvent("Cisco Firepower", "C2_EGRESS", context={"domain": exfil_domain}),
                    NetworkEvent("Check Point Firewall", "C2_EGRESS", context={"domain": exfil_domain}),
                    NetworkEvent("Fortinet FortiGate", "C2_EGRESS", context={"domain": exfil_domain}),
                ],
                post_delay=2.0,
            ),
        ],
    )


# ── New stories (P3) — recombine the validated technique palette ───────────────
# Every technique id/test below is one already proven non-destructive + cleanup-
# capable by the reference/quick/intrusion stories above; only the narratives and
# the synthetic-network mixes are new. No new live-box technique is introduced.

def get_lateral_story() -> Story:
    """A credential-access → lateral-movement arc: light identity recon, OS credential
    dumping (LSASS) and credentials-in-files on the endpoint, paired with synthetic
    INTERNAL network recon (SMB share enumeration, port scan) and lateral movement
    (SMB to a new host, RDP pivot, rare SMB file transfer) from the same box — so
    XSIAM sees the box reach OTHER internal hosts right after the creds are taken."""
    return Story(
        id="xdr_lateral",
        name="XDR Lateral Movement: recon → LSASS dump → creds-in-files → SMB/RDP pivot",
        tactics=["Discovery", "Credential Access", "Lateral Movement", "Collection"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Discovery — System Network Connections (netstat), paired with synthetic "
                 "internal SMB share enumeration and a port scan from the box.",
                 _wa("T1049"), network=_internal_recon_net()),
            Step("Discovery — Local Account enumeration (net user).", _wa("T1087.001")),
            Step("OS Credential Dumping — LSASS MiniDump via comsvcs.dll (native "
                 "rundll32); the dump file is cleaned up after.",
                 _wa("T1003.001", "2"), cleanup=True),
            Step("Unsecured Credentials — search local files for passwords with findstr.",
                 _wa("T1552.001", "4")),
            Step("Lateral Movement — endpoint process discovery paired with synthetic "
                 "SMB-to-new-host, an RDP pivot, and a rare SMB file transfer from the "
                 "same box and user.",
                 _wa("T1057"), network=_internal_lateral_net(), post_delay=2.0),
        ],
    )


def get_persistence_story() -> Story:
    """A persistence + defense-evasion arc that isolates the footholds/anti-forensics
    detections: a Run key and a scheduled task (both cleaned up), an indicator-removal
    file deletion, then a C2 beacon to the persistence callback domain so the two
    footholds read as 'installed, now phoning home' rather than isolated artifacts."""
    c2_domain = "update-check-svc.net"     # single source of truth for the beacon step
    return Story(
        id="xdr_persistence",
        name="XDR Persistence & Evasion: Run key → scheduled task → indicator removal → beacon",
        tactics=["Discovery", "Persistence", "Defense Evasion", "Command & Control"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Persistence — Registry Run Key (HKCU ...\\Run); cleaned up after.",
                 _wa("T1547.001"), cleanup=True),
            Step("Persistence — Scheduled Task (schtasks); cleaned up after.",
                 _wa("T1053.005"), cleanup=True),
            Step("Defense Evasion — Indicator Removal: delete a file from disk (prereq "
                 "stages the target file first so the deletion is self-contained).",
                 _wa("T1070.004", "6"), prereqs=True),
            Step("Command & Control — recon paired with a synthetic DNS + web C2 beacon "
                 "and perimeter-firewall egress to the persistence callback domain.",
                 _wa("T1082"),
                 params={"domain": c2_domain, "protocol": "https", "port": 443},
                 network=[
                     NetworkEvent("Infoblox NIOS", "C2_BEACON", context={"domain": c2_domain}),
                     NetworkEvent("Zscaler Web Gateway", "web_c2_beacon",
                                  context={"domain": c2_domain}, external=True),
                     *_fw_egress(c2_domain),
                 ],
                 post_delay=2.0),
        ],
    )


def get_fullchain_story() -> Story:
    """The maximal single-incident arc: the reference recon sweep + C2, then the
    intrusion's ingress → LSASS dump → creds-in-files → evasion → staging → exfil, and
    finally two persistence footholds — all pinned to one identity so XSIAM reads the
    whole thing as one long incident spanning seven tactics. The richest run; slower
    and highest-footprint, so use the shorter stories for quick iterations."""
    c2_domain    = "telemetry-sync-cdn.net"
    exfil_domain = "backup-store-sync.net"
    return Story(
        id="xdr_fullchain",
        name="XDR Extended Kill-Chain: recon → C2 → ingress → LSASS → creds → evasion → "
             "staging → exfil → persistence x2",
        tactics=["Discovery", "Command & Control", "Credential Access", "Defense Evasion",
                 "Collection", "Exfiltration", "Persistence"],
        anchor_dhcp=True, anchor_logon=True,
        steps=[
            # ── Discovery sweep ──────────────────────────────────────────────────
            Step("Discovery — System Information (systeminfo / reg).", _wa("T1082")),
            Step("Discovery — System Network Configuration (ipconfig / arp / route).", _wa("T1016")),
            Step("Discovery — System Owner/User (whoami).", _wa("T1033")),
            Step("Discovery — Process Discovery (tasklist).", _wa("T1057")),
            Step("Discovery — Security Software Discovery (find AV/EDR).", _wa("T1518.001")),
            # ── Command & Control ────────────────────────────────────────────────
            Step("Command & Control — recon paired with a synthetic DNS beacon, DNS "
                 "tunnel, web C2 and perimeter egress to the same domain.",
                 _wa("T1082"),
                 params={"domain": c2_domain, "protocol": "https", "port": 443},
                 network=[
                     NetworkEvent("Infoblox NIOS", "C2_BEACON", context={"domain": c2_domain}),
                     NetworkEvent("Infoblox NIOS", "DNS_TUNNEL"),
                     NetworkEvent("Zscaler Web Gateway", "web_c2_beacon",
                                  context={"domain": c2_domain}, external=True),
                     *_fw_egress(c2_domain),
                 ]),
            # ── Ingress Tool Transfer ────────────────────────────────────────────
            Step("Ingress Tool Transfer — a LOLBin download via MpCmdRun.exe, paired "
                 "with a synthetic large web download from the same host.",
                 _wa("T1105", "13"),
                 network=[NetworkEvent("Zscaler Web Gateway", "large_download", external=True)]),
            # ── Credential Access ────────────────────────────────────────────────
            Step("OS Credential Dumping — LSASS MiniDump via comsvcs.dll; cleaned up after.",
                 _wa("T1003.001", "2"), cleanup=True),
            Step("Unsecured Credentials — search local files for passwords with findstr.",
                 _wa("T1552.001", "4")),
            # ── Defense Evasion ──────────────────────────────────────────────────
            Step("Defense Evasion — Indicator Removal: delete a file from disk (prereq "
                 "stages the target first).", _wa("T1070.004", "6"), prereqs=True),
            # ── Collection / staging ─────────────────────────────────────────────
            Step("Data Staged — archive collected data into a zip in temp; cleaned up after.",
                 _wa("T1074.001", "3"), cleanup=True),
            # ── Exfiltration ─────────────────────────────────────────────────────
            Step("Exfiltration Over Alternative Protocol — endpoint POSTs over HTTP to "
                 "the exfil domain, paired with a synthetic web upload, DNS tunnel, "
                 "reverse SSH tunnel and perimeter egress from the same host/user.",
                 _wa("T1048.003", "4"),
                 params={"domain": exfil_domain, "protocol": "https", "port": 443,
                         "input_args": {"input_file": r"C:\Windows\win.ini",
                                        "ip_address": f"http://{exfil_domain}/upload"}},
                 network=[
                     NetworkEvent("Zscaler Web Gateway", "data_exfil",
                                  context={"domain": exfil_domain}, external=True),
                     NetworkEvent("Infoblox NIOS", "DNS_TUNNEL"),
                     NetworkEvent("Zscaler Web Gateway", "reverse_ssh_tunnel", external=True),
                     *_fw_egress(exfil_domain),
                 ],
                 post_delay=2.0),
            # ── Persistence x2 ───────────────────────────────────────────────────
            Step("Persistence — Registry Run Key (HKCU ...\\Run); cleaned up after.",
                 _wa("T1547.001"), cleanup=True),
            Step("Persistence — Scheduled Task (schtasks); cleaned up after.",
                 _wa("T1053.005"), cleanup=True),
        ],
    )


# ── Data-driven stories (YAML) ─────────────────────────────────────────────────
# Tier-2 #4: author stories as YAML under modules/xdr_orchestration/stories/ without
# touching Python. The built-in Python builders above are the validated canon; YAML
# files ADD new stories (or override a built-in of the same id). YAML is optional —
# if PyYAML isn't installed, the loader logs once and returns nothing.

STORY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stories")


def story_from_dict(d: dict) -> Story:
    """Build a Story (with Steps + NetworkEvents) from a plain dict — the shape a
    YAML file deserializes to. Unknown keys are ignored; sensible defaults fill the
    rest, so a minimal story file is just id/name/steps."""
    steps = []
    for sd in (d.get("steps") or []):
        tech = sd.get("technique") or {}
        if isinstance(tech, str):                     # allow `technique: T1033` shorthand
            tech = {"id": tech, "test_numbers": "1", "executor": "winrm_atomic"}
        tech.setdefault("executor", "winrm_atomic")
        tech.setdefault("test_numbers", "1")
        nets = []
        for ne in (sd.get("network") or []):
            nets.append(NetworkEvent(
                module=ne["module"], event=ne["event"],
                context=dict(ne.get("context") or {}), external=bool(ne.get("external", False))))
        steps.append(Step(
            narrative=sd.get("narrative", ""),
            technique=tech,
            params=dict(sd.get("params") or {}),
            network=nets,
            expected_alerts=list(sd.get("expected_alerts") or []),
            mitre=dict(sd.get("mitre") or {}),
            prereqs=bool(sd.get("prereqs", False)),
            cleanup=bool(sd.get("cleanup", False)),
            pre_delay=float(sd.get("pre_delay", 0.0)),
            post_delay=float(sd.get("post_delay", 2.0)),
        ))
    return Story(
        id=d["id"], name=d.get("name", d["id"]),
        steps=steps,
        tactics=list(d.get("tactics") or []),
        anchor_dhcp=bool(d.get("anchor_dhcp", True)),
        anchor_logon=bool(d.get("anchor_logon", True)),
    )


def load_yaml_stories(story_dir: str = STORY_DIR, *, verbose: bool = False) -> dict:
    """Return {id: builder} for every *.yaml/*.yml in `story_dir`. Each builder is a
    closure that rebuilds a fresh Story from the parsed dict on every call (so a run
    can mutate its own copy). Best-effort: a bad file is skipped with a note, never
    raised; a missing dir or missing PyYAML returns {}."""
    if not os.path.isdir(story_dir):
        return {}
    try:
        import yaml
    except Exception as e:
        print(f"[XDR] YAML stories skipped — PyYAML not installed ({e}); "
              "`pip install pyyaml` to author stories as files.")
        return {}
    builders = {}
    for fn in sorted(os.listdir(story_dir)):
        if not fn.lower().endswith((".yaml", ".yml")):
            continue
        path = os.path.join(story_dir, fn)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            if not data.get("id"):
                print(f"[XDR] YAML story {fn} skipped — no 'id'.")
                continue
            built = story_from_dict(data)              # validate it builds now
            # ...and that it names real modules/events (validate.py). Errors keep the
            # file out of the registry so it can never be fired; warnings just print.
            from .validate import validate_story, errors, format_problems
            problems = validate_story(built)
            if errors(problems):
                print(f"[XDR] YAML story {fn} skipped — invalid:\n{format_problems(problems)}")
                continue
            if problems:
                print(f"[XDR] YAML story {fn} loaded with warnings:\n{format_problems(problems)}")
            builders[data["id"]] = (lambda dd: (lambda: story_from_dict(dd)))(data)
            if verbose:
                print(f"[XDR] loaded YAML story {data['id']} from {fn}")
        except Exception as e:
            print(f"[XDR] YAML story {fn} skipped — {e}")
    return builders


# ── Registry ──────────────────────────────────────────────────────────────────

_STORY_BUILDERS = {
    "xdr_quick":       get_quick_story,
    "xdr_recon":       get_recon_story,
    "xdr_reference":   get_reference_story,
    "xdr_intrusion":   get_intrusion_story,
    "xdr_lateral":     get_lateral_story,
    "xdr_persistence": get_persistence_story,
    "xdr_fullchain":   get_fullchain_story,
    "xdr_wildfire":    get_wildfire_story,
    "xdr_shadow_delete": get_shadow_delete_story,
    "xdr_procdump":      get_procdump_story,
    "xdr_squiblydoo":    get_squiblydoo_story,
    "xdr_cradle":        get_cradle_story,
    "xdr_encoded":       get_encoded_story,
    "xdr_tamper":        get_tamper_story,
    "xdr_ransomware":         get_ransomware_story,
    "xdr_cred_theft":         get_cred_theft_story,
    "xdr_evasion":            get_evasion_story,
    "xdr_persistence_sweep":  get_persistence_sweep_story,
    "xdr_privesc":            get_privesc_story,
    "xdr_lolbin":             get_lolbin_story,
}
# YAML stories add to / override the built-ins (user-authored canon lives in files).
_STORY_BUILDERS.update(load_yaml_stories())


def list_stories() -> list:
    """[{id, name, steps, techniques, tactics, expectations, problems}] for the console
    picker. `expectations` counts DETECTIONS (endpoint + derived network), not needles;
    `problems` is validate_story()'s list (warnings only -- errored stories never load)."""
    from .scorecard import collect_expectations   # lazy: scorecard reads module maps
    from .validate import validate_story
    out = []
    for sid, build in _STORY_BUILDERS.items():
        s = _annotate(build())
        out.append({
            "problems": validate_story(s),
            "id": s.id,
            "name": s.name,
            "steps": len(s.steps),
            "techniques": [st.technique["id"] for st in s.steps],
            "tactics": list(s.tactics),
            # with the default vendor set (PAN NGFW only)
            "expectations": len(collect_expectations(s, vendors=list(DEFAULT_NETWORK_VENDORS))),
            "network_vendors": sorted({ne.module for st in s.steps for ne in st.network}),
        })
    return out


def mitre_coverage() -> dict:
    """ATT&CK coverage map across all registered stories (Tier-1 #2): which tactics
    and techniques the suite exercises, and which stories cover each technique.
    Feeds a coverage heatmap in the console / an at-a-glance 'what do we cover?'."""
    tactics = {}            # tactic -> {technique_id -> {"technique","stories":[...]}}
    for sid, build in _STORY_BUILDERS.items():
        s = _annotate(build())
        for st in s.steps:
            m = st.mitre or {}
            tac = m.get("tactic") or "Unmapped"
            tid = m.get("technique_id") or (st.technique or {}).get("id")
            bucket = tactics.setdefault(tac, {})
            row = bucket.setdefault(tid, {"technique": m.get("technique"), "stories": []})
            if s.id not in row["stories"]:
                row["stories"].append(s.id)
    # Flatten to a stable, display-friendly structure.
    out = []
    for tac in sorted(tactics):
        techs = [{"technique_id": tid, "technique": v["technique"], "stories": v["stories"]}
                 for tid, v in sorted(tactics[tac].items(), key=lambda kv: kv[0] or "")]
        out.append({"tactic": tac, "techniques": techs})
    totals = {"tactics": len(tactics),
              "techniques": len({tid for b in tactics.values() for tid in b})}
    return {"totals": totals, "by_tactic": out}


def override_domain(story: Story, new_domain: str) -> Story:
    """Per-run option: rewrite a story's C2/exfil domain in place. Replaces each step
    param `domain`, the same domain where it is embedded in that step's input_args (so
    the REAL endpoint technique hits the overridden host too), and any NetworkEvent
    context `domain`. Returns the same (freshly built) Story for chaining. No-op when
    `new_domain` is falsy or the story declares no domain."""
    if not new_domain:
        return story
    for step in story.steps:
        old = step.params.get("domain")
        if old:
            step.params["domain"] = new_domain
        ia = step.params.get("input_args")
        if isinstance(ia, dict) and old:
            for k, v in list(ia.items()):
                if isinstance(v, str) and old in v:
                    ia[k] = v.replace(old, new_domain)
        for ne in step.network:
            if ne.context.get("domain"):
                ne.context = {**ne.context, "domain": new_domain}
    return story


def story_domains(story: Story) -> list:
    """Every distinct C2/exfil domain the story uses (step params + network contexts)."""
    out = []
    for step in story.steps:
        for d in [step.params.get("domain")] + [ne.context.get("domain") for ne in step.network]:
            if d and d not in out:
                out.append(d)
    return out


def fresh_domain(domain: str, token: str) -> str:
    """'update-check-svc.net' + 'k3f9' -> 'update-check-svc-k3f9.net'."""
    name, dot, tld = domain.rpartition(".")
    return f"{name}-{token}.{tld}" if dot else f"{domain}-{token}"


def freshen_domains(story: Story, token: str) -> dict:
    """Per-run option (default ON): give every story domain a run-unique tag, in place.

    Why: the shipped C2 correlation rules suppress repeats for 1 hour keyed on
    source IP + domain, and every run fires from the same box IP. Two runs of a
    story within the hour (2026-11-18: persistence at 18:42 and 19:15) left Check
    Point, Fortinet and Infoblox silent on the second -- suppressed, not missed. A
    fresh domain per run keeps each run independently detectable. Distinct domains
    stay distinct (each gets the same tag). Rewrites step params, input_args
    strings (so the real technique hits the same host) and network contexts.
    Returns {old: new}."""
    mapping = {d: fresh_domain(d, token) for d in story_domains(story)}
    for step in story.steps:
        d = step.params.get("domain")
        if d in mapping:
            step.params["domain"] = mapping[d]
        for holder in (step.params.get("input_args"), (step.technique or {}).get("input_args")):
            if isinstance(holder, dict):
                for k, v in list(holder.items()):
                    if isinstance(v, str):
                        for old, new in mapping.items():
                            v = v.replace(old, new)
                        holder[k] = v
        for ne in step.network:
            if ne.context.get("domain") in mapping:
                ne.context = {**ne.context, "domain": mapping[ne.context["domain"]]}
    return mapping


def all_technique_ids() -> list:
    """Every distinct ATOMIC technique id across all stories — used by the Kickstarter
    to install exactly the prereqs any story might need. Builtin payload steps
    (payloads.py) are skipped: they need no Atomic prereqs, and asking Atomic for
    their technique's prereqs would stage unrelated test files."""
    ids = []
    for build in _STORY_BUILDERS.values():
        for st in build().steps:
            if (st.technique or {}).get("executor") == "builtin":
                continue
            if st.technique["id"] not in ids:
                ids.append(st.technique["id"])
    return ids


def all_atomic_tests() -> list:
    """Every distinct Atomic (technique id, test numbers) the stories actually fire:
    [{"id": "T1105", "test_numbers": "13"}, ...], one row per technique with its test
    numbers unioned across stories. The Kickstarter resolves prereqs with these EXACT
    test numbers (`-GetPrereqs -TestNumbers ...`) instead of per-technique, so Atomic
    only stages what the pinned tests need -- it never tries to satisfy unrelated
    tests' prereqs (e.g. cloud tests that pull the retired AzureAD module and then
    report 'failed to meet prerequisites'). Builtin steps are skipped."""
    by_id = {}            # id -> list of test-number tokens, in first-seen order
    for build in _STORY_BUILDERS.values():
        for st in build().steps:
            t = st.technique or {}
            if t.get("executor") == "builtin":
                continue
            tid = t.get("id")
            if not tid:
                continue
            seen = by_id.setdefault(tid, [])
            for tok in str(t.get("test_numbers") or "1").split(","):
                tok = tok.strip()
                if tok and tok not in seen:
                    seen.append(tok)
    return [{"id": tid, "test_numbers": ",".join(toks)} for tid, toks in by_id.items()]


def all_builtin_payloads() -> list:
    """Every distinct builtin payload name across all stories (the counterpart to
    all_technique_ids, which SKIPS builtin steps). The Kickstarter stages whatever
    tooling these need (e.g. ProcDump for procdump_lsass) so the builtin stages work
    without a runtime download."""
    out = []
    for build in _STORY_BUILDERS.values():
        for st in build().steps:
            t = st.technique or {}
            if t.get("executor") == "builtin" and t.get("payload") and t["payload"] not in out:
                out.append(t["payload"])
    return out


def get_story(story_id: str) -> Optional[Story]:
    """Resolve a story by id (defaults handled by the caller). Annotated so every
    step carries its ATT&CK mapping + detection expectations."""
    build = _STORY_BUILDERS.get(story_id)
    return _annotate(build()) if build else None
