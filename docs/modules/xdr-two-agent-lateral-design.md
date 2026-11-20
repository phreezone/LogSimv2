# XDR Two-Agent Lateral Movement — Design Note

**Type:** Design note (proposal) — nothing here is built yet
**Status:** Not implemented. Captures what a real A→B pivot between two Cortex-agent boxes would require, before any code starts assuming more than one box.
**Scope:** Extends [XDR Attack Orchestration](xdr-orchestration.md). Read that first; this note only covers the delta.

---

## The gap

Every XDR story today is keyed to **one** box. A story runs its real Atomic techniques on a single target (`XDR_TARGET_*` in `.env`), and LogSim emits synthetic network logs pinned to that one box's real host/user/IP.

`xdr_lateral` (`get_lateral_story`, `modules/xdr_orchestration/stories.py`) *looks* like lateral movement — "recon → LSASS dump → creds-in-files → SMB/RDP pivot" — but it is single-box theater: a real technique fires on box A, then `_internal_lateral_net()` emits synthetic internal traffic (`smb_new_host_lateral`, `rdp_lateral`, `smb_rare_file_transfer`) that *claims* a reach to some other host the generator invents. There is no second box, no second Cortex agent, and the "other host" is never a real, named, agent-covered endpoint.

A genuine lateral-movement test is a chain across **two** endpoints with **different** names:

> On **A**: credentials obtained (LSASS) → outbound authenticated connection to **B** → on **B**: successful remote logon + follow-on execution.

Both A and B run the Cortex agent, so XSIAM sees real endpoint telemetry from **two distinct agent IDs** and must stitch them — together with the network half — into one incident.

## Why the current model can't express it

The constraint is the **scalar identity**. The orchestrator discovers one identity (host / IP / user) and auto-injects it as `src_ip` / `hostname` into every `NetworkEvent.context`. The only endpoint knob on a `NetworkEvent` is:

```python
external: bool = False   # True => use the egress/public IP as src_ip; else the box's LAN IP
```

That is a **source-only** model: `external` toggles public-egress vs LAN source. There is **no destination endpoint** anywhere in the data model. An internal lateral flow is inherently `src → dst`, and both ends have to be real and named, so the pivot's logs agree with what two real agents report.

The "systems are named differently" point is the crux: the whole stack currently assumes **one** hostname injected everywhere. Supporting distinct names means every synthetic record and every correlation join becomes endpoint-aware.

---

## What has to change

### 1. Identity: scalar → a typed pair

Today the run carries one identity and the summary records one. Introduce `{source, target}` (or a small ordered inventory), each with its own hostname / IP / user. Every anchor, every injected `src_ip` / `hostname`, and the summary's `identity` become **per-role**, not global.

### 2. Two connections, two preflights, two policy gates

`WorkstationConnection.from_config(CONFIG)` returns **one** connection off one `XDR_TARGET_*` block. A pivot needs a **source** and a **target** connection, each preflighted independently:

- `cyserver` service RUNNING (`_check_cortex_agent`),
- Atomic present,
- agent in **Alert/Report** mode (`policy.py`).

The prevent-mode guard must check **both** boxes. Either box in Prevent terminates its host mid-chain and strands the pivot — so the preflight fails closed unless **both** are confirmed lab-only and in Report/Alert.

### 3. `NetworkEvent` needs a destination endpoint

Add an endpoint-role to the event so the orchestrator resolves each end to one of the two identities, e.g.:

```python
src: str = "source"     # which identity supplies src_ip / hostname
dst: Optional[str] = None  # when set, inject that identity's host/IP as the destination
```

With a destination in hand, the generators emit a **consistent** internal flow:

- PAN NGFW internal-zone `src → dst` traffic,
- the record that actually makes lateral movement detectable: a **Windows 4624 Type 3** (network logon) on the **destination** that names the **source** workstation + IP,
- the SMB/RDP pivot traffic with both real endpoints.

`expectations.py` (which derives each `NetworkEvent`'s expected network detections from its emitting module, keyed on identity) then keys on the **pair**.

### 4. A step that runs on A but targets B

Steps execute on "the connection." A pivot step needs two additions:

- a per-step **runs-on** role (source vs target), and
- the target's address/creds threaded into the step's params.

There is precedent for threading a runtime value into a step's params: the `cradle_url` kwarg flows end-to-end into the cradle builtin's params per run (see `orchestrator.run_story`). This generalizes to **"target identity → pivot-step params."**

The pivot itself must be a **vetted Atomic by pinned test number** (a WinRM / WMI / SMB remote-exec test), not a hand-rolled PsExec wrapper — non-destructive, reversible, with cleanup.

### 5. Sequencing + shared join keys

For XSIAM to stitch two differently-named agents into one incident, the events must be **time-ordered** and share join keys:

- acting **user SID / UPN**,
- **source IP**,
- **destination host / IP**.

So **both** boxes must be anchored up front — `anchor_dhcp` (Infoblox DHCP lease binding IP↔hostname) **and** `anchor_logon` (4624 binding IP↔user) — for **each** host. Neither endpoint can be an unknown entity, and the destination's inbound-logon anchor has to name the source.

### 6. Scorecard across two agent IDs

This is the same seam as the duplicate-agent case: `build_scorecard` / `get_alerts` pulls alerts for the run and attributes them by host/marker. With two endpoints it must gather from **both** agent IDs and attribute to the one run (the known marker-attribution gotcha). The run "identity" becomes a **set**, and expected endpoint alerts split:

- **on source** — credential dump / collection,
- **on target** — remote-exec / service install / the 4624 logon cluster.

### 7. Config / inventory

`.env` currently has a single `XDR_TARGET_*` block. Express ≥2 boxes — either role-suffixed blocks (`XDR_SOURCE_*` / `XDR_TARGET_*`) or a hosts list with roles. The console preflight tile and the "Synthetic logs will carry…" line become **per-box**.

---

## Safety gates (hard requirements)

Real cross-host execution on a second box is a genuinely **new offensive capability**, so it inherits all of the module's standing constraints and adds a few:

- Both boxes are **dedicated lab-only** endpoints, both running the Cortex agent in **Report/Alert** mode.
- The pivot technique is a **vetted Atomic by pinned test number** — reversible, non-destructive, cleanup-capable. No new offensive tooling authored.
- WinRM / credentials for B are **scoped to the lab**.
- Preflight **fails closed** if B is not confirmed lab-only or is not in Report mode.

---

## Recommended minimal approach

Do **not** retrofit a second endpoint into the scalar-identity path everywhere — that touches every anchor, every generator injection, and the scorecard at once.

Instead, add lateral as a **distinct two-identity story type**:

- a `{source, target}` inventory resolved from role-suffixed `.env` blocks,
- endpoint-roled `NetworkEvent`s (`src` / `dst`) used only by this story type,
- one **vetted remote-exec Atomic** on the source, target threaded in via the existing step-param path,
- both hosts anchored (DHCP + 4624) so both are known entities.

Single-host stories stay exactly as they are; the pair-aware path is opt-in and lives beside them.

## Open questions

- **Inventory shape** — role-suffixed `.env` blocks vs a JSON hosts list. Role-suffixed keeps parity with the current `.env`-only deployment model.
- **Credential provenance for the pivot** — synthetic/pre-seeded lab creds vs creds "found" on A. Pre-seeded is simpler and keeps the step non-destructive; "found on A" is more realistic but couples step outputs to the pivot params.
- **Which remote-exec Atomic** — pin the specific test number(s) once a vetted, reversible one is chosen (WinRM vs WMI vs SMB).
- **Scorecard attribution** — confirm `get_alerts` can be filtered/attributed per agent ID cleanly, or whether the marker scheme needs a per-endpoint marker.
