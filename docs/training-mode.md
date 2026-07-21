## Training Mode — Deterministic Bulk Stage & Live Stream

Training Mode turns LogSim into a repeatable classroom tool. Every other mode generates
**realistic but random** logs, so users, IPs, hostnames, and attack steps change every run —
you can't build a class around them. Training Mode produces the **same seeded story every
time**, and lets you deliver it two ways: staged as history in the morning, then streamed live
in the afternoon.

It is offered **only in the Flask dashboard** (Threats & Scenarios tab → *Training Mode* panel).
There is no CLI training mode.

### The classroom flow

| Phase | Action | What it does |
|---|---|---|
| **Morning** | **Bulk stage (backfill 4h)** | Emits ~4 hours of a simulated environment as **history** (now−4h → now), in seconds. Students explore a populated tenant and build correlation rules against stable, known datapoints. Because their rules don't exist yet, nothing alerts — it's raw data to learn from. |
| **Afternoon** | **Stream now (4h live)** | Replays the **identical** seeded story **live** over ~4 hours. The rules the students built now fire in real time — the analyst experience of watching cases and alerts appear. |

The morning and afternoon runs emit the **same events, in the same order, over the same
transport per log** — only the timestamps differ (backfilled vs live). This is the core
*alignment* guarantee.

### What is guaranteed (and what isn't)

**Reproducible (identical across every run of a pack):** the users, IPs, hostnames, GUIDs,
event types, event counts, ordering, and the transport each log is sent over. A course guide
may reference any of these datapoints and rely on them being there next week, next class.

**Intentionally *not* reproducible:** the event **timestamps**. Bulk backfills them into
`now−4h → now`; Stream stamps them live. This is a feature, not a side effect — XSIAM query
views default to **"Last 24 hours,"** so a pack re-run before class always lands inside the
default window with no time-picker edits and no expiring absolute date ranges in the courseware.

> **Author guidance:** reference **content, never absolute dates**. "Build a rule for the
> DCSync from user X on DC01" is stable; "the DCSync at 09:14 on March 24" is not.

### How it works (under the hood)

- **Content determinism** comes from seeding. The engine (`modules/training_engine.py`) seeds
  the global `random`, monkeypatches `uuid.uuid4` to a seeded generator, pins the Tor exit-node
  list to a stable list, and resets per-module and per-user caches — so the same seed yields the
  same content. Transport is chosen from `config.json` per module (never from RNG), so it is
  inherently identical between runs.
- **A fixed, mode-independent action schedule** is built once under the seed, before any
  timing. Bulk and Stream iterate the *same* list, so the RNG is consumed in the same order ⇒
  identical content. Timing only decides *when* an event is stamped, never *what* is generated.
- **Timestamps via clock control.** Modules stamp their own events inline (`datetime.now()`
  etc.) at 200+ sites, so there's no per-call injection point. Instead **Bulk** freezes the
  clock (via `freezegun`) and moves it to `window_start + offset` before each event, so the
  module bakes in the backfilled time itself; **Stream** leaves the clock real. Scenario
  functions pace their steps with `time.sleep()`; in Bulk those sleeps advance the frozen clock
  (so the run finishes in seconds and intra-scenario sequencing is preserved); in Stream they
  really sleep for live pacing.

### Authoring packs

Packs live in `config.json` under `training_config.packs`. Each pack:

```json
{
  "id": "domain-dominance-day",
  "description": "Domain Dominance kill chain staged over a 4-hour day.",
  "seed": "domain-dominance-day",
  "duration_seconds": 14400,
  "benign_events_per_second_per_module": 10,
  "benign_threat_level": "High",
  "benign_modules": ["Okta SSO", "Apache httpd", "Zscaler Web Gateway", "Infoblox NIOS"],
  "scenario": { "id": "18", "start_offset_seconds": 5400 },
  "threats": [
    { "module": "Okta SSO", "name": "mfa_fatigue", "count": 1, "offset_seconds": 3600 }
  ]
}
```

| Field | Meaning |
|---|---|
| `seed` | Friendly name (hashed) or int. **Fixed** so morning and afternoon align. |
| `duration_seconds` | Length of the day timeline (default `14400` = 4h). |
| `benign_events_per_second_per_module` | Baseline volume: each benign module emits this many events/sec, spread evenly over the window. `10` × N modules = 10·N events/sec total. |
| `benign_interval_seconds` | *Legacy fallback* used only if the rate above is absent: one benign event every N seconds, round-robined. |
| `benign_threat_level` | Realism tier for the baseline: `"Benign Traffic Only"` (clean) up through `"Realistic"`, `"Elevated"`, `"High"`, `"Extreme"`. Anything above benign mixes occasional threats into the baseline (per each module's event_mix + cooldown), so a few alertable events land in the console. Avoid `"Insane"` (constant threats). |
| `benign_modules` | Modules used for baseline noise (defaults to all). Names are module `NAME`s. |
| `scenario` | `id` from the [attack scenarios](attack-scenarios.md) list + `start_offset_seconds`. |
| `threats` | Optional injected threats: `module`, `name`, `count`, `offset_seconds`. |

> **Volume & speed.** At `2` events/sec/module over 4 hours, a 4-module pack generates ~115k
> events (~0.1 GB); at `10`/sec/module, ~740k (~0.5 GB). *Bulk* runs in two phases — generation
> under a frozen clock (~1,400 events/sec) then **concurrent sending over pooled keep-alive
> connections** — so a full pack lands in a few minutes, not the hours that per-event HTTP
> handshakes used to cost. `bulk_send_workers` (default 16) tunes send concurrency. *Stream*
> paces out live. Turn `benign_events_per_second_per_module` down if the volume is more than
> your tenant needs.

### Using it

1. Dashboard → **Threats & Scenarios** tab → **Training Mode** panel.
2. Pick a pack.
3. **Bulk stage (backfill 4h)** — stages the history. Watch progress in the panel.
4. **Stream now (4h live)** — streams the same story live. If no Bulk stage ran for that pack
   today, the UI shows a **soft warning** (you can proceed anyway). **Stop** ends a stream early.

Runs are **exclusive**: only one training run at a time, and manual module generation is
disabled while a run is active (the engine seeds the global RNG and, for Bulk, freezes the
clock — a concurrent generator would corrupt both).

### Caveats

- **Long-lived process is fine.** The dashboard resets per-module counters (`reset_state()`)
  and caches before each run, so running Bulk and Stream in the same all-day dashboard process
  still reproduces identical content.
- **Incidental embedded timestamps** a module derives from "now" (e.g. an AWS resource's
  `creationDate = now − random days`) shift by the morning↔afternoon wall-clock gap. Identity,
  sequence, and transport stay aligned; only such derived dates move.
- **XSIAM source-IP suppression.** The same attacker IPs appear in both Bulk and Stream; a
  1h–24h alert-suppression window could dedupe if you run the same pack twice inside that
  window. Once-per-day per pack is the intended cadence — add a suffix to the pack `seed` for a
  fresh IP set within the window.

### Design note — regeneration vs. playback (future option)

Today Bulk and Stream **regenerate** the events from the same seed and are proven identical by
the parity test — the *pivots* (user, IP, host, action, event-type, order, transport) are
byte-identical; only timestamps and a few incidental *now-derived* fields (e.g. a resource's
`creationDate = now − N days`) differ between the morning and afternoon runs.

A stronger **capture-once → replay** model was evaluated and **deferred**: generate the dataset
once, store it, and replay both Bulk and Stream from those exact bytes with only the timestamps
shifted. That would make *every* field byte-identical across morning/afternoon and be immune to
future module nondeterminism and LogSim upgrades, at the cost of a timestamp-shift layer (rewrite
every timestamp format by a constant Δ, preserving precision/timezone/epoch-unit) and ~0.5 GB of
stored dataset per pack per run. It reuses the existing capture hook (`log_simulator._capture_sink`)
and the timestamp locators in `_strip_volatile`, so it is an **extension, not a rewrite** — revisit
it if incidental-field drift or upgrade-stability ever matters in practice.

### Verifying determinism

`python tests/training_determinism.py` proves, with no XSIAM tenant or network:

- **Determinism** — two runs of a pack produce byte-identical content (timestamps stripped).
- **Bulk↔Stream parity** — Bulk and Stream produce the same content, order, and transport.
- **Backfill bounds** — a Bulk run stamps baseline events inside `[now−4h, now]`.
