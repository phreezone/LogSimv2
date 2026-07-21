# modules/training_engine.py
#
# Deterministic "Training Mode" engine for LogSimV2 — Web-UI only.
#
# NOTE: this module intentionally does NOT define NAME, so log_simulator.load_modules
# and dashboard._load_modules skip it (it is a helper, not a log source).
#
# ── The classroom flow this supports ──────────────────────────────────────────
#   Morning  (BULK)   : stage ~4 hours of a simulated environment as *history*
#                       (now-4h .. now) so students explore a populated tenant and
#                       build correlation rules against stable, known datapoints.
#   Afternoon (STREAM): play the *same seeded story* live over ~4 hours so the rules
#                       the students built fire in real time (the analyst experience).
#
# ── The alignment guarantee ───────────────────────────────────────────────────
# Bulk and Stream must emit the SAME events, in the SAME order, via the SAME
# transport — only timestamps differ (backfilled vs live). We guarantee this by:
#
#   1. Seeding (deterministic_env): global `random` is seeded, `uuid.uuid4` is
#      monkeypatched to a seeded generator, the Tor list is pinned to a stable list,
#      and session_utils per-user caches are cleared. Same seed => same content.
#      Transport is chosen from config per module (never from RNG), so it is
#      inherently identical between runs.
#
#   2. A FIXED, mode-independent action schedule (_build_actions): the ordered list
#      of generate() calls is computed ONCE under the seed, BEFORE any mode-specific
#      timing. Both modes iterate the identical list, so the RNG is consumed in the
#      identical order => identical content. Timing (the clock) only decides WHEN an
#      event is stamped, never WHAT is generated or in WHICH order.
#
#   3. Clock control instead of module surgery: modules stamp their own events by
#      calling datetime.now()/utcnow()/time.time() inline at 200+ sites, so we cannot
#      inject a timestamp per call. Instead BULK freezes the clock (freezegun) and
#      moves it to window_start+offset before each event, so the module bakes in the
#      backfilled time itself. STREAM leaves the clock real. Scenario functions pace
#      their internal steps with time.sleep(); in BULK those sleeps are scoped-patched
#      to advance the frozen clock (so intra-scenario sequencing is preserved and the
#      run finishes in seconds); in STREAM they really sleep for live pacing.

import copy
import datetime
import hashlib
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

# 4-hour day, one benign baseline event every 5 simulated seconds by default.
DEFAULT_DURATION_SECONDS = 4 * 60 * 60      # 14400
DEFAULT_BENIGN_INTERVAL = 5.0
# Bulk sends the whole backfilled day at once; parallelize the network I/O (esp. HTTP)
# so a run finishes in minutes, not hours. Generation stays serial for determinism —
# only the send/transport is offloaded, and bulk timestamps are already baked into each
# payload so send order is irrelevant.
BULK_SEND_WORKERS = 16
# Stream is paced live (low rate), so throughput isn't the goal — but offloading each send
# keeps a slow/laggy collector from stalling the pacing loop and drifting the schedule.
STREAM_SEND_WORKERS = 8
_UTC = datetime.timezone.utc


class _ParallelSender:
    """Sends already-generated payloads (module, payload, event_name) concurrently via a
    thread pool, with backpressure so the queue can't run away on a 100k-event run. Used
    only OUTSIDE the frozen-clock window (freezegun serializes while active)."""

    def __init__(self, ls, config, workers):
        self._ls = ls
        self._config = config
        self._pool = ThreadPoolExecutor(max_workers=workers)
        self._sem = threading.BoundedSemaphore(workers * 8)

    def send(self, module, payload, event_name):
        self._sem.acquire()
        try:
            fut = self._pool.submit(self._ls.process_and_send, payload, module,
                                    self._config, event_name)
        except Exception:
            self._sem.release()
            raise
        fut.add_done_callback(lambda _f: self._sem.release())
        return fut

    def dispatch_result(self, result, module):
        """Offload a whole generate_log() result (may be a list, needs unpacking) to the
        pool — used by stream mode so send latency doesn't block the pacing loop."""
        self._sem.acquire()
        try:
            fut = self._pool.submit(self._ls._dispatch_result, result, module, self._config)
        except Exception:
            self._sem.release()
            raise
        fut.add_done_callback(lambda _f: self._sem.release())
        return fut

    def close(self):
        self._pool.shutdown(wait=True)


# ── Seed helpers ──────────────────────────────────────────────────────────────

def stable_seed(value):
    """Resolve a pack seed to a stable int.

    Ints pass through; friendly string names are hashed (SHA-256) so a pack can be
    seeded by name and still land the same content every day, on any machine.
    """
    if isinstance(value, int):
        return value
    if value is None:
        value = "logsim-training"
    digest = hashlib.sha256(str(value).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


@contextmanager
def deterministic_env(seed, config):
    """Make all *content* randomness reproducible for the duration of a run.

    Seeds global `random`, monkeypatches `uuid.uuid4` to a seeded generator, pins
    the Tor exit-node list to a stable list, and clears session_utils per-user
    caches. Everything is restored on exit so normal (non-training) generation is
    unaffected afterwards.
    """
    seed = stable_seed(seed)

    # 1) global random
    rng_state = random.getstate()
    random.seed(seed)

    # 2) uuid.uuid4 -> seeded, independent stream (its own generator so uuid draws
    #    don't perturb the content RNG; still reproducible because generation is
    #    deterministic, so the uuids are requested in the same order every run).
    uuid_rng = random.Random(seed ^ 0x5DEECE66D)
    orig_uuid4 = uuid.uuid4

    def _seeded_uuid4():
        return uuid.UUID(int=uuid_rng.getrandbits(128), version=4)

    uuid.uuid4 = _seeded_uuid4

    # 3) pin Tor list (dashboard/main capture the static config list as
    #    _static_tor_exit_nodes BEFORE the daily live overwrite, so morning and
    #    afternoon runs pick the same anon IPs).
    saved_tor = config.get("tor_exit_nodes")
    static_tor = config.get("_static_tor_exit_nodes")
    if static_tor is not None:
        config["tor_exit_nodes"] = copy.deepcopy(static_tor)

    # 4) hermetic per-user caches
    try:
        from modules import session_utils
        session_utils.reset_caches()
    except Exception:
        session_utils = None

    try:
        yield
    finally:
        random.setstate(rng_state)
        uuid.uuid4 = orig_uuid4
        if saved_tor is not None:
            config["tor_exit_nodes"] = saved_tor
        elif "tor_exit_nodes" in config and static_tor is not None:
            config.pop("tor_exit_nodes", None)
        if session_utils is not None:
            session_utils.reset_caches()


def reset_module_state(all_modules):
    """Reset per-module mutable state before a seeded run so a long-lived process
    reproduces identical content each time.

    Calls each module's own reset_state() if it defines one; otherwise falls back to
    zeroing the near-ubiquitous `last_threat_event_time` cooldown. Does not consume the
    RNG, so it is safe to call after seeding without perturbing the content stream.
    """
    for module in all_modules.values():
        fn = getattr(module, "reset_state", None)
        if callable(fn):
            try:
                fn()
                continue
            except Exception:
                pass
        if hasattr(module, "last_threat_event_time"):
            try:
                module.last_threat_event_time = 0
            except Exception:
                pass


# ── Action schedule (mode-independent) ────────────────────────────────────────

def _emit_benign_factory(config, session_context, level, sender=None):
    """Return an ``emit(module)`` that generates one baseline event at *level* and
    dispatches it.

    ``level='Benign Traffic Only'`` (benign_only) yields a clean environment. A higher
    level (e.g. 'High') sets ``benign_only=False`` so each module mixes in occasional
    threat events per its own event_mix + cooldown — making the staged environment look
    realistic and landing a few alertable events in the console. One shared closure is
    reused for every benign event (there can be hundreds of thousands), so the schedule
    stays lightweight at high rates.

    Generation always runs serially in the caller (preserving RNG determinism). If a
    *sender* is given (stream mode) the send is offloaded to its pool so pacing isn't
    blocked; otherwise (bulk) the dispatch runs inline and is captured by _bulk_collector."""
    import log_simulator as ls
    benign_only = (level == "Benign Traffic Only")
    ctx = {"session_context": session_context}

    def emit(module):
        result = module.generate_log(config=config, threat_level=level,
                                     benign_only=benign_only, context=ctx)
        if sender is not None:
            sender.dispatch_result(result, module)
        else:
            ls._dispatch_result(result, module, config)

    return emit


def _make_scenario_action(func, all_modules, config, ls):
    def _act():
        func(all_modules, config)

    return _act


def _make_threat_action(module, threat_name, config, session_context, ls):
    def _act():
        ls.run_specific_threat(module, threat_name, config, session_context, False)

    return _act


def _resolve_benign_modules(pack, all_modules):
    names = pack.get("benign_modules")
    if names:
        return [all_modules[n] for n in names if n in all_modules]
    return [m for m in all_modules.values() if hasattr(m, "generate_log")]


def _build_actions(pack, all_modules, config, session_context, duration):
    """Build the ordered, mode-independent schedule as (offset_seconds, kind, ref).

    ``kind='benign'`` -> ref is the module object (dispatched via the shared emit
    closure); ``kind='scenario'/'threat'`` -> ref is a zero-arg callable. Offsets are
    fixed so the sequence is identical for bulk and stream, and no RNG is drawn here —
    the RNG is spent only when the actions execute, in this exact order.

    Benign volume is set by ``benign_events_per_second_per_module`` (each module emits
    that many events per second, spread evenly across the window). If absent, falls back
    to the legacy ``benign_interval_seconds`` round-robin (one event per interval).
    """
    import log_simulator as ls

    entries = []  # (offset, priority, kind, ref); priority<benign so injects win ties
    benign_modules = _resolve_benign_modules(pack, all_modules)

    rate = pack.get("benign_events_per_second_per_module")
    interval = pack.get("benign_interval_seconds")
    if benign_modules and rate:
        rate = float(rate)
        step = 1.0 / rate
        count = int(duration * rate)
        for module in benign_modules:
            for i in range(count):
                entries.append((i * step, 0, "benign", module))
    elif benign_modules and interval:
        interval = float(interval)
        count = int(duration // interval)
        for i in range(count):
            entries.append((i * interval, 0, "benign", benign_modules[i % len(benign_modules)]))

    sc = pack.get("scenario")
    if sc:
        scen = ls.get_scenarios().get(str(sc.get("id")))
        if scen:
            start = float(sc.get("start_offset_seconds", duration * 0.5))
            entries.append((start, -1, "scenario",
                            _make_scenario_action(scen["func"], all_modules, config, ls)))

    for t in pack.get("threats", []):
        module = all_modules.get(t.get("module"))
        if not module:
            continue
        name = t.get("name")
        offset = float(t.get("offset_seconds", 0))
        for k in range(int(t.get("count", 1))):
            entries.append((offset + k, -1, "threat",
                            _make_threat_action(module, name, config, session_context, ls)))

    entries.sort(key=lambda e: (e[0], e[1]))
    return [(off, kind, ref) for (off, _prio, kind, ref) in entries]


# ── Batch flush ───────────────────────────────────────────────────────────────

def _flush(config, ls):
    try:
        ls.flush_s3_batch()
    except Exception:
        pass
    try:
        ls._flush_wec_batch(config)
    except Exception:
        pass


# ── BULK: backfill now-4h .. now, virtual clock, finishes in seconds ──────────

def _run_injected_bulk(fn, frozen, base_ts):
    """Run an injected scenario/threat under BULK, scoping a time.sleep patch that
    advances the frozen clock instead of really waiting — so the scenario's internal
    sleeps become backfilled inter-event gaps and sequencing is preserved."""
    state = {"t": base_ts}
    orig_sleep = time.sleep

    def fake_sleep(secs=0):
        try:
            secs = float(secs)
        except (TypeError, ValueError):
            secs = 0.0
        state["t"] += max(0.0, secs)
        frozen.move_to(datetime.datetime.fromtimestamp(state["t"], _UTC))

    time.sleep = fake_sleep
    try:
        fn()
    finally:
        time.sleep = orig_sleep


BULK_CHUNK = 4000  # actions generated per freeze window before the parallel send flush


def _run_bulk(actions, window_start, emit_benign, sender, config, ls, stop_event, report):
    """Two-phase bulk. Per chunk: (1) generate under a frozen clock — serial, so the
    modules bake in backfilled timestamps — collecting payloads instead of sending; then
    (2) leave the freeze and send the chunk's payloads through the parallel pool (freezegun
    serializes calls while active, so sending must happen outside it). Chunking bounds the
    collected-payload memory."""
    from freezegun import freeze_time
    start_dt = datetime.datetime.fromtimestamp(window_start, _UTC)
    total = len(actions)
    prev_collector = ls._bulk_collector
    i = 0
    try:
        while i < total:
            if stop_event is not None and stop_event.is_set():
                break
            chunk = actions[i:i + BULK_CHUNK]
            collected = []
            # Phase 1 — generate under the frozen clock, collect (no send).
            ls._bulk_collector = collected
            with freeze_time(start_dt) as frozen:
                for (offset, kind, ref) in chunk:
                    frozen.move_to(datetime.datetime.fromtimestamp(window_start + offset, _UTC))
                    if kind == "benign":
                        emit_benign(ref)
                    else:  # scenario / threat: internal time.sleep advances the frozen clock
                        _run_injected_bulk(ref, frozen, window_start + offset)
            ls._bulk_collector = prev_collector
            # Phase 2 — send this chunk concurrently, outside the freeze. Drain the chunk
            # before the next chunk's phase 1 re-arms _bulk_collector, so an in-flight send
            # can't be mis-collected instead of sent.
            if sender is not None:
                futures = [sender.send(m, p, e) for (m, p, e) in collected]
                for fut in futures:
                    fut.result()
            else:
                for (module, payload, event_name) in collected:
                    ls.process_and_send(payload, module, config, event_name)
            i += len(chunk)
            report(min(i, total) - 1, "bulk")
        if sender is not None:
            sender.close()
    finally:
        ls._bulk_collector = prev_collector


# ── STREAM: live over ~4 hours, real clock, real pacing ───────────────────────

def _sleep_until(target_ts, stop_event):
    """Interruptible wait until wall-clock target_ts. Returns True if stopped."""
    while True:
        remaining = target_ts - time.time()
        if remaining <= 0:
            return False
        chunk = min(remaining, 1.0)
        if stop_event is not None:
            if stop_event.wait(chunk):
                return True
        else:
            time.sleep(chunk)


def _run_stream(actions, wall_start, emit_benign, config, ls, stop_event, report):
    # Flush batched transports (S3/WEC) periodically so events land continuously
    # instead of all at the end — this is the realtime feed.
    for i, (offset, kind, ref) in enumerate(actions):
        if stop_event is not None and stop_event.is_set():
            break
        if _sleep_until(wall_start + offset, stop_event):
            break
        if kind == "benign":
            emit_benign(ref)
        else:  # scenario/threat use real time.sleep for natural live pacing
            ref()
        if kind != "benign" or (i & 0x7F) == 0:
            report(i, kind)
        if i % 50 == 0:
            _flush(config, ls)


# ── Public entry point ────────────────────────────────────────────────────────

def run_pack(pack, all_modules, config, mode="bulk", stop_event=None, progress=None):
    """Execute a training pack in 'bulk' (backfill) or 'stream' (live) mode.

    Returns a summary dict. Both modes build the same seeded action schedule, so the
    content is aligned; only the clock/pacing differ.
    """
    if mode not in ("bulk", "stream"):
        raise ValueError(f"mode must be 'bulk' or 'stream', got {mode!r}")

    import log_simulator as ls

    seed = pack.get("seed", pack.get("id"))
    duration = float(pack.get("duration_seconds", DEFAULT_DURATION_SECONDS))
    level = pack.get("benign_threat_level", "Benign Traffic Only")

    # Bulk parallelizes sends via a two-phase collector; stream offloads each send so a
    # slow collector can't stall the live pacing loop.
    sender = None
    if mode == "bulk":
        workers = int(pack.get("bulk_send_workers", BULK_SEND_WORKERS))
        if workers > 1:
            sender = _ParallelSender(ls, config, workers)
    else:
        workers = int(pack.get("stream_send_workers", STREAM_SEND_WORKERS))
        if workers > 1:
            sender = _ParallelSender(ls, config, workers)

    with deterministic_env(seed, config):
        reset_module_state(all_modules)
        from modules.session_utils import build_session_context
        session_context = build_session_context(config)
        # Bulk emits inline into _bulk_collector (two-phase send); stream offloads each send.
        emit_benign = _emit_benign_factory(config, session_context, level,
                                           sender if mode == "stream" else None)
        actions = _build_actions(pack, all_modules, config, session_context, duration)
        total = len(actions)

        wall_start = time.time()
        window_start = (wall_start - duration) if mode == "bulk" else wall_start

        def report(i, label):
            if progress is not None:
                try:
                    progress({
                        "mode": mode, "pack": pack.get("id"),
                        "index": i + 1, "total": total,
                        "offset": actions[i][0] if i < total else duration,
                        "duration": duration, "label": label,
                    })
                except Exception:
                    pass

        prev_quiet = ls._quiet_sends
        if mode == "bulk":
            ls._quiet_sends = True  # suppress 100k+ per-event "Sending..." prints
        try:
            if mode == "bulk":
                _run_bulk(actions, window_start, emit_benign, sender, config, ls, stop_event, report)
            else:
                _run_stream(actions, wall_start, emit_benign, config, ls, stop_event, report)
                if sender is not None:
                    sender.close()   # drain offloaded stream sends before the final flush
                    sender = None

            # Drive progress to 100% and mark the finalize phase, so the UI shows the final
            # batched-transport flush/upload (S3 CloudTrail object, WEC batch) rather than
            # stalling just under 100% while _flush runs.
            if progress is not None and not (stop_event is not None and stop_event.is_set()):
                try:
                    progress({"mode": mode, "pack": pack.get("id"), "index": total,
                              "total": total, "offset": duration, "duration": duration,
                              "label": "finalizing"})
                except Exception:
                    pass

            _flush(config, ls)
        finally:
            ls._quiet_sends = prev_quiet
            if sender is not None:
                sender.close()  # idempotent; _run_bulk already drained on the happy path

    return {
        "mode": mode,
        "pack": pack.get("id"),
        "seed": stable_seed(seed),
        "actions": total,
        "duration_seconds": duration,
        "benign_threat_level": level,
        "window_start_epoch": window_start,
    }


# ── Determinism / parity verification (no network I/O) ────────────────────────

def _capture_run(pack, all_modules, config, mode):
    """Replay a pack in capture + dry-run with sleeps neutralized; return the list
    of (module_name, event_name, payload) that WOULD have been sent."""
    import log_simulator as ls

    prev_sink, prev_dry = ls._capture_sink, ls._dry_run
    sink = []
    ls._capture_sink = sink
    ls._dry_run = True

    orig_sleep = time.sleep
    time.sleep = lambda *a, **k: None  # no real waiting during verification
    try:
        with deterministic_env(pack.get("seed", pack.get("id")), config):
            reset_module_state(all_modules)
            from modules.session_utils import build_session_context
            session_context = build_session_context(config)
            duration = float(pack.get("duration_seconds", DEFAULT_DURATION_SECONDS))
            level = pack.get("benign_threat_level", "Benign Traffic Only")
            emit_benign = _emit_benign_factory(config, session_context, level)
            actions = _build_actions(pack, all_modules, config, session_context, duration)

            def _exec(kind, ref):
                if kind == "benign":
                    emit_benign(ref)
                else:
                    ref()

            # Advance the frozen clock per action for BOTH modes, exactly like the real
            # runs (bulk backfills now-duration..now; stream is now..now+duration). This is
            # essential once benign_threat_level mixes threats: the threat cooldown is
            # clock-driven, so a static clock would fire threats differently between the two
            # captures. With both advancing by the same offsets, cooldown deltas match and
            # only the base timestamp differs (which _strip_volatile removes).
            from freezegun import freeze_time
            window_start = (time.time() - duration) if mode == "bulk" else time.time()
            with freeze_time(datetime.datetime.fromtimestamp(window_start, _UTC)) as frozen:
                for _off, _kind, _ref in actions:
                    frozen.move_to(datetime.datetime.fromtimestamp(window_start + _off, _UTC))
                    _exec(_kind, _ref)
    finally:
        time.sleep = orig_sleep
        ls._capture_sink, ls._dry_run = prev_sink, prev_dry
    return sink


def verify_parity(pack, all_modules, config):
    """Confirm bulk and stream produce byte-identical content (timestamps stripped).

    Returns (ok: bool, bulk_capture, stream_capture). This is the core trust check
    for the alignment requirement; it needs no XSIAM tenant.
    """
    import log_simulator as ls

    bulk = _capture_run(pack, all_modules, config, "bulk")
    stream = _capture_run(pack, all_modules, config, "stream")

    def norm(cap):
        return [(n, e, ls._strip_volatile(p)) for (n, e, p) in cap]

    nb, ns = norm(bulk), norm(stream)
    return (nb == ns), bulk, stream
