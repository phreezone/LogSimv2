# modules/xdr_orchestration/timing.py
#
# Campaign timing for a story run (Tier-2 #5). Two realism levers that actually
# work on a LIVE run:
#
#   • pacing scale   — multiply every pre/post delay (and the anchor sleeps).
#   • jitter         — randomize each delay by ±fraction so steps don't fire on a
#                      metronome (a fixed cadence is itself an IOC).
#
# NOTE on back-dating: literal back-dating is deliberately NOT offered for a live
# run. The Cortex agent stamps the REAL endpoint technique with wall-clock time as
# it runs, and each network module bakes its own "now" into the log it emits
# (process_and_send takes no timestamp), so there is no single seam to move a run
# into the past without rewriting every module. Jitter + a dwell profile are the
# meaningful realism levers for a run that fires for real; a multi-day dwell is a
# scheduling concern (run the stories on a cadence), not a per-emit timestamp.

import random
from dataclasses import dataclass
from typing import Optional


# profile -> (scale, jitter_fraction)
PACE_PROFILES = {
    "fast":      (0.0, 0.0),   # no delays at all — fastest possible run
    "normal":    (1.0, 0.0),   # the story's declared delays, unmodified
    "realistic": (1.0, 0.4),   # declared delays ±40% so the cadence looks human
    "slow":      (2.0, 0.3),   # 2x dwell ±30% — a slower, lower-and-slower run
}
DEFAULT_PROFILE = "normal"


@dataclass
class Timing:
    """Resolved per-run timing. `delay(base)` turns a step's declared delay into the
    actual seconds to sleep, applying the scale and a bounded random jitter."""
    scale: float = 1.0
    jitter: float = 0.0
    profile: Optional[str] = None
    _rng: random.Random = None

    def __post_init__(self):
        if self._rng is None:
            self._rng = random.Random()
        self.scale = max(0.0, float(self.scale))
        self.jitter = min(0.95, max(0.0, float(self.jitter)))

    def delay(self, base: float) -> float:
        """Seconds to actually sleep for a declared `base` delay. Never negative."""
        if base <= 0 or self.scale == 0:
            return 0.0
        d = base * self.scale
        if self.jitter:
            d *= 1.0 + self._rng.uniform(-self.jitter, self.jitter)
        return max(0.0, d)

    def to_dict(self) -> dict:
        return {"profile": self.profile, "scale": round(self.scale, 3),
                "jitter": round(self.jitter, 3)}


def resolve_timing(*, pace: Optional[float] = None, profile: Optional[str] = None,
                   jitter: Optional[float] = None, rng: Optional[random.Random] = None,
                   seed: Optional[int] = None) -> Timing:
    """Build a Timing from any mix of inputs (most specific wins):

      profile : one of PACE_PROFILES — sets both scale and a default jitter.
      pace    : a raw scale multiplier; multiplies the profile's scale (or stands
                alone when no profile is given). Back-compat with the old `pace` arg.
      jitter  : explicit jitter fraction; overrides the profile's default jitter.
      rng/seed: inject a seeded Random for reproducible jitter (used by tests).
    """
    prof_scale, prof_jitter = PACE_PROFILES.get((profile or "").lower(), (None, None))
    scale = prof_scale if prof_scale is not None else 1.0
    if pace is not None:
        try:
            scale = scale * max(0.0, float(pace)) if prof_scale is not None else max(0.0, float(pace))
        except (TypeError, ValueError):
            pass
    jit = jitter if jitter is not None else (prof_jitter if prof_jitter is not None else 0.0)
    if rng is None and seed is not None:
        rng = random.Random(seed)
    return Timing(scale=scale, jitter=jit or 0.0,
                  profile=(profile or DEFAULT_PROFILE), _rng=rng)
