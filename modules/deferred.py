"""Scenario steps that reach the tenant later than the rest of their sequence.

Some attack stories have real gaps: the burner account is deleted a minute after it was
created, a sync job runs minutes after the trust was opened. Stamping those later steps
with a future time and sending the whole sequence at once is wrong -- the tenant would
receive events dated in the future (out of order against every other feed, and outside
the window a detector is looking at when it runs).

Instead a scenario stamps each step with its real time and wraps the later steps with
`at(record, release_at)`. The sender (log_simulator.process_and_send) holds a wrapped
record until `release_at` and only then transmits it, so every event arrives at its own
timestamp. Capture, run manifests and dry runs still see the step when it is generated.
The wrapper is a dict / str subclass: anything that only READS records (checks,
previews, exports) sees an ordinary record.

    t0 = time.time()
    return [deferred.at(build(stamp=t0 + d), t0 + d) for d in (0, 60)]
"""
import time


class DeferredDict(dict):
    """A dict record the sender holds until `release_at` (epoch seconds)."""


class DeferredStr(str):
    """A str record the sender holds until `release_at` (epoch seconds)."""


def at(record, release_at):
    """`record`, marked to be sent at epoch `release_at`. A step that is already due, or a
    type that cannot be marked, is returned unchanged and goes out immediately."""
    if release_at is None or release_at <= time.time():
        return record
    if isinstance(record, dict):
        out = DeferredDict(record)
    elif isinstance(record, str):
        out = DeferredStr(record)
    else:
        return record
    out.release_at = float(release_at)
    return out


def release_at(record):
    """The epoch a record must not be sent before, or None for an ordinary record."""
    return getattr(record, "release_at", None)
