# modules/xdr_orchestration/  —  XDR Attack-Orchestration package
#
# This is a *package*, not a LogSim generator module. The module loader
# (log_simulator.py:load_modules) only walks top-level `modules/*.py` files and
# keys the registry off a module-level `NAME` constant; a subdirectory package is
# never scanned, so nothing here is ever treated as a startable data source.
#
# What this package does instead: it ORCHESTRATES a purple-team run — it triggers
# *real* Atomic Red Team techniques on a live Windows box running the Cortex XDR
# agent (so XSIAM's agent-bound endpoint analytics genuinely fire) while LogSim
# emits *synthetic* network logs pinned to that same box's real host/user/IP and
# timed around the real activity, so XSIAM stitches endpoint + network into one
# incident.
#
# The orchestrator is registered as a scenario in get_scenarios() (see
# log_simulator.py) so it flows through the existing driver, run-tracking, and
# transports unchanged.
#
# Foundation-first (per plan): connection.py (preflight + identity discovery) is
# the single, obvious place the target link is defined and the ONLY way the
# orchestrator reaches the box. The orchestrator is fail-closed on preflight.

from .connection import (
    WorkstationConnection,
    PreflightReport,
    PreflightCheck,
    ConnectionError,
)

__all__ = [
    "WorkstationConnection",
    "PreflightReport",
    "PreflightCheck",
    "ConnectionError",
]
