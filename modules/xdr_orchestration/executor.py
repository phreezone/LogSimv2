# modules/xdr_orchestration/executor.py
#
# Executors turn a story step's technique declaration into a REAL (or dry-run)
# action on the target, and return a uniform ExecResult the orchestrator records
# in the run manifest.
#
# Two P1 backends behind one small protocol:
#
#   WinRMAtomicExecutor — runs Invoke-AtomicTest on the live Windows box over the
#                         WorkstationConnection's WinRM channel. This is PowerShell
#                         (that's what Atomic is), so it is deliberately the ONE
#                         place we use run_ps: tripping the Cortex agent here is the
#                         whole point — it's what generates the endpoint telemetry.
#                         (Benign health/identity probes stay on run_cmd; see
#                         connection.run_ps note.) Requires the target's prevention
#                         profiles in ALERT/Report mode, else the agent terminates
#                         the technique before it produces useful telemetry.
#
#   DryRunExecutor      — logs the intended technique and returns a synthetic OK
#                         result WITHOUT touching the box, so the whole synthetic-
#                         network + run-tracking path can be built and tested with
#                         no live target.
#
# Every run_ps invocation is a fresh wsmprovhost process, so the Atomic module is
# Import-Module'd on EVERY call — module state never carries across calls.

import time
from dataclasses import dataclass, field
from typing import Optional


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass
class ExecResult:
    """Uniform outcome of one executor action, recorded in the run manifest."""
    executor: str                      # "winrm_atomic" | "dry_run"
    action: str                        # execute | check_prereqs | get_prereqs | cleanup | show_details
    technique_id: str
    ok: bool
    rc: Optional[int] = None
    test_numbers: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    command: str = ""                  # the Invoke-AtomicTest arg string (audit trail)
    started_at: float = field(default_factory=time.time)
    duration_s: float = 0.0
    detail: str = ""                   # human-readable one-liner for banners/UI

    def to_dict(self) -> dict:
        return {
            "executor": self.executor,
            "action": self.action,
            "technique_id": self.technique_id,
            "test_numbers": self.test_numbers,
            "ok": self.ok,
            "rc": self.rc,
            "command": self.command,
            "detail": self.detail,
            "duration_s": round(self.duration_s, 3),
            "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.started_at)),
            # stdout/stderr can be large; keep them but let callers trim.
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


class ExecutorError(Exception):
    """Raised only when an action cannot be attempted at all (e.g. the channel is
    down). A technique that runs but fails is a normal ExecResult with ok=False,
    not an exception."""


# ── PowerShell argument helpers ───────────────────────────────────────────────

def _ps_single_quote(value) -> str:
    """Quote a value as a PowerShell single-quoted string (doubling embedded
    single quotes). PowerShell does not expand anything inside single quotes, so
    this is injection-safe for the string values we pass as Atomic input args."""
    return "'" + str(value).replace("'", "''") + "'"


def _input_args_to_ps_hashtable(input_args: Optional[dict]) -> str:
    """Render {k: v} as a PowerShell hashtable literal for -InputArgs, e.g.
    @{ 'output_file' = 'C:\\t.txt'; 'port' = '443' }. Values are single-quoted
    strings — Atomic coerces types from its own arg spec."""
    if not input_args:
        return ""
    pairs = "; ".join(
        f"{_ps_single_quote(k)} = {_ps_single_quote(v)}" for k, v in input_args.items()
    )
    return "@{ " + pairs + " }"


# ── Executor backends ─────────────────────────────────────────────────────────

class WinRMAtomicExecutor:
    """Runs Invoke-AtomicTest on the live box over the WorkstationConnection.

    The connection is the ONLY path to the box (it owns creds + the pywinrm
    session); this executor just composes Atomic invocations and classifies the
    results. `atomic_psd1` defaults to the module path the installer/preflight
    already standardize on (connection.ATOMIC_PSD1).
    """

    name = "winrm_atomic"

    def __init__(self, connection, atomic_psd1: Optional[str] = None, default_timeout: int = 300):
        self.connection = connection
        self.atomic_psd1 = atomic_psd1 or getattr(
            connection, "ATOMIC_PSD1",
            r"C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1")
        self.default_timeout = default_timeout

    # -- invocation plumbing ---------------------------------------------------

    def _wrap(self, atomic_args: str) -> str:
        """Every call is a fresh process: suppress the progress stream (it corrupts
        WinRM stdout/exit handling) and Import-Module before Invoke-AtomicTest."""
        return (
            "$ProgressPreference='SilentlyContinue'; "
            f"Import-Module '{self.atomic_psd1}' -Force; "
            f"Invoke-AtomicTest {atomic_args}"
        )

    def _invoke(self, action: str, technique_id: str, atomic_args: str,
                test_numbers: Optional[str], ok_predicate) -> ExecResult:
        started = time.time()
        script = self._wrap(atomic_args)
        try:
            rc, out, err = self.connection.run_ps(script, timeout=self.default_timeout)
        except Exception as e:
            # Channel-level failure — cannot even attempt the action.
            raise ExecutorError(
                f"{action} {technique_id}: WinRM channel error: {e}") from e
        dur = time.time() - started

        # A terminated PowerShell host (Cortex still in prevent mode, or a crash)
        # surfaces as this rc with truncated output — flag it precisely so the
        # user knows to move the endpoint to Alert/Report mode.
        killed = rc == 3225419877
        ok = (not killed) and bool(ok_predicate(rc, out, err))
        detail = self._detail(action, ok, killed, rc, out, err)

        return ExecResult(
            executor=self.name, action=action, technique_id=technique_id,
            ok=ok, rc=rc, test_numbers=test_numbers, stdout=out, stderr=err,
            command=atomic_args, started_at=started, duration_s=dur, detail=detail,
        )

    @staticmethod
    def _detail(action, ok, killed, rc, out, err):
        if killed:
            return ("PowerShell host was terminated (rc=3225419877) — the Cortex agent "
                    "is still preventing, not alerting. Move the endpoint's prevention "
                    "profiles to Alert/Report mode.")
        if ok:
            return f"{action} succeeded (rc={rc})"
        snippet = (err or out or "").strip().replace("\r\n", " ")[:200]
        return f"{action} returned rc={rc}: {snippet or 'no output'}"

    def _tn_args(self, test_numbers: Optional[str]) -> str:
        return f" -TestNumbers {test_numbers}" if test_numbers else ""

    # -- public actions --------------------------------------------------------

    def show_details(self, technique_id: str, test_numbers: Optional[str] = None) -> ExecResult:
        """Non-executing: print the technique's test details. Safe readiness probe."""
        args = f"{technique_id}{self._tn_args(test_numbers)} -ShowDetailsBrief"
        return self._invoke("show_details", technique_id, args, test_numbers,
                            ok_predicate=lambda rc, out, err: rc == 0 and technique_id in out)

    def check_prereqs(self, technique_id: str, test_numbers: Optional[str] = None) -> ExecResult:
        """Non-executing: verify prerequisites are met."""
        args = f"{technique_id}{self._tn_args(test_numbers)} -CheckPrereqs"
        return self._invoke("check_prereqs", technique_id, args, test_numbers,
                            ok_predicate=lambda rc, out, err: "Prerequisites met" in out or rc == 0)

    def get_prereqs(self, technique_id: str, test_numbers: Optional[str] = None) -> ExecResult:
        """Resolve/install prerequisites for the technique."""
        args = f"{technique_id}{self._tn_args(test_numbers)} -GetPrereqs"
        return self._invoke("get_prereqs", technique_id, args, test_numbers,
                            ok_predicate=lambda rc, out, err: rc == 0)

    def execute(self, technique_id: str, test_numbers: Optional[str] = None,
                input_args: Optional[dict] = None, timeout: Optional[int] = None) -> ExecResult:
        """FIRE the technique for real. `test_numbers` (e.g. "1" or "1,2") should
        pin a specific, non-destructive, cleanup-capable atomic — never run all of
        a technique's tests blindly. `input_args` come from the step's shared
        `params` so the endpoint touches the same dest/port/app as the paired
        synthetic network logs."""
        ia = _input_args_to_ps_hashtable(input_args)
        args = f"{technique_id}{self._tn_args(test_numbers)}"
        if ia:
            args += f" -InputArgs {ia}"
        # Timeout override just for this call.
        prev = self.default_timeout
        if timeout:
            self.default_timeout = timeout
        try:
            return self._invoke("execute", technique_id, args, test_numbers,
                                ok_predicate=lambda rc, out, err: rc == 0)
        finally:
            self.default_timeout = prev

    def cleanup(self, technique_id: str, test_numbers: Optional[str] = None,
                input_args: Optional[dict] = None) -> ExecResult:
        """Run the technique's cleanup commands. Use the SAME input_args as execute
        so the cleanup targets what was created."""
        ia = _input_args_to_ps_hashtable(input_args)
        args = f"{technique_id}{self._tn_args(test_numbers)}"
        if ia:
            args += f" -InputArgs {ia}"
        args += " -Cleanup"
        return self._invoke("cleanup", technique_id, args, test_numbers,
                            ok_predicate=lambda rc, out, err: rc == 0)


class DryRunExecutor:
    """No-box backend: logs the intended technique and returns a synthetic OK
    result WITHOUT touching any target. Lets the synthetic-network + run-tracking
    path be developed and tested with no live box (pair with transport='stub')."""

    name = "dry_run"

    def __init__(self, sink=None):
        # sink: optional callable(str) for capturing the log line (defaults to print).
        self._sink = sink or (lambda line: print(line))

    def _record(self, action, technique_id, test_numbers, input_args) -> ExecResult:
        tn = f" test(s) {test_numbers}" if test_numbers else ""
        ia = f" input_args={input_args}" if input_args else ""
        line = f"[DRY-RUN] {action} {technique_id}{tn}{ia} — not executed (no box)"
        self._sink(line)
        return ExecResult(
            executor=self.name, action=action, technique_id=technique_id, ok=True,
            rc=0, test_numbers=test_numbers, command=f"{technique_id}{tn}".strip(),
            detail=line,
        )

    def show_details(self, technique_id, test_numbers=None):
        return self._record("show_details", technique_id, test_numbers, None)

    def check_prereqs(self, technique_id, test_numbers=None):
        return self._record("check_prereqs", technique_id, test_numbers, None)

    def get_prereqs(self, technique_id, test_numbers=None):
        return self._record("get_prereqs", technique_id, test_numbers, None)

    def execute(self, technique_id, test_numbers=None, input_args=None, timeout=None):
        return self._record("execute", technique_id, test_numbers, input_args)

    def cleanup(self, technique_id, test_numbers=None, input_args=None):
        return self._record("cleanup", technique_id, test_numbers, input_args)


# ── Factory ───────────────────────────────────────────────────────────────────

def build_executor(connection, *, dry_run: Optional[bool] = None, sink=None):
    """Pick the backend. Explicit `dry_run` wins; otherwise a stub-transport
    connection implies DryRun (no box), a live one implies WinRMAtomic."""
    if dry_run is None:
        dry_run = getattr(connection, "transport", "winrm") == "stub"
    return DryRunExecutor(sink=sink) if dry_run else WinRMAtomicExecutor(connection)
