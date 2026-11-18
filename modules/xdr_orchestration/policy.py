# modules/xdr_orchestration/policy.py
#
# Prevention-mode gate (Tier-2 #6, opt-in).
#
# The whole module depends on the Cortex agent being in ALERT/Report mode: in
# PREVENT mode the agent terminates the PowerShell host that runs each atomic
# (observed rc 3225419877, output truncated), so a story fired into a preventing
# box produces a wall of killed steps and a fragmented/empty incident — a wasted
# run that looks like a product failure.
#
# This module adds an opt-in ACTIVE probe: before the real story fires, run ONE
# benign canary atomic and watch for the kill-rc. If prevention is active the
# orchestrator can fail closed with precise remediation instead of firing the
# whole story into a wall.
#
# What this deliberately does NOT do: silently rewrite the endpoint's prevention
# profiles via the XSIAM API. That mutates production security posture, the API
# call is not part of integrations/xsiam_client, and it cannot be validated
# offline — so an automatic flip would be an unreviewed, hard-to-reverse change.
# `PolicyController` is the seam where a vetted flip can later drop in; until one
# is supplied, `auto_flip` can only gate the run, never change the box.

from dataclasses import dataclass, field
from typing import Optional

# The rc a Cortex-terminated wsmprovhost returns (see executor._invoke / connection).
PS_HOST_KILLED_RC = 3225419877

# A single, cheap, non-destructive canary: whoami (T1033, test 1). It is already in
# every box's installed prereqs and leaves nothing behind.
CANARY_TECHNIQUE = "T1033"
CANARY_TEST = "1"


@dataclass
class PreventionResult:
    """Outcome of the prevention probe."""
    ran: bool                       # did the probe actually fire a canary?
    prevention_active: Optional[bool]  # True/False, or None when undetermined
    detail: str = ""
    rc: Optional[int] = None

    def to_dict(self) -> dict:
        return {"ran": self.ran, "prevention_active": self.prevention_active,
                "rc": self.rc, "detail": self.detail}


class PolicyController:
    """Seam for a vetted, reversible policy flip. The default controller cannot
    change the box — it only reports that no flip backend is wired, so the opt-in
    `auto_flip` path degrades to a fail-closed gate rather than a silent mutation.
    Supply a real controller (with tested XSIAM endpoint-policy calls) to enable an
    actual flip + restore."""

    available = False

    def flip_to_alert(self, identity) -> bool:
        raise NotImplementedError(
            "No policy-flip backend is wired. Move the endpoint's prevention profiles "
            "to Alert/Report mode in the Cortex console, then re-run. (A vetted "
            "PolicyController can be injected to automate this.)")

    def restore(self, identity) -> bool:
        raise NotImplementedError


def probe_prevention(executor, *, verbose: bool = True) -> PreventionResult:
    """Fire the benign canary once and classify the result.

    DryRun executor always returns rc=0, so a no-box dev run reports
    prevention_active=False (nothing to gate). A live box in PREVENT mode kills the
    host and returns PS_HOST_KILLED_RC → prevention_active=True.
    """
    try:
        r = executor.execute(CANARY_TECHNIQUE, CANARY_TEST)
    except Exception as e:
        return PreventionResult(ran=False, prevention_active=None,
                                detail=f"canary could not run: {e}")
    killed = (r.rc == PS_HOST_KILLED_RC)
    if killed:
        detail = ("canary technique was terminated (rc=%s) — the Cortex agent is "
                  "PREVENTING, not alerting. Move the endpoint's prevention profiles "
                  "to Alert/Report mode before firing." % PS_HOST_KILLED_RC)
    else:
        detail = f"canary ran clean (rc={r.rc}) — agent is alerting, safe to fire."
    if verbose:
        print(f"[XDR] prevention probe: {'PREVENT' if killed else 'OK'} — {detail}")
    return PreventionResult(ran=True, prevention_active=killed, detail=detail, rc=r.rc)
