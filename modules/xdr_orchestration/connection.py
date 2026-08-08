# modules/xdr_orchestration/connection.py
#
# WorkstationConnection — the single, obvious place the attack target link is
# defined and the ONLY way the orchestrator reaches the box.
#
# Two responsibilities, both of which run BEFORE any technique fires:
#
#   1. preflight()          — per-check pass/fail health report. The orchestrator
#                             is fail-closed on it: no command is ever launched
#                             into a box that can't receive it, and the failing
#                             check is surfaced to the user with a plain reason.
#
#   2. discover_identity()  — queries the LIVE box over the same WinRM channel and
#                             returns the ground-truth triad XSIAM aligns on
#                             (logged-in user, system name, IP). These discovered
#                             facts become the SEED for all synthetic generation,
#                             bypassing session_utils randomization — so the
#                             project works on anyone's box with zero renaming.
#
# Transport: WinRM (pywinrm), lazily imported so the whole package imports and the
# DryRun/no-box dev path works even when pywinrm isn't installed. A `stub`
# transport returns a caller-supplied identity for offline development.
#
# Config convention: ALL deployment-specific values (target host, WinRM creds,
# optional egress IP / tuning) live in .env under fixed variable names (see the
# ENV_* constants on WorkstationConnection). config.json holds only structural
# defaults and the dev-only stub identity, so an end user edits .env only and
# never has to touch config.json.

import os
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional


class ConnectionError(Exception):
    """Raised when the target link is misconfigured or unreachable in a way that
    makes preflight impossible to even attempt (as opposed to a check simply
    failing, which is reported, not raised)."""


# ── Preflight report types ────────────────────────────────────────────────────

@dataclass
class PreflightCheck:
    """One health check's result. `ok is None` means the check was skipped
    (e.g. XSIAM API reachability when policy control wasn't requested)."""
    name: str
    ok: Optional[bool]
    detail: str = ""

    @property
    def status(self) -> str:
        if self.ok is None:
            return "SKIP"
        return "PASS" if self.ok else "FAIL"


@dataclass
class PreflightReport:
    """Aggregate preflight result. `ok` is True only if every non-skipped,
    non-optional check passed. Carries the discovered identity so the user can
    confirm 'these are the names/IP your logs will carry' before firing."""
    checks: list = field(default_factory=list)
    identity: Optional[dict] = None
    checked_at: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks if c.ok is not None)

    def failures(self):
        return [c for c in self.checks if c.ok is False]

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checked_at": self.checked_at,
            "checked_at_iso": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(self.checked_at)),
            "identity": self.identity,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail}
                for c in self.checks
            ],
        }

    def render(self) -> str:
        """Human-readable banner for CLI / dashboard tile."""
        lines = []
        overall = "GREEN — ready to fire" if self.ok else "RED — orchestrator will refuse to fire"
        lines.append(f"Preflight: {overall}")
        for c in self.checks:
            mark = {"PASS": "✓", "FAIL": "✗", "SKIP": "–"}[c.status]
            lines.append(f"  {mark} {c.name}: {c.status}" + (f" — {c.detail}" if c.detail else ""))
        if self.identity:
            i = self.identity
            lines.append("  Discovered identity your synthetic logs will carry:")
            lines.append(f"    user={i.get('username')}  host={i.get('hostname')}  "
                         f"ip={i.get('ip')}" +
                         (f"  egress_ip={i.get('egress_ip')}" if i.get('egress_ip') else ""))
        return "\n".join(lines)


# ── The connection ────────────────────────────────────────────────────────────

class WorkstationConnection:
    """Target link + health checks + live identity discovery.

    Build with `WorkstationConnection.from_config(config)`; the orchestrator holds
    exactly one and reaches the box through no other path.
    """

    # Cache freshness: preflight/discovery results are reused within this window
    # so the dashboard can poll a live status tile without hammering the box.
    CACHE_TTL_SECONDS = 30

    def __init__(self, *, host, transport="winrm", winrm_port=5985, winrm_scheme="http",
                 username=None, password=None, transport_auth="ntlm",
                 overrides=None, stub_identity=None):
        self.host = host
        self.transport = transport            # "winrm" | "stub"
        self.winrm_port = winrm_port
        self.winrm_scheme = winrm_scheme
        self.username = username
        self.password = password
        self.transport_auth = transport_auth  # pywinrm auth type: ntlm/basic/kerberos
        self.overrides = overrides or {}      # config forces specific fields (e.g. egress_ip)
        self._stub_identity = stub_identity   # for transport="stub" (no-box dev)

        self._session = None                  # lazily-built pywinrm Session
        self._identity_cache = None
        self._identity_cache_at = 0.0
        self._preflight_cache = None
        self._preflight_cache_at = 0.0

    # ---- construction --------------------------------------------------------

    # Fixed .env variable names — the ONLY place a user configures the target.
    # config.json never carries deployment-specific values (host/creds/IPs), so
    # end users edit .env only and never touch config.json.
    ENV_HOST      = "XDR_TARGET_HOST"          # box IP or hostname (required, live)
    ENV_USER      = "XDR_TARGET_WINRM_USER"    # local admin username (required, live)
    ENV_PASSWORD  = "XDR_TARGET_WINRM_PASSWORD"  # local admin password (required, live)
    ENV_PORT      = "XDR_TARGET_WINRM_PORT"     # optional, default 5985
    ENV_SCHEME    = "XDR_TARGET_WINRM_SCHEME"   # optional, default http
    ENV_AUTH      = "XDR_TARGET_WINRM_AUTH"     # optional, default ntlm
    ENV_TRANSPORT = "XDR_TARGET_TRANSPORT"      # optional, "winrm" (default) or "stub"
    ENV_EGRESS_IP = "XDR_TARGET_EGRESS_IP"      # optional override (org NAT/public IP)
    ENV_EMAIL_DOM = "XDR_EMAIL_DOMAIN"          # optional override (email domain)

    @classmethod
    def from_config(cls, config):
        """Build the connection. All deployment-specific values come from .env via
        the fixed ENV_* names above; config.json only supplies structural defaults
        and the dev-only stub identity, so a user never has to edit config.json.

        .env (the only file users touch):
            XDR_TARGET_HOST=192.168.0.60
            XDR_TARGET_WINRM_USER=labadmin
            XDR_TARGET_WINRM_PASSWORD=•••••
            # optional: XDR_TARGET_WINRM_{PORT,SCHEME,AUTH}, XDR_TARGET_TRANSPORT=stub,
            #           XDR_TARGET_EGRESS_IP, XDR_EMAIL_DOMAIN

        config.json (optional `xdr_orchestration.connection` block, structural only):
            { "transport": "winrm",              # env XDR_TARGET_TRANSPORT overrides
              "stub_identity": { ... } }         # used only when transport=="stub"
        """
        def _env(name):
            v = os.getenv(name)
            return v.strip() if v and v.strip() else None

        block = (config or {}).get("xdr_orchestration", {}).get("connection", {}) or {}

        # Transport: env wins, then config default, then "winrm".
        transport = (_env(cls.ENV_TRANSPORT) or block.get("transport") or "winrm").lower()

        host = _env(cls.ENV_HOST)
        if transport != "stub" and not host:
            raise ConnectionError(
                f"{cls.ENV_HOST} is not set in .env — set the target box's IP/hostname there "
                "(config.json intentionally holds no target address).")

        # Structural WinRM settings: env first, then optional config defaults, then built-ins.
        winrm_cfg = block.get("winrm", {})
        port   = int(_env(cls.ENV_PORT)   or winrm_cfg.get("port")   or 5985)
        scheme = _env(cls.ENV_SCHEME)     or winrm_cfg.get("scheme") or "http"
        auth   = _env(cls.ENV_AUTH)       or winrm_cfg.get("auth")   or "ntlm"

        username = _env(cls.ENV_USER)
        password = _env(cls.ENV_PASSWORD)

        # Optional identity overrides — env wins over any config block overrides.
        overrides = dict(block.get("overrides", {}) or {})
        if _env(cls.ENV_EGRESS_IP):
            overrides["egress_ip"] = _env(cls.ENV_EGRESS_IP)
        if _env(cls.ENV_EMAIL_DOM):
            overrides["email_domain"] = _env(cls.ENV_EMAIL_DOM)

        return cls(
            host=host,
            transport=transport,
            winrm_port=port,
            winrm_scheme=scheme,
            username=username,
            password=password,
            transport_auth=auth,
            overrides=overrides,
            stub_identity=block.get("stub_identity"),
        )

    # ---- low-level WinRM -----------------------------------------------------

    def _winrm_session(self):
        """Lazily build (and cache) a pywinrm Session. pywinrm is imported here,
        not at module top, so the package imports fine without it and the DryRun /
        stub paths need no dependency."""
        if self.transport == "stub":
            raise ConnectionError("stub transport has no WinRM session.")
        if self._session is not None:
            return self._session
        try:
            import winrm  # pywinrm
        except ImportError as e:
            raise ConnectionError(
                "pywinrm is not installed — `pip install pywinrm` (see requirements.txt) "
                "to reach a live target, or set transport='stub' for no-box development."
            ) from e
        if not self.username or not self.password:
            raise ConnectionError(
                "WinRM credentials are empty — set the env vars named in "
                "xdr_orchestration.connection.winrm.{user_env_var,pass_env_var} in your .env.")
        endpoint = f"{self.winrm_scheme}://{self.host}:{self.winrm_port}/wsman"
        self._session = winrm.Session(
            endpoint,
            auth=(self.username, self.password),
            transport=self.transport_auth,
        )
        return self._session

    def run_ps(self, script, timeout=None):
        """Run a PowerShell snippet on the target. Returns (rc, stdout, stderr)
        with text decoded. Raises ConnectionError only if the channel itself
        can't be established; a nonzero rc is returned, not raised, so callers
        decide whether it's a check failure or fatal."""
        session = self._winrm_session()
        result = session.run_ps(script)
        rc = result.status_code
        out = (result.std_out or b"").decode("utf-8", "replace").strip()
        err = (result.std_err or b"").decode("utf-8", "replace").strip()
        return rc, out, err

    # ---- identity discovery --------------------------------------------------

    def discover_identity(self, force=False):
        """Query the live box for the ground-truth triad and return it in the SAME
        shape session_utils.get_user_by_name yields, so it drops straight into
        every network module's `context`. Config `overrides` win over discovery.

        Raises ConnectionError with a clear message when discovery can't produce a
        valid seed (e.g. no interactive user logged in) — the orchestrator turns
        that into a preflight failure rather than seeding a blank user.
        """
        now = time.time()
        if (not force and self._identity_cache is not None
                and now - self._identity_cache_at < self.CACHE_TTL_SECONDS):
            return self._identity_cache

        if self.transport == "stub":
            identity = self._identity_from_stub()
        else:
            identity = self._identity_from_box()

        identity = self._apply_overrides(identity)
        self._validate_identity(identity)

        self._identity_cache = identity
        self._identity_cache_at = now
        return identity

    def _identity_from_stub(self):
        stub = dict(self._stub_identity or {})
        if not stub:
            raise ConnectionError(
                "transport='stub' but no xdr_orchestration.connection.stub_identity "
                "was provided — supply a {username, hostname, ip, ...} seed for no-box dev.")
        return self._identity_shell(
            username=stub.get("username"),
            hostname=stub.get("hostname"),
            ip=stub.get("ip"),
            os_version=stub.get("os_version"),
            department=stub.get("department"),
            email=stub.get("email"),
            display_name=stub.get("display_name"),
            upn=stub.get("upn"),
        )

    def _identity_from_box(self):
        # One round-trip returns all three facts as KEY=VALUE lines. `query user`
        # needs an interactive/RDP session present; if none, ActiveUser is blank
        # and _validate_identity fails preflight with a clear message.
        script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$comp = $env:COMPUTERNAME
try { $fqdn = ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME)).HostName } catch { $fqdn = $comp }
$upn = (whoami /upn) 2>$null
$active = $null
$qu = (query user) 2>$null
if ($qu) {
  foreach ($line in ($qu | Select-Object -Skip 1)) {
    $cols = ($line.Trim() -replace '\s{2,}', "`t").Split("`t")
    if ($cols.Length -ge 3 -and $cols[2] -eq 'Active') { $active = $cols[0].TrimStart('>'); break }
    if ($cols.Length -ge 4 -and $cols[3] -eq 'Active') { $active = $cols[0].TrimStart('>'); break }
  }
}
if (-not $active) { $active = ($env:USERNAME) }
$ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
       Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' -and
                      $_.PrefixOrigin -ne 'WellKnown' } |
       Sort-Object -Property SkipAsSource, InterfaceMetric |
       Select-Object -First 1 -ExpandProperty IPAddress)
Write-Output ("COMPUTERNAME=" + $comp)
Write-Output ("FQDN=" + $fqdn)
Write-Output ("ACTIVEUSER=" + $active)
Write-Output ("UPN=" + ($upn | Select-Object -First 1))
Write-Output ("IPV4=" + $ip)
"""
        try:
            rc, out, err = self.run_ps(script)
        except ConnectionError:
            raise
        except Exception as e:
            raise ConnectionError(f"identity discovery failed to run on {self.host}: {e}") from e
        if rc != 0 and not out:
            raise ConnectionError(
                f"identity discovery returned rc={rc} on {self.host}: {err or 'no output'}")

        facts = {}
        for line in out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                facts[k.strip()] = v.strip()

        raw_user = facts.get("ACTIVEUSER", "")
        upn = facts.get("UPN", "") or None
        # Normalize DOMAIN\user or host\user; keep sam account for username.
        username = raw_user.split("\\")[-1] if raw_user else ""
        hostname = (facts.get("FQDN") or facts.get("COMPUTERNAME") or "").lower() or None
        ip = facts.get("IPV4") or None

        return self._identity_shell(
            username=username or None,
            hostname=hostname,
            ip=ip,
            upn=upn,
        )

    def _identity_shell(self, *, username=None, hostname=None, ip=None, os_version=None,
                        department=None, email=None, display_name=None, upn=None):
        """Build the identity dict in session_utils.get_user_by_name shape, plus a
        few orchestration-specific extras (upn, egress_ip, source='discovered')."""
        email_domain = self.overrides.get("email_domain")
        if not email and username and email_domain:
            email = f"{username}@{email_domain}"
        return {
            "username":     username,
            "ip":           ip,                 # internal IP — correct for internal net logs
            "hostname":     hostname,
            "os_type":      "windows",
            "os_version":   os_version,
            "device_type":  "workstation",
            "department":   department,
            "email":        email,
            "display_name": display_name or username,
            "aws_iam_user": None,
            # orchestration extras (not part of get_user_by_name's contract):
            "upn":          upn,
            "egress_ip":    None,               # filled by _apply_overrides if configured
            "source":       "stub" if self.transport == "stub" else "discovered",
        }

    def _apply_overrides(self, identity):
        """Config overrides win over discovery. The important one is `egress_ip`:
        discovery yields the box's INTERNAL IP (right for internal firewall/DNS);
        external-facing modules (Zscaler, perimeter FW) need the org's NAT/public
        egress IP, which the box can't self-report — so it's an explicit override."""
        ov = self.overrides or {}
        for key in ("username", "hostname", "ip", "os_version", "department",
                    "email", "display_name", "egress_ip", "upn"):
            if ov.get(key):
                identity[key] = ov[key]
        return identity

    @staticmethod
    def _validate_identity(identity):
        missing = [k for k in ("username", "hostname", "ip") if not identity.get(k)]
        if missing:
            raise ConnectionError(
                "identity discovery produced an incomplete seed (missing: "
                f"{', '.join(missing)}). If 'username' is missing, no interactive user is "
                "logged in on the target — log in (or set an override) before firing, so the "
                "synthetic logs don't carry a blank user.")

    # ---- preflight -----------------------------------------------------------

    def preflight(self, *, require_xsiam=False, xsiam_client=None, force=False):
        """Run the P1 health-check set and return a PreflightReport. Cached with a
        timestamp so a status tile can poll cheaply. `require_xsiam` includes the
        XSIAM management-API reachability check (only when policy control is used).
        """
        now = time.time()
        if (not force and self._preflight_cache is not None
                and now - self._preflight_cache_at < self.CACHE_TTL_SECONDS):
            return self._preflight_cache

        checks = []
        identity = None

        if self.transport == "stub":
            # No-box dev: everything the box would answer is stubbed. We still run
            # identity discovery so the report shows the seed the run will carry.
            try:
                identity = self.discover_identity(force=force)
                checks.append(PreflightCheck("Stub identity", True,
                                             "transport='stub' — no live box; using configured seed"))
            except ConnectionError as e:
                checks.append(PreflightCheck("Stub identity", False, str(e)))
            checks.append(PreflightCheck("WinRM reachable + auth", None, "skipped (stub transport)"))
            checks.append(PreflightCheck("Atomic present", None, "skipped (stub transport)"))
            checks.append(PreflightCheck("Cortex agent healthy", None, "skipped (stub transport)"))
        else:
            reachable = self._check_winrm(checks)
            if reachable:
                # Only probe the box further if the channel is up.
                try:
                    identity = self.discover_identity(force=force)
                    i = identity
                    checks.append(PreflightCheck(
                        "Identity discovery", True,
                        f"user={i.get('username')} host={i.get('hostname')} ip={i.get('ip')}"))
                except ConnectionError as e:
                    checks.append(PreflightCheck("Identity discovery", False, str(e)))
                self._check_atomic(checks)
                self._check_cortex_agent(checks)
            else:
                for name in ("Identity discovery", "Atomic present", "Cortex agent healthy"):
                    checks.append(PreflightCheck(name, False, "skipped — WinRM channel down"))

        # XSIAM management API reachability (only if policy control requested).
        if require_xsiam:
            self._check_xsiam(checks, xsiam_client)
        else:
            checks.append(PreflightCheck("XSIAM API reachable", None,
                                         "skipped (no policy control requested for this run)"))

        report = PreflightReport(checks=checks, identity=identity, checked_at=now)
        self._preflight_cache = report
        self._preflight_cache_at = now
        return report

    def _check_winrm(self, checks):
        # First a cheap TCP probe so a closed port fails fast with a clear reason
        # instead of a slow pywinrm timeout.
        try:
            with socket.create_connection((self.host, self.winrm_port), timeout=4):
                pass
        except OSError as e:
            checks.append(PreflightCheck(
                "WinRM reachable + auth", False,
                f"TCP {self.host}:{self.winrm_port} not open ({e}) — is WinRM enabled and the "
                "firewall rule scoped to this console? Run the Kickstarter on the box."))
            return False
        # Port open — now authenticate with a trivial round-trip.
        try:
            rc, out, err = self.run_ps("Write-Output ('WHOAMI=' + (whoami))")
        except ConnectionError as e:
            checks.append(PreflightCheck("WinRM reachable + auth", False, str(e)))
            return False
        except Exception as e:
            checks.append(PreflightCheck(
                "WinRM reachable + auth", False,
                f"port open but WinRM auth/round-trip failed: {e} — check credentials/auth type."))
            return False
        if rc != 0 or "WHOAMI=" not in out:
            checks.append(PreflightCheck(
                "WinRM reachable + auth", False,
                f"round-trip returned rc={rc}: {err or out or 'no output'}"))
            return False
        who = out.split("WHOAMI=", 1)[1].strip()
        checks.append(PreflightCheck("WinRM reachable + auth", True, f"authenticated as {who}"))
        return True

    def _check_atomic(self, checks):
        try:
            rc, out, err = self.run_ps(
                "if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) "
                "{ Write-Output 'ATOMIC=ok' } else { Write-Output 'ATOMIC=missing' }")
        except Exception as e:
            checks.append(PreflightCheck("Atomic present", False, f"probe failed: {e}"))
            return
        if "ATOMIC=ok" in out:
            checks.append(PreflightCheck("Atomic present", True, "Invoke-AtomicTest importable"))
        else:
            checks.append(PreflightCheck(
                "Atomic present", False,
                "Invoke-AtomicTest not importable — install Invoke-AtomicRedTeam "
                "(the Kickstarter does this)."))

    def _check_cortex_agent(self, checks):
        # cyserver is the Cortex XDR agent service; cyverak/cydump vary by version,
        # so we key off the primary service being present AND running.
        try:
            rc, out, err = self.run_ps(
                "$s = Get-Service -Name 'cyserver' -ErrorAction SilentlyContinue; "
                "if ($null -eq $s) { Write-Output 'AGENT=absent' } "
                "else { Write-Output ('AGENT=' + $s.Status) }")
        except Exception as e:
            checks.append(PreflightCheck("Cortex agent healthy", False, f"probe failed: {e}"))
            return
        val = ""
        for line in out.splitlines():
            if line.startswith("AGENT="):
                val = line.split("=", 1)[1].strip()
        if val == "Running":
            checks.append(PreflightCheck("Cortex agent healthy", True, "cyserver service Running"))
        elif val == "absent":
            checks.append(PreflightCheck(
                "Cortex agent healthy", False,
                "Cortex XDR agent (cyserver) not installed — no endpoint telemetry will be "
                "collected, so nothing to correlate. Install the agent before firing."))
        else:
            checks.append(PreflightCheck(
                "Cortex agent healthy", False,
                f"cyserver service is '{val or 'unknown'}', not Running."))

    def _check_xsiam(self, checks, xsiam_client):
        if xsiam_client is None:
            checks.append(PreflightCheck(
                "XSIAM API reachable", False,
                "policy control requested but no xsiam_client was provided to preflight()."))
            return
        try:
            ok, detail = xsiam_client.healthcheck()
            checks.append(PreflightCheck("XSIAM API reachable", bool(ok), detail))
        except Exception as e:
            checks.append(PreflightCheck("XSIAM API reachable", False, f"healthcheck failed: {e}"))

    # ---- introspection -------------------------------------------------------

    def describe(self):
        """Non-secret summary for logs/UI (never includes the password)."""
        return {
            "host": self.host,
            "transport": self.transport,
            "winrm": f"{self.winrm_scheme}://{self.host}:{self.winrm_port}"
                     if self.transport != "stub" else None,
            "auth": self.transport_auth if self.transport != "stub" else None,
            "username_configured": bool(self.username) or self.transport == "stub",
            "overrides": {k: v for k, v in (self.overrides or {}).items()},
        }
