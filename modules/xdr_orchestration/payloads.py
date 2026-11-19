# modules/xdr_orchestration/payloads.py
#
# Built-in payloads: endpoint actions that are NOT Atomic Red Team tests, run by the
# executor over the same WinRM channel. A story step selects one with
#   technique: {id: T1204.002, executor: builtin, payload: wildfire_pe}
#
# Each payload is a fixed, reviewed PowerShell script (no caller-supplied code; the
# only inputs are validated strings inserted single-quoted) that prints ONE line of
# compact JSON, which the executor parses into ExecResult.outputs. Outputs feed the
# step's synthetic network events (same file name / hash / URL), so the endpoint and
# network halves describe one download.
#
# wildfire_pe -- Palo Alto's WildFire malware test PE.
#   Source: the WildFire API /test resource (no API key). The non-SSL URL is used
#   because the lab NGFW does not decrypt. "Each time you download the test file,
#   it has a different SHA-256 hash value" and its verdict is always malware, so
#   every run is a never-seen sample: the Cortex agent finds no cached verdict, the
#   tenant submits it to WildFire, and the malware verdict raises the agent's
#   WildFire malware alert (Cortex XSIAM onboarding health checks list exactly this:
#   "Cortex XDR agent generates WildFire malware issues").
#   It is written to C:\Users\Public\Downloads -- deliberately OUTSIDE the Atomic
#   allow-list paths (C:\AtomicRedTeam\, the user's AppData\Local\Temp\) that the
#   setup guide exempts from malware scanning; a file there would never be judged.
#   The script then executes it (the agent evaluates PE files at execution) and
#   reports whether the agent blocked execution or quarantined the file. Blocked or
#   quarantined is a SUCCESS for this payload: it is the detection we want.
#
#   The file is LEFT ON DISK after the run. An unknown hash is allowed to run while
#   the agent uploads it to WildFire in the background; the verdict -- and the alert --
#   come minutes later. On 2026-11-18 a cleanup step deleted the file 15 s after it
#   ran: the agent logged FILE_WRITE + PROCESS_START but never a verdict, and no alert
#   came. So each run instead deletes the PREVIOUS runs' test files before
#   downloading, leaving at most one (always-malware-verdict) test file on the box.

import json
import re
from typing import Optional

WILDFIRE_TEST_URL = "http://wildfire.paloaltonetworks.com/publicapi/test/pe"
WILDFIRE_DROP_DIR = r"C:\Users\Public\Downloads"

_SAFE_TAG = re.compile(r"^[a-z0-9]{1,16}$")


def _q(value) -> str:
    """PowerShell single-quoted literal (no expansion inside single quotes)."""
    return "'" + str(value).replace("'", "''") + "'"


def wildfire_file_path(tag: str) -> str:
    return WILDFIRE_DROP_DIR + "\\" + f"wildfire-test-pe-file-{tag}.exe"


def _wildfire_execute(params: dict) -> str:
    tag = params["tag"]
    return (
        "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Continue'\n"
        f"$url = {_q(WILDFIRE_TEST_URL)}\n"
        f"$dir = {_q(WILDFIRE_DROP_DIR)}\n"
        f"$path = {_q(wildfire_file_path(tag))}\n"
        "$r = [ordered]@{ url = $url; path = $path; file_name = (Split-Path $path -Leaf) }\n"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null\n"
        # Housekeeping: remove EARLIER runs' test files. This run's file must stay on
        # disk -- see the module note on why cleanup is deferred to the next run.
        "$old = Get-ChildItem -Path $dir -Filter 'wildfire-test-pe-file-*.exe' -ErrorAction SilentlyContinue\n"
        "$r.removed_previous = @($old | ForEach-Object { $n = $_.Name;"
        " Remove-Item -Force $_.FullName -ErrorAction SilentlyContinue; $n })\n"
        "try { Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing -TimeoutSec 60;"
        " $r.downloaded = $true }\n"
        "catch { $r.downloaded = $false; $r.download_error = $_.Exception.Message }\n"
        "Start-Sleep -Seconds 3\n"
        "$r.present_after_download = Test-Path $path\n"
        "if ($r.present_after_download) {\n"
        "  try { $r.sha256 = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLower();"
        " $r.size = (Get-Item $path).Length } catch { $r.hash_error = $_.Exception.Message }\n"
        "  try {\n"
        "    $p = Start-Process -FilePath $path -PassThru -WindowStyle Hidden -ErrorAction Stop\n"
        "    Start-Sleep -Seconds 5\n"
        "    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }\n"
        "    $r.executed = $true\n"
        "  } catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "}\n"
        "Start-Sleep -Seconds 5\n"
        "$r.present_at_end = Test-Path $path\n"
        "$r | ConvertTo-Json -Compress\n"
    )


def _wildfire_cleanup(params: dict) -> str:
    return (
        f"$path = {_q(wildfire_file_path(params['tag']))}\n"
        "if (Test-Path $path) { Remove-Item -Force $path -ErrorAction SilentlyContinue }\n"
        "@{ removed = -not (Test-Path $path) } | ConvertTo-Json -Compress\n"
    )


def _wildfire_judge(rc, out: dict) -> tuple:
    """(ok, detail). ok = the sample reached the box (or the agent stopped it on
    arrival). A failed download with no agent action is the only failure."""
    if not out:
        return False, f"no result from payload (rc={rc})"
    sha = out.get("sha256")
    if not out.get("downloaded"):
        return False, f"download failed: {out.get('download_error') or 'unknown error'}"
    if not out.get("present_after_download"):
        return True, "downloaded, then removed on write (agent quarantine)"
    bits = [f"downloaded {out.get('file_name')} sha256={sha[:16] + '…' if sha else '?'}"]
    if out.get("executed") is False:
        bits.append(f"execution blocked ({(out.get('exec_error') or '')[:80]})")
    elif out.get("executed"):
        bits.append("executed")
    if out.get("present_at_end") is False:
        bits.append("file then quarantined")
    return True, "; ".join(bits)


PAYLOADS = {
    "wildfire_pe": {
        "description": "Download + run Palo Alto's WildFire test PE (unique hash per download)",
        "execute": _wildfire_execute,
        "cleanup": _wildfire_cleanup,
        "judge": _wildfire_judge,
        "needs": ("tag",),
    },
}


def parse_json_line(text: str) -> Optional[dict]:
    """The payload's last JSON object line, else None (WinRM may add noise)."""
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None


def validate_params(name: str, params: dict) -> Optional[str]:
    """Error string if the payload is unknown or its params unsafe, else None."""
    spec = PAYLOADS.get(name)
    if not spec:
        return f"unknown builtin payload '{name}' (known: {', '.join(sorted(PAYLOADS))})"
    for k in spec.get("needs", ()):
        if not params.get(k):
            return f"payload '{name}' needs param '{k}'"
    tag = params.get("tag")
    if tag is not None and not _SAFE_TAG.match(str(tag)):
        return f"payload tag '{tag}' must be 1-16 lowercase letters/digits"
    return None
