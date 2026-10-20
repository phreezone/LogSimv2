# install-atomic-on-box.ps1  —  NON-INTERACTIVE Atomic Red Team install for the
# XDR lab box. Interim stand-in for the (not-yet-built) Kickstarter's Atomic step.
#
# Run ELEVATED on the Cortex-agent box, OR let the console run it over WinRM — it
# is fully unattended: no NuGet / PSGallery / Install-Module prompts. Stock Windows
# would otherwise interrupt with "NuGet provider is required" and "Untrusted
# repository" approvals, which block automation (and silently fail over WinRM).
#
# It pre-satisfies every dependency, then installs Invoke-AtomicRedTeam + atomics.
# Idempotent: re-running is a no-op. Requires internet on the box (PSGallery + GitHub).
#
# NOTE: Cortex XDR may quarantine the dropped atomics. Add the install paths to a
# Malware-profile path allow-list (or set the endpoint's profiles to Report mode)
# BEFORE running — see docs/modules/xdr-orchestration.md.

$ErrorActionPreference = 'Stop'
Write-Host "== Atomic Red Team — unattended install ==" -ForegroundColor Cyan

# 1) TLS 1.2 — required for PSGallery + raw.githubusercontent.com on older Windows.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# 2) NuGet package provider (THE prompt you hit) — install unattended.
$nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
if (-not $nuget -or $nuget.Version -lt [version]'2.8.5.201') {
    Write-Host "Installing NuGet provider..." -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap -Scope AllUsers | Out-Null
}

# 3) Trust PSGallery so Install-Module never prompts "Untrusted repository".
if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
    Register-PSRepository -Default -ErrorAction SilentlyContinue
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# 4) Ensure PowerShellGet can install cleanly; -AllowClobber avoids stock-module clashes.
try {
    Install-Module -Name PowerShellGet -Force -Scope AllUsers -AllowClobber -ErrorAction Stop | Out-Null
} catch {
    Write-Host "PowerShellGet update skipped: $($_.Exception.Message)" -ForegroundColor DarkGray
}

# 5) Invoke-AtomicRedTeam relies on powershell-yaml — pre-install it unattended so
#    the Atomic installer doesn't trigger its own module prompt.
if (-not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
    Install-Module -Name 'powershell-yaml' -Force -Scope AllUsers -AllowClobber | Out-Null
}

# 6) Install Invoke-AtomicRedTeam + the atomics folder (unattended; -Force covers reruns).
Write-Host "Installing Invoke-AtomicRedTeam + atomics..." -ForegroundColor Yellow
$installer = 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'
IEX (New-Object Net.WebClient).DownloadString($installer)
Install-AtomicRedTeam -getAtomics -Force

# 7) Verify Invoke-AtomicTest resolves. WinRM non-interactive sessions do NOT load
#    the user profile, so import the module explicitly (the executor does the same).
$psd1 = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
if (Test-Path $psd1) { Import-Module $psd1 -Force -ErrorAction SilentlyContinue }
if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
    Write-Host "ATOMIC=ok  Invoke-AtomicTest available" -ForegroundColor Green
} else {
    Write-Host "ATOMIC=partial  module installed but Invoke-AtomicTest not resolved in this session" -ForegroundColor Red
    Write-Host "  -> import it per session: Import-Module '$psd1' -Force" -ForegroundColor DarkGray
}
