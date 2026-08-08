# enable-winrm-on-box.ps1  —  MANUAL, INTERIM WinRM enablement for the XDR lab box.
#
# This is the temporary stand-in for the (not-yet-built) Kickstarter's WinRM step.
# Run it ELEVATED (Run as Administrator) ON THE CORTEX-AGENT WORKSTATION, once.
# It only enables remote management + scopes access to the LogSim console; it does
# NOT install Atomic or touch the Cortex agent (preflight will report those).
#
# Lab-only. Scopes the WinRM firewall rule to the console IP so the listener is not
# world-open. Sets LocalAccountTokenFilterPolicy=1 so a LOCAL admin account gets a
# full (elevated) token over the network — required later for admin-level Atomic
# tests; harmless for preflight.
#
# --- EDIT THIS if the box reaches the console on a different interface ---------
$ConsoleIP = '192.168.0.45'   # LogSim console (WinRM client) LAN IP.
                              # If the box is a VMware VM on VMnet8, use 192.168.47.1;
                              # on VMnet1, use 192.168.26.1.

Write-Host "== Enabling WinRM, scoped to console $ConsoleIP ==" -ForegroundColor Cyan

# 1) Turn on PS remoting / WinRM listener (SkipNetworkProfileCheck covers a Public NIC).
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# 2) Scope the built-in HTTP-In firewall rule to just the console (least exposure).
try {
    Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP' -RemoteAddress $ConsoleIP -ErrorAction Stop
    Write-Host "Scoped WINRM-HTTP-In-TCP to $ConsoleIP" -ForegroundColor Green
} catch {
    # Fall back to adding an explicit scoped allow rule if the built-in name differs.
    New-NetFirewallRule -DisplayName 'LogSim WinRM (scoped)' -Direction Inbound `
        -Protocol TCP -LocalPort 5985 -RemoteAddress $ConsoleIP -Action Allow | Out-Null
    Write-Host "Added scoped WinRM allow rule for $ConsoleIP" -ForegroundColor Green
}

# 3) Let a local admin present a full elevated token over the network (for Atomic).
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -PropertyType DWord -Value 1 -Force | Out-Null

# 4) Confirm the service is up and report the listener.
$svc = Get-Service WinRM
Write-Host ("WinRM service: {0}" -f $svc.Status) -ForegroundColor Yellow
winrm enumerate winrm/config/listener

Write-Host "`n== Done. From the console, test with tests/xdr_preflight_check.py ==" -ForegroundColor Cyan
Write-Host "To roll back later: Disable-PSRemoting; remove the firewall rule; delete the LocalAccountTokenFilterPolicy value." -ForegroundColor DarkGray
