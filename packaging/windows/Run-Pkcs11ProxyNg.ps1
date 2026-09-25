<#
.SYNOPSIS
  Supervise the pkcs11-proxy-ng Windows daemon with restart-on-failure.

.DESCRIPTION
  Shipped in the deterministic Windows ZIP (scripts/release-windows.sh).
  Runs bin\pkcs11-proxy-ng.exe in the foreground and restarts it on any
  nonzero exit — the Windows equivalent of the Linux systemd unit's
  Restart=on-failure, covering the abnormal whole-process stop
  (exit 70, see the runbook's native-lifetime section). A clean exit
  (status 0) stops supervision; anything else sleeps $RestartDelaySecs
  and restarts. All daemon output appends to the log file.

  Never run this from an interactive/SSH shell: session-owned processes
  die with the session. Register a scheduled task instead (elevated
  PowerShell, adjust paths to your extraction layout):

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
      -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\p11\png\Run-Pkcs11ProxyNg.ps1" -ConfigPath "C:\p11\png\proxy.toml"'
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -RestartCount 3 `
      -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName 'Pkcs11ProxyNgDaemon' `
      -Action $action -Trigger $trigger -Settings $settings `
      -User 'SYSTEM' -RunLevel Highest

  Runbook: doc/runbooks/operating-pkcs11-proxy-ng.md §4b.

.PARAMETER ConfigPath
  Daemon config file. Copy proxy.toml.template to proxy.toml, edit the
  REQUIRED paths, and pass it here.

.PARAMETER LogPath
  File the daemon's combined stdout/stderr appends to.

.PARAMETER RestartDelaySecs
  Delay before restarting after a nonzero exit.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [string]$LogPath = (Join-Path $PSScriptRoot 'pkcs11-proxy-ng.log'),

    [int]$RestartDelaySecs = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$daemon = Join-Path $PSScriptRoot 'bin\pkcs11-proxy-ng.exe'
if (-not (Test-Path $daemon)) {
    throw "Daemon binary not found: $daemon (extract the full ZIP layout)"
}
if (-not (Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath (copy proxy.toml.template first)"
}

Write-Host "Supervising $daemon with config $ConfigPath (log: $LogPath)"
while ($true) {
    & $daemon $ConfigPath *>> $LogPath
    $status = $LASTEXITCODE
    if ($status -eq 0) {
        Write-Host "Daemon exited cleanly (status 0); supervision stops."
        exit 0
    }
    Write-Warning "Daemon exited with status $status; restarting in $RestartDelaySecs s."
    Start-Sleep -Seconds $RestartDelaySecs
}
