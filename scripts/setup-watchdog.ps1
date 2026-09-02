#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the STIGMA Engine watchdog as a Windows Scheduled Task.

.DESCRIPTION
    Creates a task named "STIGMA-Engine-Watchdog" that:
      - Launches watchdog.ps1 on Windows startup (no login required)
      - Runs as SYSTEM so Docker CLI is always accessible
      - Restarts automatically if the process exits
      - Writes to scripts\watchdog.log

    To remove:  Unregister-ScheduledTask -TaskName "STIGMA-Engine-Watchdog" -Confirm:$false
#>

$TaskName   = 'STIGMA-Engine-Watchdog'
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Watchdog   = Join-Path $ScriptDir 'watchdog.ps1'
$pwsh       = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
if (-not $pwsh) { $pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe' }

if (-not (Test-Path $Watchdog)) {
    Write-Error "watchdog.ps1 not found at $Watchdog"
    exit 1
}

# Remove existing task if present
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$action  = New-ScheduledTaskAction `
    -Execute  $pwsh `
    -Argument "-NonInteractive -WindowStyle Hidden -File `"$Watchdog`"" `
    -WorkingDirectory $ScriptDir

# Trigger: at system startup
$trigger = New-ScheduledTaskTrigger -AtStartup

# Settings: run indefinitely, restart on failure, highest privileges
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit     (New-TimeSpan -Days 3650) `
    -RestartCount           10 `
    -RestartInterval        (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable     `
    -MultipleInstances      IgnoreNew

$principal = New-ScheduledTaskPrincipal `
    -UserId    'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel  Highest

Register-ScheduledTask `
    -TaskName   $TaskName `
    -Action     $action `
    -Trigger    $trigger `
    -Settings   $settings `
    -Principal  $principal `
    -Description 'Monitors STIGMA Engine Docker stack, heals 502s and crashed containers' `
    -Force | Out-Null

# Start it now without waiting for reboot
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "✅  Watchdog installed and started." -ForegroundColor Green
Write-Host "    Task:    $TaskName"
Write-Host "    Script:  $Watchdog"
Write-Host "    Log:     $(Join-Path $ScriptDir 'watchdog.log')"
Write-Host ""
Write-Host "    To check status:  Get-ScheduledTask -TaskName '$TaskName'"
Write-Host "    To view log:      Get-Content '$(Join-Path $ScriptDir 'watchdog.log')' -Tail 50"
Write-Host "    To stop:          Stop-ScheduledTask -TaskName '$TaskName'"
Write-Host "    To remove:        Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
