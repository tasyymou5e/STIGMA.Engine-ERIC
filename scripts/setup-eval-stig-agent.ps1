<#
.SYNOPSIS
    Installs the STIGMA EvalStig Agent as a Windows Scheduled Task.

.DESCRIPTION
    Creates a task named "STIGMA-EvalStig-Agent" that:
      - Launches eval-stig-agent.ps1 at user login (no admin required)
      - Runs as the current user
      - Restarts automatically if the process exits
      - Writes to scripts\eval-stig-agent.log

    Uses schtasks.exe so no elevated privileges are required.

    To remove:
        schtasks /Delete /TN "STIGMA-EvalStig-Agent" /F

.NOTES
    Run: pwsh -File scripts\setup-eval-stig-agent.ps1
#>

$TaskName  = 'STIGMA-EvalStig-Agent'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentScript = Join-Path $ScriptDir 'eval-stig-agent.ps1'
$LogFile     = Join-Path $ScriptDir 'eval-stig-agent.log'

$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
if (-not $pwsh) { $pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe' }

if (-not (Test-Path $AgentScript)) {
    Write-Error "eval-stig-agent.ps1 not found at $AgentScript"
    exit 1
}

if (-not (Test-Path $pwsh)) {
    Write-Error "PowerShell 7 not found at $pwsh"
    exit 1
}

# ── Remove existing task if present ───────────────────────────────────────────
schtasks /Delete /TN $TaskName /F 2>$null | Out-Null

# ── Build the action command line ──────────────────────────────────────────────
# schtasks does not support -RedirectStandardOutput, so we wrap in a cmd /c
# to redirect stdout+stderr to the log file.
$taskCmd = "`"$pwsh`" -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$AgentScript`""

# ── Create the scheduled task (at logon, current user, no admin) ───────────────
$result = schtasks /Create `
    /TN  $TaskName `
    /TR  $taskCmd `
    /SC  ONLOGON `
    /IT `
    /F `
    /RL  LIMITED `
    /DELAY "0001:00" 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Error "schtasks /Create failed:`n$result"
    exit 1
}

# ── Optionally: set restart-on-failure via XML edit ───────────────────────────
# schtasks /Create does not expose RestartInterval directly.
# Export, patch, re-import.
$xmlPath = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.xml'
schtasks /Query /TN $TaskName /XML ONE | Set-Content -Path $xmlPath -Encoding UTF8

$xml = [xml](Get-Content $xmlPath -Raw)
$ns  = 'http://schemas.microsoft.com/windows/2004/02/mit/task'

# ---- Settings node: restart on failure, 10 retries, 1-minute interval -------
$settings = $xml.Task.Settings
if ($settings) {
    # RestartOnFailure
    $rof = $xml.CreateElement('RestartOnFailure', $ns)
    $int = $xml.CreateElement('Interval',          $ns);  $int.InnerText  = 'PT1M'
    $cnt = $xml.CreateElement('Count',             $ns);  $cnt.InnerText  = '10'
    $rof.AppendChild($int) | Out-Null
    $rof.AppendChild($cnt) | Out-Null
    $settings.AppendChild($rof) | Out-Null

    # ExecutionTimeLimit: no limit (PT0S = indefinite for schtasks XML)
    if ($settings.ExecutionTimeLimit) {
        $settings.ExecutionTimeLimit = 'PT0S'
    } else {
        $etl = $xml.CreateElement('ExecutionTimeLimit', $ns); $etl.InnerText = 'PT0S'
        $settings.AppendChild($etl) | Out-Null
    }
}

$xml.Save($xmlPath)
schtasks /Delete /TN $TaskName /F 2>$null | Out-Null
$reimport = schtasks /Create /TN $TaskName /XML $xmlPath /F 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Could not apply restart-on-failure settings (non-fatal): $reimport"
    # Re-create without XML if import failed
    schtasks /Create `
        /TN  $TaskName `
        /TR  $taskCmd `
        /SC  ONLOGON `
        /IT `
        /F `
        /RL  LIMITED `
        /DELAY "0001:00" | Out-Null
}
Remove-Item $xmlPath -ErrorAction SilentlyContinue

# ── Start the task now without waiting for next login ─────────────────────────
schtasks /Run /TN $TaskName 2>&1 | Out-Null

Write-Host ""
Write-Host "EvalStig Agent installed and started." -ForegroundColor Green
Write-Host "    Task   : $TaskName"
Write-Host "    Script : $AgentScript"
Write-Host "    Log    : $LogFile"
Write-Host ""
Write-Host "    To check status : schtasks /Query /TN `"$TaskName`" /FO LIST"
Write-Host "    To view log     : Get-Content '$LogFile' -Tail 50"
Write-Host "    To stop         : schtasks /End /TN `"$TaskName`""
Write-Host "    To remove       : schtasks /Delete /TN `"$TaskName`" /F"
