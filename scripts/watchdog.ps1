#Requires -Version 5.1
<#
.SYNOPSIS
    STIGMA Engine stack watchdog — runs in background, heals 502s and crashed containers.

.DESCRIPTION
    Every cycle (default 60s) this script:
      1. Checks that every required container is running.  Starts any that have stopped.
      2. Probes https://localhost/stigman/api/health — if 502, the nginx upstream is stale;
         restarts the webui container so nginx picks up the new container IPs.
      3. Logs all events to scripts\watchdog.log (rolling 10,000-line cap).

.NOTES
    Run manually:  pwsh -File scripts\watchdog.ps1
    Install task:  pwsh -File scripts\setup-watchdog.ps1
#>

param(
    [int]$IntervalSeconds  = 60,
    [int]$MaxLogLines      = 10000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Paths ──────────────────────────────────────────────────────────────────────
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$Compose     = Join-Path $ProjectRoot 'docker-compose.prod.yml'
$EnvFile     = Join-Path $ProjectRoot '.env.prod'
$LogFile     = Join-Path $ScriptDir   'watchdog.log'
$Docker      = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'

# ── Containers that must always be running ─────────────────────────────────────
$RequiredContainers = @(
    'stigma-prod-engine-1',
    'stigma-prod-engine-db-1',
    'stigma-prod-webui-1',
    'stigma-prod-keycloak-1',
    'stigma-prod-keycloak-db-1',
    'stigma-prod-prometheus-1',
    'stigma-prod-grafana-1'
)

# ── Health endpoint ────────────────────────────────────────────────────────────
$HealthUrl = 'https://localhost/stigman/health'

# ── Logging ───────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Level, [string]$Message)
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8

    # Rolling cap — trim oldest lines when file gets large
    try {
        $lines = Get-Content $LogFile
        if ($lines.Count -gt $MaxLogLines) {
            $lines | Select-Object -Last ($MaxLogLines - 500) | Set-Content $LogFile -Encoding UTF8
        }
    } catch {}
}

# ── Docker helpers ─────────────────────────────────────────────────────────────
function Get-RunningContainers {
    $raw = & $Docker ps --format '{{.Names}}' 2>$null
    return @($raw)
}

function Start-StackService {
    param([string]$ServiceSuffix)
    # Extract service name from container name (stigma-prod-engine-1 -> engine)
    $svc = $ServiceSuffix -replace '^stigma-prod-' -replace '-\d+$'
    Write-Log 'HEAL' "Starting service: $svc"
    & $Docker compose --project-directory $ProjectRoot `
        --env-file $EnvFile -f $Compose `
        up -d $svc 2>&1 | Out-Null
}

function Restart-Webui {
    Write-Log 'HEAL' 'Restarting webui to refresh nginx upstream DNS...'
    & $Docker compose --project-directory $ProjectRoot `
        --env-file $EnvFile -f $Compose `
        restart webui 2>&1 | Out-Null
    Start-Sleep -Seconds 5
}

# ── Health probe ───────────────────────────────────────────────────────────────
function Test-ApiHealth {
    try {
        $r = Invoke-WebRequest $HealthUrl -UseBasicParsing -SkipCertificateCheck `
                               -TimeoutSec 8 -Method GET
        return $r.StatusCode
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        return if ($code) { [int]$code } else { 0 }
    }
}

# ── Main loop ─────────────────────────────────────────────────────────────────
Write-Log 'INFO' "Watchdog started (interval=${IntervalSeconds}s, project=$ProjectRoot)"

$consecutiveFails    = 0
$lastWebUiRestartAt  = [datetime]::MinValue

while ($true) {
    $env:PATH = "C:\Program Files\Docker\Docker\resources\bin;" + $env:PATH

    # ── 1. Container presence check ──────────────────────────────────────────
    $running = Get-RunningContainers
    foreach ($name in $RequiredContainers) {
        if ($name -notin $running) {
            Write-Log 'WARN' "Container not running: $name — attempting start"
            Start-StackService $name
        }
    }

    # ── 2. HTTP health probe ──────────────────────────────────────────────────
    $status = Test-ApiHealth

    if ($status -eq 200) {
        if ($consecutiveFails -gt 0) {
            Write-Log 'INFO' "Health restored after $consecutiveFails failed probe(s)"
        }
        $consecutiveFails = 0
    } elseif ($status -eq 502) {
        $consecutiveFails++
        Write-Log 'WARN' "502 Bad Gateway (probe #$consecutiveFails) — nginx upstream stale"

        # Don't restart more than once per 90 seconds to avoid a restart loop
        $cooldown = ([datetime]::Now - $lastWebUiRestartAt).TotalSeconds
        if ($cooldown -gt 90) {
            Restart-Webui
            $lastWebUiRestartAt = [datetime]::Now
            $consecutiveFails   = 0
        } else {
            Write-Log 'INFO' "Cooldown active ($([int]$cooldown)s / 90s) — skipping restart"
        }
    } elseif ($status -eq 0) {
        $consecutiveFails++
        Write-Log 'WARN' "Health probe timed out / unreachable (probe #$consecutiveFails)"
    } else {
        Write-Log 'INFO' "Health probe returned HTTP $status"
        $consecutiveFails = 0
    }

    # ── 3. Alert on sustained failure ────────────────────────────────────────
    if ($consecutiveFails -ge 5) {
        Write-Log 'ERROR' "5+ consecutive probe failures — attempting full stack restart"
        & $Docker compose --project-directory $ProjectRoot `
            --env-file $EnvFile -f $Compose `
            up -d 2>&1 | Out-Null
        $consecutiveFails   = 0
        $lastWebUiRestartAt = [datetime]::Now
    }

    Start-Sleep -Seconds $IntervalSeconds
}
