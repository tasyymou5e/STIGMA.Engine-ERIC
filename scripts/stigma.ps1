#Requires -Version 5.1
<#
.SYNOPSIS
    STIGMA Engine — Docker management console

.DESCRIPTION
    Single entry-point for all STIGMA Engine Docker operations.
    Run from the project root directory.

    Usage:  pwsh -File scripts\stigma.ps1 <command> [options]

    Commands:
      start       Start all containers (build if needed)
      stop        Stop all containers (data preserved)
      restart     Restart one or all services
      rebuild     Rebuild images and redeploy
      status      Show container status and health
      logs        Tail logs from a container
      backup      Back up the MySQL database
      restore     Restore MySQL database from a backup file
      shell       Open a shell inside a container
      reset       !! DESTRUCTIVE: wipe all volumes and start fresh
      help        Show this help

    Examples:
      pwsh -File scripts\stigma.ps1 start
      pwsh -File scripts\stigma.ps1 logs engine
      pwsh -File scripts\stigma.ps1 restart webui
      pwsh -File scripts\stigma.ps1 backup
      pwsh -File scripts\stigma.ps1 status
#>

param(
    [Parameter(Position=0)]
    [ValidateSet('start','stop','restart','rebuild','status','logs','backup','restore','shell','reset','help','')]
    [string]$Command = 'help',

    [Parameter(Position=1)]
    [string]$Target = '',

    [Parameter(Position=2)]
    [string]$Extra = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Locate Docker ─────────────────────────────────────────────────────────────

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    $docker = Get-Command 'C:\Program Files\Docker\Docker\resources\bin\docker.exe' -ErrorAction SilentlyContinue
}
if (-not $docker) {
    Write-Error "docker not found. Install Docker Desktop and ensure it is running."
    exit 1
}
$dockerExe = $docker.Source

# ── Project paths ─────────────────────────────────────────────────────────────

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Compose     = Join-Path $ProjectRoot 'docker-compose.prod.yml'
$EnvFile     = Join-Path $ProjectRoot '.env.prod'
$BackupDir   = 'C:\Temp\STIGMA-Backups'

function dc {
    param([string[]]$Args)
    & $dockerExe compose --env-file $EnvFile -f $Compose @Args
}

function header([string]$text) {
    Write-Host "`n━━━  $text  ━━━" -ForegroundColor Cyan
}

function ok([string]$text)   { Write-Host "  ✓  $text" -ForegroundColor Green }
function warn([string]$text) { Write-Host "  ⚠  $text" -ForegroundColor Yellow }
function err([string]$text)  { Write-Host "  ✗  $text" -ForegroundColor Red }
function info([string]$text) { Write-Host "     $text" -ForegroundColor Gray }

# Container short-name → service name mapping
$ServiceMap = @{
    engine    = 'engine'
    webui     = 'webui'
    db        = 'engine-db'
    mysql     = 'engine-db'
    keycloak  = 'keycloak'
    kc        = 'keycloak'
    kcdb      = 'keycloak-db'
    prometheus= 'prometheus'
    grafana   = 'grafana'
    exporter  = 'mysqld-exporter'
}

function resolveService([string]$name) {
    if (-not $name) { return $null }
    $lower = $name.ToLower()
    if ($ServiceMap.ContainsKey($lower)) { return $ServiceMap[$lower] }
    return $name   # pass through as-is
}

# ── Commands ──────────────────────────────────────────────────────────────────

switch ($Command) {

    'start' {
        header "Starting STIGMA Engine"
        info "Project: $ProjectRoot"
        info "Compose: docker-compose.prod.yml"
        dc 'up', '-d', '--remove-orphans'
        Write-Host ""
        ok "Stack started. Open https://localhost in your browser."
        ok "Admin login: admin / $(Get-Content (Join-Path $ProjectRoot '.env.prod') | Select-String 'APP_USER_PW' | ForEach-Object { $_.ToString().Split('=')[1] })"
    }

    'stop' {
        header "Stopping STIGMA Engine"
        dc 'stop'
        ok "All containers stopped. Data volumes preserved."
    }

    'restart' {
        $svc = resolveService $Target
        header "Restarting $(if ($svc) { $svc } else { 'all services' })"
        if ($svc) {
            dc 'restart', $svc
            ok "Restarted: $svc"
        } else {
            dc 'restart'
            ok "All services restarted."
        }
    }

    'rebuild' {
        $svc = resolveService $Target
        header "Rebuilding $(if ($svc) { $svc } else { 'engine + webui' })"
        if ($svc) {
            dc 'build', $svc
            dc 'up', '-d', $svc
        } else {
            dc 'build', 'engine', 'webui'
            dc 'up', '-d', 'engine', 'webui'
        }
        ok "Rebuild and redeploy complete."
    }

    'status' {
        header "STIGMA Engine — Container Status"
        dc 'ps', '--format', 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'
        Write-Host ""

        # Health check
        Write-Host "  Health checks:" -ForegroundColor Cyan
        $checks = @(
            @{ Name='Engine API';   Url='https://localhost/stigman/health' }
            @{ Name='Keycloak';     Url='https://localhost/kc/health' }
            @{ Name='Grafana';      Url='https://localhost/grafana/api/health' }
        )
        foreach ($c in $checks) {
            try {
                $r = Invoke-WebRequest -Uri $c.Url -SkipCertificateCheck -TimeoutSec 5 -ErrorAction Stop
                ok "$($c.Name): HTTP $($r.StatusCode)"
            } catch {
                err "$($c.Name): unreachable — $($_.Exception.Message.Split([Environment]::NewLine)[0])"
            }
        }

        # Disk usage
        Write-Host ""
        Write-Host "  Volumes:" -ForegroundColor Cyan
        & $dockerExe system df --format 'table {{.Type}}\t{{.Size}}\t{{.Reclaimable}}' 2>$null
    }

    'logs' {
        $svc = resolveService $Target
        if (-not $svc) { $svc = 'engine' }
        $lines = if ($Extra) { $Extra } else { '100' }
        header "Logs: $svc (last $lines lines, Ctrl+C to exit)"
        dc 'logs', '--tail', $lines, '-f', $svc
    }

    'backup' {
        header "Database Backup"
        New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
        $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm'
        $file  = Join-Path $BackupDir "stigma-backup-$stamp.sql"

        $rootPw = (Get-Content $EnvFile | Select-String 'MYSQL_ROOT_PW').ToString().Split('=',2)[1].Trim()

        info "Dumping stigman_engine to $file ..."
        & $dockerExe exec stigma-prod-engine-db-1 `
            mysqldump -u root "-p$rootPw" stigman_engine | Out-File -FilePath $file -Encoding UTF8

        $size = [Math]::Round((Get-Item $file).Length / 1KB, 1)
        ok "Backup complete: $file ($size KB)"
        info "Restore with: pwsh -File scripts\stigma.ps1 restore `"$file`""
    }

    'restore' {
        if (-not $Target -or -not (Test-Path $Target)) {
            err "Provide a backup file path: pwsh -File scripts\stigma.ps1 restore <path-to-.sql>"
            exit 1
        }
        header "Database Restore"
        warn "This will OVERWRITE the current database. Press Ctrl+C to cancel."
        Start-Sleep -Seconds 5

        $rootPw = (Get-Content $EnvFile | Select-String 'MYSQL_ROOT_PW').ToString().Split('=',2)[1].Trim()
        info "Restoring from $Target ..."
        Get-Content $Target | & $dockerExe exec -i stigma-prod-engine-db-1 `
            mysql -u root "-p$rootPw" stigman_engine

        ok "Restore complete. Restart the engine: pwsh -File scripts\stigma.ps1 restart engine"
    }

    'shell' {
        $svc = resolveService $Target
        if (-not $svc) { $svc = 'engine' }
        header "Shell: $svc"
        $containerName = "stigma-prod-${svc}-1"
        & $dockerExe exec -it $containerName /bin/sh
    }

    'reset' {
        header "!! DESTRUCTIVE RESET !!"
        err "This will DELETE all data volumes (database, Keycloak, Grafana)."
        warn "Type 'YES' to confirm, or press Ctrl+C to cancel:"
        $confirm = Read-Host
        if ($confirm -ne 'YES') { info "Cancelled."; exit 0 }

        dc 'down', '-v', '--remove-orphans'
        ok "All containers and volumes removed."
        info "Run: pwsh -File scripts\stigma.ps1 start   to start fresh."
    }

    default {
        Write-Host @"

  ╔══════════════════════════════════════════════════╗
  ║       STIGMA Engine — Docker Management          ║
  ╚══════════════════════════════════════════════════╝

  Usage:  pwsh -File scripts\stigma.ps1 <command> [target]

  COMMANDS
  ────────────────────────────────────────────────────
  start              Start all containers
  stop               Stop all containers (data kept)
  restart [service]  Restart one or all services
  rebuild [service]  Rebuild images and redeploy
  status             Container health dashboard
  logs [service]     Tail container logs (default: engine)
  backup             Dump MySQL to C:\Temp\STIGMA-Backups\
  restore <file>     Restore MySQL from a .sql backup
  shell [service]    Interactive shell inside a container
  reset              !! Wipe all data and start fresh !!

  SERVICE ALIASES
  ────────────────────────────────────────────────────
  engine  webui  db  keycloak  kc  grafana  prometheus

  EXAMPLES
  ────────────────────────────────────────────────────
  pwsh -File scripts\stigma.ps1 start
  pwsh -File scripts\stigma.ps1 status
  pwsh -File scripts\stigma.ps1 logs engine
  pwsh -File scripts\stigma.ps1 restart webui
  pwsh -File scripts\stigma.ps1 rebuild
  pwsh -File scripts\stigma.ps1 backup

"@ -ForegroundColor White
    }
}
