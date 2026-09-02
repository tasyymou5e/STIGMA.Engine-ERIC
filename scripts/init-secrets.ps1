#Requires -Version 5.1
<#
.SYNOPSIS
    Reads .env.prod and writes each sensitive credential to a secrets/ file.
    Run this ONCE before "docker compose ... up" to populate the secrets directory.

.EXAMPLE
    .\scripts\init-secrets.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvFile     = Join-Path $ProjectRoot '.env.prod'
$SecretsDir  = Join-Path $ProjectRoot 'secrets'

# --- Verify .env.prod exists ---
if (-not (Test-Path $EnvFile)) {
    Write-Error ".env.prod not found at: $EnvFile"
    exit 1
}

# --- Create secrets/ directory if needed ---
if (-not (Test-Path $SecretsDir)) {
    New-Item -ItemType Directory -Path $SecretsDir | Out-Null
    Write-Host "Created directory: $SecretsDir"
}

# --- Map .env.prod variable names -> secret file names ---
$SecretMap = @{
    'MYSQL_PW'      = 'mysql_pw.txt'
    'MYSQL_ROOT_PW' = 'mysql_root_pw.txt'
    'KC_ADMIN_PW'   = 'kc_admin_pw.txt'
    'KC_DB_PW'      = 'kc_db_pw.txt'
}

# --- Parse .env.prod ---
$EnvVars = @{}
foreach ($line in (Get-Content $EnvFile)) {
    # Skip blank lines and comments
    if ($line -match '^\s*$' -or $line -match '^\s*#') { continue }
    if ($line -match '^([^=]+)=(.*)$') {
        $EnvVars[$Matches[1].Trim()] = $Matches[2].Trim()
    }
}

# --- Write each secret file ---
$Written = 0
foreach ($envKey in $SecretMap.Keys) {
    if (-not $EnvVars.ContainsKey($envKey)) {
        Write-Warning "Key '$envKey' not found in .env.prod — skipping."
        continue
    }

    $destFile = Join-Path $SecretsDir $SecretMap[$envKey]

    # If a directory was accidentally created at this path, remove it first.
    if (Test-Path $destFile) {
        if ((Get-Item $destFile) -is [System.IO.DirectoryInfo]) {
            Remove-Item $destFile -Recurse -Force
            Write-Warning "Removed accidental directory at: $destFile"
        }
    }

    # Write without trailing newline (Docker reads the raw bytes)
    [System.IO.File]::WriteAllText($destFile, $EnvVars[$envKey])

    # Verify the result is a file, not a directory.
    if ((Get-Item $destFile) -is [System.IO.DirectoryInfo]) {
        Remove-Item $destFile -Recurse -Force
        [System.IO.File]::WriteAllText($destFile, $EnvVars[$envKey])
        if ((Get-Item $destFile) -is [System.IO.DirectoryInfo]) {
            Write-Error "Failed to create file (still a directory): $destFile"
        }
    }

    # --- Restrict permissions: owner (current user) read/write only ---
    # Remove inherited ACEs, then grant current user FullControl only.
    $acl = Get-Acl $destFile
    $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, clear inherited
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity, 'FullControl', 'None', 'None', 'Allow'
    )
    $acl.SetAccessRule($rule)
    Set-Acl -Path $destFile -AclObject $acl

    Write-Host "  Wrote: $($SecretMap[$envKey])"
    $Written++
}

Write-Host ""
Write-Host "Done. $Written secret file(s) written to: $SecretsDir"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Verify secrets/ is listed in .gitignore (never commit these files)."
Write-Host "  2. Start the stack:"
Write-Host "       docker compose --env-file .env.prod -f docker-compose.prod.yml up --build -d"
