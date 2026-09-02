#requires -Version 7.0
# ==============================================================================
# Invoke-DefaultUserHiveRemediation.ps1
# Bakes HKCU-scoped STIG settings into C:\Users\Default\NTUSER.DAT so that every
# new user session on a VDI / AVD pooled host inherits them automatically.
#
# WHY THIS IS NEEDED:
#   Invoke-StigCklRemediation.ps1 applies HKCU settings only to the currently
#   logged-on user. On non-persistent (pooled) VDI/AVD hosts the user profile is
#   discarded at logoff, so settings must be pre-baked into the Default user hive
#   before sealing the gold image.
#
# HOW IT WORKS:
#   1. Loads C:\Users\Default\NTUSER.DAT under a temporary HKLM mount point.
#   2. Remaps every HKCU:\ path to HKLM:\STIG_DefaultUser\.
#   3. Applies the same registry items Get-StigRegistryItems extracts.
#   4. Forces GC to release open handles, then unloads the hive cleanly.
#
# REQUIRES: PowerShell 7.0+ (Windows). Will NOT run on Windows PowerShell 5.1.
#           Auto-elevates to Administrator via pwsh if needed.
#
# Usage:
#   .\Invoke-DefaultUserHiveRemediation.ps1
#   .\Invoke-DefaultUserHiveRemediation.ps1 -DefaultHivePath "E:\Profiles\Default\NTUSER.DAT"
#   .\Invoke-DefaultUserHiveRemediation.ps1 -WhatIf
#
# Prerequisites: No other process may have the default profile loaded. Close
#   Registry Editor before running.
# ==============================================================================

[CmdletBinding()]
param (
    [string]$CklDirectory    = $PSScriptRoot,
    [string]$LogDirectory    = "$PSScriptRoot\Logs",
    [string]$DefaultHivePath = "C:\Users\Default\NTUSER.DAT",
    [switch]$WhatIf
)

# ---------------------------------
# --- MODULE IMPORT + BOOTSTRAP
# ---------------------------------
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
Import-Module (Join-Path $ScriptDir 'STIG-CKL-Helpers.psm1') -Force -ErrorAction Stop

# Windows+PS7 guard, process Bypass exec policy, self-elevate via pwsh (forwards params).
if (-not (Initialize-StigEnvironment -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters)) { exit 0 }

if (-not $CklDirectory) { $CklDirectory = $ScriptDir }
if (-not $LogDirectory) { $LogDirectory = Join-Path $ScriptDir 'Logs' }

# ---------------------------------
# --- CONFIGURATION
# ---------------------------------
$TempHiveMount  = "STIG_DefaultUser"          # Temporary HKLM key name
$TempHivePSRoot = "HKLM:\$TempHiveMount"      # PowerShell path prefix for the mount
$RunTimestamp   = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$LogFile        = "$LogDirectory\DefaultHive_$RunTimestamp.log"

if (!(Test-Path $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
Start-Transcript -Path $LogFile -Append

# ---------------------------------
# --- HELPERS
# ---------------------------------
$script:LogLines = [System.Collections.Generic.List[string]]::new()

function Write-DhLog {
    param([string]$Message, [string]$Color = "Gray")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $Message"
    $script:LogLines.Add($line)
    Write-Host $line -ForegroundColor $Color
}

# Writes one value into the mounted default hive, remapping HKCU: -> mount root.
function Set-DefaultHiveValue {
    param(
        [string]$HkcuPath,            # Original HKCU:\ path from the finding
        [string]$Name,
        $Value,
        [string]$PropertyType,
        [string]$VulnNum = ""
    )
    $tag        = if ($VulnNum) { " [$VulnNum]" } else { "" }
    $mappedPath = $HkcuPath -replace '^HKCU:', $TempHivePSRoot

    if ($WhatIf) {
        Write-DhLog "WHATIF: $Name = $Value ($PropertyType) at $mappedPath$tag" "Cyan"
        return
    }
    try {
        if (!(Test-Path $mappedPath)) {
            New-Item -Path $mappedPath -Force -ErrorAction Stop | Out-Null
            Write-DhLog "Created: $mappedPath" "Gray"
        }
        Set-ItemProperty -Path $mappedPath -Name $Name -Value $Value -Type $PropertyType -Force -ErrorAction Stop
        $current = (Get-ItemProperty -Path $mappedPath -Name $Name -ErrorAction SilentlyContinue).$Name
        if ("$current" -eq "$Value") {
            Write-DhLog "[SUCCESS] $Name = $Value at $mappedPath$tag" "Green"
        } else {
            Write-DhLog "[CONFLICT] $Name written but reads back '$current' (expected '$Value')$tag" "Yellow"
        }
    } catch {
        Write-DhLog "[ERROR] $Name at $mappedPath$tag : $($_.Exception.Message)" "Red"
    }
}

# ---------------------------------
# --- VALIDATE DEFAULT HIVE EXISTS
# ---------------------------------
if (!(Test-Path $DefaultHivePath)) {
    Write-Error "Default user hive not found at '$DefaultHivePath'. Specify -DefaultHivePath."
    Stop-Transcript; exit 1
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " STIG Default User Hive Remediation" -ForegroundColor Cyan
Write-Host " Target hive : $DefaultHivePath" -ForegroundColor Cyan
Write-Host " Mount point : HKLM\$TempHiveMount" -ForegroundColor Cyan
if ($WhatIf) { Write-Host " [WHATIF - no changes will be made]" -ForegroundColor Yellow }
Write-Host "============================================================`n" -ForegroundColor Cyan

# ---------------------------------
# --- COLLECT HKCU ITEMS FROM CKLS
# ---------------------------------
$CklFiles = Get-CklFileList -Directory $CklDirectory
if (-not $CklFiles) {
    Write-Error "No CKL files found in '$CklDirectory'."; Stop-Transcript; exit 1
}

# Aggregate all HKCU items across every CKL, deduplicated by path+name.
$hkcuItems = [System.Collections.Generic.Dictionary[string, hashtable]]::new()

foreach ($f in $CklFiles) {
    $findings = Get-CklFindings -Path $f.FullName -Status Open
    foreach ($finding in $findings) {
        foreach ($item in $finding.RegistryItems) {
            if ($item.Path -notlike 'HKCU:*') { continue }
            $k = "$($item.Path)|$($item.Name)"
            if (-not $hkcuItems.ContainsKey($k)) {
                $hkcuItems[$k] = @{
                    Path     = $item.Path
                    Name     = $item.Name
                    Value    = $item.Value
                    Type     = $item.Type
                    VulnNum  = $finding.VulnNum
                    StigFile = (Split-Path $f.FullName -Leaf)
                }
            }
        }
    }
}

if ($hkcuItems.Count -eq 0) {
    Write-Host "[INFO] No HKCU-scoped STIG items found across the provided CKL files. Nothing to do." -ForegroundColor Yellow
    Stop-Transcript; exit 0
}

Write-DhLog "Found $($hkcuItems.Count) unique HKCU registry items to bake into default profile." "Cyan"

# ---------------------------------
# --- LOAD DEFAULT USER HIVE
# ---------------------------------
Write-DhLog "Loading hive: reg load HKLM\$TempHiveMount `"$DefaultHivePath`"" "Cyan"

# Abort if mount point already exists (leftover from a previous failed run).
if (Test-Path $TempHivePSRoot) {
    Write-DhLog "[WARN] Mount point HKLM\$TempHiveMount already exists. Attempting cleanup..." "Yellow"
    [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); Start-Sleep -Seconds 2
    & reg.exe unload "HKLM\$TempHiveMount" 2>&1 | Out-Null
    if (Test-Path $TempHivePSRoot) {
        Write-Error "Cannot unload existing mount point. Close Registry Editor and retry."; Stop-Transcript; exit 1
    }
}

$loadResult = & reg.exe load "HKLM\$TempHiveMount" $DefaultHivePath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "reg.exe load failed: $loadResult"
    Stop-Transcript; exit 1
}
Write-DhLog "Hive loaded successfully." "Green"

# ---------------------------------
# --- APPLY SETTINGS
# ---------------------------------
$applied = 0; $errors = 0

try {
    foreach ($item in $hkcuItems.Values) {
        Set-DefaultHiveValue `
            -HkcuPath     $item.Path `
            -Name         $item.Name `
            -Value        $item.Value `
            -PropertyType $item.Type `
            -VulnNum      $item.VulnNum
        $applied++
    }
} catch {
    Write-DhLog "[ERROR] Unexpected error during apply: $($_.Exception.Message)" "Red"
    $errors++
} finally {
    # --- UNLOAD HIVE (always runs) ---
    Write-DhLog "Flushing handles and unloading hive..." "Cyan"
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 3   # give regapi a moment to release internal handles

    $unloadResult = & reg.exe unload "HKLM\$TempHiveMount" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-DhLog "Hive unloaded cleanly." "Green"
    } else {
        Write-DhLog "[WARN] reg.exe unload returned non-zero: $unloadResult" "Yellow"
        Write-DhLog "       You may need to unload manually: reg unload HKLM\$TempHiveMount" "Yellow"
    }
}

# ---------------------------------
# --- SUMMARY
# ---------------------------------
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Default User Hive Remediation Complete" -ForegroundColor Cyan
Write-Host "  Items applied : $applied" -ForegroundColor Green
Write-Host "  Errors        : $errors"  -ForegroundColor $(if ($errors -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Log           : $LogFile" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

Stop-Transcript
