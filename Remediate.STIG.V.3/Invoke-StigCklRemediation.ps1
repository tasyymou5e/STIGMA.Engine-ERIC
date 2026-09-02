#requires -Version 7.0
# ==============================================================================
# Invoke-StigCklRemediation.ps1
# STIG CKL Auto-Remediation Engine
#
# Enumerates Open findings across all checklist files (.cklb JSON or legacy
# *_ckl.txt/.ckl/.xml), parses registry remediation items using the shared
# module parser, applies them, runs a few command-line remediations (event-log
# sizing), and writes per-file logs plus a master transcript.
#
# REQUIRES: PowerShell 7.0+ (Windows). Will NOT run on Windows PowerShell 5.1.
#           Auto-elevates to Administrator via pwsh if needed.
#
# Usage:
#   .\Invoke-StigCklRemediation.ps1
#   .\Invoke-StigCklRemediation.ps1 -CklDirectory "D:\STIGS\CKLs" -LogDirectory "D:\Logs\STIG"
#   .\Invoke-StigCklRemediation.ps1 -WhatIf        # dry run - applies nothing
#
# Note: HKCU settings apply to the currently logged-on user; for VDI/AVD
#       deployments bake them into the default user hive
#       (Invoke-DefaultUserHiveRemediation.ps1) or distribute via GPO.
# ==============================================================================

[CmdletBinding()]
param (
    [string]$CklDirectory = $PSScriptRoot,
    [string]$LogDirectory = "$PSScriptRoot\Logs",
    [switch]$WhatIf
)

# ---------------------------------
# --- MODULE IMPORT + BOOTSTRAP
# ---------------------------------
# Resolve the script directory defensively ($PSScriptRoot can be empty when a
# script is dot-sourced or pasted) so module import and default paths still work.
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
Import-Module (Join-Path $ScriptDir 'STIG-CKL-Helpers.psm1') -Force -ErrorAction Stop

# Windows+PS7 guard, process-scoped Bypass execution policy (local + remoting),
# and self-elevation via pwsh forwarding all params (incl. -WhatIf). Returns
# $false only after launching an elevated copy - in which case we exit.
if (-not (Initialize-StigEnvironment -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters)) { exit 0 }

# Normalize paths (covers the empty-$PSScriptRoot edge case).
if (-not $CklDirectory) { $CklDirectory = $ScriptDir }
if (-not $LogDirectory) { $LogDirectory = Join-Path $ScriptDir 'Logs' }

# ---------------------------------
# --- SCRIPT CONFIGURATION
# ---------------------------------
$ScriptVersion = "2.8"
$RunTimestamp  = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$MasterLog     = "$LogDirectory\Master_$RunTimestamp.log"
$StigSummary   = [System.Collections.Generic.List[pscustomobject]]::new()

if (!(Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

Start-Transcript -Path $MasterLog -Append

# ---------------------------------
# --- HELPER FUNCTIONS (script-local)
# ---------------------------------
# NOTE: the registry parser, CKL reader, and type/path converters now live in
# STIG-CKL-Helpers.psm1 (single source of truth). Only remediation-specific
# helpers remain here.

# Per-file log line buffer (reset for each CKL)
$script:FileLogBuffer = [System.Collections.Generic.List[string]]::new()

function Write-StigLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARN", "ERROR", "CMD", "MANUAL", "SECTION")]
        [string]$Level = "INFO"
    )
    $ts   = Get-Date -Format "HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    $script:FileLogBuffer.Add($line)
    switch ($Level) {
        "SUCCESS" { Write-Host $line -ForegroundColor Green   }
        "WARN"    { Write-Host $line -ForegroundColor Yellow  }
        "ERROR"   { Write-Host $line -ForegroundColor Red     }
        "CMD"     { Write-Host $line -ForegroundColor Cyan    }
        "MANUAL"  { Write-Host $line -ForegroundColor Magenta }
        "SECTION" { Write-Host $line -ForegroundColor Cyan    }
        default   { Write-Host $line -ForegroundColor Gray    }
    }
}

# Sets a registry value, verifies the write, and flags likely GPO conflicts.
function Set-StigRegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$PropertyType = "DWord",
        [string]$VulnNum = ""
    )
    $tag = if ($VulnNum) { " [$VulnNum]" } else { "" }
    if ($WhatIf) {
        Write-StigLog "WHATIF: Would set '$Name' = '$Value' ($PropertyType) at '$Path'$tag" "INFO"
        return
    }
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            Write-StigLog "Created registry path: $Path$tag" "INFO"
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $PropertyType -Force -ErrorAction Stop
        $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ("$CurrentValue" -eq "$Value") {
            Write-StigLog "Set '$Name' = '$Value' at '$Path'$tag" "SUCCESS"
        } else {
            Write-StigLog "CONFLICT: '$Name' written but current='$CurrentValue', expected='$Value' at '$Path'. GPO may override.$tag" "WARN"
        }
    } catch {
        Write-StigLog "Failed to set '$Name' at '$Path'$tag : $($_.Exception.Message)" "ERROR"
    }
}

# Executes an audit/command-line tool and logs the action.
function Invoke-StigCommand {
    param(
        [string]$Command,
        [string]$Arguments,
        [string]$VulnNum = ""
    )
    $tag = if ($VulnNum) { " [$VulnNum]" } else { "" }
    if ($WhatIf) {
        Write-StigLog "WHATIF: Would execute: $Command $Arguments$tag" "INFO"
        return
    }
    try {
        Write-StigLog "Executing: $Command $Arguments$tag" "CMD"
        Start-Process -FilePath $Command -ArgumentList $Arguments -Wait -NoNewWindow -ErrorAction Stop
        Write-StigLog "Executed: $Command $Arguments$tag" "SUCCESS"
    } catch {
        Write-StigLog "Failed to execute '$Command $Arguments'$tag : $($_.Exception.Message)" "ERROR"
    }
}

# ==============================================================================
# --- MAIN SCRIPT
# ==============================================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " STIG CKL Auto-Remediation Engine  v$ScriptVersion" -ForegroundColor Cyan
Write-Host " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
if ($WhatIf) { Write-Host " [WHATIF MODE - No changes will be made]" -ForegroundColor Yellow }
Write-Host "============================================================`n" -ForegroundColor Cyan

# Discover CKL files (module helper - fixes the -Include fallback bug).
$CklFiles = Get-CklFileList -Directory $CklDirectory
if (-not $CklFiles) {
    Write-Error "No CKL files found in '$CklDirectory'. Exiting."
    Stop-Transcript
    exit 1
}

Write-Host "Found $($CklFiles.Count) CKL file(s) in '$CklDirectory'`n" -ForegroundColor Yellow

# ==============================================================================
# Per-file processing loop
# ==============================================================================
foreach ($CklFile in $CklFiles) {

    $script:FileLogBuffer = [System.Collections.Generic.List[string]]::new()
    $FileLog  = "$LogDirectory\$($CklFile.BaseName)_remediation.log"
    $counters = @{ Applied = 0; Manual = 0; Skipped = 0; Error = 0 }

    Write-StigLog "============================================================" "SECTION"
    Write-StigLog "Processing: $($CklFile.Name)" "SECTION"
    Write-StigLog "============================================================" "SECTION"

    # --- Parse (module handles both .cklb JSON and legacy XML) ---
    $AllFindings = Get-CklFindings -Path $CklFile.FullName -Status All
    if (-not $AllFindings -or @($AllFindings).Count -eq 0) {
        Write-StigLog "Parse failed or no findings for '$($CklFile.Name)'." "ERROR"
        $script:FileLogBuffer | Out-File -FilePath $FileLog -Encoding UTF8
        continue
    }

    # --- Extract STIG metadata (uniform across every finding in the file) ---
    $StigTitle   = $AllFindings[0].StigTitle   ?? $CklFile.BaseName
    $StigVersion = $AllFindings[0].StigRelease ?? 'unknown'
    $HostName    = $AllFindings[0].HostName

    Write-StigLog "STIG   : $StigTitle"   "INFO"
    Write-StigLog "Release: $StigVersion" "INFO"
    Write-StigLog "Host   : $HostName"    "INFO"

    # --- Gather Open findings ---
    $OpenVulns  = @($AllFindings | Where-Object { $_.Status -eq 'Open' })
    $TotalVulns = @($AllFindings).Count
    $OpenCount  = $OpenVulns.Count

    Write-StigLog "Findings: $TotalVulns total, $OpenCount Open" "INFO"

    if ($OpenCount -eq 0) {
        Write-StigLog "No Open findings in this CKL. Nothing to do." "SUCCESS"
        $script:FileLogBuffer | Out-File -FilePath $FileLog -Encoding UTF8
        $StigSummary.Add([pscustomobject]@{
            File = $CklFile.Name; Title = $StigTitle
            Open = 0; Applied = 0; Manual = 0; Skipped = 0
        })
        continue
    }

    # --- Process each Open finding ---
    foreach ($finding in $OpenVulns) {

        $VulnNum  = $finding.VulnNum      ?? 'UNKNOWN'
        $RuleVer  = $finding.RuleVer      ?? ''
        $Severity = $finding.Severity     ?? 'unknown'
        $Title    = $finding.RuleTitle    ?? ''
        $CheckCC  = $finding.CheckContent ?? ''
        $FixText  = $finding.FixText      ?? ''

        Write-StigLog "" "INFO"
        Write-StigLog "--- $VulnNum ($RuleVer) [CAT $(if ($Severity -eq 'high') {'I'} elseif ($Severity -eq 'medium') {'II'} else {'III'})] ---" "SECTION"
        Write-StigLog "$Title" "INFO"

        # ----------------------------------------------------------------------
        # Special-case findings remediated by a command-line tool, not registry.
        # Event-log sizes use wevtutil. /ms is in BYTES.
        #   WN11-AU-000500 Application : >= 32768 KB  -> 33554432 bytes
        #   WN11-AU-000502 System      : >= 32768 KB  -> 33554432 bytes
        #   WN11-AU-000505 Security    : >= 1024000 KB -> 1048576000 bytes
        # (App/System were previously set to 32768000 = 32000 KB, which is BELOW
        #  the 32768 KB STIG minimum; corrected to 33554432.)
        # ----------------------------------------------------------------------
        $isCommandFinding = $false
        switch -Regex ($RuleVer) {
            'WN11-AU-000505' {
                Write-StigLog "Applying via wevtutil (Security log max size = 1024000 KB)" "CMD"
                Invoke-StigCommand -Command "wevtutil" -Arguments 'sl "Security" /ms:1048576000' -VulnNum $VulnNum
                $counters.Applied++; $isCommandFinding = $true; break
            }
            'WN11-AU-000500' {
                Write-StigLog "Applying via wevtutil (Application log max size = 32768 KB)" "CMD"
                Invoke-StigCommand -Command "wevtutil" -Arguments 'sl "Application" /ms:33554432' -VulnNum $VulnNum
                $counters.Applied++; $isCommandFinding = $true; break
            }
            'WN11-AU-000502' {
                Write-StigLog "Applying via wevtutil (System log max size = 32768 KB)" "CMD"
                Invoke-StigCommand -Command "wevtutil" -Arguments 'sl "System" /ms:33554432' -VulnNum $VulnNum
                $counters.Applied++; $isCommandFinding = $true; break
            }
        }
        if ($isCommandFinding) { continue }

        # Non-remediable via script (hardware, firmware, manual config).
        $manualKeywords = @(
            'No TPM', 'Secure Boot', 'firmware', 'Credential Guard', 'TPM is not',
            'VDI', 'virtual desktop.*NA', 'standalone systems.*NA',
            'Remove any unauthorized', 'Deny access to this computer',
            'Deny log on', 'BitLocker.*Network Unlock'
        )
        $isManual = $false
        foreach ($kw in $manualKeywords) {
            if ($FixText -match $kw -or ($finding.FindingDetails -match $kw)) { $isManual = $true; break }
        }

        # Try to extract registry items regardless - override manual flag if found.
        $RegItems = Get-StigRegistryItems -CheckContent $CheckCC -FixText $FixText

        if ($RegItems.Count -gt 0) {
            $isManual = $false
            $isHkcu   = ($RegItems | Where-Object { $_.Path -like 'HKCU:*' }).Count -gt 0
            if ($isHkcu) {
                Write-StigLog "NOTE: One or more settings are HKCU-scoped. Applied to current user's profile." "WARN"
                Write-StigLog "      For persistent VDI/AVD coverage, distribute via GPO (User Configuration) or default user hive." "WARN"
            }
            foreach ($item in $RegItems) {
                Set-StigRegistryValue -Path $item.Path -Name $item.Name -Value $item.Value -PropertyType $item.Type -VulnNum $VulnNum
                $counters.Applied++
            }
        } elseif ($isManual) {
            Write-StigLog "MANUAL REMEDIATION REQUIRED - no auto-remediable registry settings detected." "MANUAL"
            Write-StigLog "  Fix hint: $($FixText.Substring(0, [Math]::Min(200, $FixText.Length)))" "MANUAL"
            $counters.Manual++
        } else {
            Write-StigLog "SKIPPED - no registry settings extractable and no manual pattern matched." "WARN"
            Write-StigLog "  Check_Content excerpt: $($CheckCC.Substring(0, [Math]::Min(150, $CheckCC.Length)))" "INFO"
            $counters.Skipped++
        }
    }

    # --- Per-file summary ---
    Write-StigLog "" "INFO"
    Write-StigLog "============================================================" "SECTION"
    Write-StigLog "SUMMARY for $($CklFile.Name)" "SECTION"
    Write-StigLog "  Open findings processed : $OpenCount" "INFO"
    Write-StigLog "  Registry items applied  : $($counters.Applied)" "SUCCESS"
    Write-StigLog "  Manual remediation req. : $($counters.Manual)" "MANUAL"
    Write-StigLog "  Skipped (no data)       : $($counters.Skipped)" "WARN"
    Write-StigLog "  Log written to          : $FileLog" "INFO"
    Write-StigLog "============================================================" "SECTION"

    $script:FileLogBuffer | Out-File -FilePath $FileLog -Encoding UTF8 -Force

    $StigSummary.Add([pscustomobject]@{
        File = $CklFile.Name; Title = $StigTitle
        Open = $OpenCount; Applied = $counters.Applied
        Manual = $counters.Manual; Skipped = $counters.Skipped
    })
}

# ==============================================================================
# --- POST-RUN GPO CHECK
# ==============================================================================
# Local registry edits can be overwritten by Domain GPO at the next refresh.
Write-Host "`n[Performing Post-Application Domain/GPO Check...]" -ForegroundColor Cyan
try {
    $GpoResult  = gpresult /r /Scope Computer 2>&1
    $GpoApplied = $GpoResult | Select-String "Applied Group Policy Objects" -Quiet
    if ($GpoApplied) {
        Write-Warning "CRITICAL: This machine is receiving Domain GPOs. Local registry edits may be overwritten at the next GPO refresh or reboot. Confirm settings survive a 'gpupdate /force'."
    } else {
        Write-Host "[SUCCESS] No Domain GPOs detected. Settings applied directly to local registry." -ForegroundColor Green
    }
} catch {
    Write-Host "[INFO] 'gpresult' unavailable. Assuming no Domain GPOs active." -ForegroundColor Gray
}

# ==============================================================================
# --- MASTER SUMMARY TABLE
# ==============================================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " MASTER REMEDIATION SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$StigSummary | Format-Table -AutoSize
Write-Host "Master log   : $MasterLog" -ForegroundColor Cyan
Write-Host "Per-file logs: $LogDirectory\*_remediation.log" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

Stop-Transcript
