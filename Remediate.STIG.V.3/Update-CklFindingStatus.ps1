#requires -Version 7.0
# ==============================================================================
# Update-CklFindingStatus.ps1
# Post-remediation CKL updater.
#
# Reads each checklist file (.cklb JSON or legacy CKL/XML), re-checks the live
# registry for every Open finding that has extractable registry items, and
# marks compliant ones as "NotAFinding" (CKLB: not_a_finding) in a patched
# COPY of the file. Non-registry and still-failing findings are left Open. A
# comments entry is added to every updated finding for audit trail.
#
# Output: <original_name>_PATCHED.<ext> alongside the source file, preserving
#         the source's extension (originals are never modified).
#
# REQUIRES: PowerShell 7.0+ (Windows). Will NOT run on Windows PowerShell 5.1.
#           Auto-elevates to Administrator via pwsh if needed.
#
# Usage:
#   .\Update-CklFindingStatus.ps1
#   .\Update-CklFindingStatus.ps1 -CklDirectory "D:\STIGs" -OutputSuffix "_signed"
#   .\Update-CklFindingStatus.ps1 -WhatIf     # report only, write nothing
# ==============================================================================

[CmdletBinding()]
param (
    [string]$CklDirectory = $PSScriptRoot,
    [string]$LogDirectory = "$PSScriptRoot\Logs",
    [string]$OutputSuffix = "_PATCHED",
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
$RunTimestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$LogFile      = "$LogDirectory\CklUpdate_$RunTimestamp.log"
$Reviewer     = "$env:USERNAME on $env:COMPUTERNAME"
$ReviewDate   = Get-Date -Format 'MM/dd/yyyy'

if (!(Test-Path $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
Start-Transcript -Path $LogFile -Append

# ---------------------------------
# --- HELPERS
# ---------------------------------

function Write-UpdLog {
    param([string]$Message, [string]$Color = "Gray")
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

function Test-RegistryCompliance {
    <#
    .SYNOPSIS
    Returns $true if ALL items match the live registry, $false if any is missing
    or wrong, $null if the item set is empty (cannot determine).

    .NOTE
    HKCU items are checked against the registry of the user running this script
    (typically the elevated admin). If you baked HKCU settings into the Default
    user hive for VDI, those will read here as non-compliant because they live in
    C:\Users\Default\NTUSER.DAT, not the current profile. Verify the gold image
    by logging in as a fresh test user (or re-scan with Evaluate-STIG) rather
    than relying on this check for HKCU rows.
    #>
    param([array]$RegItems)
    if ($RegItems.Count -eq 0) { return $null }   # null = indeterminate

    foreach ($item in $RegItems) {
        $checkPath = $item.Path
        if (!(Test-Path $checkPath)) { return $false }
        $current = (Get-ItemProperty -Path $checkPath -Name $item.Name -ErrorAction SilentlyContinue).$($item.Name)
        if ($null -eq $current) { return $false }
        if ("$current" -ne "$($item.Value)") { return $false }
    }
    return $true
}

# Builds the COMMENTS audit string written to each updated finding.
function New-ComplianceComment {
    param([string]$Action, [int]$ItemCount, [array]$RegItems)
    $paths = ($RegItems | ForEach-Object { "$($_.Path)\$($_.Name) = $($_.Value)" }) -join '; '
    return "[$Action] Auto-verified by Update-CklFindingStatus.ps1 on $ReviewDate by $Reviewer. $ItemCount registry item(s) confirmed: $paths"
}

# Decides the compliance outcome for one finding's registry items and emits
# the same PASS/FAIL/SKIP/MANUAL log line the CKL/XML path always has, so both
# format branches share one decision+logging path instead of drifting apart.
# Returns 'Updated' (compliant -> mark NotAFinding), 'StillOpen' (verified
# non-compliant), or 'Manual' (nothing to check / indeterminate).
function Get-FindingComplianceOutcome {
    param(
        [string]$VulnNum,
        [array]$RegItems
    )
    if ($RegItems.Count -eq 0) {
        Write-UpdLog "  MANUAL  $VulnNum - no registry items extractable" "Magenta"
        return 'Manual'
    }

    $compliant = Test-RegistryCompliance -RegItems $RegItems

    if ($compliant -eq $true) {
        Write-UpdLog "  PASS    $VulnNum - $($RegItems.Count) item(s) verified compliant -> NotAFinding" "Green"
        return 'Updated'
    } elseif ($compliant -eq $false) {
        Write-UpdLog "  FAIL    $VulnNum - one or more registry values are still non-compliant" "Red"
        return 'StillOpen'
    } else {
        Write-UpdLog "  SKIP    $VulnNum - registry check returned indeterminate" "Yellow"
        return 'Manual'
    }
}

# ---------------------------------
# --- DISCOVER CKL FILES
# ---------------------------------
# Exclude previously patched output so re-runs don't re-process their own writes.
$CklFiles = Get-CklFileList -Directory $CklDirectory -ExcludePattern "*$OutputSuffix*"
if (-not $CklFiles) { Write-Error "No CKL files found in '$CklDirectory'."; Stop-Transcript; exit 1 }

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " CKL Finding Status Updater" -ForegroundColor Cyan
Write-Host " Reviewer  : $Reviewer" -ForegroundColor Cyan
Write-Host " Date      : $ReviewDate" -ForegroundColor Cyan
if ($WhatIf) { Write-Host " [WHATIF - no files will be written]" -ForegroundColor Yellow }
Write-Host "============================================================`n" -ForegroundColor Cyan

$grandTotal = @{ Updated = 0; AlreadyGood = 0; StillOpen = 0; Manual = 0 }

# ---------------------------------
# --- PROCESS EACH CKL
# ---------------------------------
foreach ($CklFile in $CklFiles) {

    $counters = @{ Updated = 0; AlreadyGood = 0; StillOpen = 0; Manual = 0 }
    Write-UpdLog "--- $($CklFile.Name) ---" "Cyan"

    if ($CklFile.Extension -ieq '.cklb') {
        # -------------------------------------------------------------------
        # CKLB (JSON) branch
        # -------------------------------------------------------------------
        try {
            $cklbObj = Get-Content -Path $CklFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 64
        } catch {
            Write-UpdLog "[ERROR] JSON parse failed: $($_.Exception.Message)" "Red"; continue
        }

        $modified = $false

        foreach ($stig in $cklbObj.stigs) {
            foreach ($rule in $stig.rules) {
                if ("$($rule.status)".Trim().ToLower() -ne 'open') { continue }

                $vulnNum = $rule.group_id ?? 'UNKNOWN'
                $items   = Get-StigRegistryItems -CheckContent ($rule.check_content ?? '') -FixText ($rule.fix_text ?? '')
                $outcome = Get-FindingComplianceOutcome -VulnNum $vulnNum -RegItems $items

                if ($outcome -eq 'Updated' -and -not $WhatIf) {
                    $rule.status          = 'not_a_finding'
                    $rule.finding_details = "Auto-remediated and verified compliant by STIG CKL Remediation Toolkit on $ReviewDate."
                    $rule.comments        = New-ComplianceComment -Action "NotAFinding" -ItemCount $items.Count -RegItems $items
                    $modified = $true
                }
                $counters[$outcome]++
            }
        }

        # Save patched copy (never overwrite the source).
        if ($modified -and -not $WhatIf) {
            $outName = [IO.Path]::GetFileNameWithoutExtension($CklFile.Name) + $OutputSuffix + $CklFile.Extension
            $outPath = Join-Path $CklFile.DirectoryName $outName
            try {
                ($cklbObj | ConvertTo-Json -Depth 64 -Compress) | Set-Content -Path $outPath -Encoding UTF8 -NoNewline
                Write-UpdLog "  Saved patched CKLB -> $outName" "Cyan"
            } catch {
                Write-UpdLog "  [ERROR] Save failed: $($_.Exception.Message)" "Red"
            }
        } elseif (-not $modified) {
            Write-UpdLog "  No changes - file not written." "Gray"
        }

    } else {
        # -------------------------------------------------------------------
        # Legacy CKL/XML branch
        # -------------------------------------------------------------------
        # Load via XmlDocument with PreserveWhitespace so the patched copy keeps formatting.
        try {
            $xmlDoc = [System.Xml.XmlDocument]::new()
            $xmlDoc.PreserveWhitespace = $true
            $xmlDoc.Load($CklFile.FullName)
        } catch {
            Write-UpdLog "[ERROR] XML parse failed: $($_.Exception.Message)" "Red"; continue
        }

        $modified = $false

        foreach ($vuln in $xmlDoc.SelectNodes("//VULN")) {
            $statusNode = $vuln.SelectSingleNode("STATUS")
            if ($null -eq $statusNode -or $statusNode.InnerText -ne "Open") { continue }

            # Rebuild STIG_DATA hashtable from this VULN node.
            $sd = @{}
            foreach ($node in $vuln.SelectNodes("STIG_DATA")) {
                $sd[$node.SelectSingleNode("VULN_ATTRIBUTE").InnerText] = $node.SelectSingleNode("ATTRIBUTE_DATA").InnerText
            }
            $vulnNum = $sd['Vuln_Num'] ?? 'UNKNOWN'
            $items   = Get-StigRegistryItems -CheckContent ($sd['Check_Content'] ?? '') -FixText ($sd['Fix_Text'] ?? '')
            $outcome = Get-FindingComplianceOutcome -VulnNum $vulnNum -RegItems $items

            if ($outcome -eq 'Updated' -and -not $WhatIf) {
                $statusNode.InnerText = "NotAFinding"
                $fdNode = $vuln.SelectSingleNode("FINDING_DETAILS")
                if ($fdNode) { $fdNode.InnerText = "Auto-remediated and verified compliant by STIG CKL Remediation Toolkit on $ReviewDate." }
                $cmtNode = $vuln.SelectSingleNode("COMMENTS")
                if ($cmtNode) { $cmtNode.InnerText = New-ComplianceComment -Action "NotAFinding" -ItemCount $items.Count -RegItems $items }
                $modified = $true
            }
            $counters[$outcome]++
        }

        # Save patched copy (never overwrite the source).
        if ($modified -and -not $WhatIf) {
            $outName = [IO.Path]::GetFileNameWithoutExtension($CklFile.Name) + $OutputSuffix + $CklFile.Extension
            $outPath = Join-Path $CklFile.DirectoryName $outName
            try {
                $xmlDoc.Save($outPath)
                Write-UpdLog "  Saved patched CKL -> $outName" "Cyan"
            } catch {
                Write-UpdLog "  [ERROR] Save failed: $($_.Exception.Message)" "Red"
            }
        } elseif (-not $modified) {
            Write-UpdLog "  No changes - file not written." "Gray"
        }
    }

    Write-UpdLog "  Updated=$($counters.Updated)  StillOpen=$($counters.StillOpen)  Manual=$($counters.Manual)" "Gray"
    foreach ($k in $counters.Keys) { $grandTotal[$k] += $counters[$k] }
}

# ---------------------------------
# --- SUMMARY
# ---------------------------------
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " CKL Update Summary" -ForegroundColor Cyan
Write-Host "  Marked NotAFinding : $($grandTotal.Updated)"   -ForegroundColor Green
Write-Host "  Still Open         : $($grandTotal.StillOpen)" -ForegroundColor Red
Write-Host "  Manual (no data)   : $($grandTotal.Manual)"    -ForegroundColor Magenta
Write-Host "  Log                : $LogFile" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

Stop-Transcript
