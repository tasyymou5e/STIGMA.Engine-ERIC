#Requires -Version 5.1
#Requires -RunAsAdministrator
# ==============================================================================
# Invoke-EvaluateSTIG.ps1
# Wrapper script that runs Evaluate-STIG.ps1 on the local machine with
# consistent, audit-ready defaults and copies results to the remediation
# toolkit's Checklist folder for immediate use.
#
# Auto-discovers Evaluate-STIG.ps1 one level up from this script's location.
# Results are written to STIGS\<hostname>\Checklist\ in the standard structure.
#
# Usage (from an elevated PowerShell 5.1+ prompt):
#   .\Invoke-EvaluateSTIG.ps1
#   .\Invoke-EvaluateSTIG.ps1 -SelectSTIG Win11,Chrome,MSOffice365
#   .\Invoke-EvaluateSTIG.ps1 -CopyToRemediation
#   .\Invoke-EvaluateSTIG.ps1 -ListApplicable
# ==============================================================================

param (
    # Path to the Evaluate-STIG root folder (contains Evaluate-STIG.ps1).
    # Auto-detected from this script's location if not provided.
    [string]$EvaluateStigRoot,

    # Where to write CKL/CKLB output. Creates <OutputPath>\<hostname>\Checklist\.
    # Defaults to STIGS\ in the Evaluate-STIG root.
    [string]$OutputPath,

    # Output formats passed to Evaluate-STIG -Output. Both CKL and CKLB by default
    # so the remediation toolkit can consume either format.
    [string]$Output = 'CKL,CKLB',

    # Which STIGs to scan. Leave empty to auto-detect all applicable STIGs.
    [string[]]$SelectSTIG,

    # STIGs to explicitly exclude from the scan.
    [string[]]$ExcludeSTIG,

    # Answer key to use from the answer files (default: DEFAULT).
    [string]$AnswerKey = 'DEFAULT',

    # Path to answer files. Defaults to <EvaluateStigRoot>\Evaluate-STIG\AnswerFiles.
    [string]$AFPath,

    # Classification marking (e.g., "CUI", "Controlled"). Leave empty for unclassified.
    [ValidateSet('Unclassified','Classified')]
    [string]$ScanType = 'Unclassified',

    # Freetext marking added to checklist header.
    [string]$Marking,

    # After scanning, copy resulting CKL/CKLB files to the remediation toolkit's
    # Checklist folder so Invoke-StigCklRemediation.ps1 can process them immediately.
    [switch]$CopyToRemediation,

    # Explicit path to the remediation toolkit's Checklist folder.
    # Auto-detected from sibling Rremediate.STIG.code folder if not provided.
    [string]$RemediationChecklist,

    # Just list which STIGs would be scanned on this machine and exit.
    [switch]$ListApplicable,

    # Number of previous result folders to keep (passed to -PreviousToKeep).
    [int]$PreviousToKeep = 3,

    # Individual vulnerability check timeout in minutes.
    [int]$VulnTimeout = 15
)

# ---------------------------------
# --- LOCATE EVALUATE-STIG.PS1
# ---------------------------------
if (-not $EvaluateStigRoot) {
    # Auxiliary\ is one level below the Evaulate.STIG root
    $EvaluateStigRoot = Split-Path $PSScriptRoot -Parent
}
$EvaluateStigScript = Join-Path $EvaluateStigRoot 'Evaluate-STIG\Evaluate-STIG.ps1'

if (-not (Test-Path $EvaluateStigScript)) {
    Write-Error "Evaluate-STIG.ps1 not found at '$EvaluateStigScript'.`nSet -EvaluateStigRoot to the folder containing the Evaluate-STIG subfolder."
    exit 1
}

# ---------------------------------
# --- OUTPUT PATH
# ---------------------------------
if (-not $OutputPath) {
    $OutputPath = Join-Path $EvaluateStigRoot 'STIGS'
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# ---------------------------------
# --- ANSWER FILE PATH
# ---------------------------------
if (-not $AFPath) {
    $AFPath = Join-Path $EvaluateStigRoot 'Evaluate-STIG\AnswerFiles'
}

# ---------------------------------
# --- LIST APPLICABLE MODE
# ---------------------------------
if ($ListApplicable) {
    Write-Host "`nListing applicable STIGs for this machine..." -ForegroundColor Cyan
    & $EvaluateStigScript -ListApplicableProducts
    exit 0
}

# ---------------------------------
# --- BUILD EVALUATE-STIG PARAMETERS
# ---------------------------------
$esParams = @{
    Output          = $Output
    OutputPath      = $OutputPath
    AnswerKey       = $AnswerKey
    AFPath          = $AFPath
    ScanType        = $ScanType
    PreviousToKeep  = $PreviousToKeep
    VulnTimeout     = $VulnTimeout
}
if ($SelectSTIG)  { $esParams.SelectSTIG  = $SelectSTIG  }
if ($ExcludeSTIG) { $esParams.ExcludeSTIG = $ExcludeSTIG }
if ($Marking)     { $esParams.Marking     = $Marking      }

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Evaluate-STIG Wrapper" -ForegroundColor Cyan
Write-Host " Script  : $EvaluateStigScript" -ForegroundColor Cyan
Write-Host " Output  : $OutputPath\$($env:COMPUTERNAME)\Checklist\" -ForegroundColor Cyan
Write-Host " Formats : $Output" -ForegroundColor Cyan
if ($SelectSTIG) { Write-Host " STIGs   : $($SelectSTIG -join ', ')" -ForegroundColor Cyan }
Write-Host "============================================================`n" -ForegroundColor Cyan

# ---------------------------------
# --- RUN EVALUATE-STIG
# ---------------------------------
$startTime = Get-Date
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting Evaluate-STIG scan..." -ForegroundColor Yellow

try {
    & $EvaluateStigScript @esParams
    $exitCode = $LASTEXITCODE
} catch {
    Write-Error "Evaluate-STIG failed: $($_.Exception.Message)"
    exit 1
}

$elapsed = (Get-Date) - $startTime
Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Scan completed in $([Math]::Round($elapsed.TotalMinutes,1)) minutes." -ForegroundColor Green

# ---------------------------------
# --- FIND RESULTS
# ---------------------------------
$checklistDir = Join-Path $OutputPath "$($env:COMPUTERNAME)\Checklist"
$resultFiles = @()
if (Test-Path $checklistDir) {
    $resultFiles = Get-ChildItem -Path $checklistDir -File |
                   Where-Object { $_.Extension -in '.ckl','.cklb' -and $_.Name -notlike '*_PATCHED*' } |
                   Sort-Object LastWriteTime -Descending
}

Write-Host "`nResults written to: $checklistDir" -ForegroundColor Cyan
if ($resultFiles.Count -gt 0) {
    Write-Host "Generated files:" -ForegroundColor Cyan
    $resultFiles | ForEach-Object {
        Write-Host "  $($_.Name)  [$([Math]::Round($_.Length/1KB,1)) KB]" -ForegroundColor Green
    }
} else {
    Write-Warning "No CKL/CKLB files found in output directory. Check Evaluate-STIG console output above."
}

# ---------------------------------
# --- COPY TO REMEDIATION CHECKLIST
# ---------------------------------
if ($CopyToRemediation -and $resultFiles.Count -gt 0) {
    if (-not $RemediationChecklist) {
        # Default: sibling Rremediate.STIG.code\Checklist
        $RemediationChecklist = Resolve-Path "$EvaluateStigRoot\..\Rremediate.STIG.code\Checklist" -ErrorAction SilentlyContinue
    }

    if (-not $RemediationChecklist) {
        Write-Warning "-CopyToRemediation specified but Rremediate.STIG.code\Checklist not found.`nSet -RemediationChecklist explicitly."
    } else {
        if (-not (Test-Path $RemediationChecklist)) {
            New-Item -ItemType Directory -Path $RemediationChecklist -Force | Out-Null
        }
        Write-Host "`nCopying results to remediation checklist: $RemediationChecklist" -ForegroundColor Cyan
        foreach ($f in $resultFiles) {
            Copy-Item -Path $f.FullName -Destination $RemediationChecklist -Force
            Write-Host "  Copied: $($f.Name)" -ForegroundColor Green
        }
    }
}

# ---------------------------------
# --- SUMMARY
# ---------------------------------
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Scan Summary" -ForegroundColor Cyan
Write-Host " Host     : $($env:COMPUTERNAME)" -ForegroundColor Cyan
Write-Host " Duration : $([Math]::Round($elapsed.TotalMinutes,1)) minutes" -ForegroundColor Cyan
Write-Host " Files    : $($resultFiles.Count) checklist file(s) in $checklistDir" -ForegroundColor Cyan
if ($CopyToRemediation -and $RemediationChecklist) {
    Write-Host " Copied to: $RemediationChecklist" -ForegroundColor Cyan
}
Write-Host "============================================================`n" -ForegroundColor Cyan
