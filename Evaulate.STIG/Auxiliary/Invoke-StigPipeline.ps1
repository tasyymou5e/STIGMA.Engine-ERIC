#Requires -Version 7.0
#Requires -RunAsAdministrator
# ==============================================================================
# Invoke-StigPipeline.ps1
# Full end-to-end STIG automation pipeline for a Windows gold image or endpoint.
#
# Pipeline stages (each can be run independently or all at once):
#
#   Stage 1 — SCAN        : Run Evaluate-STIG on this machine (generates CKL/CKLB)
#   Stage 2 — ANSWERFILES : Generate Evaluate-STIG answer files from scan results
#   Stage 3 — COPY        : Copy CKL/CKLB to the remediation toolkit's Checklist folder
#   Stage 4 — REMEDIATE   : Apply registry settings (Invoke-StigCklRemediation.ps1)
#   Stage 5 — HIVE        : Bake HKCU settings into Default user profile (VDI only)
#   Stage 6 — RESCAN      : Re-run Evaluate-STIG with answer files to verify fixes
#   Stage 7 — REPORT      : Generate HTML compliance report
#   Stage 8 — PATCH       : Update CKL/CKLB with NotAFinding status for fixed items
#
# Usage examples:
#
#   # Full pipeline with VDI mode (default — all stages)
#   .\Invoke-StigPipeline.ps1 -VdiMode
#
#   # Full pipeline, scan only Windows 11 and Chrome
#   .\Invoke-StigPipeline.ps1 -SelectSTIG Win11,Chrome -VdiMode
#
#   # Dry run — show what would be done without making changes
#   .\Invoke-StigPipeline.ps1 -WhatIf
#
#   # Skip remediation — just scan, generate answer files, and report
#   .\Invoke-StigPipeline.ps1 -SkipRemediation -SkipHive
#
#   # Skip scan — run remediation against existing checklists, then re-scan
#   .\Invoke-StigPipeline.ps1 -SkipScan -SkipRescan
#
# Pre-requisites:
#   - Evaluate-STIG must be extracted to ..\Evaluate-STIG\Evaluate-STIG.ps1
#   - STIG-CKL-Helpers.psm1 must be present in ..\..\..\Rremediate.STIG.code\
#   - All sibling scripts must be in the same Auxiliary\ folder as this script
# ==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param (
    # === PATH OVERRIDES ===
    # Root folder of the Evaluate-STIG installation (contains Evaluate-STIG subfolder)
    [string]$EvaluateStigRoot,

    # Base folder for scan output. Results go to <OutputBase>\<hostname>\Checklist\
    [string]$OutputBase,

    # Path to the remediation toolkit directory (containing Invoke-StigCklRemediation.ps1)
    [string]$RemediationRoot,

    # === SCAN OPTIONS ===
    # Specific STIGs to scan. Empty = all applicable STIGs on this machine.
    [string[]]$SelectSTIG,

    # STIGs to exclude from scanning.
    [string[]]$ExcludeSTIG,

    # Answer key name (must match what's in your answer files).
    [string]$AnswerKey = 'DEFAULT',

    # Unclassified or Classified scan type.
    [ValidateSet('Unclassified','Classified')]
    [string]$ScanType = 'Unclassified',

    # Number of previous result sets to keep (older ones are pruned by Evaluate-STIG).
    [int]$PreviousToKeep = 3,

    # === VDI OPTIONS ===
    # Enable VDI-specific Not-Applicable logic in answer file generation and
    # HKCU default profile baking (Stage 5).
    [switch]$VdiMode,

    # Optional JSON file with site-specific VDI NA finding overrides.
    # Format: { "Win11": { "V-253280": "Justification text" } }
    [string]$VdiNaFile,

    # === STAGE SKIPS ===
    # Skip each stage independently.  Use to re-run only specific stages.
    [switch]$SkipScan,
    [switch]$SkipAnswerFiles,
    [switch]$SkipRemediation,
    [switch]$SkipHive,       # Skip Stage 5 (Default user hive bake — VDI only)
    [switch]$SkipRescan,
    [switch]$SkipReport,
    [switch]$SkipPatch,

    # === REMEDIATION OPTIONS ===
    # Pass -WhatIf to remediation stage — no registry changes made.
    # Note: scan and rescan still write files even in WhatIf mode.
    [switch]$WhatIf,

    # Force-overwrite existing answer files.
    [switch]$ForceAnswerFiles
)

# ==============================================================================
# --- INITIALISATION
# ==============================================================================

$PipelineStart = Get-Date
$RunTimestamp  = $PipelineStart.ToString('yyyy-MM-dd_HH-mm-ss')
$HostName      = $env:COMPUTERNAME

# --- Resolve paths ---
if (-not $EvaluateStigRoot) {
    $EvaluateStigRoot = Split-Path $PSScriptRoot -Parent   # Auxiliary\..\
}
$EvaluateStigScript = Join-Path $EvaluateStigRoot 'Evaluate-STIG\Evaluate-STIG.ps1'
$AnswerFilePath     = Join-Path $EvaluateStigRoot 'Evaluate-STIG\AnswerFiles'

if (-not $OutputBase) {
    $OutputBase = Join-Path $EvaluateStigRoot 'STIGS'
}
$ChecklistDir = Join-Path $OutputBase "$HostName\Checklist"

if (-not $RemediationRoot) {
    $RemediationRoot = Resolve-Path "$EvaluateStigRoot\..\Rremediate.STIG.code" -ErrorAction SilentlyContinue
    $RemediationRoot = $RemediationRoot?.Path
}
$RemediationChecklist = if ($RemediationRoot) { Join-Path $RemediationRoot 'Checklist' } else { $null }

# --- Auxiliary script paths ---
$ScriptInvokeEval  = Join-Path $PSScriptRoot 'Invoke-EvaluateSTIG.ps1'
$ScriptAnswerFile  = Join-Path $PSScriptRoot 'New-StigAnswerFile.ps1'
$ScriptRemediate   = if ($RemediationRoot) { Join-Path $RemediationRoot 'Invoke-StigCklRemediation.ps1' } else { $null }
$ScriptHive        = if ($RemediationRoot) { Join-Path $RemediationRoot 'Invoke-DefaultUserHiveRemediation.ps1' } else { $null }
$ScriptReport      = if ($RemediationRoot) { Join-Path $RemediationRoot 'Get-StigComplianceReport.ps1' } else { $null }
$ScriptPatch       = if ($RemediationRoot) { Join-Path $RemediationRoot 'Update-CklFindingStatus.ps1' } else { $null }

# --- Log ---
$LogDir  = Join-Path $EvaluateStigRoot "Pipeline_Logs"
$LogFile = "$LogDir\Pipeline_$RunTimestamp.log"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
Start-Transcript -Path $LogFile -Append

# ==============================================================================
function Write-Stage {
    param([string]$Title, [int]$Num)
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 62) -ForegroundColor Cyan
    Write-Host "  Stage $Num — $Title" -ForegroundColor Cyan
    Write-Host "  $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
    Write-Host ("=" * 62) -ForegroundColor Cyan
}

function Write-StageResult {
    param([string]$Status, [string]$Detail = '')
    $color = switch ($Status) {
        'COMPLETE' { 'Green'  }
        'SKIPPED'  { 'DarkGray' }
        'WARN'     { 'Yellow' }
        'ERROR'    { 'Red'    }
        default    { 'White'  }
    }
    Write-Host "  [$Status] $Detail" -ForegroundColor $color
}

$stageResults = [ordered]@{}

# ==============================================================================
# --- BANNER
# ==============================================================================
Write-Host "`n" -NoNewline
Write-Host ("=" * 62) -ForegroundColor Cyan
Write-Host "  STIG Automation Pipeline" -ForegroundColor Cyan
Write-Host "  Host    : $HostName" -ForegroundColor Cyan
Write-Host "  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
if ($WhatIf)   { Write-Host "  [WHATIF MODE — remediation changes will NOT be applied]" -ForegroundColor Yellow }
if ($VdiMode)  { Write-Host "  [VDI MODE — Non-Applicable logic enabled]" -ForegroundColor Cyan }
Write-Host "  Log     : $LogFile" -ForegroundColor Gray
Write-Host ("=" * 62) -ForegroundColor Cyan

# ==============================================================================
# STAGE 1 — SCAN
# ==============================================================================
Write-Stage 'Scan: Run Evaluate-STIG' 1
if ($SkipScan) {
    Write-StageResult 'SKIPPED' 'Using existing checklists in output folder.'
    $stageResults['Scan'] = 'SKIPPED'
} elseif (-not (Test-Path $EvaluateStigScript)) {
    Write-StageResult 'ERROR' "Evaluate-STIG.ps1 not found: $EvaluateStigScript"
    $stageResults['Scan'] = 'ERROR'
} else {
    $invokeParams = @{
        EvaluateStigRoot = $EvaluateStigRoot
        OutputPath       = $OutputBase
        Output           = 'CKL,CKLB'
        AnswerKey        = $AnswerKey
        AFPath           = $AnswerFilePath
        ScanType         = $ScanType
        PreviousToKeep   = $PreviousToKeep
    }
    if ($SelectSTIG)  { $invokeParams.SelectSTIG  = $SelectSTIG  }
    if ($ExcludeSTIG) { $invokeParams.ExcludeSTIG = $ExcludeSTIG }

    if ($PSCmdlet.ShouldProcess($HostName, 'Run Evaluate-STIG baseline scan')) {
        & $ScriptInvokeEval @invokeParams
        $stageResults['Scan'] = if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) { 'COMPLETE' } else { 'WARN' }
    } else {
        $stageResults['Scan'] = 'WHATIF'
    }
    Write-StageResult $stageResults['Scan'] "Output: $ChecklistDir"
}

# ==============================================================================
# STAGE 2 — GENERATE ANSWER FILES
# ==============================================================================
Write-Stage 'Answer Files: Generate from scan results' 2
if ($SkipAnswerFiles) {
    Write-StageResult 'SKIPPED'
    $stageResults['AnswerFiles'] = 'SKIPPED'
} elseif (-not (Test-Path $ChecklistDir)) {
    Write-StageResult 'WARN' "Checklist directory not found: $ChecklistDir — no checklists to generate answer files from."
    $stageResults['AnswerFiles'] = 'WARN'
} else {
    $cklFiles = Get-ChildItem -Path $ChecklistDir -File |
                Where-Object { $_.Extension -in '.ckl','.cklb' -and $_.Name -notlike '*_PATCHED*' }

    if ($cklFiles.Count -eq 0) {
        Write-StageResult 'WARN' 'No CKL/CKLB files found in checklist directory.'
        $stageResults['AnswerFiles'] = 'WARN'
    } else {
        # Process only one file per STIG (prefer .ckl over .cklb if both present)
        $byBaseName = $cklFiles | Group-Object { $_.Name -replace '_\d{8}-\d{6}\.(ckl|cklb)$','' -replace '\.ckl(b)?$','' }
        $toProcess  = $byBaseName | ForEach-Object {
            $ckl  = $_.Group | Where-Object { $_.Extension -eq '.ckl'  } | Select-Object -First 1
            $cklb = $_.Group | Where-Object { $_.Extension -eq '.cklb' } | Select-Object -First 1
            if ($ckl) { $ckl } elseif ($cklb) { $cklb }
        }

        $afParams = @{
            OutputPath = $AnswerFilePath
            AnswerKey  = $AnswerKey
        }
        if ($VdiMode)      { $afParams.VdiMode  = $true   }
        if ($VdiNaFile)    { $afParams.VdiNaFile = $VdiNaFile }
        if ($ForceAnswerFiles) { $afParams.Force = $true   }

        if ($PSCmdlet.ShouldProcess("$($toProcess.Count) checklists", 'Generate answer files')) {
            $toProcess | ForEach-Object {
                & $ScriptAnswerFile -CklPath $_.FullName @afParams
            }
            $stageResults['AnswerFiles'] = 'COMPLETE'
        } else {
            $stageResults['AnswerFiles'] = 'WHATIF'
        }
        Write-StageResult $stageResults['AnswerFiles'] "Answer files written to: $AnswerFilePath"
    }
}

# ==============================================================================
# STAGE 3 — COPY TO REMEDIATION CHECKLIST
# ==============================================================================
Write-Stage 'Copy: CKL/CKLB to remediation toolkit' 3
if (-not $RemediationChecklist) {
    Write-StageResult 'WARN' 'Rremediate.STIG.code folder not found — skipping copy.'
    $stageResults['Copy'] = 'WARN'
} elseif (-not (Test-Path $ChecklistDir)) {
    Write-StageResult 'WARN' "Source checklist dir not found: $ChecklistDir"
    $stageResults['Copy'] = 'WARN'
} else {
    $cklFiles = Get-ChildItem -Path $ChecklistDir -File |
                Where-Object { $_.Extension -in '.ckl','.cklb' -and $_.Name -notlike '*_PATCHED*' }
    if ($cklFiles.Count -eq 0) {
        Write-StageResult 'WARN' 'No source CKL/CKLB files to copy.'
        $stageResults['Copy'] = 'WARN'
    } else {
        if ($PSCmdlet.ShouldProcess($RemediationChecklist, "Copy $($cklFiles.Count) checklist file(s)")) {
            if (-not (Test-Path $RemediationChecklist)) {
                New-Item -ItemType Directory -Path $RemediationChecklist -Force | Out-Null
            }
            $cklFiles | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination $RemediationChecklist -Force
                Write-Host "  Copied: $($_.Name)" -ForegroundColor Green
            }
            $stageResults['Copy'] = 'COMPLETE'
        } else {
            $stageResults['Copy'] = 'WHATIF'
        }
        Write-StageResult $stageResults['Copy'] "Destination: $RemediationChecklist"
    }
}

# ==============================================================================
# STAGE 4 — REMEDIATE
# ==============================================================================
Write-Stage 'Remediate: Apply registry settings' 4
if ($SkipRemediation) {
    Write-StageResult 'SKIPPED'
    $stageResults['Remediate'] = 'SKIPPED'
} elseif (-not $ScriptRemediate -or -not (Test-Path $ScriptRemediate)) {
    Write-StageResult 'WARN' "Invoke-StigCklRemediation.ps1 not found: $ScriptRemediate"
    $stageResults['Remediate'] = 'WARN'
} elseif (-not $RemediationChecklist -or -not (Test-Path $RemediationChecklist)) {
    Write-StageResult 'WARN' "Remediation Checklist folder not found: $RemediationChecklist"
    $stageResults['Remediate'] = 'WARN'
} else {
    $remParams = @{ CklDirectory = $RemediationChecklist }
    if ($WhatIf) { $remParams.WhatIf = $true }

    if ($PSCmdlet.ShouldProcess($RemediationChecklist, 'Run remediation')) {
        & $ScriptRemediate @remParams
        $stageResults['Remediate'] = if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) { 'COMPLETE' } else { 'WARN' }
    } else {
        $stageResults['Remediate'] = 'WHATIF'
    }
    Write-StageResult $stageResults['Remediate']
}

# ==============================================================================
# STAGE 5 — HKCU DEFAULT HIVE BAKE (VDI only)
# ==============================================================================
Write-Stage 'Default Hive: Bake HKCU settings into Default profile' 5
if ($SkipHive -or -not $VdiMode) {
    Write-StageResult 'SKIPPED' $(if (-not $VdiMode) { '-VdiMode not specified' } else { '-SkipHive specified' })
    $stageResults['Hive'] = 'SKIPPED'
} elseif (-not $ScriptHive -or -not (Test-Path $ScriptHive)) {
    Write-StageResult 'WARN' "Invoke-DefaultUserHiveRemediation.ps1 not found: $ScriptHive"
    $stageResults['Hive'] = 'WARN'
} else {
    $hiveParams = @{ CklDirectory = $RemediationChecklist }
    if ($WhatIf) { $hiveParams.WhatIf = $true }

    if ($PSCmdlet.ShouldProcess($HostName, 'Bake HKCU settings into Default user profile')) {
        & $ScriptHive @hiveParams
        $stageResults['Hive'] = if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) { 'COMPLETE' } else { 'WARN' }
    } else {
        $stageResults['Hive'] = 'WHATIF'
    }
    Write-StageResult $stageResults['Hive']
}

# ==============================================================================
# STAGE 6 — RESCAN (post-remediation verification)
# ==============================================================================
Write-Stage 'Rescan: Verify remediation with Evaluate-STIG + answer files' 6
if ($SkipRescan) {
    Write-StageResult 'SKIPPED'
    $stageResults['Rescan'] = 'SKIPPED'
} elseif (-not (Test-Path $EvaluateStigScript)) {
    Write-StageResult 'WARN' "Evaluate-STIG.ps1 not found: $EvaluateStigScript"
    $stageResults['Rescan'] = 'WARN'
} else {
    $rescanParams = @{
        EvaluateStigRoot = $EvaluateStigRoot
        OutputPath       = $OutputBase
        Output           = 'CKL,CKLB'
        AnswerKey        = $AnswerKey
        AFPath           = $AnswerFilePath
        ScanType         = $ScanType
        PreviousToKeep   = $PreviousToKeep
    }
    if ($SelectSTIG)  { $rescanParams.SelectSTIG  = $SelectSTIG  }
    if ($ExcludeSTIG) { $rescanParams.ExcludeSTIG = $ExcludeSTIG }

    if ($PSCmdlet.ShouldProcess($HostName, 'Run Evaluate-STIG post-remediation rescan')) {
        Write-Host "  Re-scanning with answer files from: $AnswerFilePath" -ForegroundColor Gray
        & $ScriptInvokeEval @rescanParams
        $stageResults['Rescan'] = if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) { 'COMPLETE' } else { 'WARN' }

        # Copy rescan results to remediation Checklist folder
        if ($RemediationChecklist -and (Test-Path $ChecklistDir)) {
            $rescanFiles = Get-ChildItem -Path $ChecklistDir -File |
                           Where-Object { $_.Extension -in '.ckl','.cklb' -and $_.Name -notlike '*_PATCHED*' }
            $rescanFiles | ForEach-Object { Copy-Item -Path $_.FullName -Destination $RemediationChecklist -Force }
            Write-Host "  Updated $($rescanFiles.Count) file(s) in remediation checklist." -ForegroundColor Gray
        }
    } else {
        $stageResults['Rescan'] = 'WHATIF'
    }
    Write-StageResult $stageResults['Rescan'] "Post-remediation output: $ChecklistDir"
}

# ==============================================================================
# STAGE 7 — COMPLIANCE REPORT
# ==============================================================================
Write-Stage 'Report: Generate HTML compliance report' 7
if ($SkipReport) {
    Write-StageResult 'SKIPPED'
    $stageResults['Report'] = 'SKIPPED'
} elseif (-not $ScriptReport -or -not (Test-Path $ScriptReport)) {
    Write-StageResult 'WARN' "Get-StigComplianceReport.ps1 not found: $ScriptReport"
    $stageResults['Report'] = 'WARN'
} elseif (-not $RemediationChecklist -or -not (Test-Path $RemediationChecklist)) {
    Write-StageResult 'WARN' "Remediation Checklist not found — nothing to report on."
    $stageResults['Report'] = 'WARN'
} else {
    $reportPath = "$LogDir\StigComplianceReport_$RunTimestamp.html"
    $reportParams = @{
        CklDirectory = $RemediationChecklist
        ReportPath   = $reportPath
    }

    if ($PSCmdlet.ShouldProcess($RemediationChecklist, 'Generate compliance report')) {
        & $ScriptReport @reportParams
        $stageResults['Report'] = if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) { 'COMPLETE' } else { 'WARN' }
        if (Test-Path $reportPath) {
            Write-StageResult $stageResults['Report'] "Report: $reportPath"
            # Open in browser automatically
            try { Start-Process $reportPath } catch {}
        }
    } else {
        $stageResults['Report'] = 'WHATIF'
    }
}

# ==============================================================================
# STAGE 8 — PATCH CHECKLISTS
# ==============================================================================
Write-Stage 'Patch: Update CKL/CKLB with NotAFinding status' 8
if ($SkipPatch) {
    Write-StageResult 'SKIPPED'
    $stageResults['Patch'] = 'SKIPPED'
} elseif (-not $ScriptPatch -or -not (Test-Path $ScriptPatch)) {
    Write-StageResult 'WARN' "Update-CklFindingStatus.ps1 not found: $ScriptPatch"
    $stageResults['Patch'] = 'WARN'
} elseif (-not $RemediationChecklist -or -not (Test-Path $RemediationChecklist)) {
    Write-StageResult 'WARN' "Remediation Checklist not found."
    $stageResults['Patch'] = 'WARN'
} else {
    $patchParams = @{ CklDirectory = $RemediationChecklist }
    if ($WhatIf) { $patchParams.WhatIf = $true }

    if ($PSCmdlet.ShouldProcess($RemediationChecklist, 'Patch CKL/CKLB with NotAFinding status')) {
        & $ScriptPatch @patchParams
        $stageResults['Patch'] = if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) { 'COMPLETE' } else { 'WARN' }
    } else {
        $stageResults['Patch'] = 'WHATIF'
    }
    Write-StageResult $stageResults['Patch']
}

# ==============================================================================
# --- PIPELINE SUMMARY
# ==============================================================================
$elapsed = (Get-Date) - $PipelineStart

Write-Host "`n" -NoNewline
Write-Host ("=" * 62) -ForegroundColor Cyan
Write-Host "  PIPELINE SUMMARY" -ForegroundColor Cyan
Write-Host "  Host     : $HostName" -ForegroundColor Cyan
Write-Host "  Duration : $([Math]::Round($elapsed.TotalMinutes,1)) minutes" -ForegroundColor Cyan
Write-Host "  Log      : $LogFile" -ForegroundColor Cyan
Write-Host ("=" * 62) -ForegroundColor Cyan

$stageOrder = @('Scan','AnswerFiles','Copy','Remediate','Hive','Rescan','Report','Patch')
foreach ($stage in $stageOrder) {
    $result = $stageResults[$stage]
    if (-not $result) { $result = 'NOT RUN' }
    $color = switch ($result) {
        'COMPLETE' { 'Green'    }
        'SKIPPED'  { 'DarkGray' }
        'WHATIF'   { 'Yellow'   }
        'WARN'     { 'Yellow'   }
        'ERROR'    { 'Red'      }
        default    { 'White'    }
    }
    Write-Host ("  {0,-14} {1}" -f $stage, $result) -ForegroundColor $color
}
Write-Host ("=" * 62) -ForegroundColor Cyan

# Deliver next-step guidance
$openStages = $stageResults.Values | Where-Object { $_ -in 'ERROR','WARN' }
if ($openStages.Count -gt 0) {
    Write-Host "`n  One or more stages completed with warnings. Review the log:" -ForegroundColor Yellow
    Write-Host "  $LogFile" -ForegroundColor Yellow
}
if ($stageResults['Rescan'] -eq 'COMPLETE') {
    Write-Host "`n  Next step: review the HTML compliance report and the patched" -ForegroundColor Cyan
    Write-Host "  CKL files (*_PATCHED.ckl) for STIG Manager / eMASS submission." -ForegroundColor Cyan
}

Stop-Transcript
