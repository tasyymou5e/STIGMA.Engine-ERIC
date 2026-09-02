#requires -Version 7.0
# ==============================================================================
# Invoke-StigGpoRemediation.ps1
# STIG GPO (LGPO) Remediation Engine
#
# Parses Open findings from .cklb (JSON) checklist files ONLY, extracts their
# registry-backed policy settings using the shared module parser, converts
# them to Microsoft LGPO.exe "LGPO text" format, and applies them as genuine
# Local Group Policy via LGPO.exe /t - instead of raw Set-ItemProperty writes.
# This means the settings show up in gpresult/RSOP and sit correctly in normal
# GPO precedence, rather than being invisible ad hoc registry pokes.
#
# Scope: registry-backed Administrative Template settings only (the same
# subset Get-StigRegistryItems already extracts from Check_Content/Fix_Text).
# Security Options / User Rights Assignment / Audit Policy findings are NOT
# covered here - LGPO applies those via a different mode (/s GptTmpl.inf,
# /ac Audit.csv) that needs a different text extractor. Open findings with no
# extractable registry items are logged as out-of-scope and left untouched.
#
# REQUIRES: PowerShell 7.0+ (Windows). Will NOT run on Windows PowerShell 5.1.
#           Auto-elevates to Administrator via pwsh if needed.
#           LGPO.exe (Microsoft Security Compliance Toolkit) - resolved from
#           -LgpoExePath, else "<script dir>\LGPO.exe", else PATH.
#
# Usage:
#   .\Invoke-StigGpoRemediation.ps1
#   .\Invoke-StigGpoRemediation.ps1 -WhatIf     # generate LGPO text only, apply nothing
#   .\Invoke-StigGpoRemediation.ps1 -CklDirectory "D:\STIGS" -LgpoExePath "C:\Tools\LGPO.exe"
#
# Note: User-scope entries apply to whoever is logged on when LGPO.exe runs -
#       same caveat as HKCU settings elsewhere in this toolkit. For VDI/AVD,
#       prefer Invoke-DefaultUserHiveRemediation.ps1 or a domain GPO for those.
# ==============================================================================

[CmdletBinding()]
param (
    [string]$CklDirectory = $PSScriptRoot,
    [string]$LogDirectory = "$PSScriptRoot\Logs",
    [string]$LgpoExePath,
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
$LogFile      = "$LogDirectory\GpoRemediation_$RunTimestamp.log"

if (!(Test-Path $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
Start-Transcript -Path $LogFile -Append

# ---------------------------------
# --- HELPERS
# ---------------------------------

function Write-GpoLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARN", "ERROR", "CMD", "MANUAL", "SECTION")]
        [string]$Level = "INFO"
    )
    $ts   = Get-Date -Format "HH:mm:ss"
    $line = "[$ts][$Level] $Message"
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

# --- Resolve LGPO.exe -------------------------------------------------------
if (-not $LgpoExePath) {
    $coLocated = Join-Path $ScriptDir 'LGPO.exe'
    if (Test-Path -LiteralPath $coLocated) {
        $LgpoExePath = $coLocated
    } else {
        $onPath = Get-Command 'LGPO.exe' -ErrorAction SilentlyContinue
        if ($onPath) { $LgpoExePath = $onPath.Source }
    }
}
if (-not $LgpoExePath -or -not (Test-Path -LiteralPath $LgpoExePath)) {
    Write-GpoLog "LGPO.exe not found. Pass -LgpoExePath, or place LGPO.exe next to this script. (Microsoft Security Compliance Toolkit)" "ERROR"
    Stop-Transcript
    exit 1
}
Write-GpoLog "Using LGPO.exe: $LgpoExePath" "INFO"

# Maps a PowerShell registry drive path (HKLM:\... / HKCU:\...) to the
# {Scope; SubPath} pair LGPO text format needs. LGPO only has Computer (HKLM)
# and User (HKCU) scope - anything else (e.g. HKCR, from ConvertTo-PsRegistryPath's
# generic fallback) is not representable and is treated as out of scope.
function ConvertTo-LgpoScope {
    param([string]$PsPath)
    if ($PsPath -match '^HKLM:\\(.+)$') { return [pscustomobject]@{ Scope = 'Computer'; SubPath = $Matches[1] } }
    if ($PsPath -match '^HKCU:\\(.+)$') { return [pscustomobject]@{ Scope = 'User';     SubPath = $Matches[1] } }
    return $null
}

# Maps a PowerShell -Type token (as produced by ConvertTo-RegistryType) to the
# LGPO text type token. $null means "not representable in LGPO text" - callers
# should treat that item as out of scope rather than guess.
function ConvertTo-LgpoTypeToken {
    param([string]$PsType)
    switch ($PsType) {
        'DWord'        { return 'DWORD'   }
        'QWord'        { return 'QWORD'   }
        'String'       { return 'SZ'      }
        'ExpandString' { return 'EXSZ'    }
        'Binary'       { return 'BINARY'  }
        'MultiString'  { return 'MULTISZ' }
        default        { return $null }
    }
}

# Builds the LGPO text lines for one registry item. Every entry restates its
# own Computer/User scope keyword (matches real LGPO /parse output - it is not
# one header followed by many paths). MULTISZ is a best-effort split on ';' or
# newlines - no real STIG sample in this toolkit's test data ever produced a
# MultiString item, so spot-check the output if this path ever actually fires.
function ConvertTo-LgpoStanzaLines {
    param(
        [string]$Scope,
        [string]$SubPath,
        [string]$ValueName,
        [string]$LgpoType,
        [string]$Value
    )
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add($Scope)
    $lines.Add($SubPath)
    $lines.Add($ValueName)
    if ($LgpoType -eq 'MULTISZ') {
        $lines.Add('MULTISZ:')
        foreach ($part in @($Value -split '(?:;|\r?\n)' | Where-Object { $_ -ne '' })) { $lines.Add($part) }
    } elseif ($LgpoType -eq 'BINARY') {
        $lines.Add("BINARY:$($Value -replace '[^0-9A-Fa-f]', '')")
    } else {
        $lines.Add("$($LgpoType):$Value")
    }
    $lines.Add('')   # blank line terminates the entry
    return , $lines
}

# Runs LGPO.exe, honoring -WhatIf (report what would run, apply nothing).
function Invoke-Lgpo {
    param([string[]]$LgpoArgs, [string]$Description)
    if ($WhatIf) {
        Write-GpoLog "WHATIF: Would execute: `"$LgpoExePath`" $($LgpoArgs -join ' ')" "INFO"
        return $true
    }
    try {
        Write-GpoLog "Executing: $Description" "CMD"
        $proc = Start-Process -FilePath $LgpoExePath -ArgumentList $LgpoArgs -Wait -NoNewWindow -PassThru -ErrorAction Stop
        if ($proc.ExitCode -eq 0) {
            Write-GpoLog "LGPO.exe completed successfully (exit 0)." "SUCCESS"
            return $true
        } else {
            Write-GpoLog "LGPO.exe exited with code $($proc.ExitCode)." "ERROR"
            return $false
        }
    } catch {
        Write-GpoLog "Failed to execute LGPO.exe: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ==============================================================================
# --- MAIN SCRIPT
# ==============================================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " STIG GPO (LGPO) Remediation Engine" -ForegroundColor Cyan
Write-Host " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
if ($WhatIf) { Write-Host " [WHATIF MODE - LGPO text will be generated but nothing applied]" -ForegroundColor Yellow }
Write-Host "============================================================`n" -ForegroundColor Cyan

# .cklb only - this script's scope is explicitly the JSON checklist format
# (legacy CKL/XML is handled by Invoke-StigCklRemediation.ps1).
$CklbFiles = @(Get-ChildItem -Path $CklDirectory -Filter '*.cklb' -File -ErrorAction SilentlyContinue)
if (-not $CklbFiles -or $CklbFiles.Count -eq 0) {
    Write-Error "No .cklb files found in '$CklDirectory'. Exiting."
    Stop-Transcript
    exit 1
}
Write-Host "Found $($CklbFiles.Count) .cklb file(s) in '$CklDirectory'`n" -ForegroundColor Yellow

$MasterLines = [System.Collections.Generic.List[string]]::new()
$SeenKeys    = [System.Collections.Generic.HashSet[string]]::new()
$Summary     = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($CklbFile in $CklbFiles) {

    Write-GpoLog "============================================================" "SECTION"
    Write-GpoLog "Processing: $($CklbFile.Name)" "SECTION"
    Write-GpoLog "============================================================" "SECTION"

    $OpenFindings = Get-CklFindings -Path $CklbFile.FullName -Status Open
    if (-not $OpenFindings -or @($OpenFindings).Count -eq 0) {
        Write-GpoLog "No Open findings (or parse failed) - nothing to do." "SUCCESS"
        $Summary.Add([pscustomobject]@{ File = $CklbFile.Name; Title = $CklbFile.BaseName; Open = 0; GpoItems = 0; FindingsCovered = 0; NoData = 0 })
        continue
    }

    $FileLines       = [System.Collections.Generic.List[string]]::new()
    $itemCount       = 0
    $coveredFindings = 0
    $noDataFindings  = 0

    foreach ($finding in $OpenFindings) {
        if (@($finding.RegistryItems).Count -eq 0) {
            $noDataFindings++
            continue
        }

        $hitThisFinding = $false
        foreach ($item in $finding.RegistryItems) {
            $scopeInfo = ConvertTo-LgpoScope -PsPath $item.Path
            if (-not $scopeInfo) {
                Write-GpoLog "  SKIP $($finding.VulnNum) - '$($item.Path)' is not a Computer/User (HKLM/HKCU) hive; not LGPO-applicable." "WARN"
                continue
            }
            $lgpoType = ConvertTo-LgpoTypeToken -PsType $item.Type
            if (-not $lgpoType) {
                Write-GpoLog "  SKIP $($finding.VulnNum) - registry type '$($item.Type)' has no LGPO text equivalent." "WARN"
                continue
            }

            $key = "$($scopeInfo.Scope)|$($scopeInfo.SubPath)|$($item.Name)"
            if (-not $SeenKeys.Add($key)) {
                Write-GpoLog "  CONFLICT $($finding.VulnNum) - '$($scopeInfo.SubPath)\$($item.Name)' was already set by an earlier finding/STIG in this run. Last write wins." "WARN"
            }

            $stanza = ConvertTo-LgpoStanzaLines -Scope $scopeInfo.Scope -SubPath $scopeInfo.SubPath -ValueName $item.Name -LgpoType $lgpoType -Value $item.Value
            $FileLines.AddRange($stanza)
            $MasterLines.AddRange($stanza)
            $itemCount++
            $hitThisFinding = $true
        }
        if ($hitThisFinding) { $coveredFindings++ } else { $noDataFindings++ }
    }

    Write-GpoLog "Open findings: $(@($OpenFindings).Count) | LGPO items: $itemCount | Findings covered: $coveredFindings | No GPO data: $noDataFindings" "INFO"

    if ($FileLines.Count -gt 0) {
        $fileLgpoPath = "$LogDirectory\$($CklbFile.BaseName)_gpo.lgpo.txt"
        $FileLines | Set-Content -Path $fileLgpoPath -Encoding utf8
        Write-GpoLog "Per-file LGPO text written -> $fileLgpoPath" "INFO"
    }

    $Summary.Add([pscustomobject]@{
        File = $CklbFile.Name; Title = $OpenFindings[0].StigTitle
        Open = @($OpenFindings).Count; GpoItems = $itemCount
        FindingsCovered = $coveredFindings; NoData = $noDataFindings
    })
}

# ==============================================================================
# --- APPLY MERGED LGPO TEXT
# ==============================================================================
if ($MasterLines.Count -eq 0) {
    Write-GpoLog "No LGPO-applicable settings found across any .cklb file. Nothing to apply." "WARN"
} else {
    $MasterLgpoPath = "$LogDirectory\Master_GPO_$RunTimestamp.lgpo.txt"
    $MasterLines | Set-Content -Path $MasterLgpoPath -Encoding utf8
    Write-GpoLog "Master LGPO text written -> $MasterLgpoPath" "INFO"

    $lgpoArgs = @('/t', ('"{0}"' -f $MasterLgpoPath), '/v')
    Invoke-Lgpo -LgpoArgs $lgpoArgs -Description "Apply merged GPO text ($MasterLgpoPath) via LGPO.exe" | Out-Null
}

# ==============================================================================
# --- POST-RUN GPO CHECK
# ==============================================================================
# Local GPO edits (via LGPO) can still be overwritten by Domain GPO at the next refresh.
Write-Host "`n[Performing Post-Application Domain/GPO Check...]" -ForegroundColor Cyan
try {
    $GpoResult  = gpresult /r /Scope Computer 2>&1
    $GpoApplied = $GpoResult | Select-String "Applied Group Policy Objects" -Quiet
    if ($GpoApplied) {
        Write-Warning "CRITICAL: This machine is receiving Domain GPOs. Local GPO settings applied by LGPO may be overwritten at the next GPO refresh or reboot. Confirm settings survive a 'gpupdate /force'."
    } else {
        Write-Host "[SUCCESS] No Domain GPOs detected. Local GPO settings applied via LGPO.exe should persist." -ForegroundColor Green
    }
} catch {
    Write-Host "[INFO] 'gpresult' unavailable. Assuming no Domain GPOs active." -ForegroundColor Gray
}

# ==============================================================================
# --- MASTER SUMMARY TABLE
# ==============================================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " MASTER GPO REMEDIATION SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$Summary | Format-Table -AutoSize
Write-Host "Run log      : $LogFile" -ForegroundColor Cyan
Write-Host "Per-file text: $LogDirectory\*_gpo.lgpo.txt" -ForegroundColor Cyan
if ($MasterLines.Count -gt 0) { Write-Host "Master text  : $MasterLgpoPath" -ForegroundColor Cyan }
Write-Host "============================================================`n" -ForegroundColor Cyan

Stop-Transcript
