#requires -Version 7.0
# ==============================================================================
# STIG-CKL-Helpers.psm1
# Shared utility module for the STIG CKL Remediation Toolkit.
#
# REQUIRES PowerShell 7.0+ (the #requires statement above hard-blocks Windows
# PowerShell 5.1 — the toolkit uses PS7-only syntax such as the null-coalescing
# operator `??` and is only validated on the 7.x runtime).
#
# Import in any companion script with:
#   Import-Module "$PSScriptRoot\STIG-CKL-Helpers.psm1" -Force
#
# SUPPORTED CHECKLIST FORMATS:
#   .cklb                 - current Evaluate-STIG native format (JSON).
#   *_ckl.txt, .ckl, .xml - legacy Evaluate-STIG / STIG Viewer format (XML).
#   Get-CklFindings detects the format from the file extension and returns the
#   same finding-object shape either way, so every caller stays format-agnostic.
#
# Public surface (see Export-ModuleMember at the bottom):
#   Initialize-StigEnvironment  - one-call bootstrap: OS/version guard, process
#                                 execution policy, and self-elevation via pwsh.
#   Get-CklFileList             - robust CKL/checklist file discovery (.cklb + XML).
#   Get-CklFindings             - parse a CKLB or CKL into structured finding objects.
#   Get-StigRegistryItems       - extract registry items from Check/Fix text.
#   ConvertTo-PsRegistryPath    - CKL hive+path  -> PowerShell registry path.
#   ConvertTo-RegistryType      - REG_* token    -> PowerShell -Type token.
#   ConvertFrom-RegHexValue     - "0x..(N)"       -> "N".
# ==============================================================================

# ==============================================================================
# --- ENVIRONMENT BOOTSTRAP
# ==============================================================================

function Initialize-StigEnvironment {
<#
.SYNOPSIS
    One-call environment bootstrap shared by every entry script.

.DESCRIPTION
    Performs three jobs, in order:
      1. Platform/version guard - the toolkit manipulates the Windows registry
         (Get/Set-ItemProperty), reg.exe and wevtutil, so it refuses to run on
         anything other than Windows. (The #requires -Version 7.0 line in each
         file already guarantees PowerShell 7+.)
      2. Execution policy - sets a *Process-scoped* Bypass policy. Process scope
         does not persist on disk and is honored both for normal local launches
         AND for sessions created over PowerShell Remoting (Invoke-Command),
         where the machine policy might otherwise be Restricted/AllSigned.
      3. Self-elevation - if the current process is not running as Administrator,
         it relaunches the *same* script, elevated, under PowerShell 7 (pwsh),
         forwarding every bound parameter verbatim so switches like -WhatIf and
         custom paths are never silently dropped.

.PARAMETER ScriptPath
    Pass the caller's $PSCommandPath. Used to relaunch the script elevated.

.PARAMETER BoundParameters
    Pass the caller's $PSBoundParameters. Forwarded verbatim to the elevated
    relaunch.

.OUTPUTS
    [bool]  $true  -> already elevated; the caller should continue.
            $false -> an elevated copy was launched; the caller should `exit`.

.EXAMPLE
    if (-not (Initialize-StigEnvironment -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters)) { exit 0 }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [hashtable]$BoundParameters = @{}
    )

    # --- 1. Windows-only guard --------------------------------------------------
    # $IsWindows is a PowerShell 7 automatic variable ($true only on Windows).
    if (-not $IsWindows) {
        throw "This toolkit targets Windows endpoints only. Run it under PowerShell 7 on Windows."
    }

    # --- 2. Process-scoped execution policy (local + remote) --------------------
    # -Scope Process applies to THIS instance only and is not written to disk,
    # so it is safe on managed endpoints and effective inside remoting sessions.
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not set process execution policy: $($_.Exception.Message)"
    }

    # --- 3. Administrator check / self-elevation --------------------------------
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Verbose "Already running elevated."
        return $true   # caller continues
    }

    Write-Host "[INFO] Not elevated - relaunching under PowerShell 7 as Administrator (UAC prompt)..." -ForegroundColor Yellow

    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) {
        throw "Cannot self-elevate: script path '$ScriptPath' is unavailable. Re-run from an elevated PowerShell 7 prompt."
    }

    # Resolve the PowerShell 7 host. We deliberately NEVER fall back to
    # powershell.exe (Windows PowerShell 5.1), because this toolkit will not
    # parse on 5.1.
    $pwshExe = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if (-not $pwshExe) { $pwshExe = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe' }
    if (-not (Test-Path -LiteralPath $pwshExe)) {
        throw "PowerShell 7 (pwsh.exe) was not found. Install PowerShell 7 before running this toolkit."
    }

    # Rebuild the argument list, forwarding every bound parameter so the elevated
    # instance behaves identically to the one the operator launched.
    $argv = [System.Collections.Generic.List[string]]::new()
    $argv.AddRange([string[]]@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $ScriptPath)))
    foreach ($entry in $BoundParameters.GetEnumerator()) {
        $val = $entry.Value
        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val.IsPresent) { $argv.Add("-$($entry.Key)") }          # switch: name only when present
        } else {
            $argv.Add("-$($entry.Key)")
            $argv.Add(('"{0}"' -f ([string]$val)))                       # quote values (handles spaces in paths)
        }
    }

    # -Verb RunAs triggers the UAC elevation prompt and starts a fresh process.
    Start-Process -FilePath $pwshExe -Verb RunAs -ArgumentList $argv | Out-Null
    return $false   # signal the non-elevated caller to exit
}

# ==============================================================================
# --- CKL FILE DISCOVERY
# ==============================================================================

function Get-CklFileList {
<#
.SYNOPSIS
    Returns the set of CKL/checklist files to process from a directory.

.DESCRIPTION
    Primary match is the Evaluate-STIG naming convention (*_ckl.txt). If none are
    found, it falls back to any *.ckl / *.xml file.

    NOTE on the fallback: Get-ChildItem's -Include parameter is ignored unless the
    -Path ends in a wildcard (or -Recurse is used). The original scripts called
    `Get-ChildItem -Path $dir -Include '*.ckl','*.xml'` which silently returned
    nothing. We join '*' onto the path so -Include actually takes effect.

.PARAMETER Directory
    Directory to search (non-recursive).

.PARAMETER ExcludePattern
    Optional -like pattern; files whose Name matches are excluded (e.g. patched
    output written back into the same folder).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [string]$ExcludePattern
    )

    # Primary: current Evaluate-STIG output - native CKLB (JSON) and the
    # *_ckl.txt (XML) naming, merged together (a directory may legitimately
    # contain a mix from different scan runs / tool versions).
    $files  = @(Get-ChildItem -Path $Directory -Filter '*.cklb'    -File -ErrorAction SilentlyContinue)
    $files += @(Get-ChildItem -Path $Directory -Filter '*_ckl.txt' -File -ErrorAction SilentlyContinue)

    # Fallback: classic .ckl / .xml. The trailing '*' is REQUIRED for -Include to work.
    if (-not $files -or $files.Count -eq 0) {
        $files = @(Get-ChildItem -Path (Join-Path $Directory '*') -Include '*.ckl', '*.xml' -File -ErrorAction SilentlyContinue)
    }

    if ($ExcludePattern) {
        $files = @($files | Where-Object { $_.Name -notlike $ExcludePattern })
    }

    # Comma-wrap so a single match is returned as a 1-element array (not unrolled
    # to a bare FileInfo), keeping .Count / indexing correct for callers.
    return , $files
}

# ==============================================================================
# --- REGISTRY PATH / TYPE HELPERS
# ==============================================================================

function ConvertTo-PsRegistryPath {
    # Converts a CKL hive name + sub-path to a PowerShell registry drive path.
    param([string]$Hive, [string]$SubPath)
    # Normalize: trim whitespace, leading/trailing backslashes, and a stray
    # trailing period that sometimes appears in CKL text.
    $SubPath = $SubPath.Trim().TrimStart('\').TrimEnd('\').TrimEnd('.')
    switch -Regex ($Hive.Trim()) {
        'HKEY_LOCAL_MACHINE|^HKLM'  { return "HKLM:\$SubPath" }
        'HKEY_CURRENT_USER|^HKCU'   { return "HKCU:\$SubPath" }
        'HKEY_CLASSES_ROOT|^HKCR'   { return "HKCR:\$SubPath" }
        default                     { return "$($Hive.Trim()):\$SubPath" }
    }
}

function ConvertTo-RegistryType {
    # Normalizes a REG_* string to the PowerShell Set-ItemProperty -Type token.
    # NOTE: unknown/blank types fall back to DWord (the overwhelmingly common
    # case in STIG content). A Write-Verbose is emitted so mis-detections are
    # discoverable with -Verbose without changing behavior.
    param([string]$RegType)
    switch -Wildcard ($RegType.Trim().ToUpper()) {
        'REG_DWORD*'    { return 'DWord'       }
        'REG_SZ'        { return 'String'      }
        'REG_EXPAND_SZ' { return 'ExpandString' }
        'REG_BINARY'    { return 'Binary'      }
        'REG_QWORD*'    { return 'QWord'       }
        'REG_MULTI_SZ'  { return 'MultiString' }
        default         {
            Write-Verbose "ConvertTo-RegistryType: unrecognized type '$RegType' - defaulting to DWord."
            return 'DWord'
        }
    }
}

function ConvertFrom-RegHexValue {
    # Strips the hex-with-decimal format "0x00000001 (1)" down to just "1";
    # otherwise trims surrounding quotes/whitespace.
    param([string]$RawValue)
    if ($RawValue -match '0x[0-9a-fA-F]+\s*\((\d+)\)') { return $Matches[1] }
    return $RawValue.Trim().Trim('"').Trim("'")
}

# ==============================================================================
# --- CORE REGISTRY ITEM EXTRACTOR
# ==============================================================================

function Get-StigRegistryItems {
    <#
    .SYNOPSIS
    Extracts registry remediation items from STIG Check_Content and Fix_Text.
    Returns an array of @{ Path; Name; Value; Type } hashtables.

    Patterns handled:
      A - Structured "Registry Hive / Registry Path / Value Name / Type / Value" block
      B - "Navigate to key" + "not a finding" / "is a finding" value assertions
          B1: "If [the] value [for] X is [set to] REG_TYPE = val, this is not a finding"
          B2: "value for "X" is not set to "REG_TYPE = N", this is a finding"
          B3: Compact inline "Value Name / Type / Value" block (Adobe style)
      C - Defender ASR GUID-keyed rules extracted from Fix_Text

    .NOTE
    This is heuristic text parsing. Always review a -WhatIf / report run before
    applying to production. Treat extracted items as a gap-filler, not an
    authoritative control source.
    #>
    param(
        [string]$CheckContent,
        [string]$FixText
    )

    $items = [System.Collections.Generic.List[hashtable]]::new()
    $seen  = [System.Collections.Generic.HashSet[string]]::new()

    # Combine check and fix text; normalize hive aliases to short forms.
    $normText = ($CheckContent + "`n`n--- FIX ---`n`n" + $FixText) `
        -replace 'HKEY_LOCAL_MACHINE', 'HKLM' `
        -replace 'HKEY_CURRENT_USER',  'HKCU'

    # --- Pattern A: structured multi-line block --------------------------------
    $reA = [regex]::new(
        'Registry Hive:\s*(HK[A-Z_ ]+?)\s+Registry Path:\s*(\\[^\r\n]+?)\s+Value Name:\s*([^\r\n]+?)\s+(?:Value Type|Type):\s*(REG_[A-Z_]+)\s+Value:\s*([^\r\n]+)',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    foreach ($m in $reA.Matches($normText)) {
        $path = ConvertTo-PsRegistryPath -Hive $m.Groups[1].Value -SubPath $m.Groups[2].Value
        $name = $m.Groups[3].Value.Trim()
        $type = ConvertTo-RegistryType $m.Groups[4].Value
        $val  = ConvertFrom-RegHexValue $m.Groups[5].Value
        if ($seen.Add("$path|$name")) { $items.Add(@{ Path = $path; Name = $name; Value = $val; Type = $type }) }
    }

    # --- Pattern B: "navigate to key" + value assertion ------------------------
    $reNav = [regex]::new(
        '(?:navigate to the following(?:\s+key)?[:\s]+|Utilizing the Registry Editor[^,]*,\s*navigate[^:]*:\s+)(HK(?:LM|CU)\\[^\r\n]+)',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    foreach ($km in $reNav.Matches($normText)) {
        $rawK = $km.Groups[1].Value.Trim()
        if ($rawK -notmatch '^(HK(?:LM|CU))\\(.+)$') { continue }
        $psPath = ConvertTo-PsRegistryPath -Hive $Matches[1] -SubPath $Matches[2]

        # Capture the text window after this key (up to next HK reference or 1000 chars).
        $after  = $normText.Substring($km.Index + $km.Length)
        $nextHK = [regex]::Match($after, 'HK(?:LM|CU)\\')
        $capLen = if ($nextHK.Success -and $nextHK.Index -lt 1000) { $nextHK.Index } else { [Math]::Min(1000, $after.Length) }
        $win    = $after.Substring(0, $capLen)

        # B1 - "this is not a finding"
        $reB1 = [regex]::new(
            'If (?:the )?value(?: for)?\s+"?([A-Za-z][A-Za-z0-9_\s]{0,60}?)"?\s+(?:is|is set to)\s+(REG_[A-Z_]+)\s*=\s*(?:"([^"]{1,300})"|([^",\r\n]{1,100}?)),?\s*this is not a finding',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        foreach ($vm in $reB1.Matches($win)) {
            $vname = ($vm.Groups[1].Value.Trim() -replace '\s+', '')   # collapse multi-word value names
            $vtype = ConvertTo-RegistryType $vm.Groups[2].Value
            $vval  = if ($vm.Groups[3].Success -and $vm.Groups[3].Value) { $vm.Groups[3].Value.Trim() } else { ConvertFrom-RegHexValue $vm.Groups[4].Value }
            if ($seen.Add("$psPath|$vname")) { $items.Add(@{ Path = $psPath; Name = $vname; Value = $vval; Type = $vtype }) }
        }

        # B2 - "this is a finding"
        $reB2 = [regex]::new(
            'value(?: for)?\s+"([^"]{1,80})"\s+is not set to\s+"(REG_[A-Z_]+)\s*=\s*(\d+)",\s*this is a finding',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        foreach ($vm in $reB2.Matches($win)) {
            $vname = $vm.Groups[1].Value.Trim()
            $vtype = ConvertTo-RegistryType $vm.Groups[2].Value
            $vval  = $vm.Groups[3].Value.Trim()
            if ($seen.Add("$psPath|$vname")) { $items.Add(@{ Path = $psPath; Name = $vname; Value = $vval; Type = $vtype }) }
        }

        # B3 - compact inline block (Adobe style)
        $reB3 = [regex]::new(
            'Value Name:\s*([^\r\n]+?)\s*[\r\n]+\s*(?:Value\s+)?Type:\s*(REG_[A-Z_]+)\s*[\r\n]+\s*Value:\s*([^\r\n]+)',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        foreach ($vm in $reB3.Matches($win)) {
            $vname = $vm.Groups[1].Value.Trim()
            $vtype = ConvertTo-RegistryType $vm.Groups[2].Value
            $vval  = ConvertFrom-RegHexValue $vm.Groups[3].Value
            if ($seen.Add("$psPath|$vname")) { $items.Add(@{ Path = $psPath; Name = $vname; Value = $vval; Type = $vtype }) }
        }
    }

    # --- Pattern C: Defender ASR GUID rules ------------------------------------
    $reAsrKey  = [regex]::new('(HK(?:LM|CU)\\[^\r\n]*ASR\\Rules)', 'IgnoreCase')
    $reAsrGuid = [regex]::new(
        '(?:Set the [Vv]alue name to|Enter GUID)\s+"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"\s+(?:and the Value to|in the "Value Name" column\.\s+Enter)\s+"(\d+)"',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    $asrKM = $reAsrKey.Match($normText)
    if ($asrKM.Success -and $asrKM.Groups[1].Value -match '^(HK(?:LM|CU))\\(.+)$') {
        $asrPath = ConvertTo-PsRegistryPath -Hive $Matches[1] -SubPath $Matches[2]
        foreach ($gm in $reAsrGuid.Matches($normText)) {
            $guid = $gm.Groups[1].Value.ToUpper()
            if ($seen.Add("$asrPath|$guid")) { $items.Add(@{ Path = $asrPath; Name = $guid; Value = $gm.Groups[2].Value; Type = 'DWord' }) }
        }
    }

    # Comma-wrap so a single extracted item is NOT unrolled to a bare hashtable
    # (which would make $result.Count report the key count, not the item count).
    return , $items
}

# ==============================================================================
# --- CKLB (JSON) STATUS NORMALIZATION + PARSER
# ==============================================================================

function ConvertTo-NormalizedStigStatus {
    # Maps CKLB's lowercase/underscore status tokens to the same CKL-style
    # casing used throughout this module and by every caller (Open,
    # NotAFinding, Not_Reviewed, Not_Applicable). Unrecognized values pass
    # through unchanged so they surface visibly rather than being swallowed.
    param([string]$RawStatus)
    switch (($RawStatus ?? '').Trim().ToLower()) {
        'open'           { return 'Open' }
        'not_a_finding'  { return 'NotAFinding' }
        'not_reviewed'   { return 'Not_Reviewed' }
        'not_applicable' { return 'Not_Applicable' }
        default          { return $RawStatus }
    }
}

function Get-CklbFindings {
    <#
    .SYNOPSIS
    Parses a STIG CKLB (.cklb, JSON) file and returns the same structured
    finding-object shape as Get-CklFindings' XML path. Internal helper - only
    called via the format dispatch at the top of Get-CklFindings.

    .PARAMETER Path
    Full path to the .cklb file.

    .PARAMETER Status
    Filter by finding status (CKL-style casing). Defaults to 'Open'. Pass
    'All' for every rule.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Open', 'NotAFinding', 'Not_Reviewed', 'Not_Applicable', 'All')]
        [string]$Status = 'Open'
    )

    try {
        $cklb = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 64
    } catch {
        Write-Warning "Get-CklbFindings: failed to parse '$Path': $($_.Exception.Message)"
        return @()
    }

    $hostName = $cklb.target_data.host_name
    $results  = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($stig in $cklb.stigs) {
        foreach ($rule in $stig.rules) {
            $normStatus = ConvertTo-NormalizedStigStatus $rule.status
            if ($Status -ne 'All' -and $normStatus -ne $Status) { continue }

            $checkContent = $rule.check_content ?? ''
            $fixText      = $rule.fix_text      ?? ''
            $regItems     = Get-StigRegistryItems -CheckContent $checkContent -FixText $fixText

            $results.Add([pscustomobject]@{
                # STIG-level metadata
                StigTitle      = $stig.stig_name    ?? $stig.display_name ?? ''
                StigFile       = $stig.stig_id       ?? ''
                StigRelease    = $stig.release_info  ?? ''
                HostName       = $hostName
                CklPath        = $Path

                # Finding fields
                VulnNum        = $rule.group_id      ?? ''
                RuleId         = $rule.rule_id_src    ?? ''
                RuleVer        = $rule.rule_version   ?? ''
                RuleTitle      = $rule.rule_title     ?? ''
                Severity       = $rule.severity       ?? ''
                CheckContent   = $checkContent
                FixText        = $fixText
                Status         = $normStatus
                FindingDetails = $rule.finding_details ?? ''
                Comments       = $rule.comments        ?? ''

                # Pre-extracted registry items
                RegistryItems  = $regItems
            })
        }
    }

    # Comma-wrap so a single finding is returned as a 1-element array.
    return , $results
}

# ==============================================================================
# --- CKL FILE PARSER
# ==============================================================================

function Get-CklFindings {
    <#
    .SYNOPSIS
    Parses a STIG checklist file (.cklb JSON, or legacy *_ckl.txt/.ckl/.xml)
    and returns structured finding objects. Each object exposes the same set
    of named properties regardless of source format, plus a RegistryItems
    array pre-populated by Get-StigRegistryItems.

    .PARAMETER Path
    Full path to the checklist file. The .cklb extension is dispatched to the
    JSON parser (Get-CklbFindings); everything else is parsed as XML.

    .PARAMETER Status
    Filter by finding status. Defaults to 'Open'. Pass 'All' for every VULN.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Open', 'NotAFinding', 'Not_Reviewed', 'Not_Applicable', 'All')]
        [string]$Status = 'Open'
    )

    if ([IO.Path]::GetExtension($Path) -ieq '.cklb') {
        return Get-CklbFindings -Path $Path -Status $Status
    }

    try {
        [xml]$ckl = Get-Content -Path $Path -Raw -Encoding UTF8
    } catch {
        Write-Warning "Get-CklFindings: failed to parse '$Path': $($_.Exception.Message)"
        return @()
    }

    # Pull STIG-level metadata (title / release / filename).
    $meta = @{}
    foreach ($sid in $ckl.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA) {
        if ($sid.SID_NAME -and $sid.SID_DATA) { $meta[$sid.SID_NAME] = $sid.SID_DATA }
    }

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($vuln in $ckl.CHECKLIST.STIGS.iSTIG.VULN) {
        if ($Status -ne 'All' -and $vuln.STATUS -ne $Status) { continue }

        $sd = @{}
        foreach ($node in $vuln.STIG_DATA) { $sd[$node.VULN_ATTRIBUTE] = $node.ATTRIBUTE_DATA }

        $checkContent = $sd['Check_Content'] ?? ''
        $fixText      = $sd['Fix_Text']      ?? ''
        $regItems     = Get-StigRegistryItems -CheckContent $checkContent -FixText $fixText

        $results.Add([pscustomobject]@{
            # STIG-level metadata
            StigTitle      = $meta['title']       ?? ''
            StigFile       = $meta['filename']    ?? ''
            StigRelease    = $meta['releaseinfo'] ?? ''
            HostName       = $ckl.CHECKLIST.ASSET.HOST_NAME
            CklPath        = $Path

            # Finding fields
            VulnNum        = $sd['Vuln_Num']    ?? ''
            RuleId         = $sd['Rule_ID']     ?? ''
            RuleVer        = $sd['Rule_Ver']    ?? ''
            RuleTitle      = $sd['Rule_Title']  ?? ''
            Severity       = $sd['Severity']    ?? ''
            CheckContent   = $checkContent
            FixText        = $fixText
            Status         = $vuln.STATUS       ?? ''
            FindingDetails = $vuln.FINDING_DETAILS ?? ''
            Comments       = $vuln.COMMENTS     ?? ''

            # Pre-extracted registry items
            RegistryItems  = $regItems
        })
    }

    # Comma-wrap so a single finding is returned as a 1-element array.
    return , $results
}

# ==============================================================================
# --- MODULE EXPORTS
# ==============================================================================
Export-ModuleMember -Function @(
    'Initialize-StigEnvironment',
    'Get-CklFileList',
    'ConvertTo-PsRegistryPath',
    'ConvertTo-RegistryType',
    'ConvertFrom-RegHexValue',
    'Get-StigRegistryItems',
    'Get-CklFindings'
)
