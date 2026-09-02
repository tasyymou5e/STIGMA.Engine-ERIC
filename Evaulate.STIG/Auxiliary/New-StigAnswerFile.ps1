#Requires -Version 7.0
# ==============================================================================
# New-StigAnswerFile.ps1
# Generates Evaluate-STIG answer files (.xml) from existing CKL or CKLB checklist
# files.  For each Open finding whose registry items can be extracted by the
# STIG-CKL-Helpers parser, a ValidationCode block is generated that reads the live
# registry and automatically marks the finding Not A Finding when the expected
# value is present.  This makes re-scans self-verifying: after remediation, the
# answer file confirms compliance without manual review.
#
# Usage:
#   # Generate answer files from all checklists in a folder
#   Get-ChildItem .\Checklist\*.ckl,*.cklb | .\New-StigAnswerFile.ps1
#
#   # Single file, VDI mode (marks known VDI Not-Applicable findings)
#   .\New-StigAnswerFile.ps1 -CklPath .\OFFICEDESK_Win11_V2R9.ckl -VdiMode
#
#   # Specify output location and answer key name
#   .\New-StigAnswerFile.ps1 -CklPath .\Win11.ckl -OutputPath ..\Evaluate-STIG\AnswerFiles -AnswerKey VDI_GOLD
#
# Answer file placement:
#   By default, files are saved to <EvaluateStigRoot>\Evaluate-STIG\AnswerFiles\
#   as <StigShortName>.xml.  If a file already exists, -Force overwrites it;
#   without -Force the existing file is left untouched and a warning is shown.
# ==============================================================================

param (
    # One or more CKL or CKLB files to generate answer files from.
    # Pass multiple files as an array or pipe file paths as strings.
    # Example: Get-ChildItem .\Checklist\*.ckl | ForEach-Object { .\New-StigAnswerFile.ps1 -CklPath $_.FullName }
    [Parameter(Mandatory)]
    [string[]]$CklPath,

    # Where to save generated answer files.
    # Defaults to <EvaluateStigRoot>\Evaluate-STIG\AnswerFiles\.
    [string]$OutputPath,

    # Answer key name embedded in the generated file.
    # Must match the -AnswerKey you pass to Evaluate-STIG.ps1.
    [string]$AnswerKey = 'DEFAULT',

    # Apply VDI / non-persistent desktop Not-Applicable logic.
    # Marks findings in the VdiNaMap below as NA with a justification comment.
    [switch]$VdiMode,

    # Optional JSON file defining additional VDI NA findings beyond the built-in map.
    # Format: { "Win11": ["V-253280","V-253281"], "Chrome": [] }
    [string]$VdiNaFile,

    # Generate registry ValidationCode for findings that have extractable items.
    # On by default. Disable with -NoRegistryValidation if you want bare NR stubs.
    [switch]$NoRegistryValidation,

    # Overwrite an existing answer file. Without this switch, existing files are skipped.
    [switch]$Force,

    # Path to STIG-CKL-Helpers.psm1. Auto-detected from sibling folder.
    [string]$HelpersModule
)

# ==============================================================================
# --- HELPER FUNCTIONS (must be defined before begin/process/end blocks)
# ==============================================================================

function Add-XmlChild {
    param([System.Xml.XmlElement]$Parent, [string]$Name, [string]$Text)
    $el = $Parent.OwnerDocument.CreateElement($Name)
    if ($Text) { $el.InnerText = $Text }
    [void]$Parent.AppendChild($el)
}

function New-RegistryValidationCode {
    <#
    .SYNOPSIS
    Generates PowerShell 5.1-compatible ValidationCode that reads each registry
    item and returns a hashtable with Valid (bool) and Results (string).

    The Results string is written to the CKL Comments field, giving a per-finding
    audit trail of which values were checked and what was found.
    #>
    param([object[]]$RegItems)

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('$_valid   = $true')
    $lines.Add('$_results = @()')
    $lines.Add('')

    foreach ($item in $RegItems) {
        $path          = $item.Path
        $name          = $item.Name
        $val           = $item.Value
        $escapedPath   = $path.Replace("'","''")
        $escapedName   = $name.Replace("'","''")

        $lines.Add("try {")
        $lines.Add("    `$_actual = (Get-ItemProperty -Path '$escapedPath' -Name '$escapedName' -ErrorAction Stop).'$escapedName'")
        $lines.Add("    if ((`"`$_actual`") -ne (`"$val`")) {")
        $lines.Add("        `$_valid = `$false")
        $lines.Add("        `$_results += `"FAIL: $escapedName = '`$_actual' (expected '$val') @ $escapedPath`"")
        $lines.Add("    } else {")
        $lines.Add("        `$_results += `"PASS: $escapedName = '`$_actual' @ $escapedPath`"")
        $lines.Add("    }")
        $lines.Add("} catch {")
        $lines.Add("    `$_valid = `$false")
        $lines.Add("    `$_results += `"FAIL: $escapedName NOT FOUND @ $escapedPath`"")
        $lines.Add("}")
        $lines.Add('')
    }

    $lines.Add('@{ Valid = $_valid; Results = ($_results -join "`r`n") }')
    return ($lines -join "`r`n")
}

# ==============================================================================
# --- MAIN SCRIPT
# ==============================================================================

# ---------------------------------
# --- LOCATE HELPERS MODULE
    # ---------------------------------
    if (-not $HelpersModule) {
        # Auxiliary\ -> Evaulate.STIG\ -> STIG.Security.Hardening\ -> Rremediate.STIG.code\
        $HelpersModule = Join-Path $PSScriptRoot `
            '..\..\Rremediate.STIG.code\STIG-CKL-Helpers.psm1'
    }
    $HelpersModule = (Resolve-Path $HelpersModule -ErrorAction SilentlyContinue)?.Path
    if (-not $HelpersModule) {
        Write-Error "STIG-CKL-Helpers.psm1 not found. Set -HelpersModule explicitly.`nExpected location: Rremediate.STIG.code\STIG-CKL-Helpers.psm1"
        exit 1
    }
    Import-Module $HelpersModule -Force -ErrorAction Stop

    # ---------------------------------
    # --- DEFAULT OUTPUT PATH
    # ---------------------------------
    if (-not $OutputPath) {
        $ESRoot    = Split-Path $PSScriptRoot -Parent   # Evaulate.STIG\
        $OutputPath = Join-Path $ESRoot 'Evaluate-STIG\AnswerFiles'
    }
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # ---------------------------------
    # --- STIG SHORT-NAME LOOKUP TABLE
    # Maps the xccdf filename prefix (from CKL StigFile / CKLB stig_id) to the
    # ShortName that Evaluate-STIG expects in <STIGComments Name="...">.
    # Add entries here for any STIGs not in the default map.
    # ---------------------------------
    $script:StigShortNameMap = @{
        'U_Google_Chrome_STIG'                           = 'Chrome'
        'U_MS_Windows_11_STIG'                           = 'Win11'
        'U_MS_Windows_10_STIG'                           = 'Win10'
        'U_Office_365_ProPlus_STIG'                      = 'MSOffice365'
        'U_MS_Edge_STIG'                                 = 'MSEdge'
        'U_MS_OneDrive_STIG'                             = 'MSOneDrive'
        'U_Windows_Defender_Antivirus_STIG'              = 'MSDefender'
        'U_Windows_Firewall_with_Advanced_Security_STIG' = 'WinFirewall'
        'U_Adobe_Acrobat_Pro_DC_Continuous_STIG'         = 'AdobeAcrobatProDCContinuous'
        'U_Adobe_Acrobat_Reader_DC_Continuous_STIG'      = 'AdobeReaderDCContinuous'
        'U_Adobe_Acrobat_Pro_DC_Classic_STIG'            = 'AdobeAcrobatProDCClassic'
        'U_Microsoft_DotNet_Framework_4_STIG'            = 'DotNET4'
        'U_MS_Windows_Server_2022_STIG'                  = 'WinServer2022'
        'U_MS_Windows_Server_2019_STIG'                  = 'WinServer2019'
        'U_MS_Windows_Server_2025_STIG'                  = 'WinServer2025'
        'U_MS_Windows_Defender_Antivirus_STIG'           = 'MSDefender'
        'U_Trellix_ENS_10_x_Local_Client_STIG'          = 'TrellixENS10xLocal'
    }

    # ---------------------------------
    # --- VDI NOT-APPLICABLE FINDING MAP
    # Built-in NA reasons for Omnissa Horizon non-persistent VDI environments.
    # Keys are STIG ShortNames; values are hashtables of VulnNum -> NA justification.
    # Extend via -VdiNaFile for site-specific exemptions.
    # ---------------------------------
    $script:VdiNaMap = @{
        'Win11' = @{
            # These are REPRESENTATIVE — verify V-numbers match your STIG version.
            # Run Evaluate-STIG with -ListApplicableProducts then cross-reference.
            'PLACEHOLDER_BitLocker'     = 'BitLocker full-volume encryption is not applicable to non-persistent VDI desktops. Data at rest protection is enforced at the hypervisor/storage layer per site policy.'
            'PLACEHOLDER_WindowsHello'  = 'Windows Hello for Business is not applicable in CAC/PIV-only VDI environments where PIN-based login is disabled and Smart Card is the sole authentication method.'
            'PLACEHOLDER_StandaloneNA'  = 'This requirement is not applicable to non-persistent pooled VDI desktops managed through Omnissa Horizon. Session state does not persist between logons.'
        }
    }

    # Load site-specific NA additions from JSON file if provided
    if ($VdiNaFile -and (Test-Path $VdiNaFile)) {
        try {
            $extra = Get-Content $VdiNaFile -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            foreach ($stig in $extra.Keys) {
                if (-not $script:VdiNaMap.ContainsKey($stig)) { $script:VdiNaMap[$stig] = @{} }
                foreach ($vuln in $extra[$stig].Keys) {
                    $script:VdiNaMap[$stig][$vuln] = $extra[$stig][$vuln]
                }
            }
            Write-Verbose "Loaded VDI NA additions from $VdiNaFile"
        } catch {
            Write-Warning "Failed to parse VdiNaFile '$VdiNaFile': $($_.Exception.Message)"
        }
    }

    # Track processed STIGs to avoid duplicate answer files within the same run
    $processedStigs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# ==============================================================================
# --- PROCESS EACH CKL FILE
# ==============================================================================
foreach ($path in $CklPath) {
    $resolvedPath = (Resolve-Path $path -ErrorAction SilentlyContinue)?.Path
        if (-not $resolvedPath) {
            Write-Warning "File not found: $path"
            continue
        }

        Write-Host "`n--- Processing: $(Split-Path $resolvedPath -Leaf)" -ForegroundColor Cyan

        # Load all findings (Open and Not_Reviewed — we want to answer both)
        $findings = Get-StigFindings -Path $resolvedPath -Status 'All' |
                    Where-Object { $_.Status -in 'Open','Not_Reviewed' }

        if ($findings.Count -eq 0) {
            Write-Host "  No Open or Not_Reviewed findings — skipping." -ForegroundColor Gray
            continue
        }

        # ---------------------------------
        # --- DETERMINE STIG SHORT NAME
        # ---------------------------------
        $firstFinding = $findings[0]
        $stigFile     = $firstFinding.StigFile   # e.g. "U_Google_Chrome_STIG_V2R11_Manual-xccdf.xml"
        $stigTitle    = $firstFinding.StigTitle
        $shortName    = $null

        foreach ($prefix in $script:StigShortNameMap.Keys) {
            if ($stigFile -like "$prefix*") { $shortName = $script:StigShortNameMap[$prefix]; break }
        }

        if (-not $shortName) {
            # Fallback: strip version/extension from filename
            $shortName = $stigFile -replace '^U_','' -replace '_STIG_V\d.*$','' -replace '[^A-Za-z0-9]',''
            Write-Warning "  STIG short name not in lookup table. Using derived name: '$shortName'. Verify against Evaluate-STIG -ListSupportedProducts."
        }

        Write-Host "  STIG      : $stigTitle" -ForegroundColor Gray
        Write-Host "  ShortName : $shortName" -ForegroundColor Gray
        Write-Host "  Findings  : $($findings.Count) (Open + NR)" -ForegroundColor Gray

        # ---------------------------------
        # --- CHECK FOR EXISTING FILE
        # ---------------------------------
        $outFile = Join-Path $OutputPath "$shortName.xml"
        if ((Test-Path $outFile) -and -not $Force) {
            Write-Warning "  Answer file already exists: $outFile`n  Use -Force to overwrite."
            continue
        }

        # ---------------------------------
        # --- BUILD XML DOCUMENT
        # ---------------------------------
        $xml = [System.Xml.XmlDocument]::new()
        $decl = $xml.CreateXmlDeclaration('1.0','utf-8',$null)
        [void]$xml.AppendChild($decl)

        # File-level comment
        $comment = $xml.CreateComment(@"

  Evaluate-STIG Answer File — $shortName
  STIG    : $stigTitle
  Source  : $(Split-Path $resolvedPath -Leaf)
  Host    : $($firstFinding.HostName)
  Release : $($firstFinding.StigRelease)
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

  For registry-validated findings:
    ValidTrueStatus  = NF (Not a Finding)  — registry value matches expected
    ValidFalseStatus = O  (Open)           — registry value missing or wrong

  For VDI Not-Applicable findings (VdiMode):
    ValidTrueStatus  = NA                  — always marked Not Applicable

  Place this file in the Evaluate-STIG AnswerFiles folder and run:
    .\Evaluate-STIG.ps1 -AnswerKey $AnswerKey -Output CKL,CKLB

"@)
        [void]$xml.AppendChild($comment)

        $root = $xml.CreateElement('STIGComments')
        $root.SetAttribute('Name', $shortName)
        [void]$xml.AppendChild($root)

        $generated = 0; $naCount = 0; $skipped = 0

        # ---------------------------------
        # --- PROCESS EACH FINDING
        # ---------------------------------
        $naMap = if ($VdiMode -and $script:VdiNaMap.ContainsKey($shortName)) { $script:VdiNaMap[$shortName] } else { @{} }

        foreach ($finding in ($findings | Sort-Object VulnNum)) {
            $vulnId   = $finding.VulnNum
            $regItems = $finding.RegistryItems
            $status   = $finding.Status   # Open | Not_Reviewed

            # Map to EvalSTIG format for ExpectedStatus attribute
            $esStatus = switch ($status) {
                'Open'         { 'O'  }
                'Not_Reviewed' { 'NR' }
                default        { 'NR' }
            }

            # --- VDI Not Applicable override ---
            if ($VdiMode -and $naMap.ContainsKey($vulnId)) {
                $vulnNode = $xml.CreateElement('Vuln')
                $vulnNode.SetAttribute('ID', $vulnId)

                $akNode = $xml.CreateElement('AnswerKey')
                $akNode.SetAttribute('Name', $AnswerKey)

                $ansNode = $xml.CreateElement('Answer')
                $ansNode.SetAttribute('Index', '1')
                $ansNode.SetAttribute('ExpectedStatus', $esStatus)

                Add-XmlChild $ansNode 'ValidationCode'    '$true'
                Add-XmlChild $ansNode 'ValidTrueStatus'   'NA'
                Add-XmlChild $ansNode 'ValidTrueComment'  $naMap[$vulnId]
                Add-XmlChild $ansNode 'ValidFalseStatus'  ''
                Add-XmlChild $ansNode 'ValidFalseComment' ''

                [void]$akNode.AppendChild($ansNode)
                [void]$vulnNode.AppendChild($akNode)
                [void]$root.AppendChild($vulnNode)
                $naCount++
                continue
            }

            # --- Registry-validated answer ---
            if (-not $NoRegistryValidation -and $regItems.Count -gt 0) {
                $code = New-RegistryValidationCode -RegItems $regItems

                $vulnNode = $xml.CreateElement('Vuln')
                $vulnNode.SetAttribute('ID', $vulnId)

                # Add finding title as comment for readability
                $titleComment = $xml.CreateComment(" $($finding.RuleVer): $($finding.RuleTitle.Substring(0,[Math]::Min(80,$finding.RuleTitle.Length))) ")
                [void]$vulnNode.AppendChild($titleComment)

                $akNode = $xml.CreateElement('AnswerKey')
                $akNode.SetAttribute('Name', $AnswerKey)

                $ansNode = $xml.CreateElement('Answer')
                $ansNode.SetAttribute('Index', '1')
                $ansNode.SetAttribute('ExpectedStatus', $esStatus)

                Add-XmlChild $ansNode 'ValidationCode'    $code
                Add-XmlChild $ansNode 'ValidTrueStatus'   'NF'
                Add-XmlChild $ansNode 'ValidTrueComment'  "All required registry values verified present and correctly set. Remediated by automated STIG hardening toolkit."
                Add-XmlChild $ansNode 'ValidFalseStatus'  'O'
                Add-XmlChild $ansNode 'ValidFalseComment' "One or more required registry values are missing or incorrect. Run Invoke-StigCklRemediation.ps1 to remediate."

                [void]$akNode.AppendChild($ansNode)
                [void]$vulnNode.AppendChild($akNode)
                [void]$root.AppendChild($vulnNode)
                $generated++
                continue
            }

            $skipped++
        }

        # ---------------------------------
        # --- WRITE OUTPUT FILE
        # ---------------------------------
        $writerSettings = [System.Xml.XmlWriterSettings]::new()
        $writerSettings.Encoding      = [System.Text.Encoding]::UTF8
        $writerSettings.Indent        = $true
        $writerSettings.IndentChars   = '  '
        $writer = [System.Xml.XmlWriter]::Create($outFile, $writerSettings)
        $xml.Save($writer)
        $writer.Close()

        Write-Host "  Registry-validated answers : $generated" -ForegroundColor Green
        Write-Host "  VDI Not-Applicable answers : $naCount" -ForegroundColor $(if ($naCount -gt 0) { 'Cyan' } else { 'Gray' })
        Write-Host "  Skipped (no extractable data): $skipped" -ForegroundColor Gray
        Write-Host "  Answer file written: $outFile" -ForegroundColor Green

        [void]$processedStigs.Add($shortName)
}

# ==============================================================================
# --- SUMMARY
# ==============================================================================
if ($processedStigs.Count -gt 0) {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " Answer files generated for: $($processedStigs -join ', ')" -ForegroundColor Cyan
    Write-Host " Location: $OutputPath" -ForegroundColor Cyan
    Write-Host " Next step: run Evaluate-STIG.ps1 with -AnswerKey $AnswerKey" -ForegroundColor Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan
}
