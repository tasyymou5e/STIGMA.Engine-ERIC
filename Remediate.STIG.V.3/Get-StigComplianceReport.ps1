#requires -Version 7.0
# ==============================================================================
# Get-StigComplianceReport.ps1
# Post-remediation compliance verification and HTML report generator.
#
# Reads all CKL files, checks each finding's extracted registry items against
# the live registry, and produces a self-contained dark-themed HTML report
# showing what passed, what still fails, and what needs manual review.
#
# REQUIRES: PowerShell 7.0+ (Windows). Will NOT run on Windows PowerShell 5.1.
#           Auto-elevates to Administrator via pwsh (needed to read HKLM).
#
# Usage:
#   .\Get-StigComplianceReport.ps1
#   .\Get-StigComplianceReport.ps1 -CklDirectory "D:\STIGs" -ReportPath "D:\Reports\stig.html"
#   .\Get-StigComplianceReport.ps1 -IncludeNotFindings   # also check already-passing items
# ==============================================================================

[CmdletBinding()]
param (
    [string]$CklDirectory = $PSScriptRoot,
    [string]$ReportPath   = "$PSScriptRoot\Logs\StigComplianceReport_$(Get-Date -Format 'yyyy-MM-dd_HHmm').html",
    [switch]$IncludeNotFindings
)

# ---------------------------------
# --- MODULE IMPORT + BOOTSTRAP
# ---------------------------------
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
Import-Module (Join-Path $ScriptDir 'STIG-CKL-Helpers.psm1') -Force -ErrorAction Stop

# Windows+PS7 guard, process Bypass exec policy, self-elevate via pwsh (forwards params).
if (-not (Initialize-StigEnvironment -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters)) { exit 0 }

if (-not $CklDirectory) { $CklDirectory = $ScriptDir }
if (-not $ReportPath)   { $ReportPath   = Join-Path $ScriptDir ("Logs\StigComplianceReport_{0}.html" -f (Get-Date -Format 'yyyy-MM-dd_HHmm')) }

# ---------------------------------
# --- DISCOVER CKL FILES
# ---------------------------------
$CklFiles = Get-CklFileList -Directory $CklDirectory -ExcludePattern "*PATCHED*"
if (-not $CklFiles) { Write-Error "No CKL files found in '$CklDirectory'."; exit 1 }

# ---------------------------------
# --- COMPLIANCE CHECK
# ---------------------------------

function Get-RegistryComplianceStatus {
    param([array]$RegItems)
    if ($RegItems.Count -eq 0) { return 'Manual' }
    foreach ($item in $RegItems) {
        if (!(Test-Path $item.Path)) { return 'NonCompliant' }
        $cur = (Get-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction SilentlyContinue).$($item.Name)
        if ($null -eq $cur -or "$cur" -ne "$($item.Value)") { return 'NonCompliant' }
    }
    return 'Compliant'
}

# HTML-encode helper. Uses System.Net.WebUtility, which is built into the PS7
# runtime (no Add-Type / System.Web assembly needed - the original called
# System.Web.HttpUtility BEFORE loading the assembly, which would throw).
function Format-Html { param([string]$Text) return [System.Net.WebUtility]::HtmlEncode($Text) }

$reportData     = [System.Collections.Generic.List[hashtable]]::new()
$grandCompliant = 0; $grandNon = 0; $grandManual = 0

$statusFilter = if ($IncludeNotFindings) { 'All' } else { 'Open' }

foreach ($f in $CklFiles) {
    Write-Host "Checking $($f.Name) ..." -ForegroundColor Cyan
    $findings = Get-CklFindings -Path $f.FullName -Status $statusFilter
    $fileRows = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($finding in $findings) {
        if ($finding.Status -eq 'NotAFinding' -and -not $IncludeNotFindings) { continue }

        $compStatus = Get-RegistryComplianceStatus -RegItems $finding.RegistryItems

        $regDetail = if ($finding.RegistryItems.Count -gt 0) {
            ($finding.RegistryItems | ForEach-Object {
                $cur = (Get-ItemProperty -Path $_.Path -Name $_.Name -ErrorAction SilentlyContinue).$($_.Name)
                $curStr = if ($null -eq $cur) { '<missing>' } else { $cur }
                "$($_.Path)\$($_.Name) = $($_.Value) (live: $curStr)"
            }) -join '<br>'
        } else {
            '<em>No registry items extractable — manual review required</em>'
        }

        $catNum = switch ($finding.Severity) {
            'high'   { 'CAT I'   }
            'medium' { 'CAT II'  }
            'low'    { 'CAT III' }
            default  { '?'       }
        }

        $fileRows.Add(@{
            VulnNum   = $finding.VulnNum
            RuleVer   = $finding.RuleVer
            Cat       = $catNum
            Title     = Format-Html $finding.RuleTitle
            Status    = $compStatus
            CklStatus = $finding.Status
            RegDetail = $regDetail
        })

        switch ($compStatus) {
            'Compliant'    { $grandCompliant++ }
            'NonCompliant' { $grandNon++ }
            'Manual'       { $grandManual++ }
        }
    }

    if ($fileRows.Count -gt 0) {
        $reportData.Add(@{
            StigTitle = $findings[0].StigTitle
            HostName  = $findings[0].HostName
            CklFile   = $f.Name
            Rows      = $fileRows
        })
    }
}

$grandTotal = $grandCompliant + $grandNon + $grandManual
$pctGood    = if ($grandTotal -gt 0) { [Math]::Round(($grandCompliant / $grandTotal) * 100, 1) } else { 0 }

# ---------------------------------
# --- BUILD HTML REPORT
# ---------------------------------
$now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$sb  = [System.Text.StringBuilder]::new()

[void]$sb.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>STIG Compliance Report — $now</title>
<style>
  :root {
    --bg:       #0d1117;  --bg2:      #161b22;  --bg3:      #21262d;
    --border:   #30363d;  --text:     #c9d1d9;  --muted:    #8b949e;
    --green:    #3fb950;  --red:      #f85149;  --yellow:   #d29922;
    --blue:     #58a6ff;  --purple:   #bc8cff;
    --cat1:     #f85149;  --cat2:     #d29922;  --cat3:     #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: "Segoe UI", Consolas, monospace; font-size: 13px; }
  a    { color: var(--blue); text-decoration: none; }

  .header { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 20px 32px; }
  .header h1 { font-size: 20px; font-weight: 600; color: var(--blue); }
  .header .meta { color: var(--muted); font-size: 12px; margin-top: 4px; }

  .cards { display: flex; gap: 16px; padding: 20px 32px; flex-wrap: wrap; }
  .card  { background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
           padding: 16px 20px; min-width: 140px; flex: 1; }
  .card .num  { font-size: 28px; font-weight: 700; }
  .card .lbl  { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; margin-top: 2px; }
  .card.pass  .num { color: var(--green);  }
  .card.fail  .num { color: var(--red);    }
  .card.warn  .num { color: var(--yellow); }
  .card.total .num { color: var(--blue);   }

  .pbar-wrap { padding: 0 32px 20px; }
  .pbar-bg   { background: var(--bg3); border-radius: 4px; height: 8px; overflow: hidden; }
  .pbar-fill { height: 100%; background: var(--green); border-radius: 4px;
               transition: width .3s ease; width: $pctGood%; }
  .pbar-lbl  { color: var(--muted); font-size: 11px; margin-top: 4px; }

  .stig-section { margin: 0 32px 32px; }
  .stig-title   { background: var(--bg2); border: 1px solid var(--border); border-radius: 6px 6px 0 0;
                  padding: 10px 16px; font-weight: 600; font-size: 13px; color: var(--blue); }
  .stig-meta    { color: var(--muted); font-size: 11px; margin-top: 2px; }

  table { width: 100%; border-collapse: collapse; border: 1px solid var(--border);
          border-top: none; background: var(--bg2); border-radius: 0 0 6px 6px; }
  th    { background: var(--bg3); color: var(--muted); text-align: left; padding: 8px 12px;
          font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
          border-bottom: 1px solid var(--border); position: sticky; top: 0; }
  td    { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(88,166,255,.04); }

  .cat  { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px;
          font-weight: 700; letter-spacing: .04em; }
  .cat1 { background: rgba(248,81,73,.15);  color: var(--cat1); }
  .cat2 { background: rgba(210,153,34,.15); color: var(--cat2); }
  .cat3 { background: rgba(88,166,255,.15); color: var(--cat3); }

  .st   { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
  .st-c { background: rgba(63,185,80,.15);  color: var(--green);  }
  .st-n { background: rgba(248,81,73,.15);  color: var(--red);    }
  .st-m { background: rgba(210,153,34,.15); color: var(--yellow); }

  .reg-detail { font-family: Consolas, monospace; font-size: 11px; color: var(--muted);
                margin-top: 4px; line-height: 1.6; }

  .footer { text-align: center; color: var(--muted); font-size: 11px; padding: 24px 32px 40px; }
</style>
</head>
<body>
<div class="header">
  <h1>&#128737; STIG Compliance Report</h1>
  <div class="meta">Generated: $now &nbsp;|&nbsp; Host: $env:COMPUTERNAME &nbsp;|&nbsp; User: $env:USERNAME</div>
</div>

<div class="cards">
  <div class="card total"><div class="num">$grandTotal</div><div class="lbl">Findings Checked</div></div>
  <div class="card pass"><div class="num">$grandCompliant</div><div class="lbl">Compliant</div></div>
  <div class="card fail"><div class="num">$grandNon</div><div class="lbl">Non-Compliant</div></div>
  <div class="card warn"><div class="num">$grandManual</div><div class="lbl">Manual Review</div></div>
</div>

<div class="pbar-wrap">
  <div class="pbar-bg"><div class="pbar-fill"></div></div>
  <div class="pbar-lbl">$pctGood% of registry-verifiable findings are compliant</div>
</div>
"@)

foreach ($section in $reportData) {
    [void]$sb.AppendLine("<div class='stig-section'>")
    [void]$sb.AppendLine("<div class='stig-title'>$(Format-Html $section.StigTitle)<div class='stig-meta'>$($section.CklFile) &nbsp;|&nbsp; Host: $($section.HostName)</div></div>")
    [void]$sb.AppendLine("<table><thead><tr>")
    [void]$sb.AppendLine("<th>Vuln</th><th>Rule</th><th>CAT</th><th>Status</th><th>Title / Registry Items</th>")
    [void]$sb.AppendLine("</tr></thead><tbody>")

    foreach ($row in $section.Rows) {
        $stClass = switch ($row.Status) {
            'Compliant'    { 'st-c'; break }
            'NonCompliant' { 'st-n'; break }
            default        { 'st-m'; break }
        }
        $stLabel = switch ($row.Status) {
            'Compliant'    { 'PASS';   break }
            'NonCompliant' { 'FAIL';   break }
            default        { 'MANUAL'; break }
        }
        $catClass = switch ($row.Cat) {
            'CAT I'  { 'cat1'; break }
            'CAT II' { 'cat2'; break }
            default  { 'cat3'; break }
        }
        [void]$sb.AppendLine("<tr>")
        [void]$sb.AppendLine("<td>$($row.VulnNum)</td>")
        [void]$sb.AppendLine("<td>$($row.RuleVer)</td>")
        [void]$sb.AppendLine("<td><span class='cat $catClass'>$($row.Cat)</span></td>")
        [void]$sb.AppendLine("<td><span class='st $stClass'>$stLabel</span></td>")
        [void]$sb.AppendLine("<td>$($row.Title)<div class='reg-detail'>$($row.RegDetail)</div></td>")
        [void]$sb.AppendLine("</tr>")
    }

    [void]$sb.AppendLine("</tbody></table></div>")
}

[void]$sb.AppendLine(@"
<div class="footer">STIG CKL Remediation Toolkit &nbsp;&bull;&nbsp; Report generated $now</div>
</body></html>
"@)

# ---------------------------------
# --- WRITE REPORT
# ---------------------------------
$reportDir = Split-Path $ReportPath -Parent
if (!(Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }

$sb.ToString() | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
Write-Host "`n[SUCCESS] Report written to: $ReportPath" -ForegroundColor Green
Write-Host "  Compliant    : $grandCompliant / $grandTotal  ($pctGood%)" -ForegroundColor Green
Write-Host "  Non-Compliant: $grandNon"    -ForegroundColor Red
Write-Host "  Manual Review: $grandManual" -ForegroundColor Yellow

# Attempt to open in default browser (no-op if headless).
try { Start-Process $ReportPath } catch { }
