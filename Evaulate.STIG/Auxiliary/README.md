# Evaluate-STIG Auxiliary Scripts

This folder contains automation scripts that work alongside Evaluate-STIG.ps1. Three of them
(`Invoke-EvaluateSTIG.ps1`, `New-StigAnswerFile.ps1`, `Invoke-StigPipeline.ps1`) form a complete
automated STIG scan-remediate-verify pipeline. The remaining scripts are the original Evaluate-STIG
utilities for reporting, maintenance, and CI/CD integration.

---

## Quick Start

```powershell
# Run the full pipeline on this machine (elevated PowerShell 7+ prompt)
.\Invoke-StigPipeline.ps1 -VdiMode

# Dry run first — see every action before it happens
.\Invoke-StigPipeline.ps1 -VdiMode -WhatIf
```

---

## Automation Pipeline Scripts (NEW)

### `Invoke-StigPipeline.ps1`

**The single entry point for full automation.** Orchestrates all 8 stages in sequence.
Requires PowerShell 7.0+ and an elevated (Administrator) session.

#### Pipeline Stages

| # | Stage | What it does |
|---|---|---|
| 1 | **Scan** | Runs Evaluate-STIG.ps1 on this machine — generates `.ckl` + `.cklb` checklists |
| 2 | **Answer Files** | Calls `New-StigAnswerFile.ps1` on every checklist — builds registry-validating answer files |
| 3 | **Copy** | Copies checklists to the remediation toolkit's `Checklist\` folder |
| 4 | **Remediate** | Runs `Invoke-StigCklRemediation.ps1` — applies all extractable registry settings |
| 5 | **Default Hive** | *(VDI only)* Bakes HKCU settings into `C:\Users\Default\NTUSER.DAT` |
| 6 | **Rescan** | Re-runs Evaluate-STIG with the generated answer files — auto-closes fixed findings |
| 7 | **Report** | Generates a colour-coded HTML compliance report |
| 8 | **Patch** | Writes `*_PATCHED.ckl` / `*_PATCHED.cklb` with `NotAFinding` for verified fixes |

#### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-EvaluateStigRoot` | Auto-detected | Path to the folder containing `Evaluate-STIG\Evaluate-STIG.ps1` |
| `-OutputBase` | `..\STIGS` | Root folder for scan output; results go to `<OutputBase>\<hostname>\Checklist\` |
| `-RemediationRoot` | Auto-detected | Path to `Rremediate.STIG.code\` folder |
| `-SelectSTIG` | *(all applicable)* | Limit scan to specific STIG short names (e.g., `Win11,Chrome`) |
| `-ExcludeSTIG` | *(none)* | Exclude specific STIGs from the scan |
| `-AnswerKey` | `DEFAULT` | Answer key name; must match the key in your answer files |
| `-ScanType` | `Unclassified` | `Unclassified` or `Classified` |
| `-PreviousToKeep` | `3` | How many previous scan result sets to retain |
| `-VdiMode` | *(off)* | Enable VDI-specific Not-Applicable logic and default-hive baking (Stage 5) |
| `-VdiNaFile` | *(none)* | Path to `VdiNaFindings.json` with site-specific NA overrides |
| `-WhatIf` | *(off)* | Show all actions without making any registry changes |
| `-SkipScan` | *(off)* | Skip Stage 1 — use existing checklists |
| `-SkipAnswerFiles` | *(off)* | Skip Stage 2 |
| `-SkipRemediation` | *(off)* | Skip Stage 4 — scan only, no changes |
| `-SkipHive` | *(off)* | Skip Stage 5 even in VDI mode |
| `-SkipRescan` | *(off)* | Skip Stage 6 |
| `-SkipReport` | *(off)* | Skip Stage 7 |
| `-SkipPatch` | *(off)* | Skip Stage 8 |
| `-ForceAnswerFiles` | *(off)* | Overwrite existing answer files in Stage 2 |

#### Usage Examples

```powershell
# Full pipeline — all 8 stages, VDI non-persistent desktop mode
.\Invoke-StigPipeline.ps1 -VdiMode

# Target specific STIGs only (faster for focused hardening)
.\Invoke-StigPipeline.ps1 -SelectSTIG Win11,Chrome,MSOffice365,MSEdge,WinFirewall,MSDefender -VdiMode

# Dry run — prints every action, writes no registry values
.\Invoke-StigPipeline.ps1 -VdiMode -WhatIf

# Scan only (no remediation) — useful for before/after audit
.\Invoke-StigPipeline.ps1 -SkipRemediation -SkipHive -SkipRescan -SkipReport -SkipPatch

# Skip scan — remediate against existing checklists, then re-scan
.\Invoke-StigPipeline.ps1 -SkipScan -VdiMode

# Custom output location and VDI NA file
.\Invoke-StigPipeline.ps1 -VdiMode -OutputBase "D:\STIGScans" -VdiNaFile ".\VdiNaFindings.json"
```

#### Output Files

All logs go to `Evaulate.STIG\Pipeline_Logs\Pipeline_<timestamp>.log`.

After a full run you will have:

```
Evaulate.STIG\
  Pipeline_Logs\
    Pipeline_2026-05-28_09-00-00.log    ← Full transcript
    StigComplianceReport_2026-05-28.html ← Colour-coded compliance report

  STIGS\<HOSTNAME>\Checklist\
    HOSTNAME_Win11_V2R9_<date>.ckl      ← Baseline scan (Open findings)
    HOSTNAME_Win11_V2R9_<date>.cklb
    ... (one pair per applicable STIG)

  Evaluate-STIG\AnswerFiles\
    Win11.xml                           ← Auto-generated answer file
    Chrome.xml
    ... (one per STIG)

Rremediate.STIG.code\Checklist\
  HOSTNAME_Win11_V2R9_<date>.ckl        ← Copied for remediation
  HOSTNAME_Win11_V2R9_<date>_PATCHED.ckl  ← Patched (NotAFinding updated)
  Logs\
    Master_<timestamp>.log
    <STIG>_remediation.log
```

---

### `Invoke-EvaluateSTIG.ps1`

Wrapper around `Evaluate-STIG.ps1` with sensible defaults and optional copy-to-remediation.
Requires PowerShell 5.1+ (same as Evaluate-STIG itself) and elevation.

#### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-EvaluateStigRoot` | Auto-detected | Path containing `Evaluate-STIG\Evaluate-STIG.ps1` |
| `-OutputPath` | `..\STIGS` | Root for output; creates `<OutputPath>\<hostname>\Checklist\` |
| `-Output` | `CKL,CKLB` | Output formats (comma-separated) passed to Evaluate-STIG `-Output` |
| `-SelectSTIG` | *(all)* | Specific STIG short names to scan |
| `-ExcludeSTIG` | *(none)* | STIGs to skip |
| `-AnswerKey` | `DEFAULT` | Answer key name |
| `-AFPath` | Auto-detected | Path to answer files folder |
| `-ScanType` | `Unclassified` | Classification level |
| `-Marking` | *(none)* | Text marking added to checklist headers (e.g., `CUI`) |
| `-CopyToRemediation` | *(off)* | Copy results to the remediation Checklist folder after scan |
| `-RemediationChecklist` | Auto-detected | Explicit path for copy destination |
| `-ListApplicable` | *(off)* | List which STIGs would scan on this machine, then exit |
| `-PreviousToKeep` | `3` | Previous result sets to retain |
| `-VulnTimeout` | `15` | Per-check timeout in minutes |

#### Usage Examples

```powershell
# Default scan — all applicable STIGs, CKL + CKLB output
.\Invoke-EvaluateSTIG.ps1

# Specific STIGs only, copy to remediation folder when done
.\Invoke-EvaluateSTIG.ps1 -SelectSTIG Win11,Chrome -CopyToRemediation

# See what STIGs would be scanned on this machine
.\Invoke-EvaluateSTIG.ps1 -ListApplicable

# Scan with answer files from a custom location
.\Invoke-EvaluateSTIG.ps1 -AFPath "D:\AnswerFiles" -AnswerKey VDI_GOLD
```

---

### `New-StigAnswerFile.ps1`

Reads a CKL or CKLB checklist file and generates an Evaluate-STIG answer file (`.xml`) that
**automatically verifies remediation** on re-scan. For every Open finding whose registry settings
can be parsed, a `ValidationCode` block is generated that reads the live registry and returns
`Not a Finding` when the expected value is present, or stays `Open` if it is not.

Requires PowerShell 7.0+ and `STIG-CKL-Helpers.psm1` from the sibling `Rremediate.STIG.code\` folder.

#### How the generated ValidationCode works

```xml
<Answer Index="1" ExpectedStatus="O">
  <ValidationCode>
    $_valid   = $true
    $_results = @()
    try {
        $_actual = (Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome'
                      -Name 'RemoteAccessHostFirewallTraversal' -ErrorAction Stop
                   ).'RemoteAccessHostFirewallTraversal'
        if ("$_actual") -ne ("0")) {
            $_valid = $false
            $_results += "FAIL: RemoteAccessHostFirewallTraversal = '$_actual' (expected '0')"
        } else {
            $_results += "PASS: RemoteAccessHostFirewallTraversal = '$_actual'"
        }
    } catch {
        $_valid = $false
        $_results += "FAIL: RemoteAccessHostFirewallTraversal NOT FOUND"
    }
    @{ Valid = $_valid; Results = ($_results -join "`r`n") }
  </ValidationCode>
  <ValidTrueStatus>NF</ValidTrueStatus>   <!-- registry correct → Not A Finding -->
  <ValidFalseStatus>O</ValidFalseStatus>  <!-- registry wrong/missing → Open     -->
</Answer>
```

The `Results` string is written to the CKL `Comments` field on every re-scan, giving a per-finding
audit trail of exactly which registry values were checked and what was found.

#### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-CklPath` | *(required)* | One or more `.ckl` or `.cklb` file paths |
| `-OutputPath` | `Evaluate-STIG\AnswerFiles\` | Where to save generated `.xml` files |
| `-AnswerKey` | `DEFAULT` | Answer key name embedded in the file |
| `-VdiMode` | *(off)* | Mark findings in `VdiNaFindings.json` / built-in map as Not Applicable |
| `-VdiNaFile` | *(none)* | JSON file with additional site-specific NA overrides |
| `-NoRegistryValidation` | *(off)* | Skip ValidationCode generation (produce bare `<Vuln>` stubs instead) |
| `-Force` | *(off)* | Overwrite an existing answer file |
| `-HelpersModule` | Auto-detected | Path to `STIG-CKL-Helpers.psm1` |

#### Usage Examples

```powershell
# Generate answer file from a single CKL
.\New-StigAnswerFile.ps1 -CklPath .\STIGS\MYMACHINE\Checklist\MYMACHINE_Win11_V2R9.ckl

# Generate for all STIGs in a folder at once, VDI mode, force overwrite
Get-ChildItem ..\STIGS\MYMACHINE\Checklist\*.ckl |
  ForEach-Object { .\New-StigAnswerFile.ps1 -CklPath $_.FullName -VdiMode -Force }

# Use the CKLB file instead (produces identical answer files)
.\New-StigAnswerFile.ps1 -CklPath .\STIGS\MYMACHINE\Checklist\MYMACHINE_Chrome_V2R11.cklb -Force

# Custom answer key for a specific environment
.\New-StigAnswerFile.ps1 -CklPath .\Win11.ckl -AnswerKey VDI_GOLD -OutputPath D:\AnswerFiles
```

#### STIG Short Name Mapping

The script maps the xccdf filename in the checklist to the Evaluate-STIG `ShortName`.
Built-in mappings cover all common Windows/VDI STIGs:

| xccdf filename prefix | Answer file name | ShortName |
|---|---|---|
| `U_MS_Windows_11_STIG` | `Win11.xml` | `Win11` |
| `U_Google_Chrome_STIG` | `Chrome.xml` | `Chrome` |
| `U_Office_365_ProPlus_STIG` | `MSOffice365.xml` | `MSOffice365` |
| `U_MS_Edge_STIG` | `MSEdge.xml` | `MSEdge` |
| `U_Windows_Defender_Antivirus_STIG` | `MSDefender.xml` | `MSDefender` |
| `U_Windows_Firewall_*_STIG` | `WinFirewall.xml` | `WinFirewall` |
| `U_Adobe_Acrobat_Pro_DC_Continuous_STIG` | `AdobeAcrobatProDCContinuous.xml` | `AdobeAcrobatProDCContinuous` |
| `U_MS_Windows_Server_2022_STIG` | `WinServer2022.xml` | `WinServer2022` |

If your STIG xccdf filename is not in this table, the script derives a name automatically
and warns you to verify it against `Evaluate-STIG.ps1 -ListSupportedProducts`.

---

### `VdiNaFindings.json`

Configuration file for site-specific Not-Applicable finding overrides. Used by
`New-StigAnswerFile.ps1` and `Invoke-StigPipeline.ps1` via the `-VdiNaFile` parameter.

#### Format

```json
{
  "Win11": {
    "V-253280": "Justification text — why this finding is NA in your environment."
  },
  "Chrome": {
    "V-221562": "Chrome extension allowlist is managed via Group Policy ADMX..."
  }
}
```

Keys are Evaluate-STIG `ShortName` values. Values are objects mapping VulnNum strings
to justification text that is written to the CKL `Comments` field.

> **Important:** V-numbers change between STIG versions. The placeholder entries in the
> file are templates only. Cross-reference against your current STIG xccdf files or run
> `.\Invoke-EvaluateSTIG.ps1 -ListApplicable` to see current finding IDs. All NA markings
> must be reviewed and approved by your ISSO/ISSM before submission.

---

## Original Evaluate-STIG Auxiliary Scripts

### `Get-AnswerFileSummary.ps1`

Creates an HTML report from Evaluate-STIG answer files showing all configured answers,
their ValidationCode, and current status mappings.

```powershell
.\Get-AnswerFileSummary.ps1 -AFPath ..\Evaluate-STIG\AnswerFiles
Get-Help .\Get-AnswerFileSummary.ps1 -Full
```

### `Get-SummaryReport.ps1`

Creates an Excel workbook from Evaluate-STIG summary XML reports. Requires Microsoft Excel
to be installed on the system running the script.

```powershell
Get-Help .\Get-SummaryReport.ps1 -Full
```

### `Maintain-AnswerFiles.ps1`

Keeps answer files current when STIGs are updated: updates changed Vuln IDs, removes entries
for deleted findings, converts legacy format answer files to the current schema.

```powershell
# Update answer files to match current Evaluate-STIG STIG content
.\Maintain-AnswerFiles.ps1 -ESPath ..\Evaluate-STIG -AFPath ..\Evaluate-STIG\AnswerFiles

# Remove entries whose VulnIDs no longer exist in the STIG
.\Maintain-AnswerFiles.ps1 -ESPath ..\Evaluate-STIG -RemoveMissingVulnIDs

Get-Help .\Maintain-AnswerFiles.ps1 -Full
```

Run this after each Evaluate-STIG update or STIG content refresh to keep answer files valid.

### `Evaluate-STIG.yml`

Ansible playbook for running Evaluate-STIG on remote Linux hosts. Copies Evaluate-STIG to
the target, runs it, fetches results, and cleans up. Temporarily modifies `/etc/sudoers`
during the rsync phase.

### `ConfigMgr\`

Sample Configuration Baseline and Configuration Item for Microsoft Configuration Manager
(SCCM/MECM). Allows Evaluate-STIG scans to run as a compliance baseline on managed endpoints.
See the included documentation for import instructions.

---

## Prerequisites

| Requirement | Details |
|---|---|
| PowerShell version | 5.1+ for `Invoke-EvaluateSTIG.ps1` and Evaluate-STIG itself; **7.0+** for `New-StigAnswerFile.ps1` and `Invoke-StigPipeline.ps1` |
| Elevation | All pipeline scripts require **Run as Administrator** |
| Evaluate-STIG | Must be extracted to `..\Evaluate-STIG\Evaluate-STIG.ps1` (one level up from `Auxiliary\`) |
| STIG-CKL-Helpers.psm1 | Must be present in `..\..\Rremediate.STIG.code\STIG-CKL-Helpers.psm1` |
| DOD certificates | Run `..\Evaluate-STIG\Prerequisites\Import-Certificates.ps1` once before first scan |
| Network | Not required for local scans; required for Evaluate-STIG update (`-Update`) and STIG Manager upload |

---

## Folder Structure Reference

```
STIG.Security.Hardening\
│
├── Evaulate.STIG\                          ← This folder
│   ├── Auxiliary\                          ← These scripts
│   │   ├── Invoke-StigPipeline.ps1         ← Full pipeline (START HERE)
│   │   ├── Invoke-EvaluateSTIG.ps1         ← Scan wrapper
│   │   ├── New-StigAnswerFile.ps1          ← Answer file generator
│   │   ├── VdiNaFindings.json              ← VDI NA configuration
│   │   ├── Get-AnswerFileSummary.ps1       ← Answer file HTML report
│   │   ├── Get-SummaryReport.ps1           ← Excel summary report
│   │   ├── Maintain-AnswerFiles.ps1        ← Answer file maintenance
│   │   ├── Evaluate-STIG.yml               ← Ansible playbook (Linux)
│   │   └── ConfigMgr\                      ← SCCM integration
│   │
│   ├── Evaluate-STIG\
│   │   ├── Evaluate-STIG.ps1              ← Core scanner (do not edit)
│   │   ├── AnswerFiles\                   ← Generated answer files go here
│   │   │   ├── Win11.xml                  ← Auto-generated by New-StigAnswerFile
│   │   │   ├── Chrome.xml
│   │   │   └── Template_AnswerFile.xml    ← Manual authoring reference
│   │   ├── Modules\                       ← 100+ STIG scan modules
│   │   ├── StigContent\                   ← XCCDF benchmark files
│   │   ├── Prerequisites\                 ← DOD certs + prerequisite check
│   │   └── Preferences.xml               ← Evaluate-STIG defaults
│   │
│   ├── STIGS\                             ← Scan output (per-hostname)
│   │   └── <HOSTNAME>\
│   │       ├── Checklist\                 ← CKL + CKLB files from scans
│   │       └── Evaluate-STIG.log
│   │
│   └── Pipeline_Logs\                     ← Pipeline run transcripts + HTML reports
│
└── Rremediate.STIG.code\                  ← Remediation toolkit
    ├── Invoke-StigCklRemediation.ps1      ← Registry remediation
    ├── Invoke-DefaultUserHiveRemediation.ps1
    ├── Get-StigComplianceReport.ps1
    ├── Update-CklFindingStatus.ps1
    ├── STIG-CKL-Helpers.psm1             ← Shared parser (used by New-StigAnswerFile)
    └── Checklist\                         ← CKL/CKLB files for remediation
```

---

## Typical Gold Image Workflow

```
 Gold image machine (elevated PowerShell 7 session)
 ─────────────────────────────────────────────────────

 1. First time setup (once):
    .\Invoke-EvaluateSTIG.ps1 -ListApplicable
    # Review list. Update VdiNaFindings.json with site NA justifications.

 2. Full pipeline run:
    .\Invoke-StigPipeline.ps1 -SelectSTIG Win11,Chrome,MSOffice365,MSEdge,WinFirewall,MSDefender,AdobeAcrobatProDCContinuous -VdiMode -VdiNaFile .\VdiNaFindings.json

 3. Review outputs:
    # Open: Pipeline_Logs\StigComplianceReport_<date>.html  ← compliance dashboard
    # Review: Rremediate.STIG.code\Checklist\*_PATCHED.ckl  ← for eMASS / STIG Manager
    # Review: Pipeline_Logs\Pipeline_<date>.log              ← for manual findings

 4. For findings that remain Open:
    # MANUAL findings: check the log for "[MANUAL]" entries and action each one
    # SKIPPED findings: check the log for "[WARN] SKIPPED" and add to answer file or remediate manually

 5. After STIG content updates (quarterly):
    .\Maintain-AnswerFiles.ps1 -ESPath ..\Evaluate-STIG -AFPath ..\Evaluate-STIG\AnswerFiles -UpdateChangedRuleIDs
    .\Invoke-StigPipeline.ps1 -SkipScan -ForceAnswerFiles -VdiMode   # re-remediate with new STIG content
```

---

## Answer File Maintenance

When DISA releases a new STIG version:
1. Update Evaluate-STIG to the new version (run `.\Evaluate-STIG.ps1 -Update` or download the zip)
2. Run `.\Maintain-AnswerFiles.ps1` to update Vuln IDs and remove obsolete entries
3. Re-generate answer files: `.\Invoke-StigPipeline.ps1 -SkipScan -ForceAnswerFiles -VdiMode`
4. Re-run the full pipeline to pick up any new findings added in the new version

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| "Evaluate-STIG.ps1 not found" | Script is not where expected | Set `-EvaluateStigRoot` explicitly |
| "STIG-CKL-Helpers.psm1 not found" | Sibling folder missing | Set `-HelpersModule` or verify `Rremediate.STIG.code\` exists |
| Answer file has wrong ShortName | STIG not in built-in map | Add entry to `$StigShortNameMap` in `New-StigAnswerFile.ps1` line ~80 |
| Stage 4 (Remediate) shows all `[WARN] CONFLICT` | Domain GPO active | Apply settings via GPO or run on a pre-domain-join snapshot |
| Stage 6 (Rescan) findings still Open after remediation | Evaluate-STIG scan module detects differently than parser | Check the STIG scan module logic; consider adding ValidationCode manually to the answer file |
| `Not_Reviewed` findings stay NR in rescan | Answer file only covers `ExpectedStatus="O"` entries | Re-run `New-StigAnswerFile.ps1 -Force` after a full rescan to capture NR findings |
