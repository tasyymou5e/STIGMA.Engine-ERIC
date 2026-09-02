# STIG CKL Remediation Toolkit (PowerShell 7)

Automated STIG remediation toolkit for Windows 10/11 and associated application
STIGs. Parses Evaluate-STIG checklist output — both the current **CKLB (JSON)**
format and the legacy **CKL (XML)** format — extracts registry settings from
Open findings, applies them, and produces per-file logs, patched checklists,
and a compliance HTML report.

> **This is the fixed build.** See `CHANGES` at the bottom for what changed versus
> the original.

---

## File Overview

| File | Purpose |
|---|---|
| `Invoke-StigCklRemediation.ps1` | **Main script.** Enumerates every CKL file, extracts and applies registry settings, writes per-file logs and a master transcript. |
| `Invoke-StigGpoRemediation.ps1` | **GPO (LGPO) alternative to the main script.** `.cklb`-only. Extracts the same registry items but applies them as real Local Group Policy via `LGPO.exe /t` instead of raw `Set-ItemProperty`, so they show up in `gpresult`/RSOP and sit at correct GPO precedence. See [GPO (LGPO) Remediation Path](#gpo-lgpo-remediation-path) below. |
| `STIG-CKL-Helpers.psm1` | **Shared module.** Environment bootstrap (`Initialize-StigEnvironment`), file discovery (`Get-CklFileList`), parser (`Get-StigRegistryItems`), CKL reader (`Get-CklFindings`), and type/path helpers. Imported by all five scripts. |
| `Invoke-DefaultUserHiveRemediation.ps1` | **VDI/AVD helper.** Mounts `C:\Users\Default\NTUSER.DAT` and bakes all HKCU-scoped STIG settings into the default user profile so every new session inherits them. |
| `Update-CklFindingStatus.ps1` | **CKL patcher.** Re-reads the live registry, verifies each finding, and writes `*_PATCHED` copies with compliant findings flipped to `NotAFinding`. |
| `Get-StigComplianceReport.ps1` | **Report generator.** Checks registry values against expectations and produces a self-contained dark-themed HTML compliance report. |

---

## Prerequisites

- **PowerShell 7.0 or later (`pwsh`). The scripts will NOT run on Windows
  PowerShell 5.1** — each file declares `#requires -Version 7.0`, so 5.1 refuses
  to execute them. Install PS7 from <https://aka.ms/powershell>.
- **Windows** (the toolkit manipulates the Windows registry, `reg.exe`, and
  `wevtutil`; it self-aborts on non-Windows).
- **Administrator** — every script **auto-elevates**: if you launch it
  non-elevated it relaunches itself under `pwsh` with a UAC prompt, forwarding
  all parameters (including `-WhatIf`).
- All files in the same directory (scripts locate the module via `$PSScriptRoot`).
- Checklist files are discovered in this order: **`.cklb`** (current
  Evaluate-STIG native JSON output) and **`*_ckl.txt`** (Evaluate-STIG XML
  output) are merged as the primary tier; if neither is present, any `.ckl` /
  `.xml` file is picked up as a fallback.
- **`Invoke-StigGpoRemediation.ps1` additionally requires `LGPO.exe`**
  (Microsoft Security Compliance Toolkit) — resolved from `-LgpoExePath`, else
  `<script dir>\LGPO.exe`, else `PATH`. Not needed by the other four scripts.

### Execution policy / remoting

Each script sets a **process-scoped** `Bypass` execution policy
(`Set-ExecutionPolicy -Scope Process`) at startup. This applies only to the
current instance (nothing is written to disk) and works both for local launches
and for sessions created over PowerShell Remoting (`Invoke-Command`) where the
machine policy might otherwise block script execution.

---

## Recommended Run Order

```
1. Invoke-StigCklRemediation.ps1         <- apply settings
2. Invoke-DefaultUserHiveRemediation.ps1 <- bake HKCU into default profile (VDI/AVD only)
3. Get-StigComplianceReport.ps1          <- verify what took, generate HTML report
4. Update-CklFindingStatus.ps1           <- update checklist file for compliance package submission
```

Steps 2–4 are independent and can be re-run in any order.

`Invoke-StigGpoRemediation.ps1` is an **alternative to step 1**, not an addition
to it — it applies the same registry-backed findings but through `LGPO.exe`
instead of direct registry writes. Run one or the other, not both (both would
just set the same values by two different mechanisms). Steps 2–4 work
unchanged afterward either way, since they read the resulting registry state.

---

## Usage Examples

```powershell
# Apply all Open findings (dry-run first - -WhatIf survives the auto-elevation)
.\Invoke-StigCklRemediation.ps1 -WhatIf
.\Invoke-StigCklRemediation.ps1

# Custom CKL directory and log path
.\Invoke-StigCklRemediation.ps1 -CklDirectory "D:\STIG_Scans\UHHZ-VM-24H2" -LogDirectory "D:\Logs\STIG"

# Bake HKCU settings into the default user hive (run on the gold image BEFORE sealing)
.\Invoke-DefaultUserHiveRemediation.ps1

# Generate compliance HTML report (saved under <script dir>\Logs\ by default)
.\Get-StigComplianceReport.ps1
.\Get-StigComplianceReport.ps1 -ReportPath "D:\Reports\PreATO_Compliance.html"

# Update CKL files with remediation status
.\Update-CklFindingStatus.ps1 -WhatIf
.\Update-CklFindingStatus.ps1

# GPO (LGPO) alternative to Invoke-StigCklRemediation.ps1 - .cklb only
.\Invoke-StigGpoRemediation.ps1 -WhatIf   # generates LGPO text under Logs\, applies nothing
.\Invoke-StigGpoRemediation.ps1
.\Invoke-StigGpoRemediation.ps1 -CklDirectory "D:\STIG_Scans\UHHZ-VM-24H2" -LgpoExePath "C:\Tools\LGPO.exe"
```

---

## Log and Output Files

All logs default to a `Logs\` subfolder created in the same directory as the
scripts. Change with `-LogDirectory`.

| File pattern | Source |
|---|---|
| `Logs\Master_<timestamp>.log` | Main remediation transcript |
| `Logs\<CklBaseName>_remediation.log` | Per-STIG finding-level log |
| `Logs\DefaultHive_<timestamp>.log` | Default user hive apply log |
| `Logs\CklUpdate_<timestamp>.log` | CKL patcher transcript |
| `Logs\StigComplianceReport_<timestamp>.html` | HTML compliance report |
| `<original>_PATCHED.<ext>` | CKL with compliant findings marked NotAFinding |
| `Logs\GpoRemediation_<timestamp>.log` | GPO (LGPO) remediation transcript |
| `Logs\<CklBaseName>_gpo.lgpo.txt` | Per-STIG generated LGPO text (review before trusting) |
| `Logs\Master_GPO_<timestamp>.lgpo.txt` | Combined LGPO text actually passed to `LGPO.exe /t` |

---

## What Gets Auto-Remediated vs. Manual

| Pattern | Example finding types |
|---|---|
| **Structured block** (`Registry Hive / Path / Value Name / Type / Value`) | Win10/11, Adobe, some Defender |
| **Navigate-to-key + value assertion** (`If value X is REG_DWORD = N, not a finding`) | Office 365, Edge, Adobe |
| **Defender ASR GUIDs** (GUID + value from Fix_Text) | Defender ASR rules |
| **Event-log sizing** (`wevtutil`) | `WN11-AU-000500/000502/000505` |

**Cannot be auto-remediated** (logged as `[MANUAL]`): TPM/Secure Boot/Credential
Guard hardware, User Rights Assignments (`secedit`), account management, app-UI
findings, and audit policy (`auditpol`, unless extended).

> The registry parsing is **heuristic text extraction**. Always run `-WhatIf` (or
> the report) and review before applying to production. Treat it as a gap-filler,
> not the authoritative control source — prefer DISA STIG GPO baselines / LGPO
> for HKLM, and this toolkit's default-hive script for HKCU.

---

## VDI / AVD Notes

- `Invoke-StigCklRemediation.ps1` applies HKCU settings to whoever is logged on.
- `Invoke-DefaultUserHiveRemediation.ps1` bakes them into
  `C:\Users\Default\NTUSER.DAT` — **run on the gold image before sealing.**
- For domain-joined hosts, deliver via **GPO User Configuration** (GPO wins over
  local HKCU/default-hive).
- After baking into the default hive, the report/patcher HKCU checks reflect the
  *current* profile, not the default hive — verify with a fresh test login or a
  re-scan (Evaluate-STIG), not those HKCU rows.

### GPO override

The main script runs `gpresult /r` (Computer scope) and warns if Domain GPOs are
active — local registry edits are overwritten at the next `gpupdate`. HKCU GPO
conflicts come from **User** scope, which this check does not enumerate.

---

## GPO (LGPO) Remediation Path

`Invoke-StigGpoRemediation.ps1` reads Open findings from `.cklb` files only
(via the same shared `Get-CklFindings`/`Get-StigRegistryItems` parser as the
main script), converts each extracted registry item to Microsoft's **LGPO
text** format, and applies it with `LGPO.exe /t` — a real local GPO write
instead of a direct `Set-ItemProperty`. It writes a per-file `<name>_gpo.lgpo.txt`
for traceability plus one combined `Master_GPO_<timestamp>.lgpo.txt`, which is
what actually gets passed to `LGPO.exe`.

**Scope:** registry-backed Administrative Template settings only — the same
subset `Get-StigRegistryItems` already extracts. Security Options / User
Rights Assignment / Audit Policy findings need a different LGPO mode (`/s`
GptTmpl.inf, `/ac` Audit.csv) and are not covered; findings with no
extractable registry items are logged and left untouched, same as today.

**Always review the generated `.lgpo.txt` before trusting a live run** — the
underlying parser is heuristic text extraction from Check_Content/Fix_Text,
and it will faithfully carry forward whatever the STIG text says even when
that text is a placeholder, not a real value. Two examples hit during testing
against the real sample checklists in this folder:
- An Evaluate-STIG OneDrive finding's Fix Text literally says to set the
  tenant allow-list value to *"Organization's Tenant GUID"* — that placeholder
  string gets extracted and would be applied as-is unless replaced with your
  org's actual tenant GUID.
- An Office finding's Check_Content contains a `COM Compatibility` comment
  line that gets misread as a `REG_SZ` value (`COMMENT` = `Block all Flash
  activation`) — a parser false-positive, not a real setting to apply.

Neither is unique to this script (the same heuristic parser feeds the main
registry-remediation path too); the per-file LGPO text output just makes
issues like these easy to spot before `/t` ever runs. `-WhatIf` generates all
`.lgpo.txt` output without invoking `LGPO.exe` at all.

---

## CHANGES (fixed build)

- **PowerShell 7 enforced.** `#requires -Version 7.0` on every file; 5.1 is
  blocked. README prerequisite corrected (was incorrectly "5.1 or 7+").
- **Auto-elevation + execution policy.** New `Initialize-StigEnvironment`:
  Windows/PS7 guard, `Set-ExecutionPolicy -Scope Process Bypass` (local + remote),
  and self-elevation that relaunches via **`pwsh`** (never `powershell.exe`) and
  **forwards all parameters** (the old relaunch dropped `-WhatIf`).
- **Event-log sizes corrected.** `WN11-AU-000500`/`-000502` were set to
  `32768000` bytes (= 32,000 KB, **below** the 32,768 KB STIG minimum); now
  `33554432`.
- **CKL discovery fixed.** The `-Include '*.ckl','*.xml'` fallback silently
  matched nothing (needs a wildcard path); centralized into `Get-CklFileList`.
- **Report HTML-encode fixed.** Used `System.Web.HttpUtility` before loading the
  assembly; switched to `System.Net.WebUtility` (built into PS7, no `Add-Type`).
- **De-duplicated parser.** The main script no longer carries its own copy of the
  parser/converters — all four scripts share the module (single source of truth).
- **Robustness/annotation.** `$PSScriptRoot` fallback, `[CmdletBinding()]`,
  accurate HKCU-verification comments, and extensive inline documentation.
- **CKLB (JSON) support added.** `Get-CklFileList` now discovers `.cklb`
  files; the module's `Get-CklFindings` transparently dispatches to a new
  `Get-CklbFindings` parser for them and normalizes CKLB's lowercase/underscore
  status tokens (`open`, `not_a_finding`, `not_reviewed`, `not_applicable`) to
  the same casing used by the CKL/XML path, so every caller gets an identical
  finding-object shape regardless of source format. `Invoke-StigCklRemediation.ps1`
  was refactored to call the shared parser instead of parsing XML inline (it
  previously duplicated — and would have crashed on — this logic), and
  `Update-CklFindingStatus.ps1` gained a parallel JSON read/mutate/write branch
  (`ConvertFrom-Json` / `ConvertTo-Json -Compress`) alongside the existing
  XML-DOM branch, sharing one `Get-FindingComplianceOutcome` helper for the
  compliance decision and logging so the two formats can't drift apart.
  `Get-StigRegistryItems` (the heuristic Check_Content/Fix_Text parser) needed
  no changes — it operates on the same text regardless of container format.
- **GPO (LGPO) remediation path added.** New standalone
  `Invoke-StigGpoRemediation.ps1` — parses GPO-applicable (registry-backed)
  settings from `.cklb` files only and applies them as real Local Group Policy
  via `LGPO.exe /t` rather than direct registry writes. Separate script, not a
  modification to the main remediation engine; see
  [GPO (LGPO) Remediation Path](#gpo-lgpo-remediation-path).
