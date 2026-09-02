// POA&M (Plan of Action & Milestones) XLSX export.
// Produces a DoD eMASS-compatible POA&M workbook matching the official
// "Attachment 0030 - POAMImportTemplate RM Standard" column layout.
import ExcelJS from 'exceljs'
import type { Cell as ExcelJSCell } from 'exceljs'
import type { OpenFinding } from '../engine/metrics.js'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * A single row in the POA&M sheet (legacy internal type kept for compatibility).
 */
export interface FindingRecord {
  title: string
  ruleId: string
  ruleVersion: string
  ccis: string[]
  severity?: string
}

/**
 * Enriched finding coming from repositories/findings.ts — carries DB-resolved
 * CCI list and asset count.
 */
export interface DbFindingRecord {
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: string
  title: string
  assetCount: number
  ccis?: string[]
  nistControl?: string     // NIST 800-53 parent control from cci_reference_map
  assetNames?: string[]    // asset names where this finding is open
  vulnDiscussion?: string  // from rule.vulnDiscussion
  fixText?: string         // from fix_text.text
  stigTitle?: string       // from stig.title
  stigVersion?: string     // from current_rev.version
  stigRelease?: string     // from current_rev.release
  detail?: string          // review detail/finding text
}

// ---------------------------------------------------------------------------
// eMASS POA&M column map (columns A–V = 22 columns)
// ---------------------------------------------------------------------------

// Column indices (1-based) matching the eMASS template exactly.
const COL = {
  A:  1,   // "Control Vulnerability Description" merged label / row A header
  B:  2,   // POA&M Item ID
  C:  3,   // Control Vulnerability Description (data)
  D:  4,   // Security Control Number (NC/NA controls only)
  E:  5,   // Office/Org
  F:  6,   // Security Checks
  G:  7,   // Resources Required
  H:  8,   // Scheduled Completion Date
  I:  9,   // Milestone with Completion Dates
  J:  10,  // Milestone Changes
  K:  11,  // Source Identifying Vulnerability
  L:  12,  // Status
  M:  13,  // Comments
  N:  14,  // Raw Severity
  O:  15,  // Mitigations
  P:  16,  // Severity
  Q:  17,  // Relevance of Threat
  R:  18,  // Likelihood
  S:  19,  // Impact
  T:  20,  // Impact Description
  U:  21,  // Residual Risk Level
  V:  22,  // Recommendations
} as const

const TOTAL_COLS = 22

// Column headers for row 7
const COLUMN_HEADERS: Record<number, string> = {
  [COL.A]: 'Control Vulnerability Description',
  [COL.B]: 'POA&M Item ID',
  [COL.C]: 'Control Vulnerability Description',
  [COL.D]: 'Security Control Number (NC/NA controls only)',
  [COL.E]: 'Office/Org',
  [COL.F]: 'Security Checks',
  [COL.G]: 'Resources Required',
  [COL.H]: 'Scheduled Completion Date',
  [COL.I]: 'Milestone with Completion Dates',
  [COL.J]: 'Milestone Changes',
  [COL.K]: 'Source Identifying Vulnerability',
  [COL.L]: 'Status',
  [COL.M]: 'Comments',
  [COL.N]: 'Raw Severity',
  [COL.O]: 'Mitigations',
  [COL.P]: 'Severity',
  [COL.Q]: 'Relevance of Threat',
  [COL.R]: 'Likelihood',
  [COL.S]: 'Impact',
  [COL.T]: 'Impact Description',
  [COL.U]: 'Residual Risk Level',
  [COL.V]: 'Recommendations',
}

// Column widths (characters). Columns not listed default to 10.
const COLUMN_WIDTHS: Partial<Record<number, number>> = {
  [COL.A]: 8,
  [COL.B]: 8,
  [COL.C]: 45,
  [COL.D]: 25,
  [COL.E]: 30,
  [COL.F]: 25,
  [COL.G]: 25,
  [COL.H]: 15,
  [COL.I]: 35,
  [COL.J]: 25,
  [COL.K]: 35,
  [COL.L]: 15,
  [COL.M]: 25,
  [COL.N]: 10,
  [COL.O]: 20,
  [COL.P]: 12,
  [COL.Q]: 15,
  [COL.R]: 12,
  [COL.S]: 12,
  [COL.T]: 25,
  [COL.U]: 15,
  [COL.V]: 25,
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

function classificationBannerText(c: string): string {
  const label = c === 'CUI' ? 'CONTROLLED UNCLASSIFIED INFORMATION' : c
  return `***** ${label} *****`
}

function classificationFillArgb(c: string): string {
  switch (c.toUpperCase()) {
    case 'UNCLASSIFIED': return 'FF00B050'  // green
    case 'SECRET':       return 'FFC8102E'  // red
    case 'TOP SECRET':   return 'FFFF6600'  // orange
    case 'CUI':
    default:             return 'FF003087'  // dark blue (DoD CUI)
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** US DoD MM/DD/YYYY date format */
function fmtDate(d: Date): string {
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  return `${mm}/${dd}/${d.getFullYear()}`
}

function severityRawCode(severity?: string): string {
  switch (severity?.toLowerCase()) {
    case 'high':   return 'I'
    case 'medium': return 'II'
    case 'low':    return 'III'
    default:       return ''
  }
}

function severityLabel(severity?: string): string {
  switch (severity?.toLowerCase()) {
    case 'high':   return 'High'
    case 'medium': return 'Moderate'
    case 'low':    return 'Low'
    default:       return ''
  }
}

function severityToLikelihood(s?: string): string {
  switch (s?.toLowerCase()) {
    case 'high': case 'critical': return 'Moderate'
    case 'medium':                return 'Moderate'
    case 'low':                   return 'Low'
    default:                      return ''
  }
}

function severityToImpact(s?: string): string {
  switch (s?.toLowerCase()) {
    case 'high': case 'critical': return 'High'
    case 'medium':                return 'Moderate'
    case 'low':                   return 'Low'
    default:                      return ''
  }
}

function severityToResidual(s?: string): string {
  switch (s?.toLowerCase()) {
    case 'high': case 'critical': return 'Moderate'
    case 'medium':                return 'Moderate'
    case 'low':                   return 'Low'
    default:                      return ''
  }
}

/**
 * Sanitize text for POAM cells — mirrors ckl2POAM's replaceSpecialCharacters
 * and createCVD stripping of "Solution :" suffix.
 */
function sanitizePoamText(s: string): string {
  if (!s) return ''
  // Strip text after "Solution :" (ckl2POAM pattern)
  const solutionIdx = s.indexOf('Solution :')
  const cleaned = solutionIdx !== -1 ? s.slice(0, solutionIdx).trim() : s
  return cleaned
    .replace(/[<]/g, '(').replace(/[>]/g, ')')
    .trim()
}

/** Apply eMASS classification banner styling to a cell */
function applyBannerCell(cell: ExcelJSCell, text: string, fillArgb: string): void {
  cell.value = text
  cell.font = { bold: true, size: 13, color: { argb: 'FFFFFFFF' } }
  cell.alignment = { horizontal: 'center', vertical: 'middle' }
  cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: fillArgb } }
  cell.border = {
    top:    { style: 'medium', color: { argb: 'FFFFFFFF' } },
    bottom: { style: 'medium', color: { argb: 'FFFFFFFF' } },
    left:   { style: 'medium', color: { argb: 'FFFFFFFF' } },
    right:  { style: 'medium', color: { argb: 'FFFFFFFF' } },
  }
}

/** Apply header row cell styling (bold, light grey fill) */
function applyHeaderCell(cell: ExcelJSCell, value: string): void {
  cell.value = value
  cell.font = { bold: true, size: 10 }
  cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true }
  cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD9D9D9' } }
  cell.border = {
    top:    { style: 'thin', color: { argb: 'FF000000' } },
    bottom: { style: 'thin', color: { argb: 'FF000000' } },
    left:   { style: 'thin', color: { argb: 'FF000000' } },
    right:  { style: 'thin', color: { argb: 'FF000000' } },
  }
}

/** Apply metadata label styling (bold) */
function applyLabelCell(cell: ExcelJSCell, value: string): void {
  cell.value = value
  cell.font = { bold: true, size: 10 }
  cell.alignment = { horizontal: 'left', vertical: 'middle' }
}

/** Apply metadata value styling */
function applyValueCell(cell: ExcelJSCell, value: string): void {
  cell.value = value
  cell.font = { size: 10 }
  cell.alignment = { horizontal: 'left', vertical: 'middle' }
}

/** Apply data row cell styling */
function applyDataCell(cell: ExcelJSCell, value: string | number, wrapText = true): void {
  cell.value = value
  cell.font = { size: 10 }
  cell.alignment = { vertical: 'top', wrapText }
  cell.border = {
    top:    { style: 'thin', color: { argb: 'FFBFBFBF' } },
    bottom: { style: 'thin', color: { argb: 'FFBFBFBF' } },
    left:   { style: 'thin', color: { argb: 'FFBFBFBF' } },
    right:  { style: 'thin', color: { argb: 'FFBFBFBF' } },
  }
}

// ---------------------------------------------------------------------------
// Shared PoamMetadata type
// ---------------------------------------------------------------------------

export interface PoamMetadata {
  pocName?: string
  pocEmail?: string
  pocPhone?: string
  dodComponent?: string
  systemType?: string
  dodItRegNo?: string
  ombProjectId?: string
  securityCosts?: string
  exportedBy?: string
}

// ---------------------------------------------------------------------------
// addPoamSheet — write one POA&M sheet into an existing workbook
// ---------------------------------------------------------------------------

/**
 * Add a new worksheet to an existing ExcelJS workbook and write a full
 * eMASS-format POA&M layout (22 columns, rows 1–6 metadata, row 7 headers,
 * rows 8+ data, footer banner) into it.
 *
 * Used by the multi-collection /meta/poam/emass.xlsx endpoint so each
 * collection becomes its own sheet in a single workbook.
 *
 * @param wb             Target ExcelJS workbook (must be already created).
 * @param sheetName      Name for the new worksheet (max 31 chars, Excel limit).
 * @param findings       Enriched DB finding records.
 * @param collectionName Human-readable collection / system name (row 5 header).
 * @param classification DoD classification level (default "CUI").
 * @param metadata       Optional eMASS header metadata fields.
 */
export function addPoamSheet(
  wb: ExcelJS.Workbook,
  sheetName: string,
  findings: DbFindingRecord[],
  collectionName: string,
  classification = 'CUI',
  metadata?: PoamMetadata
): void {
  // Excel sheet names: max 31 chars, no special chars
  const safeName = sheetName.replace(/[:\\/?*[\]]/g, '_').slice(0, 31)
  const ws = wb.addWorksheet(safeName)
  _writePoamSheet(ws, findings, collectionName, classification, metadata)
}

// ---------------------------------------------------------------------------
// Primary export function (new eMASS-format signature)
// ---------------------------------------------------------------------------

/**
 * Build an eMASS-format POA&M XLSX workbook matching the official
 * "Attachment 0030 - POAMImportTemplate RM Standard" layout.
 *
 * Column layout: A–V (22 columns), rows 1–6 metadata, row 7 headers,
 * rows 8+ data, final row classification footer banner.
 *
 * @param findings       DB finding records (from repositories/findings.ts)
 * @param collectionName Human-readable collection / system name
 * @param classification DoD classification level (default: "CUI")
 * @param metadata       Optional eMASS header metadata fields
 */
export async function generatePoamXlsx(
  findings: DbFindingRecord[],
  collectionName: string,
  classification = 'CUI',
  metadata?: PoamMetadata
): Promise<Buffer> {
  const wb = new ExcelJS.Workbook()
  wb.creator = 'STIGMA Engine'
  wb.created = new Date()

  const ws = wb.addWorksheet('POA&M')
  _writePoamSheet(ws, findings, collectionName, classification, metadata)
  const buf = await wb.xlsx.writeBuffer()
  return Buffer.from(buf)
}

// ---------------------------------------------------------------------------
// _writePoamSheet — internal: write eMASS layout onto an existing worksheet
// ---------------------------------------------------------------------------

function _writePoamSheet(
  ws: ExcelJS.Worksheet,
  findings: DbFindingRecord[],
  collectionName: string,
  classification: string,
  metadata?: PoamMetadata
): void {
  // Set column widths up-front
  for (let c = 1; c <= TOTAL_COLS; c++) {
    ws.getColumn(c).width = COLUMN_WIDTHS[c] ?? 10
  }

  const today = new Date()
  const bannerText = classificationBannerText(classification)
  const bannerFill = classificationFillArgb(classification)

  // ------------------------------------------------------------------
  // Row 1 — Classification banner
  // ------------------------------------------------------------------
  ws.mergeCells(1, 1, 1, TOTAL_COLS)
  applyBannerCell(ws.getCell(1, 1), bannerText, bannerFill)
  ws.getRow(1).height = 28

  // ------------------------------------------------------------------
  // Row 2 — Date Exported / System Type / OMB Project ID
  // A2="Date Exported:" D2={date} J2="System Type:" K2={systemType}
  // M2="OMB Project ID:" N2={ombId}
  // ------------------------------------------------------------------
  applyLabelCell(ws.getCell(2, COL.A), 'Date Exported:')
  ws.mergeCells(2, COL.D, 2, COL.I)
  applyValueCell(ws.getCell(2, COL.D), fmtDate(today))
  applyLabelCell(ws.getCell(2, COL.J), 'System Type:')
  applyValueCell(ws.getCell(2, COL.K), metadata?.systemType ?? '')
  applyLabelCell(ws.getCell(2, COL.M), 'OMB Project ID:')
  applyValueCell(ws.getCell(2, COL.N), metadata?.ombProjectId ?? '')
  ws.getRow(2).height = 16

  // ------------------------------------------------------------------
  // Row 3 — Exported By
  // A3="Exported By:" D3={exportedBy}
  // ------------------------------------------------------------------
  applyLabelCell(ws.getCell(3, COL.A), 'Exported By:')
  ws.mergeCells(3, COL.D, 3, COL.I)
  applyValueCell(ws.getCell(3, COL.D), metadata?.exportedBy ?? '')
  ws.getRow(3).height = 16

  // ------------------------------------------------------------------
  // Row 4 — DoD Component / POC Name
  // A4="DoD Component:" D4={dodComponent} J4="POC Name:" K4={pocName}
  // ------------------------------------------------------------------
  applyLabelCell(ws.getCell(4, COL.A), 'DoD Component:')
  ws.mergeCells(4, COL.D, 4, COL.I)
  applyValueCell(ws.getCell(4, COL.D), metadata?.dodComponent ?? '')
  applyLabelCell(ws.getCell(4, COL.J), 'POC Name:')
  applyValueCell(ws.getCell(4, COL.K), metadata?.pocName ?? '')
  ws.getRow(4).height = 16

  // ------------------------------------------------------------------
  // Row 5 — System/Project Name / POC Phone / Security Costs
  // A5="System / Project Name:" D5={systemName}
  // J5="POC Phone:" K5={pocPhone} M5="Security Costs:" N5={securityCosts}
  // ------------------------------------------------------------------
  applyLabelCell(ws.getCell(5, COL.A), 'System / Project Name:')
  ws.mergeCells(5, COL.D, 5, COL.I)
  applyValueCell(ws.getCell(5, COL.D), collectionName)
  applyLabelCell(ws.getCell(5, COL.J), 'POC Phone:')
  applyValueCell(ws.getCell(5, COL.K), metadata?.pocPhone ?? '')
  applyLabelCell(ws.getCell(5, COL.M), 'Security Costs:')
  applyValueCell(ws.getCell(5, COL.N), metadata?.securityCosts ?? '')
  ws.getRow(5).height = 16

  // ------------------------------------------------------------------
  // Row 6 — DoD IT Registration No / POC E-Mail
  // A6="DoD IT Registration No:" D6={dodItRegNo}
  // J6="POC E-Mail:" K6={pocEmail}
  // ------------------------------------------------------------------
  applyLabelCell(ws.getCell(6, COL.A), 'DoD IT Registration No:')
  ws.mergeCells(6, COL.D, 6, COL.I)
  applyValueCell(ws.getCell(6, COL.D), metadata?.dodItRegNo ?? '')
  applyLabelCell(ws.getCell(6, COL.J), 'POC E-Mail:')
  applyValueCell(ws.getCell(6, COL.K), metadata?.pocEmail ?? '')
  ws.getRow(6).height = 16

  // ------------------------------------------------------------------
  // Row 7 — Column headers (A–V)
  // ------------------------------------------------------------------
  const headerRow = ws.getRow(7)
  for (let c = 1; c <= TOTAL_COLS; c++) {
    applyHeaderCell(headerRow.getCell(c), COLUMN_HEADERS[c] ?? '')
  }
  headerRow.height = 30
  headerRow.commit()

  // ------------------------------------------------------------------
  // Rows 8+ — Data rows
  // ------------------------------------------------------------------
  findings.forEach((f, i) => {
    const rowNum = 8 + i
    const row = ws.getRow(rowNum)

    // A: blank per eMASS template
    applyDataCell(row.getCell(COL.A), '')

    // B: sequential POA&M Item ID
    applyDataCell(row.getCell(COL.B), i + 1, false)

    // C: Control Vulnerability Description — Rule Title + sanitized finding detail
    const cvd = 'Rule Title: ' + f.title + (f.detail ? '\r\n\r\n' + sanitizePoamText(f.detail) : '')
    applyDataCell(row.getCell(COL.C), cvd)

    // D: Security Control Number — NIST 800-53 parent control from cci_reference_map
    applyDataCell(row.getCell(COL.D), f.nistControl ?? '')

    // E: Office/Org — "pocName, pocEmail" from metadata
    const orgField = [metadata?.pocName, metadata?.pocEmail].filter(Boolean).join(', ')
    applyDataCell(row.getCell(COL.E), orgField)

    // F: Security Checks — ruleId
    applyDataCell(row.getCell(COL.F), f.ruleId)

    // G: Resources Required — 'NA' per ckl2POAM pattern
    applyDataCell(row.getCell(COL.G), 'NA')

    // H: Scheduled Completion Date — one year from today
    const dueDate = new Date(today)
    dueDate.setFullYear(today.getFullYear() + 1)
    applyDataCell(row.getCell(COL.H), fmtDate(dueDate), false)

    // I: Milestone with Completion Dates
    applyDataCell(row.getCell(COL.I), 'Pending remediation')

    // J: Milestone Changes — blank
    applyDataCell(row.getCell(COL.J), '')

    // K: Source Identifying Vulnerability — richer format when stigTitle available
    const srcVuln = f.stigTitle
      ? 'Identified by ' + f.stigTitle + ' :: Version ' + (f.stigVersion ?? '?') + ', Release: ' + (f.stigRelease ?? '?')
      : 'DISA STIG - ' + f.ruleVersion
    applyDataCell(row.getCell(COL.K), srcVuln)

    // L: Status
    applyDataCell(row.getCell(COL.L), 'Ongoing')

    // M: Comments — per-asset failure lines (ruleId failed on <assetName>)
    const assetList = f.assetNames?.length
      ? f.assetNames.map(a => f.ruleId + ' failed on ' + a).join('\r\n')
      : ''
    applyDataCell(row.getCell(COL.M), assetList)

    // N: Raw Severity — Roman numeral CAT (I/II/III)
    applyDataCell(row.getCell(COL.N), severityRawCode(f.severity))

    // O: Mitigations — blank
    applyDataCell(row.getCell(COL.O), '')

    // P: Severity — text label (High/Moderate/Low)
    applyDataCell(row.getCell(COL.P), severityLabel(f.severity))

    // Q: Relevance of Threat — always 'Moderate' per ckl2POAM
    applyDataCell(row.getCell(COL.Q), 'Moderate')

    // R: Likelihood
    applyDataCell(row.getCell(COL.R), severityToLikelihood(f.severity))

    // S: Impact
    applyDataCell(row.getCell(COL.S), severityToImpact(f.severity))

    // T: Impact Description — sanitized Vuln_Discuss
    applyDataCell(row.getCell(COL.T), sanitizePoamText(f.vulnDiscussion ?? ''))

    // U: Residual Risk Level
    applyDataCell(row.getCell(COL.U), severityToResidual(f.severity))

    // V: Recommendations — sanitized fix text
    applyDataCell(row.getCell(COL.V), sanitizePoamText(f.fixText ?? ''))

    row.height = 60
    row.commit()
  })

  // ------------------------------------------------------------------
  // Footer — classification banner
  // ------------------------------------------------------------------
  const footerRowNum = ws.rowCount + 1
  ws.mergeCells(footerRowNum, 1, footerRowNum, TOTAL_COLS)
  applyBannerCell(ws.getCell(footerRowNum, 1), bannerText, bannerFill)
  ws.getRow(footerRowNum).height = 28
  ws.getRow(footerRowNum).commit()

  // Freeze rows 1–7
  ws.views = [{ state: 'frozen', xSplit: 0, ySplit: 7, activeCell: 'B8' }]

  // Auto-filter on header row
  ws.autoFilter = {
    from: { row: 7, column: 1 },
    to:   { row: 7, column: TOTAL_COLS },
  }
}

// ---------------------------------------------------------------------------
// Legacy adapter — used by the existing /collections/:id/poam.xlsx route
// in routes/index.ts which passes OpenFinding[] from engine/metrics.ts.
// Preserved for backward compatibility; new code should call generatePoamXlsx
// directly with DbFindingRecord[].
// ---------------------------------------------------------------------------

export function openFindingToRecord(f: OpenFinding): FindingRecord {
  return {
    title:       f.title,
    ruleId:      f.ruleId,
    ruleVersion: f.ruleVersion,
    ccis:        [],
    severity:    f.severity,
  }
}

/**
 * Convert an OpenFinding to a DbFindingRecord, passing through all available
 * enrichment fields so generatePoamXlsx can populate all 22 columns.
 */
export function openFindingToDbRecord(f: OpenFinding): DbFindingRecord {
  return {
    ruleId:         f.ruleId,
    groupId:        (f as any).groupId ?? '',
    ruleVersion:    f.ruleVersion,
    severity:       f.severity ?? '',
    title:          f.title,
    assetCount:     (f as any).assetCount ?? 1,
    ccis:           (f as any).ccis ?? [],
    assetNames:     (f as any).assetNames,
    vulnDiscussion: (f as any).vulnDiscussion,
    fixText:        (f as any).fixText,
    stigTitle:      (f as any).stigTitle,
    stigVersion:    (f as any).stigVersion,
    stigRelease:    (f as any).stigRelease,
    detail:         (f as any).detail,
  }
}
