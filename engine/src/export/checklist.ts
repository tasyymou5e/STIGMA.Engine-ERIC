// CKL (STIG Viewer 2 XML) and CKLB (STIG Viewer 3 JSON) export.
// Generates checklist files from stored asset reviews for a given benchmark.
import { XMLBuilder } from 'fast-xml-parser'
import type { RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface AssetRow {
  name: string
  fqdn: string | null
  ip: string | null
}

interface StigRow {
  benchmarkId: string
  title: string | null
  revision: string | null
}

interface ReviewRow {
  ruleId: string
  groupId: string | null
  ruleVersion: string | null
  severity: string | null
  title: string | null
  result: string | null
  detail: string | null
  comment: string | null
}

// ---------------------------------------------------------------------------
// Result mapping
// ---------------------------------------------------------------------------

// Map internal result ENUM -> CKL STATUS string.
function resultToCklStatus(result: string | null): string {
  switch (result) {
    case 'pass': return 'NotAFinding'
    case 'fail': return 'Open'
    case 'notapplicable': return 'Not_Applicable'
    case 'notchecked':
    case 'informational':
    case null:
    default: return 'Not_Reviewed'
  }
}

// Map internal result ENUM -> CKLB status string (lowercase with underscores).
function resultToCklbStatus(result: string | null): string {
  switch (result) {
    case 'pass': return 'not_a_finding'
    case 'fail': return 'open'
    case 'notapplicable': return 'not_applicable'
    case 'notchecked':
    case 'informational':
    case null:
    default: return 'not_reviewed'
  }
}

// ---------------------------------------------------------------------------
// Shared DB query helpers
// ---------------------------------------------------------------------------

async function fetchAsset(assetId: number): Promise<AssetRow> {
  const [rows] = await pool.query<RowDataPacket[]>(
    'SELECT name, fqdn, ip FROM asset WHERE assetId = :assetId LIMIT 1',
    { assetId }
  )
  if (rows.length === 0) throw new Error(`Asset not found: assetId=${assetId}`)
  return rows[0] as unknown as AssetRow
}

async function fetchStig(benchmarkId: string): Promise<StigRow> {
  // The stig table uses (benchmarkId, revision) as PK; pick the latest revision
  // row by sorting lexicographically (e.g. V1R1 < V1R23 < V2R1) descending.
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT benchmarkId, title, revision
       FROM stig
      WHERE benchmarkId = :benchmarkId
      ORDER BY revision DESC
      LIMIT 1`,
    { benchmarkId }
  )
  if (rows.length === 0) throw new Error(`STIG not found: benchmarkId=${benchmarkId}`)
  return rows[0] as unknown as StigRow
}

async function fetchReviews(assetId: number, benchmarkId: string): Promise<ReviewRow[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT ruleId, groupId, ruleVersion, severity, title, result, detail, comment
       FROM review
      WHERE assetId    = :assetId
        AND benchmarkId = :benchmarkId
      ORDER BY ruleId ASC`,
    { assetId, benchmarkId }
  )
  return rows as unknown as ReviewRow[]
}

// ---------------------------------------------------------------------------
// Classification banner helper
// ---------------------------------------------------------------------------

function classificationBanner(c: string): string {
  return c === 'CUI' ? 'CONTROLLED UNCLASSIFIED INFORMATION' : c
}

/**
 * Generate a STIG Viewer 2-compatible CKL XML string for the given asset and
 * benchmark.  Only rules that have stored reviews are included as VULN elements.
 *
 * @param assetId        - Primary key of the asset row.
 * @param benchmarkId    - STIG benchmark identifier, e.g. "Windows_11_STIG".
 * @param classification - DoD classification level (default: "CUI").
 * @returns              - UTF-8 XML string.
 */
export async function generateCkl(assetId: number, benchmarkId: string, classification = 'CUI'): Promise<string> {
  const [asset, stig, reviews] = await Promise.all([
    fetchAsset(assetId),
    fetchStig(benchmarkId),
    fetchReviews(assetId, benchmarkId),
  ])

  // STIG_INFO SI_DATA entries matching the NAVY/STIG Viewer expected field set.
  const siData = [
    { SID_NAME: 'version',     SID_DATA: extractVersion(stig.revision) },
    { SID_NAME: 'classification' },
    { SID_NAME: 'customname' },
    { SID_NAME: 'stigid',      SID_DATA: stig.benchmarkId },
    { SID_NAME: 'description', SID_DATA: '' },
    { SID_NAME: 'filename',    SID_DATA: 'stigma-engine' },
    { SID_NAME: 'releaseinfo', SID_DATA: stig.revision ?? '' },
    { SID_NAME: 'title',       SID_DATA: stig.title ?? '' },
    { SID_NAME: 'uuid',        SID_DATA: '' },
    { SID_NAME: 'notice',      SID_DATA: 'terms-of-use' },
    { SID_NAME: 'source' },
  ]

  // Build VULN elements.
  const vulns = reviews.map((r) => {
    const stigData = [
      { VULN_ATTRIBUTE: 'Vuln_Num',  ATTRIBUTE_DATA: r.groupId ?? '' },
      { VULN_ATTRIBUTE: 'Severity',  ATTRIBUTE_DATA: r.severity ?? '' },
      { VULN_ATTRIBUTE: 'Group_Title', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'Rule_ID',   ATTRIBUTE_DATA: r.ruleId },
      { VULN_ATTRIBUTE: 'Rule_Ver',  ATTRIBUTE_DATA: r.ruleVersion ?? '' },
      { VULN_ATTRIBUTE: 'Rule_Title', ATTRIBUTE_DATA: r.title ?? '' },
      { VULN_ATTRIBUTE: 'Vuln_Discuss', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'IA_Controls', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'Check_Content', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'Fix_Text',  ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'False_Positives', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'False_Negatives', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'Documentable', ATTRIBUTE_DATA: 'false' },
      { VULN_ATTRIBUTE: 'Mitigations', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'Potential_Impact', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'Third_Party_Tools', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'Mitigation_Control', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'Responsibility', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'Security_Override_Guidance', ATTRIBUTE_DATA: '' },
      { VULN_ATTRIBUTE: 'STIGRef', ATTRIBUTE_DATA: `${stig.title ?? ''} :: ${stig.revision ?? ''}` },
    ]

    return {
      STIG_DATA:           stigData,
      STATUS:              resultToCklStatus(r.result),
      FINDING_DETAILS:     r.detail ?? '',
      COMMENTS:            r.comment ?? '',
      SEVERITY_OVERRIDE:   null,
      SEVERITY_JUSTIFICATION: null,
    }
  })

  const xmlJs = {
    CHECKLIST: {
      CLASSIFICATION: classificationBanner(classification),
      ASSET: {
        ROLE:             'None',
        ASSET_TYPE:       'Computing',
        MARKING:          null,
        HOST_NAME:        asset.name,
        HOST_IP:          asset.ip ?? '',
        HOST_MAC:         '',
        HOST_FQDN:        asset.fqdn ?? '',
        TARGET_COMMENT:   null,
        TECH_AREA:        null,
        TARGET_KEY:       '2350',
        WEB_OR_DATABASE:  'false',
        WEB_DB_SITE:      null,
        WEB_DB_INSTANCE:  null,
      },
      STIGS: {
        iSTIG: [
          {
            STIG_INFO: { SI_DATA: siData },
            VULN:      vulns,
          },
        ],
      },
    },
  }

  const builder = new XMLBuilder({
    attributeNamePrefix: '@_',
    textNodeName:        '#text',
    ignoreAttributes:    true,
    format:              true,
    indentBy:            '  ',
  })

  const xmlBody: string = builder.build(xmlJs)
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!-- Classification: ${classification} -->\n<!-- STIGMA Engine export -->\n${xmlBody}`
}

// ---------------------------------------------------------------------------
// generateCklb
// ---------------------------------------------------------------------------

/**
 * Generate a STIG Viewer 3-compatible CKLB JSON string for the given asset and
 * benchmark.  The output shape matches the CKLB parser's expected input.
 *
 * @param assetId     - Primary key of the asset row.
 * @param benchmarkId - STIG benchmark identifier.
 * @returns           - JSON string.
 */
export async function generateCklb(assetId: number, benchmarkId: string, classification = 'CUI'): Promise<string> {
  const [asset, stig, reviews] = await Promise.all([
    fetchAsset(assetId),
    fetchStig(benchmarkId),
    fetchReviews(assetId, benchmarkId),
  ])

  const rules = reviews.map((r) => ({
    group_id:        r.groupId ?? '',
    rule_id:         r.ruleId.replace(/_rule$/, ''),
    rule_id_src:     r.ruleId,
    severity:        r.severity ?? 'unknown',
    rule_version:    r.ruleVersion ?? '',
    group_title:     '',
    rule_title:      r.title ?? '',
    fix_text:        '',
    false_positives: '',
    false_negatives: '',
    discussion:      '',
    check_content:   '',
    documentable:    'false',
    mitigations:     '',
    potential_impacts: '',
    third_party_tools: '',
    mitigation_control: '',
    responsibility:  '',
    security_override_guidance: '',
    ia_controls:     '',
    status:          resultToCklbStatus(r.result),
    overrides:       {},
    comments:        r.comment ?? '',
    finding_details: r.detail ?? '',
    ccis:            [] as string[],
  }))

  const cklb = {
    title:       `${stig.title ?? benchmarkId} — ${asset.name}`,
    classification: classificationBanner(classification),
    id:          '',
    active:      false,
    mode:        1,
    has_path:    true,
    target_data: {
      target_type:      'Computing',
      host_name:        asset.name,
      ip_address:       asset.ip ?? '',
      mac_address:      '',
      fqdn:             asset.fqdn ?? '',
      comments:         '',
      role:             'None',
      is_web_database:  false,
      technology_area:  '',
      web_db_site:      '',
      web_db_instance:  '',
    },
    stigs: [
      {
        stig_name:            stig.title ?? benchmarkId,
        display_name:         (stig.title ?? benchmarkId).replace(' Security Technical Implementation Guide', ''),
        stig_id:              stig.benchmarkId,
        version:              extractVersion(stig.revision),
        release_info:         stig.revision ?? '',
        uuid:                 '',
        reference_identifier: '0000',
        size:                 rules.length,
        rules,
      },
    ],
  }

  return JSON.stringify(cklb, null, 2)
}

// ---------------------------------------------------------------------------
// generateXccdf
// ---------------------------------------------------------------------------

/**
 * Generate an XCCDF 1.2 TestResult XML document for the given asset and
 * benchmark.  Each review row becomes a <rule-result> element with the
 * appropriate XCCDF result value.
 *
 * @param assetId     - Primary key of the asset row.
 * @param benchmarkId - STIG benchmark identifier, e.g. "Windows_11_STIG".
 * @returns           - UTF-8 XML string.
 */
export async function generateXccdf(assetId: number, benchmarkId: string, classification = 'CUI'): Promise<string> {
  const [asset, reviews] = await Promise.all([
    fetchAsset(assetId),
    fetchReviews(assetId, benchmarkId),
  ])

  const now = new Date().toISOString()

  // Map internal result → XCCDF result string.
  function toXccdfResult(result: string | null): string {
    switch (result) {
      case 'pass':          return 'pass'
      case 'fail':          return 'fail'
      case 'notapplicable': return 'notapplicable'
      case 'notchecked':
      case 'informational':
      case null:
      default:              return 'notchecked'
    }
  }

  // Build rule-result elements manually for precise attribute ordering.
  const ruleResults = reviews.map((r) => {
    const ts = now
    const severity = r.severity ?? 'unknown'
    return [
      `  <rule-result idref="${escapeXml(r.ruleId)}" time="${ts}" severity="${escapeXml(severity)}">`,
      `    <result>${toXccdfResult(r.result)}</result>`,
      `  </rule-result>`,
    ].join('\n')
  }).join('\n')

  const xml = [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<!-- STIGMA Engine XCCDF export -->`,
    `<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"`,
    `            id="stigma-result-${assetId}-${escapeXml(benchmarkId)}"`,
    `            start-time="${now}"`,
    `            end-time="${now}">`,
    `  <benchmark href="${escapeXml(benchmarkId)}"/>`,
    `  <notice id="classification">${escapeXml(classificationBanner(classification))}</notice>`,
    `  <target>${escapeXml(asset.name)}</target>`,
    `  <target-address>${escapeXml(asset.ip ?? '')}</target-address>`,
    ruleResults,
    `</TestResult>`,
  ].join('\n')

  return xml
}

// ---------------------------------------------------------------------------
// XML escape helper (used by generateXccdf)
// ---------------------------------------------------------------------------

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the numeric version string from a revision such as "V1R23" or
 * "Release: 23 Benchmark Date: 2023-10-26".  Falls back to the raw string.
 */
function extractVersion(revision: string | null | undefined): string {
  if (!revision) return ''
  // "V1R23" style
  const vr = revision.match(/^V(\d+)R\d+/)
  if (vr) return vr[1]
  // "Version: 1 Release: 23 ..." style
  const ver = revision.match(/[Vv]ersion[:\s]+(\d+)/)
  if (ver) return ver[1]
  return revision
}
