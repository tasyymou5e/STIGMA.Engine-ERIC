// CKL (STIG Viewer 2 / Evaluate-STIG XML) parser -> ParsedChecklist.
import { XMLParser } from 'fast-xml-parser'
import { normalizeSeverity, type NormalizedReview, type ParsedChecklist, type ReviewResult } from '../types.js'

const parser = new XMLParser({
  ignoreAttributes: true,
  trimValues: true,
  // Force these repeated nodes to always be arrays for stable iteration.
  isArray: (name) => ['VULN', 'STIG_DATA', 'SI_DATA', 'iSTIG'].includes(name)
})

// CKL STATUS -> normalized result.
// All non-pass/fail/na variants (including extended result values) collapse to
// 'notchecked' at parse time; the ingest layer assigns resultId from the DB
// lookup table and can promote the value as needed.
function mapStatus(status: string): ReviewResult {
  switch ((status ?? '').trim()) {
    case 'NotAFinding': return 'pass'
    case 'Open': return 'fail'
    case 'Not_Applicable': return 'notapplicable'
    case 'Not_Reviewed':
    case 'unknown':
    case 'error':
    case 'notselected':
    case 'fixed':
    default: return 'notchecked'
  }
}

// Collapse a VULN's STIG_DATA array into a flat attribute map.
function stigDataMap(stigData: Array<{ VULN_ATTRIBUTE?: string; ATTRIBUTE_DATA?: string }>): Record<string, string> {
  const map: Record<string, string> = {}
  for (const d of stigData ?? []) {
    if (d.VULN_ATTRIBUTE) map[d.VULN_ATTRIBUTE] = d.ATTRIBUTE_DATA ?? ''
  }
  return map
}

export function parseCkl(xml: string): ParsedChecklist {
  const doc = parser.parse(xml)
  const checklist = doc?.CHECKLIST
  if (!checklist) throw new Error('Not a CKL document (missing CHECKLIST root)')

  const istig = checklist.STIGS?.iSTIG?.[0] ?? checklist.STIGS?.iSTIG
  const siData: Array<{ SID_NAME?: string; SID_DATA?: string }> = istig?.STIG_INFO?.SI_DATA ?? []
  const info: Record<string, string> = {}
  for (const s of siData) if (s.SID_NAME) info[s.SID_NAME] = s.SID_DATA ?? ''

  const vulns = istig?.VULN ?? []
  const reviews: NormalizedReview[] = vulns.map((v: { STIG_DATA?: []; STATUS?: string; FINDING_DETAILS?: string; COMMENTS?: string }) => {
    const sd = stigDataMap(v.STIG_DATA ?? [])
    return {
      ruleId: sd['Rule_ID'] ?? '',
      groupId: sd['Vuln_Num'] ?? '',
      ruleVersion: sd['Rule_Ver'] ?? '',
      severity: normalizeSeverity(sd['Severity']),
      title: sd['Rule_Title'] ?? '',
      result: mapStatus(v.STATUS ?? ''),
      detail: String(v.FINDING_DETAILS ?? ''),
      comment: String(v.COMMENTS ?? '')
    }
  })

  return {
    source: 'ckl',
    hostName: String(checklist.ASSET?.HOST_NAME ?? ''),
    benchmarkId: info['stigid'] ?? info['title'] ?? 'unknown',
    revision: info['releaseinfo'] ?? info['version'] ?? 'unknown',
    stigTitle: info['title'] ?? '',
    reviews
  }
}
