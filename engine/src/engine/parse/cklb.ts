// CKLB (STIG Viewer 3 JSON) parser -> ParsedChecklist.
import { normalizeSeverity, type NormalizedReview, type ParsedChecklist, type ReviewResult } from '../types.js'

interface CklbRule {
  group_id?: string
  rule_id?: string
  rule_version?: string
  severity?: string
  rule_title?: string
  status?: string
  finding_details?: string
  comments?: string
}
interface CklbStig {
  stig_id?: string
  stig_name?: string
  display_name?: string
  version?: string | number
  release_info?: string
  rules?: CklbRule[]
}
interface CklbDoc {
  title?: string
  target_data?: { host_name?: string }
  stigs?: CklbStig[]
}

// CKLB status -> normalized result.
// All non-pass/fail/na variants (including extended result values) collapse to
// 'notchecked' at parse time; the ingest layer assigns resultId from the DB
// lookup table and can promote the value as needed.
function mapStatus(status: string): ReviewResult {
  switch ((status ?? '').trim().toLowerCase()) {
    case 'not_a_finding': return 'pass'
    case 'open': return 'fail'
    case 'not_applicable': return 'notapplicable'
    case 'not_reviewed':
    case 'unknown':
    case 'error':
    case 'notselected':
    case 'fixed':
    default: return 'notchecked'
  }
}

export function parseCklb(json: string): ParsedChecklist {
  const doc: CklbDoc = typeof json === 'string' ? JSON.parse(json) : json
  if (!doc?.stigs) throw new Error('Not a CKLB document (missing stigs[])')

  const stig = doc.stigs[0] ?? {}
  const reviews: NormalizedReview[] = (stig.rules ?? []).map((r) => ({
    ruleId: r.rule_id ?? '',
    groupId: r.group_id ?? '',
    ruleVersion: r.rule_version ?? '',
    severity: normalizeSeverity(r.severity),
    title: r.rule_title ?? '',
    result: mapStatus(r.status ?? ''),
    detail: r.finding_details ?? '',
    comment: r.comments ?? ''
  }))

  return {
    source: 'cklb',
    hostName: doc.target_data?.host_name ?? '',
    benchmarkId: stig.stig_id ?? stig.stig_name ?? 'unknown',
    revision: stig.release_info ?? String(stig.version ?? 'unknown'),
    stigTitle: stig.display_name ?? stig.stig_name ?? doc.title ?? '',
    reviews
  }
}
