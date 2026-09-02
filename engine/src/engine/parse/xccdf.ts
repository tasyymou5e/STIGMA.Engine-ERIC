// XCCDF (SCAP results) parser -> ParsedChecklist.
// Handles the common SCC/OpenSCAP TestResult shape with <rule-result> entries.
import { XMLParser } from 'fast-xml-parser'
import { normalizeSeverity, type NormalizedReview, type ParsedChecklist, type ReviewResult } from '../types.js'

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
  trimValues: true,
  isArray: (name) => ['rule-result', 'Rule', 'Group'].includes(name)
})

function mapResult(result: string): ReviewResult {
  switch ((result ?? '').trim().toLowerCase()) {
    case 'pass': return 'pass'
    case 'fail': return 'fail'
    case 'notapplicable': return 'notapplicable'
    case 'notchecked': case 'notselected': case 'unknown': return 'notchecked'
    case 'informational': return 'informational'
    default: return 'notchecked'
  }
}

export function parseXccdf(xml: string): ParsedChecklist {
  const doc = parser.parse(xml)
  const bench = doc?.Benchmark
  const testResult = bench?.TestResult ?? doc?.TestResult
  if (!testResult) throw new Error('Not an XCCDF results document (missing TestResult)')

  // Build a lookup of Rule metadata (severity/title) by id from the Benchmark definition.
  const ruleMeta = new Map<string, { severity: string; title: string }>()
  const collectRules = (groups: Array<{ Rule?: Array<{ '@_id'?: string; '@_severity'?: string; title?: string }>; Group?: [] }>) => {
    for (const g of groups ?? []) {
      for (const r of g.Rule ?? []) {
        if (r['@_id']) ruleMeta.set(r['@_id'], { severity: r['@_severity'] ?? '', title: typeof r.title === 'string' ? r.title : '' })
      }
      if (g.Group) collectRules(g.Group)
    }
  }
  if (bench?.Group) collectRules(bench.Group)
  for (const r of bench?.Rule ?? []) {
    if (r['@_id']) ruleMeta.set(r['@_id'], { severity: r['@_severity'] ?? '', title: typeof r.title === 'string' ? r.title : '' })
  }

  const rr: Array<{ '@_idref'?: string; '@_version'?: string; result?: string | { '#text'?: string } }> = testResult['rule-result'] ?? []
  const reviews: NormalizedReview[] = rr.map((r) => {
    const idref = (r['@_idref'] ?? '').replace(/^xccdf_[^_]+_rule_/, '')
    const meta = ruleMeta.get(r['@_idref'] ?? '') ?? ruleMeta.get(idref)
    const rawResult = typeof r.result === 'object' && r.result !== null ? (r.result as { '#text'?: string })['#text'] : r.result
    return {
      ruleId: idref,
      groupId: '',
      ruleVersion: r['@_version'] ?? '',
      severity: normalizeSeverity(meta?.severity),
      title: meta?.title ?? '',
      result: mapResult(typeof rawResult === 'string' ? rawResult : ''),
      detail: '',
      comment: ''
    }
  })

  return {
    source: 'xccdf',
    hostName: String(testResult['@_test-system'] ?? testResult.target ?? ''),
    benchmarkId: String(bench?.['@_id'] ?? 'unknown').replace(/^xccdf_[^_]+_benchmark_/, ''),
    revision: String(bench?.['@_style'] ?? bench?.version ?? 'unknown'),
    stigTitle: typeof bench?.title === 'string' ? bench.title : '',
    reviews
  }
}
