// Compliance metrics + findings rollups computed from normalized reviews.
// This is the reporting engine: counts, severity rollups, open-findings (POA&M source).
import type { NormalizedReview, Severity } from './types.js'

export interface Metrics {
  assessed: number                                   // reviews with a definitive result
  total: number                                      // all reviews
  results: { pass: number; fail: number; notapplicable: number; notchecked: number; informational: number }
  findings: Record<Exclude<Severity, 'unknown'>, number>   // OPEN (fail) by severity -> POA&M
  assessedBySeverity: Record<Exclude<Severity, 'unknown'>, number>
  compliancePct: number                              // pass / (pass+fail) * 100
}

const emptySev = (): Record<Exclude<Severity, 'unknown'>, number> => ({ high: 0, medium: 0, low: 0 })

export function computeMetrics(reviews: NormalizedReview[]): Metrics {
  const results = { pass: 0, fail: 0, notapplicable: 0, notchecked: 0, informational: 0 }
  const findings = emptySev()
  const assessedBySeverity = emptySev()

  for (const r of reviews) {
    if (r.result in results) (results as Record<string, number>)[r.result]++
    const sev = r.severity
    if (sev !== 'unknown') {
      if (r.result === 'pass' || r.result === 'fail' || r.result === 'notapplicable') assessedBySeverity[sev]++
      if (r.result === 'fail') findings[sev]++
    }
  }

  const assessed = results.pass + results.fail + results.notapplicable
  const denom = results.pass + results.fail
  const compliancePct = denom > 0 ? Math.round((results.pass / denom) * 1000) / 10 : 0

  return { assessed, total: reviews.length, results, findings, assessedBySeverity, compliancePct }
}

// Open findings as flat records (one per failed rule) — the POA&M feed.
export interface OpenFinding {
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: Severity
  title: string
}

export function openFindings(reviews: NormalizedReview[]): OpenFinding[] {
  return reviews
    .filter((r) => r.result === 'fail')
    .map(({ ruleId, groupId, ruleVersion, severity, title }) => ({ ruleId, groupId, ruleVersion, severity, title }))
}
