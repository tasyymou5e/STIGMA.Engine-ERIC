/**
 * metrics.test.ts
 *
 * Tests for computeMetrics() and openFindings() from engine/metrics.ts.
 *
 * All tests are pure-function — no DB, no network.
 *
 * Coverage:
 *   - Basic result counting and assessed/total tallies
 *   - Severity rollup in the findings map (open = fail)
 *   - compliancePct boundary cases (0 %, 100 %, and mixed)
 *   - NaN/unknown-result safety: unrecognised result values must not corrupt counts
 *   - openFindings: one record per failed review, correct shape
 */

import { describe, it, expect } from 'vitest'
import { computeMetrics, openFindings } from '../../src/engine/metrics.js'
import type { NormalizedReview } from '../../src/engine/types.js'

// ---------------------------------------------------------------------------
// Helper factory — creates a minimal NormalizedReview
// ---------------------------------------------------------------------------

let _seq = 0
function mk(
  result: NormalizedReview['result'],
  severity: NormalizedReview['severity'],
  overrides: Partial<NormalizedReview> = {},
): NormalizedReview {
  _seq++
  return {
    ruleId: `SV-${_seq}r1_rule`,
    groupId: `V-${_seq}`,
    ruleVersion: `WN-${_seq}`,
    severity,
    title: `Rule ${_seq}`,
    result,
    detail: '',
    comment: '',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Basic result-counting (existing tests, kept and extended)
// ---------------------------------------------------------------------------

describe('computeMetrics – result counting', () => {
  const reviews = [
    mk('pass', 'high'),
    mk('fail', 'high'),
    mk('fail', 'medium'),
    mk('pass', 'low'),
    mk('notapplicable', 'medium'),
    mk('notchecked', 'low'),
  ]
  const m = computeMetrics(reviews)

  it('counts each result bucket correctly', () => {
    expect(m.results).toMatchObject({ pass: 2, fail: 2, notapplicable: 1, notchecked: 1 })
  })

  it('assessed = pass + fail + notapplicable', () => {
    expect(m.assessed).toBe(5)
  })

  it('total = all reviews including notchecked', () => {
    expect(m.total).toBe(6)
  })

  it('rolls up open findings (fail) by severity', () => {
    expect(m.findings).toEqual({ high: 1, medium: 1, low: 0 })
  })

  it('computes compliancePct = pass / (pass+fail) * 100', () => {
    // 2 pass / 4 (2 pass + 2 fail) = 50 %
    expect(m.compliancePct).toBe(50)
  })
})

// ---------------------------------------------------------------------------
// compliancePct boundary cases
// ---------------------------------------------------------------------------

describe('computeMetrics – compliancePct boundaries', () => {
  it('compliancePct = 0 when all reviews fail', () => {
    const reviews = [
      mk('fail', 'high'),
      mk('fail', 'medium'),
      mk('fail', 'low'),
    ]
    const m = computeMetrics(reviews)
    expect(m.compliancePct).toBe(0)
    expect(m.results.fail).toBe(3)
    expect(m.results.pass).toBe(0)
  })

  it('compliancePct = 100 when all reviews pass', () => {
    const reviews = [
      mk('pass', 'high'),
      mk('pass', 'medium'),
      mk('pass', 'low'),
    ]
    const m = computeMetrics(reviews)
    expect(m.compliancePct).toBe(100)
    expect(m.findings).toEqual({ high: 0, medium: 0, low: 0 })
  })

  it('compliancePct = 0 when there are no pass or fail results (only notapplicable)', () => {
    const reviews = [mk('notapplicable', 'medium'), mk('notchecked', 'low')]
    const m = computeMetrics(reviews)
    // denominator is 0 → should return 0, not NaN
    expect(m.compliancePct).toBe(0)
    expect(Number.isFinite(m.compliancePct)).toBe(true)
  })

  it('compliancePct = 0 when the review array is empty', () => {
    const m = computeMetrics([])
    expect(m.compliancePct).toBe(0)
    expect(m.total).toBe(0)
    expect(m.assessed).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// findings.high counts only severity=high AND result=fail
// ---------------------------------------------------------------------------

describe('computeMetrics – findings severity isolation', () => {
  it('findings.high counts severity=high AND result=fail only', () => {
    const reviews = [
      mk('fail', 'high'),    // counted
      mk('fail', 'high'),    // counted
      mk('pass', 'high'),    // NOT counted — pass
      mk('fail', 'medium'),  // NOT counted in .high
      mk('fail', 'low'),     // NOT counted in .high
    ]
    const m = computeMetrics(reviews)
    expect(m.findings.high).toBe(2)
    expect(m.findings.medium).toBe(1)
    expect(m.findings.low).toBe(1)
  })

  it('a notapplicable high-severity rule does NOT appear in findings.high', () => {
    const reviews = [mk('notapplicable', 'high')]
    const m = computeMetrics(reviews)
    expect(m.findings.high).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// assessedBySeverity
// ---------------------------------------------------------------------------

describe('computeMetrics – assessedBySeverity', () => {
  it('counts pass, fail, and notapplicable per severity', () => {
    const reviews = [
      mk('pass', 'high'),
      mk('fail', 'high'),
      mk('notapplicable', 'high'),
      mk('notchecked', 'high'),   // NOT assessed
      mk('pass', 'medium'),
    ]
    const m = computeMetrics(reviews)
    // high: pass + fail + na = 3
    expect(m.assessedBySeverity.high).toBe(3)
    // medium: 1 pass only
    expect(m.assessedBySeverity.medium).toBe(1)
    expect(m.assessedBySeverity.low).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// NaN safety — unknown result values must not corrupt counts
// ---------------------------------------------------------------------------

describe('computeMetrics – NaN safety with unknown/edge-case results', () => {
  it('ignores unrecognised result strings in all buckets', () => {
    // 'error' and 'notselected' are valid ReviewResult values that are not
    // in the results map initialiser — they should not increment any bucket.
    const reviews = [
      mk('error', 'high'),
      mk('notselected', 'medium'),
      mk('fixed', 'low'),
    ]
    const m = computeMetrics(reviews)
    // None of these are pass/fail/notapplicable/notchecked/informational
    expect(m.results.pass).toBe(0)
    expect(m.results.fail).toBe(0)
    expect(m.results.notapplicable).toBe(0)
    expect(m.results.notchecked).toBe(0)
    expect(m.results.informational).toBe(0)
    expect(m.assessed).toBe(0)
    expect(m.compliancePct).toBe(0)
    expect(Number.isNaN(m.compliancePct)).toBe(false)
  })

  it('unknown severity reviews are excluded from severity rollups but still counted in total', () => {
    const reviews = [
      mk('fail', 'unknown'),   // severity 'unknown' → NOT added to findings or assessedBySeverity
      mk('pass', 'unknown'),
    ]
    const m = computeMetrics(reviews)
    expect(m.total).toBe(2)
    expect(m.findings.high).toBe(0)
    expect(m.findings.medium).toBe(0)
    expect(m.findings.low).toBe(0)
  })

  it('all numeric result fields are finite numbers', () => {
    const m = computeMetrics([mk('fail', 'high'), mk('pass', 'medium')])
    const numerics = [
      m.assessed, m.total, m.compliancePct,
      m.results.pass, m.results.fail, m.results.notapplicable,
      m.results.notchecked, m.results.informational,
      m.findings.high, m.findings.medium, m.findings.low,
    ]
    for (const n of numerics) {
      expect(Number.isFinite(n)).toBe(true)
    }
  })
})

// ---------------------------------------------------------------------------
// informational result
// ---------------------------------------------------------------------------

describe('computeMetrics – informational result', () => {
  it('informational reviews are counted in results but NOT in assessed', () => {
    const reviews = [
      mk('informational', 'medium'),
      mk('pass', 'high'),
    ]
    const m = computeMetrics(reviews)
    expect(m.results.informational).toBe(1)
    // assessed = pass + fail + notapplicable (informational excluded)
    expect(m.assessed).toBe(1)
    expect(m.total).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// openFindings
// ---------------------------------------------------------------------------

describe('openFindings', () => {
  it('returns exactly one record per failed review', () => {
    const reviews = [
      mk('fail', 'high'),
      mk('pass', 'low'),
      mk('fail', 'low'),
      mk('notapplicable', 'medium'),
    ]
    const findings = openFindings(reviews)
    expect(findings).toHaveLength(2)
    expect(findings.every((f) => f.severity)).toBe(true)
  })

  it('returns an empty array when no reviews have failed', () => {
    const reviews = [mk('pass', 'high'), mk('notapplicable', 'medium')]
    expect(openFindings(reviews)).toHaveLength(0)
  })

  it('each open finding contains ruleId, groupId, ruleVersion, severity, title', () => {
    const reviews = [mk('fail', 'high', { ruleId: 'SV-KNOWN', groupId: 'V-KNOWN', title: 'Known' })]
    const findings = openFindings(reviews)
    expect(findings[0]).toMatchObject({
      ruleId: 'SV-KNOWN',
      groupId: 'V-KNOWN',
      severity: 'high',
      title: 'Known',
    })
  })
})
