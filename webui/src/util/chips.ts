// Maps review result / severity values to PrimeVue Tag severities + labels.
import type { ReviewResult, Severity } from '../api/types'

type TagSeverity = 'success' | 'info' | 'warn' | 'danger' | 'secondary' | 'contrast'

const RESULT: Record<ReviewResult, { label: string; severity: TagSeverity }> = {
  pass: { label: 'Not a Finding', severity: 'success' },
  fail: { label: 'Open', severity: 'danger' },
  notapplicable: { label: 'Not Applicable', severity: 'secondary' },
  notchecked: { label: 'Not Reviewed', severity: 'warn' },
  informational: { label: 'Informational', severity: 'info' }
}

const SEVERITY: Record<Severity, { label: string; severity: TagSeverity }> = {
  high: { label: 'CAT I', severity: 'danger' },
  medium: { label: 'CAT II', severity: 'warn' },
  low: { label: 'CAT III', severity: 'info' },
  unknown: { label: 'Unknown', severity: 'secondary' }
}

export const resultTag = (r: ReviewResult) => RESULT[r] ?? { label: r, severity: 'secondary' as TagSeverity }
export const severityTag = (s: Severity) => SEVERITY[s] ?? { label: s, severity: 'secondary' as TagSeverity }
