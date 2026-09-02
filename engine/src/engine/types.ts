// Normalized domain types produced by the ingest engine, independent of source format.

export type ReviewResult =
  | 'pass'
  | 'fail'
  | 'notapplicable'
  | 'notchecked'
  | 'informational'
  | 'unknown'
  | 'error'
  | 'notselected'
  | 'fixed'
export type Severity = 'high' | 'medium' | 'low' | 'unknown'
export type ChecklistSource = 'ckl' | 'cklb' | 'xccdf'

export interface NormalizedReview {
  ruleId: string        // e.g. SV-220706r958478_rule
  groupId: string       // e.g. V-220706
  ruleVersion: string   // STIG ID, e.g. WN11-CC-000005
  severity: Severity
  title: string
  result: ReviewResult
  detail: string
  comment: string
  /** STIG rule version string, resolved from rule_version_check_digest at ingest time */
  version?: string
  /** SHA-256 of the rule's check content (BINARY(32)), resolved at ingest time */
  checkDigest?: string
}

export interface ParsedChecklist {
  source: ChecklistSource
  hostName: string
  benchmarkId: string   // STIG identifier, e.g. Windows_11_STIG
  revision: string      // e.g. V1R23 or release string
  stigTitle: string
  reviews: NormalizedReview[]
}

// Re-export UserRecord from the repository layer so engine code can import it
// from a single, transport-agnostic types module.
export type { UserRecord } from '../repositories/users.js'

export function normalizeSeverity(raw: string | undefined | null): Severity {
  switch ((raw ?? '').trim().toLowerCase()) {
    case 'high': case 'cat i': case 'cat_i': return 'high'
    case 'medium': case 'cat ii': case 'cat_ii': return 'medium'
    case 'low': case 'cat iii': case 'cat_iii': return 'low'
    default: return 'unknown'
  }
}
