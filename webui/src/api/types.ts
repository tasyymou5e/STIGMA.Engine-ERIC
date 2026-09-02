// Hand-authored API types aligned to the ERIC engine's actual routes
// (engine/src/routes/index.ts). For the full generated surface, run `npm run gen:api`.

export type ReviewResult = 'pass' | 'fail' | 'notapplicable' | 'notchecked' | 'informational'
export type ReviewStatus = 'saved' | 'submitted' | 'accepted' | 'rejected'
export type Severity = 'high' | 'medium' | 'low' | 'unknown'

export interface Collection {
  collectionId: number
  name: string
  description?: string | null
  metadata?: Record<string, string> | null
  settings?: Record<string, unknown> | null
  createdAt?: string | null
  owner?: string | null
}

export interface Asset {
  assetId: number
  collectionId?: number
  name: string
  fqdn?: string | null
  ip?: string | null
  mac?: string | null
  description?: string | null
  noncomputing?: boolean
  state?: 'enabled' | 'disabled'
  stigs?: StigAssignment[]
  labels?: LabelRef[]
}

export interface StigAssignment {
  benchmarkId: string
  revisionStr: string
  title: string
}

export interface LabelRef {
  clId: number
  name: string
  color: string | null
}

export interface AssetChecklist {
  benchmarkId: string
  title: string | null
  reviewCount: number
}

export interface Review {
  reviewId?: number
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: Severity
  title: string
  vulnDiscussion?: string | null
  result: ReviewResult
  detail: string
  comment: string
  status?: ReviewStatus
  statusText?: string | null
  userId?: string | null
  username?: string | null
  ts?: string | null
}

export interface ReviewAttachment {
  attachmentId: number
  reviewId: number
  filename: string
  mimetype: string
  size: number
  uploadedBy: string | null
  uploadedAt: string
}

export interface ReviewHistoryEntry {
  reviewId?: number
  result: ReviewResult
  detail: string
  comment: string
  status?: ReviewStatus
  statusText?: string | null
  userId?: string | null
  username?: string | null
  ts: string
}

// ---------------------------------------------------------------------------
// Checklist view types
// ---------------------------------------------------------------------------

/** One row in the Rules grid — GET /collections/:id/checklist/:benchmarkId/rules */
export interface ChecklistRule {
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: Severity
  /** Numeric sort key derived from severity for default grid ordering (1=high, 2=medium, 3=low) */
  severityOrder?: number
  title: string
  /** Count of reviews with result 'fail' */
  failCount: number
  /** Count of reviews with result 'pass' */
  passCount: number
  /** Count of reviews with result 'notapplicable' */
  naCount: number
  /** Count of reviews with result 'notchecked' */
  nrCount: number
  /** Count of reviews with status 'submitted' */
  submittedCount: number
  /** Count of reviews with status 'accepted' */
  acceptedCount: number
}

/** One row in the Reviews grid — GET /collections/:id/checklist/:benchmarkId/rules/:ruleId/reviews */
export interface ChecklistReview {
  assetId: number
  assetName: string
  ruleId: string
  result: ReviewResult
  detail: string | null
  comment: string | null
  status: ReviewStatus | null
  statusText?: string | null
  userId?: string | null
  username?: string | null
  ts?: string | null
}

export interface OpenFinding {
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: Severity
  title: string
  /** Number of assets where this finding is open (populated by engine if supported). */
  assetCount?: number | null
  /** Associated CCI identifiers, e.g. ["CCI-000068", "CCI-000877"]. */
  ccis?: string[] | null
}

export interface PoamEntry {
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: Severity
  title: string
  assetCount?: number | null
  ccis: string[]
  poamStatus: 'Ongoing'
}

export interface Metrics {
  collectionId: number
  assessed: number
  total: number
  results: { pass: number; fail: number; notapplicable: number; notchecked: number; informational: number }
  findings: { high: number; medium: number; low: number }
  assessedBySeverity: { high: number; medium: number; low: number }
  compliancePct: number
}

export interface AssetMetricsRow {
  assetId: number
  assetName: string
  assessed: number
  total: number
  results: { pass: number; fail: number; notapplicable: number; notchecked: number; informational: number }
  compliancePct: number
}

export interface StigMetricsRow {
  benchmarkId: string
  assessed: number
  total: number
  results: { pass: number; fail: number; notapplicable: number; notchecked: number; informational: number }
  compliancePct: number
}

/** Row returned by GET /collections/:id/metrics/stigs-agg */
export interface StigAggRow {
  benchmarkId: string
  title: string
  assetCount: number
  assessed: number
  total: number
  compliancePct: number
  findings: { high: number; medium: number; low: number }
}

/** Row returned by GET /collections/:id/metrics/assets-agg */
export interface AssetAggRow {
  assetId: number
  assetName: string
  stigCount: number
  assessed: number
  total: number
  compliancePct: number
  findings: { high: number; medium: number; low: number }
}

/** Row returned by GET /collections/meta/metrics */
export interface CollectionMetaRow {
  collectionId: number
  name: string
  assetCount: number
  stigCount: number
  passCount: number
  failCount: number
  catI: number
  catII: number
  catIII: number
  compliancePct: number
}

export interface CurrentUser {
  userId: string
  username: string
  displayName?: string
  email?: string | null
  scopes?: string[]
  privileges?: Record<string, boolean>
}

type Json<T> = { responses: { 200: { content: { 'application/json': T } } } }
type JsonP<P, T> = { parameters: { path: P }; responses: { 200: { content: { 'application/json': T } } } }

// openapi-fetch paths shape (subset of the engine API).
export interface paths {
  '/user': { get: Json<CurrentUser> }
  '/collections': {
    get: Json<Collection[]>
    post: {
      requestBody: { content: { 'application/json': { name: string; description?: string; metadata?: Record<string, string> } } }
      responses: { 200: { content: { 'application/json': Collection } } }
    }
  }
  '/collections/{id}': {
    get: JsonP<{ id: number }, Collection>
    patch: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': { name?: string; description?: string | null; metadata?: Record<string, string> | null } } }
      responses: { 200: { content: { 'application/json': Collection } } }
    }
    delete: {
      parameters: { path: { id: number } }
      responses: { 204: Record<string, never> }
    }
  }
  '/collections/{id}/assets': {
    get: JsonP<{ id: number }, Asset[]>
    post: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': { name: string; fqdn?: string; ip?: string } } }
      responses: { 201: { content: { 'application/json': { assetId: number } } } }
    }
  }
  '/collections/meta/metrics': { get: Json<CollectionMetaRow[]> }
  '/collections/{id}/metrics': { get: JsonP<{ id: number }, Metrics> }
  '/collections/{id}/metrics/assets': { get: JsonP<{ id: number }, AssetMetricsRow[]> }
  '/collections/{id}/metrics/stigs': { get: JsonP<{ id: number }, StigMetricsRow[]> }
  '/collections/{id}/metrics/stigs-agg': { get: JsonP<{ id: number }, StigAggRow[]> }
  '/collections/{id}/metrics/assets-agg': { get: JsonP<{ id: number }, AssetAggRow[]> }
  '/collections/{id}/metrics/stigs-agg/{benchmarkId}': {
    get: {
      parameters: { path: { id: number; benchmarkId: string } }
      responses: { 200: { content: { 'application/json': AssetAggRow[] } } }
    }
  }
  '/collections/{id}/metrics/assets-agg/{assetId}': {
    get: {
      parameters: { path: { id: number; assetId: number } }
      responses: { 200: { content: { 'application/json': StigAggRow[] } } }
    }
  }
  '/collections/{id}/metrics/stigs/{benchmarkId}/assets': {
    get: {
      parameters: { path: { id: number; benchmarkId: string } }
      responses: { 200: { content: { 'application/json': StigAssetMetricsRow[] } } }
    }
  }
  '/collections/{id}/metrics/assets/{assetId}/stigs': {
    get: {
      parameters: { path: { id: number; assetId: number } }
      responses: { 200: { content: { 'application/json': StigAggRow[] } } }
    }
  }
  '/collections/{id}/metrics/labels': {
    get: {
      parameters: { path: { id: number } }
      responses: { 200: { content: { 'application/json': LabelMetrics[] } } }
    }
  }
  // Checklist workspace routes
  '/collections/{id}/checklist/{benchmarkId}/rules': {
    get: {
      parameters: { path: { id: number; benchmarkId: string }; query?: { assetId?: string } }
      responses: { 200: { content: { 'application/json': ChecklistRule[] } } }
    }
  }
  '/collections/{id}/checklist/{benchmarkId}/rules/{ruleId}/reviews': {
    get: {
      parameters: { path: { id: number; benchmarkId: string; ruleId: string }; query?: { assetId?: string } }
      responses: { 200: { content: { 'application/json': ChecklistReview[] } } }
    }
  }
  '/collections/{id}/checklist/{benchmarkId}/rules/{ruleId}/reviews/{assetId}': {
    patch: {
      parameters: { path: { id: number; benchmarkId: string; ruleId: string; assetId: number } }
      requestBody: { content: { 'application/json': { result?: ReviewResult; detail?: string | null; comment?: string | null } } }
      responses: { 200: { content: { 'application/json': ChecklistReview } } }
    }
  }
  '/collections/{id}/checklist/{benchmarkId}/rules/{ruleId}/reviews/{assetId}/status': {
    patch: {
      parameters: { path: { id: number; benchmarkId: string; ruleId: string; assetId: number } }
      requestBody: { content: { 'application/json': { status: ReviewStatus } } }
      responses: { 200: { content: { 'application/json': ChecklistReview } } }
    }
  }
  '/collections/{id}/reviews/batch': {
    post: {
      parameters: { path: { id: number } }
      requestBody: {
        content: {
          'application/json': {
            ruleIds: string[]
            assetIds: number[]
            result: ReviewResult
            detail?: string
            comment?: string
          }
        }
      }
      responses: { 200: { content: { 'application/json': { submitted: number; errors: number } } } }
    }
  }

  '/collections/{id}/findings': { get: JsonP<{ id: number }, OpenFinding[]> }
  '/collections/{id}/poam': { get: JsonP<{ id: number }, PoamEntry[]> }
  '/assets/{id}/reviews': { get: JsonP<{ id: number }, Review[]> }

  // Asset CRUD (Phase 6 — routes/assets.ts)
  '/assets': {
    get: {
      parameters: { query: { collectionId: number } }
      responses: { 200: { content: { 'application/json': Asset[] } } }
    }
  }
  '/assets/{id}': {
    get: JsonP<{ id: number }, Asset>
    patch: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': { name?: string; fqdn?: string | null; ip?: string | null; mac?: string | null; description?: string | null; noncomputing?: boolean } } }
      responses: { 200: { content: { 'application/json': Asset } } }
    }
    delete: {
      parameters: { path: { id: number } }
      responses: { 204: Record<string, never> }
    }
  }
  '/assets/{id}/stigs': {
    get: JsonP<{ id: number }, StigAssignment[]>
  }
  '/assets/{id}/stigs/{benchmarkId}': {
    put: {
      parameters: { path: { id: number; benchmarkId: string } }
      requestBody: { content: { 'application/json': Record<string, never> } }
      responses: { 200: { content: { 'application/json': StigAssignment[] } } }
    }
    delete: {
      parameters: { path: { id: number; benchmarkId: string } }
      responses: { 200: { content: { 'application/json': StigAssignment[] } } }
    }
  }
  '/assets/{id}/checklists': { get: JsonP<{ id: number }, AssetChecklist[]> }
  '/assets/{id}/checklists/{benchmarkId}/ckl': {
    get: {
      parameters: { path: { id: number; benchmarkId: string } }
      responses: { 200: { content: { 'text/xml': string } } }
    }
  }
  '/assets/{id}/checklists/{benchmarkId}/cklb': {
    get: {
      parameters: { path: { id: number; benchmarkId: string } }
      responses: { 200: { content: { 'application/json': Record<string, unknown> } } }
    }
  }

  '/collections/{cid}/reviews/{assetId}/{ruleId}': {
    get: { parameters: { path: { cid: number; assetId: number; ruleId: string } }; responses: { 200: { content: { 'application/json': Review } } } }
    patch: {
      parameters: { path: { cid: number; assetId: number; ruleId: string } }
      requestBody: { content: { 'application/json': { result: ReviewResult; detail?: string; comment?: string } } }
      responses: { 200: { content: { 'application/json': Review } } }
    }
    put: {
      parameters: { path: { cid: number; assetId: number; ruleId: string } }
      requestBody: { content: { 'application/json': { result: ReviewResult; detail?: string; comment?: string; status?: ReviewStatus; statusText?: string | null } } }
      responses: { 200: { content: { 'application/json': Review } } }
    }
    delete: {
      parameters: { path: { cid: number; assetId: number; ruleId: string } }
      responses: { 200: { content: { 'application/json': { reviewId: number } } } }
    }
  }
  '/collections/{cid}/reviews/{assetId}/{ruleId}/submit': {
    post: { parameters: { path: { cid: number; assetId: number; ruleId: string } }; requestBody: { content: { 'application/json': Record<string, never> } }; responses: { 200: { content: { 'application/json': Review } } } }
  }
  '/collections/{cid}/reviews/{assetId}/{ruleId}/accept': {
    post: { parameters: { path: { cid: number; assetId: number; ruleId: string } }; requestBody: { content: { 'application/json': Record<string, never> } }; responses: { 200: { content: { 'application/json': Review } } } }
  }
  '/collections/{cid}/reviews/{assetId}/{ruleId}/reject': {
    post: {
      parameters: { path: { cid: number; assetId: number; ruleId: string } }
      requestBody: { content: { 'application/json': { statusText: string } } }
      responses: { 200: { content: { 'application/json': Review } } }
    }
  }
  '/reviews/{reviewId}/history': {
    get: { parameters: { path: { reviewId: number } }; responses: { 200: { content: { 'application/json': ReviewHistoryEntry[] } } } }
  }
  '/reviews/{reviewId}/attachments': {
    get: { parameters: { path: { reviewId: number } }; responses: { 200: { content: { 'application/json': ReviewAttachment[] } } } }
    post: {
      parameters: { path: { reviewId: number } }
      requestBody: { content: { 'multipart/form-data': { file: File } } }
      responses: { 201: { content: { 'application/json': ReviewAttachment } } }
    }
  }
  '/reviews/{reviewId}/attachments/{id}': {
    get: {
      parameters: { path: { reviewId: number; id: number } }
      responses: { 200: { content: { 'application/octet-stream': Blob } } }
    }
    delete: {
      parameters: { path: { reviewId: number; id: number } }
      responses: { 204: Record<string, never> }
    }
  }

  // ---------------------------------------------------------------------------
  // Metadata endpoints — GET/PUT for collection, asset, and review entities
  // ---------------------------------------------------------------------------
  '/collections/{id}/metadata': {
    get: JsonP<{ id: number }, Record<string, string>>
    put: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': Record<string, string> } }
      responses: { 200: { content: { 'application/json': Record<string, string> } } }
    }
    patch: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': Record<string, string> } }
      responses: { 200: { content: { 'application/json': Record<string, string> } } }
    }
  }
  '/assets/{id}/metadata': {
    get: JsonP<{ id: number }, Record<string, string>>
    put: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': Record<string, string> } }
      responses: { 200: { content: { 'application/json': Record<string, string> } } }
    }
    patch: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': Record<string, string> } }
      responses: { 200: { content: { 'application/json': Record<string, string> } } }
    }
  }
  '/reviews/{id}/metadata': {
    get: JsonP<{ id: number }, Record<string, string>>
    put: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': Record<string, string> } }
      responses: { 200: { content: { 'application/json': Record<string, string> } } }
    }
    patch: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': Record<string, string> } }
      responses: { 200: { content: { 'application/json': Record<string, string> } } }
    }
  }

  // Grants
  '/collections/{id}/grants': {
    get: JsonP<{ id: number }, GrantRecord[]>
    post: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': { granteeType: 'user' | 'userGroup'; userId?: number; userGroupId?: number; accessLevel: number } } }
      responses: { 201: { content: { 'application/json': GrantRecord } } }
    }
  }
  '/collections/{id}/grants/{grantId}': {
    get: { parameters: { path: { id: number; grantId: number } }; responses: { 200: { content: { 'application/json': GrantRecord } } } }
    put: {
      parameters: { path: { id: number; grantId: number } }
      requestBody: { content: { 'application/json': { accessLevel: number } } }
      responses: { 200: { content: { 'application/json': GrantRecord } } }
    }
    delete: {
      parameters: { path: { id: number; grantId: number } }
      responses: { 204: Record<string, never> }
    }
  }
  '/collections/{id}/grants/{grantId}/effective-acl': {
    get: { parameters: { path: { id: number; grantId: number } }; responses: { 200: { content: { 'application/json': EffectiveAcl[] } } } }
  }

  // Labels
  '/collections/{id}/labels': {
    get: JsonP<{ id: number }, LabelRecord[]>
    post: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': { name: string; color?: string | null; description?: string } } }
      responses: { 201: { content: { 'application/json': LabelRecord } } }
    }
  }
  '/collections/{id}/labels/{clId}': {
    get: { parameters: { path: { id: number; clId: number } }; responses: { 200: { content: { 'application/json': LabelRecord } } } }
    put: {
      parameters: { path: { id: number; clId: number } }
      requestBody: { content: { 'application/json': { name: string; color?: string | null; description?: string } } }
      responses: { 200: { content: { 'application/json': LabelRecord } } }
    }
    delete: {
      parameters: { path: { id: number; clId: number } }
      responses: { 204: Record<string, never> }
    }
  }
  '/collections/{id}/labels/{clId}/assets': {
    get: { parameters: { path: { id: number; clId: number } }; responses: { 200: { content: { 'application/json': LabelAsset[] } } } }
    put: {
      parameters: { path: { id: number; clId: number } }
      requestBody: { content: { 'application/json': { assetIds: number[] } } }
      responses: { 200: { content: { 'application/json': LabelAsset[] } } }
    }
  }

  // Users
  '/users': { get: Json<UserRecord[]> }
  '/users/{userId}': {
    get: JsonP<{ userId: number }, UserRecord>
    patch: {
      parameters: { path: { userId: number } }
      requestBody: { content: { 'application/json': { username?: string; status?: 'enabled' | 'disabled' } } }
      responses: { 200: { content: { 'application/json': UserRecord } } }
    }
    delete: {
      parameters: { path: { userId: number } }
      responses: { 204: Record<string, never> }
    }
  }

  // User groups
  '/user-groups': {
    get: Json<UserGroupRecord[]>
    post: {
      requestBody: { content: { 'application/json': { name: string; description?: string } } }
      responses: { 201: { content: { 'application/json': UserGroupRecord } } }
    }
  }
  '/user-groups/{id}': {
    get: JsonP<{ id: number }, UserGroupRecord>
    put: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': { name: string; description?: string } } }
      responses: { 200: { content: { 'application/json': UserGroupRecord } } }
    }
    delete: {
      parameters: { path: { id: number } }
      responses: { 204: Record<string, never> }
    }
  }
  '/user-groups/{id}/users': {
    get: JsonP<{ id: number }, UserGroupMember[]>
    post: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': { userId: number } } }
      responses: { 201: { content: { 'application/json': UserGroupMember } } }
    }
    delete: {
      parameters: { path: { id: number } }
      requestBody: { content: { 'application/json': { userId: number } } }
      responses: { 204: Record<string, never> }
    }
  }

  // Collection STIG management
  '/collections/{id}/stigs': {
    get: JsonP<{ id: number }, CollectionStigRow[]>
  }
  '/collections/{id}/stigs/{benchmarkId}/assets': {
    get: {
      parameters: { path: { id: number; benchmarkId: string } }
      responses: { 200: { content: { 'application/json': CollectionStigAsset[] } } }
    }
    put: {
      parameters: { path: { id: number; benchmarkId: string } }
      requestBody: { content: { 'application/json': { assetIds: number[] } } }
      responses: { 200: { content: { 'application/json': CollectionStigAsset[] } } }
    }
  }
  '/collections/{id}/stigs/{benchmarkId}': {
    delete: {
      parameters: { path: { id: number; benchmarkId: string } }
      responses: { 200: { content: { 'application/json': { removed: number } } } }
    }
  }
  // Unreviewed tracking
  '/collections/{id}/unreviewed/assets': {
    get: {
      parameters: { path: { id: number }; query?: { benchmarkId?: string; severity?: string } }
      responses: { 200: { content: { 'application/json': UnreviewedAsset[] } } }
    }
  }
  '/collections/{id}/unreviewed/rules': {
    get: {
      parameters: { path: { id: number }; query?: { benchmarkId?: string; severity?: string } }
      responses: { 200: { content: { 'application/json': UnreviewedRule[] } } }
    }
  }

  // STIG Library
  '/stigs': {
    get: Json<Stig[]>
    post: { requestBody: { content: { 'application/json': { content: string; source: 'xccdf' } } }; responses: { 200: { content: { 'application/json': Stig } }; 201: { content: { 'application/json': Stig } } } }
  }
  '/stigs/{benchmarkId}': { get: JsonP<{ benchmarkId: string }, Stig> }
  '/stigs/{benchmarkId}/revisions': { get: JsonP<{ benchmarkId: string }, Revision[]> }
  // Jobs
  '/jobs': { get: Json<JobRecord[]> }
  '/jobs/{jobId}/run': {
    post: {
      parameters: { path: { jobId: string } }
      requestBody: { content: { 'application/json': Record<string, never> } }
      responses: { 200: { content: { 'application/json': JobRecord } } }
    }
  }

  '/stigs/{benchmarkId}/revisions/{revisionStr}/rules': {
    get: {
      parameters: { path: { benchmarkId: string; revisionStr: string }; query?: { projection?: 'detail' | 'cci' } }
      responses: { 200: { content: { 'application/json': Rule[] } } }
    }
  }
  '/stigs/{benchmarkId}/revisions/diff': {
    get: {
      parameters: { path: { benchmarkId: string }; query: { rev1: string; rev2: string } }
      responses: { 200: { content: { 'application/json': StigDiff } } }
    }
  }
}

// ---------------------------------------------------------------------------
// STIG Diff types
// ---------------------------------------------------------------------------

export interface StigDiff {
  added: Rule[]
  removed: Rule[]
  changed: Array<{ before: Rule; after: Rule }>
  unchanged: number
}

// ---------------------------------------------------------------------------
// STIG Library types
// ---------------------------------------------------------------------------

export interface Stig {
  benchmarkId: string
  title: string
  /** Latest revision string, e.g. "V2R1" */
  lastRevisionStr?: string | null
  lastRevisionDate?: string | null
}

export interface Revision {
  benchmarkId: string
  revisionStr: string
  version: string
  release: string
  ruleCount: number
  highCount?: number | null
  mediumCount?: number | null
  lowCount?: number | null
  releaseInfo?: string | null
  benchmarkDate?: string | null
}

export interface Rule {
  ruleId: string
  ruleVersion: string
  groupId?: string | null
  groupTitle?: string | null
  severity: Severity
  title: string
  description?: string | null
  /** Vulnerability discussion text (returned when projection=detail) */
  vulnDiscussion?: string | null
  /** Check procedure content (returned when projection=detail) */
  checkContent?: string | null
  /** Fix action text (returned when projection=detail) */
  fixText?: string | null
  /** CCI identifiers array (returned when projection=cci) */
  ccis?: string[] | null
  weight?: number | null
}

// ---------------------------------------------------------------------------
// Grant types
// ---------------------------------------------------------------------------

export interface GrantRecord {
  grantId: number
  collectionId: number
  granteeType: 'user' | 'userGroup'
  userId: number | null
  userGroupId: number | null
  granteeName: string
  accessLevel: number
}

export interface EffectiveAcl {
  grantId: number
  collectionId: number
  userId: number
  username: string
  accessLevel: number
  inherited: boolean
}

// ---------------------------------------------------------------------------
// Label types
// ---------------------------------------------------------------------------

export interface LabelRecord {
  clId: number
  collectionId: number
  name: string
  color: string | null
  description: string | null
}

export interface LabelAsset {
  assetId: number
  name: string
  fqdn: string | null
  ip: string | null
}

// ---------------------------------------------------------------------------
// User / user-group types
// ---------------------------------------------------------------------------

export interface UserRecord {
  userId: number
  sub: string
  username: string
  status: string
  lastAccess: string | null
}

export interface UserGroupRecord {
  userGroupId: number
  name: string
  description: string | null
}

export interface UserGroupMember {
  userId: number
  username: string
  status: string
}

// ---------------------------------------------------------------------------
// Collection settings types (Phase 3)
// ---------------------------------------------------------------------------

export interface CollectionSettings {
  reviewFields?: {
    detail?:  { enabled?: 'always' | 'findings'; required?: 'always' | 'findings' | 'optional' }
    comment?: { enabled?: 'always' | 'findings'; required?: 'always' | 'findings' | 'optional' }
  }
  status?: {
    canAccept?: boolean
    minAcceptGrant?: 3 | 4
    resetCriteria?: 'result-change' | 'any-change' | 'never'
  }
  history?: {
    maxReviews?: number | null
  }
}

// ---------------------------------------------------------------------------
// Jobs types (Phase 3)
// ---------------------------------------------------------------------------

export type JobStatus = 'idle' | 'running' | 'error' | 'disabled'

export interface JobRecord {
  jobId: string
  name: string
  status: JobStatus
  lastRun: string | null
  nextRun: string | null
  description?: string
}

// ---------------------------------------------------------------------------
// Meta metrics row alias (Phase 4)
// ---------------------------------------------------------------------------

/** Alias for the row returned by GET /collections/meta/metrics (same as CollectionMetaRow) */
export type MetaMetricsRow = CollectionMetaRow

// ---------------------------------------------------------------------------
// Collection-STIG management types
// ---------------------------------------------------------------------------

/** Row returned by GET /collections/:id/stigs */
export interface CollectionStigRow {
  benchmarkId: string
  title: string | null
  revId: string | null
  version: string | null
  release: string | null
  ruleCount: number | null
  highCount: number | null
  mediumCount: number | null
  lowCount: number | null
  assetCount: number
  pinnedRevision?: string | null
}

/** Row returned by GET /collections/:id/stigs/:benchmarkId/assets */
export interface CollectionStigAsset {
  assetId: number
  name: string
  fqdn: string | null
  ip: string | null
}

// ---------------------------------------------------------------------------
// Unreviewed tracking types
// ---------------------------------------------------------------------------

/** Row returned by GET /collections/:id/unreviewed/assets */
export interface UnreviewedAsset {
  assetId: number
  name: string
  benchmarkId: string
  stigTitle: string | null
}

/** Row returned by GET /collections/:id/unreviewed/rules */
export interface UnreviewedRule {
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: Severity
  title: string
  benchmarkId: string
  assetCount: number
}

// ---------------------------------------------------------------------------
// Drill-down metrics types (new endpoints)
// ---------------------------------------------------------------------------

/** Row returned by GET /collections/:id/metrics/stigs/:benchmarkId/assets — per-asset counts for a STIG */
export interface StigAssetMetricsRow {
  assetId: number
  assetName: string
  assessed: number
  total: number
  compliancePct: number
  results: { pass: number; fail: number; notapplicable: number; notchecked: number; submitted: number; accepted: number }
  findings: { high: number; medium: number; low: number }
}

/** Row returned by GET /collections/:id/metrics/labels — per-label aggregate metrics */
export interface LabelMetrics {
  clId: number
  name: string
  color: string | null
  assetCount: number
  assessed: number
  total: number
  compliancePct: number
  findings: { high: number; medium: number; low: number }
}

// ---------------------------------------------------------------------------
// Evaluate-STIG types
// ---------------------------------------------------------------------------

export interface EvalStigJob {
  jobId: number
  collectionId: number
  status: string
  targetHosts: string[]
  selectedStigs: string[] | null
  outputPath: string
  importedCount: number
  createdBy: string
  startedAt: string | null
  completedAt: string | null
  errorMsg: string | null
}

export interface EvalStigStatus {
  available: boolean
  jobsDirExists: boolean
  evalStigFound: boolean
  agentRunning: boolean
  evalStigPath: string | null
}
