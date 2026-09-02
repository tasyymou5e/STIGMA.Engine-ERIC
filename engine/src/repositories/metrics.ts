// SQL-based metrics aggregation — replaces in-memory computeMetrics for
// collection-scoped queries.  All three exported functions operate against the
// live review + asset tables and return pre-shaped summary objects so callers
// need no post-processing.
//
// The pure-function fallback (computeMetrics) remains in engine/metrics.ts for
// single-asset or offline use; this module handles the collection level.
//
// --- 3-Tab workspace aggregations (added) ---
// stigAggregation   — one row per benchmarkId, collection-wide
// assetAggregation  — one row per asset, collection-wide
// assetStigDetail   — per-STIG breakdown for one asset
// stigAssetDetail   — per-asset breakdown for one STIG
import type { RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/** Full-width result vocabulary stored in the review table. */
type ReviewResult =
  | 'pass'
  | 'fail'
  | 'notapplicable'
  | 'notchecked'
  | 'informational'
  | 'unknown'
  | 'error'
  | 'notselected'
  | 'fixed'

/** Review workflow statuses. */
type ReviewStatus = 'saved' | 'submitted' | 'accepted' | 'rejected'

/** Aggregated metrics for an entire collection. */
export interface MetricsSummary {
  /** Reviews with a definitive result (pass | fail | notapplicable). */
  assessed: number
  /** Total review rows for this collection. */
  total: number
  /** Per-result counts. */
  results: {
    pass: number
    fail: number
    notapplicable: number
    notchecked: number
    informational: number
    unknown: number
    error: number
    notselected: number
    fixed: number
  }
  /** Open (fail) reviews broken down by severity — the POA&M feed. */
  findings: {
    high: number
    medium: number
    low: number
  }
  /** pass / (pass + fail) * 100, rounded to one decimal place.  0 when denom is 0. */
  compliancePct: number
  /** Review workflow status counts. */
  statuses: {
    saved: number
    submitted: number
    accepted: number
    rejected: number
  }
}

/** Per-asset compliance summary row. */
export interface AssetMetrics {
  assetId: number
  name: string
  /** Reviews with a definitive result on this asset. */
  assessed: number
  pass: number
  fail: number
  /** pass / (pass + fail) * 100, rounded to one decimal place. */
  compliancePct: number
}

/** Per-STIG (benchmarkId) compliance summary row. */
export interface StigMetrics {
  benchmarkId: string
  assessed: number
  pass: number
  fail: number
  notapplicable: number
  /** pass / (pass + fail) * 100, rounded to one decimal place. */
  compliancePct: number
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function zeroResults(): MetricsSummary['results'] {
  return {
    pass: 0,
    fail: 0,
    notapplicable: 0,
    notchecked: 0,
    informational: 0,
    unknown: 0,
    error: 0,
    notselected: 0,
    fixed: 0
  }
}

function zeroFindings(): MetricsSummary['findings'] {
  return { high: 0, medium: 0, low: 0 }
}

function zeroStatuses(): MetricsSummary['statuses'] {
  return { saved: 0, submitted: 0, accepted: 0, rejected: 0 }
}

function pct(pass: number, fail: number): number {
  const denom = pass + fail
  return denom > 0 ? Math.round((pass / denom) * 1000) / 10 : 0
}

// ---------------------------------------------------------------------------
// collectionMetrics
// ---------------------------------------------------------------------------

/**
 * Aggregate all review results for a collection into a MetricsSummary.
 *
 * The single GROUP BY query replaces iterating over every NormalizedReview in
 * memory and is orders of magnitude faster for large collections.
 *
 * SQL shape:
 *   SELECT result, severity, status, COUNT(*) AS cnt
 *     FROM review r
 *     JOIN asset a ON a.assetId = r.assetId
 *    WHERE a.collectionId = :id
 *    GROUP BY result, severity, status
 *
 * The result/status columns may be stored either as their string API value
 * (direct on the review row) or as an integer FK (resultId / statusId) joined
 * to the result / status lookup tables.  We try the joined form first and fall
 * back to direct string columns so the function works against both schema
 * variants.
 */
export async function collectionMetrics(collectionId: number): Promise<MetricsSummary> {
  // --- primary query: uses result/status lookup-table joins ---
  const primarySql = `
    SELECT
      COALESCE(res.api, r.result) AS result,
      r.severity,
      COALESCE(st.api, r.status)  AS status,
      COUNT(*)   AS cnt
    FROM review r
    JOIN asset a
      ON a.assetId = r.assetId
    LEFT JOIN result res
      ON res.resultId = r.resultId
    LEFT JOIN status st
      ON st.statusId = r.statusId
    WHERE a.collectionId = :id
    GROUP BY COALESCE(res.api, r.result), r.severity, COALESCE(st.api, r.status)`

  // --- fallback query: string columns stored directly on review ---
  const fallbackSql = `
    SELECT
      r.result,
      r.severity,
      r.status,
      COUNT(*) AS cnt
    FROM review r
    JOIN asset a
      ON a.assetId = r.assetId
    WHERE a.collectionId = :id
    GROUP BY r.result, r.severity, r.status`

  let rows: RowDataPacket[]
  try {
    ;[rows] = await pool.query<RowDataPacket[]>(primarySql, { id: collectionId })
  } catch {
    ;[rows] = await pool.query<RowDataPacket[]>(fallbackSql, { id: collectionId })
  }

  const results = zeroResults()
  const findings = zeroFindings()
  const statuses = zeroStatuses()
  let total = 0

  for (const row of rows) {
    const result   = (row.result   as ReviewResult | null) ?? 'unknown'
    const severity = (row.severity as string        | null) ?? 'unknown'
    const status   = (row.status   as ReviewStatus  | null) ?? 'saved'
    const cnt      = Number(row.cnt ?? 0)

    total += cnt

    // Accumulate result bucket
    if (result in results) {
      (results as Record<string, number>)[result] += cnt
    } else {
      results.unknown += cnt
    }

    // Accumulate findings (fail by severity)
    if (result === 'fail') {
      if (severity === 'high' || severity === 'medium' || severity === 'low') {
        findings[severity] += cnt
      }
    }

    // Accumulate status bucket
    if (status in statuses) {
      (statuses as Record<string, number>)[status] += cnt
    }
  }

  const assessed = results.pass + results.fail + results.notapplicable
  const compliancePct = pct(results.pass, results.fail)

  return { assessed, total, results, findings, compliancePct, statuses }
}

// ---------------------------------------------------------------------------
// assetMetrics
// ---------------------------------------------------------------------------

/**
 * Per-asset compliance breakdown for every asset in a collection.
 *
 * SQL shape:
 *   SELECT a.assetId, a.name,
 *          COUNT(*)                                               AS assessed,
 *          SUM(result = 'pass')                                   AS pass,
 *          SUM(result = 'fail')                                   AS fail,
 *          ROUND(SUM(result='pass') / NULLIF(SUM(result IN ('pass','fail')),0) * 100, 1)
 *            AS compliancePct
 *     FROM asset a
 *     JOIN review r ON r.assetId = a.assetId
 *    WHERE a.collectionId = :id
 *      AND r.result IN ('pass','fail','notapplicable')
 *    GROUP BY a.assetId, a.name
 *    ORDER BY a.name
 */
export async function assetMetrics(collectionId: number): Promise<AssetMetrics[]> {
  // Primary: resultId FK → result lookup
  const primarySql = `
    SELECT
      a.assetId,
      a.name,
      COUNT(*)                                                                 AS assessed,
      SUM(res.api = 'pass')                                                    AS pass,
      SUM(res.api = 'fail')                                                    AS fail,
      ROUND(
        SUM(res.api = 'pass') /
        NULLIF(SUM(res.api IN ('pass', 'fail')), 0) * 100,
        1
      )                                                                        AS compliancePct
    FROM asset a
    JOIN review r
      ON r.assetId = a.assetId
    JOIN result res
      ON res.resultId = r.resultId
    WHERE a.collectionId = :id
      AND res.api IN ('pass', 'fail', 'notapplicable')
    GROUP BY a.assetId, a.name
    ORDER BY a.name`

  // Fallback: result stored as string on review
  const fallbackSql = `
    SELECT
      a.assetId,
      a.name,
      COUNT(*)                                                                 AS assessed,
      SUM(r.result = 'pass')                                                   AS pass,
      SUM(r.result = 'fail')                                                   AS fail,
      ROUND(
        SUM(r.result = 'pass') /
        NULLIF(SUM(r.result IN ('pass', 'fail')), 0) * 100,
        1
      )                                                                        AS compliancePct
    FROM asset a
    JOIN review r
      ON r.assetId = a.assetId
    WHERE a.collectionId = :id
      AND r.result IN ('pass', 'fail', 'notapplicable')
    GROUP BY a.assetId, a.name
    ORDER BY a.name`

  let rows: RowDataPacket[]
  try {
    ;[rows] = await pool.query<RowDataPacket[]>(primarySql, { id: collectionId })
  } catch {
    ;[rows] = await pool.query<RowDataPacket[]>(fallbackSql, { id: collectionId })
  }

  return rows.map((row) => ({
    assetId:       Number(row.assetId),
    name:          row.name          as string,
    assessed:      Number(row.assessed      ?? 0),
    pass:          Number(row.pass          ?? 0),
    fail:          Number(row.fail          ?? 0),
    compliancePct: row.compliancePct != null ? Number(row.compliancePct) : 0
  }))
}

// ---------------------------------------------------------------------------
// stigMetrics
// ---------------------------------------------------------------------------

/**
 * Per-STIG (benchmarkId) compliance breakdown for a collection.
 *
 * The benchmarkId is expected to be stored on the review row itself (written
 * by upsertReviews in the reviews repository).  All JOIN paths gracefully
 * degrade if the STIG library tables are absent.
 *
 * SQL shape:
 *   SELECT r.benchmarkId,
 *          COUNT(*)                   AS assessed,
 *          SUM(result = 'pass')       AS pass,
 *          SUM(result = 'fail')       AS fail,
 *          SUM(result = 'notapplicable') AS notapplicable,
 *          ...compliancePct...
 *     FROM review r
 *     JOIN asset a ON a.assetId = r.assetId
 *    WHERE a.collectionId = :id
 *      AND r.result IN ('pass','fail','notapplicable')
 *    GROUP BY r.benchmarkId
 *    ORDER BY r.benchmarkId
 */
export async function stigMetrics(collectionId: number): Promise<StigMetrics[]> {
  // Primary: resultId FK → result lookup
  const primarySql = `
    SELECT
      r.benchmarkId,
      COUNT(*)                                                                 AS assessed,
      SUM(res.api = 'pass')                                                    AS pass,
      SUM(res.api = 'fail')                                                    AS fail,
      SUM(res.api = 'notapplicable')                                           AS notapplicable,
      ROUND(
        SUM(res.api = 'pass') /
        NULLIF(SUM(res.api IN ('pass', 'fail')), 0) * 100,
        1
      )                                                                        AS compliancePct
    FROM review r
    JOIN asset a
      ON a.assetId = r.assetId
    JOIN result res
      ON res.resultId = r.resultId
    WHERE a.collectionId = :id
      AND res.api IN ('pass', 'fail', 'notapplicable')
    GROUP BY r.benchmarkId
    ORDER BY r.benchmarkId`

  // Fallback: result stored as string
  const fallbackSql = `
    SELECT
      r.benchmarkId,
      COUNT(*)                                                                 AS assessed,
      SUM(r.result = 'pass')                                                   AS pass,
      SUM(r.result = 'fail')                                                   AS fail,
      SUM(r.result = 'notapplicable')                                          AS notapplicable,
      ROUND(
        SUM(r.result = 'pass') /
        NULLIF(SUM(r.result IN ('pass', 'fail')), 0) * 100,
        1
      )                                                                        AS compliancePct
    FROM review r
    JOIN asset a
      ON a.assetId = r.assetId
    WHERE a.collectionId = :id
      AND r.result IN ('pass', 'fail', 'notapplicable')
    GROUP BY r.benchmarkId
    ORDER BY r.benchmarkId`

  let rows: RowDataPacket[]
  try {
    ;[rows] = await pool.query<RowDataPacket[]>(primarySql, { id: collectionId })
  } catch {
    ;[rows] = await pool.query<RowDataPacket[]>(fallbackSql, { id: collectionId })
  }

  return rows.map((row) => ({
    benchmarkId:    row.benchmarkId   as string,
    assessed:       Number(row.assessed       ?? 0),
    pass:           Number(row.pass           ?? 0),
    fail:           Number(row.fail           ?? 0),
    notapplicable:  Number(row.notapplicable  ?? 0),
    compliancePct:  row.compliancePct != null ? Number(row.compliancePct) : 0
  }))
}

// ---------------------------------------------------------------------------
// 3-Tab workspace aggregation types
// ---------------------------------------------------------------------------

/**
 * Per-STIG aggregation row for the workspace STIG tab.
 * One row per benchmarkId present in reviews for the collection.
 */
export interface StigAggRow {
  benchmarkId:   string
  stigTitle:     string | null
  assetCount:    number
  ruleCount:     number
  passCount:     number
  failCount:     number
  naCount:       number
  nrCount:       number
  catI:          number
  catII:         number
  catIII:        number
  /** pass / (pass + fail) * 100, rounded to 1 dp.  0 when denominator is 0. */
  compliancePct: number
}

/**
 * Per-asset aggregation row for the workspace Asset tab.
 * One row per asset in the collection.
 */
export interface AssetAggRow {
  assetId:       number
  assetName:     string
  stigCount:     number
  ruleCount:     number
  passCount:     number
  failCount:     number
  naCount:       number
  nrCount:       number
  catI:          number
  catII:         number
  catIII:        number
  /** pass / (pass + fail) * 100, rounded to 1 dp.  0 when denominator is 0. */
  compliancePct: number
}

// ---------------------------------------------------------------------------
// stigAggregation
// ---------------------------------------------------------------------------

/**
 * One row per benchmarkId present in reviews for the given collection.
 *
 * Counts distinct assets and rules evaluated, full result breakdown, and
 * CAT I/II/III findings (fail by severity).  The stig table is LEFT-JOINed so
 * that benchmarkIds with no library entry still appear (stigTitle will be null).
 *
 * Note: the stig table uses a (benchmarkId, revision) composite PK; we pick
 * ANY_VALUE(s.title) to collapse multiple revisions to a single display string.
 */
export async function stigAggregation(collectionId: number): Promise<StigAggRow[]> {
  const sql = `
    SELECT
      rv.benchmarkId,
      ANY_VALUE(s.title)                                              AS stigTitle,
      COUNT(DISTINCT rv.assetId)                                      AS assetCount,
      COUNT(DISTINCT rv.ruleId)                                       AS ruleCount,
      SUM(rv.result = 'pass')                                         AS passCount,
      SUM(rv.result = 'fail')                                         AS failCount,
      SUM(rv.result = 'notapplicable')                                AS naCount,
      SUM(rv.result = 'notchecked')                                   AS nrCount,
      SUM(rv.severity = 'high'   AND rv.result = 'fail')              AS catI,
      SUM(rv.severity = 'medium' AND rv.result = 'fail')              AS catII,
      SUM(rv.severity = 'low'    AND rv.result = 'fail')              AS catIII
    FROM review rv
    JOIN asset a
      ON a.assetId = rv.assetId
     AND a.collectionId = :collectionId
    LEFT JOIN stig s
      ON s.benchmarkId = rv.benchmarkId COLLATE utf8mb4_0900_as_cs
    GROUP BY rv.benchmarkId
    ORDER BY rv.benchmarkId`

  const [rows] = await pool.query<RowDataPacket[]>(sql, { collectionId })

  return rows.map((row): StigAggRow => {
    const passCount = Number(row.passCount ?? 0)
    const failCount = Number(row.failCount ?? 0)
    return {
      benchmarkId:   String(row.benchmarkId ?? ''),
      stigTitle:     row.stigTitle != null ? String(row.stigTitle) : null,
      assetCount:    Number(row.assetCount  ?? 0),
      ruleCount:     Number(row.ruleCount   ?? 0),
      passCount,
      failCount,
      naCount:       Number(row.naCount     ?? 0),
      nrCount:       Number(row.nrCount     ?? 0),
      catI:          Number(row.catI        ?? 0),
      catII:         Number(row.catII       ?? 0),
      catIII:        Number(row.catIII      ?? 0),
      compliancePct: pct(passCount, failCount)
    }
  })
}

// ---------------------------------------------------------------------------
// assetAggregation
// ---------------------------------------------------------------------------

/**
 * One row per asset in the collection.
 *
 * LEFT JOIN ensures assets with no reviews are included (all counts will be 0).
 * Distinct benchmarkId count gives the number of STIGs evaluated on that asset.
 */
export async function assetAggregation(collectionId: number): Promise<AssetAggRow[]> {
  const sql = `
    SELECT
      a.assetId,
      a.name                                                          AS assetName,
      COUNT(DISTINCT rv.benchmarkId)                                  AS stigCount,
      COUNT(rv.reviewId)                                              AS ruleCount,
      SUM(rv.result = 'pass')                                         AS passCount,
      SUM(rv.result = 'fail')                                         AS failCount,
      SUM(rv.result = 'notapplicable')                                AS naCount,
      SUM(rv.result = 'notchecked')                                   AS nrCount,
      SUM(rv.severity = 'high'   AND rv.result = 'fail')              AS catI,
      SUM(rv.severity = 'medium' AND rv.result = 'fail')              AS catII,
      SUM(rv.severity = 'low'    AND rv.result = 'fail')              AS catIII
    FROM asset a
    LEFT JOIN review rv
      ON rv.assetId = a.assetId
    WHERE a.collectionId = :collectionId
    GROUP BY a.assetId, a.name
    ORDER BY a.name`

  const [rows] = await pool.query<RowDataPacket[]>(sql, { collectionId })

  return rows.map((row): AssetAggRow => {
    const passCount = Number(row.passCount ?? 0)
    const failCount = Number(row.failCount ?? 0)
    return {
      assetId:       Number(row.assetId    ?? 0),
      assetName:     String(row.assetName  ?? ''),
      stigCount:     Number(row.stigCount  ?? 0),
      ruleCount:     Number(row.ruleCount  ?? 0),
      passCount,
      failCount,
      naCount:       Number(row.naCount    ?? 0),
      nrCount:       Number(row.nrCount    ?? 0),
      catI:          Number(row.catI       ?? 0),
      catII:         Number(row.catII      ?? 0),
      catIII:        Number(row.catIII     ?? 0),
      compliancePct: pct(passCount, failCount)
    }
  })
}

// ---------------------------------------------------------------------------
// assetStigDetail
// ---------------------------------------------------------------------------

/**
 * Per-STIG breakdown for one asset within a collection.
 * Returned when the user selects an asset row in the workspace Asset tab —
 * the bottom grid shows all STIGs evaluated on that asset with their results.
 *
 * Identical SELECT to stigAggregation but scoped to a single assetId.
 */
export async function assetStigDetail(
  collectionId: number,
  assetId: number
): Promise<StigAggRow[]> {
  const sql = `
    SELECT
      rv.benchmarkId,
      ANY_VALUE(s.title)                                              AS stigTitle,
      COUNT(DISTINCT rv.assetId)                                      AS assetCount,
      COUNT(DISTINCT rv.ruleId)                                       AS ruleCount,
      SUM(rv.result = 'pass')                                         AS passCount,
      SUM(rv.result = 'fail')                                         AS failCount,
      SUM(rv.result = 'notapplicable')                                AS naCount,
      SUM(rv.result = 'notchecked')                                   AS nrCount,
      SUM(rv.severity = 'high'   AND rv.result = 'fail')              AS catI,
      SUM(rv.severity = 'medium' AND rv.result = 'fail')              AS catII,
      SUM(rv.severity = 'low'    AND rv.result = 'fail')              AS catIII
    FROM review rv
    JOIN asset a
      ON a.assetId = rv.assetId
     AND a.collectionId = :collectionId
    LEFT JOIN stig s
      ON s.benchmarkId = rv.benchmarkId COLLATE utf8mb4_0900_as_cs
    WHERE rv.assetId = :assetId
    GROUP BY rv.benchmarkId
    ORDER BY rv.benchmarkId`

  const [rows] = await pool.query<RowDataPacket[]>(sql, { collectionId, assetId })


  return rows.map((row): StigAggRow => {
    const passCount = Number(row.passCount ?? 0)
    const failCount = Number(row.failCount ?? 0)
    return {
      benchmarkId:   String(row.benchmarkId ?? ''),
      stigTitle:     row.stigTitle != null ? String(row.stigTitle) : null,
      assetCount:    Number(row.assetCount  ?? 0),
      ruleCount:     Number(row.ruleCount   ?? 0),
      passCount,
      failCount,
      naCount:       Number(row.naCount     ?? 0),
      nrCount:       Number(row.nrCount     ?? 0),
      catI:          Number(row.catI        ?? 0),
      catII:         Number(row.catII       ?? 0),
      catIII:        Number(row.catIII      ?? 0),
      compliancePct: pct(passCount, failCount)
    }
  })
}

// ---------------------------------------------------------------------------
// metaSummary
// ---------------------------------------------------------------------------

/**
 * Single summary row aggregating every review across all collections.
 * Returns a flat object with totals and an overall compliance percentage.
 */
export interface MetaSummaryRow {
  totalCollections: number
  totalAssets: number
  totalReviews: number
  totalAssessed: number
  overallCompliancePct: number
}

export async function metaSummary(): Promise<MetaSummaryRow> {
  const sql = `
    SELECT
      COUNT(DISTINCT a.collectionId)                            AS totalCollections,
      COUNT(DISTINCT a.assetId)                                 AS totalAssets,
      COUNT(rv.reviewId)                                        AS totalReviews,
      SUM(rv.result IN ('pass','fail','notapplicable'))          AS totalAssessed,
      SUM(rv.result = 'pass')                                   AS passCount,
      SUM(rv.result = 'fail')                                   AS failCount
    FROM asset a
    LEFT JOIN review rv ON rv.assetId = a.assetId`

  const [rows] = await pool.query<RowDataPacket[]>(sql)
  const row = rows[0] ?? {}
  const passCount  = Number(row.passCount  ?? 0)
  const failCount  = Number(row.failCount  ?? 0)
  return {
    totalCollections:    Number(row.totalCollections ?? 0),
    totalAssets:         Number(row.totalAssets      ?? 0),
    totalReviews:        Number(row.totalReviews     ?? 0),
    totalAssessed:       Number(row.totalAssessed    ?? 0),
    overallCompliancePct: pct(passCount, failCount)
  }
}

// ---------------------------------------------------------------------------
// metaDetailByCollection
// ---------------------------------------------------------------------------

/**
 * One row per collection — the full cross-collection analytics set.
 * Shape matches CollectionMetaRow used by GET /collections/meta/metrics.
 */
export interface CollectionMetaDetailRow {
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

export async function metaDetailByCollection(): Promise<CollectionMetaDetailRow[]> {
  const sql = `
    SELECT
      c.collectionId,
      c.name,
      COUNT(DISTINCT a.assetId)                                       AS assetCount,
      COUNT(DISTINCT rv.benchmarkId)                                  AS stigCount,
      SUM(rv.result = 'pass')                                         AS passCount,
      SUM(rv.result = 'fail')                                         AS failCount,
      SUM(rv.severity = 'high'   AND rv.result = 'fail')              AS catI,
      SUM(rv.severity = 'medium' AND rv.result = 'fail')              AS catII,
      SUM(rv.severity = 'low'    AND rv.result = 'fail')              AS catIII
    FROM collection c
    LEFT JOIN asset a   ON a.collectionId = c.collectionId
    LEFT JOIN review rv ON rv.assetId = a.assetId
    GROUP BY c.collectionId, c.name
    ORDER BY c.name`

  const [rows] = await pool.query<RowDataPacket[]>(sql)
  return rows.map((row): CollectionMetaDetailRow => {
    const passCount = Number(row.passCount ?? 0)
    const failCount = Number(row.failCount ?? 0)
    return {
      collectionId: Number(row.collectionId),
      name:         String(row.name         ?? ''),
      assetCount:   Number(row.assetCount   ?? 0),
      stigCount:    Number(row.stigCount    ?? 0),
      passCount,
      failCount,
      catI:         Number(row.catI         ?? 0),
      catII:        Number(row.catII        ?? 0),
      catIII:       Number(row.catIII       ?? 0),
      compliancePct: pct(passCount, failCount)
    }
  })
}

// ---------------------------------------------------------------------------
// metaDetailByStig
// ---------------------------------------------------------------------------

/**
 * One row per STIG across all collections.
 * Shows how many collections and assets each benchmarkId appears in, plus
 * full result and CAT breakdown.
 */
export interface StigMetaRow {
  benchmarkId:    string
  title:          string | null
  collectionCount: number
  assetCount:     number
  passCount:      number
  failCount:      number
  catI:           number
  catII:          number
  catIII:         number
  compliancePct:  number
}

export async function metaDetailByStig(): Promise<StigMetaRow[]> {
  const sql = `
    SELECT
      rv.benchmarkId,
      ANY_VALUE(s.title)                                              AS title,
      COUNT(DISTINCT a.collectionId)                                  AS collectionCount,
      COUNT(DISTINCT rv.assetId)                                      AS assetCount,
      SUM(rv.result = 'pass')                                         AS passCount,
      SUM(rv.result = 'fail')                                         AS failCount,
      SUM(rv.severity = 'high'   AND rv.result = 'fail')              AS catI,
      SUM(rv.severity = 'medium' AND rv.result = 'fail')              AS catII,
      SUM(rv.severity = 'low'    AND rv.result = 'fail')              AS catIII
    FROM review rv
    JOIN asset a
      ON a.assetId = rv.assetId
    LEFT JOIN stig s
      ON s.benchmarkId = rv.benchmarkId COLLATE utf8mb4_0900_as_cs
    GROUP BY rv.benchmarkId
    ORDER BY rv.benchmarkId`

  const [rows] = await pool.query<RowDataPacket[]>(sql)
  return rows.map((row): StigMetaRow => {
    const passCount = Number(row.passCount ?? 0)
    const failCount = Number(row.failCount ?? 0)
    return {
      benchmarkId:     String(row.benchmarkId     ?? ''),
      title:           row.title != null ? String(row.title) : null,
      collectionCount: Number(row.collectionCount ?? 0),
      assetCount:      Number(row.assetCount      ?? 0),
      passCount,
      failCount,
      catI:            Number(row.catI            ?? 0),
      catII:           Number(row.catII           ?? 0),
      catIII:          Number(row.catIII          ?? 0),
      compliancePct:   pct(passCount, failCount)
    }
  })
}

// ---------------------------------------------------------------------------
// stigAssetDetail
// ---------------------------------------------------------------------------

/**
 * Per-asset breakdown for one STIG within a collection.
 * Returned when the user selects a STIG row in the workspace STIG tab —
 * the bottom grid shows all assets evaluated against that STIG.
 *
 * Identical SELECT to assetAggregation but scoped to a single benchmarkId.
 */
export async function stigAssetDetail(
  collectionId: number,
  benchmarkId: string
): Promise<AssetAggRow[]> {
  const sql = `
    SELECT
      a.assetId,
      a.name                                                          AS assetName,
      COUNT(DISTINCT rv.benchmarkId)                                  AS stigCount,
      COUNT(rv.reviewId)                                              AS ruleCount,
      SUM(rv.result = 'pass')                                         AS passCount,
      SUM(rv.result = 'fail')                                         AS failCount,
      SUM(rv.result = 'notapplicable')                                AS naCount,
      SUM(rv.result = 'notchecked')                                   AS nrCount,
      SUM(rv.severity = 'high'   AND rv.result = 'fail')              AS catI,
      SUM(rv.severity = 'medium' AND rv.result = 'fail')              AS catII,
      SUM(rv.severity = 'low'    AND rv.result = 'fail')              AS catIII
    FROM asset a
    LEFT JOIN review rv
      ON rv.assetId = a.assetId
     AND rv.benchmarkId = :benchmarkId
    WHERE a.collectionId = :collectionId
    GROUP BY a.assetId, a.name
    ORDER BY a.name`

  const [rows] = await pool.query<RowDataPacket[]>(sql, { collectionId, benchmarkId })

  return rows.map((row): AssetAggRow => {
    const passCount = Number(row.passCount ?? 0)
    const failCount = Number(row.failCount ?? 0)
    return {
      assetId:       Number(row.assetId    ?? 0),
      assetName:     String(row.assetName  ?? ''),
      stigCount:     Number(row.stigCount  ?? 0),
      ruleCount:     Number(row.ruleCount  ?? 0),
      passCount,
      failCount,
      naCount:       Number(row.naCount    ?? 0),
      nrCount:       Number(row.nrCount    ?? 0),
      catI:          Number(row.catI       ?? 0),
      catII:         Number(row.catII      ?? 0),
      catIII:        Number(row.catIII     ?? 0),
      compliancePct: pct(passCount, failCount)
    }
  })
}

// ---------------------------------------------------------------------------
// Unreviewed tracking types
// ---------------------------------------------------------------------------

export interface UnreviewedAsset {
  assetId: number
  name: string
  benchmarkId: string
  stigTitle: string | null
}

export interface UnreviewedRule {
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: string
  title: string
  benchmarkId: string
  assetCount: number
}

// ---------------------------------------------------------------------------
// unreviewedAssets
// ---------------------------------------------------------------------------

/**
 * Assets in the collection that have a STIG assigned (via stig_asset_map) but
 * have ZERO review rows for that (asset, STIG) pair.
 *
 * Optional filter: benchmarkId.
 */
export async function unreviewedAssets(
  collectionId: number,
  params: { benchmarkId?: string; severity?: string }
): Promise<UnreviewedAsset[]> {
  const binds: Record<string, string | number | null> = { collectionId }
  const filters: string[] = []

  if (params.benchmarkId) {
    filters.push('sam.benchmarkId = :benchmarkId')
    binds.benchmarkId = params.benchmarkId
  }

  const whereExtra = filters.length > 0 ? `AND ${filters.join(' AND ')}` : ''

  const sql = `
    SELECT
      a.assetId,
      a.name,
      sam.benchmarkId,
      s.title AS stigTitle
    FROM stig_asset_map sam
    JOIN asset a
      ON a.assetId = sam.assetId
     AND a.collectionId = :collectionId
     AND a.state = 'enabled'
    LEFT JOIN stig s ON s.benchmarkId = sam.benchmarkId
    WHERE NOT EXISTS (
      SELECT 1
      FROM review rv
      WHERE rv.assetId = sam.assetId
        AND rv.benchmarkId COLLATE utf8mb4_0900_as_cs = sam.benchmarkId
    )
    ${whereExtra}
    ORDER BY a.name, sam.benchmarkId`

  const [rows] = await pool.query<RowDataPacket[]>(sql, binds)
  return rows as unknown as UnreviewedAsset[]
}

// ---------------------------------------------------------------------------
// unreviewedRules
// ---------------------------------------------------------------------------

/**
 * Rules in the STIG library (scoped to STIGs assigned to assets in the
 * collection via stig_asset_map) for which NO review record exists on any
 * asset in the collection.
 *
 * assetCount = number of collection assets assigned to that STIG (i.e. how
 * many assets "owe" a review for this rule).
 *
 * Optional filters: benchmarkId, severity.
 */
export async function unreviewedRules(
  collectionId: number,
  params: { benchmarkId?: string; severity?: string }
): Promise<UnreviewedRule[]> {
  const binds: Record<string, string | number | null> = { collectionId }
  const filters: string[] = []

  if (params.benchmarkId) {
    filters.push('cr.benchmarkId = :benchmarkId')
    binds.benchmarkId = params.benchmarkId
  }
  if (params.severity) {
    filters.push('r.severity = :severity')
    binds.severity = params.severity
  }

  const whereExtra = filters.length > 0 ? `AND ${filters.join(' AND ')}` : ''

  const sql = `
    SELECT
      r.ruleId,
      r.groupId,
      r.ruleVersion,
      r.severity,
      r.title,
      cr.benchmarkId,
      COUNT(DISTINCT sam.assetId) AS assetCount
    FROM \`rule\` r
    JOIN current_rev cr ON cr.revId = r.revId
    JOIN stig_asset_map sam ON sam.benchmarkId = cr.benchmarkId
    JOIN asset a
      ON a.assetId = sam.assetId
     AND a.collectionId = :collectionId
     AND a.state = 'enabled'
    WHERE NOT EXISTS (
      SELECT 1
      FROM review rv
      JOIN asset a2
        ON a2.assetId = rv.assetId
       AND a2.collectionId = :collectionId
      WHERE rv.ruleId COLLATE utf8mb4_0900_as_cs = r.ruleId
    )
    ${whereExtra}
    GROUP BY r.ruleId, r.groupId, r.ruleVersion, r.severity, r.title, cr.benchmarkId
    ORDER BY FIELD(r.severity, 'high', 'medium', 'low'), cr.benchmarkId, r.groupId`

  const [rows] = await pool.query<RowDataPacket[]>(sql, binds)
  return rows as unknown as UnreviewedRule[]
}
