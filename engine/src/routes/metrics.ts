// Metrics endpoints for a collection.
//
// GET /collections/:id/metrics
//   operationId: getMetricsSummaryByCollectionAgg
//   Aggregated result + severity rollup for the whole collection.
//
// GET /collections/:id/metrics/assets
//   operationId: getMetricsSummaryByCollectionAggAsset
//   Per-asset result rollup — one row per asset in the collection.
//
// GET /collections/:id/metrics/stigs
//   operationId: getMetricsSummaryByCollectionAggStig
//   Per-benchmarkId result rollup — one row per STIG evaluated in the collection.
//
// GET /collections/:id/metrics/detail
//   operationId: getMetricsDetailByCollection
//   All result buckets for every (asset, benchmarkId) pair — the most granular view.
//
// All endpoints require a valid bearer token AND the 'stig-manager:collection' scope.

import type { FastifyInstance } from 'fastify'
import type { RowDataPacket } from 'mysql2'
import { requireScope } from '../auth/plugin.js'
import { pool } from '../db/pool.js'
import { computeMetrics } from '../engine/metrics.js'
import { listReviewsByCollection, refreshStigAssetMap } from '../repositories/reviews.js'
import {
  stigAggregation,
  assetAggregation,
  assetStigDetail,
  stigAssetDetail,
  metaSummary,
  metaDetailByCollection,
  metaDetailByStig,
  unreviewedAssets,
  unreviewedRules
} from '../repositories/metrics.js'
import type { MetaSummaryRow, CollectionMetaDetailRow, StigMetaRow } from '../repositories/metrics.js'
import { toCSV } from '../export/csv.js'

const SCOPE_COLLECTION = 'stig-manager:collection'

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

export interface ResultBuckets {
  pass: number
  fail: number
  notapplicable: number
  notchecked: number
  informational: number
}

export interface SeverityBuckets {
  high: number
  medium: number
  low: number
}

/** Aggregated collection-level metrics (operationId: getMetricsSummaryByCollectionAgg). */
export interface CollectionMetrics {
  collectionId: number
  assessed: number
  total: number
  results: ResultBuckets
  findings: SeverityBuckets
  assessedBySeverity: SeverityBuckets
  compliancePct: number
}

/** Per-asset result rollup (operationId: getMetricsSummaryByCollectionAggAsset). */
export interface AssetMetricsRow {
  assetId: number
  assetName: string
  assessed: number
  total: number
  results: ResultBuckets
  compliancePct: number
}

/** Per-STIG result rollup (operationId: getMetricsSummaryByCollectionAggStig). */
export interface StigMetricsRow {
  benchmarkId: string
  assessed: number
  total: number
  results: ResultBuckets
  compliancePct: number
}

/** Per-(asset, benchmarkId) detail row (operationId: getMetricsDetailByCollection). */
export interface DetailMetricsRow {
  assetId: number
  assetName: string
  benchmarkId: string
  assessed: number
  total: number
  results: ResultBuckets
  compliancePct: number
}

// ---------------------------------------------------------------------------
// SQL helpers
// ---------------------------------------------------------------------------

/** Shared SELECT fragment for result bucket counts, used in all three SQL queries. */
const RESULT_COUNTS = `
  SUM(CASE WHEN res.api = 'pass'          THEN 1 ELSE 0 END) AS pass,
  SUM(CASE WHEN res.api = 'fail'          THEN 1 ELSE 0 END) AS fail,
  SUM(CASE WHEN res.api = 'notapplicable' THEN 1 ELSE 0 END) AS notapplicable,
  SUM(CASE WHEN res.api = 'notchecked'    THEN 1 ELSE 0 END) AS notchecked,
  SUM(CASE WHEN res.api = 'informational' THEN 1 ELSE 0 END) AS informational,
  COUNT(*)                                                    AS total`

/** Build a ResultBuckets object from a raw DB row. */
function bucketsFromRow(row: RowDataPacket): ResultBuckets {
  return {
    pass:          Number(row.pass          ?? 0),
    fail:          Number(row.fail          ?? 0),
    notapplicable: Number(row.notapplicable ?? 0),
    notchecked:    Number(row.notchecked    ?? 0),
    informational: Number(row.informational ?? 0)
  }
}

/** Compute assessed count and compliance percentage from a ResultBuckets object. */
function deriveAssessed(b: ResultBuckets): { assessed: number; compliancePct: number } {
  const assessed = b.pass + b.fail + b.notapplicable
  const denom    = b.pass + b.fail
  const compliancePct = denom > 0 ? Math.round((b.pass / denom) * 1000) / 10 : 0
  return { assessed, compliancePct }
}

// ---------------------------------------------------------------------------
// Numeric id helper
// ---------------------------------------------------------------------------

function numId(params: unknown, key = 'id'): number {
  const raw = (params as Record<string, string>)[key]
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0) throw Object.assign(new Error(`Invalid id: ${raw}`), { statusCode: 400 })
  return n
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Cross-collection meta row type
// ---------------------------------------------------------------------------

/** One row per collection returned by GET /collections/meta/metrics. */
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

export async function registerMetricsRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // --------------------------------------------------------------------------
  // GET /collections/meta/metrics
  // operationId: getMetaMetrics
  //
  // Cross-collection analytics dashboard.  Returns one row per collection the
  // requesting user can read (admin sees all; others see only collections they
  // have a direct grant on via collection_grant → user_data).
  //
  // Columns:
  //   collectionId, name, assetCount, stigCount,
  //   passCount, failCount, catI, catII, catIII, compliancePct
  // --------------------------------------------------------------------------
  app.get(
    '/collections/meta/metrics',
    { preHandler: guard },
    async (req): Promise<CollectionMetaRow[]> => {
      const isAdmin = req.user.roles.has('admin') || req.user.roles.has('superuser')

      // Build a visibility filter: admins skip the grant JOIN entirely.
      // For non-admins we restrict to collections the user has a grant on.
      const visibilityJoin = isAdmin
        ? ''
        : `INNER JOIN collection_grant cg
                  ON cg.collectionId = c.collectionId
             INNER JOIN user_data ud
                  ON ud.userId = cg.userId
                 AND ud.username = :username`

      const sql = `
        SELECT
          c.collectionId,
          c.name,
          COUNT(DISTINCT a.assetId)                                         AS assetCount,
          COUNT(DISTINCT rv.benchmarkId)                                    AS stigCount,
          SUM(rv.result = 'pass')                                           AS passCount,
          SUM(rv.result = 'fail')                                           AS failCount,
          SUM(rv.severity = 'high'   AND rv.result = 'fail')               AS catI,
          SUM(rv.severity = 'medium' AND rv.result = 'fail')               AS catII,
          SUM(rv.severity = 'low'    AND rv.result = 'fail')               AS catIII
        FROM collection c
        ${visibilityJoin}
        LEFT JOIN asset a
               ON a.collectionId = c.collectionId
        LEFT JOIN review rv
               ON rv.assetId = a.assetId
        GROUP BY c.collectionId, c.name
        ORDER BY c.name`

      const [rows] = await pool.execute<import('mysql2').RowDataPacket[]>(sql, {
        username: req.user.username
      })

      return rows.map((row): CollectionMetaRow => {
        const passCount = Number(row.passCount ?? 0)
        const failCount = Number(row.failCount ?? 0)
        const denom = passCount + failCount
        const compliancePct = denom > 0 ? Math.round((passCount / denom) * 1000) / 10 : 0
        return {
          collectionId: Number(row.collectionId),
          name:         String(row.name ?? ''),
          assetCount:   Number(row.assetCount ?? 0),
          stigCount:    Number(row.stigCount  ?? 0),
          passCount,
          failCount,
          catI:         Number(row.catI  ?? 0),
          catII:        Number(row.catII ?? 0),
          catIII:       Number(row.catIII ?? 0),
          compliancePct
        }
      })
    }
  )

  // --------------------------------------------------------------------------
  // GET /metrics/summary
  // operationId: getMetaSummary
  //
  // Single summary row: totalCollections, totalAssets, totalReviews,
  // totalAssessed, overallCompliancePct — across ALL collections.
  // --------------------------------------------------------------------------
  app.get(
    '/metrics/summary',
    { preHandler: guard },
    async (): Promise<MetaSummaryRow> => metaSummary()
  )

  // --------------------------------------------------------------------------
  // GET /metrics/detail
  // GET /metrics/summary/agg-collection
  // GET /metrics/detail/agg-collection
  // operationId: getMetaDetailByCollection
  //
  // One row per collection (same SQL as /collections/meta/metrics, but served
  // from a shared repository function to avoid duplication).
  // --------------------------------------------------------------------------
  const collectionDetailHandler = async (): Promise<CollectionMetaDetailRow[]> =>
    metaDetailByCollection()

  app.get('/metrics/detail',                 { preHandler: guard }, collectionDetailHandler)
  app.get('/metrics/summary/agg-collection', { preHandler: guard }, collectionDetailHandler)
  app.get('/metrics/detail/agg-collection',  { preHandler: guard }, collectionDetailHandler)

  // --------------------------------------------------------------------------
  // GET /metrics/summary/agg-stig
  // GET /metrics/detail/agg-stig
  // operationId: getMetaDetailByStig
  //
  // One row per STIG across all collections: collectionCount, assetCount,
  // passCount, failCount, CAT I/II/III, compliancePct.
  // --------------------------------------------------------------------------
  const stigDetailHandler = async (): Promise<StigMetaRow[]> => metaDetailByStig()

  app.get('/metrics/summary/agg-stig', { preHandler: guard }, stigDetailHandler)
  app.get('/metrics/detail/agg-stig',  { preHandler: guard }, stigDetailHandler)

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics
  // operationId: getMetricsSummaryByCollectionAgg
  //
  // Returns the full Metrics snapshot (results, findings-by-severity,
  // assessedBySeverity, compliancePct) for the collection, computed by the
  // engine/metrics module over all reviews fetched from the DB.
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/metrics',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const format = (req.query as Record<string, string>).format ?? 'json'
      const reviews = await listReviewsByCollection(collectionId)
      const m = computeMetrics(reviews)
      const data = { collectionId, ...m } satisfies CollectionMetrics
      if (format === 'csv') {
        // Flatten nested objects for CSV: results.* and findings.* become flat columns
        const flat: Record<string, unknown> = {
          collectionId:    data.collectionId,
          assessed:        data.assessed,
          total:           data.total,
          compliancePct:   data.compliancePct,
          pass:            data.results.pass,
          fail:            data.results.fail,
          notapplicable:   data.results.notapplicable,
          notchecked:      data.results.notchecked,
          informational:   data.results.informational,
          findings_high:   data.findings.high,
          findings_medium: data.findings.medium,
          findings_low:    data.findings.low,
        }
        const columns = [
          'collectionId', 'assessed', 'total', 'compliancePct',
          'pass', 'fail', 'notapplicable', 'notchecked', 'informational',
          'findings_high', 'findings_medium', 'findings_low'
        ]
        const csv = toCSV([flat], columns)
        return reply
          .header('Content-Type', 'text/csv; charset=utf-8')
          .header('Content-Disposition', `attachment; filename="metrics-collection-${collectionId}.csv"`)
          .send(csv)
      }
      return data
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/assets
  // operationId: getMetricsSummaryByCollectionAggAsset
  //
  // One row per asset that has at least one review in the collection.
  // Uses a single GROUP BY SQL query to avoid loading all review rows into Node.
  // Falls back to a simpler query if the result / result_id join fails.
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/metrics/assets',
    { preHandler: guard },
    async (_req) => {
      const collectionId = numId(_req.params)

      const sql = `
        SELECT
          a.assetId,
          a.name AS assetName,
          ${RESULT_COUNTS}
        FROM review rv
        INNER JOIN asset a
                ON a.assetId = rv.assetId
               AND a.collectionId = :collectionId
        LEFT JOIN result res ON res.resultId = rv.resultId
        GROUP BY a.assetId, a.name
        ORDER BY a.name`

      let rows: RowDataPacket[]
      try {
        ;[rows] = await pool.query<RowDataPacket[]>(sql, { collectionId })
      } catch {
        // Fallback: resultId column may not exist yet — join on the legacy result ENUM
        const fallback = `
          SELECT
            a.assetId,
            a.name AS assetName,
            SUM(rv.result = 'pass')          AS pass,
            SUM(rv.result = 'fail')          AS fail,
            SUM(rv.result = 'notapplicable') AS notapplicable,
            SUM(rv.result = 'notchecked')    AS notchecked,
            SUM(rv.result = 'informational') AS informational,
            COUNT(*)                         AS total
          FROM review rv
          INNER JOIN asset a
                  ON a.assetId = rv.assetId
                 AND a.collectionId = :collectionId
          GROUP BY a.assetId, a.name
          ORDER BY a.name`
        ;[rows] = await pool.query<RowDataPacket[]>(fallback, { collectionId })
      }

      return rows.map((row): AssetMetricsRow => {
        const results = bucketsFromRow(row)
        const { assessed, compliancePct } = deriveAssessed(results)
        return {
          assetId:   Number(row.assetId),
          assetName: String(row.assetName ?? ''),
          assessed,
          total:     Number(row.total ?? 0),
          results,
          compliancePct
        }
      })
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/stigs
  // operationId: getMetricsSummaryByCollectionAggStig
  //
  // One row per STIG (benchmarkId) evaluated in the collection.
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/metrics/stigs',
    { preHandler: guard },
    async (_req) => {
      const collectionId = numId(_req.params)

      const sql = `
        SELECT
          rv.benchmarkId,
          ${RESULT_COUNTS}
        FROM review rv
        INNER JOIN asset a
                ON a.assetId = rv.assetId
               AND a.collectionId = :collectionId
        LEFT JOIN result res ON res.resultId = rv.resultId
        GROUP BY rv.benchmarkId
        ORDER BY rv.benchmarkId`

      let rows: RowDataPacket[]
      try {
        ;[rows] = await pool.query<RowDataPacket[]>(sql, { collectionId })
      } catch {
        const fallback = `
          SELECT
            rv.benchmarkId,
            SUM(rv.result = 'pass')          AS pass,
            SUM(rv.result = 'fail')          AS fail,
            SUM(rv.result = 'notapplicable') AS notapplicable,
            SUM(rv.result = 'notchecked')    AS notchecked,
            SUM(rv.result = 'informational') AS informational,
            COUNT(*)                         AS total
          FROM review rv
          INNER JOIN asset a
                  ON a.assetId = rv.assetId
                 AND a.collectionId = :collectionId
          GROUP BY rv.benchmarkId
          ORDER BY rv.benchmarkId`
        ;[rows] = await pool.query<RowDataPacket[]>(fallback, { collectionId })
      }

      return rows.map((row): StigMetricsRow => {
        const results = bucketsFromRow(row)
        const { assessed, compliancePct } = deriveAssessed(results)
        return {
          benchmarkId: String(row.benchmarkId ?? ''),
          assessed,
          total:       Number(row.total ?? 0),
          results,
          compliancePct
        }
      })
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/detail
  // operationId: getMetricsDetailByCollection
  //
  // Most granular view: one row per (asset, benchmarkId) pair.
  // Equivalent to getMetricsDetailByCollection in the STIG Manager spec —
  // unaggregated Asset/STIG metrics.
  //
  // Optional query param: ?labelId=N  restricts results to assets that carry
  // the specified collection label (collection_label_asset_map).
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/metrics/detail',
    { preHandler: guard },
    async (_req) => {
      const collectionId = numId(_req.params)
      const query = _req.query as Record<string, string>
      const labelId = query.labelId != null ? Number(query.labelId) : undefined
      if (labelId !== undefined && (!Number.isInteger(labelId) || labelId <= 0)) {
        throw Object.assign(new Error('Invalid labelId'), { statusCode: 400 })
      }

      // Optional label sub-filter — inlined as an AND clause rather than a JOIN
      // so the rest of the query shape (GROUP BY, result buckets) stays unchanged.
      const labelFilter = labelId != null
        ? 'AND a.assetId IN (SELECT assetId FROM collection_label_asset_map WHERE clId = :labelId)'
        : ''

      const sql = `
        SELECT
          a.assetId,
          a.name AS assetName,
          rv.benchmarkId,
          ${RESULT_COUNTS}
        FROM review rv
        INNER JOIN asset a
                ON a.assetId = rv.assetId
               AND a.collectionId = :collectionId
        LEFT JOIN result res ON res.resultId = rv.resultId
        WHERE 1=1
        ${labelFilter}
        GROUP BY a.assetId, a.name, rv.benchmarkId
        ORDER BY a.name, rv.benchmarkId`

      const binds: Record<string, unknown> = { collectionId }
      if (labelId != null) binds.labelId = labelId

      let rows: RowDataPacket[]
      try {
        ;[rows] = await pool.query<RowDataPacket[]>(sql, binds as any)
      } catch {
        const fallback = `
          SELECT
            a.assetId,
            a.name AS assetName,
            rv.benchmarkId,
            SUM(rv.result = 'pass')          AS pass,
            SUM(rv.result = 'fail')          AS fail,
            SUM(rv.result = 'notapplicable') AS notapplicable,
            SUM(rv.result = 'notchecked')    AS notchecked,
            SUM(rv.result = 'informational') AS informational,
            COUNT(*)                         AS total
          FROM review rv
          INNER JOIN asset a
                  ON a.assetId = rv.assetId
                 AND a.collectionId = :collectionId
          WHERE 1=1
          ${labelFilter}
          GROUP BY a.assetId, a.name, rv.benchmarkId
          ORDER BY a.name, rv.benchmarkId`
        ;[rows] = await pool.query<RowDataPacket[]>(fallback, binds as any)
      }

      return rows.map((row): DetailMetricsRow => {
        const results = bucketsFromRow(row)
        const { assessed, compliancePct } = deriveAssessed(results)
        return {
          assetId:     Number(row.assetId),
          assetName:   String(row.assetName ?? ''),
          benchmarkId: String(row.benchmarkId ?? ''),
          assessed,
          total:       Number(row.total ?? 0),
          results,
          compliancePct
        }
      })
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/stigs-agg
  // operationId: getMetricsStigAggByCollection
  //
  // One row per benchmarkId present in reviews for the collection.
  // Includes STIG title (from the stig library table), asset count, rule count,
  // full result breakdown, CAT I/II/III findings, and compliance percentage.
  // Used by the workspace STIG tab top grid.
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/metrics/stigs-agg',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      return stigAggregation(collectionId)
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/assets-agg
  // operationId: getMetricsAssetAggByCollection
  //
  // One row per asset in the collection (LEFT JOIN — assets with no reviews
  // are included with zero counts).  Includes STIG count, rule count, full
  // result breakdown, CAT I/II/III findings, and compliance percentage.
  // Used by the workspace Asset tab top grid.
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/metrics/assets-agg',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      return assetAggregation(collectionId)
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/assets-agg/:assetId
  // operationId: getMetricsStigDetailByAsset
  //
  // Per-STIG breakdown for a single asset within the collection.
  // Used by the workspace Asset tab bottom grid when an asset row is selected.
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/metrics/assets-agg/:assetId',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const assetId      = numId(req.params, 'assetId')
      return assetStigDetail(collectionId, assetId)
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/stigs-agg/:benchmarkId
  // operationId: getMetricsAssetDetailByStig
  //
  // Per-asset breakdown for a single STIG within the collection.
  // Used by the workspace STIG tab bottom grid when a STIG row is selected.
  // :benchmarkId may contain slashes/dots; Fastify treats the whole segment as
  // a single string param automatically for non-wildcard routes.
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/metrics/stigs-agg/:benchmarkId',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const benchmarkId  = (req.params as Record<string, string>).benchmarkId
      return stigAssetDetail(collectionId, benchmarkId)
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/unreviewed/assets?benchmarkId=&severity=
  // operationId: getUnreviewedAssets
  //
  // Assets in the collection that have a STIG assigned but have zero reviews
  // for that (asset, STIG) pair.  Optional query filters: benchmarkId, severity.
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/unreviewed/assets',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const query = req.query as Record<string, string>
      return unreviewedAssets(collectionId, {
        benchmarkId: query.benchmarkId,
        severity:    query.severity
      })
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/unreviewed/rules?benchmarkId=&severity=
  // operationId: getUnreviewedRules
  //
  // Rules in the STIG library (for STIGs assigned to collection assets) that
  // have no review record on any asset in the collection.
  // Optional query filters: benchmarkId, severity.
  // --------------------------------------------------------------------------
  app.get(
    '/collections/:id/unreviewed/rules',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const query = req.query as Record<string, string>
      return unreviewedRules(collectionId, {
        benchmarkId: query.benchmarkId,
        severity:    query.severity
      })
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/stigs/:benchmarkId/assets
  // operationId: getMetricsStigAssetDrilldown
  //
  // For a specific STIG in a collection, return per-asset review counts.
  // Rows include every asset that has the STIG in stig_asset_map, even with
  // zero reviews (LEFT JOIN on review scoped to rules in the current revision).
  //
  // Optional query param: ?labelId=N  restricts to assets carrying that label.
  //
  // Columns:
  //   assetId, assetName, fqdn, ip,
  //   passCount, failCount, naCount, nrCount,
  //   submittedCount, acceptedCount, totalRules, compliancePct
  // --------------------------------------------------------------------------

  /** Row type for GET /collections/:id/metrics/stigs/:benchmarkId/assets. */
  interface StigAssetDrilldownRow {
    assetId:        number
    assetName:      string
    fqdn:           string | null
    ip:             string | null
    passCount:      number
    failCount:      number
    naCount:        number
    nrCount:        number
    submittedCount: number
    acceptedCount:  number
    totalRules:     number
    compliancePct:  number
  }

  app.get(
    '/collections/:id/metrics/stigs/:benchmarkId/assets',
    { preHandler: guard },
    async (req): Promise<StigAssetDrilldownRow[]> => {
      const collectionId = numId(req.params)
      const benchmarkId  = (req.params as Record<string, string>).benchmarkId
      const query        = req.query as Record<string, string>
      const labelId      = query.labelId != null ? Number(query.labelId) : undefined
      if (labelId !== undefined && (!Number.isInteger(labelId) || labelId <= 0)) {
        throw Object.assign(new Error('Invalid labelId'), { statusCode: 400 })
      }

      const labelJoin = labelId != null
        ? 'INNER JOIN collection_label_asset_map clam_lf ON clam_lf.assetId = a.assetId AND clam_lf.clId = :labelId'
        : ''

      // Join path for counting rules per (asset, STIG):
      //   current_rev cr (filtered to :benchmarkId)
      //     -> rule ru ON ru.revId = cr.revId   (all rules in that revision)
      //     -> review r LEFT JOIN ON r.assetId = a.assetId AND r.ruleId = ru.ruleId
      // This correctly scopes counts to rules that belong to the current revision
      // of the target STIG, matching the pattern used in unreviewedRules().
      const sql = `
        SELECT
          a.assetId,
          a.name                                                               AS assetName,
          a.fqdn,
          a.ip,
          COUNT(CASE WHEN r.result = 'pass'                           THEN 1 END) AS passCount,
          COUNT(CASE WHEN r.result = 'fail'                           THEN 1 END) AS failCount,
          COUNT(CASE WHEN r.result = 'notapplicable'                  THEN 1 END) AS naCount,
          COUNT(CASE WHEN r.result = 'notchecked' OR r.result IS NULL THEN 1 END) AS nrCount,
          COUNT(CASE WHEN r.status = 'submitted'                      THEN 1 END) AS submittedCount,
          COUNT(CASE WHEN r.status = 'accepted'                       THEN 1 END) AS acceptedCount,
          COUNT(ru.ruleId)                                                         AS totalRules
        FROM asset a
        JOIN stig_asset_map sam
          ON sam.assetId     = a.assetId
         AND sam.benchmarkId = :benchmarkId
        ${labelJoin}
        JOIN current_rev cr
          ON cr.benchmarkId  = :benchmarkId
        JOIN \`rule\` ru
          ON ru.revId        = cr.revId
        LEFT JOIN review r
          ON r.assetId       = a.assetId
         AND r.ruleId        = ru.ruleId
        WHERE a.collectionId = :collectionId
        GROUP BY a.assetId, a.name, a.fqdn, a.ip
        ORDER BY a.name`

      const binds: Record<string, unknown> = { collectionId, benchmarkId }
      if (labelId != null) binds.labelId = labelId

      const [rows] = await pool.query<RowDataPacket[]>(sql, binds as any)
      return rows.map((row): StigAssetDrilldownRow => {
        const passCount = Number(row.passCount ?? 0)
        const failCount = Number(row.failCount ?? 0)
        const denom = passCount + failCount
        return {
          assetId:        Number(row.assetId),
          assetName:      String(row.assetName      ?? ''),
          fqdn:           row.fqdn  != null ? String(row.fqdn)  : null,
          ip:             row.ip    != null ? String(row.ip)    : null,
          passCount,
          failCount,
          naCount:        Number(row.naCount        ?? 0),
          nrCount:        Number(row.nrCount        ?? 0),
          submittedCount: Number(row.submittedCount ?? 0),
          acceptedCount:  Number(row.acceptedCount  ?? 0),
          totalRules:     Number(row.totalRules     ?? 0),
          compliancePct:  denom > 0 ? Math.round((passCount / denom) * 1000) / 10 : 0
        }
      })
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/assets/:assetId/stigs
  // operationId: getMetricsAssetStigDrilldown
  //
  // For a specific asset in a collection, return per-STIG review counts.
  // Rows include every STIG assigned to the asset via stig_asset_map.
  //
  // Columns:
  //   benchmarkId, stigTitle, passCount, failCount, naCount, nrCount,
  //   submittedCount, acceptedCount, totalRules, compliancePct
  // --------------------------------------------------------------------------

  /** Row type for GET /collections/:id/metrics/assets/:assetId/stigs. */
  interface AssetStigDrilldownRow {
    benchmarkId:    string
    stigTitle:      string | null
    passCount:      number
    failCount:      number
    naCount:        number
    nrCount:        number
    submittedCount: number
    acceptedCount:  number
    totalRules:     number
    compliancePct:  number
  }

  app.get(
    '/collections/:id/metrics/assets/:assetId/stigs',
    { preHandler: guard },
    async (req): Promise<AssetStigDrilldownRow[]> => {
      const collectionId = numId(req.params)
      const assetId      = numId(req.params, 'assetId')

      // For each STIG assigned to the asset (via stig_asset_map) count reviews
      // scoped to the rules belonging to the current revision of that STIG.
      const sql = `
        SELECT
          sam.benchmarkId,
          ANY_VALUE(s.title)                                                      AS stigTitle,
          COUNT(CASE WHEN r.result = 'pass'                           THEN 1 END) AS passCount,
          COUNT(CASE WHEN r.result = 'fail'                           THEN 1 END) AS failCount,
          COUNT(CASE WHEN r.result = 'notapplicable'                  THEN 1 END) AS naCount,
          COUNT(CASE WHEN r.result = 'notchecked' OR r.result IS NULL THEN 1 END) AS nrCount,
          COUNT(CASE WHEN r.status = 'submitted'                      THEN 1 END) AS submittedCount,
          COUNT(CASE WHEN r.status = 'accepted'                       THEN 1 END) AS acceptedCount,
          COUNT(ru.ruleId)                                                         AS totalRules
        FROM stig_asset_map sam
        JOIN asset a
          ON a.assetId      = sam.assetId
         AND a.collectionId = :collectionId
        LEFT JOIN stig s
          ON s.benchmarkId  = sam.benchmarkId COLLATE utf8mb4_0900_as_cs
        LEFT JOIN current_rev cr
          ON cr.benchmarkId = sam.benchmarkId
        LEFT JOIN \`rule\` ru
          ON ru.revId       = cr.revId
        LEFT JOIN review r
          ON r.assetId   = sam.assetId
         AND r.ruleId    = ru.ruleId
        WHERE sam.assetId = :assetId
        GROUP BY sam.benchmarkId
        ORDER BY sam.benchmarkId`

      const [rows] = await pool.query<RowDataPacket[]>(sql, { collectionId, assetId })
      return rows.map((row): AssetStigDrilldownRow => {
        const passCount = Number(row.passCount ?? 0)
        const failCount = Number(row.failCount ?? 0)
        const denom = passCount + failCount
        return {
          benchmarkId:    String(row.benchmarkId    ?? ''),
          stigTitle:      row.stigTitle != null ? String(row.stigTitle) : null,
          passCount,
          failCount,
          naCount:        Number(row.naCount        ?? 0),
          nrCount:        Number(row.nrCount        ?? 0),
          submittedCount: Number(row.submittedCount ?? 0),
          acceptedCount:  Number(row.acceptedCount  ?? 0),
          totalRules:     Number(row.totalRules     ?? 0),
          compliancePct:  denom > 0 ? Math.round((passCount / denom) * 1000) / 10 : 0
        }
      })
    }
  )

  // --------------------------------------------------------------------------
  // GET /collections/:id/metrics/labels
  // operationId: getMetricsLabelsByCollection
  //
  // Per-label aggregate metrics for the collection.  Returns one row per label
  // defined on the collection (collection_label).  Assets are linked via
  // collection_label_asset_map.  Reviews are LEFT-JOINed so labels with no
  // reviews still appear (all counts will be 0).
  //
  // Columns:
  //   labelId (clId), labelName, color, assetCount,
  //   passCount, failCount, naCount, totalReviews, compliancePct
  // --------------------------------------------------------------------------

  /** Row type for GET /collections/:id/metrics/labels. */
  interface LabelMetricsRow {
    labelId:      number
    labelName:    string
    color:        string | null
    assetCount:   number
    passCount:    number
    failCount:    number
    naCount:      number
    totalReviews: number
    compliancePct: number
  }

  app.get(
    '/collections/:id/metrics/labels',
    { preHandler: guard },
    async (req): Promise<LabelMetricsRow[]> => {
      const collectionId = numId(req.params)

      const sql = `
        SELECT
          cl.clId                                                              AS labelId,
          cl.name                                                              AS labelName,
          cl.color,
          COUNT(DISTINCT a.assetId)                                            AS assetCount,
          COUNT(CASE WHEN r.result = 'pass'          THEN 1 END)              AS passCount,
          COUNT(CASE WHEN r.result = 'fail'          THEN 1 END)              AS failCount,
          COUNT(CASE WHEN r.result = 'notapplicable' THEN 1 END)              AS naCount,
          COUNT(r.reviewId)                                                    AS totalReviews
        FROM collection_label cl
        JOIN collection_label_asset_map clam
          ON clam.clId       = cl.clId
        JOIN asset a
          ON a.assetId       = clam.assetId
         AND a.collectionId  = :collectionId
        LEFT JOIN review r
          ON r.assetId       = a.assetId
        WHERE cl.collectionId = :collectionId
        GROUP BY cl.clId, cl.name, cl.color
        ORDER BY cl.name`

      const [rows] = await pool.query<RowDataPacket[]>(sql, { collectionId })
      return rows.map((row): LabelMetricsRow => {
        const passCount = Number(row.passCount ?? 0)
        const failCount = Number(row.failCount ?? 0)
        const denom = passCount + failCount
        return {
          labelId:      Number(row.labelId),
          labelName:    String(row.labelName    ?? ''),
          color:        row.color != null ? String(row.color) : null,
          assetCount:   Number(row.assetCount   ?? 0),
          passCount,
          failCount,
          naCount:      Number(row.naCount      ?? 0),
          totalReviews: Number(row.totalReviews ?? 0),
          compliancePct: denom > 0 ? Math.round((passCount / denom) * 1000) / 10 : 0
        }
      })
    }
  )

  // --------------------------------------------------------------------------
  // POST /collections/:id/stigs-asset-map/refresh
  // operationId: refreshStigAssetMapByCollection
  //
  // Backfill / repair all stig_asset_map rollup counters for every
  // (assetId, benchmarkId) pair that has reviews in the given collection.
  // Useful after bulk imports or when counters are suspected to be stale.
  //
  // Returns: { refreshed: number } — count of (assetId, benchmarkId) pairs updated.
  // --------------------------------------------------------------------------
  app.post(
    '/collections/:id/stigs-asset-map/refresh',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)

      // Find all distinct (assetId, benchmarkId) pairs in this collection
      const [pairs] = await pool.query<RowDataPacket[]>(
        `SELECT DISTINCT r.assetId, r.benchmarkId
           FROM review r
           JOIN asset a ON a.assetId = r.assetId AND a.collectionId = ?`,
        [collectionId]
      )

      if (pairs.length === 0) return { refreshed: 0 }

      const conn = await pool.getConnection()
      let refreshed = 0
      try {
        for (const pair of pairs) {
          try {
            await refreshStigAssetMap(conn, pair.assetId as number, pair.benchmarkId as string)
            refreshed++
          } catch {
            // Log and continue — one bad pair should not abort the whole backfill
          }
        }
      } finally {
        conn.release()
      }

      return { refreshed }
    }
  )
}
