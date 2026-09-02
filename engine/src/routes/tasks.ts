// Review-aging task-config endpoints + Jobs API + background scheduler.
//
// Routes:
//   GET    /collections/:id/task-config/review-aging
//   PUT    /collections/:id/task-config/review-aging
//   DELETE /collections/:id/task-config/review-aging
//   POST   /collections/:id/tasks/review-aging/run
//
//   GET    /jobs
//   GET    /jobs/tasks
//   GET    /jobs/:jobId
//   POST   /jobs/:jobId/run
//
// Exports:
//   startReviewAgingScheduler(log)  — call from server.ts startup

import type { FastifyInstance, FastifyBaseLogger } from 'fastify'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import {
  getCollection,
  deleteReviewAgingConfig,
  type ReviewAgingConfig
} from '../repositories/collections.js'
import { pool } from '../db/pool.js'
import type { RowDataPacket, ResultSetHeader } from 'mysql2'

const SCOPE_COLLECTION = 'stig-manager:collection'

// ---------------------------------------------------------------------------
// Shape of the review-aging config stored in collection.metadata JSON
// ---------------------------------------------------------------------------

interface ReviewAgingMetadata {
  enabled:        boolean
  minDays:        number
  targetStatus:   'notchecked' | 'informational'
  daysUntilStale: number
}

const REVIEW_AGING_DEFAULTS: ReviewAgingMetadata = {
  enabled:        false,
  minDays:        90,
  targetStatus:   'notchecked',
  daysUntilStale: 90
}

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

const ReviewAgingBody = z.object({
  enabled:        z.boolean(),
  minDays:        z.number().int().min(1).max(36500),
  targetStatus:   z.enum(['notchecked', 'informational']),
  daysUntilStale: z.number().int().min(1).max(36500)
})

// ---------------------------------------------------------------------------
// Static job catalog (system jobs always present, not stored in DB)
// ---------------------------------------------------------------------------

const SYSTEM_JOBS = [
  {
    jobId:       'job-1',
    name:        'Cleanup Database',
    description: 'Wipe soft-deleted objects and analyze tables',
    tasks:       ['WipeDeletedObjects', 'AnalyzeReviewTables'],
    status:      'idle',
    enabled:     true,
    lastRun:     null,
    nextRun:     null
  },
  {
    jobId:       'job-2',
    name:        'Delete Unmapped Reviews',
    description: 'Remove reviews with no matching rule in library',
    tasks:       ['DeleteUnmappedReviews', 'AnalyzeReviewTables'],
    status:      'idle',
    enabled:     true,
    lastRun:     null,
    nextRun:     null
  },
  {
    jobId:       'job-3',
    name:        'Delete Unmapped Asset Reviews',
    description: 'Remove reviews for STIGs unassigned from assets',
    tasks:       ['DeleteUnmappedAssetReviews', 'AnalyzeReviewTables'],
    status:      'idle',
    enabled:     true,
    lastRun:     null,
    nextRun:     null
  },
  {
    jobId:       'job-4',
    name:        'Update Aged Reviews',
    description: 'Apply per-collection review aging rules',
    tasks:       ['ReviewAging'],
    status:      'idle',
    enabled:     true,
    lastRun:     null,
    nextRun:     null
  }
] as const

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function numId(params: unknown, key = 'id'): number {
  const raw = (params as Record<string, string>)[key]
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0) throw Object.assign(new Error(`Invalid id: ${raw}`), { statusCode: 400 })
  return n
}

/**
 * Read the reviewAging sub-object from collection.metadata.
 * Returns REVIEW_AGING_DEFAULTS when no config is stored yet.
 */
async function getReviewAgingMetadata(collectionId: number): Promise<ReviewAgingMetadata | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reviewAging')) AS aging
       FROM collection
      WHERE collectionId = ?
      LIMIT 1`,
    [collectionId]
  )
  if (rows.length === 0) return null  // collection not found
  const raw = rows[0].aging as string | null
  if (!raw || raw === 'null') return { ...REVIEW_AGING_DEFAULTS }
  try {
    return JSON.parse(raw) as ReviewAgingMetadata
  } catch {
    return { ...REVIEW_AGING_DEFAULTS }
  }
}

/**
 * Upsert the reviewAging sub-object into collection.metadata via JSON_SET.
 */
async function putReviewAgingMetadata(
  collectionId: number,
  cfg: ReviewAgingMetadata
): Promise<void> {
  await pool.query(
    `UPDATE collection
        SET metadata = JSON_SET(COALESCE(metadata, '{}'), '$.reviewAging', CAST(? AS JSON))
      WHERE collectionId = ?`,
    [JSON.stringify(cfg), collectionId]
  )
}

// ---------------------------------------------------------------------------
// Register routes
// ---------------------------------------------------------------------------

export async function registerTaskRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // ── GET /collections/:id/task-config/review-aging ─────────────────────────
  // Returns stored config, or defaults if none configured yet.
  app.get(
    '/collections/:id/task-config/review-aging',
    { preHandler: guard },
    async (req, reply) => {
      const id = numId(req.params)
      const cfg = await getReviewAgingMetadata(id)
      if (cfg === null) {
        return reply.code(404).send({ error: 'Collection not found' })
      }
      return cfg
    }
  )

  // ── PUT /collections/:id/task-config/review-aging ─────────────────────────
  // Validates body, upserts into metadata JSON, returns updated config.
  app.put(
    '/collections/:id/task-config/review-aging',
    { preHandler: guard },
    async (req, reply) => {
      const id = numId(req.params)
      const collection = await getCollection(id)
      if (!collection) return reply.code(404).send({ error: 'Collection not found' })

      const body = ReviewAgingBody.parse(req.body)
      const cfg: ReviewAgingMetadata = {
        enabled:        body.enabled,
        minDays:        body.minDays,
        targetStatus:   body.targetStatus,
        daysUntilStale: body.daysUntilStale
      }
      await putReviewAgingMetadata(id, cfg)
      return reply.code(200).send(cfg)
    }
  )

  // ── DELETE /collections/:id/task-config/review-aging ──────────────────────
  // Removes the reviewAging key from metadata JSON.
  app.delete(
    '/collections/:id/task-config/review-aging',
    { preHandler: guard },
    async (req, reply) => {
      const id = numId(req.params)
      // Try both the metadata JSON approach and the legacy review_aging_rule table.
      await pool.query(
        `UPDATE collection
            SET metadata = JSON_REMOVE(metadata, '$.reviewAging')
          WHERE collectionId = ? AND JSON_EXTRACT(metadata, '$.reviewAging') IS NOT NULL`,
        [id]
      )
      // Also clean up legacy table rows if they exist (non-fatal if table absent).
      try {
        await deleteReviewAgingConfig(id)
      } catch {
        // legacy table may not exist — ignore
      }
      return reply.code(204).send()
    }
  )

  // ── POST /collections/:id/tasks/review-aging/run ──────────────────────────
  // Immediately execute the aging task for one collection.
  // Reads config from metadata; uses REVIEW_AGING_DEFAULTS when not configured.
  app.post(
    '/collections/:id/tasks/review-aging/run',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const collection = await getCollection(collectionId)
      if (!collection) return reply.code(404).send({ error: 'Collection not found' })

      const cfg = await getReviewAgingMetadata(collectionId) ?? { ...REVIEW_AGING_DEFAULTS }
      const ranAt = new Date().toISOString()

      const [res] = await pool.query<ResultSetHeader>(
        `UPDATE review r
           JOIN asset a ON a.assetId = r.assetId
            SET r.result   = 'notchecked',
                r.resultId = NULL,
                r.status   = 'saved',
                r.detail   = NULL,
                r.comment  = NULL,
                r.touchTs  = NOW()
          WHERE a.collectionId = ?
            AND r.status = 'saved'
            AND r.touchTs < DATE_SUB(NOW(), INTERVAL ? DAY)`,
        [collectionId, cfg.minDays]
      )

      return reply.code(200).send({
        updated:      res.affectedRows,
        collectionId,
        ranAt
      })
    }
  )

  // ── GET /jobs ──────────────────────────────────────────────────────────────
  // Returns the 4 system jobs plus one job per collection with a review aging config.
  app.get(
    '/jobs',
    { preHandler: [app.authenticate] },
    async () => {
      let agingJobs: object[] = []
      try {
        // Prefer metadata JSON; fall back to review_aging_rule if that table exists.
        const [rows] = await pool.query<RowDataPacket[]>(
          `SELECT c.collectionId,
                  c.name AS collectionName,
                  JSON_EXTRACT(c.metadata, '$.reviewAging.enabled')        AS enabled,
                  JSON_EXTRACT(c.metadata, '$.reviewAging.minDays')        AS minDays,
                  JSON_EXTRACT(c.metadata, '$.reviewAging.targetStatus')   AS targetStatus,
                  JSON_EXTRACT(c.metadata, '$.reviewAging.daysUntilStale') AS daysUntilStale
             FROM collection c
            WHERE JSON_EXTRACT(c.metadata, '$.reviewAging') IS NOT NULL
            ORDER BY c.name`
        )
        agingJobs = rows.map((r) => ({
          jobId:        `ReviewAging-${r.collectionId as number}`,
          name:         `ReviewAging-${r.collectionName as string}`,
          description:  `Review aging for collection "${r.collectionName as string}"`,
          tasks:        ['ReviewAging'],
          collectionId: Number(r.collectionId),
          enabled:      Boolean(r.enabled),
          status:       'idle',
          lastRun:      null,
          nextRun:      null,
          config: {
            minDays:        Number(r.minDays) || REVIEW_AGING_DEFAULTS.minDays,
            targetStatus:   (r.targetStatus as string | null)?.replace(/"/g, '') ?? REVIEW_AGING_DEFAULTS.targetStatus,
            daysUntilStale: Number(r.daysUntilStale) || REVIEW_AGING_DEFAULTS.daysUntilStale
          }
        }))
      } catch {
        // metadata column may not yet have reviewAging data — return no aging jobs
      }
      return [...SYSTEM_JOBS, ...agingJobs]
    }
  )

  // ── GET /jobs/tasks ────────────────────────────────────────────────────────
  // Static catalog of known background task types.
  // NOTE: This route MUST be registered before /jobs/:jobId to avoid Fastify
  // treating "tasks" as a :jobId param value.
  app.get(
    '/jobs/tasks',
    { preHandler: [app.authenticate] },
    async () => [
      {
        taskId:      'review-aging',
        name:        'Review Aging',
        description: 'Reset stale reviews to Not Reviewed'
      },
      {
        taskId:      'wipe-deleted-objects',
        name:        'WipeDeletedObjects',
        description: 'Delete soft-deleted collections and assets plus all their reviews and history',
        command:     'wipe_deleted_objects()'
      },
      {
        taskId:      'delete-unmapped-reviews',
        name:        'DeleteUnmappedReviews',
        description: 'Delete reviews whose ruleId no longer exists in the rule table',
        command:     'delete_unmapped_reviews()'
      },
      {
        taskId:      'delete-unmapped-asset-reviews',
        name:        'DeleteUnmappedAssetReviews',
        description: 'Delete reviews where the asset no longer has the STIG assigned',
        command:     'delete_unmapped_asset_reviews()'
      },
      {
        taskId:      'analyze-review-tables',
        name:        'AnalyzeReviewTables',
        description: 'Run ANALYZE TABLE on main review tables to update query optimizer stats',
        command:     'analyze_review_tables()'
      }
    ]
  )

  // ── GET /jobs/:jobId ───────────────────────────────────────────────────────
  app.get(
    '/jobs/:jobId',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { jobId } = req.params as { jobId: string }

      // Check system jobs first
      const sys = SYSTEM_JOBS.find((j) => j.jobId === jobId)
      if (sys) return sys

      // Check ReviewAging-{collectionId}
      const match = jobId.match(/^ReviewAging-(\d+)$/)
      if (match) {
        const collectionId = Number(match[1])
        try {
          const [rows] = await pool.query<RowDataPacket[]>(
            `SELECT c.collectionId,
                    c.name AS collectionName,
                    JSON_EXTRACT(c.metadata, '$.reviewAging.enabled')        AS enabled,
                    JSON_EXTRACT(c.metadata, '$.reviewAging.minDays')        AS minDays,
                    JSON_EXTRACT(c.metadata, '$.reviewAging.targetStatus')   AS targetStatus,
                    JSON_EXTRACT(c.metadata, '$.reviewAging.daysUntilStale') AS daysUntilStale
               FROM collection c
              WHERE c.collectionId = ?
              LIMIT 1`,
            [collectionId]
          )
          if (rows.length === 0) {
            return reply.code(404).send({ error: `Job not found: ${jobId}` })
          }
          const r = rows[0]
          if (r.enabled === null) {
            // No aging config for this collection
            return reply.code(404).send({ error: `Job not found: ${jobId}` })
          }
          return {
            jobId,
            name:         `ReviewAging-${r.collectionName as string}`,
            description:  `Review aging for collection "${r.collectionName as string}"`,
            tasks:        ['ReviewAging'],
            collectionId: Number(r.collectionId),
            enabled:      Boolean(r.enabled),
            status:       'idle',
            lastRun:      null,
            nextRun:      null,
            config: {
              minDays:        Number(r.minDays) || REVIEW_AGING_DEFAULTS.minDays,
              targetStatus:   (r.targetStatus as string | null)?.replace(/"/g, '') ?? REVIEW_AGING_DEFAULTS.targetStatus,
              daysUntilStale: Number(r.daysUntilStale) || REVIEW_AGING_DEFAULTS.daysUntilStale
            }
          }
        } catch {
          return reply.code(404).send({ error: `Job not found: ${jobId}` })
        }
      }

      return reply.code(404).send({ error: `Job not found: ${jobId}` })
    }
  )

  // ── POST /jobs/:jobId/run ──────────────────────────────────────────────────
  app.post(
    '/jobs/:jobId/run',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      // Admin-only: service jobs can delete data across all collections.
      if (!req.user.roles.has('admin') && !req.elevated) {
        return reply.code(403).send({ error: 'Admin role required to run service jobs' })
      }

      const { jobId } = req.params as { jobId: string }

      // ── job-1: Cleanup Database ──────────────────────────────────────────
      if (jobId === 'job-1') {
        const conn = await pool.getConnection()
        try {
          const wipeResult = await wipeDeletedObjects(conn)
          await analyzeReviewTables(conn)
          return reply.code(202).send({
            message: 'Cleanup Database executed',
            ...wipeResult
          })
        } catch (err) {
          return reply.code(500).send({ error: (err as Error).message })
        } finally {
          conn.release()
        }
      }

      // ── job-2: Delete Unmapped Reviews ───────────────────────────────────
      if (jobId === 'job-2') {
        const conn = await pool.getConnection()
        try {
          const result = await deleteUnmappedReviews(conn)
          await analyzeReviewTables(conn)
          return reply.code(202).send({
            message: 'Delete Unmapped Reviews executed',
            ...result
          })
        } catch (err) {
          return reply.code(500).send({ error: (err as Error).message })
        } finally {
          conn.release()
        }
      }

      // ── job-3: Delete Unmapped Asset Reviews ─────────────────────────────
      if (jobId === 'job-3') {
        const conn = await pool.getConnection()
        try {
          const result = await deleteUnmappedAssetReviews(conn)
          await analyzeReviewTables(conn)
          return reply.code(202).send({
            message: 'Delete Unmapped Asset Reviews executed',
            ...result
          })
        } catch (err) {
          return reply.code(500).send({ error: (err as Error).message })
        } finally {
          conn.release()
        }
      }

      // ── job-4: Update Aged Reviews (all collections) ─────────────────────
      if (jobId === 'job-4') {
        let totalAffected = 0
        try {
          const [rows] = await pool.query<RowDataPacket[]>(
            `SELECT c.collectionId,
                    CAST(JSON_EXTRACT(c.metadata, '$.reviewAging.minDays') AS UNSIGNED) AS minDays
               FROM collection c
              WHERE JSON_EXTRACT(c.metadata, '$.reviewAging.enabled') = true`
          )
          for (const r of rows) {
            try {
              const minDays = Number(r.minDays) || REVIEW_AGING_DEFAULTS.minDays
              const [res] = await pool.query<ResultSetHeader>(
                `UPDATE review rv
                   JOIN asset a ON a.assetId = rv.assetId
                    SET rv.result   = 'notchecked',
                        rv.resultId = NULL,
                        rv.status   = 'saved',
                        rv.detail   = NULL,
                        rv.comment  = NULL,
                        rv.touchTs  = NOW()
                  WHERE a.collectionId = ?
                    AND rv.status = 'saved'
                    AND rv.touchTs < DATE_SUB(NOW(), INTERVAL ? DAY)`,
                [Number(r.collectionId), minDays]
              )
              totalAffected += res.affectedRows
            } catch {
              // skip individual collection errors
            }
          }
        } catch {
          // metadata column or reviewAging key may not exist yet
        }
        return reply.code(202).send({
          message: 'ReviewAging executed for all collections',
          affected: totalAffected
        })
      }

      // ── ReviewAging-{collectionId}: per-collection aging ─────────────────
      const match = jobId.match(/^ReviewAging-(\d+)$/)
      if (match) {
        const collectionId = Number(match[1])
        const cfg = await getReviewAgingMetadata(collectionId)
        if (cfg === null) {
          return reply.code(404).send({ error: 'Collection not found' })
        }
        if (!cfg.enabled) {
          return reply.code(200).send({ message: 'Job is disabled — no action taken', affected: 0 })
        }
        const [res] = await pool.query<ResultSetHeader>(
          `UPDATE review rv
             JOIN asset a ON a.assetId = rv.assetId
              SET rv.result   = 'notchecked',
                  rv.resultId = NULL,
                  rv.status   = 'saved',
                  rv.detail   = NULL,
                  rv.comment  = NULL,
                  rv.touchTs  = NOW()
            WHERE a.collectionId = ?
              AND rv.status = 'saved'
              AND rv.touchTs < DATE_SUB(NOW(), INTERVAL ? DAY)`,
          [collectionId, cfg.minDays]
        )
        return reply.code(202).send({
          message: `ReviewAging executed for collection ${collectionId}`,
          affected: res.affectedRows
        })
      }

      return reply.code(400).send({ error: `Unknown jobId: ${jobId}` })
    }
  )
}

// ---------------------------------------------------------------------------
// startReviewAgingScheduler — background 24-hour aging loop
// ---------------------------------------------------------------------------

/**
 * Start a background scheduler that runs review aging every 24 hours.
 * Call this from server.ts after the app is ready.
 *
 * For each collection that has reviewAging.enabled = true in its metadata,
 * the aging UPDATE is executed using the collection's configured minDays.
 */
export function startReviewAgingScheduler(log: FastifyBaseLogger): void {
  const INTERVAL_MS = 24 * 60 * 60 * 1000  // 24 hours

  async function runScheduledAging(): Promise<void> {
    log.info('ReviewAgingScheduler: starting scheduled run')
    let processed = 0
    let totalUpdated = 0

    try {
      const [rows] = await pool.query<RowDataPacket[]>(
        `SELECT c.collectionId,
                c.name AS collectionName,
                CAST(JSON_EXTRACT(c.metadata, '$.reviewAging.minDays') AS UNSIGNED) AS minDays
           FROM collection c
          WHERE JSON_EXTRACT(c.metadata, '$.reviewAging.enabled') = true`
      )

      for (const r of rows) {
        const collectionId = Number(r.collectionId)
        const minDays = Number(r.minDays) || REVIEW_AGING_DEFAULTS.minDays
        try {
          const [res] = await pool.query<ResultSetHeader>(
            `UPDATE review rv
               JOIN asset a ON a.assetId = rv.assetId
                SET rv.result   = 'notchecked',
                    rv.resultId = NULL,
                    rv.status   = 'saved',
                    rv.detail   = NULL,
                    rv.comment  = NULL,
                    rv.touchTs  = NOW()
              WHERE a.collectionId = ?
                AND rv.status = 'saved'
                AND rv.touchTs < DATE_SUB(NOW(), INTERVAL ? DAY)`,
            [collectionId, minDays]
          )
          log.info(
            { collectionId, collectionName: r.collectionName, updated: res.affectedRows },
            'ReviewAgingScheduler: processed collection'
          )
          totalUpdated += res.affectedRows
          processed++
        } catch (err) {
          log.warn(
            { collectionId, err },
            'ReviewAgingScheduler: error processing collection, skipping'
          )
        }
      }

      log.info(
        { collectionsProcessed: processed, totalUpdated },
        'ReviewAgingScheduler: run complete'
      )
    } catch (err) {
      log.error({ err }, 'ReviewAgingScheduler: fatal error during scheduled run')
    }
  }

  // Run immediately on startup, then every 24 hours.
  void runScheduledAging()
  setInterval(() => { void runScheduledAging() }, INTERVAL_MS)

  log.info({ intervalHours: 24 }, 'ReviewAgingScheduler: started')
}

// ---------------------------------------------------------------------------
// Task: WipeDeletedObjects
// ---------------------------------------------------------------------------

interface WipeResult {
  deletedCollections: number
  deletedAssets:      number
  deletedReviews:     number
}

export async function wipeDeletedObjects(
  conn: Awaited<ReturnType<typeof pool.getConnection>>
): Promise<WipeResult> {
  const disabledReviewSubquery = `
    SELECT rv.reviewId
      FROM review rv
      JOIN asset a ON a.assetId = rv.assetId
     WHERE a.state = 'disabled'
        OR EXISTS (
             SELECT 1 FROM collection c
              WHERE c.collectionId = a.collectionId
                AND c.state = 'disabled'
           )
  `

  await conn.query(
    `DELETE FROM review_history WHERE reviewId IN (${disabledReviewSubquery})`
  )

  await conn.query(
    `DELETE FROM review_attachment WHERE reviewId IN (${disabledReviewSubquery})`
  )

  const [rvRes] = await conn.query<ResultSetHeader>(
    `DELETE rv FROM review rv
       JOIN asset a ON a.assetId = rv.assetId
      WHERE a.state = 'disabled'
         OR EXISTS (
              SELECT 1 FROM collection c
               WHERE c.collectionId = a.collectionId
                 AND c.state = 'disabled'
            )`
  )

  const [assetRes] = await conn.query<ResultSetHeader>(
    `DELETE FROM asset
      WHERE state = 'disabled'
         OR collectionId IN (SELECT collectionId FROM collection WHERE state = 'disabled')`
  )

  const [colRes] = await conn.query<ResultSetHeader>(
    `DELETE FROM collection WHERE state = 'disabled'`
  )

  return {
    deletedCollections: colRes.affectedRows,
    deletedAssets:      assetRes.affectedRows,
    deletedReviews:     rvRes.affectedRows
  }
}

// ---------------------------------------------------------------------------
// Task: DeleteUnmappedReviews
// ---------------------------------------------------------------------------

interface DeletedResult {
  deleted: number
}

export async function deleteUnmappedReviews(
  conn: Awaited<ReturnType<typeof pool.getConnection>>
): Promise<DeletedResult> {
  const [orphaned] = await conn.query<RowDataPacket[]>(
    `SELECT rv.reviewId
       FROM review rv
       LEFT JOIN rule r ON r.ruleId = rv.ruleId COLLATE utf8mb4_0900_as_cs
      WHERE r.ruleId IS NULL`
  )

  if (orphaned.length === 0) return { deleted: 0 }

  const ids = orphaned.map((r) => r.reviewId as number)

  await conn.query(`DELETE FROM review_history WHERE reviewId IN (?)`, [ids])
  await conn.query(`DELETE FROM review_attachment WHERE reviewId IN (?)`, [ids])

  const [res] = await conn.query<ResultSetHeader>(
    `DELETE FROM review WHERE reviewId IN (?)`,
    [ids]
  )

  return { deleted: res.affectedRows }
}

// ---------------------------------------------------------------------------
// Task: DeleteUnmappedAssetReviews
// ---------------------------------------------------------------------------

export async function deleteUnmappedAssetReviews(
  conn: Awaited<ReturnType<typeof pool.getConnection>>
): Promise<DeletedResult> {
  const [orphaned] = await conn.query<RowDataPacket[]>(
    `SELECT rv.reviewId
       FROM review rv
       LEFT JOIN stig_asset_map sam
              ON sam.assetId = rv.assetId
             AND sam.benchmarkId = rv.benchmarkId
      WHERE sam.saId IS NULL`
  )

  if (orphaned.length === 0) return { deleted: 0 }

  const ids = orphaned.map((r) => r.reviewId as number)

  await conn.query(`DELETE FROM review_history WHERE reviewId IN (?)`, [ids])
  await conn.query(`DELETE FROM review_attachment WHERE reviewId IN (?)`, [ids])

  const [res] = await conn.query<ResultSetHeader>(
    `DELETE FROM review WHERE reviewId IN (?)`,
    [ids]
  )

  return { deleted: res.affectedRows }
}

// ---------------------------------------------------------------------------
// Task: AnalyzeReviewTables
// ---------------------------------------------------------------------------

export async function analyzeReviewTables(
  conn: Awaited<ReturnType<typeof pool.getConnection>>
): Promise<void> {
  await conn.query(
    `ANALYZE TABLE review, review_history, stig_asset_map, asset, collection`
  )
}

// ---------------------------------------------------------------------------
// runReviewAging — legacy core aging logic (kept for backward compatibility)
// ---------------------------------------------------------------------------

/**
 * Legacy aging function used by older job-runner paths that reference
 * the review_aging_rule table config shape.
 * New code should use the metadata-based approach directly.
 */
export async function runReviewAging(
  collectionId: number,
  cfg: ReviewAgingConfig
): Promise<number> {
  const field = cfg.triggerField
  const days  = cfg.triggerInterval

  if (cfg.triggerAction === 'delete') {
    const [res] = await pool.query<ResultSetHeader>(
      `DELETE rv FROM review rv
         JOIN asset a ON a.assetId = rv.assetId AND a.collectionId = ?
        WHERE rv.${field} IS NOT NULL
          AND rv.${field} < DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [collectionId, days]
    )
    return res.affectedRows
  }

  if (!cfg.updateField || cfg.updateValue == null) {
    throw new Error('updateField and updateValue are required when triggerAction=update')
  }

  const allowedFields = new Set(['result', 'status', 'detail', 'comment'])
  if (!allowedFields.has(cfg.updateField)) {
    throw new Error(`updateField '${cfg.updateField}' is not an allowed aging target`)
  }

  const [res] = await pool.query<ResultSetHeader>(
    `UPDATE review rv
       JOIN asset a ON a.assetId = rv.assetId AND a.collectionId = ?
        SET rv.${cfg.updateField} = ?
      WHERE rv.${field} IS NOT NULL
        AND rv.${field} < DATE_SUB(NOW(), INTERVAL ? DAY)`,
    [collectionId, cfg.updateValue, days]
  )
  return res.affectedRows
}
