// Enhanced archive import endpoints with processing options.
//
// POST /collections/:id/import/ckl
// POST /collections/:id/import/cklb
// POST /collections/:id/import/xccdf
//
// All three accept the same body:
//   { content: string, options?: ImportOptions }
//
// Post-ingest option processing:
//   unreviewed='never'   — delete notchecked reviews after ingest
//   autoStatus=true      — set status='submitted' for pass/fail/notapplicable reviews
//   emptyDetail='ignore' — skip overwriting existing detail when imported detail is ''
//   emptyComment='ignore'— skip overwriting existing comment when imported comment is ''

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import { ingestChecklist } from '../engine/ingest.js'
import type { ChecklistSource } from '../engine/types.js'
import { pool } from '../db/pool.js'
import type { ResultSetHeader, RowDataPacket } from 'mysql2'

const SCOPE_COLLECTION = 'stig-manager:collection'
const SCOPE_STIG = 'stig-manager:stig'

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

const ImportOptions = z.object({
  autoStatus:    z.boolean().optional(),
  unreviewed:    z.enum(['always', 'never', 'preserve']).optional(),
  emptyDetail:   z.enum(['ignore', 'replace']).optional(),
  emptyComment:  z.enum(['ignore', 'replace']).optional()
})

export type ImportOptions = z.infer<typeof ImportOptions>

const ImportBody = z.object({
  content: z.string().min(1),
  options: ImportOptions.optional()
})

// ---------------------------------------------------------------------------
// Post-ingest option processing
// ---------------------------------------------------------------------------

/**
 * unreviewed='never': delete all reviews for the asset+benchmarkId whose
 * result is 'notchecked'.
 */
async function deleteNotcheckedReviews(assetId: number, benchmarkId: string): Promise<number> {
  const [res] = await pool.query<ResultSetHeader>(
    `DELETE r FROM review r
     JOIN result res ON res.resultId = r.resultId
     WHERE r.assetId     = ?
       AND r.benchmarkId = ?
       AND res.api       = 'notchecked'`,
    [assetId, benchmarkId]
  )
  return res.affectedRows
}

/**
 * autoStatus=true: set status='submitted' for every pass/fail/notapplicable
 * review on this asset+benchmarkId that currently has no meaningful status
 * (status is NULL or 'saved').
 *
 * Submitted/accepted/rejected reviews are intentionally left untouched.
 */
async function autoSubmitReviews(assetId: number, benchmarkId: string): Promise<number> {
  // Look up the statusId for 'submitted'
  const [statusRows] = await pool.query<RowDataPacket[]>(
    `SELECT statusId FROM status WHERE api = 'submitted' LIMIT 1`
  )
  if (!statusRows.length) return 0
  const submittedStatusId = (statusRows[0] as { statusId: number }).statusId

  const [res] = await pool.query<ResultSetHeader>(
    `UPDATE review r
     JOIN result res ON res.resultId = r.resultId
     SET r.statusId = ?
     WHERE r.assetId     = ?
       AND r.benchmarkId = ?
       AND res.api       IN ('pass', 'fail', 'notapplicable')
       AND (r.statusId IS NULL OR r.statusId IN (
             SELECT statusId FROM status WHERE api IN ('saved')
           ))`,
    [submittedStatusId, assetId, benchmarkId]
  )
  return res.affectedRows
}

/**
 * emptyDetail='ignore': for every review we just wrote that has an empty
 * detail string, restore the prior detail from review_history (the most
 * recent history row).  Only acts when there IS a prior value to restore.
 *
 * emptyComment='ignore': same logic for the comment field.
 */
async function restoreBlankFields(
  assetId: number,
  benchmarkId: string,
  restoreDetail: boolean,
  restoreComment: boolean
): Promise<void> {
  if (!restoreDetail && !restoreComment) return

  if (restoreDetail) {
    await pool.query(
      `UPDATE review r
       JOIN (
         SELECT rh.reviewId,
                rh.detail
         FROM   review_history rh
         INNER JOIN (
           SELECT reviewId, MAX(historyId) AS maxId
           FROM   review_history
           GROUP BY reviewId
         ) latest ON latest.reviewId = rh.reviewId AND latest.maxId = rh.historyId
         WHERE  rh.detail IS NOT NULL AND rh.detail <> ''
       ) prior ON prior.reviewId = r.reviewId
       WHERE r.assetId     = ?
         AND r.benchmarkId = ?
         AND (r.detail IS NULL OR r.detail = '')`,
      [assetId, benchmarkId]
    )
  }

  if (restoreComment) {
    await pool.query(
      `UPDATE review r
       JOIN (
         SELECT rh.reviewId,
                rh.comment
         FROM   review_history rh
         INNER JOIN (
           SELECT reviewId, MAX(historyId) AS maxId
           FROM   review_history
           GROUP BY reviewId
         ) latest ON latest.reviewId = rh.reviewId AND latest.maxId = rh.historyId
         WHERE  rh.comment IS NOT NULL AND rh.comment <> ''
       ) prior ON prior.reviewId = r.reviewId
       SET r.comment = prior.comment
       WHERE r.assetId     = ?
         AND r.benchmarkId = ?
         AND (r.comment IS NULL OR r.comment = '')`,
      [assetId, benchmarkId]
    )
  }
}

// ---------------------------------------------------------------------------
// Shared handler
// ---------------------------------------------------------------------------

async function handleImport(
  _app: FastifyInstance,
  source: ChecklistSource,
  collectionId: number,
  body: z.infer<typeof ImportBody>,
  username: string
) {
  const opts: ImportOptions = body.options ?? {}

  // 1. Core ingest (parse + upsert reviews)
  const result = await ingestChecklist(collectionId, body.content, username, source)
  const { assetId, benchmarkId } = result

  // 2. Post-ingest option processing
  if (opts.unreviewed === 'never') {
    await deleteNotcheckedReviews(assetId, benchmarkId)
  }

  if (opts.autoStatus === true) {
    await autoSubmitReviews(assetId, benchmarkId)
  }

  const restoreDetail  = opts.emptyDetail  === 'ignore'
  const restoreComment = opts.emptyComment === 'ignore'
  if (restoreDetail || restoreComment) {
    await restoreBlankFields(assetId, benchmarkId, restoreDetail, restoreComment)
  }

  // 3. Enhanced result
  return {
    ...result,
    options: {
      autoStatus:   opts.autoStatus   ?? false,
      unreviewed:   opts.unreviewed   ?? 'always',
      emptyDetail:  opts.emptyDetail  ?? 'replace',
      emptyComment: opts.emptyComment ?? 'replace'
    }
  }
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function registerImportRoutes(app: FastifyInstance): Promise<void> {
  const auth = [app.authenticate, requireScope(SCOPE_COLLECTION, SCOPE_STIG)] as const

  const idOf = (params: unknown): number => Number((params as { id: string }).id)

  // POST /collections/:id/import/ckl
  app.post('/collections/:id/import/ckl', { preHandler: [...auth] }, async (req, reply) => {
    const body = ImportBody.parse(req.body)
    const result = await handleImport(app, 'ckl', idOf(req.params), body, req.user.username)
    return reply.code(201).send(result)
  })

  // POST /collections/:id/import/cklb
  app.post('/collections/:id/import/cklb', { preHandler: [...auth] }, async (req, reply) => {
    const body = ImportBody.parse(req.body)
    const result = await handleImport(app, 'cklb', idOf(req.params), body, req.user.username)
    return reply.code(201).send(result)
  })

  // POST /collections/:id/import/xccdf
  app.post('/collections/:id/import/xccdf', { preHandler: [...auth] }, async (req, reply) => {
    const body = ImportBody.parse(req.body)
    const result = await handleImport(app, 'xccdf', idOf(req.params), body, req.user.username)
    return reply.code(201).send(result)
  })
}
