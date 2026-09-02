// Review CRUD + status-workflow endpoints.
// All endpoints require a valid bearer token (app.authenticate) plus
// the 'stig-manager:collection' scope unless noted otherwise.
//
// Mapped operationIds from the STIG Manager OpenAPI spec:
//   GET    /collections/:id/reviews              → getReviewsByCollection
//   POST   /collections/:id/reviews              → postReviewBatch
//   GET    /collections/:id/reviews/:assetId     → getReviewsByAsset
//   GET    /collections/:id/reviews/:assetId/:ruleId  → getReviewByAssetRule
//   PATCH  /collections/:id/reviews/:assetId/:ruleId  → patchReviewByAssetRule
//   PUT    /collections/:id/reviews/:assetId/:ruleId  → putReviewByAssetRule
//   DELETE /collections/:id/reviews/:assetId/:ruleId  → deleteReviewByAssetRule
//   PATCH  /assets/:assetId/reviews              → setReviewStatus  (kept from index.ts)
//   GET    /reviews/:reviewId/history            → getReviewHistoryByCollection
//
// Checklist workspace aggregation endpoints:
//   GET    /collections/:id/checklist/:benchmarkId/rules
//          ?assetId=N (optional)                 → checklistRules (aggregate per ruleId)
//   GET    /collections/:id/checklist/:benchmarkId/rules/:ruleId/reviews
//                                                → checklistReviews (per-asset reviews for a rule)
//   PATCH  /collections/:id/checklist/:benchmarkId/rules/:ruleId/reviews/:assetId
//                                                → patchReview (partial update)

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import {
  listReviewsByCollection,
  listReviewsByAsset,
  upsertReviews,
  setReviewStatus,
  getReview,
  patchReview,
  deleteReview,
  listReviewHistory,
  checklistRules,
  checklistReviews,
  listCollectionReviewHistory,
  deleteCollectionReviewHistory,
  getCollectionReviewHistoryStats
} from '../repositories/reviews.js'
import { toCSV } from '../export/csv.js'

const SCOPE_COLLECTION = 'stig-manager:collection'

// ---- Zod schemas -----------------------------------------------------------

/** All possible review result values (mirrors NormalizedReview.result). */
const ReviewResult = z.enum([
  'pass',
  'fail',
  'notapplicable',
  'notchecked',
  'informational',
  'unknown',
  'error',
  'notselected',
  'fixed'
])

/** Review status lifecycle values. */
const ReviewStatus = z.enum(['saved', 'submitted', 'accepted', 'rejected'])

/**
 * A single review item in a batch-upsert body.
 * status defaults to 'saved' when omitted.
 */
const ReviewItemSchema = z.object({
  ruleId: z.string().min(1),
  result: ReviewResult,
  detail: z.string().default(''),
  comment: z.string().default(''),
  status: ReviewStatus.default('saved')
})

/** POST /collections/:id/reviews — array of review items. */
const UpsertBatchBody = z.array(ReviewItemSchema).min(1, 'At least one review item is required')

/**
 * PATCH /collections/:id/reviews/:assetId/:ruleId
 * All fields optional so callers can update only what changed.
 */
const PatchReviewBody = z.object({
  result: ReviewResult.optional(),
  detail: z.string().optional(),
  comment: z.string().optional(),
  status: ReviewStatus.optional()
})

/**
 * PUT /collections/:id/reviews/:assetId/:ruleId
 * Full replace — result is required; others default to empty / saved.
 */
const PutReviewBody = z.object({
  result: ReviewResult,
  detail: z.string().default(''),
  comment: z.string().default(''),
  status: ReviewStatus.default('saved')
})

/**
 * PATCH /assets/:assetId/reviews — status transition for a single rule on an asset.
 * statusText is optional free-text reason (e.g. rejection rationale).
 */
const SetStatusBody = z.object({
  ruleId: z.string().min(1),
  status: ReviewStatus,
  statusText: z.string().optional()
})

/**
 * PATCH /collections/:id/checklist/:benchmarkId/rules/:ruleId/reviews/:assetId
 * Partial update for a single checklist review.
 * result and detail are required together; status/statusText are optional.
 */
const ChecklistPatchBody = z.object({
  result: ReviewResult.optional(),
  detail: z.string().optional(),
  comment: z.string().optional(),
  status: ReviewStatus.optional(),
  statusText: z.string().optional()
})

// ---- Param helpers ---------------------------------------------------------

function numId(params: unknown, key = 'id'): number {
  const raw = (params as Record<string, string>)[key]
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0) throw Object.assign(new Error(`Invalid id: ${raw}`), { statusCode: 400 })
  return n
}

function strParam(params: unknown, key: string): string {
  return (params as Record<string, string>)[key]
}

// ---- Route registration ----------------------------------------------------

export async function registerReviewRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // GET /collections/:id/reviews[?format=csv]
  // operationId: getReviewsByCollection
  // Optional ?format=csv returns a CSV download instead of JSON.
  app.get(
    '/collections/:id/reviews',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const format = (req.query as Record<string, string>).format ?? 'json'
      const reviews = await listReviewsByCollection(collectionId)
      if (format === 'csv') {
        const columns = ['ruleId', 'groupId', 'ruleVersion', 'severity', 'title', 'result', 'detail', 'comment']
        const csv = toCSV(reviews as unknown as Record<string, unknown>[], columns)
        return reply
          .header('Content-Type', 'text/csv; charset=utf-8')
          .header('Content-Disposition', `attachment; filename="reviews-collection-${collectionId}.csv"`)
          .send(csv)
      }
      return reviews
    }
  )

  // POST /collections/:id/reviews
  // operationId: postReviewBatch
  // Body: ReviewItem[]  (ruleId, result, detail, comment, status?)
  // The route receives a flat batch; the caller must supply assetId as a query
  // param because the collection-level batch endpoint in the NAVY spec targets
  // a specific asset via ?assetId=<id>.
  const UpsertQuery = z.object({ assetId: z.coerce.number().int().positive() })
  app.post(
    '/collections/:id/reviews',
    { preHandler: guard },
    async (req, reply) => {
      const { assetId } = UpsertQuery.parse(req.query)
      const items = UpsertBatchBody.parse(req.body)
      // upsertReviews expects NormalizedReview shape; adapt the slim batch items.
      const reviews = items.map((item) => ({
        ruleId: item.ruleId,
        groupId: '',          // not supplied in a manual batch; ingest sets this
        ruleVersion: '',
        severity: 'unknown' as const,
        title: '',
        result: item.result,
        detail: item.detail,
        comment: item.comment
      }))
      const affected = await upsertReviews(assetId, '', reviews, req.user.username)
      // Apply status overrides for any item that specifies a non-default status.
      for (const item of items) {
        if (item.status !== 'saved') {
          await setReviewStatus(assetId, item.ruleId, item.status)
        }
      }
      return reply.code(201).send({ inserted: affected })
    }
  )

  // GET /collections/:id/reviews/:assetId
  // operationId: getReviewsByAsset (scoped to a collection)
  app.get(
    '/collections/:id/reviews/:assetId',
    { preHandler: guard },
    (req) => listReviewsByAsset(numId(req.params, 'assetId'))
  )

  // GET /collections/:id/reviews/:assetId/:ruleId
  // operationId: getReviewByAssetRule
  app.get(
    '/collections/:id/reviews/:assetId/:ruleId',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params, 'assetId')
      const ruleId = strParam(req.params, 'ruleId')
      const review = await getReview(assetId, ruleId)
      return review ?? reply.code(404).send({ error: 'Review not found' })
    }
  )

  // PATCH /collections/:id/reviews/:assetId/:ruleId
  // operationId: patchReviewByAssetRule — partial update
  app.patch(
    '/collections/:id/reviews/:assetId/:ruleId',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params, 'assetId')
      const ruleId = strParam(req.params, 'ruleId')
      const patch = PatchReviewBody.parse(req.body)
      const updated = await patchReview(assetId, ruleId, patch, req.user.username)
      return updated ?? reply.code(404).send({ error: 'Review not found' })
    }
  )

  // PUT /collections/:id/reviews/:assetId/:ruleId
  // operationId: putReviewByAssetRule — full replace (same handler, full body)
  app.put(
    '/collections/:id/reviews/:assetId/:ruleId',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params, 'assetId')
      const ruleId = strParam(req.params, 'ruleId')
      const body = PutReviewBody.parse(req.body)
      // PUT is equivalent to a full patch — delegate to patchReview which issues
      // an UPSERT so a missing row is created rather than 404'd.
      const result = await patchReview(assetId, ruleId, body, req.user.username, { upsert: true })
      return result ?? reply.code(404).send({ error: 'Review could not be written' })
    }
  )

  // DELETE /collections/:id/reviews/:assetId/:ruleId
  // operationId: deleteReviewByAssetRule
  app.delete(
    '/collections/:id/reviews/:assetId/:ruleId',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params, 'assetId')
      const ruleId = strParam(req.params, 'ruleId')
      const deleted = await deleteReview(assetId, ruleId)
      if (!deleted) return reply.code(404).send({ error: 'Review not found' })
      return reply.code(204).send()
    }
  )

  // PATCH /assets/:assetId/reviews
  // operationId: setReviewStatus — status-workflow transition for a single rule.
  // Kept separate from the /collections prefix because status transitions are an
  // asset-scoped operation that does not require knowing the collection.
  app.patch(
    '/assets/:assetId/reviews',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params, 'assetId')
      const body = SetStatusBody.parse(req.body)
      const ok = await setReviewStatus(assetId, body.ruleId, body.status)
      return ok ? { updated: true } : reply.code(404).send({ error: 'Review not found' })
    }
  )

  // GET /reviews/:reviewId/history
  // operationId: getReviewHistoryByCollection (item-level history log)
  app.get(
    '/reviews/:reviewId/history',
    { preHandler: guard },
    async (req, reply) => {
      const reviewId = numId(req.params, 'reviewId')
      const history = await listReviewHistory(reviewId)
      return history ?? reply.code(404).send({ error: 'Review not found' })
    }
  )

  // ---- Checklist workspace aggregation ----------------------------------------

  // GET /collections/:id/checklist/:benchmarkId/rules
  // Optional query param: ?assetId=N to scope to a single asset.
  // Returns one aggregated ChecklistRule row per ruleId, ordered by severity.
  const ChecklistQuery = z.object({ assetId: z.coerce.number().int().positive().optional() })
  app.get(
    '/collections/:id/checklist/:benchmarkId/rules',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const benchmarkId = strParam(req.params, 'benchmarkId')
      const { assetId } = ChecklistQuery.parse(req.query)
      return checklistRules(collectionId, benchmarkId, assetId)
    }
  )

  // GET /collections/:id/checklist/:benchmarkId/rules/:ruleId/reviews
  // Returns all per-asset reviews for a specific ruleId in the collection.
  app.get(
    '/collections/:id/checklist/:benchmarkId/rules/:ruleId/reviews',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const benchmarkId = strParam(req.params, 'benchmarkId')
      const ruleId = strParam(req.params, 'ruleId')
      return checklistReviews(collectionId, benchmarkId, ruleId)
    }
  )

  // PATCH /collections/:id/checklist/:benchmarkId/rules/:ruleId/reviews/:assetId
  // Partial update for a single review identified by assetId + ruleId.
  // Body: { result?, detail?, comment?, status?, statusText? }
  app.patch(
    '/collections/:id/checklist/:benchmarkId/rules/:ruleId/reviews/:assetId',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params, 'assetId')
      const ruleId = strParam(req.params, 'ruleId')
      const patch = ChecklistPatchBody.parse(req.body)
      const updated = await patchReview(assetId, ruleId, patch, req.user.username)
      return updated ? { updated: true } : reply.code(404).send({ error: 'Review not found' })
    }
  )

  // ---- Collection-level review history ----------------------------------------

  // GET /collections/:id/reviews/history?ruleId=&assetId=&maxResults=
  // operationId: listCollectionReviewHistory
  const HistoryQuery = z.object({
    ruleId:     z.string().optional(),
    assetId:    z.coerce.number().int().positive().optional(),
    maxResults: z.coerce.number().int().min(1).max(5000).optional()
  })
  app.get(
    '/collections/:id/reviews/history',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const q = HistoryQuery.parse(req.query)
      return listCollectionReviewHistory(collectionId, q)
    }
  )

  // DELETE /collections/:id/reviews/history?retainDays=
  // operationId: deleteCollectionReviewHistory
  const DeleteHistoryQuery = z.object({
    retainDays: z.coerce.number().int().min(0).optional()
  })
  app.delete(
    '/collections/:id/reviews/history',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const { retainDays } = DeleteHistoryQuery.parse(req.query)
      const deleted = await deleteCollectionReviewHistory(collectionId, retainDays)
      return reply.code(200).send({ deleted })
    }
  )

  // GET /collections/:id/reviews/history/stats
  // operationId: getCollectionReviewHistoryStats
  app.get(
    '/collections/:id/reviews/history/stats',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      return getCollectionReviewHistoryStats(collectionId)
    }
  )

  // ---- Batch review (cross-product of rules × assets) -------------------------

  /**
   * POST /collections/:id/reviews/batch
   * operationId: postBatchReviews
   *
   * Applies the same result/detail/comment to every (assetId, ruleId) pair in
   * the cross-product of the supplied arrays.  Empty detail/comment strings are
   * treated as "no-op" — the field is left as-is for existing reviews and set to
   * '' for new ones.
   *
   * Body:
   *   {
   *     ruleIds:  string[]          // 1-based STIG rule IDs
   *     assetIds: number[]          // asset primary keys
   *     result:   ReviewResult      // required
   *     detail?:  string            // optional — applied to all pairs
   *     comment?: string            // optional — applied to all pairs
   *   }
   *
   * Response 200:
   *   { submitted: number, errors: number }
   */
  const BatchReviewBody = z.object({
    ruleIds:  z.array(z.string().min(1)).min(1),
    assetIds: z.array(z.number().int().positive()).min(1),
    result:   ReviewResult,
    detail:   z.string().optional(),
    comment:  z.string().optional()
  })

  app.post(
    '/collections/:id/reviews/batch',
    { preHandler: guard },
    async (req, reply) => {
      const body = BatchReviewBody.parse(req.body)
      let submitted = 0
      let errors = 0

      for (const assetId of body.assetIds) {
        // Build a NormalizedReview list for this asset (one entry per ruleId)
        const reviewItems = body.ruleIds.map((ruleId) => ({
          ruleId,
          groupId: '',
          ruleVersion: '',
          severity: 'unknown' as const,
          title: '',
          result: body.result,
          detail: body.detail ?? '',
          comment: body.comment ?? ''
        }))

        try {
          await upsertReviews(assetId, '', reviewItems, req.user.username)
          submitted += body.ruleIds.length
        } catch {
          errors += body.ruleIds.length
        }
      }

      return reply.code(200).send({ submitted, errors })
    }
  )
}
