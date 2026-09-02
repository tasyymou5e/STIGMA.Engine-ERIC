// Collection-STIG management endpoints.
//
// A STIG is "in" a collection when at least one enabled asset in that
// collection has it assigned in stig_asset_map.
//
// GET    /collections/:id/stigs                          → list all STIGs in collection
// GET    /collections/:id/stigs/:benchmarkId/assets      → assets that have this STIG
// PUT    /collections/:id/stigs/:benchmarkId/assets      → bulk-set asset assignments
// DELETE /collections/:id/stigs/:benchmarkId             → remove STIG from all assets
// GET    /collections/:id/stigs/:benchmarkId/pin         → read revision pin
// PUT    /collections/:id/stigs/:benchmarkId/pin         → set revision pin
// DELETE /collections/:id/stigs/:benchmarkId/pin         → remove revision pin
//
// All endpoints require a valid bearer token + 'stig-manager:collection' scope.

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import {
  stigsByCollection,
  assetsByStig,
  getCollectionStigPin,
  setCollectionStigPin
} from '../repositories/stigs.js'
import {
  assignStigToAsset,
  listAssets
} from '../repositories/assets.js'
import { pool } from '../db/pool.js'
import type { ResultSetHeader } from 'mysql2'

const SCOPE_COLLECTION = 'stig-manager:collection'

const BulkAssignBody = z.object({
  assetIds: z.array(z.number().int().positive())
})

const PinBody = z.object({
  revisionStr: z.string().min(1)
})

function numId(params: unknown, key = 'id'): number {
  return Number((params as Record<string, string>)[key])
}

function strParam(params: unknown, key: string): string {
  return (params as Record<string, string>)[key]
}

export async function registerCollectionStigRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // GET /collections/:id/stigs
  // Returns all STIGs assigned to at least one asset in the collection.
  app.get(
    '/collections/:id/stigs',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      return stigsByCollection(collectionId)
    }
  )

  // GET /collections/:id/stigs/:benchmarkId/assets
  // Returns all assets in the collection that have this STIG assigned.
  app.get(
    '/collections/:id/stigs/:benchmarkId/assets',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const benchmarkId  = strParam(req.params, 'benchmarkId')
      return assetsByStig(collectionId, benchmarkId)
    }
  )

  // PUT /collections/:id/stigs/:benchmarkId/assets
  // Body: { assetIds: number[] }
  // Sets the full asset list for this STIG in the collection:
  //   - adds assignments for new assetIds
  //   - removes assignments for collection assets not in the list
  // Returns the updated asset list.
  app.put(
    '/collections/:id/stigs/:benchmarkId/assets',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const benchmarkId  = strParam(req.params, 'benchmarkId')

      let body: z.infer<typeof BulkAssignBody>
      try {
        body = BulkAssignBody.parse(req.body)
      } catch (e) {
        return reply.code(400).send({ error: 'Invalid body', details: (e as Error).message })
      }

      const { assetIds: desiredIds } = body

      // Fetch all enabled assets in this collection so we know which ones to remove.
      const allAssets = await listAssets(collectionId)
      const allAssetIds = allAssets.map(a => a.assetId)
      const desiredSet = new Set(desiredIds)

      // Remove STIG from collection assets NOT in the desired list
      const toRemove = allAssetIds.filter(id => !desiredSet.has(id))
      if (toRemove.length > 0) {
        await pool.query<ResultSetHeader>(
          `DELETE FROM stig_asset_map
           WHERE benchmarkId = ?
             AND assetId IN (?)`,
          [benchmarkId, toRemove]
        )
      }

      // Add assignments for desired assets (INSERT IGNORE = idempotent)
      for (const assetId of desiredIds) {
        await assignStigToAsset(assetId, benchmarkId)
      }

      return assetsByStig(collectionId, benchmarkId)
    }
  )

  // DELETE /collections/:id/stigs/:benchmarkId
  // Removes this STIG assignment from ALL assets in the collection.
  // Returns { removed: number }.
  app.delete(
    '/collections/:id/stigs/:benchmarkId',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const benchmarkId  = strParam(req.params, 'benchmarkId')

      const [res] = await pool.query<ResultSetHeader>(
        `DELETE sam
         FROM stig_asset_map sam
         JOIN asset a ON a.assetId = sam.assetId
           AND a.collectionId = ?
         WHERE sam.benchmarkId = ?`,
        [collectionId, benchmarkId]
      )

      return { removed: res.affectedRows }
    }
  )

  // GET /collections/:id/stigs/:benchmarkId/pin
  // Returns the current revision pin for this STIG in the collection.
  // When no pin exists, returns { benchmarkId, revisionStr: null, pinnedAt: null, pinnedBy: null }.
  app.get(
    '/collections/:id/stigs/:benchmarkId/pin',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const benchmarkId  = strParam(req.params, 'benchmarkId')

      const pin = await getCollectionStigPin(collectionId, benchmarkId)
      if (pin) return pin

      // No pin — return a canonical "unpinned" shape instead of 404 so callers
      // can unconditionally read the pin status.
      return { benchmarkId, revisionStr: null, pinnedAt: null, pinnedBy: null }
    }
  )

  // PUT /collections/:id/stigs/:benchmarkId/pin
  // Body: { revisionStr: string }  e.g. { "revisionStr": "V2R1" }
  // Pins this STIG to the specified revision for the collection.
  // Returns the updated pin record.
  app.put(
    '/collections/:id/stigs/:benchmarkId/pin',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const benchmarkId  = strParam(req.params, 'benchmarkId')

      let body: z.infer<typeof PinBody>
      try {
        body = PinBody.parse(req.body)
      } catch (e) {
        return reply.code(400).send({ error: 'Invalid body', details: (e as Error).message })
      }

      // Derive pinnedBy from the authenticated user if available.
      const pinnedBy = (req.user as { preferred_username?: string } | undefined)
        ?.preferred_username ?? undefined

      await setCollectionStigPin(collectionId, benchmarkId, body.revisionStr, pinnedBy)

      const pin = await getCollectionStigPin(collectionId, benchmarkId)
      return pin ?? { benchmarkId, revisionStr: body.revisionStr, pinnedAt: null, pinnedBy: null }
    }
  )

  // DELETE /collections/:id/stigs/:benchmarkId/pin
  // Removes the revision pin; the collection reverts to tracking the latest revision.
  // Returns 204 No Content.
  app.delete(
    '/collections/:id/stigs/:benchmarkId/pin',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const benchmarkId  = strParam(req.params, 'benchmarkId')

      await setCollectionStigPin(collectionId, benchmarkId, null)
      return reply.code(204).send()
    }
  )
}
