// Metadata CRUD endpoints for collection, asset, and review entities.
//
// Routes registered (under /api prefix via server.ts):
//
//   GET    /collections/:id/metadata           → getMetadata
//   PATCH  /collections/:id/metadata           → patchMetadata
//   PUT    /collections/:id/metadata           → putMetadata
//   GET    /collections/:id/metadata/keys      → getMetadataKeys
//   GET    /collections/:id/metadata/:key      → getMetadataValue
//   PUT    /collections/:id/metadata/:key      → putMetadataValue
//   DELETE /collections/:id/metadata/:key      → deleteMetadataKey
//   (same pattern for /assets/:id and /collections/:cid/reviews/:id)

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import {
  collectionMetadata,
  assetMetadata,
  reviewMetadata
} from '../repositories/metadata.js'

const SCOPE_COLLECTION = 'stig-manager:collection'

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

const MetaMapBody   = z.record(z.string(), z.string())
const MetaValueBody = z.object({ value: z.string() })

// ---------------------------------------------------------------------------
// Helper to attach the 7 CRUD sub-routes under a given prefix
// ---------------------------------------------------------------------------

function numId(params: unknown, key = 'id'): number {
  return Number((params as Record<string, string>)[key])
}

interface MetadataRepoIface {
  getMetadata(id: number): Promise<Record<string, string>>
  patchMetadata(id: number, patch: Record<string, string>): Promise<Record<string, string>>
  putMetadata(id: number, meta: Record<string, string>): Promise<Record<string, string>>
  getMetadataKeys(id: number): Promise<string[]>
  getMetadataValue(id: number, key: string): Promise<string | null>
  putMetadataValue(id: number, key: string, value: string): Promise<void>
  deleteMetadataKey(id: number, key: string): Promise<void>
}

function registerEntityMetadataRoutes(
  app: FastifyInstance,
  prefix: string,         // e.g. '/collections/:id'
  repo: MetadataRepoIface,
  idParam = 'id'
): void {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // GET /{entity}/:id/metadata
  app.get(`${prefix}/metadata`, { preHandler: guard }, async (req) => {
    const id = numId(req.params, idParam)
    return repo.getMetadata(id)
  })

  // PATCH /{entity}/:id/metadata
  app.patch(`${prefix}/metadata`, { preHandler: guard }, async (req) => {
    const id    = numId(req.params, idParam)
    const patch = MetaMapBody.parse(req.body)
    return repo.patchMetadata(id, patch)
  })

  // PUT /{entity}/:id/metadata
  app.put(`${prefix}/metadata`, { preHandler: guard }, async (req) => {
    const id   = numId(req.params, idParam)
    const meta = MetaMapBody.parse(req.body)
    return repo.putMetadata(id, meta)
  })

  // GET /{entity}/:id/metadata/keys
  // NOTE: This route MUST be registered before /:key to avoid shadowing.
  app.get(`${prefix}/metadata/keys`, { preHandler: guard }, async (req) => {
    const id = numId(req.params, idParam)
    return repo.getMetadataKeys(id)
  })

  // GET /{entity}/:id/metadata/:key
  app.get(`${prefix}/metadata/:key`, { preHandler: guard }, async (req, reply) => {
    const id  = numId(req.params, idParam)
    const key = (req.params as Record<string, string>).key
    const val = await repo.getMetadataValue(id, key)
    if (val === null) return reply.code(404).send({ error: `Metadata key '${key}' not found` })
    return { key, value: val }
  })

  // PUT /{entity}/:id/metadata/:key
  app.put(`${prefix}/metadata/:key`, { preHandler: guard }, async (req, reply) => {
    const id    = numId(req.params, idParam)
    const key   = (req.params as Record<string, string>).key
    const { value } = MetaValueBody.parse(req.body)
    await repo.putMetadataValue(id, key, value)
    return reply.code(204).send()
  })

  // DELETE /{entity}/:id/metadata/:key
  app.delete(`${prefix}/metadata/:key`, { preHandler: guard }, async (req, reply) => {
    const id  = numId(req.params, idParam)
    const key = (req.params as Record<string, string>).key
    await repo.deleteMetadataKey(id, key)
    return reply.code(204).send()
  })
}

// ---------------------------------------------------------------------------
// Public registration function
// ---------------------------------------------------------------------------

export async function registerMetadataRoutes(app: FastifyInstance): Promise<void> {
  // Collections
  registerEntityMetadataRoutes(app, '/collections/:id', collectionMetadata, 'id')

  // Assets
  registerEntityMetadataRoutes(app, '/assets/:id', assetMetadata, 'id')

  // Reviews — nested under collection for auth context
  // Path: /collections/:collectionId/reviews/:id/metadata/...
  registerEntityMetadataRoutes(
    app,
    '/collections/:collectionId/reviews/:id',
    reviewMetadata,
    'id'
  )
}
