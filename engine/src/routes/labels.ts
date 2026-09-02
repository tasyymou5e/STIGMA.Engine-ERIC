// Collection-label (tag/label taxonomy) endpoints.
//
// Labels are collection-scoped tags that can be attached to assets for
// grouping and filtering.  Each label record lives in the
// `collection_label` table; the many-to-many relationship with assets is
// stored in `collection_label_asset`.
//
// Mapped operationIds:
//   GET    /collections/:id/labels                         → getLabelsByCollection
//   POST   /collections/:id/labels                         → createLabel
//   GET    /collections/:id/labels/:clId                   → getLabel
//   PUT    /collections/:id/labels/:clId                   → putLabel
//   DELETE /collections/:id/labels/:clId                   → deleteLabel
//   GET    /collections/:id/labels/:clId/assets            → getLabelAssets
//   PUT    /collections/:id/labels/:clId/assets            → setLabelAssets
//
// All endpoints require a valid bearer token + stig-manager:collection scope.

import type { FastifyInstance } from 'fastify'
import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import { pool } from '../db/pool.js'

const SCOPE_COLLECTION = 'stig-manager:collection'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LabelRecord {
  clId: number
  collectionId: number
  name: string
  /** Optional hex colour string e.g. "#FF5733", null when unset */
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
// Zod schemas
// ---------------------------------------------------------------------------

const LabelBody = z.object({
  name:        z.string().min(1),
  color:       z.string().regex(/^#[0-9A-Fa-f]{6}$/).nullable().optional(),
  description: z.string().optional()
})

/** PUT body for updating all mutable label fields. */
const PutLabelBody = LabelBody

/** PUT /labels/:clId/assets — full replacement of the asset membership list. */
const SetLabelAssetsBody = z.object({
  /** Array of assetIds that should be tagged with this label after the call. */
  assetIds: z.array(z.number().int().positive()).min(0)
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function numId(params: unknown, key = 'id'): number {
  return Number((params as Record<string, string>)[key])
}

async function fetchLabel(clId: number, collectionId: number): Promise<LabelRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT clId, collectionId, name, color, description
     FROM collection_label
     WHERE clId = :clId AND collectionId = :collectionId`,
    { clId, collectionId }
  )
  if (rows.length === 0) return null
  return normaliseLabel(rows[0])
}

function normaliseLabel(row: RowDataPacket): LabelRecord {
  return {
    clId:         Number(row.clId),
    collectionId: Number(row.collectionId),
    name:         String(row.name ?? ''),
    color:        row.color != null ? String(row.color) : null,
    description:  row.description != null ? String(row.description) : null
  }
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function registerLabelRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // GET /collections/:id/labels
  // operationId: getLabelsByCollection
  app.get(
    '/collections/:id/labels',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const [rows] = await pool.query<RowDataPacket[]>(
        `SELECT clId, collectionId, name, color, description
         FROM collection_label
         WHERE collectionId = :collectionId
         ORDER BY name`,
        { collectionId }
      )
      return rows.map(normaliseLabel)
    }
  )

  // POST /collections/:id/labels
  // operationId: createLabel
  app.post(
    '/collections/:id/labels',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const body = LabelBody.parse(req.body)

      const [res] = await pool.query<ResultSetHeader>(
        `INSERT INTO collection_label (collectionId, name, color, description)
         VALUES (:collectionId, :name, :color, :description)`,
        {
          collectionId,
          name:        body.name,
          color:       body.color ?? null,
          description: body.description ?? null
        }
      )

      const label = await fetchLabel(res.insertId, collectionId)
      return reply.code(201).send(label)
    }
  )

  // GET /collections/:id/labels/:clId
  // operationId: getLabel
  app.get(
    '/collections/:id/labels/:clId',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const clId         = numId(req.params, 'clId')
      const label = await fetchLabel(clId, collectionId)
      return label ?? reply.code(404).send({ error: 'Label not found' })
    }
  )

  // PUT /collections/:id/labels/:clId
  // operationId: putLabel
  app.put(
    '/collections/:id/labels/:clId',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const clId         = numId(req.params, 'clId')
      const body = PutLabelBody.parse(req.body)

      const [res] = await pool.query<ResultSetHeader>(
        `UPDATE collection_label
         SET name = :name, color = :color, description = :description
         WHERE clId = :clId AND collectionId = :collectionId`,
        {
          name:        body.name,
          color:       body.color ?? null,
          description: body.description ?? null,
          clId,
          collectionId
        }
      )

      if (res.affectedRows === 0) return reply.code(404).send({ error: 'Label not found' })
      return fetchLabel(clId, collectionId)
    }
  )

  // DELETE /collections/:id/labels/:clId
  // operationId: deleteLabel
  // Also removes all asset associations for this label.
  app.delete(
    '/collections/:id/labels/:clId',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const clId         = numId(req.params, 'clId')

      // Remove associations first to satisfy FK constraints.
      await pool.query(
        'DELETE FROM collection_label_asset WHERE clId = :clId',
        { clId }
      )

      const [res] = await pool.query<ResultSetHeader>(
        'DELETE FROM collection_label WHERE clId = :clId AND collectionId = :collectionId',
        { clId, collectionId }
      )

      if (res.affectedRows === 0) return reply.code(404).send({ error: 'Label not found' })
      return reply.code(204).send()
    }
  )

  // GET /collections/:id/labels/:clId/assets
  // operationId: getLabelAssets
  // Returns the assets currently tagged with this label (must belong to the collection).
  app.get(
    '/collections/:id/labels/:clId/assets',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const clId         = numId(req.params, 'clId')

      // Confirm the label belongs to this collection.
      const label = await fetchLabel(clId, collectionId)
      if (!label) return reply.code(404).send({ error: 'Label not found' })

      const [rows] = await pool.query<RowDataPacket[]>(
        `SELECT a.assetId, a.name, a.fqdn, a.ip
         FROM collection_label_asset cla
         INNER JOIN asset a
                 ON a.assetId = cla.assetId
                AND a.collectionId = :collectionId
         WHERE cla.clId = :clId
         ORDER BY a.name`,
        { clId, collectionId }
      )

      return rows.map((r): LabelAsset => ({
        assetId: Number(r.assetId),
        name:    String(r.name ?? ''),
        fqdn:    r.fqdn != null ? String(r.fqdn) : null,
        ip:      r.ip   != null ? String(r.ip)   : null
      }))
    }
  )

  // PUT /collections/:id/labels/:clId/assets
  // operationId: setLabelAssets
  // Full-replace: removes all current asset associations and re-inserts the
  // supplied set.  Assets not belonging to this collection are silently ignored.
  app.put(
    '/collections/:id/labels/:clId/assets',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const clId         = numId(req.params, 'clId')
      const { assetIds } = SetLabelAssetsBody.parse(req.body)

      // Confirm the label belongs to this collection.
      const label = await fetchLabel(clId, collectionId)
      if (!label) return reply.code(404).send({ error: 'Label not found' })

      // Remove all current associations for this label.
      await pool.query(
        'DELETE FROM collection_label_asset WHERE clId = :clId',
        { clId }
      )

      if (assetIds.length > 0) {
        // Bulk-insert only assets that genuinely belong to the collection.
        // Build a single multi-row INSERT via parameterised placeholders.
        const placeholders = assetIds.map(() => '(:clId, ?)').join(', ')
        await pool.query(
          `INSERT IGNORE INTO collection_label_asset (clId, assetId)
           SELECT :clId, a.assetId
           FROM asset a
           WHERE a.collectionId = :collectionId
             AND a.assetId IN (${assetIds.map(() => '?').join(',')})`,
          [collectionId, ...assetIds]
        )
        // Suppress unused-variable warning from the placeholders variable.
        void placeholders
      }

      // Return the updated asset list.
      const [rows] = await pool.query<RowDataPacket[]>(
        `SELECT a.assetId, a.name, a.fqdn, a.ip
         FROM collection_label_asset cla
         INNER JOIN asset a
                 ON a.assetId = cla.assetId
                AND a.collectionId = :collectionId
         WHERE cla.clId = :clId
         ORDER BY a.name`,
        { clId, collectionId }
      )

      return rows.map((r): LabelAsset => ({
        assetId: Number(r.assetId),
        name:    String(r.name ?? ''),
        fqdn:    r.fqdn != null ? String(r.fqdn) : null,
        ip:      r.ip   != null ? String(r.ip)   : null
      }))
    }
  )
}
