// Asset endpoints — CRUD, STIG assignments, and checklist export.
//
// All endpoints require a valid bearer token (app.authenticate) plus
// the 'stig-manager:collection' scope.
//
// Mapped operationIds from the STIG Manager OpenAPI spec:
//   GET    /assets                              → getAssets (with ?collectionId filter)
//   GET    /assets/:id                          → getAsset
//   PATCH  /assets/:id                          → updateAsset
//   DELETE /assets/:id                          → deleteAsset
//   GET    /assets/:id/stigs                    → getStigsByAsset
//   PUT    /assets/:id/stigs/:benchmarkId       → attachStigToAsset
//   DELETE /assets/:id/stigs/:benchmarkId       → removeStigFromAsset
//   GET    /assets/:id/checklists               → list available checklists
//   GET    /assets/:id/checklists/:benchmarkId/ckl   → generateCkl  (text/xml)
//   GET    /assets/:id/checklists/:benchmarkId/cklb  → generateCklb (application/json)
//   POST   /collections/:id/assets/import       → importAssetsFromCsv

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import { config } from '../config.js'
import {
  listAssets,
  createAsset,
  getAsset,
  ensureAsset,
  updateAsset,
  deleteAsset,
  listAssetStigs,
  assignStigToAsset,
  removeStigFromAsset,
  listAssetChecklists,
  generateCkl,
  generateCklb
} from '../repositories/assets.js'
import { generateXccdf } from '../export/checklist.js'
import { toCSV } from '../export/csv.js'

const SCOPE_COLLECTION = 'stig-manager:collection'

// ---- Zod schemas ------------------------------------------------------------

/** ?collectionId=<number> — required for the list endpoint. */
const ListAssetsQuery = z.object({
  collectionId: z.coerce.number().int().positive(),
  format: z.enum(['json', 'csv']).optional().default('json')
})

/**
 * PATCH /assets/:id body — all fields optional for a partial update.
 * Mirrors AssetPatch in repositories/assets.ts.
 */
const UpdateAssetBody = z.object({
  name: z.string().min(1).optional(),
  fqdn: z.string().nullable().optional(),
  ip: z.string().nullable().optional(),
  mac: z.string().nullable().optional(),
  description: z.string().nullable().optional(),
  noncomputing: z.boolean().optional()
})

/**
 * POST /collections/:id/assets/import body.
 * csv      — raw CSV text (first row = headers)
 * fields   — which columns to map (name is always required)
 * delimiter — field separator character
 */
const CsvImportBody = z.object({
  csv: z.string().min(1),
  fields: z.object({
    name:        z.boolean().default(true),
    fqdn:        z.boolean().default(false),
    ip:          z.boolean().default(false),
    mac:         z.boolean().default(false),
    description: z.boolean().default(false),
    stigs:       z.boolean().default(false)
  }),
  delimiter: z.string().min(1).max(1).default(',')
})

// ---- CSV helpers ------------------------------------------------------------

/**
 * Minimal RFC-4180-ish CSV parser — no external library.
 * Splits `text` into rows then cells using `delimiter`.
 * Handles double-quoted cells (including embedded newlines and escaped quotes).
 * Returns an array of string arrays; empty trailing rows are skipped.
 */
function parseCsv(text: string, delimiter: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let inQuote = false

  // Normalise line endings
  const chars = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')

  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i]

    if (inQuote) {
      if (ch === '"') {
        // Escaped quote ("") or closing quote?
        if (chars[i + 1] === '"') {
          cell += '"'
          i++
        } else {
          inQuote = false
        }
      } else {
        cell += ch
      }
    } else if (ch === '"') {
      inQuote = true
    } else if (ch === delimiter) {
      row.push(cell)
      cell = ''
    } else if (ch === '\n') {
      row.push(cell)
      cell = ''
      if (row.some(c => c !== '')) rows.push(row)
      row = []
    } else {
      cell += ch
    }
  }

  // Flush final cell / row
  row.push(cell)
  if (row.some(c => c !== '')) rows.push(row)

  return rows
}

// ---- Param helpers ----------------------------------------------------------

function numId(params: unknown, key = 'id'): number {
  const raw = (params as Record<string, string>)[key]
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0) throw Object.assign(new Error(`Invalid id: ${raw}`), { statusCode: 400 })
  return n
}

function strParam(params: unknown, key: string): string {
  return (params as Record<string, string>)[key]
}

// ---- Route registration -----------------------------------------------------

export async function registerAssetRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // GET /collections/:id/assets — canonical collection-scoped path (upstream convention).
  // Alias for GET /assets?collectionId=:id so both paths work.
  app.get(
    '/collections/:id/assets',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      return listAssets(collectionId)
    }
  )

  // POST /collections/:id/assets — create a single asset in a collection.
  app.post(
    '/collections/:id/assets',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const body = z.object({ name: z.string().min(1), fqdn: z.string().optional(), ip: z.string().optional() }).parse(req.body)
      const assetId = await createAsset({ collectionId, ...body })
      return reply.code(201).send({ assetId })
    }
  )

  // GET /assets?collectionId=<id>[&format=csv]
  // operationId: getAssets
  // Returns all enabled assets in a collection.  collectionId is required.
  // Optional ?format=csv returns a CSV download instead of JSON.
  app.get(
    '/assets',
    { preHandler: guard },
    async (req, reply) => {
      const query = ListAssetsQuery.safeParse(req.query)
      if (!query.success) {
        return reply.code(400).send({
          error: 'collectionId query parameter is required and must be a positive integer',
          details: query.error.flatten()
        })
      }
      const assets = await listAssets(query.data.collectionId)
      if (query.data.format === 'csv') {
        const csv = toCSV(assets as unknown as Record<string, unknown>[], [
          'assetId', 'name', 'fqdn', 'ip', 'mac', 'state', 'stigCount'
        ])
        return reply
          .header('Content-Type', 'text/csv; charset=utf-8')
          .header('Content-Disposition', `attachment; filename="assets-collection-${query.data.collectionId}.csv"`)
          .send(csv)
      }
      return assets
    }
  )

  // GET /assets/:id
  // operationId: getAsset
  // Includes stigs[] and labels[] projections via the repository.
  app.get(
    '/assets/:id',
    { preHandler: guard },
    async (req, reply) => {
      const asset = await getAsset(numId(req.params))
      return asset ?? reply.code(404).send({ error: 'Asset not found' })
    }
  )

  // PATCH /assets/:id
  // operationId: updateAsset — partial update, returns the updated asset record.
  app.patch(
    '/assets/:id',
    { preHandler: guard },
    async (req, reply) => {
      const id = numId(req.params)
      const patch = UpdateAssetBody.parse(req.body)
      const updated = await updateAsset(id, patch)
      if (!updated) return reply.code(404).send({ error: 'Asset not found' })
      // Re-fetch so the response includes stigs[] and labels[] projections.
      const asset = await getAsset(id)
      return asset ?? reply.code(404).send({ error: 'Asset not found' })
    }
  )

  // DELETE /assets/:id
  // operationId: deleteAsset — soft-delete (state = 'disabled').
  // Returns 204 No Content on success, 404 if not found.
  app.delete(
    '/assets/:id',
    { preHandler: guard },
    async (req, reply) => {
      const deleted = await deleteAsset(numId(req.params))
      if (!deleted) return reply.code(404).send({ error: 'Asset not found' })
      return reply.code(204).send()
    }
  )

  // GET /assets/:id/stigs
  // operationId: getStigsByAsset
  // Returns all STIG benchmark assignments (benchmarkId, revisionStr, title).
  app.get(
    '/assets/:id/stigs',
    { preHandler: guard },
    async (req, reply) => {
      const asset = await getAsset(numId(req.params))
      if (!asset) return reply.code(404).send({ error: 'Asset not found' })
      return listAssetStigs(numId(req.params))
    }
  )

  // PUT /assets/:id/stigs/:benchmarkId
  // operationId: attachStigToAsset
  // Assigns a STIG to the asset (idempotent).  Returns the full assignment list.
  app.put(
    '/assets/:id/stigs/:benchmarkId',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params)
      const benchmarkId = strParam(req.params, 'benchmarkId')
      const asset = await getAsset(assetId)
      if (!asset) return reply.code(404).send({ error: 'Asset not found' })
      await assignStigToAsset(assetId, benchmarkId)
      return listAssetStigs(assetId)
    }
  )

  // DELETE /assets/:id/stigs/:benchmarkId
  // operationId: removeStigFromAsset
  // Removes a single STIG assignment.  Returns the remaining assignment list.
  app.delete(
    '/assets/:id/stigs/:benchmarkId',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params)
      const benchmarkId = strParam(req.params, 'benchmarkId')
      const asset = await getAsset(assetId)
      if (!asset) return reply.code(404).send({ error: 'Asset not found' })
      const removed = await removeStigFromAsset(assetId, benchmarkId)
      if (!removed) return reply.code(404).send({ error: 'STIG assignment not found' })
      return listAssetStigs(assetId)
    }
  )

  // GET /assets/:id/checklists
  // operationId: getChecklistByAsset (listing variant)
  // Returns benchmarks that have at least one review row for this asset,
  // i.e. the checklists that can actually be exported.
  app.get(
    '/assets/:id/checklists',
    { preHandler: guard },
    async (req, reply) => {
      const asset = await getAsset(numId(req.params))
      if (!asset) return reply.code(404).send({ error: 'Asset not found' })
      return listAssetChecklists(numId(req.params))
    }
  )

  // GET /assets/:id/checklists/:benchmarkId/ckl
  // operationId: generateCkl
  // Returns a STIG Viewer 2-compatible CKL XML document.
  // Content-Type: text/xml; charset=utf-8
  app.get(
    '/assets/:id/checklists/:benchmarkId/ckl',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params)
      const benchmarkId = strParam(req.params, 'benchmarkId')
      const xml = await generateCkl(assetId, benchmarkId, config.CLASSIFICATION)
      if (xml == null) return reply.code(404).send({ error: 'Asset or benchmark not found' })
      const safeBenchmark = benchmarkId.replace(/[^A-Za-z0-9_-]/g, '_')
      return reply
        .header('Content-Type', 'text/xml; charset=utf-8')
        .header('Content-Disposition', `attachment; filename="${safeBenchmark}.ckl"`)
        .send(xml)
    }
  )

  // GET /assets/:id/checklists/:benchmarkId/cklb
  // operationId: generateCklb
  // Returns a STIG Viewer 3-compatible CKLB JSON document.
  // Content-Type: application/json
  app.get(
    '/assets/:id/checklists/:benchmarkId/cklb',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params)
      const benchmarkId = strParam(req.params, 'benchmarkId')
      const cklb = await generateCklb(assetId, benchmarkId, config.CLASSIFICATION)
      if (cklb == null) return reply.code(404).send({ error: 'Asset or benchmark not found' })
      const safeBenchmark = benchmarkId.replace(/[^A-Za-z0-9_-]/g, '_')
      return reply
        .header('Content-Type', 'application/json')
        .header('Content-Disposition', `attachment; filename="${safeBenchmark}.cklb"`)
        .send(cklb)
    }
  )

  // GET /assets/:id/checklists/:benchmarkId/xccdf
  // operationId: generateXccdf
  // Returns an XCCDF 1.2 TestResult XML document.
  // Content-Type: text/xml; charset=utf-8
  app.get(
    '/assets/:id/checklists/:benchmarkId/xccdf',
    { preHandler: guard },
    async (req, reply) => {
      const assetId = numId(req.params)
      const benchmarkId = strParam(req.params, 'benchmarkId')
      try {
        const xml = await generateXccdf(assetId, benchmarkId, config.CLASSIFICATION)
        const safeBenchmark = benchmarkId.replace(/[^A-Za-z0-9_-]/g, '_')
        return reply
          .header('Content-Type', 'text/xml; charset=utf-8')
          .header('Content-Disposition', `attachment; filename="${safeBenchmark}.xccdf.xml"`)
          .send(xml)
      } catch (e) {
        const msg = (e as Error).message ?? ''
        if (msg.includes('not found')) return reply.code(404).send({ error: msg })
        throw e
      }
    }
  )

  // POST /collections/:id/assets/import
  // operationId: importAssetsFromCsv
  //
  // Bulk-imports assets (and optional STIG assignments) from a CSV string.
  // The first CSV row is treated as a header row.  Headers are matched
  // case-insensitively to the field names enabled in `fields`.
  //
  // Body:
  //   { csv: string, fields: { name, fqdn, ip, mac, description, stigs }, delimiter }
  //
  // Response:
  //   { imported: number, errors: string[] }
  //
  // The "name" field is always required — rows without a usable name value are
  // recorded as errors and skipped.  Other fields are applied only when their
  // flag is true AND a matching header column exists.
  //
  // The "stigs" cell is treated as a pipe-delimited (|) list of benchmarkIds,
  // matching the STIG Manager inventory CSV convention.
  app.post(
    '/collections/:id/assets/import',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)

      let body: ReturnType<typeof CsvImportBody.parse>
      try {
        body = CsvImportBody.parse(req.body)
      } catch (e) {
        return reply.code(400).send({ error: 'Invalid request body', details: (e as Error).message })
      }

      const { csv, fields, delimiter } = body

      // Parse the CSV — first row is the header
      const allRows = parseCsv(csv, delimiter)
      if (allRows.length < 2) {
        return reply.code(400).send({ error: 'CSV must contain a header row and at least one data row' })
      }

      const [headerRow, ...dataRows] = allRows

      // Build a map from column index → canonical field name.
      // Only columns whose field flag is enabled are included.
      const FIELD_NAMES = ['name', 'fqdn', 'ip', 'mac', 'description', 'stigs'] as const
      type FieldName = typeof FIELD_NAMES[number]

      const colMap: Record<number, FieldName> = {}
      for (let i = 0; i < headerRow.length; i++) {
        const h = headerRow[i].trim().toLowerCase()
        for (const f of FIELD_NAMES) {
          if (h === f && fields[f]) {
            colMap[i] = f
            break
          }
        }
      }

      // name column is mandatory
      const nameColIndex = Object.entries(colMap).find(([, v]) => v === 'name')?.[0]
      if (nameColIndex === undefined) {
        return reply.code(400).send({ error: 'CSV must include a "name" column and fields.name must be true' })
      }

      // Process each data row
      let imported = 0
      const errors: string[] = []

      for (let rowIdx = 0; rowIdx < dataRows.length; rowIdx++) {
        const row = dataRows[rowIdx]
        const rowNum = rowIdx + 2 // 1-indexed, +1 for header

        try {
          // Extract field values by column
          const getValue = (f: FieldName): string | undefined => {
            const idx = Object.entries(colMap).find(([, v]) => v === f)?.[0]
            if (idx === undefined) return undefined
            return row[Number(idx)]?.trim() ?? undefined
          }

          const name = getValue('name')
          if (!name) {
            errors.push(`Row ${rowNum}: missing required "name" value — skipped`)
            continue
          }

          // Get or create the asset
          const assetId = await ensureAsset(collectionId, name)

          // Patch optional scalar fields when present and non-empty
          const patch: Parameters<typeof updateAsset>[1] = {}
          for (const f of ['fqdn', 'ip', 'mac', 'description'] as const) {
            if (fields[f]) {
              const v = getValue(f)
              if (v !== undefined) {
                patch[f] = v || null
              }
            }
          }
          if (Object.keys(patch).length > 0) {
            await updateAsset(assetId, patch)
          }

          // Assign STIGs — cell value is pipe-delimited benchmarkId list
          if (fields.stigs) {
            const stigCell = getValue('stigs')
            if (stigCell) {
              const benchmarkIds = stigCell
                .split('|')
                .map(s => s.trim())
                .filter(Boolean)
              for (const benchmarkId of benchmarkIds) {
                await assignStigToAsset(assetId, benchmarkId)
              }
            }
          }

          imported++
        } catch (e) {
          errors.push(`Row ${rowNum}: ${(e as Error).message}`)
        }
      }

      return reply.code(200).send({ imported, errors })
    }
  )
}
