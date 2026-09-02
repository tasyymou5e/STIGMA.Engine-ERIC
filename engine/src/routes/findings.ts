// Findings + POA&M endpoints for a collection.
//
// GET /collections/:id/findings?aggregator=ruleId|groupId|cci&severity=high|medium|low
//   Returns open findings (fail reviews) aggregated by the chosen dimension.
//   Delegates to repositories/findings.ts which uses LEFT JOINs to rule/CCI
//   tables so the endpoint works regardless of whether the STIG library has
//   been imported.
//
// GET /collections/:id/poam
//   Returns the same open-findings data shaped for POA&M consumption: every
//   finding is enriched with its CCI array (sourced from rev_group_rule_cci_map)
//   so downstream tooling can map findings to NIST 800-53 controls.
//   Internally calls openFindings with aggregator='ruleId' (default) so the
//   CCI column is always populated when library data is present.

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import { openFindings, enrichFindingsForPoam } from '../repositories/findings.js'
import type { FindingRecord, CciFindingRecord } from '../repositories/findings.js'
import { toCSV } from '../export/csv.js'
import { getCollection, listCollections } from '../repositories/collections.js'
import { generatePoamXlsx, addPoamSheet } from '../export/poam.js'
import type { DbFindingRecord } from '../export/poam.js'
import ExcelJS from 'exceljs'
import { config } from '../config.js'

const SCOPE_COLLECTION = 'stig-manager:collection'

// ---------------------------------------------------------------------------
// Query-string schemas
// ---------------------------------------------------------------------------

const FindingsQuery = z.object({
  aggregator: z.enum(['ruleId', 'groupId', 'cci']).optional().default('ruleId'),
  severity: z.enum(['high', 'medium', 'low']).optional(),
  format: z.enum(['json', 'csv']).optional().default('json')
})

const PoamQuery = z.object({
  severity: z.enum(['high', 'medium', 'low']).optional()
})

const PoamEmassQuery = z.object({
  includeNA: z.coerce.boolean().default(false)
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function numId(params: unknown, key = 'id'): number {
  return Number((params as Record<string, string>)[key])
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function registerFindingsRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // GET /collections/:id/findings
  // operationId: getFindingsByCollection
  //
  // Query params:
  //   aggregator — 'ruleId' (default) | 'groupId' | 'cci'
  //   severity   — 'high' | 'medium' | 'low'  (omit = all severities)
  //
  // Response shape depends on aggregator:
  //   ruleId / groupId → FindingRecord[]
  //   cci              → CciFindingRecord[]
  app.get(
    '/collections/:id/findings',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const query = FindingsQuery.safeParse(req.query)
      if (!query.success) {
        return reply.code(400).send({ error: 'Invalid query parameters', details: query.error.flatten() })
      }
      const { aggregator, severity, format } = query.data
      const findings = await openFindings(collectionId, { aggregator, severity })
      if (format === 'csv') {
        // Flatten ccis array to a pipe-separated string for CSV compatibility
        const rows = (findings as unknown as Record<string, unknown>[]).map((f) => ({
          ...f,
          ccis: Array.isArray(f.ccis) ? (f.ccis as string[]).join('|') : (f.ccis ?? '')
        }))
        const columns = aggregator === 'cci'
          ? ['cci', 'ruleId', 'groupId', 'ruleVersion', 'severity', 'title', 'assetCount']
          : ['ruleId', 'groupId', 'ruleVersion', 'severity', 'title', 'assetCount', 'ccis']
        const csv = toCSV(rows, columns)
        return reply
          .header('Content-Type', 'text/csv; charset=utf-8')
          .header('Content-Disposition', `attachment; filename="findings-collection-${collectionId}.csv"`)
          .send(csv)
      }
      return findings
    }
  )

  // GET /collections/:id/poam
  // operationId: getPoamByCollection
  //
  // Returns findings shaped for POA&M export.  Always uses the ruleId
  // aggregator so every record carries its associated CCI list, which
  // downstream POA&M tools use to populate the "AP Acronym / Control" column.
  //
  // Optional query param:
  //   severity — 'high' | 'medium' | 'low'  (omit = all, i.e. all open findings)
  //
  // The response is a JSON array of PoamEntry objects, each wrapping a
  // FindingRecord with an explicit poamStatus field set to 'Ongoing' by default
  // (callers that track remediation timelines may override this field).
  app.get(
    '/collections/:id/poam',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const query = PoamQuery.safeParse(req.query)
      if (!query.success) {
        return reply.code(400).send({ error: 'Invalid query parameters', details: query.error.flatten() })
      }
      const { severity } = query.data

      // Always ruleId-aggregated so ccis is populated
      const findings = await openFindings(collectionId, { aggregator: 'ruleId', severity })

      // Shape each finding into a POAM entry
      const poam = (findings as FindingRecord[]).map((f) => ({
        ruleId: f.ruleId,
        groupId: f.groupId,
        ruleVersion: f.ruleVersion,
        severity: f.severity,
        title: f.title,
        assetCount: f.assetCount,
        ccis: f.ccis ?? [],
        // Derived NIST control acronyms from CCI prefix, e.g. "CCI-000001" → keep raw
        // so the client can do control mapping via a CCI-to-control reference table.
        poamStatus: 'Ongoing' as const
      }))

      return poam
    }
  )

  // GET /collections/:id/poam/emass.xlsx
  // operationId: getPoamEmassXlsx
  //
  // Produces an eMASS-compatible POA&M XLSX file matching the official
  // "Attachment 0030 - POAMImportTemplate RM Standard" layout (22 columns,
  // rows 1-6 metadata, row 7 headers, rows 8+ data, footer banner).
  //
  // Collection metadata keys used (stored in collection.metadata JSON):
  //   pocName, pocEmail, pocPhone, dodComponent, systemType,
  //   dodItRegNo, ombProjectId, securityCosts, exportedBy
  app.get(
    '/collections/:id/poam/emass.xlsx',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const qp = PoamEmassQuery.safeParse(req.query)
      if (!qp.success) {
        return reply.code(400).send({ error: 'Invalid query parameters', details: qp.error.flatten() })
      }
      const { includeNA } = qp.data

      const collection = await getCollection(collectionId)
      if (!collection) return reply.code(404).send({ error: 'Collection not found' })

      // Single enriched query — no N+1; fetches rule details, asset names,
      // NIST control, fix text, and STIG metadata in one pass.
      const enriched = await enrichFindingsForPoam(collectionId, includeNA)

      const meta = (collection.metadata ?? {}) as Record<string, string>
      const poamMeta = {
        pocName:       meta.pocName       ?? '',
        pocEmail:      meta.pocEmail      ?? '',
        pocPhone:      meta.pocPhone      ?? '',
        dodComponent:  meta.dodComponent  ?? '',
        systemType:    meta.systemType    ?? '',
        dodItRegNo:    meta.dodItRegNo    ?? '',
        ombProjectId:  meta.ombProjectId  ?? '',
        securityCosts: meta.securityCosts ?? '',
        exportedBy:    meta.exportedBy    ?? '',
      }

      const buf = await generatePoamXlsx(
        enriched,
        collection.name,
        config.CLASSIFICATION,
        poamMeta
      )

      const date = new Date().toISOString().slice(0, 10)
      const safeName = collection.name.replace(/[^A-Za-z0-9_\-. ]/g, '_').replace(/\s+/g, '_').slice(0, 60)

      return reply
        .header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        .header('Content-Disposition', `attachment; filename="POAM-eMASS-${safeName}-${date}.xlsx"`)
        .send(buf)
    }
  )

  // GET /collections/meta/poam/emass.xlsx
  // operationId: getMetaPoamEmassXlsx
  //
  // Produces a multi-sheet eMASS POA&M workbook where each accessible
  // collection becomes one worksheet named after the collection.
  //
  // Query params:
  //   includeNA — boolean (default false) — include notapplicable findings
  app.get(
    '/collections/meta/poam/emass.xlsx',
    { preHandler: guard },
    async (req, reply) => {
      const qp = PoamEmassQuery.safeParse(req.query)
      if (!qp.success) {
        return reply.code(400).send({ error: 'Invalid query parameters', details: qp.error.flatten() })
      }
      const { includeNA } = qp.data

      const collections = await listCollections()

      const wb = new ExcelJS.Workbook()
      wb.creator = 'STIGMA Engine'
      wb.created = new Date()

      for (const col of collections) {
        const findings = await enrichFindingsForPoam(col.collectionId, includeNA)
        const meta = (col.metadata ?? {}) as Record<string, string>
        const poamMeta = {
          pocName:       meta.pocName       ?? '',
          pocEmail:      meta.pocEmail      ?? '',
          pocPhone:      meta.pocPhone      ?? '',
          dodComponent:  meta.dodComponent  ?? '',
          systemType:    meta.systemType    ?? '',
          dodItRegNo:    meta.dodItRegNo    ?? '',
          ombProjectId:  meta.ombProjectId  ?? '',
          securityCosts: meta.securityCosts ?? '',
          exportedBy:    meta.exportedBy    ?? '',
        }
        addPoamSheet(wb, col.name, findings, col.name, config.CLASSIFICATION, poamMeta)
      }

      // If no collections exist, add a placeholder sheet so the workbook is valid
      if (collections.length === 0) {
        wb.addWorksheet('No Collections')
      }

      const buf = await wb.xlsx.writeBuffer()
      const date = new Date().toISOString().slice(0, 10)

      return reply
        .header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        .header('Content-Disposition', `attachment; filename="POAM-eMASS-ALL-${date}.xlsx"`)
        .send(Buffer.from(buf))
    }
  )
}

// ---------------------------------------------------------------------------
// Re-export types so callers can import from this module if convenient
// ---------------------------------------------------------------------------
export type { FindingRecord, CciFindingRecord }
export type { DbFindingRecord }
