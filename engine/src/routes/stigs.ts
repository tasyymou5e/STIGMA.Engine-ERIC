// STIG library routes — catalog read/write (benchmarks, revisions, rules).
// All endpoints require a valid bearer token (app.authenticate).
// Mutation endpoints additionally require the 'stig-manager:stig' scope.
import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import {
  listStigs,
  getStig,
  deleteStig,
  listRevisions,
  getRevision,
  listRules,
  listGroups,
  getGroup,
  getRuleByRuleId,
  listCcis,
  getCciById
} from '../repositories/stigs.js'
import { importBenchmark } from '../engine/importBenchmark.js'

const SCOPE_STIG = 'stig-manager:stig'

// ---- Zod schemas -------------------------------------------------------

const ImportBody = z.object({
  content: z.string().min(1, 'content must be a non-empty XCCDF XML string')
})

const RulesQuery = z.object({
  projection: z.enum(['detail', 'cci']).optional()
})

const DiffQuery = z.object({
  rev1: z.string().min(1),
  rev2: z.string().min(1)
})

const CciListQuery = z.object({
  apAcronym: z.string().optional()
})

// ---- Helper to extract typed path params --------------------------------

function benchmarkIdOf(params: unknown): string {
  return (params as { benchmarkId: string }).benchmarkId
}

function revOf(params: unknown): string {
  return (params as { rev: string }).rev
}

// ---- Route registration -------------------------------------------------

export async function registerStigRoutes(app: FastifyInstance): Promise<void> {
  // GET /stigs — list all available STIGs (operationId: getSTIGs)
  app.get(
    '/stigs',
    { preHandler: [app.authenticate] },
    () => listStigs()
  )

  // POST /stigs — import a STIG benchmark from XCCDF XML (operationId: importBenchmark)
  app.post(
    '/stigs',
    { preHandler: [app.authenticate, requireScope(SCOPE_STIG)] },
    async (req, reply) => {
      const body = ImportBody.parse(req.body)
      const result = await importBenchmark(body.content)
      return reply.code(201).send(result)
    }
  )

  // GET /stigs/cci — list CCIs, optionally filtered by apAcronym
  // MUST be registered before /:benchmarkId to avoid param conflict.
  // (operationId: listCcis)
  app.get(
    '/stigs/cci',
    { preHandler: [app.authenticate] },
    async (req) => {
      const { apAcronym } = CciListQuery.parse(req.query)
      return listCcis({ apAcronym })
    }
  )

  // GET /stigs/cci/:cciId — single CCI lookup (operationId: getCciById)
  app.get(
    '/stigs/cci/:cciId',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { cciId } = req.params as { cciId: string }
      const record = await getCciById(cciId)
      return record ?? reply.code(404).send({ error: 'CCI not found' })
    }
  )

  // GET /stigs/rule/:ruleId — global rule lookup by ruleId (operationId: getRuleByRuleId)
  // MUST be registered before /:benchmarkId to avoid param conflict.
  app.get(
    '/stigs/rule/:ruleId',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { ruleId } = req.params as { ruleId: string }
      const rule = await getRuleByRuleId(ruleId)
      return rule ?? reply.code(404).send({ error: 'Rule not found' })
    }
  )

  // GET /stigs/:benchmarkId — single STIG metadata (operationId: getStigById)
  app.get(
    '/stigs/:benchmarkId',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const stig = await getStig(benchmarkIdOf(req.params))
      return stig ?? reply.code(404).send({ error: 'STIG not found' })
    }
  )

  // DELETE /stigs/:benchmarkId — delete STIG + all revisions (operationId: deleteStigById)
  app.delete(
    '/stigs/:benchmarkId',
    { preHandler: [app.authenticate, requireScope(SCOPE_STIG)] },
    async (req, reply) => {
      const deleted = await deleteStig(benchmarkIdOf(req.params))
      return deleted ?? reply.code(404).send({ error: 'STIG not found' })
    }
  )

  // GET /stigs/:benchmarkId/revisions — list revisions (operationId: getRevisionsByBenchmarkId)
  app.get(
    '/stigs/:benchmarkId/revisions',
    { preHandler: [app.authenticate] },
    (req) => listRevisions(benchmarkIdOf(req.params))
  )

  // GET /stigs/:benchmarkId/revisions/:rev — single revision; 'latest' supported
  // (operationId: getRevisionByString)
  app.get(
    '/stigs/:benchmarkId/revisions/:rev',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const revision = await getRevision(benchmarkIdOf(req.params), revOf(req.params))
      return revision ?? reply.code(404).send({ error: 'Revision not found' })
    }
  )

  // GET /stigs/:benchmarkId/revisions/:rev/rules?projection=detail|cci
  // (operationId: getRulesByRevision)
  app.get(
    '/stigs/:benchmarkId/revisions/:rev/rules',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { projection } = RulesQuery.parse(req.query)
      const revision = await getRevision(benchmarkIdOf(req.params), revOf(req.params))
      if (!revision) return reply.code(404).send({ error: 'Revision not found' })
      return listRules(revision.revId, projection)
    }
  )

  // GET /stigs/:benchmarkId/revisions/:rev/groups
  // (operationId: getGroupsByRevision)
  app.get(
    '/stigs/:benchmarkId/revisions/:rev/groups',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const revision = await getRevision(benchmarkIdOf(req.params), revOf(req.params))
      if (!revision) return reply.code(404).send({ error: 'Revision not found' })
      return listGroups(revision.revId)
    }
  )

  // GET /stigs/:benchmarkId/revisions/:rev/groups/:groupId
  // (operationId: getGroupByRevisionAndId)
  app.get(
    '/stigs/:benchmarkId/revisions/:rev/groups/:groupId',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const revision = await getRevision(benchmarkIdOf(req.params), revOf(req.params))
      if (!revision) return reply.code(404).send({ error: 'Revision not found' })
      const { groupId } = req.params as { benchmarkId: string; rev: string; groupId: string }
      const result = await getGroup(revision.revId, groupId)
      return result ?? reply.code(404).send({ error: 'Group not found' })
    }
  )

  // GET /stigs/:benchmarkId/revisions/diff?rev1=V1R1&rev2=V2R1
  // Returns added/removed/changed/unchanged diff between two revisions.
  // (operationId: diffRevisions)
  app.get(
    '/stigs/:benchmarkId/revisions/diff',
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const benchmarkId = benchmarkIdOf(req.params)
      const { rev1, rev2 } = DiffQuery.parse(req.query)

      const [revision1, revision2] = await Promise.all([
        getRevision(benchmarkId, rev1),
        getRevision(benchmarkId, rev2)
      ])
      if (!revision1) return reply.code(404).send({ error: `Revision not found: ${rev1}` })
      if (!revision2) return reply.code(404).send({ error: `Revision not found: ${rev2}` })

      const [rules1, rules2] = await Promise.all([
        listRules(revision1.revId),
        listRules(revision2.revId)
      ])

      const map1 = new Map(rules1.map(r => [r.ruleId, r]))
      const map2 = new Map(rules2.map(r => [r.ruleId, r]))

      const added = rules2.filter(r => !map1.has(r.ruleId))
      const removed = rules1.filter(r => !map2.has(r.ruleId))
      const changed: Array<{ before: typeof rules1[0]; after: typeof rules2[0] }> = []
      let unchanged = 0

      for (const r2 of rules2) {
        const r1 = map1.get(r2.ruleId)
        if (!r1) continue // already counted as added
        const isDifferent =
          r1.severity !== r2.severity ||
          r1.title !== r2.title ||
          r1.ruleVersion !== r2.ruleVersion
        if (isDifferent) {
          changed.push({ before: r1, after: r2 })
        } else {
          unchanged++
        }
      }

      return { added, removed, changed, unchanged }
    }
  )
}
