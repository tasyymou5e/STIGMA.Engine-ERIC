import Fastify, { type FastifyInstance } from 'fastify'
import cors from '@fastify/cors'
import multipart from '@fastify/multipart'
import { ZodError } from 'zod'
import { Registry, collectDefaultMetrics, Counter, Gauge } from 'prom-client'
import type { RowDataPacket } from 'mysql2'
import { config } from './config.js'
import { authPlugin } from './auth/plugin.js'
import { pool, type Row } from './db/pool.js'
import { registerRoutes } from './routes/index.js'
import { registerStigRoutes } from './routes/stigs.js'
import { registerAssetRoutes } from './routes/assets.js'
import { registerReviewRoutes } from './routes/reviews.js'
import { registerFindingsRoutes } from './routes/findings.js'
import { registerMetricsRoutes } from './routes/metrics.js'
import { registerGrantRoutes } from './routes/grants.js'
import { registerLabelRoutes } from './routes/labels.js'
import { registerUserRoutes } from './routes/users.js'
import { registerExportRoutes } from './routes/exports.js'
import { registerAttachmentRoutes } from './routes/attachments.js'
import { registerImportRoutes } from './routes/import.js'
import { registerMetadataRoutes } from './routes/metadata.js'
import { registerCollectionStigRoutes } from './routes/collection-stigs.js'
import { registerEvalStigRoutes, startEvalStigMonitor } from './routes/eval-stig.js'
import { registerLogsRoutes } from './routes/logs.js'
import { startReviewAgingScheduler } from './routes/tasks.js'
import { appLog, initLoggerDb } from './utils/appLogger.js'

const registry = new Registry()
collectDefaultMetrics({ register: registry })

// ── Custom metrics ────────────────────────────────────────────────────────────

const httpRequestsTotal = new Counter({
  name: 'stigman_http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [registry]
})

// Scalar gauges (existing)
const reviewsTotal = new Gauge({
  name: 'stigman_reviews_total',
  help: 'Total reviews in DB',
  registers: [registry]
})
const collectionsTotal = new Gauge({
  name: 'stigman_collections_total',
  help: 'Total collections',
  registers: [registry]
})

// 1. Per-collection compliance percentage
const collectionCompliancePct = new Gauge({
  name: 'stigman_collection_compliance_pct',
  help: 'Compliance percentage per collection (pass/(pass+fail)*100)',
  labelNames: ['collection_id', 'collection_name'],
  registers: [registry]
})

// 2. Open findings by collection and severity
const collectionFindingsTotal = new Gauge({
  name: 'stigman_collection_findings_total',
  help: 'Open (fail) reviews by collection and severity',
  labelNames: ['collection_id', 'collection_name', 'severity'],
  registers: [registry]
})

// 3. Reviews grouped by result
const reviewsByResultTotal = new Gauge({
  name: 'stigman_reviews_by_result_total',
  help: 'Total reviews grouped by result value',
  labelNames: ['result'],
  registers: [registry]
})

// 4. Reviews grouped by status
const reviewsByStatusTotal = new Gauge({
  name: 'stigman_reviews_by_status_total',
  help: 'Total reviews grouped by status value',
  labelNames: ['status'],
  registers: [registry]
})

// 5. Assets per collection
const collectionAssetsTotal = new Gauge({
  name: 'stigman_collection_assets_total',
  help: 'Number of assets per collection',
  labelNames: ['collection_id', 'collection_name'],
  registers: [registry]
})

// 6. STIGs in library
const stigsTotal = new Gauge({
  name: 'stigman_stigs_total',
  help: 'Total STIG benchmarks in library',
  registers: [registry]
})

// 7. Rules in library
const rulesTotal = new Gauge({
  name: 'stigman_rules_total',
  help: 'Total rules across all imported STIG revisions',
  registers: [registry]
})

// 8. Assets total (enabled)
const assetsTotal = new Gauge({
  name: 'stigman_assets_total',
  help: 'Total enabled assets across all collections',
  registers: [registry]
})

// ── Metrics cache ─────────────────────────────────────────────────────────────
let lastRefreshed = 0
const REFRESH_INTERVAL_MS = 30_000

async function refreshMetrics(): Promise<void> {
  const now = Date.now()
  if (now - lastRefreshed < REFRESH_INTERVAL_MS) return
  lastRefreshed = now

  // Existing scalar gauges
  try {
    const [rows] = await pool.query<Row[]>('SELECT COUNT(*) AS n FROM review')
    reviewsTotal.set(Number(rows[0]?.n ?? 0))
  } catch {}

  try {
    const [rows] = await pool.query<Row[]>('SELECT COUNT(*) AS n FROM collection')
    collectionsTotal.set(Number(rows[0]?.n ?? 0))
  } catch {}

  // 1. Per-collection compliance percentage
  try {
    const sql = `
      SELECT c.collectionId, c.name,
        ROUND(SUM(rv.result="pass") / NULLIF(SUM(rv.result IN ("pass","fail")),0) * 100, 1) AS pct
      FROM collection c
      LEFT JOIN asset a ON a.collectionId=c.collectionId
      LEFT JOIN review rv ON rv.assetId=a.assetId
      GROUP BY c.collectionId, c.name`
    const [rows] = await pool.query<RowDataPacket[]>(sql)
    collectionCompliancePct.reset()
    for (const row of rows) {
      collectionCompliancePct
        .labels(String(row.collectionId), String(row.name))
        .set(Number(row.pct ?? 0))
    }
  } catch {}

  // 2. Open findings by collection and severity
  try {
    const sql = `
      SELECT c.collectionId, c.name, rv.severity, COUNT(*) AS cnt
      FROM review rv
      JOIN asset a ON a.assetId=rv.assetId
      JOIN collection c ON c.collectionId=a.collectionId
      WHERE rv.result="fail"
      GROUP BY c.collectionId, c.name, rv.severity`
    const [rows] = await pool.query<RowDataPacket[]>(sql)
    collectionFindingsTotal.reset()
    for (const row of rows) {
      collectionFindingsTotal
        .labels(String(row.collectionId), String(row.name), String(row.severity ?? ''))
        .set(Number(row.cnt))
    }
  } catch {}

  // 3. Reviews by result
  try {
    const [rows] = await pool.query<RowDataPacket[]>('SELECT result, COUNT(*) AS cnt FROM review GROUP BY result')
    reviewsByResultTotal.reset()
    for (const row of rows) {
      reviewsByResultTotal.labels(String(row.result ?? '')).set(Number(row.cnt))
    }
  } catch {}

  // 4. Reviews by status
  try {
    const [rows] = await pool.query<RowDataPacket[]>('SELECT status, COUNT(*) AS cnt FROM review GROUP BY status')
    reviewsByStatusTotal.reset()
    for (const row of rows) {
      reviewsByStatusTotal.labels(String(row.status ?? '')).set(Number(row.cnt))
    }
  } catch {}

  // 5. Assets per collection
  try {
    const sql = `
      SELECT c.collectionId, c.name, COUNT(a.assetId) AS cnt
      FROM collection c
      LEFT JOIN asset a ON a.collectionId=c.collectionId
      GROUP BY c.collectionId, c.name`
    const [rows] = await pool.query<RowDataPacket[]>(sql)
    collectionAssetsTotal.reset()
    for (const row of rows) {
      collectionAssetsTotal
        .labels(String(row.collectionId), String(row.name))
        .set(Number(row.cnt))
    }
  } catch {}

  // 6. STIGs in library
  try {
    const [rows] = await pool.query<RowDataPacket[]>('SELECT COUNT(*) AS n FROM stig')
    stigsTotal.set(Number((rows[0] as RowDataPacket)?.n ?? 0))
  } catch {}

  // 7. Rules in library
  try {
    const [rows] = await pool.query<RowDataPacket[]>('SELECT COUNT(*) AS n FROM rule')
    rulesTotal.set(Number((rows[0] as RowDataPacket)?.n ?? 0))
  } catch {}

  // 8. Enabled assets total
  try {
    const [rows] = await pool.query<RowDataPacket[]>('SELECT COUNT(*) AS n FROM asset WHERE state="enabled" OR state IS NULL')
    assetsTotal.set(Number((rows[0] as RowDataPacket)?.n ?? 0))
  } catch {}
}

export async function buildServer(): Promise<FastifyInstance> {
  const app = Fastify({ logger: true, bodyLimit: 10 * 1024 * 1024 })

  await app.register(cors, { origin: config.CORS_ORIGIN })
  // Enable multipart parsing for file upload endpoints (attachment routes).
  await app.register(multipart)

  app.addHook("onSend", async (_req, reply) => {
    reply.header("X-Classification", config.CLASSIFICATION)
  })

  // Run auth decorators on the ROOT instance (not via register, which would
  // encapsulate them in a child scope and leave app.authenticate undefined
  // for the routes registered below).
  await authPlugin(app)

  // Map validation errors to 400, Fastify built-in client errors to their
  // status + message (already safe), and all server errors to a generic 500
  // message to avoid leaking internal details.
  app.setErrorHandler((err: Error & { statusCode?: number }, _req, reply) => {
    if (err instanceof ZodError) {
      return reply.code(400).send({ error: 'validation', issues: err.issues })
    }
    if (err.statusCode && err.statusCode < 500) {
      return reply.code(err.statusCode).send({ error: err.message })
    }
    app.log.error(err)
    return reply.code(500).send({ error: 'Internal server error' })
  })

  app.addHook('onResponse', (req, reply, done) => {
    httpRequestsTotal.inc({ method: req.method, route: req.routeOptions?.url ?? req.url, status: String(reply.statusCode) })
    done()
  })

  app.get('/metrics', async (_req, reply) => {
    await refreshMetrics()
    reply.header('Content-Type', registry.contentType)
    return registry.metrics()
  })

  app.get('/health', async () => ({ status: 'ok' }))

  // All domain endpoints under /api.
  await app.register(async (instance) => registerRoutes(instance), { prefix: '/api' })
  await app.register(async i => registerStigRoutes(i), { prefix: '/api' })
  await app.register(async i => registerAssetRoutes(i), { prefix: '/api' })
  await app.register(async i => registerReviewRoutes(i), { prefix: '/api' })
  await app.register(async i => registerFindingsRoutes(i), { prefix: '/api' })
  await app.register(async i => registerMetricsRoutes(i), { prefix: '/api' })
  await app.register(async i => registerGrantRoutes(i), { prefix: '/api' })
  await app.register(async i => registerLabelRoutes(i), { prefix: '/api' })
  await app.register(async i => registerUserRoutes(i), { prefix: '/api' })
  await app.register(async i => registerExportRoutes(i), { prefix: '/api' })
  await app.register(async i => registerAttachmentRoutes(i), { prefix: '/api' })
  await app.register(async i => registerImportRoutes(i), { prefix: '/api' })
  await app.register(async i => registerMetadataRoutes(i), { prefix: '/api' })
  await app.register(async i => registerCollectionStigRoutes(i), { prefix: '/api' })
  await app.register(async i => registerEvalStigRoutes(i), { prefix: '/api' })
  startEvalStigMonitor(app.log)
  startReviewAgingScheduler(app.log)
  await app.register(async i => registerLogsRoutes(i), { prefix: '/api' })

  // Wire DB pool into the logger so entries are persisted to app_log table
  initLoggerDb(pool)

  // Hook Fastify lifecycle into structured appLog
  app.addHook('onResponse', async (req, reply) => {
    const ms  = Math.round(reply.elapsedTime)
    const uid = (req as any).user?.sub as string | undefined
    appLog.api(req.method, req.routeOptions?.url ?? req.url, reply.statusCode, ms, uid)
  })

  app.addHook('onError', async (req, _reply, error) => {
    appLog.err('api', `Unhandled error: ${req.method} ${req.url}`, error, { url: req.url })
  })

  appLog.info('system', 'STIGMA Engine started')

  return app
}
