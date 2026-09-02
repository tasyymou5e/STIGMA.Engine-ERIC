// Aggregates all route plugins under a single registrable function.
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'
import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import { config } from '../config.js'

// Resolve package.json relative to this compiled file's directory tree
const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
// Works from both src/ (tsx dev) and dist/ (compiled) because package.json is always two levels up
function readPackageVersion(): string {
  for (const rel of ['../../package.json', '../../../package.json']) {
    try {
      const raw = readFileSync(resolve(__dirname, rel), 'utf-8')
      return (JSON.parse(raw) as { version?: string }).version ?? '0.0.0'
    } catch {
      // try next path
    }
  }
  return '0.0.0'
}
const APP_VERSION = readPackageVersion()
import type { RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'
import { listCollections, getCollection, createCollection, updateCollection, deleteCollection, cloneCollection } from '../repositories/collections.js'
import { listReviewsByAsset, listReviewsByCollection } from '../repositories/reviews.js'
import { registerTaskRoutes } from './tasks.js'
import { listRemediationRuns, recordRemediationRun } from '../repositories/runs.js'
import { openFindings } from '../engine/metrics.js'
import { ingestChecklist } from '../engine/ingest.js'
import { getUserBySub, updateWebPreferences } from '../repositories/users.js'
import { generatePoamXlsx, openFindingToRecord } from '../export/poam.js'

const SCOPE_COLLECTION = 'stig-manager:collection'
const SCOPE_STIG = 'stig-manager:stig'

function idOf(params: unknown, key = 'id'): number {
  const raw = (params as Record<string, string>)[key]
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0) throw Object.assign(new Error(`Invalid id: ${raw}`), { statusCode: 400 })
  return n
}

export async function registerRoutes(app: FastifyInstance): Promise<void> {
  // Tables eligible for app-data export (in dependency order)
  const EXPORT_TABLES = [
    'collection',
    'asset',
    'stig',
    'revision',
    'rule',
    'stig_asset_map',
    'collection_grant',
    'collection_label',
    'collection_label_asset_map',
    'user_data',
    'user_group',
    'user_group_user_map',
    'review',
  ] as const

  // --- op/appinfo (no auth) ---
  app.get('/op/appinfo', async () => ({
    version: APP_VERSION,
    node: process.version,
    db: 'MySQL 8',
    commit: 'ERIC rewrite'
  }))

  // --- op/watchdog (no auth) — reads the watchdog log mounted at /app/scripts/watchdog.log ---
  app.get('/op/watchdog', async () => {
    const { statSync, readFileSync: rfs } = await import('fs')
    const { join } = await import('path')
    const logPath   = join(__dirname, '../../scripts/watchdog.log')
    const taskName  = 'STIGMA-Engine-Watchdog'
    const scriptPath = join(__dirname, '../../scripts/watchdog.ps1')
    const installCmd = `pwsh -File "${scriptPath}"`
    const setupCmd   = `pwsh -File "${join(__dirname, '../../scripts/setup-watchdog.ps1')}"`

    // Read log to determine watchdog health
    let logExists = false
    let lastLine = ''
    let lastWritten: string | null = null
    let isRunning = false
    try {
      const stat = statSync(logPath)
      logExists = true
      lastWritten = stat.mtime.toISOString()
      // Running = log written within last 3 minutes
      isRunning = (Date.now() - stat.mtimeMs) < 180_000
      const lines = rfs(logPath, 'utf8').trim().split('\n')
      lastLine = lines[lines.length - 1] ?? ''
    } catch { /* log not mounted or not yet created */ }

    return {
      taskName,
      installed: logExists,
      running: isRunning,
      lastWritten,
      lastLogLine: lastLine,
      scriptPath,
      installCommand: installCmd,
      setupCommand: setupCmd,
      // Commands to show in the UI for manual install
      manualInstall: [
        `# Run in an elevated PowerShell terminal on the Windows host:`,
        setupCmd,
        `# Or start immediately without a persistent task:`,
        installCmd
      ].join('\n')
    }
  })

  // --- op/definition (no auth) ---
  app.get('/op/definition', async () => ({
    name: 'STIGMA.Engine',
    description: 'STIG Manager rewrite on the Tech stack',
    version: APP_VERSION
  }))

  // --- op/configuration (no auth) ---
  app.get('/op/configuration', async () => {
    let dbVersion = 'unknown'
    try {
      const [rows] = await pool.query<RowDataPacket[]>('SELECT VERSION() AS v')
      dbVersion = String((rows[0] as { v: string }).v ?? 'unknown')
    } catch { /* ignore */ }
    return {
      allowInsecureTokens: config.ALLOW_INSECURE_TOKENS ?? false,
      oidcIssuer: config.OIDC_ISSUER,
      corsOrigin: config.CORS_ORIGIN,
      dbHost: config.DB_HOST,
      dbName: config.DB_NAME,
      nodeVersion: process.version,
      dbVersion,
      classification: config.CLASSIFICATION
    }
  })

  // --- op/appdata/tables (no auth) ---
  app.get('/op/appdata/tables', async () => {
    // Discover which export tables actually exist in the current DB
    const placeholders = EXPORT_TABLES.map(() => '?').join(',')
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT table_name AS name, table_rows AS rowCount
       FROM information_schema.tables
       WHERE table_schema = DATABASE()
         AND table_name IN (${placeholders})
       ORDER BY FIELD(table_name, ${placeholders})`,
      [...EXPORT_TABLES, ...EXPORT_TABLES]
    )
    return rows.map((r) => ({ name: String(r.name), rowCount: Number(r.rowCount ?? 0) }))
  })

  // --- op/appdata (streaming JSON export, no auth) ---
  app.get('/op/appdata', async (_req, reply) => {
    const date = new Date().toISOString().slice(0, 10)

    reply.raw.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="stigman-backup-${date}.json"`
    })

    // Discover which tables actually exist so we don't error on missing ones
    const placeholders = EXPORT_TABLES.map(() => '?').join(',')
    const [existingRows] = await pool.query<RowDataPacket[]>(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = DATABASE() AND table_name IN (${placeholders})`,
      [...EXPORT_TABLES]
    )
    const existingSet = new Set(existingRows.map((r) => String(r.table_name)))
    const tablesToExport = EXPORT_TABLES.filter((t) => existingSet.has(t))

    reply.raw.write(`{"version":${JSON.stringify(APP_VERSION)},"exportedAt":${JSON.stringify(new Date().toISOString())},"tables":{`)

    let firstTable = true
    for (const tableName of tablesToExport) {
      if (!firstTable) reply.raw.write(',')
      firstTable = false
      reply.raw.write(`${JSON.stringify(tableName)}:[`)

      // Stream rows in pages to avoid loading large tables into memory
      const PAGE_SIZE = 500
      let offset = 0
      let firstRow = true
      while (true) {
        const [rows] = await pool.query<RowDataPacket[]>(
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          `SELECT * FROM \`${tableName}\` LIMIT ? OFFSET ?` as any,
          [PAGE_SIZE, offset]
        )
        for (const row of rows) {
          if (!firstRow) reply.raw.write(',')
          firstRow = false
          reply.raw.write(JSON.stringify(row))
        }
        if (rows.length < PAGE_SIZE) break
        offset += PAGE_SIZE
      }

      reply.raw.write(']')
    }

    reply.raw.write('}}')
    reply.raw.end()
    // Tell Fastify not to send its own response
    return reply
  })

  // --- op/state helpers ---
  async function fetchOpState() {
    const sql = `
      SELECT
        (SELECT COUNT(*) FROM collection)                AS collectionCount,
        (SELECT COUNT(*) FROM asset)                     AS assetCount,
        (SELECT COUNT(*) FROM review)                    AS reviewCount,
        (SELECT COUNT(*) FROM user_data)                 AS userCount,
        (SELECT COUNT(*) FROM stig)                      AS stigCount,
        VERSION()                                        AS dbVersion`
    try {
      const [rows] = await pool.query<RowDataPacket[]>(sql)
      const row = rows[0] ?? {}
      return {
        collectionCount: Number(row.collectionCount ?? 0),
        assetCount:      Number(row.assetCount      ?? 0),
        reviewCount:     Number(row.reviewCount     ?? 0),
        userCount:       Number(row.userCount       ?? 0),
        stigCount:       Number(row.stigCount       ?? 0),
        dbVersion:       String(row.dbVersion       ?? 'unknown'),
        ts:              new Date().toISOString()
      }
    } catch {
      return { collectionCount: 0, assetCount: 0, reviewCount: 0, userCount: 0, stigCount: 0, dbVersion: 'unknown', ts: new Date().toISOString() }
    }
  }

  // --- op/state (snapshot, no auth) ---
  app.get('/op/state', async () => fetchOpState())

  // --- op/state/sse (SSE real-time state, no auth) ---
  app.get('/op/state/sse', async (req, reply) => {
    reply.raw.writeHead(200, {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no'
    })

    // Helper to write an SSE event
    const sendState = async () => {
      const state = await fetchOpState()
      reply.raw.write(`event: state\ndata: ${JSON.stringify(state)}\n\n`)
    }

    // Send initial state immediately
    await sendState()

    // Keepalive comment every 30 s keeps proxies from killing the connection
    const keepalive = setInterval(() => {
      reply.raw.write(': keepalive\n\n')
    }, 30_000)

    // Clean up when the client disconnects
    req.raw.on('close', () => {
      clearInterval(keepalive)
    })

    // Never resolve — Fastify must not send a final response
    await new Promise<void>((resolve) => req.raw.on('close', resolve))
  })

  // --- whoami ---
  app.get('/user', { preHandler: [app.authenticate] }, async (req) => ({
    sub: req.user.sub,
    userId: req.userId,           // numeric DB primary key, 0 if DB unavailable
    username: req.user.username,
    scopes: [...req.user.scopes],
    privileges: Object.fromEntries([...req.user.roles].map((r) => [r, true]))
  }))

  // --- user web-preferences ---
  const WebPreferencesBody = z.record(z.unknown())
  app.patch('/user/web-preferences', { preHandler: [app.authenticate] }, async (req, reply) => {
    const prefs = WebPreferencesBody.parse(req.body)
    if (req.userId === 0) {
      // If upsert failed during auth the userId is unknown; fetch by sub as a fallback.
      const record = await getUserBySub(req.user.sub)
      if (!record) return reply.code(404).send({ error: 'user record not found' })
      await updateWebPreferences(record.userId, prefs)
    } else {
      await updateWebPreferences(req.userId, prefs)
    }
    return { updated: true }
  })

  // --- collections ---
  app.get('/collections', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, () => listCollections())

  app.get('/collections/:id', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, async (req, reply) => {
    const c = await getCollection(idOf(req.params))
    return c ?? reply.code(404).send({ error: 'collection not found' })
  })

  const CollectionBody = z.object({
    name: z.string().min(1),
    description: z.string().optional(),
    metadata: z.record(z.string()).optional()
  })
  app.post('/collections', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, async (req, reply) => {
    const body = CollectionBody.parse(req.body)
    const id = await createCollection(body)
    return reply.code(200).send(await getCollection(id))
  })

  const CollectionPatchBody = z.object({
    name: z.string().min(1).optional(),
    description: z.string().nullable().optional(),
    metadata: z.record(z.string()).nullable().optional(),
    settings: z.record(z.unknown()).nullable().optional()
  })
  app.patch('/collections/:id', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, async (req, reply) => {
    const id = idOf(req.params)
    const existing = await getCollection(id)
    if (!existing) return reply.code(404).send({ error: 'collection not found' })
    const body = CollectionPatchBody.parse(req.body)
    await updateCollection(id, body)
    return getCollection(id)
  })

  app.delete('/collections/:id', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, async (req, reply) => {
    const id = idOf(req.params)
    const existing = await getCollection(id)
    if (!existing) return reply.code(404).send({ error: 'collection not found' })
    await deleteCollection(id)
    return reply.code(204).send()
  })

  const CollectionCloneBody = z.object({
    name: z.string().min(1),
    description: z.string().optional(),
    options: z.object({
      grants: z.boolean().optional(),
      labels: z.boolean().optional(),
      assets: z.boolean().optional()
    }).optional()
  })
  app.post('/collections/:id/clones', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, async (req, reply) => {
    const sourceId = idOf(req.params)
    const source = await getCollection(sourceId)
    if (!source) return reply.code(404).send({ error: 'collection not found' })
    const body = CollectionCloneBody.parse(req.body)
    const newId = await cloneCollection(
      sourceId,
      { name: body.name, description: body.description },
      body.options ?? {}
    )
    return reply.code(201).send(await getCollection(newId))
  })

  // NOTE: Asset CRUD routes (GET /assets, GET /assets/:id, PATCH /assets/:id,
  // DELETE /assets/:id, etc.) are registered by routes/assets.ts (Phase 6).
  // GET /collections/:id/assets and POST /collections/:id/assets were here
  // previously but have been removed to avoid duplicate route conflicts.

  // --- reviews ---
  app.get('/assets/:id/reviews', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, (req) =>
    listReviewsByAsset(idOf(req.params))
  )

  // PATCH /assets/:assetId/reviews is handled by routes/reviews.ts (Phase 2)

  // --- ingest (engine) ---
  const IngestBody = z.object({ content: z.string().min(1), source: z.enum(['ckl', 'cklb', 'xccdf']).optional() })
  app.post(
    '/collections/:id/ingest',
    { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION, SCOPE_STIG)] },
    async (req, reply) => {
      const body = IngestBody.parse(req.body)
      const result = await ingestChecklist(idOf(req.params), body.content, req.user.username, body.source)
      return reply.code(201).send(result)
    }
  )

  // NOTE: Metrics routes are registered by routes/metrics.ts (registerMetricsRoutes).
  // GET /collections/:id/metrics and sub-routes must NOT be duplicated here.

  // NOTE: GET /collections/:id/findings is now registered by routes/findings.ts (Phase 3)
  // and must NOT be duplicated here.

  // --- POA&M XLSX export ---
  app.get('/collections/:id/poam.xlsx', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, async (req, reply) => {
    const id = idOf(req.params)
    const collection = await getCollection(id)
    if (!collection) return reply.code(404).send({ error: 'collection not found' })

    const reviews = await listReviewsByCollection(id)
    const findings = openFindings(reviews).map(openFindingToRecord)
    // Adapt legacy FindingRecord to DbFindingRecord for the updated generatePoamXlsx
    const dbFindings = findings.map((f) => ({
      ruleId:      f.ruleId,
      groupId:     '',
      ruleVersion: f.ruleVersion,
      severity:    f.severity ?? 'unknown',
      title:       f.title,
      assetCount:  0,
      ccis:        f.ccis,
    }))
    const buf = await generatePoamXlsx(dbFindings, collection.name)

    const date = new Date().toISOString().slice(0, 10)
    const safeName = collection.name.replace(/[^A-Za-z0-9_-]/g, '_')

    return reply
      .header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
      .header('Content-Disposition', `attachment; filename="POAM-${safeName}-${date}.xlsx"`)
      .send(buf)
  })

  // --- service jobs + review-aging task-config (delegated to routes/tasks.ts) ---
  await registerTaskRoutes(app)

  // --- remediation tracking ---
  app.get('/assets/:id/remediation-runs', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, (req) =>
    listRemediationRuns(idOf(req.params))
  )

  const RemediationBody = z.object({
    tool: z.string().min(1),
    applied: z.number().int().nonnegative().default(0),
    manual: z.number().int().nonnegative().default(0),
    skipped: z.number().int().nonnegative().default(0),
    notes: z.string().optional()
  })
  app.post('/assets/:id/remediation-runs', { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] }, async (req, reply) => {
    const body = RemediationBody.parse(req.body)
    const remediationId = await recordRemediationRun({ assetId: idOf(req.params), username: req.user.username, ...body })
    return reply.code(201).send({ remediationId })
  })
}
