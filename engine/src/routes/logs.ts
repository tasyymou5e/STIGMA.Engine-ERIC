// Log API routes — reads from MySQL app_log table.
// GET /op/logs          — paginated query with filters
// GET /op/logs/stream   — SSE real-time stream (token in ?token= for EventSource)
// GET /op/logs/dates    — available log dates
// GET /op/logs/stats    — counts by level

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { appLog, logEmitter, queryLogs, getLogDates, type LogLevel, type LogCategory } from '../utils/appLogger.js'
import { verifyToken } from '../auth/jwt.js'

export async function registerLogsRoutes(app: FastifyInstance): Promise<void> {

  // ── GET /op/logs ────────────────────────────────────────────────────────────
  app.get('/op/logs', { preHandler: [app.authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const q = req.query as Record<string, string>
    try {
      const entries = await queryLogs({
        level:    q.level    as LogLevel    | undefined,
        category: q.category as LogCategory | undefined,
        search:   q.search,
        since:    q.since,
        limit:    q.limit ? parseInt(q.limit, 10) : 500,
        date:     q.date,
      })
      return entries
    } catch (e) {
      appLog.err('system', 'Failed to query logs', e)
      return reply.status(500).send({ error: 'Failed to read logs' })
    }
  })

  // ── GET /op/logs/dates ──────────────────────────────────────────────────────
  app.get('/op/logs/dates', { preHandler: [app.authenticate] }, async (_req, reply: FastifyReply) => {
    try {
      return await getLogDates()
    } catch (e) {
      return reply.status(500).send({ error: 'Failed to fetch log dates' })
    }
  })


  // ── GET /op/logs/stream — SSE real-time ─────────────────────────────────────
  // EventSource cannot send Authorization headers — accept ?token= query param.
  app.get('/op/logs/stream', async (req: FastifyRequest, reply: FastifyReply) => {
    const q = req.query as Record<string, string>

    // Auth: Authorization header OR ?token= query param (for EventSource)
    const rawToken = req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : (q.token ?? null)

    if (!rawToken) return reply.code(401).send({ error: 'Missing token' })
    try { await verifyToken(rawToken) }
    catch { return reply.code(401).send({ error: 'Invalid token' }) }

    reply.raw.setHeader('Content-Type',      'text/event-stream')
    reply.raw.setHeader('Cache-Control',     'no-cache')
    reply.raw.setHeader('Connection',        'keep-alive')
    reply.raw.setHeader('X-Accel-Buffering', 'no')
    reply.raw.flushHeaders()

    // Backfill: last 100 entries from DB
    try {
      const recent = await queryLogs({ limit: 100 })
      for (const entry of recent) {
        reply.raw.write(`data: ${JSON.stringify(entry)}\n\n`)
      }
    } catch { /* skip backfill on error */ }

    // Live stream via EventEmitter
    function onEntry(entry: unknown) {
      const e = entry as import('../utils/appLogger.js').LogEntry
      if (q.level    && e.level    !== q.level)    return
      if (q.category && e.category !== q.category) return
      if (q.search   && !JSON.stringify(e).toLowerCase().includes(q.search.toLowerCase())) return
      try { reply.raw.write(`data: ${JSON.stringify(e)}\n\n`) } catch { /* closed */ }
    }

    logEmitter.on('entry', onEntry)

    // Keepalive every 20s
    const ka = setInterval(() => {
      try { reply.raw.write(': keepalive\n\n') } catch { clearInterval(ka) }
    }, 20_000)

    req.raw.on('close', () => {
      clearInterval(ka)
      logEmitter.off('entry', onEntry)
    })

    await new Promise<void>(resolve => req.raw.once('close', resolve))
  })
}
