// Structured application logger — writes to MySQL app_log table.
// Also fires an in-process EventEmitter so SSE subscribers get live entries.
//
// Usage:
//   import { appLog, initLoggerDb } from './utils/appLogger.js'
//   initLoggerDb(pool)   ← call once after pool is ready (in server.ts)
//   appLog.info('system', 'Engine started')

import { EventEmitter } from 'events'
import type { Pool } from 'mysql2/promise'
import mysql from 'mysql2/promise'
import { config } from '../config.js'

export type LogLevel    = 'debug' | 'info' | 'warn' | 'error'
export type LogCategory =
  | 'system' | 'auth' | 'import' | 'review' | 'job'
  | 'eval-stig' | 'metrics' | 'db' | 'export' | 'stig' | 'api'

export interface LogEntry {
  id?:      number
  ts:       string        // ISO-8601
  level:    LogLevel
  category: LogCategory
  msg:      string
  data?:    Record<string, unknown>
  err?:     string
  userId?:  string
  ms?:      number
}

// ── EventEmitter for SSE ──────────────────────────────────────────────────────

export const logEmitter = new EventEmitter()
logEmitter.setMaxListeners(200)

// ── DB pool reference (injected after server start) ───────────────────────────

// Logger uses its own pool WITHOUT namedPlaceholders so positional ? params work.
let _pool: Pool | null = null

export function initLoggerDb(_sourcePool: Pool): void {
  // Create a dedicated pool WITHOUT namedPlaceholders so positional ? params work.
  _pool = mysql.createPool({
    host:             config.DB_HOST,
    port:             config.DB_PORT,
    user:             config.DB_USER,
    password:         config.DB_PASSWORD,
    database:         config.DB_NAME,
    connectionLimit:  3,
    namedPlaceholders: false,
  })
  // Flush anything queued before the pool was ready
  if (_queue.length > 0) flushQueue()
  // Auto-purge entries older than 14 days every hour
  setInterval(purgeLogs, 60 * 60 * 1000)
  appLog.info('system', 'Logger connected to database', { data: { table: 'app_log' } })
}

async function purgeLogs(): Promise<void> {
  if (!_pool) return
  try {
    await _pool.execute(
      `DELETE FROM app_log WHERE ts < DATE_SUB(NOW(), INTERVAL 14 DAY)`
    )
  } catch { /* silently ignore */ }
}

// ── Write ─────────────────────────────────────────────────────────────────────

// Write queue — batched every 100ms to avoid per-request round-trips
const _queue: LogEntry[] = []
let   _flushTimer: ReturnType<typeof setTimeout> | null = null

function scheduleFlush(): void {
  if (_flushTimer) return
  _flushTimer = setTimeout(flushQueue, 100)
}

async function flushQueue(): Promise<void> {
  _flushTimer = null
  if (!_pool || _queue.length === 0) return
  const batch = _queue.splice(0, _queue.length)
  try {
    // Convert ISO-8601 (2026-05-31T01:38:11.916Z) → MySQL DATETIME (2026-05-31 01:38:11.916)
  const toMysqlTs = (iso: string) => iso.replace('T', ' ').replace('Z', '')

  const values = batch.map(e => [
      toMysqlTs(e.ts),
      e.level,
      e.category,
      e.msg,
      e.data ? JSON.stringify(e.data) : null,
      e.err  ?? null,
      e.userId ?? null,
      e.ms   ?? null,
    ])
    const placeholders = values.map(() => '(?,?,?,?,?,?,?,?)').join(',')
    await _pool.execute(
      `INSERT INTO app_log (ts, level, category, msg, data_json, err_text, user_id, ms)
       VALUES ${placeholders}`,
      values.flat()
    )
  } catch (e) {
    console.error('[appLogger] DB write failed:', (e as Error)?.message ?? e)
  }
}

function writeEntry(entry: LogEntry): void {
  // Always emit synchronously for SSE subscribers
  logEmitter.emit('entry', entry)
  // Queue for DB write (non-blocking)
  _queue.push(entry)
  scheduleFlush()
}

// ── Public logging API ────────────────────────────────────────────────────────

function makeLog(level: LogLevel) {
  return (category: LogCategory, msg: string, extra?: Omit<LogEntry, 'ts'|'level'|'category'|'msg'>) => {
    writeEntry({ ts: new Date().toISOString(), level, category, msg, ...extra })
  }
}

export const appLog = {
  debug: makeLog('debug'),
  info:  makeLog('info'),
  warn:  makeLog('warn'),
  error: makeLog('error'),

  err(category: LogCategory, msg: string, e: unknown, extra?: Record<string, unknown>) {
    const errStr = e instanceof Error
      ? `${e.message}\n${e.stack ?? ''}`
      : String(e)
    writeEntry({
      ts:       new Date().toISOString(),
      level:    'error',
      category,
      msg,
      err:      errStr,
      data:     extra,
    })
  },

  api(method: string, url: string, status: number, ms: number, userId?: string) {
    const level: LogLevel = status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info'
    writeEntry({
      ts:       new Date().toISOString(),
      level,
      category: 'api',
      msg:      `${method} ${url} → ${status}`,
      ms,
      userId,
      data:     { method, url, status },
    })
  },
}

// ── Query helpers ─────────────────────────────────────────────────────────────

export interface LogQuery {
  level?:    LogLevel
  category?: LogCategory
  search?:   string
  since?:    string
  limit?:    number
  date?:     string   // YYYY-MM-DD — filter to a specific day
}

export async function queryLogs(q: LogQuery): Promise<LogEntry[]> {
  if (!_pool) return []

  const limit  = Math.min(q.limit ?? 500, 5000)
  const wheres: string[] = []
  const params: unknown[] = []

  if (q.level)    { wheres.push('level = ?');    params.push(q.level) }
  if (q.category) { wheres.push('category = ?'); params.push(q.category) }
  if (q.since)    { wheres.push('ts > ?');        params.push(new Date(q.since).toISOString().replace('T',' ').replace('Z','')) }
  if (q.date)     { wheres.push('DATE(ts) = ?');  params.push(q.date) }
  if (q.search)   {
    wheres.push('(msg LIKE ? OR data_json LIKE ? OR err_text LIKE ?)')
    const like = `%${q.search}%`
    params.push(like, like, like)
  }

  const where = wheres.length ? `WHERE ${wheres.join(' AND ')}` : ''
  params.push(limit)

  const [rows] = await (_pool as any).execute(
    `SELECT id, ts, level, category, msg, data_json, err_text AS err, user_id AS userId, ms
     FROM app_log ${where}
     ORDER BY ts DESC, id DESC
     LIMIT ?`,
    params
  )

  return (rows as any[]).map(r => ({
    id:       r.id,
    ts:       r.ts instanceof Date ? r.ts.toISOString() : String(r.ts),
    level:    r.level    as LogLevel,
    category: r.category as LogCategory,
    msg:      r.msg,
    data:     r.data_json ? (typeof r.data_json === 'string' ? JSON.parse(r.data_json) : r.data_json) : undefined,
    err:      r.err      ?? undefined,
    userId:   r.userId   ?? undefined,
    ms:       r.ms       ?? undefined,
  })).reverse()  // return chronological order
}

export async function getLogDates(): Promise<string[]> {
  if (!_pool) return []
  const [rows] = await (_pool as any).execute(
    `SELECT DISTINCT DATE(ts) AS d FROM app_log ORDER BY d DESC LIMIT 30`
  )
  return (rows as any[]).map(r => {
    const d = r.d
    if (d instanceof Date) return d.toISOString().slice(0,10)
    return String(d)
  })
}
