// Applies db/schema.sql, incremental migrations/NNN_*.sql files, and seed.sql.
// Run with `npm run db:migrate`.
import { readFile, readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import mysql from 'mysql2/promise'
import { config } from '../config.js'

const here = dirname(fileURLToPath(import.meta.url))

// MySQL error numbers that are safe to ignore (idempotent migration):
//   1050 table already exists       1060 duplicate column name
//   1061 duplicate key name         1826 duplicate FK constraint name
//   3780 referencing column and referenced column mismatch (already exists variant)
const IGNORABLE_MYSQL = new Set([1050, 1060, 1061, 1826])

function splitStatements(sql: string): string[] {
  // Strip SQL line comments first.
  const stripped = sql.replace(/--[^\n]*/g, '')

  // Support DELIMITER directives (e.g. used around CREATE PROCEDURE bodies).
  // When "DELIMITER $$" is encountered we switch to splitting on $$ instead
  // of ; until "DELIMITER ;" restores the default.
  const stmts: string[] = []
  let delimiter = ';'
  let remaining = stripped

  while (remaining.length > 0) {
    // Check for a DELIMITER directive at the start (after trimming whitespace).
    const delimMatch = remaining.match(/^\s*DELIMITER\s+(\S+)\s*/i)
    if (delimMatch) {
      delimiter = delimMatch[1]
      remaining = remaining.slice(delimMatch[0].length)
      continue
    }

    const idx = remaining.indexOf(delimiter)
    if (idx === -1) {
      // No more delimiters — take the rest if non-empty.
      const last = remaining.trim()
      if (last) stmts.push(last)
      break
    }

    const stmt = remaining.slice(0, idx).trim()
    if (stmt) stmts.push(stmt)
    remaining = remaining.slice(idx + delimiter.length)
  }

  return stmts
}

async function runSqlFile(conn: mysql.Connection, path: string, label: string): Promise<void> {
  let sql: string
  try {
    sql = await readFile(path, 'utf8')
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      console.warn(`[migrate] ${label} not found — skipping`)
      return
    }
    throw err
  }

  // Run each statement individually so ignorable errors don't abort the batch.
  const stmts = splitStatements(sql)
  let applied = 0, skipped = 0
  for (const stmt of stmts) {
    try {
      await conn.query(stmt)
      applied++
    } catch (err: unknown) {
      const errno = (err as { errno?: number }).errno
      if (errno !== undefined && IGNORABLE_MYSQL.has(errno)) {
        skipped++
      } else {
        console.error(`[migrate] ${label}: statement failed:\n  ${stmt.slice(0, 120)}`)
        throw err
      }
    }
  }
  console.log(`[migrate] ${label} — ${applied} applied, ${skipped} skipped (already exists)`)
}

async function migrate(): Promise<void> {
  // Dedicated one-time connection with multipleStatements enabled solely for
  // migration. The shared runtime pool does NOT have multipleStatements so that
  // stacked-statement SQL injection is impossible in normal query paths.
  const migrateConn = await mysql.createConnection({
    host: config.DB_HOST,
    port: config.DB_PORT,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
    database: config.DB_NAME,
    multipleStatements: true,
    namedPlaceholders: true
  })
  try {
    // 1. Base schema (idempotent CREATE TABLE IF NOT EXISTS)
    await runSqlFile(migrateConn, join(here, 'schema.sql'), 'schema.sql')

    // 2. Phase 0 foundation (new tables + column expansions)
    //    Must run before seed so lookup tables exist.
    const migrationsDir = join(here, 'migrations')
    const phase0 = join(migrationsDir, '001_phase0_foundation.sql')
    await runSqlFile(migrateConn, phase0, 'migrations/001_phase0_foundation.sql')

    // 3. Seed lookup data NOW — before later migrations add FK constraints
    //    that reference result/status rows (e.g. fk_review_status in phase 1).
    await runSqlFile(migrateConn, join(here, 'seed.sql'), 'seed.sql')

    // 4. Remaining incremental migrations in filename order (002 onwards)
    try {
      const files = (await readdir(migrationsDir))
        .filter((f) => f.endsWith('.sql') && f > '001_phase0_foundation.sql')
        .sort()
      for (const f of files) {
        await runSqlFile(migrateConn, join(migrationsDir, f), `migrations/${f}`)
      }
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err
      console.warn('[migrate] migrations/ directory not found — skipping')
    }
  } finally {
    await migrateConn.end()
  }
}

migrate().catch((err) => {
  console.error('[migrate] failed:', err)
  process.exit(1)
})
