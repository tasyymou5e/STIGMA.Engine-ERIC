import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'
import type { ChecklistSource } from '../engine/types.js'

export async function recordIngestRun(input: {
  collectionId: number
  assetId: number
  source: ChecklistSource
  benchmarkId: string
  reviewCount: number
  username: string
}): Promise<number> {
  const [res] = await pool.query<ResultSetHeader>(
    `INSERT INTO ingest_run (collectionId, assetId, source, benchmarkId, reviewCount, username)
     VALUES (:collectionId, :assetId, :source, :benchmarkId, :reviewCount, :username)`,
    input
  )
  return res.insertId
}

export async function recordRemediationRun(input: {
  assetId: number
  tool: string
  applied: number
  manual: number
  skipped: number
  notes?: string
  username: string
}): Promise<number> {
  const [res] = await pool.query<ResultSetHeader>(
    `INSERT INTO remediation_run (assetId, tool, applied, manual, skipped, notes, username)
     VALUES (:assetId, :tool, :applied, :manual, :skipped, :notes, :username)`,
    { ...input, notes: input.notes ?? null }
  )
  return res.insertId
}

export async function listRemediationRuns(assetId: number): Promise<RowDataPacket[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    'SELECT remediationId, tool, applied, manual, skipped, notes, username, ts FROM remediation_run WHERE assetId = :id ORDER BY ts DESC',
    { id: assetId }
  )
  return rows
}
