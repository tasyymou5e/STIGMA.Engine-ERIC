import type { RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type MetaTable = 'collection' | 'asset' | 'review'
type MetaPk    = 'collectionId' | 'assetId' | 'reviewId'

interface MetadataRepo {
  getMetadata(id: number): Promise<Record<string, string>>
  patchMetadata(id: number, patch: Record<string, string>): Promise<Record<string, string>>
  putMetadata(id: number, meta: Record<string, string>): Promise<Record<string, string>>
  getMetadataKeys(id: number): Promise<string[]>
  getMetadataValue(id: number, key: string): Promise<string | null>
  putMetadataValue(id: number, key: string, value: string): Promise<void>
  deleteMetadataKey(id: number, key: string): Promise<void>
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

function metadataRepo(tableName: MetaTable, pkName: MetaPk): MetadataRepo {
  async function getMetadata(id: number): Promise<Record<string, string>> {
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT metadata FROM \`${tableName}\` WHERE \`${pkName}\` = :id`,
      { id }
    )
    if (rows.length === 0) return {}
    const raw = rows[0].metadata
    if (raw == null) return {}
    if (typeof raw === 'object') return raw as Record<string, string>
    try { return JSON.parse(raw as string) } catch { return {} }
  }

  async function patchMetadata(
    id: number,
    patch: Record<string, string>
  ): Promise<Record<string, string>> {
    const current = await getMetadata(id)
    const merged  = { ...current, ...patch }
    await pool.query(
      `UPDATE \`${tableName}\` SET metadata = JSON(:meta) WHERE \`${pkName}\` = :id`,
      { meta: JSON.stringify(merged), id }
    )
    return merged
  }

  async function putMetadata(
    id: number,
    meta: Record<string, string>
  ): Promise<Record<string, string>> {
    await pool.query(
      `UPDATE \`${tableName}\` SET metadata = JSON(:meta) WHERE \`${pkName}\` = :id`,
      { meta: JSON.stringify(meta), id }
    )
    return meta
  }

  async function getMetadataKeys(id: number): Promise<string[]> {
    return Object.keys(await getMetadata(id))
  }

  async function getMetadataValue(id: number, key: string): Promise<string | null> {
    const meta = await getMetadata(id)
    return Object.prototype.hasOwnProperty.call(meta, key) ? (meta[key] ?? null) : null
  }

  async function putMetadataValue(id: number, key: string, value: string): Promise<void> {
    const current = await getMetadata(id)
    current[key]  = value
    await pool.query(
      `UPDATE \`${tableName}\` SET metadata = JSON(:meta) WHERE \`${pkName}\` = :id`,
      { meta: JSON.stringify(current), id }
    )
  }

  async function deleteMetadataKey(id: number, key: string): Promise<void> {
    const current = await getMetadata(id)
    delete current[key]
    await pool.query(
      `UPDATE \`${tableName}\` SET metadata = JSON(:meta) WHERE \`${pkName}\` = :id`,
      { meta: JSON.stringify(current), id }
    )
  }

  return {
    getMetadata,
    patchMetadata,
    putMetadata,
    getMetadataKeys,
    getMetadataValue,
    putMetadataValue,
    deleteMetadataKey
  }
}

// ---------------------------------------------------------------------------
// Exports — one repo instance per entity
// ---------------------------------------------------------------------------

export const collectionMetadata = metadataRepo('collection', 'collectionId')
export const assetMetadata      = metadataRepo('asset',      'assetId')
export const reviewMetadata     = metadataRepo('review',     'reviewId')
