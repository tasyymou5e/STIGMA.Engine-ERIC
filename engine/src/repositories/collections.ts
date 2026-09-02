import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'

// ---------------------------------------------------------------------------
// Review Aging Config types
// ---------------------------------------------------------------------------

export interface ReviewAgingConfig {
  collectionId: number
  enabled: boolean
  triggerInterval: number          // days
  triggerField: 'ts' | 'statusTs' | 'touchTs'
  triggerAction: 'delete' | 'update'
  updateField?: string | null
  updateValue?: string | null
}

export interface CollectionRecord {
  collectionId: number
  name: string
  description: string | null
  metadata: Record<string, string> | null
  settings: Record<string, unknown> | null
}

export async function listCollections(): Promise<CollectionRecord[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    'SELECT collectionId, name, description, metadata, settings FROM collection ORDER BY name'
  )
  return rows as unknown as CollectionRecord[]
}

export async function getCollection(collectionId: number): Promise<CollectionRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    'SELECT collectionId, name, description, metadata, settings FROM collection WHERE collectionId = :id',
    { id: collectionId }
  )
  return (rows[0] as unknown as CollectionRecord) ?? null
}

export async function createCollection(input: {
  name: string
  description?: string
  metadata?: Record<string, string>
}): Promise<number> {
  const [res] = await pool.query<ResultSetHeader>(
    'INSERT INTO collection (name, description, metadata) VALUES (:name, :description, :metadata)',
    {
      name: input.name,
      description: input.description ?? null,
      metadata: input.metadata ? JSON.stringify(input.metadata) : null
    }
  )
  return res.insertId
}

export async function updateCollection(
  collectionId: number,
  input: {
    name?: string
    description?: string | null
    metadata?: Record<string, string> | null
    settings?: Record<string, unknown> | null
  }
): Promise<boolean> {
  const fields: string[] = []
  const values: Record<string, unknown> = { id: collectionId }

  if (input.name !== undefined) { fields.push('name = :name'); values.name = input.name }
  if (input.description !== undefined) { fields.push('description = :description'); values.description = input.description }
  if (input.metadata !== undefined) {
    fields.push('metadata = :metadata')
    values.metadata = input.metadata ? JSON.stringify(input.metadata) : null
  }
  if (input.settings !== undefined) {
    fields.push('settings = :settings')
    values.settings = input.settings ? JSON.stringify(input.settings) : null
  }

  if (fields.length === 0) return true

  const [res] = await pool.query<ResultSetHeader>(
    `UPDATE collection SET ${fields.join(', ')} WHERE collectionId = :id`,
    values as unknown as import('mysql2').QueryValues
  )
  return res.affectedRows > 0
}

export async function deleteCollection(collectionId: number): Promise<boolean> {
  const [res] = await pool.query<ResultSetHeader>(
    'DELETE FROM collection WHERE collectionId = :id',
    { id: collectionId }
  )
  return res.affectedRows > 0
}

/**
 * Clone a collection, optionally copying labels, assets (with STIG assignments),
 * and grants.  Returns the collectionId of the newly created collection.
 *
 * Steps:
 *  1. INSERT new collection row → newCollectionId
 *  2. (labels)  INSERT INTO collection_label … SELECT … WHERE collectionId = sourceId
 *  3. (assets)  INSERT cloned asset rows; build source→new assetId map; copy stig_asset_map
 *  4. (grants)  INSERT INTO collection_grant … SELECT … WHERE collectionId = sourceId
 */
export async function cloneCollection(
  sourceId: number,
  input: { name: string; description?: string },
  options: { grants?: boolean; labels?: boolean; assets?: boolean } = {}
): Promise<number> {
  const conn = await pool.getConnection()
  try {
    await conn.beginTransaction()

    // 1. Create the new collection
    const [insertRes] = await conn.query<ResultSetHeader>(
      'INSERT INTO collection (name, description) VALUES (:name, :description)',
      { name: input.name, description: input.description ?? null }
    )
    const newCollectionId = insertRes.insertId

    // 2. Copy labels
    if (options.labels) {
      await conn.query(
        `INSERT INTO collection_label (collectionId, name, description, color, uuid)
         SELECT :newId, name, description, color, UUID_TO_BIN(UUID(), 1)
         FROM   collection_label
         WHERE  collectionId = :sourceId`,
        { newId: newCollectionId, sourceId }
      )
    }

    // 3. Copy assets + stig_asset_map
    if (options.assets) {
      // Fetch source assets so we can map old → new assetIds
      const [sourceAssets] = await conn.query<import('mysql2').RowDataPacket[]>(
        `SELECT assetId, name, fqdn, ip, mac, description, noncomputing
         FROM asset
         WHERE collectionId = :sourceId AND state = 'enabled'`,
        { sourceId }
      )

      for (const row of sourceAssets as Array<Record<string, unknown>>) {
        const [assetRes] = await conn.query<ResultSetHeader>(
          `INSERT INTO asset (collectionId, name, fqdn, ip, mac, description, noncomputing)
           VALUES (:collectionId, :name, :fqdn, :ip, :mac, :description, :noncomputing)`,
          {
            collectionId: newCollectionId,
            name: row.name as string,
            fqdn: (row.fqdn ?? null) as string | null,
            ip: (row.ip ?? null) as string | null,
            mac: (row.mac ?? null) as string | null,
            description: (row.description ?? null) as string | null,
            noncomputing: (row.noncomputing ?? 0) as number
          } as import('mysql2').QueryValues
        )
        const newAssetId = assetRes.insertId

        // Copy STIG assignments for this asset
        await conn.query(
          `INSERT IGNORE INTO stig_asset_map (assetId, benchmarkId)
           SELECT :newAssetId, benchmarkId
           FROM   stig_asset_map
           WHERE  assetId = :oldAssetId`,
          { newAssetId, oldAssetId: row.assetId as number } as import('mysql2').QueryValues
        )
      }
    }

    // 4. Copy grants
    if (options.grants) {
      await conn.query(
        `INSERT INTO collection_grant (collectionId, userId, userGroupId, roleId)
         SELECT :newId, userId, userGroupId, roleId
         FROM   collection_grant
         WHERE  collectionId = :sourceId`,
        { newId: newCollectionId, sourceId }
      )
    }

    await conn.commit()
    return newCollectionId
  } catch (err) {
    await conn.rollback()
    throw err
  } finally {
    conn.release()
  }
}

// ---------------------------------------------------------------------------
// Review Aging Config CRUD
// ---------------------------------------------------------------------------

/**
 * Fetch the review aging config for a collection (first ordinal row).
 * Returns null when no rule exists for this collection.
 */
export async function getReviewAgingConfig(
  collectionId: number
): Promise<ReviewAgingConfig | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT collectionId, enabled, triggerInterval, triggerField,
            triggerAction, updateField, updateValue
       FROM review_aging_rule
      WHERE collectionId = :collectionId
      ORDER BY ordinal
      LIMIT 1`,
    { collectionId }
  )
  if (rows.length === 0) return null
  const r = rows[0]
  return {
    collectionId: Number(r.collectionId),
    enabled:         Boolean(r.enabled),
    triggerInterval: Number(r.triggerInterval),
    triggerField:    r.triggerField  as ReviewAgingConfig['triggerField'],
    triggerAction:   r.triggerAction as ReviewAgingConfig['triggerAction'],
    updateField:     (r.updateField  as string | null) ?? null,
    updateValue:     (r.updateValue  as string | null) ?? null
  }
}

/**
 * Replace the review aging config for a collection.
 * Deletes any existing rows then inserts the new config at ordinal 0.
 */
export async function putReviewAgingConfig(
  collectionId: number,
  config: ReviewAgingConfig
): Promise<void> {
  const conn = await pool.getConnection()
  try {
    await conn.beginTransaction()
    await conn.query(
      'DELETE FROM review_aging_rule WHERE collectionId = ?',
      [collectionId]
    )
    await conn.query(
      `INSERT INTO review_aging_rule
         (collectionId, ordinal, enabled, triggerInterval, triggerField,
          triggerAction, updateField, updateValue)
       VALUES (?, 0, ?, ?, ?, ?, ?, ?)`,
      [
        collectionId,
        config.enabled ? 1 : 0,
        config.triggerInterval,
        config.triggerField,
        config.triggerAction,
        config.updateField ?? null,
        config.updateValue ?? null
      ]
    )
    await conn.commit()
  } catch (err) {
    await conn.rollback()
    throw err
  } finally {
    conn.release()
  }
}

/**
 * Delete all review aging config rows for a collection.
 */
export async function deleteReviewAgingConfig(
  collectionId: number
): Promise<void> {
  await pool.query(
    'DELETE FROM review_aging_rule WHERE collectionId = ?',
    [collectionId]
  )
}
