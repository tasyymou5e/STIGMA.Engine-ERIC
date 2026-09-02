import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AclRule {
  cgAclId?: number
  grantId: number
  benchmarkId: string | null
  assetId: number | null
  clId: number | null
  access: 'none' | 'r' | 'rw'
}

export interface EffectiveAclEntry {
  benchmarkId: string | null
  assetId: number | null
  clId: number | null
  access: 'none' | 'r' | 'rw'
  roleId: number
}

export interface Grant {
  grantId: number
  collectionId: number
  userId?: number
  username?: string
  userGroupId?: number
  userGroupName?: string
  roleId: number
}

/**
 * A single effective ACL entry produced by getEffectiveAcl.
 * Each row represents a (benchmarkId, assetId) pairing that the user can
 * access, together with the resolved access level and the grant that provided
 * the highest role.
 */
export interface AclEntry {
  access: 'none' | 'r' | 'rw'
  asset: { assetId: string; name: string }
  benchmarkId: string
  aclSources: unknown[]
}

// ---------------------------------------------------------------------------
// listGrants
// ---------------------------------------------------------------------------

/**
 * Return every grant row for a collection, joining user_data and user_group
 * to surface human-readable names alongside the IDs.
 */
export async function listGrants(collectionId: number): Promise<Grant[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       cg.grantId,
       cg.collectionId,
       cg.userId,
       ud.username,
       cg.userGroupId,
       ug.name  AS userGroupName,
       cg.roleId
     FROM collection_grant cg
     LEFT JOIN user_data   ud ON cg.userId      = ud.userId
     LEFT JOIN user_group  ug ON cg.userGroupId = ug.userGroupId
     WHERE cg.collectionId = :collectionId
     ORDER BY cg.grantId`,
    { collectionId }
  )
  return rows as unknown as Grant[]
}

// ---------------------------------------------------------------------------
// createGrant
// ---------------------------------------------------------------------------

/**
 * Insert a new grant row.  Exactly one of userId / userGroupId must be
 * provided (the CHECK constraint on the table enforces mutual exclusivity).
 * Returns the new grantId.
 */
export async function createGrant(
  collectionId: number,
  input: { userId?: number; userGroupId?: number; roleId: number }
): Promise<number> {
  const column = input.userId != null ? 'userId' : 'userGroupId'
  const value  = input.userId ?? input.userGroupId

  const [res] = await pool.query<ResultSetHeader>(
    `INSERT INTO collection_grant (collectionId, ${column}, roleId)
     VALUES (:collectionId, :value, :roleId)`,
    { collectionId, value, roleId: input.roleId }
  )
  return res.insertId
}

// ---------------------------------------------------------------------------
// updateGrant
// ---------------------------------------------------------------------------

/**
 * Update the roleId on an existing grant.
 * Returns true when the row was found and modified.
 */
export async function updateGrant(
  grantId: number,
  patch: { roleId: number }
): Promise<boolean> {
  const [res] = await pool.query<ResultSetHeader>(
    'UPDATE collection_grant SET roleId = :roleId WHERE grantId = :grantId',
    { roleId: patch.roleId, grantId }
  )
  return res.affectedRows > 0
}

// ---------------------------------------------------------------------------
// deleteGrant
// ---------------------------------------------------------------------------

/**
 * Delete a grant by its primary key.
 * Returns true when a row was actually deleted.
 */
export async function deleteGrant(grantId: number): Promise<boolean> {
  const [res] = await pool.query<ResultSetHeader>(
    'DELETE FROM collection_grant WHERE grantId = :grantId',
    { grantId }
  )
  return res.affectedRows > 0
}

// ---------------------------------------------------------------------------
// getEffectiveAcl
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// getAclRules
// ---------------------------------------------------------------------------

/**
 * Return every ACL rule row for a specific grant.
 */
export async function getAclRules(grantId: number): Promise<AclRule[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT cgAclId, grantId, benchmarkId, assetId, clId, access
     FROM collection_grant_acl
     WHERE grantId = :grantId
     ORDER BY cgAclId`,
    { grantId }
  )
  return rows.map((r) => ({
    cgAclId:     Number(r.cgAclId),
    grantId:     Number(r.grantId),
    benchmarkId: r.benchmarkId ?? null,
    assetId:     r.assetId != null ? Number(r.assetId) : null,
    clId:        r.clId    != null ? Number(r.clId)    : null,
    access:      r.access  as 'none' | 'r' | 'rw'
  }))
}

// ---------------------------------------------------------------------------
// putAclRules
// ---------------------------------------------------------------------------

/**
 * Replace all ACL rules for a grant atomically (DELETE + bulk INSERT).
 */
export async function putAclRules(grantId: number, rules: AclRule[]): Promise<void> {
  const conn = await pool.getConnection()
  try {
    await conn.beginTransaction()

    await conn.query(
      'DELETE FROM collection_grant_acl WHERE grantId = :grantId',
      { grantId }
    )

    if (rules.length > 0) {
      const values = rules.map((r) => [
        grantId,
        r.benchmarkId ?? null,
        r.assetId     ?? null,
        r.clId        ?? null,
        r.access
      ])
      await conn.query(
        `INSERT INTO collection_grant_acl (grantId, benchmarkId, assetId, clId, access)
         VALUES ?`,
        [values]
      )
    }

    await conn.commit()
  } catch (err) {
    await conn.rollback()
    throw err
  } finally {
    conn.release()
  }
}

// ---------------------------------------------------------------------------
// getEffectiveAclForUser
// ---------------------------------------------------------------------------

/**
 * Resolve raw ACL rule rows that apply to a specific user in a collection,
 * across both direct user grants and group grants.
 */
export async function getEffectiveAclForUser(
  collectionId: number,
  userId: number
): Promise<EffectiveAclEntry[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       cga.benchmarkId,
       cga.assetId,
       cga.clId,
       cga.access,
       cg.roleId
     FROM collection_grant cg
     LEFT JOIN user_group_user_map ugu
            ON cg.userGroupId = ugu.userGroupId
           AND ugu.userId = :userId
     LEFT JOIN collection_grant_acl cga
            ON cga.grantId = cg.grantId
     WHERE cg.collectionId = :collectionId
       AND (cg.userId = :userId OR ugu.userId = :userId)`,
    { collectionId, userId }
  )
  return rows.map((r) => ({
    benchmarkId: r.benchmarkId ?? null,
    assetId:     r.assetId != null ? Number(r.assetId) : null,
    clId:        r.clId    != null ? Number(r.clId)    : null,
    access:      r.access  as 'none' | 'r' | 'rw',
    roleId:      Number(r.roleId)
  }))
}

// ---------------------------------------------------------------------------
// getEffectiveAcl (original — complex per-stig-asset resolution)
// ---------------------------------------------------------------------------

/**
 * Resolve the effective fine-grained ACL for a user against a collection.
 *
 * The logic follows the upstream NAVY pattern:
 *   1. Direct user grant — takes precedence over any group grant.
 *   2. Group grants — highest roleId wins when the user belongs to multiple
 *      groups that all have a grant to the same collection.
 *   3. The resolved grantId set is then expanded through collection_grant_acl
 *      rows.  The most-specific matching rule (by a specificity score) wins
 *      for each (saId, access) pair, and rows with access = 'none' are
 *      excluded from the result.
 *
 * Returns an array of AclEntry objects, one per accessible stig_asset_map row.
 */
export async function getEffectiveAcl(
  collectionId: number,
  userId: number
): Promise<AclEntry[]> {
  const sql = `
    WITH cteGrantees AS (
      -- Direct user grant
      SELECT JSON_ARRAY(cg.grantId) AS grantIds
      FROM   collection_grant cg
      WHERE  cg.userId       IS NOT NULL
        AND  cg.collectionId = :collectionId
        AND  cg.userId       = :userId

      UNION

      -- Group grants — highest roleId row per (user, collection), only when
      -- the user does not already have a direct grant to the same collection.
      SELECT grantIds
      FROM (
        SELECT
          ROW_NUMBER() OVER (
            PARTITION BY ugu.userId, cg.collectionId
            ORDER BY cg.roleId DESC
          ) AS rn,
          JSON_ARRAYAGG(cg.grantId) OVER (
            PARTITION BY ugu.userId, cg.collectionId, cg.roleId
          ) AS grantIds
        FROM collection_grant            cg
        LEFT JOIN user_group_user_map    ugu ON cg.userGroupId  = ugu.userGroupId
        LEFT JOIN user_group             ug  ON ugu.userGroupId = ug.userGroupId
        -- exclude users that already have a direct grant to the collection
        LEFT JOIN collection_grant       cgDirect
               ON  cg.collectionId = cgDirect.collectionId
               AND ugu.userId      = cgDirect.userId
        WHERE  cg.userGroupId  IS NOT NULL
          AND  cgDirect.userId  IS NULL
          AND  cg.collectionId  = :collectionId
          AND  ugu.userId       = :userId
      ) dt
      WHERE dt.rn = 1
    ),

    cteAclRules AS (
      SELECT
        sa.saId,
        sa.assetId,
        sa.benchmarkId,
        cga.grantId,
        cga.access,
        JSON_OBJECT('assetId', CAST(a.assetId AS CHAR), 'name', a.name) AS asset,
        JSON_OBJECT(
          'grantee', JSON_REMOVE(JSON_OBJECT(
            CASE WHEN ud.userId      IS NULL THEN 'x' ELSE 'userId'      END, CAST(ud.userId AS CHAR),
            CASE WHEN ud.userId      IS NULL THEN 'x' ELSE 'username'    END, ud.username,
            CASE WHEN ug.userGroupId IS NULL THEN 'x' ELSE 'userGroupId' END, CAST(ug.userGroupId AS CHAR),
            CASE WHEN ug.userGroupId IS NULL THEN 'x' ELSE 'name'        END, ug.name,
            'roleId', cg.roleId
          ), '$.x'),
          'aclRule', JSON_REMOVE(JSON_OBJECT(
            CASE WHEN cga.benchmarkId IS NULL THEN 'x' ELSE 'benchmarkId' END, cga.benchmarkId,
            CASE WHEN cga.assetId     IS NULL THEN 'x' ELSE 'asset'       END,
              CASE WHEN cga.assetId IS NULL THEN NULL
                   ELSE JSON_OBJECT('assetId', CAST(cga.assetId AS CHAR), 'name', a.name)
              END,
            CASE WHEN cga.clId IS NULL THEN 'x' ELSE 'label' END,
              CASE WHEN cga.clId IS NULL THEN NULL
                   ELSE JSON_OBJECT('labelId', BIN_TO_UUID(cl.uuid, 1), 'name', cl.name)
              END,
            'access', cga.access
          ), '$.x')
        ) AS aclSource,
        CASE WHEN cga.benchmarkId IS NOT NULL THEN 1 ELSE 0 END +
        CASE WHEN cga.assetId     IS NOT NULL THEN 1 ELSE 0 END +
        CASE WHEN cga.assetId IS NOT NULL AND cga.benchmarkId IS NOT NULL THEN 1 ELSE 0 END +
        CASE WHEN cga.clId        IS NOT NULL THEN 1 ELSE 0 END AS specificity
      FROM collection_grant_acl           cga
      LEFT JOIN collection_grant          cg  ON cga.grantId     = cg.grantId
      LEFT JOIN user_data                 ud  ON cg.userId        = ud.userId
      LEFT JOIN user_group                ug  ON cg.userGroupId   = ug.userGroupId
      LEFT JOIN collection_label_asset_map cla ON cga.clId        = cla.clId
      LEFT JOIN collection_label          cl  ON cla.clId         = cl.clId
      INNER JOIN stig_asset_map           sa  ON (
        CASE WHEN cga.assetId     IS NOT NULL THEN cga.assetId  = sa.assetId     ELSE TRUE END AND
        CASE WHEN cga.benchmarkId IS NOT NULL THEN cga.benchmarkId = sa.benchmarkId ELSE TRUE END AND
        CASE WHEN cga.clId        IS NOT NULL THEN cla.assetId  = sa.assetId     ELSE TRUE END
      )
      INNER JOIN asset                    a   ON sa.assetId = a.assetId
                                             AND cg.collectionId = a.collectionId
      WHERE cga.grantId IN (
        SELECT /*+ NO_MERGE() */ jt.grantId
        FROM cteGrantees
        LEFT JOIN JSON_TABLE(
          cteGrantees.grantIds, '$[*]' COLUMNS (grantId INT PATH '$')
        ) jt ON TRUE
      )
    ),

    cteAclRulesRanked AS (
      SELECT /*+ NO_MERGE() */
        saId,
        access,
        asset,
        benchmarkId,
        JSON_ARRAYAGG(aclSource) OVER (PARTITION BY saId, access, specificity) AS aclSources,
        specificity,
        ROW_NUMBER() OVER (PARTITION BY saId ORDER BY specificity DESC, access ASC) AS rn
      FROM cteAclRules
    )

    SELECT access, asset, benchmarkId, aclSources
    FROM   cteAclRulesRanked
    WHERE  rn = 1
      AND  access != 'none'`

  const [rows] = await pool.query<RowDataPacket[]>(sql, { collectionId, userId })
  return rows as unknown as AclEntry[]
}
