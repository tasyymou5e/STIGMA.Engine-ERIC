import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'

// ---------------------------------------------------------------------------
// Collection-STIG types
// ---------------------------------------------------------------------------

export interface CollectionStigRow {
  benchmarkId: string
  title: string | null
  revId: string | null
  version: string | null
  release: string | null
  ruleCount: number | null
  highCount: number | null
  mediumCount: number | null
  lowCount: number | null
  assetCount: number
  pinnedRevision: string | null
}

export interface CollectionStigPin {
  benchmarkId: string
  revisionStr: string | null
  pinnedAt: string | null
  pinnedBy: string | null
}

export interface CollectionStigAsset {
  assetId: number
  name: string
  fqdn: string | null
  ip: string | null
}

export interface StigRecord {
  benchmarkId: string
  title: string
}

export interface RevisionRecord {
  revId: string
  benchmarkId: string
  version: string
  release: string
  revisionStr: string
  benchmarkDate: string
  ruleCount: number
  highCount: number
  mediumCount: number
  lowCount: number
}

export interface RuleRecord {
  ruleId: string
  ruleVersion: string
  groupId: string
  groupTitle: string
  title: string
  severity: string
  vulnDiscussion?: string
  checkContent?: string
  fixText?: string
  ccis?: string[]
  // enriched fields returned by getRuleByRuleId
  stigTitle?: string
  revisionStr?: string
}

export interface GroupRecord {
  groupId: string
  groupTitle: string
  ruleCount: number
  severity: string
}

export interface CciRecord {
  cci: string
  status?: string
  publishdate?: string
  contributor?: string
  type?: string
  definition?: string
  apAcronym?: string
  implementation?: string
  assessmentProcedure?: string
  /** comma-separated parentControl values from cci_reference_map */
  controls?: string
}

// ---------------------------------------------------------------------------
// STIGs
// ---------------------------------------------------------------------------

export async function listStigs(): Promise<StigRecord[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    'SELECT benchmarkId, title FROM stig ORDER BY benchmarkId'
  )
  return rows as unknown as StigRecord[]
}

export async function getStig(benchmarkId: string): Promise<StigRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    'SELECT benchmarkId, title FROM stig WHERE benchmarkId = :benchmarkId',
    { benchmarkId }
  )
  return (rows[0] as unknown as StigRecord) ?? null
}

export async function deleteStig(benchmarkId: string): Promise<boolean> {
  const [res] = await pool.query<ResultSetHeader>(
    'DELETE FROM stig WHERE benchmarkId = :benchmarkId',
    { benchmarkId }
  )
  return res.affectedRows > 0
}

// ---------------------------------------------------------------------------
// Revisions
// ---------------------------------------------------------------------------

export async function listRevisions(benchmarkId: string): Promise<RevisionRecord[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       r.revId,
       r.benchmarkId,
       CAST(r.version AS CHAR)                       AS version,
       r.release,
       CONCAT('V', r.version, 'R', r.release)        AS revisionStr,
       DATE_FORMAT(r.benchmarkDateSql, '%Y-%m-%d')   AS benchmarkDate,
       r.ruleCount,
       r.highCount,
       r.mediumCount,
       r.lowCount
     FROM revision r
     WHERE r.benchmarkId = :benchmarkId
     ORDER BY r.benchmarkDateSql DESC`,
    { benchmarkId }
  )
  return rows as unknown as RevisionRecord[]
}

export async function getRevision(
  benchmarkId: string,
  revisionStr: string
): Promise<RevisionRecord | null> {
  let sql: string
  let params: Record<string, unknown>

  if (revisionStr === 'latest') {
    // current_rev holds the materialised latest revision per benchmarkId
    sql = `SELECT
             cr.revId,
             cr.benchmarkId,
             CAST(cr.version AS CHAR)                      AS version,
             cr.release,
             CONCAT('V', cr.version, 'R', cr.release)      AS revisionStr,
             DATE_FORMAT(cr.benchmarkDateSql, '%Y-%m-%d')  AS benchmarkDate,
             cr.ruleCount,
             cr.highCount,
             cr.mediumCount,
             cr.lowCount
           FROM current_rev cr
           WHERE cr.benchmarkId = :benchmarkId`
    params = { benchmarkId }
  } else {
    // Parse V{n}R{n} into version and release components
    const match = revisionStr.match(/^V(\d+)R(\d+(?:\.\d+)?)$/)
    if (!match) return null
    const [, version, release] = match
    sql = `SELECT
             r.revId,
             r.benchmarkId,
             CAST(r.version AS CHAR)                      AS version,
             r.release,
             CONCAT('V', r.version, 'R', r.release)       AS revisionStr,
             DATE_FORMAT(r.benchmarkDateSql, '%Y-%m-%d')  AS benchmarkDate,
             r.ruleCount,
             r.highCount,
             r.mediumCount,
             r.lowCount
           FROM revision r
           WHERE r.benchmarkId = :benchmarkId
             AND r.version     = :version
             AND r.release     = :release`
    params = { benchmarkId, version, release }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [rows] = await pool.query<RowDataPacket[]>(sql, params as any)
  return (rows[0] as unknown as RevisionRecord) ?? null
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export async function listRules(
  revId: string,
  projection?: 'detail' | 'cci'
): Promise<RuleRecord[]> {
  const columns = [
    'rgr.ruleId',
    'rgr.version   AS ruleVersion',
    'rgr.groupId',
    'rgr.groupTitle',
    'rgr.title',
    'rgr.severity',
  ]

  const joins: string[] = [
    'rev_group_rule_map rgr',
  ]

  if (projection === 'detail') {
    // Return vulnDiscussion, check content, fix text, AND aggregated CCIs in one query
    columns.push('ANY_VALUE(rgr.vulnDiscussion) AS vulnDiscussion')
    columns.push('ANY_VALUE(cc.content)          AS checkContent')
    columns.push('ANY_VALUE(ft.text)             AS fixText')
    columns.push(
      `CAST(
         CASE WHEN COUNT(rgrcc.cci) = 0
           THEN JSON_ARRAY()
           ELSE JSON_ARRAYAGG(rgrcc.cci)
         END
       AS JSON) AS ccis`
    )
    joins.push('LEFT JOIN check_content          cc    ON cc.digest   = rgr.checkDigest')
    joins.push('LEFT JOIN fix_text               ft    ON ft.digest   = rgr.fixDigest')
    joins.push('LEFT JOIN rev_group_rule_cci_map rgrcc ON rgrcc.rgrId = rgr.rgrId')
  } else if (projection === 'cci') {
    // Aggregate CCI identifiers into a JSON array then let TypeScript parse it
    columns.push(
      `CAST(
         CASE WHEN COUNT(rgrcc.cci) = 0
           THEN JSON_ARRAY()
           ELSE JSON_ARRAYAGG(rgrcc.cci)
         END
       AS JSON) AS ccis`
    )
    joins.push('LEFT JOIN rev_group_rule_cci_map rgrcc ON rgrcc.rgrId = rgr.rgrId')
  }

  const groupByNeeded = projection === 'detail' || projection === 'cci'
  const groupByCols = groupByNeeded
    ? 'rgr.rgrId, rgr.ruleId, rgr.version, rgr.groupId, rgr.groupTitle, rgr.title, rgr.severity'
    : ''

  const sql = `
    SELECT ${columns.join(',\n           ')}
    FROM   ${joins.join('\n    ')}
    WHERE  rgr.revId = :revId
    ${groupByNeeded ? `GROUP BY ${groupByCols}` : ''}
    ORDER BY SUBSTRING(rgr.ruleId FROM 4) + 0`

  const [rows] = await pool.query<RowDataPacket[]>(sql, { revId })
  return rows as unknown as RuleRecord[]
}

// ---------------------------------------------------------------------------
// Collection-STIG queries
// ---------------------------------------------------------------------------

/**
 * All STIGs "in" a collection — derived from stig_asset_map.
 * A STIG is in the collection when at least one enabled asset in that
 * collection has it assigned.
 */
export async function stigsByCollection(
  collectionId: number
): Promise<CollectionStigRow[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       sam.benchmarkId,
       s.title,
       cr.revId,
       CAST(cr.version AS CHAR)  AS version,
       cr.release,
       cr.ruleCount,
       cr.highCount,
       cr.mediumCount,
       cr.lowCount,
       COUNT(DISTINCT sam.assetId) AS assetCount,
       csp.revisionStr            AS pinnedRevision
     FROM stig_asset_map sam
     JOIN asset a ON a.assetId = sam.assetId
       AND a.collectionId = :collectionId
       AND a.state = 'enabled'
     LEFT JOIN stig s ON s.benchmarkId = sam.benchmarkId
     LEFT JOIN current_rev cr ON cr.benchmarkId = sam.benchmarkId
     LEFT JOIN collection_stig_pin csp
           ON  csp.collectionId = :collectionId
           AND csp.benchmarkId  = sam.benchmarkId
     GROUP BY sam.benchmarkId, s.title, cr.revId, cr.version, cr.release,
              cr.ruleCount, cr.highCount, cr.mediumCount, cr.lowCount,
              csp.revisionStr
     ORDER BY sam.benchmarkId`,
    { collectionId }
  )
  return rows as unknown as CollectionStigRow[]
}

/**
 * Read the current pin record for a (collection, STIG) pair.
 * Returns null when no pin exists (collection tracks latest revision).
 */
export async function getCollectionStigPin(
  collectionId: number,
  benchmarkId: string
): Promise<CollectionStigPin | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       benchmarkId,
       revisionStr,
       DATE_FORMAT(pinnedAt, '%Y-%m-%dT%TZ') AS pinnedAt,
       pinnedBy
     FROM collection_stig_pin
     WHERE collectionId = :collectionId
       AND benchmarkId  = :benchmarkId`,
    { collectionId, benchmarkId }
  )
  if (rows.length === 0) return null
  return rows[0] as unknown as CollectionStigPin
}

/**
 * Upsert or delete the pin record for a (collection, STIG) pair.
 *
 * - revisionStr non-null  → pin to that revision (upsert)
 * - revisionStr null      → remove pin (DELETE); collection reverts to latest
 */
export async function setCollectionStigPin(
  collectionId: number,
  benchmarkId: string,
  revisionStr: string | null,
  pinnedBy?: string
): Promise<void> {
  if (revisionStr === null) {
    await pool.query(
      `DELETE FROM collection_stig_pin
       WHERE collectionId = :collectionId
         AND benchmarkId  = :benchmarkId`,
      { collectionId, benchmarkId }
    )
  } else {
    await pool.query(
      `INSERT INTO collection_stig_pin
         (collectionId, benchmarkId, revisionStr, pinnedAt, pinnedBy)
       VALUES
         (:collectionId, :benchmarkId, :revisionStr, NOW(), :pinnedBy)
       ON DUPLICATE KEY UPDATE
         revisionStr = VALUES(revisionStr),
         pinnedAt    = VALUES(pinnedAt),
         pinnedBy    = VALUES(pinnedBy)`,
      { collectionId, benchmarkId, revisionStr, pinnedBy: pinnedBy ?? null }
    )
  }
}

/**
 * Assets in a collection that have a specific STIG assigned.
 */
export async function assetsByStig(
  collectionId: number,
  benchmarkId: string
): Promise<CollectionStigAsset[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       a.assetId,
       a.name,
       a.fqdn,
       a.ip
     FROM stig_asset_map sam
     JOIN asset a ON a.assetId = sam.assetId
       AND a.collectionId = :collectionId
       AND a.state = 'enabled'
     WHERE sam.benchmarkId = :benchmarkId
     ORDER BY a.name`,
    { collectionId, benchmarkId }
  )
  return rows as unknown as CollectionStigAsset[]
}

export async function getRule(ruleId: string): Promise<RuleRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       rgr.ruleId,
       ANY_VALUE(rgr.version)      AS ruleVersion,
       ANY_VALUE(rgr.groupId)      AS groupId,
       ANY_VALUE(rgr.groupTitle)   AS groupTitle,
       ANY_VALUE(rgr.title)        AS title,
       ANY_VALUE(rgr.severity)     AS severity,
       ANY_VALUE(rgr.vulnDiscussion) AS vulnDiscussion,
       ANY_VALUE(cc.content)       AS checkContent,
       ANY_VALUE(ft.text)          AS fixText,
       CAST(
         CASE WHEN COUNT(rgrcc.cci) = 0
           THEN JSON_ARRAY()
           ELSE JSON_ARRAYAGG(DISTINCT rgrcc.cci)
         END
       AS JSON) AS ccis
     FROM rev_group_rule_map rgr
     LEFT JOIN check_content          cc    ON cc.digest    = rgr.checkDigest
     LEFT JOIN fix_text               ft    ON ft.digest    = rgr.fixDigest
     LEFT JOIN rev_group_rule_cci_map rgrcc ON rgrcc.rgrId  = rgr.rgrId
     WHERE rgr.ruleId = :ruleId
     GROUP BY rgr.ruleId`,
    { ruleId }
  )
  return (rows[0] as unknown as RuleRecord) ?? null
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/**
 * List all groups for a revision, derived from the rule table.
 * severity is resolved from the minimum-severity rule in each group
 * (high < medium < low).
 */
export async function listGroups(revId: string): Promise<GroupRecord[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       r.groupId,
       r.groupTitle,
       COUNT(*)                                                          AS ruleCount,
       CASE MIN(CASE r.severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END)
         WHEN 1 THEN 'high'
         WHEN 2 THEN 'medium'
         ELSE 'low'
       END                                                               AS severity
     FROM rule r
     WHERE r.revId = :revId
     GROUP BY r.groupId, r.groupTitle
     ORDER BY r.groupId`,
    { revId }
  )
  return rows as unknown as GroupRecord[]
}

/**
 * Single group with all its rules (full detail).
 */
export async function getGroup(
  revId: string,
  groupId: string
): Promise<{ group: GroupRecord; rules: RuleRecord[] } | null> {
  // Fetch group summary
  const [groupRows] = await pool.query<RowDataPacket[]>(
    `SELECT
       r.groupId,
       r.groupTitle,
       COUNT(*)                                                          AS ruleCount,
       CASE MIN(CASE r.severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END)
         WHEN 1 THEN 'high'
         WHEN 2 THEN 'medium'
         ELSE 'low'
       END                                                               AS severity
     FROM rule r
     WHERE r.revId = :revId AND r.groupId = :groupId
     GROUP BY r.groupId, r.groupTitle`,
    { revId, groupId }
  )
  if (groupRows.length === 0) return null
  const group = groupRows[0] as unknown as GroupRecord

  // Fetch all rules in this group with full detail
  const [ruleRows] = await pool.query<RowDataPacket[]>(
    `SELECT
       r.ruleId,
       r.ruleVersion,
       r.groupId,
       r.groupTitle,
       r.title,
       r.severity,
       r.vulnDiscussion,
       cc.content                                                        AS checkContent,
       ft.text                                                           AS fixText,
       CAST(
         CASE WHEN COUNT(rcm.cci) = 0
           THEN JSON_ARRAY()
           ELSE JSON_ARRAYAGG(rcm.cci)
         END
       AS JSON)                                                          AS ccis
     FROM rule r
     LEFT JOIN check_content  cc  ON cc.digest  = r.checkDigest
     LEFT JOIN fix_text        ft  ON ft.digest  = r.fixDigest
     LEFT JOIN rule_cci_map   rcm ON rcm.rgrId   = r.rgrId
     WHERE r.revId = :revId AND r.groupId = :groupId
     GROUP BY r.rgrId, r.ruleId, r.ruleVersion, r.groupId, r.groupTitle,
              r.title, r.severity, r.vulnDiscussion, cc.content, ft.text
     ORDER BY SUBSTRING(r.ruleId FROM 4) + 0`,
    { revId, groupId }
  )
  const rules = ruleRows as unknown as RuleRecord[]

  return { group, rules }
}

/**
 * Global rule lookup by ruleId — enriched with STIG title and revision string.
 * Returns the first matching row (ruleId is unique per revision but may appear
 * in multiple revisions; LIMIT 1 returns the most recently imported).
 */
export async function getRuleByRuleId(ruleId: string): Promise<RuleRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       r.ruleId,
       r.ruleVersion,
       r.groupId,
       r.groupTitle,
       r.title,
       r.severity,
       r.vulnDiscussion,
       cc.content                                                        AS checkContent,
       ft.text                                                           AS fixText,
       CAST(
         CASE WHEN COUNT(rcm.cci) = 0
           THEN JSON_ARRAY()
           ELSE JSON_ARRAYAGG(rcm.cci)
         END
       AS JSON)                                                          AS ccis,
       s.title                                                           AS stigTitle,
       CONCAT('V', rev.version, 'R', rev.release)                       AS revisionStr
     FROM rule r
     JOIN revision rev ON rev.revId = r.revId
     JOIN stig     s   ON s.benchmarkId = rev.benchmarkId
     LEFT JOIN check_content  cc  ON cc.digest  = r.checkDigest
     LEFT JOIN fix_text        ft  ON ft.digest  = r.fixDigest
     LEFT JOIN rule_cci_map   rcm ON rcm.rgrId   = r.rgrId
     WHERE r.ruleId = :ruleId
     GROUP BY r.rgrId, r.ruleId, r.ruleVersion, r.groupId, r.groupTitle,
              r.title, r.severity, r.vulnDiscussion, cc.content, ft.text,
              s.title, rev.version, rev.release
     LIMIT 1`,
    { ruleId }
  )
  return (rows[0] as unknown as RuleRecord) ?? null
}

// ---------------------------------------------------------------------------
// CCI (global lookup)
// ---------------------------------------------------------------------------

/**
 * Look up a single CCI by its identifier (e.g. "CCI-000001").
 * The controls field is a comma-separated list of parentControl values
 * from cci_reference_map.
 */
export async function getCciById(cci: string): Promise<CciRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       c.cci,
       c.status,
       DATE_FORMAT(c.publishdate, '%Y-%m-%d') AS publishdate,
       c.contributor,
       c.type,
       c.definition,
       c.apAcronym,
       c.implementation,
       c.assessmentProcedure,
       GROUP_CONCAT(crm.parentControl ORDER BY crm.parentControl SEPARATOR ',') AS controls
     FROM cci c
     LEFT JOIN cci_reference_map crm ON crm.cci = c.cci
     WHERE c.cci = :cci
     GROUP BY c.cci`,
    { cci }
  )
  return (rows[0] as unknown as CciRecord) ?? null
}

/**
 * List CCIs, optionally filtered by apAcronym.  Hard-capped at 500 rows.
 */
export async function listCcis(params: { apAcronym?: string }): Promise<CciRecord[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       c.cci,
       c.apAcronym,
       c.definition,
       DATE_FORMAT(c.publishdate, '%Y-%m-%d') AS publishdate
     FROM cci c
     WHERE (:apAcronym IS NULL OR c.apAcronym = :apAcronym)
     ORDER BY c.cci
     LIMIT 500`,
    { apAcronym: params.apAcronym ?? null }
  )
  return rows as unknown as CciRecord[]
}
