// Open-findings repository — the POA&M source data layer.
// Queries review(result='fail') joined to asset, rule metadata, and CCI tables.
// All JOINs to rule/CCI tables are LEFT JOINs so the query degrades gracefully
// when the STIG library tables (rev_group_rule_map, cci, etc.) are not populated.
import type { RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FindingRecord {
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: string
  title: string
  assetCount: number
  ccis?: string[]
}

/**
 * Enriched finding record carrying all columns needed for eMASS POA&M export.
 * Returned by enrichFindingsForPoam — no N+1 queries.
 */
export interface EnrichedFindingRecord {
  ruleId: string
  groupId: string
  ruleVersion: string
  severity: string
  title: string
  assetCount: number
  assetNames: string[]
  ccis?: string[]
  nistControl: string
  vulnDiscussion: string
  fixText: string
  stigTitle: string
  stigVersion: string
  stigRelease: string
}

export interface CciFindingRecord {
  cci: string
  apAcronym: string
  definition: string
  ruleCount: number
  assetCount: number
}

export interface FindingOptions {
  /** Group results by 'ruleId' (default), 'groupId', or 'cci'. */
  aggregator?: 'ruleId' | 'groupId' | 'cci'
  /** Filter to a specific severity: 'high', 'medium', or 'low'. */
  severity?: string
}

// ---------------------------------------------------------------------------
// openFindings
// ---------------------------------------------------------------------------

/**
 * Return open findings (fail reviews) for a collection, aggregated by the
 * chosen dimension.
 *
 * aggregator='ruleId' (default):
 *   One row per failing rule with COUNT(DISTINCT assetId) and a comma-separated
 *   list of CCIs sourced from rev_group_rule_cci_map / cci (LEFT JOINs).
 *
 * aggregator='groupId':
 *   One row per STIG group (V-NNNNN) with COUNT(DISTINCT assetId).
 *
 * aggregator='cci':
 *   One row per CCI with ruleCount and assetCount — suitable for NIST
 *   control-level reporting and POA&M generation.
 *
 * All joins to STIG library tables are LEFT JOINs so the function works even
 * if the benchmark has not been imported into rev_group_rule_map.
 */
export async function openFindings(
  collectionId: number,
  options: FindingOptions = {}
): Promise<FindingRecord[] | CciFindingRecord[]> {
  const { aggregator = 'ruleId', severity } = options

  // Build severity predicate (optional)
  const severityPredicate = severity
    ? `AND COALESCE(rgr.severity, rv.severity) = :severity`
    : ''

  if (aggregator === 'cci') {
    return _openFindingsByCci(collectionId, severity)
  }

  // ------------------------------------------------------------------
  // ruleId / groupId aggregation
  // ------------------------------------------------------------------

  // Columns differ by aggregator but the JOIN tree is the same.
  let selectColumns: string
  let groupByClause: string
  let orderByClause: string

  if (aggregator === 'groupId') {
    selectColumns = `
      COALESCE(rgr.groupId,  rv.groupId)               AS groupId,
      ANY_VALUE(COALESCE(rgr.ruleId,   rv.ruleId))     AS ruleId,
      ANY_VALUE(COALESCE(rgr.version,  rv.ruleVersion)) AS ruleVersion,
      ANY_VALUE(COALESCE(rgr.severity, rv.severity))   AS severity,
      ANY_VALUE(COALESCE(rgr.groupTitle, rgr.title, rv.title)) AS title,
      COUNT(DISTINCT rv.assetId)                        AS assetCount,
      NULL                                              AS ccis`
    groupByClause = `COALESCE(rgr.groupId, rv.groupId)`
    orderByClause = `SUBSTRING(COALESCE(rgr.groupId, rv.groupId) FROM 3) + 0`
  } else {
    // ruleId (default)
    selectColumns = `
      COALESCE(rgr.ruleId,  rv.ruleId)                  AS ruleId,
      ANY_VALUE(COALESCE(rgr.groupId,  rv.groupId))     AS groupId,
      ANY_VALUE(COALESCE(rgr.version,  rv.ruleVersion)) AS ruleVersion,
      ANY_VALUE(COALESCE(rgr.severity, rv.severity))    AS severity,
      ANY_VALUE(COALESCE(rgr.title,    rv.title))       AS title,
      COUNT(DISTINCT rv.assetId)                         AS assetCount,
      GROUP_CONCAT(DISTINCT rgrcc.cci ORDER BY rgrcc.cci SEPARATOR ',') AS ccis`
    groupByClause = `COALESCE(rgr.ruleId, rv.ruleId)`
    orderByClause = `COALESCE(rgr.ruleId, rv.ruleId)`
  }

  const sql = `
    SELECT
      ${selectColumns}
    FROM review rv
    INNER JOIN asset a
            ON a.assetId = rv.assetId
           AND a.collectionId = :collectionId
    -- Resolve rule metadata from STIG library if available
    LEFT JOIN rule_version_check_digest rvcd
           ON rvcd.version = rv.version
          AND rvcd.checkDigest = rv.checkDigest
    LEFT JOIN rev_group_rule_map rgr
           ON rgr.ruleId = rvcd.ruleId
    -- CCI mappings (only needed for ruleId aggregator ccis column)
    LEFT JOIN rev_group_rule_cci_map rgrcc
           ON rgrcc.rgrId = rgr.rgrId
    WHERE rv.resultId = (SELECT resultId FROM result WHERE api = 'fail' LIMIT 1)
      ${severityPredicate}
    GROUP BY ${groupByClause}
    ORDER BY ${orderByClause}`

  const binds: Record<string, unknown> = { collectionId }
  if (severity) binds.severity = severity

  let rows: RowDataPacket[]
  try {
    ;[rows] = await pool.query<RowDataPacket[]>(sql, binds as any)
  } catch {
    // Fallback: rvcd / rgr / rgrcc tables absent — query review directly
    const fallbackSql = `
      SELECT
        rv.ruleId,
        ANY_VALUE(rv.groupId)      AS groupId,
        ANY_VALUE(rv.ruleVersion)  AS ruleVersion,
        ANY_VALUE(rv.severity)     AS severity,
        ANY_VALUE(rv.title)        AS title,
        COUNT(DISTINCT rv.assetId) AS assetCount,
        NULL AS ccis
      FROM review rv
      INNER JOIN asset a
              ON a.assetId = rv.assetId
             AND a.collectionId = :collectionId
      WHERE rv.result = 'fail'
        ${severity ? 'AND rv.severity = :severity' : ''}
      GROUP BY rv.ruleId
      ORDER BY rv.ruleId`
    ;[rows] = await pool.query<RowDataPacket[]>(fallbackSql, binds as any)
  }

  return rows.map((row) => ({
    ruleId: (row.ruleId as string) ?? '',
    groupId: (row.groupId as string) ?? '',
    ruleVersion: (row.ruleVersion as string) ?? '',
    severity: (row.severity as string) ?? 'unknown',
    title: (row.title as string) ?? '',
    assetCount: Number(row.assetCount ?? 0),
    ccis: row.ccis
      ? (row.ccis as string).split(',').filter(Boolean)
      : undefined
  })) as FindingRecord[]
}

// ---------------------------------------------------------------------------
// enrichFindingsForPoam — single-query enriched records for eMASS export
// ---------------------------------------------------------------------------

/**
 * Return all open (fail) findings for a collection in a single SQL query,
 * fully enriched with rule details, asset names, NIST control, fix text,
 * and STIG metadata.  No N+1 queries.
 *
 * @param collectionId  Target collection.
 * @param includeNA     When true also include notapplicable results.
 */
export async function enrichFindingsForPoam(
  collectionId: number,
  includeNA = false
): Promise<EnrichedFindingRecord[]> {
  const resultFilter = includeNA
    ? `rv.result IN ('fail', 'notapplicable')`
    : `rv.result = 'fail'`

  const sql = `
    SELECT
      rv.ruleId,
      ANY_VALUE(rv.groupId)                                              AS groupId,
      ANY_VALUE(rv.ruleVersion)                                          AS ruleVersion,
      ANY_VALUE(rv.severity)                                             AS severity,
      ANY_VALUE(rv.title)                                                AS title,
      COUNT(DISTINCT rv.assetId)                                         AS assetCount,
      GROUP_CONCAT(DISTINCT a.name ORDER BY a.name SEPARATOR ', ')       AS assetNames,
      ANY_VALUE(rl.vulnDiscussion)                                       AS vulnDiscussion,
      ANY_VALUE(ft.text)                                                  AS fixText,
      ANY_VALUE(s.title)                                                  AS stigTitle,
      ANY_VALUE(cr.\`version\`)                                          AS stigVersion,
      ANY_VALUE(cr.\`release\`)                                          AS stigRelease,
      ANY_VALUE(crm.parentControl)                                       AS nistControl,
      GROUP_CONCAT(DISTINCT rcm.cci ORDER BY rcm.cci SEPARATOR ',')      AS ccis
    FROM review rv
    JOIN asset a
      ON a.assetId = rv.assetId
     AND a.collectionId = :collectionId
    LEFT JOIN rule rl
      ON rl.ruleId = rv.ruleId
    LEFT JOIN fix_text ft
      ON ft.digest = rl.fixDigest
    LEFT JOIN current_rev cr
      ON cr.benchmarkId = rv.benchmarkId
    LEFT JOIN stig s
      ON s.benchmarkId = rv.benchmarkId
    LEFT JOIN rule_cci_map rcm
      ON rcm.ruleId = rl.ruleId
    LEFT JOIN cci_reference_map crm
      ON crm.cci = rcm.cci
    WHERE ${resultFilter}
    GROUP BY rv.ruleId
    ORDER BY CASE ANY_VALUE(rv.severity) WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`

  let rows: RowDataPacket[]
  try {
    ;[rows] = await pool.query<RowDataPacket[]>(sql, { collectionId })
  } catch {
    // Fallback: extended library tables absent — degrade gracefully
    const fallbackFilter = includeNA
      ? `rv.result IN ('fail', 'notapplicable')`
      : `rv.result = 'fail'`
    const fallbackSql = `
      SELECT
        rv.ruleId,
        ANY_VALUE(rv.groupId)                                             AS groupId,
        ANY_VALUE(rv.ruleVersion)                                         AS ruleVersion,
        ANY_VALUE(rv.severity)                                            AS severity,
        ANY_VALUE(rv.title)                                               AS title,
        COUNT(DISTINCT rv.assetId)                                        AS assetCount,
        GROUP_CONCAT(DISTINCT a.name ORDER BY a.name SEPARATOR ', ')      AS assetNames,
        NULL AS vulnDiscussion,
        NULL AS fixText,
        NULL AS stigTitle,
        NULL AS stigVersion,
        NULL AS stigRelease,
        NULL AS nistControl,
        NULL AS ccis
      FROM review rv
      JOIN asset a
        ON a.assetId = rv.assetId
       AND a.collectionId = :collectionId
      WHERE ${fallbackFilter}
      GROUP BY rv.ruleId
      ORDER BY CASE ANY_VALUE(rv.severity) WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`
    ;[rows] = await pool.query<RowDataPacket[]>(fallbackSql, { collectionId })
  }

  return rows.map((row) => ({
    ruleId:        (row.ruleId as string)        ?? '',
    groupId:       (row.groupId as string)       ?? '',
    ruleVersion:   (row.ruleVersion as string)   ?? '',
    severity:      (row.severity as string)      ?? 'unknown',
    title:         (row.title as string)         ?? '',
    assetCount:    Number(row.assetCount ?? 0),
    assetNames:    row.assetNames
                     ? (row.assetNames as string).split(', ').filter(Boolean)
                     : [],
    ccis:          row.ccis
                     ? (row.ccis as string).split(',').filter(Boolean)
                     : [],
    nistControl:   (row.nistControl as string)   ?? '',
    vulnDiscussion:(row.vulnDiscussion as string) ?? '',
    fixText:       (row.fixText as string)       ?? '',
    stigTitle:     (row.stigTitle as string)     ?? '',
    stigVersion:   (row.stigVersion as string)   ?? '',
    stigRelease:   (row.stigRelease as string)   ?? '',
  }))
}

// ---------------------------------------------------------------------------
// CCI-aggregated findings (internal helper)
// ---------------------------------------------------------------------------

async function _openFindingsByCci(
  collectionId: number,
  severity?: string
): Promise<CciFindingRecord[]> {
  const severityPredicate = severity
    ? `AND COALESCE(rgr.severity, rv.severity) = :severity`
    : ''

  const sql = `
    SELECT
      cci.cci,
      cci.apAcronym,
      cci.definition,
      COUNT(DISTINCT COALESCE(rgr.ruleId, rv.ruleId)) AS ruleCount,
      COUNT(DISTINCT rv.assetId)                       AS assetCount
    FROM review rv
    INNER JOIN asset a
            ON a.assetId = rv.assetId
           AND a.collectionId = :collectionId
    LEFT JOIN rule_version_check_digest rvcd
           ON rvcd.version = rv.version
          AND rvcd.checkDigest = rv.checkDigest
    LEFT JOIN rev_group_rule_map rgr
           ON rgr.ruleId = rvcd.ruleId
    INNER JOIN rev_group_rule_cci_map rgrcc
            ON rgrcc.rgrId = rgr.rgrId
    INNER JOIN cci
            ON cci.cci = rgrcc.cci
    WHERE rv.resultId = (SELECT resultId FROM result WHERE api = 'fail' LIMIT 1)
      ${severityPredicate}
    GROUP BY cci.cci
    ORDER BY cci.cci`

  const binds: Record<string, unknown> = { collectionId }
  if (severity) binds.severity = severity

  let rows: RowDataPacket[]
  try {
    ;[rows] = await pool.query<RowDataPacket[]>(sql, binds as any)
  } catch {
    // CCI tables not available — return empty array gracefully
    return []
  }

  return rows.map((row) => ({
    cci: row.cci as string,
    apAcronym: (row.apAcronym as string) ?? '',
    definition: (row.definition as string) ?? '',
    ruleCount: Number(row.ruleCount ?? 0),
    assetCount: Number(row.assetCount ?? 0)
  }))
}
