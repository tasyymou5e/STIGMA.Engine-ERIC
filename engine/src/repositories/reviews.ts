import type { ResultSetHeader, RowDataPacket, PoolConnection } from 'mysql2/promise'
import { pool } from '../db/pool.js'
import type { NormalizedReview } from '../engine/types.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ChecklistRule {
  ruleId: string
  groupId: string | null
  ruleVersion: string | null
  severity: string | null
  title: string | null
  totalAssets: number
  passCount: number
  failCount: number
  naCount: number
  nrCount: number
  submittedCount: number
  rejectedCount: number
  acceptedCount: number
}

export interface ChecklistReview extends NormalizedReview {
  reviewId: number
  assetId: number
  assetName: string
  status: string | null
  statusText: string | null
  username: string | null
  ts: string | null
}

export interface ReviewRecord {
  reviewId: number
  assetId: number
  ruleId: string
  resultId: number | null
  result: string | null
  detail: string
  comment: string
  status: string | null
  statusId: number
  statusText: string | null
  userId: number | null
  username: string | null
  ts: string | null
  statusTs: string | null
  touchTs: string | null
  version: string | null
  checkDigest: string | null
  metadata: Record<string, unknown> | null
  resultEngine: Record<string, unknown> | null
}

export interface ReviewHistoryRecord {
  historyId: number
  reviewId: number
  ruleId: string
  resultId: number | null
  result: string | null
  detail: string
  comment: string
  autoResult: boolean
  ts: string | null
  touchTs: string | null
  userId: number | null
  username: string | null
  statusId: number
  statusText: string | null
  statusUserId: number | null
  statusTs: string | null
  resultEngine: Record<string, unknown> | null
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Escape a string value for use in a SQL literal (wraps in single quotes,
 *  doubles interior single-quotes).  Used only when building bulk-VALUES
 *  lists where parameterised placeholders are impractical. */
function sqlStr(v: string | null | undefined): string {
  if (v == null) return 'NULL'
  return `'${v.replace(/'/g, "''")}'`
}

function sqlNum(v: number | null | undefined): string {
  return v == null ? 'NULL' : String(v)
}

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------

export async function listReviewsByAsset(assetId: number): Promise<NormalizedReview[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT ruleId, groupId, ruleVersion, severity, title, result, detail, comment
       FROM review WHERE assetId = :id`,
    { id: assetId }
  )
  return rows as unknown as NormalizedReview[]
}

export async function listReviewsByCollection(collectionId: number): Promise<NormalizedReview[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT r.ruleId, r.groupId, r.ruleVersion, r.severity, r.title, r.result, r.detail, r.comment
       FROM review r JOIN asset a ON a.assetId = r.assetId
      WHERE a.collectionId = :id`,
    { id: collectionId }
  )
  return rows as unknown as NormalizedReview[]
}

// ---------------------------------------------------------------------------
// getReview
// ---------------------------------------------------------------------------

/**
 * Fetch a single review by assetId + ruleId.
 * Joins result, status, user_data, and rule_version_check_digest (LEFT JOIN so
 * the row is returned even when no rvcd entry exists for the rule).
 */
export async function getReview(
  assetId: number,
  ruleId: string
): Promise<ReviewRecord | null> {
  const sql = `
    SELECT
      r.reviewId,
      r.assetId,
      rvcd.ruleId,
      r.resultId,
      res.api            AS result,
      COALESCE(LEFT(r.detail,  32767), '') AS detail,
      COALESCE(LEFT(r.comment, 32767), '') AS comment,
      st.api             AS status,
      r.statusId,
      r.statusText,
      r.userId,
      ud.username,
      DATE_FORMAT(r.ts,       '%Y-%m-%dT%H:%i:%sZ') AS ts,
      DATE_FORMAT(r.statusTs, '%Y-%m-%dT%H:%i:%sZ') AS statusTs,
      DATE_FORMAT(r.touchTs,  '%Y-%m-%dT%H:%i:%sZ') AS touchTs,
      r.version,
      r.checkDigest,
      r.metadata,
      CASE WHEN r.resultEngine = 0 THEN NULL ELSE r.resultEngine END AS resultEngine
    FROM review r
    LEFT JOIN rule_version_check_digest rvcd
           ON (r.version = rvcd.version AND r.checkDigest = rvcd.checkDigest)
    LEFT JOIN result  res ON r.resultId  = res.resultId
    LEFT JOIN status  st  ON r.statusId  = st.statusId
    LEFT JOIN user_data ud ON r.userId   = ud.userId
    WHERE r.assetId = :assetId
      AND rvcd.ruleId = :ruleId
    LIMIT 1`
  const [rows] = await pool.query<RowDataPacket[]>(sql, { assetId, ruleId })
  return rows.length > 0 ? (rows[0] as unknown as ReviewRecord) : null
}

// ---------------------------------------------------------------------------
// deleteReview
// ---------------------------------------------------------------------------

/**
 * Delete a review identified by assetId + ruleId.
 * Follows the upstream pattern: joins rule_version_check_digest to resolve
 * the ruleId to version/checkDigest which is the actual PK axis on review.
 */
export async function deleteReview(
  assetId: number,
  ruleId: string
): Promise<boolean> {
  const sql = `
    DELETE review
    FROM review
    LEFT JOIN rule_version_check_digest rvcd
           ON (rvcd.version = review.version AND rvcd.checkDigest = review.checkDigest)
    WHERE review.assetId = :assetId
      AND rvcd.ruleId    = :ruleId`
  const [res] = await pool.query<ResultSetHeader>(sql, { assetId, ruleId })
  return res.affectedRows > 0
}

// ---------------------------------------------------------------------------
// patchReview
// ---------------------------------------------------------------------------

/**
 * Partial UPDATE — only the fields present in `patch` are written.
 * Allowed patch fields: result, detail, comment, status, statusText, metadata,
 * resultEngine.  status/result are translated to their *Id counterparts via
 * sub-selects so the caller can pass string API values.
 */
export async function patchReview(
  assetId: number,
  ruleId: string,
  patch: Partial<ReviewRecord>,
  _username?: string,
  _options?: { upsert?: boolean }
): Promise<boolean> {
  const setClauses: string[] = []
  const binds: Record<string, unknown> = { assetId, ruleId }

  if (patch.result !== undefined) {
    // Keep both the lookup-FK column and the ENUM column in sync
    setClauses.push('r.resultId = (SELECT resultId FROM result WHERE api = :pResult LIMIT 1)')
    setClauses.push('r.result = :pResult')
    binds.pResult = patch.result
  }
  if (patch.detail !== undefined) {
    setClauses.push('r.detail = :pDetail')
    binds.pDetail = patch.detail
  }
  if (patch.comment !== undefined) {
    setClauses.push('r.comment = :pComment')
    binds.pComment = patch.comment
  }
  if (patch.status !== undefined) {
    setClauses.push('r.statusId = (SELECT statusId FROM status WHERE api = :pStatus LIMIT 1)')
    binds.pStatus = patch.status
  }
  if (patch.statusText !== undefined) {
    setClauses.push('r.statusText = :pStatusText')
    binds.pStatusText = patch.statusText
  }
  if (patch.metadata !== undefined) {
    setClauses.push('r.metadata = :pMetadata')
    binds.pMetadata = JSON.stringify(patch.metadata)
  }
  if (patch.resultEngine !== undefined) {
    setClauses.push('r.resultEngine = :pResultEngine')
    binds.pResultEngine = patch.resultEngine == null ? 0 : JSON.stringify(patch.resultEngine)
  }

  if (setClauses.length === 0) return false

  const sql = `
    UPDATE review r
    SET ${setClauses.join(',\n        ')}
    WHERE r.assetId = :assetId
      AND r.ruleId  = :ruleId`

  const [res] = await pool.query<ResultSetHeader>(sql, binds as unknown as import('mysql2').QueryValues)
  return res.affectedRows > 0
}

// ---------------------------------------------------------------------------
// listReviewHistory
// ---------------------------------------------------------------------------

/**
 * Return all history rows for a given reviewId, newest first.
 */
export async function listReviewHistory(reviewId: number): Promise<ReviewHistoryRecord[]> {
  const sql = `
    SELECT
      rh.historyId,
      rh.reviewId,
      rh.ruleId,
      rh.resultId,
      res.api             AS result,
      COALESCE(LEFT(rh.detail,  32767), '') AS detail,
      COALESCE(LEFT(rh.comment, 32767), '') AS comment,
      rh.autoResult,
      DATE_FORMAT(rh.ts,       '%Y-%m-%dT%H:%i:%sZ') AS ts,
      DATE_FORMAT(rh.touchTs,  '%Y-%m-%dT%H:%i:%sZ') AS touchTs,
      rh.userId,
      ud.username,
      rh.statusId,
      rh.statusText,
      rh.statusUserId,
      DATE_FORMAT(rh.statusTs, '%Y-%m-%dT%H:%i:%sZ') AS statusTs,
      CASE WHEN rh.resultEngine = 0 THEN NULL ELSE rh.resultEngine END AS resultEngine
    FROM review_history rh
    LEFT JOIN result    res ON rh.resultId = res.resultId
    LEFT JOIN user_data ud  ON rh.userId   = ud.userId
    WHERE rh.reviewId = :reviewId
    ORDER BY rh.historyId DESC`
  const [rows] = await pool.query<RowDataPacket[]>(sql, { reviewId })
  return rows as unknown as ReviewHistoryRecord[]
}

// ---------------------------------------------------------------------------
// setReviewStatus
// ---------------------------------------------------------------------------

export async function setReviewStatus(
  assetId: number,
  ruleId: string,
  status: 'saved' | 'submitted' | 'accepted' | 'rejected'
): Promise<boolean> {
  const [res] = await pool.query<ResultSetHeader>(
    'UPDATE review SET status = :status WHERE assetId = :assetId AND ruleId = :ruleId',
    { status, assetId, ruleId }
  )
  return res.affectedRows > 0
}

// ---------------------------------------------------------------------------
// upsertReviews
// ---------------------------------------------------------------------------

/**
 * Bulk-upsert a batch of NormalizedReviews for a given asset.
 *
 * Enhancements over the original per-row loop:
 *
 * 1. resultId  — resolved by joining `result WHERE api = :result`
 * 2. version / checkDigest — resolved via LEFT JOIN on rule_version_check_digest
 *    (nullable; rows without an rvcd entry still upsert with NULL version/digest)
 * 3. userId    — resolved from user_data WHERE username = :username
 * 4. history   — prior state of every updated review is snapshotted into
 *                review_history before the upsert writes new values
 * 5. bulk INSERT — a single multi-row VALUES (...),(...) statement replaces
 *    the old per-row loop, giving far better throughput on large batches
 *
 * Returns the total number of affected rows (inserts + updates).
 */
export async function upsertReviews(
  assetId: number,
  benchmarkId: string,
  reviews: NormalizedReview[],
  username: string
): Promise<number> {
  if (reviews.length === 0) return 0

  const conn = await pool.getConnection()
  try {
    await conn.beginTransaction()

    // ------------------------------------------------------------------
    // 1.  Resolve userId from username
    // ------------------------------------------------------------------
    const [userRows] = await conn.query<RowDataPacket[]>(
      'SELECT userId FROM user_data WHERE username = ? LIMIT 1',
      [username]
    )
    const userId: number | null = userRows.length > 0 ? (userRows[0].userId as number) : null

    // ------------------------------------------------------------------
    // 2.  Resolve resultId for every distinct result string in the batch,
    //     and version/checkDigest for every distinct ruleId.
    //     We fetch all at once to avoid N+1 round-trips.
    // ------------------------------------------------------------------
    const distinctResults = [...new Set(reviews.map(r => r.result))]
    const distinctRuleIds = [...new Set(reviews.map(r => r.ruleId))]

    // result  => resultId
    const resultMap = new Map<string, number>()
    if (distinctResults.length > 0) {
      const placeholders = distinctResults.map(() => '?').join(',')
      const [resRows] = await conn.query<RowDataPacket[]>(
        `SELECT api, resultId FROM result WHERE api IN (${placeholders})`,
        distinctResults
      )
      for (const row of resRows) {
        resultMap.set(row.api as string, row.resultId as number)
      }
    }

    // ruleId  => { version, checkDigest }
    const rvcdMap = new Map<string, { version: string; checkDigest: string }>()
    try {
      const placeholders = distinctRuleIds.map(() => '?').join(',')
      const [rvcdRows] = await conn.query<RowDataPacket[]>(
        `SELECT ruleId, version, checkDigest
           FROM rule_version_check_digest
          WHERE ruleId IN (${placeholders})`,
        distinctRuleIds
      )
      for (const row of rvcdRows) {
        rvcdMap.set(row.ruleId as string, {
          version: row.version as string,
          checkDigest: row.checkDigest as string
        })
      }
    } catch {
      // table may not exist in all deployments — treat as empty map
    }

    // ------------------------------------------------------------------
    // 3.  Snapshot prior state of reviews that already exist (for history)
    //     We identify them by assetId + ruleId (via rvcd join) and collect
    //     their current reviewId values so we can INSERT history rows.
    // ------------------------------------------------------------------
    const ruleIdPlaceholders = distinctRuleIds.map(() => '?').join(',')

    // Fetch existing reviewIds that will be updated (not inserted)
    let existingReviewIds: number[] = []
    try {
      const [existRows] = await conn.query<RowDataPacket[]>(
        `SELECT r.reviewId
           FROM review r
           LEFT JOIN rule_version_check_digest rvcd
                  ON (r.version = rvcd.version AND r.checkDigest = rvcd.checkDigest)
          WHERE r.assetId = ?
            AND rvcd.ruleId IN (${ruleIdPlaceholders})`,
        [assetId, ...distinctRuleIds]
      )
      existingReviewIds = existRows.map(row => row.reviewId as number)
    } catch {
      // rvcd table absent — fall back gracefully
      const [existRows] = await conn.query<RowDataPacket[]>(
        `SELECT reviewId FROM review WHERE assetId = ? AND ruleId IN (${ruleIdPlaceholders})`,
        [assetId, ...distinctRuleIds]
      )
      existingReviewIds = existRows.map(row => row.reviewId as number)
    }

    // ------------------------------------------------------------------
    // 4.  Write history for rows that are about to be updated
    // ------------------------------------------------------------------
    if (existingReviewIds.length > 0) {
      const idPlaceholders = existingReviewIds.map(() => '?').join(',')
      await conn.query(
        `INSERT INTO review_history (
           reviewId, ruleId, resultId, detail, comment, autoResult,
           ts, userId, statusText, statusUserId, statusTs, statusId,
           touchTs, resultEngine
         )
         SELECT
           reviewId, ruleId, resultId,
           LEFT(detail,  32767),
           LEFT(comment, 32767),
           autoResult, ts, userId, statusText, statusUserId, statusTs,
           statusId, touchTs,
           CASE WHEN resultEngine = 0 THEN NULL ELSE resultEngine END
         FROM review
         WHERE reviewId IN (${idPlaceholders})
         FOR UPDATE`,
        existingReviewIds
      )
    }

    // ------------------------------------------------------------------
    // 5.  Build bulk VALUES list and execute a single INSERT … ON DUPLICATE
    // ------------------------------------------------------------------
    //
    // Row shape (matches column list below):
    //   assetId, benchmarkId, ruleId, groupId, ruleVersion, severity,
    //   title, resultId, detail, comment, username, userId, version, checkDigest
    //
    const valueFragments: string[] = reviews.map(r => {
      const resultId = sqlNum(resultMap.get(r.result) ?? null)
      const rvcd = rvcdMap.get(r.ruleId)
      const version = sqlStr(rvcd?.version ?? null)
      const checkDigest = sqlStr(rvcd?.checkDigest ?? null)

      return (
        '(' +
        [
          sqlNum(assetId),
          sqlStr(benchmarkId),
          sqlStr(r.ruleId),
          sqlStr(r.groupId),
          sqlStr(r.ruleVersion),
          sqlStr(r.severity),
          sqlStr(r.title),
          resultId,
          sqlStr(r.result),        // keep ENUM column in sync — metrics reads this
          sqlStr(r.detail),
          sqlStr(r.comment),
          sqlStr(username),
          sqlNum(userId),
          version,
          checkDigest
        ].join(', ') +
        ')'
      )
    })

    const bulkSql = `
      INSERT INTO review
        (assetId, benchmarkId, ruleId, groupId, ruleVersion, severity,
         title, resultId, result, detail, comment, username, userId, version, checkDigest)
      VALUES ${valueFragments.join(',\n      ')}
      ON DUPLICATE KEY UPDATE
        resultId   = VALUES(resultId),
        result     = VALUES(result),
        detail     = VALUES(detail),
        comment    = VALUES(comment),
        severity   = VALUES(severity),
        title      = VALUES(title),
        ruleVersion= VALUES(ruleVersion),
        username   = VALUES(username),
        userId     = VALUES(userId),
        version    = VALUES(version),
        checkDigest= VALUES(checkDigest)`

    const [res] = await conn.query<ResultSetHeader>(bulkSql)

    await conn.commit()

    // ------------------------------------------------------------------
    // 6.  Refresh stig_asset_map rollup counters for this (assetId, benchmarkId)
    //     so per-STIG metrics stay in sync.  Runs after commit so the new
    //     review rows are visible to the aggregation query.
    // ------------------------------------------------------------------
    try {
      await refreshStigAssetMap(conn, assetId, benchmarkId)
    } catch {
      // Non-fatal: table may not exist in all deployments; metrics will fall
      // back to the live-aggregate queries.
    }

    // affectedRows counts 1 for an insert, 2 for an update-on-duplicate
    return res.affectedRows
  } catch (e) {
    await conn.rollback()
    throw e
  } finally {
    conn.release()
  }
}

// ---------------------------------------------------------------------------
// refreshStigAssetMap
// ---------------------------------------------------------------------------

/**
 * Recompute all rollup counters for a single (assetId, benchmarkId) pair and
 * upsert the result into stig_asset_map.
 *
 * Called automatically after every upsertReviews commit so that per-STIG
 * metrics (pass, fail, highCount, etc.) never show stale zeros.
 *
 * Uses the review table's string columns (result, status, severity) directly
 * because the aggregation query is executed outside a JOIN context and the
 * enum-based resultId / statusId are not needed here.
 */
export async function refreshStigAssetMap(
  conn: PoolConnection,
  assetId: number,
  benchmarkId: string
): Promise<void> {
  // ------------------------------------------------------------------
  // 1. Aggregate current review state for this (assetId, benchmarkId)
  // ------------------------------------------------------------------
  const aggSql = `
    SELECT
      SUM(result = 'pass')                              AS passCount,
      SUM(result = 'fail')                              AS failCount,
      SUM(result = 'notchecked')                        AS notchecked,
      SUM(result = 'notapplicable')                     AS notapplicable,
      SUM(result = 'informational')                     AS informational,
      SUM(severity = 'high'   AND result = 'fail')      AS highCount,
      SUM(severity = 'medium' AND result = 'fail')      AS mediumCount,
      SUM(severity = 'low'    AND result = 'fail')      AS lowCount,
      SUM(status = 'saved')                             AS saved,
      SUM(status = 'submitted')                         AS submitted,
      SUM(status = 'accepted')                          AS accepted,
      SUM(status = 'rejected')                          AS rejected,
      MIN(ts)                                           AS minTs,
      MAX(ts)                                           AS maxTs
    FROM review
    WHERE assetId     = ?
      AND benchmarkId = ?`

  const [aggRows] = await conn.query<RowDataPacket[]>(aggSql, [assetId, benchmarkId])
  const agg = aggRows[0] ?? {}

  // ------------------------------------------------------------------
  // 2. Upsert into stig_asset_map
  // ------------------------------------------------------------------
  const upsertSql = `
    INSERT INTO stig_asset_map
      (benchmarkId, assetId, pass, fail, notchecked, notapplicable,
       informational, highCount, mediumCount, lowCount,
       saved, submitted, accepted, rejected, minTs, maxTs)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      pass          = VALUES(pass),
      fail          = VALUES(fail),
      notchecked    = VALUES(notchecked),
      notapplicable = VALUES(notapplicable),
      informational = VALUES(informational),
      highCount     = VALUES(highCount),
      mediumCount   = VALUES(mediumCount),
      lowCount      = VALUES(lowCount),
      saved         = VALUES(saved),
      submitted     = VALUES(submitted),
      accepted      = VALUES(accepted),
      rejected      = VALUES(rejected),
      minTs         = VALUES(minTs),
      maxTs         = VALUES(maxTs)`

  await conn.query(upsertSql, [
    benchmarkId,
    assetId,
    Number(agg.passCount     ?? 0),
    Number(agg.failCount     ?? 0),
    Number(agg.notchecked    ?? 0),
    Number(agg.notapplicable ?? 0),
    Number(agg.informational ?? 0),
    Number(agg.highCount     ?? 0),
    Number(agg.mediumCount   ?? 0),
    Number(agg.lowCount      ?? 0),
    Number(agg.saved         ?? 0),
    Number(agg.submitted     ?? 0),
    Number(agg.accepted      ?? 0),
    Number(agg.rejected      ?? 0),
    agg.minTs ?? null,
    agg.maxTs ?? null,
  ])
}

// ---------------------------------------------------------------------------
// carryReviewsOnRevisionUpgrade
// ---------------------------------------------------------------------------

/**
 * Content-hash review persistence: carry reviews from any prior revision of a
 * benchmark into the new revision for a given asset.
 *
 * Algorithm:
 * 1. Collect all existing reviews for (assetId, benchmarkId) — any revision —
 *    keyed by their stored checkDigest (BINARY(32) hex string).
 * 2. Collect all rules in newRevId from the `rule` table, keyed by checkDigest.
 * 3. For each new rule whose checkDigest matches an existing review's checkDigest
 *    (meaning the check content is identical across the revision boundary):
 *    - Upsert a review row for the new ruleId carrying result/detail/comment
 *      from the old review, and update version/checkDigest to the new values.
 * 4. Return the number of reviews that were carried.
 *
 * This implements the upstream STIG Manager feature: reviews survive STIG revision
 * changes when check content (SHA-256) is unchanged, regardless of ruleId changes.
 */
export async function carryReviewsOnRevisionUpgrade(
  assetId: number,
  benchmarkId: string,
  newRevId: string,
  username: string
): Promise<number> {
  const conn = await pool.getConnection()
  try {
    await conn.beginTransaction()

    // ------------------------------------------------------------------
    // 1. Fetch existing reviews for (assetId, benchmarkId) that have a
    //    checkDigest stored (i.e., they were ingested with content-hash binding).
    //    We use HEX() to get a comparable string key from the BINARY column.
    // ------------------------------------------------------------------
    const [existingRows] = await conn.query<RowDataPacket[]>(
      `SELECT ruleId, resultId, detail, comment, HEX(checkDigest) AS checkDigestHex
         FROM review
        WHERE assetId     = ?
          AND benchmarkId = ?
          AND checkDigest IS NOT NULL`,
      [assetId, benchmarkId]
    )

    if (existingRows.length === 0) {
      await conn.commit()
      return 0
    }

    // Map: checkDigestHex => existing review data
    const existingByDigest = new Map<
      string,
      { ruleId: string; resultId: number | null; detail: string; comment: string }
    >()
    for (const row of existingRows) {
      // When multiple old reviews share the same digest (shouldn't normally happen)
      // keep the most-recently seen one; the map will naturally do last-write-wins.
      existingByDigest.set(row.checkDigestHex as string, {
        ruleId: row.ruleId as string,
        resultId: row.resultId as number | null,
        detail: (row.detail as string) ?? '',
        comment: (row.comment as string) ?? '',
      })
    }

    // ------------------------------------------------------------------
    // 2. Fetch all rules in newRevId with a checkDigest.
    //    Columns needed: ruleId, version (rule version string), checkDigest
    // ------------------------------------------------------------------
    const [newRuleRows] = await conn.query<RowDataPacket[]>(
      `SELECT ruleId, \`version\`, HEX(checkDigest) AS checkDigestHex, checkDigest,
              groupId, severity, title
         FROM rule
        WHERE revId       = ?
          AND checkDigest IS NOT NULL`,
      [newRevId]
    )

    if (newRuleRows.length === 0) {
      await conn.commit()
      return 0
    }

    // ------------------------------------------------------------------
    // 3. Determine which new rules have a matching old review by checkDigest.
    //    Skip rules that are already covered by an existing review with the
    //    same ruleId (same rule, same asset — upsertReviews handles those).
    // ------------------------------------------------------------------
    interface CarryCandidate {
      newRuleId: string
      newVersion: string
      checkDigest: Buffer
      checkDigestHex: string
      groupId: string | null
      severity: string | null
      title: string | null
      oldResultId: number | null
      oldDetail: string
      oldComment: string
    }

    // Build a set of ruleIds already present for this asset+benchmarkId so we
    // don't double-carry into a rule that already has its own review row.
    const [ownedRows] = await conn.query<RowDataPacket[]>(
      `SELECT ruleId FROM review WHERE assetId = ? AND benchmarkId = ?`,
      [assetId, benchmarkId]
    )
    const ownedRuleIds = new Set(ownedRows.map(r => r.ruleId as string))

    const candidates: CarryCandidate[] = []
    for (const nr of newRuleRows) {
      const hex = nr.checkDigestHex as string
      const existing = existingByDigest.get(hex)
      if (!existing) continue              // no matching old review
      if (ownedRuleIds.has(nr.ruleId as string)) continue  // already has a review
      if (existing.ruleId === nr.ruleId) continue           // same ruleId — not a carry

      candidates.push({
        newRuleId: nr.ruleId as string,
        newVersion: (nr.version as string) ?? '',
        checkDigest: nr.checkDigest as Buffer,
        checkDigestHex: hex,
        groupId: (nr.groupId as string) ?? null,
        severity: (nr.severity as string) ?? null,
        title: (nr.title as string) ?? null,
        oldResultId: existing.resultId,
        oldDetail: existing.detail,
        oldComment: existing.comment,
      })
    }

    if (candidates.length === 0) {
      await conn.commit()
      return 0
    }

    // ------------------------------------------------------------------
    // 4. Resolve userId for history bookkeeping
    // ------------------------------------------------------------------
    const [userRows] = await conn.query<RowDataPacket[]>(
      'SELECT userId FROM user_data WHERE username = ? LIMIT 1',
      [username]
    )
    const userId: number | null = userRows.length > 0 ? (userRows[0].userId as number) : null

    // ------------------------------------------------------------------
    // 5. Upsert carried reviews — one INSERT … ON DUPLICATE KEY per candidate
    //    so we can pass the binary checkDigest correctly.
    //    (A bulk VALUES list would require manual hex→binary conversion; doing
    //    it per-row keeps the code readable and the batch is typically small.)
    // ------------------------------------------------------------------
    let carried = 0
    for (const c of candidates) {
      const [res] = await conn.query<ResultSetHeader>(
        `INSERT INTO review
           (assetId, benchmarkId, ruleId, groupId, severity, title,
            resultId, detail, comment, username, userId, version, checkDigest)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           resultId    = VALUES(resultId),
           detail      = VALUES(detail),
           comment     = VALUES(comment),
           severity    = VALUES(severity),
           title       = VALUES(title),
           username    = VALUES(username),
           userId      = VALUES(userId),
           version     = VALUES(version),
           checkDigest = VALUES(checkDigest)`,
        [
          assetId, benchmarkId, c.newRuleId, c.groupId, c.severity, c.title,
          c.oldResultId, c.oldDetail, c.oldComment,
          username, userId, c.newVersion, c.checkDigest,
        ]
      )
      if (res.affectedRows > 0) carried++
    }

    await conn.commit()
    return carried
  } catch (e) {
    await conn.rollback()
    throw e
  } finally {
    conn.release()
  }
}

// ---------------------------------------------------------------------------
// listCollectionReviewHistory
// ---------------------------------------------------------------------------

export interface CollectionReviewHistoryRecord extends ReviewHistoryRecord {
  assetName: string
}

/**
 * Return review_history rows scoped to a collection.
 * Optionally filter by ruleId and/or assetId.  Ordered newest-first.
 */
export async function listCollectionReviewHistory(
  collectionId: number,
  params: { ruleId?: string; assetId?: number; maxResults?: number } = {}
): Promise<CollectionReviewHistoryRecord[]> {
  const maxResults = params.maxResults ?? 500
  const sql = `
    SELECT
      rh.historyId,
      rh.reviewId,
      rv.ruleId,
      rh.resultId,
      res.api             AS result,
      COALESCE(LEFT(rh.detail,  32767), '') AS detail,
      COALESCE(LEFT(rh.comment, 32767), '') AS comment,
      rh.autoResult,
      DATE_FORMAT(rh.ts,       '%Y-%m-%dT%H:%i:%sZ') AS ts,
      DATE_FORMAT(rh.touchTs,  '%Y-%m-%dT%H:%i:%sZ') AS touchTs,
      rh.userId,
      ud.username,
      rh.statusId,
      rh.statusText,
      rh.statusUserId,
      DATE_FORMAT(rh.statusTs, '%Y-%m-%dT%H:%i:%sZ') AS statusTs,
      CASE WHEN rh.resultEngine = 0 THEN NULL ELSE rh.resultEngine END AS resultEngine,
      a.name AS assetName
    FROM review_history rh
    JOIN review rv ON rv.reviewId = rh.reviewId
    JOIN asset  a  ON a.assetId   = rv.assetId AND a.collectionId = :collectionId
    LEFT JOIN result    res ON rh.resultId = res.resultId
    LEFT JOIN user_data ud  ON rh.userId   = ud.userId
    WHERE (:ruleId  IS NULL OR rv.ruleId  = :ruleId)
      AND (:assetId IS NULL OR rv.assetId = :assetId)
    ORDER BY rh.historyId DESC
    LIMIT :maxResults`
  const [rows] = await pool.query<RowDataPacket[]>(sql, {
    collectionId,
    ruleId:     params.ruleId  ?? null,
    assetId:    params.assetId ?? null,
    maxResults
  })
  return rows as unknown as CollectionReviewHistoryRecord[]
}

// ---------------------------------------------------------------------------
// deleteCollectionReviewHistory
// ---------------------------------------------------------------------------

/**
 * Delete review_history rows for a collection.
 * When retainDays is supplied, only rows older than that many days are removed.
 * Returns the number of deleted rows.
 */
export async function deleteCollectionReviewHistory(
  collectionId: number,
  retainDays?: number
): Promise<number> {
  let sql: string
  const binds: Record<string, unknown> = { collectionId }

  if (retainDays != null && retainDays > 0) {
    sql = `
      DELETE rh FROM review_history rh
      JOIN review rv ON rv.reviewId = rh.reviewId
      JOIN asset  a  ON a.assetId   = rv.assetId AND a.collectionId = :collectionId
      WHERE rh.ts < DATE_SUB(NOW(), INTERVAL :retainDays DAY)`
    binds.retainDays = retainDays
  } else {
    sql = `
      DELETE rh FROM review_history rh
      JOIN review rv ON rv.reviewId = rh.reviewId
      JOIN asset  a  ON a.assetId   = rv.assetId AND a.collectionId = :collectionId`
  }

  const [res] = await pool.query<ResultSetHeader>(
    sql,
    binds as unknown as import('mysql2').QueryValues
  )
  return res.affectedRows
}

// ---------------------------------------------------------------------------
// getCollectionReviewHistoryStats
// ---------------------------------------------------------------------------

export interface CollectionReviewHistoryStats {
  totalRows: number
  oldestTs:  string | null
  newestTs:  string | null
}

/**
 * Return aggregate statistics about review_history for a collection.
 */
export async function getCollectionReviewHistoryStats(
  collectionId: number
): Promise<CollectionReviewHistoryStats> {
  const sql = `
    SELECT
      COUNT(*)                                               AS totalRows,
      DATE_FORMAT(MIN(rh.ts), '%Y-%m-%dT%H:%i:%sZ')        AS oldestTs,
      DATE_FORMAT(MAX(rh.ts), '%Y-%m-%dT%H:%i:%sZ')        AS newestTs
    FROM review_history rh
    JOIN review rv ON rv.reviewId = rh.reviewId
    JOIN asset  a  ON a.assetId   = rv.assetId AND a.collectionId = :collectionId`
  const [rows] = await pool.query<RowDataPacket[]>(sql, { collectionId })
  const row = rows[0] ?? {}
  return {
    totalRows: Number(row.totalRows ?? 0),
    oldestTs:  (row.oldestTs  as string | null) ?? null,
    newestTs:  (row.newestTs  as string | null) ?? null
  }
}

// ---------------------------------------------------------------------------
// checklistRules
// ---------------------------------------------------------------------------

/**
 * Aggregate review results per ruleId across all assets in a collection
 * for a given benchmarkId.  Optionally filtered to a single assetId.
 *
 * Returns one ChecklistRule row per ruleId, ordered by severity then ruleId.
 */
export async function checklistRules(
  collectionId: number,
  benchmarkId: string,
  assetId?: number
): Promise<ChecklistRule[]> {
  const sql = `
    SELECT
      rv.ruleId,
      ANY_VALUE(rv.groupId)      AS groupId,
      ANY_VALUE(rv.ruleVersion)  AS ruleVersion,
      ANY_VALUE(rv.severity)     AS severity,
      ANY_VALUE(rv.title)        AS title,
      COUNT(rv.reviewId)                                                   AS totalAssets,
      SUM(rv.result = 'pass')                                              AS passCount,
      SUM(rv.result = 'fail')                                              AS failCount,
      SUM(rv.result = 'notapplicable')                                     AS naCount,
      SUM(CASE WHEN rv.result NOT IN ('pass','fail','notapplicable') THEN 1 ELSE 0 END) AS nrCount,
      SUM(rv.status = 'submitted')                                         AS submittedCount,
      SUM(rv.status = 'rejected')                                          AS rejectedCount,
      SUM(rv.status = 'accepted')                                          AS acceptedCount
    FROM review rv
    JOIN asset a ON a.assetId = rv.assetId AND a.collectionId = :collectionId
    WHERE rv.benchmarkId = :benchmarkId
      AND ((:assetId IS NULL) OR rv.assetId = :assetId)
    GROUP BY rv.ruleId
    ORDER BY
      CASE ANY_VALUE(rv.severity) WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
      rv.ruleId`
  const [rows] = await pool.query<RowDataPacket[]>(sql, {
    collectionId,
    benchmarkId,
    assetId: assetId ?? null
  })
  return rows as unknown as ChecklistRule[]
}

// ---------------------------------------------------------------------------
// checklistReviews
// ---------------------------------------------------------------------------

/**
 * Return all reviews for a specific ruleId across every asset in a collection
 * for a given benchmarkId, ordered by asset name.
 */
export async function checklistReviews(
  collectionId: number,
  benchmarkId: string,
  ruleId: string
): Promise<ChecklistReview[]> {
  const sql = `
    SELECT
      rv.reviewId,
      rv.assetId,
      a.name        AS assetName,
      rv.ruleId,
      rv.groupId,
      rv.ruleVersion,
      rv.severity,
      rv.title,
      rv.result,
      COALESCE(LEFT(rv.detail,  32767), '') AS detail,
      COALESCE(LEFT(rv.comment, 32767), '') AS comment,
      rv.status,
      rv.statusText,
      rv.username,
      DATE_FORMAT(rv.ts, '%Y-%m-%dT%H:%i:%sZ') AS ts
    FROM review rv
    JOIN asset a ON a.assetId = rv.assetId AND a.collectionId = :collectionId
    WHERE rv.benchmarkId = :benchmarkId
      AND rv.ruleId = :ruleId
    ORDER BY a.name`
  const [rows] = await pool.query<RowDataPacket[]>(sql, { collectionId, benchmarkId, ruleId })
  return rows as unknown as ChecklistReview[]
}
