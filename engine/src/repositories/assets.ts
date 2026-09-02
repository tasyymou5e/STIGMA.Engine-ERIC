import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AssetRecord {
  assetId: number
  collectionId: number
  name: string
  fqdn: string | null
  ip: string | null
  mac: string | null
  description: string | null
  noncomputing: boolean
  state: 'enabled' | 'disabled'
  stigs?: StigAssignment[]
  labels?: LabelRef[]
}

export interface StigAssignment {
  benchmarkId: string
  revisionStr: string
  title: string
}

export interface LabelRef {
  clId: number
  name: string
  color: string | null
}

export type AssetPatch = Partial<
  Pick<AssetRecord, 'name' | 'fqdn' | 'ip' | 'mac' | 'description' | 'noncomputing'>
>

// ---------------------------------------------------------------------------
// listAssets
// ---------------------------------------------------------------------------

export async function listAssets(collectionId: number): Promise<AssetRecord[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       a.assetId,
       a.collectionId,
       a.name,
       a.fqdn,
       a.ip,
       a.mac,
       a.description,
       a.noncomputing,
       a.state
     FROM asset a
     WHERE a.collectionId = :id
       AND a.state = 'enabled'
     ORDER BY a.name`,
    { id: collectionId }
  )
  return rows as unknown as AssetRecord[]
}

// ---------------------------------------------------------------------------
// getAsset
// ---------------------------------------------------------------------------

/**
 * Fetch a single asset by primary key.
 * Includes stigs[] (benchmarkId + revisionStr from the collection default_rev
 * or the revision table directly via stig_asset_map) and labels[] (clId,
 * name, color from collection_label).
 * Returns null when no enabled row is found.
 */
export async function getAsset(assetId: number): Promise<AssetRecord | null> {
  const [assetRows] = await pool.query<RowDataPacket[]>(
    `SELECT
       a.assetId,
       a.collectionId,
       a.name,
       a.fqdn,
       a.ip,
       a.mac,
       a.description,
       a.noncomputing,
       a.state
     FROM asset a
     WHERE a.assetId = :assetId
       AND a.state = 'enabled'`,
    { assetId }
  )

  if (assetRows.length === 0) return null

  const asset = assetRows[0] as unknown as AssetRecord

  // Fetch STIG assignments with revisionStr from the default_rev / revision chain.
  // Falls back to a bare revisionStr string when no default_rev row exists yet
  // (phase-0 stub mode).
  const [stigRows] = await pool.query<RowDataPacket[]>(
    `SELECT
       sam.benchmarkId,
       COALESCE(CONCAT('V', r.version, 'R', r.release), '') AS revisionStr,
       COALESCE(s.title, '')                                  AS title
     FROM stig_asset_map sam
     LEFT JOIN stig s ON sam.benchmarkId = s.benchmarkId
     LEFT JOIN default_rev dr
            ON sam.benchmarkId = dr.benchmarkId
           AND dr.collectionId = (
                 SELECT collectionId FROM asset WHERE assetId = :assetId
               )
     LEFT JOIN revision r ON dr.revId = r.revId
     WHERE sam.assetId = :assetId
     ORDER BY sam.benchmarkId`,
    { assetId }
  )

  // Fetch label assignments
  const [labelRows] = await pool.query<RowDataPacket[]>(
    `SELECT
       cl.clId,
       cl.name,
       cl.color
     FROM collection_label_asset_map cla
     INNER JOIN collection_label cl ON cla.clId = cl.clId
     WHERE cla.assetId = :assetId
     ORDER BY cl.name`,
    { assetId }
  )

  asset.stigs = stigRows as unknown as StigAssignment[]
  asset.labels = labelRows as unknown as LabelRef[]

  return asset
}

// ---------------------------------------------------------------------------
// createAsset
// ---------------------------------------------------------------------------

export async function createAsset(input: {
  collectionId: number
  name: string
  fqdn?: string
  ip?: string
  mac?: string
  description?: string
  noncomputing?: boolean
}): Promise<number> {
  const [res] = await pool.query<ResultSetHeader>(
    `INSERT INTO asset (collectionId, name, fqdn, ip, mac, description, noncomputing)
     VALUES (:collectionId, :name, :fqdn, :ip, :mac, :description, :noncomputing)`,
    {
      collectionId: input.collectionId,
      name: input.name,
      fqdn: input.fqdn ?? null,
      ip: input.ip ?? null,
      mac: input.mac ?? null,
      description: input.description ?? null,
      noncomputing: input.noncomputing ? 1 : 0
    }
  )
  return res.insertId
}

// ---------------------------------------------------------------------------
// ensureAsset
// ---------------------------------------------------------------------------

/**
 * Returns the assetId for (collection, name), creating the asset if it does
 * not exist.
 */
export async function ensureAsset(collectionId: number, name: string): Promise<number> {
  const [rows] = await pool.query<RowDataPacket[]>(
    'SELECT assetId FROM asset WHERE collectionId = :id AND name = :name',
    { id: collectionId, name }
  )
  const existing = rows[0] as { assetId: number } | undefined
  if (existing) return existing.assetId
  return createAsset({ collectionId, name })
}

// ---------------------------------------------------------------------------
// updateAsset
// ---------------------------------------------------------------------------

/**
 * Partial PATCH — only keys present in `patch` are included in the UPDATE.
 * Returns true when the row was found and at least one column value changed.
 */
export async function updateAsset(assetId: number, patch: AssetPatch): Promise<boolean> {
  const setClauses: string[] = []
  const binds: Record<string, unknown> = { assetId }

  if (patch.name !== undefined) {
    setClauses.push('name = :pName')
    binds.pName = patch.name
  }
  if (patch.fqdn !== undefined) {
    setClauses.push('fqdn = :pFqdn')
    binds.pFqdn = patch.fqdn
  }
  if (patch.ip !== undefined) {
    setClauses.push('ip = :pIp')
    binds.pIp = patch.ip
  }
  if (patch.mac !== undefined) {
    setClauses.push('mac = :pMac')
    binds.pMac = patch.mac
  }
  if (patch.description !== undefined) {
    setClauses.push('description = :pDescription')
    binds.pDescription = patch.description
  }
  if (patch.noncomputing !== undefined) {
    setClauses.push('noncomputing = :pNoncomputing')
    binds.pNoncomputing = patch.noncomputing ? 1 : 0
  }

  if (setClauses.length === 0) return false

  const [res] = await pool.query<ResultSetHeader>(
    `UPDATE asset SET ${setClauses.join(', ')} WHERE assetId = :assetId`,
    binds as unknown as import('mysql2').QueryValues
  )
  return res.affectedRows > 0
}

// ---------------------------------------------------------------------------
// deleteAsset
// ---------------------------------------------------------------------------

/**
 * Soft-delete a single asset by setting state = 'disabled'.
 * Returns true when the row was found and updated.
 */
export async function deleteAsset(assetId: number): Promise<boolean> {
  const [res] = await pool.query<ResultSetHeader>(
    `UPDATE asset SET state = 'disabled', stateDate = NOW() WHERE assetId = :assetId`,
    { assetId }
  )
  return res.affectedRows > 0
}

// ---------------------------------------------------------------------------
// bulkDeleteAssets
// ---------------------------------------------------------------------------

/**
 * Soft-delete multiple assets in one statement.
 * Returns the number of rows actually updated (may be less than assetIds.length
 * if some ids did not exist or were already disabled).
 */
export async function bulkDeleteAssets(assetIds: number[]): Promise<number> {
  if (assetIds.length === 0) return 0

  const [res] = await pool.query<ResultSetHeader>(
    `UPDATE asset SET state = 'disabled', stateDate = NOW() WHERE assetId IN (?)`,
    [assetIds]
  )
  return res.affectedRows
}

// ---------------------------------------------------------------------------
// listAssetStigs
// ---------------------------------------------------------------------------

/**
 * Return the STIG assignments for one asset, joined to the default revision
 * for the asset's collection so callers get a populated revisionStr and title.
 */
export async function listAssetStigs(assetId: number): Promise<StigAssignment[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       sam.benchmarkId,
       COALESCE(CONCAT('V', r.version, 'R', r.release), '') AS revisionStr,
       COALESCE(s.title, '')                                  AS title
     FROM stig_asset_map sam
     LEFT JOIN stig s ON sam.benchmarkId = s.benchmarkId
     LEFT JOIN default_rev dr
            ON sam.benchmarkId = dr.benchmarkId
           AND dr.collectionId = (
                 SELECT collectionId FROM asset WHERE assetId = :assetId
               )
     LEFT JOIN revision r ON dr.revId = r.revId
     WHERE sam.assetId = :assetId
     ORDER BY sam.benchmarkId`,
    { assetId }
  )
  return rows as unknown as StigAssignment[]
}

// ---------------------------------------------------------------------------
// assignStigToAsset
// ---------------------------------------------------------------------------

/**
 * Map a STIG to an asset.  Silently succeeds when the mapping already exists
 * (INSERT IGNORE semantics mirror the upstream AssetService.attachStigToAsset).
 */
export async function assignStigToAsset(
  assetId: number,
  benchmarkId: string
): Promise<void> {
  await pool.query(
    'INSERT IGNORE INTO stig_asset_map (assetId, benchmarkId) VALUES (?, ?)',
    [assetId, benchmarkId]
  )
}

// ---------------------------------------------------------------------------
// removeStigFromAsset
// ---------------------------------------------------------------------------

/**
 * Remove a single STIG assignment.
 * Returns true when a row was actually deleted.
 */
export async function removeStigFromAsset(
  assetId: number,
  benchmarkId: string
): Promise<boolean> {
  const [res] = await pool.query<ResultSetHeader>(
    'DELETE FROM stig_asset_map WHERE assetId = ? AND benchmarkId = ?',
    [assetId, benchmarkId]
  )
  return res.affectedRows > 0
}

// ---------------------------------------------------------------------------
// listAssetChecklists
// ---------------------------------------------------------------------------

export interface AssetChecklistRecord {
  benchmarkId: string
  title: string | null
  reviewCount: number
}

/**
 * Return the benchmarks for which this asset has at least one review row —
 * i.e. the checklists that can actually be exported.
 */
export async function listAssetChecklists(assetId: number): Promise<AssetChecklistRecord[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       r.benchmarkId,
       s.title,
       COUNT(*) AS reviewCount
     FROM review r
     LEFT JOIN stig s ON s.benchmarkId = r.benchmarkId
     WHERE r.assetId = :assetId
       AND r.benchmarkId IS NOT NULL
       AND r.benchmarkId <> ''
     GROUP BY r.benchmarkId, s.title
     ORDER BY r.benchmarkId`,
    { assetId }
  )
  return rows as unknown as AssetChecklistRecord[]
}

// ---------------------------------------------------------------------------
// generateCkl
// ---------------------------------------------------------------------------

function escXml(s: string | null | undefined): string {
  return (s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

/**
 * Build a STIG Viewer 2-compatible CKL XML string for an asset + benchmark.
 * Returns null when the asset does not exist or there are no rules for the
 * benchmark (i.e. the STIG library has not been imported).
 *
 * The CKL format follows the CHECKLIST/ASSET/STIGS/iSTIG/VULN schema
 * consumed by STIG Viewer 2 and Evaluate-STIG.  Columns that do not exist
 * in every deployment (e.g. result.ckl) are coalesced to safe defaults so
 * the query does not break when the schema differs.
 */
function classificationBanner(c: string): string {
  return c === 'CUI' ? 'CONTROLLED UNCLASSIFIED INFORMATION' : c
}

export async function generateCkl(
  assetId: number,
  benchmarkId: string,
  classification = 'CUI'
): Promise<string | null> {
  const asset = await getAsset(assetId)
  if (!asset) return null

  const [stigRows] = await pool.query<RowDataPacket[]>(
    `SELECT s.title, cr.version, cr.release
     FROM stig s
     LEFT JOIN current_rev cr ON cr.benchmarkId = s.benchmarkId
     WHERE s.benchmarkId = :benchmarkId`,
    { benchmarkId }
  )
  const stig = stigRows[0] as { title: string; version: string; release: string } | undefined

  const [reviewRows] = await pool.query<RowDataPacket[]>(
    `SELECT
       rgr.ruleId,
       rgr.version       AS ruleVersion,
       rgr.groupId,
       rgr.groupTitle,
       rgr.title         AS ruleTitle,
       rgr.severity,
       COALESCE(res.api, 'notchecked')    AS result,
       COALESCE(LEFT(rv.detail,  32767), '') AS detail,
       COALESCE(LEFT(rv.comment, 32767), '') AS comment
     FROM rev_group_rule_map rgr
     JOIN current_rev cr ON cr.revId = rgr.revId
       AND cr.benchmarkId = :benchmarkId
     LEFT JOIN stig_asset_map sam
            ON sam.assetId = :assetId
           AND sam.benchmarkId = :benchmarkId
     LEFT JOIN rule_version_check_digest rvcd
            ON (rvcd.version = rgr.version AND rvcd.checkDigest = rgr.checkDigest)
     LEFT JOIN review rv
            ON rv.assetId = :assetId
           AND rv.version = rgr.version
           AND rv.checkDigest = rgr.checkDigest
     LEFT JOIN result res ON res.resultId = rv.resultId
     ORDER BY SUBSTRING(rgr.ruleId FROM 4) + 0`,
    { assetId, benchmarkId }
  )

  if (reviewRows.length === 0) return null

  // Map normalized result -> CKL STATUS token
  const toCklStatus = (result: string): string => {
    switch (result) {
      case 'pass': return 'NotAFinding'
      case 'fail': return 'Open'
      case 'notapplicable': return 'Not_Applicable'
      default: return 'Not_Reviewed'
    }
  }

  const revisionStr = stig ? `V${stig.version}R${stig.release}` : 'unknown'

  const vulns = (reviewRows as Array<Record<string, string>>).map((r) => `    <VULN>
      <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>${escXml(r.groupId)}</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>${escXml(r.severity)}</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>${escXml(r.groupTitle)}</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>${escXml(r.ruleId)}</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>${escXml(r.ruleVersion)}</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>${escXml(r.ruleTitle)}</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>stigid</VULN_ATTRIBUTE><ATTRIBUTE_DATA>${escXml(benchmarkId)}</ATTRIBUTE_DATA></STIG_DATA>
      <STATUS>${toCklStatus(r.result)}</STATUS>
      <FINDING_DETAILS>${escXml(r.detail)}</FINDING_DETAILS>
      <COMMENTS>${escXml(r.comment)}</COMMENTS>
    </VULN>`).join('\n')

  return `<?xml version="1.0" encoding="UTF-8"?>
<!-- Classification: ${classification} -->
<CHECKLIST>
  <CLASSIFICATION>${classificationBanner(classification)}</CLASSIFICATION>
  <ASSET>
    <ROLE>Member Server</ROLE>
    <ASSET_TYPE>Computing</ASSET_TYPE>
    <HOST_NAME>${escXml(asset.name)}</HOST_NAME>
    <HOST_IP>${escXml(asset.ip)}</HOST_IP>
    <HOST_FQDN>${escXml(asset.fqdn)}</HOST_FQDN>
  </ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA><SID_NAME>stigid</SID_NAME><SID_DATA>${escXml(benchmarkId)}</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>${escXml(stig?.title)}</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>${escXml(stig?.version)}</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>${escXml(revisionStr)}</SID_DATA></SI_DATA>
      </STIG_INFO>
${vulns}
    </iSTIG>
  </STIGS>
</CHECKLIST>`
}

// ---------------------------------------------------------------------------
// generateCklb
// ---------------------------------------------------------------------------

/**
 * Build a STIG Viewer 3-compatible CKLB JSON object for an asset + benchmark.
 * Returns null when the asset does not exist or there are no rules for the
 * benchmark.
 *
 * The returned object is serialized by Fastify as the JSON response body.
 * It follows the CKLB schema consumed by STIG Viewer 3.
 */
export async function generateCklb(
  assetId: number,
  benchmarkId: string,
  classification = 'CUI'
): Promise<Record<string, unknown> | null> {
  const asset = await getAsset(assetId)
  if (!asset) return null

  const [stigRows] = await pool.query<RowDataPacket[]>(
    `SELECT s.title, cr.version, cr.release,
            DATE_FORMAT(cr.benchmarkDateSql, '%d %b %Y') AS benchmarkDate
     FROM stig s
     LEFT JOIN current_rev cr ON cr.benchmarkId = s.benchmarkId
     WHERE s.benchmarkId = :benchmarkId`,
    { benchmarkId }
  )
  const stig = stigRows[0] as { title: string; version: string; release: string; benchmarkDate: string } | undefined

  const [reviewRows] = await pool.query<RowDataPacket[]>(
    `SELECT
       rgr.ruleId      AS rule_id,
       rgr.version     AS rule_version,
       rgr.groupId     AS group_id,
       rgr.groupTitle  AS group_title,
       rgr.title       AS rule_title,
       rgr.severity,
       COALESCE(res.api, 'notchecked')    AS status,
       COALESCE(LEFT(rv.detail,  32767), '') AS finding_details,
       COALESCE(LEFT(rv.comment, 32767), '') AS comments
     FROM rev_group_rule_map rgr
     JOIN current_rev cr ON cr.revId = rgr.revId
       AND cr.benchmarkId = :benchmarkId
     LEFT JOIN rule_version_check_digest rvcd
            ON (rvcd.version = rgr.version AND rvcd.checkDigest = rgr.checkDigest)
     LEFT JOIN review rv
            ON rv.assetId = :assetId
           AND rv.version = rgr.version
           AND rv.checkDigest = rgr.checkDigest
     LEFT JOIN result res ON res.resultId = rv.resultId
     ORDER BY SUBSTRING(rgr.ruleId FROM 4) + 0`,
    { assetId, benchmarkId }
  )

  if (reviewRows.length === 0) return null

  // Map normalized result -> CKLB status token
  const toCklbStatus = (result: string): string => {
    switch (result) {
      case 'pass': return 'not_a_finding'
      case 'fail': return 'open'
      case 'notapplicable': return 'not_applicable'
      default: return 'not_reviewed'
    }
  }

  const rules = (reviewRows as Array<Record<string, string>>).map((r) => ({
    ...r,
    status: toCklbStatus(r.status)
  }))

  return {
    title: stig?.title ?? benchmarkId,
    classification: classificationBanner(classification),
    id: crypto.randomUUID(),
    active: true,
    mode: 1,
    has_path: true,
    target_data: {
      target_type: 'Computing',
      host_name: asset.name,
      ip_address: asset.ip ?? '',
      fqdn: asset.fqdn ?? '',
      mac_address: asset.mac ?? '',
      network_id: '',
      role: 'Member Server',
      is_web_database: false,
      technology_area: '',
      web_db_site: '',
      web_db_instance: ''
    },
    stigs: [
      {
        stig_id: benchmarkId,
        stig_name: stig?.title ?? benchmarkId,
        display_name: stig?.title ?? benchmarkId,
        version: stig?.version ?? '',
        release_info: stig
          ? `Release: ${stig.release} Benchmark Date: ${stig.benchmarkDate}`
          : '',
        uuid: crypto.randomUUID(),
        reference_identifier: '',
        size: rules.length,
        rules
      }
    ]
  }
}
