// importBenchmark.ts — Parse a STIG/SRG XCCDF benchmark file (not scan results)
// and upsert it into the STIGMA.Engine database.
import { createHash } from 'node:crypto'
import { XMLParser } from 'fast-xml-parser'
import { pool } from '../db/pool.js'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ImportBenchmarkResult {
  benchmarkId: string
  title: string
  revId: string
  revisionStr: string
  ruleCount: number
  groupCount: number
}

// ---------------------------------------------------------------------------
// Internal parsed-data shapes
// ---------------------------------------------------------------------------

interface RuleData {
  ruleId: string
  ruleVersion: string | null
  title: string | null
  severity: string | null
  weight: string | null
  vulnDiscussion: string | null
  falsePositives: string | null
  falseNegatives: string | null
  documentable: string | null
  mitigations: string | null
  severityOverrideGuidance: string | null
  potentialImpacts: string | null
  thirdPartyTools: string | null
  mitigationControl: string | null
  responsibility: string | null
  iaControls: string | null
  checkSystem: string
  checkContent: string
  checkDigest: Buffer | null
  fixref: string
  fixText: string
  fixDigest: Buffer | null
  ccis: string[]
}

interface GroupData {
  groupId: string
  groupTitle: string | null
  rules: RuleData[]
}

interface ParsedBenchmark {
  benchmarkId: string
  title: string
  version: number
  release: string
  benchmarkDate: string
  benchmarkDateSql: string | null
  status: string | null
  statusDate: string | null
  description: string | null
  groups: GroupData[]
}

// ---------------------------------------------------------------------------
// XML parser (same config as xccdf.ts, plus isArray forcing for catalog elements)
// ---------------------------------------------------------------------------

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
  trimValues: true,
  parseTagValue: false,
  parseAttributeValue: false,
  alwaysCreateTextNode: true,
  textNodeName: '_',
  isArray: (_name, _jpath, _isLeaf, isAttr) => !isAttr,
  // DISA STIGs routinely have 1000+ XML entity references (e.g. &amp; in rule text).
  // processEntities:false bypasses fast-xml-parser's entity expansion counter (default
  // limit 1000). We run our own lightweight decoder on extracted text afterwards.
  processEntities: false,
})

/** Decode the five predefined XML/HTML entities left raw by processEntities:false. */
function decodeXmlEntities(s: string | undefined | null): string {
  if (!s) return ''
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n: string) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BENCHMARK_ID_PREFIX = /^xccdf_[^_]+_benchmark_/
const RULE_ID_PREFIX = /^xccdf_[^_]+_rule_/
const GROUP_ID_PREFIX = /^xccdf_[^_]+_group_/

function stripPrefix(id: string, re: RegExp): string {
  return id.replace(re, '')
}

/** Extract content between <TagName>...</TagName> from a possibly-malformed XML string. */
function extractTag(text: string, tag: string): string | null {
  const re = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`)
  const m = re.exec(text)
  return m ? m[1] : null
}

interface RuleDescription {
  vulnDiscussion: string | null
  falsePositives: string | null
  falseNegatives: string | null
  documentable: string | null
  mitigations: string | null
  severityOverrideGuidance: string | null
  potentialImpacts: string | null
  thirdPartyTools: string | null
  mitigationControl: string | null
  responsibility: string | null
  iaControls: string | null
}

function parseRuleDescription(raw: string | null | undefined): RuleDescription {
  const s = raw ?? ''
  let responsibility = extractTag(s, 'Responsibility')
  if (responsibility) {
    responsibility = responsibility.replace(/<\/Responsibility><Responsibility>/g, ', ')
  }
  return {
    vulnDiscussion: extractTag(s, 'VulnDiscussion'),
    falsePositives: extractTag(s, 'FalsePositives'),
    falseNegatives: extractTag(s, 'FalseNegatives'),
    documentable: extractTag(s, 'Documentable'),
    mitigations: extractTag(s, 'Mitigations'),
    severityOverrideGuidance: extractTag(s, 'SeverityOverrideGuidance'),
    potentialImpacts: extractTag(s, 'PotentialImpacts'),
    thirdPartyTools: extractTag(s, 'ThirdPartyTools'),
    mitigationControl: extractTag(s, 'MitigationControl'),
    responsibility,
    iaControls: extractTag(s, 'IAControls'),
  }
}

const MONTH_MAP: Record<string, string> = {
  Jan: '01', January: '01',
  Feb: '02', February: '02',
  Mar: '03', March: '03',
  Apr: '04', April: '04',
  May: '05',
  Jun: '06', June: '06',
  Jul: '07', July: '07',
  Aug: '08', August: '08',
  Sep: '09', Sept: '09', September: '09',
  Oct: '10', October: '10',
  Nov: '11', November: '11',
  Dec: '12', December: '12',
}

/** Convert "25 Jan 2025" -> "2025-01-25", or null on parse failure. */
function benchmarkDateTo8601(dateStr: string): string | null {
  const parts = dateStr.trim().split(/\s+/)
  if (parts.length !== 3) return null
  const [day, monStr, year] = parts
  const month = MONTH_MAP[monStr]
  if (!month) return null
  return `${year}-${month}-${day.padStart(2, '0')}`
}

/** Digest a string to a 32-byte SHA-256 Buffer (matches MySQL UNHEX(SHA2(col,256))). */
function sha256Buffer(text: string): Buffer {
  return createHash('sha256').update(text, 'utf8').digest()
}

// ---------------------------------------------------------------------------
// XML -> ParsedBenchmark
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyObj = Record<string, any>

function textOf(node: AnyObj[] | undefined): string | null {
  const raw = node?.[0]?._ ?? null
  return raw !== null ? decodeXmlEntities(raw) : null
}

function parseRule(ruleEl: AnyObj): RuleData {
  const ruleId = stripPrefix(String(ruleEl['@_id'] ?? ''), RULE_ID_PREFIX)
  const severity = (ruleEl['@_severity'] as string | undefined) ?? null
  const weight = (ruleEl['@_weight'] as string | undefined) ?? null

  const ruleVersion = textOf(ruleEl.version)
  const title = textOf(ruleEl.title)
  const desc = parseRuleDescription(textOf(ruleEl.description))

  // Checks
  const checkEls: AnyObj[] = Array.isArray(ruleEl.check) ? ruleEl.check : []
  const checkSystem = checkEls.map((c: AnyObj) => String(c['@_system'] ?? '')).join(',')
  const checkContentParts = checkEls
    .map((c: AnyObj) => {
      const ccArr: AnyObj[] = Array.isArray(c['check-content']) ? c['check-content'] : []
      return decodeXmlEntities(ccArr[0]?._ ?? '')
    })
    .filter(Boolean)
  const checkContent = checkContentParts.join('\n\n-----AND-----\n\n')
  const checkDigest = checkContent ? sha256Buffer(checkContent) : null

  // Fixes
  const fixEls: AnyObj[] = Array.isArray(ruleEl.fixtext) ? ruleEl.fixtext : []
  const fixref = fixEls.map((f: AnyObj) => String(f['@_fixref'] ?? '')).join(',')
  const fixTextParts = fixEls.map((f: AnyObj) => decodeXmlEntities(f._ ?? '')).filter(Boolean)
  const fixText = fixTextParts.join('\n\n-----AND-----\n\n')
  const fixDigest = fixText ? sha256Buffer(fixText) : null

  // CCI idents
  const identEls: AnyObj[] = Array.isArray(ruleEl.ident) ? ruleEl.ident : []
  const ccis = identEls
    .filter((id: AnyObj) => {
      const sys = String(id['@_system'] ?? '')
      return sys === 'http://iase.disa.mil/cci' || sys === 'http://cyber.mil/cci'
    })
    .map((id: AnyObj) => decodeXmlEntities(String(id._ ?? '')).replace('CCI-', ''))
    .filter(Boolean)

  return {
    ruleId,
    ruleVersion,
    title,
    severity,
    weight,
    ...desc,
    checkSystem,
    checkContent,
    checkDigest,
    fixref,
    fixText,
    fixDigest,
    ccis,
  }
}

function collectGroups(groupEls: AnyObj[]): GroupData[] {
  const result: GroupData[] = []
  for (const g of groupEls ?? []) {
    const groupId = stripPrefix(String(g['@_id'] ?? ''), GROUP_ID_PREFIX)
    const groupTitle = textOf(g.title)
    const ruleEls: AnyObj[] = Array.isArray(g.Rule) ? g.Rule : []
    const rules = ruleEls.map(parseRule)
    result.push({ groupId, groupTitle, rules })
    // Recurse into nested Group elements
    if (Array.isArray(g.Group) && g.Group.length > 0) {
      result.push(...collectGroups(g.Group))
    }
  }
  return result
}

function parseBenchmarkXml(xml: string): ParsedBenchmark {
  const doc = parser.parse(xml) as AnyObj

  let bIn: AnyObj | undefined

  if (doc['data-stream-collection']?.[0]) {
    // SCAP
    const components: AnyObj[] = doc['data-stream-collection'][0].component ?? []
    const candidate = components.find((c: AnyObj) => 'Benchmark' in c)
    bIn = candidate?.Benchmark?.[0]
    if (!bIn) throw new Error('Cannot parse as DISA SCAP benchmark: no Benchmark element found')
  } else if (doc.Benchmark?.[0]) {
    bIn = doc.Benchmark[0]
  } else {
    throw new Error('Cannot parse XML document as a STIG or SCAP Benchmark')
  }

  // bIn is guaranteed to be defined here (all other paths throw)
  const b = bIn!

  // Strip benchmark prefix from id
  const rawId = String(b['@_id'] ?? '')
  const benchmarkId = stripPrefix(rawId, BENCHMARK_ID_PREFIX)

  const title = textOf(b.title) ?? benchmarkId

  // Version
  const versionStr = textOf(b.version) ?? '0'
  const version = parseInt(versionStr, 10) || 0

  // Release + date from plain-text element
  const plainTexts: AnyObj[] = Array.isArray(b['plain-text']) ? b['plain-text'] : []
  const plainText = plainTexts.find((pt: AnyObj) => /Release:/i.test(pt._ ?? '')) ?? plainTexts[0]
  const plainStr: string = decodeXmlEntities(plainText?._ ?? '')

  let release = '0'
  let benchmarkDate = ''
  const releaseMatch = /Release:\s+(\S+)\s+Benchmark\s+Date:\s+(.*)/i.exec(plainStr)
  if (releaseMatch) {
    release = releaseMatch[1]
    benchmarkDate = releaseMatch[2].trim()
  }

  const benchmarkDateSql = benchmarkDate ? benchmarkDateTo8601(benchmarkDate) : null

  // Status
  const statusEls: AnyObj[] = Array.isArray(b.status) ? b.status : []
  const status = textOf(statusEls) ?? null
  const statusDate: string | null = (statusEls[0]?.['@_date'] as string | undefined) ?? null

  // Description
  const description = textOf(b.description) ?? null

  // Groups
  const groupEls: AnyObj[] = Array.isArray(b.Group) ? b.Group : []
  const groups = collectGroups(groupEls)

  return {
    benchmarkId,
    title,
    version,
    release,
    benchmarkDate,
    benchmarkDateSql,
    status,
    statusDate,
    description,
    groups,
  }
}

// ---------------------------------------------------------------------------
// DB upsert helpers
// ---------------------------------------------------------------------------

const CHUNK = 100

async function chunkInsert<T>(
  conn: Awaited<ReturnType<typeof pool.getConnection>>,
  sql: string,
  rows: T[][],
): Promise<void> {
  for (let i = 0; i < rows.length; i += CHUNK) {
    const batch = rows.slice(i, i + CHUNK)
    if (batch.length > 0) {
      await conn.query(sql, [batch])
    }
  }
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function importBenchmark(xml: string): Promise<ImportBenchmarkResult> {
  const b = parseBenchmarkXml(xml)
  const { benchmarkId, title, version, release, groups } = b

  const revisionStr = `V${version}R${release}`
  const revId = `${benchmarkId}-${revisionStr}`

  // Pre-compute severity counts
  let lowCount = 0
  let mediumCount = 0
  let highCount = 0
  let totalRules = 0

  const checkContentRows: [string][] = []
  const fixTextRows: [string][] = []
  const tempRuleCciRows: [string, string][] = []

  // Rule rows: [revId, groupId, groupTitle, groupSeverity, ruleId, version, title, severity,
  //             weight, vulnDiscussion, falsePositives, falseNegatives, documentable, mitigations,
  //             severityOverrideGuidance, potentialImpacts, thirdPartyTools, mitigationControl,
  //             responsibility, iaControls, checkSystem, checkDigest, fixref, fixDigest]
  type RuleRow = [
    string, string | null, string | null, string | null,
    string, string | null, string | null, string | null,
    string | null, string | null, string | null, string | null,
    string | null, string | null, string | null, string | null,
    string | null, string | null, string | null, string | null,
    string, Buffer | null, string, Buffer | null,
  ]
  const ruleRows: RuleRow[] = []

  for (const group of groups) {
    let groupSeverity: string | null = null

    for (const rule of group.rules) {
      totalRules++

      // Severity counts
      const sev = (rule.severity ?? '').toLowerCase()
      if (sev === 'high') highCount++
      else if (sev === 'medium') mediumCount++
      else if (sev === 'low') lowCount++

      // Group severity (first rule wins; 'mixed' if inconsistent)
      if (groupSeverity === null) {
        groupSeverity = rule.severity
      } else if (groupSeverity !== rule.severity) {
        groupSeverity = 'mixed'
      }

      // check_content dedup
      if (rule.checkContent) {
        checkContentRows.push([rule.checkContent])
      }

      // fix_text dedup
      if (rule.fixText) {
        fixTextRows.push([rule.fixText])
      }

      // CCI temp map
      for (const cci of rule.ccis) {
        tempRuleCciRows.push([rule.ruleId, cci])
      }

      ruleRows.push([
        revId,
        group.groupId || null,
        group.groupTitle,
        groupSeverity,
        rule.ruleId,
        rule.ruleVersion,
        rule.title,
        rule.severity,
        rule.weight,
        rule.vulnDiscussion,
        rule.falsePositives,
        rule.falseNegatives,
        rule.documentable,
        rule.mitigations,
        rule.severityOverrideGuidance,
        rule.potentialImpacts,
        rule.thirdPartyTools,
        rule.mitigationControl,
        rule.responsibility,
        rule.iaControls,
        rule.checkSystem,
        rule.checkDigest,
        rule.fixref,
        rule.fixDigest,
      ])
    }
  }

  const groupCount = groups.length
  const checkCount = checkContentRows.length
  const fixCount = fixTextRows.length

  const conn = await pool.getConnection()
  // Enable named placeholders for this connection
  ;(conn as AnyObj).config.namedPlaceholders = true

  try {
    // 1. Upsert stig (outside transaction — idempotent)
    await conn.query(
      `INSERT INTO stig (benchmarkId, title) VALUES (:benchmarkId, :title)
       ON DUPLICATE KEY UPDATE title = VALUES(title)`,
      { benchmarkId, title },
    )

    // 2. Transaction for all revision + rule data
    await conn.beginTransaction()

    // 3. Upsert revision row
    await conn.query(
      `INSERT INTO revision (
         revId, benchmarkId, \`version\`, \`release\`,
         benchmarkDate, benchmarkDateSql, \`status\`, statusDate,
         description, groupCount, checkCount, fixCount,
         lowCount, mediumCount, highCount
       ) VALUES (
         :revId, :benchmarkId, :version, :release,
         :benchmarkDate, STR_TO_DATE(:benchmarkDateSql, '%Y-%m-%d'),
         :status, :statusDate,
         :description, :groupCount, :checkCount, :fixCount,
         :lowCount, :mediumCount, :highCount
       )
       ON DUPLICATE KEY UPDATE
         benchmarkDate    = VALUES(benchmarkDate),
         benchmarkDateSql = VALUES(benchmarkDateSql),
         \`status\`        = VALUES(\`status\`),
         statusDate       = VALUES(statusDate),
         description      = VALUES(description),
         groupCount       = VALUES(groupCount),
         checkCount       = VALUES(checkCount),
         fixCount         = VALUES(fixCount),
         lowCount         = VALUES(lowCount),
         mediumCount      = VALUES(mediumCount),
         highCount        = VALUES(highCount)`,
      {
        revId,
        benchmarkId,
        version,
        release,
        benchmarkDate: b.benchmarkDate || null,
        benchmarkDateSql: b.benchmarkDateSql,
        status: b.status,
        statusDate: b.statusDate,
        description: b.description,
        groupCount,
        checkCount,
        fixCount,
        lowCount,
        mediumCount,
        highCount,
      },
    )

    // 4. Upsert check_content rows (deduped by generated digest column via IGNORE)
    if (checkContentRows.length > 0) {
      await chunkInsert(conn, 'INSERT IGNORE INTO check_content (content) VALUES ?', checkContentRows)
    }

    // 5. Upsert fix_text rows
    if (fixTextRows.length > 0) {
      await chunkInsert(conn, 'INSERT IGNORE INTO fix_text (`text`) VALUES ?', fixTextRows)
    }

    // 6. Delete existing rule rows for this revId so we can replace cleanly
    await conn.query('DELETE FROM rule WHERE revId = ?', [revId])

    // 7. Insert rule rows in chunks
    if (ruleRows.length > 0) {
      await chunkInsert(
        conn,
        `INSERT INTO rule (
           revId,
           groupId, groupTitle, groupSeverity,
           ruleId, ruleVersion, title, severity, weight,
           vulnDiscussion, falsePositives, falseNegatives, documentable, mitigations,
           severityOverrideGuidance, potentialImpacts, thirdPartyTools, mitigationControl,
           responsibility, iaControls,
           checkSystem, checkDigest, fixref, fixDigest
         ) VALUES ?`,
        ruleRows,
      )
    }

    // 8. Upsert rule_cci_map via temp approach: batch insert (ruleId, cci) then JOIN back
    //    to get the rgrId. Use a loop per rule to stay within plain mysql2 capabilities.
    if (tempRuleCciRows.length > 0) {
      // Build a map from ruleId -> [ccis] to avoid repeated queries
      const ruleIdToCcis = new Map<string, string[]>()
      for (const [ruleId, cci] of tempRuleCciRows) {
        let arr = ruleIdToCcis.get(ruleId)
        if (!arr) { arr = []; ruleIdToCcis.set(ruleId, arr) }
        arr.push(cci)
      }

      // Fetch the just-inserted rgrIds for this revision
      const ruleIdList = Array.from(ruleIdToCcis.keys())
      // Chunk the IN list to avoid huge queries
      const CCI_CHUNK = 200
      for (let i = 0; i < ruleIdList.length; i += CCI_CHUNK) {
        const slice = ruleIdList.slice(i, i + CCI_CHUNK)
        const placeholders = slice.map(() => '?').join(',')
        type RgrRow = { rgrId: number; ruleId: string }
        const [rgrRows] = (await conn.query(
          `SELECT rgrId, ruleId FROM rule WHERE revId = ? AND ruleId IN (${placeholders})`,
          [revId, ...slice],
        )) as unknown as [RgrRow[], unknown]

        const cciInsertRows: [number, string][] = []
        for (const row of rgrRows) {
          const ccis = ruleIdToCcis.get(row.ruleId) ?? []
          for (const cci of ccis) {
            cciInsertRows.push([row.rgrId, cci])
          }
        }
        if (cciInsertRows.length > 0) {
          await chunkInsert(
            conn,
            'INSERT IGNORE INTO rule_cci_map (rgrId, cci) VALUES ?',
            cciInsertRows,
          )
        }
      }
    }

    // 9. Upsert rule_version_check_digest — keeps the most recent (by benchmarkDateSql)
    //    version+checkDigest per ruleId across ALL revisions of this benchmark.
    await conn.query(
      `INSERT INTO rule_version_check_digest (ruleId, \`version\`, checkDigest)
       WITH ranked AS (
         SELECT
           r.ruleId,
           r.ruleVersion AS \`version\`,
           r.checkDigest,
           rev.benchmarkDateSql,
           ROW_NUMBER() OVER (PARTITION BY r.ruleId ORDER BY rev.benchmarkDateSql DESC) AS rowNum
         FROM rule r
         LEFT JOIN revision rev ON rev.revId = r.revId
         WHERE r.checkDigest IS NOT NULL
           AND rev.benchmarkId = ?
       )
       SELECT ruleId, \`version\`, checkDigest
       FROM ranked
       WHERE rowNum = 1
       ON DUPLICATE KEY UPDATE
         \`version\`  = VALUES(\`version\`),
         checkDigest = VALUES(checkDigest)`,
      [benchmarkId],
    )

    // 10. Update current_rev — upsert pointing to this revision
    await conn.query(
      `INSERT INTO current_rev (
         revId, benchmarkId, \`version\`, \`release\`,
         benchmarkDate,
         groupCount, lowCount, mediumCount, highCount
       ) VALUES (
         :revId, :benchmarkId, :version, :release,
         :benchmarkDate,
         :groupCount, :lowCount, :mediumCount, :highCount
       )
       ON DUPLICATE KEY UPDATE
         revId         = VALUES(revId),
         \`version\`   = VALUES(\`version\`),
         \`release\`   = VALUES(\`release\`),
         benchmarkDate = VALUES(benchmarkDate),
         groupCount    = VALUES(groupCount),
         lowCount      = VALUES(lowCount),
         mediumCount   = VALUES(mediumCount),
         highCount     = VALUES(highCount)`,
      {
        revId,
        benchmarkId,
        version,
        release,
        benchmarkDate: b.benchmarkDate || null,
        groupCount,
        lowCount,
        mediumCount,
        highCount,
      },
    )

    await conn.commit()
  } catch (err) {
    await conn.rollback()
    throw err
  } finally {
    conn.release()
  }

  return {
    benchmarkId,
    title,
    revId,
    revisionStr,
    ruleCount: totalRules,
    groupCount,
  }
}
