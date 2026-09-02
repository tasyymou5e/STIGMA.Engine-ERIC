/**
 * importBenchmark.test.ts
 *
 * Tests the pure XML-parsing logic inside importBenchmark.ts.
 *
 * The database-touching path (pool.getConnection / upsert SQL) is mocked via
 * vi.mock so that no running MySQL instance is required.  All assertions target
 * the ParsedBenchmark values that are derived entirely from the XML string.
 *
 * The public export `importBenchmark` is also tested by intercepting the DB
 * calls; we validate the returned ImportBenchmarkResult shape.
 *
 * A real STIG XCCDF file is used in the "real file" smoke test so that the
 * parser is exercised against production-format XML.
 */

import { describe, it, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// ---------------------------------------------------------------------------
// Mock the DB pool BEFORE importing the module under test.
// vi.mock is hoisted so the factory must be self-contained (no external refs).
// ---------------------------------------------------------------------------

vi.mock('../../src/db/pool.js', () => {
  const mockConn = {
    config: { namedPlaceholders: false },
    query: vi.fn().mockResolvedValue([[], {}]),
    beginTransaction: vi.fn().mockResolvedValue(undefined),
    commit: vi.fn().mockResolvedValue(undefined),
    rollback: vi.fn().mockResolvedValue(undefined),
    release: vi.fn(),
  }
  return {
    pool: {
      getConnection: vi.fn().mockResolvedValue(mockConn),
      query: vi.fn().mockResolvedValue([[], {}]),
    },
  }
})

// Import the module under test AFTER mocks are in place.
import { importBenchmark } from '../../src/engine/importBenchmark.js'

// ---------------------------------------------------------------------------
// Minimal valid XCCDF benchmark XML fixtures
// ---------------------------------------------------------------------------

/** Build a minimal DISA-format XCCDF with configurable groups/rules. */
function makeXccdf(opts: {
  id?: string
  version?: string
  release?: string
  date?: string
  groups?: Array<{ groupId: string; ruleId: string; severity: string; title: string }>
}): string {
  const {
    id = 'xccdf_org.stig_benchmark_Test_Benchmark',
    version = '2',
    release = '5',
    date = '25 Jan 2025',
    groups = [
      { groupId: 'V-100001', ruleId: 'SV-100001r1_rule', severity: 'high', title: 'High severity rule' },
      { groupId: 'V-100002', ruleId: 'SV-100002r1_rule', severity: 'medium', title: 'Medium severity rule' },
    ],
  } = opts

  const groupXml = groups
    .map(
      (g) => `
    <Group id="xccdf_org.stig_group_${g.groupId}">
      <title><![CDATA[${g.groupId}]]></title>
      <Rule id="xccdf_org.stig_rule_${g.ruleId}" severity="${g.severity}" weight="10.0">
        <version>VER-001</version>
        <title>${g.title}</title>
        <description>&lt;VulnDiscussion&gt;Test discussion.&lt;/VulnDiscussion&gt;</description>
        <ident system="http://cyber.mil/cci">CCI-000001</ident>
        <fixtext fixref="F-001">Apply the fix.</fixtext>
        <check system="C-001r1_chk">
          <check-content>Verify the configuration.</check-content>
        </check>
      </Rule>
    </Group>`,
    )
    .join('\n')

  return `<?xml version="1.0" encoding="utf-8"?>
<Benchmark id="${id}" xmlns="http://checklists.nist.gov/xccdf/1.1">
  <status date="2025-01-25">accepted</status>
  <title>Test Benchmark STIG</title>
  <description>A test benchmark for unit tests.</description>
  <plain-text id="release-info">Release: ${release} Benchmark Date: ${date}</plain-text>
  <version>${version}</version>
  ${groupXml}
</Benchmark>`
}

// ---------------------------------------------------------------------------
// describe: DISA prefix stripping
// ---------------------------------------------------------------------------

describe('importBenchmark – benchmarkId prefix stripping', () => {
  it('strips the xccdf_<org>_benchmark_ prefix from the id attribute', async () => {
    const xml = makeXccdf({ id: 'xccdf_org.stig_benchmark_My_Test_Benchmark' })
    const result = await importBenchmark(xml)
    // The prefix should be stripped, leaving just the bare STIG id
    expect(result.benchmarkId).toBe('My_Test_Benchmark')
    expect(result.benchmarkId).not.toMatch(/^xccdf_/)
  })

  it('returns the id unchanged when there is no DISA prefix', async () => {
    // Real STIGs downloaded from cyber.mil sometimes have bare IDs
    const xml = makeXccdf({ id: 'Windows_Firewall_STIG' })
    const result = await importBenchmark(xml)
    expect(result.benchmarkId).toBe('Windows_Firewall_STIG')
  })
})

// ---------------------------------------------------------------------------
// describe: ruleCount / groupCount
// ---------------------------------------------------------------------------

describe('importBenchmark – rule and group counts', () => {
  it('ruleCount > 0 for a benchmark with groups and rules', async () => {
    const xml = makeXccdf({
      groups: [
        { groupId: 'V-1', ruleId: 'SV-1r1_rule', severity: 'high', title: 'Rule 1' },
        { groupId: 'V-2', ruleId: 'SV-2r1_rule', severity: 'medium', title: 'Rule 2' },
        { groupId: 'V-3', ruleId: 'SV-3r1_rule', severity: 'low', title: 'Rule 3' },
      ],
    })
    const result = await importBenchmark(xml)
    expect(result.ruleCount).toBe(3)
    expect(result.groupCount).toBe(3)
  })

  it('ruleCount is 0 for a benchmark with no groups', async () => {
    const xml = makeXccdf({ groups: [] })
    const result = await importBenchmark(xml)
    expect(result.ruleCount).toBe(0)
    expect(result.groupCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// describe: revisionStr format
// ---------------------------------------------------------------------------

describe('importBenchmark – revisionStr', () => {
  it('revisionStr matches "VNR{N}" pattern for integer version + release', async () => {
    const xml = makeXccdf({ version: '3', release: '7' })
    const result = await importBenchmark(xml)
    expect(result.revisionStr).toMatch(/^V\d+R\S+$/)
    expect(result.revisionStr).toBe('V3R7')
  })

  it('constructs revId as benchmarkId-VNR{N}', async () => {
    const xml = makeXccdf({ id: 'xccdf_org.stig_benchmark_My_STIG', version: '1', release: '2' })
    const result = await importBenchmark(xml)
    expect(result.revId).toBe('My_STIG-V1R2')
  })

  it('handles decimal release numbers without crashing', async () => {
    const xml = makeXccdf({ version: '2', release: '10' })
    const result = await importBenchmark(xml)
    expect(result.revisionStr).toBe('V2R10')
  })
})

// ---------------------------------------------------------------------------
// describe: error handling
// ---------------------------------------------------------------------------

describe('importBenchmark – error handling', () => {
  it('throws a meaningful error for completely invalid XML', async () => {
    await expect(importBenchmark('not xml at all')).rejects.toThrow(
      /Cannot parse XML document as a STIG or SCAP Benchmark/,
    )
  })

  it('throws for XML that has no Benchmark root element', async () => {
    const xml = `<?xml version="1.0"?><SomeOtherRoot><title>Nope</title></SomeOtherRoot>`
    await expect(importBenchmark(xml)).rejects.toThrow(
      /Cannot parse XML document as a STIG or SCAP Benchmark/,
    )
  })

  it('throws for SCAP with no Benchmark component', async () => {
    const xml = `<?xml version="1.0"?>
<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2">
  <component id="comp-1">
    <SomeElement/>
  </component>
</data-stream-collection>`
    await expect(importBenchmark(xml)).rejects.toThrow(
      /Cannot parse as DISA SCAP benchmark/,
    )
  })

  it('does not throw or hit entity-expansion limits on deeply-encoded text', async () => {
    // Build a rule description with many XML entities — this exercises the
    // processEntities:false path and the manual decodeXmlEntities decoder.
    const manyEntities = '&amp;'.repeat(1500) // well above the default 1000-entity limit
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<Benchmark id="Entity_Test_STIG" xmlns="http://checklists.nist.gov/xccdf/1.1">
  <plain-text id="release-info">Release: 1 Benchmark Date: 01 Jan 2024</plain-text>
  <version>1</version>
  <Group id="V-1">
    <title>V-1</title>
    <Rule id="SV-1r1_rule" severity="medium" weight="10.0">
      <version>ENT-001</version>
      <title>Entity test rule</title>
      <description>&lt;VulnDiscussion&gt;${manyEntities}&lt;/VulnDiscussion&gt;</description>
      <fixtext fixref="F-1">Fix.</fixtext>
      <check system="C-1r1_chk"><check-content>Check.</check-content></check>
    </Rule>
  </Group>
</Benchmark>`
    // Should parse without throwing an entity-limit error
    const result = await importBenchmark(xml)
    expect(result.ruleCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// describe: real STIG file smoke test
// ---------------------------------------------------------------------------

describe('importBenchmark – real STIG XCCDF file', () => {
  // Uses a small-ish real STIG from the local Evaluate-STIG content library.
  // If the path does not exist the test is skipped gracefully.
  const REAL_STIG_PATH = join(
    'C:\\Temp\\Evaulate.STIG\\Evaluate-STIG\\StigContent',
    'U_Adobe_Acrobat_Pro_XI_STIG_V1R2_Manual-xccdf.xml',
  )

  let realXml: string | null = null
  try {
    realXml = readFileSync(REAL_STIG_PATH, 'utf8')
  } catch {
    // File not accessible — tests below will be skipped
  }

  it('parses a real STIG XCCDF without throwing', { skip: realXml === null }, async () => {
    const result = await importBenchmark(realXml!)
    expect(result.ruleCount).toBeGreaterThan(0)
    expect(result.benchmarkId).toBeTruthy()
  })

  it('extracts a non-empty benchmarkId from the real file', { skip: realXml === null }, async () => {
    const result = await importBenchmark(realXml!)
    // The Adobe XI file uses a bare id (no DISA prefix) — id should pass through
    expect(result.benchmarkId).toMatch(/\S+/)
    expect(result.benchmarkId).not.toMatch(/^xccdf_/)
  })

  it('real file revisionStr follows VNR{N} pattern', { skip: realXml === null }, async () => {
    const result = await importBenchmark(realXml!)
    expect(result.revisionStr).toMatch(/^V\d+R\S+$/)
  })
})
