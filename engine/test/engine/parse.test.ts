import { describe, it, expect } from 'vitest'
import { parseChecklist, detectFormat } from '../../src/engine/parse/index.js'

const CKL = `<?xml version="1.0"?>
<CHECKLIST>
  <ASSET><HOST_NAME>WIN11-TEST</HOST_NAME></ASSET>
  <STIGS><iSTIG>
    <STIG_INFO>
      <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Microsoft Windows 11 STIG</SID_DATA></SI_DATA>
      <SI_DATA><SID_NAME>stigid</SID_NAME><SID_DATA>Windows_11_STIG</SID_DATA></SI_DATA>
      <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>Release: 1 Benchmark Date: 01 Jan 2026</SID_DATA></SI_DATA>
    </STIG_INFO>
    <VULN>
      <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-220706</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-220706r1_rule</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>WN11-CC-000005</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Camera access disabled.</ATTRIBUTE_DATA></STIG_DATA>
      <STATUS>Open</STATUS><FINDING_DETAILS>x</FINDING_DETAILS><COMMENTS>c</COMMENTS>
    </VULN>
    <VULN>
      <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-220707</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-220707r1_rule</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Some high rule.</ATTRIBUTE_DATA></STIG_DATA>
      <STATUS>NotAFinding</STATUS><FINDING_DETAILS></FINDING_DETAILS><COMMENTS></COMMENTS>
    </VULN>
  </iSTIG></STIGS>
</CHECKLIST>`

const CKLB = JSON.stringify({
  title: 'Win11',
  target_data: { host_name: 'WIN11-CKLB' },
  stigs: [{
    stig_id: 'Windows_11_STIG', display_name: 'Microsoft Windows 11 STIG', release_info: 'V1R1',
    rules: [
      { group_id: 'V-1', rule_id: 'SV-1r1_rule', rule_version: 'WN11-1', severity: 'high', rule_title: 'r1', status: 'open' },
      { group_id: 'V-2', rule_id: 'SV-2r1_rule', rule_version: 'WN11-2', severity: 'low', rule_title: 'r2', status: 'not_a_finding' }
    ]
  }]
})

const XCCDF = `<?xml version="1.0"?>
<Benchmark id="Windows_11_STIG" xmlns="http://checklists.nist.gov/xccdf/1.2">
  <title>Microsoft Windows 11 STIG</title>
  <Group id="V-1"><Rule id="SV-1r1_rule" severity="high"><title>High rule</title></Rule></Group>
  <Group id="V-2"><Rule id="SV-2r1_rule" severity="medium"><title>Med rule</title></Rule></Group>
  <TestResult test-system="SCC">
    <rule-result idref="SV-1r1_rule"><result>fail</result></rule-result>
    <rule-result idref="SV-2r1_rule"><result>pass</result></rule-result>
  </TestResult>
</Benchmark>`

describe('format detection', () => {
  it('detects each format', () => {
    expect(detectFormat(CKL)).toBe('ckl')
    expect(detectFormat(CKLB)).toBe('cklb')
    expect(detectFormat(XCCDF)).toBe('xccdf')
  })
})

describe('CKL parser', () => {
  it('normalizes status and metadata', () => {
    const p = parseChecklist(CKL)
    expect(p.source).toBe('ckl')
    expect(p.hostName).toBe('WIN11-TEST')
    expect(p.benchmarkId).toBe('Windows_11_STIG')
    expect(p.reviews).toHaveLength(2)
    expect(p.reviews[0]).toMatchObject({ groupId: 'V-220706', ruleVersion: 'WN11-CC-000005', severity: 'medium', result: 'fail' })
    expect(p.reviews[1]).toMatchObject({ severity: 'high', result: 'pass' })
  })
})

describe('CKLB parser', () => {
  it('maps JSON statuses', () => {
    const p = parseChecklist(CKLB)
    expect(p.source).toBe('cklb')
    expect(p.hostName).toBe('WIN11-CKLB')
    expect(p.reviews.map((r) => r.result)).toEqual(['fail', 'pass'])
    expect(p.reviews[0].severity).toBe('high')
  })
})

describe('XCCDF parser', () => {
  it('joins rule-result with Rule metadata', () => {
    const p = parseChecklist(XCCDF)
    expect(p.source).toBe('xccdf')
    expect(p.benchmarkId).toBe('Windows_11_STIG')
    expect(p.reviews).toHaveLength(2)
    expect(p.reviews[0]).toMatchObject({ ruleId: 'SV-1r1_rule', severity: 'high', result: 'fail' })
    expect(p.reviews[1]).toMatchObject({ severity: 'medium', result: 'pass' })
  })
})
