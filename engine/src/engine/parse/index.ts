// Format detection + dispatch. Sniffs the content and routes to the right parser.
import type { ChecklistSource, ParsedChecklist } from '../types.js'
import { parseCkl } from './ckl.js'
import { parseCklb } from './cklb.js'
import { parseXccdf } from './xccdf.js'

export function detectFormat(content: string): ChecklistSource {
  const head = content.slice(0, 4096)
  if (/^\s*[{[]/.test(content)) return 'cklb'           // JSON
  if (/<CHECKLIST/i.test(head)) return 'ckl'
  if (/<Benchmark|<xccdf|<TestResult/i.test(head)) return 'xccdf'
  throw new Error('Unrecognized checklist format (expected CKL, CKLB, or XCCDF)')
}

export function parseChecklist(content: string, source?: ChecklistSource): ParsedChecklist {
  const fmt = source ?? detectFormat(content)
  switch (fmt) {
    case 'ckl': return parseCkl(content)
    case 'cklb': return parseCklb(content)
    case 'xccdf': return parseXccdf(content)
  }
}

export { parseCkl, parseCklb, parseXccdf }
