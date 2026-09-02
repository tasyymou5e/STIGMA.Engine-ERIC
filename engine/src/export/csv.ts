// Minimal CSV serialiser.
// RFC-4180-ish: values that contain a comma, double-quote, or newline are
// wrapped in double-quotes; any interior double-quote is doubled.

/**
 * Convert an array of plain objects to a CSV string.
 *
 * @param rows    - Data rows.  Each row is a plain object (nested objects are
 *                  JSON-serialised to a single cell value).
 * @param columns - Ordered list of keys to include.  Only these keys are emitted;
 *                  any key absent from a row is rendered as an empty cell.
 * @returns       - CSV string with \r\n line endings (RFC-4180).
 */
export function toCSV(rows: Record<string, unknown>[], columns: string[]): string {
  const lines: string[] = []

  // Header row
  lines.push(columns.map(quoteCell).join(','))

  // Data rows
  for (const row of rows) {
    const cells = columns.map((col) => {
      const v = row[col]
      if (v === null || v === undefined) return ''
      if (typeof v === 'object') return quoteCell(JSON.stringify(v))
      return quoteCell(String(v))
    })
    lines.push(cells.join(','))
  }

  return lines.join('\r\n')
}

/**
 * Wrap a cell value in double-quotes if it contains a comma, double-quote,
 * or newline character.  Interior double-quotes are escaped by doubling them.
 */
function quoteCell(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}
