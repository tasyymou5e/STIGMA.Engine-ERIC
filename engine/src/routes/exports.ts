// Archive export endpoints — ZIP bundles of CKL / CKLB files for a collection.
//
// GET /collections/:id/archive/ckl   → {collectionName}_{date}.ckl.zip
// GET /collections/:id/archive/cklb  → {collectionName}_{date}.cklb.zip
//
// Implementation uses a pure-Node ZIP builder (no extra dependencies) so the
// package.json stays untouched.  The ZIP is assembled in memory via
// buildZipBuffer() and sent as a single application/zip response.

import type { FastifyInstance } from 'fastify'
import { deflateRawSync } from 'node:zlib'
import { requireScope } from '../auth/plugin.js'
import { getCollection } from '../repositories/collections.js'
import { generateCkl, generateCklb } from '../repositories/assets.js'
import { pool } from '../db/pool.js'
import type { RowDataPacket } from 'mysql2'

const SCOPE_COLLECTION = 'stig-manager:collection'

// ---------------------------------------------------------------------------
// Minimal in-memory ZIP builder (PKZIP / ZIP 2.0, Store + Deflate)
// Spec ref: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
// ---------------------------------------------------------------------------

interface ZipEntry {
  filename: string
  data: Buffer
}

function crc32(buf: Buffer): number {
  // CRC-32 table (ISO 3309 polynomial)
  const table = getCrc32Table()
  let crc = 0xffffffff
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xff]
  }
  return (crc ^ 0xffffffff) >>> 0
}

let _crcTable: Uint32Array | null = null
function getCrc32Table(): Uint32Array {
  if (_crcTable) return _crcTable
  _crcTable = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }
    _crcTable[n] = c
  }
  return _crcTable
}

function writeUint16LE(buf: Buffer, offset: number, value: number): number {
  buf.writeUInt16LE(value, offset)
  return offset + 2
}

function writeUint32LE(buf: Buffer, offset: number, value: number): number {
  buf.writeUInt32LE(value, offset)
  return offset + 4
}

function buildZipBuffer(entries: ZipEntry[]): Buffer {
  const localHeaders: Buffer[] = []
  const centralHeaders: Buffer[] = []
  const offsets: number[] = []
  let offset = 0

  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.filename, 'utf8')
    const uncompressed = entry.data
    const compressed = deflateRawSync(uncompressed, { level: 6 })
    // Use deflate only if it actually shrinks the data
    const useDeflate = compressed.length < uncompressed.length
    const compData = useDeflate ? compressed : uncompressed
    const method = useDeflate ? 8 : 0   // 8=deflate, 0=store
    const crc = crc32(uncompressed)

    // --- Local file header (30 bytes + name) ---
    const lhSize = 30 + nameBytes.length
    const lh = Buffer.alloc(lhSize)
    let p = 0
    p = writeUint32LE(lh, p, 0x04034b50)   // signature
    p = writeUint16LE(lh, p, 20)            // version needed (2.0)
    p = writeUint16LE(lh, p, 0x0800)        // general flags: UTF-8 filename
    p = writeUint16LE(lh, p, method)
    p = writeUint16LE(lh, p, 0)             // last mod time
    p = writeUint16LE(lh, p, 0)             // last mod date
    p = writeUint32LE(lh, p, crc)
    p = writeUint32LE(lh, p, compData.length)
    p = writeUint32LE(lh, p, uncompressed.length)
    p = writeUint16LE(lh, p, nameBytes.length)
    p = writeUint16LE(lh, p, 0)             // extra field length
    nameBytes.copy(lh, p)

    offsets.push(offset)
    localHeaders.push(lh)
    localHeaders.push(compData)
    offset += lh.length + compData.length

    // --- Central directory header (46 bytes + name) ---
    const chSize = 46 + nameBytes.length
    const ch = Buffer.alloc(chSize)
    let q = 0
    q = writeUint32LE(ch, q, 0x02014b50)   // signature
    q = writeUint16LE(ch, q, 20)            // version made by
    q = writeUint16LE(ch, q, 20)            // version needed
    q = writeUint16LE(ch, q, 0x0800)        // flags: UTF-8
    q = writeUint16LE(ch, q, method)
    q = writeUint16LE(ch, q, 0)             // last mod time
    q = writeUint16LE(ch, q, 0)             // last mod date
    q = writeUint32LE(ch, q, crc)
    q = writeUint32LE(ch, q, compData.length)
    q = writeUint32LE(ch, q, uncompressed.length)
    q = writeUint16LE(ch, q, nameBytes.length)
    q = writeUint16LE(ch, q, 0)             // extra field length
    q = writeUint16LE(ch, q, 0)             // comment length
    q = writeUint16LE(ch, q, 0)             // disk number start
    q = writeUint16LE(ch, q, 0)             // internal attrs
    q = writeUint32LE(ch, q, 0)             // external attrs
    q = writeUint32LE(ch, q, offsets[offsets.length - 1])  // local header offset
    nameBytes.copy(ch, q)
    centralHeaders.push(ch)
  }

  const cdOffset = offset
  const cdSize = centralHeaders.reduce((s, b) => s + b.length, 0)

  // --- End of central directory record (22 bytes) ---
  const eocd = Buffer.alloc(22)
  let e = 0
  e = writeUint32LE(eocd, e, 0x06054b50)   // signature
  e = writeUint16LE(eocd, e, 0)             // disk number
  e = writeUint16LE(eocd, e, 0)             // disk with start of cd
  e = writeUint16LE(eocd, e, entries.length)
  e = writeUint16LE(eocd, e, entries.length)
  e = writeUint32LE(eocd, e, cdSize)
  e = writeUint32LE(eocd, e, cdOffset)
  e = writeUint16LE(eocd, e, 0)             // comment length

  return Buffer.concat([...localHeaders, ...centralHeaders, eocd])
}

// ---------------------------------------------------------------------------
// DB helper: list asset+benchmark pairs for a collection that have reviews
// ---------------------------------------------------------------------------

interface AssetBenchmarkPair {
  assetId: number
  assetName: string
  benchmarkId: string
}

async function listCollectionAssetBenchmarks(
  collectionId: number
): Promise<AssetBenchmarkPair[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT DISTINCT
       a.assetId,
       a.name  AS assetName,
       r.benchmarkId
     FROM review r
     JOIN asset a ON a.assetId = r.assetId
     WHERE a.collectionId = :collectionId
       AND a.state = 'enabled'
       AND r.benchmarkId IS NOT NULL
       AND r.benchmarkId <> ''
     ORDER BY a.name, r.benchmarkId`,
    { collectionId }
  )
  return rows as unknown as AssetBenchmarkPair[]
}

// ---------------------------------------------------------------------------
// Filename helpers
// ---------------------------------------------------------------------------

function safeFilename(s: string): string {
  return s.replace(/[^A-Za-z0-9_\-. ]/g, '_').replace(/\s+/g, '_').slice(0, 80)
}

function isoDate(): string {
  return new Date().toISOString().slice(0, 10)
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function registerExportRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // GET /collections/:id/archive/ckl
  // Returns a ZIP containing one .ckl file per asset+STIG pair in the collection.
  app.get(
    '/collections/:id/archive/ckl',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = Number((req.params as { id: string }).id)
      const collection = await getCollection(collectionId)
      if (!collection) return reply.code(404).send({ error: 'Collection not found' })

      const pairs = await listCollectionAssetBenchmarks(collectionId)
      if (pairs.length === 0) {
        return reply.code(404).send({ error: 'No reviewed checklists found in this collection' })
      }

      const entries: ZipEntry[] = []
      const errors: string[] = []

      for (const pair of pairs) {
        try {
          const xml = await generateCkl(pair.assetId, pair.benchmarkId)
          if (xml == null) continue
          const filename = `${safeFilename(pair.assetName)}__${safeFilename(pair.benchmarkId)}.ckl`
          entries.push({ filename, data: Buffer.from(xml, 'utf8') })
        } catch (err) {
          errors.push(`${pair.assetName}/${pair.benchmarkId}: ${String(err)}`)
        }
      }

      if (entries.length === 0) {
        return reply.code(404).send({ error: 'No exportable CKL files found', details: errors })
      }

      const zip = buildZipBuffer(entries)
      const safeName = safeFilename(collection.name)
      const date = isoDate()

      return reply
        .header('Content-Type', 'application/zip')
        .header('Content-Disposition', `attachment; filename="${safeName}_${date}.ckl.zip"`)
        .send(zip)
    }
  )

  // GET /collections/:id/archive/cklb
  // Returns a ZIP containing one .cklb file per asset+STIG pair in the collection.
  app.get(
    '/collections/:id/archive/cklb',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = Number((req.params as { id: string }).id)
      const collection = await getCollection(collectionId)
      if (!collection) return reply.code(404).send({ error: 'Collection not found' })

      const pairs = await listCollectionAssetBenchmarks(collectionId)
      if (pairs.length === 0) {
        return reply.code(404).send({ error: 'No reviewed checklists found in this collection' })
      }

      const entries: ZipEntry[] = []
      const errors: string[] = []

      for (const pair of pairs) {
        try {
          const cklb = await generateCklb(pair.assetId, pair.benchmarkId)
          if (cklb == null) continue
          const json = JSON.stringify(cklb, null, 2)
          const filename = `${safeFilename(pair.assetName)}__${safeFilename(pair.benchmarkId)}.cklb`
          entries.push({ filename, data: Buffer.from(json, 'utf8') })
        } catch (err) {
          errors.push(`${pair.assetName}/${pair.benchmarkId}: ${String(err)}`)
        }
      }

      if (entries.length === 0) {
        return reply.code(404).send({ error: 'No exportable CKLB files found', details: errors })
      }

      const zip = buildZipBuffer(entries)
      const safeName = safeFilename(collection.name)
      const date = isoDate()

      return reply
        .header('Content-Type', 'application/zip')
        .header('Content-Disposition', `attachment; filename="${safeName}_${date}.cklb.zip"`)
        .send(zip)
    }
  )
}
