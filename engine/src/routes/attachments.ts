// Review attachment endpoints.
// Stores file content as MEDIUMBLOB in the review_attachment table.
// Requires @fastify/multipart registered on the app instance (done in server.ts).
//
//   GET    /reviews/:reviewId/attachments         → list attachment metadata
//   POST   /reviews/:reviewId/attachments         → upload file (multipart/form-data)
//   GET    /reviews/:reviewId/attachments/:id     → stream file with correct headers
//   DELETE /reviews/:reviewId/attachments/:id     → delete attachment row

import type { FastifyInstance } from 'fastify'
import { pool } from '../db/pool.js'
import { requireScope } from '../auth/plugin.js'

const SCOPE_COLLECTION = 'stig-manager:collection'

/** Maximum upload size: 10 MB */
const MAX_BYTES = 10 * 1024 * 1024

function numParam(params: unknown, key: string): number {
  return Number((params as Record<string, string>)[key])
}

export async function registerAttachmentRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // --------------------------------------------------------------------------
  // GET /reviews/:reviewId/attachments
  // Returns metadata only (no file content).
  // --------------------------------------------------------------------------
  app.get(
    '/reviews/:reviewId/attachments',
    { preHandler: guard },
    async (req, _reply) => {
      const reviewId = numParam(req.params, 'reviewId')
      const [rows] = await pool.execute(
        `SELECT attachmentId, reviewId, filename, mimetype, size, uploadedBy, uploadedAt
           FROM review_attachment
          WHERE reviewId = ?
          ORDER BY uploadedAt DESC`,
        [reviewId]
      )
      return rows
    }
  )

  // --------------------------------------------------------------------------
  // POST /reviews/:reviewId/attachments
  // Accepts a single file field named "file" via multipart/form-data.
  // --------------------------------------------------------------------------
  app.post(
    '/reviews/:reviewId/attachments',
    { preHandler: guard },
    async (req, reply) => {
      const reviewId = numParam(req.params, 'reviewId')

      // Verify the review exists.
      const [reviewRows] = await pool.execute<import('../db/pool.js').Row[]>(
        'SELECT reviewId FROM review WHERE reviewId = ?',
        [reviewId]
      )
      if ((reviewRows as unknown[]).length === 0) {
        return reply.code(404).send({ error: 'Review not found' })
      }

      // Read the multipart file.
      const data = await req.file({ limits: { fileSize: MAX_BYTES } })
      if (!data) {
        return reply.code(400).send({ error: 'No file uploaded — expected a multipart field named "file"' })
      }

      // Collect the stream into a Buffer.
      const chunks: Buffer[] = []
      for await (const chunk of data.file) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
      }
      const content = Buffer.concat(chunks)

      if (content.length === 0) {
        return reply.code(400).send({ error: 'Uploaded file is empty' })
      }
      if (content.length > MAX_BYTES) {
        return reply.code(413).send({ error: 'File exceeds 10 MB limit' })
      }

      const filename = data.filename || 'upload'
      const mimetype = data.mimetype || 'application/octet-stream'
      const uploadedBy = req.user?.username ?? null

      const [result] = await pool.execute<import('mysql2').ResultSetHeader>(
        `INSERT INTO review_attachment (reviewId, filename, mimetype, size, content, uploadedBy)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [reviewId, filename, mimetype, content.length, content, uploadedBy]
      )

      const attachmentId = (result as import('mysql2').ResultSetHeader).insertId
      return reply.code(201).send({
        attachmentId,
        reviewId,
        filename,
        mimetype,
        size: content.length,
        uploadedBy,
        uploadedAt: new Date().toISOString()
      })
    }
  )

  // --------------------------------------------------------------------------
  // GET /reviews/:reviewId/attachments/:id
  // Streams the file content with correct Content-Type and Content-Disposition.
  // --------------------------------------------------------------------------
  app.get(
    '/reviews/:reviewId/attachments/:id',
    { preHandler: guard },
    async (req, reply) => {
      const reviewId = numParam(req.params, 'reviewId')
      const attachmentId = numParam(req.params, 'id')

      const [rows] = await pool.execute<import('../db/pool.js').Row[]>(
        `SELECT filename, mimetype, size, content
           FROM review_attachment
          WHERE attachmentId = ? AND reviewId = ?`,
        [attachmentId, reviewId]
      )

      const row = (rows as unknown[])[0] as {
        filename: string
        mimetype: string
        size: number
        content: Buffer
      } | undefined

      if (!row) {
        return reply.code(404).send({ error: 'Attachment not found' })
      }

      reply
        .header('Content-Type', row.mimetype)
        .header('Content-Disposition', `attachment; filename="${encodeURIComponent(row.filename)}"`)
        .header('Content-Length', String(row.size))
      return reply.send(row.content)
    }
  )

  // --------------------------------------------------------------------------
  // DELETE /reviews/:reviewId/attachments/:id
  // --------------------------------------------------------------------------
  app.delete(
    '/reviews/:reviewId/attachments/:id',
    { preHandler: guard },
    async (req, reply) => {
      const reviewId = numParam(req.params, 'reviewId')
      const attachmentId = numParam(req.params, 'id')

      const [result] = await pool.execute<import('mysql2').ResultSetHeader>(
        'DELETE FROM review_attachment WHERE attachmentId = ? AND reviewId = ?',
        [attachmentId, reviewId]
      )

      const affected = (result as import('mysql2').ResultSetHeader).affectedRows
      if (affected === 0) {
        return reply.code(404).send({ error: 'Attachment not found' })
      }
      return reply.code(204).send()
    }
  )
}
