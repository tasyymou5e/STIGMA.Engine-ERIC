// Evaluate-STIG backend routes.
// Manages job lifecycle for the Windows Evaluate-STIG PowerShell agent.
// The agent runs on the Windows host, polls /app/scripts/eval-jobs/ for .json
// job files, executes Invoke-EvaluateSTIG.ps1, writes .log / .done / .running
// sentinel files, and ERIC picks up the results via the background monitor.

import fs from 'fs'
import path from 'path'
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { z } from 'zod'
import type { RowDataPacket, ResultSetHeader } from 'mysql2'
import { pool } from '../db/pool.js'
import { requireScope } from '../auth/plugin.js'
import { ingestChecklist } from '../engine/ingest.js'
import { runWinRmCommand } from '../utils/winrm.js'

// ── Constants ─────────────────────────────────────────────────────────────────

const JOBS_DIR = '/app/scripts/eval-jobs'
const AGENT_LOG = '/app/scripts/eval-stig-agent.log'

// Paths checked from inside the Docker container (Linux paths via volume mounts).
// ./Evaulate.STIG is mounted as /app/eval-stig in docker-compose.prod.yml.
const EVAL_STIG_PATHS = [
  '/app/eval-stig/Auxiliary/Invoke-EvaluateSTIG.ps1',
  '/app/eval-stig/Evaluate-STIG/Evaluate-STIG.ps1',
]

const SCOPE_COLLECTION = 'stig-manager:collection'

// Maximum wall-clock time to stream a job log (4 hours)
const STREAM_MAX_MS = 4 * 60 * 60 * 1_000
// SSE keepalive interval
const SSE_KEEPALIVE_MS = 15_000
// Background monitor poll interval
const MONITOR_POLL_MS = 10_000

// ── STIG catalogue ────────────────────────────────────────────────────────────

const STIG_GROUPS: Record<string, string[]> = {
  Windows:  ['Win11', 'Win10', 'WinServer2022', 'WinServer2019', 'WinServer2016'],
  Browsers: ['Chrome', 'MSEdge', 'IE11', 'Firefox'],
  Office:   ['MSOffice365', 'Excel2016', 'Word2016', 'PowerPoint2016'],
  Security: ['MSDefender', 'WinFirewall'],
  Database: ['SQLServer2019', 'PostgreSQL', 'Oracle12c'],
  Server:   ['IIS10_0_Server', 'IIS10_0_Site'],
  Other:    ['AdobeAcrobatProDCContinuous', 'AdobeReaderDCClassic', 'CiscoIOSRouter'],
}

// ── Zod schemas ───────────────────────────────────────────────────────────────

const CreateJobBody = z.object({
  collectionId:  z.number().int().positive(),
  targetHosts:   z.array(z.string().min(1)).min(1),
  selectedStigs: z.array(z.string()).optional(),
  outputPath:    z.string().optional(),
  vdiMode:       z.boolean().optional().default(false),
  vulnTimeout:   z.number().int().min(1).max(1440).optional().default(15),
  credential:    z.object({ username: z.string(), password: z.string() }).optional(),
})

const StartAgentBody = z.object({
  host:         z.string().optional().default('host.docker.internal'),
  port:         z.number().int().min(1).max(65535).optional().default(5985),
  useSSL:       z.boolean().optional().default(false),
  username:     z.string().min(1),
  password:     z.string().min(1),
  skipCertCheck: z.boolean().optional().default(true),
  agentScript:  z.string().optional().default('C:\\Temp\\Evaulate.STIG\\eval-stig-agent.ps1'),
})

// ── Helpers ───────────────────────────────────────────────────────────────────

function jobFilePath(jobId: number | bigint, ext = '.json'): string {
  return path.join(JOBS_DIR, `${jobId}${ext}`)
}

function jobsDirExists(): boolean {
  try { return fs.statSync(JOBS_DIR).isDirectory() } catch { return false }
}

function findEvalStigPath(): string | null {
  for (const p of EVAL_STIG_PATHS) {
    try { fs.accessSync(p, fs.constants.F_OK); return p } catch { /* next */ }
  }
  return null
}

function agentRunning(): boolean {
  try {
    const stat = fs.statSync(AGENT_LOG)
    return (Date.now() - stat.mtimeMs) < 180_000   // written in last 3 minutes
  } catch { return false }
}

/** Detect sentinel files and return the most-advanced status. */
function liveStatus(jobId: number | bigint): string | null {
  if (fs.existsSync(jobFilePath(jobId, '.done')))    return 'completed'
  if (fs.existsSync(jobFilePath(jobId, '.failed')))  return 'failed'
  if (fs.existsSync(jobFilePath(jobId, '.cancel')))  return 'cancelled'
  if (fs.existsSync(jobFilePath(jobId, '.running'))) return 'running'
  return null
}

// ── Route registration ────────────────────────────────────────────────────────

export async function registerEvalStigRoutes(app: FastifyInstance): Promise<void> {

  // 1. GET /eval-stig/status ─────────────────────────────────────────────────
  app.get(
    '/eval-stig/status',
    { preHandler: [app.authenticate] },
    async () => {
      const dirExists  = jobsDirExists()
      const evalPath   = findEvalStigPath()
      const agentAlive = agentRunning()
      return {
        available:      dirExists && evalPath !== null,
        jobsDirExists:  dirExists,
        evalStigFound:  evalPath !== null,
        agentRunning:   agentAlive,
        evalStigPath:   evalPath,
      }
    }
  )

  // 2. POST /eval-stig/agent/start — invoke agent on Windows host via WinRM ──
  app.post(
    '/eval-stig/agent/start',
    { preHandler: [app.authenticate] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const parsed = StartAgentBody.safeParse(req.body)
      if (!parsed.success) return reply.status(400).send({ error: 'Invalid body', detail: parsed.error.flatten() })
      const { host, port, useSSL, username, password, skipCertCheck, agentScript } = parsed.data

      // PowerShell command: start agent as a detached background job so WinRM
      // doesn't block waiting for the long-running script to finish.
      const psCmd = [
        `$p = Start-Process -FilePath pwsh.exe`,
        `-ArgumentList '-NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \\"${agentScript}\\"'`,
        `-WindowStyle Hidden -PassThru;`,
        `Write-Output "PID:$($p.Id)"`,
      ].join(' ')

      try {
        const result = await runWinRmCommand(
          { host: host!, port: port!, useSSL: useSSL!, username, password, skipCertCheck, timeoutMs: 30_000 },
          `powershell.exe -NonInteractive -Command "${psCmd.replace(/"/g, '\\"')}"`
        )

        const pidMatch = result.stdout.match(/PID:(\d+)/)
        return {
          started:  result.exitCode === 0,
          pid:      pidMatch ? parseInt(pidMatch[1], 10) : null,
          stdout:   result.stdout.trim(),
          stderr:   result.stderr.trim(),
          exitCode: result.exitCode,
          host,
          agentScript,
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        reply.status(502).send({
          error: 'WinRM connection failed',
          detail: msg,
          hint: 'Ensure WinRM is enabled on the host: Run-As-Admin → Enable-PSRemoting -Force',
        })
      }
    }
  )

  // 3. GET /eval-stig/stigs ──────────────────────────────────────────────────
  app.get(
    '/eval-stig/stigs',
    { preHandler: [app.authenticate] },
    async () => ({ groups: STIG_GROUPS })
  )

  // 3. POST /eval-stig/jobs ──────────────────────────────────────────────────
  app.post(
    '/eval-stig/jobs',
    { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const body = CreateJobBody.parse(req.body)
      const {
        collectionId, targetHosts, selectedStigs,
        outputPath, vdiMode, vulnTimeout, credential
      } = body

      const resolvedOutput = outputPath ?? 'C:\\Temp\\EvalSTIG-Results'

      // a. Insert DB record (no credential stored)
      const [result] = await pool.execute<ResultSetHeader>(
        `INSERT INTO eval_stig_job
           (collectionId, status, targetHosts, selectedStigs, outputPath, createdBy)
         VALUES (?, 'pending', ?, ?, ?, ?)`,
        [
          collectionId,
          JSON.stringify(targetHosts),
          selectedStigs ? JSON.stringify(selectedStigs) : null,
          resolvedOutput,
          req.user.username,
        ]
      )
      const jobId = result.insertId

      // b/c. Build and write job JSON to shared volume
      const jobObj = {
        jobId,
        collectionId,
        targetHosts,
        selectedStigs: selectedStigs ?? null,
        outputPath:    resolvedOutput,
        vdiMode:       vdiMode ?? false,
        vulnTimeout:   vulnTimeout ?? 15,
        // Credential is written to the file (consumed by agent) but not to DB
        credential:    credential ?? null,
        createdBy:     req.user.username,
        createdAt:     new Date().toISOString(),
      }

      try {
        if (!jobsDirExists()) {
          fs.mkdirSync(JOBS_DIR, { recursive: true })
        }
        const filePath = jobFilePath(jobId)
        fs.writeFileSync(filePath, JSON.stringify(jobObj, null, 2), 'utf-8')
        await pool.execute(
          'UPDATE eval_stig_job SET jobFile = ? WHERE jobId = ?',
          [filePath, jobId]
        )
      } catch (err) {
        app.log.error({ err }, '[eval-stig] failed to write job file')
        // Job is still queued in DB; agent will not pick it up without the file
      }

      return reply.code(201).send({ jobId, status: 'pending' })
    }
  )

  // 4. GET /eval-stig/jobs ───────────────────────────────────────────────────
  app.get(
    '/eval-stig/jobs',
    { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] },
    async (req: FastifyRequest) => {
      const { collectionId } = (req.query as Record<string, string | undefined>)
      const collId = collectionId ? Number(collectionId) : null

      const sql = `
        SELECT jobId, collectionId, status, targetHosts, selectedStigs,
               outputPath, importedCount, createdBy, startedAt, completedAt, errorMsg
        FROM eval_stig_job
        ${collId ? 'WHERE collectionId = ?' : ''}
        ORDER BY jobId DESC
        LIMIT 50`
      const params = collId ? [collId] : []
      const [rows] = await pool.query<RowDataPacket[]>(sql, params)

      // Enrich with sentinel-file live status (may lead DB if monitor hasn't run yet)
      return rows.map((row) => {
        const live = liveStatus(row.jobId as number)
        return {
          ...row,
          status: live ?? row.status,
        }
      })
    }
  )

  // 5. GET /eval-stig/jobs/:id ───────────────────────────────────────────────
  app.get(
    '/eval-stig/jobs/:id',
    { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const id = Number((req.params as Record<string, string>).id)
      if (!Number.isInteger(id) || id <= 0) {
        return reply.code(400).send({ error: 'invalid job id' })
      }

      const [rows] = await pool.query<RowDataPacket[]>(
        `SELECT jobId, collectionId, status, targetHosts, selectedStigs,
                outputPath, importedCount, createdBy, startedAt, completedAt, errorMsg, jobFile
         FROM eval_stig_job WHERE jobId = ? LIMIT 1`,
        [id]
      )
      if (rows.length === 0) return reply.code(404).send({ error: 'job not found' })

      const row = rows[0]
      const live = liveStatus(id)

      // Read last 200 lines of the log file if it exists
      let logTail: string[] = []
      const logFile = jobFilePath(id, '.log')
      try {
        const raw = fs.readFileSync(logFile, 'utf-8')
        const lines = raw.split('\n')
        logTail = lines.slice(-200)
      } catch { /* no log yet */ }

      return {
        ...row,
        status:  live ?? row.status,
        logTail,
      }
    }
  )

  // 6. DELETE /eval-stig/jobs/:id ────────────────────────────────────────────
  app.delete(
    '/eval-stig/jobs/:id',
    { preHandler: [app.authenticate, requireScope(SCOPE_COLLECTION)] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const id = Number((req.params as Record<string, string>).id)
      if (!Number.isInteger(id) || id <= 0) {
        return reply.code(400).send({ error: 'invalid job id' })
      }

      const [rows] = await pool.query<RowDataPacket[]>(
        'SELECT jobId FROM eval_stig_job WHERE jobId = ? LIMIT 1',
        [id]
      )
      if (rows.length === 0) return reply.code(404).send({ error: 'job not found' })

      await pool.execute(
        "UPDATE eval_stig_job SET status = 'cancelled' WHERE jobId = ?",
        [id]
      )

      // Write .cancel sentinel for the agent
      try {
        if (jobsDirExists()) {
          fs.writeFileSync(jobFilePath(id, '.cancel'), new Date().toISOString(), 'utf-8')
        }
      } catch (err) {
        app.log.warn({ err }, '[eval-stig] could not write .cancel sentinel')
      }

      return reply.code(204).send()
    }
  )

  // 7. GET /eval-stig/jobs/:id/stream (SSE) ──────────────────────────────────
  app.get(
    '/eval-stig/jobs/:id/stream',
    { preHandler: [app.authenticate] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const id = Number((req.params as Record<string, string>).id)
      if (!Number.isInteger(id) || id <= 0) {
        return reply.code(400).send({ error: 'invalid job id' })
      }

      reply.raw.writeHead(200, {
        'Content-Type':      'text/event-stream',
        'Cache-Control':     'no-cache',
        'Connection':        'keep-alive',
        'X-Accel-Buffering': 'no',
      })

      const logFile  = jobFilePath(id, '.log')
      const doneFile = jobFilePath(id, '.done')
      let   filePos  = 0
      let   closed   = false

      const sendEvent = (event: string, data: unknown) => {
        if (closed) return
        reply.raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
      }

      const readNewBytes = () => {
        try {
          const stat = fs.statSync(logFile)
          if (stat.size <= filePos) return
          const buf = Buffer.alloc(stat.size - filePos)
          const fd  = fs.openSync(logFile, 'r')
          fs.readSync(fd, buf, 0, buf.length, filePos)
          fs.closeSync(fd)
          filePos = stat.size
          const lines = buf.toString('utf-8').split('\n').filter(Boolean)
          for (const line of lines) sendEvent('log', { line })
        } catch { /* log not yet created */ }
      }

      const finish = () => {
        if (closed) return
        closed = true
        clearInterval(keepalive)
        fs.unwatchFile(logFile)
        clearTimeout(deadline)
        let finalStatus = 'completed'
        try {
          const raw = fs.readFileSync(doneFile, 'utf-8').trim()
          if (raw) finalStatus = raw
        } catch { /* use default */ }
        sendEvent('done', { status: finalStatus })
        reply.raw.end()
      }

      // Keepalive comment
      const keepalive = setInterval(() => {
        if (!closed) reply.raw.write(': keepalive\n\n')
      }, SSE_KEEPALIVE_MS)

      // Deadline (4 hours)
      const deadline = setTimeout(() => {
        sendEvent('timeout', { message: 'stream time limit reached' })
        finish()
      }, STREAM_MAX_MS)

      // Watch the log file for new data
      fs.watchFile(logFile, { interval: 1_000 }, () => {
        if (closed) { fs.unwatchFile(logFile); return }
        readNewBytes()
        if (fs.existsSync(doneFile)) finish()
      })

      // Also poll the .done file in case watchFile fires after the done write
      const donePoller = setInterval(() => {
        if (closed) { clearInterval(donePoller); return }
        if (fs.existsSync(doneFile)) { clearInterval(donePoller); finish() }
      }, 2_000)

      // Send whatever is already in the log
      readNewBytes()
      if (fs.existsSync(doneFile)) { clearInterval(donePoller); finish(); return reply }

      req.raw.on('close', () => {
        if (!closed) {
          closed = true
          clearInterval(keepalive)
          clearInterval(donePoller)
          clearTimeout(deadline)
          fs.unwatchFile(logFile)
        }
      })

      // Park until client disconnects or finish() resolves
      await new Promise<void>((resolve) => req.raw.on('close', resolve))
      return reply
    }
  )
}

// ── Background monitor ────────────────────────────────────────────────────────

// Track which .done files we have already processed to avoid re-importing.
const processedDoneFiles = new Set<string>()

async function processDoneFile(
  doneFile: string,
  log: FastifyInstance['log']
): Promise<void> {
  if (processedDoneFiles.has(doneFile)) return
  processedDoneFiles.add(doneFile)

  const base   = path.basename(doneFile, '.done')
  const jobId  = Number(base)
  if (!Number.isInteger(jobId) || jobId <= 0) return

  // Read terminal status from done file contents
  let terminalStatus = 'completed'
  try {
    const raw = fs.readFileSync(doneFile, 'utf-8').trim()
    if (['completed', 'failed', 'cancelled'].includes(raw)) terminalStatus = raw
  } catch { /* use default */ }

  // Fetch job record
  let jobRow: RowDataPacket | null = null
  try {
    const [rows] = await pool.query<RowDataPacket[]>(
      'SELECT jobId, collectionId, outputPath, status FROM eval_stig_job WHERE jobId = ? LIMIT 1',
      [jobId]
    )
    jobRow = rows[0] ?? null
  } catch (err) {
    log.error({ err }, `[eval-stig-monitor] DB fetch failed for job ${jobId}`)
    return
  }

  if (!jobRow) return
  // Don't overwrite a final status that was already set (e.g. cancelled by user)
  if (['cancelled', 'failed'].includes(String(jobRow.status))) terminalStatus = String(jobRow.status)

  // Auto-import .cklb files from outputPath
  let importedCount = 0
  const outputPath = String(jobRow.outputPath ?? '')
  if (outputPath && terminalStatus === 'completed') {
    try {
      const files = fs.readdirSync(outputPath).filter((f) => f.endsWith('.cklb'))
      for (const file of files) {
        try {
          const content = fs.readFileSync(path.join(outputPath, file), 'utf-8')
          await ingestChecklist(Number(jobRow.collectionId), content, 'eval-stig-agent', 'cklb')
          importedCount++
        } catch (err) {
          log.warn({ err, file }, '[eval-stig-monitor] failed to ingest file')
        }
      }
    } catch (err) {
      log.warn({ err, outputPath }, '[eval-stig-monitor] could not read outputPath')
    }
  }

  // Update DB
  try {
    await pool.execute(
      `UPDATE eval_stig_job
          SET status = ?,
              completedAt  = NOW(),
              importedCount = importedCount + ?
        WHERE jobId = ?`,
      [terminalStatus, importedCount, jobId]
    )
    log.info(`[eval-stig-monitor] job ${jobId} → ${terminalStatus}, imported ${importedCount} files`)
  } catch (err) {
    log.error({ err }, `[eval-stig-monitor] DB update failed for job ${jobId}`)
  }

  // Zero out credential in the job JSON file so it's not left on disk
  const jobFile = jobFilePath(jobId)
  try {
    if (fs.existsSync(jobFile)) {
      const raw  = JSON.parse(fs.readFileSync(jobFile, 'utf-8')) as Record<string, unknown>
      if (raw.credential) {
        raw.credential = null
        fs.writeFileSync(jobFile, JSON.stringify(raw, null, 2), 'utf-8')
      }
    }
  } catch (err) {
    log.warn({ err }, `[eval-stig-monitor] could not zero credential in job file ${jobFile}`)
  }
}

export function startEvalStigMonitor(log: FastifyInstance['log']): void {
  setInterval(async () => {
    if (!jobsDirExists()) return
    let entries: string[]
    try {
      entries = fs.readdirSync(JOBS_DIR)
    } catch { return }

    const doneFiles = entries
      .filter((e) => e.endsWith('.done'))
      .map((e) => path.join(JOBS_DIR, e))

    for (const df of doneFiles) {
      await processDoneFile(df, log).catch((err) =>
        log.error({ err, df }, '[eval-stig-monitor] unexpected error')
      )
    }
  }, MONITOR_POLL_MS)

  log.info('[eval-stig-monitor] background job monitor started')
}
