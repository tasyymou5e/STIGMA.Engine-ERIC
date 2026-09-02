// Cron-based maintenance job scheduler.
//
// Jobs:
//   job-1: Cleanup Database          — daily at 02:00
//   job-2: Delete Unmapped Reviews   — every Sunday at 03:00
//   job-3: Delete Unmapped Asset Reviews — every Sunday at 03:30
//   job-4: Review Aging              — daily at 04:00 (all enabled collections)

import cron from 'node-cron'
import type { FastifyBaseLogger } from 'fastify'
import { pool } from './db/pool.js'
import {
  wipeDeletedObjects,
  deleteUnmappedReviews,
  deleteUnmappedAssetReviews,
  analyzeReviewTables,
  runReviewAging
} from './routes/tasks.js'
import { getReviewAgingConfig } from './repositories/collections.js'
import type { RowDataPacket } from 'mysql2'

export function startScheduler(logger: FastifyBaseLogger): void {
  // job-1: Cleanup Database — daily at 02:00
  cron.schedule('0 2 * * *', async () => {
    logger.info('[cron] Starting: Cleanup Database')
    const conn = await pool.getConnection()
    try {
      await wipeDeletedObjects(conn)
      await analyzeReviewTables(conn)
    } catch (e) {
      logger.error({ err: e }, '[cron] Cleanup Database failed')
    } finally {
      conn.release()
    }
  })

  // job-2: Delete Unmapped Reviews — every Sunday at 03:00
  cron.schedule('0 3 * * 0', async () => {
    logger.info('[cron] Starting: Delete Unmapped Reviews')
    const conn = await pool.getConnection()
    try {
      await deleteUnmappedReviews(conn)
      await analyzeReviewTables(conn)
    } catch (e) {
      logger.error({ err: e }, '[cron] Delete Unmapped Reviews failed')
    } finally {
      conn.release()
    }
  })

  // job-3: Delete Unmapped Asset Reviews — every Sunday at 03:30
  cron.schedule('30 3 * * 0', async () => {
    logger.info('[cron] Starting: Delete Unmapped Asset Reviews')
    const conn = await pool.getConnection()
    try {
      await deleteUnmappedAssetReviews(conn)
      await analyzeReviewTables(conn)
    } catch (e) {
      logger.error({ err: e }, '[cron] Delete Unmapped Asset Reviews failed')
    } finally {
      conn.release()
    }
  })

  // job-4: Review Aging — daily at 04:00 for all configured collections
  cron.schedule('0 4 * * *', async () => {
    logger.info('[cron] Starting: Review Aging')
    try {
      const [rows] = await pool.query<RowDataPacket[]>(
        'SELECT collectionId FROM review_aging_rule WHERE enabled = 1'
      )
      for (const r of rows) {
        const cfg = await getReviewAgingConfig(r.collectionId as number)
        if (cfg) {
          try {
            await runReviewAging(r.collectionId as number, cfg)
          } catch (e) {
            logger.error({ err: e, collectionId: r.collectionId }, '[cron] Review Aging failed for collection')
          }
        }
      }
    } catch (e) {
      logger.error({ err: e }, '[cron] Review Aging failed')
    }
  })

  logger.info('[cron] Scheduler started: Cleanup@02:00, DeleteUnmapped@Sun03:00/03:30, Aging@04:00')
}
