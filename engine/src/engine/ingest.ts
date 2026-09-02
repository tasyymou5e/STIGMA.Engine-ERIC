// Ingest engine: parse a checklist of any supported format and persist the
// normalized reviews against an asset, recording an ingest run.
import { parseChecklist } from './parse/index.js'
import type { ChecklistSource } from './types.js'
import { ensureAsset } from '../repositories/assets.js'
import { upsertReviews, carryReviewsOnRevisionUpgrade } from '../repositories/reviews.js'
import { recordIngestRun } from '../repositories/runs.js'
import { pool } from '../db/pool.js'
import type { RowDataPacket } from 'mysql2'

export interface IngestResult {
  assetId: number
  assetName: string
  source: ChecklistSource
  benchmarkId: string
  revision: string
  reviewCount: number
  /** Number of reviews carried forward from a prior revision via content-hash matching */
  reviewsCarried: number
}

export async function ingestChecklist(
  collectionId: number,
  content: string,
  username: string,
  source?: ChecklistSource
): Promise<IngestResult> {
  const parsed = parseChecklist(content, source)
  const assetName = parsed.hostName || 'unknown-host'
  const assetId = await ensureAsset(collectionId, assetName)
  await upsertReviews(assetId, parsed.benchmarkId, parsed.reviews, username)

  // ------------------------------------------------------------------
  // Content-hash review persistence: carry reviews that survived a STIG
  // revision upgrade (same check content, potentially different ruleId).
  // We resolve the current active revId from current_rev for this benchmark
  // and pass it to carryReviewsOnRevisionUpgrade which does the digest
  // matching across revision boundaries.
  // ------------------------------------------------------------------
  let reviewsCarried = 0
  try {
    const [revRows] = await pool.query<RowDataPacket[]>(
      'SELECT revId FROM current_rev WHERE benchmarkId = ? LIMIT 1',
      [parsed.benchmarkId]
    )
    if (revRows.length > 0) {
      const currentRevId = revRows[0].revId as string
      reviewsCarried = await carryReviewsOnRevisionUpgrade(
        assetId,
        parsed.benchmarkId,
        currentRevId,
        username
      )
    }
  } catch {
    // current_rev table may not exist in minimal deployments — degrade gracefully
    reviewsCarried = 0
  }

  await recordIngestRun({
    collectionId,
    assetId,
    source: parsed.source,
    benchmarkId: parsed.benchmarkId,
    reviewCount: parsed.reviews.length,
    username
  })
  return {
    assetId,
    assetName,
    source: parsed.source,
    benchmarkId: parsed.benchmarkId,
    revision: parsed.revision,
    reviewCount: parsed.reviews.length,
    reviewsCarried
  }
}
