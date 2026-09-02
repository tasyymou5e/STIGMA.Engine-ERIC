/**
 * reviews.test.ts
 *
 * Unit tests for the reviews repository (src/repositories/reviews.ts).
 *
 * The MySQL pool is mocked entirely via vi.mock so no database is required.
 * Tests focus on:
 *
 *   1. upsertReviews([]) — short-circuits and returns 0 without touching the DB
 *   2. upsertReviews with data — calls pool.getConnection() and runs a transaction
 *   3. Rollback on error — conn.rollback() is invoked when a query throws
 *   4. Connection release — conn.release() is always called (happy + error paths)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { NormalizedReview } from '../../src/engine/types.js'

// ---------------------------------------------------------------------------
// Hoist mock functions so they are available inside the vi.mock() factory.
// vi.mock() calls are hoisted to the top of the file by Vitest — any variables
// referenced in the factory must also be hoisted via vi.hoisted().
// ---------------------------------------------------------------------------

const { mockPoolGetConnection, mockPoolQuery } = vi.hoisted(() => ({
  mockPoolGetConnection: vi.fn(),
  mockPoolQuery: vi.fn().mockResolvedValue([[], {}]),
}))

vi.mock('../../src/db/pool.js', () => ({
  pool: {
    getConnection: mockPoolGetConnection,
    query: mockPoolQuery,
  },
}))

// ---------------------------------------------------------------------------
// Build the mock connection object (can reference vi.fn() directly here)
// ---------------------------------------------------------------------------

// Mutable mock state — reset between tests via beforeEach
let mockQueryImpl: () => Promise<unknown>

const mockConn = {
  config: { namedPlaceholders: false },
  query: vi.fn((..._args: unknown[]) => mockQueryImpl()),
  beginTransaction: vi.fn().mockResolvedValue(undefined),
  commit: vi.fn().mockResolvedValue(undefined),
  rollback: vi.fn().mockResolvedValue(undefined),
  release: vi.fn(),
}

// Import the module under test AFTER the mock is registered
import { upsertReviews } from '../../src/repositories/reviews.js'

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

function makeReview(overrides: Partial<NormalizedReview> = {}): NormalizedReview {
  return {
    ruleId: 'SV-220706r1_rule',
    groupId: 'V-220706',
    ruleVersion: 'WN11-CC-000005',
    severity: 'medium',
    title: 'Camera access disabled.',
    result: 'fail',
    detail: 'Finding detail',
    comment: '',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Reset mocks before each test
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()

  // Default mock: every query returns an empty resultset with affectedRows = 1
  mockQueryImpl = async () => [[{ userId: 42 }], { affectedRows: 1 }]

  mockConn.query.mockImplementation((..._args: unknown[]) => mockQueryImpl())
  mockConn.beginTransaction.mockResolvedValue(undefined)
  mockConn.commit.mockResolvedValue(undefined)
  mockConn.rollback.mockResolvedValue(undefined)
  mockConn.release.mockReset()
  mockPoolGetConnection.mockResolvedValue(mockConn)
})

// ---------------------------------------------------------------------------
// describe: empty-array short-circuit
// ---------------------------------------------------------------------------

describe('upsertReviews – empty array', () => {
  it('returns 0 immediately when reviews array is empty', async () => {
    const result = await upsertReviews(1, 'Test_STIG', [], 'testuser')
    expect(result).toBe(0)
  })

  it('does NOT call pool.getConnection() when the array is empty', async () => {
    await upsertReviews(1, 'Test_STIG', [], 'testuser')
    expect(mockPoolGetConnection).not.toHaveBeenCalled()
  })

  it('does NOT call conn.beginTransaction() when the array is empty', async () => {
    await upsertReviews(1, 'Test_STIG', [], 'testuser')
    expect(mockConn.beginTransaction).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// describe: happy path with reviews
// ---------------------------------------------------------------------------

describe('upsertReviews – with reviews', () => {
  it('calls pool.getConnection() exactly once', async () => {
    // Arrange: set up query responses for each call in order
    // 1st: userRows  2nd: resultId rows  3rd: rvcd rows  4th: existRows  5th: bulk INSERT
    let callCount = 0
    mockConn.query.mockImplementation(async () => {
      callCount++
      if (callCount === 1) return [[{ userId: 5 }], {}]         // user lookup
      if (callCount === 2) return [[{ api: 'fail', resultId: 2 }], {}] // result map
      if (callCount === 3) return [[], {}]                        // rvcd map
      if (callCount === 4) return [[], {}]                        // existing reviewIds
      // bulk INSERT result
      return [{ affectedRows: 1 }, {}]
    })

    await upsertReviews(42, 'Test_STIG', [makeReview()], 'testuser')
    expect(mockPoolGetConnection).toHaveBeenCalledTimes(1)
  })

  it('begins and commits a transaction', async () => {
    let callCount = 0
    mockConn.query.mockImplementation(async () => {
      callCount++
      if (callCount === 1) return [[{ userId: 5 }], {}]
      if (callCount === 2) return [[{ api: 'fail', resultId: 2 }], {}]
      if (callCount === 3) return [[], {}]
      if (callCount === 4) return [[], {}]
      return [{ affectedRows: 1 }, {}]
    })

    await upsertReviews(42, 'Test_STIG', [makeReview()], 'testuser')

    expect(mockConn.beginTransaction).toHaveBeenCalledTimes(1)
    expect(mockConn.commit).toHaveBeenCalledTimes(1)
    expect(mockConn.rollback).not.toHaveBeenCalled()
  })

  it('releases the connection after a successful upsert', async () => {
    let callCount = 0
    mockConn.query.mockImplementation(async () => {
      callCount++
      if (callCount === 1) return [[{ userId: 5 }], {}]
      if (callCount === 2) return [[{ api: 'fail', resultId: 2 }], {}]
      if (callCount === 3) return [[], {}]
      if (callCount === 4) return [[], {}]
      return [{ affectedRows: 1 }, {}]
    })

    await upsertReviews(42, 'Test_STIG', [makeReview()], 'testuser')
    expect(mockConn.release).toHaveBeenCalledTimes(1)
  })

  it('returns the affectedRows count from the bulk INSERT', async () => {
    let callCount = 0
    mockConn.query.mockImplementation(async () => {
      callCount++
      if (callCount === 1) return [[{ userId: 5 }], {}]
      if (callCount === 2) return [[{ api: 'fail', resultId: 2 }], {}]
      if (callCount === 3) return [[], {}]
      if (callCount === 4) return [[], {}]
      return [{ affectedRows: 3 }, {}]
    })

    const result = await upsertReviews(42, 'Test_STIG', [makeReview(), makeReview(), makeReview()], 'testuser')
    expect(result).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// describe: error path — rollback + release
// ---------------------------------------------------------------------------

describe('upsertReviews – error handling', () => {
  it('rolls back the transaction when a query throws', async () => {
    let callCount = 0
    mockConn.query.mockImplementation(async () => {
      callCount++
      if (callCount === 1) return [[{ userId: 5 }], {}]
      if (callCount === 2) return [[{ api: 'fail', resultId: 2 }], {}]
      if (callCount === 3) return [[], {}]
      // Simulate a DB error on the existing-reviews lookup
      throw new Error('DB connection lost')
    })

    await expect(
      upsertReviews(42, 'Test_STIG', [makeReview()], 'testuser'),
    ).rejects.toThrow('DB connection lost')

    expect(mockConn.rollback).toHaveBeenCalledTimes(1)
    expect(mockConn.commit).not.toHaveBeenCalled()
  })

  it('releases the connection even when an error is thrown', async () => {
    mockConn.query.mockRejectedValue(new Error('Fatal DB error'))

    await expect(
      upsertReviews(42, 'Test_STIG', [makeReview()], 'testuser'),
    ).rejects.toThrow('Fatal DB error')

    // release() must always be called in the finally block
    expect(mockConn.release).toHaveBeenCalledTimes(1)
  })

  it('rethrows the original error after rolling back', async () => {
    const originalError = new Error('Unique constraint violation')
    mockConn.query.mockRejectedValue(originalError)

    await expect(
      upsertReviews(42, 'Test_STIG', [makeReview()], 'testuser'),
    ).rejects.toBe(originalError)
  })
})

// ---------------------------------------------------------------------------
// describe: multiple reviews in a single call
// ---------------------------------------------------------------------------

describe('upsertReviews – batch of multiple reviews', () => {
  it('processes multiple reviews in a single getConnection call', async () => {
    let callCount = 0
    mockConn.query.mockImplementation(async () => {
      callCount++
      if (callCount === 1) return [[{ userId: 5 }], {}]
      if (callCount === 2) return [
        [{ api: 'fail', resultId: 2 }, { api: 'pass', resultId: 1 }], {}
      ]
      if (callCount === 3) return [[], {}]
      if (callCount === 4) return [[], {}]
      return [{ affectedRows: 4 }, {}]
    })

    const reviews = [
      makeReview({ result: 'fail', severity: 'high' }),
      makeReview({ result: 'pass', severity: 'medium' }),
      makeReview({ result: 'fail', severity: 'low' }),
      makeReview({ result: 'pass', severity: 'high' }),
    ]

    const result = await upsertReviews(99, 'Multi_STIG', reviews, 'batchuser')
    expect(mockPoolGetConnection).toHaveBeenCalledTimes(1)
    expect(result).toBe(4)
  })
})
