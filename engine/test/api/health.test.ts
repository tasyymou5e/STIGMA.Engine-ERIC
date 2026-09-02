/**
 * health.test.ts
 *
 * Integration smoke-test: spins up the Fastify server via buildServer() and
 * sends a real HTTP request to GET /health.
 *
 * The database pool and OIDC/JWT dependencies are mocked so that the server
 * boots without a running MySQL instance or Keycloak.
 *
 * What this validates:
 *   - buildServer() resolves without crashing
 *   - All plugins and route registrations complete successfully
 *   - GET /health returns HTTP 200 with body { status: "ok" }
 */

import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest'
import type { FastifyInstance } from 'fastify'

// ---------------------------------------------------------------------------
// Mock the DB pool — must be hoisted before any module that imports pool.js
// ---------------------------------------------------------------------------
vi.mock('../../src/db/pool.js', () => ({
  pool: {
    query: vi.fn().mockResolvedValue([[], {}]),
    getConnection: vi.fn().mockResolvedValue({
      config: { namedPlaceholders: false },
      query: vi.fn().mockResolvedValue([[], {}]),
      beginTransaction: vi.fn().mockResolvedValue(undefined),
      commit: vi.fn().mockResolvedValue(undefined),
      rollback: vi.fn().mockResolvedValue(undefined),
      release: vi.fn(),
    }),
    end: vi.fn().mockResolvedValue(undefined),
  },
}))

// ---------------------------------------------------------------------------
// Mock OIDC/JWT verification so the auth plugin doesn't try to fetch JWKS
// ---------------------------------------------------------------------------
vi.mock('../../src/auth/jwt.js', () => ({
  verifyToken: vi.fn().mockResolvedValue({
    sub: 'test-user',
    username: 'test',
    roles: new Set<string>(),
    scopes: new Set<string>(),
  }),
}))

// ---------------------------------------------------------------------------
// Mock user repository (called by auth plugin on every authenticated request)
// ---------------------------------------------------------------------------
vi.mock('../../src/repositories/users.js', () => ({
  upsertUser: vi.fn().mockResolvedValue(1),
}))

// ---------------------------------------------------------------------------
// Import the server builder AFTER all mocks are registered
// ---------------------------------------------------------------------------
import { buildServer } from '../../src/server.js'

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('GET /health', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildServer()
    // Use Fastify's inject transport — no real TCP socket needed
    await app.ready()
  })

  afterAll(async () => {
    await app.close()
  })

  it('returns HTTP 200', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
    })
    expect(response.statusCode).toBe(200)
  })

  it('returns { status: "ok" }', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
    })
    const body = response.json<{ status: string }>()
    expect(body).toEqual({ status: 'ok' })
  })

  it('responds with Content-Type: application/json', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
    })
    expect(response.headers['content-type']).toMatch(/application\/json/)
  })

  it('does not require an Authorization header', async () => {
    // /health is an unauthenticated route — no bearer token needed
    const response = await app.inject({
      method: 'GET',
      url: '/health',
      // deliberately no authorization header
    })
    expect(response.statusCode).not.toBe(401)
    expect(response.statusCode).not.toBe(403)
  })
})
