// Fastify auth: a `authenticate` preHandler that verifies the bearer token and
// populates request.user, plus a `requireScope(...)` factory for endpoint guards.
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { verifyToken, type AuthUser } from './jwt.js'
import { upsertUser } from '../repositories/users.js'

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (req: FastifyRequest, reply: FastifyReply) => Promise<unknown>
  }
  interface FastifyRequest {
    user: AuthUser
    userId: number
    elevated: boolean
  }
}

export async function authPlugin(app: FastifyInstance): Promise<void> {
  app.decorateRequest('user', null as unknown as AuthUser)
  app.decorateRequest('userId', 0)
  app.decorateRequest('elevated', false)

  app.decorate('authenticate', async (req: FastifyRequest, reply: FastifyReply) => {
    const hdr = req.headers.authorization
    if (!hdr || !hdr.startsWith('Bearer ')) {
      return reply.code(401).send({ error: 'Missing bearer token' })
    }
    try {
      req.user = await verifyToken(hdr.slice('Bearer '.length))
    } catch (e) {
      return reply.code(401).send({ error: 'Invalid token', detail: (e as Error).message })
    }
    // Upsert the user in the DB and attach the numeric userId to the request.
    // If the DB is unavailable this must not block the request — fail silently.
    try {
      req.userId = await upsertUser(req.user.sub, req.user.username, {})
    } catch (e) {
      req.log.warn({ err: (e as Error).message }, '[auth] upsertUser failed')
      req.userId = 0
    }
    // Elevation: admin + ?elevate=true gives full visibility across collections.
    req.elevated =
      req.user.roles.has('admin') &&
      (req as unknown as { query: Record<string, string> }).query?.elevate === 'true'
  })
}

// Returns a preHandler that 403s unless ALL given scopes are present in the token.
export function requireScope(...scopes: string[]) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    if (!scopes.every((s) => req.user?.scopes.has(s))) {
      return reply.code(403).send({ error: 'Required scope(s) not present', required: scopes })
    }
  }
}
