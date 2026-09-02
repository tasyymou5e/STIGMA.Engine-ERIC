// Per-collection RBAC middleware for ERIC.
// requireCollectionRole(minRole) → Fastify preHandler that enforces a minimum
// collection-level role (1=Restricted, 2=Full, 3=Manage, 4=Owner).
// Admin users (realm role "admin") bypass the check entirely.
import type { FastifyReply, FastifyRequest } from 'fastify'
import { pool, type Row } from '../db/pool.js'

// Augment FastifyRequest so that req.userId is available after the auth
// plugin's upsert resolves the Keycloak sub to the DB bigint PK.
declare module 'fastify' {
  interface FastifyRequest {
    userId: number
  }
}

// ---------------------------------------------------------------------------
// Shared query helper
// ---------------------------------------------------------------------------

/**
 * Returns the effective (MAX) roleId granted to userId on collectionId,
 * considering both direct grants and group-inherited grants.
 * Returns null when the user has no grant on this collection.
 */
export async function getCollectionRole(
  collectionId: number,
  userId: number
): Promise<number | null> {
  const sql = `
    SELECT MAX(cg.roleId) AS roleId
    FROM collection_grant cg
    WHERE cg.collectionId = :collectionId
      AND (
        cg.userId = :userId
        OR cg.userGroupId IN (
          SELECT userGroupId FROM user_group_user_map WHERE userId = :userId
        )
      )
  `
  const [rows] = await pool.execute<Row[]>(sql, { collectionId, userId })
  const row = rows[0] as { roleId: number | null } | undefined
  if (!row || row.roleId === null) return null
  return row.roleId
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/**
 * Returns a Fastify preHandler that 403s unless the authenticated user holds
 * at least minRole on the collection identified by the :id route parameter.
 *
 * Users with the "admin" realm role bypass the collection-role check.
 *
 * @param minRole  1=Restricted | 2=Full | 3=Manage | 4=Owner
 */
export function requireCollectionRole(minRole: 1 | 2 | 3 | 4) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    // Admin bypass — no collection-role check needed.
    if (req.user.roles.has('admin')) return
    // Elevated session bypass — admin with ?elevate=true sees everything.
    if (req.elevated) return

    const collectionId = Number((req.params as { id: string }).id)
    const userId = req.userId

    const roleId = await getCollectionRole(collectionId, userId)

    if (roleId === null) {
      await reply.code(403).send({ error: 'No collection grant' })
      return
    }

    if (roleId < minRole) {
      await reply
        .code(403)
        .send({ error: 'Insufficient collection role', required: minRole, actual: roleId })
      return
    }
  }
}
