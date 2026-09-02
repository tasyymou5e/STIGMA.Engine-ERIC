// Collection-grant (access-control) endpoints.
//
// A grant ties a user or user-group to a collection with an access-level
// (integer 1-4 matching the STIG Manager grantee access ladder):
//   1 = Restricted  2 = Full  3 = Manage  4 = Owner
//
// Mapped operationIds:
//   GET    /collections/:id/grants                         → getGrantsByCollection
//   POST   /collections/:id/grants                         → createGrant
//   GET    /collections/:id/grants/:grantId                → getGrant
//   PUT    /collections/:id/grants/:grantId                → putGrant
//   DELETE /collections/:id/grants/:grantId                → deleteGrant
//   GET    /collections/:id/grants/:grantId/effective-acl  → getEffectiveAcl
//
// All endpoints require a valid bearer token + stig-manager:collection scope.

import type { FastifyInstance } from 'fastify'
import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import { pool } from '../db/pool.js'
import {
  getAclRules,
  putAclRules,
  getEffectiveAclForUser,
  type AclRule
} from '../repositories/grants.js'

const SCOPE_COLLECTION = 'stig-manager:collection'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GrantRecord {
  grantId: number
  collectionId: number
  /** Grantee type: 'user' or 'userGroup' */
  granteeType: 'user' | 'userGroup'
  /** userId when granteeType === 'user', null otherwise */
  userId: number | null
  /** userGroupId when granteeType === 'userGroup', null otherwise */
  userGroupId: number | null
  /** Display name derived from the joined user/group row */
  granteeName: string
  /** Access level 1–4 */
  accessLevel: number
}

export interface EffectiveAcl {
  grantId: number
  collectionId: number
  userId: number
  username: string
  accessLevel: number
  /** True when the access level was inherited from a group grant */
  inherited: boolean
}

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

const AccessLevel = z.number().int().min(1).max(4)

const AclRuleSchema = z.object({
  benchmarkId: z.string().nullable().optional().default(null),
  assetId:     z.number().int().positive().nullable().optional().default(null),
  clId:        z.number().int().positive().nullable().optional().default(null),
  access:      z.enum(['none', 'r', 'rw'])
})

const AclRulesBody = z.array(AclRuleSchema)

const GrantBody = z.object({
  /** 'user' or 'userGroup' — determines which id field is required */
  granteeType: z.enum(['user', 'userGroup']),
  userId: z.number().int().positive().optional(),
  userGroupId: z.number().int().positive().optional(),
  accessLevel: AccessLevel
}).refine(
  (b) => b.granteeType === 'user' ? b.userId != null : b.userGroupId != null,
  { message: 'userId required when granteeType=user; userGroupId required when granteeType=userGroup' }
)

const PutGrantBody = z.object({ accessLevel: AccessLevel })

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function numId(params: unknown, key = 'id'): number {
  const raw = (params as Record<string, string>)[key]
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0) throw Object.assign(new Error(`Invalid id: ${raw}`), { statusCode: 400 })
  return n
}

async function fetchGrant(grantId: number, collectionId: number): Promise<GrantRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT
       cg.grantId,
       cg.collectionId,
       CASE WHEN cg.userId IS NOT NULL THEN 'user' ELSE 'userGroup' END AS granteeType,
       cg.userId,
       cg.userGroupId,
       cg.roleId AS accessLevel,
       COALESCE(ud.username, ug.name, '') AS granteeName
     FROM collection_grant cg
     LEFT JOIN user_data ud ON ud.userId = cg.userId
     LEFT JOIN user_group ug ON ug.userGroupId = cg.userGroupId
     WHERE cg.grantId = :grantId AND cg.collectionId = :collectionId`,
    { grantId, collectionId }
  )
  if (rows.length === 0) return null
  return normaliseGrant(rows[0])
}

function normaliseGrant(row: RowDataPacket): GrantRecord {
  return {
    grantId:      Number(row.grantId),
    collectionId: Number(row.collectionId),
    granteeType:  row.granteeType as 'user' | 'userGroup',
    userId:       row.userId != null ? Number(row.userId) : null,
    userGroupId:  row.userGroupId != null ? Number(row.userGroupId) : null,
    granteeName:  String(row.granteeName ?? ''),
    accessLevel:  Number(row.accessLevel)
  }
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function registerGrantRoutes(app: FastifyInstance): Promise<void> {
  const guard = [app.authenticate, requireScope(SCOPE_COLLECTION)]

  // GET /collections/:id/grants
  // operationId: getGrantsByCollection
  app.get(
    '/collections/:id/grants',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const [rows] = await pool.query<RowDataPacket[]>(
        `SELECT
           cg.grantId,
           cg.collectionId,
           CASE WHEN cg.userId IS NOT NULL THEN 'user' ELSE 'userGroup' END AS granteeType,
           cg.userId,
           cg.userGroupId,
           cg.roleId AS accessLevel,
           COALESCE(ud.username, ug.name, '') AS granteeName
         FROM collection_grant cg
         LEFT JOIN user_data ud ON ud.userId = cg.userId
         LEFT JOIN user_group ug ON ug.userGroupId = cg.userGroupId
         WHERE cg.collectionId = :collectionId
         ORDER BY cg.grantId`,
        { collectionId }
      )
      return rows.map(normaliseGrant)
    }
  )

  // POST /collections/:id/grants
  // operationId: createGrant
  app.post(
    '/collections/:id/grants',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const body = GrantBody.parse(req.body)

      const [res] = await pool.query<ResultSetHeader>(
        `INSERT INTO collection_grant
           (collectionId, userId, userGroupId, roleId)
         VALUES
           (:collectionId, :userId, :userGroupId, :roleId)`,
        {
          collectionId,
          userId:      body.userId ?? null,
          userGroupId: body.userGroupId ?? null,
          roleId:      body.accessLevel
        }
      )

      const grant = await fetchGrant(res.insertId, collectionId)
      return reply.code(201).send(grant)
    }
  )

  // GET /collections/:id/grants/:grantId
  // operationId: getGrant
  app.get(
    '/collections/:id/grants/:grantId',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const grantId      = numId(req.params, 'grantId')
      const grant = await fetchGrant(grantId, collectionId)
      return grant ?? reply.code(404).send({ error: 'Grant not found' })
    }
  )

  // PUT /collections/:id/grants/:grantId
  // operationId: putGrant
  // Only the accessLevel can be updated on an existing grant; grantee is immutable.
  app.put(
    '/collections/:id/grants/:grantId',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const grantId      = numId(req.params, 'grantId')
      const { accessLevel } = PutGrantBody.parse(req.body)

      const [res] = await pool.query<ResultSetHeader>(
        `UPDATE collection_grant
         SET roleId = :roleId
         WHERE grantId = :grantId AND collectionId = :collectionId`,
        { roleId: accessLevel, grantId, collectionId }
      )

      if (res.affectedRows === 0) return reply.code(404).send({ error: 'Grant not found' })
      return fetchGrant(grantId, collectionId)
    }
  )

  // DELETE /collections/:id/grants/:grantId
  // operationId: deleteGrant
  app.delete(
    '/collections/:id/grants/:grantId',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const grantId      = numId(req.params, 'grantId')

      const [res] = await pool.query<ResultSetHeader>(
        'DELETE FROM collection_grant WHERE grantId = :grantId AND collectionId = :collectionId',
        { grantId, collectionId }
      )

      if (res.affectedRows === 0) return reply.code(404).send({ error: 'Grant not found' })
      return reply.code(204).send()
    }
  )

  // GET /collections/:id/grants/:grantId/effective-acl
  // operationId: getEffectiveAcl
  //
  // Resolves the set of individual users that are covered by this grant —
  // for a user grant this is always a single row; for a group grant it is
  // every member of that group.  Access level is inherited from the grant;
  // no per-user override logic is applied here.
  app.get(
    '/collections/:id/grants/:grantId/effective-acl',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const grantId      = numId(req.params, 'grantId')

      // Confirm the grant exists and belongs to this collection.
      const grant = await fetchGrant(grantId, collectionId)
      if (!grant) return reply.code(404).send({ error: 'Grant not found' })

      let rows: RowDataPacket[]

      if (grant.granteeType === 'user') {
        // Single-user grant — return the one user row.
        ;[rows] = await pool.query<RowDataPacket[]>(
          `SELECT ud.userId, ud.username, :accessLevel AS accessLevel, 0 AS inherited
           FROM user_data ud
           WHERE ud.userId = :userId`,
          { userId: grant.userId, accessLevel: grant.accessLevel }
        )
      } else {
        // Group grant — expand membership.
        ;[rows] = await pool.query<RowDataPacket[]>(
          `SELECT ud.userId, ud.username, :accessLevel AS accessLevel, 1 AS inherited
           FROM user_group_user ugu
           INNER JOIN user_data ud ON ud.userId = ugu.userId
           WHERE ugu.userGroupId = :userGroupId
           ORDER BY ud.username`,
          { userGroupId: grant.userGroupId, accessLevel: grant.accessLevel }
        )
      }

      return rows.map((r): EffectiveAcl => ({
        grantId,
        collectionId,
        userId:      Number(r.userId),
        username:    String(r.username ?? ''),
        accessLevel: Number(r.accessLevel),
        inherited:   Boolean(r.inherited)
      }))
    }
  )

  // GET /collections/:id/grants/:grantId/acl
  // operationId: getAclRulesByGrant
  app.get(
    '/collections/:id/grants/:grantId/acl',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const grantId      = numId(req.params, 'grantId')
      const grant = await fetchGrant(grantId, collectionId)
      if (!grant) return reply.code(404).send({ error: 'Grant not found' })
      return getAclRules(grantId)
    }
  )

  // PUT /collections/:id/grants/:grantId/acl
  // operationId: putAclRulesByGrant
  app.put(
    '/collections/:id/grants/:grantId/acl',
    { preHandler: guard },
    async (req, reply) => {
      const collectionId = numId(req.params)
      const grantId      = numId(req.params, 'grantId')
      const grant = await fetchGrant(grantId, collectionId)
      if (!grant) return reply.code(404).send({ error: 'Grant not found' })

      const rules = AclRulesBody.parse(req.body)
      const mapped: AclRule[] = rules.map((r) => ({
        grantId,
        benchmarkId: r.benchmarkId ?? null,
        assetId:     r.assetId     ?? null,
        clId:        r.clId        ?? null,
        access:      r.access
      }))
      await putAclRules(grantId, mapped)
      return getAclRules(grantId)
    }
  )

  // GET /collections/:id/users/:userId/acl
  // operationId: getEffectiveAclForUser
  app.get(
    '/collections/:id/users/:userId/acl',
    { preHandler: guard },
    async (req) => {
      const collectionId = numId(req.params)
      const userId       = numId(req.params, 'userId')
      return getEffectiveAclForUser(collectionId, userId)
    }
  )
}
