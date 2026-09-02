// User and user-group management endpoints.
//
// Users are created implicitly on first authentication (upsertUser); these
// endpoints expose read/update/delete operations and group membership management.
//
// Mapped operationIds:
//   GET    /users                        → getUsers
//   GET    /users/:userId                → getUser
//   PATCH  /users/:userId                → patchUser
//   DELETE /users/:userId                → deleteUser
//
//   GET    /user-groups                  → getUserGroups
//   POST   /user-groups                  → createUserGroup
//   GET    /user-groups/:id              → getUserGroup
//   PUT    /user-groups/:id              → putUserGroup
//   DELETE /user-groups/:id              → deleteUserGroup
//
//   GET    /user-groups/:id/users        → getUserGroupUsers
//   POST   /user-groups/:id/users        → addUserGroupUser
//   DELETE /user-groups/:id/users        → removeUserGroupUser
//
// All endpoints require a valid bearer token + stig-manager:user scope.

import type { FastifyInstance } from 'fastify'
import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { z } from 'zod'
import { requireScope } from '../auth/plugin.js'
import { pool } from '../db/pool.js'
import { createUser, replaceUser } from '../repositories/users.js'

const SCOPE_USER = 'stig-manager:user'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UserRecord {
  userId: number
  sub: string
  username: string
  status: string
  lastAccess: string | null
}

export interface UserGroupRecord {
  userGroupId: number
  name: string
  description: string | null
}

export interface UserGroupMember {
  userId: number
  username: string
  status: string
}

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

/** POST /users — admin create */
const CreateUserBody = z.object({
  username: z.string().min(1)
})

/** PUT /users/:userId — admin full replace */
const PutUserBody = z.object({
  username: z.string().min(1),
  status:   z.enum(['available', 'unavailable'])
})

/** PATCH /users/:userId — all fields optional */
const PatchUserBody = z.object({
  username: z.string().min(1).optional(),
  status:   z.enum(['enabled', 'disabled']).optional()
})

const UserGroupBody = z.object({
  name:        z.string().min(1),
  description: z.string().optional()
})

const PutUserGroupBody = UserGroupBody

/** POST/DELETE /user-groups/:id/users — identify the target user */
const GroupUserBody = z.object({
  userId: z.number().int().positive()
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function numId(params: unknown, key = 'id'): number {
  return Number((params as Record<string, string>)[key])
}

function normaliseUser(row: RowDataPacket): UserRecord {
  return {
    userId:     Number(row.userId),
    sub:        String(row.sub ?? ''),
    username:   String(row.username ?? ''),
    status:     String(row.status ?? 'enabled'),
    lastAccess: row.lastAccess != null ? new Date(row.lastAccess as string).toISOString() : null
  }
}

function normaliseGroup(row: RowDataPacket): UserGroupRecord {
  return {
    userGroupId: Number(row.userGroupId),
    name:        String(row.name ?? ''),
    description: row.description != null ? String(row.description) : null
  }
}

async function fetchGroup(userGroupId: number): Promise<UserGroupRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    'SELECT userGroupId, name, description FROM user_group WHERE userGroupId = :userGroupId',
    { userGroupId }
  )
  if (rows.length === 0) return null
  return normaliseGroup(rows[0])
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

/** preHandler that 403s unless the token carries the "admin" realm role. */
async function requireAdmin(req: import('fastify').FastifyRequest, reply: import('fastify').FastifyReply) {
  if (!req.user?.roles?.has('admin')) {
    return reply.code(403).send({ error: 'Admin role required' })
  }
}

export async function registerUserRoutes(app: FastifyInstance): Promise<void> {
  const guard      = [app.authenticate, requireScope(SCOPE_USER)]
  const adminGuard = [app.authenticate, requireScope(SCOPE_USER), requireAdmin]

  // --------------------------------------------------------------------------
  // User endpoints
  // --------------------------------------------------------------------------

  // GET /users
  // operationId: getUsers
  app.get(
    '/users',
    { preHandler: guard },
    async () => {
      const [rows] = await pool.query<RowDataPacket[]>(
        `SELECT userId, sub, username, status, lastAccess
         FROM user_data
         ORDER BY username`
      )
      return rows.map(normaliseUser)
    }
  )

  // GET /users/:userId
  // operationId: getUser
  app.get(
    '/users/:userId',
    { preHandler: guard },
    async (req, reply) => {
      const userId = numId(req.params, 'userId')
      const [rows] = await pool.query<RowDataPacket[]>(
        'SELECT userId, sub, username, status, lastAccess FROM user_data WHERE userId = :userId',
        { userId }
      )
      if (rows.length === 0) return reply.code(404).send({ error: 'User not found' })
      return normaliseUser(rows[0])
    }
  )

  // POST /users
  // operationId: createUser (admin only)
  // Creates an admin-provisioned user record with an empty sub.
  app.post(
    '/users',
    { preHandler: adminGuard },
    async (req, reply) => {
      const body = CreateUserBody.parse(req.body)
      const userId = await createUser(body.username, {})
      const [rows] = await pool.query<RowDataPacket[]>(
        'SELECT userId, sub, username, status, lastAccess FROM user_data WHERE userId = :userId',
        { userId }
      )
      return reply.code(201).send(normaliseUser(rows[0]))
    }
  )

  // PUT /users/:userId
  // operationId: putUser (admin only)
  // Full replace: sets username and status atomically.
  app.put(
    '/users/:userId',
    { preHandler: adminGuard },
    async (req, reply) => {
      const userId = numId(req.params, 'userId')
      const body = PutUserBody.parse(req.body)
      const updated = await replaceUser(userId, body)
      if (!updated) return reply.code(404).send({ error: 'User not found' })
      const [rows] = await pool.query<RowDataPacket[]>(
        'SELECT userId, sub, username, status, lastAccess FROM user_data WHERE userId = :userId',
        { userId }
      )
      return normaliseUser(rows[0])
    }
  )

  // PATCH /users/:userId
  // operationId: patchUser
  // Allows updating username and/or status.  Sub (OIDC subject) is immutable.
  app.patch(
    '/users/:userId',
    { preHandler: guard },
    async (req, reply) => {
      const userId = numId(req.params, 'userId')
      const patch = PatchUserBody.parse(req.body)

      if (Object.keys(patch).length === 0) {
        return reply.code(400).send({ error: 'At least one field is required for PATCH' })
      }

      // Build SET clause dynamically from provided keys.
      const setClauses: string[] = []
      const values: Record<string, unknown> = { userId }

      if (patch.username !== undefined) {
        setClauses.push('username = :username')
        values.username = patch.username
      }
      if (patch.status !== undefined) {
        setClauses.push('status = :status')
        values.status = patch.status
      }

      const [res] = await pool.query<ResultSetHeader>(
        `UPDATE user_data SET ${setClauses.join(', ')} WHERE userId = :userId`,
        values as any
      )

      if (res.affectedRows === 0) return reply.code(404).send({ error: 'User not found' })

      const [rows] = await pool.query<RowDataPacket[]>(
        'SELECT userId, sub, username, status, lastAccess FROM user_data WHERE userId = :userId',
        { userId }
      )
      return normaliseUser(rows[0])
    }
  )

  // DELETE /users/:userId
  // operationId: deleteUser
  // Removes the user record.  Callers should remove grants/memberships first.
  app.delete(
    '/users/:userId',
    { preHandler: guard },
    async (req, reply) => {
      const userId = numId(req.params, 'userId')

      const [res] = await pool.query<ResultSetHeader>(
        'DELETE FROM user_data WHERE userId = :userId',
        { userId }
      )

      if (res.affectedRows === 0) return reply.code(404).send({ error: 'User not found' })
      return reply.code(204).send()
    }
  )

  // --------------------------------------------------------------------------
  // User-group endpoints
  // --------------------------------------------------------------------------

  // GET /user-groups
  // operationId: getUserGroups
  app.get(
    '/user-groups',
    { preHandler: guard },
    async () => {
      const [rows] = await pool.query<RowDataPacket[]>(
        'SELECT userGroupId, name, description FROM user_group ORDER BY name'
      )
      return rows.map(normaliseGroup)
    }
  )

  // POST /user-groups
  // operationId: createUserGroup
  app.post(
    '/user-groups',
    { preHandler: guard },
    async (req, reply) => {
      const body = UserGroupBody.parse(req.body)

      const [res] = await pool.query<ResultSetHeader>(
        'INSERT INTO user_group (name, description) VALUES (:name, :description)',
        { name: body.name, description: body.description ?? null }
      )

      const group = await fetchGroup(res.insertId)
      return reply.code(201).send(group)
    }
  )

  // GET /user-groups/:id
  // operationId: getUserGroup
  app.get(
    '/user-groups/:id',
    { preHandler: guard },
    async (req, reply) => {
      const userGroupId = numId(req.params)
      const group = await fetchGroup(userGroupId)
      return group ?? reply.code(404).send({ error: 'User group not found' })
    }
  )

  // PUT /user-groups/:id
  // operationId: putUserGroup
  app.put(
    '/user-groups/:id',
    { preHandler: guard },
    async (req, reply) => {
      const userGroupId = numId(req.params)
      const body = PutUserGroupBody.parse(req.body)

      const [res] = await pool.query<ResultSetHeader>(
        'UPDATE user_group SET name = :name, description = :description WHERE userGroupId = :userGroupId',
        { name: body.name, description: body.description ?? null, userGroupId }
      )

      if (res.affectedRows === 0) return reply.code(404).send({ error: 'User group not found' })
      return fetchGroup(userGroupId)
    }
  )

  // DELETE /user-groups/:id
  // operationId: deleteUserGroup
  // Also removes all membership rows and collection grants tied to this group.
  app.delete(
    '/user-groups/:id',
    { preHandler: guard },
    async (req, reply) => {
      const userGroupId = numId(req.params)

      // Remove dependent rows first to satisfy FK constraints.
      await pool.query(
        'DELETE FROM user_group_user WHERE userGroupId = :userGroupId',
        { userGroupId }
      )
      await pool.query(
        'DELETE FROM collection_grant WHERE userGroupId = :userGroupId',
        { userGroupId }
      )

      const [res] = await pool.query<ResultSetHeader>(
        'DELETE FROM user_group WHERE userGroupId = :userGroupId',
        { userGroupId }
      )

      if (res.affectedRows === 0) return reply.code(404).send({ error: 'User group not found' })
      return reply.code(204).send()
    }
  )

  // --------------------------------------------------------------------------
  // User-group membership endpoints
  // --------------------------------------------------------------------------

  // GET /user-groups/:id/users
  // operationId: getUserGroupUsers
  app.get(
    '/user-groups/:id/users',
    { preHandler: guard },
    async (req, reply) => {
      const userGroupId = numId(req.params)

      // Confirm group exists.
      const group = await fetchGroup(userGroupId)
      if (!group) return reply.code(404).send({ error: 'User group not found' })

      const [rows] = await pool.query<RowDataPacket[]>(
        `SELECT ud.userId, ud.username, ud.status
         FROM user_group_user ugu
         INNER JOIN user_data ud ON ud.userId = ugu.userId
         WHERE ugu.userGroupId = :userGroupId
         ORDER BY ud.username`,
        { userGroupId }
      )

      return rows.map((r): UserGroupMember => ({
        userId:   Number(r.userId),
        username: String(r.username ?? ''),
        status:   String(r.status ?? 'enabled')
      }))
    }
  )

  // POST /user-groups/:id/users
  // operationId: addUserGroupUser
  // Adds a user to the group (idempotent via INSERT IGNORE).
  app.post(
    '/user-groups/:id/users',
    { preHandler: guard },
    async (req, reply) => {
      const userGroupId = numId(req.params)
      const { userId } = GroupUserBody.parse(req.body)

      // Confirm group exists.
      const group = await fetchGroup(userGroupId)
      if (!group) return reply.code(404).send({ error: 'User group not found' })

      // Confirm user exists.
      const [userRows] = await pool.query<RowDataPacket[]>(
        'SELECT userId, username, status FROM user_data WHERE userId = :userId',
        { userId }
      )
      if (userRows.length === 0) return reply.code(404).send({ error: 'User not found' })

      await pool.query(
        'INSERT IGNORE INTO user_group_user (userGroupId, userId) VALUES (:userGroupId, :userId)',
        { userGroupId, userId }
      )

      return reply.code(201).send({
        userId:   Number(userRows[0].userId),
        username: String(userRows[0].username ?? ''),
        status:   String(userRows[0].status ?? 'enabled')
      } satisfies UserGroupMember)
    }
  )

  // DELETE /user-groups/:id/users
  // operationId: removeUserGroupUser
  // Removes a user from the group; 404 if the group or membership does not exist.
  app.delete(
    '/user-groups/:id/users',
    { preHandler: guard },
    async (req, reply) => {
      const userGroupId = numId(req.params)
      const { userId } = GroupUserBody.parse(req.body)

      const [res] = await pool.query<ResultSetHeader>(
        'DELETE FROM user_group_user WHERE userGroupId = :userGroupId AND userId = :userId',
        { userGroupId, userId }
      )

      if (res.affectedRows === 0) {
        return reply.code(404).send({ error: 'Membership not found' })
      }
      return reply.code(204).send()
    }
  )
}
