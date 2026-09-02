import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'
import type { UserRecord } from './users.js'

export interface UserGroup {
  userGroupId: number
  name: string
  description: string
  memberCount?: number
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/**
 * Return all user groups, each with a memberCount derived from the join table.
 */
export async function listUserGroups(): Promise<UserGroup[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT ug.userGroupId,
            ug.name,
            ug.description,
            COUNT(ugm.userId) AS memberCount
     FROM user_groups ug
     LEFT JOIN user_group_members ugm ON ugm.userGroupId = ug.userGroupId
     GROUP BY ug.userGroupId`
  )
  return rows.map(normaliseGroup)
}

/**
 * Look up a single group by its primary key.
 * Returns null when not found.
 */
export async function getUserGroup(id: number): Promise<UserGroup | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT ug.userGroupId,
            ug.name,
            ug.description,
            COUNT(ugm.userId) AS memberCount
     FROM user_groups ug
     LEFT JOIN user_group_members ugm ON ugm.userGroupId = ug.userGroupId
     WHERE ug.userGroupId = :id
     GROUP BY ug.userGroupId`,
    { id }
  )
  if (rows.length === 0) return null
  return normaliseGroup(rows[0])
}

/**
 * Insert a new user group.
 * Returns the generated userGroupId.
 */
export async function createUserGroup(
  { name, description }: { name: string; description: string },
  createdUserId: number
): Promise<number> {
  const [result] = await pool.query<ResultSetHeader>(
    `INSERT INTO user_groups (name, description, createdUserId, created)
     VALUES (:name, :description, :createdUserId, NOW())`,
    { name, description, createdUserId }
  )
  return result.insertId
}

/**
 * Apply a partial update to a group's mutable fields.
 * Returns true when a row was matched (and potentially changed).
 */
export async function updateUserGroup(
  id: number,
  patch: Partial<Pick<UserGroup, 'name' | 'description'>>
): Promise<boolean> {
  const fields: string[] = []
  const params: Record<string, unknown> = { id }

  if (patch.name !== undefined) {
    fields.push('name = :name')
    params['name'] = patch.name
  }
  if (patch.description !== undefined) {
    fields.push('description = :description')
    params['description'] = patch.description
  }
  if (fields.length === 0) return false

  const [result] = await pool.query<ResultSetHeader>(
    `UPDATE user_groups SET ${fields.join(', ')} WHERE userGroupId = :id`,
    params as any
  )
  return result.affectedRows > 0
}

/**
 * Delete a group (and its member associations via ON DELETE CASCADE or explicit cleanup).
 * Returns true when the row existed and was removed.
 */
export async function deleteUserGroup(id: number): Promise<boolean> {
  // Remove members first in case the schema does not declare CASCADE.
  await pool.query<ResultSetHeader>(
    'DELETE FROM user_group_members WHERE userGroupId = :id',
    { id }
  )
  const [result] = await pool.query<ResultSetHeader>(
    'DELETE FROM user_groups WHERE userGroupId = :id',
    { id }
  )
  return result.affectedRows > 0
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

/**
 * Return all users that belong to the given group.
 */
export async function listGroupMembers(id: number): Promise<UserRecord[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT ud.userId, ud.sub, ud.username, ud.status, ud.webPreferences, ud.lastAccess
     FROM user_group_members ugm
     JOIN user_data ud ON ud.userId = ugm.userId
     WHERE ugm.userGroupId = :id`,
    { id }
  )
  return rows.map(normaliseUser)
}

/**
 * Add a user to a group.  Silently ignores duplicate membership (INSERT IGNORE).
 */
export async function addGroupMember(userGroupId: number, userId: number): Promise<void> {
  await pool.query<ResultSetHeader>(
    'INSERT IGNORE INTO user_group_members (userGroupId, userId) VALUES (:userGroupId, :userId)',
    { userGroupId, userId }
  )
}

/**
 * Remove a user from a group.
 */
export async function removeGroupMember(userGroupId: number, userId: number): Promise<void> {
  await pool.query<ResultSetHeader>(
    'DELETE FROM user_group_members WHERE userGroupId = :userGroupId AND userId = :userId',
    { userGroupId, userId }
  )
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function normaliseGroup(row: RowDataPacket): UserGroup {
  return {
    userGroupId: row['userGroupId'] as number,
    name: row['name'] as string,
    description: row['description'] as string,
    memberCount: row['memberCount'] != null ? Number(row['memberCount']) : undefined
  }
}

function normaliseUser(row: RowDataPacket): UserRecord {
  return {
    userId: row['userId'] as number,
    sub: row['sub'] as string,
    username: row['username'] as string,
    status: row['status'] as string,
    webPreferences:
      typeof row['webPreferences'] === 'string'
        ? (JSON.parse(row['webPreferences']) as Record<string, unknown>)
        : ((row['webPreferences'] as Record<string, unknown>) ?? {}),
    lastAccess: row['lastAccess'] != null ? new Date(row['lastAccess'] as string) : null
  }
}
