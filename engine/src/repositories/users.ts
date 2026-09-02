import type { ResultSetHeader, RowDataPacket } from 'mysql2'
import { pool } from '../db/pool.js'

export interface UserRecord {
  userId: number
  sub: string
  username: string
  status: string
  webPreferences: Record<string, unknown>
  lastAccess: Date | null
}

/**
 * Upsert a user row keyed on `sub` (OIDC subject / Keycloak UUID).
 * Returns the userId for both the insert and update paths.
 */
export async function upsertUser(
  sub: string,
  username: string,
  lastClaims: Record<string, unknown>
): Promise<number> {
  // Use LAST_INSERT_ID(userId) trick: forces LAST_INSERT_ID to return the
  // existing PK on UPDATE paths (not just on INSERT).
  await pool.query<ResultSetHeader>(
    `INSERT INTO user_data (sub, username, lastClaims, webPreferences, lastAccess, created)
     VALUES (:sub, :username, :lastClaims, '{}', NOW(), NOW())
     ON DUPLICATE KEY UPDATE
       userId     = LAST_INSERT_ID(userId),
       username   = VALUES(username),
       lastClaims = VALUES(lastClaims),
       lastAccess = NOW()`,
    {
      sub,
      username,
      lastClaims: JSON.stringify(lastClaims)
    }
  )

  const [rows] = await pool.query<RowDataPacket[]>('SELECT LAST_INSERT_ID() AS id')
  return Number((rows[0] as { id: number | string }).id)
}

/**
 * Look up a user by their OIDC subject claim.
 */
export async function getUserBySub(sub: string): Promise<UserRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT userId, sub, username, status, webPreferences, lastAccess
     FROM user_data
     WHERE sub = :sub`,
    { sub }
  )
  if (rows.length === 0) return null
  return normalise(rows[0])
}

/**
 * Look up a user by their numeric primary key.
 */
export async function getUserById(userId: number): Promise<UserRecord | null> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT userId, sub, username, status, webPreferences, lastAccess
     FROM user_data
     WHERE userId = :userId`,
    { userId }
  )
  if (rows.length === 0) return null
  return normalise(rows[0])
}

/**
 * Overwrite the webPreferences JSON column for a user.
 */
export async function updateWebPreferences(
  userId: number,
  prefs: Record<string, unknown>
): Promise<void> {
  await pool.query<ResultSetHeader>(
    'UPDATE user_data SET webPreferences = :prefs WHERE userId = :userId',
    { prefs: JSON.stringify(prefs), userId }
  )
}

// ---------------------------------------------------------------------------
// User management
// ---------------------------------------------------------------------------

/**
 * Return all user records ordered by username.
 */
export async function listUsers(): Promise<UserRecord[]> {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT userId, sub, username, status, webPreferences, lastAccess
     FROM user_data
     ORDER BY username`
  )
  return rows.map(normalise)
}

/**
 * Hard-delete a user row by primary key.
 * Returns true when the row existed and was removed.
 */
export async function deleteUser(userId: number): Promise<boolean> {
  const [result] = await pool.query<ResultSetHeader>(
    'DELETE FROM user_data WHERE userId = :userId',
    { userId }
  )
  return result.affectedRows > 0
}

/**
 * Set the status field for a user.
 * Returns true when the row was found and updated.
 */
export async function updateUserStatus(
  userId: number,
  status: 'available' | 'unavailable'
): Promise<boolean> {
  const [result] = await pool.query<ResultSetHeader>(
    'UPDATE user_data SET status = :status WHERE userId = :userId',
    { status, userId }
  )
  return result.affectedRows > 0
}

/**
 * Create a new user record with an empty sub (admin-provisioned user).
 * Returns the insertId of the new row.
 */
export async function createUser(
  username: string,
  lastClaims: Record<string, unknown>
): Promise<number> {
  const [result] = await pool.query<ResultSetHeader>(
    `INSERT INTO user_data (sub, username, lastClaims, webPreferences, created)
     VALUES ('', :username, :lastClaims, '{}', NOW())`,
    {
      username,
      lastClaims: JSON.stringify(lastClaims)
    }
  )
  return result.insertId
}

/**
 * Full replace of username and status for a user (admin PUT).
 * Returns true when the row was found and updated.
 */
export async function replaceUser(
  userId: number,
  input: { username: string; status: 'available' | 'unavailable' }
): Promise<boolean> {
  const [result] = await pool.query<ResultSetHeader>(
    'UPDATE user_data SET username = :username, status = :status WHERE userId = :userId',
    { username: input.username, status: input.status, userId }
  )
  return result.affectedRows > 0
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function normalise(row: RowDataPacket): UserRecord {
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
