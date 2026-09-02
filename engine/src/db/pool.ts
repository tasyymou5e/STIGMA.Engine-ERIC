import mysql from 'mysql2/promise'
import { config } from '../config.js'

// Shared connection pool. multipleStatements is intentionally disabled to prevent
// stacked-statement SQL injection. Migration uses its own dedicated connection.
export const pool = mysql.createPool({
  host: config.DB_HOST,
  port: config.DB_PORT,
  user: config.DB_USER,
  password: config.DB_PASSWORD,
  database: config.DB_NAME,
  connectionLimit: config.DB_POOL_SIZE,
  namedPlaceholders: true
})

export type Row = mysql.RowDataPacket
