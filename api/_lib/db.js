// api/_lib/db.js
//
// Purpose: Single shared MySQL connection pool for TiDB Cloud.
// Every API endpoint imports { query } from this file to talk to the database.
// The actual host/user/password come from Environment Variables set inside
// the Vercel dashboard (Project Settings -> Environment Variables) — never
// written directly in code, and never committed to GitHub.

const mysql = require('mysql2/promise');

const requiredEnvVars = [
  'TIDB_HOST',
  'TIDB_PORT',
  'TIDB_USER',
  'TIDB_PASSWORD',
  'TIDB_DATABASE',
];

for (const key of requiredEnvVars) {
  if (!process.env[key]) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
}

// Reuse the pool across warm serverless invocations instead of creating a
// new one on every request (important for TiDB Cloud connection limits).
const pool = mysql.createPool({
  host: process.env.TIDB_HOST,
  port: Number(process.env.TIDB_PORT),
  user: process.env.TIDB_USER,
  password: process.env.TIDB_PASSWORD,
  database: process.env.TIDB_DATABASE,
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true,
  },
  waitForConnections: true,
  connectionLimit: 5,
  maxIdle: 5,
  idleTimeout: 60000,
  queueLimit: 0,
  dateStrings: true,
  decimalNumbers: true,
});

/**
 * Run a parameterized SQL query.
 * Always pass user input through `params` (the ? placeholders) —
 * never build SQL strings by concatenating user input directly.
 */
async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

/**
 * Run multiple queries as a single all-or-nothing transaction.
 * `work` receives a connection; use connection.execute(...) inside it.
 * If anything inside `work` throws, everything is rolled back.
 *
 * Example:
 *   const newId = await withTransaction(async (conn) => {
 *     const [result] = await conn.execute('INSERT INTO ... VALUES (?)', [value]);
 *     await conn.execute('UPDATE ... WHERE id = ?', [otherId]);
 *     return result.insertId;
 *   });
 */
async function withTransaction(work) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await work(conn);
    await conn.commit();
    return result;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

module.exports = { pool, query, withTransaction };
