// api/auth/setup-admin.js
//
// POST /api/auth/setup-admin
// Body: { setup_key, full_name, username, password }
//
// One-time endpoint to create the very first administrator account.
// Protected by SETUP_KEY (an environment variable only you know), and it
// refuses to run again once ANY user already exists in the database —
// so even if someone found this URL, they couldn't use it after your
// first admin is created.
//
// After you've created your admin account, you can optionally remove this
// file (or just leave it — it's harmless once the users table is non-empty).

const { query } = require('../_lib/db');
const { hashPassword } = require('../_lib/auth');
const { sendSuccess, sendError } = require('../_lib/http');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return sendSuccess(res, 200, null);
  }
  if (req.method !== 'POST') {
    return sendError(res, 405, 'Method not allowed');
  }

  try {
    const { setup_key, full_name, username, password } = req.body || {};

    if (!process.env.SETUP_KEY) {
      return sendError(res, 500, 'SETUP_KEY is not configured on the server');
    }
    if (!setup_key || setup_key !== process.env.SETUP_KEY) {
      return sendError(res, 403, 'Invalid setup key');
    }

    const existing = await query('SELECT id FROM users LIMIT 1');
    if (existing.length > 0) {
      return sendError(res, 409, 'Setup already completed — a user already exists. This endpoint is now locked.');
    }

    const cleanFullName = (full_name || '').trim();
    const cleanUsername = (username || '').trim().toLowerCase();

    if (!cleanFullName || !cleanUsername || !password) {
      return sendError(res, 400, 'full_name, username and password are all required');
    }
    if (password.length < 8) {
      return sendError(res, 400, 'Password must be at least 8 characters');
    }

    const passwordHash = await hashPassword(password);

    const result = await query(
      `INSERT INTO users (full_name, username, password_hash, role, is_active)
       VALUES (?, ?, ?, 'admin', TRUE)`,
      [cleanFullName, cleanUsername, passwordHash]
    );

    return sendSuccess(res, 201, {
      id: result.insertId,
      username: cleanUsername,
      role: 'admin',
      message: 'Admin account created. You can now log in.',
    });
  } catch (err) {
    if (err && err.code === 'ER_DUP_ENTRY') {
      return sendError(res, 409, 'This username is already taken');
    }
    console.error('POST /api/auth/setup-admin failed:', err);
    return sendError(res, 500, 'Failed to create admin account');
  }
};
