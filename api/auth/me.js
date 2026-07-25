// api/auth/me.js
//
// GET /api/auth/me
// Header: Authorization: Bearer <token>
//
// Returns the current logged-in user's info if the token is valid.
// Used by the frontend to check "is this person still logged in?"
// and by us right now to test that login + token verification works.

const { query } = require('../_lib/db');
const { requireAuth } = require('../_lib/auth');
const { sendSuccess, sendError } = require('../_lib/http');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return sendSuccess(res, 200, null);
  }
  if (req.method !== 'GET') {
    return sendError(res, 405, 'Method not allowed');
  }

  const decoded = requireAuth(req);
  if (!decoded) {
    return sendError(res, 401, 'Unauthorized — invalid or missing token');
  }

  try {
    const rows = await query(
      `SELECT id, full_name, username, role, department_id, is_active
       FROM users WHERE id = ? LIMIT 1`,
      [decoded.sub]
    );

    if (rows.length === 0 || !rows[0].is_active) {
      return sendError(res, 401, 'Account no longer active');
    }

    return sendSuccess(res, 200, rows[0]);
  } catch (err) {
    console.error('GET /api/auth/me failed:', err);
    return sendError(res, 500, 'Failed to load current user');
  }
};
