// api/users/index.js
//
// GET /api/users -> list active users (id, full_name, role)
//
// This is a read-only endpoint for now — just enough to populate
// "assign technician" dropdowns. Full user management (create/edit/
// deactivate accounts) is a separate module we'll build later.

const { query } = require('../_lib/db');
const { requireAuth } = require('../_lib/auth');
const { sendSuccess, sendError } = require('../_lib/http');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return sendSuccess(res, 200, null);
  }

  const user = requireAuth(req);
  if (!user) {
    return sendError(res, 401, 'Unauthorized — please log in');
  }

  if (req.method !== 'GET') {
    return sendError(res, 405, 'Method not allowed');
  }

  try {
    const rows = await query(
      `SELECT id, full_name, username, role
       FROM users
       WHERE is_active = TRUE
       ORDER BY full_name ASC`
    );
    return sendSuccess(res, 200, rows);
  } catch (err) {
    console.error('GET /api/users failed:', err);
    return sendError(res, 500, 'Failed to load users');
  }
};
