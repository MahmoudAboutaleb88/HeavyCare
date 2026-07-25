// api/departments/index.js
//
// GET  /api/departments  -> list all active departments
// POST /api/departments  -> create a new department { name: string }
//
// This is the first real endpoint in the project. It's intentionally simple
// (the `departments` table has no foreign keys pointing INTO it from user
// input yet) so we can verify the whole chain works end to end:
//   browser -> Vercel serverless function -> TiDB Cloud -> back to browser

const { query } = require('../_lib/db');
const { requireAuth } = require('../_lib/auth');
const { sendSuccess, sendError } = require('../_lib/http');

// Roles allowed to create/edit departments. Everyone who is logged in
// (any role) can still VIEW the list — this list only restricts writes.
const CAN_MANAGE_DEPARTMENTS = ['admin', 'workshop_manager'];

module.exports = async function handler(req, res) {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return sendSuccess(res, 200, null);
  }

  // Every request to this endpoint must be from a logged-in user —
  // no anonymous access, whether viewing or writing.
  const user = requireAuth(req);
  if (!user) {
    return sendError(res, 401, 'Unauthorized — please log in');
  }

  if (req.method === 'GET') {
    return handleList(req, res);
  }

  if (req.method === 'POST') {
    if (!CAN_MANAGE_DEPARTMENTS.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to create departments');
    }
    return handleCreate(req, res);
  }

  return sendError(res, 405, 'Method not allowed');
};

async function handleList(req, res) {
  try {
    const rows = await query(
      `SELECT id, name, is_active, created_at
       FROM departments
       WHERE is_active = TRUE
       ORDER BY name ASC`
    );
    return sendSuccess(res, 200, rows);
  } catch (err) {
    console.error('GET /api/departments failed:', err);
    return sendError(res, 500, 'Failed to load departments');
  }
}

async function handleCreate(req, res) {
  try {
    const name = (req.body && req.body.name ? String(req.body.name) : '').trim();

    if (!name) {
      return sendError(res, 400, 'Department name is required');
    }
    if (name.length > 100) {
      return sendError(res, 400, 'Department name must be 100 characters or fewer');
    }

    const result = await query(
      `INSERT INTO departments (name) VALUES (?)`,
      [name]
    );

    const [created] = await query(
      `SELECT id, name, is_active, created_at FROM departments WHERE id = ?`,
      [result.insertId]
    );

    return sendSuccess(res, 201, created);
  } catch (err) {
    // MySQL/TiDB duplicate key error code
    if (err && err.code === 'ER_DUP_ENTRY') {
      return sendError(res, 409, 'A department with this name already exists');
    }
    console.error('POST /api/departments failed:', err);
    return sendError(res, 500, 'Failed to create department');
  }
}
