// api/workshop-entries/[id].js
//
// GET /api/workshop-entries/:id -> full details of a single workshop entry
// Used by the "close entry" page to show what's being closed.

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

  const id = Number(req.query.id);
  if (!id) {
    return sendError(res, 400, 'Invalid workshop entry id');
  }

  if (req.method !== 'GET') {
    return sendError(res, 405, 'Method not allowed');
  }

  try {
    const rows = await query(
      `SELECT
         we.*, e.code AS equipment_code, e.equipment_type,
         d.name AS department_name, jc.progress_status
       FROM workshop_entries we
       JOIN equipment e ON e.id = we.equipment_id
       JOIN departments d ON d.id = we.department_id
       LEFT JOIN job_cards jc ON jc.workshop_entry_id = we.id
       WHERE we.id = ?`,
      [id]
    );

    if (rows.length === 0) {
      return sendError(res, 404, 'Workshop entry not found');
    }

    return sendSuccess(res, 200, rows[0]);
  } catch (err) {
    console.error('GET /api/workshop-entries/[id] failed:', err);
    return sendError(res, 500, 'Failed to load workshop entry');
  }
};
