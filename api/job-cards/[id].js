// api/job-cards/[id].js
//
// GET /api/job-cards/:id -> full job card details (with entry/equipment
//                           context, assigned technician name, parts list)
// PUT /api/job-cards/:id -> update diagnosis/cost/status/etc.
//
// Whenever progress_status changes, we log it into job_card_status_history
// — this is what lets future reports calculate "average time in each
// stage" without guessing from updated_at timestamps.

const { query, withTransaction } = require('../_lib/db');
const { requireAuth } = require('../_lib/auth');
const { sendSuccess, sendError } = require('../_lib/http');

const VALID_STATUSES = [
  'waiting', 'inspection', 'repairing', 'waiting_spare_parts',
  'testing', 'completed', 'delivered', 'cancelled',
];

// Day-to-day work on a job card (diagnosis, status updates) is done by
// technicians too, not just managers.
const CAN_EDIT_JOB_CARD = ['admin', 'workshop_manager', 'supervisor', 'technician'];

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
    return sendError(res, 400, 'Invalid job card id');
  }

  if (req.method === 'GET') {
    return handleGet(req, res, id);
  }

  if (req.method === 'PUT') {
    if (!CAN_EDIT_JOB_CARD.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to edit this job card');
    }
    return handleUpdate(req, res, id, user);
  }

  return sendError(res, 405, 'Method not allowed');
};

async function handleGet(req, res, id) {
  try {
    const rows = await query(
      `SELECT
         jc.*,
         we.entry_number, we.maintenance_type, we.reported_problem, we.status AS entry_status,
         e.code AS equipment_code, e.equipment_type,
         u.full_name AS technician_name
       FROM job_cards jc
       JOIN workshop_entries we ON we.id = jc.workshop_entry_id
       JOIN equipment e ON e.id = we.equipment_id
       LEFT JOIN users u ON u.id = jc.assigned_technician_id
       WHERE jc.id = ?`,
      [id]
    );

    if (rows.length === 0) {
      return sendError(res, 404, 'Job card not found');
    }

    const parts = await query(
      `SELECT id, part_name, quantity, unit_cost, total_cost, created_at
       FROM job_card_parts WHERE job_card_id = ? ORDER BY created_at ASC`,
      [id]
    );

    const jobCard = rows[0];
    jobCard.parts = parts;
    jobCard.parts_total_cost = parts.reduce((sum, p) => sum + Number(p.total_cost), 0);

    return sendSuccess(res, 200, jobCard);
  } catch (err) {
    console.error('GET /api/job-cards/[id] failed:', err);
    return sendError(res, 500, 'Failed to load job card');
  }
}

async function handleUpdate(req, res, id, user) {
  try {
    const existing = await query('SELECT * FROM job_cards WHERE id = ?', [id]);
    if (existing.length === 0) {
      return sendError(res, 404, 'Job card not found');
    }
    const current = existing[0];

    const body = req.body || {};
    const diagnosis = optionalString(body.diagnosis);
    const rootCause = optionalString(body.root_cause);
    const inspectionResults = optionalString(body.inspection_results);
    const laborCost = body.labor_cost !== undefined && body.labor_cost !== '' ? Number(body.labor_cost) : 0;
    const assignedTechnicianId = body.assigned_technician_id ? Number(body.assigned_technician_id) : null;
    const technicianNotes = optionalString(body.technician_notes);
    const progressStatus = body.progress_status;

    if (!VALID_STATUSES.includes(progressStatus)) {
      return sendError(res, 400, 'Invalid progress status');
    }

    if (assignedTechnicianId) {
      const techRows = await query('SELECT id FROM users WHERE id = ? AND is_active = TRUE', [assignedTechnicianId]);
      if (techRows.length === 0) {
        return sendError(res, 400, 'Selected technician does not exist');
      }
    }

    const statusChanged = progressStatus !== current.progress_status;

    await withTransaction(async (conn) => {
      await conn.execute(
        `UPDATE job_cards SET
           diagnosis = ?, root_cause = ?, inspection_results = ?,
           labor_cost = ?, assigned_technician_id = ?, technician_notes = ?,
           progress_status = ?
         WHERE id = ?`,
        [
          diagnosis, rootCause, inspectionResults,
          laborCost, assignedTechnicianId, technicianNotes,
          progressStatus, id,
        ]
      );

      if (statusChanged) {
        await conn.execute(
          `INSERT INTO job_card_status_history (job_card_id, status, changed_by) VALUES (?, ?, ?)`,
          [id, progressStatus, user.sub]
        );
      }
    });

    const updatedRows = await query(
      `SELECT jc.*, u.full_name AS technician_name
       FROM job_cards jc LEFT JOIN users u ON u.id = jc.assigned_technician_id
       WHERE jc.id = ?`,
      [id]
    );

    return sendSuccess(res, 200, updatedRows[0]);
  } catch (err) {
    console.error('PUT /api/job-cards/[id] failed:', err);
    return sendError(res, 500, 'Failed to update job card');
  }
}

function optionalString(value) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed === '' ? null : trimmed;
}
