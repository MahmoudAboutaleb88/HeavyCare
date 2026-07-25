// api/job-cards/[id]/parts/index.js
//
// GET  /api/job-cards/:id/parts -> list parts used on this job card
// POST /api/job-cards/:id/parts -> add a part { part_name, quantity, unit_cost }

const { query } = require('../../../_lib/db');
const { requireAuth } = require('../../../_lib/auth');
const { sendSuccess, sendError } = require('../../../_lib/http');

const CAN_EDIT_JOB_CARD = ['admin', 'workshop_manager', 'supervisor', 'technician'];

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return sendSuccess(res, 200, null);
  }

  const user = requireAuth(req);
  if (!user) {
    return sendError(res, 401, 'Unauthorized — please log in');
  }

  const jobCardId = Number(req.query.id);
  if (!jobCardId) {
    return sendError(res, 400, 'Invalid job card id');
  }

  if (req.method === 'GET') {
    return handleList(req, res, jobCardId);
  }

  if (req.method === 'POST') {
    if (!CAN_EDIT_JOB_CARD.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to edit this job card');
    }
    return handleCreate(req, res, jobCardId);
  }

  return sendError(res, 405, 'Method not allowed');
};

async function handleList(req, res, jobCardId) {
  try {
    const rows = await query(
      `SELECT id, part_name, quantity, unit_cost, total_cost, created_at
       FROM job_card_parts WHERE job_card_id = ? ORDER BY created_at ASC`,
      [jobCardId]
    );
    return sendSuccess(res, 200, rows);
  } catch (err) {
    console.error('GET /api/job-cards/[id]/parts failed:', err);
    return sendError(res, 500, 'Failed to load parts');
  }
}

async function handleCreate(req, res, jobCardId) {
  try {
    const jobCardRows = await query('SELECT id FROM job_cards WHERE id = ?', [jobCardId]);
    if (jobCardRows.length === 0) {
      return sendError(res, 404, 'Job card not found');
    }

    const body = req.body || {};
    const partName = String(body.part_name || '').trim();
    const quantity = body.quantity ? Number(body.quantity) : 1;
    const unitCost = body.unit_cost ? Number(body.unit_cost) : 0;

    if (!partName) return sendError(res, 400, 'Part name is required');
    if (quantity <= 0) return sendError(res, 400, 'Quantity must be greater than zero');
    if (unitCost < 0) return sendError(res, 400, 'Unit cost cannot be negative');

    const result = await query(
      `INSERT INTO job_card_parts (job_card_id, part_name, quantity, unit_cost) VALUES (?, ?, ?, ?)`,
      [jobCardId, partName, quantity, unitCost]
    );

    const [created] = await query(
      `SELECT id, part_name, quantity, unit_cost, total_cost, created_at FROM job_card_parts WHERE id = ?`,
      [result.insertId]
    );

    return sendSuccess(res, 201, created);
  } catch (err) {
    console.error('POST /api/job-cards/[id]/parts failed:', err);
    return sendError(res, 500, 'Failed to add part');
  }
}
