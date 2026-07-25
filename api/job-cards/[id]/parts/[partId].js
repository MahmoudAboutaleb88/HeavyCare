// api/job-cards/[id]/parts/[partId].js
//
// DELETE /api/job-cards/:id/parts/:partId -> remove a single part row.
// (Parts don't need an edit endpoint — removing and re-adding is simpler
// and there's no history requirement for individual part corrections.)

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
  if (!CAN_EDIT_JOB_CARD.includes(user.role)) {
    return sendError(res, 403, 'You do not have permission to edit this job card');
  }

  if (req.method !== 'DELETE') {
    return sendError(res, 405, 'Method not allowed');
  }

  const jobCardId = Number(req.query.id);
  const partId = Number(req.query.partId);
  if (!jobCardId || !partId) {
    return sendError(res, 400, 'Invalid ids');
  }

  try {
    const rows = await query(
      'SELECT id FROM job_card_parts WHERE id = ? AND job_card_id = ?',
      [partId, jobCardId]
    );
    if (rows.length === 0) {
      return sendError(res, 404, 'Part not found on this job card');
    }

    await query('DELETE FROM job_card_parts WHERE id = ?', [partId]);
    return sendSuccess(res, 200, { id: partId, deleted: true });
  } catch (err) {
    console.error('DELETE /api/job-cards/[id]/parts/[partId] failed:', err);
    return sendError(res, 500, 'Failed to delete part');
  }
};
