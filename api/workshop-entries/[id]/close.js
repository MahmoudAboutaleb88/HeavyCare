// api/workshop-entries/[id]/close.js
//
// POST /api/workshop-entries/:id/close
// Body: {
//   exit_date, exit_time, final_technician_notes, maintenance_result,
//   equipment_condition, final_equipment_status ('available' | 'breakdown')
// }
//
// What happens here:
//   1. duration_hours (if PM) or duration_days (if BD) is calculated from
//      entry datetime -> exit datetime, and stored permanently — it's never
//      recalculated later even if business rules change.
//   2. workshop_entries.status becomes 'closed'.
//   3. equipment.current_status goes back to 'available' or 'breakdown',
//      based on what the closer says about the equipment's real condition.

const { query, withTransaction } = require('../../_lib/db');
const { requireAuth } = require('../../_lib/auth');
const { sendSuccess, sendError } = require('../../_lib/http');

// Closing implies approving the work is done — technicians can work on
// entries, but closing (like creating departments/equipment) needs a
// supervisor-level role.
const CAN_CLOSE_ENTRY = ['admin', 'workshop_manager', 'supervisor'];

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return sendSuccess(res, 200, null);
  }
  if (req.method !== 'POST') {
    return sendError(res, 405, 'Method not allowed');
  }

  const user = requireAuth(req);
  if (!user) {
    return sendError(res, 401, 'Unauthorized — please log in');
  }
  if (!CAN_CLOSE_ENTRY.includes(user.role)) {
    return sendError(res, 403, 'You do not have permission to close a workshop entry');
  }

  const id = Number(req.query.id);
  if (!id) {
    return sendError(res, 400, 'Invalid workshop entry id');
  }

  try {
    const entries = await query('SELECT * FROM workshop_entries WHERE id = ?', [id]);
    if (entries.length === 0) {
      return sendError(res, 404, 'Workshop entry not found');
    }
    const entry = entries[0];

    if (entry.status === 'closed') {
      return sendError(res, 409, 'هذه الزيارة مقفولة بالفعل');
    }

    const body = req.body || {};
    const exitDate = String(body.exit_date || '').trim();
    const exitTime = String(body.exit_time || '').trim();
    const finalNotes = optionalString(body.final_technician_notes);
    const maintenanceResult = optionalString(body.maintenance_result);
    const equipmentCondition = optionalString(body.equipment_condition);
    const finalEquipmentStatus = body.final_equipment_status;

    if (!exitDate || !exitTime) {
      return sendError(res, 400, 'Exit date and time are required');
    }
    if (!['available', 'breakdown'].includes(finalEquipmentStatus)) {
      return sendError(res, 400, 'final_equipment_status must be "available" or "breakdown"');
    }

    const entryDateTime = new Date(entry.entry_date + 'T' + entry.entry_time);
    const exitDateTime = new Date(exitDate + 'T' + exitTime);

    if (isNaN(exitDateTime.getTime())) {
      return sendError(res, 400, 'Invalid exit date/time');
    }
    if (exitDateTime < entryDateTime) {
      return sendError(res, 400, 'وقت الخروج لازم يكون بعد وقت الدخول');
    }

    const diffMs = exitDateTime.getTime() - entryDateTime.getTime();
    let durationHours = null;
    let durationDays = null;

    if (entry.maintenance_type === 'PM') {
      durationHours = Math.round((diffMs / (1000 * 60 * 60)) * 100) / 100;
    } else {
      durationDays = Math.round((diffMs / (1000 * 60 * 60 * 24)) * 100) / 100;
    }

    await withTransaction(async (conn) => {
      await conn.execute(
        `UPDATE workshop_entries SET
           exit_date = ?, exit_time = ?, final_technician_notes = ?,
           maintenance_result = ?, equipment_condition = ?,
           closed_by = ?, duration_hours = ?, duration_days = ?,
           status = 'closed'
         WHERE id = ?`,
        [
          exitDate, exitTime, finalNotes,
          maintenanceResult, equipmentCondition,
          user.sub, durationHours, durationDays,
          id,
        ]
      );

      await conn.execute(
        `UPDATE equipment SET current_status = ? WHERE id = ?`,
        [finalEquipmentStatus, entry.equipment_id]
      );
    });

    const [updated] = await query(
      `SELECT we.*, e.code AS equipment_code
       FROM workshop_entries we JOIN equipment e ON e.id = we.equipment_id
       WHERE we.id = ?`,
      [id]
    );

    return sendSuccess(res, 200, updated);
  } catch (err) {
    console.error('POST /api/workshop-entries/[id]/close failed:', err);
    return sendError(res, 500, 'Failed to close workshop entry');
  }
};

function optionalString(value) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed === '' ? null : trimmed;
}
