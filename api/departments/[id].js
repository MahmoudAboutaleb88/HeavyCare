// api/departments/[id].js
//
// GET    /api/departments/:id  -> single department
// PUT    /api/departments/:id  -> rename a department
// DELETE /api/departments/:id  -> archive (soft delete)
//
// Departments are referenced by `equipment.department_id` (and later by
// workshop_entries, users...). We deliberately BLOCK archiving a department
// that still has active equipment pointing at it — the person doing this
// should reassign that equipment first, rather than the system silently
// leaving orphaned references or auto-reassigning them.

const { query } = require('../_lib/db');
const { requireAuth } = require('../_lib/auth');
const { sendSuccess, sendError } = require('../_lib/http');

const CAN_MANAGE_DEPARTMENTS = ['admin', 'workshop_manager'];

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
    return sendError(res, 400, 'Invalid department id');
  }

  if (req.method === 'GET') {
    return handleGet(req, res, id);
  }

  if (req.method === 'PUT') {
    if (!CAN_MANAGE_DEPARTMENTS.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to edit departments');
    }
    return handleUpdate(req, res, id);
  }

  if (req.method === 'DELETE') {
    if (!CAN_MANAGE_DEPARTMENTS.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to archive departments');
    }
    return handleArchive(req, res, id);
  }

  return sendError(res, 405, 'Method not allowed');
};

async function handleGet(req, res, id) {
  try {
    const rows = await query('SELECT id, name, is_active, created_at FROM departments WHERE id = ?', [id]);
    if (rows.length === 0) {
      return sendError(res, 404, 'Department not found');
    }
    return sendSuccess(res, 200, rows[0]);
  } catch (err) {
    console.error('GET /api/departments/[id] failed:', err);
    return sendError(res, 500, 'Failed to load department');
  }
}

async function handleUpdate(req, res, id) {
  try {
    const existing = await query('SELECT id FROM departments WHERE id = ?', [id]);
    if (existing.length === 0) {
      return sendError(res, 404, 'Department not found');
    }

    const name = (req.body && req.body.name ? String(req.body.name) : '').trim();
    if (!name) {
      return sendError(res, 400, 'Department name is required');
    }
    if (name.length > 100) {
      return sendError(res, 400, 'Department name must be 100 characters or fewer');
    }

    await query('UPDATE departments SET name = ? WHERE id = ?', [name, id]);

    const [updated] = await query('SELECT id, name, is_active, created_at FROM departments WHERE id = ?', [id]);
    return sendSuccess(res, 200, updated);
  } catch (err) {
    if (err && err.code === 'ER_DUP_ENTRY') {
      return sendError(res, 409, 'يوجد قسم آخر بنفس الاسم بالفعل');
    }
    console.error('PUT /api/departments/[id] failed:', err);
    return sendError(res, 500, 'Failed to update department');
  }
}

async function handleArchive(req, res, id) {
  try {
    const existing = await query('SELECT id FROM departments WHERE id = ?', [id]);
    if (existing.length === 0) {
      return sendError(res, 404, 'Department not found');
    }

    // Guard: refuse to archive a department that still has non-archived
    // equipment assigned to it — the person should reassign those first.
    const linkedEquipment = await query(
      'SELECT COUNT(*) AS count FROM equipment WHERE department_id = ? AND is_archived = FALSE',
      [id]
    );
    if (linkedEquipment[0].count > 0) {
      return sendError(
        res, 409,
        'لا يمكن أرشفة هذا القسم لأنه مرتبط بـ ' + linkedEquipment[0].count + ' معدة. انقل المعدات لقسم آخر أولاً.'
      );
    }

    await query('UPDATE departments SET is_active = FALSE WHERE id = ?', [id]);
    return sendSuccess(res, 200, { id, archived: true });
  } catch (err) {
    console.error('DELETE /api/departments/[id] failed:', err);
    return sendError(res, 500, 'Failed to archive department');
  }
}
