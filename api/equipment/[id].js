// api/equipment/[id].js
//
// GET    /api/equipment/:id  -> single equipment record
// PUT    /api/equipment/:id  -> update an equipment record
// DELETE /api/equipment/:id  -> archive (soft delete) — never a hard delete,
//                               so maintenance history tied to this equipment
//                               (workshop entries, job cards...) stays intact.
//
// Same auth pattern as the rest of the project: must be logged in to view,
// must be admin/workshop_manager to change anything.

const { query } = require('../_lib/db');
const { requireAuth } = require('../_lib/auth');
const { sendSuccess, sendError } = require('../_lib/http');

const CAN_MANAGE_EQUIPMENT = ['admin', 'workshop_manager'];

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
    return sendError(res, 400, 'Invalid equipment id');
  }

  if (req.method === 'GET') {
    return handleGet(req, res, id);
  }

  if (req.method === 'PUT') {
    if (!CAN_MANAGE_EQUIPMENT.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to edit equipment');
    }
    return handleUpdate(req, res, id);
  }

  if (req.method === 'DELETE') {
    if (!CAN_MANAGE_EQUIPMENT.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to archive equipment');
    }
    return handleArchive(req, res, id);
  }

  return sendError(res, 405, 'Method not allowed');
};

async function handleGet(req, res, id) {
  try {
    const rows = await query(
      `SELECT e.*, d.name AS department_name
       FROM equipment e JOIN departments d ON d.id = e.department_id
       WHERE e.id = ?`,
      [id]
    );
    if (rows.length === 0) {
      return sendError(res, 404, 'Equipment not found');
    }
    return sendSuccess(res, 200, rows[0]);
  } catch (err) {
    console.error('GET /api/equipment/[id] failed:', err);
    return sendError(res, 500, 'Failed to load equipment');
  }
}

async function handleUpdate(req, res, id) {
  try {
    const existing = await query('SELECT id FROM equipment WHERE id = ?', [id]);
    if (existing.length === 0) {
      return sendError(res, 404, 'Equipment not found');
    }

    const body = req.body || {};
    const code = String(body.code || '').trim();
    const name = String(body.name || code).trim();
    const departmentId = Number(body.department_id);

    if (!code) return sendError(res, 400, 'Equipment code is required');
    if (!departmentId) return sendError(res, 400, 'Department is required');

    const dept = await query('SELECT id FROM departments WHERE id = ? AND is_active = TRUE', [departmentId]);
    if (dept.length === 0) {
      return sendError(res, 400, 'Selected department does not exist');
    }

    const assetNumber = optionalString(body.asset_number);
    const equipmentType = optionalString(body.equipment_type);
    const brand = optionalString(body.brand);
    const model = optionalString(body.model);
    const manufacturingYear = body.manufacturing_year ? Number(body.manufacturing_year) : null;
    const purchaseDate = optionalString(body.purchase_date);
    const warrantyExpiry = optionalString(body.warranty_expiry);
    const hourMeter = body.hour_meter !== undefined && body.hour_meter !== '' ? Number(body.hour_meter) : 0;

    await query(
      `UPDATE equipment SET
         code = ?, name = ?, department_id = ?, equipment_type = ?,
         brand = ?, model = ?, asset_number = ?, manufacturing_year = ?,
         purchase_date = ?, warranty_expiry = ?, hour_meter = ?
       WHERE id = ?`,
      [
        code, name, departmentId, equipmentType,
        brand, model, assetNumber, manufacturingYear,
        purchaseDate, warrantyExpiry, hourMeter,
        id,
      ]
    );

    const [updated] = await query(
      `SELECT e.*, d.name AS department_name
       FROM equipment e JOIN departments d ON d.id = e.department_id
       WHERE e.id = ?`,
      [id]
    );

    return sendSuccess(res, 200, updated);
  } catch (err) {
    if (err && err.code === 'ER_DUP_ENTRY') {
      const message = String(err.sqlMessage || err.message || '');
      if (message.includes('uq_equipment_asset_number')) {
        return sendError(res, 409, 'رقم الأصل ده مستخدم لمعدة تانية بالفعل');
      }
      if (message.includes('uq_equipment_code')) {
        return sendError(res, 409, 'كود المعدة ده مستخدم بالفعل');
      }
      return sendError(res, 409, 'هذه القيمة مكررة ومسجلة من قبل');
    }
    console.error('PUT /api/equipment/[id] failed:', err);
    return sendError(res, 500, 'Failed to update equipment');
  }
}

async function handleArchive(req, res, id) {
  try {
    const existing = await query('SELECT id, is_archived FROM equipment WHERE id = ?', [id]);
    if (existing.length === 0) {
      return sendError(res, 404, 'Equipment not found');
    }

    await query(
      `UPDATE equipment SET is_archived = TRUE, current_status = 'archived' WHERE id = ?`,
      [id]
    );

    return sendSuccess(res, 200, { id, archived: true });
  } catch (err) {
    console.error('DELETE /api/equipment/[id] failed:', err);
    return sendError(res, 500, 'Failed to archive equipment');
  }
}

function optionalString(value) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed === '' ? null : trimmed;
}
