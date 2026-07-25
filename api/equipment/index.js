// api/equipment/index.js
//
// GET  /api/equipment  -> list all non-archived equipment (with department name)
// POST /api/equipment  -> register a new piece of equipment
//
// Same protection pattern as /api/departments:
//   - must be logged in to view or create
//   - only admin / workshop_manager can create

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

  if (req.method === 'GET') {
    return handleList(req, res);
  }

  if (req.method === 'POST') {
    if (!CAN_MANAGE_EQUIPMENT.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to register equipment');
    }
    return handleCreate(req, res);
  }

  return sendError(res, 405, 'Method not allowed');
};

async function handleList(req, res) {
  try {
    const rows = await query(
      `SELECT
         e.id, e.name, e.code, e.asset_number, e.serial_number,
         e.brand, e.model, e.manufacturing_year,
         e.department_id, d.name AS department_name,
         e.equipment_type, e.plate_number, e.engine_number, e.chassis_number,
         e.purchase_date, e.supplier, e.warranty_expiry,
         e.hour_meter, e.current_status, e.notes, e.image_url,
         e.created_at
       FROM equipment e
       JOIN departments d ON d.id = e.department_id
       WHERE e.is_archived = FALSE
       ORDER BY e.created_at DESC`
    );
    return sendSuccess(res, 200, rows);
  } catch (err) {
    console.error('GET /api/equipment failed:', err);
    return sendError(res, 500, 'Failed to load equipment');
  }
}

async function handleCreate(req, res) {
  try {
    const body = req.body || {};

    const code = String(body.code || '').trim();
    // "name" is no longer collected from the form — the code is the
    // real identifier. We still fill the database column (it's NOT NULL)
    // with the code itself so nothing breaks if a name is added later.
    const name = String(body.name || code).trim();
    const departmentId = Number(body.department_id);

    // --- Required fields ---
    if (!code) return sendError(res, 400, 'Equipment code is required');
    if (!name) return sendError(res, 400, 'Equipment name is required');
    if (!departmentId) return sendError(res, 400, 'Department is required');

    // Confirm the department actually exists (avoids a confusing FK error
    // and gives a clear message instead).
    const dept = await query('SELECT id FROM departments WHERE id = ? AND is_active = TRUE', [departmentId]);
    if (dept.length === 0) {
      return sendError(res, 400, 'Selected department does not exist');
    }

    // --- Optional fields (all nullable in the schema) ---
    const assetNumber = optionalString(body.asset_number);
    const serialNumber = optionalString(body.serial_number);
    const brand = optionalString(body.brand);
    const model = optionalString(body.model);
    const manufacturingYear = body.manufacturing_year ? Number(body.manufacturing_year) : null;
    const equipmentType = optionalString(body.equipment_type);
    const plateNumber = optionalString(body.plate_number);
    const engineNumber = optionalString(body.engine_number);
    const chassisNumber = optionalString(body.chassis_number);
    const purchaseDate = optionalString(body.purchase_date); // 'YYYY-MM-DD' or null
    const supplier = optionalString(body.supplier);
    const warrantyExpiry = optionalString(body.warranty_expiry);
    const hourMeter = body.hour_meter ? Number(body.hour_meter) : 0;
    const notes = optionalString(body.notes);
    const imageUrl = optionalString(body.image_url);

    const result = await query(
      `INSERT INTO equipment (
         image_url, name, code, asset_number, serial_number, brand, model,
         manufacturing_year, department_id, equipment_type, plate_number,
         engine_number, chassis_number, purchase_date, supplier,
         warranty_expiry, hour_meter, notes
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        imageUrl, name, code, assetNumber, serialNumber, brand, model,
        manufacturingYear, departmentId, equipmentType, plateNumber,
        engineNumber, chassisNumber, purchaseDate, supplier,
        warrantyExpiry, hourMeter, notes,
      ]
    );

    const [created] = await query(
      `SELECT e.*, d.name AS department_name
       FROM equipment e JOIN departments d ON d.id = e.department_id
       WHERE e.id = ?`,
      [result.insertId]
    );

    return sendSuccess(res, 201, created);
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
    console.error('POST /api/equipment failed:', err);
    return sendError(res, 500, 'Failed to register equipment');
  }
}

function optionalString(value) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed === '' ? null : trimmed;
}
