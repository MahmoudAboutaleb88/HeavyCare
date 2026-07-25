// api/[...path].js
//
// ============================================================================
// SINGLE ENTRY POINT FOR THE ENTIRE API
// ============================================================================
// Why this file exists:
//   Vercel's Hobby (free) plan caps a deployment at 12 Serverless Functions.
//   Every separate file under /api used to count as one function — we had
//   14 and hit the wall. Vercel's catch-all dynamic route ([...path].js)
//   means EVERY request under /api/* is handled by this ONE file, so the
//   whole backend now counts as a single function, with no practical limit
//   on how many endpoints we add inside it.
//
//   Nothing changes from the frontend's point of view: a request to
//   /api/equipment/5 still arrives here, just internally routed based on
//   the URL path instead of the filesystem.
//
// How routing works:
//   Each entry in `routes` below has a `pattern` (URL segments, where a
//   segment starting with ':' is a captured parameter) and a `methods`
//   map from HTTP method -> handler function. Handlers get
//   (req, res, params) where `params` holds any captured segments
//   (e.g. { id: '5' }).
// ============================================================================

const { query, withTransaction } = require('./_lib/db');
const { hashPassword, verifyPassword, signToken, requireAuth } = require('./_lib/auth');
const { sendSuccess, sendError } = require('./_lib/http');

function optionalString(value) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed === '' ? null : trimmed;
}

// ============================================================================
// AUTH handlers
// ============================================================================

async function authLogin(req, res) {
  if (req.method !== 'POST') return sendError(res, 405, 'Method not allowed');
  try {
    const { username, password } = req.body || {};
    const cleanUsername = (username || '').trim().toLowerCase();

    if (!cleanUsername || !password) {
      return sendError(res, 400, 'Username and password are required');
    }

    const rows = await query(
      `SELECT id, full_name, username, password_hash, role, is_active
       FROM users WHERE username = ? LIMIT 1`,
      [cleanUsername]
    );

    const genericError = () => sendError(res, 401, 'Invalid username or password');
    if (rows.length === 0) return genericError();

    const user = rows[0];
    if (!user.is_active) return sendError(res, 403, 'This account has been deactivated');

    const passwordMatches = await verifyPassword(password, user.password_hash);
    if (!passwordMatches) return genericError();

    const token = signToken(user);

    return sendSuccess(res, 200, {
      token,
      user: { id: user.id, full_name: user.full_name, username: user.username, role: user.role },
    });
  } catch (err) {
    console.error('POST /api/auth/login failed:', err);
    return sendError(res, 500, 'Login failed');
  }
}

async function authMe(req, res) {
  if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');
  const decoded = requireAuth(req);
  if (!decoded) return sendError(res, 401, 'Unauthorized — invalid or missing token');

  try {
    const rows = await query(
      `SELECT id, full_name, username, role, department_id, is_active
       FROM users WHERE id = ? LIMIT 1`,
      [decoded.sub]
    );
    if (rows.length === 0 || !rows[0].is_active) {
      return sendError(res, 401, 'Account no longer active');
    }
    return sendSuccess(res, 200, rows[0]);
  } catch (err) {
    console.error('GET /api/auth/me failed:', err);
    return sendError(res, 500, 'Failed to load current user');
  }
}

async function authSetupAdmin(req, res) {
  if (req.method !== 'POST') return sendError(res, 405, 'Method not allowed');
  try {
    const { setup_key, full_name, username, password } = req.body || {};

    if (!process.env.SETUP_KEY) {
      return sendError(res, 500, 'SETUP_KEY is not configured on the server');
    }
    if (!setup_key || setup_key !== process.env.SETUP_KEY) {
      return sendError(res, 403, 'Invalid setup key');
    }

    const existing = await query('SELECT id FROM users LIMIT 1');
    if (existing.length > 0) {
      return sendError(res, 409, 'Setup already completed — a user already exists. This endpoint is now locked.');
    }

    const cleanFullName = (full_name || '').trim();
    const cleanUsername = (username || '').trim().toLowerCase();

    if (!cleanFullName || !cleanUsername || !password) {
      return sendError(res, 400, 'full_name, username and password are all required');
    }
    if (password.length < 8) {
      return sendError(res, 400, 'Password must be at least 8 characters');
    }

    const passwordHash = await hashPassword(password);
    const result = await query(
      `INSERT INTO users (full_name, username, password_hash, role, is_active)
       VALUES (?, ?, ?, 'admin', TRUE)`,
      [cleanFullName, cleanUsername, passwordHash]
    );

    return sendSuccess(res, 201, {
      id: result.insertId, username: cleanUsername, role: 'admin',
      message: 'Admin account created. You can now log in.',
    });
  } catch (err) {
    if (err && err.code === 'ER_DUP_ENTRY') {
      return sendError(res, 409, 'This username is already taken');
    }
    console.error('POST /api/auth/setup-admin failed:', err);
    return sendError(res, 500, 'Failed to create admin account');
  }
}

// ============================================================================
// DEPARTMENTS handlers
// ============================================================================

const CAN_MANAGE_DEPARTMENTS = ['admin', 'workshop_manager'];

async function departmentsCollection(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');

  if (req.method === 'GET') {
    try {
      const rows = await query(
        `SELECT id, name, is_active, created_at FROM departments WHERE is_active = TRUE ORDER BY name ASC`
      );
      return sendSuccess(res, 200, rows);
    } catch (err) {
      console.error('GET /api/departments failed:', err);
      return sendError(res, 500, 'Failed to load departments');
    }
  }

  if (req.method === 'POST') {
    if (!CAN_MANAGE_DEPARTMENTS.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to create departments');
    }
    try {
      const name = (req.body && req.body.name ? String(req.body.name) : '').trim();
      if (!name) return sendError(res, 400, 'Department name is required');
      if (name.length > 100) return sendError(res, 400, 'Department name must be 100 characters or fewer');

      const result = await query(`INSERT INTO departments (name) VALUES (?)`, [name]);
      const [created] = await query(
        `SELECT id, name, is_active, created_at FROM departments WHERE id = ?`,
        [result.insertId]
      );
      return sendSuccess(res, 201, created);
    } catch (err) {
      if (err && err.code === 'ER_DUP_ENTRY') {
        return sendError(res, 409, 'A department with this name already exists');
      }
      console.error('POST /api/departments failed:', err);
      return sendError(res, 500, 'Failed to create department');
    }
  }

  return sendError(res, 405, 'Method not allowed');
}

async function departmentItem(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');

  const id = Number(params.id);
  if (!id) return sendError(res, 400, 'Invalid department id');

  if (req.method === 'GET') {
    try {
      const rows = await query('SELECT id, name, is_active, created_at FROM departments WHERE id = ?', [id]);
      if (rows.length === 0) return sendError(res, 404, 'Department not found');
      return sendSuccess(res, 200, rows[0]);
    } catch (err) {
      console.error('GET /api/departments/[id] failed:', err);
      return sendError(res, 500, 'Failed to load department');
    }
  }

  if (req.method === 'PUT') {
    if (!CAN_MANAGE_DEPARTMENTS.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to edit departments');
    }
    try {
      const existing = await query('SELECT id FROM departments WHERE id = ?', [id]);
      if (existing.length === 0) return sendError(res, 404, 'Department not found');

      const name = (req.body && req.body.name ? String(req.body.name) : '').trim();
      if (!name) return sendError(res, 400, 'Department name is required');
      if (name.length > 100) return sendError(res, 400, 'Department name must be 100 characters or fewer');

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

  if (req.method === 'DELETE') {
    if (!CAN_MANAGE_DEPARTMENTS.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to archive departments');
    }
    try {
      const existing = await query('SELECT id FROM departments WHERE id = ?', [id]);
      if (existing.length === 0) return sendError(res, 404, 'Department not found');

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

  return sendError(res, 405, 'Method not allowed');
}

// ============================================================================
// EQUIPMENT handlers
// ============================================================================

const CAN_MANAGE_EQUIPMENT = ['admin', 'workshop_manager'];

async function equipmentCollection(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');

  if (req.method === 'GET') {
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

  if (req.method === 'POST') {
    if (!CAN_MANAGE_EQUIPMENT.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to register equipment');
    }
    try {
      const body = req.body || {};
      const code = String(body.code || '').trim();
      const name = String(body.name || code).trim();
      const departmentId = Number(body.department_id);

      if (!code) return sendError(res, 400, 'Equipment code is required');
      if (!name) return sendError(res, 400, 'Equipment name is required');
      if (!departmentId) return sendError(res, 400, 'Department is required');

      const dept = await query('SELECT id FROM departments WHERE id = ? AND is_active = TRUE', [departmentId]);
      if (dept.length === 0) return sendError(res, 400, 'Selected department does not exist');

      const assetNumber = optionalString(body.asset_number);
      const equipmentType = optionalString(body.equipment_type);
      const brand = optionalString(body.brand);
      const model = optionalString(body.model);
      const manufacturingYear = body.manufacturing_year ? Number(body.manufacturing_year) : null;
      const purchaseDate = optionalString(body.purchase_date);
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
          imageUrl, name, code, assetNumber, optionalString(body.serial_number), brand, model,
          manufacturingYear, departmentId, equipmentType, optionalString(body.plate_number),
          optionalString(body.engine_number), optionalString(body.chassis_number), purchaseDate,
          optionalString(body.supplier), warrantyExpiry, hourMeter, notes,
        ]
      );

      const [created] = await query(
        `SELECT e.*, d.name AS department_name
         FROM equipment e JOIN departments d ON d.id = e.department_id WHERE e.id = ?`,
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

  return sendError(res, 405, 'Method not allowed');
}

async function equipmentItem(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');

  const id = Number(params.id);
  if (!id) return sendError(res, 400, 'Invalid equipment id');

  if (req.method === 'GET') {
    try {
      const rows = await query(
        `SELECT e.*, d.name AS department_name
         FROM equipment e JOIN departments d ON d.id = e.department_id WHERE e.id = ?`,
        [id]
      );
      if (rows.length === 0) return sendError(res, 404, 'Equipment not found');
      return sendSuccess(res, 200, rows[0]);
    } catch (err) {
      console.error('GET /api/equipment/[id] failed:', err);
      return sendError(res, 500, 'Failed to load equipment');
    }
  }

  if (req.method === 'PUT') {
    if (!CAN_MANAGE_EQUIPMENT.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to edit equipment');
    }
    try {
      const existing = await query('SELECT id FROM equipment WHERE id = ?', [id]);
      if (existing.length === 0) return sendError(res, 404, 'Equipment not found');

      const body = req.body || {};
      const code = String(body.code || '').trim();
      const name = String(body.name || code).trim();
      const departmentId = Number(body.department_id);

      if (!code) return sendError(res, 400, 'Equipment code is required');
      if (!departmentId) return sendError(res, 400, 'Department is required');

      const dept = await query('SELECT id FROM departments WHERE id = ? AND is_active = TRUE', [departmentId]);
      if (dept.length === 0) return sendError(res, 400, 'Selected department does not exist');

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
        [code, name, departmentId, equipmentType, brand, model, assetNumber,
         manufacturingYear, purchaseDate, warrantyExpiry, hourMeter, id]
      );

      const [updated] = await query(
        `SELECT e.*, d.name AS department_name
         FROM equipment e JOIN departments d ON d.id = e.department_id WHERE e.id = ?`,
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

  if (req.method === 'DELETE') {
    if (!CAN_MANAGE_EQUIPMENT.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to archive equipment');
    }
    try {
      const existing = await query('SELECT id FROM equipment WHERE id = ?', [id]);
      if (existing.length === 0) return sendError(res, 404, 'Equipment not found');

      await query(`UPDATE equipment SET is_archived = TRUE, current_status = 'archived' WHERE id = ?`, [id]);
      return sendSuccess(res, 200, { id, archived: true });
    } catch (err) {
      console.error('DELETE /api/equipment/[id] failed:', err);
      return sendError(res, 500, 'Failed to archive equipment');
    }
  }

  return sendError(res, 405, 'Method not allowed');
}

// ============================================================================
// USERS handlers (read-only for now)
// ============================================================================

async function usersCollection(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');

  try {
    const rows = await query(
      `SELECT id, full_name, username, role FROM users WHERE is_active = TRUE ORDER BY full_name ASC`
    );
    return sendSuccess(res, 200, rows);
  } catch (err) {
    console.error('GET /api/users failed:', err);
    return sendError(res, 500, 'Failed to load users');
  }
}

// ============================================================================
// WORKSHOP ENTRIES handlers
// ============================================================================

const CAN_CREATE_ENTRY = ['admin', 'workshop_manager', 'supervisor', 'technician'];
const CAN_CLOSE_ENTRY = ['admin', 'workshop_manager', 'supervisor'];

async function workshopEntriesCollection(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');

  if (req.method === 'GET') {
    try {
      const statusFilter = req.query.status || 'open';
      let whereClause = '';
      const params = [];
      if (statusFilter === 'open' || statusFilter === 'closed') {
        whereClause = 'WHERE we.status = ?';
        params.push(statusFilter);
      }

      const rows = await query(
        `SELECT
           we.id, we.entry_number, we.equipment_id, e.code AS equipment_code,
           e.equipment_type, we.entry_date, we.entry_time, we.maintenance_type,
           we.department_id, d.name AS department_name,
           we.driver_operator, we.hour_meter_km_at_entry,
           we.reported_problem, we.priority, we.status,
           we.exit_date, we.exit_time, we.duration_hours, we.duration_days,
           jc.id AS job_card_id, jc.progress_status,
           we.created_at
         FROM workshop_entries we
         JOIN equipment e ON e.id = we.equipment_id
         JOIN departments d ON d.id = we.department_id
         LEFT JOIN job_cards jc ON jc.workshop_entry_id = we.id
         ${whereClause}
         ORDER BY we.created_at DESC`,
        params
      );
      return sendSuccess(res, 200, rows);
    } catch (err) {
      console.error('GET /api/workshop-entries failed:', err);
      return sendError(res, 500, 'Failed to load workshop entries');
    }
  }

  if (req.method === 'POST') {
    if (!CAN_CREATE_ENTRY.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to register a workshop entry');
    }
    try {
      const body = req.body || {};
      const equipmentId = Number(body.equipment_id);
      const maintenanceType = body.maintenance_type;
      const departmentId = Number(body.department_id);
      const reportedProblem = String(body.reported_problem || '').trim();
      const priority = body.priority || 'medium';

      if (!equipmentId) return sendError(res, 400, 'Equipment is required');
      if (!['PM', 'BD'].includes(maintenanceType)) return sendError(res, 400, 'Maintenance type must be PM or BD');
      if (!departmentId) return sendError(res, 400, 'Department is required');
      if (!reportedProblem) return sendError(res, 400, 'Reported problem is required');
      if (!['low', 'medium', 'high', 'critical'].includes(priority)) {
        return sendError(res, 400, 'Invalid priority value');
      }

      const equipmentRows = await query('SELECT id, is_archived FROM equipment WHERE id = ?', [equipmentId]);
      if (equipmentRows.length === 0 || equipmentRows[0].is_archived) {
        return sendError(res, 400, 'Selected equipment does not exist');
      }

      const deptRows = await query('SELECT id FROM departments WHERE id = ? AND is_active = TRUE', [departmentId]);
      if (deptRows.length === 0) return sendError(res, 400, 'Selected department does not exist');

      const openEntry = await query(
        "SELECT id, entry_number FROM workshop_entries WHERE equipment_id = ? AND status = 'open'",
        [equipmentId]
      );
      if (openEntry.length > 0) {
        return sendError(
          res, 409,
          'هذه المعدة مسجلة بالفعل داخل الورشة (رقم الزيارة: ' + openEntry[0].entry_number + ') — لازم تقفل الزيارة الحالية الأول'
        );
      }

      const driverOperator = optionalString(body.driver_operator);
      const hourMeterAtEntry = body.hour_meter_km_at_entry ? Number(body.hour_meter_km_at_entry) : null;
      const initialDiagnosis = optionalString(body.technician_initial_diagnosis);
      const notes = optionalString(body.notes);

      const now = new Date();
      const entryDate = optionalString(body.entry_date) || now.toISOString().slice(0, 10);
      const entryTime = optionalString(body.entry_time) || now.toTimeString().slice(0, 8);

      const entryId = await withTransaction(async (conn) => {
        const [insertResult] = await conn.execute(
          `INSERT INTO workshop_entries (
             entry_number, equipment_id, entry_date, entry_time, maintenance_type,
             department_id, driver_operator, hour_meter_km_at_entry,
             technician_initial_diagnosis, reported_problem, priority, notes,
             status, created_by
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)`,
          [
            'TEMP', equipmentId, entryDate, entryTime, maintenanceType,
            departmentId, driverOperator, hourMeterAtEntry,
            initialDiagnosis, reportedProblem, priority, notes,
            user.sub,
          ]
        );

        const newId = insertResult.insertId;
        const year = entryDate.slice(0, 4);
        const entryNumber = 'WE-' + year + '-' + String(newId).padStart(6, '0');

        await conn.execute('UPDATE workshop_entries SET entry_number = ? WHERE id = ?', [entryNumber, newId]);
        await conn.execute(
          `INSERT INTO job_cards (workshop_entry_id, progress_status) VALUES (?, 'waiting')`,
          [newId]
        );
        await conn.execute(`UPDATE equipment SET current_status = 'in_workshop' WHERE id = ?`, [equipmentId]);

        return newId;
      });

      const [created] = await query(
        `SELECT we.*, e.code AS equipment_code, d.name AS department_name
         FROM workshop_entries we
         JOIN equipment e ON e.id = we.equipment_id
         JOIN departments d ON d.id = we.department_id
         WHERE we.id = ?`,
        [entryId]
      );

      return sendSuccess(res, 201, created);
    } catch (err) {
      console.error('POST /api/workshop-entries failed:', err);
      return sendError(res, 500, 'Failed to register workshop entry');
    }
  }

  return sendError(res, 405, 'Method not allowed');
}

async function workshopEntryItem(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');

  const id = Number(params.id);
  if (!id) return sendError(res, 400, 'Invalid workshop entry id');

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
    if (rows.length === 0) return sendError(res, 404, 'Workshop entry not found');
    return sendSuccess(res, 200, rows[0]);
  } catch (err) {
    console.error('GET /api/workshop-entries/[id] failed:', err);
    return sendError(res, 500, 'Failed to load workshop entry');
  }
}

async function workshopEntryClose(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'POST') return sendError(res, 405, 'Method not allowed');
  if (!CAN_CLOSE_ENTRY.includes(user.role)) {
    return sendError(res, 403, 'You do not have permission to close a workshop entry');
  }

  const id = Number(params.id);
  if (!id) return sendError(res, 400, 'Invalid workshop entry id');

  try {
    const entries = await query('SELECT * FROM workshop_entries WHERE id = ?', [id]);
    if (entries.length === 0) return sendError(res, 404, 'Workshop entry not found');
    const entry = entries[0];

    if (entry.status === 'closed') return sendError(res, 409, 'هذه الزيارة مقفولة بالفعل');

    const body = req.body || {};
    const exitDate = String(body.exit_date || '').trim();
    const exitTime = String(body.exit_time || '').trim();
    const finalNotes = optionalString(body.final_technician_notes);
    const maintenanceResult = optionalString(body.maintenance_result);
    const equipmentCondition = optionalString(body.equipment_condition);
    const finalEquipmentStatus = body.final_equipment_status;

    if (!exitDate || !exitTime) return sendError(res, 400, 'Exit date and time are required');
    if (!['available', 'breakdown'].includes(finalEquipmentStatus)) {
      return sendError(res, 400, 'final_equipment_status must be "available" or "breakdown"');
    }

    const entryDateTime = new Date(entry.entry_date + 'T' + entry.entry_time);
    const exitDateTime = new Date(exitDate + 'T' + exitTime);

    if (isNaN(exitDateTime.getTime())) return sendError(res, 400, 'Invalid exit date/time');
    if (exitDateTime < entryDateTime) return sendError(res, 400, 'وقت الخروج لازم يكون بعد وقت الدخول');

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
        [exitDate, exitTime, finalNotes, maintenanceResult, equipmentCondition,
         user.sub, durationHours, durationDays, id]
      );
      await conn.execute(`UPDATE equipment SET current_status = ? WHERE id = ?`, [finalEquipmentStatus, entry.equipment_id]);
    });

    const [updated] = await query(
      `SELECT we.*, e.code AS equipment_code
       FROM workshop_entries we JOIN equipment e ON e.id = we.equipment_id WHERE we.id = ?`,
      [id]
    );
    return sendSuccess(res, 200, updated);
  } catch (err) {
    console.error('POST /api/workshop-entries/[id]/close failed:', err);
    return sendError(res, 500, 'Failed to close workshop entry');
  }
}

// ============================================================================
// JOB CARDS handlers
// ============================================================================

const VALID_JOB_STATUSES = [
  'waiting', 'inspection', 'repairing', 'waiting_spare_parts',
  'testing', 'completed', 'delivered', 'cancelled',
];
const CAN_EDIT_JOB_CARD = ['admin', 'workshop_manager', 'supervisor', 'technician'];

async function jobCardItem(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');

  const id = Number(params.id);
  if (!id) return sendError(res, 400, 'Invalid job card id');

  if (req.method === 'GET') {
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
      if (rows.length === 0) return sendError(res, 404, 'Job card not found');

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

  if (req.method === 'PUT') {
    if (!CAN_EDIT_JOB_CARD.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to edit this job card');
    }
    try {
      const existing = await query('SELECT * FROM job_cards WHERE id = ?', [id]);
      if (existing.length === 0) return sendError(res, 404, 'Job card not found');
      const current = existing[0];

      const body = req.body || {};
      const diagnosis = optionalString(body.diagnosis);
      const rootCause = optionalString(body.root_cause);
      const inspectionResults = optionalString(body.inspection_results);
      const laborCost = body.labor_cost !== undefined && body.labor_cost !== '' ? Number(body.labor_cost) : 0;
      const assignedTechnicianId = body.assigned_technician_id ? Number(body.assigned_technician_id) : null;
      const technicianNotes = optionalString(body.technician_notes);
      const progressStatus = body.progress_status;

      if (!VALID_JOB_STATUSES.includes(progressStatus)) return sendError(res, 400, 'Invalid progress status');

      if (assignedTechnicianId) {
        const techRows = await query('SELECT id FROM users WHERE id = ? AND is_active = TRUE', [assignedTechnicianId]);
        if (techRows.length === 0) return sendError(res, 400, 'Selected technician does not exist');
      }

      const statusChanged = progressStatus !== current.progress_status;

      await withTransaction(async (conn) => {
        await conn.execute(
          `UPDATE job_cards SET
             diagnosis = ?, root_cause = ?, inspection_results = ?,
             labor_cost = ?, assigned_technician_id = ?, technician_notes = ?,
             progress_status = ?
           WHERE id = ?`,
          [diagnosis, rootCause, inspectionResults, laborCost, assignedTechnicianId, technicianNotes, progressStatus, id]
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
         FROM job_cards jc LEFT JOIN users u ON u.id = jc.assigned_technician_id WHERE jc.id = ?`,
        [id]
      );
      return sendSuccess(res, 200, updatedRows[0]);
    } catch (err) {
      console.error('PUT /api/job-cards/[id] failed:', err);
      return sendError(res, 500, 'Failed to update job card');
    }
  }

  return sendError(res, 405, 'Method not allowed');
}

async function jobCardParts(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');

  const jobCardId = Number(params.id);
  if (!jobCardId) return sendError(res, 400, 'Invalid job card id');

  if (req.method === 'GET') {
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

  if (req.method === 'POST') {
    if (!CAN_EDIT_JOB_CARD.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to edit this job card');
    }
    try {
      const jobCardRows = await query('SELECT id FROM job_cards WHERE id = ?', [jobCardId]);
      if (jobCardRows.length === 0) return sendError(res, 404, 'Job card not found');

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

  return sendError(res, 405, 'Method not allowed');
}

async function jobCardPartItem(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'DELETE') return sendError(res, 405, 'Method not allowed');
  if (!CAN_EDIT_JOB_CARD.includes(user.role)) {
    return sendError(res, 403, 'You do not have permission to edit this job card');
  }

  const jobCardId = Number(params.id);
  const partId = Number(params.partId);
  if (!jobCardId || !partId) return sendError(res, 400, 'Invalid ids');

  try {
    const rows = await query('SELECT id FROM job_card_parts WHERE id = ? AND job_card_id = ?', [partId, jobCardId]);
    if (rows.length === 0) return sendError(res, 404, 'Part not found on this job card');

    await query('DELETE FROM job_card_parts WHERE id = ?', [partId]);
    return sendSuccess(res, 200, { id: partId, deleted: true });
  } catch (err) {
    console.error('DELETE /api/job-cards/[id]/parts/[partId] failed:', err);
    return sendError(res, 500, 'Failed to delete part');
  }
}

// ============================================================================
// ROUTING TABLE
// ============================================================================
// Add new endpoints here as the project grows — this is the only place
// that needs to change to wire up a new route.

const routes = [
  { pattern: ['auth', 'login'], methods: { POST: authLogin } },
  { pattern: ['auth', 'me'], methods: { GET: authMe } },
  { pattern: ['auth', 'setup-admin'], methods: { POST: authSetupAdmin } },

  { pattern: ['departments'], methods: { GET: departmentsCollection, POST: departmentsCollection } },
  { pattern: ['departments', ':id'], methods: { GET: departmentItem, PUT: departmentItem, DELETE: departmentItem } },

  { pattern: ['equipment'], methods: { GET: equipmentCollection, POST: equipmentCollection } },
  { pattern: ['equipment', ':id'], methods: { GET: equipmentItem, PUT: equipmentItem, DELETE: equipmentItem } },

  { pattern: ['users'], methods: { GET: usersCollection } },

  { pattern: ['workshop-entries'], methods: { GET: workshopEntriesCollection, POST: workshopEntriesCollection } },
  { pattern: ['workshop-entries', ':id'], methods: { GET: workshopEntryItem } },
  { pattern: ['workshop-entries', ':id', 'close'], methods: { POST: workshopEntryClose } },

  { pattern: ['job-cards', ':id'], methods: { GET: jobCardItem, PUT: jobCardItem } },
  { pattern: ['job-cards', ':id', 'parts'], methods: { GET: jobCardParts, POST: jobCardParts } },
  { pattern: ['job-cards', ':id', 'parts', ':partId'], methods: { DELETE: jobCardPartItem } },
];

function matchRoute(pattern, segments) {
  if (pattern.length !== segments.length) return null;
  const params = {};
  for (let i = 0; i < pattern.length; i++) {
    const part = pattern[i];
    if (part.startsWith(':')) {
      params[part.slice(1)] = segments[i];
    } else if (part !== segments[i]) {
      return null;
    }
  }
  return params;
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    return res.status(200).json(null);
  }

  const rawPath = req.query.path;
  const segments = Array.isArray(rawPath) ? rawPath : (rawPath ? [rawPath] : []);

  for (const route of routes) {
    const params = matchRoute(route.pattern, segments);
    if (params) {
      const fn = route.methods[req.method];
      if (!fn) return sendError(res, 405, 'Method not allowed');
      return fn(req, res, params);
    }
  }

  return sendError(res, 404, 'Not found: /' + segments.join('/'));
};
