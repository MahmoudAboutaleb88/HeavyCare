// api/router.js
//
// ============================================================================
// SINGLE ENTRY POINT FOR THE ENTIRE API
// ============================================================================
// Why this file exists:
//   Vercel's Hobby (free) plan caps a deployment at 12 Serverless Functions.
//   Every separate file under /api used to count as one function — we had
//   14 and hit the wall. So the whole backend lives in ONE plain file
//   (this one) with an ordinary name — no brackets, no dots — because
//   filenames with special characters (like the previous "[...path].js")
//   proved fragile to type/upload correctly through GitHub's mobile web
//   editor. `vercel.json` at the project root rewrites every request
//   under /api/* to this single file; the routing table below then reads
//   the real path from the request URL and dispatches accordingly.
//
//   Nothing changes from the frontend's point of view: a request to
//   /api/equipment/5 still works exactly the same, just internally
//   routed by this file instead of the filesystem.
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
           e.created_at,
           we.entry_number AS current_entry_number,
           jc.id AS current_job_card_id
         FROM equipment e
         JOIN departments d ON d.id = e.department_id
         LEFT JOIN workshop_entries we ON we.equipment_id = e.id AND we.status = 'open'
         LEFT JOIN job_cards jc ON jc.workshop_entry_id = we.id
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
      const imageUrl = optionalString(body.image_url);

      await query(
        `UPDATE equipment SET
           code = ?, name = ?, department_id = ?, equipment_type = ?,
           brand = ?, model = ?, asset_number = ?, manufacturing_year = ?,
           purchase_date = ?, warranty_expiry = ?, hour_meter = ?, image_url = ?
         WHERE id = ?`,
        [code, name, departmentId, equipmentType, brand, model, assetNumber,
         manufacturingYear, purchaseDate, warrantyExpiry, hourMeter, imageUrl, id]
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
// EQUIPMENT HISTORY handler
// ============================================================================
// Full maintenance timeline for one piece of equipment: every workshop
// entry it's ever had (open or closed), with the matching job card's
// diagnosis/result/cost, plus a small stats summary. This is what the
// "أهو دخل، أهو خرج، أهو اتصلح" question actually needs — one screen,
// full history, nothing hidden behind separate report filters.

async function equipmentHistory(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');

  const id = Number(params.id);
  if (!id) return sendError(res, 400, 'Invalid equipment id');

  try {
    const equipmentRows = await query(
      `SELECT e.*, d.name AS department_name
       FROM equipment e JOIN departments d ON d.id = e.department_id
       WHERE e.id = ?`,
      [id]
    );
    if (equipmentRows.length === 0) return sendError(res, 404, 'Equipment not found');

    const entries = await query(
      `SELECT
         we.id, we.entry_number, we.entry_date, we.entry_time,
         we.exit_date, we.exit_time, we.maintenance_type, we.priority,
         we.reported_problem, we.status, we.duration_hours, we.duration_days,
         we.maintenance_result, we.equipment_condition,
         jc.id AS job_card_id, jc.progress_status, jc.diagnosis, jc.root_cause, jc.labor_cost,
         COALESCE((SELECT SUM(total_cost) FROM job_card_parts WHERE job_card_id = jc.id), 0) AS parts_cost
       FROM workshop_entries we
       LEFT JOIN job_cards jc ON jc.workshop_entry_id = we.id
       WHERE we.equipment_id = ?
       ORDER BY we.entry_date DESC, we.entry_time DESC`,
      [id]
    );

    const closedPM = entries.filter((e) => e.status === 'closed' && e.maintenance_type === 'PM' && e.duration_hours != null);
    const closedBD = entries.filter((e) => e.status === 'closed' && e.maintenance_type === 'BD' && e.duration_days != null);
    const avgHoursPM = closedPM.length ? closedPM.reduce((s, e) => s + Number(e.duration_hours), 0) / closedPM.length : null;
    const avgDaysBD = closedBD.length ? closedBD.reduce((s, e) => s + Number(e.duration_days), 0) / closedBD.length : null;
    const totalCost = entries.reduce((s, e) => s + Number(e.labor_cost || 0) + Number(e.parts_cost || 0), 0);

    return sendSuccess(res, 200, {
      equipment: equipmentRows[0],
      entries,
      stats: {
        total_visits: entries.length,
        pm_count: entries.filter((e) => e.maintenance_type === 'PM').length,
        bd_count: entries.filter((e) => e.maintenance_type === 'BD').length,
        avg_hours_pm: avgHoursPM !== null ? Math.round(avgHoursPM * 10) / 10 : null,
        avg_days_bd: avgDaysBD !== null ? Math.round(avgDaysBD * 10) / 10 : null,
        total_cost: Math.round(totalCost * 100) / 100,
      },
    });
  } catch (err) {
    console.error('GET /api/equipment/[id]/history failed:', err);
    return sendError(res, 500, 'Failed to load equipment history');
  }
}

// ============================================================================
// USERS handlers
// ============================================================================
// Only admins can create/edit accounts — this controls who gets into the
// system at all, so it's kept tighter than other modules.

const CAN_MANAGE_USERS = ['admin'];
const VALID_ROLES = ['admin', 'workshop_manager', 'supervisor', 'technician', 'viewer'];

async function usersCollection(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');

  if (req.method === 'GET') {
    try {
      // Dropdowns elsewhere (assign technician, etc.) only want active users.
      // The user-management page itself needs to see everyone, including
      // deactivated accounts, so it can reactivate them — but only an
      // admin is allowed to ask for that.
      const includeInactive = req.query.include_inactive === '1' && user.role === 'admin';

      const rows = await query(
        `SELECT u.id, u.full_name, u.username, u.role, u.department_id,
                d.name AS department_name, u.is_active, u.created_at
         FROM users u
         LEFT JOIN departments d ON d.id = u.department_id
         ${includeInactive ? '' : 'WHERE u.is_active = TRUE'}
         ORDER BY u.full_name ASC`
      );
      return sendSuccess(res, 200, rows);
    } catch (err) {
      console.error('GET /api/users failed:', err);
      return sendError(res, 500, 'Failed to load users');
    }
  }

  if (req.method === 'POST') {
    if (!CAN_MANAGE_USERS.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to create users');
    }
    try {
      const body = req.body || {};
      const fullName = String(body.full_name || '').trim();
      const username = String(body.username || '').trim().toLowerCase();
      const password = body.password || '';
      const role = body.role;
      const departmentId = body.department_id ? Number(body.department_id) : null;

      if (!fullName) return sendError(res, 400, 'Full name is required');
      if (!username) return sendError(res, 400, 'Username is required');
      if (!password || password.length < 8) return sendError(res, 400, 'Password must be at least 8 characters');
      if (!VALID_ROLES.includes(role)) return sendError(res, 400, 'Invalid role');

      if (departmentId) {
        const dept = await query('SELECT id FROM departments WHERE id = ? AND is_active = TRUE', [departmentId]);
        if (dept.length === 0) return sendError(res, 400, 'Selected department does not exist');
      }

      const passwordHash = await hashPassword(password);
      const result = await query(
        `INSERT INTO users (full_name, username, password_hash, role, department_id, is_active)
         VALUES (?, ?, ?, ?, ?, TRUE)`,
        [fullName, username, passwordHash, role, departmentId]
      );

      const [created] = await query(
        `SELECT u.id, u.full_name, u.username, u.role, u.department_id,
                d.name AS department_name, u.is_active, u.created_at
         FROM users u LEFT JOIN departments d ON d.id = u.department_id WHERE u.id = ?`,
        [result.insertId]
      );
      return sendSuccess(res, 201, created);
    } catch (err) {
      if (err && err.code === 'ER_DUP_ENTRY') {
        return sendError(res, 409, 'اسم المستخدم ده مستخدم بالفعل');
      }
      console.error('POST /api/users failed:', err);
      return sendError(res, 500, 'Failed to create user');
    }
  }

  return sendError(res, 405, 'Method not allowed');
}

async function userItem(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'PUT') return sendError(res, 405, 'Method not allowed');
  if (!CAN_MANAGE_USERS.includes(user.role)) {
    return sendError(res, 403, 'You do not have permission to edit users');
  }

  const id = Number(params.id);
  if (!id) return sendError(res, 400, 'Invalid user id');

  try {
    const existing = await query('SELECT id FROM users WHERE id = ?', [id]);
    if (existing.length === 0) return sendError(res, 404, 'User not found');

    const body = req.body || {};
    const fullName = String(body.full_name || '').trim();
    const role = body.role;
    const departmentId = body.department_id ? Number(body.department_id) : null;
    const isActive = body.is_active !== false; // defaults true unless explicitly false
    const newPassword = body.password || '';

    if (!fullName) return sendError(res, 400, 'Full name is required');
    if (!VALID_ROLES.includes(role)) return sendError(res, 400, 'Invalid role');

    // Safety guard: an admin can't lock themselves out by deactivating
    // their own account.
    if (id === user.sub && !isActive) {
      return sendError(res, 400, 'لا يمكنك إيقاف حسابك الخاص');
    }

    if (departmentId) {
      const dept = await query('SELECT id FROM departments WHERE id = ? AND is_active = TRUE', [departmentId]);
      if (dept.length === 0) return sendError(res, 400, 'Selected department does not exist');
    }

    if (newPassword) {
      if (newPassword.length < 8) return sendError(res, 400, 'Password must be at least 8 characters');
      const passwordHash = await hashPassword(newPassword);
      await query(
        `UPDATE users SET full_name = ?, role = ?, department_id = ?, is_active = ?, password_hash = ? WHERE id = ?`,
        [fullName, role, departmentId, isActive, passwordHash, id]
      );
    } else {
      await query(
        `UPDATE users SET full_name = ?, role = ?, department_id = ?, is_active = ? WHERE id = ?`,
        [fullName, role, departmentId, isActive, id]
      );
    }

    const [updated] = await query(
      `SELECT u.id, u.full_name, u.username, u.role, u.department_id,
              d.name AS department_name, u.is_active, u.created_at
       FROM users u LEFT JOIN departments d ON d.id = u.department_id WHERE u.id = ?`,
      [id]
    );
    return sendSuccess(res, 200, updated);
  } catch (err) {
    console.error('PUT /api/users/[id] failed:', err);
    return sendError(res, 500, 'Failed to update user');
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
// NOTIFICATIONS handler
// ============================================================================
// No notifications table, no background jobs, no email/SMS — every alert
// here is computed live from current data each time this endpoint is
// called. That's the right level of complexity for this system's scale:
// a small in-house workshop tool checked by a handful of people, not a
// platform that needs push delivery or a queue.

const DELAYED_PM_HOURS = 24;
const DELAYED_BD_DAYS = 3;

async function notificationsSummary(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');

  try {
    const baseSelect = `
      SELECT we.id, we.entry_number, we.maintenance_type, we.entry_date, we.entry_time,
             e.code AS equipment_code, d.name AS department_name,
             jc.id AS job_card_id, jc.progress_status
      FROM workshop_entries we
      JOIN equipment e ON e.id = we.equipment_id
      JOIN departments d ON d.id = we.department_id
      JOIN job_cards jc ON jc.workshop_entry_id = we.id
      WHERE we.status = 'open'`;

    const waitingApproval = await query(
      baseSelect + ` AND jc.progress_status IN ('completed', 'delivered') ORDER BY we.entry_date ASC`
    );

    const waitingParts = await query(
      baseSelect + ` AND jc.progress_status = 'waiting_spare_parts' ORDER BY we.entry_date ASC`
    );

    const delayed = await query(
      baseSelect + `
        AND (
          (we.maintenance_type = 'PM' AND TIMESTAMPDIFF(HOUR, CONCAT(we.entry_date, ' ', we.entry_time), NOW()) > ?)
          OR
          (we.maintenance_type = 'BD' AND TIMESTAMPDIFF(DAY, we.entry_date, CURDATE()) > ?)
        )
        ORDER BY we.entry_date ASC`,
      [DELAYED_PM_HOURS, DELAYED_BD_DAYS]
    );

    return sendSuccess(res, 200, {
      waiting_approval: waitingApproval,
      waiting_parts: waitingParts,
      delayed,
      total: waitingApproval.length + waitingParts.length + delayed.length,
    });
  } catch (err) {
    console.error('GET /api/notifications failed:', err);
    return sendError(res, 500, 'Failed to load notifications');
  }
}

// ============================================================================
// CONFIG handler — public, non-secret frontend settings
// ============================================================================
// Cloud name + unsigned upload preset are meant to be visible in the
// browser (that's how Cloudinary's unsigned upload flow works — there's
// no secret involved). We still serve them from an env-var-backed
// endpoint instead of hardcoding them in every HTML file, so changing
// them later is a one-line env var edit, not a find-and-replace across
// a dozen pages.

async function publicConfig(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');

  return sendSuccess(res, 200, {
    cloudinary_cloud_name: process.env.CLOUDINARY_CLOUD_NAME || null,
    cloudinary_upload_preset: process.env.CLOUDINARY_UPLOAD_PRESET || null,
  });
}

// ============================================================================
// WORKSHOP ENTRY PHOTOS handlers
// ============================================================================
// Photos are tagged by stage (entry / before_repair / during_repair /
// after_repair) per the original spec. The actual image bytes live on
// Cloudinary — we only ever store the resulting secure_url here.

const CAN_MANAGE_PHOTOS = ['admin', 'workshop_manager', 'supervisor', 'technician'];

async function entryPhotosCollection(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');

  const entryId = Number(params.id);
  if (!entryId) return sendError(res, 400, 'Invalid workshop entry id');

  if (req.method === 'GET') {
    try {
      const rows = await query(
        `SELECT id, photo_url, stage, uploaded_at
         FROM workshop_entry_photos WHERE workshop_entry_id = ? ORDER BY uploaded_at ASC`,
        [entryId]
      );
      return sendSuccess(res, 200, rows);
    } catch (err) {
      console.error('GET photos failed:', err);
      return sendError(res, 500, 'Failed to load photos');
    }
  }

  if (req.method === 'POST') {
    if (!CAN_MANAGE_PHOTOS.includes(user.role)) {
      return sendError(res, 403, 'You do not have permission to add photos');
    }
    try {
      const entryRows = await query('SELECT id FROM workshop_entries WHERE id = ?', [entryId]);
      if (entryRows.length === 0) return sendError(res, 404, 'Workshop entry not found');

      const body = req.body || {};
      const photoUrl = String(body.photo_url || '').trim();
      const stage = body.stage;
      const validStages = ['entry', 'before_repair', 'during_repair', 'after_repair'];

      if (!photoUrl) return sendError(res, 400, 'photo_url is required');
      if (!validStages.includes(stage)) return sendError(res, 400, 'Invalid stage');

      const result = await query(
        `INSERT INTO workshop_entry_photos (workshop_entry_id, photo_url, stage) VALUES (?, ?, ?)`,
        [entryId, photoUrl, stage]
      );
      const [created] = await query(
        `SELECT id, photo_url, stage, uploaded_at FROM workshop_entry_photos WHERE id = ?`,
        [result.insertId]
      );
      return sendSuccess(res, 201, created);
    } catch (err) {
      console.error('POST photos failed:', err);
      return sendError(res, 500, 'Failed to save photo');
    }
  }

  return sendError(res, 405, 'Method not allowed');
}

async function entryPhotoItem(req, res, params) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'DELETE') return sendError(res, 405, 'Method not allowed');
  if (!CAN_MANAGE_PHOTOS.includes(user.role)) {
    return sendError(res, 403, 'You do not have permission to delete photos');
  }

  const entryId = Number(params.id);
  const photoId = Number(params.photoId);
  if (!entryId || !photoId) return sendError(res, 400, 'Invalid ids');

  try {
    const rows = await query(
      'SELECT id FROM workshop_entry_photos WHERE id = ? AND workshop_entry_id = ?',
      [photoId, entryId]
    );
    if (rows.length === 0) return sendError(res, 404, 'Photo not found');

    await query('DELETE FROM workshop_entry_photos WHERE id = ?', [photoId]);
    return sendSuccess(res, 200, { id: photoId, deleted: true });
  } catch (err) {
    console.error('DELETE photo failed:', err);
    return sendError(res, 500, 'Failed to delete photo');
  }
}

// ============================================================================
// SEARCH handler
// ============================================================================
// One global search box, three sources. Kept intentionally simple (LIKE
// matching, small per-category limits) since this is an internal tool
// with a modest amount of data — a full-text search engine would be
// over-engineering at this scale.

async function globalSearch(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');

  const q = String(req.query.q || '').trim();
  if (q.length < 2) {
    return sendSuccess(res, 200, { equipment: [], workshop_entries: [], users: [] });
  }

  try {
    const pattern = '%' + q.replace(/[%_]/g, '\\$&') + '%';

    const equipment = await query(
      `SELECT e.id, e.code, e.equipment_type, e.brand, e.model, d.name AS department_name
       FROM equipment e JOIN departments d ON d.id = e.department_id
       WHERE e.is_archived = FALSE
         AND (e.code LIKE ? OR e.equipment_type LIKE ? OR e.brand LIKE ? OR e.model LIKE ?)
       LIMIT 6`,
      [pattern, pattern, pattern, pattern]
    );

    const workshopEntries = await query(
      `SELECT we.id, we.entry_number, we.status, we.reported_problem, e.code AS equipment_code
       FROM workshop_entries we JOIN equipment e ON e.id = we.equipment_id
       WHERE we.entry_number LIKE ? OR we.reported_problem LIKE ? OR e.code LIKE ?
       ORDER BY we.created_at DESC LIMIT 6`,
      [pattern, pattern, pattern]
    );

    const users = await query(
      `SELECT id, full_name, username, role FROM users
       WHERE is_active = TRUE AND (full_name LIKE ? OR username LIKE ?)
       LIMIT 6`,
      [pattern, pattern]
    );

    return sendSuccess(res, 200, {
      equipment,
      workshop_entries: workshopEntries,
      users,
    });
  } catch (err) {
    console.error('GET /api/search failed:', err);
    return sendError(res, 500, 'Search failed');
  }
}

// ============================================================================
// REPORTS handler
// ============================================================================
// One flexible endpoint covers every report type from the spec (equipment
// history, department report, daily/monthly, breakdown-only, PM-only,
// downtime, cost) — they're all just different filter combinations over
// the same underlying workshop_entries data, so one query + query-string
// filters is more maintainable than eight near-identical endpoints.

async function reportsWorkshopEntries(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');

  try {
    const { date_from, date_to, department_id, equipment_id, maintenance_type, status } = req.query;

    const conditions = [];
    const params = [];

    if (date_from) { conditions.push('we.entry_date >= ?'); params.push(date_from); }
    if (date_to) { conditions.push('we.entry_date <= ?'); params.push(date_to); }
    if (department_id) { conditions.push('we.department_id = ?'); params.push(Number(department_id)); }
    if (equipment_id) { conditions.push('we.equipment_id = ?'); params.push(Number(equipment_id)); }
    if (maintenance_type && ['PM', 'BD'].includes(maintenance_type)) {
      conditions.push('we.maintenance_type = ?'); params.push(maintenance_type);
    }
    if (status && ['open', 'closed'].includes(status)) {
      conditions.push('we.status = ?'); params.push(status);
    }

    const whereClause = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const rows = await query(
      `SELECT
         we.id, we.entry_number, we.entry_date, we.entry_time,
         we.exit_date, we.exit_time, we.maintenance_type, we.priority,
         we.status, we.reported_problem, we.duration_hours, we.duration_days,
         e.code AS equipment_code, e.equipment_type,
         d.name AS department_name,
         jc.progress_status, jc.labor_cost,
         COALESCE(
           (SELECT SUM(total_cost) FROM job_card_parts WHERE job_card_id = jc.id),
           0
         ) AS parts_cost
       FROM workshop_entries we
       JOIN equipment e ON e.id = we.equipment_id
       JOIN departments d ON d.id = we.department_id
       LEFT JOIN job_cards jc ON jc.workshop_entry_id = we.id
       ${whereClause}
       ORDER BY we.entry_date DESC, we.entry_time DESC`,
      params
    );

    return sendSuccess(res, 200, rows);
  } catch (err) {
    console.error('GET /api/reports/workshop-entries failed:', err);
    return sendError(res, 500, 'Failed to generate report');
  }
}

// ============================================================================
// DASHBOARD handler
// ============================================================================
// One endpoint, one round trip: every KPI card and chart on the dashboard
// comes from this single call instead of the page firing off 6 separate
// requests.

async function dashboardStats(req, res) {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Unauthorized — please log in');
  if (req.method !== 'GET') return sendError(res, 405, 'Method not allowed');

  try {
    const equipmentByStatus = await query(
      `SELECT current_status, COUNT(*) AS count
       FROM equipment WHERE is_archived = FALSE GROUP BY current_status`
    );
    const equipment = { total: 0, available: 0, in_workshop: 0, breakdown: 0 };
    equipmentByStatus.forEach((row) => {
      equipment[row.current_status] = row.count;
      equipment.total += row.count;
    });

    const [openCounts] = await query(
      `SELECT
         COUNT(*) AS open_total,
         SUM(CASE WHEN maintenance_type = 'PM' THEN 1 ELSE 0 END) AS open_pm,
         SUM(CASE WHEN maintenance_type = 'BD' THEN 1 ELSE 0 END) AS open_bd
       FROM workshop_entries WHERE status = 'open'`
    );

    const [closedThisMonth] = await query(
      `SELECT COUNT(*) AS count FROM workshop_entries
       WHERE status = 'closed' AND exit_date >= DATE_FORMAT(CURDATE(), '%Y-%m-01')`
    );

    const [avgDuration] = await query(
      `SELECT
         AVG(CASE WHEN maintenance_type = 'PM' THEN duration_hours END) AS avg_hours_pm,
         AVG(CASE WHEN maintenance_type = 'BD' THEN duration_days END) AS avg_days_bd
       FROM workshop_entries WHERE status = 'closed'`
    );

    const departmentOpenCounts = await query(
      `SELECT d.name AS department_name, COUNT(*) AS count
       FROM workshop_entries we JOIN departments d ON d.id = we.department_id
       WHERE we.status = 'open'
       GROUP BY we.department_id ORDER BY count DESC LIMIT 8`
    );

    const topEquipment = await query(
      `SELECT e.code, e.equipment_type, COUNT(*) AS visit_count
       FROM workshop_entries we JOIN equipment e ON e.id = we.equipment_id
       GROUP BY we.equipment_id ORDER BY visit_count DESC LIMIT 5`
    );

    const monthlyTrend = await query(
      `SELECT DATE_FORMAT(entry_date, '%Y-%m') AS month, COUNT(*) AS count
       FROM workshop_entries
       WHERE entry_date >= DATE_SUB(CURDATE(), INTERVAL 5 MONTH)
       GROUP BY month ORDER BY month ASC`
    );

    return sendSuccess(res, 200, {
      equipment,
      entries: {
        open_total: openCounts.open_total || 0,
        open_pm: openCounts.open_pm || 0,
        open_bd: openCounts.open_bd || 0,
        closed_this_month: closedThisMonth.count || 0,
      },
      avg_duration: {
        hours_pm: avgDuration.avg_hours_pm ? Math.round(avgDuration.avg_hours_pm * 10) / 10 : null,
        days_bd: avgDuration.avg_days_bd ? Math.round(avgDuration.avg_days_bd * 10) / 10 : null,
      },
      department_open_counts: departmentOpenCounts,
      top_equipment: topEquipment,
      monthly_trend: monthlyTrend,
    });
  } catch (err) {
    console.error('GET /api/dashboard failed:', err);
    return sendError(res, 500, 'Failed to load dashboard statistics');
  }
}

// ============================================================================
// ROUTING TABLE
// ============================================================================
// Add new endpoints here as the project grows — this is the only place
// that needs to change to wire up a new route.

const routes = [
  { pattern: ['notifications'], methods: { GET: notificationsSummary } },

  { pattern: ['config'], methods: { GET: publicConfig } },

  { pattern: ['workshop-entries', ':id', 'photos'], methods: { GET: entryPhotosCollection, POST: entryPhotosCollection } },
  { pattern: ['workshop-entries', ':id', 'photos', ':photoId'], methods: { DELETE: entryPhotoItem } },

  { pattern: ['search'], methods: { GET: globalSearch } },

  { pattern: ['reports', 'workshop-entries'], methods: { GET: reportsWorkshopEntries } },

  { pattern: ['dashboard'], methods: { GET: dashboardStats } },

  { pattern: ['auth', 'login'], methods: { POST: authLogin } },
  { pattern: ['auth', 'me'], methods: { GET: authMe } },
  { pattern: ['auth', 'setup-admin'], methods: { POST: authSetupAdmin } },

  { pattern: ['departments'], methods: { GET: departmentsCollection, POST: departmentsCollection } },
  { pattern: ['departments', ':id'], methods: { GET: departmentItem, PUT: departmentItem, DELETE: departmentItem } },

  { pattern: ['equipment'], methods: { GET: equipmentCollection, POST: equipmentCollection } },
  { pattern: ['equipment', ':id'], methods: { GET: equipmentItem, PUT: equipmentItem, DELETE: equipmentItem } },
  { pattern: ['equipment', ':id', 'history'], methods: { GET: equipmentHistory } },

  { pattern: ['users'], methods: { GET: usersCollection, POST: usersCollection } },
  { pattern: ['users', ':id'], methods: { PUT: userItem } },

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

  // Read the path directly from the request URL instead of relying on
  // Vercel's dynamic-route query param name (which depends on the exact
  // filename and has proven fragile). This works regardless of how the
  // catch-all file ends up named.
  const urlPath = (req.url || '').split('?')[0]; // e.g. "/api/departments/5"
  const segments = urlPath.replace(/^\/api\/?/, '').split('/').filter(Boolean);

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
