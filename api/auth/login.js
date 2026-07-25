// api/auth/login.js
//
// POST /api/auth/login
// Body: { username, password }
// Returns: { token, user: { id, full_name, username, role } }

const { query } = require('../_lib/db');
const { verifyPassword, signToken } = require('../_lib/auth');
const { sendSuccess, sendError } = require('../_lib/http');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return sendSuccess(res, 200, null);
  }
  if (req.method !== 'POST') {
    return sendError(res, 405, 'Method not allowed');
  }

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

    // Same error message whether the username doesn't exist or the
    // password is wrong — don't reveal which one it was.
    const genericError = () => sendError(res, 401, 'Invalid username or password');

    if (rows.length === 0) {
      return genericError();
    }

    const user = rows[0];

    if (!user.is_active) {
      return sendError(res, 403, 'This account has been deactivated');
    }

    const passwordMatches = await verifyPassword(password, user.password_hash);
    if (!passwordMatches) {
      return genericError();
    }

    const token = signToken(user);

    return sendSuccess(res, 200, {
      token,
      user: {
        id: user.id,
        full_name: user.full_name,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('POST /api/auth/login failed:', err);
    return sendError(res, 500, 'Login failed');
  }
};
