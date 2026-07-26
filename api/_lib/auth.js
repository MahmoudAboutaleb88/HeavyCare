// api/_lib/auth.js
//
// Helpers for password hashing/verification and JWT token creation/verification.
// Used by: auth/setup-admin.js, auth/login.js, auth/me.js, and (later) every
// protected endpoint that needs to know "who is calling this?".

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

if (!process.env.JWT_SECRET) {
  throw new Error('Missing required environment variable: JWT_SECRET');
}

const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_EXPIRY = '8h'; // a work shift's worth of session length

async function hashPassword(plainPassword) {
  const saltRounds = 10;
  return bcrypt.hash(plainPassword, saltRounds);
}

async function verifyPassword(plainPassword, passwordHash) {
  return bcrypt.compare(plainPassword, passwordHash);
}

function signToken(user) {
  // Keep the payload minimal — id and role are what every protected
  // endpoint needs to make authorization decisions.
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

function verifyToken(token) {
  // Throws if invalid/expired — caller should catch this.
  return jwt.verify(token, JWT_SECRET);
}

/**
 * Extracts and verifies the JWT from the Authorization header.
 * Returns the decoded payload, or null if missing/invalid.
 * Usage inside a protected endpoint:
 *
 *   const user = requireAuth(req);
 *   if (!user) return sendError(res, 401, 'Unauthorized');
 */
function requireAuth(req) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return null;
  }

  try {
    return verifyToken(token);
  } catch (err) {
    return null;
  }
}

module.exports = { hashPassword, verifyPassword, signToken, verifyToken, requireAuth };
