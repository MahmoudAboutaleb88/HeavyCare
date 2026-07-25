// api/_lib/http.js
//
// Small helpers so every endpoint returns responses in the same shape,
// and CORS headers are set consistently (useful during initial testing).

function sendJson(res, statusCode, payload) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.status(statusCode).json(payload);
}

function sendError(res, statusCode, message) {
  sendJson(res, statusCode, { success: false, error: message });
}

function sendSuccess(res, statusCode, data) {
  sendJson(res, statusCode, { success: true, data });
}

module.exports = { sendJson, sendError, sendSuccess };
