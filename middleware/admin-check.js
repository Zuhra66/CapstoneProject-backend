// middleware/admin-check.js
const { auth } = require('express-oauth2-jwt-bearer');
const { pool } = require('../db');

const checkJwt = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
  // tokenSigningAlg can be left default (RS256) unless you customized
});

async function attachAdminUser(req, _res, next) {
  try {
    // Auth0 "sub" identifies the user (e.g., google-oauth2|123...)
    const sub = req.auth?.payload?.sub;
    const email = req.auth?.payload?.email;

    if (!sub && !email) {
      return next(new Error('Missing user identity in token'));
    }

    // Find your app user by auth0 id OR email
    const { rows } = await pool.query(
      `SELECT id, email, role, is_admin
         FROM public.users
        WHERE auth0_id = $1 OR email = $2
        LIMIT 1`,
      [sub || null, email || null]
    );

    if (!rows.length) {
      const err = new Error('User not found in app DB');
      err.status = 403;
      return next(err);
    }

    req.adminUser = rows[0];
    next();
  } catch (e) {
    e.status = 500;
    next(e);
  }
}

function requireAdmin(req, res, next) {
  const u = req.adminUser;
  if (u && (u.is_admin === true || u.role === 'admin')) return next();
  return res.status(403).json({ error: 'Admin role required' });
}

module.exports = { checkJwt, attachAdminUser, requireAdmin };
