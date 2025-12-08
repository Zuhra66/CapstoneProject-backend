// routes/auth.js
const express = require('express');
const router = express.Router();

const { pool } = require('../db');
const { checkJwt } = require('../middleware/admin-check');

// Simple ping for debugging (optional)
router.get('/ping', (req, res) => {
  res.json({ ok: true });
});

// Handle preflight so browser doesn't get blocked
router.options('/me', (req, res) => {
  res.sendStatus(200);
});

// GET /api/auth/me
router.get('/me', checkJwt, async (req, res) => {
  try {
    // req.auth comes from express-oauth2-jwt-bearer via our checkJwt
    const payload = req.auth?.payload || req.auth || {};
    const sub = payload.sub;
    const email = payload.email;

    console.log('🔐 /api/auth/me DEBUG ==========');
    console.log('Token sub:', sub);
    console.log('Token email:', email);

    if (!sub) {
      return res.status(401).json({ error: 'Missing sub in token' });
    }

    // Look up user by auth0_id or auth_sub
    const q = `
      SELECT
        id,
        auth0_id,
        auth_sub,
        email,
        first_name,
        last_name,
        name,
        role,
        is_admin,
        is_active,
        auth_provider,
        created_at,
        updated_at
      FROM public.users
      WHERE auth0_id = $1 OR auth_sub = $1
      LIMIT 1
    `;
    const result = await pool.query(q, [sub]);

    if (result.rows.length === 0) {
      console.log('❌ /api/auth/me: user not found for sub', sub);
      return res.status(404).json({ error: 'User not found' });
    }

    const dbUser = result.rows[0];

    console.log('✅ /api/auth/me: user found:', {
      id: dbUser.id,
      email: dbUser.email,
      role: dbUser.role,
      is_admin: dbUser.is_admin,
      is_active: dbUser.is_active,
    });

    res.json({
      user: {
        id: dbUser.id,
        auth0_id: dbUser.auth0_id,
        auth_sub: dbUser.auth_sub,
        email: dbUser.email,
        first_name: dbUser.first_name,
        last_name: dbUser.last_name,
        name: dbUser.name,
        role: dbUser.role,
        is_admin: dbUser.is_admin,
        is_active: dbUser.is_active,
        auth_provider: dbUser.auth_provider,
        createdAt: dbUser.created_at,
        updatedAt: dbUser.updated_at,
      },
    });
  } catch (err) {
    console.error('Error in /api/auth/me:', err);
    res.status(500).json({ error: 'Failed to load auth user' });
  }
});

module.exports = router;
