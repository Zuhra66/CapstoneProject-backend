const express = require('express');
const router = express.Router();
const pool = require('../db');
const checkJwt = require('../middleware/auth0-check');

// Get current user profile
router.get('/', checkJwt, async (req, res) => {
  try {
    const auth0Id = req.user.sub;
    if (!auth0Id) return res.status(400).json({ error: 'Missing Auth0 user ID' });

    const query = `
      SELECT id, auth_provider, auth_sub, auth0_id, email, first_name, last_name, name, role, metadata, created_at, updated_at
      FROM users
      WHERE auth0_id = $1
      LIMIT 1;
    `;
    const result = await pool.query(query, [auth0Id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found in database' });

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

// Update current user profile
router.patch('/', checkJwt, async (req, res) => {
  try {
    const auth0Id = req.user.sub;
    if (!auth0Id) return res.status(400).json({ error: 'Missing Auth0 user ID' });

    const { first_name, last_name, name, email } = req.body;

    const query = `
      UPDATE users
      SET first_name = $1,
          last_name = $2,
          name = $3,
          email = $4,
          updated_at = NOW()
      WHERE auth0_id = $5
      RETURNING id, auth_provider, auth_sub, auth0_id, email, first_name, last_name, name, role, metadata, created_at, updated_at;
    `;
    const result = await pool.query(query, [first_name, last_name, name, email, auth0Id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

module.exports = router;
