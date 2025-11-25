// routes/sync.js
const express = require('express');
const router = express.Router();
const { pool } = require('../db'); // force correct import

if (!pool || typeof pool.query !== 'function') {
  throw new Error('Postgres pool is not initialized correctly');
}

router.post('/sync-user', async (req, res) => {
  const apiKey = req.headers['x-internal-api-key'];

  if (apiKey !== process.env.INTERNAL_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { auth0_id, auth_sub, email, given_name, family_name, name, role } = req.body;

  if (!auth0_id || !auth_sub || !email || !role) {
    return res.status(400).json({ error: 'auth0_id, auth_sub, email, and role are required' });
  }

  const firstName = given_name || '';
  const lastName = family_name || '';
  const fullName = name || `${firstName} ${lastName}`.trim();

  const query = `
    INSERT INTO users
      (auth_provider, auth_sub, auth0_id, email, first_name, last_name, name, role, created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
    ON CONFLICT (auth0_id) DO UPDATE
      SET auth_sub = EXCLUDED.auth_sub,
          email = EXCLUDED.email,
          first_name = EXCLUDED.first_name,
          last_name = EXCLUDED.last_name,
          name = EXCLUDED.name,
          role = CASE
                   WHEN users.role = 'Administrator' THEN users.role -- preserve manual admin
                   ELSE EXCLUDED.role
                 END,
          updated_at = NOW()
    RETURNING id, auth0_id, email, role;
  `;

  try {
    const result = await pool.query(query, [
      'auth0',
      auth_sub,
      auth0_id,
      email,
      firstName,
      lastName,
      fullName,
      role
    ]);

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('DB sync error:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});

module.exports = router;
