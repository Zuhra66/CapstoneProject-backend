const express = require('express');
const router = express.Router();
const pool = require('../db'); // your Postgres pool

router.post('/sync-user', async (req, res) => {
  console.log('Header key received:', req.headers['x-internal-api-key']);
  console.log('Env key expected:', process.env.INTERNAL_API_KEY);

  if (req.headers['x-internal-api-key'] !== process.env.INTERNAL_API_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const { auth0_id, auth_sub, email, given_name, family_name } = req.body;

  const query = `
      INSERT INTO users (auth0_id, auth_sub, email, first_name, last_name, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
          ON CONFLICT (auth0_id) DO UPDATE
                                        SET auth_sub = EXCLUDED.auth_sub,
                                        email = EXCLUDED.email,
                                        first_name = EXCLUDED.first_name,
                                        last_name = EXCLUDED.last_name
                                        RETURNING *;
  `;

  const result = await pool.query(query, [auth0_id, auth_sub, email, given_name, family_name]);

  try {
    const result = await pool.query(query, [auth0_id, email, given_name, family_name]);
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('DB sync error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

module.exports = router;
