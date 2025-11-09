// routes/profile.js (or in /routes/auth use a new endpoint)
const express = require('express');
const router = express.Router();
const checkJwt = require('../middleware/auth0-check');
const pool = require('../db');

router.get('/profile', checkJwt, async (req, res) => {
  // Auth0 puts the user sub in req.auth.sub
  const auth0Id = req.auth && req.auth.sub;
  if (!auth0Id) return res.status(400).json({ error: 'Missing sub' });

  const result = await pool.query('SELECT id, auth0_id, email, first_name, last_name, provider FROM users WHERE auth0_id=$1', [auth0Id]);
  if (result.rowCount === 0) {
    return res.json({ authenticated: true, user: { auth0Id } });
  }

  res.json({ authenticated: true, user: result.rows[0] });
});

module.exports = router;
