const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const authCheck = require('../middleware/authCheck');

const createJwtAndSetCookie = (res, payload) => {
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' });
  const secureFlag = process.env.NODE_ENV === 'production';
  res.cookie('token', token, {
    httpOnly: true,
    secure: secureFlag,
    sameSite: 'strict',
    maxAge: 2 * 60 * 60 * 1000
  });
};

// Local signup
router.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 12);
  const result = await pool.query(
      'INSERT INTO users(email, password_hash, created_at) VALUES($1,$2,NOW()) RETURNING id,email',
      [email, hashed]
  );
  createJwtAndSetCookie(res, { sub: result.rows[0].id, email: result.rows[0].email });
  res.json({ success: true });
});

// Local login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT id, email, password_hash FROM users WHERE email=$1', [email]);
  if (result.rowCount === 0) return res.status(401).json({ error: 'Invalid credentials' });
  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  createJwtAndSetCookie(res, { sub: user.id, email: user.email });
  res.json({ success: true });
});

// Auth0 token verification
router.get('/profile', authCheck, async (req, res) => {
  const email = req.user?.email;
  if (!email) return res.status(400).json({ error: 'Missing email in token' });
  const user = await pool.query('SELECT id, email, provider, created_at FROM users WHERE email=$1', [email]);
  res.json({ authenticated: true, user: user.rows[0] || { email } });
});

// Logout
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// Optional: Dummy Google route to stop 404
router.get('/google', (req, res) => {
  res.status(200).send('Use frontend Auth0 login at ' + process.env.FRONTEND_URL);
});

module.exports = router;
