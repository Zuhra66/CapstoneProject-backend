// routes/admin.js
const express = require('express');
const router = express.Router();
const pool = require('../db');
const checkJwt = require('../middleware/auth0-check');

router.use(checkJwt);

// Only allow users with admin role
const requireAdmin = async (req, res, next) => {
  try {
    const auth0Id = req.user.sub;
    const result = await pool.query('SELECT role FROM users WHERE auth0_id = $1', [auth0Id]);
    if (result.rows.length === 0 || result.rows[0].role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden — admin access required' });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err.message });
  }
};

// -------------------- USERS --------------------

// List all users
router.get('/users', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
        `SELECT id, auth0_id, email, first_name, last_name, role, created_at, updated_at
       FROM users
       ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

// Update user role
router.patch('/users/:id/role', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  if (!['member', 'provider', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role value' });
  }

  try {
    const result = await pool.query(
        `UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, role`,
        [role, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

// -------------------- MEMBERSHIPS --------------------

// View user memberships
router.get('/users/:id/memberships', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
        `SELECT um.id, um.membership_plan_id AS plan_id, mp.name AS plan_name, um.status, um.start_date, um.end_date
       FROM user_memberships um
       JOIN membership_plans mp ON mp.id = um.membership_plan_id
       WHERE um.user_id = $1
       ORDER BY um.start_date DESC`,
        [id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

// Create new membership
router.post('/users/:id/memberships', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { membership_plan_id, status, start_date, end_date } = req.body;

  if (!membership_plan_id || !status || !start_date || !end_date) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const result = await pool.query(
        `INSERT INTO user_memberships
       (user_id, membership_plan_id, status, start_date, end_date, created_at)
       VALUES ($1,$2,$3,$4,$5,NOW())
       RETURNING *`,
        [id, membership_plan_id, status, start_date, end_date]
    );
    res.json({ success: true, membership: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

// Update membership
router.patch('/users/:id/memberships/:membershipId', requireAdmin, async (req, res) => {
  const { id, membershipId } = req.params;
  const { status, start_date, end_date, membership_plan_id } = req.body;

  try {
    const result = await pool.query(
        `UPDATE user_memberships
       SET status = $1, start_date = $2, end_date = $3, membership_plan_id = $4, updated_at = NOW()
       WHERE id = $5 AND user_id = $6
       RETURNING *`,
        [status, start_date, end_date, membership_plan_id, membershipId, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Membership not found' });
    res.json({ success: true, membership: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

// Delete membership
router.delete('/users/:id/memberships/:membershipId', requireAdmin, async (req, res) => {
  const { id, membershipId } = req.params;

  try {
    const result = await pool.query(
        `DELETE FROM user_memberships
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
        [membershipId, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Membership not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

module.exports = router;
