// routes/admin.js
const express = require("express");
const router = express.Router();
const pool = require("../db");
const checkJwt = require("../middleware/auth0-check");

router.use(checkJwt);

// Only allow admin role
const requireAdmin = async (req, res, next) => {
  try {
    const auth0Id = req.user.sub;
    const result = await pool.query(
        "SELECT role FROM users WHERE auth0_id = $1",
        [auth0Id]
    );
    if (!result.rows.length || result.rows[0].role !== "admin") {
      return res.status(403).json({ error: "Forbidden — admin access required" });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: "Database error", details: err.message });
  }
};

// List all users
router.get("/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
        `SELECT id, auth0_id, email, first_name, last_name, role, created_at, updated_at
       FROM users ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Database error", details: err.message });
  }
});

// Update user role
router.patch("/users/:id/role", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  if (!["member", "provider", "admin"].includes(role)) {
    return res.status(400).json({ error: "Invalid role value" });
  }
  try {
    const result = await pool.query(
        "UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, role",
        [role, id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Database error", details: err.message });
  }
});

// View user memberships
router.get("/users/:id/memberships", requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const query = `
      SELECT um.id, um.plan_id, mp.name AS plan_name, um.status, um.start_date, um.end_date
      FROM user_memberships um
      JOIN membership_plans mp ON mp.id = um.plan_id
      WHERE um.user_id = $1
      ORDER BY um.start_date DESC;
    `;
    const result = await pool.query(query, [id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Database error", details: err.message });
  }
});

module.exports = router;
