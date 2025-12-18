// middleware/attachUser.js
const { pool } = require("../db");

async function attachUser(req, res, next) {
  try {
    if (!req.auth || !req.auth.sub) {
      return res.status(401).json({ error: "Missing auth subject" });
    }

    const auth0Id = req.auth.sub;

    const { rows } = await pool.query(
      "SELECT * FROM users WHERE auth0_id = $1",
      [auth0Id]
    );

    if (!rows.length) {
      return res.status(401).json({ error: "User not found in database" });
    }

    const user = rows[0];

    // ✅ Attach canonical user
    req.user = user;

    // ✅ BRIDGE: make requireAdmin happy
    if (user.is_admin === true || user.role === "Administrator") {
      req.adminUser = user;
    }

    next();
  } catch (err) {
    console.error("attachUser error:", err);
    res.status(500).json({ error: "Server error" });
  }
}

module.exports = attachUser;
