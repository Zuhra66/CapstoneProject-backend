// routes/messages.js
const express = require("express");
const { pool } = require("../db");
const requireAdmin = require("../middleware/requireAdmin");
const { encryptMessage, decryptMessage } = require("../lib/messageCrypto");

const router = express.Router();

/* ===================================================
   USER → ADMIN : Send message
   POST /messages/user-send
=================================================== */
router.post("/user-send", async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Message required" });
    }

    // Find an admin (role OR is_admin)
    const { rows: adminRows } = await pool.query(
      `SELECT id
       FROM users
       WHERE is_admin = TRUE OR role = 'Administrator'
       ORDER BY created_at ASC
       LIMIT 1`
    );

    if (!adminRows.length) {
      return res.status(500).json({ error: "No admin user found" });
    }

    const adminId = adminRows[0].id;
    const { ciphertext, iv, auth_tag } = encryptMessage(message.trim());

    const { rows } = await pool.query(
      `INSERT INTO contact_messages
        (sender_id, receiver_id, sender_role, ciphertext, iv, auth_tag)
       VALUES ($1, $2, 'user', $3, $4, $5)
       RETURNING id`,
      [req.user.id, adminId, ciphertext, iv, auth_tag]
    );

    res.json({ success: true, messageId: rows[0].id });
  } catch (err) {
    console.error("user-send error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ===================================================
   USER : View own messages
   GET /messages/user
=================================================== */
router.get("/user", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT *
       FROM contact_messages
       WHERE (sender_id = $1 OR receiver_id = $1)
         AND deleted_at IS NULL
       ORDER BY created_at ASC`,
      [req.user.id]
    );

    const messages = rows.map((row) => ({
      id: row.id,
      sender_id: row.sender_id,
      receiver_id: row.receiver_id,
      sender_role: row.sender_role,
      text: decryptMessage(row),
      created_at: row.created_at,
      read_at: row.read_at,
    }));

    // mark received unread as read
    const unreadIds = rows
      .filter(
        (r) => r.receiver_id === req.user.id && !r.read_at
      )
      .map((r) => r.id);

    if (unreadIds.length) {
      await pool.query(
        `UPDATE contact_messages
         SET read_at = NOW()
         WHERE id = ANY($1::uuid[])`,
        [unreadIds]
      );
    }

    res.json({ messages });
  } catch (err) {
    console.error("user messages error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ===================================================
   ADMIN : View all messages
   GET /messages/admin
=================================================== */
router.get("/admin", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        cm.id,
        cm.sender_id,
        cm.receiver_id,
        cm.sender_role,
        u1.email AS sender_email,
        u2.email AS receiver_email,
        cm.ciphertext,
        cm.iv,
        cm.auth_tag,
        cm.created_at,
        cm.read_at
      FROM contact_messages cm
      LEFT JOIN users u1 ON u1.id = cm.sender_id
      LEFT JOIN users u2 ON u2.id = cm.receiver_id
      ORDER BY cm.created_at ASC
    `);

    const messages = result.rows.map((row) => {
      const text = decryptMessage({
        ciphertext: row.ciphertext,
        iv: row.iv,
        auth_tag: row.auth_tag,
      });

      return {
        id: row.id,
        sender_id: row.sender_id,
        receiver_id: row.receiver_id,
        sender_role: row.sender_role,
        sender_email: row.sender_email,
        receiver_email: row.receiver_email,
        text, 
        created_at: row.created_at,
        read_at: row.read_at,
      };
    });

    res.json({ messages });
  } catch (err) {
    console.error("Admin message fetch error:", err);
    res.status(500).json({ error: "Failed to load messages" });
  }
});

/* ===================================================
   ADMIN → USER : Send reply
   POST /messages/admin-send
=================================================== */
router.post("/admin-send", requireAdmin, async (req, res) => {
  try {
    const { userId, message } = req.body;

    if (!userId || !message || !message.trim()) {
      return res.status(400).json({ error: "userId and message required" });
    }

    const { rows: userRows } = await pool.query(
      "SELECT id FROM users WHERE id = $1",
      [userId]
    );

    if (!userRows.length) {
      return res.status(404).json({ error: "User not found" });
    }

    const { ciphertext, iv, auth_tag } = encryptMessage(message.trim());

    const { rows } = await pool.query(
      `INSERT INTO contact_messages
        (sender_id, receiver_id, sender_role, ciphertext, iv, auth_tag)
       VALUES ($1, $2, 'admin', $3, $4, $5)
       RETURNING id`,
      [req.user.id, userId, ciphertext, iv, auth_tag]
    );

    res.json({ success: true, messageId: rows[0].id });
  } catch (err) {
    console.error("admin-send error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ===================================================
   ADMIN : Search users by email
   GET /messages/admin-users?email=...
=================================================== */
router.get("/admin-users", requireAdmin, async (req, res) => {
  try {
    const { email } = req.query;

    if (!email) {
      return res.status(400).json({ error: "Email query required" });
    }

    const { rows } = await pool.query(
      `SELECT id, email, name
       FROM users
       WHERE LOWER(email) LIKE LOWER($1)
       ORDER BY email
       LIMIT 10`,
      [`%${email}%`]
    );

    res.json({ users: rows });
  } catch (err) {
    console.error("admin-users error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
