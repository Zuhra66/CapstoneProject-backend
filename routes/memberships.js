const express = require("express");
const router = express.Router();
const { pool } = require("../db");
const checkJwt = require('../middleware/auth0-check');

// =============================
// INTERNAL SERVICE FUNCTIONS
// =============================

async function getActiveMembershipForUser(userId) {
  const sql = `
    SELECT 
      um.status,
      um.start_at AS start_date,
      um.end_at AS end_date,
      um.provider,
      mp.name AS plan_name,
      mp.interval
    FROM user_memberships um
    LEFT JOIN membership_plans mp ON um.plan_id = mp.id
    WHERE um.user_id = $1
    ORDER BY um.updated_at DESC
    LIMIT 1;
  `;
  
  const result = await pool.query(sql, [userId]);
  return result.rows[0] || null;
}

async function activateMembership(userId, planId, provider, externalRef = null) {
  const sql = `
    INSERT INTO user_memberships (user_id, plan_id, status, provider, external_ref, start_at, end_at)
    VALUES ($1, $2, 'active', $3, $4, NOW(), NOW() + INTERVAL '1 month')
    ON CONFLICT (user_id)
    DO UPDATE SET 
      status = 'active',
      provider = $3,
      external_ref = $4,
      start_at = NOW(),
      end_at = NOW() + INTERVAL '1 month',
      updated_at = NOW();
  `;

  await pool.query(sql, [userId, planId, provider, externalRef]);

  // Automatically assign role = 'Member'
  await pool.query(
    `UPDATE users SET role = 'Member', updated_at = NOW()
     WHERE id = $1`,
    [userId]
  );
}

async function cancelMembership(userId) {
  await pool.query(
    `UPDATE user_memberships
     SET status = 'cancelled', end_at = NOW(), updated_at = NOW()
     WHERE user_id = $1`,
    [userId]
  );

  // Revert role back to User
  await pool.query(
    `UPDATE users SET role = 'User', updated_at = NOW()
     WHERE id = $1`,
    [userId]
  );
}

// =============================
// CANCEL MEMBERSHIP (USER)
// =============================
router.post("/cancel", checkJwt, async (req, res) => {
  console.log("🔥 [CANCEL] Hit /membership/cancel route");

  try {
    // 1. Validate JWT + extract Auth0 ID
    if (!req.auth || !req.auth.sub) {
      console.log("❌ [CANCEL] Missing req.auth.sub");
      return res.status(401).json({ error: "Unauthorized" });
    }

    const auth0Id = req.auth.sub;
    console.log("🔑 [CANCEL] Auth0 ID:", auth0Id);

    // 2. Lookup internal user ID
    const userLookup = await pool.query(
      "SELECT id FROM users WHERE auth0_id = $1 LIMIT 1",
      [auth0Id]
    );

    console.log("🧪 [CANCEL] User lookup:", userLookup.rows);

    if (!userLookup.rows.length) {
      console.log("❌ [CANCEL] User not found in DB");
      return res.status(404).json({ error: "User not found" });
    }

    const userId = userLookup.rows[0].id;
    console.log("👤 [CANCEL] Internal userId =", userId);

    // 3. Cancel membership + update role
    console.log("🛑 [CANCEL] Updating membership + role...");

    await pool.query(
      `UPDATE user_memberships
       SET status = 'cancelled', end_at = NOW(), updated_at = NOW()
       WHERE user_id = $1`,
      [userId]
    );

    const roleUpdate = await pool.query(
      `UPDATE users
       SET role = 'User', updated_at = NOW()
       WHERE id = $1
       RETURNING role`,
      [userId]
    );

    console.log("🎭 [CANCEL] Role updated to:", roleUpdate.rows[0].role);

    // 4. Success response
    console.log("✅ [CANCEL] Membership cancelled successfully!");

    return res.json({
      success: true,
      message: "Membership cancelled",
    });

  } catch (err) {
    console.error("🔥 [CANCEL ERROR] Unexpected error:", err);
    return res.status(500).json({ error: "Failed to cancel membership" });
  }
});


async function markMembershipPastDue(userId) {
  await pool.query(
    `UPDATE user_memberships
     SET status = 'past_due', updated_at = NOW()
     WHERE user_id = $1;`,
    [userId]
  );
}

async function markMembershipFailed(userId) {
  await pool.query(
    `UPDATE user_memberships
     SET status = 'failed', updated_at = NOW()
     WHERE user_id = $1`,
    [userId]
  );

  await pool.query(
    `UPDATE users SET role = 'User', updated_at = NOW()
     WHERE id = $1`,
    [userId]
  );
}


// =============================
// ROUTES
// =============================

// Get all plans
router.get("/plans", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM membership_plans WHERE is_active = TRUE ORDER BY price_cents ASC;"
    );
    res.json({ plans: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Failed to load plans" });
  }
});

// Get logged-in user's membership
router.get("/me", checkJwt, async (req, res) => {
  try {
    const auth0Id = req.auth.sub;

    const lookup = await pool.query("SELECT id FROM users WHERE auth0_id = $1", [
      auth0Id,
    ]);

    if (!lookup.rows.length) {
      return res.json({ membership: null });
    }

    const membership = await getActiveMembershipForUser(lookup.rows[0].id);
    res.json({ membership });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch membership" });
  }
});

// Local test webhook
router.get("/test-event", async (req, res) => {
  let { userId, planId, event } = req.query;

  try {
    // Auto-create a plan if none provided
    if (!planId) {
      const slugBase = "temp-plan-" + Date.now();

      const result = await pool.query(`
        INSERT INTO membership_plans (name, slug, price_cents, interval)
        VALUES ($1, $2, 0, 'monthly')
        ON CONFLICT (slug) DO NOTHING
        RETURNING id;
      `, ["Temp Test Plan", slugBase]);

      // Use the newly created plan OR pick any existing plan
      if (result.rows[0]) {
        planId = result.rows[0].id;
      } else {
        const existing = await pool.query(`SELECT id FROM membership_plans LIMIT 1;`);
        planId = existing.rows[0]?.id;
      }

      if (!planId) {
        return res.status(500).json({ error: "No plan could be created or found" });
      }
    }

    // Fake webhook behavior
    if (event === "success") {
      await activateMembership(userId, planId, "local_test", "ref_test");
    } else if (event === "cancelled") {
      await cancelMembership(userId);
    } else if (event === "past_due") {
      await markMembershipPastDue(userId);
    } else if (event === "failed") {
      await markMembershipFailed(userId);
    } else {
      return res.status(400).json({ error: "Invalid event" });
    }

    res.json({ ok: true, planId });

  } catch (err) {
    console.error("🔥 Test event error:", err);
    res.status(500).json({ error: "Test event failed", details: err.message });
  }
});


// Admin update
router.post("/admin/update", checkJwt, async (req, res) => {
  const { userId, status } = req.body;

  try {
    await pool.query(
      `
      UPDATE user_memberships
      SET status = $1, updated_at = NOW()
      WHERE user_id = $2;
      `,
      [status, userId]
    );

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Admin update failed" });
  }
});

router.getActiveMembershipForUser = getActiveMembershipForUser;
module.exports = router;
