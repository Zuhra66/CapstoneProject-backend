const express = require("express");
const router = express.Router();
const { pool } = require("../db");
const checkJwt = require('../middleware/auth0-check');
const { cancelPaypalSubscription } = require("../lib/paypal");
const { verifyPaypalWebhook } = require("../lib/paypal");

const { createSubscription } = require("../lib/paypal");

const PAYPAL_PLANS = {
  general: process.env.PAYPAL_GENERAL_PLAN_ID,
  student: process.env.PAYPAL_STUDENT_PLAN_ID,
};

/* ======================================================
   INTERNAL SERVICE FUNCTIONS
====================================================== */

async function getActiveMembershipForUser(userId) {
  const sql = `
    SELECT
      um.id,
      um.status,
      um.provider,
      um.paypal_subscription_id,
      um.start_at,
      um.end_at,
      mp.name AS plan_name,
      mp.slug AS plan_slug,
      mp.interval
    FROM user_memberships um
    LEFT JOIN membership_plans mp ON um.plan_id = mp.id
    WHERE um.user_id = $1
    ORDER BY um.updated_at DESC
    LIMIT 1;
  `;
  const { rows } = await pool.query(sql, [userId]);
  return rows[0] || null;
}

async function activateMembership(userId, planId, provider, paypalSubId = null) {
  const isPaypal = provider === "paypal";

  await pool.query(
      `
    INSERT INTO user_memberships (
      user_id,
      plan_id,
      status,
      provider,
      paypal_subscription_id,
      start_at,
      end_at
    )
    VALUES (
      $1,
      $2,
      'active',
      $3,
      $4,
      NOW(),
      ${isPaypal ? "NULL" : "NOW() + INTERVAL '1 month'"}
    )
    ON CONFLICT (user_id)
    DO UPDATE SET
      plan_id = EXCLUDED.plan_id,
      status = 'active',
      provider = $3,
      paypal_subscription_id = $4,
      start_at = NOW(),
      end_at = ${isPaypal ? "NULL" : "NOW() + INTERVAL '1 month'"},
      updated_at = NOW();
    `,
      [userId, planId, provider, paypalSubId]
  );

  await pool.query(
      `UPDATE users SET role = 'Member', updated_at = NOW() WHERE id = $1`,
      [userId]
  );
}

async function markMembershipPastDue(userId) {
  await pool.query(
      `UPDATE user_memberships SET status = 'past_due', updated_at = NOW()
     WHERE user_id = $1`,
      [userId]
  );
}

async function markMembershipFailed(userId) {
  await pool.query(
      `
    UPDATE user_memberships
    SET status = 'past_due',
        updated_at = NOW()
    WHERE user_id = $1
    `,
      [userId]
  );
}

async function cancelMembership(userId) {
  // Cancel membership only if not already cancelled
  const result = await pool.query(
      `
    UPDATE user_memberships
    SET
      status = 'cancelled',
      end_at = COALESCE(end_at, NOW()),
      updated_at = NOW()
    WHERE user_id = $1
      AND status != 'cancelled'
    `,
      [userId]
  );

  // Downgrade role only if needed
  await pool.query(
      `
    UPDATE users
    SET role = 'User',
        updated_at = NOW()
    WHERE id = $1
      AND role != 'User'
    `,
      [userId]
  );
}

async function getInternalPlanIdFromPaypalPlan(paypalPlanId) {
  const { rows } = await pool.query(
      `
    SELECT id
    FROM membership_plans
    WHERE paypal_plan_id = $1
      AND is_active = TRUE
    LIMIT 1
    `,
      [paypalPlanId]
  );

  if (!rows.length) {
    throw new Error(`No membership plan found for PayPal plan ${paypalPlanId}`);
  }

  return rows[0].id;
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

// =============================
// CANCEL MEMBERSHIP (USER)
// =============================
router.post("/cancel", checkJwt, async (req, res) => {
  try {
    const auth0Id = req.auth.sub;

    const userRes = await pool.query(
        "SELECT id FROM users WHERE auth0_id = $1",
        [auth0Id]
    );

    if (!userRes.rows.length) {
      return res.status(404).json({ error: "User not found" });
    }

    const userId = userRes.rows[0].id;
    const membership = await getActiveMembershipForUser(userId);

    if (!membership) {
      return res.json({ success: true, message: "No active membership" });
    }

    // Cancel PayPal if applicable
    if (
        membership.provider === "paypal" &&
        membership.paypal_subscription_id
    ) {
      await cancelPaypalSubscription(membership.paypal_subscription_id);
    }

    // Always cancel locally
    await cancelMembership(userId);

    res.json({ success: true, message: "Membership cancelled" });
  } catch (err) {
    console.error("User cancel error:", err);
    res.status(500).json({ error: "Failed to cancel membership" });
  }
});

// =============================
// ADMIN: ASSIGN MEMBERSHIP
// =============================
router.post("/admin/assign", checkJwt, async (req, res) => {
  const { userId, membershipType } = req.body;

  if (!userId || !membershipType) {
    return res.status(400).json({ error: "Missing userId or membershipType" });
  }

  try {
    await pool.query("BEGIN");

    // ASSIGN STUDENT / GENERAL
    const planRes = await pool.query(
        `SELECT id FROM membership_plans WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
        [membershipType]
    );

    if (!planRes.rows.length) {
      throw new Error("Membership plan not found");
    }

    const planId = planRes.rows[0].id;

    await pool.query(
        `
      INSERT INTO user_memberships (
        user_id,
        plan_id,
        status,
        provider,
        paypal_subscription_id,
        start_at,
        end_at
      )
      VALUES ($1, $2, 'active', 'admin_override', NULL, NOW(), NOW() + INTERVAL '1 month')
      ON CONFLICT (user_id)
      DO UPDATE SET
        plan_id = EXCLUDED.plan_id,
        status = 'active',
        provider = 'admin_override',
        paypal_subscription_id = NULL,
        start_at = NOW(),
        end_at = NOW() + INTERVAL '1 month',
        updated_at = NOW()
      `,
        [userId, planId]
    );

    await pool.query(
        `UPDATE users SET role = 'Member', updated_at = NOW() WHERE id = $1`,
        [userId]
    );

    await pool.query("COMMIT");
    res.json({ success: true, action: "assigned" });

  } catch (err) {
    await pool.query("ROLLBACK");
    console.error("Admin assign membership error:", err);
    res.status(500).json({ error: "Failed to assign membership" });
  }
});

// =============================
// ADMIN: CANCEL MEMBERSHIP
// =============================
router.post("/admin/cancel", checkJwt, async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: "Missing userId" });
    }

    // Get latest membership
    const membership = await getActiveMembershipForUser(userId);

    if (!membership || membership.status !== "active") {
      return res.json({ success: true, message: "No active membership" });
    }

    // Cancel PayPal subscription if applicable
    if (
        membership.provider === "paypal" &&
        membership.paypal_subscription_id
    ) {
      await cancelPaypalSubscription(membership.paypal_subscription_id);
    }

    // Always cancel locally
    await cancelMembership(userId);

    res.json({ success: true, message: "Membership cancelled by admin" });

  } catch (err) {
    console.error("Admin cancel membership error:", err);
    res.status(500).json({ error: "Failed to cancel membership" });
  }
});

router.post("/paypal", async (req, res) => {
  try {
    // Verification temporarily disabled (OK for testing)
    // const isValid = await verifyPaypalWebhook(req);
    // if (!isValid) {
    //   return res.sendStatus(400);
    // }

    const event = req.body;

    const subscriptionId = event.resource?.id;
    const userId = event.resource?.custom_id;
    const planId = event.resource?.plan_id;

    if (!subscriptionId || !userId) {
      return res.sendStatus(200);
    }

    switch (event.event_type) {
      case "BILLING.SUBSCRIPTION.ACTIVATED": {
        const internalPlanId =
            await getInternalPlanIdFromPaypalPlan(planId);
        await activateMembership(
            userId,
            internalPlanId,
            "paypal",
            subscriptionId
        );
        break;
      }

      case "BILLING.SUBSCRIPTION.CANCELLED":
        await cancelMembership(userId);
        break;

      case "BILLING.SUBSCRIPTION.SUSPENDED":
        await markMembershipPastDue(userId);
        break;

      case "BILLING.SUBSCRIPTION.PAYMENT.FAILED":
        await markMembershipFailed(userId);
        break;

      case "BILLING.SUBSCRIPTION.RE-ACTIVATED": {
        const internalPlanId =
            await getInternalPlanIdFromPaypalPlan(planId);
        await activateMembership(
            userId,
            internalPlanId,
            "paypal",
            subscriptionId
        );
        break;
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error("PayPal Webhook Error:", err);
    res.sendStatus(500);
  }
});

router.post("/paypal/create", checkJwt, async (req, res) => {
  try {
    const planType = req.body.planType?.toLowerCase();

    if (!PAYPAL_PLANS[planType]) {
      return res.status(400).json({ error: "Invalid plan type" });
    }

    // Find internal user
    const auth0Id = req.auth.sub;
    const userRes = await pool.query(
        "SELECT id FROM users WHERE auth0_id = $1",
        [auth0Id]
    );

    if (!userRes.rows.length) {
      return res.status(404).json({ error: "User not found" });
    }

    const userId = userRes.rows[0].id;

    const existing = await getActiveMembershipForUser(userId);

    if (existing && existing.status === "active") {
      return res.status(409).json({
        error: "You already have an active membership",
      });
    }

    // Create PayPal subscription
    const subscription = await createSubscription({
      planId: PAYPAL_PLANS[planType],
      userId,
    });

    // Return approval URL
    const approvalLink = subscription.links.find(
        (l) => l.rel === "approve"
    )?.href;

    if (!approvalLink) {
      return res.status(500).json({ error: "No approval link returned from PayPal" });
    }

    res.json({ approvalUrl: approvalLink });
  } catch (err) {
    console.error("PayPal create error:", err.response?.data || err);
    res.status(500).json({ error: "Failed to create subscription" });
  }
});

router.getActiveMembershipForUser = getActiveMembershipForUser;
module.exports = router;