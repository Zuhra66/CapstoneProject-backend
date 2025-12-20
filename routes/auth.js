// routes/auth.js - Fixed version with consistent JWT middleware
const express = require('express');
const router = express.Router();
const axios = require('axios');
const { pool } = require('../db');
const { decryptMessage } = require("../lib/messageCrypto");

// Import the SAME JWT middleware from admin-check
const { checkJwt } = require('../middleware/admin-check');

// Membership
const membershipRoutes = require("./memberships");
const getActiveMembershipForUser = membershipRoutes.getActiveMembershipForUser;

/**
 * Get complete user profile from Auth0 userinfo endpoint
 * This ensures we get the full profile including email, name, etc.
 */
async function getCompleteUserProfile(access_token) {
  try {
    const response = await axios.get(`https://${process.env.AUTH0_DOMAIN}/userinfo`, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });

    return response.data;
  } catch (error) {
    // Fallback to JWT decoding if userinfo endpoint fails
    const jwt = require('jsonwebtoken');
    const decoded = jwt.decode(access_token);
    return decoded || {};
  }
}

/**
 * Extract access token from request
 */
function getAccessTokenFromHeader(req) {
  if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
    return req.headers.authorization.split(' ')[1];
  }
  return null;
}

async function upsertUserFromAuth0(profile) {
  const auth0_id = profile.sub;

  // Extract provider from auth0_id (e.g., 'google-oauth2|12345' -> 'google-oauth2')
  const auth_provider = auth0_id.split('|')[0] || 'auth0';
  const auth_sub = auth0_id;

  // Use real data from Auth0 userinfo - these should now be available
  const email = profile.email || `${auth0_id}@temp.auth0user.com`;
  const name = profile.name || profile.nickname || 'User';
  const first_name = profile.given_name || profile.first_name || '';
  const last_name = profile.family_name || profile.last_name || '';

  try {
    // Check if user exists to preserve admin status
    const existingUser = await pool.query(
        'SELECT id, role, is_admin FROM users WHERE auth0_id = $1',
        [auth0_id]
    );

    let role = 'User';
    let is_admin = false;

    if (existingUser.rows.length > 0) {
      // Preserve existing role and admin status
      role = existingUser.rows[0].role || 'User';
      is_admin = existingUser.rows[0].is_admin === true;
    }

    const result = await pool.query(`
      INSERT INTO users (
        auth0_id, auth_provider, auth_sub, email, name, 
        first_name, last_name, is_active, role, is_admin
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8, $9)
      ON CONFLICT (auth0_id) 
      DO UPDATE SET 
        email = EXCLUDED.email, 
        name = EXCLUDED.name,
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name,
        auth_provider = EXCLUDED.auth_provider,
        auth_sub = EXCLUDED.auth_sub,
        updated_at = NOW()
      RETURNING id, email, name, first_name, last_name, role, is_admin, is_active, created_at, updated_at, auth_provider
    `, [
      auth0_id, auth_provider, auth_sub, email, name,
      first_name, last_name, role, is_admin
    ]);

    const user = { ...result.rows[0], auth0_id };
    return user;
  } catch (error) {
    console.error('Database error in upsertUserFromAuth0:', error);
    throw error;
  }
}

/* ----------------- routes ------------------ */

// GET /auth/me - Get current user info using Bearer token
router.get('/me', checkJwt, async (req, res) => {
  try {
    // Check if token is present and valid
    if (!req.auth || !req.auth.sub) {
      return res.status(200).json({ user: null, error: 'No valid authentication token' });
    }

    const accessToken = getAccessTokenFromHeader(req);
    if (!accessToken) {
      return res.status(401).json({ user: null, error: 'No access token provided' });
    }

    // Get complete user profile from Auth0 userinfo endpoint
    const completeProfile = await getCompleteUserProfile(accessToken);

    if (!completeProfile.sub) {
      return res.status(401).json({ user: null, error: 'Invalid user profile' });
    }

    const user = await upsertUserFromAuth0(completeProfile);

    const rawMembership = await getActiveMembershipForUser(user.id);

    const membership = rawMembership
        ? {
          id: rawMembership.id,
          status: rawMembership.status,
          provider: rawMembership.provider,
          plan_name: rawMembership.plan_name,
          plan_slug: rawMembership.plan_slug,
          start_date: rawMembership.start_at,
          end_date: rawMembership.end_at,
          interval: rawMembership.interval,
          paypal_subscription_id: rawMembership.paypal_subscription_id
        }
        : null;

    /* -------------------------------------------
      AUTO-LINK EXISTING APPOINTMENTS BY EMAIL
    ------------------------------------------- */
    try {
      // Normalize both sides
      const normalizedEmail = user.email.trim().toLowerCase();

      const linkRes = await pool.query(
          `UPDATE appointments
          SET user_id = $1, updated_at = NOW()
          WHERE LOWER(TRIM(email)) = $2 AND user_id IS NULL`,
          [user.id, normalizedEmail]
      );
    } catch (err) {
      // Silent fail for appointment linking
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
        is_admin: !!user.is_admin,
        is_active: user.is_active,
        created_at: user.created_at,
        updated_at: user.updated_at,
        auth_provider: user.auth_provider,
        membership
      }
    });
  } catch (err) {
    console.error('/me error:', err.message);

    if (err.name === 'UnauthorizedError') {
      return res.status(401).json({
        user: null,
        error: 'Invalid or expired token'
      });
    }

    res.status(500).json({
      user: null,
      error: 'Server error: ' + err.message
    });
  }
});

/* ===================================================
   GET /auth/me/messages
   Returns messages scoped to logged-in user
=================================================== */
router.get("/me/messages", checkJwt, async (req, res) => {
  try {
    // req.auth.sub is guaranteed by checkJwt
    const auth0Id = req.auth.sub;

    // Get DB user
    const userRes = await pool.query(
        "SELECT id, role, is_admin FROM users WHERE auth0_id = $1",
        [auth0Id]
    );

    if (userRes.rows.length === 0) {
      return res.status(404).json({ messages: [] });
    }

    const user = userRes.rows[0];
    const isAdmin = user.is_admin === true;

    const result = isAdmin
        ? await pool.query(`
          SELECT *
          FROM contact_messages
          WHERE deleted_at IS NULL
          ORDER BY created_at ASC
        `)
        : await pool.query(
            `
          SELECT *
          FROM contact_messages
          WHERE (sender_id = $1 OR receiver_id = $1)
            AND deleted_at IS NULL
          ORDER BY created_at ASC
        `,
            [user.id]
        );

    const messages = result.rows.map(row => ({
      id: row.id,
      sender_id: row.sender_id,
      receiver_id: row.receiver_id,
      sender_role: row.sender_role,
      text: decryptMessage({
        ciphertext: row.ciphertext,
        iv: row.iv,
        auth_tag: row.auth_tag,
      }),
      created_at: row.created_at,
      read_at: row.read_at,
    }));

    res.json({ messages });
  } catch (err) {
    console.error("/auth/me/messages error:", err);
    res.status(500).json({ messages: [], error: "Failed to load messages" });
  }
});

// POST /auth/logout
router.post('/logout', (req, res) => {
  res.clearCookie('refresh_token');
  res.clearCookie('access_token');
  res.json({ message: 'Logged out successfully' });
});

module.exports = router;