// routes/auth.js - Production-ready version
const express = require('express');
const router = express.Router();
const axios = require('axios');
const { pool } = require('../db');

// Import the SAME JWT middleware from admin-check
const { checkJwt } = require('../middleware/admin-check');

// Membership
const membershipRoutes = require("./memberships");
const getActiveMembershipForUser = membershipRoutes.getActiveMembershipForUser;

// --- ADDED FROM SECOND FILE ---
// Simple ping for debugging
router.get('/ping', (req, res) => {
  res.json({ ok: true });
});

// Handle preflight for CORS
router.options('/me', (req, res) => {
  res.sendStatus(200);
});
// --- END ADDITIONS ---

/**
 * Get complete user profile from Auth0 userinfo endpoint
 * This ensures we get the full profile including email, name, etc.
 */
async function getCompleteUserProfile(access_token) {
  try {
    console.log('🔍 Fetching complete user profile from Auth0...');
    const response = await axios.get(`https://${process.env.AUTH0_DOMAIN}/userinfo`, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });

    console.log('✅ Full user profile received:', response.data);
    return response.data;
  } catch (error) {
    console.error('❌ Failed to fetch userinfo from Auth0:', error.message);
    console.error('❌ Auth0 response:', error.response?.data);

    // Fallback to JWT decoding if userinfo endpoint fails
    const jwt = require('jsonwebtoken');
    const decoded = jwt.decode(access_token);
    console.log('🔄 Falling back to JWT decoding:', decoded);
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

  console.log('🔄 Upserting user from Auth0 with complete profile:', {
    auth0_id,
    auth_provider,
    auth_sub,
    email,
    name,
    first_name,
    last_name,
    hasEmail: !!profile.email,
    hasName: !!profile.name
  });

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
      console.log('📋 Found existing user:', { role, is_admin });
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
    console.log('✅ User upserted successfully:', {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      is_admin: user.is_admin,
      created_at: user.created_at,
      updated_at: user.updated_at
    });
    return user;
  } catch (error) {
    console.error('❌ Database error in upsertUserFromAuth0:', error);
    throw error;
  }
}

/* ----------------- routes ------------------ */

// GET /auth/me - Get current user info using Bearer token
router.get('/me', checkJwt, async (req, res) => {
  try {
    console.log('🔐 /auth/me called');

    // Check if token is present and valid
    if (!req.auth || !req.auth.sub) {
      console.log('❌ No valid JWT token found');
      return res.status(200).json({ user: null, error: 'No valid authentication token' });
    }

    const accessToken = getAccessTokenFromHeader(req);
    if (!accessToken) {
      console.log('❌ No access token found in header');
      return res.status(401).json({ user: null, error: 'No access token provided' });
    }

    console.log('👤 Auth0 JWT payload (basic):', {
      sub: req.auth.sub,
      email: req.auth.email
    });

    // Get complete user profile from Auth0 userinfo endpoint
    const completeProfile = await getCompleteUserProfile(accessToken);

    if (!completeProfile.sub) {
      console.log('❌ No user sub in complete profile');
      return res.status(401).json({ user: null, error: 'Invalid user profile' });
    }

    console.log('👤 Complete user profile:', {
      sub: completeProfile.sub,
      email: completeProfile.email,
      name: completeProfile.name,
      given_name: completeProfile.given_name,
      family_name: completeProfile.family_name
    });

    const user = await upsertUserFromAuth0(completeProfile);

    console.log("🔐 Logged-in user:", user);
    const membership = await getActiveMembershipForUser(user.id);

    /* -------------------------------------------
      🔗 AUTO-LINK EXISTING APPOINTMENTS BY EMAIL - MAY NEED TO REMOVE WILL TEST FURTHER
    ------------------------------------------- */
    try {
      // Normalize both sides
      const normalizedEmail = user.email.trim().toLowerCase();
      console.log("🔗 Normalized email for linking:", normalizedEmail);

      const linkRes = await pool.query(
          `UPDATE appointments
        SET user_id = $1, updated_at = NOW()
        WHERE LOWER(TRIM(email)) = $2 AND user_id IS NULL`,
          [user.id, normalizedEmail]
      );

      console.log(`🔗 Linked ${linkRes.rowCount} appointments to user ${user.email}`);
    } catch (err) {
      console.error("❌ Linking error:", err);
    }

    console.log('✅ Authentication successful for user:', user.email);

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
    console.error('❌ /me error:', err.message);
    console.error('❌ Full error details:', err);

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

// POST /auth/logout
router.post('/logout', (req, res) => {
  console.log('🚪 Clearing auth cookies');
  res.clearCookie('refresh_token');
  res.clearCookie('access_token');
  res.json({ message: 'Logged out successfully' });
});

module.exports = router;