// routes/auth.js
const express = require('express');
const router = express.Router();

const { pool } = require('../db');
const { checkJwt } = require('../middleware/admin-check');

// Simple ping for debugging (optional)
router.get('/ping', (req, res) => {
  res.json({ ok: true });
});
// Membership
const membershipRoutes = require("./memberships");
const getActiveMembershipForUser = membershipRoutes.getActiveMembershipForUser;

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

// Handle preflight so browser doesn't get blocked
router.options('/me', (req, res) => {
  res.sendStatus(200);
});

// GET /api/auth/me
router.get('/me', checkJwt, async (req, res) => {
  try {
    // req.auth comes from express-oauth2-jwt-bearer via our checkJwt
    const payload = req.auth?.payload || req.auth || {};
    const sub = payload.sub;
    const email = payload.email;

    console.log('🔐 /api/auth/me DEBUG ==========');
    console.log('Token sub:', sub);
    console.log('Token email:', email);

    if (!sub) {
      return res.status(401).json({ error: 'Missing sub in token' });
    }

    // Look up user by auth0_id or auth_sub
    const q = `
      SELECT
        id,
        auth0_id,
        auth_sub,
        email,
        first_name,
        last_name,
        name,
        role,
        is_admin,
        is_active,
        auth_provider,
        created_at,
        updated_at
      FROM public.users
      WHERE auth0_id = $1 OR auth_sub = $1
      LIMIT 1
    `;
    const result = await pool.query(q, [sub]);

    if (result.rows.length === 0) {
      console.log('❌ /api/auth/me: user not found for sub', sub);
      return res.status(404).json({ error: 'User not found' });
    }

    const dbUser = result.rows[0];

    console.log('✅ /api/auth/me: user found:', {
      id: dbUser.id,
      email: dbUser.email,
      role: dbUser.role,
      is_admin: dbUser.is_admin,
      is_active: dbUser.is_active,
    });

    res.json({
      user: {
        id: dbUser.id,
        auth0_id: dbUser.auth0_id,
        auth_sub: dbUser.auth_sub,
        email: dbUser.email,
        first_name: dbUser.first_name,
        last_name: dbUser.last_name,
        name: dbUser.name,
        role: dbUser.role,
        is_admin: dbUser.is_admin,
        is_active: dbUser.is_active,
        auth_provider: dbUser.auth_provider,
        createdAt: dbUser.created_at,
        updatedAt: dbUser.updated_at,
      },
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
    console.error('Error in /api/auth/me:', err);
    res.status(500).json({ error: 'Failed to load auth user' });
  }
});

module.exports = router;
