// routes/auth.js
const express = require('express');
const router = express.Router();
const axios = require('axios');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { pool } = require('../db');

router.use(cookieParser());

const AUTH0_DOMAIN   = process.env.AUTH0_DOMAIN;
const AUTH0_TOKEN_URL = `https://${AUTH0_DOMAIN}/oauth/token`;
const AUTH0_USERINFO_URL = `https://${AUTH0_DOMAIN}/userinfo`;
const REDIRECT_URI   = `${process.env.AUTH0_BASE_URL}/auth/callback`;
const FRONTEND_URL   = process.env.FRONTEND_URL || '/';
const AUDIENCE       = process.env.AUTH0_AUDIENCE;

const COOKIE_NAME = 'refresh_token';
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production', // required for SameSite=None
  sameSite: 'None', // frontend and backend are on different domains
  maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  path: '/', // make available to all routes
};

// Optional: allow auto-admin by email list (comma-separated)
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

/* ------------------------- helpers ------------------------- */

async function exchangeAuthCodeForTokens(code) {
  const resp = await axios.post(
    AUTH0_TOKEN_URL,
    {
      grant_type: 'authorization_code',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      code,
      redirect_uri: REDIRECT_URI,
      audience: AUDIENCE,
    },
    { headers: { 'Content-Type': 'application/json' } }
  );
  return resp.data; // { access_token, refresh_token, id_token, expires_in, token_type }
}

async function refreshTokens(refresh_token) {
  const resp = await axios.post(
    AUTH0_TOKEN_URL,
    {
      grant_type: 'refresh_token',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      refresh_token,
      audience: AUDIENCE,
    },
    { headers: { 'Content-Type': 'application/json' } }
  );
  return resp.data; // { access_token, id_token?, expires_in, ... }
}

async function fetchUserinfo(access_token) {
  const resp = await axios.get(AUTH0_USERINFO_URL, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  return resp.data; // {sub, email, name, given_name, family_name, ...}
}

// Ensure a local user row exists; update name/email if changed.
// You can adapt this for your schema (users table/columns).
async function upsertUserFromProfile(profile) {
  const auth0_id = profile.sub; // e.g., "auth0|abc..."
  const email = (profile.email || '').toLowerCase();
  const name = profile.name || `${profile.given_name || ''} ${profile.family_name || ''}`.trim();

  // Is admin based on email allowlist (optional). DB can override later.
  const adminByEmail = ADMIN_EMAILS.includes(email);

  const result = await pool.query(
    `
    INSERT INTO users (auth0_id, email, name, is_active, role, is_admin)
    VALUES ($1, $2, $3, TRUE, COALESCE($4,'member'), $5)
    ON CONFLICT (auth0_id)
    DO UPDATE SET email = EXCLUDED.email, name = EXCLUDED.name, updated_at = NOW()
    RETURNING id, email, name, role, COALESCE(is_admin, false) AS is_admin
    `,
    [
      auth0_id,
      email,
      name,
      adminByEmail ? 'admin' : 'member',
      adminByEmail,
    ]
  );

  return { ...result.rows[0], auth0_id };
}

// Given an access token (JWT for your API), decode or fall back to /userinfo
async function getProfileFromAccessToken(access_token) {
  let decoded = null;
  try {
    decoded = jwt.decode(access_token) || null;
  } catch (_) {
    decoded = null;
  }
  // If we didn't get email/sub reliably, hit /userinfo
  if (!decoded?.sub || !decoded?.email) {
    const ui = await fetchUserinfo(access_token);
    return ui;
  }
  return decoded;
}

/* -------------------------- routes ------------------------- */

// Auth0 callback -> set refresh cookie, upsert user, redirect to app
router.get('/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code');

  try {
    const tokens = await exchangeAuthCodeForTokens(code);
    const { access_token, refresh_token } = tokens;

    if (!refresh_token) {
      console.error('No refresh token returned from Auth0.');
      return res.status(500).send('No refresh token received');
    }

    // Identify the user and ensure they exist locally
    const profile = await getProfileFromAccessToken(access_token);
    await upsertUserFromProfile(profile);

    // Store the refresh token securely
    res.cookie(COOKIE_NAME, refresh_token, COOKIE_OPTIONS);

    // Go back to the frontend
    res.redirect(FRONTEND_URL);
  } catch (err) {
    const data = err.response?.data || err.message;
    console.error('Auth callback error:', data);
    res.status(500).send('Authentication failed');
  }
});

// Exchange refresh cookie for a fresh access token
router.get('/session', async (req, res) => {
  try {
    const refreshToken = req.cookies[COOKIE_NAME];
    if (!refreshToken) return res.status(401).json({ error: 'Missing refresh token' });

    const { access_token, expires_in, id_token } = await refreshTokens(refreshToken);
    res.json({ accessToken: access_token, expiresIn: expires_in, idToken: id_token });
  } catch (err) {
    const data = err.response?.data || err.message;
    console.error('Session refresh error:', data);
    res.status(401).json({ error: 'Failed to refresh session' });
  }
});

// Frontend “who am I?” with raw token claims (debuggy; kept for compatibility)
router.get('/whoami', async (req, res) => {
  try {
    const refreshToken = req.cookies[COOKIE_NAME];
    if (!refreshToken) return res.status(401).json({ authenticated: false });

    const { access_token } = await refreshTokens(refreshToken);
    const decoded = await getProfileFromAccessToken(access_token);
    res.json({ authenticated: true, user: decoded });
  } catch (err) {
    console.error('whoami error:', err.response?.data || err.message);
    res.status(401).json({ authenticated: false });
  }
});

// 🚀 Preferred: app-friendly profile with DB role/is_admin
router.get('/me', async (req, res) => {
  try {
    const refreshToken = req.cookies[COOKIE_NAME];
    if (!refreshToken) return res.status(401).json({ user: null });

    const { access_token } = await refreshTokens(refreshToken);
    const profile = await getProfileFromAccessToken(access_token);

    // Ensure user exists and get DB flags
    const user = await upsertUserFromProfile(profile);

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        is_admin: !!user.is_admin,
        // (optionally) expose the sub to the client: auth0_id: user.auth0_id
      },
    });
  } catch (err) {
    console.error('/me error:', err.response?.data || err.message);
    res.status(401).json({ user: null });
  }
});

// Logout -> clear cookie & return Auth0 logout URL for client redirect
router.post('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { ...COOKIE_OPTIONS, maxAge: 0 });
  const returnTo = FRONTEND_URL;
  const logoutUrl = `https://${AUTH0_DOMAIN}/v2/logout?client_id=${process.env.AUTH0_CLIENT_ID}&returnTo=${encodeURIComponent(returnTo)}`;
  res.json({ logoutUrl });
});

module.exports = router;
