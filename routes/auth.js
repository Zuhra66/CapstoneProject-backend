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
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'None',
  maxAge: 30 * 24 * 60 * 60 * 1000,
  path: '/',
};

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

async function exchangeAuthCodeForTokens(code) {
  const resp = await axios.post(AUTH0_TOKEN_URL, {
    grant_type: 'authorization_code',
    client_id: process.env.AUTH0_CLIENT_ID,
    client_secret: process.env.AUTH0_CLIENT_SECRET,
    code,
    redirect_uri: REDIRECT_URI,
    audience: AUDIENCE,
  }, { headers: { 'Content-Type': 'application/json' } });
  return resp.data;
}

async function refreshTokens(refresh_token) {
  const resp = await axios.post(AUTH0_TOKEN_URL, {
    grant_type: 'refresh_token',
    client_id: process.env.AUTH0_CLIENT_ID,
    client_secret: process.env.AUTH0_CLIENT_SECRET,
    refresh_token,
    audience: AUDIENCE,
  }, { headers: { 'Content-Type': 'application/json' } });
  return resp.data;
}

async function fetchUserinfo(access_token) {
  const resp = await axios.get(AUTH0_USERINFO_URL, {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  return resp.data;
}

async function upsertUserFromProfile(profile) {
  const auth0_id = profile.sub;
  const email = (profile.email || '').toLowerCase();
  const name = profile.name || `${profile.given_name || ''} ${profile.family_name || ''}`.trim();
  const adminByEmail = ADMIN_EMAILS.includes(email);

  const result = await pool.query(`
    INSERT INTO users (auth0_id, email, name, is_active, role, is_admin)
    VALUES ($1,$2,$3,TRUE,COALESCE($4,'member'),$5)
    ON CONFLICT (auth0_id)
    DO UPDATE SET email=EXCLUDED.email, name=EXCLUDED.name, updated_at=NOW()
    RETURNING id,email,name,role,COALESCE(is_admin,false) AS is_admin
  `, [auth0_id,email,name, adminByEmail?'Administrator':'member', adminByEmail]);

  return { ...result.rows[0], auth0_id };
}

async function getProfileFromAccessToken(access_token) {
  let decoded = null;
  try { decoded = jwt.decode(access_token) || null; } catch(_) { decoded=null; }
  if (!decoded?.sub || !decoded?.email) return await fetchUserinfo(access_token);
  return decoded;
}

/* ----------------- routes ------------------ */

// /auth/me now works using refresh_token cookie, sends DB flags
router.get('/me', async (req,res)=>{
  try {
    const refreshToken = req.cookies[COOKIE_NAME];
    if (!refreshToken) return res.status(401).json({ user: null });

    const { access_token } = await refreshTokens(refreshToken);
    const profile = await getProfileFromAccessToken(access_token);

    const user = await upsertUserFromProfile(profile);

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        is_admin: !!user.is_admin
      }
    });
  } catch(err) {
    console.error('/me error:', err.response?.data || err.message);
    res.status(401).json({ user: null });
  }
});

module.exports = router;
