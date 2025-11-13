const express = require('express');
const router = express.Router();
const axios = require('axios');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

router.use(cookieParser());

const AUTH0_TOKEN_URL = `https://${process.env.AUTH0_DOMAIN}/oauth/token`;
const REDIRECT_URI = `${process.env.AUTH0_BASE_URL}/auth/callback`;
const COOKIE_NAME = 'refresh_token';
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'Strict',
  maxAge: 30 * 24 * 60 * 60 * 1000
};

router.get('/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code');

  try {
    const resp = await axios.post(AUTH0_TOKEN_URL, {
      grant_type: 'authorization_code',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      code,
      redirect_uri: REDIRECT_URI
    }, { headers: { 'Content-Type': 'application/json' } });

    const { access_token, refresh_token, id_token, expires_in } = resp.data;

    if (!refresh_token) return res.status(500).send('No refresh token received');

    res.cookie(COOKIE_NAME, refresh_token, COOKIE_OPTIONS);

    res.redirect(process.env.FRONTEND_URL || '/');
  } catch (err) {
    const data = err.response?.data || err.message;
    console.error('Auth callback error:', data);
    res.status(500).send('Authentication failed');
  }
});

router.get('/session', async (req, res) => {
  try {
    const refreshToken = req.cookies[COOKIE_NAME];
    if (!refreshToken) return res.status(401).json({ error: 'Missing refresh token' });

    const resp = await axios.post(AUTH0_TOKEN_URL, {
      grant_type: 'refresh_token',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      refresh_token: refreshToken,
      audience: process.env.AUTH0_AUDIENCE
    }, { headers: { 'Content-Type': 'application/json' } });

    const { access_token, expires_in, id_token } = resp.data;

    res.json({ accessToken: access_token, expiresIn: expires_in, idToken: id_token });
  } catch (err) {
    const data = err.response?.data || err.message;
    console.error('Session refresh error:', data);
    res.status(401).json({ error: 'Failed to refresh session' });
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  const returnTo = process.env.FRONTEND_URL || '/';
  const logoutUrl = `https://${process.env.AUTH0_DOMAIN}/v2/logout?client_id=${process.env.AUTH0_CLIENT_ID}&returnTo=${encodeURIComponent(returnTo)}`;
  res.json({ logoutUrl });
});

router.get('/whoami', async (req, res) => {
  try {
    const refreshToken = req.cookies[COOKIE_NAME];
    if (!refreshToken) return res.status(401).json({ authenticated: false });

    const resp = await axios.post(AUTH0_TOKEN_URL, {
      grant_type: 'refresh_token',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      refresh_token: refreshToken,
      audience: process.env.AUTH0_AUDIENCE
    }, { headers: { 'Content-Type': 'application/json' } });

    const { access_token } = resp.data;
    const decoded = jwt.decode(access_token);
    res.json({ authenticated: true, user: decoded });
  } catch (err) {
    console.error('whoami error:', err.response?.data || err.message);
    res.status(401).json({ authenticated: false });
  }
});

module.exports = router;
