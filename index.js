// server.js (main backend entry)

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const { pool, healthCheck } = require('./db');
const { checkJwt, attachAdminUser } = require('./middleware/admin-check');

const profileRoutes   = require('./routes/profile');
const authRoutes      = require('./routes/auth');
const syncRoutes      = require('./routes/sync');
const adminRoutes     = require('./routes/admin');
const catalogRouter   = require('./routes/catalog');
const educationRouter = require('./routes/education');
const blogRoutes      = require('./routes/blog');
const eventsRoutes    = require('./routes/events');

const app = express();
const PORT = process.env.PORT || 5001;
const isProd = process.env.NODE_ENV === 'production';

// Domain configuration - IMPORTANT: Use proper domain for cookies
const COOKIE_DOMAIN = isProd ? '.empowermedwellness.com' : undefined;

console.log('🔧 Environment Configuration:');
console.log('   NODE_ENV:', process.env.NODE_ENV);
console.log('   Cookie Domain:', COOKIE_DOMAIN || 'localhost');

/* ---------- Security hardening ---------- */
app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

// 🔸 allow larger JSON bodies so base64 / big payloads work
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

/* ---------- Static for uploaded files ---------- */
// All files saved under ./uploads (e.g. ./uploads/events/...) are served at /uploads/...
const uploadsRoot = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadsRoot, { recursive: true });
app.use('/uploads', express.static(uploadsRoot));

/* ---------- Simple request logger (helps debug 404s) ---------- */
app.use((req, _res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

/* ---------- CORS Configuration ---------- */
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://empowermedwellness.com',
  'https://www.empowermedwellness.com',
  'https://api.empowermedwellness.com',
  'https://empowermed-backend.onrender.com',
  'https://empowermed-frontend.onrender.com',
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-XSRF-TOKEN, X-CSRF-Token, X-Internal-API-Key'
  );
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PATCH, PUT, DELETE, OPTIONS'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  next();
});

/* ---------- Public routes ---------- */
app.get('/', (_req, res) => res.send('EmpowerMed backend running'));
app.get('/health', (_req, res) => res.status(200).json({ status: 'ok' }));
app.get('/health/db', async (_req, res) => {
  try {
    const ok = await healthCheck();
    res.json({ db: ok ? 'up' : 'down' });
  } catch (e) {
    res.status(500).json({ db: 'down', error: e.message });
  }
});

// Debug endpoint
app.get('/debug/cookies', (req, res) => {
  res.json({
    cookies: req.cookies,
    headers: {
      origin: req.headers.origin,
      cookie: req.headers.cookie,
    },
    environment: {
      NODE_ENV: process.env.NODE_ENV,
      cookieDomain: COOKIE_DOMAIN,
    },
  });
});

/* ---------- Route mounting ---------- */

// Internal sync
app.use('/internal', syncRoutes);

// Auth router (login, callback, etc.)
app.use('/auth', authRoutes);        // legacy path
app.use('/api/auth', authRoutes);    // API-style path for frontend

// Explicit "who am I" handler so /auth/me and /api/auth/me exist
const meHandler = (req, res) => {
  const user = req.user || req.auth || null;

  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const roles =
    user.roles ||
    user['https://empowermedwellness.com/roles'] ||
    [];

  res.json({
    user: {
      sub: user.sub,
      email: user.email,
      name: user.name,
    },
    roles,
  });
};

app.get('/auth/me', checkJwt, attachAdminUser, meHandler);
app.get('/api/auth/me', checkJwt, attachAdminUser, meHandler);

// Public-ish API
app.use('/api/blog', blogRoutes);
app.use('/api/events', eventsRoutes);

/* ---------- CSRF Protection ---------- */
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: isProd ? 'none' : 'lax',
    secure: isProd,
    domain: COOKIE_DOMAIN,
    path: '/',
  },
});

// Apply CSRF protection to routes that need it
app.use((req, res, next) => {
  // Skip CSRF for these paths
  if (
    req.path.startsWith('/internal') ||
    req.path.startsWith('/auth') ||
    req.path.startsWith('/api/auth') ||
    req.path.startsWith('/api/blog') ||
    req.path.startsWith('/api/events') ||
    req.path.startsWith('/uploads') || // static files, no CSRF
    req.path === '/csrf-token' ||
    req.path === '/health' ||
    req.path === '/debug/cookies'
  ) {
    return next();
  }

  return csrfProtection(req, res, next);
});

// CSRF token endpoint
app.get('/csrf-token', csrfProtection, (req, res) => {
  const token = req.csrfToken();

  console.log('🔐 Generated CSRF token for origin:', req.headers.origin);

  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,
    sameSite: isProd ? 'none' : 'lax',
    secure: isProd,
    domain: COOKIE_DOMAIN,
    path: '/',
  });

  res.json({
    csrfToken: token,
    timestamp: new Date().toISOString(),
  });
});

// CSRF test endpoint
app.post('/csrf-test', csrfProtection, (req, res) => {
  res.json({
    success: true,
    message: 'CSRF validation successful',
    timestamp: new Date().toISOString(),
  });
});

/* ---------- API routes ---------- */
app.use('/api/profile', profileRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', catalogRouter);
app.use('/api/education', educationRouter);

/* ---------- Error Handling ---------- */
app.use((err, req, res, next) => {
  console.error('🚨 Error:', {
    name: err.name,
    code: err.code,
    message: err.message,
    path: req.path,
    timestamp: new Date().toISOString(),
  });

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or missing token' });
  }

  if (err.code === 'EBADCSRFTOKEN') {
    console.log('🔍 CSRF Error Details:', {
      headers: {
        'x-xsrf-token': req.headers['x-xsrf-token'] ? 'present' : 'missing',
        cookie: req.headers.cookie ? 'present' : 'missing',
      },
      cookies: req.cookies,
    });

    return res.status(403).json({
      error: 'Invalid CSRF token',
      details: 'Please refresh the page',
    });
  }

  // 413: entity too large
  if (err.type === 'entity.too.large' || err.status === 413) {
    return res.status(413).json({
      error: 'Payload too large',
      details: 'Request body is too big. Try a smaller image.',
    });
  }

  res.status(err.status || 500).json({
    error: 'Server error',
    details: isProd ? 'Internal server error' : err.message,
  });
});

/* ---------- Start Server ---------- */
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
🚀 EmpowerMed Backend Started
📡 Port: ${PORT}
🌐 Environment: ${process.env.NODE_ENV}
🔐 CSRF Protection: Enabled
🍪 Cookie Domain: ${COOKIE_DOMAIN || 'localhost'}
🔒 Secure Cookies: ${isProd}
🎯 Allowed Origins: ${allowedOrigins.join(', ')}
  `);
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

async function shutdown() {
  console.log('Shutting down...');
  server.close(async () => {
    try {
      await pool.end();
      console.log('DB pool closed');
    } catch (e) {
      console.error('Error closing DB pool:', e);
    } finally {
      process.exit(0);
    }
  });
}

module.exports = app;
