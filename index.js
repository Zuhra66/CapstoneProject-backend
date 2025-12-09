// index.js

// Core imports
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const { pool, healthCheck } = require('./db');

// Auth / admin middleware – import ONCE
const {
  checkJwt,
  attachAdminUser,
  requireAdmin,
  requireAuthenticated,
} = require('./middleware/admin-check');

// Routes
const profileRoutes    = require('./routes/profile');
const authRoutes       = require('./routes/auth');
const syncRoutes       = require('./routes/sync');
const adminRoutes      = require('./routes/admin');
const catalogRouter    = require('./routes/catalog');
const educationRouter  = require('./routes/education');
const blogRoutes       = require('./routes/blog');
const eventsRoutes     = require('./routes/events');
const calendarRoutes   = require('./routes/calendar');
const membershipRoutes = require('./routes/memberships');
const newsletterRoutes = require('./routes/newsletter');
const auditLogsRoutes  = require('./routes/auditLogs');

// Audit middleware
const auditMiddleware  = require('./middleware/auditMiddleware');

const app = express();
const PORT = process.env.PORT || 5001;
const isProd = process.env.NODE_ENV === 'production';

// Domain configuration for cookies
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

// allow larger JSON bodies so base64 / big payloads work
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

/* ---------- Static for uploaded files ---------- */
/**
 * Any files written under ./uploads (e.g. ./uploads/events/xyz.png)
 * will be publicly available at:
 *   http://localhost:5001/uploads/events/xyz.png
 */
const uploadsRoot = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadsRoot, { recursive: true });
console.log('📂 Serving uploads from:', uploadsRoot);
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

const corsMiddleware = (req, res, next) => {
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
};

app.use(corsMiddleware);

/* ---------- Public routes ---------- */
app.get('/', (_req, res) => res.send('{ "status": "ok" }\n'));

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

/* ---------- Core auth/sync/public API BEFORE CSRF ---------- */

// Internal sync
app.use('/internal', syncRoutes);

// Auth router (login, callback, etc.)
app.use('/auth', authRoutes);     // legacy
app.use('/api/auth', authRoutes); // API-style

// “Who am I” handler
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

// Public-ish API that doesn’t need CSRF
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

/* ---------- Audit middleware ---------- */
// Apply audit middleware to all routes after basic setup.
// It can see req.user if auth has already run; otherwise it logs anonymous.
app.use(auditMiddleware);

/* ---------- CSRF Skip Middleware ---------- */
const csrfSkipMiddleware = (req, res, next) => {
  const fullPath = req.originalUrl || req.url;

  if (
    // API endpoints that don't need CSRF
    fullPath.startsWith('/internal') ||          // Internal sync routes
    fullPath.startsWith('/auth') ||              // Auth routes
    fullPath.startsWith('/api/auth') ||          // Auth API
    fullPath.startsWith('/api/blog') ||          // Public blog API
    fullPath.startsWith('/api/events') ||        // Public events API
    fullPath.startsWith('/api/newsletter') ||    // Newsletter subscribe/unsubscribe
    fullPath.startsWith('/api/audit') ||         // Audit logs (admin-protected)

    // Health and status endpoints
    fullPath === '/' ||
    fullPath === '/health' ||
    fullPath === '/health/db' ||
    fullPath === '/debug/cookies' ||

    // CSRF token endpoint itself
    fullPath === '/csrf-token' ||

    // Static files
    fullPath.startsWith('/uploads') ||
    fullPath.startsWith('/static') ||

    // Webhooks (if any)
    fullPath.startsWith('/webhooks/') ||

    // Calendar / memberships (if you want them CSRF-free)
    fullPath.startsWith('/calendar') ||
    fullPath.startsWith('/memberships') ||

    // OPTIONS preflight
    req.method === 'OPTIONS'
  ) {
    console.log(`🔓 Skipping CSRF for: ${fullPath}`);
    return next();
  }

  console.log(`🔐 Applying CSRF for: ${fullPath}`);
  return csrfProtection(req, res, next);
};

app.use(csrfSkipMiddleware);

/* ---------- CSRF token helpers ---------- */
app.get('/csrf-token', (req, res) => {
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

app.post('/csrf-test', csrfProtection, (req, res) => {
  res.json({
    success: true,
    message: 'CSRF validation successful',
    timestamp: new Date().toISOString(),
  });
});

/* ---------- API routes (after CSRF & audit) ---------- */

app.use('/api/newsletter', newsletterRoutes);
app.use('/calendar', calendarRoutes);
app.use('/memberships', membershipRoutes);
app.use('/api/profile', checkJwt, attachAdminUser, requireAuthenticated, profileRoutes);
app.use('/api/admin',  checkJwt, attachAdminUser, requireAdmin, adminRoutes);
app.use('/api', catalogRouter);
app.use('/api/education', educationRouter);

// Audit logs – admin-only
app.use('/api/audit', checkJwt, attachAdminUser, requireAdmin, auditLogsRoutes);

/* ---------- Error Handling ---------- */
app.use((err, req, res, next) => {
  console.error('🚨 Error:', {
    name: err.name,
    code: err.code,
    message: err.message,
    path: req.path,
    originalUrl: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      error: 'Invalid CSRF token',
      details: 'Please refresh the page',
      path: req.originalUrl,
    });
  }

  if (err.type === 'entity.too.large' || err.status === 413) {
    return res.status(413).json({
      error: 'Payload too large',
      details: 'Request body is too big. Try a smaller image.',
      path: req.originalUrl,
    });
  }

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: 'Invalid or missing token',
      path: req.originalUrl,
    });
  }

  res.status(err.status || 500).json({
    error: 'Server error',
    details:
      process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : err.message,
    path: req.originalUrl,
    timestamp: new Date().toISOString(),
  });
});

/* ---------- Start Server ---------- */
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
🚀 EmpowerMed Backend Started
📡 Port: ${PORT}
🌐 Environment: ${process.env.NODE_ENV}
🔐 CSRF Protection: Enabled
🔍 Audit Logging: Enabled
🍪 Cookie Domain: ${COOKIE_DOMAIN || 'localhost'}
🔒 Secure Cookies: ${isProd}

🎯 Allowed Origins: ${allowedOrigins.join(', ')}
📂 Uploads served at: /uploads  ->  ${uploadsRoot}
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

/* ---------- Log DB Local Connection ---------- */
(async () => {
  try {
    const { rows } = await pool.query('SELECT NOW() AS now');
    console.log('✅ Database connected @', rows[0].now);
  } catch (err) {
    console.error('❌ Database connection error:', err.message);
  }
})();

module.exports = app;
