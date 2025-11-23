// index.js
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const { pool, healthCheck } = require('./db');

// ✅ admin JWT + role guard
const { checkJwt, attachAdminUser, requireAdmin } = require('./middleware/admin-check');

// Routers
const profileRoutes   = require('./routes/profile');
const authRoutes      = require('./routes/auth');
const syncRoutes      = require('./routes/sync');
const adminRoutes     = require('./routes/admin');
const catalogRouter   = require('./routes/catalog');    // /api/products, /api/categories
const educationRouter = require('./routes/education');  // /api/education

const app  = express();
const PORT = process.env.PORT || 5001;

/* ---------- Security hardening ---------- */
app.set('trust proxy', 1);

function requireHttps(req, res, next) {
  const xfProto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
  if (req.secure || xfProto === 'https') return next();
  return res.status(426).json({ error: 'Upgrade Required: Use HTTPS' });
}
if (process.env.NODE_ENV === 'production') {
  app.use(requireHttps);
}

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.use(express.json());
app.use(cookieParser());

/* ---------- CORS ---------- */
const allowedOrigins = new Set([
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://empowermedwellness.com',
  'https://www.empowermedwellness.com',
  'https://empowermed-frontend.onrender.com',
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || allowedOrigins.has(origin)) {
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-XSRF-TOKEN'
    );
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET, POST, PATCH, PUT, DELETE, OPTIONS'
    );
  }
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

/* ---------- Public/utility routes (no CSRF) ---------- */
app.get('/', (_req, res) => res.send('EmpowerMed backend running'));
app.get('/health', (_req, res) => res.status(200).json({ status: 'ok' }));

// (optional) simple "me" endpoint some frontends call
app.get('/auth/me', (_req, res) => res.json({ ok: true }));

app.get('/health/db', async (_req, res) => {
  try {
    const ok = await healthCheck();
    res.json({ db: ok ? 'up' : 'down' });
  } catch (e) {
    res.status(500).json({ db: 'down', error: e.message });
  }
});

app.use('/internal', syncRoutes);
app.use('/auth', authRoutes);

/* ---------- CSRF: protect pages & non-JWT API, skip for Bearer JWT ---------- */
const isProd = process.env.NODE_ENV === 'production';
const csrfProtection = csrf({
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProd },
});

/**
 * Apply CSRF normally, UNLESS:
 *  - the path starts with /api/
 *  - AND request has Authorization: Bearer <token>
 * In that case we trust the JWT and skip CSRF.
 */
function csrfUnlessBearer(req, res, next) {
  // Always allow these through without CSRF
  if (req.path.startsWith('/internal') || req.path.startsWith('/auth')) {
    return next();
  }

  const isApi = req.path.startsWith('/api/');
  const auth = req.headers.authorization || '';
  const hasBearer = auth.startsWith('Bearer ');

  if (isApi && hasBearer) {
    return next();
  }
  return csrfProtection(req, res, next);
}

app.use(csrfUnlessBearer);

// Token endpoint for any pages/forms that still need CSRF
app.get('/csrf-token', csrfProtection, (req, res) => {
  const token = req.csrfToken();
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,
    sameSite: 'lax',
    secure: isProd,
  });
  res.json({ csrfToken: token });
});

/* ---------- API routes ---------- */
app.use('/api/profile', profileRoutes);

// ✅ Admin routes guarded by JWT → attach DB user → require admin
app.use('/api/admin', checkJwt, attachAdminUser, requireAdmin, adminRoutes);

app.use('/api',           catalogRouter);     // e.g. GET /api/products, /api/categories
app.use('/api/education', educationRouter);   // e.g. GET /api/education

/* ---------- Log DB connection once at startup ---------- */
(async () => {
  try {
    const { rows } = await pool.query('SELECT NOW() AS now');
    console.log('✅ Database connected @', rows[0].now);
  } catch (err) {
    console.error('❌ Database connection error:', err.message);
  }
})();

/* ---------- Global error handler ---------- */
app.use((err, _req, res, _next) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or missing token', details: err.message });
  }
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  console.error(err);
  res.status(err.status || 500).json({ error: 'Server error', details: err.message });
});

/* ---------- Start server & graceful shutdown ---------- */
const server = app.listen(PORT, () => {
  console.log(`🔐 Secure server running on port ${PORT}`);
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  console.log('Shutting down...');
  server.close(() => {
    pool.end(() => process.exit(0));
  });
}

module.exports = app;
