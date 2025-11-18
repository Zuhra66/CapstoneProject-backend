// index.js
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const { pool, healthCheck } = require('./db');

// Routers
const profileRoutes   = require('./routes/profile');
const authRoutes      = require('./routes/auth');
const syncRoutes      = require('./routes/sync');
const adminRoutes     = require('./routes/admin');
const catalogRouter   = require('./routes/catalog');    // expects /products, /categories, etc.
const educationRouter = require('./routes/education');  // expects /  → mount at /api/education

const app  = express();
const PORT = process.env.PORT || 5000;

/* ---------- Security hardening ---------- */
app.set('trust proxy', 1); // behind Render/other proxies

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.use(express.json());
app.use(cookieParser());

/* ---------- CORS (frontends allowed to call API) ---------- */
const allowedOrigins = new Set([
  'http://localhost:5173',
  'http://127.0.0.1:5173',
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
  if (req.method === 'OPTIONS') return res.sendStatus(200); // preflight
  next();
});

/* ---------- Public/utility routes (no CSRF) ---------- */
app.get('/', (_req, res) => res.send('EmpowerMed backend running'));
app.get('/health', (_req, res) => res.status(200).json({ status: 'ok' }));

// Database health check against your Render Postgres
app.get('/health/db', async (_req, res) => {
  try {
    const ok = await healthCheck();
    res.json({ db: ok ? 'up' : 'down' });
  } catch (e) {
    res.status(500).json({ db: 'down', error: e.message });
  }
});

// Internal hooks/utilities (keep CSRF off here)
app.use('/internal', syncRoutes);

// Auth routes (handle their own token/cookie flows; no CSRF)
app.use('/auth', authRoutes);

/* ---------- CSRF protection for the rest ---------- */
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  },
});

// Apply CSRF to everything except /internal and /auth
app.use((req, res, next) => {
  if (req.path.startsWith('/internal') || req.path.startsWith('/auth')) return next();
  return csrfProtection(req, res, next);
});

// Expose CSRF token so SPA can read it and send back on mutating requests
app.get('/csrf-token', (req, res) => {
  const token = req.csrfToken();
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  });
  res.json({ csrfToken: token });
});

/* ---------- API routes (CSRF-protected) ---------- */
app.use('/api/profile', profileRoutes);
app.use('/api/admin',   adminRoutes);
app.use('/api',         catalogRouter);          // e.g. GET /api/products, /api/categories
app.use('/api/education', educationRouter);      // e.g. GET /api/education

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
  res.status(500).json({ error: 'Server error', details: err.message });
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
