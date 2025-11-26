// index.js
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
require('dotenv').config();

const { pool, healthCheck } = require('./db');

// ✅ admin JWT + role guard
const { checkJwt, attachAdminUser, requireAdmin } = require('./middleware/admin-check');

// Routers
const profileRoutes   = require('./routes/profile');
const authRoutes      = require('./routes/auth');
const syncRoutes      = require('./routes/sync');
const adminRoutes     = require('./routes/admin');
const catalogRouter   = require('./routes/catalog');
const educationRouter = require('./routes/education');
const blogRoutes      = require('./routes/blog');
const eventsRoutes    = require('./routes/events');

const app  = express();
const PORT = process.env.PORT || 5001;
const isProd = process.env.NODE_ENV === 'production';

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

  // only set CORS when there *is* an Origin and it's allowed
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
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

app.get('/health/db', async (_req, res) => {
  try {
    const ok = await healthCheck();
    res.json({ db: ok ? 'up' : 'down' });
  } catch (e) {
    res.status(500).json({ db: 'down', error: e.message });
  }
});

app.use('/internal', syncRoutes);

// Auth routes (no CSRF)
app.use('/auth', authRoutes);

// ✅ Public blog + events routes (no CSRF, but WITH CORS)
app.use('/api/blog', blogRoutes);
app.use('/api/events', eventsRoutes);

/* ---------- CSRF protection for the rest ---------- */
const csrfProtection = csrf({
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProd },
});

// Apply CSRF to everything EXCEPT internal/auth/blog/events
app.use((req, res, next) => {
  if (req.path.startsWith('/internal')) return next();
  if (req.path.startsWith('/auth')) return next();
  if (req.path.startsWith('/api/blog')) return next();
  if (req.path.startsWith('/api/events')) return next();
  return csrfProtection(req, res, next);
});

// Expose CSRF token
app.get('/csrf-token', (req, res) => {
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
app.use('/api/admin',   adminRoutes);
app.use('/api',         catalogRouter);
app.use('/api/education', educationRouter);

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
