// index.js - Fix the HTTPS requirement
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
require('dotenv').config();

const { pool, healthCheck } = require('./db');
const { checkJwt, attachAdminUser, requireAdmin } = require('./middleware/admin-check');

const profileRoutes   = require('./routes/profile');
const authRoutes      = require('./routes/auth');
const syncRoutes      = require('./routes/sync');
const adminRoutes     = require('./routes/admin');
const catalogRouter   = require('./routes/catalog');
const educationRouter = require('./routes/education');
const blogRoutes      = require('./routes/blog');
const eventsRoutes    = require('./routes/events');

const app = express();
const PORT = process.env.PORT || 5000;
const isProd = process.env.NODE_ENV === 'production';

/* ---------- Security hardening ---------- */
app.set('trust proxy', 1);

// REMOVE or COMMENT OUT the requireHttps middleware for local development
// function requireHttps(req, res, next) {
//   if (!isProd) return next();
//   const xfProto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
//   if (req.secure || xfProto === 'https') return next();
//   return res.status(426).json({ error: 'Upgrade Required: Use HTTPS' });
// }
// app.use(requireHttps); // COMMENT THIS LINE

app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    })
);

app.use(express.json());
app.use(cookieParser());

/* ---------- CORS ---------- */
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://empowermedwellness.com',
  'https://www.empowermedwellness.com',
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
      'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-XSRF-TOKEN, X-Internal-API-Key'
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

// Add a test endpoint to verify CORS is working
app.get('/test-cors', (req, res) => {
  res.json({
    message: 'CORS test successful',
    origin: req.headers.origin,
    timestamp: new Date().toISOString()
  });
});

app.use('/internal', syncRoutes);
app.use('/auth', authRoutes);
app.use('/api/blog', blogRoutes);
app.use('/api/events', eventsRoutes);

/* ---------- CSRF protection ---------- */
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd
  }
});

app.use((req, res, next) => {
  if (
      req.path.startsWith('/internal') ||
      req.path.startsWith('/auth') ||
      req.path.startsWith('/api/blog') ||
      req.path.startsWith('/api/events')
  ) return next();
  return csrfProtection(req, res, next);
});

app.get('/csrf-token', (req, res) => {
  const token = req.csrfToken();
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,
    sameSite: 'lax',
    secure: isProd
  });
  res.json({ csrfToken: token });
});

/* ---------- API routes ---------- */
app.use('/api/profile', profileRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', catalogRouter);
app.use('/api/education', educationRouter);

/* ---------- DB connection check ---------- */
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
  console.error('Global error handler:', err);
  res.status(err.status || 500).json({
    error: 'Server error',
    details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

/* ---------- Start server ---------- */
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🔐 Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV}`);
  console.log(`🎯 Allowed origins: ${allowedOrigins.join(', ')}`);
  console.log(`🔄 Sync routes available at /internal/sync-user`);
  console.log(`🧪 Test CORS endpoint: http://localhost:${PORT}/test-cors`);
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  console.log('Shutting down...');
  server.close(() => pool.end(() => process.exit(0)));
}

module.exports = app;