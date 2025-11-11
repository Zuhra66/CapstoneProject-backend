require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const profileRoutes = require('./routes/profile');
const authRoutes = require('./routes/auth');
const syncRoutes = require('./routes/sync');
const adminRoutes = require('./routes/admin');
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

// ---- SECURITY ----
app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    })
);

app.use(express.json());
app.use(cookieParser());

// ---- ALLOWED ORIGINS ----
const allowedOrigins = [
  'http://localhost:5173',
  process.env.FRONTEND_URL || 'https://www.empowermedwellness.com',
];

// ---- DYNAMIC CORS + OPTIONS PRE-FLIGHT ----
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type,Authorization,X-XSRF-TOKEN'
    );
    res.setHeader(
        'Access-Control-Allow-Methods',
        'GET,POST,PATCH,PUT,DELETE,OPTIONS'
    );
  }
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200); // Preflight OK
  }
  next();
});

// ---- INTERNAL SYNC (no CSRF) ----
app.use('/internal', syncRoutes);

// ---- CSRF PROTECTION ----
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  },
});

// Apply CSRF to all non-internal routes
app.use((req, res, next) => {
  if (req.path.startsWith('/internal')) return next();
  csrfProtection(req, res, next);
});

// CSRF token endpoint
app.get('/csrf-token', (req, res) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), {
    httpOnly: false, // frontend JS needs to read it
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  });
  res.json({ csrfToken: req.csrfToken() });
});

// ---- ROUTES ----
app.use('/auth', authRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/admin', adminRoutes);

// ---- HEALTH CHECK ----
app.get('/', (req, res) => res.send('EmpowerMed backend running'));

// ---- DATABASE CONNECTION CHECK ----
pool.query('SELECT NOW()', (err, result) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Database connected:', result.rows[0]);
});

// ---- GLOBAL ERROR HANDLER ----
app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    return res
    .status(401)
    .json({ error: 'Invalid or missing token', details: err.message });
  }
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  console.error(err);
  res.status(500).json({ error: 'Server error', details: err.message });
});

// ---- START SERVER ----
app.listen(PORT, () =>
    console.log(`Secure server running on port ${PORT}`)
);
