// server.js (or index.js)
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const path = require('path');
require('dotenv').config();

const { pool, healthCheck } = require('./db');
const checkJwt = require('./middleware/auth0-check');
const attachUser = require('./middleware/attachUser');

// Import routes
const profileRoutes = require('./routes/profile');
const authRoutes = require('./routes/auth');
const syncRoutes = require('./routes/sync');
const adminRoutes = require('./routes/admin');
const catalogRouter = require('./routes/catalog');
const educationRouter = require('./routes/education');
const blogRoutes = require('./routes/blog');
const eventsRoutes = require('./routes/events');
const calendarRoutes = require('./routes/calendar');
const membershipRoutes = require('./routes/memberships');
const newsletterRoutes = require('./routes/newsletter');
const auditLogsRoutes = require('./routes/auditLogs');
const messagesRouter = require("./routes/messages");

// Import audit middleware
const auditMiddleware = require('./middleware/auditMiddleware');

const app = express();
const PORT = process.env.PORT || 5000;
const isProd = process.env.NODE_ENV === 'production';

// Domain configuration
const COOKIE_DOMAIN = isProd ? '.empowermedwellness.com' : undefined;

/* ---------- Security hardening ---------- */
app.set('trust proxy', 1);

app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
      crossOriginResourcePolicy: false,
    })
);

// PayPal Webhook
app.use("/memberships/paypal/webhook", express.raw({ type: "application/json" }));

app.use(express.json());
app.use(cookieParser());

/* ---------- Static uploads ---------- */
app.use(
    '/uploads',
    express.static(path.join(__dirname, 'uploads'))
);

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

// CORS middleware function
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

// Apply CORS to all routes
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

// Create a middleware that skips CSRF for specific routes
const csrfSkipMiddleware = (req, res, next) => {
  const fullPath = req.originalUrl || req.url;

  if (
      fullPath.startsWith('/internal') ||
      fullPath.startsWith('/auth') ||
      fullPath.startsWith('/api/blog') ||
      fullPath.startsWith('/api/events') ||
      fullPath === '/csrf-token' ||
      fullPath === '/health' ||
      fullPath === '/health/db' ||
      fullPath === '/' ||
      fullPath.startsWith('/api/newsletter') ||
      fullPath.startsWith('/api/audit') ||
      fullPath.startsWith('/calendar') ||
      fullPath.startsWith('/memberships') ||
      fullPath.startsWith('/messages')
  ) {
    return next();
  }

  return csrfProtection(req, res, next);
};

// Apply the CSRF skip middleware BEFORE mounting routes
app.use(csrfSkipMiddleware);

// CSRF token endpoint
app.get('/csrf-token', csrfProtection, (req, res) => {
  const token = req.csrfToken();

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

/* ---------- Apply audit middleware ---------- */
app.use(auditMiddleware);

/* ---------- API routes ---------- */
app.use('/api/newsletter', newsletterRoutes);
app.use('/api/blog', blogRoutes);
app.use('/internal', syncRoutes);
app.use('/auth', authRoutes);
app.use('/calendar', calendarRoutes);
app.use('/api/blog', blogRoutes);
app.use('/api/events', eventsRoutes);
app.use('/memberships', membershipRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', catalogRouter);
app.use('/api/education', educationRouter);
app.use('/api/audit', auditLogsRoutes);

app.use(
    '/messages',
    checkJwt,
    attachUser,
    messagesRouter
);

/* ---------- Error Handling ---------- */
app.use((err, req, res, next) => {
  console.error('Error:', {
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
    return res.status(403).json({
      error: 'Invalid CSRF token',
      details: 'Please refresh the page',
      path: req.originalUrl,
    });
  }

  res.status(err.status || 500).json({
    error: 'Server error',
    details: isProd ? 'Internal server error' : err.message,
    path: req.originalUrl,
  });
});

/* ---------- Start Server ---------- */
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server started on port ${PORT}`);
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  console.log('Shutting down...');
  server.close(() => pool.end(() => process.exit(0)));
}

/* ---------- Log DB Connection ---------- */
(async () => {
  try {
    const { rows } = await pool.query('SELECT NOW() AS now');
    console.log('Database connected');
  } catch (err) {
    console.error('Database connection error:', err.message);
  }
})();

module.exports = app;