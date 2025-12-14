// server.js (or index.js)
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const path = require('path');              // ✅ for static uploads
require('dotenv').config();

const { pool, healthCheck } = require('./db');
const { checkJwt, attachAdminUser, requireAdmin } = require('./middleware/admin-check');

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



// Import audit middleware
const auditMiddleware = require('./middleware/auditMiddleware');  // NEW: Audit middleware

const app = express();
const PORT = process.env.PORT || 5000;
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
    // ✅ Allow images and other static assets to be loaded from another origin
    // (e.g., frontend on 5173, backend on 5001)
    crossOriginResourcePolicy: false,
  })
);

// PayPal Webhook 
app.use("/memberships/paypal/webhook", express.raw({ type: "application/json" }));

app.use(express.json());
app.use(cookieParser());

/* ---------- Static uploads (for event images etc.) ---------- */
// ✅ serve /uploads/... from <project-root>/uploads
//    (matches admin.js which writes to path.join(__dirname, 'uploads', 'events'))
app.use(
  '/uploads',
  express.static(path.join(__dirname, 'uploads'))  // 🔁 using __dirname + 'uploads'
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

  // Handle OPTIONS requests (preflight)
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

/* ---------- CSRF Protection ---------- */
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: isProd ? 'none' : 'lax', // 'none' for cross-origin subdomains
    secure: isProd,                   // Must be true with sameSite: 'none'
    domain: COOKIE_DOMAIN,            // Root domain for subdomain sharing
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
    fullPath.startsWith('/api/events') ||        // public events API
    fullPath === '/csrf-token' ||
    fullPath === '/health' ||
    fullPath === '/health/db' ||
    fullPath === '/debug/cookies' ||
    fullPath === '/' ||
    fullPath.startsWith('/api/newsletter') ||
    fullPath.startsWith('/api/audit') ||         // Skip CSRF for audit logs API
    fullPath.startsWith('/calendar') ||
    fullPath.startsWith('/memberships')
  ) {
    console.log(`🔓 Skipping CSRF for: ${fullPath}`);
    return next();
  }

  console.log(`🔐 Applying CSRF for: ${fullPath}`);
  return csrfProtection(req, res, next);
};

// Apply the CSRF skip middleware BEFORE mounting routes
app.use(csrfSkipMiddleware);

// CSRF token endpoint - MUST use csrfProtection to generate token
app.get('/csrf-token', csrfProtection, (req, res) => {
  const token = req.csrfToken();

  console.log('🔐 Generated CSRF token for origin:', req.headers.origin);

  // Set cookie that JavaScript can read
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
// Note: This comes AFTER CSRF but BEFORE routes
app.use(auditMiddleware);

/* ---------- API routes ---------- */
app.use('/api/newsletter', newsletterRoutes);
app.use('/api/blog', blogRoutes);
app.use('/internal', syncRoutes);
app.use('/auth', authRoutes);
app.use('/calendar', calendarRoutes);
app.use('/api/blog', blogRoutes);
app.use('/api/events', eventsRoutes);   // public events routes (list for Events page)
app.use('/memberships', membershipRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/admin', adminRoutes);     // admin routes (includes /api/admin/events)
app.use('/api', catalogRouter);
app.use('/api/education', educationRouter);

// NEW: Add audit logs routes (protected by admin middleware)
app.use('/api/audit', auditLogsRoutes);

/* ---------- Error Handling ---------- */
app.use((err, req, res, next) => {
  console.error('🚨 Error:', {
    name: err.name,
    code: err.code,
    message: err.message,
    path: req.path,
    originalUrl: req.originalUrl,
    timestamp: new Date().toISOString(),
  });

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or missing token' });
  }

  if (err.code === 'EBADCSRFTOKEN') {
    console.log('🔍 CSRF Error Details:', {
      path: req.path,
      originalUrl: req.originalUrl,
      headers: {
        'x-xsrf-token': req.headers['x-xsrf-token'] ? 'present' : 'missing',
        cookie: req.headers.cookie ? 'present' : 'missing',
      },
      cookies: req.cookies,
    });

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
  console.log(`
🚀 EmpowerMed Backend Started
📡 Port: ${PORT}
🌐 Environment: ${process.env.NODE_ENV}
🔐 CSRF Protection: Enabled
🔍 Audit Logging: Enabled
🍪 Cookie Domain: ${COOKIE_DOMAIN || 'localhost'}
🔒 Secure Cookies: ${isProd}
🎯 Allowed Origins: ${allowedOrigins.join(', ')}
  `);
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  console.log('Shutting down...');
  server.close(() => pool.end(() => process.exit(0)));
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
