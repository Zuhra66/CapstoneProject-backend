// index.js - Updated for api.empowermedwellness.com subdomain
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
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

// Domain configuration
const COOKIE_DOMAIN = isProd ? '.empowermedwellness.com' : undefined;
const API_DOMAIN = isProd ? 'api.empowermedwellness.com' : `localhost:${PORT}`;
const FRONTEND_DOMAIN = isProd ? 'www.empowermedwellness.com' : 'localhost:5173';

console.log('🔧 Environment Configuration:');
console.log('   NODE_ENV:', process.env.NODE_ENV);
console.log('   Cookie Domain:', COOKIE_DOMAIN || 'localhost');
console.log('   API Domain:', API_DOMAIN);
console.log('   Frontend Domain:', FRONTEND_DOMAIN);

/* ---------- Security hardening ---------- */
app.set('trust proxy', 1);

app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    })
);

// Additional security headers
app.use((req, res, next) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Remove server header
  res.removeHeader('X-Powered-By');

  next();
});

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path.startsWith('/health') // Skip for health checks
});

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

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

  // Set CORS headers for all origins (development) or only allowed ones (production)
  if (origin) {
    if (isProd) {
      // In production, only allow specific origins
      if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      } else {
        console.log('⚠️ Blocked CORS origin in production:', origin);
      }
    } else {
      // In development, allow all origins for easier testing
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
  }

  // Always set these headers (they're safe)
  res.setHeader(
      'Access-Control-Allow-Headers',
      'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-XSRF-TOKEN, X-CSRF-Token, X-Internal-API-Key'
  );
  res.setHeader(
      'Access-Control-Allow-Methods',
      'GET, POST, PATCH, PUT, DELETE, OPTIONS'
  );
  res.setHeader('Access-Control-Expose-Headers', 'XSRF-TOKEN');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  next();
});

/* ---------- Public routes ---------- */
app.get('/', (_req, res) => res.send('EmpowerMed API v1.0.0'));
app.get('/health', (_req, res) => res.status(200).json({
  status: 'ok',
  timestamp: new Date().toISOString(),
  environment: process.env.NODE_ENV,
  apiDomain: API_DOMAIN
}));

app.get('/health/db', async (_req, res) => {
  try {
    const ok = await healthCheck();
    res.json({
      db: ok ? 'up' : 'down',
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({
      db: 'down',
      error: e.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Debug endpoint
app.get('/debug/env', (req, res) => {
  res.json({
    nodeEnv: process.env.NODE_ENV,
    backendUrl: process.env.BACKEND_URL,
    frontendUrl: process.env.FRONTEND_URL,
    cookieDomain: COOKIE_DOMAIN,
    allowedOrigins,
    request: {
      hostname: req.hostname,
      origin: req.headers.origin,
      secure: req.secure
    }
  });
});

// Test CORS endpoint
app.get('/test-cors', (req, res) => {
  res.json({
    message: 'CORS test successful',
    origin: req.headers.origin,
    cookieDomain: COOKIE_DOMAIN,
    timestamp: new Date().toISOString()
  });
});

// Apply rate limiting to API routes
app.use('/api/', apiLimiter);

// Routes that don't need CSRF
app.use('/internal', syncRoutes);
app.use('/auth', authRoutes);
app.use('/api/blog', blogRoutes);
app.use('/api/events', eventsRoutes);

/* ---------- CSRF Protection ---------- */
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: isProd ? 'none' : 'lax',  // Use 'none' for cross-origin in production
    secure: isProd,                     // HTTPS only in production
    domain: COOKIE_DOMAIN,              // Root domain for subdomain sharing
    path: '/',
    maxAge: 3600000                     // 1 hour
  },
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  value: (req) => {
    // Check for CSRF token in headers
    return req.headers['x-xsrf-token'] || req.headers['x-csrf-token'];
  }
});

// Apply CSRF middleware selectively
app.use((req, res, next) => {
  // Skip CSRF for these paths
  const skipPaths = [
    '/internal',
    '/auth',
    '/api/blog',
    '/api/events',
    '/csrf-token',
    '/health',
    '/debug',
    '/test-cors'
  ];

  if (skipPaths.some(path => req.path.startsWith(path))) {
    return next();
  }

  return csrfProtection(req, res, next);
});

// CSRF token endpoint
app.get('/csrf-token', (req, res) => {
  const token = req.csrfToken();

  console.log('🔐 Generating CSRF token for:', req.headers.origin);

  // Set cookie that JavaScript can read
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,        // JavaScript can read this
    sameSite: isProd ? 'none' : 'lax',  // Match CSRF cookie settings
    secure: isProd,         // HTTPS only
    domain: COOKIE_DOMAIN,  // Root domain
    path: '/',
    maxAge: 3600000,
    encode: String
  });

  res.json({
    csrfToken: token,
    timestamp: new Date().toISOString(),
    expiresIn: 3600,
    cookieDomain: COOKIE_DOMAIN
  });
});

// CSRF test endpoint
app.post('/csrf-test', csrfProtection, (req, res) => {
  res.json({
    success: true,
    message: 'CSRF validation successful',
    timestamp: new Date().toISOString(),
    receivedFrom: req.headers.origin
  });
});

/* ---------- API routes ---------- */
app.use('/api/profile', profileRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', catalogRouter);
app.use('/api/education', educationRouter);

/* ---------- Database connection ---------- */
(async () => {
  try {
    const { rows } = await pool.query('SELECT NOW() AS now');
    console.log('✅ Database connected @', rows[0].now);
  } catch (err) {
    console.error('❌ Database connection error:', err.message);
  }
})();

/* ---------- Error Handling ---------- */
app.use((err, req, res, next) => {
  console.error('🚨 Error:', {
    name: err.name,
    code: err.code,
    message: err.message,
    path: req.path,
    method: req.method,
    origin: req.headers.origin,
    timestamp: new Date().toISOString()
  });

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: 'Invalid or missing token',
      details: err.message
    });
  }

  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      error: 'Invalid CSRF token',
      details: {
        receivedToken: req.headers['x-xsrf-token'] ? 'present' : 'missing',
        path: req.path,
        method: req.method
      }
    });
  }

  res.status(err.status || 500).json({
    error: 'Internal server error',
    details: isProd ? 'Please try again later' : err.message
  });
});

/* ---------- 404 Handler ---------- */
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
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
📊 Database: Connected
  `);
});

// Graceful shutdown
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  console.log('🛑 Shutting down gracefully...');
  server.close(() => {
    pool.end(() => {
      console.log('✅ Shutdown complete');
      process.exit(0);
    });
  });
}

module.exports = app;