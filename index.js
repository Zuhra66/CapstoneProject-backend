require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const authRoutes = require('./routes/auth');
const syncRoutes = require('./routes/sync'); // internal sync route
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

// Security headers
app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    })
);

// JSON + Cookies
app.use(express.json());
app.use(cookieParser());

// CORS
const allowedOrigins = [
  'http://localhost:5173',
  process.env.VITE_FRONTEND_URL || 'https://empowermed-frontend.onrender.com',
];

app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) callback(null, true);
        else callback(new Error('Not allowed by CORS'));
      },
      credentials: true,
    })
);

// -----------------------------
// Mount internal route BEFORE CSRF
// -----------------------------
app.use('/internal', syncRoutes); // internal sync-user API (no CSRF)

// -----------------------------
// CSRF protection for all other routes
// -----------------------------
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  },
});

// apply CSRF only for non-internal routes
app.use((req, res, next) => {
  if (req.path.startsWith('/internal')) return next();
  csrfProtection(req, res, next);
});

// CSRF token endpoint (still protected by CSRF)
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Auth routes (with CSRF)
app.use('/auth', authRoutes);

// Health check
app.get('/', (req, res) => res.send('EmpowerMed backend running'));

// Database connection check
pool.query('SELECT NOW()', (err, result) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Database connected:', result.rows[0]);
});

// Start server
app.listen(PORT, () => console.log(`Secure server running on port ${PORT}`));
