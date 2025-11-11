require('dotenv').config();
const express = require('express');
const cors = require('cors');
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

// ---- SECURITY MIDDLEWARE ----
app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    })
);

app.use(express.json());
app.use(cookieParser());

// ---- CORS CONFIG ----
const allowedOrigins = [
  'http://localhost:5173',
  process.env.VITE_FRONTEND_URL || 'https://empowermed-frontend.onrender.com',
  'https://www.empowermedwellness.com'
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

// ---- INTERNAL SYNC ROUTES (no CSRF, no extra CORS) ----
app.use('/internal', syncRoutes);

// ---- CSRF PROTECTION ----
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  },
});

// Apply CSRF to all non-internal routes
app.use((req, res, next) => {
  if (req.path.startsWith('/internal')) return next();
  csrfProtection(req, res, next);
});

app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ---- AUTH AND PROFILE ROUTES ----
app.use('/auth', authRoutes);
app.use('/api/profile', profileRoutes);

// ---- ADMIN ROUTES (CORS + Auth0 check included in routes) ----
app.use('/api/admin', adminRoutes);

// ---- HEALTH CHECK ----
app.get('/', (req, res) => res.send('EmpowerMed backend running'));

// ---- DATABASE CONNECTION CHECK ----
pool.query('SELECT NOW()', (err, result) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Database connected:', result.rows[0]);
});

// ---- SERVER START ----
app.listen(PORT, () => console.log(`Secure server running on port ${PORT}`));
