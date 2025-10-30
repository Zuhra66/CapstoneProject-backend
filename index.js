require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const authRoutes = require('./routes/auth');
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

// Security
app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false
    })
);

// JSON + Cookies
app.use(express.json());
app.use(cookieParser());

// CORS
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  process.env.FRONTEND_URL
];

app.use(
    cors({
      origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) callback(null, true);
        else callback(new Error('Not allowed by CORS'));
      },
      credentials: true
    })
);

// CSRF protection
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
});
app.use(csrfProtection);

app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Routes
app.use('/auth', authRoutes);

// Health check
app.get('/', (req, res) => res.send('EmpowerMed backend running securely'));

// Database connection check
pool.query('SELECT NOW()', (err, r) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Database connected:', r.rows[0]);
});

app.listen(PORT, () => console.log(`Secure server running on port ${PORT}`));
