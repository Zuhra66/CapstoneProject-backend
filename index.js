// index.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const passport = require('./middleware/passport-setup');
const authRoutes = require('./routes/auth');
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json());
app.use(cookieParser());

const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  process.env.FRONTEND_URL
];

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

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

app.use(passport.initialize());
app.use('/auth', authRoutes);

app.get('/', (req, res) => res.send('EmpowerMed backend running securely'));

pool.query('SELECT NOW()', (err, r) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Database connected:', r.rows[0]);
});

app.listen(PORT, () => console.log(`Secure server running on port ${PORT}`));
