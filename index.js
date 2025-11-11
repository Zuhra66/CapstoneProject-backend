require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const profileRoutes = require('./routes/profile');
const authRoutes = require('./routes/auth');
const syncRoutes = require('./routes/sync');
const pool = require('./db');
const adminRoutes = require('./routes/admin');
const app = express();
const PORT = process.env.PORT || 5000;

app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    })
);

app.use(express.json());
app.use(cookieParser());

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

app.use('/internal', syncRoutes);
app.use('/api/admin', adminRoutes);
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  },
});

app.use((req, res, next) => {
  if (req.path.startsWith('/internal')) return next();
  csrfProtection(req, res, next);
});

app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.use('/auth', authRoutes);
app.use('/api/profile', profileRoutes);

app.get('/', (req, res) => res.send('EmpowerMed backend running'));

pool.query('SELECT NOW()', (err, result) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Database connected:', result.rows[0]);
});

app.listen(PORT, () => console.log(`Secure server running on port ${PORT}`));
