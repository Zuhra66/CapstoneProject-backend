// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const app = express();
const PORT = process.env.PORT || 5000;

// ---------------- Security & Middleware ----------------
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// Allow both local and deployed frontends (for dev flexibility)
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://empowermed-frontend.onrender.com'
];

app.use(
    cors({
      origin(origin, callback) {
        // allow requests with no origin (like Postman)
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          console.warn(`Blocked CORS request from origin: ${origin}`);
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
    })
);
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // required for Render Postgres
  },
});

// Test connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected:', res.rows[0]);
  }
});

// ---------------- CSRF Protection ----------------
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // switch to true when using HTTPS in prod
  },
});
app.use(csrfProtection);

// ---------------- Routes ----------------
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get('/', (req, res) => {
  res.send('Backend is running securely');
});

app.get('/endpoint', (req, res) => {
  console.log('GET /endpoint called');
  res.json({ message: 'Hello from secure backend!' });
});

app.post('/secure', (req, res) => {
  console.log('POST /secure called with body:', req.body);
  res.json({
    success: true,
    message: 'Secure data received successfully!',
    received: req.body, // echo back data sent from frontend
  });
});

// ---------------- Start Server ----------------
app.listen(PORT, () => {
  console.log(`Server running securely on http://localhost:${PORT}`);
});
