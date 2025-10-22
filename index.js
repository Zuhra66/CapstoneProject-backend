const express = require('express');
const cors = require('cors');
const helmet = require('helmet');     //HIPAA security
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: "http://localhost:5173", //  frontend
  credentials: true
}));
//app.options('*', cors());
app.use(express.json());
app.use(cookieParser());

// Setup CSRF protection
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false  // HTTPS required for HIPAA compliance
  }
});
app.use(csrfProtection);

//  route to send CSRF token to frontend
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get('/', (req, res) => {
  res.send('Backend is running securely');
});

app.get('/endpoint', (req, res) => {
  res.json({ message: "Hello from secure backend!" });
});
app.post('/secure', (req, res) => {
  res.json({ success: true, message: 'Secure data received successfully!' });
});

app.listen(PORT, () =>
    console.log(`Server running securely on http://localhost:${PORT}`)
);
