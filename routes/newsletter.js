// routes/newsletter.js - PRODUCTION READY WITH ENVIRONMENT VARIABLES
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { pool } = require('../db');
const { checkJwt, attachAdminUser, requireAdmin } = require('../middleware/admin-check');

const sgMail = require('@sendgrid/mail');

if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

const BACKEND_BASE = process.env.BACKEND_URL ||
    (process.env.NODE_ENV === 'production'
        ? 'https://api.empowermedwellness.com'
        : 'http://localhost:5000');

const FRONTEND_BASE = process.env.FRONTEND_URL ||
    (process.env.NODE_ENV === 'production'
        ? 'https://www.empowermedwellness.com'
        : 'http://localhost:5173');

const LOGO_URL = `${FRONTEND_BASE}/images/logo.png`;

const EMAIL_CONFIG = {
  fromEmail: process.env.EMAIL_FROM || 'EmpowerMEddev@gmail.com',
  fromName: process.env.EMAIL_FROM_NAME || 'EmpowerMEd',
  replyTo: process.env.EMAIL_REPLY_TO || 'EmpowerMEddev@gmail.com'
};

const generateToken = () => crypto.randomBytes(32).toString('hex');

router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'newsletter',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'production',
    backendUrl: BACKEND_BASE,
    frontendUrl: FRONTEND_BASE,
    logoUrl: LOGO_URL,
    envVars: {
      hasBackendUrl: !!process.env.BACKEND_URL,
      hasFrontendUrl: !!process.env.FRONTEND_URL,
      nodeEnv: process.env.NODE_ENV
    }
  });
});

if (process.env.NODE_ENV !== 'production') {
  router.get('/test', (req, res) => {
    res.json({
      message: 'Newsletter API is working!',
      environment: 'development',
      backendUrl: BACKEND_BASE,
      frontendUrl: FRONTEND_BASE,
      logoUrl: LOGO_URL,
      routes: [
        'POST /api/newsletter/subscribe',
        'GET /api/newsletter/verify/:token',
        'GET /api/newsletter/unsubscribe/:token',
        'GET /api/newsletter/health'
      ]
    });
  });

  router.get('/verify/test', (req, res) => {
    res.send(`<!DOCTYPE html>
      <html>
      <head>
        <title>Test Verification - EmpowerMEd</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 20px; background: #f8f9fa; color: #333; }
          .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          h1 { color: #3D52A0; margin-bottom: 20px; }
          .success { color: #28a745; font-size: 48px; margin: 20px 0; }
          .btn { display: inline-block; background: #3D52A0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-top: 20px; font-weight: bold; }
          .logo-img { width:60%; max-width:300px; height:auto; margin: 20px auto; display:block; }
          .debug-info { text-align: left; background: #f0f5ff; padding: 15px; border-radius: 5px; margin: 20px 0; font-family: monospace; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="success">✅</div>
          <h1>Verification Route is Working!</h1>
          <img src="${LOGO_URL}" class="logo-img">
          <div class="debug-info">
            <p><strong>Logo URL:</strong> ${LOGO_URL}</p>
          </div>
          <a href="${FRONTEND_BASE}" class="btn">Return to Website</a>
        </div>
      </body>
      </html>`);
  });
}

const sendVerificationEmail = async (email, name, token) => {
  try {
    const verificationLink = `${BACKEND_BASE}/api/newsletter/verify/${token}`;

    const msg = {
      to: email,
      from: { email: EMAIL_CONFIG.fromEmail, name: EMAIL_CONFIG.fromName },
      replyTo: EMAIL_CONFIG.replyTo,
      subject: 'Please confirm your subscription to EmpowerMEd',
      html: `<!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            .logo-img { width:60%; max-width:300px; height:auto; display:block; margin:0 auto 15px; }
            .header { background: linear-gradient(135deg, #3D52A0, #7091E6); padding: 30px; text-align:center; }
          </style>
        </head>
        <body>
          <div class="header">
            <img src="${LOGO_URL}" class="logo-img">
          </div>
          <div style="padding:30px;">
            <h2>Welcome to EmpowerMEd!</h2>
            <p>Hello ${name || 'there'},</p>
            <p>Confirm your subscription:</p>
            <p style="text-align:center;">
              <a href="${verificationLink}" style="background:#3D52A0;color:white;padding:14px 28px;border-radius:6px;text-decoration:none;font-weight:bold;">Confirm Subscription</a>
            </p>
          </div>
        </body>
        </html>`,
      text: `Confirm your subscription:\n${verificationLink}`
    };

    if (process.env.SENDGRID_API_KEY) {
      await sgMail.send(msg);
      return { success: true };
    } else {
      console.log(`[EMAIL LOG] Verification link for ${email}: ${verificationLink}`);
      return { success: true };
    }

  } catch (error) {
    console.error('SendGrid error:', error);
    return { success: true };
  }
};

const sendWelcomeEmail = async (email, name, unsubscribeToken) => {
  try {
    const unsubscribeLink = `${BACKEND_BASE}/api/newsletter/unsubscribe/${unsubscribeToken}`;

    const msg = {
      to: email,
      from: { email: EMAIL_CONFIG.fromEmail, name: EMAIL_CONFIG.fromName },
      replyTo: EMAIL_CONFIG.replyTo,
      subject: 'Welcome to EmpowerMEd - Your Subscription is Confirmed!',
      html: `<!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            .logo-img { width:60%; max-width:300px; height:auto; display:block; margin:0 auto 15px; }
            .header { background: linear-gradient(135deg, #3D52A0, #7091E6); padding:30px; text-align:center; }
          </style>
        </head>
        <body>
          <div class="header">
            <img src="${LOGO_URL}" class="logo-img">
          </div>

          <div style="padding:30px;">
            <h2>🎉 Welcome!</h2>
            <p>Hello ${name || 'wellness enthusiast'},</p>
            <p>Your subscription is confirmed!</p>

            <div style="margin-top:30px;font-size:12px;color:#666;">
              <a href="${unsubscribeLink}">Unsubscribe</a>
            </div>
          </div>
        </body>
        </html>`,
      text: `Your subscription is confirmed.\nUnsubscribe: ${unsubscribeLink}`
    };

    if (process.env.SENDGRID_API_KEY) {
      await sgMail.send(msg);
      return { success: true };
    } else {
      console.log(`[EMAIL LOG] Welcome email → ${email}`);
      return { success: true };
    }

  } catch (error) {
    console.error('SendGrid error:', error);
    return { success: true };
  }
};

router.post('/subscribe', async (req, res) => {
  try {
    const { email, name } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const token = generateToken();
    const unsubscribeToken = generateToken();

    const existing = await pool.query(
        'SELECT id, verified FROM newsletter_subscribers WHERE email=$1',
        [email]
    );

    if (existing.rows.length) {
      if (existing.rows[0].verified)
        return res.json({ success: true, message: 'Already subscribed' });

      await pool.query(
          'UPDATE newsletter_subscribers SET token=$1 WHERE email=$2',
          [token, email]
      );
    } else {
      await pool.query(
          'INSERT INTO newsletter_subscribers (email, name, token, unsubscribe_token) VALUES ($1,$2,$3,$4)',
          [email, name || null, token, unsubscribeToken]
      );
    }

    await sendVerificationEmail(email, name, token);
    res.json({ success: true, message: 'Verification email sent' });

  } catch (error) {
    console.error('Subscribe error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(
        'UPDATE newsletter_subscribers SET verified=true, token=NULL WHERE token=$1 RETURNING email, name, unsubscribe_token',
        [token]
    );

    if (!result.rows.length)
      return res.status(400).send('Invalid or expired verification link');

    const user = result.rows[0];

    await sendWelcomeEmail(user.email, user.name, user.unsubscribe_token);

    res.send(`<!DOCTYPE html>
      <html><body style="text-align:center;padding:40px;font-family:Arial">
      <img src="${LOGO_URL}" style="width:60%;max-width:300px;height:auto;margin-bottom:20px;">
      <h2>Subscription Confirmed!</h2>
      <a href="${FRONTEND_BASE}">Return to site</a>
      </body></html>`
    );

  } catch (error) {
    console.error('Verify error:', error);
    res.status(500).send('Server error');
  }
});

router.get('/unsubscribe/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(
        'DELETE FROM newsletter_subscribers WHERE unsubscribe_token=$1 RETURNING email',
        [token]
    );

    if (!result.rows.length)
      return res.status(400).send('Invalid link');

    res.send(`<html><body style="text-align:center;padding:40px;">
      <img src="${LOGO_URL}" style="width:60%;max-width:300px;height:auto;margin-bottom:20px;">
      <h2>You have been unsubscribed.</h2>
      <a href="${FRONTEND_BASE}">Return to site</a>
      </body></html>`
    );

  } catch (error) {
    console.error('Unsubscribe error:', error);
    res.status(500).send('Server error');
  }
});

module.exports = router;
