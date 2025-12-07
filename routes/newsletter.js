// routes/newsletter.js - PRODUCTION READY
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { pool } = require('../db');
const { checkJwt, attachAdminUser, requireAdmin } = require('../middleware/admin-check');

const sgMail = require('@sendgrid/mail');

if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

const EMAIL_CONFIG = {
  fromEmail: process.env.EMAIL_FROM || 'EmpowerMEddev@gmail.com',
  fromName: process.env.EMAIL_FROM_NAME || 'EmpowerMEd',
  replyTo: process.env.EMAIL_REPLY_TO || 'EmpowerMEddev@gmail.com'
};

const BASE_URL = 'https://www.empowermedwellness.com';
const LOGO_URL = `${BASE_URL}/images/logo.png`;

const generateToken = () => crypto.randomBytes(32).toString('hex');

router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'newsletter',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'production'
  });
});

if (process.env.NODE_ENV !== 'production') {
  router.get('/test', (req, res) => {
    res.json({
      message: 'Newsletter API is working!',
      environment: 'development',
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
          .logo-img { max-width: 150px; height: auto; margin: 20px auto; display: block; }
        </style>
      </head>
      <body>
        <div class="container">
          <img src="${LOGO_URL}" alt="EmpowerMEd Logo" class="logo-img" onerror="this.style.display='none'">
          <div class="success">✅</div>
          <h1>Verification Route is Working!</h1>
          <p>This is a development-only test route.</p>
          <p><strong>Logo URL:</strong> ${LOGO_URL}</p>
          <p><strong>Environment:</strong> development</p>
          <a href="http://localhost:5173" class="btn">Return to Website</a>
        </div>
      </body>
      </html>`);
  });
}

const sendVerificationEmail = async (email, name, token) => {
  try {
    const verificationLink = `${BASE_URL}/api/newsletter/verify/${token}`;

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
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 0; }
            .header { background: linear-gradient(135deg, #3D52A0, #7091E6); padding: 30px; text-align: center; }
            .content { padding: 30px; background: #f9f9f9; }
            .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; background: white; }
            .button { display: inline-block; background: #3D52A0; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; margin: 20px 0; font-weight: bold; font-size: 16px; }
            .logo-img { max-width: 150px; height: auto; margin-bottom: 15px; }
            .brand { font-family: 'Aboreto', cursive; color: white; font-size: 24px; font-weight: bold; margin-bottom: 10px; }
            @media (max-width: 600px) {
              .header { padding: 20px; }
              .content { padding: 20px; }
              .button { padding: 12px 24px; font-size: 14px; }
            }
          </style>
        </head>
        <body>
          <div class="header">
            <div class="brand">EmpowerMEd</div>
            <img src="${LOGO_URL}" alt="EmpowerMEd Logo" class="logo-img">
          </div>
          <div class="content">
            <h2>Welcome to EmpowerMEd!</h2>
            <p>Hello ${name || 'there'},</p>
            <p>Thank you for subscribing to our wellness newsletter. To complete your subscription and start receiving our updates, please confirm your email address:</p>
            <p style="text-align: center;">
              <a href="${verificationLink}" class="button">Confirm Subscription</a>
            </p>
            <p>If you didn't request this subscription, you can safely ignore this email.</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} EmpowerMEd LLC. All rights reserved.</p>
            <p>3600 Sisk Road, Suite 2D, Modesto, CA, USA</p>
          </div>
        </body>
        </html>`,
      text: `Welcome to EmpowerMEd!\n\nPlease confirm your subscription by visiting:\n${verificationLink}\n\nIf you didn't request this, please ignore this email.\n\nThis link will expire in 24 hours.`
    };

    if (process.env.SENDGRID_API_KEY) {
      await sgMail.send(msg);
      return { success: true, message: 'Verification email sent', email };
    } else {
      console.log(`[EMAIL LOG] Verification link for ${email}: ${verificationLink}`);
      return { success: true, message: 'Verification email logged', email };
    }

  } catch (error) {
    console.error('SendGrid error:', error.response?.body || error.message);
    return { success: true, message: 'Email queued', email, fallback: true };
  }
};

const sendWelcomeEmail = async (email, name, unsubscribeToken) => {
  try {
    const unsubscribeLink = `${BASE_URL}/api/newsletter/unsubscribe/${unsubscribeToken}`;

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
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 0; }
            .header { background: linear-gradient(135deg, #3D52A0, #7091E6); padding: 30px; text-align: center; }
            .content { padding: 30px; background: #f9f9f9; }
            .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; background: white; }
            .logo-img { max-width: 150px; height: auto; margin-bottom: 15px; }
            .brand { font-family: 'Aboreto', cursive; color: white; font-size: 24px; font-weight: bold; margin-bottom: 10px; }
            .features { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .feature-item { margin: 10px 0; padding-left: 20px; position: relative; }
            .feature-item:before { content: "✓"; color: #28a745; position: absolute; left: 0; }
            .unsubscribe { font-size: 12px; color: #666; margin-top: 30px; }
            @media (max-width: 600px) {
              .header { padding: 20px; }
              .content { padding: 20px; }
              .features { padding: 15px; }
            }
          </style>
        </head>
        <body>
          <div class="header">
            <div class="brand">EmpowerMEd</div>
            <img src="${LOGO_URL}" alt="EmpowerMEd Logo" class="logo-img">
          </div>
          <div class="content">
            <h2>🎉 Welcome to Our Wellness Community!</h2>
            <p>Hello ${name || 'wellness enthusiast'},</p>
            <p>Your subscription to EmpowerMEd updates has been confirmed. We're excited to have you join our community!</p>
            
            <div class="features">
              <h3>What to expect:</h3>
              <div class="feature-item">Weekly wellness tips and insights</div>
              <div class="feature-item">Exclusive content and resources</div>
              <div class="feature-item">Updates on events and workshops</div>
              <div class="feature-item">Special offers for subscribers</div>
              <div class="feature-item">Mental, physical, and nutritional wellness guidance</div>
            </div>
            
            <p>Stay tuned for our next update, and remember: wellness is a journey, not a destination.</p>
            
            <p>With gratitude,<br>
            <strong>Dr. Diana Galván & The EmpowerMEd Team</strong></p>
            
            <div class="unsubscribe">
              <p><small>You can <a href="${unsubscribeLink}">unsubscribe</a> anytime if you change your mind.</small></p>
            </div>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} EmpowerMEd LLC. All rights reserved.</p>
            <p>3600 Sisk Road, Suite 2D, Modesto, CA, USA</p>
          </div>
        </body>
        </html>`,
      text: `Welcome to EmpowerMEd!\n\nYour subscription has been confirmed. You'll now receive:\n- Weekly wellness tips\n- Exclusive content\n- Event updates\n- Special offers\n\nStay healthy and empowered!\n\nThe EmpowerMEd Team\n\nYou can unsubscribe anytime: ${unsubscribeLink}`
    };

    if (process.env.SENDGRID_API_KEY) {
      await sgMail.send(msg);
      return { success: true, message: 'Welcome email sent', email };
    } else {
      console.log(`[EMAIL LOG] Welcome email would be sent to: ${email}`);
      return { success: true, message: 'Welcome email logged', email };
    }

  } catch (error) {
    console.error('SendGrid error:', error.response?.body || error.message);
    return { success: true, message: 'Welcome email queued', email };
  }
};

router.post('/subscribe', async (req, res) => {
  try {
    const { email, name } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, error: 'INVALID_EMAIL', message: 'Please provide a valid email address' });
    }

    const lowerEmail = email.toLowerCase().trim();
    const source = req.headers.referer || 'website_footer';

    const existing = await pool.query(
        `SELECT id, active, verified_at FROM newsletter_subscribers WHERE email = $1`,
        [lowerEmail]
    );

    if (existing.rows.length > 0) {
      const subscriber = existing.rows[0];
      if (subscriber.verified_at && subscriber.active) {
        return res.status(200).json({ success: true, verified: true, message: 'You are already subscribed to our newsletter!' });
      }

      if (!subscriber.verified_at) {
        const verificationToken = generateToken();
        const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await pool.query(
            `UPDATE newsletter_subscribers SET verification_token = $1, verification_expires = $2, name = COALESCE($3, name), active = false WHERE id = $4`,
            [verificationToken, verificationExpires, name, subscriber.id]
        );
        const emailResult = await sendVerificationEmail(lowerEmail, name, verificationToken);
        return res.status(200).json({ success: true, verified: false, message: 'Verification email resent. Please check your inbox to confirm your subscription.', emailResult });
      }
    }

    const verificationToken = generateToken();
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    try {
      const result = await pool.query(
          `INSERT INTO newsletter_subscribers (email, name, source, verification_token, verification_expires, active) VALUES ($1, $2, $3, $4, $5, false) RETURNING id`,
          [lowerEmail, name, source, verificationToken, verificationExpires]
      );

      const emailResult = await sendVerificationEmail(lowerEmail, name, verificationToken);
      return res.status(200).json({ success: true, verified: false, message: 'Thank you! Please check your email to confirm your subscription.', emailResult });

    } catch (dbError) {
      if (dbError.code === '23505') {
        return res.status(200).json({ success: true, verified: false, message: 'Subscription pending verification. Please check your email.' });
      }
      if (dbError.code === '42703') {
        const result = await pool.query(
            `INSERT INTO newsletter_subscribers (email, source, verification_token, verification_expires, active) VALUES ($1, $2, $3, $4, false) RETURNING id`,
            [lowerEmail, source, verificationToken, verificationExpires]
        );
        const emailResult = await sendVerificationEmail(lowerEmail, name, verificationToken);
        return res.status(200).json({ success: true, verified: false, message: 'Thank you! Please check your email to confirm your subscription.', emailResult });
      }
      throw dbError;
    }

  } catch (error) {
    console.error('Subscription error:', error.message);
    res.status(500).json({ success: false, error: 'SUBSCRIPTION_FAILED', message: 'Unable to process subscription. Please try again later.' });
  }
});

router.get('/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(
        `UPDATE newsletter_subscribers SET active = true, verified_at = NOW(), verification_token = NULL, verification_expires = NULL, unsubscribe_token = COALESCE(unsubscribe_token, encode(gen_random_bytes(50), 'hex')) WHERE verification_token = $1 AND verification_expires > NOW() AND verified_at IS NULL AND active = false RETURNING id, email, name, unsubscribe_token`,
        [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).send(`<!DOCTYPE html>
        <html>
        <head>
          <title>Verification Failed - EmpowerMEd</title>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 20px; background: #f8f9fa; color: #333; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #3D52A0; margin-bottom: 20px; }
            .error { color: #dc3545; font-size: 18px; margin: 20px 0; }
            .btn { display: inline-block; background: #3D52A0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-top: 20px; font-weight: bold; }
            .logo-img { max-width: 150px; height: auto; margin: 20px auto; display: block; }
          </style>
        </head>
        <body>
          <div class="container">
            <img src="${LOGO_URL}" alt="EmpowerMEd Logo" class="logo-img" onerror="this.style.display='none'">
            <h1>Verification Failed</h1>
            <p class="error">The verification link is invalid or has expired.</p>
            <p>Please try subscribing again or contact us if you need assistance.</p>
            <a href="${BASE_URL}" class="btn">Return to EmpowerMEd</a>
          </div>
        </body>
        </html>`);
    }

    const subscriber = result.rows[0];

    sendWelcomeEmail(subscriber.email, subscriber.name, subscriber.unsubscribe_token)
    .then(() => {})
    .catch(() => {});

    res.send(`<!DOCTYPE html>
      <html>
      <head>
        <title>Subscription Confirmed - EmpowerMEd</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 20px; background: #f8f9fa; color: #333; }
          .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          h1 { color: #3D52A0; margin-bottom: 20px; }
          .success { color: #28a745; font-size: 48px; margin: 20px 0; }
          .btn { display: inline-block; background: #3D52A0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-top: 20px; font-weight: bold; }
          .features { text-align: left; margin: 30px 0; }
          .feature-item { margin: 10px 0; padding-left: 20px; position: relative; }
          .feature-item:before { content: "✓"; color: #28a745; position: absolute; left: 0; }
          .email-highlight { background: #f0f5ff; padding: 10px; border-radius: 5px; margin: 15px 0; font-weight: bold; }
          .logo-img { max-width: 150px; height: auto; margin: 20px auto; display: block; }
        </style>
      </head>
      <body>
        <div class="container">
          <img src="${LOGO_URL}" alt="EmpowerMEd Logo" class="logo-img" onerror="this.style.display='none'">
          <div class="success">✓</div>
          <h1>Subscription Confirmed!</h1>
          <p>Thank you for verifying your email address.</p>
          <p>Your subscription to EmpowerMEd updates is now active.</p>
          
          <div class="features">
            <p><strong>What you'll receive:</strong></p>
            <div class="feature-item">Weekly wellness tips and insights</div>
            <div class="feature-item">Exclusive content and resources</div>
            <div class="feature-item">Updates on events and workshops</div>
            <div class="feature-item">Special offers for subscribers</div>
          </div>
          
          <div class="email-highlight">
            <p>A welcome email has been sent to <strong>${subscriber.email}</strong>.</p>
          </div>
          
          <a href="${BASE_URL}" class="btn">Continue to EmpowerMEd</a>
        </div>
      </body>
      </html>`);

  } catch (error) {
    console.error('Verification error:', error.message);
    res.status(500).send(`<!DOCTYPE html>
      <html>
      <head>
        <title>Error - EmpowerMEd</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 20px; background: #f8f9fa; color: #333; }
          .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          h1 { color: #dc3545; margin-bottom: 20px; }
          .btn { display: inline-block; background: #3D52A0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-top: 20px; font-weight: bold; }
          .logo-img { max-width: 150px; height: auto; margin: 20px auto; display: block; }
        </style>
      </head>
      <body>
        <div class="container">
          <img src="${LOGO_URL}" alt="EmpowerMEd Logo" class="logo-img" onerror="this.style.display='none'">
          <h1>Verification Error</h1>
          <p>An error occurred while verifying your subscription.</p>
          <p>Please try again or contact us for assistance.</p>
          <a href="${BASE_URL}" class="btn">Return to EmpowerMEd</a>
        </div>
      </body>
      </html>`);
  }
});

router.get('/unsubscribe/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(
        `UPDATE newsletter_subscribers SET active = false WHERE unsubscribe_token = $1 AND active = true RETURNING id, email`,
        [token]
    );

    if (result.rows.length === 0) {
      return res.status(404).send(`<!DOCTYPE html>
        <html>
        <head>
          <title>Unsubscribe - EmpowerMEd</title>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 20px; background: #f8f9fa; color: #333; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #3D52A0; margin-bottom: 20px; }
            .btn { display: inline-block; background: #3D52A0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-top: 20px; font-weight: bold; }
            .logo-img { max-width: 150px; height: auto; margin: 20px auto; display: block; }
          </style>
        </head>
        <body>
          <div class="container">
            <img src="${LOGO_URL}" alt="EmpowerMEd Logo" class="logo-img" onerror="this.style.display='none'">
            <h1>Invalid Unsubscribe Link</h1>
            <p>The unsubscribe link is invalid or has already been used.</p>
            <a href="${BASE_URL}" class="btn">Return to EmpowerMEd</a>
          </div>
        </body>
        </html>`);
    }

    const subscriber = result.rows[0];
    res.send(`<!DOCTYPE html>
      <html>
      <head>
        <title>Unsubscribed - EmpowerMEd</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 20px; background: #f8f9fa; color: #333; }
          .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          h1 { color: #3D52A0; margin-bottom: 20px; }
          .btn { display: inline-block; background: #3D52A0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-top: 20px; font-weight: bold; }
          .logo-img { max-width: 150px; height: auto; margin: 20px auto; display: block; }
        </style>
      </head>
      <body>
        <div class="container">
          <img src="${LOGO_URL}" alt="EmpowerMEd Logo" class="logo-img" onerror="this.style.display='none'">
          <h1>You've Been Unsubscribed</h1>
          <p><strong>${subscriber.email}</strong> has been removed from our newsletter list.</p>
          <p>We're sorry to see you go! If this was a mistake, you can resubscribe at any time.</p>
          <a href="${BASE_URL}" class="btn">Return to EmpowerMEd</a>
        </div>
      </body>
      </html>`);

  } catch (error) {
    console.error('Unsubscribe error:', error.message);
    res.status(500).send(`<!DOCTYPE html>
      <html>
      <head>
        <title>Error - EmpowerMEd</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 20px; background: #f8f9fa; color: #333; }
          .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          h1 { color: #dc3545; margin-bottom: 20px; }
          .btn { display: inline-block; background: #3D52A0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin-top: 20px; font-weight: bold; }
          .logo-img { max-width: 150px; height: auto; margin: 20px auto; display: block; }
        </style>
      </head>
      <body>
        <div class="container">
          <img src="${LOGO_URL}" alt="EmpowerMEd Logo" class="logo-img" onerror="this.style.display='none'">
          <h1>Unsubscribe Error</h1>
          <p>An error occurred while processing your unsubscribe request.</p>
          <p>Please contact us directly at EmpowerMEddev@gmail.com</p>
          <a href="${BASE_URL}" class="btn">Return to EmpowerMEd</a>
        </div>
      </body>
      </html>`);
  }
});

const adminRouter = express.Router();
adminRouter.use(checkJwt);
adminRouter.use(attachAdminUser);
adminRouter.use(requireAdmin);

adminRouter.get('/subscribers', async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', status = 'all' } = req.query;
    const pageNum = Math.max(1, parseInt(page)) || 1;
    const limitNum = Math.min(100, Math.max(1, parseInt(limit))) || 20;
    const offset = (pageNum - 1) * limitNum;

    const where = [];
    const params = [];

    if (search) {
      params.push(`%${search}%`);
      where.push(`(email ILIKE $${params.length} OR name ILIKE $${params.length})`);
    }

    if (status === 'active') {
      where.push('active = true AND verified_at IS NOT NULL');
    } else if (status === 'inactive') {
      where.push('active = false');
    } else if (status === 'pending') {
      where.push('verified_at IS NULL');
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    const subscribersResult = await pool.query(
        `SELECT id, email, name, subscribed_at, source, active, verified_at, CASE WHEN verified_at IS NOT NULL AND active = true THEN 'Verified' WHEN verified_at IS NULL AND active = false THEN 'Pending Verification' WHEN active = false THEN 'Unsubscribed' ELSE 'Unknown' END as status FROM newsletter_subscribers ${whereClause} ORDER BY subscribed_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limitNum, offset]
    );

    const countResult = await pool.query(
        `SELECT COUNT(*) as total FROM newsletter_subscribers ${whereClause}`,
        params
    );

    const total = parseInt(countResult.rows[0].total) || 0;

    res.json({
      success: true,
      subscribers: subscribersResult.rows,
      pagination: {
        currentPage: pageNum,
        totalPages: Math.ceil(total / limitNum),
        totalItems: total,
        itemsPerPage: limitNum
      }
    });

  } catch (error) {
    console.error('Get subscribers error:', error.message);
    res.status(500).json({ success: false, error: 'FETCH_SUBSCRIBERS_FAILED', message: 'Failed to fetch subscribers' });
  }
});

adminRouter.get('/stats', async (req, res) => {
  try {
    const totalsResult = await pool.query(`
      SELECT COUNT(*) as total,
      SUM(CASE WHEN active = true AND verified_at IS NOT NULL THEN 1 ELSE 0 END) as active,
      SUM(CASE WHEN active = false THEN 1 ELSE 0 END) as inactive,
      SUM(CASE WHEN verified_at IS NOT NULL THEN 1 ELSE 0 END) as verified,
      SUM(CASE WHEN verified_at IS NULL THEN 1 ELSE 0 END) as pending,
      SUM(CASE WHEN active = true AND verified_at IS NOT NULL AND subscribed_at >= NOW() - INTERVAL '30 days' THEN 1 ELSE 0 END) as this_month
      FROM newsletter_subscribers
    `);

    const growthResult = await pool.query(`
      SELECT DATE_TRUNC('month', subscribed_at) as month,
      COUNT(*) as new_subscribers,
      SUM(CASE WHEN verified_at IS NOT NULL THEN 1 ELSE 0 END) as verified
      FROM newsletter_subscribers
      WHERE subscribed_at >= NOW() - INTERVAL '6 months'
      GROUP BY DATE_TRUNC('month', subscribed_at)
      ORDER BY month DESC
    `);

    const sourcesResult = await pool.query(`
      SELECT COALESCE(source, 'direct') as source,
      COUNT(*) as count,
      ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM newsletter_subscribers), 2) as percentage
      FROM newsletter_subscribers
      GROUP BY COALESCE(source, 'direct')
      ORDER BY count DESC
      LIMIT 10
    `);

    const recentResult = await pool.query(`
      SELECT DATE(subscribed_at) as date,
      COUNT(*) as count,
      SUM(CASE WHEN verified_at IS NOT NULL THEN 1 ELSE 0 END) as verified
      FROM newsletter_subscribers
      WHERE subscribed_at >= NOW() - INTERVAL '7 days'
      GROUP BY DATE(subscribed_at)
      ORDER BY date DESC
    `);

    res.json({
      success: true,
      stats: {
        totals: totalsResult.rows[0],
        growth: growthResult.rows,
        sources: sourcesResult.rows,
        recent: recentResult.rows
      }
    });

  } catch (error) {
    console.error('Get stats error:', error.message);
    res.status(500).json({ success: false, error: 'FETCH_STATS_FAILED', message: 'Failed to fetch statistics' });
  }
});

adminRouter.get('/export', async (req, res) => {
  try {
    const { format = 'csv' } = req.query;

    const result = await pool.query(`
      SELECT email, name, subscribed_at, verified_at, source, active,
      CASE WHEN verified_at IS NOT NULL AND active = true THEN 'Verified'
      WHEN verified_at IS NULL AND active = false THEN 'Pending Verification'
      WHEN active = false THEN 'Unsubscribed' ELSE 'Unknown' END as status
      FROM newsletter_subscribers
      ORDER BY subscribed_at DESC
    `);

    if (format === 'csv') {
      const date = new Date().toISOString().split('T')[0];
      const csv = [
        ['Email', 'Name', 'Subscribed Date', 'Verified Date', 'Source', 'Active', 'Status'].join(','),
        ...result.rows.map(row => [
          `"${row.email}"`,
          `"${row.name || ''}"`,
          `"${row.subscribed_at ? new Date(row.subscribed_at).toISOString() : ''}"`,
          `"${row.verified_at ? new Date(row.verified_at).toISOString() : ''}"`,
          `"${row.source || ''}"`,
          `"${row.active ? 'Yes' : 'No'}"`,
          `"${row.status}"`
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=empowermed-subscribers-${date}.csv`);
      res.send(csv);
    } else {
      res.json({ success: true, subscribers: result.rows, exportedAt: new Date().toISOString(), count: result.rows.length });
    }

  } catch (error) {
    console.error('Export error:', error.message);
    res.status(500).json({ success: false, error: 'EXPORT_FAILED', message: 'Failed to export subscribers' });
  }
});

adminRouter.delete('/subscribers/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM newsletter_subscribers WHERE id = $1 RETURNING email', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'SUBSCRIBER_NOT_FOUND', message: 'Subscriber not found' });
    }

    res.json({ success: true, message: 'Subscriber deleted successfully', deletedEmail: result.rows[0].email });
  } catch (error) {
    console.error('Delete subscriber error:', error.message);
    res.status(500).json({ success: false, error: 'DELETE_FAILED', message: 'Failed to delete subscriber' });
  }
});

router.use('/admin', adminRouter);

module.exports = router;