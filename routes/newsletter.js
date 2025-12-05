// routes/newsletter.js - SIMPLIFIED WORKING VERSION
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { pool } = require('../db');
const { checkJwt, attachAdminUser, requireAdmin } = require('../middleware/admin-check');

// ==================== SENDGRID EMAIL INTEGRATION ====================
const sgMail = require('@sendgrid/mail');

// Initialize SendGrid
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  console.log('✅ SendGrid initialized');
} else {
  console.log('⚠️  SENDGRID_API_KEY not found. Emails will be logged to console.');
}

// Email configuration
const EMAIL_CONFIG = {
  fromEmail: process.env.EMAIL_FROM || 'wellness@empowermedwellness.com',
  fromName: process.env.EMAIL_FROM_NAME || 'EmpowerMed Wellness',
  replyTo: process.env.EMAIL_REPLY_TO || 'EmpowerMEddev@gmail.com'
};

/**
 * Generate a secure random token
 */
const generateToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Send verification email
 */
const sendVerificationEmail = async (email, name, token) => {
  try {
    const verificationLink = `https://www.empowermedwellness.com/api/newsletter/verify/${token}`;

    const msg = {
      to: email,
      from: {
        email: EMAIL_CONFIG.fromEmail,
        name: EMAIL_CONFIG.fromName
      },
      replyTo: EMAIL_CONFIG.replyTo,
      subject: 'Please confirm your subscription to EmpowerMed Wellness',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
            .header { background: linear-gradient(135deg, #3D52A0, #7091E6); padding: 30px; text-align: center; }
            .content { padding: 30px; background: #f9f9f9; }
            .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
            .button { display: inline-block; background: #3D52A0; color: white; padding: 12px 24px; 
                     text-decoration: none; border-radius: 6px; margin: 20px 0; }
            .logo { font-family: 'Aboreto', cursive; color: white; font-size: 24px; }
          </style>
        </head>
        <body>
          <div class="header">
            <div class="logo">EmpowerMed Wellness</div>
          </div>
          <div class="content">
            <h2>Welcome to EmpowerMed Wellness!</h2>
            <p>Hello ${name || 'there'},</p>
            <p>Thank you for subscribing to our wellness newsletter. To complete your subscription and start receiving our updates, please confirm your email address:</p>
            <p style="text-align: center;">
              <a href="${verificationLink}" class="button">Confirm Subscription</a>
            </p>
            <p>If you didn't request this subscription, you can safely ignore this email.</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} EmpowerMed Wellness LLC. All rights reserved.</p>
            <p>3600 Sisk Road, Suite 2D, Modesto, CA, USA</p>
          </div>
        </body>
        </html>
      `,
      text: `Welcome to EmpowerMed Wellness!\n\nPlease confirm your subscription by visiting:\n${verificationLink}\n\nIf you didn't request this, please ignore this email.\n\nThis link will expire in 24 hours.`
    };

    if (process.env.SENDGRID_API_KEY) {
      await sgMail.send(msg);
      console.log(`✅ Verification email sent to: ${email}`);
    } else {
      console.log(`[EMAIL LOG] Verification link for ${email}: ${verificationLink}`);
    }

    return { success: true };

  } catch (error) {
    console.error('SendGrid error:', error.response?.body || error.message);
    console.log(`[EMAIL FALLBACK] Verification link: https://www.empowermedwellness.com/api/newsletter/verify/${token}`);
    return { success: false };
  }
};

/**
 * Send welcome email
 */
const sendWelcomeEmail = async (email, name, unsubscribeToken) => {
  try {
    const unsubscribeLink = unsubscribeToken ?
        `https://www.empowermedwellness.com/api/newsletter/unsubscribe/${unsubscribeToken}` :
        'https://www.empowermedwellness.com';

    const msg = {
      to: email,
      from: {
        email: EMAIL_CONFIG.fromEmail,
        name: EMAIL_CONFIG.fromName
      },
      replyTo: EMAIL_CONFIG.replyTo,
      subject: 'Welcome to EmpowerMed Wellness - Your Subscription is Confirmed!',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
            .header { background: linear-gradient(135deg, #3D52A0, #7091E6); padding: 30px; text-align: center; }
            .content { padding: 30px; background: #f9f9f9; }
            .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
            .logo { font-family: 'Aboreto', cursive; color: white; font-size: 24px; }
            .features { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .feature-item { margin: 10px 0; }
            .unsubscribe { font-size: 12px; color: #666; margin-top: 30px; }
          </style>
        </head>
        <body>
          <div class="header">
            <div class="logo">EmpowerMed Wellness</div>
          </div>
          <div class="content">
            <h2>🎉 Welcome to Our Wellness Community!</h2>
            <p>Hello ${name || 'wellness enthusiast'},</p>
            <p>Your subscription to EmpowerMed Wellness updates has been confirmed. We're excited to have you join our community!</p>
            
            <div class="features">
              <h3>What to expect:</h3>
              <div class="feature-item">✓ Weekly wellness tips and insights</div>
              <div class="feature-item">✓ Exclusive content and resources</div>
              <div class="feature-item">✓ Updates on events and workshops</div>
              <div class="feature-item">✓ Special offers for subscribers</div>
            </div>
            
            <p>Stay tuned for our next update, and remember: wellness is a journey, not a destination.</p>
            
            <p>With gratitude,<br>
            <strong>Dr. Diana Galván & The EmpowerMed Team</strong></p>
            
            ${unsubscribeToken ? `<div class="unsubscribe">
              <p><small>You can <a href="${unsubscribeLink}">unsubscribe</a> anytime if you change your mind.</small></p>
            </div>` : ''}
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} EmpowerMed Wellness LLC. All rights reserved.</p>
            <p>3600 Sisk Road, Suite 2D, Modesto, CA, USA</p>
          </div>
        </body>
        </html>
      `,
      text: `Welcome to EmpowerMed Wellness!\n\nYour subscription has been confirmed. You'll now receive:\n- Weekly wellness tips\n- Exclusive content\n- Event updates\n- Special offers\n\nStay healthy and empowered!\n\nThe EmpowerMed Wellness Team`
    };

    if (process.env.SENDGRID_API_KEY) {
      await sgMail.send(msg);
      console.log(`✅ Welcome email sent to: ${email}`);
    } else {
      console.log(`[EMAIL LOG] Welcome email would be sent to: ${email}`);
    }

    return { success: true };

  } catch (error) {
    console.error('SendGrid error:', error.response?.body || error.message);
    return { success: false };
  }
};

// ==================== DATABASE SETUP ====================

/**
 * Check and create necessary tables if they don't exist
 */
const setupDatabase = async () => {
  try {
    // Check if newsletter_subscribers table exists
    const tableCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'newsletter_subscribers'
      )
    `);

    if (!tableCheck.rows[0].exists) {
      console.log('Creating newsletter_subscribers table...');

      // Create basic table
      await pool.query(`
        CREATE TABLE newsletter_subscribers (
          id SERIAL PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          name VARCHAR(100),
          subscribed_at TIMESTAMP DEFAULT NOW(),
          source VARCHAR(50) DEFAULT 'website_footer',
          active BOOLEAN DEFAULT TRUE,
          verification_token VARCHAR(100),
          verification_expires TIMESTAMP,
          verified_at TIMESTAMP,
          unsubscribe_token VARCHAR(100) UNIQUE DEFAULT encode(gen_random_bytes(50), 'hex')
        )
      `);

      console.log('✅ Created newsletter_subscribers table');
    }

    return true;
  } catch (error) {
    console.error('Database setup error:', error.message);
    return false;
  }
};

// ==================== PUBLIC ROUTES ====================

/**
 * PUBLIC ROUTE: Subscribe to newsletter
 */
router.post('/subscribe', async (req, res) => {
  try {
    const { email, name } = req.body;

    // Validate email
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_EMAIL',
        message: 'Please provide a valid email address'
      });
    }

    const lowerEmail = email.toLowerCase().trim();
    const source = req.headers.referer || 'website_footer';

    // Setup database if needed
    await setupDatabase();

    // Check if already subscribed
    const existing = await pool.query(
        `SELECT id, active, verified_at FROM newsletter_subscribers WHERE email = $1`,
        [lowerEmail]
    );

    if (existing.rows.length > 0) {
      const subscriber = existing.rows[0];

      // If already verified and active
      if (subscriber.verified_at && subscriber.active) {
        return res.status(200).json({
          success: true,
          verified: true,
          message: 'You are already subscribed to our newsletter!'
        });
      }

      // If pending verification, resend verification
      if (!subscriber.verified_at) {
        const verificationToken = generateToken();
        const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        await pool.query(
            `UPDATE newsletter_subscribers 
           SET verification_token = $1, 
               verification_expires = $2,
               name = COALESCE($3, name)
           WHERE id = $4`,
            [verificationToken, verificationExpires, name, subscriber.id]
        );

        // Send verification email
        await sendVerificationEmail(lowerEmail, name, verificationToken);

        return res.status(200).json({
          success: true,
          verified: false,
          message: 'Verification email resent. Please check your inbox to confirm your subscription.'
        });
      }
    }

    // New subscriber
    const verificationToken = generateToken();
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    try {
      const result = await pool.query(
          `INSERT INTO newsletter_subscribers 
         (email, name, source, verification_token, verification_expires) 
         VALUES ($1, $2, $3, $4, $5) 
         RETURNING id`,
          [lowerEmail, name, source, verificationToken, verificationExpires]
      );

      console.log(`✅ New subscriber: ${lowerEmail}`);

      // Send verification email
      await sendVerificationEmail(lowerEmail, name, verificationToken);

      res.status(200).json({
        success: true,
        verified: false,
        message: 'Thank you! Please check your email to confirm your subscription.'
      });

    } catch (dbError) {
      // Handle duplicate email gracefully
      if (dbError.code === '23505') {
        return res.status(200).json({
          success: true,
          verified: false,
          message: 'Subscription pending verification. Please check your email.'
        });
      }
      throw dbError;
    }

  } catch (error) {
    console.error('Subscription error:', error.message);

    res.status(500).json({
      success: false,
      error: 'SUBSCRIPTION_FAILED',
      message: 'Unable to process subscription. Please try again later.'
    });
  }
});

/**
 * PUBLIC ROUTE: Verify email subscription
 */
router.get('/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(
        `UPDATE newsletter_subscribers 
       SET active = true, 
           verified_at = NOW(),
           verification_token = NULL,
           verification_expires = NULL,
           unsubscribe_token = COALESCE(unsubscribe_token, encode(gen_random_bytes(50), 'hex'))
       WHERE verification_token = $1 
         AND verification_expires > NOW()
         AND verified_at IS NULL
       RETURNING id, email, name, unsubscribe_token`,
        [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Verification Failed</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .container { max-width: 600px; margin: 0 auto; }
            h1 { color: #3D52A0; }
            .error { color: #dc3545; }
            .btn { display: inline-block; background: #3D52A0; color: white; 
                  padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Verification Failed</h1>
            <p class="error">The verification link is invalid or has expired.</p>
            <p>Please try subscribing again.</p>
            <a href="https://www.empowermedwellness.com" class="btn">Return to Website</a>
          </div>
        </body>
        </html>
      `);
    }

    const subscriber = result.rows[0];

    // Send welcome email
    await sendWelcomeEmail(subscriber.email, subscriber.name, subscriber.unsubscribe_token);

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Subscription Confirmed</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          .container { max-width: 600px; margin: 0 auto; }
          h1 { color: #3D52A0; }
          .success { color: #28a745; font-size: 48px; margin: 20px 0; }
          .btn { display: inline-block; background: #3D52A0; color: white; 
                padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="success">✓</div>
          <h1>Subscription Confirmed!</h1>
          <p>Thank you for verifying your email address.</p>
          <p>Your subscription to EmpowerMed Wellness updates is now active.</p>
          <p>A welcome email has been sent to <strong>${subscriber.email}</strong>.</p>
          <a href="https://www.empowermedwellness.com" class="btn">Continue to EmpowerMed Wellness</a>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('Verification error:', error.message);
    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Error</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          .container { max-width: 600px; margin: 0 auto; }
          h1 { color: #dc3545; }
          .btn { display: inline-block; background: #3D52A0; color: white; 
                padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Verification Error</h1>
          <p>An error occurred while verifying your subscription.</p>
          <p>Please try again or contact us for assistance.</p>
          <a href="https://www.empowermedwellness.com" class="btn">Return to Website</a>
        </div>
      </body>
      </html>
    `);
  }
});

/**
 * PUBLIC ROUTE: Unsubscribe
 */
router.get('/unsubscribe/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(
        `UPDATE newsletter_subscribers 
       SET active = false
       WHERE unsubscribe_token = $1 
         AND active = true
       RETURNING id, email`,
        [token]
    );

    if (result.rows.length === 0) {
      return res.status(404).send(`
        <html>
        <head><title>Invalid Link</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
          <h1>Invalid Unsubscribe Link</h1>
          <p>The unsubscribe link is invalid or has already been used.</p>
          <a href="https://www.empowermedwellness.com">Return to Website</a>
        </body>
        </html>
      `);
    }

    const subscriber = result.rows[0];

    res.send(`
      <html>
      <head><title>Unsubscribed</title></head>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1>You've Been Unsubscribed</h1>
        <p><strong>${subscriber.email}</strong> has been removed from our newsletter list.</p>
        <p>We're sorry to see you go!</p>
        <a href="https://www.empowermedwellness.com">Return to EmpowerMed Wellness</a>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('Unsubscribe error:', error.message);
    res.status(500).send(`
      <html>
      <head><title>Error</title></head>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1>Unsubscribe Error</h1>
        <p>An error occurred while processing your unsubscribe request.</p>
        <p>Please contact us directly at EmpowerMEddev@gmail.com</p>
        <a href="https://www.empowermedwellness.com">Return to Website</a>
      </body>
      </html>
    `);
  }
});

// ==================== ADMIN ROUTES ====================

const adminRouter = express.Router();

// Apply admin middleware
adminRouter.use(checkJwt);
adminRouter.use(attachAdminUser);
adminRouter.use(requireAdmin);

/**
 * ADMIN: Get all subscribers
 */
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
      where.push('active = true');
    } else if (status === 'inactive') {
      where.push('active = false');
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    const subscribersResult = await pool.query(
        `SELECT id, email, name, subscribed_at, source, active, verified_at 
       FROM newsletter_subscribers 
       ${whereClause}
       ORDER BY subscribed_at DESC
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
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
    console.error('Admin get subscribers error:', error.message);
    res.status(500).json({
      success: false,
      error: 'FETCH_SUBSCRIBERS_FAILED',
      message: 'Failed to fetch subscribers'
    });
  }
});

/**
 * ADMIN: Get statistics
 */
adminRouter.get('/stats', async (req, res) => {
  try {
    const totalsResult = await pool.query(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN active THEN 1 ELSE 0 END) as active,
        SUM(CASE WHEN NOT active THEN 1 ELSE 0 END) as inactive,
        SUM(CASE WHEN verified_at IS NOT NULL THEN 1 ELSE 0 END) as verified,
        SUM(CASE WHEN verified_at IS NULL THEN 1 ELSE 0 END) as pending
      FROM newsletter_subscribers
    `);

    const recentResult = await pool.query(`
      SELECT 
        DATE(subscribed_at) as date,
        COUNT(*) as count
      FROM newsletter_subscribers
      WHERE subscribed_at >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(subscribed_at)
      ORDER BY date DESC
    `);

    res.json({
      success: true,
      stats: {
        totals: totalsResult.rows[0],
        recentSubscriptions: recentResult.rows
      }
    });

  } catch (error) {
    console.error('Admin get stats error:', error.message);
    res.status(500).json({
      success: false,
      error: 'FETCH_STATS_FAILED',
      message: 'Failed to fetch statistics'
    });
  }
});

// Mount admin routes
router.use('/', adminRouter);

module.exports = router;