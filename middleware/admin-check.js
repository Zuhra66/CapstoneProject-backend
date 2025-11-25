// middleware/admin-check.js
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const pool = require('../db');

// Reuse your existing Auth0 JWT check
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5, // Reduced for production
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
  }),
  audience: process.env.AUTH0_AUDIENCE,
  issuer: `https://${process.env.AUTH0_DOMAIN}/`,
  algorithms: ['RS256']
});

// Admin role check using your database
const requireAdmin = async (req, res, next) => {
  try {
    // User is already validated by checkJwt at this point
    const auth0Id = req.auth?.payload?.sub;

    if (!auth0Id) {
      console.error('No auth0_id found in token');
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid authentication token'
      });
    }

    // Check user role in your PostgreSQL database
    const userResult = await pool.query(
        'SELECT id, role, is_active, email FROM users WHERE auth0_id = $1',
        [auth0Id]
    );

    if (userResult.rows.length === 0) {
      console.warn(`User not found in database: ${auth0Id}`);
      return res.status(404).json({
        error: 'User not found',
        message: 'Please complete your profile setup'
      });
    }

    const user = userResult.rows[0];

    // Check if account is active
    if (!user.is_active) {
      console.warn(`Inactive admin access attempt: ${user.email}`);
      return res.status(403).json({
        error: 'Account deactivated',
        message: 'Your account has been deactivated. Please contact support.'
      });
    }

    // Check if user has admin role
    if (user.role !== 'Administrator') {
      console.warn(`Non-admin access attempt: ${user.email} (role: ${user.role})`);
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Administrator privileges required to access this resource'
      });
    }

    // Add admin user to request for audit logging
    req.adminUser = user;
    next();
  } catch (error) {
    console.error('Admin role check error:', error);
    res.status(500).json({
      error: 'Authorization error',
      message: 'Failed to verify administrator access'
    });
  }
};

module.exports = { checkJwt, requireAdmin };
