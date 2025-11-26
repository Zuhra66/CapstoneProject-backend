// middleware/admin-check.js
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const { pool } = require('../db');

// Reuse your existing Auth0 JWT check
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5, // Reduced for production
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
  }),
  audience: process.env.AUTH0_AUDIENCE,
  issuer: `https://${process.env.AUTH0_DOMAIN}/`,
  algorithms: ['RS256'],
});

/**
 * attachAdminUser
 * - Uses the Auth0 sub from the validated token
 * - Loads the user from Postgres
 * - Checks active status
 * - Attaches user to req.adminUser
 */
const attachAdminUser = async (req, res, next) => {
  try {
    // express-jwt puts payload on req.auth
    const auth0Id =
      req.auth?.sub ||
      req.auth?.payload?.sub; // keep this fallback just in case

    if (!auth0Id) {
      console.error('No auth0_id found in token');
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid authentication token',
      });
    }

    const userResult = await pool.query(
      'SELECT id, role, is_active, email FROM users WHERE auth0_id = $1',
      [auth0Id]
    );

    if (userResult.rows.length === 0) {
      console.warn(`User not found in database: ${auth0Id}`);
      return res.status(404).json({
        error: 'User not found',
        message: 'Please complete your profile setup',
      });
    }

    const user = userResult.rows[0];

    if (!user.is_active) {
      console.warn(`Inactive account access attempt: ${user.email}`);
      return res.status(403).json({
        error: 'Account deactivated',
        message: 'Your account has been deactivated. Please contact support.',
      });
    }

    // Attach user for downstream middleware/routes
    req.adminUser = user;
    next();
  } catch (error) {
    console.error('attachAdminUser error:', error);
    res.status(500).json({
      error: 'Authorization error',
      message: 'Failed to verify user account',
    });
  }
};

/**
 * requireAdmin
 * - Requires that req.adminUser (from attachAdminUser) has role 'Administrator'
 */
const requireAdmin = (req, res, next) => {
  const user = req.adminUser;

  if (!user) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'User context missing. Did you forget attachAdminUser?',
    });
  }

  if (user.role !== 'Administrator') {
    console.warn(`Non-admin access attempt: ${user.email} (role: ${user.role})`);
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Administrator privileges required to access this resource',
    });
  }

  next();
};

module.exports = { checkJwt, attachAdminUser, requireAdmin };
