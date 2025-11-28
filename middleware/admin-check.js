// middleware/admin-check.js - Fixed version with consistent JWT configuration
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const { pool } = require('../db');

// JWT validation middleware - SAME configuration used everywhere
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
  }),
  audience: process.env.AUTH0_AUDIENCE,
  issuer: `https://${process.env.AUTH0_DOMAIN}/`,
  algorithms: ['RS256'],
  credentialsRequired: true, // Explicitly set to true for consistency
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
    const auth0Id = req.auth?.sub;

    if (!auth0Id) {
      console.error('No auth0_id found in token');
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid authentication token',
      });
    }

    const userResult = await pool.query(
        `SELECT id, auth0_id, email, first_name, last_name, name, role, 
              is_active, is_admin, created_at, updated_at 
       FROM users WHERE auth0_id = $1`,
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

    console.log('✅ Admin user attached:', { id: user.id, email: user.email, role: user.role });

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
 * - Requires that req.adminUser (from attachAdminUser) has role 'Administrator' or is_admin = true
 */
const requireAdmin = (req, res, next) => {
  const user = req.adminUser;

  if (!user) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'User context missing. Did you forget attachAdminUser?',
    });
  }

  // Check both is_admin flag and role for flexibility
  const isAdmin = user.is_admin === true || user.role === 'Administrator';

  if (!isAdmin) {
    console.warn(`Non-admin access attempt: ${user.email} (role: ${user.role}, is_admin: ${user.is_admin})`);
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Administrator privileges required to access this resource',
    });
  }

  console.log('✅ Admin access granted for:', user.email);
  next();
};

module.exports = { checkJwt, attachAdminUser, requireAdmin };