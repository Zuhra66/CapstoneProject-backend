// middleware/admin-check.js - Fixed version with JWT error handling
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const { pool } = require('../db');

// Create the base JWT middleware
const checkJwtBase = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
  }),
  audience: process.env.AUTH0_AUDIENCE,
  issuer: `https://${process.env.AUTH0_DOMAIN}/`,
  algorithms: ['RS256'],
  credentialsRequired: true,
});

// Wrap it with proper error handling
const checkJwt = (req, res, next) => {
  console.log('🔐 JWT Validation Starting...');
  console.log('Request Path:', req.path);
  console.log('Auth Header Present:', !!req.headers.authorization);

  checkJwtBase(req, res, (err) => {
    if (err) {
      console.error('❌ JWT Validation Failed:', {
        name: err.name,
        message: err.message,
        code: err.code,
        status: err.status
      });

      // Handle specific JWT errors
      if (err.name === 'UnauthorizedError') {
        if (err.code === 'invalid_token') {
          return res.status(401).json({
            error: 'Invalid token',
            message: 'Token is malformed or invalid'
          });
        }
        if (err.code === 'credentials_required') {
          return res.status(401).json({
            error: 'Token required',
            message: 'No authorization token was found'
          });
        }
        return res.status(401).json({
          error: 'Authentication failed',
          message: err.message
        });
      }

      // For any other JWT errors, return 403
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Token validation failed'
      });
    }

    // JWT validation successful
    console.log('✅ JWT Validation Successful');
    console.log('Token payload sub:', req.auth?.sub);
    console.log('Token payload email:', req.auth?.email);
    next();
  });
};

/**
 * attachAdminUser - Your existing code is fine
 */
const attachAdminUser = async (req, res, next) => {
  try {
    const auth0Sub = req.auth?.sub;

    console.log('🔐 ADMIN AUTH DEBUG ==========');
    console.log('Token sub:', auth0Sub);
    console.log('Token email:', req.auth?.email);

    if (!auth0Sub) {
      console.error('❌ No sub found in token');
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid authentication token' });
    }

    // Try to find user by auth0_id
    console.log('🔍 Looking for user with auth0_id:', auth0Sub);
    const userResult = await pool.query(
        `SELECT id, auth0_id, auth_sub, email, first_name, last_name, name, role, 
              is_active, is_admin, created_at, updated_at 
       FROM users WHERE auth0_id = $1`,
        [auth0Sub]
    );

    console.log('📊 Query result:', userResult.rows.length ? 'FOUND' : 'NOT FOUND');

    if (userResult.rows.length === 0) {
      console.warn('❌ User not found by auth0_id, trying auth_sub...');
      // Try auth_sub as fallback
      const userResult2 = await pool.query(
          `SELECT id, auth0_id, auth_sub, email, first_name, last_name, name, role, 
                is_active, is_admin, created_at, updated_at 
         FROM users WHERE auth_sub = $1`,
          [auth0Sub]
      );
      console.log('📊 auth_sub query result:', userResult2.rows.length ? 'FOUND' : 'NOT FOUND');

      if (userResult2.rows.length === 0) {
        console.error('❌ User not found by any method');
        return res.status(404).json({
          error: 'User not found',
          message: 'Please complete your profile setup',
        });
      }

      var user = userResult2.rows[0];
    } else {
      var user = userResult.rows[0];
    }

    console.log('✅ User found:', {
      id: user.id,
      email: user.email,
      is_admin: user.is_admin,
      is_active: user.is_active,
      auth0_id: user.auth0_id,
      auth_sub: user.auth_sub
    });

    if (!user.is_active) {
      console.error('❌ User account is inactive');
      return res.status(403).json({
        error: 'Account deactivated',
        message: 'Your account has been deactivated. Please contact support.',
      });
    }

    console.log('✅ Admin user attached successfully');
    console.log('========================');

    req.adminUser = user;
    next();
  } catch (error) {
    console.error('❌ attachAdminUser error:', error);
    res.status(500).json({
      error: 'Authorization error',
      message: 'Failed to verify user account',
    });
  }
};

const requireAdmin = (req, res, next) => {
  console.log('🔐 REQUIRE ADMIN CHECK ==========');
  console.log('Admin user present:', !!req.adminUser);

  if (!req.adminUser) {
    console.error('❌ No admin user found in request');
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'User context missing. Did you forget attachAdminUser?',
    });
  }

  console.log('👤 Checking admin privileges for:', req.adminUser.email);
  console.log('is_admin:', req.adminUser.is_admin);
  console.log('role:', req.adminUser.role);

  const isAdmin = req.adminUser.is_admin === true || req.adminUser.role === 'Administrator';

  if (!isAdmin) {
    console.error('❌ User is not admin');
    console.log('========================');
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Administrator privileges required to access this resource',
    });
  }

  console.log('✅ Admin access granted');
  console.log('========================');
  next();
};

module.exports = { checkJwt, attachAdminUser, requireAdmin };