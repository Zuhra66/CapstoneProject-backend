// middleware/admin-check.js - COMPLETE VERSION
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const { pool } = require('../db');

// IMPORTANT: Only import AuditLogger AFTER we verify it exists
// This prevents circular dependencies or startup issues

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
  getToken: (req) => {
    // Check Authorization header first (Bearer token from frontend)
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1];
    }

    // Fall back to cookie
    if (req.cookies && req.cookies.access_token) {
      return req.cookies.access_token;
    }

    return null;
  }
});

// Wrap with audit logging
const checkJwt = (req, res, next) => {
  console.log('🔐 JWT Validation Starting...');
  console.log('Request Path:', req.path);
  console.log('Auth Header Present:', !!req.headers.authorization);

  const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  checkJwtBase(req, res, async (err) => {
    if (err) {
      console.error('❌ JWT Validation Failed:', {
        name: err.name,
        message: err.message,
        code: err.code,
        status: err.status
      });

      // Log failed authentication attempt (only if AuditLogger is available)
      try {
        // Dynamically require AuditLogger to avoid circular dependencies
        const AuditLogger = require('../services/auditLogger');
        await AuditLogger.logSecurityEvent(
            null,
            'AUTH_FAILURE',
            `Failed authentication attempt: ${err.message}`,
            'high',
            ipAddress,
            userAgent
        );
      } catch (auditError) {
        // Only log if it's not a module not found error
        if (!auditError.message.includes('Cannot find module')) {
          console.error('Failed to log security event:', auditError);
        }
      }

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

    // Attach minimal user info for audit logging
    req.user = {
      sub: req.auth?.sub,
      email: req.auth?.email,
      // Will be populated with full user data in attachAdminUser
    };

    // Log successful authentication (only if AuditLogger is available)
    try {
      const AuditLogger = require('../services/auditLogger');
      await AuditLogger.log({
        userId: req.auth?.sub,
        userEmail: req.auth?.email,
        auth0UserId: req.auth?.sub,
        eventType: 'TOKEN_VALIDATION',
        eventCategory: 'authentication',
        eventDescription: 'JWT token validation successful',
        resourceType: 'system',
        ipAddress,
        userAgent,
        status: 'success'
      });
    } catch (auditError) {
      if (!auditError.message.includes('Cannot find module')) {
        console.error('Failed to log auth success:', auditError);
      }
    }

    next();
  });
};

/**
 * attachAdminUser - Enhanced with audit logging
 */
const attachAdminUser = async (req, res, next) => {
  const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  try {
    const auth0Sub = req.auth?.sub;

    console.log('🔐 ADMIN AUTH DEBUG ==========');
    console.log('Token sub:', auth0Sub);
    console.log('Token email:', req.auth?.email);

    if (!auth0Sub) {
      console.error('❌ No sub found in token');

      // Log the failure
      try {
        const AuditLogger = require('../services/auditLogger');
        await AuditLogger.logSecurityEvent(
            null,
            'USER_NOT_FOUND',
            'No user sub found in JWT token',
            'high',
            ipAddress,
            userAgent
        );
      } catch (auditError) {
        if (!auditError.message.includes('Cannot find module')) {
          console.error('Failed to log security event:', auditError);
        }
      }

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

      // Log the auth_sub fallback attempt
      try {
        const AuditLogger = require('../services/auditLogger');
        await AuditLogger.logSecurityEvent(
            { email: req.auth?.email, sub: auth0Sub },
            'USER_LOOKUP_FALLBACK',
            'User not found by auth0_id, trying auth_sub',
            'medium',
            ipAddress,
            userAgent
        );
      } catch (auditError) {
        if (!auditError.message.includes('Cannot find module')) {
          console.error('Failed to log security event:', auditError);
        }
      }

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

        // Log user not found
        try {
          const AuditLogger = require('../services/auditLogger');
          await AuditLogger.logSecurityEvent(
              { email: req.auth?.email, sub: auth0Sub },
              'USER_NOT_FOUND',
              'User not found in database - profile setup may be required',
              'medium',
              ipAddress,
              userAgent
          );
        } catch (auditError) {
          if (!auditError.message.includes('Cannot find module')) {
            console.error('Failed to log security event:', auditError);
          }
        }

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

    // Update req.user with full user data for audit middleware
    req.user = {
      id: user.id,
      sub: user.auth0_id || user.auth_sub,
      email: user.email,
      role: user.role,
      is_admin: user.is_admin,
      auth0_id: user.auth0_id,
      first_name: user.first_name,
      last_name: user.last_name,
      name: user.name
    };

    if (!user.is_active) {
      console.error('❌ User account is inactive');

      // Log inactive account attempt
      try {
        const AuditLogger = require('../services/auditLogger');
        await AuditLogger.logSecurityEvent(
            req.user,
            'ACCOUNT_INACTIVE',
            'User attempted to access with inactive account',
            'high',
            ipAddress,
            userAgent
        );
      } catch (auditError) {
        if (!auditError.message.includes('Cannot find module')) {
          console.error('Failed to log security event:', auditError);
        }
      }

      return res.status(403).json({
        error: 'Account deactivated',
        message: 'Your account has been deactivated. Please contact support.',
      });
    }

    console.log('✅ Admin user attached successfully');
    console.log('========================');

    // Log successful user attachment
    try {
      const AuditLogger = require('../services/auditLogger');
      await AuditLogger.log({
        userId: user.id,
        userEmail: user.email,
        userRole: user.role,
        auth0UserId: user.auth0_id,
        eventType: 'USER_ATTACHED',
        eventCategory: 'authentication',
        eventDescription: 'User successfully attached to request',
        resourceType: 'user',
        resourceId: user.id,
        resourceName: user.email,
        ipAddress,
        userAgent,
        status: 'success'
      });
    } catch (auditError) {
      if (!auditError.message.includes('Cannot find module')) {
        console.error('Failed to log user attachment:', auditError);
      }
    }

    req.adminUser = user;
    next();
  } catch (error) {
    console.error('❌ attachAdminUser error:', error);

    // Log the error
    try {
      const AuditLogger = require('../services/auditLogger');
      await AuditLogger.logSecurityEvent(
          req.user || { email: req.auth?.email, sub: req.auth?.sub },
          'ATTACH_USER_ERROR',
          `Failed to attach user: ${error.message}`,
          'high',
          ipAddress,
          userAgent
      );
    } catch (auditError) {
      if (!auditError.message.includes('Cannot find module')) {
        console.error('Failed to log security event:', auditError);
      }
    }

    res.status(500).json({
      error: 'Authorization error',
      message: 'Failed to verify user account',
    });
  }
};

const requireAdmin = async (req, res, next) => {
  const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  console.log('🔐 REQUIRE ADMIN CHECK ==========');
  console.log('Admin user present:', !!req.adminUser);

  if (!req.adminUser) {
    console.error('❌ No admin user found in request');

    try {
      const AuditLogger = require('../services/auditLogger');
      await AuditLogger.logSecurityEvent(
          req.user || null,
          'MISSING_ADMIN_CONTEXT',
          'Admin check failed - no admin user in request',
          'high',
          ipAddress,
          userAgent
      );
    } catch (auditError) {
      if (!auditError.message.includes('Cannot find module')) {
        console.error('Failed to log security event:', auditError);
      }
    }

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

    // Log unauthorized admin access attempt
    try {
      const AuditLogger = require('../services/auditLogger');
      await AuditLogger.logSecurityEvent(
          req.user,
          'UNAUTHORIZED_ADMIN_ACCESS',
          `Non-admin user attempted to access admin resource: ${req.method} ${req.path}`,
          'high',
          ipAddress,
          userAgent
      );
    } catch (auditError) {
      if (!auditError.message.includes('Cannot find module')) {
        console.error('Failed to log security event:', auditError);
      }
    }

    return res.status(403).json({
      error: 'Forbidden',
      message: 'Administrator privileges required to access this resource',
    });
  }

  console.log('✅ Admin access granted');
  console.log('========================');

  // Log successful admin access
  try {
    const AuditLogger = require('../services/auditLogger');
    await AuditLogger.log({
      userId: req.adminUser.id,
      userEmail: req.adminUser.email,
      userRole: req.adminUser.role,
      auth0UserId: req.adminUser.auth0_id,
      eventType: 'ADMIN_ACCESS_GRANTED',
      eventCategory: 'access',
      eventDescription: `Admin access to ${req.method} ${req.path}`,
      resourceType: 'system',
      ipAddress,
      userAgent,
      status: 'success'
    });
  } catch (auditError) {
    if (!auditError.message.includes('Cannot find module')) {
      console.error('Failed to log admin access:', auditError);
    }
  }

  next();
};

// Helper middleware for non-admin authenticated routes
const requireAuthenticated = async (req, res, next) => {
  console.log('🔐 AUTHENTICATED CHECK ==========');

  if (!req.user) {
    console.error('❌ No user found in request');

    try {
      const AuditLogger = require('../services/auditLogger');
      await AuditLogger.logSecurityEvent(
          null,
          'UNAUTHENTICATED_ACCESS',
          'Unauthenticated access attempt',
          'high',
          req.ip || req.headers['x-forwarded-for'],
          req.headers['user-agent']
      );
    } catch (auditError) {
      if (!auditError.message.includes('Cannot find module')) {
        console.error('Failed to log security event:', auditError);
      }
    }

    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required',
    });
  }

  console.log('✅ User authenticated:', req.user.email);
  next();
};

module.exports = {
  checkJwt,
  attachAdminUser,
  requireAdmin,
  requireAuthenticated
};