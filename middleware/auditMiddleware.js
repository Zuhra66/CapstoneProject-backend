// middleware/auditMiddleware.js
// IMPORTANT: Use dynamic require to avoid circular dependencies

/**
 * Middleware to log all authenticated requests
 */
const auditMiddleware = async (req, res, next) => {
  // Store original send function
  const originalSend = res.send;
  const originalJson = res.json;

  // Capture response data
  let responseBody;

  // Override send to capture response
  res.send = function(body) {
    responseBody = body;
    return originalSend.call(this, body);
  };

  res.json = function(body) {
    responseBody = body;
    return originalJson.call(this, body);
  };

  // Log after response is sent
  res.on('finish', async () => {
    try {
      // Only log authenticated requests
      if (req.user) {
        const user = req.user;
        const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];

        // Determine event type based on route and method
        let eventType = 'API_REQUEST';
        let eventCategory = 'access';
        let resourceType = getResourceType(req.path);
        let resourceId = req.params.id || null;

        // Log based on HTTP method
        if (req.method === 'GET') {
          eventType = 'DATA_ACCESS';
        } else if (req.method === 'POST') {
          eventType = 'DATA_CREATE';
          eventCategory = 'modification';
        } else if (req.method === 'PUT' || req.method === 'PATCH') {
          eventType = 'DATA_UPDATE';
          eventCategory = 'modification';
        } else if (req.method === 'DELETE') {
          eventType = 'DATA_DELETE';
          eventCategory = 'modification';
        }

        // Dynamically require AuditLogger to avoid circular dependencies
        try {
          const AuditLogger = require('../services/auditLogger');
          await AuditLogger.log({
            userId: user.id || user.sub,
            userEmail: user.email,
            userRole: user.role || 'user',
            auth0UserId: user.sub || user.auth0_id,
            eventType,
            eventCategory,
            eventDescription: `${req.method} ${req.path} - Status: ${res.statusCode}`,
            resourceType,
            resourceId,
            resourceName: getResourceName(req.path, resourceId),
            ipAddress,
            userAgent,
            status: res.statusCode >= 400 ? 'failure' : 'success',
            errorMessage: res.statusCode >= 400 ? (responseBody?.error || responseBody?.message || 'Request failed') : null
          });
        } catch (auditError) {
          // Only log if it's not a module not found error
          if (!auditError.message.includes('Cannot find module')) {
            console.error('Audit logging failed:', auditError);
          }
        }
      }
    } catch (error) {
      console.error('Audit middleware error:', error);
      // Don't break the response
    }
  });

  next();
};

// Helper functions
function getResourceType(path) {
  if (path.includes('/api/patients')) return 'patient';
  if (path.includes('/api/appointments')) return 'appointment';
  if (path.includes('/api/medical-records')) return 'medical_record';
  if (path.includes('/api/users')) return 'user';
  if (path.includes('/api/newsletter')) return 'newsletter';
  if (path.includes('/api/admin')) return 'admin';
  if (path.includes('/api/audit')) return 'audit_log';
  if (path.includes('/api/profile')) return 'profile';
  if (path.includes('/api/catalog')) return 'catalog';
  if (path.includes('/api/education')) return 'education';
  if (path.includes('/api/blog')) return 'blog';
  if (path.includes('/api/events')) return 'event';
  return 'system';
}

function getResourceName(path, resourceId) {
  const resourceType = getResourceType(path);

  if (resourceId) {
    return `${resourceType}_${resourceId}`;
  }

  // Extract resource name from path if possible
  const pathParts = path.split('/').filter(Boolean);
  if (pathParts.length > 2) {
    return pathParts.slice(-1)[0] || resourceType;
  }

  return resourceType;
}

module.exports = auditMiddleware;