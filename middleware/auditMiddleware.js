const auditMiddleware = async (req, res, next) => {
  const originalSend = res.send;
  const originalJson = res.json;
  let responseBody;
  let auditLogged = false;

  res.send = function (body) {
    responseBody = body;
    return originalSend.call(this, body);
  };

  res.json = function (body) {
    responseBody = body;
    return originalJson.call(this, body);
  };

  const cleanup = () => {
    if (!auditLogged) {
      res.removeListener('finish', logAudit);
      res.removeListener('close', cleanup);
      res.removeListener('error', cleanup);
    }
  };

  const logAudit = async () => {
    if (auditLogged) return;
    auditLogged = true;

    try {
      if (!req.user) return;

      const user = req.user;
      const ipAddress = req.ip ||
          req.headers['x-forwarded-for'] ||
          req.connection.remoteAddress ||
          req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'] || 'Unknown';

      let eventType, eventCategory;
      switch (req.method) {
        case 'GET':
          eventType = 'DATA_ACCESS';
          eventCategory = 'access';
          break;
        case 'POST':
          eventType = 'DATA_CREATE';
          eventCategory = 'modification';
          break;
        case 'PUT':
        case 'PATCH':
          eventType = 'DATA_UPDATE';
          eventCategory = 'modification';
          break;
        case 'DELETE':
          eventType = 'DATA_DELETE';
          eventCategory = 'modification';
          break;
        default:
          eventType = 'API_REQUEST';
          eventCategory = 'access';
      }

      const resourceType = getResourceType(req.path);
      const resourceId = req.params.id ||
          req.body?.id ||
          req.query?.id ||
          null;
      const resourceName = getResourceName(req.path, resourceId);

      let errorMessage = null;
      if (res.statusCode >= 400) {
        if (typeof responseBody === 'string') {
          try {
            const parsed = JSON.parse(responseBody);
            errorMessage = parsed.error || parsed.message || 'Request failed';
          } catch {
            errorMessage = responseBody || 'Request failed';
          }
        } else if (responseBody && typeof responseBody === 'object') {
          errorMessage = responseBody.error || responseBody.message || 'Request failed';
        } else {
          errorMessage = 'Request failed';
        }
      }

      const auditData = {
        userId: user.id || user.sub || null,
        userEmail: user.email || null,
        userRole: user.role || 'user',
        auth0UserId: user.sub || user.auth0_id || null,
        eventType,
        eventCategory,
        eventDescription: `${req.method} ${req.path} - ${res.statusCode}`,
        resourceType,
        resourceId,
        resourceName,
        ipAddress: ipAddress ? ipAddress.split(',')[0].trim() : null,
        userAgent,
        status: res.statusCode >= 400 ? 'failure' : 'success',
        errorMessage,
        requestMethod: req.method,
        requestPath: req.path,
        responseCode: res.statusCode,
        timestamp: new Date().toISOString()
      };

      if (process.env.NODE_ENV !== 'test') {
        try {
          const AuditLogger = require('../services/auditLogger');
          await AuditLogger.log(auditData);
        } catch (loggerError) {
          if (!loggerError.message.includes('Cannot find module')) {
            console.warn('Audit logging failed:', loggerError.message);
          }
        }
      }
    } catch (error) {
      console.warn('Audit middleware processing error:', error.message);
    } finally {
      cleanup();
    }
  };

  res.on('finish', logAudit);
  res.on('close', cleanup);
  res.on('error', cleanup);

  next();
};

function getResourceType(path) {
  const pathLower = path.toLowerCase();

  if (pathLower.includes('/api/patients')) return 'patient';
  if (pathLower.includes('/api/appointments')) return 'appointment';
  if (pathLower.includes('/api/medical-records')) return 'medical_record';
  if (pathLower.includes('/api/users')) return 'user';
  if (pathLower.includes('/api/newsletter')) return 'newsletter';
  if (pathLower.includes('/api/admin')) return 'admin';
  if (pathLower.includes('/api/audit')) return 'audit_log';
  if (pathLower.includes('/api/profile')) return 'profile';
  if (pathLower.includes('/api/catalog')) return 'catalog';
  if (pathLower.includes('/api/education')) return 'education';
  if (pathLower.includes('/api/blog')) return 'blog';
  if (pathLower.includes('/api/events')) return 'event';
  if (pathLower.includes('/api/auth')) return 'auth';
  if (pathLower.includes('/api/products')) return 'product';
  if (pathLower.includes('/api/services')) return 'service';
  if (pathLower.includes('/api/membership')) return 'membership';
  if (pathLower.includes('/api/payments')) return 'payment';

  return 'system';
}

function getResourceName(path, resourceId) {
  const resourceType = getResourceType(path);

  if (resourceId) {
    return `${resourceType}_${resourceId}`;
  }

  const pathParts = path.split('/').filter(Boolean);

  if (pathParts.length >= 3) {
    const lastPart = pathParts[pathParts.length - 1];
    if (!isNaN(lastPart) || lastPart.includes('-') || lastPart.length === 36) {
      return `${resourceType}_${lastPart}`;
    }
    return lastPart;
  }

  return resourceType;
}

module.exports = auditMiddleware;