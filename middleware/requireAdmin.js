// middleware/requireAdmin.js
const requireAdmin = (req, res, next) => {
  if (!req.adminUser) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'User context missing. Did you forget attachAdminUser?',
    });
  }

  const isAdmin = req.adminUser.is_admin === true || req.adminUser.role === 'Administrator';

  if (!isAdmin) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Administrator privileges required to access this resource',
    });
  }

  next();
};

module.exports = requireAdmin;