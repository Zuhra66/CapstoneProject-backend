// middleware/requireAdmin.js
module.exports = function requireAdmin(req, res, next) {
  // must be authenticated and admin
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  if (!req.user.is_admin && !req.user?.roles?.includes?.('Administrator')) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};
