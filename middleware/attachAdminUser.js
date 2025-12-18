// middleware/attachAdminUser.js
function attachAdminUser(req, res, next) {
  if (!req.user) return next();

  if (req.user.is_admin === true || req.user.role === "Administrator") {
    req.adminUser = req.user;
  }

  next();
}

module.exports = attachAdminUser;
