// middleware/requireAdmin.js
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
