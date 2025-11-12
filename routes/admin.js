// routes/admin.js
const express = require('express');
const router = express.Router();
const pool = require('../db');
const { checkJwt, requireAdmin } = require('../middleware/admin-check');

// Apply admin middleware to all routes
router.use(checkJwt, requireAdmin);

// Audit logging helper
const logAdminAction = async (adminUserId, actionType, targetUserId = null, details = {}) => {
  try {
    await pool.query(
        `INSERT INTO admin_audit_logs 
       (admin_user_id, action_type, target_user_id, details, ip_address, user_agent) 
       VALUES ($1, $2, $3, $4, $5, $6)`,
        [adminUserId, actionType, targetUserId, details, details.ip, details.userAgent]
    );
  } catch (error) {
    console.error('Failed to log admin action:', error);
  }
};

// Get admin dashboard stats
router.get('/dashboard-stats', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;

    const [
      totalUsers,
      activeUsers,
      newUsersThisMonth,
      totalAppointments,
      pendingAppointments,
      totalMemberships,
      activeMemberships,
      userRoles
    ] = await Promise.all([
      // Total users
      pool.query('SELECT COUNT(*) FROM users'),
      // Active users
      pool.query('SELECT COUNT(*) FROM users WHERE is_active = true'),
      // New users this month
      pool.query(`SELECT COUNT(*) FROM users 
                  WHERE created_at >= DATE_TRUNC('month', CURRENT_DATE)`),
      // Total appointments
      pool.query('SELECT COUNT(*) FROM appointments'),
      // Pending appointments
      pool.query('SELECT COUNT(*) FROM appointments WHERE status = $1', ['pending']),
      // Total memberships
      pool.query('SELECT COUNT(*) FROM user_memberships'),
      // Active memberships
      pool.query('SELECT COUNT(*) FROM user_memberships WHERE status = $1', ['active']),
      // User roles breakdown
      pool.query('SELECT role, COUNT(*) FROM users GROUP BY role')
    ]);

    const stats = {
      users: {
        total: parseInt(totalUsers.rows[0].count),
        active: parseInt(activeUsers.rows[0].count),
        newThisMonth: parseInt(newUsersThisMonth.rows[0].count),
        roles: userRoles.rows.reduce((acc, row) => {
          acc[row.role] = parseInt(row.count);
          return acc;
        }, {})
      },
      appointments: {
        total: parseInt(totalAppointments.rows[0].count),
        pending: parseInt(pendingAppointments.rows[0].count)
      },
      memberships: {
        total: parseInt(totalMemberships.rows[0].count),
        active: parseInt(activeMemberships.rows[0].count)
      }
    };

    await logAdminAction(adminUserId, 'VIEW_DASHBOARD_STATS');

    res.json(stats);
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// Get users with pagination and filtering
router.get('/users', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const {
      page = 1,
      limit = 10,
      search = '',
      role = '',
      status = ''
    } = req.query;

    const offset = (page - 1) * limit;

    let whereConditions = ['1=1'];
    let queryParams = [];
    let paramCount = 0;

    if (search) {
      paramCount++;
      whereConditions.push(
          `(email ILIKE $${paramCount} OR first_name ILIKE $${paramCount} OR last_name ILIKE $${paramCount} OR name ILIKE $${paramCount})`
      );
      queryParams.push(`%${search}%`);
    }

    if (role) {
      paramCount++;
      whereConditions.push(`role = $${paramCount}`);
      queryParams.push(role);
    }

    if (status === 'active') {
      whereConditions.push('is_active = true');
    } else if (status === 'inactive') {
      whereConditions.push('is_active = false');
    }

    const whereClause = whereConditions.join(' AND ');

    // Get users
    const usersQuery = `
      SELECT 
        id, auth0_id, email, first_name, last_name, name, role, is_active,
        last_login, login_count, created_at, updated_at
      FROM users 
      WHERE ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}
    `;

    // Get total count
    const countQuery = `
      SELECT COUNT(*) FROM users WHERE ${whereClause}
    `;

    const [usersResult, countResult] = await Promise.all([
      pool.query(usersQuery, [...queryParams, limit, offset]),
      pool.query(countQuery, queryParams)
    ]);

    const totalUsers = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalUsers / limit);

    await logAdminAction(adminUserId, 'VIEW_USERS_LIST', null, {
      page,
      limit,
      search,
      role,
      status
    });

    res.json({
      users: usersResult.rows,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalUsers,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get user details
router.get('/users/:userId', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;

    const userResult = await pool.query(
        `SELECT 
        u.id, u.auth0_id, u.email, u.first_name, u.last_name, u.name, u.role, 
        u.is_active, u.last_login, u.login_count, u.created_at, u.updated_at,
        um.id as membership_id, um.plan_id, um.status as membership_status,
        um.start_date, um.end_date, mp.name as plan_name,
        COUNT(a.id) as appointment_count
       FROM users u
       LEFT JOIN user_memberships um ON u.id = um.user_id AND um.status = 'active'
       LEFT JOIN membership_plans mp ON um.plan_id = mp.id
       LEFT JOIN appointments a ON u.id = a.user_id
       WHERE u.id = $1
       GROUP BY u.id, um.id, mp.name`,
        [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get user's recent appointments
    const appointmentsResult = await pool.query(
        `SELECT id, service_type, appointment_date, status, created_at 
       FROM appointments 
       WHERE user_id = $1 
       ORDER BY appointment_date DESC 
       LIMIT 10`,
        [userId]
    );

    const user = userResult.rows[0];
    user.appointments = appointmentsResult.rows;

    await logAdminAction(adminUserId, 'VIEW_USER_DETAILS', userId);

    res.json({ user });
  } catch (error) {
    console.error('Get user details error:', error);
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

// Update user role
router.patch('/users/:userId/role', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;
    const { role } = req.body;

    // Validate role
    const validRoles = ['admin', 'provider', 'member'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({
        error: 'Invalid role',
        message: `Role must be one of: ${validRoles.join(', ')}`
      });
    }

    // Prevent self-demotion
    if (parseInt(userId) === adminUserId && role !== 'admin') {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'Cannot remove admin role from yourself'
      });
    }

    const result = await pool.query(
        'UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
        [role, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await logAdminAction(adminUserId, 'UPDATE_USER_ROLE', userId, { role });

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Update user role error:', error);
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

// Update user status
router.patch('/users/:userId/status', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;
    const { is_active } = req.body;

    // Prevent self-deactivation
    if (parseInt(userId) === adminUserId && !is_active) {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'Cannot deactivate your own account'
      });
    }

    const result = await pool.query(
        'UPDATE users SET is_active = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
        [is_active, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await logAdminAction(adminUserId, 'UPDATE_USER_STATUS', userId, { is_active });

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// Get all appointments
router.get('/appointments', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const {
      page = 1,
      limit = 10,
      status = '',
      date_from = '',
      date_to = ''
    } = req.query;

    const offset = (page - 1) * limit;

    let whereConditions = ['1=1'];
    let queryParams = [];
    let paramCount = 0;

    if (status) {
      paramCount++;
      whereConditions.push(`a.status = $${paramCount}`);
      queryParams.push(status);
    }

    if (date_from) {
      paramCount++;
      whereConditions.push(`a.appointment_date >= $${paramCount}`);
      queryParams.push(date_from);
    }

    if (date_to) {
      paramCount++;
      whereConditions.push(`a.appointment_date <= $${paramCount}`);
      queryParams.push(date_to);
    }

    const whereClause = whereConditions.join(' AND ');

    const appointmentsQuery = `
      SELECT 
        a.*,
        u.first_name, u.last_name, u.email,
        s.name as service_name
      FROM appointments a
      LEFT JOIN users u ON a.user_id = u.id
      LEFT JOIN services s ON a.service_id = s.id
      WHERE ${whereClause}
      ORDER BY a.appointment_date DESC
      LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}
    `;

    const countQuery = `
      SELECT COUNT(*) FROM appointments a WHERE ${whereClause}
    `;

    const [appointmentsResult, countResult] = await Promise.all([
      pool.query(appointmentsQuery, [...queryParams, limit, offset]),
      pool.query(countQuery, queryParams)
    ]);

    const totalAppointments = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalAppointments / limit);

    await logAdminAction(adminUserId, 'VIEW_APPOINTMENTS_LIST', null, {
      page,
      limit,
      status,
      date_from,
      date_to
    });

    res.json({
      appointments: appointmentsResult.rows,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalAppointments,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Get appointments error:', error);
    res.status(500).json({ error: 'Failed to fetch appointments' });
  }
});

// Update appointment status
router.patch('/appointments/:appointmentId/status', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { appointmentId } = req.params;
    const { status } = req.body;

    const validStatuses = ['pending', 'confirmed', 'cancelled', 'completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const result = await pool.query(
        `UPDATE appointments 
       SET status = $1, updated_at = NOW() 
       WHERE id = $2 
       RETURNING *`,
        [status, appointmentId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    await logAdminAction(adminUserId, 'UPDATE_APPOINTMENT_STATUS', null, {
      appointmentId,
      status
    });

    res.json({ appointment: result.rows[0] });
  } catch (error) {
    console.error('Update appointment status error:', error);
    res.status(500).json({ error: 'Failed to update appointment status' });
  }
});

// Get admin audit logs
router.get('/audit-logs', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const logsQuery = `
      SELECT 
        al.*,
        admin_u.email as admin_email,
        target_u.email as target_email
      FROM admin_audit_logs al
      LEFT JOIN users admin_u ON al.admin_user_id = admin_u.id
      LEFT JOIN users target_u ON al.target_user_id = target_u.id
      ORDER BY al.created_at DESC
      LIMIT $1 OFFSET $2
    `;

    const countQuery = 'SELECT COUNT(*) FROM admin_audit_logs';

    const [logsResult, countResult] = await Promise.all([
      pool.query(logsQuery, [limit, offset]),
      pool.query(countQuery)
    ]);

    const totalLogs = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalLogs / limit);

    await logAdminAction(adminUserId, 'VIEW_AUDIT_LOGS');

    res.json({
      logs: logsResult.rows,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalLogs,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

module.exports = router;