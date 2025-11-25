// routes/admin.js
const express = require('express');
const router = express.Router();

const { pool: dbPool } = require('../db');
const { checkJwt, attachAdminUser, requireAdmin } = require('../middleware/admin-check');

// Apply in this order to all admin routes
router.use(checkJwt, attachAdminUser, requireAdmin);

/* ------------------------ helpers ------------------------ */

function toInt(v, fallback = null) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function makeSlug(s) {
  return String(s || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-]/g, '');
}

// Audit logging helper
const logAdminAction = async (
  adminUserId,
  actionType,
  targetId = null,
  details = {},
  req = null
) => {
  try {
    const ip = req?.ip || details.ip || null;
    const ua = req?.headers['user-agent'] || details.userAgent || null;

    await dbPool.query(
      `INSERT INTO public.admin_audit_logs
       (admin_user_id, action_type, target_user_id, details, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [adminUserId, actionType, targetId, details, ip, ua]
    );
  } catch (error) {
    // Keep non-fatal
    console.error('Failed to log admin action:', error);
  }
};

/* ===================== DASHBOARD / USERS ===================== */

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
      todayAppointments,

      totalMemberships,
      activeMemberships,
      userRoles,

      productCount,
      categoryCount,

      blogCount,
      eduVideos,
      eduArticles,
      eventsUpcoming,

      plansCount,
      messagesCount,
      auditCount
    ] = await Promise.all([
      dbPool.query('SELECT COUNT(*) FROM public.users'),
      dbPool.query('SELECT COUNT(*) FROM public.users WHERE is_active = true'),
      dbPool.query(
        `SELECT COUNT(*) FROM public.users WHERE created_at >= DATE_TRUNC('month', CURRENT_DATE)`
      ),

      dbPool.query('SELECT COUNT(*) FROM public.appointments'),
      // ⚠️ If your enum is uppercase (e.g., 'PENDING'), change the literal here.
      dbPool.query('SELECT COUNT(*) FROM public.appointments WHERE status = $1', ['pending']),
      dbPool.query(`SELECT COUNT(*) FROM public.appointments WHERE DATE(appointment_date) = CURRENT_DATE`),

      dbPool.query('SELECT COUNT(*) FROM public.user_memberships'),
      dbPool.query('SELECT COUNT(*) FROM public.user_memberships WHERE status = $1', ['active']),
      dbPool.query('SELECT role, COUNT(*) FROM public.users GROUP BY role'),

      dbPool.query('SELECT COUNT(*) FROM public.products'),
      dbPool.query('SELECT COUNT(*) FROM public.categories'),

      dbPool.query('SELECT COUNT(*) FROM public.blog_posts'),
      dbPool.query('SELECT COUNT(*) FROM public.education_videos'),
      dbPool.query('SELECT COUNT(*) FROM public.education_articles'),
      dbPool.query('SELECT COUNT(*) FROM public.events WHERE start_at >= NOW()'),

      dbPool.query('SELECT COUNT(*) FROM public.membership_plans'),
      dbPool.query('SELECT COUNT(*) FROM public.contact_messages'),
      dbPool.query('SELECT COUNT(*) FROM public.admin_audit_logs'),
    ]);

    const stats = {
      users: {
        total: parseInt(totalUsers.rows[0].count),
        active: parseInt(activeUsers.rows[0].count),
        newThisMonth: parseInt(newUsersThisMonth.rows[0].count),
        roles: userRoles.rows.reduce((acc, row) => {
          acc[row.role] = parseInt(row.count);
          return acc;
        }, {}),
      },
      appointments: {
        total: parseInt(totalAppointments.rows[0].count),
        pending: parseInt(pendingAppointments.rows[0].count),
        today: parseInt(todayAppointments.rows[0].count),
      },
      memberships: {
        total: parseInt(totalMemberships.rows[0].count),
        active: parseInt(activeMemberships.rows[0].count),
        plans: parseInt(plansCount.rows[0].count),
      },
      products:   { total: parseInt(productCount.rows[0].count) },
      categories: { total: parseInt(categoryCount.rows[0].count) },
      blog:       { total: parseInt(blogCount.rows[0].count) },
      education:  {
        videos:   parseInt(eduVideos.rows[0].count),
        articles: parseInt(eduArticles.rows[0].count),
      },
      events:   { upcoming: parseInt(eventsUpcoming.rows[0].count) },
      messages: { total: parseInt(messagesCount.rows[0].count) },
      audit:    { total: parseInt(auditCount.rows[0].count) },
    };

    await logAdminAction(adminUserId, 'VIEW_DASHBOARD_STATS', null, {}, req);
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
    const { page = 1, limit = 10, search = '', role = '', status = '' } = req.query;

    const pageNum = toInt(page, 1);
    const lim = toInt(limit, 10);
    const offset = (pageNum - 1) * lim;

    const where = ['1=1'];
    const params = [];
    let i = 0;

    if (search) {
      i++;
      where.push(
        `(email ILIKE $${i} OR first_name ILIKE $${i} OR last_name ILIKE $${i} OR name ILIKE $${i})`
      );
      params.push(`%${search}%`);
    }
    if (role) {
      i++;
      where.push(`role = $${i}`);
      params.push(role);
    }
    if (status === 'active') where.push('is_active = true');
    if (status === 'inactive') where.push('is_active = false');

    const usersSql = `
      SELECT id, auth0_id, email, first_name, last_name, name, role, is_active,
             last_login, login_count, created_at, updated_at
      FROM public.users
      WHERE ${where.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT $${i + 1} OFFSET $${i + 2}
    `;
    const countSql = `SELECT COUNT(*) FROM public.users WHERE ${where.join(' AND ')}`;

    const [usersResult, countResult] = await Promise.all([
      dbPool.query(usersSql, [...params, lim, offset]),
      dbPool.query(countSql, params),
    ]);

    const totalUsers = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalUsers / lim);

    await logAdminAction(
      adminUserId,
      'VIEW_USERS_LIST',
      null,
      { page: pageNum, limit: lim, search, role, status },
      req
    );

    res.json({
      users: usersResult.rows,
      pagination: {
        currentPage: pageNum,
        totalPages,
        totalUsers,
        hasNext: pageNum < totalPages,
        hasPrev: pageNum > 1,
      },
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

    const userResult = await dbPool.query(
      `SELECT
         u.id, u.auth0_id, u.email, u.first_name, u.last_name, u.name, u.role,
         u.is_active, u.last_login, u.login_count, u.created_at, u.updated_at,
         um.id as membership_id, um.plan_id, um.status as membership_status,
         um.start_date, um.end_date, mp.name as plan_name,
         COUNT(a.id) as appointment_count
       FROM public.users u
       LEFT JOIN public.user_memberships um
         ON u.id = um.user_id AND um.status = 'active'
       LEFT JOIN public.membership_plans mp ON um.plan_id = mp.id
       LEFT JOIN public.appointments a ON u.id = a.user_id
       WHERE u.id = $1
       GROUP BY u.id, um.id, mp.name`,
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const appointmentsResult = await dbPool.query(
      `SELECT id, service_type, appointment_date, status, created_at
       FROM public.appointments
       WHERE user_id = $1
       ORDER BY appointment_date DESC
       LIMIT 10`,
      [userId]
    );

    const user = userResult.rows[0];
    user.appointments = appointmentsResult.rows;

    await logAdminAction(adminUserId, 'VIEW_USER_DETAILS', userId, {}, req);
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
    const validRoles = ['Administrator', 'Provider', 'User'];

    if (!validRoles.includes(role)) {
      return res
        .status(400)
        .json({ error: 'Invalid role', message: `Role must be one of: ${validRoles.join(', ')}` });
    }

    // Prevent self-demotion
    if (parseInt(userId) === adminUserId && role !== 'Administrator') {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'Cannot remove admin role from yourself'
      });
    }

    const result = await dbPool.query(
      'UPDATE public.users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
      [role, userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });

    await logAdminAction(adminUserId, 'UPDATE_USER_ROLE', userId, { role }, req);
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

    if (toInt(userId) === adminUserId && !is_active) {
      return res.status(400).json({ error: 'Invalid operation', message: 'Cannot deactivate your own account' });
    }

    const result = await dbPool.query(
      'UPDATE public.users SET is_active = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
      [!!is_active, userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });

    await logAdminAction(adminUserId, 'UPDATE_USER_STATUS', userId, { is_active: !!is_active }, req);
    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

/* ====================== APPOINTMENTS ====================== */

// Get all appointments
router.get('/appointments', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { page = 1, limit = 10, status = '', date_from = '', date_to = '' } = req.query;

    const pageNum = toInt(page, 1);
    const lim = toInt(limit, 10);
    const offset = (pageNum - 1) * lim;

    const where = ['1=1'];
    const params = [];
    let i = 0;

    if (status) { i++; where.push(`a.status = $${i}`); params.push(status); }
    if (date_from) { i++; where.push(`a.appointment_date >= $${i}`); params.push(date_from); }
    if (date_to) { i++; where.push(`a.appointment_date <= $${i}`); params.push(date_to); }

    const appointmentsQuery = `
      SELECT
        a.*,
        u.first_name, u.last_name, u.email,
        s.name as service_name
      FROM public.appointments a
      LEFT JOIN public.users u ON a.user_id = u.id
      LEFT JOIN public.services s ON a.service_id = s.id
      WHERE ${where.join(' AND ')}
      ORDER BY a.appointment_date DESC
      LIMIT $${i + 1} OFFSET $${i + 2}
    `;
    const countQuery = `SELECT COUNT(*) FROM public.appointments a WHERE ${where.join(' AND ')}`;

    const [appointmentsResult, countResult] = await Promise.all([
      dbPool.query(appointmentsQuery, [...params, lim, offset]),
      dbPool.query(countQuery, params),
    ]);

    const totalAppointments = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalAppointments / lim);

    await logAdminAction(
      adminUserId,
      'VIEW_APPOINTMENTS_LIST',
      null,
      { page: pageNum, limit: lim, status, date_from, date_to },
      req
    );

    res.json({
      appointments: appointmentsResult.rows,
      pagination: {
        currentPage: pageNum,
        totalPages,
        totalAppointments,
        hasNext: pageNum < totalPages,
        hasPrev: pageNum > 1,
      },
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

    const valid = ['pending', 'confirmed', 'cancelled', 'completed'];
    if (!valid.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const result = await dbPool.query(
      `UPDATE public.appointments
       SET status = $1, updated_at = NOW()
       WHERE id = $2 RETURNING *`,
      [status, appointmentId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Appointment not found' });

    await logAdminAction(adminUserId, 'UPDATE_APPOINTMENT_STATUS', appointmentId, { status }, req);
    res.json({ appointment: result.rows[0] });
  } catch (error) {
    console.error('Update appointment status error:', error);
    res.status(500).json({ error: 'Failed to update appointment status' });
  }
});

/* ====================== PRODUCTS (ADMIN) ====================== */

// Admin list (with pagination and optional search/category)
router.get('/products', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { search = '', category = '', page = 1, limit = 20 } = req.query;

    const pageNum = toInt(page, 1);
    const lim = toInt(limit, 20);
    const offset = (pageNum - 1) * lim;

    const where = ['1=1'];
    const params = [];
    let i = 0;

    if (search) {
      i++; params.push(`%${search}%`);
      where.push(`(p.name ILIKE $${i} OR p.slug ILIKE $${i})`);
    }
    if (category) {
      i++; params.push(category.toString().toLowerCase());
      where.push(`LOWER(COALESCE(c.slug, REPLACE(c.name,' ','-'))) = $${i}`);
    }

    const sql = `
      SELECT
        p.id, p.name, p.slug, p.price_cents, p.image_url, p.external_url,
        p.category_id, COALESCE(p.is_active, TRUE) AS is_active,
        json_build_object('name', c.name, 'slug', LOWER(REPLACE(COALESCE(c.slug, c.name, ''), ' ', '-'))) AS category
      FROM public.products p
      LEFT JOIN public.categories c ON c.id = p.category_id
      WHERE ${where.join(' AND ')}
      ORDER BY p.id DESC
      LIMIT $${i + 1} OFFSET $${i + 2}
    `;
    const countSql = `
      SELECT COUNT(*)
      FROM public.products p
      LEFT JOIN public.categories c ON c.id = p.category_id
      WHERE ${where.join(' AND ')}
    `;

    const [rows, count] = await Promise.all([
      dbPool.query(sql, [...params, lim, offset]),
      dbPool.query(countSql, params),
    ]);

    await logAdminAction(adminUserId, 'VIEW_PRODUCTS_LIST', null, { search, category, page: pageNum, limit: lim }, req);

    res.json({
      products: rows.rows,
      pagination: {
        currentPage: pageNum,
        totalPages: Math.ceil(parseInt(count.rows[0].count) / lim),
        total: parseInt(count.rows[0].count),
      },
    });
  } catch (e) {
    console.error('admin list products error:', e);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Create product
router.post('/products', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { name, price_cents, image_url = null, external_url = null, category_id = null, slug = null, is_active = true } = req.body;

    if (!name || toInt(price_cents) === null) {
      return res.status(400).json({ error: 'name and price_cents are required' });
    }

    const finalSlug = slug ? makeSlug(slug) : makeSlug(name);

    const { rows } = await dbPool.query(
      `INSERT INTO public.products
         (name, slug, price_cents, image_url, external_url, category_id, is_active)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, name, slug, price_cents, image_url, external_url, category_id, is_active`,
      [name, finalSlug, toInt(price_cents), image_url, external_url, toInt(category_id), !!is_active]
    );

    await logAdminAction(adminUserId, 'CREATE_PRODUCT', rows[0].id, { name, category_id }, req);
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error('admin create product error:', e);
    res.status(500).json({ error: 'Failed to create product' });
  }
});

// Update product
router.put('/products/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const id = toInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });

    const { name, slug, price_cents, image_url, external_url, category_id, is_active } = req.body;
    const patchedSlug = slug ? makeSlug(slug) : null;

    const { rows } = await dbPool.query(
      `UPDATE public.products
       SET name        = COALESCE($2, name),
           slug        = COALESCE($3, slug),
           price_cents = COALESCE($4, price_cents),
           image_url   = COALESCE($5, image_url),
           external_url= COALESCE($6, external_url),
           category_id = COALESCE($7, category_id),
           is_active   = COALESCE($8, is_active),
           updated_at  = NOW()
       WHERE id = $1
       RETURNING id, name, slug, price_cents, image_url, external_url, category_id, is_active`,
      [id, name || null, patchedSlug, toInt(price_cents), image_url || null, external_url || null, toInt(category_id), typeof is_active === 'boolean' ? is_active : null]
    );

    if (!rows.length) return res.status(404).json({ error: 'Not found' });

    await logAdminAction(adminUserId, 'UPDATE_PRODUCT', id, req.body, req);
    res.json(rows[0]);
  } catch (e) {
    console.error('admin update product error:', e);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// Delete product
router.delete('/products/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const id = toInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });

    const { rowCount } = await dbPool.query(
      `DELETE FROM public.products WHERE id = $1`,
      [id]
    );
    if (!rowCount) return res.status(404).json({ error: 'Not found' });

    await logAdminAction(adminUserId, 'DELETE_PRODUCT', id, {}, req);
    res.status(204).end();
  } catch (e) {
    console.error('admin delete product error:', e);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

/* ====================== AUDIT LOGS ====================== */

router.get('/audit-logs', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { page = 1, limit = 20 } = req.query;
    const pageNum = toInt(page, 1);
    const lim = toInt(limit, 20);
    const offset = (pageNum - 1) * lim;

    const logsQuery = `
      SELECT
        al.*,
        admin_u.email as admin_email,
        target_u.email as target_email
      FROM public.admin_audit_logs al
      LEFT JOIN public.users admin_u ON al.admin_user_id = admin_u.id
      LEFT JOIN public.users target_u ON al.target_user_id = target_u.id
      ORDER BY al.created_at DESC
      LIMIT $1 OFFSET $2
    `;
    const countQuery = 'SELECT COUNT(*) FROM public.admin_audit_logs';

    const [logsResult, countResult] = await Promise.all([
      dbPool.query(logsQuery, [lim, offset]),
      dbPool.query(countQuery),
    ]);

    const totalLogs = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalLogs / lim);

    await logAdminAction(adminUserId, 'VIEW_AUDIT_LOGS', null, {}, req);

    res.json({
      logs: logsResult.rows,
      pagination: {
        currentPage: pageNum,
        totalPages,
        totalLogs,
        hasNext: pageNum < totalPages,
        hasPrev: pageNum > 1,
      },
    });
  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

module.exports = router;
