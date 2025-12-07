const express = require('express');
const router = express.Router();

const { pool: dbPool } = require('../db');
const { checkJwt, attachAdminUser, requireAdmin } = require('../middleware/admin-check');

// Middleware for all routes
router.use(checkJwt);
router.use(attachAdminUser);
router.use(requireAdmin);

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

// Auth0 Management API Token Caching
let managementApiToken = null;
let tokenExpiry = null;

const getManagementApiToken = async () => {
  // Return cached token if it's still valid (with 5-minute buffer)
  if (managementApiToken && tokenExpiry && Date.now() < tokenExpiry - 300000) {
    console.log('🔄 Using cached Management API token');
    return managementApiToken;
  }

  try {
    console.log('🔄 Getting new Management API token...');

    // Use the dedicated Management API audience
    const managementApiAudience = process.env.AUTH0_MANAGEMENT_AUDIENCE || `https://${process.env.AUTH0_DOMAIN}/api/v2/`;

    if (!managementApiAudience) {
      throw new Error('AUTH0_MANAGEMENT_AUDIENCE environment variable is not set');
    }

    console.log('🔧 Management API audience:', managementApiAudience);

    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        client_id: process.env.AUTH0_MANAGEMENT_CLIENT_ID,
        client_secret: process.env.AUTH0_MANAGEMENT_CLIENT_SECRET,
        audience: managementApiAudience,
        grant_type: 'client_credentials'
      })
    });

    console.log('🔧 Token response status:', response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('🔧 Token error response:', errorText);
      throw new Error(`Failed to get Management API token: ${response.status} ${errorText}`);
    }

    const data = await response.json();

    // Cache the token
    managementApiToken = data.access_token;
    tokenExpiry = Date.now() + (data.expires_in * 1000);

    console.log('✅ New Management API token acquired');
    return managementApiToken;

  } catch (error) {
    console.error('❌ Error getting Management API token:', error);
    throw error;
  }
};

// Get Auth0 Role ID by name
const getAuth0RoleId = async (roleName) => {
  const token = await getManagementApiToken();

  const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/roles`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error('❌ Failed to fetch roles:', errorText);
    throw new Error(`Failed to fetch roles: ${response.status} ${errorText}`);
  }

  const roles = await response.json();
  console.log('🔧 Available Auth0 roles:', roles.map(r => r.name));

  const role = roles.find(r => r.name === roleName);

  if (!role) {
    console.error(`❌ Role "${roleName}" not found in Auth0. Available roles:`, roles.map(r => r.name));
    throw new Error(`Role "${roleName}" not found in Auth0. Available roles: ${roles.map(r => r.name).join(', ')}`);
  }

  console.log(`✅ Found Auth0 role "${roleName}" with ID: ${role.id}`);
  return role.id;
};

// Update Auth0 user roles
const updateAuth0UserRoles = async (auth0UserId, roleName) => {
  try {
    console.log('🔄 Updating Auth0 roles for user:', auth0UserId);
    console.log('🔧 New role to assign:', roleName);

    const token = await getManagementApiToken();

    // First, get all current roles assigned to the user
    const getRolesResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(auth0UserId)}/roles`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (!getRolesResponse.ok) {
      const errorText = await getRolesResponse.text();
      console.error('❌ Failed to get user roles:', errorText);
      throw new Error(`Failed to get user roles: ${getRolesResponse.status} ${errorText}`);
    }

    const currentRoles = await getRolesResponse.json();
    console.log('🔧 Current Auth0 roles:', currentRoles.map(r => r.name));

    // Get the new role ID
    const newRoleId = await getAuth0RoleId(roleName);

    // Remove all existing roles
    if (currentRoles.length > 0) {
      const roleIdsToRemove = currentRoles.map(role => role.id);

      console.log('🔧 Removing roles:', roleIdsToRemove);

      const removeResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(auth0UserId)}/roles`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          roles: roleIdsToRemove
        })
      });

      if (!removeResponse.ok) {
        const errorText = await removeResponse.text();
        console.error('❌ Failed to remove roles:', errorText);
        throw new Error(`Failed to remove roles: ${removeResponse.status} ${errorText}`);
      }
      console.log('✅ Removed existing roles');
    }

    // Add the new role
    console.log('🔧 Adding role ID:', newRoleId);

    const addResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(auth0UserId)}/roles`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        roles: [newRoleId]
      })
    });

    if (!addResponse.ok) {
      const errorText = await addResponse.text();
      console.error('❌ Failed to add role:', errorText);
      throw new Error(`Failed to add role: ${addResponse.status} ${errorText}`);
    }

    console.log('✅ Added new role:', roleName);
    return true;

  } catch (error) {
    console.error('❌ Error updating Auth0 roles:', error);
    throw error;
  }
};

const updateAuth0User = async (auth0UserId, userData) => {
  try {
    console.log('🔄 Starting Auth0 update for:', auth0UserId);
    console.log('🔧 User data for Auth0:', userData);

    const token = await getManagementApiToken();

    // Build the update payload for Auth0 user profile
    const auth0UpdatePayload = {
      given_name: userData.first_name || undefined,
      family_name: userData.last_name || undefined,
      name: userData.name || undefined,
      email: userData.email || undefined,
      blocked: userData.is_active === false,
      app_metadata: {}
    };

    // Only add app_metadata fields if they are defined
    if (userData.role !== undefined) {
      auth0UpdatePayload.app_metadata.role = userData.role;
    }
    if (userData.is_admin !== undefined) {
      auth0UpdatePayload.app_metadata.is_admin = userData.is_admin;
    }

    // For Google OAuth2 users, we need to be careful about what we can update
    const isGoogleUser = auth0UserId.startsWith('google-oauth2|');
    console.log('🔧 Is Google OAuth2 user:', isGoogleUser);

    if (isGoogleUser) {
      // Google users have restrictions
      delete auth0UpdatePayload.email;
      delete auth0UpdatePayload.given_name;
      delete auth0UpdatePayload.family_name;
      delete auth0UpdatePayload.name;
    }

    // Remove undefined values
    Object.keys(auth0UpdatePayload).forEach(key => {
      if (auth0UpdatePayload[key] === undefined) {
        delete auth0UpdatePayload[key];
      }
    });

    // Handle app_metadata
    if (auth0UpdatePayload.app_metadata && Object.keys(auth0UpdatePayload.app_metadata).length === 0) {
      delete auth0UpdatePayload.app_metadata;
    }

    console.log('🔧 Auth0 profile update payload:', JSON.stringify(auth0UpdatePayload, null, 2));

    // Update user profile
    const apiDomain = process.env.AUTH0_CUSTOM_DOMAIN || process.env.AUTH0_DOMAIN;
    const apiUrl = `https://${apiDomain}/api/v2/users/${encodeURIComponent(auth0UserId)}`;
    console.log('🔧 Auth0 API URL:', apiUrl);

    const response = await fetch(apiUrl, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(auth0UpdatePayload)
    });

    console.log('🔧 Auth0 profile update response status:', response.status);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Auth0 profile update failed: ${response.status} ${errorText}`);
    }

    const result = await response.json();
    console.log('✅ Auth0 profile updated successfully');

    // ALSO update Auth0 Roles if role is specified
    if (userData.role) {
      try {
        await updateAuth0UserRoles(auth0UserId, userData.role);
        console.log('✅ Auth0 roles updated successfully');
      } catch (roleError) {
        console.error('⚠️ Auth0 role update failed (profile still updated):', roleError.message);
        // Don't throw here - profile update was successful
      }
    }

    return result;

  } catch (error) {
    console.error('❌ Error updating Auth0 user:', error);
    throw error;
  }
};

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
    console.error('Failed to log admin action:', error);
  }
};

// Enhanced debug route
router.get('/debug-user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const userResult = await dbPool.query(
        'SELECT id, auth0_id, email, first_name, last_name, name, is_active, role, is_admin FROM public.users WHERE id = $1',
        [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    // Test Auth0 Management API setup
    let auth0Test = { success: false, message: '' };
    let auth0UserData = null;
    let auth0RolesData = null;
    let allAuth0Roles = null;

    if (user.auth0_id) {
      try {
        const token = await getManagementApiToken();
        const apiDomain = process.env.AUTH0_CUSTOM_DOMAIN || process.env.AUTH0_DOMAIN;

        // Get all available roles first
        const allRolesResponse = await fetch(`https://${apiDomain}/api/v2/roles`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json'
          }
        });

        if (allRolesResponse.ok) {
          allAuth0Roles = await allRolesResponse.json();
        }

        // Get user profile
        const userResponse = await fetch(`https://${apiDomain}/api/v2/users/${encodeURIComponent(user.auth0_id)}`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json'
          }
        });

        if (userResponse.ok) {
          auth0UserData = await userResponse.json();

          // Get user roles
          const rolesResponse = await fetch(`https://${apiDomain}/api/v2/users/${encodeURIComponent(user.auth0_id)}/roles`, {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Accept': 'application/json'
            }
          });

          if (rolesResponse.ok) {
            auth0RolesData = await rolesResponse.json();
          }

          auth0Test = {
            success: true,
            message: 'Auth0 Management API is working'
          };
        } else {
          const errorData = await userResponse.json().catch(() => ({}));
          auth0Test = {
            success: false,
            message: `Auth0 API error: ${userResponse.status} - ${errorData.message || errorData.error || userResponse.statusText}`
          };
        }
      } catch (error) {
        auth0Test = { success: false, message: `Auth0 test failed: ${error.message}` };
      }
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        auth0_id: user.auth0_id,
        has_auth0_id: !!user.auth0_id,
        is_active: user.is_active,
        role: user.role,
        is_admin: user.is_admin
      },
      auth0_test: auth0Test,
      auth0_user_data: auth0UserData,
      auth0_roles: auth0RolesData,
      available_auth0_roles: allAuth0Roles ? allAuth0Roles.map(r => ({ id: r.id, name: r.name, description: r.description })) : null,
      environment: {
        has_domain: !!process.env.AUTH0_DOMAIN,
        has_custom_domain: !!process.env.AUTH0_CUSTOM_DOMAIN,
        has_client_id: !!process.env.AUTH0_MANAGEMENT_CLIENT_ID,
        has_client_secret: !!process.env.AUTH0_MANAGEMENT_CLIENT_SECRET,
        has_audience: !!process.env.AUTH0_MANAGEMENT_AUDIENCE
      }
    });

  } catch (error) {
    console.error('Debug error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add this section to your existing admin.js file - RIGHT AFTER the dashboard-stats route

// ============================================
// UPDATED DASHBOARD-STATS ROUTE WITH AUDIT STATS
// ============================================
router.get('/dashboard-stats', async (req, res) => {
  try {
    // Get users stats
    const totalUsers = await dbPool.query('SELECT COUNT(*) FROM public.users');
    const activeUsers = await dbPool.query('SELECT COUNT(*) FROM public.users WHERE is_active = true');
    const newUsersThisMonth = await dbPool.query(`
      SELECT COUNT(*) 
      FROM public.users 
      WHERE created_at >= date_trunc('month', CURRENT_DATE)
    `);

    // ✅ ADD NEWSLETTER STATS
    let newsletterTotal = 0;
    let newsletterActive = 0;

    try {
      const newsletterResult = await dbPool.query(`
        SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN active THEN 1 ELSE 0 END) as active
        FROM newsletter_subscribers
      `);

      if (newsletterResult.rows.length > 0) {
        newsletterTotal = parseInt(newsletterResult.rows[0].total) || 0;
        newsletterActive = parseInt(newsletterResult.rows[0].active) || 0;
      }
    } catch (newsletterError) {
      console.log('Newsletter stats not available:', newsletterError.message);
      // Newsletter table might not exist yet, that's okay
    }

    // ✅ ADD AUDIT LOG STATS
    let auditStats = {
      total: 0,
      today: 0,
      security: 0,
      authentication: 0,
      access: 0,
      modification: 0
    };

    try {
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      // Run all audit stat queries
      const auditQueries = await Promise.all([
        // Total audit logs
        dbPool.query('SELECT COUNT(*) FROM audit_logs'),

        // Today's audit logs
        dbPool.query('SELECT COUNT(*) FROM audit_logs WHERE created_at >= $1', [today]),

        // Security events
        dbPool.query(`SELECT COUNT(*) FROM audit_logs WHERE event_category = 'security'`),

        // Authentication events
        dbPool.query(`SELECT COUNT(*) FROM audit_logs WHERE event_category = 'authentication'`),

        // Access events
        dbPool.query(`SELECT COUNT(*) FROM audit_logs WHERE event_category = 'access'`),

        // Modification events
        dbPool.query(`SELECT COUNT(*) FROM audit_logs WHERE event_category = 'modification'`)
      ]);

      auditStats = {
        total: parseInt(auditQueries[0].rows[0].count) || 0,
        today: parseInt(auditQueries[1].rows[0].count) || 0,
        security: parseInt(auditQueries[2].rows[0].count) || 0,
        authentication: parseInt(auditQueries[3].rows[0].count) || 0,
        access: parseInt(auditQueries[4].rows[0].count) || 0,
        modification: parseInt(auditQueries[5].rows[0].count) || 0
      };

    } catch (auditError) {
      console.log('Audit stats not available:', auditError.message);
      // Audit table might not have all columns yet, that's okay
    }

    const stats = {
      users: {
        total: parseInt(totalUsers.rows[0].count),
        active: parseInt(activeUsers.rows[0].count),
        newThisMonth: parseInt(newUsersThisMonth.rows[0].count)
      },
      // ✅ Newsletter stats added here
      newsletter: {
        total: newsletterTotal,
        active: newsletterActive
      },
      appointments: {
        total: 0,
        pending: 0,
        today: 0
      },
      products: { total: 0 },
      categories: { total: 0 },
      blog: { total: 0 },
      education: {
        videos: 0,
        articles: 0
      },
      events: { upcoming: 0 },
      memberships: {
        plans: 0,
        active: 0
      },
      messages: { total: 0 },
      // ✅ Audit stats added here
      audit: auditStats
    };

    // Try to get additional stats if tables exist (KEEP ALL YOUR EXISTING CODE HERE)
    try {
      // Appointments stats
      const appointmentsTotal = await dbPool.query('SELECT COUNT(*) FROM appointments');
      const appointmentsPending = await dbPool.query("SELECT COUNT(*) FROM appointments WHERE status = 'pending'");
      const appointmentsToday = await dbPool.query(`
        SELECT COUNT(*) FROM appointments 
        WHERE DATE(appointment_date) = CURRENT_DATE
      `);
      stats.appointments = {
        total: parseInt(appointmentsTotal.rows[0].count) || 0,
        pending: parseInt(appointmentsPending.rows[0].count) || 0,
        today: parseInt(appointmentsToday.rows[0].count) || 0
      };
    } catch (e) {
      console.log('Appointments stats not available:', e.message);
    }

    try {
      // Products stats
      const productsTotal = await dbPool.query('SELECT COUNT(*) FROM products');
      stats.products.total = parseInt(productsTotal.rows[0].count) || 0;
    } catch (e) {
      console.log('Products stats not available:', e.message);
    }

    try {
      // Blog stats
      const blogTotal = await dbPool.query('SELECT COUNT(*) FROM blog_posts');
      stats.blog.total = parseInt(blogTotal.rows[0].count) || 0;
    } catch (e) {
      console.log('Blog stats not available:', e.message);
    }

    try {
      // Education stats
      const educationVideos = await dbPool.query('SELECT COUNT(*) FROM education_videos');
      const educationArticles = await dbPool.query('SELECT COUNT(*) FROM education_articles');
      stats.education = {
        videos: parseInt(educationVideos.rows[0].count) || 0,
        articles: parseInt(educationArticles.rows[0].count) || 0
      };
    } catch (e) {
      console.log('Education stats not available:', e.message);
    }

    try {
      // Categories stats
      const categoriesTotal = await dbPool.query('SELECT COUNT(*) FROM categories');
      stats.categories.total = parseInt(categoriesTotal.rows[0].count) || 0;
    } catch (e) {
      console.log('Categories stats not available:', e.message);
    }

    try {
      // Events stats (upcoming)
      const upcomingEvents = await dbPool.query(`
        SELECT COUNT(*) FROM events 
        WHERE event_date >= CURRENT_DATE
      `);
      stats.events.upcoming = parseInt(upcomingEvents.rows[0].count) || 0;
    } catch (e) {
      console.log('Events stats not available:', e.message);
    }

    try {
      // Memberships stats
      const membershipPlans = await dbPool.query('SELECT COUNT(*) FROM membership_plans');
      const activeMemberships = await dbPool.query("SELECT COUNT(*) FROM user_memberships WHERE status = 'active'");
      stats.memberships = {
        plans: parseInt(membershipPlans.rows[0].count) || 0,
        active: parseInt(activeMemberships.rows[0].count) || 0
      };
    } catch (e) {
      console.log('Memberships stats not available:', e.message);
    }

    try {
      // Messages stats
      const messagesTotal = await dbPool.query('SELECT COUNT(*) FROM contact_messages');
      stats.messages.total = parseInt(messagesTotal.rows[0].count) || 0;
    } catch (e) {
      console.log('Messages stats not available:', e.message);
    }

    // Get user roles distribution
    try {
      const rolesResult = await dbPool.query(`
        SELECT role, COUNT(*) as count 
        FROM users 
        WHERE role IS NOT NULL 
        GROUP BY role
      `);

      stats.users.roles = {};
      rolesResult.rows.forEach(row => {
        stats.users.roles[row.role] = parseInt(row.count);
      });
    } catch (e) {
      console.log('User roles stats not available:', e.message);
    }

    await logAdminAction(req.adminUser.id, 'VIEW_DASHBOARD_STATS', null, {}, req);

    console.log('📊 Dashboard stats generated successfully');
    res.json(stats);

  } catch (error) {
    console.error('❌ Dashboard stats error:', error);

    const fallbackStats = {
      users: {
        total: 1,
        active: 1,
        newThisMonth: 0
      },
      newsletter: {
        total: 0,
        active: 0
      },
      appointments: {
        total: 0,
        pending: 0,
        today: 0
      },
      products: { total: 0 },
      categories: { total: 0 },
      blog: { total: 0 },
      education: {
        videos: 0,
        articles: 0
      },
      events: { upcoming: 0 },
      memberships: {
        plans: 0,
        active: 0
      },
      messages: { total: 0 },
      audit: {
        total: 0,
        today: 0,
        security: 0,
        authentication: 0,
        access: 0,
        modification: 0
      }
    };

    res.json(fallbackStats);
  }
});

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
             is_admin, auth_provider, created_at, updated_at
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

router.get('/users/:userId', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;

    const userResult = await dbPool.query(
        `SELECT
         u.id, u.auth0_id, u.email, u.first_name, u.last_name, u.name, u.role,
         u.is_active, u.is_admin, u.auth_provider, u.created_at, u.updated_at,
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

router.put('/users/:userId', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;
    const {
      first_name,
      last_name,
      name,
      email,
      role,
      is_active,
      is_admin
    } = req.body;

    console.log('👤 USER UPDATE DEBUG ==========');
    console.log('Admin user ID:', adminUserId);
    console.log('Target user ID:', userId);
    console.log('Request body:', req.body);

    if (!email) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'Email is required'
      });
    }

    // Get user with auth0_id
    const existingUser = await dbPool.query(
        'SELECT id, auth0_id, email, is_active, role, is_admin FROM public.users WHERE id = $1',
        [userId]
    );

    if (existingUser.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The requested user does not exist'
      });
    }

    const targetUser = existingUser.rows[0];
    console.log('🎯 Target user auth0_id:', targetUser.auth0_id);
    console.log('🎯 Current role in DB:', targetUser.role);
    console.log('🎯 New role from request:', role);

    // Validate role against your available roles - UPDATED to match your Auth0 roles
    const validRoles = ['Administrator', 'Provider', 'Member', 'User'];
    if (role && !validRoles.includes(role)) {
      return res.status(400).json({
        error: 'Invalid role',
        message: `Role must be one of: ${validRoles.join(', ')}`
      });
    }

    // Update in PostgreSQL
    const updateQuery = `
      UPDATE public.users 
      SET 
        first_name = $1,
        last_name = $2,
        name = $3,
        email = $4,
        role = $5,
        is_active = $6,
        is_admin = $7,
        updated_at = NOW()
      WHERE id = $8
      RETURNING *
    `;

    const updateResult = await dbPool.query(updateQuery, [
      first_name || null,
      last_name || null,
      name || null,
      email,
      role || 'Member', // Default to 'Member' to match your Auth0 roles
      is_active !== undefined ? is_active : true,
      is_admin !== undefined ? is_admin : false,
      userId
    ]);

    const updatedUser = updateResult.rows[0];
    console.log('✅ User updated in PostgreSQL');
    console.log('✅ Updated user role in DB:', updatedUser.role);

    // Sync with Auth0 if user has an auth0_id
    let auth0SyncResult = null;
    let auth0RoleSyncResult = null;
    if (targetUser.auth0_id) {
      try {
        console.log('🔄 Starting Auth0 sync for:', targetUser.auth0_id);
        auth0SyncResult = await updateAuth0User(targetUser.auth0_id, {
          first_name,
          last_name,
          name,
          email,
          role: updatedUser.role,
          is_active: updatedUser.is_active,
          is_admin: updatedUser.is_admin
        });
        console.log('✅ Auth0 sync completed');
        auth0RoleSyncResult = true;
      } catch (auth0Error) {
        console.error('⚠️ Auth0 sync failed:', auth0Error.message);
      }
    } else {
      console.log('ℹ️ No auth0_id found, skipping Auth0 sync');
    }

    await logAdminAction(adminUserId, 'UPDATE_USER', userId, {
      first_name, last_name, name, email, role, is_active, is_admin,
      auth0_sync: !!auth0SyncResult,
      auth0_role_sync: !!auth0RoleSyncResult,
      auth0_id: targetUser.auth0_id
    }, req);

    res.json({
      message: 'User updated successfully' +
          (auth0SyncResult ? ' (Auth0 synced)' : ' (Auth0 not synced)'),
      user: updatedUser,
      auth0_synced: !!auth0SyncResult,
      auth0_role_synced: !!auth0RoleSyncResult,
      auth0_id_present: !!targetUser.auth0_id
    });

  } catch (error) {
    console.error('❌ Error updating user:', error);

    if (error.code === '23505') {
      return res.status(400).json({
        error: 'Duplicate email',
        message: 'A user with this email already exists'
      });
    }

    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to update user'
    });
  }
});

router.patch('/users/:userId/role', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;
    const { role } = req.body;

    // UPDATED to match your Auth0 roles
    const validRoles = ['Administrator', 'Provider', 'Member', 'User'];

    if (!validRoles.includes(role)) {
      return res
      .status(400)
      .json({ error: 'Invalid role', message: `Role must be one of: ${validRoles.join(', ')}` });
    }

    // Get user to check auth0_id and current values
    const userResult = await dbPool.query(
        'SELECT auth0_id, is_active, is_admin, role FROM public.users WHERE id = $1',
        [userId]
    );

    if (!userResult.rows.length) return res.status(404).json({ error: 'User not found' });

    const targetUser = userResult.rows[0];

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

    const updatedUser = result.rows[0];

    // Sync with Auth0
    if (targetUser.auth0_id) {
      try {
        console.log('🔄 Syncing role to Auth0 for user:', targetUser.auth0_id);

        // Update Auth0 user with new role (this will update both profile and roles)
        await updateAuth0User(targetUser.auth0_id, {
          role: updatedUser.role,
          is_active: targetUser.is_active,
          is_admin: updatedUser.is_admin
        });

        console.log('✅ Auth0 role sync completed');
      } catch (auth0Error) {
        console.error('⚠️ Auth0 sync failed for role update:', auth0Error.message);
      }
    } else {
      console.log('ℹ️ No auth0_id found, skipping Auth0 sync');
    }

    await logAdminAction(adminUserId, 'UPDATE_USER_ROLE', userId, {
      role,
      previous_role: targetUser.role,
      new_role: updatedUser.role
    }, req);

    res.json({
      user: updatedUser,
      auth0_synced: !!targetUser.auth0_id
    });
  } catch (error) {
    console.error('Update user role error:', error);
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

router.patch('/users/:userId/status', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;
    const { is_active } = req.body;

    console.log('🔧 STATUS UPDATE DEBUG ==========');
    console.log('User ID:', userId);
    console.log('New is_active value:', is_active);

    // Get user to check auth0_id
    const userResult = await dbPool.query(
        'SELECT auth0_id, is_active as current_active, role, is_admin FROM public.users WHERE id = $1',
        [userId]
    );

    if (!userResult.rows.length) return res.status(404).json({ error: 'User not found' });

    const targetUser = userResult.rows[0];
    console.log('Current is_active in DB:', targetUser.current_active);

    if (toInt(userId) === adminUserId && !is_active) {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'Cannot deactivate your own account'
      });
    }

    const result = await dbPool.query(
        'UPDATE public.users SET is_active = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
        [!!is_active, userId]
    );

    const updatedUser = result.rows[0];
    console.log('Updated is_active in DB:', updatedUser.is_active);

    // Sync with Auth0 - Use the 'blocked' field (inverse of is_active)
    if (targetUser.auth0_id) {
      try {
        console.log('🔄 Syncing status to Auth0');
        console.log('is_active:', updatedUser.is_active);
        console.log('blocked in Auth0:', !updatedUser.is_active);

        await updateAuth0User(targetUser.auth0_id, {
          is_active: updatedUser.is_active,
          role: targetUser.role, // Include current role to not overwrite it
          is_admin: targetUser.is_admin // Include current admin status
        });
        console.log('✅ Auth0 status sync completed');
      } catch (auth0Error) {
        console.error('⚠️ Auth0 sync failed for status update:', auth0Error.message);
      }
    } else {
      console.log('ℹ️ No auth0_id found, skipping Auth0 sync');
    }

    await logAdminAction(adminUserId, 'UPDATE_USER_STATUS', userId, {
      is_active: !!is_active,
      previous_status: targetUser.current_active,
      new_status: updatedUser.is_active
    }, req);

    res.json({
      user: updatedUser,
      auth0_synced: !!targetUser.auth0_id
    });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

router.delete('/users/:userId', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;

    const existingUser = await dbPool.query(
        'SELECT id, email, auth0_id FROM public.users WHERE id = $1',
        [userId]
    );

    if (existingUser.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The requested user does not exist'
      });
    }

    if (req.adminUser.id === userId) {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'You cannot delete your own account'
      });
    }

    await dbPool.query('DELETE FROM public.users WHERE id = $1', [userId]);

    await logAdminAction(adminUserId, 'DELETE_USER', userId, {}, req);

    res.json({
      message: 'User deleted successfully',
      deletedUser: existingUser.rows[0]
    });

  } catch (error) {
    console.error('Error deleting user:', error);

    if (error.code === '23503') {
      return res.status(400).json({
        error: 'Cannot delete user',
        message: 'This user has associated records and cannot be deleted'
      });
    }

    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to delete user'
    });
  }
});

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

module.exports = router;