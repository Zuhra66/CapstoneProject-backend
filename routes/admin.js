// routes/admin.js - PRODUCTION-READY MERGED VERSION
const express = require('express');
const router = express.Router();

const path = require('path');
const fs = require('fs');
const multer = require('multer');

const { pool: dbPool } = require('../db');
const {
  checkJwt,
  attachAdminUser,
  requireAdmin,
} = require('../middleware/admin-check');

// Polyfill fetch for Node < 18
const fetch =
    global.fetch ||
    ((...args) =>
        import('node-fetch').then(({ default: nodeFetch }) => nodeFetch(...args)));

// ----------------------
// Global admin middleware
// ----------------------
router.use(checkJwt);
router.use(attachAdminUser);
router.use(requireAdmin);

// ----------------------
// Helpers
// ----------------------
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

function normalizeDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

// Ensure product slug is unique by appending -2, -3, ... if needed
async function ensureUniqueProductSlug(baseSlug) {
  const { rows } = await dbPool.query(
      `
    SELECT slug
    FROM public.products
    WHERE slug = $1 OR slug LIKE $2
  `,
      [baseSlug, `${baseSlug}-%`],
  );

  if (!rows.length) {
    return baseSlug;
  }

  let maxSuffix = 1;
  const suffixRegex = new RegExp(`^${baseSlug}-(\\d+)$`);

  for (const row of rows) {
    if (row.slug === baseSlug) {
      if (maxSuffix < 2) maxSuffix = 2;
    } else {
      const match = row.slug.match(suffixRegex);
      if (match) {
        const n = parseInt(match[1], 10);
        if (!Number.isNaN(n) && n + 1 > maxSuffix) {
          maxSuffix = n + 1;
        }
      }
    }
  }

  return `${baseSlug}-${maxSuffix}`;
}

// Ensure education article slug is unique
async function ensureUniqueEducationArticleSlug(baseSlug) {
  const { rows } = await dbPool.query(
      `
    SELECT slug
    FROM public.education_articles
    WHERE slug = $1 OR slug LIKE $2
  `,
      [baseSlug, `${baseSlug}-%`],
  );

  if (!rows.length) {
    return baseSlug;
  }

  let maxSuffix = 1;
  const suffixRegex = new RegExp(`^${baseSlug}-(\\d+)$`);

  for (const row of rows) {
    if (row.slug === baseSlug) {
      if (maxSuffix < 2) maxSuffix = 2;
    } else {
      const match = row.slug.match(suffixRegex);
      if (match) {
        const n = parseInt(match[1], 10);
        if (!Number.isNaN(n) && n + 1 > maxSuffix) {
          maxSuffix = n + 1;
        }
      }
    }
  }

  return `${baseSlug}-${maxSuffix}`;
}

// ----------------------
// Auth0 Management helpers
// ----------------------
let managementApiToken = null;
let tokenExpiry = null;

const getManagementApiToken = async () => {
  if (managementApiToken && tokenExpiry && Date.now() < tokenExpiry - 300000) {
    console.log('🔄 Using cached Management API token');
    return managementApiToken;
  }

  try {
    console.log('🔄 Getting new Management API token...');

    const managementApiAudience =
        process.env.AUTH0_MANAGEMENT_AUDIENCE ||
        `https://${process.env.AUTH0_DOMAIN}/api/v2/`;

    if (!managementApiAudience) {
      throw new Error('AUTH0_MANAGEMENT_AUDIENCE environment variable is not set');
    }

    console.log('🔧 Management API audience:', managementApiAudience);

    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.AUTH0_MANAGEMENT_CLIENT_ID,
        client_secret: process.env.AUTH0_MANAGEMENT_CLIENT_SECRET,
        audience: managementApiAudience,
        grant_type: 'client_credentials',
      }),
    });

    console.log('🔧 Token response status:', response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('🔧 Token error response:', errorText);
      throw new Error(
          `Failed to get Management API token: ${response.status} ${errorText}`,
      );
    }

    const data = await response.json();
    managementApiToken = data.access_token;
    tokenExpiry = Date.now() + data.expires_in * 1000;

    console.log('✅ New Management API token acquired');
    return managementApiToken;
  } catch (error) {
    console.error('❌ Error getting Management API token:', error);
    throw error;
  }
};

const getAuth0RoleId = async (roleName) => {
  const token = await getManagementApiToken();

  const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/roles`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error('❌ Failed to fetch roles:', errorText);
    throw new Error(`Failed to fetch roles: ${response.status} ${errorText}`);
  }

  const roles = await response.json();
  console.log('🔧 Available Auth0 roles:', roles.map((r) => r.name));

  const role = roles.find((r) => r.name === roleName);
  if (!role) {
    console.error(`❌ Role "${roleName}" not found in Auth0`);
    throw new Error(
        `Role "${roleName}" not found in Auth0. Available roles: ${roles
        .map((r) => r.name)
        .join(', ')}`,
    );
  }

  console.log(`✅ Found Auth0 role "${roleName}" with ID: ${role.id}`);
  return role.id;
};

const updateAuth0UserRoles = async (auth0UserId, roleName) => {
  try {
    console.log('🔄 Updating Auth0 roles for user:', auth0UserId);
    console.log('🔧 New role to assign:', roleName);

    const token = await getManagementApiToken();

    // get existing roles
    const getRolesResponse = await fetch(
        `https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(
            auth0UserId,
        )}/roles`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        },
    );

    if (!getRolesResponse.ok) {
      const errorText = await getRolesResponse.text();
      console.error('❌ Failed to get user roles:', errorText);
      throw new Error(
          `Failed to get user roles: ${getRolesResponse.status} ${errorText}`,
      );
    }

    const currentRoles = await getRolesResponse.json();
    console.log('🔧 Current Auth0 roles:', currentRoles.map((r) => r.name));

    const newRoleId = await getAuth0RoleId(roleName);

    // remove old roles
    if (currentRoles.length > 0) {
      const roleIdsToRemove = currentRoles.map((r) => r.id);

      console.log('🔧 Removing roles:', roleIdsToRemove);

      const removeResponse = await fetch(
          `https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(
              auth0UserId,
          )}/roles`,
          {
            method: 'DELETE',
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ roles: roleIdsToRemove }),
          },
      );

      if (!removeResponse.ok) {
        const errorText = await removeResponse.text();
        console.error('❌ Failed to remove roles:', errorText);
        throw new Error(
            `Failed to remove roles: ${removeResponse.status} ${errorText}`,
        );
      }

      console.log('✅ Removed existing roles');
    }

    // add new role
    console.log('🔧 Adding role ID:', newRoleId);
    const addResponse = await fetch(
        `https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(
            auth0UserId,
        )}/roles`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ roles: [newRoleId] }),
        },
    );

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

    const auth0UpdatePayload = {
      given_name: userData.first_name || undefined,
      family_name: userData.last_name || undefined,
      name: userData.name || undefined,
      email: userData.email || undefined,
      blocked: userData.is_active === false,
      app_metadata: {},
    };

    if (userData.role !== undefined) {
      auth0UpdatePayload.app_metadata.role = userData.role;
    }
    if (userData.is_admin !== undefined) {
      auth0UpdatePayload.app_metadata.is_admin = userData.is_admin;
    }

    const isGoogleUser = auth0UserId.startsWith('google-oauth2|');
    if (isGoogleUser) {
      // can't change profile for social identities
      delete auth0UpdatePayload.email;
      delete auth0UpdatePayload.given_name;
      delete auth0UpdatePayload.family_name;
      delete auth0UpdatePayload.name;
    }

    Object.keys(auth0UpdatePayload).forEach((k) => {
      if (auth0UpdatePayload[k] === undefined) delete auth0UpdatePayload[k];
    });

    if (
        auth0UpdatePayload.app_metadata &&
        Object.keys(auth0UpdatePayload.app_metadata).length === 0
    ) {
      delete auth0UpdatePayload.app_metadata;
    }

    const apiDomain = process.env.AUTH0_CUSTOM_DOMAIN || process.env.AUTH0_DOMAIN;
    const apiUrl = `https://${apiDomain}/api/v2/users/${encodeURIComponent(
        auth0UserId,
    )}`;
    console.log('🔧 Auth0 API URL:', apiUrl);

    const response = await fetch(apiUrl, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(auth0UpdatePayload),
    });

    console.log('🔧 Auth0 profile update response status:', response.status);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Auth0 profile update failed: ${response.status} ${errorText}`);
    }

    const result = await response.json();
    console.log('✅ Auth0 profile updated successfully');

    if (userData.role) {
      try {
        await updateAuth0UserRoles(auth0UserId, userData.role);
        console.log('✅ Auth0 roles updated successfully');
      } catch (roleError) {
        console.error(
            '⚠️ Auth0 role update failed (profile still updated):',
            roleError.message,
        );
      }
    }

    return result;
  } catch (error) {
    console.error('❌ Error updating Auth0 user:', error);
    throw error;
  }
};

// ----------------------
// File upload config for events
// ----------------------
const uploadEventsDir = path.join(__dirname, '..', 'uploads', 'events');
fs.mkdirSync(uploadEventsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadEventsDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path
    .basename(file.originalname, ext)
    .replace(/\s+/g, '-')
    .toLowerCase();
    cb(null, `${Date.now()}-${base}${ext}`);
  },
});

// Only allow JPG/PNG/PDF
const fileFilter = (_req, file, cb) => {
  const allowed = ['image/jpeg', 'image/png', 'application/pdf'];
  if (allowed.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type (allowed: jpg, png, pdf)'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// ----------------------
// Admin audit logging
// ----------------------
const logAdminAction = async (
    adminUserId,
    actionType,
    targetId = null,
    details = {},
    req = null,
) => {
  try {
    const ip = req?.ip || details.ip || null;
    const ua = req?.headers['user-agent'] || details.userAgent || null;

    await dbPool.query(
        `INSERT INTO public.admin_audit_logs
       (admin_user_id, action_type, target_user_id, details, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6)`,
        [adminUserId, actionType, targetId, details, ip, ua],
    );
  } catch (error) {
    console.error('Failed to log admin action:', error);
  }
};

// ----------------------
// Membership sync helper
// ----------------------
const syncMembershipWithRole = async (userId, newRole, isActive) => {
  try {
    console.log('🔄 Syncing membership with role for user:', userId);
    console.log('🔧 New role:', newRole, 'Is active:', isActive);

    const membershipResult = await dbPool.query(
        `SELECT um.status, um.id FROM user_memberships um WHERE um.user_id = $1`,
        [userId]
    );

    if (membershipResult.rows.length > 0) {
      const currentMembership = membershipResult.rows[0];

      // If user is being deactivated, cancel membership
      if (!isActive && currentMembership.status === 'active') {
        console.log('⚠️ User deactivated - cancelling membership');
        await dbPool.query(
            `UPDATE user_memberships SET status = 'cancelled', updated_at = NOW() WHERE id = $1`,
            [currentMembership.id]
        );
        console.log('✅ Membership cancelled due to user deactivation');
      }

      // If role changes from Member to User, cancel membership
      if (newRole !== 'Member' && currentMembership.status === 'active') {
        console.log('⚠️ Role changed from Member to User - cancelling membership');
        await dbPool.query(
            `UPDATE user_memberships SET status = 'cancelled', updated_at = NOW() WHERE id = $1`,
            [currentMembership.id]
        );
        console.log('✅ Membership cancelled due to role change');
      }

      // If role changes to Member and user is active, ensure membership is active
      if (newRole === 'Member' && isActive && currentMembership.status !== 'active') {
        console.log('⚠️ Role changed to Member - activating membership');
        await dbPool.query(
            `UPDATE user_memberships SET status = 'active', updated_at = NOW() WHERE id = $1`,
            [currentMembership.id]
        );
        console.log('✅ Membership activated due to role change to Member');
      }
    }

    // If role is Member but user is inactive, change role to User
    if (newRole === 'Member' && !isActive) {
      console.log('⚠️ Cannot have inactive Member - changing role to User');
      return 'User'; // Return new role
    }

    return newRole; // Return original role if no change needed
  } catch (error) {
    console.error('❌ Error syncing membership with role:', error);
    return newRole; // Return original role on error
  }
};

// ============================================
// ROUTES
// ============================================

// ----------------------
// Dashboard Stats (ENHANCED)
// ----------------------
router.get('/dashboard-stats', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;

    // Run all main stats queries in parallel
    const [
      totalUsersResult,
      activeUsersResult,
      newUsersResult,
      totalAppointmentsResult,
      pendingAppointmentsResult,
      todayAppointmentsResult,
      productsResult,
      categoriesResult,
      blogPostsResult,
      upcomingEventsResult,
      membershipPlansResult,
      activeMembershipsResult,
      adminAuditLogsResult
    ] = await Promise.all([
      // Users
      dbPool.query('SELECT COUNT(*) FROM public.users'),
      dbPool.query('SELECT COUNT(*) FROM public.users WHERE is_active = TRUE'),
      dbPool.query(`
        SELECT COUNT(*)
        FROM public.users
        WHERE created_at >= date_trunc('month', NOW())
      `),

      // Appointments
      dbPool.query('SELECT COUNT(*) FROM public.appointments'),
      dbPool.query(`
        SELECT COUNT(*)
        FROM public.appointments
        WHERE status = 'pending'
      `),
      dbPool.query(`
        SELECT COUNT(*)
        FROM public.appointments
        WHERE appointment_date::date = CURRENT_DATE
      `),

      // Products & Categories
      dbPool.query(`
        SELECT COUNT(*)
        FROM public.products
        WHERE COALESCE(is_active, TRUE) = TRUE
      `),
      dbPool.query('SELECT COUNT(*) FROM public.categories'),

      // Blog
      dbPool.query(`
        SELECT COUNT(*)
        FROM public.blog_posts
        WHERE status = 'published'
      `),

      // Events
      dbPool.query(`
        SELECT COUNT(*)
        FROM public.events
        WHERE is_published = TRUE
          AND start_at::date >= CURRENT_DATE
      `),

      // Memberships
      dbPool.query('SELECT COUNT(*) FROM public.membership_plans'),
      dbPool.query(`
        SELECT COUNT(*)
        FROM public.user_memberships
        WHERE status = 'active'
      `),

      // Admin Audit Logs
      dbPool.query('SELECT COUNT(*) FROM public.admin_audit_logs')
    ]);

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
        total: parseInt(totalUsersResult.rows[0].count, 10) || 0,
        active: parseInt(activeUsersResult.rows[0].count, 10) || 0,
        newThisMonth: parseInt(newUsersResult.rows[0].count, 10) || 0,
      },

      // ✅ NEW: Newsletter stats added here
      newsletter: {
        total: newsletterTotal,
        active: newsletterActive
      },

      // ✅ NEW: Audit stats added here
      audit: auditStats,

      appointments: {
        total: parseInt(totalAppointmentsResult.rows[0].count, 10) || 0,
        pending: parseInt(pendingAppointmentsResult.rows[0].count, 10) || 0,
        today: parseInt(todayAppointmentsResult.rows[0].count, 10) || 0,
      },

      products: {
        total: parseInt(productsResult.rows[0].count, 10) || 0,
        categories: parseInt(categoriesResult.rows[0].count, 10) || 0,
      },

      content: {
        blogPosts: parseInt(blogPostsResult.rows[0].count, 10) || 0,
        upcomingEvents: parseInt(upcomingEventsResult.rows[0].count, 10) || 0,
      },

      membership: {
        plans: parseInt(membershipPlansResult.rows[0].count, 10) || 0,
        active: parseInt(activeMembershipsResult.rows[0].count, 10) || 0,
      },

      adminLogs: parseInt(adminAuditLogsResult.rows[0].count, 10) || 0,
    };

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

    // Simple fallback stats
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
      audit: {
        total: 0,
        today: 0,
        security: 0,
        authentication: 0,
        access: 0,
        modification: 0
      },
      appointments: {
        total: 0,
        pending: 0,
        today: 0
      },
      products: {
        total: 0,
        categories: 0
      },
      content: {
        blogPosts: 0,
        upcomingEvents: 0
      },
      membership: {
        plans: 0,
        active: 0
      },
      adminLogs: 0
    };

    res.json(fallbackStats);
  }
});

// ----------------------
// Debug User Route
// ----------------------
router.get('/debug-user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const userResult = await dbPool.query(
        'SELECT id, auth0_id, email, first_name, last_name, name, is_active, role, is_admin FROM public.users WHERE id = $1',
        [userId],
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    let auth0Test = { success: false, message: '' };
    let auth0UserData = null;
    let auth0RolesData = null;
    let allAuth0Roles = null;

    if (user.auth0_id) {
      try {
        const token = await getManagementApiToken();
        const apiDomain = process.env.AUTH0_CUSTOM_DOMAIN || process.env.AUTH0_DOMAIN;

        const allRolesResponse = await fetch(
            `https://${apiDomain}/api/v2/roles`,
            {
              headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/json',
              },
            },
        );

        if (allRolesResponse.ok) {
          allAuth0Roles = await allRolesResponse.json();
        }

        const userResponse = await fetch(
            `https://${apiDomain}/api/v2/users/${encodeURIComponent(
                user.auth0_id,
            )}`,
            {
              headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/json',
              },
            },
        );

        if (userResponse.ok) {
          auth0UserData = await userResponse.json();

          const rolesResponse = await fetch(
              `https://${apiDomain}/api/v2/users/${encodeURIComponent(
                  user.auth0_id,
              )}/roles`,
              {
                headers: {
                  Authorization: `Bearer ${token}`,
                  Accept: 'application/json',
                },
              },
          );

          if (rolesResponse.ok) {
            auth0RolesData = await rolesResponse.json();
          }

          auth0Test = { success: true, message: 'Auth0 Management API is working' };
        } else {
          const errorData = await userResponse.json().catch(() => ({}));
          auth0Test = {
            success: false,
            message: `Auth0 API error: ${userResponse.status} - ${
                errorData.message || errorData.error || userResponse.statusText
            }`,
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
        is_admin: user.is_admin,
      },
      auth0_test: auth0Test,
      auth0_user_data: auth0UserData,
      auth0_roles: auth0RolesData,
      available_auth0_roles: allAuth0Roles
          ? allAuth0Roles.map((r) => ({
            id: r.id,
            name: r.name,
            description: r.description,
          }))
          : null,
      environment: {
        has_domain: !!process.env.AUTH0_DOMAIN,
        has_custom_domain: !!process.env.AUTH0_CUSTOM_DOMAIN,
        has_client_id: !!process.env.AUTH0_MANAGEMENT_CLIENT_ID,
        has_client_secret: !!process.env.AUTH0_MANAGEMENT_CLIENT_SECRET,
        has_audience: !!process.env.AUTH0_MANAGEMENT_AUDIENCE,
      },
    });
  } catch (error) {
    console.error('Debug error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ----------------------
// Educational Hub admin
// ----------------------
router.get('/education', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;

    const canManageEducation =
        !!req.adminUser.is_admin || req.adminUser.role === 'Administrator';

    if (!canManageEducation) {
      await logAdminAction(
          adminUserId,
          'VIEW_EDUCATION_ADMIN_DENIED',
          null,
          { role: req.adminUser.role },
          req,
      );
      return res.status(403).json({
        ok: false,
        canManageEducation: false,
        message: "You don't have permission to manage education content.",
      });
    }

    const [videosResult, articlesResult] = await Promise.all([
      dbPool
      .query(
          `
        SELECT COUNT(*) FROM public.education_videos
        WHERE status = 'published'
      `,
      )
      .catch(() => ({ rows: [{ count: 0 }] })),
      dbPool
      .query(
          `
        SELECT COUNT(*) FROM public.education_articles
        WHERE status = 'published'
      `,
      )
      .catch(() => ({ rows: [{ count: 0 }] })),
    ]);

    const videosCount = parseInt(videosResult.rows[0].count, 10) || 0;
    const articlesCount = parseInt(articlesResult.rows[0].count, 10) || 0;

    await logAdminAction(
        adminUserId,
        'VIEW_EDUCATION_ADMIN',
        null,
        { videosCount, articlesCount },
        req,
    );

    return res.json({
      ok: true,
      canManageEducation: true,
      videosCount,
      articlesCount,
    });
  } catch (err) {
    console.error('Education admin root error:', err);
    return res.status(500).json({
      ok: false,
      canManageEducation: false,
      message: 'Failed to load education admin data',
    });
  }
});

// ----------------------
// Users Management (ENHANCED with membership sync)
// ----------------------
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
          `(email ILIKE $${i} OR first_name ILIKE $${i} OR last_name ILIKE $${i} OR name ILIKE $${i})`,
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
      SELECT
        users.id,
        users.auth0_id,
        users.email,
        users.first_name,
        users.last_name,
        users.name,
        users.role,
        users.is_active,
        users.is_admin,
        users.auth_provider,
        users.created_at,
        users.updated_at,

        -- Add correct membership object
        json_build_object(
          'status', um.status,
          'start_date', um.start_at,
          'end_date', um.end_at,
          'plan_name', mp.name
        ) AS membership

      FROM public.users

      LEFT JOIN user_memberships um
        ON um.user_id = users.id 
        AND um.status = 'active'

      LEFT JOIN membership_plans mp
        ON mp.id = um.plan_id

      WHERE ${where.join(' AND ')}

      ORDER BY users.created_at DESC
      LIMIT $${i+1} OFFSET $${i+2}
    `;

    const countSql = `SELECT COUNT(*) FROM public.users WHERE ${where.join(' AND ')}`;

    const [usersResult, countResult] = await Promise.all([
      dbPool.query(usersSql, [...params, lim, offset]),
      dbPool.query(countSql, params),
    ]);

    const totalUsers = parseInt(countResult.rows[0].count, 10);
    const totalPages = Math.ceil(totalUsers / lim);

    await logAdminAction(
        adminUserId,
        'VIEW_USERS_LIST',
        null,
        { page: pageNum, limit: lim, search, role, status },
        req,
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
        [userId],
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
        [userId],
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

// UPDATED: PUT route with membership sync logic
router.put('/users/:userId', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;
    const { first_name, last_name, name, email, role, is_active, is_admin } = req.body;

    console.log('👤 USER UPDATE DEBUG ==========');
    console.log('Admin user ID:', adminUserId);
    console.log('Target user ID:', userId);
    console.log('Request body:', req.body);

    if (!email) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'Email is required',
      });
    }

    // Get user with auth0_id and current values
    const existingUser = await dbPool.query(
        'SELECT id, auth0_id, email, is_active, role, is_admin FROM public.users WHERE id = $1',
        [userId],
    );

    if (existingUser.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The requested user does not exist',
      });
    }

    const targetUser = existingUser.rows[0];
    console.log('🎯 Target user auth0_id:', targetUser.auth0_id);
    console.log('🎯 Current role in DB:', targetUser.role);
    console.log('🎯 Current is_active in DB:', targetUser.is_active);
    console.log('🎯 New role from request:', role);
    console.log('🎯 New is_active from request:', is_active);

    const validRoles = ['Administrator', 'Provider', 'Member', 'User'];
    if (role && !validRoles.includes(role)) {
      return res.status(400).json({
        error: 'Invalid role',
        message: `Role must be one of: ${validRoles.join(', ')}`,
      });
    }

    // ADDED: Sync membership with role and active status
    let finalRole = role || targetUser.role;
    let finalIsActive = is_active !== undefined ? is_active : targetUser.is_active;

    // Check for Member/inactive conflict
    if (finalRole === 'Member' && !finalIsActive) {
      console.log('⚠️ Cannot have inactive Member - changing role to User');
      finalRole = 'User';
    }

    // Sync membership based on role changes
    await syncMembershipWithRole(userId, finalRole, finalIsActive);

    // Update in PostgreSQL
    const updateQuery = `
      UPDATE public.users
      SET
        first_name = $1,
        last_name  = $2,
        name       = $3,
        email      = $4,
        role       = $5,
        is_active  = $6,
        is_admin   = $7,
        updated_at = NOW()
      WHERE id = $8
      RETURNING *
    `;

    const updateResult = await dbPool.query(updateQuery, [
      first_name || null,
      last_name || null,
      name || null,
      email,
      finalRole,
      finalIsActive,
      is_admin !== undefined ? is_admin : targetUser.is_admin,
      userId
    ]);

    const updatedUser = updateResult.rows[0];
    console.log('✅ User updated in PostgreSQL');
    console.log('✅ Updated user role in DB:', updatedUser.role);
    console.log('✅ Updated user is_active in DB:', updatedUser.is_active);

    let auth0SyncResult = null;
    let auth0RoleSyncResult = null;

    if (targetUser.auth0_id) {
      try {
        auth0SyncResult = await updateAuth0User(targetUser.auth0_id, {
          first_name,
          last_name,
          name,
          email,
          role: updatedUser.role,
          is_active: updatedUser.is_active,
          is_admin: updatedUser.is_admin,
        });
        auth0RoleSyncResult = true;
      } catch (auth0Error) {
        console.error('⚠️ Auth0 sync failed:', auth0Error.message);
      }
    }

    await logAdminAction(
        adminUserId,
        'UPDATE_USER',
        userId,
        {
          first_name,
          last_name,
          name,
          email,
          role: finalRole,
          is_active: finalIsActive,
          is_admin,
          auth0_sync: !!auth0SyncResult,
          auth0_role_sync: !!auth0RoleSyncResult,
          auth0_id: targetUser.auth0_id,
          membership_synced: true
        },
        req,
    );

    res.json({
      message:
          'User updated successfully' +
          (auth0SyncResult ? ' (Auth0 synced)' : ' (Auth0 not synced)'),
      user: updatedUser,
      auth0_synced: !!auth0SyncResult,
      auth0_role_synced: !!auth0RoleSyncResult,
      auth0_id_present: !!targetUser.auth0_id,
      role_adjusted: finalRole !== role ? 'Role adjusted from Member to User because user is inactive' : null
    });
  } catch (error) {
    console.error('❌ Error updating user:', error);

    if (error.code === '23505') {
      return res.status(400).json({
        error: 'Duplicate email',
        message: 'A user with this email already exists',
      });
    }

    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to update user',
    });
  }
});

// UPDATED: PATCH route for role changes
router.patch('/users/:userId/role', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;
    const { role } = req.body;

    const validRoles = ['Administrator', 'Provider', 'Member', 'User'];

    if (!validRoles.includes(role)) {
      return res.status(400).json({
        error: 'Invalid role',
        message: `Role must be one of: ${validRoles.join(', ')}`,
      });
    }

    const userResult = await dbPool.query(
        'SELECT auth0_id, is_active, is_admin, role FROM public.users WHERE id = $1',
        [userId],
    );

    if (!userResult.rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }

    const targetUser = userResult.rows[0];

    if (parseInt(userId, 10) === adminUserId && role !== 'Administrator') {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'Cannot remove admin role from yourself',
      });
    }

    // ADDED: Check if trying to set Member role on inactive user
    if (role === 'Member' && !targetUser.is_active) {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'Cannot set Member role on inactive user'
      });
    }

    // ADDED: Sync membership with role change
    await syncMembershipWithRole(userId, role, targetUser.is_active);

    const result = await dbPool.query(
        'UPDATE public.users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
        [role, userId],
    );

    const updatedUser = result.rows[0];

    if (targetUser.auth0_id) {
      try {
        await updateAuth0User(targetUser.auth0_id, {
          role: updatedUser.role,
          is_active: targetUser.is_active,
          is_admin: targetUser.is_admin
        });
      } catch (auth0Error) {
        console.error('⚠️ Auth0 sync failed for role update:', auth0Error.message);
      }
    }

    await logAdminAction(
        adminUserId,
        'UPDATE_USER_ROLE',
        userId,
        {
          role,
          previous_role: targetUser.role,
          new_role: updatedUser.role,
          membership_synced: true
        },
        req,
    );

    res.json({
      user: updatedUser,
      auth0_synced: !!targetUser.auth0_id,
    });
  } catch (error) {
    console.error('Update user role error:', error);
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

// UPDATED: PATCH route for status changes
router.patch('/users/:userId/status', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;
    const { is_active } = req.body;

    console.log('🔧 STATUS UPDATE DEBUG ==========');
    console.log('User ID:', userId);
    console.log('New is_active value:', is_active);

    // Get user to check auth0_id and current role
    const userResult = await dbPool.query(
        'SELECT auth0_id, is_active as current_active, role, is_admin FROM public.users WHERE id = $1',
        [userId],
    );

    if (!userResult.rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }

    const targetUser = userResult.rows[0];
    console.log('Current is_active in DB:', targetUser.current_active);
    console.log('Current role in DB:', targetUser.role);

    if (toInt(userId) === adminUserId && !is_active) {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'Cannot deactivate your own account',
      });
    }

    // ADDED: Check if deactivating a Member
    let roleAdjustment = null;
    let finalRole = targetUser.role;

    if (!is_active && targetUser.role === 'Member') {
      console.log('⚠️ Deactivating a Member - changing role to User');
      finalRole = 'User';
      roleAdjustment = 'Role changed from Member to User';
    }

    // ADDED: Sync membership with status change
    await syncMembershipWithRole(userId, finalRole, is_active);

    const result = await dbPool.query(
        'UPDATE public.users SET is_active = $1, role = $2, updated_at = NOW() WHERE id = $3 RETURNING *',
        [!!is_active, finalRole, userId]
    );

    const updatedUser = result.rows[0];
    console.log('Updated is_active in DB:', updatedUser.is_active);
    console.log('Updated role in DB:', updatedUser.role);

    if (targetUser.auth0_id) {
      try {
        console.log('🔄 Syncing status to Auth0');
        console.log('is_active:', updatedUser.is_active);
        console.log('blocked in Auth0:', !updatedUser.is_active);
        console.log('new role:', updatedUser.role);

        await updateAuth0User(targetUser.auth0_id, {
          is_active: updatedUser.is_active,
          role: updatedUser.role,
          is_admin: targetUser.is_admin
        });
      } catch (auth0Error) {
        console.error('⚠️ Auth0 sync failed for status update:', auth0Error.message);
      }
    }

    await logAdminAction(
        adminUserId,
        'UPDATE_USER_STATUS',
        userId,
        {
          is_active: !!is_active,
          previous_status: targetUser.current_active,
          new_status: updatedUser.is_active,
          role_adjustment: roleAdjustment,
          membership_synced: true
        },
        req,
    );

    res.json({
      user: updatedUser,
      auth0_synced: !!targetUser.auth0_id,
      role_adjusted: roleAdjustment
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
        [userId],
    );

    if (!existingUser.rows.length) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The requested user does not exist',
      });
    }

    if (toInt(userId) === adminUserId) {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'You cannot delete your own account',
      });
    }

    await dbPool.query('DELETE FROM public.users WHERE id = $1', [userId]);

    await logAdminAction(adminUserId, 'DELETE_USER', userId, {}, req);

    res.json({
      message: 'User deleted successfully',
      deletedUser: existingUser.rows[0],
    });
  } catch (error) {
    console.error('Error deleting user:', error);

    if (error.code === '23503') {
      return res.status(400).json({
        error: 'Cannot delete user',
        message: 'This user has associated records and cannot be deleted',
      });
    }

    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to delete user',
    });
  }
});

// ----------------------
// Appointments Management
// ----------------------
router.get('/appointments', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const {
      page = 1,
      limit = 10,
      status = '',
      date_from = '',
      date_to = '',
    } = req.query;

    const pageNum = toInt(page, 1);
    const lim = toInt(limit, 10);
    const offset = (pageNum - 1) * lim;

    const where = ['1=1'];
    const params = [];
    let i = 0;

    if (status) {
      i++;
      where.push(`a.status = $${i}`);
      params.push(status);
    }
    if (date_from) {
      i++;
      where.push(`a.appointment_date >= $${i}`);
      params.push(date_from);
    }
    if (date_to) {
      i++;
      where.push(`a.appointment_date <= $${i}`);
      params.push(date_to);
    }

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
    const countQuery = `SELECT COUNT(*) FROM public.appointments a WHERE ${where.join(
        ' AND ',
    )}`;

    const [appointmentsResult, countResult] = await Promise.all([
      dbPool.query(appointmentsQuery, [...params, lim, offset]),
      dbPool.query(countQuery, params),
    ]);

    const totalAppointments = parseInt(countResult.rows[0].count, 10);
    const totalPages = Math.ceil(totalAppointments / lim);

    await logAdminAction(
        adminUserId,
        'VIEW_APPOINTMENTS_LIST',
        null,
        { page: pageNum, limit: lim, status, date_from, date_to },
        req,
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
    if (!valid.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const result = await dbPool.query(
        `UPDATE public.appointments
       SET status = $1, updated_at = NOW()
       WHERE id = $2 RETURNING *`,
        [status, appointmentId],
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    await logAdminAction(
        adminUserId,
        'UPDATE_APPOINTMENT_STATUS',
        appointmentId,
        { status },
        req,
    );

    res.json({ appointment: result.rows[0] });
  } catch (error) {
    console.error('Update appointment status error:', error);
    res.status(500).json({ error: 'Failed to update appointment status' });
  }
});

// ----------------------
// PRODUCTS (DOLLARS VERSION)
// ----------------------

// List products (admin)
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
      i++;
      params.push(`%${search}%`);
      where.push(`(p.name ILIKE $${i} OR p.slug ILIKE $${i})`);
    }

    if (category && category !== 'all') {
      i++;
      params.push(category.toLowerCase());
      where.push(`LOWER(c.slug) = $${i}`);
    }

    const listSql = `
      SELECT
        p.id,
        p.name,
        p.slug,
        p.price,
        p.image_url,
        p.external_url,
        p.category_id,
        COALESCE(p.is_active, TRUE) AS is_active,
        json_build_object('name', c.name, 'slug', c.slug) AS category
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

    const [listResult, countResult] = await Promise.all([
      dbPool.query(listSql, [...params, lim, offset]),
      dbPool.query(countSql, params),
    ]);

    const total = Number(countResult.rows[0].count) || 0;

    await logAdminAction(
        adminUserId,
        'ADMIN_LIST_PRODUCTS',
        null,
        { search, category, page: pageNum, limit: lim },
        req,
    );

    res.json({
      products: listResult.rows,
      pagination: {
        currentPage: pageNum,
        totalPages: Math.ceil(total / lim),
        total,
        hasNext: pageNum * lim < total,
        hasPrev: pageNum > 1,
      },
    });
  } catch (e) {
    console.error('admin list products error:', e);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// CREATE PRODUCT — DOLLARS
router.post('/products', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const {
      name,
      price,
      image_url,
      external_url,
      category_id,
      slug,
      is_active = true,
    } = req.body;

    const priceNumber = Number(price);

    if (!name || !Number.isFinite(priceNumber)) {
      return res.status(400).json({
        error: 'Validation error',
        message: '`name` and numeric `price` (in dollars) are required',
      });
    }

    const baseSlug = slug ? makeSlug(slug) : makeSlug(name);
    const finalSlug = await ensureUniqueProductSlug(baseSlug);

    let categoryIdValue = null;
    if (category_id !== undefined && category_id !== null && category_id !== '') {
      const maybeNum = Number(category_id);
      categoryIdValue = Number.isFinite(maybeNum) ? maybeNum : category_id;
    }

    const insertSql = `
      INSERT INTO public.products
        (name, slug, price, image_url, external_url, category_id, is_active)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, name, slug, price, image_url, external_url, category_id, is_active
    `;

    const { rows } = await dbPool.query(insertSql, [
      name,
      finalSlug,
      priceNumber,
      image_url || null,
      external_url || null,
      categoryIdValue,
      !!is_active,
    ]);

    const product = rows[0];

    await logAdminAction(
        adminUserId,
        'ADMIN_CREATE_PRODUCT',
        product.id,
        { name: product.name, price: product.price },
        req,
    );

    res.status(201).json(product);
  } catch (e) {
    console.error('admin create product error:', e);

    if (e.code === '23505') {
      return res.status(400).json({
        error: 'Duplicate product',
        message: 'A product with this slug or name already exists',
      });
    }

    res.status(500).json({ error: 'Failed to create product', message: e.message });
  }
});

// UPDATE PRODUCT — DOLLARS
router.put('/products/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid product ID' });

    const {
      name,
      slug,
      price,
      image_url,
      external_url,
      category_id,
      is_active,
    } = req.body;

    const existingResult = await dbPool.query(
        'SELECT * FROM public.products WHERE id = $1',
        [id],
    );

    if (!existingResult.rows.length) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const existing = existingResult.rows[0];

    const newName = name ?? existing.name;

    let newSlug = existing.slug;
    if (slug || name) {
      const baseSlug = slug ? makeSlug(slug) : makeSlug(newName);
      newSlug = await ensureUniqueProductSlug(baseSlug);
    }

    const priceNumber =
        price !== undefined && price !== null && price !== ''
            ? Number(price)
            : null;

    const hasCategory = Object.prototype.hasOwnProperty.call(req.body, 'category_id');
    let categoryValue = existing.category_id;

    if (hasCategory) {
      if (category_id === null || category_id === '') {
        categoryValue = null;
      } else {
        const maybeNum = Number(category_id);
        categoryValue = Number.isFinite(maybeNum) ? maybeNum : category_id;
      }
    }

    const updateSql = `
      UPDATE public.products
      SET
        name        = $2,
        slug        = $3,
        price       = COALESCE($4, price),
        image_url   = COALESCE($5, image_url),
        external_url= COALESCE($6, external_url),
        category_id = $7,
        is_active   = COALESCE($8, is_active),
        updated_at  = NOW()
      WHERE id = $1
      RETURNING id, name, slug, price, image_url, external_url, category_id, is_active
    `;

    const { rows } = await dbPool.query(updateSql, [
      id,
      newName,
      newSlug,
      Number.isFinite(priceNumber) ? priceNumber : null,
      image_url || null,
      external_url || null,
      categoryValue,
      typeof is_active === 'boolean' ? is_active : null,
    ]);

    const product = rows[0];

    await logAdminAction(
        adminUserId,
        'ADMIN_UPDATE_PRODUCT',
        id,
        {
          name: product.name,
          price: product.price,
          is_active: product.is_active,
        },
        req,
    );

    res.json(product);
  } catch (e) {
    console.error('admin update product error:', e);

    if (e.code === '23505') {
      return res.status(400).json({
        error: 'Duplicate product',
        message: 'A product with this slug or name already exists',
      });
    }

    res.status(500).json({ error: 'Failed to update product', message: e.message });
  }
});

// DELETE PRODUCT
router.delete('/products/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid product ID' });

    const result = await dbPool.query(
        'DELETE FROM public.products WHERE id = $1 RETURNING id, name',
        [id],
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const deleted = result.rows[0];

    await logAdminAction(
        adminUserId,
        'ADMIN_DELETE_PRODUCT',
        deleted.id,
        { name: deleted.name },
        req,
    );

    res.json({
      success: true,
      message: 'Product deleted successfully',
      deletedProduct: deleted,
    });
  } catch (e) {
    console.error('admin delete product error:', e);
    res.status(500).json({ error: 'Failed to delete product', message: e.message });
  }
});

// ----------------------
// Admin Events (CRUD)
// ----------------------

// 🔹 Admin events list (GET /api/admin/events)
router.get('/events', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { status } = req.query; // "draft" | "published" | "cancelled" | "all"

    let whereClause = '';
    if (status && status !== 'all') {
      if (status === 'published') {
        whereClause = 'WHERE is_published = TRUE';
      } else if (status === 'draft') {
        whereClause = 'WHERE is_published = FALSE';
      } else if (status === 'cancelled') {
        whereClause = 'WHERE FALSE';
      }
    }

    const { rows } = await dbPool.query(
        `
      SELECT
        id,
        title,
        description,
        location,
        start_at   AS "startTime",
        end_at     AS "endTime",
        CASE
          WHEN is_published THEN 'published'
          ELSE 'draft'
        END         AS "status",
        image_url   AS "imageUrl"
      FROM public.events
      ${whereClause}
      ORDER BY start_at ASC
      `,
    );

    await logAdminAction(
        adminUserId,
        'ADMIN_LIST_EVENTS',
        null,
        { status: status || 'all' },
        req,
    );

    res.json({ events: rows });
  } catch (err) {
    console.error('Admin events list error:', err);
    res.status(500).json({ error: 'Failed to load events.' });
  }
});

// Create event (supports multipart/form-data + file)
router.post('/events', upload.single('file'), async (req, res) => {
  try {
    const adminUserId = req.adminUser?.id;

    const body = req.body || {};
    console.log('📝 Create event body:', body, 'file:', !!req.file);

    const {
      title,
      description,
      location,
      startTime,
      endTime,
      status = 'draft',
      imageUrl,
    } = body;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const startAt = normalizeDate(startTime);
    const endAt = normalizeDate(endTime);
    const isPublished = status === 'published';

    const uploadedUrl = req.file
        ? `/uploads/events/${req.file.filename}`
        : null;
    const finalImageUrl = uploadedUrl || imageUrl || null;

    const { rows } = await dbPool.query(
        `
      INSERT INTO public.events
        (title, description, location, start_at, end_at, is_published, image_url)
      VALUES
        ($1, $2, $3, $4, $5, $6, $7)
      RETURNING
        id,
        title,
        description,
        location,
        start_at   AS "startTime",
        end_at     AS "endTime",
        is_published,
        image_url  AS "imageUrl"
      `,
        [
          title,
          description || null,
          location || null,
          startAt,
          endAt,
          isPublished,
          finalImageUrl,
        ],
    );

    const row = rows[0];
    const event = {
      id: row.id,
      title: row.title,
      description: row.description,
      location: row.location,
      startTime: row.startTime,
      endTime: row.endTime,
      status: row.is_published ? 'published' : 'draft',
      imageUrl: row.imageUrl,
    };

    if (adminUserId) {
      await logAdminAction(
          adminUserId,
          'ADMIN_CREATE_EVENT',
          event.id,
          { status: event.status },
          req,
      );
    }

    res.status(201).json({ event });
  } catch (err) {
    console.error('Admin create event error:', err);
    res.status(500).json({ error: 'Failed to create event.' });
  }
});

// Update event (supports multipart/form-data + file)
router.put('/events/:id', upload.single('file'), async (req, res) => {
  try {
    const adminUserId = req.adminUser?.id;
    const { id } = req.params;
    const eventId = Number(id);
    if (!eventId) {
      return res.status(400).json({ error: 'Invalid event ID' });
    }

    const existingResult = await dbPool.query(
        'SELECT * FROM public.events WHERE id = $1',
        [eventId],
    );
    if (!existingResult.rows.length) {
      return res.status(404).json({ error: 'Event not found' });
    }
    const existing = existingResult.rows[0];

    const body = req.body || {};
    console.log('📝 Update event body:', body, 'file:', !!req.file);

    const {
      title,
      description,
      location,
      startTime,
      endTime,
      status,
      imageUrl,
    } = body;

    const newTitle = title ?? existing.title;
    const newDescription = description ?? existing.description;
    const newLocation = location ?? existing.location;
    const newStartAt =
        startTime !== undefined ? normalizeDate(startTime) : existing.start_at;
    const newEndAt =
        endTime !== undefined ? normalizeDate(endTime) : existing.end_at;

    let newIsPublished = existing.is_published;
    if (status === 'published') newIsPublished = true;
    if (status === 'draft') newIsPublished = false;

    const uploadedUrl = req.file
        ? `/uploads/events/${req.file.filename}`
        : null;

    const newImageUrl =
        uploadedUrl !== null
            ? uploadedUrl
            : imageUrl !== undefined
                ? imageUrl || null
                : existing.image_url;

    const { rows } = await dbPool.query(
        `
      UPDATE public.events
      SET
        title        = $2,
        description  = $3,
        location     = $4,
        start_at     = $5,
        end_at       = $6,
        is_published = $7,
        image_url    = $8,
        updated_at   = NOW()
      WHERE id = $1
      RETURNING
        id,
        title,
        description,
        location,
        start_at   AS "startTime",
        end_at     AS "endTime",
        is_published,
        image_url  AS "imageUrl"
      `,
        [
          eventId,
          newTitle,
          newDescription,
          newLocation,
          newStartAt,
          newEndAt,
          newIsPublished,
          newImageUrl,
        ],
    );

    const row = rows[0];
    const event = {
      id: row.id,
      title: row.title,
      description: row.description,
      location: row.location,
      startTime: row.startTime,
      endTime: row.endTime,
      status: row.is_published ? 'published' : 'draft',
      imageUrl: row.imageUrl,
    };

    if (adminUserId) {
      await logAdminAction(
          adminUserId,
          'ADMIN_UPDATE_EVENT',
          event.id,
          { status: event.status },
          req,
      );
    }

    res.json({ event });
  } catch (err) {
    console.error('Admin update event error:', err);
    res.status(500).json({ error: 'Failed to update event.' });
  }
});

// Delete event
router.delete('/events/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser?.id;
    const { id } = req.params;
    const eventId = Number(id);
    if (!eventId) {
      return res.status(400).json({ error: 'Invalid event ID' });
    }

    const result = await dbPool.query(
        'DELETE FROM public.events WHERE id = $1 RETURNING id, title',
        [eventId],
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'Event not found' });
    }

    const deleted = result.rows[0];

    if (adminUserId) {
      await logAdminAction(
          adminUserId,
          'ADMIN_DELETE_EVENT',
          deleted.id,
          { title: deleted.title },
          req,
      );
    }

    res.json({
      success: true,
      deletedEvent: deleted,
    });
  } catch (err) {
    console.error('Admin delete event error:', err);
    res.status(500).json({ error: 'Failed to delete event.' });
  }
});

// ----------------------
// Blog post admin endpoints
// ----------------------
router.get('/blog-posts', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { status } = req.query;

    let query = `
      SELECT id, author_id, title, slug, content_md, status,
             published_at, created_at, updated_at
      FROM public.blog_posts
    `;
    const params = [];

    if (status && status !== 'all') {
      query += ' WHERE status = $1';
      params.push(status);
    }

    query += ' ORDER BY published_at DESC NULLS LAST, created_at DESC';

    const { rows } = await dbPool.query(query, params);

    const posts = rows.map((row) => ({
      id: row.id,
      authorId: row.author_id,
      title: row.title,
      slug: row.slug,
      contentMd: row.content_md,
      status: row.status,
      publishedAt: row.published_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      preview: row.content_md ? row.content_md.slice(0, 220) : '',
    }));

    await logAdminAction(
        adminUserId,
        'ADMIN_LIST_BLOG_POSTS',
        null,
        { status: status || 'all' },
        req,
    );

    res.json({ posts });
  } catch (err) {
    console.error('Admin blog list error:', err);
    res.status(500).json({ error: 'Failed to load blog posts' });
  }
});

// Create a new blog post
router.post('/blog-posts', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { title, slug, contentMd, status, publishedAt } = req.body;

    if (!title || !contentMd) {
      return res
      .status(400)
      .json({ error: 'Title and content are required.' });
    }

    const finalSlug = makeSlug(slug || title);
    const finalStatus = status === 'published' ? 'published' : 'draft';

    const authorId = adminUserId;

    const publishedAtValue =
        finalStatus === 'published'
            ? publishedAt
                ? new Date(publishedAt)
                : new Date()
            : null;

    const { rows } = await dbPool.query(
        `
      INSERT INTO public.blog_posts
        (author_id, title, slug, content_md, status, published_at)
      VALUES
        ($1, $2, $3, $4, $5, $6)
      RETURNING id, author_id, title, slug, content_md, status,
                published_at, created_at, updated_at
      `,
        [authorId, title, finalSlug, contentMd, finalStatus, publishedAtValue],
    );

    const row = rows[0];

    await logAdminAction(
        adminUserId,
        'ADMIN_CREATE_BLOG_POST',
        row.id,
        { title, status: finalStatus },
        req,
    );

    res.status(201).json({
      id: row.id,
      authorId: row.author_id,
      title: row.title,
      slug: row.slug,
      contentMd: row.content_md,
      status: row.status,
      publishedAt: row.published_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    console.error('Admin blog create error:', err);
    res.status(500).json({ error: 'Failed to create blog post' });
  }
});

// Update a blog post
router.put('/blog-posts/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { id } = req.params;
    const { title, slug, contentMd, status, publishedAt } = req.body;

    const { rows: existingRows } = await dbPool.query(
        'SELECT * FROM public.blog_posts WHERE id = $1',
        [id],
    );

    if (!existingRows.length) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const existing = existingRows[0];

    const newTitle = title ?? existing.title;
    const newSlug = makeSlug(slug || newTitle || existing.slug);
    const newContent = contentMd ?? existing.content_md;
    const newStatus =
        status === 'published' || status === 'draft' ? status : existing.status;

    let newPublishedAt = existing.published_at;
    if (newStatus === 'published') {
      newPublishedAt = publishedAt
          ? new Date(publishedAt)
          : existing.published_at || new Date();
    } else {
      newPublishedAt = null;
    }

    const { rows } = await dbPool.query(
        `
      UPDATE public.blog_posts
      SET
        title       = $1,
        slug        = $2,
        content_md  = $3,
        status      = $4,
        published_at= $5,
        updated_at  = NOW()
      WHERE id = $6
      RETURNING id, author_id, title, slug, content_md, status,
                published_at, created_at, updated_at
      `,
        [newTitle, newSlug, newContent, newStatus, newPublishedAt, id],
    );

    const row = rows[0];

    await logAdminAction(
        adminUserId,
        'ADMIN_UPDATE_BLOG_POST',
        id,
        { title: newTitle, status: newStatus },
        req,
    );

    res.json({
      id: row.id,
      authorId: row.author_id,
      title: row.title,
      slug: row.slug,
      contentMd: row.content_md,
      status: row.status,
      publishedAt: row.published_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    console.error('Admin blog update error:', err);
    res.status(500).json({ error: 'Failed to update blog post' });
  }
});

// Delete a blog post
router.delete('/blog-posts/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { id } = req.params;

    const { rowCount } = await dbPool.query(
        'DELETE FROM public.blog_posts WHERE id = $1',
        [id],
    );

    if (rowCount === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    await logAdminAction(adminUserId, 'ADMIN_DELETE_BLOG_POST', id, {}, req);

    res.json({ success: true });
  } catch (err) {
    console.error('Admin blog delete error:', err);
    res.status(500).json({ error: 'Failed to delete blog post' });
  }
});

// ----------------------
// Audit logs
// ----------------------
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

    const totalLogs = parseInt(countResult.rows[0].count, 10);
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