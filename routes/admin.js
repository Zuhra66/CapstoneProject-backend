// routes/admin.js
const express = require('express');
const router = express.Router();

const path = require('path');
const fs = require('fs');
const multer = require('multer');

const { pool: dbPool } = require('../db');
const { checkJwt, attachAdminUser, requireAdmin } = require('../middleware/admin-check');

const { cancelPaypalSubscription } = require('../lib/paypal');

// ---------- File upload config for events & education ----------

// Root uploads folder: <project-root>/uploads
const uploadsRoot = path.join(__dirname, '..', 'uploads');

// Events subfolder: <project-root>/uploads/events
const eventsUploadDir = path.join(uploadsRoot, 'events');
// Education subfolder: <project-root>/uploads/education
const educationUploadDir = path.join(uploadsRoot, 'education');

// Ensure directories exist
fs.mkdirSync(eventsUploadDir, { recursive: true });
fs.mkdirSync(educationUploadDir, { recursive: true });

const makeDiskStorage = (destinationDir) =>
  multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, destinationDir);
    },
    filename: (req, file, cb) => {
      const safeName = file.originalname.replace(/[^\w.-]/g, '_');
      const ts = Date.now();
      cb(null, `${ts}-${safeName}`);
    },
  });

// ✅ Allow images *and* PDFs
function fileFilter(req, file, cb) {
  const allowedMimeTypes = [
    'image/png',
    'image/jpeg',
    'image/jpg',
    'image/webp',
    'image/gif',
    'application/pdf',
  ];

  if (!allowedMimeTypes.includes(file.mimetype)) {
    return cb(
      new Error(
        'Only image files (PNG, JPG, JPEG, WebP, GIF) or PDF files are allowed.'
      ),
      false
    );
  }

  cb(null, true);
}

const eventsUpload = multer({
  storage: makeDiskStorage(eventsUploadDir),
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
});

const educationUpload = multer({
  storage: makeDiskStorage(educationUploadDir),
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
});
// ---------- end upload config ----------
// -------------------------------------
// Global admin middleware
// -------------------------------------
router.use(checkJwt);
router.use(attachAdminUser);
router.use(requireAdmin);

// -------------------------------------
// Helpers
// -------------------------------------
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

// helper for education tags: "tag1, tag2" -> ["tag1", "tag2"]
function parseTags(tagsStr) {
  if (!tagsStr) return [];
  if (Array.isArray(tagsStr)) return tagsStr;
  return String(tagsStr)
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
}

// ensure product slug is unique
async function ensureUniqueProductSlug(baseSlug) {
  const rootSlug = baseSlug && baseSlug.length ? baseSlug : 'product';
  let slug = rootSlug;
  let suffix = 2;

  while (true) {
    const { rows } = await dbPool.query(
      'SELECT 1 FROM public.products WHERE slug = $1 LIMIT 1',
      [slug]
    );

    if (rows.length === 0) return slug;

    slug = `${rootSlug}-${suffix}`;
    suffix += 1;
  }
}

// -------------------------------------
// Auth0 Management helpers
// -------------------------------------
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
      throw new Error(
        'AUTH0_MANAGEMENT_AUDIENCE environment variable is not set'
      );
    }

    const response = await fetch(
      `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: process.env.AUTH0_MANAGEMENT_CLIENT_ID,
          client_secret: process.env.AUTH0_MANAGEMENT_CLIENT_SECRET,
          audience: managementApiAudience,
          grant_type: 'client_credentials',
        }),
      }
    );

    console.log('🔧 Token response status:', response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('🔧 Token error response:', errorText);
      throw new Error(
        `Failed to get Management API token: ${response.status} ${errorText}`
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

  const response = await fetch(
    `https://${process.env.AUTH0_DOMAIN}/api/v2/roles`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    console.error('❌ Failed to fetch roles:', errorText);
    throw new Error(`Failed to fetch roles: ${response.status} ${errorText}`);
  }

  const roles = await response.json();
  console.log('🔧 Available Auth0 roles:', roles.map((r) => r.name));

  const role = roles.find((r) => r.name === roleName);

  if (!role) {
    console.error(
      `❌ Role "${roleName}" not found in Auth0. Available roles:`,
      roles.map((r) => r.name)
    );
    throw new Error(
      `Role "${roleName}" not found in Auth0. Available roles: ${roles
        .map((r) => r.name)
        .join(', ')}`
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

    const getRolesResponse = await fetch(
      `https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(
        auth0UserId
      )}/roles`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      }
    );

    if (!getRolesResponse.ok) {
      const errorText = await getRolesResponse.text();
      console.error('❌ Failed to get user roles:', errorText);
      throw new Error(
        `Failed to get user roles: ${getRolesResponse.status} ${errorText}`
      );
    }

    const currentRoles = await getRolesResponse.json();
    console.log('🔧 Current Auth0 roles:', currentRoles.map((r) => r.name));

    const newRoleId = await getAuth0RoleId(roleName);

    if (currentRoles.length > 0) {
      const roleIdsToRemove = currentRoles.map((role) => role.id);

      console.log('🔧 Removing roles:', roleIdsToRemove);

      const removeResponse = await fetch(
        `https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(
          auth0UserId
        )}/roles`,
        {
          method: 'DELETE',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ roles: roleIdsToRemove }),
        }
      );

      if (!removeResponse.ok) {
        const errorText = await removeResponse.text();
        console.error('❌ Failed to remove roles:', errorText);
        throw new Error(
          `Failed to remove roles: ${removeResponse.status} ${errorText}`
        );
      }
      console.log('✅ Removed existing roles');
    }

    console.log('🔧 Adding role ID:', newRoleId);

    const addResponse = await fetch(
      `https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(
        auth0UserId
      )}/roles`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ roles: [newRoleId] }),
      }
    );

    if (!addResponse.ok) {
      const errorText = await addResponse.text();
      console.error('❌ Failed to add role:', errorText);
      throw new Error(
        `Failed to add role: ${addResponse.status} ${errorText}`
      );
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
    console.log('🔧 Is Google OAuth2 user:', isGoogleUser);

    if (isGoogleUser) {
      delete auth0UpdatePayload.email;
      delete auth0UpdatePayload.given_name;
      delete auth0UpdatePayload.family_name;
      delete auth0UpdatePayload.name;
    }

    Object.keys(auth0UpdatePayload).forEach((key) => {
      if (auth0UpdatePayload[key] === undefined) {
        delete auth0UpdatePayload[key];
      }
    });

    if (
      auth0UpdatePayload.app_metadata &&
      Object.keys(auth0UpdatePayload.app_metadata).length === 0
    ) {
      delete auth0UpdatePayload.app_metadata;
    }

    console.log(
      '🔧 Auth0 profile update payload:',
      JSON.stringify(auth0UpdatePayload, null, 2)
    );

    const apiDomain =
      process.env.AUTH0_CUSTOM_DOMAIN || process.env.AUTH0_DOMAIN;
    const apiUrl = `https://${apiDomain}/api/v2/users/${encodeURIComponent(
      auth0UserId
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
      throw new Error(
        `Auth0 profile update failed: ${response.status} ${errorText}`
      );
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
          roleError.message
        );
      }
    }

    return result;
  } catch (error) {
    console.error('❌ Error updating Auth0 user:', error);
    throw error;
  }
};

// -------------------------------------
// Admin audit helper
// -------------------------------------
function isUuidLike(value) {
  if (typeof value !== 'string') return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    value
  );
}

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

    const adminIdForLog = isUuidLike(adminUserId) ? adminUserId : null;
    const targetUserIdForLog = isUuidLike(targetId) ? targetId : null;

    await dbPool.query(
      `INSERT INTO public.admin_audit_logs
         (admin_user_id, action_type, target_user_id, details, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [adminIdForLog, actionType, targetUserIdForLog, details, ip, ua]
    );
  } catch (error) {
    console.error('Failed to log admin action:', error);
  }
};

const syncMembershipWithRole = async (userId, newRole, isActive) => {
  try {
    const { rows } = await dbPool.query(
      `
      SELECT id, status, provider, external_ref
      FROM user_memberships
      WHERE user_id = $1
      ORDER BY updated_at DESC
      LIMIT 1
      `,
      [userId]
    );

    if (!rows.length) return newRole;

    const membership = rows[0];
    const isActiveMembership = membership.status === "active";

    if (newRole === "Member" && !isActiveMembership) {
      return "User";
    }

    // -----------------------------
    //  CANCEL CONDITIONS
    // -----------------------------

    const shouldCancel =
      !isActive ||               // user deactivated
      newRole !== "Member";      // role downgraded

    if (shouldCancel && isActiveMembership) {
      console.log("🛑 Cancelling membership for user:", userId);

      // Cancel PayPal subscription (STOP BILLING)
      if (
        membership.provider === "paypal" &&
        membership.external_ref
      ) {
        console.log(
          "🔔 Cancelling PayPal subscription:",
          membership.external_ref
        );

        try {
          await cancelPaypalSubscription(membership.external_ref);
        } catch (paypalErr) {
          console.error(
            "⚠️ PayPal cancellation failed (continuing local cancel):",
            paypalErr.message
          );
          // ❗ Do NOT throw — access must still be revoked
        }
      }

      // ✅ Always cancel locally
      await dbPool.query(
        `
        UPDATE user_memberships
        SET status = 'cancelled',
            end_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        `,
        [membership.id]
      );

      console.log("✅ Membership cancelled locally");
    }

    // NEVER ACTIVATE THROUGH ADMIN
    return newRole;
  } catch (err) {
    console.error("❌ syncMembershipWithRole error:", err);
    return newRole;
  }
};

// -------------------------------------
// Debug route
// -------------------------------------
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

    let auth0Test = { success: false, message: '' };
    let auth0UserData = null;
    let auth0RolesData = null;
    let allAuth0Roles = null;

    if (user.auth0_id) {
      try {
        const token = await getManagementApiToken();
        const apiDomain =
          process.env.AUTH0_CUSTOM_DOMAIN || process.env.AUTH0_DOMAIN;

        const allRolesResponse = await fetch(
          `https://${apiDomain}/api/v2/roles`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: 'application/json',
            },
          }
        );

        if (allRolesResponse.ok) {
          allAuth0Roles = await allRolesResponse.json();
        }

        const userResponse = await fetch(
          `https://${apiDomain}/api/v2/users/${encodeURIComponent(
            user.auth0_id
          )}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: 'application/json',
            },
          }
        );

        if (userResponse.ok) {
          auth0UserData = await userResponse.json();

          const rolesResponse = await fetch(
            `https://${apiDomain}/api/v2/users/${encodeURIComponent(
              user.auth0_id
            )}/roles`,
            {
              headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/json',
              },
            }
          );

          if (rolesResponse.ok) {
            auth0RolesData = await rolesResponse.json();
          }

          auth0Test = {
            success: true,
            message: 'Auth0 Management API is working',
          };
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
        auth0Test = {
          success: false,
          message: `Auth0 test failed: ${error.message}`,
        };
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

// -------------------------------------
// Dashboard stats
// -------------------------------------
router.get('/dashboard-stats', async (req, res) => {
  try {
    const totalUsers = await dbPool.query('SELECT COUNT(*) FROM public.users');
    const activeUsers = await dbPool.query(
      'SELECT COUNT(*) FROM public.users WHERE is_active = true'
    );
    const newUsersThisMonth = await dbPool.query(`
      SELECT COUNT(*)
      FROM public.users
      WHERE created_at >= date_trunc('month', CURRENT_DATE)
    `);

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
    }

    let auditStats = {
      total: 0,
      today: 0,
      security: 0,
      authentication: 0,
      access: 0,
      modification: 0,
    };

    try {
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      const auditQueries = await Promise.all([
        dbPool.query('SELECT COUNT(*) FROM audit_logs'),
        dbPool.query('SELECT COUNT(*) FROM audit_logs WHERE created_at >= $1', [
          today,
        ]),
        dbPool.query(
          `SELECT COUNT(*) FROM audit_logs WHERE event_category = 'security'`
        ),
        dbPool.query(
          `SELECT COUNT(*) FROM audit_logs WHERE event_category = 'authentication'`
        ),
        dbPool.query(
          `SELECT COUNT(*) FROM audit_logs WHERE event_category = 'access'`
        ),
        dbPool.query(
          `SELECT COUNT(*) FROM audit_logs WHERE event_category = 'modification'`
        ),
      ]);

      auditStats = {
        total: parseInt(auditQueries[0].rows[0].count) || 0,
        today: parseInt(auditQueries[1].rows[0].count) || 0,
        security: parseInt(auditQueries[2].rows[0].count) || 0,
        authentication: parseInt(auditQueries[3].rows[0].count) || 0,
        access: parseInt(auditQueries[4].rows[0].count) || 0,
        modification: parseInt(auditQueries[5].rows[0].count) || 0,
      };
    } catch (auditError) {
      console.log('Audit stats not available:', auditError.message);
    }

    const stats = {
      users: {
        total: parseInt(totalUsers.rows[0].count),
        active: parseInt(activeUsers.rows[0].count),
        newThisMonth: parseInt(newUsersThisMonth.rows[0].count),
      },
      newsletter: {
        total: newsletterTotal,
        active: newsletterActive,
      },
      appointments: { total: 0, pending: 0, today: 0 },
      products: { total: 0 },
      categories: { total: 0 },
      blog: { total: 0 },
      education: { videos: 0, articles: 0 },
      events: { total: 0, upcoming: 0 },
      memberships: { plans: 0, active: 0 },
      messages: { total: 0 },
      audit: auditStats,
    };

    // appointments stats
    try {
      const appointmentsTotal = await dbPool.query(
        'SELECT COUNT(*) FROM public.appointments'
      );
      const appointmentsPending = await dbPool.query(
        "SELECT COUNT(*) FROM public.appointments WHERE status = 'pending'"
      );
      const appointmentsToday = await dbPool.query(`
        SELECT COUNT(*) FROM public.appointments
        WHERE DATE(appointment_date) = CURRENT_DATE
      `);
      stats.appointments = {
        total: parseInt(appointmentsTotal.rows[0].count) || 0,
        pending: parseInt(appointmentsPending.rows[0].count) || 0,
        today: parseInt(appointmentsToday.rows[0].count) || 0,
      };
    } catch (e) {
      console.log('Appointments stats not available:', e.message);
    }

    // products stats
    try {
      const productsTotal = await dbPool.query(
        'SELECT COUNT(*) FROM public.products'
      );
      stats.products.total = parseInt(productsTotal.rows[0].count) || 0;
    } catch (e) {
      console.log('Products stats not available:', e.message);
    }

    // blog stats
    try {
      const blogTotal = await dbPool.query(
        'SELECT COUNT(*) FROM public.blog_posts'
      );
      stats.blog.total = parseInt(blogTotal.rows[0].count) || 0;
    } catch (e) {
      console.log('Blog stats not available:', e.message);
    }

    // education stats
    try {
      const educationVideos = await dbPool.query(
        'SELECT COUNT(*) FROM public.education_videos'
      );
      const educationArticles = await dbPool.query(
        'SELECT COUNT(*) FROM public.education_articles'
      );
      stats.education = {
        videos: parseInt(educationVideos.rows[0].count) || 0,
        articles: parseInt(educationArticles.rows[0].count) || 0,
      };
    } catch (e) {
      console.log('Education stats not available:', e.message);
    }

    // categories stats
    try {
      const categoriesTotal = await dbPool.query(
        'SELECT COUNT(*) FROM public.categories'
      );
      stats.categories.total = parseInt(categoriesTotal.rows[0].count) || 0;
    } catch (e) {
      console.log('Categories stats not available:', e.message);
    }

    // events stats
    try {
      const totalEvents = await dbPool.query(
        'SELECT COUNT(*) FROM public.events'
      );
      const upcomingEvents = await dbPool.query(`
        SELECT COUNT(*)
        FROM public.events
        WHERE is_published = TRUE
          AND start_at >= CURRENT_DATE
      `);
      stats.events.total = parseInt(totalEvents.rows[0].count) || 0;
      stats.events.upcoming = parseInt(upcomingEvents.rows[0].count) || 0;
    } catch (e) {
      console.log('Events stats not available:', e.message);
    }

    // memberships stats
    try {
      const membershipPlans = await dbPool.query(
        'SELECT COUNT(*) FROM public.membership_plans'
      );
      const activeMemberships = await dbPool.query(
        "SELECT COUNT(*) FROM public.user_memberships WHERE status = 'active'"
      );
      stats.memberships = {
        plans: parseInt(membershipPlans.rows[0].count) || 0,
        active: parseInt(activeMemberships.rows[0].count) || 0,
      };
    } catch (e) {
      console.log('Memberships stats not available:', e.message);
    }

    // messages stats
    try {
      const messagesTotal = await dbPool.query(
        'SELECT COUNT(*) FROM public.contact_messages'
      );
      stats.messages.total = parseInt(messagesTotal.rows[0].count) || 0;
    } catch (e) {
      console.log('Messages stats not available:', e.message);
    }

    // user roles
    try {
      const rolesResult = await dbPool.query(`
        SELECT role, COUNT(*) as count
        FROM public.users
        WHERE role IS NOT NULL
        GROUP BY role
      `);

      stats.users.roles = {};
      rolesResult.rows.forEach((row) => {
        stats.users.roles[row.role] = parseInt(row.count);
      });
    } catch (e) {
      console.log('User roles stats not available:', e.message);
    }

    await logAdminAction(
      req.adminUser.id,
      'VIEW_DASHBOARD_STATS',
      null,
      {},
      req
    );

    console.log('📊 Dashboard stats generated successfully');
    res.json(stats);
  } catch (error) {
    console.error('❌ Dashboard stats error:', error);

    res.json({
      users: { total: 1, active: 1, newThisMonth: 0 },
      newsletter: { total: 0, active: 0 },
      appointments: { total: 0, pending: 0, today: 0 },
      products: { total: 0 },
      categories: { total: 0 },
      blog: { total: 0 },
      education: { videos: 0, articles: 0 },
      events: { total: 0, upcoming: 0 },
      memberships: { plans: 0, active: 0 },
      messages: { total: 0 },
      audit: {
        total: 0,
        today: 0,
        security: 0,
        authentication: 0,
        access: 0,
        modification: 0,
      },
    });
  }
});

// -------------------------------------
// EDUCATION ROUTES (Admin CRUD)
// -------------------------------------

// ---- Articles ----

// GET /api/admin/education/articles
router.get('/education/articles', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;

    const { rows } = await dbPool.query(
      `
        SELECT
          id,
          title,
          summary,
          minutes,
          COALESCE(tags, '{}') AS tags,
          cover_url,
          href,
          is_active,
          created_at
        FROM public.education_articles
        ORDER BY created_at DESC
      `
    );

    await logAdminAction(
      adminUserId,
      'ADMIN_LIST_EDUCATION_ARTICLES',
      null,
      {},
      req
    );

    res.json({ articles: rows });
  } catch (err) {
    console.error('Admin education articles list error:', err);
    res.status(500).json({ error: 'Failed to load education articles.' });
  }
});

// POST /api/admin/education/articles
// POST /api/admin/education/articles
router.post('/education/articles', educationUpload.single('file'), async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const {
      title,
      summary,
      minutes,
      tags,
      cover_url,
      href,
      is_active = true,
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const tagsArray = parseTags(tags);
    const minutesValue =
      minutes === '' || minutes === null || minutes === undefined
        ? null
        : Number(minutes);

    // ✅ If a file was uploaded, build URL like /uploads/education/filename
    const uploadedUrl = req.file
      ? `/uploads/education/${req.file.filename}`
      : null;

    const finalCoverUrl = uploadedUrl || (cover_url || '').trim() || null;

    const { rows } = await dbPool.query(
      `
        INSERT INTO public.education_articles
          (title, summary, minutes, tags, cover_url, href, is_active)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING
          id,
          title,
          summary,
          minutes,
          COALESCE(tags, '{}') AS tags,
          cover_url,
          href,
          is_active,
          created_at
      `,
      [
        title.trim(),
        (summary || '').trim() || null,
        Number.isFinite(minutesValue) ? minutesValue : null,
        tagsArray,
        finalCoverUrl,
        (href || '').trim() || null,
        !!is_active,
      ]
    );

    const article = rows[0];

    await logAdminAction(
      adminUserId,
      'ADMIN_CREATE_EDUCATION_ARTICLE',
      article.id,
      { title: article.title },
      req
    );

    res.json(article);
  } catch (err) {
    console.error('Admin create education article error:', err);
    res.status(500).json({ error: 'Failed to save article.' });
  }
});


// PUT /api/admin/education/articles/:id
// PUT /api/admin/education/articles/:id
router.put('/education/articles/:id', educationUpload.single('file'), async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { id } = req.params;

    const existing = await dbPool.query(
      'SELECT * FROM public.education_articles WHERE id = $1',
      [id]
    );
    if (!existing.rows.length) {
      return res.status(404).json({ error: 'Article not found' });
    }

    const {
      title,
      summary,
      minutes,
      tags,
      cover_url,
      href,
      is_active,
    } = req.body;

    const tagsArray = parseTags(tags);
    const minutesValue =
      minutes === '' || minutes === null || minutes === undefined
        ? null
        : Number(minutes);

    // ✅ Handle possible new uploaded file
    const uploadedUrl = req.file
      ? `/uploads/education/${req.file.filename}`
      : null;

    const current = existing.rows[0];

    let newCoverUrl = current.cover_url;
    if (uploadedUrl !== null) {
      // New file replaces whatever was there before
      newCoverUrl = uploadedUrl;
    } else if (cover_url !== undefined) {
      // Explicitly set via body; empty string clears it
      newCoverUrl = cover_url || null;
    }

    const { rows } = await dbPool.query(
      `
        UPDATE public.education_articles
        SET
          title      = $2,
          summary    = $3,
          minutes    = $4,
          tags       = $5,
          cover_url  = $6,
          href       = $7,
          is_active  = $8,
          updated_at = NOW()
        WHERE id = $1
        RETURNING
          id,
          title,
          summary,
          minutes,
          COALESCE(tags, '{}') AS tags,
          cover_url,
          href,
          is_active,
          created_at,
          updated_at
      `,
      [
        id,
        title || current.title,
        summary !== undefined ? summary : current.summary,
        Number.isFinite(minutesValue) ? minutesValue : current.minutes,
        tagsArray.length ? tagsArray : current.tags || [],
        newCoverUrl,
        href !== undefined ? href : current.href,
        typeof is_active === 'boolean' ? is_active : current.is_active,
      ]
    );

    const article = rows[0];

    await logAdminAction(
      adminUserId,
      'ADMIN_UPDATE_EDUCATION_ARTICLE',
      article.id,
      { title: article.title },
      req
    );

    res.json(article);
  } catch (err) {
    console.error('Admin update education article error:', err);
    res.status(500).json({ error: 'Failed to update article.' });
  }
});

// DELETE /api/admin/education/articles/:id
router.delete('/education/articles/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { id } = req.params;

    const result = await dbPool.query(
      'DELETE FROM public.education_articles WHERE id = $1 RETURNING id, title',
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'Article not found' });
    }

    const deleted = result.rows[0];

    await logAdminAction(
      adminUserId,
      'ADMIN_DELETE_EDUCATION_ARTICLE',
      deleted.id,
      { title: deleted.title },
      req
    );

    res.status(204).end();
  } catch (err) {
    console.error('Admin delete education article error:', err);
    res.status(500).json({ error: 'Failed to delete article.' });
  }
});

// ---- Videos ----

// GET /api/admin/education/videos
router.get('/education/videos', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;

    const { rows } = await dbPool.query(
      `
        SELECT
          id,
          title,
          duration,
          COALESCE(tags, '{}') AS tags,
          thumb_url,
          href,
          is_active,
          created_at
        FROM public.education_videos
        ORDER BY created_at DESC
      `
    );

    await logAdminAction(
      adminUserId,
      'ADMIN_LIST_EDUCATION_VIDEOS',
      null,
      {},
      req
    );

    res.json({ videos: rows });
  } catch (err) {
    console.error('Admin education videos list error:', err);
    res.status(500).json({ error: 'Failed to load education videos.' });
  }
});

// POST /api/admin/education/videos
router.post('/education/videos', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const {
      title,
      duration,
      tags,
      thumb_url,
      href,
      is_active = true,
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const tagsArray = parseTags(tags);

    const { rows } = await dbPool.query(
      `
        INSERT INTO public.education_videos
          (title, duration, tags, thumb_url, href, is_active)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING
          id,
          title,
          duration,
          COALESCE(tags, '{}') AS tags,
          thumb_url,
          href,
          is_active,
          created_at
      `,
      [
        title.trim(),
        (duration || '').trim() || null,
        tagsArray,
        (thumb_url || '').trim() || null,
        (href || '').trim() || null,
        !!is_active,
      ]
    );

    const video = rows[0];

    await logAdminAction(
      adminUserId,
      'ADMIN_CREATE_EDUCATION_VIDEO',
      video.id,
      { title: video.title },
      req
    );

    res.json(video);
  } catch (err) {
    console.error('Admin create education video error:', err);
    res.status(500).json({ error: 'Failed to save video.' });
  }
});

// PUT /api/admin/education/videos/:id
router.put('/education/videos/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { id } = req.params;

    const existing = await dbPool.query(
      'SELECT * FROM public.education_videos WHERE id = $1',
      [id]
    );
    if (!existing.rows.length) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const {
      title,
      duration,
      tags,
      thumb_url,
      href,
      is_active,
    } = req.body;

    const tagsArray = parseTags(tags);

    const { rows } = await dbPool.query(
      `
        UPDATE public.education_videos
        SET
          title      = $2,
          duration   = $3,
          tags       = $4,
          thumb_url  = $5,
          href       = $6,
          is_active  = $7,
          updated_at = NOW()
        WHERE id = $1
        RETURNING
          id,
          title,
          duration,
          COALESCE(tags, '{}') AS tags,
          thumb_url,
          href,
          is_active,
          created_at,
          updated_at
      `,
      [
        id,
        title || existing.rows[0].title,
        duration !== undefined ? duration : existing.rows[0].duration,
        tagsArray.length ? tagsArray : existing.rows[0].tags || [],
        thumb_url !== undefined ? thumb_url : existing.rows[0].thumb_url,
        href !== undefined ? href : existing.rows[0].href,
        typeof is_active === 'boolean'
          ? is_active
          : existing.rows[0].is_active,
      ]
    );

    const video = rows[0];

    await logAdminAction(
      adminUserId,
      'ADMIN_UPDATE_EDUCATION_VIDEO',
      video.id,
      { title: video.title },
      req
    );

    res.json(video);
  } catch (err) {
    console.error('Admin update education video error:', err);
    res.status(500).json({ error: 'Failed to update video.' });
  }
});

// DELETE /api/admin/education/videos/:id
router.delete('/education/videos/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { id } = req.params;

    const result = await dbPool.query(
      'DELETE FROM public.education_videos WHERE id = $1 RETURNING id, title',
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const deleted = result.rows[0];

    await logAdminAction(
      adminUserId,
      'ADMIN_DELETE_EDUCATION_VIDEO',
      deleted.id,
      { title: deleted.title },
      req
    );

    res.status(204).end();
  } catch (err) {
    console.error('Admin delete education video error:', err);
    res.status(500).json({ error: 'Failed to delete video.' });
  }
});
// -------------------------------------
// USERS ROUTES
// -------------------------------------
router.get('/users', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { page = 1, limit = 10, search = '', role = '', status = '' } =
      req.query;

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
        CASE
          WHEN m.status = 'active' THEN json_build_object(
            'status', m.status,
            'start_date', m.start_at,
            'end_date', m.end_at,
            'plan_name', m.plan_name,
            'plan_slug', m.plan_slug
          )
          ELSE NULL
        END AS membership

      FROM public.users
      LEFT JOIN LATERAL (
        SELECT
          um.status,
          um.start_at,
          um.end_at,
          mp.name AS plan_name,
          mp.slug AS plan_slug
        FROM public.user_memberships um
        JOIN public.membership_plans mp ON mp.id = um.plan_id
        WHERE um.user_id = users.id
        ORDER BY um.updated_at DESC
        LIMIT 1
      ) m ON true
      WHERE ${where.join(' AND ')}
      ORDER BY users.created_at DESC
      LIMIT $${params.length + 1}
      OFFSET $${params.length + 2}
    `;


    const countSql = `SELECT COUNT(*) FROM public.users WHERE ${where.join(
      ' AND '
    )}`;

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

    await logAdminAction(
      adminUserId,
      'VIEW_USER_DETAILS',
      userId,
      {},
      req
    );
    res.json({ user });
  } catch (error) {
    console.error('Get user details error:', error);
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});

// PUT /users/:userId
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
      is_admin,
    } = req.body;

    if (!email) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'Email is required',
      });
    }

    const existingUser = await dbPool.query(
      'SELECT id, auth0_id, email, is_active, role, is_admin FROM public.users WHERE id = $1',
      [userId]
    );

    if (existingUser.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The requested user does not exist',
      });
    }

    const targetUser = existingUser.rows[0];

    const validRoles = ['Administrator', 'Provider', 'Member', 'User'];
    if (role && !validRoles.includes(role)) {
      return res.status(400).json({
        error: 'Invalid role',
        message: `Role must be one of: ${validRoles.join(', ')}`,
      });
    }

    let finalRole = role || targetUser.role;
    let finalIsActive =
      is_active !== undefined ? is_active : targetUser.is_active;

    if (finalRole === 'Member' && !finalIsActive) {
      finalRole = 'User';
    }

    await syncMembershipWithRole(userId, finalRole, finalIsActive);

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
      finalRole,
      finalIsActive,
      is_admin !== undefined ? is_admin : targetUser.is_admin,
      userId,
    ]);

    const updatedUser = updateResult.rows[0];

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
        membership_synced: true,
      },
      req
    );

    res.json({
      message:
        'User updated successfully' +
        (auth0SyncResult ? ' (Auth0 synced)' : ' (Auth0 not synced)'),
      user: updatedUser,
      auth0_synced: !!auth0SyncResult,
      auth0_role_synced: !!auth0RoleSyncResult,
      auth0_id_present: !!targetUser.auth0_id,
      role_adjusted:
        finalRole !== role
          ? 'Role adjusted from Member to User because user is inactive'
          : null,
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

// PATCH role
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
      [userId]
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

    if (role === 'Member' && !targetUser.is_active) {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'Cannot set Member role on inactive user',
      });
    }

    await syncMembershipWithRole(userId, role, targetUser.is_active);

    const result = await dbPool.query(
      'UPDATE public.users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
      [role, userId]
    );

    const updatedUser = result.rows[0];

    if (targetUser.role !== updatedUser.role) {
      try {
        await updateAuth0User(targetUser.auth0_id, {
          role: updatedUser.role,
          is_active: targetUser.is_active,
          is_admin: targetUser.is_admin,
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
        membership_synced: true,
      },
      req
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

// PATCH status
router.patch('/users/:userId/status', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { userId } = req.params;
    const { is_active } = req.body;

    const userResult = await dbPool.query(
      'SELECT auth0_id, is_active as current_active, role, is_admin FROM public.users WHERE id = $1',
      [userId]
    );

    if (!userResult.rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }

    const targetUser = userResult.rows[0];

    if (toInt(userId) === adminUserId && !is_active) {
      return res.status(400).json({
        error: 'Invalid operation',
        message: 'Cannot deactivate your own account',
      });
    }

    let roleAdjustment = null;
    let finalRole = targetUser.role;

    if (!is_active && targetUser.role === 'Member') {
      finalRole = 'User';
      roleAdjustment = 'Role changed from Member to User';
    }

    await syncMembershipWithRole(userId, finalRole, is_active);

    const result = await dbPool.query(
      'UPDATE public.users SET is_active = $1, role = $2, updated_at = NOW() WHERE id = $3 RETURNING *',
      [!!is_active, finalRole, userId]
    );

    const updatedUser = result.rows[0];

    if (targetUser.auth0_id) {
      try {
        await updateAuth0User(targetUser.auth0_id, {
          is_active: updatedUser.is_active,
          role: updatedUser.role,
          is_admin: targetUser.is_admin,
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
        membership_synced: true,
      },
      req
    );

    res.json({
      user: updatedUser,
      auth0_synced: !!targetUser.auth0_id,
      role_adjusted: roleAdjustment,
    });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// DELETE user
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
        message: 'The requested user does not exist',
      });
    }

    if (req.adminUser.id === userId) {
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

// -------------------------------------
// APPOINTMENTS ROUTES
// -------------------------------------
router.get('/appointments', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const { page = 1, limit = 10, status = '', date_from = '', date_to = '' } =
      req.query;

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
      ' AND '
    )}`;

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
    if (!valid.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const result = await dbPool.query(
      `UPDATE public.appointments
       SET status = $1, updated_at = NOW()
       WHERE id = $2 RETURNING *`,
      [status, appointmentId]
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    await logAdminAction(
      adminUserId,
      'UPDATE_APPOINTMENT_STATUS',
      appointmentId,
      { status },
      req
    );
    res.json({ appointment: result.rows[0] });
  } catch (error) {
    console.error('Update appointment status error:', error);
    res.status(500).json({ error: 'Failed to update appointment status' });
  }
});

// -------------------------------------
// PRODUCTS ROUTES (dollars)
// -------------------------------------
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
      req
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
      req
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

    res
      .status(500)
      .json({ error: 'Failed to create product', message: e.message });
  }
});

router.put('/products/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const id = Number(req.params.id);
    if (!id) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }

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
      [id]
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

    const hasCategory = Object.prototype.hasOwnProperty.call(
      req.body,
      'category_id'
    );
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
      req
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

    res
      .status(500)
      .json({ error: 'Failed to update product', message: e.message });
  }
});

router.delete('/products/:id', async (req, res) => {
  try {
    const adminUserId = req.adminUser.id;
    const id = Number(req.params.id);
    if (!id) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }

    const result = await dbPool.query(
      'DELETE FROM public.products WHERE id = $1 RETURNING id, name',
      [id]
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
      req
    );

    res.json({
      success: true,
      message: 'Product deleted successfully',
      deletedProduct: deleted,
    });
  } catch (e) {
    console.error('admin delete product error:', e);
    res
      .status(500)
      .json({ error: 'Failed to delete product', message: e.message });
  }
});

// -------------------------------------
// EVENTS ROUTES (Admin CRUD)
// -------------------------------------

// helper: normalize date strings
function normalizeDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

// list events
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
        // no cancelled flag yet; return empty set
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
      `
    );

    await logAdminAction(
      adminUserId,
      'ADMIN_LIST_EVENTS',
      null,
      { status: status || 'all' },
      req
    );

    res.json({ events: rows });
  } catch (err) {
    console.error('Admin events list error:', err);
    res.status(500).json({ error: 'Failed to load events.' });
  }
});

// create event (multipart/form-data + file)
router.post('/events', eventsUpload.single('file'), async (req, res) => {
  try {
    const adminUserId = req.adminUser?.id;

    const body = req.body || {};

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
      ]
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
        req
      );
    }

    res.status(201).json({ event });
  } catch (err) {
    console.error('Admin create event error:', err);
    res.status(500).json({ error: 'Failed to create event.' });
  }
});

// update event (multipart/form-data + file)
router.put('/events/:id', eventsUpload.single('file'), async (req, res) => {
  try {
    const adminUserId = req.adminUser?.id;
    const { id } = req.params;
    const eventId = Number(id);
    if (!eventId) {
      return res.status(400).json({ error: 'Invalid event ID' });
    }

    const existingResult = await dbPool.query(
      'SELECT * FROM public.events WHERE id = $1',
      [eventId]
    );
    if (!existingResult.rows.length) {
      return res.status(404).json({ error: 'Event not found' });
    }
    const existing = existingResult.rows[0];

    const body = req.body || {};

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
      ]
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
        req
      );
    }

    res.json({ event });
  } catch (err) {
    console.error('Admin update event error:', err);
    res.status(500).json({ error: 'Failed to update event.' });
  }
});

// delete event
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
      [eventId]
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
        req
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

// -------------------------------------
// AUDIT LOGS
// -------------------------------------
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

    await logAdminAction(
      adminUserId,
      'VIEW_AUDIT_LOGS',
      null,
      {},
      req
    );

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
