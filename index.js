// index.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const { Pool } = require('pg');

const app = express();

// ---------------- Env / Network ----------------
const PORT = process.env.PORT || 5001;
const HOST = process.env.HOST || '127.0.0.1';

// ---------------- Postgres Pool ----------------
// Render External URL needs SSL; Internal URL may not.
// We’ll be permissive so both work.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_URL?.includes('render.com') ||
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,
});

// Quick startup test (non-fatal if fails, but we log it)
(async () => {
  try {
    const r = await pool.query('select now() as now');
    console.log('✅ Database connected at', r.rows[0].now);
  } catch (e) {
    console.error('❌ Database connection failed:', e.message);
  }
})();

// Make pool available via req.db if you like
app.use((req, _res, next) => {
  req.db = pool;
  next();
});

// ---------------- Security & Core Middleware ----------------
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://empowermed-frontend.onrender.com',
];

app.use(
  cors({
    origin(origin, cb) {
      // allow requests with no origin (curl, Postman)
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      console.warn('Blocked CORS request from origin:', origin);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
    optionsSuccessStatus: 200,
  })
);

const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

// Verify Auth0 access tokens
const jwtCheck = jwt({
  secret: jwksRsa.expressJwtSecret({
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
    cache: true,
    rateLimit: true,
  }),
  audience: process.env.AUTH0_AUDIENCE,
  issuer: `https://${process.env.AUTH0_DOMAIN}/`,
  algorithms: ['RS256'],
  credentialsRequired: false, // public routes work; we’ll require on admin routes
});

// Attach req.auth if token present
app.use(jwtCheck);

// helper: is admin? (supports either roles array claim or permissions)
function isAdmin(req) {
  // Option A: roles via custom claim (configure Auth0 Rule/Action to add it)
  const roles = req.auth?.['https://empowermed.app/roles'] || req.auth?.roles || [];
  if (Array.isArray(roles) && roles.includes('admin')) return true;

  // Option B: RBAC permissions
  const perms = req.auth?.permissions || [];
  if (Array.isArray(perms) && perms.includes('manage:education')) return true;

  return false;
}

function requireAuth(req, res, next) {
  if (!req.auth) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.auth) return res.status(401).json({ error: 'Unauthorized' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ---------------- Public routes (no CSRF) ----------------
app.get('/', (_req, res) => res.send('Backend is running securely'));

// Healthcheck also verifies DB connectivity
app.get('/health', async (req, res) => {
  try {
    const r = await req.db.query('select 1 as ok');
    return res.status(200).json({ status: 'ok', db: r.rows[0].ok === 1 });
  } catch (e) {
    return res.status(500).json({ status: 'error', db: false, error: e.message });
  }
});

// ---------------- CSRF (apply after public routes) ----------------
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // set true when you serve HTTPS (Render prod)
  },
});
app.use(csrfProtection);

// Frontend will call this first to get a token, then include it in X-CSRF-Token
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ---------------- API: Catalog ----------------
// GET /api/categories
app.get('/api/categories', async (req, res, next) => {
  try {
    const { rows } = await req.db.query(
      `SELECT id, name, slug
       FROM categories
       ORDER BY name ASC`
    );
    res.json(rows);
  } catch (e) {
    next(e);
  }
});

// GET /api/products  (includes category + aggregated tags)
app.get('/api/products', async (req, res, next) => {
  const { q, category } = req.query;

  // Optional search filter (ILIKE) and category filter by slug
  const params = [];
  const where = [];

  if (q) {
    params.push(`%${q}%`);
    where.push(`(p.name ILIKE $${params.length} OR p.slug ILIKE $${params.length})`);
  }
  if (category && category !== 'All') {
    params.push(category);
    where.push(`c.slug = $${params.length}`);
  }

  const sql = `
    SELECT
      p.id,
      p.name,
      p.slug,
      p.price_cents,
      p.image_url,
      p.external_url,
      p.is_active,
      c.id   AS category_id,
      c.name AS category_name,
      c.slug AS category_slug,
      COALESCE(
        json_agg(DISTINCT t.name) FILTER (WHERE t.id IS NOT NULL),
        '[]'
      ) AS tags
    FROM products p
    LEFT JOIN categories c    ON c.id = p.category_id
    LEFT JOIN product_tags pt ON pt.product_id = p.id
    LEFT JOIN tags t          ON t.id = pt.tag_id
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    GROUP BY p.id, c.id
    ORDER BY p.created_at DESC, p.id DESC
  `;

  try {
    const { rows } = await req.db.query(sql, params);
    res.json(
      rows.map((r) => ({
        id: r.id,
        name: r.name,
        slug: r.slug,
        price: r.price_cents != null ? r.price_cents / 100 : null,
        image: r.image_url,
        externalUrl: r.external_url,
        isActive: r.is_active,
        category: {
          id: r.category_id,
          name: r.category_name,
          slug: r.category_slug,
        },
        tags: r.tags,
      }))
    );
  } catch (e) {
    next(e);
  }
});

// GET /api/products/:slug
app.get('/api/products/:slug', async (req, res, next) => {
  try {
    const { rows } = await req.db.query(
      `
      SELECT
        p.*,
        c.name AS category_name,
        c.slug AS category_slug,
        COALESCE(
          json_agg(DISTINCT t.name) FILTER (WHERE t.id IS NOT NULL),
          '[]'
        ) AS tags
      FROM products p
      LEFT JOIN categories c    ON c.id = p.category_id
      LEFT JOIN product_tags pt ON pt.product_id = p.id
      LEFT JOIN tags t          ON t.id = pt.tag_id
      WHERE p.slug = $1
      GROUP BY p.id, c.id
      `,
      [req.params.slug]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });

    const p = rows[0];
    res.json({
      id: p.id,
      name: p.name,
      slug: p.slug,
      price: p.price_cents != null ? p.price_cents / 100 : null,
      image: p.image_url,
      externalUrl: p.external_url,
      isActive: p.is_active,
      category: { name: p.category_name, slug: p.category_slug },
      tags: p.tags,
    });
  } catch (e) {
    next(e);
  }
});

// GET /api/services
app.get('/api/services', async (req, res, next) => {
  try {
    const { rows } = await req.db.query(
      `SELECT id, name, slug, description, duration_min, price_cents, is_active
       FROM services
       WHERE is_active = TRUE
       ORDER BY name ASC`
    );
    res.json(
      rows.map((s) => ({
        id: s.id,
        name: s.name,
        slug: s.slug,
        description: s.description,
        durationMin: s.duration_min,
        price: s.price_cents != null ? s.price_cents / 100 : null,
        isActive: s.is_active,
      }))
    );
  } catch (e) {
    next(e);
  }
});

// Example protected write route (contact form)
app.post('/api/contact', async (req, res, next) => {
  const { name, email, phone, subject, message } = req.body || {};
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'name, email, and message are required' });
  }
  try {
    await req.db.query(
      `INSERT INTO contact_messages (name, email, phone, subject, message)
       VALUES ($1,$2,$3,$4,$5)`,
      [name, email, phone || null, subject || null, message]
    );
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});
// =============== Educational Hub API ===============

// GET /api/education  -> { articles:[], videos:[], downloads:[] }
// Optional query: ?q=term&tag=TagName
app.get('/api/education', async (req, res, next) => {
  const { q, tag } = req.query;

  // Build WHERE pieces once and reuse
  const whereA = ['is_active = TRUE'];
  const paramsA = [];
  if (q) {
    paramsA.push(`%${q}%`);
    whereA.push(`(title ILIKE $${paramsA.length} OR summary ILIKE $${paramsA.length})`);
  }
  if (tag) {
    paramsA.push(tag);
    whereA.push(`$${paramsA.length} = ANY (tags)`);
  }

  const whereV = ['is_active = TRUE'];
  const paramsV = [];
  if (q) {
    paramsV.push(`%${q}%`);
    whereV.push(`title ILIKE $${paramsV.length}`);
  }
  if (tag) {
    paramsV.push(tag);
    whereV.push(`$${paramsV.length} = ANY (tags)`);
  }

  try {
    const [articles, videos, downloads] = await Promise.all([
      req.db.query(
        `
        SELECT id, title, summary, minutes, tags, cover_url AS "cover", href
        FROM education_articles
        ${whereA.length ? 'WHERE ' + whereA.join(' AND ') : ''}
        ORDER BY created_at DESC
        `,
        paramsA
      ),
      req.db.query(
        `
        SELECT id, title, duration, tags, thumb_url AS "thumb", href
        FROM education_videos
        ${whereV.length ? 'WHERE ' + whereV.join(' AND ') : ''}
        ORDER BY created_at DESC
        `,
        paramsV
      ),
      req.db.query(
        `
        SELECT id, title, file_size AS "size", href
        FROM education_downloads
        WHERE is_active = TRUE
        ORDER BY created_at DESC
        `
      ),
    ]);

    res.json({
      articles: articles.rows,
      videos: videos.rows,
      downloads: downloads.rows,
    });
  } catch (e) {
    next(e);
  }
});

// =============== Educational Hub: Admin CRUD (Auth + CSRF required) ===============

// ARTICLES
app.post('/api/education/articles', requireAuth, requireAdmin, csrfProtection, async (req, res, next) => {
  const { title, summary, minutes, tags = [], cover, href, isActive = true } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title is required' });
  try {
    const { rows } = await req.db.query(
      `INSERT INTO education_articles (title, summary, minutes, tags, cover_url, href, is_active)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, title, summary, minutes, tags, cover_url AS "cover", href, is_active AS "isActive"`,
      [title, summary || null, minutes || null, tags, cover || null, href || null, !!isActive]
    );
    res.status(201).json(rows[0]);
  } catch (e) { next(e); }
});

app.put('/api/education/articles/:id', requireAuth, requireAdmin, csrfProtection, async (req, res, next) => {
  const { id } = req.params;
  const { title, summary, minutes, tags, cover, href, isActive } = req.body || {};
  try {
    const { rows } = await req.db.query(
      `UPDATE education_articles
       SET title = COALESCE($2, title),
           summary = COALESCE($3, summary),
           minutes = COALESCE($4, minutes),
           tags = COALESCE($5, tags),
           cover_url = COALESCE($6, cover_url),
           href = COALESCE($7, href),
           is_active = COALESCE($8, is_active)
       WHERE id = $1
       RETURNING id, title, summary, minutes, tags, cover_url AS "cover", href, is_active AS "isActive"`,
      [id, title, summary, minutes, tags, cover, href, isActive]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) { next(e); }
});

app.delete('/api/education/articles/:id', requireAuth, requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const r = await req.db.query(`DELETE FROM education_articles WHERE id=$1`, [req.params.id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// VIDEOS
app.post('/api/education/videos', requireAuth, requireAdmin, csrfProtection, async (req, res, next) => {
  const { title, duration, tags = [], thumb, href, isActive = true } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title is required' });
  try {
    const { rows } = await req.db.query(
      `INSERT INTO education_videos (title, duration, tags, thumb_url, href, is_active)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, title, duration, tags, thumb_url AS "thumb", href, is_active AS "isActive"`,
      [title, duration || null, tags, thumb || null, href || null, !!isActive]
    );
    res.status(201).json(rows[0]);
  } catch (e) { next(e); }
});

app.put('/api/education/videos/:id', requireAuth, requireAdmin, csrfProtection, async (req, res, next) => {
  const { id } = req.params;
  const { title, duration, tags, thumb, href, isActive } = req.body || {};
  try {
    const { rows } = await req.db.query(
      `UPDATE education_videos
       SET title = COALESCE($2, title),
           duration = COALESCE($3, duration),
           tags = COALESCE($4, tags),
           thumb_url = COALESCE($5, thumb_url),
           href = COALESCE($6, href),
           is_active = COALESCE($7, is_active)
       WHERE id = $1
       RETURNING id, title, duration, tags, thumb_url AS "thumb", href, is_active AS "isActive"`,
      [id, title, duration, tags, thumb, href, isActive]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) { next(e); }
});

app.delete('/api/education/videos/:id', requireAuth, requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const r = await req.db.query(`DELETE FROM education_videos WHERE id=$1`, [req.params.id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// DOWNLOADS
app.post('/api/education/downloads', requireAuth, requireAdmin, csrfProtection, async (req, res, next) => {
  const { title, size, href, isActive = true } = req.body || {};
  if (!title || !href) return res.status(400).json({ error: 'title and href are required' });
  try {
    const { rows } = await req.db.query(
      `INSERT INTO education_downloads (title, file_size, href, is_active)
       VALUES ($1,$2,$3,$4)
       RETURNING id, title, file_size AS "size", href, is_active AS "isActive"`,
      [title, size || null, href, !!isActive]
    );
    res.status(201).json(rows[0]);
  } catch (e) { next(e); }
});

app.put('/api/education/downloads/:id', requireAuth, requireAdmin, csrfProtection, async (req, res, next) => {
  const { id } = req.params;
  const { title, size, href, isActive } = req.body || {};
  try {
    const { rows } = await req.db.query(
      `UPDATE education_downloads
       SET title = COALESCE($2, title),
           file_size = COALESCE($3, file_size),
           href = COALESCE($4, href),
           is_active = COALESCE($5, is_active)
       WHERE id = $1
       RETURNING id, title, file_size AS "size", href, is_active AS "isActive"`,
      [id, title, size, href, isActive]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) { next(e); }
});

app.delete('/api/education/downloads/:id', requireAuth, requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const r = await req.db.query(`DELETE FROM education_downloads WHERE id=$1`, [req.params.id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) { next(e); }
});


// ---------------- Error handlers ----------------
app.use((err, _req, res, _next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Server error', detail: err.message });
});

// ---------------- Start ----------------
app.listen(PORT, HOST, () => {
  console.log(`Server running securely on http://${HOST}:${PORT}`);
});
