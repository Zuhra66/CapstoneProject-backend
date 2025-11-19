// routes/catalog.js
const router = require('express').Router();
const { pool } = require('../db');

/* -------------------- CATEGORIES -------------------- */
// GET /api/categories
router.get('/categories', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        id,
        COALESCE(name, slug)            AS name,
        LOWER(COALESCE(slug, name))     AS slug
      FROM public.categories
      WHERE COALESCE(is_active, TRUE) = TRUE
      ORDER BY name ASC
    `);
    res.json(rows ?? []);
  } catch (e) {
    console.error('categories route error:', e);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

/* ---------------------- PRODUCTS --------------------- */
// GET /api/products?q=&category=&limit=&offset=
router.get('/products', async (req, res) => {
  try {
    const qRaw   = (req.query.q || '').toString();
    const catRaw = (req.query.category || '').toString();
    const q      = qRaw.trim();
    const cat    = catRaw.trim().toLowerCase();

    // pagination (optional)
    const limit  = Math.min(Math.max(parseInt(req.query.limit, 10) || 60, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    // Build WHERE with parameters
    const params = [];
    const where = [];

    // only active products by default
    where.push(`COALESCE(p.is_active, TRUE) = TRUE`);

    if (q) {
      params.push(`%${q}%`);
      // search in name and tags (if tags is text[])
      where.push(`(p.name ILIKE $${params.length} OR EXISTS (
        SELECT 1 FROM unnest(COALESCE(p.tags, ARRAY[]::text[])) t WHERE t ILIKE $${params.length}
      ))`);
    }

    if (cat && cat !== 'all') {
      params.push(cat);
      // match by slug or name, case-insensitive
      where.push(`(
        LOWER(c.slug) = $${params.length} OR LOWER(c.name) = $${params.length}
      )`);
    }

    params.push(limit);
    params.push(offset);

    const sql = `
      SELECT
        p.id,
        p.name,
        p.slug,
        p.price_cents,
        p.image_url,
        p.external_url,
        COALESCE(p.tags, ARRAY[]::text[])                     AS tags,
        COALESCE(p.is_active, TRUE)                           AS is_active,
        json_build_object('name', c.name, 'slug', LOWER(c.slug)) AS category,
        p.created_at
      FROM public.products p
      LEFT JOIN public.categories c ON c.id = p.category_id
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY p.created_at DESC NULLS LAST, p.id ASC
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `;

    const { rows } = await pool.query(sql, params);
    res.json(rows ?? []);
  } catch (e) {
    console.error('products route error:', e);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

module.exports = router;
