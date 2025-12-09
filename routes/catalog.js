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

        COALESCE(name, '')                                 AS name,

        COALESCE(name, '') AS name,

        LOWER(REPLACE(COALESCE(slug, name, ''), ' ', '-')) AS slug
      FROM public.categories
      ORDER BY name ASC, id ASC
    `);
    res.json(rows ?? []);
  } catch (e) {
    console.error('Categories route error:', e);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

/* -------------------- PRODUCTS (public catalog, dollars) -------------------- */
// GET /api/products
router.get('/products', async (req, res) => {
  try {

    const { q = '', category = '' } = req.query;

    const qRaw = (req.query.q || '').toString().trim();
    const catRaw = (req.query.category || '').toString().trim().toLowerCase();

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 60, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);


    const where = ['COALESCE(p.is_active, TRUE) = TRUE'];
    const params = [];

    let i = 0;

    if (q) {
      i++;
      params.push(`%${q}%`);
      where.push(`(p.name ILIKE $${i} OR p.slug ILIKE $${i})`);
    }

    if (category) {
      i++;
      params.push(category.toLowerCase());
      where.push(`LOWER(c.slug) = $${i}`);

    const where = ['COALESCE(p.is_active, TRUE) = TRUE'];

    if (qRaw) {
      params.push(`%${qRaw}%`);
      where.push(`(p.name ILIKE $${params.length})`);
    }

    if (catRaw && catRaw !== 'all') {
      params.push(catRaw);
      where.push(`LOWER(COALESCE(c.slug, REPLACE(c.name, ' ', '-'))) = $${params.length}`);

    }

    const sql = `
      SELECT
        p.id,
        p.name,
        p.slug,

        p.price AS price,                     -- dollars in DB
        (p.price * 100)::int AS price_cents,  -- optional computed cents

        ROUND(COALESCE(p.price, 0) * 100)::INTEGER as price_cents,

        p.image_url,
        p.external_url,
        p.category_id,
        COALESCE(p.is_active, TRUE) AS is_active,

        json_build_object('name', c.name, 'slug', c.slug) AS category

        json_build_object(
          'name', COALESCE(c.name, 'Uncategorized'),
          'slug', LOWER(REPLACE(COALESCE(c.slug, COALESCE(c.name, 'uncategorized'), ''), ' ', '-'))
        ) AS category

      FROM public.products p
      LEFT JOIN public.categories c ON c.id = p.category_id
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY p.id ASC
    `;

    const { rows } = await pool.query(sql, params);
    res.json(rows ?? []);

  } catch (err) {
    console.error('products route error:', err);
    res.status(500).json({ error: 'Failed to load products' });

  } catch (e) {
    console.error('Products route error:', e);
    res.status(500).json({ error: 'Failed to fetch products' });

  }
});

module.exports = router;