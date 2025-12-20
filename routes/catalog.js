const express = require('express');
const router = express.Router();
const { pool } = require('../db');

router.get('/categories', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        id,
        COALESCE(name, '') AS name,
        LOWER(REPLACE(COALESCE(slug, name, ''), ' ', '-')) AS slug
      FROM public.categories
      ORDER BY name ASC, id ASC
    `);
    res.json(rows ?? []);
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

router.get('/products', async (req, res) => {
  try {
    const qRaw = (req.query.q || '').toString().trim();
    const catRaw = (req.query.category || '').toString().trim().toLowerCase();

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 60, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    const params = [];
    const where = ['COALESCE(p.is_active, TRUE) = TRUE'];

    if (qRaw) {
      params.push(`%${qRaw}%`);
      where.push(`(p.name ILIKE $${params.length})`);
    }

    if (catRaw && catRaw !== 'all') {
      params.push(catRaw);
      where.push(`LOWER(COALESCE(c.slug, REPLACE(c.name, ' ', '-'))) = $${params.length}`);
    }

    params.push(limit);
    params.push(offset);

    const sql = `
      SELECT
        p.id,
        p.name,
        p.slug,
        ROUND(COALESCE(p.price, 0) * 100)::INTEGER as price_cents,
        p.image_url,
        p.external_url,
        COALESCE(p.is_active, TRUE) AS is_active,
        json_build_object(
          'name', COALESCE(c.name, 'Uncategorized'),
          'slug', LOWER(REPLACE(COALESCE(c.slug, COALESCE(c.name, 'uncategorized'), ''), ' ', '-'))
        ) AS category
      FROM public.products p
      LEFT JOIN public.categories c ON c.id = p.category_id
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY p.id ASC
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `;

    const { rows } = await pool.query(sql, params);
    res.json(rows ?? []);
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

module.exports = router;