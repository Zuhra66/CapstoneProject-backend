// routes/catalog.js - CORRECT SINGLE VERSION
const express = require('express');
const router = express.Router();

const { pool: dbPool } = require('../db');

/**
 * Helper to safely convert values to int
 */
function toInt(v, fallback = null) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Normalize text search
 */
function normalizeLike(s) {
  if (!s) return null;
  return `%${String(s).trim().toLowerCase()}%`;
}

/* ------------------------------------------------------------------
 * CATEGORIES
 *  GET /api/categories
 * ------------------------------------------------------------------ */
router.get('/categories', async (_req, res) => {
  try {
    const { rows } = await dbPool.query(
        `
        SELECT id, name, slug, description
        FROM public.categories
        ORDER BY name ASC
      `,
    );

    // Frontend (AdminProducts & Products) can handle either
    // { categories: [...] } or just array, so we return object.
    res.json({ categories: rows });
  } catch (err) {
    console.error('GET /api/categories error:', err);
    res.status(500).json({ error: 'Failed to load categories' });
  }
});

/* ------------------------------------------------------------------
 * PRODUCTS (public storefront)
 *  GET /api/products
 *  Query params:
 *    q        - text search on name/tags
 *    category - category slug or name
 * ------------------------------------------------------------------ */
router.get('/products', async (req, res) => {
  try {
    const { q = '', category = '' } = req.query;

    const where = ['COALESCE(p.is_active, TRUE) = TRUE'];
    const params = [];
    let i = 0;

    // Text search on name + tags
    const like = normalizeLike(q);
    if (like) {
      i++;
      params.push(like);
      where.push(
          `(LOWER(p.name) LIKE $${i} OR EXISTS (
          SELECT 1
          FROM unnest(COALESCE(p.tags, '{}'::text[])) AS t
          WHERE LOWER(t) LIKE $${i}
        ))`,
      );
    }

    // Filter by category (slug or name)
    if (category && category !== 'all') {
      i++;
      params.push(category.toLowerCase());
      where.push(
          `(LOWER(c.slug) = $${i} OR LOWER(c.name) = $${i})`,
      );
    }

    const sql = `
      SELECT
        p.id,
        p.name,
        p.slug,
        p.price,              -- dollars (numeric)
        p.price_cents,        -- legacy safety
        p.image_url,
        p.external_url,
        p.tags,
        json_build_object(
          'id', c.id,
          'name', c.name,
          'slug', c.slug
        ) AS category
      FROM public.products p
      LEFT JOIN public.categories c ON c.id = p.category_id
      WHERE ${where.join(' AND ')}
      ORDER BY p.id DESC
    `;

    const { rows } = await dbPool.query(sql, params);

    // Products.jsx expects a flat array of products
    res.json(rows);
  } catch (err) {
    console.error('GET /api/products error:', err);
    res.status(500).json({ error: 'Failed to load products' });
  }
});

/* ------------------------------------------------------------------
 * EDUCATION (public)
 *  GET /api/education
 *  Query params:
 *    q   - text search
 *    tag - filter on tags[]
 *
 *  Uses tables:
 *    education_articles(id, title, summary, minutes, tags, cover_url, href, is_active)
 *    education_videos(id, title, duration, tags, thumb_url, href, is_active)
 *    education_downloads(id, title, file_size, href, is_active)
 * ------------------------------------------------------------------ */
router.get('/education', async (req, res) => {
  try {
    const { q = '', tag = '' } = req.query;

    const like = normalizeLike(q);
    const tagVal = tag && tag !== 'All' ? tag : '';

    // -------- Articles --------
    const articleWhere = ['ea.is_active = TRUE'];
    const articleParams = [];
    let ia = 0;

    if (like) {
      ia++;
      articleParams.push(like);
      articleWhere.push(
          `(LOWER(ea.title) LIKE $${ia} OR LOWER(ea.summary) LIKE $${ia})`,
      );
    }

    if (tagVal) {
      ia++;
      articleParams.push(tagVal);
      articleWhere.push(`$${ia} = ANY(ea.tags)`);
    }

    const articlesSql = `
      SELECT
        ea.id,
        ea.title,
        ea.summary,
        ea.minutes,
        ea.tags,
        ea.cover_url,
        ea.href
      FROM public.education_articles ea
      WHERE ${articleWhere.join(' AND ')}
      ORDER BY ea.created_at DESC
    `;

    // -------- Videos --------
    const videoWhere = ['ev.is_active = TRUE'];
    const videoParams = [];
    let iv = 0;

    if (like) {
      iv++;
      videoParams.push(like);
      videoWhere.push(
          `(LOWER(ev.title) LIKE $${iv})`,
      );
    }

    if (tagVal) {
      iv++;
      videoParams.push(tagVal);
      videoWhere.push(`$${iv} = ANY(ev.tags)`);
    }

    const videosSql = `
      SELECT
        ev.id,
        ev.title,
        ev.duration,
        ev.tags,
        ev.thumb_url,
        ev.href
      FROM public.education_videos ev
      WHERE ${videoWhere.join(' AND ')}
      ORDER BY ev.created_at DESC
    `;

    // -------- Downloads --------
    const downloadsSql = `
      SELECT
        ed.id,
        ed.title,
        ed.file_size,
        ed.href
      FROM public.education_downloads ed
      WHERE ed.is_active = TRUE
      ORDER BY ed.created_at DESC
    `;

    const [articlesResult, videosResult, downloadsResult] = await Promise.all([
      dbPool.query(articlesSql, articleParams),
      dbPool.query(videosSql, videoParams),
      dbPool.query(downloadsSql),
    ]);

    res.json({
      articles: articlesResult.rows,
      videos: videosResult.rows,
      downloads: downloadsResult.rows,
    });
  } catch (err) {
    console.error('GET /api/education error:', err);
    res.status(500).json({ error: 'Failed to load education content' });
  }
});

module.exports = router;