// routes/education.js
const express = require('express');
const router = express.Router();
const { pool } = require('../db');

// ---------- helpers ----------
function normalizePath(p, fallback = null) {
  if (!p) return fallback;
  const s = String(p).trim();
  if (!s) return fallback;
  // Allow absolute http(s) or site-relative (/images/...)
  if (s.startsWith('http://') || s.startsWith('https://') || s.startsWith('/')) return s;
  // Treat anything else as a site-relative file under /images/
  return `/images/${s.replace(/^\/+/, '')}`;
}

// routes/education.js

function shapeArticle(r) {
  return {
    id: r.id,
    title: r.title,
    summary: r.summary || "",
    minutes: r.minutes ?? 3,
    tags: r.tags || [],
    // 🔧 use cover_url as the key the frontend expects
    cover_url: normalizePath(
      r.cover_url || r.cover,
      "/images/edu/iv-therapy.jpg"
    ),
    href: r.href || null,
    is_active: r.is_active,
    created_at: r.created_at,
  };
}

function shapeVideo(r) {
  return {
    id: r.id,
    title: r.title,
    duration: r.duration || "",
    tags: r.tags || [],
    // 🔧 use thumb_url as the key the frontend expects
    thumb_url: normalizePath(
      r.thumb_url || r.thumb,
      "/images/edu/iv-therapy.jpg"
    ),
    href: r.href || null,
    is_active: r.is_active,
    created_at: r.created_at,
  };
}

function shapeDownload(r) {
  return {
    id: r.id,
    title: r.title,
    size: r.file_size || r.size || '',
    href: r.href,
    isActive: r.is_active,
    createdAt: r.created_at,
  };
}

// Build WHERE + params for a table.
// opts = { hasSummary: boolean }
function buildWhere({ q, tag, hasSummary }) {
  const likeQ = q ? `%${q.toLowerCase()}%` : null;
  const tagQ  = tag && tag !== 'All' ? tag : null;

  const where = ['is_active = TRUE'];
  const params = [];

  if (likeQ) {
    params.push(likeQ);
    const idx = `$${params.length}`;
    // title LIKE q OR (summary LIKE q if present)
    if (hasSummary) {
      where.push(`(LOWER(title) LIKE ${idx} OR LOWER(COALESCE(summary,'')) LIKE ${idx})`);
    } else {
      where.push(`LOWER(title) LIKE ${idx}`);
    }
  }

  if (tagQ) {
    params.push(tagQ);
    const idx = `$${params.length}`;
    // tags is TEXT[]; match if tag is present
    where.push(`${idx} = ANY(COALESCE(tags, '{}'))`);
  }

  return {
    sql: where.length ? `WHERE ${where.join(' AND ')}` : '',
    params,
  };
}

// GET /api/education?q=...&tag=...
router.get('/', async (req, res) => {
  const qRaw = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  const tagRaw = typeof req.query.tag === 'string' ? req.query.tag.trim() : '';

  const whereArticles = buildWhere({ q: qRaw, tag: tagRaw, hasSummary: true });
  const whereVideos   = buildWhere({ q: qRaw, tag: tagRaw, hasSummary: false });
  const whereDl       = buildWhere({ q: qRaw, tag: tagRaw, hasSummary: false });

  try {
    const client = await pool.connect();
    try {
      const [articles, videos, downloads] = await Promise.all([
        client.query(
          `
          SELECT id, title, summary, minutes, COALESCE(tags,'{}') AS tags,
                 cover_url, href, is_active, created_at
          FROM education_articles
          ${whereArticles.sql}
          ORDER BY created_at DESC
          LIMIT 24
          `,
          whereArticles.params
        ),
        client.query(
          `
          SELECT id, title, duration, COALESCE(tags,'{}') AS tags,
                 thumb_url, href, is_active, created_at
          FROM education_videos
          ${whereVideos.sql}
          ORDER BY created_at DESC
          LIMIT 24
          `,
          whereVideos.params
        ),
        client.query(
          `
          SELECT id, title, file_size, href, is_active, created_at
          FROM education_downloads
          ${whereDl.sql}
          ORDER BY created_at DESC
          LIMIT 24
          `,
          whereDl.params
        ),
      ]);

      res.json({
        articles:  articles.rows.map(shapeArticle),
        videos:    videos.rows.map(shapeVideo),
        downloads: downloads.rows.map(shapeDownload),
      });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('GET /api/education failed:', err);
    res.status(500).json({ error: 'Education query failed' });
  }
});

module.exports = router;
