// routes/blog.js
const express = require("express");
const router = express.Router();
const { pool } = require("../db");

// GET /api/blog  -> list published blog posts
router.get("/", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `
      SELECT
        id,
        title,
        slug,
        content_md,
        status,
        published_at,
        created_at,
        updated_at
      FROM blog_posts
      WHERE status = 'published'
      ORDER BY published_at DESC NULLS LAST, created_at DESC
      `
    );

    // Shape data for frontend
    const posts = rows.map((row) => ({
      id: row.id,
      title: row.title,
      slug: row.slug,
      publishedAt: row.published_at,
      // simple preview – first ~220 chars
      preview: row.content_md ? row.content_md.slice(0, 220) : "",
    }));

    res.json({ posts });
  } catch (err) {
    console.error("Blog list error:", err);
    res.status(500).json({ error: "Failed to load blog posts" });
  }
});

// OPTIONAL: Blog post detail by slug
router.get("/:slug", async (req, res) => {
  try {
    const { slug } = req.params;

    const { rows } = await pool.query(
      `
      SELECT
        id,
        title,
        slug,
        content_md,
        status,
        published_at,
        created_at,
        updated_at
      FROM blog_posts
      WHERE slug = $1
        AND status = 'published'
      LIMIT 1
      `,
      [slug]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Post not found" });
    }

    const row = rows[0];

    res.json({
      id: row.id,
      title: row.title,
      slug: row.slug,
      publishedAt: row.published_at,
      contentMd: row.content_md,
    });
  } catch (err) {
    console.error("Blog detail error:", err);
    res.status(500).json({ error: "Failed to load blog post" });
  }
});

module.exports = router;
