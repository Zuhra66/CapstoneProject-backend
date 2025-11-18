// routes/products.js
const express = require("express");
const router = express.Router();
const pool = require("../db");

// GET /api/categories  -> [{id, name, slug}]
router.get("/categories", async (_req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, slug
       FROM categories
       ORDER BY name ASC`
    );
    res.json(rows);
  } catch (e) { next(e); }
});

// GET /api/products  -> list products with badges (tags)
router.get("/products", async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT p.id,
              p.name,
              p.slug,
              p.price_cents,
              (p.price_cents::numeric / 100.0) AS price,
              p.image_url    AS image,
              p.external_url AS externalurl,
              c.name         AS category,
              COALESCE(ARRAY_AGG(t.name ORDER BY t.name)
                       FILTER (WHERE t.name IS NOT NULL), '{}') AS badges
       FROM products p
       LEFT JOIN categories c   ON c.id = p.category_id
       LEFT JOIN product_tags pt ON pt.product_id = p.id
       LEFT JOIN tags t          ON t.id = pt.tag_id
       WHERE p.is_active = TRUE
       GROUP BY p.id, c.name
       ORDER BY p.created_at DESC`
    );
    res.json(rows);
  } catch (e) { next(e); }
});

module.exports = router;
