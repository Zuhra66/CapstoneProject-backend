// routes/events.js
const express = require("express");
const router = express.Router();
const { pool } = require("../db");

// Public Events API
// Base path: /api/events

// GET /api/events – list published events
router.get("/", async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `
      SELECT
        id,
        title,
        description,
        category,
        location,
        start_at   AS "startTime",
        end_at     AS "endTime",
        image_url  AS "imageUrl",
        is_published AS "isPublished"
      FROM events
      WHERE is_published = TRUE
      ORDER BY start_at ASC
      `
    );

    // Only published events will be returned anyway,
    // but we keep isPublished in case the frontend wants it.
    res.json({ events: rows });
  } catch (err) {
    console.error("Error fetching events:", err);
    res.status(500).json({ error: "Failed to load events" });
  }
});

// GET /api/events/:id – single published event
router.get("/:id", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `
      SELECT
        id,
        title,
        description,
        category,
        location,
        start_at   AS "startTime",
        end_at     AS "endTime",
        image_url  AS "imageUrl",
        is_published AS "isPublished"
      FROM events
      WHERE id = $1
      `,
      [req.params.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Event not found" });
    }

    const event = rows[0];

    // Only expose published events on the public API
    if (!event.isPublished) {
      return res.status(404).json({ error: "Event not found" });
    }

    res.json({ event });
  } catch (err) {
    console.error("Error fetching event by id:", err);
    res.status(500).json({ error: "Failed to load event" });
  }
});

module.exports = router;
