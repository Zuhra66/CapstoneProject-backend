// routes/events.js
const express = require('express');
const router = express.Router();
const { pool } = require('../db');

/**
 * GET /api/events
 * Public list of events (default: only published)
 */
router.get('/', async (req, res) => {
  try {
    const { status = 'published' } = req.query;
    let whereClause = 'WHERE is_published = TRUE';

    if (status === 'all') {
      whereClause = 'WHERE TRUE';
    } else if (status === 'draft') {
      whereClause = 'WHERE is_published = FALSE';
    }

    const { rows } = await pool.query(
      `
      SELECT
        id,
        title,
        description,
        location,
        start_at   AS "startTime",
        end_at     AS "endTime",
        image_url  AS "imageUrl",
        is_published
      FROM public.events
      ${whereClause}
      ORDER BY start_at ASC
      `
    );

    res.json(rows);
  } catch (err) {
    console.error('Public events list error:', err);
    res.status(500).json({ error: 'Failed to load events.' });
  }
});

/**
 * GET /api/events/:id
 * Simple detail endpoint (by numeric ID)
 */
router.get('/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!id) {
    return res.status(400).json({ error: 'Invalid event ID' });
  }

  try {
    const { rows } = await pool.query(
      `
      SELECT
        id,
        title,
        description,
        location,
        start_at   AS "startTime",
        end_at     AS "endTime",
        image_url  AS "imageUrl",
        is_published
      FROM public.events
      WHERE id = $1
      `,
      [id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'Event not found' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Public event detail error:', err);
    res.status(500).json({ error: 'Failed to load event.' });
  }
});

module.exports = router;
