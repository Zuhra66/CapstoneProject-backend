// routes/events.js
const express = require('express');
const router = express.Router();
const { pool } = require('../db');

// GET /api/events
router.get('/', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         id,
         title,
         description,
         category,
         location,
         start_at,
         end_time,
         is_published
       FROM events
       WHERE is_published = TRUE
       ORDER BY start_at ASC`
    );

    res.json({ events: rows });
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).json({ error: 'Failed to load events' });
  }
});

// GET /api/events/:id
router.get('/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         id,
         title,
         description,
         category,
         location,
         start_at,
         end_time,
         is_published
       FROM events
       WHERE id = $1`,
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }

    const event = rows[0];

    if (!event.is_published) {
      return res.status(404).json({ error: 'Event not found' });
    }

    res.json({ event });
  } catch (err) {
    console.error('Error fetching event by id:', err);
    res.status(500).json({ error: 'Failed to load event' });
  }
});

module.exports = router;
