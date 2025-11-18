// db.js
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,   // set this in .env
  // Render/railway often require SSL:
  ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : false,
});

async function healthCheck() {
  await pool.query('SELECT 1');
  return true;
}

module.exports = { pool, healthCheck };
