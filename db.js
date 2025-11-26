// db.js
const { Pool } = require('pg');

const isProd = process.env.NODE_ENV === 'production';

// Build the connection string
// Prefer DATABASE_URL (e.g., Render), or fall back to PG* vars for local dev
const connectionString =
  process.env.DATABASE_URL ||
  process.env.PG_CONNECTION_STRING ||
  `postgresql://${process.env.PGUSER || 'postgres'}:${process.env.PGPASSWORD || ''}` +
  `@${process.env.PGHOST || 'localhost'}:${process.env.PGPORT || 5432}/` +
  `${process.env.PGDATABASE || 'empowermed'}`;

// Create the pool
const pool = new Pool({
  connectionString,
  ssl: isProd ? { rejectUnauthorized: false } : false,
  keepAlive: true,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  max: 10,
});

// Health check used by /health/db
async function healthCheck() {
  try {
    const r = await pool.query('SELECT 1 AS ok');
    return r.rows[0].ok === 1;
  } catch (err) {
    console.error('DB health check failed:', err.message);
    return false;
  }
}

module.exports = {
  pool,
  healthCheck,
};
