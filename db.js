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

// SSL config: on in production (Render, etc.), off locally
const useSSL = isProd ? { rejectUnauthorized: false } : false;

// Create the pool
const pool = new Pool({
  connectionString,
  ssl: useSSL,
  // These options help with remote DBs that drop idle connections
  keepAlive: true,
  idleTimeoutMillis: 30000,        // close idle clients after 30s
  connectionTimeoutMillis: 10000,  // fail if connection takes >10s
  max: 5,                          // small pool is usually enough
});

// Optional: basic event logging for debugging pool issues
pool.on('error', (err) => {
  console.error('Unexpected PG pool error:', err);
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
