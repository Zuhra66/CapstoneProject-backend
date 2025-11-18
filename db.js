// db.js
const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;

// Always enable SSL in production (Render, etc.). Locally you can leave it off.
const useSSL =
  process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false;

const pool = new Pool({
  connectionString,
  ssl: useSSL,
  // optional but helpful:
  keepAlive: true,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  max: 10,
});

async function healthCheck() {
  await pool.query('SELECT 1');
  return true;
}

module.exports = { pool, healthCheck };
