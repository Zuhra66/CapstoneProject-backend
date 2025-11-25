// db.js
import pkg from 'pg';
const { Pool } = pkg;

const isRender = /render\.com/.test(process.env.DATABASE_URL || '');

// Always enable SSL in production (Render, etc.). Locally you can leave it off.
const useSSL =
  process.env.NODE_ENV === 'Production'
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

// optional: quick ping at startup
export async function pingDB() {
  const r = await pool.query('select 1 as ok');
  return r.rows[0].ok === 1;
}
