// db.js
import pkg from 'pg';
const { Pool } = pkg;

const isRender = /render\.com/.test(process.env.DATABASE_URL || '');

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isRender ? { rejectUnauthorized: false } : false,
});

// optional: quick ping at startup
export async function pingDB() {
  const r = await pool.query('select 1 as ok');
  return r.rows[0].ok === 1;
}
