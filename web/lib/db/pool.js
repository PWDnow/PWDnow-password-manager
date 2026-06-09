// web/lib/db/pool.js
import pg from 'pg';

let _pool = null;

export function getPool() {
  if (_pool) return _pool;
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error('DATABASE_URL is required for the Postgres backend');
  _pool = new pg.Pool({
    connectionString,
    max: Number(process.env.PG_POOL_MAX || 10),
    idleTimeoutMillis: 30_000,
    // TLS to managed Postgres. For self-run dev set PGSSL=disable.
    ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: process.env.PGSSL !== 'no-verify' },
  });
  return _pool;
}

export async function query(text, params) { return getPool().query(text, params); }

// Run fn inside a single transaction with one dedicated client.
export async function withTx(fn) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const r = await fn(client);
    await client.query('COMMIT');
    return r;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw e;
  } finally {
    client.release();
  }
}

export async function closePool() { if (_pool) { await _pool.end(); _pool = null; } }
