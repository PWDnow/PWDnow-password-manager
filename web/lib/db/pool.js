// web/lib/db/pool.js
import pg from 'pg';
import { pgQueryDuration } from '../metrics.js';

let _pool = null;

// TLS 1.3 + AES-256-GCM only (CNSA 2.0). Group preference tries hybrid ML-KEM first
// (matching the daemon's own PQC-L5 KEM choice), falling back to classical ECDHE since
// no Postgres provider negotiates a PQC group yet — safe because rows are already
// envelope-ciphertext before they reach this connection.
const PG_TLS_OPTIONS = {
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
  ciphers: 'TLS_AES_256_GCM_SHA384',
  ecdhCurve: 'SecP384r1MLKEM1024:X25519MLKEM768:secp384r1:X25519',
};

export function getPool() {
  if (_pool) return _pool;
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error('DATABASE_URL is required for the Postgres backend');
  _pool = new pg.Pool({
    connectionString,
    max: Number(process.env.PG_POOL_MAX || 10),
    idleTimeoutMillis: 30_000,
    // TLS to managed Postgres. For self-run dev with no TLS at all, set PGSSL=disable.
    ssl: process.env.PGSSL === 'disable'
      ? false
      : { ...PG_TLS_OPTIONS, rejectUnauthorized: process.env.PGSSL !== 'no-verify' },
  });
  return _pool;
}

// `shape` labels the query-duration histogram: 'point_read' | 'write' | 'unspecified'.
export async function query(text, params, shape = 'unspecified') {
  const start = process.hrtime.bigint();
  try {
    return await getPool().query(text, params);
  } finally {
    pgQueryDuration.labels(shape).observe(Number(process.hrtime.bigint() - start) / 1e9);
  }
}

// Run fn inside a single transaction with one dedicated client. `shape` defaults to
// 'rmw_tx' since every current caller is a row-locked read-modify-write.
export async function withTx(fn, shape = 'rmw_tx') {
  const start = process.hrtime.bigint();
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
    pgQueryDuration.labels(shape).observe(Number(process.hrtime.bigint() - start) / 1e9);
  }
}

export async function closePool() { if (_pool) { await _pool.end(); _pool = null; } }
