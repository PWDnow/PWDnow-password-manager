// web/tests/httpIntegration.test.js
// End-to-end HTTP test through the REAL auth+vault routes, run against both the file
// and (when DATABASE_URL is set) the Postgres backend. This is the deterministic
// substitute for the browser E2E and the proof that the P1.A refactor + the Postgres
// envelope path are behavior-equivalent for the mainline flows.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import cookieParser from 'cookie-parser';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { randomBytes } from 'crypto';

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

// Minimal cookie jar + CSRF-aware fetch wrapper.
function makeClient(base) {
  const jar = new Map();
  function cookieHeader() { return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; '); }
  function store(setCookies) {
    for (const sc of setCookies) {
      const [pair] = sc.split(';');
      const eq = pair.indexOf('=');
      const k = pair.slice(0, eq).trim();
      const v = pair.slice(eq + 1).trim();
      if (v === '' ) jar.delete(k); else jar.set(k, v);
    }
  }
  async function req(method, url, body) {
    const headers = { 'content-type': 'application/json' };
    const ck = cookieHeader();
    if (ck) headers.cookie = ck;
    const csrf = jar.get('_pwd_csrf');
    if (csrf && method !== 'GET') headers['x-csrf-token'] = csrf;
    const res = await fetch(base + url, {
      method, headers, body: body ? JSON.stringify(body) : undefined,
    });
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    if (setCookies.length) store(setCookies);
    let json = null; try { json = await res.json(); } catch { /* non-json */ }
    return { status: res.status, json, jar };
  }
  return {
    get: (u) => req('GET', u),
    post: (u, b) => req('POST', u, b),
    put: (u, b) => req('PUT', u, b),
    del: (u, b) => req('DELETE', u, b),
    jar,
  };
}

function suite(label, setupEnv) {
  describe(`HTTP integration — ${label}`, () => {
    let server, base, dataDir, initAuth, mountAuthAndVault;

    before(async () => {
      dataDir = mkdtempSync(path.join(tmpdir(), 'pwdnow-http-'));
      setupEnv(dataDir);
      // Import after env is set so module-level config reads the right values.
      ({ initAuth, mountAuthAndVault } = await import('../auth.js'));
      await initAuth({ dataDir });
      const app = express();
      app.use(express.json({ limit: '512kb' }));
      app.use(cookieParser());
      mountAuthAndVault(app);
      await new Promise((resolve) => { server = app.listen(0, '127.0.0.1', resolve); });
      base = `http://127.0.0.1:${server.address().port}`;
    });

    after(async () => {
      if (server) await new Promise((r) => server.close(r));
      // Close the Postgres pool (no-op for the file backend) so the runner can exit.
      try { const { closePool } = await import('../lib/db/pool.js'); await closePool(); } catch { /* no pool */ }
      if (dataDir) rmSync(dataDir, { recursive: true, force: true });
    });

    const email = `user_${randomBytes(4).toString('hex')}@example.com`;
    const password = 'correct-horse-battery-staple';
    const c = () => _client;
    let _client;

    it('register creates an account and sets a session', async () => {
      _client = makeClient(base);
      const r = await c().post('/api/auth/register', { email, password, firstName: 'Ada', lastName: 'Lovelace' });
      assert.equal(r.status, 200, JSON.stringify(r.json));
      assert.equal(r.json.ok, true);
      assert.ok(c().jar.get('_pwd_sess'), 'session cookie set');
      assert.ok(c().jar.get('_pwd_csrf'), 'csrf cookie set');
    });

    it('register rejects a duplicate email with 409', async () => {
      const tmp = makeClient(base);
      const r = await tmp.post('/api/auth/register', { email, password, firstName: 'X', lastName: 'Y' });
      assert.equal(r.status, 409);
    });

    it('/api/auth/me returns the authenticated profile', async () => {
      const r = await c().get('/api/auth/me');
      assert.equal(r.status, 200);
      assert.equal(r.json.authenticated, true);
      assert.equal(r.json.user.email, email);
      assert.equal(r.json.user.firstName, 'Ada');
    });

    // The vault endpoints store an opaque client-encrypted envelope {data:"<ciphertext>"}.
    const credsEnvelope = { data: 'ENVELOPE_CREDENTIALS_CIPHERTEXT' };

    it('credentials + folders CRUD round-trips (encrypted envelopes)', async () => {
      assert.equal((await c().put('/api/vault/credentials', credsEnvelope)).status, 200);
      assert.deepEqual((await c().get('/api/vault/credentials')).json, credsEnvelope);

      const folders = { data: 'ENVELOPE_FOLDERS_CIPHERTEXT' };
      assert.equal((await c().put('/api/vault/folders', folders)).status, 200);
      assert.deepEqual((await c().get('/api/vault/folders')).json, folders);
    });

    it('asset-holder round-trips', async () => {
      const ah = { data: 'ENVELOPE_ASSET_CIPHERTEXT' };
      assert.equal((await c().put('/api/vault/asset-holder', ah)).status, 200);
      assert.deepEqual((await c().get('/api/vault/asset-holder')).json, ah);
    });

    it('duress-enforce arm/disarm persists flexible user fields', async () => {
      assert.equal((await c().put('/api/vault/duress-enforce', { armed: true, maxAttempts: 3 })).status, 200);
      assert.equal((await c().del('/api/vault/duress-enforce')).status, 200);
    });

    it('sessions list returns the current session', async () => {
      const r = await c().get('/api/auth/sessions');
      assert.equal(r.status, 200);
      assert.ok(Array.isArray(r.json));
      assert.ok(r.json.length >= 1);
    });

    it('login from a fresh client succeeds and can read the vault', async () => {
      const c2 = makeClient(base);
      const r = await c2.post('/api/auth/login', { email, password });
      assert.equal(r.status, 200, JSON.stringify(r.json));
      assert.equal(r.json.ok, true);
      const creds = await c2.get('/api/vault/credentials');
      assert.deepEqual(creds.json, credsEnvelope, 'second client reads the same encrypted vault');
    });

    it('login with wrong password fails', async () => {
      const c3 = makeClient(base);
      const r = await c3.post('/api/auth/login', { email, password: 'wrong-password-here' });
      assert.equal(r.json.ok, false);
    });

    it('password change works and invalidates the old session', async () => {
      const newPassword = 'a-brand-new-very-long-password';
      const r = await c().post('/api/auth/password', { oldPassword: password, newPassword });
      assert.equal(r.status, 200, JSON.stringify(r.json));
      // Old session JTI was revoked on password change → /me should now be unauthenticated.
      const me = await c().get('/api/auth/me');
      assert.equal(me.json.authenticated, false);
      // New password logs in.
      const c4 = makeClient(base);
      const li = await c4.post('/api/auth/login', { email, password: newPassword });
      assert.equal(li.json.ok, true);
    });

    it('logout clears the session', async () => {
      const c5 = makeClient(base);
      await c5.post('/api/auth/login', { email, password: 'a-brand-new-very-long-password' });
      assert.equal((await c5.get('/api/auth/me')).json.authenticated, true);
      await c5.post('/api/auth/logout', {});
      assert.equal((await c5.get('/api/auth/me')).json.authenticated, false);
    });
  });
}

suite('file backend', (dataDir) => {
  process.env.VAULT_BACKEND = 'file';
  delete process.env.DATABASE_URL;
});

if (process.env.PG_TEST_URL) {
  suite('postgres backend', (dataDir) => {
    process.env.VAULT_BACKEND = 'postgres';
    process.env.KMS_PROVIDER = 'local';
    process.env.LOCAL_KMS_KEY = process.env.LOCAL_KMS_KEY || randomBytes(32).toString('hex');
    process.env.DATABASE_URL = process.env.PG_TEST_URL;
    process.env.PGSSL = 'disable';
  });
}
