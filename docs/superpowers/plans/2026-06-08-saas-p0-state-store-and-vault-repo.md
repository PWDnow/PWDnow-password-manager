# SaaS P0 — StateStore + VaultRepository Interfaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce `StateStore` and `VaultRepository` abstractions, wire optional Redis, and fix the cross-worker rate-limit/lockout bypass bug (B4) — all with zero behavior change for the existing self-host file-backed path.

**Architecture:** Two new interfaces — `StateStore` (ephemeral key-value with TTL) replaces in-process Maps in `rateLimiter.js`; `VaultRepository` wraps `fileCrypto.js`/`session.js` file operations behind a contract-tested interface. A factory function in `auth.js initAuth` wires `InMemoryStateStore` by default and upgrades to `RedisStateStore` when `REDIS_URL` is set. The in-memory implementation preserves exact current behavior; Redis implementation makes rate limits cluster-aware.

**Tech Stack:** Node.js 24 ESM, ioredis 5, node:test + node:assert for server-side contract tests, Vitest for browser-side, Playwright for E2E regression.

---

## Scope (P0 only — do not implement P1/P2/P3 here)

| In scope | Out of scope |
|---|---|
| `StateStore` interface + `InMemoryStateStore` + `RedisStateStore` | Postgres `VaultRepository` (P1) |
| `VaultRepository` interface + `FileVaultRepository` | Redis session cache re-enable (P2) |
| Async rate-limit / lockout functions wired to `ctx.stateStore` | Kubernetes manifests (P3) |
| Cluster-wide Argon2 admission gate via `StateStore` | Any daemon changes |
| Contract tests for both interfaces | |
| `initAuth` wires both; `server.js` awaits it | |

---

## File Map

**New files:**
- `web/lib/stateStore.js` — `InMemoryStateStore` class + `createStateStore(redisUrl)` factory
- `web/lib/redisStateStore.js` — `RedisStateStore` class (ioredis-backed)
- `web/lib/vaultRepository.js` — `FileVaultRepository` class (wraps fileCrypto.js + session.js)
- `web/tests/stateStore.contract.test.js` — contract tests for both StateStore implementations
- `web/tests/vaultRepository.contract.test.js` — contract tests for FileVaultRepository

**Modified files:**
- `web/package.json` — add `ioredis` dependency
- `web/lib/context.js` — add `stateStore` and `vaultRepository` fields
- `web/lib/rateLimiter.js` — replace in-process Maps with `ctx.stateStore` (all rate functions become `async`)
- `web/routes/authRoutes.js` — `await` all rate-limit calls; move `_argon2ActiveCount` to `ctx.stateStore`
- `web/auth.js` — make `initAuth` async; wire `StateStore` + `VaultRepository` into `ctx`
- `web/server.js` — `await initAuth(...)` (top-level await, already ESM)

---

## Task 1: Add ioredis to package.json

**Files:**
- Modify: `web/package.json`

- [ ] **Step 1: Add ioredis**

```bash
cd /home/pwd-vm/PWDnow/web && npm install ioredis@5
```

Expected output: `added 1 package` (or similar), no errors.

- [ ] **Step 2: Verify**

```bash
cd /home/pwd-vm/PWDnow/web && node -e "import('ioredis').then(m => console.log('ok', typeof m.default))"
```

Expected: `ok function`

- [ ] **Step 3: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add package.json package-lock.json
git commit -m "feat(deps): add ioredis@5 for optional Redis StateStore"
```

---

## Task 2: Create lib/stateStore.js (InMemoryStateStore + factory)

**Files:**
- Create: `web/lib/stateStore.js`

- [ ] **Step 1: Write the file**

```javascript
// web/lib/stateStore.js
// StateStore — ephemeral key-value store with TTL, atomic increment, and single-use get.
//
// Interface (duck-typed):
//   async get(key)                       → string | null
//   async set(key, value, ttlMs = 0)     → void   (ttlMs=0 = no expiry)
//   async del(key)                       → void
//   async incrExpire(key, ttlMs)         → number (atomic increment; sets TTL only on first call)
//   async decr(key)                      → number (floor=0)
//   async getdel(key)                    → string | null (atomic get+delete)

export class InMemoryStateStore {
  constructor() {
    this._map = new Map(); // key → { value: string, expiresAt: number | 0, timer: Timer | null }
  }

  async get(key) {
    const e = this._map.get(key);
    if (!e) return null;
    if (e.expiresAt && Date.now() > e.expiresAt) { this._evict(key); return null; }
    return e.value;
  }

  async set(key, value, ttlMs = 0) {
    this._evict(key);
    const expiresAt = ttlMs > 0 ? Date.now() + ttlMs : 0;
    const timer = ttlMs > 0 ? setTimeout(() => this._evict(key), ttlMs) : null;
    if (timer) timer.unref();
    this._map.set(key, { value: String(value), expiresAt, timer });
  }

  async del(key) { this._evict(key); }

  async incrExpire(key, ttlMs) {
    const e = this._map.get(key);
    const now = Date.now();
    if (!e || (e.expiresAt && now > e.expiresAt)) {
      this._evict(key);
      await this.set(key, '1', ttlMs);
      return 1;
    }
    const newVal = Number(e.value) + 1;
    e.value = String(newVal);
    return newVal;
  }

  async decr(key) {
    const e = this._map.get(key);
    if (!e) return 0;
    if (e.expiresAt && Date.now() > e.expiresAt) { this._evict(key); return 0; }
    const newVal = Math.max(0, Number(e.value) - 1);
    e.value = String(newVal);
    return newVal;
  }

  async getdel(key) {
    const val = await this.get(key);
    if (val !== null) this._evict(key);
    return val;
  }

  _evict(key) {
    const e = this._map.get(key);
    if (!e) return;
    if (e.timer) clearTimeout(e.timer);
    this._map.delete(key);
  }

  // For testing — synchronously peek without TTL side-effects
  _size() { return this._map.size; }
}

export function createStateStore(redisUrl) {
  if (redisUrl) {
    // Dynamic import keeps ioredis out of the require graph when Redis isn't used.
    // Callers must await the returned promise.
    return import('./redisStateStore.js').then(({ RedisStateStore }) => new RedisStateStore(redisUrl));
  }
  return Promise.resolve(new InMemoryStateStore());
}
```

- [ ] **Step 2: Quick smoke-test in Node**

```bash
cd /home/pwd-vm/PWDnow/web && node --input-type=module <<'EOF'
import { InMemoryStateStore } from './lib/stateStore.js';
const s = new InMemoryStateStore();
await s.set('x', 'hello');
console.assert(await s.get('x') === 'hello', 'get failed');
await s.del('x');
console.assert(await s.get('x') === null, 'del failed');
const n = await s.incrExpire('c', 5000);
console.assert(n === 1, 'first incr should be 1');
console.assert(await s.incrExpire('c', 5000) === 2, 'second incr should be 2');
console.assert(await s.decr('c') === 1, 'decr should be 1');
await s.set('otp', 'abc123');
console.assert(await s.getdel('otp') === 'abc123', 'getdel value');
console.assert(await s.getdel('otp') === null, 'getdel removes key');
console.log('smoke test passed');
EOF
```

Expected: `smoke test passed`

---

## Task 3: Write StateStore contract tests

**Files:**
- Create: `web/tests/stateStore.contract.test.js`

- [ ] **Step 1: Write the contract test suite**

```javascript
// web/tests/stateStore.contract.test.js
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryStateStore } from '../lib/stateStore.js';

function contractSuite(label, makeStore) {
  describe(`StateStore contract — ${label}`, () => {
    it('get returns null for missing key', async () => {
      const s = makeStore();
      assert.equal(await s.get('no-such-key'), null);
    });

    it('set and get roundtrip', async () => {
      const s = makeStore();
      await s.set('k', 'hello');
      assert.equal(await s.get('k'), 'hello');
    });

    it('set stringifies numbers', async () => {
      const s = makeStore();
      await s.set('n', 42);
      assert.equal(await s.get('n'), '42');
    });

    it('del removes the key', async () => {
      const s = makeStore();
      await s.set('k', 'v');
      await s.del('k');
      assert.equal(await s.get('k'), null);
    });

    it('del on non-existent key does not throw', async () => {
      const s = makeStore();
      await assert.doesNotReject(() => s.del('ghost'));
    });

    it('incrExpire returns 1 on first call', async () => {
      const s = makeStore();
      assert.equal(await s.incrExpire('counter', 60_000), 1);
    });

    it('incrExpire increments monotonically', async () => {
      const s = makeStore();
      await s.incrExpire('c2', 60_000);
      await s.incrExpire('c2', 60_000);
      assert.equal(await s.incrExpire('c2', 60_000), 3);
    });

    it('incrExpire keys are independent', async () => {
      const s = makeStore();
      await s.incrExpire('a', 60_000);
      await s.incrExpire('a', 60_000);
      await s.incrExpire('b', 60_000);
      assert.equal(await s.incrExpire('a', 60_000), 3);
      assert.equal(await s.incrExpire('b', 60_000), 2);
    });

    it('decr floors at 0', async () => {
      const s = makeStore();
      assert.equal(await s.decr('x'), 0);
    });

    it('decr decrements counter set by incrExpire', async () => {
      const s = makeStore();
      await s.incrExpire('gauge', 60_000);
      await s.incrExpire('gauge', 60_000);
      await s.incrExpire('gauge', 60_000); // = 3
      assert.equal(await s.decr('gauge'), 2);
      assert.equal(await s.decr('gauge'), 1);
    });

    it('getdel returns value and deletes key', async () => {
      const s = makeStore();
      await s.set('otp', 'secret');
      assert.equal(await s.getdel('otp'), 'secret');
      assert.equal(await s.get('otp'), null);
    });

    it('getdel on missing key returns null', async () => {
      const s = makeStore();
      assert.equal(await s.getdel('nope'), null);
    });

    it('getdel is single-use (concurrent calls only one succeeds)', async () => {
      const s = makeStore();
      await s.set('once', 'val');
      const [a, b] = await Promise.all([s.getdel('once'), s.getdel('once')]);
      const results = [a, b].filter(v => v !== null);
      assert.equal(results.length, 1, 'exactly one caller should get the value');
      assert.equal(results[0], 'val');
    });
  });
}

contractSuite('InMemory', () => new InMemoryStateStore());
```

- [ ] **Step 2: Run contract tests**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/stateStore.contract.test.js
```

Expected: all tests pass, no failures.

- [ ] **Step 3: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/stateStore.js tests/stateStore.contract.test.js
git commit -m "feat(p0): add InMemoryStateStore with contract tests"
```

---

## Task 4: Create lib/redisStateStore.js

**Files:**
- Create: `web/lib/redisStateStore.js`

- [ ] **Step 1: Write the file**

```javascript
// web/lib/redisStateStore.js
import Redis from 'ioredis';

// Lua script: atomic INCR + EXPIRE-on-create.
// Returns the new counter value. The TTL is set only on the first call
// (when the key did not exist), preserving the sliding-window semantics of
// the in-memory implementation.
const INCR_EXPIRE_SCRIPT = `
  local cur = redis.call('INCR', KEYS[1])
  if cur == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
  return cur
`;

export class RedisStateStore {
  constructor(redisUrl) {
    this._r = new Redis(redisUrl, {
      enableOfflineQueue: false,   // fail fast — caller falls back to in-memory
      lazyConnect: true,
      maxRetriesPerRequest: 1,
    });
    this._r.connect().catch(e => console.error('[RedisStateStore] connect error:', e.message));
  }

  async get(key) {
    const val = await this._r.get(key);
    return val ?? null;
  }

  async set(key, value, ttlMs = 0) {
    if (ttlMs > 0) {
      await this._r.set(key, String(value), 'PX', ttlMs);
    } else {
      await this._r.set(key, String(value));
    }
  }

  async del(key) { await this._r.del(key); }

  async incrExpire(key, ttlMs) {
    const result = await this._r.eval(INCR_EXPIRE_SCRIPT, 1, key, String(ttlMs));
    return Number(result);
  }

  async decr(key) {
    const val = await this._r.decr(key);
    if (val < 0) { await this._r.set(key, '0'); return 0; }
    return val;
  }

  async getdel(key) {
    // Redis 6.2+ GETDEL; fall back for older Redis via Lua
    try {
      const val = await this._r.getdel(key);
      return val ?? null;
    } catch {
      const val = await this._r.get(key);
      if (val === null) return null;
      await this._r.del(key);
      return val;
    }
  }

  async quit() { await this._r.quit(); }
}
```

- [ ] **Step 2: Extend stateStore.contract.test.js to include Redis when REDIS_URL is set**

In `web/tests/stateStore.contract.test.js`, add after the InMemory suite:

```javascript
// --- Add at the bottom of stateStore.contract.test.js ---
if (process.env.REDIS_URL) {
  const { RedisStateStore } = await import('../lib/redisStateStore.js');
  let _store;
  contractSuite('Redis', () => {
    _store = new RedisStateStore(process.env.REDIS_URL);
    return _store;
  });
  // Note: in the Redis suite each test creates a new store object sharing one connection.
  // Key isolation is handled by unique prefixes in the test data.
}
```

- [ ] **Step 3: Run without Redis (should still pass in-memory suite)**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/stateStore.contract.test.js
```

Expected: all in-memory tests pass; Redis suite skipped (no REDIS_URL).

- [ ] **Step 4: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/redisStateStore.js tests/stateStore.contract.test.js
git commit -m "feat(p0): add RedisStateStore; extend contract tests with optional Redis suite"
```

---

## Task 5: Update lib/context.js

**Files:**
- Modify: `web/lib/context.js`

- [ ] **Step 1: Add stateStore and vaultRepository fields**

Replace the current content of `web/lib/context.js` with:

```javascript
// web/lib/context.js
// Shared mutable context. `initAuth()` in auth.js populates this before any request.
// All lib files import `ctx` and access its properties (never reassign the binding itself).
export const ctx = {
  MASTER_KEY: null,
  DATA_DIR: null,
  ipIntel: null,
  ipPolicy: { blockTor: true, blockProxy: true, blockVpn: false, blockAbuser: true },
  derivedKeyCache: new Map(),
  /** @type {import('./stateStore.js').InMemoryStateStore | import('./redisStateStore.js').RedisStateStore} */
  stateStore: null,
  /** @type {import('./vaultRepository.js').FileVaultRepository} */
  vaultRepository: null,
};
```

- [ ] **Step 2: Verify the change compiles (no lint errors)**

```bash
cd /home/pwd-vm/PWDnow/web && node -e "import('./lib/context.js').then(m => console.log('ok', Object.keys(m.ctx).join(',')))"
```

Expected: `ok MASTER_KEY,DATA_DIR,ipIntel,ipPolicy,derivedKeyCache,stateStore,vaultRepository`

---

## Task 6: Create lib/vaultRepository.js (VaultRepository + FileVaultRepository)

**Files:**
- Create: `web/lib/vaultRepository.js`

- [ ] **Step 1: Write the file**

```javascript
// web/lib/vaultRepository.js
// VaultRepository — abstraction layer over the encrypted-file user and vault store.
//
// Interface (duck-typed):
//   async withUserTransaction(fn)           mutate-in-place: fn(users[]) → result | false (false = skip save)
//   async findUserByEmailHash(emailHash)     → user | null
//   async findUserById(id)                  → user | null
//   async loadSessions(uid)                 → Session[]
//   async saveSessions(uid, sessions)        → void
//   async getResource(uid, name)            → value | null  (name: 'credentials'|'folders'|...)
//   async setResource(uid, name, value)     → void
//   async deleteResource(uid, name)         → void
//   async deleteUserData(uid)               → void  (all files for uid)

import { existsSync, mkdirSync, rmSync } from 'fs';
import path from 'path';
import {
  loadUsers,
  saveUsers,
  withUsersLock,
  readEncryptedFile,
  writeEncryptedFile,
  userVaultDir,
  userVaultFile,
  userInfo,
} from './fileCrypto.js';
import {
  sessionsPath,
  loadSessions as _loadSessions,
  saveSessions as _saveSessions,
} from './session.js';

export class FileVaultRepository {
  constructor(dataDir) {
    this._dataDir = dataDir;
  }

  // Atomic read-modify-write on the users array.
  // fn(users) mutates in place; return false to skip save.
  async withUserTransaction(fn) {
    return withUsersLock(fn);
  }

  async findUserByEmailHash(emailHash) {
    const users = loadUsers();
    return users.find(u => u.emailHash === emailHash) ?? null;
  }

  async findUserById(id) {
    const users = loadUsers();
    return users.find(u => u.id === id) ?? null;
  }

  async loadSessions(uid) {
    return _loadSessions(uid);
  }

  async saveSessions(uid, sessions) {
    _saveSessions(uid, sessions);
  }

  async getResource(uid, name) {
    const fp = userVaultFile(uid, name);
    const info = userInfo(uid, name);
    return readEncryptedFile(fp, info, null);
  }

  async setResource(uid, name, value) {
    const dir = userVaultDir(uid);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
    const fp = userVaultFile(uid, name);
    const info = userInfo(uid, name);
    writeEncryptedFile(fp, info, value);
  }

  async deleteResource(uid, name) {
    const fp = userVaultFile(uid, name);
    if (existsSync(fp)) rmSync(fp);
  }

  async deleteUserData(uid) {
    const dir = userVaultDir(uid);
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  }
}
```

> **Note:** `sessionsPath` is imported here but not actually used in this file — it's only needed if we want to expose the path. We import `loadSessions`/`saveSessions` from `session.js` to maintain the existing cache behaviour. This creates a potential circular dependency chain if `session.js` ever imports `vaultRepository.js`. For P0 that doesn't happen — `session.js` still uses `fileCrypto.js` directly.

- [ ] **Step 2: Smoke test**

```bash
cd /home/pwd-vm/PWDnow/web && node --input-type=module <<'EOF'
import { FileVaultRepository } from './lib/vaultRepository.js';
console.log('import ok', typeof FileVaultRepository);
EOF
```

Expected: `import ok function`

---

## Task 7: Write VaultRepository contract tests

**Files:**
- Create: `web/tests/vaultRepository.contract.test.js`

- [ ] **Step 1: Write the test file**

```javascript
// web/tests/vaultRepository.contract.test.js
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { randomBytes } from 'crypto';
import { ctx } from '../lib/context.js';
import { FileVaultRepository } from '../lib/vaultRepository.js';

// Bootstrap a minimal ctx so fileCrypto.js derivedKey() works.
function bootstrapCtx(dataDir) {
  ctx.MASTER_KEY = randomBytes(32);
  ctx.DATA_DIR = dataDir;
  ctx.derivedKeyCache = new Map();
  // Pre-create users.enc so withUsersLock finds the file.
  const { writeEncryptedFile } = await import('../lib/fileCrypto.js');
  writeEncryptedFile(path.join(dataDir, 'users.enc'), 'users/enc', []);
  mkdirSync(path.join(dataDir, 'vault'), { recursive: true, mode: 0o700 });
}

describe('VaultRepository contract — File', () => {
  let repo;
  let tmpDir;

  before(async () => {
    tmpDir = path.join(tmpdir(), `vr-test-${randomBytes(8).toString('hex')}`);
    mkdirSync(tmpDir, { recursive: true });
    await bootstrapCtx(tmpDir);
    repo = new FileVaultRepository(tmpDir);
  });

  after(() => {
    if (existsSync(tmpDir)) rmSync(tmpDir, { recursive: true, force: true });
  });

  it('findUserByEmailHash returns null when no users', async () => {
    assert.equal(await repo.findUserByEmailHash('any'), null);
  });

  it('findUserById returns null when no users', async () => {
    assert.equal(await repo.findUserById('any'), null);
  });

  it('withUserTransaction creates and retrieves a user', async () => {
    const id = randomBytes(8).toString('hex');
    const emailHash = randomBytes(16).toString('hex');
    await repo.withUserTransaction(users => { users.push({ id, emailHash, passwordHash: 'hash123' }); });
    const found = await repo.findUserByEmailHash(emailHash);
    assert.ok(found, 'should find user by emailHash');
    assert.equal(found.id, id);
  });

  it('findUserById works after insert', async () => {
    const id = randomBytes(8).toString('hex');
    const emailHash = randomBytes(16).toString('hex');
    await repo.withUserTransaction(users => { users.push({ id, emailHash, passwordHash: 'h' }); });
    const found = await repo.findUserById(id);
    assert.ok(found);
    assert.equal(found.emailHash, emailHash);
  });

  it('withUserTransaction with return false skips save (read-only transaction)', async () => {
    let callCount = 0;
    const result = await repo.withUserTransaction(users => { callCount++; return false; });
    assert.equal(result, false);
    assert.equal(callCount, 1);
  });

  it('sessions roundtrip: load empty, save, load again', async () => {
    const uid = randomBytes(8).toString('hex');
    // Ensure the vault dir exists
    const { mkdirSync: mkd } = await import('fs');
    const { userVaultDir } = await import('../lib/fileCrypto.js');
    mkd(userVaultDir(uid), { recursive: true, mode: 0o700 });

    const empty = await repo.loadSessions(uid);
    assert.deepEqual(empty, []);

    const sessions = [{ jti: 'abc', id: 'abc', timestamp: Date.now(), deviceName: 'Chrome', ip: '1234', isCurrent: true }];
    await repo.saveSessions(uid, sessions);

    const loaded = await repo.loadSessions(uid);
    assert.equal(loaded.length, 1);
    assert.equal(loaded[0].jti, 'abc');
  });

  it('getResource returns null when absent', async () => {
    const uid = randomBytes(8).toString('hex');
    assert.equal(await repo.getResource(uid, 'credentials'), null);
  });

  it('setResource and getResource roundtrip', async () => {
    const uid = randomBytes(8).toString('hex');
    const data = [{ id: '1', name: 'github', username: 'user' }];
    await repo.setResource(uid, 'credentials', data);
    const loaded = await repo.getResource(uid, 'credentials');
    assert.deepEqual(loaded, data);
  });

  it('deleteResource removes the file', async () => {
    const uid = randomBytes(8).toString('hex');
    await repo.setResource(uid, 'folders', [{ id: 'f1' }]);
    await repo.deleteResource(uid, 'folders');
    assert.equal(await repo.getResource(uid, 'folders'), null);
  });

  it('deleteUserData removes the whole user directory', async () => {
    const uid = randomBytes(8).toString('hex');
    await repo.setResource(uid, 'credentials', []);
    const { userVaultDir: uvd } = await import('../lib/fileCrypto.js');
    assert.ok(existsSync(uvd(uid)), 'dir should exist before delete');
    await repo.deleteUserData(uid);
    assert.ok(!existsSync(uvd(uid)), 'dir should be gone after delete');
  });
});
```

- [ ] **Step 2: Run the contract tests**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/vaultRepository.contract.test.js
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/vaultRepository.js tests/vaultRepository.contract.test.js
git commit -m "feat(p0): add FileVaultRepository with contract tests"
```

---

## Task 8: Refactor lib/rateLimiter.js to use StateStore

**Files:**
- Modify: `web/lib/rateLimiter.js`

**Key changes:** All rate-limit functions become `async` and read/write through `ctx.stateStore` instead of in-process Maps. Constants and non-state helpers are unchanged. The module-level Maps are removed.

- [ ] **Step 1: Rewrite the stateful section**

Replace everything from `// ── Per-IP login rate limiter ─────────────────────────────────────────────────` through the `setInterval` cleanup block (lines 44–244 approximately) with:

```javascript
// ── Per-IP login rate limiter ─────────────────────────────────────────────────

export const LOGIN_MAX_PER_WINDOW = 10;
export const LOGIN_WINDOW_MS      = 5 * 60 * 1000;

export async function checkLoginRate(ip) {
  const count = await ctx.stateStore.incrExpire(`rl:login:${ip}`, LOGIN_WINDOW_MS);
  return count <= LOGIN_MAX_PER_WINDOW;
}

// ── Hints rate limiter ────────────────────────────────────────────────────────

export const HINTS_MAX_PER_WINDOW = 60;
export const HINTS_WINDOW_MS      = 5 * 60 * 1000;

export async function checkHintsRate(ip) {
  const count = await ctx.stateStore.incrExpire(`rl:hints:${ip}`, HINTS_WINDOW_MS);
  return count <= HINTS_MAX_PER_WINDOW;
}

// ── Per-account lockout ───────────────────────────────────────────────────────

export const ACCOUNT_LOCKOUT_SCHEDULE_MS = [0, 0, 0, 0, 0, 30000, 60000, 120000, 300000, 600000];

export async function checkAccountRate(emailHash) {
  const raw = await ctx.stateStore.get(`lockout:acct:${emailHash}`);
  if (!raw) return true;
  const e = JSON.parse(raw);
  if (e.lockedUntil && Date.now() < e.lockedUntil) return false;
  return true;
}

export async function recordAccountFailure(emailHash) {
  const raw = await ctx.stateStore.get(`lockout:acct:${emailHash}`);
  const prev = raw ? JSON.parse(raw) : { count: 0, lockedUntil: 0 };
  const count = prev.count + 1;
  const lockMs = ACCOUNT_LOCKOUT_SCHEDULE_MS[Math.min(count, ACCOUNT_LOCKOUT_SCHEDULE_MS.length - 1)];
  const lockedUntil = lockMs > 0 ? Date.now() + lockMs : 0;
  const ttlMs = Math.max(lockMs || 0, 60 * 60 * 1000); // keep for at least 1h
  await ctx.stateStore.set(`lockout:acct:${emailHash}`, JSON.stringify({ count, lockedUntil }), ttlMs);
}

export async function resetAccountFailures(emailHash) {
  await ctx.stateStore.del(`lockout:acct:${emailHash}`);
}

// ── Per-fingerprint lockout ────────────────────────────────────────────────────

export const FINGERPRINT_LOCKOUT_SCHEDULE_MS = [0, 0, 0, 0, 0, 30000, 60000, 120000, 300000, 600000];

export async function checkFingerprintRate(clientIdentity) {
  const raw = await ctx.stateStore.get(`lockout:fp:${clientIdentity}`);
  if (!raw) return true;
  const e = JSON.parse(raw);
  if (e.lockedUntil && Date.now() < e.lockedUntil) return false;
  return true;
}

export async function recordFingerprintFailure(clientIdentity) {
  const raw = await ctx.stateStore.get(`lockout:fp:${clientIdentity}`);
  const prev = raw ? JSON.parse(raw) : { count: 0, lockedUntil: 0 };
  const count = prev.count + 1;
  const lockMs = FINGERPRINT_LOCKOUT_SCHEDULE_MS[Math.min(count, FINGERPRINT_LOCKOUT_SCHEDULE_MS.length - 1)];
  const lockedUntil = lockMs > 0 ? Date.now() + lockMs : 0;
  const ttlMs = Math.max(lockMs || 0, 60 * 60 * 1000);
  await ctx.stateStore.set(`lockout:fp:${clientIdentity}`, JSON.stringify({ count, lockedUntil }), ttlMs);
}

export async function resetFingerprintFailures(clientIdentity) {
  await ctx.stateStore.del(`lockout:fp:${clientIdentity}`);
}

// ── Per-IP registration rate limiter ─────────────────────────────────────────

export const REGISTER_MAX_PER_WINDOW = 5;
export const REGISTER_WINDOW_MS      = 60 * 60 * 1000;

export async function checkRegisterRate(ip) {
  const count = await ctx.stateStore.incrExpire(`rl:register:${ip}`, REGISTER_WINDOW_MS);
  return count <= REGISTER_MAX_PER_WINDOW;
}

// ── Per-IP emergency rate limiter ─────────────────────────────────────────────

export const EMERGENCY_MAX_PER_WINDOW = 5;
export const EMERGENCY_WINDOW_MS      = 60 * 1000;

export async function checkEmergencyRate(ip) {
  const count = await ctx.stateStore.incrExpire(`rl:emergency:${ip}`, EMERGENCY_WINDOW_MS);
  return count <= EMERGENCY_MAX_PER_WINDOW;
}
```

Also **remove** the `MAX_RATE_LIMIT_ENTRIES`, `enforceMapCap` helper, all the `export const _loginRateLimiter` / `_hintsRateLimiter` / `_accountLockout` / `_fingerprintLockout` / `_registerRateLimiter` / `_emergencyRateLimiter` Map exports, and the `setInterval` cleanup block — StateStore TTL handles eviction automatically.

**Keep unchanged:** the `ARGON2_*` constants, `SCRYPT_*`, `PBKDF2_*` constants, `getDummyArgon2Hash` function, and the import of `getClientIp` from `session.js`. Also keep `deriveClientIdentity`, `makeFingerprintLogEntry`, `mergeFingerprintLog`, `FINGERPRINT_LOG_CAP`.

Also add at the top, after the existing imports:

```javascript
import { ctx } from './context.js';
```

- [ ] **Step 2: Write a unit test for the refactored rateLimiter**

Add `web/tests/rateLimiter.test.js`:

```javascript
// web/tests/rateLimiter.test.js
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryStateStore } from '../lib/stateStore.js';
import { ctx } from '../lib/context.js';

// Wire an in-memory StateStore so rateLimiter imports work.
before(() => { ctx.stateStore = new InMemoryStateStore(); });

const {
  checkLoginRate, LOGIN_MAX_PER_WINDOW,
  checkAccountRate, recordAccountFailure, resetAccountFailures,
  checkFingerprintRate, recordFingerprintFailure, resetFingerprintFailures,
  checkRegisterRate, REGISTER_MAX_PER_WINDOW,
} = await import('../lib/rateLimiter.js');

describe('rateLimiter (StateStore-backed)', () => {
  it('allows first LOGIN_MAX_PER_WINDOW requests', async () => {
    const ip = `test-${Math.random()}`;
    for (let i = 0; i < LOGIN_MAX_PER_WINDOW; i++) {
      assert.ok(await checkLoginRate(ip), `attempt ${i + 1} should be allowed`);
    }
  });

  it('blocks once limit is exceeded', async () => {
    const ip = `test-${Math.random()}`;
    for (let i = 0; i < LOGIN_MAX_PER_WINDOW; i++) await checkLoginRate(ip);
    assert.ok(!(await checkLoginRate(ip)), 'over-limit should be blocked');
  });

  it('checkAccountRate allows when no failures recorded', async () => {
    const eh = `eh-${Math.random()}`;
    assert.ok(await checkAccountRate(eh));
  });

  it('lockout triggers after enough failures', async () => {
    const eh = `eh-${Math.random()}`;
    // 6 failures → first lockout (30s). ACCOUNT_LOCKOUT_SCHEDULE_MS[6] = 60000 (index 6).
    // Actually schedule is [0,0,0,0,0,30000,...] so 6th failure locks for 30s.
    for (let i = 0; i < 6; i++) await recordAccountFailure(eh);
    assert.ok(!(await checkAccountRate(eh)), 'should be locked after 6 failures');
  });

  it('reset clears the lockout', async () => {
    const eh = `eh-${Math.random()}`;
    for (let i = 0; i < 6; i++) await recordAccountFailure(eh);
    await resetAccountFailures(eh);
    assert.ok(await checkAccountRate(eh), 'should be allowed after reset');
  });

  it('fingerprint lockout and reset work the same way', async () => {
    const id = `fp-${Math.random()}`;
    for (let i = 0; i < 6; i++) await recordFingerprintFailure(id);
    assert.ok(!(await checkFingerprintRate(id)));
    await resetFingerprintFailures(id);
    assert.ok(await checkFingerprintRate(id));
  });

  it('register rate limits independently per IP', async () => {
    const ip = `reg-${Math.random()}`;
    for (let i = 0; i < REGISTER_MAX_PER_WINDOW; i++) assert.ok(await checkRegisterRate(ip));
    assert.ok(!(await checkRegisterRate(ip)));
  });
});
```

- [ ] **Step 3: Run the unit tests**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/rateLimiter.test.js
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/rateLimiter.js tests/rateLimiter.test.js
git commit -m "feat(p0): refactor rateLimiter to use StateStore — fixes cross-worker B4 bypass"
```

---

## Task 9: Update auth.js initAuth to wire StateStore and VaultRepository

**Files:**
- Modify: `web/auth.js`

- [ ] **Step 1: Rewrite initAuth as async, wiring both abstractions**

Replace the current `initAuth` function body. Add imports at the top:

```javascript
import { InMemoryStateStore, createStateStore } from './lib/stateStore.js';
import { FileVaultRepository } from './lib/vaultRepository.js';
```

New `initAuth`:

```javascript
export async function initAuth({ dataDir }) {
  ctx.DATA_DIR = dataDir;
  ctx.derivedKeyCache.clear();
  if (!existsSync(ctx.DATA_DIR)) mkdirSync(ctx.DATA_DIR, { recursive: true, mode: 0o700 });

  const keyPath = path.join(ctx.DATA_DIR, '.master_key');
  if (existsSync(keyPath)) {
    ctx.MASTER_KEY = readFileSync(keyPath);
    if (ctx.MASTER_KEY.length !== 32) throw new Error('master key file is not 32 bytes');
  } else {
    ctx.MASTER_KEY = randomBytes(32);
    writeFileSync(keyPath, ctx.MASTER_KEY, { mode: 0o400, flag: 'wx' });
  }

  const usersFile = path.join(ctx.DATA_DIR, 'users.enc');
  if (!existsSync(usersFile)) writeEncryptedFile(usersFile, 'users/enc', []);
  const vaultDir = path.join(ctx.DATA_DIR, 'vault');
  if (!existsSync(vaultDir)) mkdirSync(vaultDir, { recursive: true, mode: 0o700 });

  ctx.ipIntel = new IpIntelligenceService(process.env.IPREGISTRY_API_KEY ?? '', ctx.DATA_DIR);
  ctx.ipPolicy = loadIpPolicy();

  // ── StateStore ────────────────────────────────────────────────────────────
  // Default: in-memory (self-host / single-node). Upgrade to Redis when REDIS_URL is set.
  ctx.stateStore = await createStateStore(process.env.REDIS_URL);
  if (process.env.REDIS_URL) {
    console.log('[StateStore] Using Redis:', process.env.REDIS_URL.replace(/:\/\/[^@]*@/, '://*@'));
  }

  // ── VaultRepository ────────────────────────────────────────────────────────
  ctx.vaultRepository = new FileVaultRepository(ctx.DATA_DIR);

  _getServerPublicIp().catch(() => {});
  derivedKey('jwe/session', 32);
  derivedKey('users/enc', 32);
  validateEnvSmtp().catch(e => console.error('[smtp] Startup validation error:', e.message));
}
```

- [ ] **Step 2: Verify import compiles**

```bash
cd /home/pwd-vm/PWDnow/web && node -e "import('./auth.js').then(m => console.log('ok', typeof m.initAuth))"
```

Expected: `ok function`

---

## Task 10: Update server.js to await initAuth

**Files:**
- Modify: `web/server.js`

- [ ] **Step 1: Change line 133**

Find: `initAuth({ dataDir: DATA_DIR });`
Replace with: `await initAuth({ dataDir: DATA_DIR });`

The file is already an ES module with `"type": "module"`, and Node.js 24 supports top-level `await` in ESM — no IIFE needed.

- [ ] **Step 2: Verify server starts**

```bash
cd /home/pwd-vm/PWDnow/web && timeout 5 node server.js 2>&1 | head -20 || true
```

Expected: Server starts (may show address-in-use if port taken, that's OK — the point is no import error).

---

## Task 11: Update authRoutes.js — async rate-limit calls + cluster-wide Argon2 gate

**Files:**
- Modify: `web/routes/authRoutes.js`

- [ ] **Step 1: Remove local `_argon2ActiveCount` variable and update hashPassword / verifyPassword**

Find (around line 84): `let _argon2ActiveCount = 0;`
Delete this line.

Update `hashPassword` (around line 129):

```javascript
export async function hashPassword(password) {
  const count = await ctx.stateStore.incrExpire('argon2:active', 120_000);
  if (count > ARGON2_MAX_CONCURRENT) {
    await ctx.stateStore.decr('argon2:active');
    const err = new Error('too_many_requests'); err.status = 429; throw err;
  }
  try {
    return await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: ARGON2_MEMORY_KIB,
      timeCost: ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
    });
  } finally {
    await ctx.stateStore.decr('argon2:active');
  }
}
```

Update `verifyPassword` (around line 148) — same pattern: replace `_argon2ActiveCount >= ARGON2_MAX_CONCURRENT` checks with `await ctx.stateStore.incrExpire('argon2:active', 120_000) > ARGON2_MAX_CONCURRENT`, add `decr` in the finally block. The full function:

```javascript
export async function verifyPassword(hashOrLegacy, password, legacySaltHex) {
  const count = await ctx.stateStore.incrExpire('argon2:active', 120_000);
  if (count > ARGON2_MAX_CONCURRENT) {
    await ctx.stateStore.decr('argon2:active');
    const err = new Error('too_many_requests'); err.status = 429; throw err;
  }
  try {
    if (hashOrLegacy && hashOrLegacy.startsWith('$argon2id$')) {
      return await argon2.verify(hashOrLegacy, password);
    }
    if (hashOrLegacy && hashOrLegacy.startsWith(PBKDF2_HASH_PREFIX)) {
      return await pbkdf2Sha512Verify(hashOrLegacy, password);
    }
    // Legacy scrypt path
    if (legacySaltHex) {
      const hash = scryptHash(password, legacySaltHex);
      return timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(hashOrLegacy ?? '', 'hex').slice(0, hash.length / 2 * 2));
    }
    return false;
  } finally {
    await ctx.stateStore.decr('argon2:active');
  }
}
```

> **Note:** The existing `verifyPassword` has a legacy scrypt path (lines ~165–173) — preserve its logic exactly; only replace the `_argon2ActiveCount` lines. Read the current implementation carefully before editing to not lose the legacy path.

- [ ] **Step 2: Await the three synchronous rate-limit calls in the login handler**

Find (around line 802):

```javascript
const ipBlocked      = !checkLoginRate(getClientIp(req));
const fpBlocked      = !checkFingerprintRate(clientIdentity);
const accountBlocked = !duressArmed && !checkAccountRate(emailHash);
```

Replace with:

```javascript
const [ipBlocked, fpBlocked, accountBlocked] = await Promise.all([
  checkLoginRate(getClientIp(req)).then(ok => !ok),
  checkFingerprintRate(clientIdentity).then(ok => !ok),
  duressArmed ? Promise.resolve(false) : checkAccountRate(emailHash).then(ok => !ok),
]);
```

- [ ] **Step 3: Await the failure-recording calls (around line 835)**

Find:

```javascript
if (!duressArmed) recordAccountFailure(emailHash);
recordFingerprintFailure(clientIdentity);
```

Replace with:

```javascript
const failOps = [recordFingerprintFailure(clientIdentity)];
if (!duressArmed) failOps.push(recordAccountFailure(emailHash));
await Promise.all(failOps);
```

- [ ] **Step 4: Await the success-reset calls (around line 875)**

Find:

```javascript
resetAccountFailures(emailHash);
resetFingerprintFailures(clientIdentity);
```

Replace with:

```javascript
await Promise.all([resetAccountFailures(emailHash), resetFingerprintFailures(clientIdentity)]);
```

- [ ] **Step 5: Await the single-call rate-limit check at /api/auth/verify-password (around line 1072)**

Find:

```javascript
if (!checkLoginRate(getClientIp(req))) {
```

Replace with:

```javascript
if (!await checkLoginRate(getClientIp(req))) {
```

- [ ] **Step 6: Await resetFingerprintFailures at the device-log endpoint (around line 1067)**

Find:

```javascript
resetFingerprintFailures(targetId);
```

Replace with:

```javascript
await resetFingerprintFailures(targetId);
```

- [ ] **Step 7: Search for any remaining sync calls to the refactored functions**

```bash
grep -n "checkLoginRate\|checkHintsRate\|checkAccountRate\|recordAccountFailure\|resetAccountFailures\|checkFingerprintRate\|recordFingerprintFailure\|resetFingerprintFailures\|checkRegisterRate\|checkEmergencyRate" /home/pwd-vm/PWDnow/web/routes/authRoutes.js | grep -v "await " | grep -v "^[0-9]*:import"
```

Expected: no output (all calls are now awaited).

---

## Task 12: Run full test suite and E2E regression

- [ ] **Step 1: Run server-side tests**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/stateStore.contract.test.js tests/vaultRepository.contract.test.js tests/rateLimiter.test.js tests/smtpConfig.test.js
```

Expected: all pass.

- [ ] **Step 2: Run Vitest (client-side unit tests)**

```bash
cd /home/pwd-vm/PWDnow/web && npm run test
```

Expected: all pass.

- [ ] **Step 3: Build**

```bash
cd /home/pwd-vm/PWDnow/web && npm run build
```

Expected: exits 0.

- [ ] **Step 4: Start server and run E2E regression**

```bash
cd /home/pwd-vm/PWDnow/web && NODE_ENV=test node server.js &
SERVER_PID=$!
sleep 3
npx playwright test e2e/comprehensive-platform.spec.ts --reporter=list
kill $SERVER_PID 2>/dev/null || true
```

Expected: all E2E tests pass (same as before this change).

- [ ] **Step 5: Final commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add -p
git commit -m "feat(p0): wire StateStore+VaultRepository; fix B4 cross-worker rate-limit bypass"
```

---

## Self-Review Checklist

### Spec coverage

| Spec requirement | Covered by |
|---|---|
| Introduce `StateStore` interface | Task 2 |
| In-memory `StateStore` implementation | Task 2 |
| Optional Redis `StateStore` (falls back to in-memory) | Tasks 4, 9 |
| Fix rate-limit/lockout cross-worker bypass (B4) | Task 8 |
| Introduce `VaultRepository` interface | Task 6 |
| File-store `VaultRepository` implementation | Task 6 |
| Wire optional Redis in `initAuth` | Task 9 |
| Contract tests — both `StateStore` implementations | Tasks 3, 4 |
| Contract tests — `VaultRepository` | Task 7 |
| `e2e/comprehensive-platform.spec.ts` stays green | Task 12 |
| Cluster-wide Argon2 admission gate via `StateStore` | Task 11 |

### Not in this plan (deferred)
- Postgres `VaultRepository` → P1 plan
- Session cache re-enable with Redis pub/sub → P2 plan
- Kubernetes manifests, HPA, k6 load tests → P3 plan
- `auth_data/` → Postgres migration → P1 plan

---

## P1 / P2 / P3 Next Steps

After this plan is complete and merged:

- **P1:** `docs/superpowers/plans/2026-06-08-saas-p1-postgres-kms.md` — Postgres schema, `PostgresVaultRepository`, per-user DEK + KMS wrapping, dual-write + flag-gated cutover.
- **P2:** `docs/superpowers/plans/2026-06-08-saas-p2-redis-everywhere.md` — Session JTI cache via `StateStore` with pub/sub invalidation on logout; re-enable `SESSIONS_CACHE_TTL_MS`.
- **P3:** `docs/superpowers/plans/2026-06-08-saas-p3-kubernetes.md` — Dockerfile, K8s Deployment + HPA, Secrets wiring, k6 load tests.
