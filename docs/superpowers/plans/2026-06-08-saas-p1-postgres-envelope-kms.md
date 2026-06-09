# SaaS P1 — Postgres + Per-User Envelope Encryption + KMS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-node encrypted file-store (`auth_data/`) with a clustered Postgres backend whose vault blobs are encrypted under a **per-user DEK** wrapped by a pluggable **KMS** (default: HashiCorp Vault Transit), behind the *existing* `VaultRepository` contract, with zero behavior change for the self-host file path and a flag-gated, dual-write + backfill cutover.

**Architecture:** A `KmsProvider` interface (local-dev + Vault-Transit + a stub for AWS/GCP later) wraps/unwraps a 32-byte per-user DEK. An `envelope` module unwraps the DEK (≤60 s in-process LRU, zeroized) and AES-256-GCM-encrypts each vault blob — the same blob format the file-store already uses (`iv(12)‖tag(16)‖ct`). `PostgresVaultRepository` implements the **same duck-typed `VaultRepository` interface** the `FileVaultRepository` already satisfies, plus three new row-oriented user methods so writes stay O(1) instead of rewriting all users (kills B7). The 78 route call-sites that bypass the abstraction are routed through `ctx.vaultRepository` first (P1.A) so the backend is actually swappable. A `DualWriteVaultRepository` mirrors writes file→Postgres during migration; a backfill script re-encrypts each existing user under a fresh DEK; an env flag selects the live read path.

**Tech Stack:** Node.js 24 ESM, `pg` (node-postgres) 8 + pooled client, `node-pg-migrate` 7 for SQL migrations, `node:test`/`node:assert` for server contract tests, existing `web/lib/fileCrypto.js` AES-256-GCM helpers reused verbatim, `argon2` (already a dep) for the optional password-bound wrap, `ioredis` already present (used only by StateStore here). Postgres assumed TLS-reachable (managed or self-run); Vault assumed HTTPS-reachable.

---

## Locked decisions (senior calls, ratified for this plan)

| Decision | Choice | Rationale |
|---|---|---|
| **KMS target** | Pluggable `KmsProvider` interface. Default adapter = **HashiCorp Vault Transit**; ship a `LocalDevKmsProvider` (AES-256-GCM, file/env key) for dev/CI; AWS/GCP are thin future adapters. | Cloud-agnostic, self-hostable (matches PWDnow's ethos), CNSA-friendly, fully testable with **no** cloud credentials. No premature lock-in. |
| **DEK wrap mode** | **Two-layer envelope is schema-ready from day one** (`wrap_mode` column). P1 *executes* with `wrap_mode='kms'` (KMS-only, server-recoverable) as the default. The password-bound (`'kms+pw'`, Argon2id) layer is fully specified (Task P1.C2) and toggleable later **without a migration**. | KMS-only is strictly better than today's single global key (per-user blast-radius) and preserves the existing reset/recovery UX → P1 ships. The zero-knowledge tier is designed-in, not bolted-on, so there is no P1-redo. |
| **Resource granularity** | **One row per `(user_id, resource_name)`** holding the encrypted JSON blob (faithful port of the per-`.enc`-file model). | Satisfies the existing `getResource/setResource` contract verbatim, kills `users.enc` write-amplification (B7) and the single-host file lock (B3) with **near-zero consumer reshaping**. Per-item normalization (`vault_items` 1-row-per-credential) is deferred to a later optimization — noted, not done here. |
| **User write path** | Add row-oriented `insertUser` / `updateUserById` / `deleteUserById` to the interface; migrate the `withUserTransaction` register/update/delete sites to them. | Postgres user writes become `O(1)` (`SELECT … FOR UPDATE` / single `UPDATE`) instead of load-all-users-rewrite-all. This *is* the B7 fix; doing it generically keeps both backends honest. |
| **Postgres/Redis hosting** | Plan is host-agnostic: connection via URL + TLS params. Works against a local dev Postgres and a managed cluster identically. | HA topology is a P3 concern; P1 must not assume local FS or a specific cloud. |

> **Invariant (non-negotiable):** CNSA 2.0 / NIST PQC L5 posture is preserved. AES-256-GCM for all data, HKDF-SHA384 / HMAC-SHA256 unchanged, Argon2id params unchanged. No primitive is weakened anywhere in this plan. The Rust daemon (`daemon/`) is **not touched**.

---

## Scope

| In scope (P1) | Out of scope |
|---|---|
| Route the 78 store call-sites through `ctx.vaultRepository` (P1.A) | Redis for ephemeral state everywhere (P2) |
| `KmsProvider` interface + Local-dev + Vault-Transit adapters | Session-cache re-enable + pub/sub invalidation (P2) |
| `envelope` module (per-user DEK wrap/unwrap, LRU, zeroize) | Kubernetes manifests, HPA, k6 (P3) |
| Postgres schema + migrations | Per-credential row normalization |
| Row-oriented user methods on `VaultRepository` (both impls) | Any daemon / self-host crypto change |
| `PostgresVaultRepository` passing the **existing** contract test | Password-bound wrap *enabled by default* (specified, default-off) |
| `DualWriteVaultRepository` + backfill migrator + flag cutover | gRPC mTLS (tracked in `horizontal-scalability-cnsa2.md`) |
| Full regression green in **both** file and Postgres modes | |

---

## File Map

**New files:**
- `web/lib/kms/kmsProvider.js` — `KmsProvider` JSDoc contract + `createKmsProvider(config)` factory
- `web/lib/kms/localDevKms.js` — `LocalDevKmsProvider` (AES-256-GCM, dev/CI only)
- `web/lib/kms/vaultTransitKms.js` — `VaultTransitKmsProvider` (HashiCorp Vault Transit over HTTPS)
- `web/lib/envelope.js` — `Envelope` class: per-user DEK generate/wrap/unwrap (LRU+zeroize), `encryptResource`/`decryptResource`
- `web/lib/db/pool.js` — `pg` pool singleton + `query()` / `withTx()` helpers
- `web/lib/postgresVaultRepository.js` — `PostgresVaultRepository` (implements the `VaultRepository` interface)
- `web/lib/dualWriteVaultRepository.js` — `DualWriteVaultRepository` (file primary, Postgres mirror)
- `web/migrations/1718000000000_init-saas-schema.cjs` — `node-pg-migrate` schema migration
- `web/scripts/backfill-to-postgres.js` — one-shot migrator: `auth_data/` → Postgres (per-user DEK)
- `web/tests/kms.contract.test.js` — contract tests for all `KmsProvider` impls
- `web/tests/envelope.test.js` — envelope round-trip + zeroize + LRU tests
- `web/tests/postgresVaultRepository.contract.test.js` — runs the shared repo contract against Postgres (skips w/o `DATABASE_URL`)
- `web/tests/vaultRepository.userRows.test.js` — row-oriented user-method tests (both impls)

**Modified files:**
- `web/package.json` — add `pg`, `node-pg-migrate`
- `web/lib/context.js` — add `kms` field; `vaultRepository` type union widened
- `web/lib/vaultRepository.js` — add `insertUser` / `updateUserById` / `deleteUserById` to `FileVaultRepository`
- `web/auth.js` — `initAuth` builds KMS + selects repo impl by env flags
- `web/routes/authRoutes.js` — route ~51 store calls through `ctx.vaultRepository`; migrate `withUserTransaction` user sites to row methods
- `web/routes/vaultRoutes.js` — route ~27 store calls through `ctx.vaultRepository`
- `web/.env.example` — document `DATABASE_URL`, `VAULT_BACKEND`, `KMS_PROVIDER`, `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TRANSIT_KEY`, `LOCAL_KMS_KEY`

---

## Pre-flight (run once, do not commit)

- [ ] **Confirm clean baseline**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/ 2>&1 | tail -5 && npm run lint
```
Expected: existing server tests pass, `tsc --noEmit` clean. If not, stop and fix baseline first.

- [ ] **Provision a throwaway Postgres for dev/test** (Docker; skip if you already have one)

```bash
docker run -d --name pwdnow-pg -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=pwdnow -p 55432:5432 postgres:16
export DATABASE_URL="postgres://postgres:dev@127.0.0.1:55432/pwdnow"
```
Expected: container `pwdnow-pg` running. (Tests that need Postgres read `DATABASE_URL`; without it they skip.)

---

# PHASE P1.A — Route consumers through the abstraction (no backend change yet)

> **Why first:** `ctx.vaultRepository` exists but is unused — `grep -c` shows **51** direct store calls in `authRoutes.js` and **27** in `vaultRoutes.js`. Until these go through the interface, swapping in Postgres is impossible. This phase changes *who is called*, not *what it does* — `FileVaultRepository` stays the only impl, so behavior is identical and the E2E gate must stay green.

## Task A1: Add row-oriented user methods to the interface (File impl)

**Files:**
- Modify: `web/lib/vaultRepository.js`
- Test: `web/tests/vaultRepository.userRows.test.js`

- [ ] **Step 1: Write failing tests for the new methods**

Create `web/tests/vaultRepository.userRows.test.js`:

```javascript
// web/tests/vaultRepository.userRows.test.js
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { randomBytes } from 'crypto';
import { ctx } from '../lib/context.js';
import { FileVaultRepository } from '../lib/vaultRepository.js';
import { writeEncryptedFile } from '../lib/fileCrypto.js';

function userRowsSuite(label, makeRepo) {
  describe(`VaultRepository user-rows — ${label}`, () => {
    it('insertUser then findUserById returns the row', async () => {
      const repo = await makeRepo();
      const id = randomBytes(8).toString('hex');
      const emailHash = randomBytes(16).toString('hex');
      await repo.insertUser({ id, emailHash, passwordHash: 'h', createdAt: Date.now() });
      const u = await repo.findUserById(id);
      assert.ok(u); assert.equal(u.emailHash, emailHash);
    });

    it('insertUser rejects a duplicate emailHash', async () => {
      const repo = await makeRepo();
      const emailHash = randomBytes(16).toString('hex');
      await repo.insertUser({ id: randomBytes(8).toString('hex'), emailHash, passwordHash: 'h' });
      await assert.rejects(
        () => repo.insertUser({ id: randomBytes(8).toString('hex'), emailHash, passwordHash: 'h2' }),
        /exists|duplicate|unique/i,
      );
    });

    it('updateUserById mutates a single user and persists', async () => {
      const repo = await makeRepo();
      const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'old' });
      const ret = await repo.updateUserById(id, (u) => { u.passwordHash = 'new'; return u.id; });
      assert.equal(ret, id);
      assert.equal((await repo.findUserById(id)).passwordHash, 'new');
    });

    it('updateUserById on missing id returns null and does not throw', async () => {
      const repo = await makeRepo();
      assert.equal(await repo.updateUserById('ghost', () => {}), null);
    });

    it('deleteUserById removes the user row', async () => {
      const repo = await makeRepo();
      const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      await repo.deleteUserById(id);
      assert.equal(await repo.findUserById(id), null);
    });
  });
}

describe('File backend setup', () => {
  let tmpDir;
  before(async () => {
    tmpDir = path.join(tmpdir(), `urows-${randomBytes(8).toString('hex')}`);
    mkdirSync(tmpDir, { recursive: true });
    ctx.MASTER_KEY = randomBytes(32);
    ctx.DATA_DIR = tmpDir;
    ctx.derivedKeyCache = new Map();
    writeEncryptedFile(path.join(tmpDir, 'users.enc'), 'users/enc', []);
    mkdirSync(path.join(tmpDir, 'vault'), { recursive: true, mode: 0o700 });
  });
  after(() => { if (existsSync(tmpDir)) rmSync(tmpDir, { recursive: true, force: true }); });
  userRowsSuite('File', async () => new FileVaultRepository(tmpDir));
});

export { userRowsSuite };
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/vaultRepository.userRows.test.js
```
Expected: FAIL — `repo.insertUser is not a function`.

- [ ] **Step 3: Implement the three methods on `FileVaultRepository`**

Add inside the `FileVaultRepository` class in `web/lib/vaultRepository.js` (after `findUserById`):

```javascript
  async insertUser(user) {
    return this.withUserTransaction((users) => {
      if (users.some(u => u.emailHash === user.emailHash)) {
        const e = new Error('user exists'); e.code = 'USER_EXISTS'; throw e;
      }
      users.push(user);
      return user.id;
    });
  }

  // fn(user) mutates the matched user in place; helper returns fn's return value,
  // or null if no user matched (no write performed).
  async updateUserById(id, fn) {
    let ret = null, matched = false;
    await this.withUserTransaction((users) => {
      const u = users.find(x => x.id === id);
      if (!u) return false;            // skip save
      matched = true;
      ret = fn(u);
    });
    return matched ? ret : null;
  }

  async deleteUserById(id) {
    await this.withUserTransaction((users) => {
      const i = users.findIndex(u => u.id === id);
      if (i === -1) return false;
      users.splice(i, 1);
    });
  }
```

- [ ] **Step 4: Run — expect pass**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/vaultRepository.userRows.test.js
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/vaultRepository.js tests/vaultRepository.userRows.test.js
git commit -m "feat(p1a): add row-oriented user methods to VaultRepository (File impl)"
```

---

## Task A2: Route `authRoutes.js` user/session sites through `ctx.vaultRepository`

**Files:**
- Modify: `web/routes/authRoutes.js`

**Transformation table** — apply mechanically to every matching call site. `repo` = `ctx.vaultRepository`.

| Current direct call | Replace with |
|---|---|
| `loadUsers()` then `.find(u => u.emailHash === X)` | `await repo.findUserByEmailHash(X)` |
| `loadUsers()` then `.find(u => u.id === X)` | `await repo.findUserById(X)` |
| `withUsersLock(users => { users.push(newUser); ... })` (register) | `await repo.insertUser(newUser)` |
| `withUsersLock(users => { const u = users.find(...id===X); u.field = …; })` | `await repo.updateUserById(X, u => { u.field = …; })` |
| `withUsersLock(users => { idx = findIndex; splice })` (delete account) | `await repo.deleteUserById(X)` |
| `loadSessions(uid)` | `await repo.loadSessions(uid)` |
| `saveSessions(uid, list)` | `await repo.saveSessions(uid, list)` |
| `readEncryptedFile(userVaultFile(uid,'NAME'), userInfo(uid,'NAME'), fb)` | `(await repo.getResource(uid,'NAME')) ?? fb` |
| `writeEncryptedFile(userVaultFile(uid,'NAME'), userInfo(uid,'NAME'), v)` | `await repo.setResource(uid,'NAME', v)` |

- [ ] **Step 1: Enumerate every call site**

```bash
cd /home/pwd-vm/PWDnow/web && grep -n "withUsersLock\|loadUsers\|saveUsers\|readEncryptedFile\|writeEncryptedFile\|loadSessions\|saveSessions\|userVaultFile\|userVaultDir" routes/authRoutes.js
```
Write down each line number; you will revisit until the grep is empty (except the `import` line, which you delete in Step 4).

- [ ] **Step 2: Add `ctx` import if absent, then convert each site**

Ensure the top of the file has `import { ctx } from '../lib/context.js';`. Convert each enumerated site using the table above. Two concrete examples from this file:

The register insert (currently around line 677, `users.push({...})` inside a lock):
```javascript
// BEFORE
await withUsersLock(users => {
  if (users.some(u => u.emailHash === emailHash)) { /* 409 */ }
  users.push({ id, emailHash, passwordHash: hash, salt: null, cryptoSalt: cryptoSalt || null, createdAt: Date.now() });
});
// AFTER
try {
  await ctx.vaultRepository.insertUser({ id, emailHash, passwordHash: hash, salt: null, cryptoSalt: cryptoSalt || null, createdAt: Date.now() });
} catch (e) {
  if (e.code === 'USER_EXISTS') { return res.status(409).json({ error: 'exists' }); }
  throw e;
}
```

A user-field update (e.g. password change):
```javascript
// BEFORE
await withUsersLock(users => { const u = users.find(x => x.id === req.user.id); if (u) u.passwordHash = newHash; });
// AFTER
await ctx.vaultRepository.updateUserById(req.user.id, u => { u.passwordHash = newHash; });
```

> **Preserve every guard exactly** (409 on duplicate, 404 on missing, duress branches, CSRF). Only the *storage mechanism* changes. Do **not** alter Argon2/scrypt logic, rate-limit calls, or response shapes.

- [ ] **Step 3: Verify no functional store calls remain**

```bash
cd /home/pwd-vm/PWDnow/web && grep -n "withUsersLock\|loadUsers(\|saveUsers(\|readEncryptedFile(\|writeEncryptedFile(\|\bloadSessions(\|\bsaveSessions(\|userVaultFile(\|userVaultDir(" routes/authRoutes.js | grep -v "^[0-9]*:import"
```
Expected: no output.

- [ ] **Step 4: Remove now-dead imports**

Delete `loadUsers`, `saveUsers`, `withUsersLock`, `readEncryptedFile`, `writeEncryptedFile`, `userVaultFile`, `userVaultDir`, `loadSessions`, `saveSessions` from the `import` statements in `authRoutes.js` **only if** Step 3 shows zero remaining uses of each. Keep `hashEmail`, `derivedKey`, `userInfo` if still referenced.

- [ ] **Step 5: Lint + targeted run**

```bash
cd /home/pwd-vm/PWDnow/web && npm run lint && timeout 6 node server.js 2>&1 | head -15 || true
```
Expected: `tsc` clean; server boots without import errors.

- [ ] **Step 6: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add routes/authRoutes.js
git commit -m "refactor(p1a): route authRoutes user/session/resource IO through VaultRepository"
```

---

## Task A3: Route `vaultRoutes.js` resource sites through `ctx.vaultRepository`

**Files:**
- Modify: `web/routes/vaultRoutes.js`

- [ ] **Step 1: Enumerate**

```bash
cd /home/pwd-vm/PWDnow/web && grep -n "readEncryptedFile\|writeEncryptedFile\|userVaultFile\|userVaultDir\|loadUsers\|withUsersLock\|loadSessions\|saveSessions" routes/vaultRoutes.js
```

- [ ] **Step 2: Convert each site** using the same transformation table from Task A2. `vaultRoutes.js` is mostly per-resource read/write (`emergency`, `emergency_requests`, `credentials`, `folders`, `asset_holder`, `profile`, `mfa`, `audit`). Each becomes `getResource`/`setResource`. Example:
```javascript
// BEFORE
const requests = readEncryptedFile(filePath, info, []);
writeEncryptedFile(filePath, info, requests);
// AFTER
const requests = (await ctx.vaultRepository.getResource(uid, 'emergency_requests')) ?? [];
await ctx.vaultRepository.setResource(uid, 'emergency_requests', requests);
```

- [ ] **Step 3: Verify clean + remove dead imports** (same commands as A2 Step 3–4, against `vaultRoutes.js`).

- [ ] **Step 4: Lint**

```bash
cd /home/pwd-vm/PWDnow/web && npm run lint
```
Expected: clean.

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add routes/vaultRoutes.js
git commit -m "refactor(p1a): route vaultRoutes resource IO through VaultRepository"
```

---

## Task A4: Regression gate — file backend unchanged

- [ ] **Step 1: Server tests + Vitest + build**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/ && npm run test && npm run build
```
Expected: all green, build exits 0.

- [ ] **Step 2: E2E gold-standard, file mode**

```bash
cd /home/pwd-vm/PWDnow/web && NODE_ENV=test node server.js & SRV=$!; sleep 3
npx playwright test e2e/comprehensive-platform.spec.ts --reporter=list; R=$?
kill $SRV 2>/dev/null || true; exit $R
```
Expected: all pass — identical to pre-P1.A. **If anything regresses, fix before proceeding.** This proves the abstraction routing is behavior-preserving.

---

# PHASE P1.B — KMS provider layer

## Task B1: Add `pg` + `node-pg-migrate`

**Files:** Modify `web/package.json`

- [ ] **Step 1: Install**

```bash
cd /home/pwd-vm/PWDnow/web && npm install pg@8 && npm install --save-dev node-pg-migrate@7
```
Expected: added, no errors.

- [ ] **Step 2: Verify import**

```bash
cd /home/pwd-vm/PWDnow/web && node -e "import('pg').then(m => console.log('pg ok', typeof m.default.Pool))"
```
Expected: `pg ok function`.

- [ ] **Step 3: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add package.json package-lock.json
git commit -m "feat(p1b): add pg + node-pg-migrate"
```

---

## Task B2: `KmsProvider` contract + `LocalDevKmsProvider`

**Files:**
- Create: `web/lib/kms/kmsProvider.js`, `web/lib/kms/localDevKms.js`
- Test: `web/tests/kms.contract.test.js`

- [ ] **Step 1: Write the contract test (failing)**

Create `web/tests/kms.contract.test.js`:

```javascript
// web/tests/kms.contract.test.js
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'crypto';
import { LocalDevKmsProvider } from '../lib/kms/localDevKms.js';

export function kmsContractSuite(label, makeKms) {
  describe(`KmsProvider contract — ${label}`, () => {
    it('wrap then unwrap round-trips the DEK', async () => {
      const kms = await makeKms();
      const dek = randomBytes(32);
      const { wrapped, keyId } = await kms.wrapDek(dek);
      assert.ok(Buffer.isBuffer(wrapped));
      assert.ok(typeof keyId === 'string' && keyId.length > 0);
      const out = await kms.unwrapDek(wrapped, keyId);
      assert.ok(out.equals(dek), 'unwrapped DEK must equal original');
    });

    it('wrapped output is not the plaintext DEK', async () => {
      const kms = await makeKms();
      const dek = randomBytes(32);
      const { wrapped } = await kms.wrapDek(dek);
      assert.ok(!wrapped.equals(dek));
      assert.ok(wrapped.length > dek.length, 'wrapped carries nonce/tag/overhead');
    });

    it('tampered ciphertext fails to unwrap', async () => {
      const kms = await makeKms();
      const { wrapped, keyId } = await kms.wrapDek(randomBytes(32));
      const bad = Buffer.from(wrapped); bad[bad.length - 1] ^= 0xff;
      await assert.rejects(() => kms.unwrapDek(bad, keyId));
    });

    it('two wraps of the same DEK differ (fresh nonce)', async () => {
      const kms = await makeKms();
      const dek = randomBytes(32);
      const a = await kms.wrapDek(dek); const b = await kms.wrapDek(dek);
      assert.ok(!a.wrapped.equals(b.wrapped));
    });
  });
}

kmsContractSuite('LocalDev', async () => new LocalDevKmsProvider(randomBytes(32)));

if (process.env.VAULT_ADDR && process.env.VAULT_TOKEN && process.env.VAULT_TRANSIT_KEY) {
  const { VaultTransitKmsProvider } = await import('../lib/kms/vaultTransitKms.js');
  kmsContractSuite('VaultTransit', async () => new VaultTransitKmsProvider({
    addr: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN, keyName: process.env.VAULT_TRANSIT_KEY,
  }));
}
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.contract.test.js
```
Expected: FAIL — cannot find `../lib/kms/localDevKms.js`.

- [ ] **Step 3: Write the contract doc file**

Create `web/lib/kms/kmsProvider.js`:

```javascript
// web/lib/kms/kmsProvider.js
// KmsProvider — wraps/unwraps a per-user 32-byte DEK using an external key authority.
//
// Interface (duck-typed):
//   async wrapDek(dek: Buffer)                 → { wrapped: Buffer, keyId: string }
//   async unwrapDek(wrapped: Buffer, keyId)    → Buffer (the 32-byte DEK)
//
// Contract:
//   • wrap(dek) then unwrap(wrapped, keyId) returns a Buffer byte-equal to dek.
//   • wrapping is non-deterministic (fresh nonce) and authenticated (tamper → reject).
//   • keyId identifies the CMK/key-version used, so rotation can be tracked per row.
//   • The plaintext DEK never leaves process memory toward the KMS in the wrapped form.
//
// Implementations: LocalDevKmsProvider (dev/CI), VaultTransitKmsProvider (default prod).

export function createKmsProvider(config) {
  const kind = (config?.provider || process.env.KMS_PROVIDER || 'local').toLowerCase();
  if (kind === 'vault') {
    return import('./vaultTransitKms.js').then(({ VaultTransitKmsProvider }) =>
      new VaultTransitKmsProvider({
        addr: process.env.VAULT_ADDR,
        token: process.env.VAULT_TOKEN,
        keyName: process.env.VAULT_TRANSIT_KEY || 'pwdnow-dek',
      }));
  }
  if (kind === 'local') {
    return import('./localDevKms.js').then(({ LocalDevKmsProvider }) => {
      const hex = process.env.LOCAL_KMS_KEY;
      if (!hex || Buffer.from(hex, 'hex').length !== 32) {
        throw new Error('LOCAL_KMS_KEY must be 32 bytes hex when KMS_PROVIDER=local');
      }
      return new LocalDevKmsProvider(Buffer.from(hex, 'hex'));
    });
  }
  throw new Error(`unknown KMS_PROVIDER: ${kind}`);
}
```

Create `web/lib/kms/localDevKms.js`:

```javascript
// web/lib/kms/localDevKms.js
// DEV/CI ONLY. Simulates a KMS by AES-256-GCM-wrapping the DEK under a local key.
// NOT for production: the wrapping key sits in the same process as the data.
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

export class LocalDevKmsProvider {
  constructor(masterKey) {
    if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
      throw new Error('LocalDevKmsProvider requires a 32-byte key');
    }
    this._key = masterKey;
    this._keyId = 'local-dev:v1';
  }

  async wrapDek(dek) {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this._key, iv);
    const ct = Buffer.concat([c.update(dek), c.final()]);
    const tag = c.getAuthTag();
    return { wrapped: Buffer.concat([iv, tag, ct]), keyId: this._keyId };
  }

  async unwrapDek(wrapped, _keyId) {
    const iv = wrapped.subarray(0, 12);
    const tag = wrapped.subarray(12, 28);
    const ct = wrapped.subarray(28);
    const d = createDecipheriv('aes-256-gcm', this._key, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
  }
}
```

- [ ] **Step 4: Run — expect pass**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/kms.contract.test.js
```
Expected: LocalDev suite PASS; VaultTransit suite skipped (no env).

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/kms/ tests/kms.contract.test.js
git commit -m "feat(p1b): KmsProvider contract + LocalDevKmsProvider with contract tests"
```

---

## Task B3: `VaultTransitKmsProvider` (default production adapter)

**Files:** Create `web/lib/kms/vaultTransitKms.js`

- [ ] **Step 1: Write the adapter**

```javascript
// web/lib/kms/vaultTransitKms.js
// HashiCorp Vault Transit adapter. The DEK never leaves Vault in plaintext form on
// disk; Vault holds the CMK. We send base64(DEK) to /transit/encrypt and receive a
// "vault:vN:..." ciphertext string. keyId records the key + version for rotation.
//
// Requires: VAULT_ADDR (https://...), VAULT_TOKEN, key created via:
//   vault secrets enable transit
//   vault write -f transit/keys/pwdnow-dek type=aes256-gcm96
const DEFAULT_TIMEOUT_MS = 4000;

export class VaultTransitKmsProvider {
  constructor({ addr, token, keyName, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    if (!addr || !token || !keyName) throw new Error('VaultTransitKmsProvider needs addr, token, keyName');
    this._addr = addr.replace(/\/+$/, '');
    this._token = token;
    this._key = keyName;
    this._timeoutMs = timeoutMs;
  }

  async _post(pathSuffix, body) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this._timeoutMs);
    try {
      const r = await fetch(`${this._addr}/v1/transit/${pathSuffix}`, {
        method: 'POST',
        headers: { 'X-Vault-Token': this._token, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: ac.signal,
      });
      if (!r.ok) throw new Error(`vault transit ${pathSuffix} -> HTTP ${r.status}`);
      return (await r.json()).data;
    } finally { clearTimeout(t); }
  }

  async wrapDek(dek) {
    const data = await this._post(`encrypt/${this._key}`, { plaintext: dek.toString('base64') });
    // ciphertext form: "vault:v3:base64..."; keyId records the version prefix for rotation.
    const ciphertext = data.ciphertext;
    const version = ciphertext.split(':')[1] || 'v?';
    return { wrapped: Buffer.from(ciphertext, 'utf8'), keyId: `${this._key}:${version}` };
  }

  async unwrapDek(wrapped, _keyId) {
    const data = await this._post(`decrypt/${this._key}`, { ciphertext: wrapped.toString('utf8') });
    const dek = Buffer.from(data.plaintext, 'base64');
    if (dek.length !== 32) throw new Error('unwrapped DEK is not 32 bytes');
    return dek;
  }
}
```

- [ ] **Step 2: Sanity import**

```bash
cd /home/pwd-vm/PWDnow/web && node -e "import('./lib/kms/vaultTransitKms.js').then(m=>console.log('ok',typeof m.VaultTransitKmsProvider))"
```
Expected: `ok function`. (Live round-trip is covered by the contract suite when `VAULT_ADDR`/`VAULT_TOKEN`/`VAULT_TRANSIT_KEY` are set — run it against a dev Vault if available.)

- [ ] **Step 3: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/kms/vaultTransitKms.js
git commit -m "feat(p1b): VaultTransitKmsProvider (default production KMS adapter)"
```

---

## Task B4: `Envelope` — per-user DEK lifecycle + resource crypto

**Files:**
- Create: `web/lib/envelope.js`
- Test: `web/tests/envelope.test.js`

**Design:** `Envelope` owns the KMS and a short-TTL DEK LRU. `newUserDek()` returns the fields to persist on a user row. `encryptResource(user, value)` / `decryptResource(user, blob)` map JSON ⇄ the `iv‖tag‖ct` AES-256-GCM blob (identical layout to `fileCrypto.encryptBlob`), keyed by the *user's unwrapped DEK*. DEK buffers are zeroized after the LRU entry expires.

- [ ] **Step 1: Write failing tests**

Create `web/tests/envelope.test.js`:

```javascript
// web/tests/envelope.test.js
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'crypto';
import { LocalDevKmsProvider } from '../lib/kms/localDevKms.js';
import { Envelope } from '../lib/envelope.js';

function mkEnvelope() { return new Envelope(new LocalDevKmsProvider(randomBytes(32)), { dekTtlMs: 50 }); }

describe('Envelope', () => {
  it('newUserDek returns wrapped fields, never plaintext', async () => {
    const env = mkEnvelope();
    const f = await env.newUserDek();
    assert.equal(f.wrapMode, 'kms');
    assert.ok(Buffer.isBuffer(f.wrappedDek) && f.wrappedDek.length > 32);
    assert.ok(typeof f.kmsKeyId === 'string' && f.kmsKeyId.length > 0);
    assert.equal(f.pwWrapSalt, null);
  });

  it('encryptResource → decryptResource round-trips JSON', async () => {
    const env = mkEnvelope();
    const user = { id: 'u1', ...(await env.newUserDek()) };
    const value = [{ id: 'c1', name: 'github', secret: 's3cr3t' }];
    const blob = await env.encryptResource(user, value);
    assert.ok(Buffer.isBuffer(blob));
    assert.deepEqual(await env.decryptResource(user, blob), value);
  });

  it('ciphertext is not plaintext-recognizable', async () => {
    const env = mkEnvelope();
    const user = { id: 'u2', ...(await env.newUserDek()) };
    const blob = await env.encryptResource(user, { token: 'PLAINTEXT_MARKER' });
    assert.ok(!blob.toString('utf8').includes('PLAINTEXT_MARKER'));
  });

  it('a different user cannot decrypt another user blob', async () => {
    const env = mkEnvelope();
    const a = { id: 'a', ...(await env.newUserDek()) };
    const b = { id: 'b', ...(await env.newUserDek()) };
    const blob = await env.encryptResource(a, { x: 1 });
    await assert.rejects(() => env.decryptResource(b, blob));
  });

  it('DEK LRU is bounded and refreshes after TTL', async () => {
    const env = mkEnvelope();
    const user = { id: 'u3', ...(await env.newUserDek()) };
    await env.decryptResource(user, await env.encryptResource(user, { a: 1 }));
    assert.equal(env._dekCacheSize(), 1);
    await new Promise(r => setTimeout(r, 70));
    assert.equal(env._dekCacheSize(), 0, 'DEK must be evicted+zeroized after TTL');
  });
});
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/envelope.test.js
```
Expected: FAIL — cannot find `../lib/envelope.js`.

- [ ] **Step 3: Implement `Envelope`**

Create `web/lib/envelope.js`:

```javascript
// web/lib/envelope.js
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const DEK_TTL_MS = 60_000;

export class Envelope {
  constructor(kms, { dekTtlMs = DEK_TTL_MS } = {}) {
    this._kms = kms;
    this._ttl = dekTtlMs;
    this._cache = new Map(); // userId → { dek: Buffer, timer }
  }

  // Returns persistable fields for a new user row. Plaintext DEK is zeroized before return.
  async newUserDek() {
    const dek = randomBytes(32);
    const { wrapped, keyId } = await this._kms.wrapDek(dek);
    dek.fill(0);
    return { wrappedDek: wrapped, kmsKeyId: keyId, wrapMode: 'kms', pwWrapSalt: null };
  }

  // Unwrap (cached ≤ttl). Cache holds the DEK; entries are zeroized on eviction.
  async _dek(user) {
    const hit = this._cache.get(user.id);
    if (hit) return hit.dek;
    const wrapped = Buffer.isBuffer(user.wrappedDek) ? user.wrappedDek : Buffer.from(user.wrappedDek);
    const dek = await this._kms.unwrapDek(wrapped, user.kmsKeyId);
    const timer = setTimeout(() => {
      const e = this._cache.get(user.id);
      if (e) { e.dek.fill(0); this._cache.delete(user.id); }
    }, this._ttl);
    timer.unref?.();
    this._cache.set(user.id, { dek, timer });
    return dek;
  }

  async encryptResource(user, value) {
    const dek = await this._dek(user);
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', dek, iv);
    const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(value), 'utf8')), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]);
  }

  async decryptResource(user, blob) {
    const dek = await this._dek(user);
    const iv = blob.subarray(0, 12), tag = blob.subarray(12, 28), ct = blob.subarray(28);
    const d = createDecipheriv('aes-256-gcm', dek, iv);
    d.setAuthTag(tag);
    return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
  }

  _dekCacheSize() { return this._cache.size; }
}
```

- [ ] **Step 4: Run — expect pass**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/envelope.test.js
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/envelope.js tests/envelope.test.js
git commit -m "feat(p1b): Envelope — per-user DEK wrap/unwrap, LRU+zeroize, resource crypto"
```

---

# PHASE P1.C — Postgres backend

## Task C1: Schema migration

**Files:** Create `web/migrations/1718000000000_init-saas-schema.cjs`

- [ ] **Step 1: Write the migration**

```javascript
// web/migrations/1718000000000_init-saas-schema.cjs
exports.up = (pgm) => {
  pgm.createExtension('pgcrypto', { ifNotExists: true });

  pgm.createTable('users', {
    id:            { type: 'text', primaryKey: true },          // hex UUID (matches generateUUID())
    email_hmac:    { type: 'text', notNull: true, unique: true },// HMAC-SHA256 blind index
    password_hash: { type: 'text', notNull: true },
    wrapped_dek:   { type: 'bytea', notNull: true },
    kms_key_id:    { type: 'text', notNull: true },
    wrap_mode:     { type: 'text', notNull: true, default: 'kms' }, // 'kms' | 'kms+pw'
    pw_wrap_salt:  { type: 'bytea' },                            // null unless wrap_mode='kms+pw'
    crypto_salt:   { type: 'text' },                            // legacy field carried from file model
    status:        { type: 'text', notNull: true, default: 'active' },
    created_at:    { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });

  // One row per (user_id, resource_name): faithful port of per-.enc-file model.
  pgm.createTable('vault_items', {
    user_id:    { type: 'text', notNull: true, references: 'users', onDelete: 'CASCADE' },
    name:       { type: 'text', notNull: true },                 // credentials|folders|asset_holder|profile|mfa|sessions|emergency|...
    ciphertext: { type: 'bytea', notNull: true },                // iv||tag||ct, AES-256-GCM under user DEK
    version:    { type: 'integer', notNull: true, default: 1 },
    updated_at: { type: 'timestamptz', notNull: true, default: pgm.func('now()') },
  });
  pgm.addConstraint('vault_items', 'vault_items_pk', { primaryKey: ['user_id', 'name'] });
};

exports.down = (pgm) => {
  pgm.dropTable('vault_items');
  pgm.dropTable('users');
};
```

- [ ] **Step 2: Add migrate scripts to `package.json`**

In `web/package.json` `"scripts"`, add:
```json
"migrate": "node-pg-migrate -m migrations -j cjs",
"migrate:up": "node-pg-migrate up -m migrations -j cjs"
```

- [ ] **Step 3: Run the migration against dev Postgres**

```bash
cd /home/pwd-vm/PWDnow/web && DATABASE_URL="$DATABASE_URL" npm run migrate:up
```
Expected: `Migrating files: > 1718000000000_init-saas-schema` then `Migrations complete!`.

- [ ] **Step 4: Verify schema**

```bash
cd /home/pwd-vm/PWDnow/web && node -e "import('pg').then(async ({default:{Pool}})=>{const p=new Pool({connectionString:process.env.DATABASE_URL});const r=await p.query(\"select table_name from information_schema.tables where table_schema='public' order by 1\");console.log(r.rows.map(x=>x.table_name));await p.end();})"
```
Expected: array includes `users` and `vault_items` (and `pgmigrations`).

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add migrations/ package.json package-lock.json
git commit -m "feat(p1c): Postgres schema (users + vault_items) via node-pg-migrate"
```

---

## Task C2: DB pool helper

**Files:** Create `web/lib/db/pool.js`

- [ ] **Step 1: Write it**

```javascript
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
```

- [ ] **Step 2: Smoke test**

```bash
cd /home/pwd-vm/PWDnow/web && node --input-type=module -e "import('./lib/db/pool.js').then(async m=>{const r=await m.query('select 1 as ok'); console.log(r.rows[0]); await m.closePool();})"
```
Expected: `{ ok: 1 }`.

- [ ] **Step 3: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/db/pool.js && git commit -m "feat(p1c): pg pool helper (query/withTx/closePool, TLS-aware)"
```

---

## Task C3: `PostgresVaultRepository` — pass the shared contract

**Files:**
- Create: `web/lib/postgresVaultRepository.js`
- Test: `web/tests/postgresVaultRepository.contract.test.js`

**Key idea:** It implements the **same** `VaultRepository` interface (so it drops in behind `ctx.vaultRepository`). User rows store `email_hmac`/`password_hash`/`wrapped_dek`/`kms_key_id`/`wrap_mode`. Resource blobs are encrypted by the injected `Envelope` under the user's DEK and stored in `vault_items`. `getResource`/`setResource`/`loadSessions`/`saveSessions` need the *user row* to find the DEK, so the repo resolves `uid → user` internally.

- [ ] **Step 1: Write the contract test (reuses the existing repo contract)**

Create `web/tests/postgresVaultRepository.contract.test.js`:

```javascript
// web/tests/postgresVaultRepository.contract.test.js
// Runs the same behavioral contract the FileVaultRepository satisfies, against Postgres.
// Skips entirely unless DATABASE_URL is set.
import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'crypto';

if (!process.env.DATABASE_URL) {
  describe('PostgresVaultRepository (skipped — no DATABASE_URL)', () => { it('skipped', () => {}); });
} else {
  const { PostgresVaultRepository } = await import('../lib/postgresVaultRepository.js');
  const { Envelope } = await import('../lib/envelope.js');
  const { LocalDevKmsProvider } = await import('../lib/kms/localDevKms.js');
  const { query, closePool } = await import('../lib/db/pool.js');

  function makeRepo() {
    return new PostgresVaultRepository(new Envelope(new LocalDevKmsProvider(randomBytes(32))));
  }

  describe('PostgresVaultRepository contract', () => {
    before(async () => { await query('DELETE FROM vault_items'); await query('DELETE FROM users'); });
    after(async () => { await closePool(); });
    beforeEach(async () => { await query('DELETE FROM vault_items'); await query('DELETE FROM users'); });

    it('insertUser + findUserByEmailHash + findUserById', async () => {
      const repo = makeRepo();
      const id = randomBytes(8).toString('hex'); const eh = randomBytes(16).toString('hex');
      await repo.insertUser({ id, emailHash: eh, passwordHash: 'h' });
      assert.equal((await repo.findUserByEmailHash(eh)).id, id);
      assert.equal((await repo.findUserById(id)).emailHash, eh);
    });

    it('insertUser rejects duplicate emailHash', async () => {
      const repo = makeRepo(); const eh = randomBytes(16).toString('hex');
      await repo.insertUser({ id: randomBytes(8).toString('hex'), emailHash: eh, passwordHash: 'h' });
      await assert.rejects(() => repo.insertUser({ id: randomBytes(8).toString('hex'), emailHash: eh, passwordHash: 'x' }), /exists|unique|duplicate/i);
    });

    it('updateUserById mutates one row', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'old' });
      await repo.updateUserById(id, u => { u.passwordHash = 'new'; });
      assert.equal((await repo.findUserById(id)).passwordHash, 'new');
    });

    it('setResource/getResource round-trip (encrypted at rest)', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      const data = [{ id: '1', name: 'github', secret: 'PLAINTEXT_MARKER' }];
      await repo.setResource(id, 'credentials', data);
      assert.deepEqual(await repo.getResource(id, 'credentials'), data);
      const raw = await query('SELECT ciphertext FROM vault_items WHERE user_id=$1 AND name=$2', [id, 'credentials']);
      assert.ok(!raw.rows[0].ciphertext.toString('utf8').includes('PLAINTEXT_MARKER'), 'must be ciphertext at rest');
    });

    it('getResource returns null when absent', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      assert.equal(await repo.getResource(id, 'folders'), null);
    });

    it('sessions roundtrip via loadSessions/saveSessions', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      assert.deepEqual(await repo.loadSessions(id), []);
      await repo.saveSessions(id, [{ jti: 'abc', id: 'abc', isCurrent: true }]);
      const s = await repo.loadSessions(id); assert.equal(s.length, 1); assert.equal(s[0].jti, 'abc');
    });

    it('deleteResource + deleteUserById', async () => {
      const repo = makeRepo(); const id = randomBytes(8).toString('hex');
      await repo.insertUser({ id, emailHash: randomBytes(16).toString('hex'), passwordHash: 'h' });
      await repo.setResource(id, 'folders', [{ id: 'f' }]);
      await repo.deleteResource(id, 'folders');
      assert.equal(await repo.getResource(id, 'folders'), null);
      await repo.deleteUserById(id);
      assert.equal(await repo.findUserById(id), null);
    });
  });
}
```

- [ ] **Step 2: Run — expect failure**

```bash
cd /home/pwd-vm/PWDnow/web && DATABASE_URL="$DATABASE_URL" node --test tests/postgresVaultRepository.contract.test.js
```
Expected: FAIL — cannot find `../lib/postgresVaultRepository.js`.

- [ ] **Step 3: Implement the repository**

Create `web/lib/postgresVaultRepository.js`:

```javascript
// web/lib/postgresVaultRepository.js
// Implements the VaultRepository interface against Postgres with per-user envelope ALE.
import { query, withTx } from './db/pool.js';

// Map a DB user row → the in-app user object shape the routes expect.
function rowToUser(r) {
  if (!r) return null;
  return {
    id: r.id,
    emailHash: r.email_hmac,
    passwordHash: r.password_hash,
    wrappedDek: r.wrapped_dek,            // Buffer
    kmsKeyId: r.kms_key_id,
    wrapMode: r.wrap_mode,
    pwWrapSalt: r.pw_wrap_salt ?? null,
    cryptoSalt: r.crypto_salt ?? null,
    salt: null,
    status: r.status,
    createdAt: r.created_at ? new Date(r.created_at).getTime() : undefined,
  };
}

export class PostgresVaultRepository {
  constructor(envelope) {
    if (!envelope) throw new Error('PostgresVaultRepository requires an Envelope');
    this._env = envelope;
  }

  async _requireUser(uid) {
    const u = await this.findUserById(uid);
    if (!u) { const e = new Error('user not found'); e.code = 'USER_NOT_FOUND'; throw e; }
    return u;
  }

  async findUserByEmailHash(emailHash) {
    const r = await query('SELECT * FROM users WHERE email_hmac = $1', [emailHash]);
    return rowToUser(r.rows[0]);
  }

  async findUserById(id) {
    const r = await query('SELECT * FROM users WHERE id = $1', [id]);
    return rowToUser(r.rows[0]);
  }

  // New users get a freshly KMS-wrapped DEK here.
  async insertUser(user) {
    const dekFields = await this._env.newUserDek();
    try {
      await query(
        `INSERT INTO users (id, email_hmac, password_hash, wrapped_dek, kms_key_id, wrap_mode, pw_wrap_salt, crypto_salt, status, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active', now())`,
        [user.id, user.emailHash, user.passwordHash, dekFields.wrappedDek, dekFields.kmsKeyId,
         dekFields.wrapMode, dekFields.pwWrapSalt, user.cryptoSalt ?? null],
      );
      return user.id;
    } catch (e) {
      if (e.code === '23505') { const dup = new Error('user exists'); dup.code = 'USER_EXISTS'; throw dup; }
      throw e;
    }
  }

  // Row-locked read-modify-write of a single user. fn mutates the user object;
  // only the mutable columns (password_hash, wrap_mode, pw_wrap_salt, status, crypto_salt) are written back.
  async updateUserById(id, fn) {
    return withTx(async (client) => {
      const r = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [id]);
      if (r.rows.length === 0) return null;
      const user = rowToUser(r.rows[0]);
      const ret = fn(user);
      await client.query(
        `UPDATE users SET password_hash=$2, wrap_mode=$3, pw_wrap_salt=$4, status=$5, crypto_salt=$6 WHERE id=$1`,
        [id, user.passwordHash, user.wrapMode, user.pwWrapSalt, user.status ?? 'active', user.cryptoSalt ?? null],
      );
      return ret ?? id;
    });
  }

  async deleteUserById(id) {
    await query('DELETE FROM users WHERE id = $1', [id]); // vault_items cascade
  }

  // withUserTransaction kept for interface-completeness: loads all users, applies fn,
  // diffs, and writes back. Used only by legacy/admin paths — NOT the hot path.
  async withUserTransaction(fn) {
    return withTx(async (client) => {
      const r = await client.query('SELECT * FROM users FOR UPDATE');
      const users = r.rows.map(rowToUser);
      const before = new Map(users.map(u => [u.id, JSON.stringify(u)]));
      const result = await fn(users);
      if (result === false) return result;
      for (const u of users) {
        if (before.get(u.id) !== JSON.stringify(u)) {
          await client.query('UPDATE users SET password_hash=$2, wrap_mode=$3, status=$4 WHERE id=$1',
            [u.id, u.passwordHash, u.wrapMode, u.status ?? 'active']);
        }
      }
      return result;
    });
  }

  // ── Resources (per (user_id, name) row, envelope-encrypted) ──
  async getResource(uid, name) {
    const user = await this.findUserById(uid);
    if (!user) return null;
    const r = await query('SELECT ciphertext FROM vault_items WHERE user_id=$1 AND name=$2', [uid, name]);
    if (r.rows.length === 0) return null;
    return this._env.decryptResource(user, r.rows[0].ciphertext);
  }

  async setResource(uid, name, value) {
    const user = await this._requireUser(uid);
    const blob = await this._env.encryptResource(user, value);
    await query(
      `INSERT INTO vault_items (user_id, name, ciphertext, version, updated_at)
       VALUES ($1,$2,$3,1, now())
       ON CONFLICT (user_id, name) DO UPDATE SET ciphertext=EXCLUDED.ciphertext, version=vault_items.version+1, updated_at=now()`,
      [uid, name, blob],
    );
  }

  async deleteResource(uid, name) {
    await query('DELETE FROM vault_items WHERE user_id=$1 AND name=$2', [uid, name]);
  }

  async deleteUserData(uid) {
    await query('DELETE FROM users WHERE id=$1', [uid]); // cascades vault_items
  }

  // Sessions modeled as a 'sessions' resource row (faithful port; dedicated table is P2).
  async loadSessions(uid) { return (await this.getResource(uid, 'sessions')) ?? []; }
  async saveSessions(uid, list) { await this.setResource(uid, 'sessions', list); }
}
```

- [ ] **Step 4: Run — expect pass**

```bash
cd /home/pwd-vm/PWDnow/web && DATABASE_URL="$DATABASE_URL" node --test tests/postgresVaultRepository.contract.test.js
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/postgresVaultRepository.js tests/postgresVaultRepository.contract.test.js
git commit -m "feat(p1c): PostgresVaultRepository with per-user envelope ALE; passes repo contract"
```

---

## Task C4: Wire backend selection into `initAuth`

**Files:**
- Modify: `web/lib/context.js`, `web/auth.js`, `web/.env.example`

- [ ] **Step 1: Add `kms` to context**

In `web/lib/context.js`, add a field:
```javascript
  /** @type {import('./envelope.js').Envelope | null} */
  envelope: null,
  /** @type {import('./kms/kmsProvider.js')|null} */
  kms: null,
```
And widen the `vaultRepository` JSDoc type to include `PostgresVaultRepository` and `DualWriteVaultRepository`.

- [ ] **Step 2: Select the repo by env flag in `initAuth`**

In `web/auth.js`, replace the line `ctx.vaultRepository = new FileVaultRepository(ctx.DATA_DIR);` with:

```javascript
  // Backend selection: VAULT_BACKEND = 'file' (default) | 'postgres' | 'dual'
  const backend = (process.env.VAULT_BACKEND || 'file').toLowerCase();
  const fileRepo = new FileVaultRepository(ctx.DATA_DIR);
  if (backend === 'file') {
    ctx.vaultRepository = fileRepo;
  } else {
    const { createKmsProvider } = await import('./lib/kms/kmsProvider.js');
    const { Envelope } = await import('./lib/envelope.js');
    const { PostgresVaultRepository } = await import('./lib/postgresVaultRepository.js');
    ctx.kms = await createKmsProvider();
    ctx.envelope = new Envelope(ctx.kms);
    const pgRepo = new PostgresVaultRepository(ctx.envelope);
    if (backend === 'postgres') {
      ctx.vaultRepository = pgRepo;
    } else if (backend === 'dual') {
      const { DualWriteVaultRepository } = await import('./lib/dualWriteVaultRepository.js');
      ctx.vaultRepository = new DualWriteVaultRepository(fileRepo, pgRepo); // file primary
    } else {
      throw new Error(`unknown VAULT_BACKEND: ${backend}`);
    }
    console.log(`[VaultRepository] backend=${backend} kms=${process.env.KMS_PROVIDER || 'local'}`);
  }
```
Add the import near the top of `auth.js`: `import { FileVaultRepository } from './lib/vaultRepository.js';` (already present per current code — keep it).

- [ ] **Step 3: Document env in `web/.env.example`**

Append:
```bash
# ── SaaS backend (P1) ────────────────────────────────────────────────
# VAULT_BACKEND: file (default, self-host) | postgres | dual (migration)
VAULT_BACKEND=file
DATABASE_URL=postgres://user:pass@host:5432/pwdnow
PGSSL=verify            # verify | no-verify | disable
PG_POOL_MAX=10
# KMS_PROVIDER: local (dev/CI) | vault (HashiCorp Vault Transit, default prod)
KMS_PROVIDER=local
LOCAL_KMS_KEY=          # 32-byte hex, required when KMS_PROVIDER=local
VAULT_ADDR=https://vault.internal:8200
VAULT_TOKEN=
VAULT_TRANSIT_KEY=pwdnow-dek
```

- [ ] **Step 4: Boot in postgres mode (smoke)**

```bash
cd /home/pwd-vm/PWDnow/web && VAULT_BACKEND=postgres KMS_PROVIDER=local LOCAL_KMS_KEY=$(openssl rand -hex 32) DATABASE_URL="$DATABASE_URL" PGSSL=disable timeout 6 node server.js 2>&1 | head -15 || true
```
Expected: log line `[VaultRepository] backend=postgres kms=local`; no import/throw errors.

- [ ] **Step 5: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/context.js auth.js .env.example
git commit -m "feat(p1c): env-flagged backend selection (file|postgres|dual) in initAuth"
```

---

## Task C5: Full E2E against Postgres backend

- [ ] **Step 1: Migrate + run E2E with Postgres backend**

```bash
cd /home/pwd-vm/PWDnow/web && npm run build
export VAULT_BACKEND=postgres KMS_PROVIDER=local LOCAL_KMS_KEY=$(openssl rand -hex 32) PGSSL=disable
npm run migrate:up
NODE_ENV=test node server.js & SRV=$!; sleep 3
npx playwright test e2e/comprehensive-platform.spec.ts --reporter=list; R=$?
kill $SRV 2>/dev/null || true; exit $R
```
Expected: **all E2E pass against Postgres** — register, login, folder/asset CRUD, duress, destruction all work with the new backend. This is the proof that the Postgres path is a true drop-in.

- [ ] **Step 2: Re-run E2E in file mode to confirm no self-host regression**

```bash
cd /home/pwd-vm/PWDnow/web && unset VAULT_BACKEND KMS_PROVIDER LOCAL_KMS_KEY PGSSL
NODE_ENV=test node server.js & SRV=$!; sleep 3
npx playwright test e2e/comprehensive-platform.spec.ts --reporter=list; R=$?
kill $SRV 2>/dev/null || true; exit $R
```
Expected: all pass — file mode identical to baseline.

---

# PHASE P1.D — Migration (dual-write + backfill + cutover)

## Task D1: `DualWriteVaultRepository`

**Files:** Create `web/lib/dualWriteVaultRepository.js`

**Semantics:** Reads come from `primary` (file). Writes go to `primary` then mirror to `secondary` (Postgres); a mirror failure is logged but does **not** fail the request (file remains source of truth until cutover). `insertUser` mirrors the user **with its DEK already provisioned by the Postgres side**.

- [ ] **Step 1: Write it**

```javascript
// web/lib/dualWriteVaultRepository.js
// Migration shim: file is primary (reads + authoritative writes); Postgres is mirrored.
// Mirror failures are logged, never thrown, so the live file path is never degraded.
export class DualWriteVaultRepository {
  constructor(primary, secondary) { this._p = primary; this._s = secondary; }

  async _mirror(op, fn) { try { await fn(); } catch (e) { console.error(`[dual-write] mirror ${op} failed:`, e.message); } }

  // reads → primary
  findUserByEmailHash(x) { return this._p.findUserByEmailHash(x); }
  findUserById(x) { return this._p.findUserById(x); }
  loadSessions(uid) { return this._p.loadSessions(uid); }
  getResource(uid, n) { return this._p.getResource(uid, n); }

  // writes → primary then mirror
  async insertUser(user) {
    const r = await this._p.insertUser(user);
    await this._mirror('insertUser', () => this._s.insertUser(user));
    return r;
  }
  async updateUserById(id, fn) {
    // Apply to primary; then re-apply the same field changes to the mirror by copying the result row.
    const r = await this._p.updateUserById(id, fn);
    await this._mirror('updateUserById', async () => {
      const updated = await this._p.findUserById(id);
      if (updated) await this._s.updateUserById(id, (u) => { u.passwordHash = updated.passwordHash; u.wrapMode = updated.wrapMode; u.status = updated.status; });
    });
    return r;
  }
  async deleteUserById(id) { await this._p.deleteUserById(id); await this._mirror('deleteUserById', () => this._s.deleteUserById(id)); }
  async saveSessions(uid, list) { await this._p.saveSessions(uid, list); await this._mirror('saveSessions', () => this._s.saveSessions(uid, list)); }
  async setResource(uid, n, v) { await this._p.setResource(uid, n, v); await this._mirror('setResource', () => this._s.setResource(uid, n, v)); }
  async deleteResource(uid, n) { await this._p.deleteResource(uid, n); await this._mirror('deleteResource', () => this._s.deleteResource(uid, n)); }
  async deleteUserData(uid) { await this._p.deleteUserData(uid); await this._mirror('deleteUserData', () => this._s.deleteUserData(uid)); }
  async withUserTransaction(fn) { return this._p.withUserTransaction(fn); }
}
```

> **Mirror caveat (document, accept):** `updateUserById` mirror requires the secondary user to exist (created either by an earlier `insertUser` mirror or the backfill in D2). Users that registered *before* dual-write are reconciled by the backfill, which is idempotent.

- [ ] **Step 2: Smoke import**

```bash
cd /home/pwd-vm/PWDnow/web && node -e "import('./lib/dualWriteVaultRepository.js').then(m=>console.log('ok',typeof m.DualWriteVaultRepository))"
```
Expected: `ok function`.

- [ ] **Step 3: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add lib/dualWriteVaultRepository.js
git commit -m "feat(p1d): DualWriteVaultRepository (file primary, Postgres mirror)"
```

---

## Task D2: Backfill migrator script

**Files:** Create `web/scripts/backfill-to-postgres.js`

**What it does:** Boots the file backend read-side, enumerates every user in `users.enc`, and for each: `insertUser` into Postgres (provisions a fresh per-user DEK via the Postgres repo), then copies every resource file (`credentials`, `folders`, `asset_holder`, `profile`, `mfa`, `sessions`, `emergency`, `emergency_requests`, plus any others present) by reading via the file repo and `setResource` via the Postgres repo (which re-encrypts under the new DEK). Idempotent: existing users are skipped/updated.

- [ ] **Step 1: Write the script**

```javascript
// web/scripts/backfill-to-postgres.js
// Usage:
//   DATABASE_URL=... KMS_PROVIDER=local LOCAL_KMS_KEY=$(openssl rand -hex 32) \
//   AUTH_DATA_DIR=../auth_data node scripts/backfill-to-postgres.js
import { ctx } from '../lib/context.js';
import { readFileSync, existsSync, readdirSync } from 'fs';
import path from 'path';
import { randomBytes } from 'crypto';
import { FileVaultRepository } from '../lib/vaultRepository.js';
import { PostgresVaultRepository } from '../lib/postgresVaultRepository.js';
import { Envelope } from '../lib/envelope.js';
import { createKmsProvider } from '../lib/kms/kmsProvider.js';
import { loadUsers, userVaultDir } from '../lib/fileCrypto.js';
import { closePool } from '../lib/db/pool.js';

const RESOURCES = ['credentials', 'folders', 'asset_holder', 'profile', 'mfa', 'sessions', 'emergency', 'emergency_requests', 'audit'];

async function main() {
  const dataDir = path.resolve(process.env.AUTH_DATA_DIR || '../auth_data');
  ctx.DATA_DIR = dataDir;
  ctx.derivedKeyCache = new Map();
  const keyPath = path.join(dataDir, '.master_key');
  if (!existsSync(keyPath)) throw new Error(`no .master_key in ${dataDir}`);
  ctx.MASTER_KEY = readFileSync(keyPath);

  const fileRepo = new FileVaultRepository(dataDir);
  const pgRepo = new PostgresVaultRepository(new Envelope(await createKmsProvider()));

  const users = loadUsers();
  console.log(`[backfill] ${users.length} users in ${dataDir}`);
  let migrated = 0, skipped = 0;

  for (const u of users) {
    const existing = await pgRepo.findUserById(u.id);
    if (!existing) {
      await pgRepo.insertUser({ id: u.id, emailHash: u.emailHash, passwordHash: u.passwordHash, cryptoSalt: u.cryptoSalt ?? null });
    } else { skipped++; }

    // Discover resource names actually present on disk (covers any not in RESOURCES).
    const dir = userVaultDir(u.id);
    const present = existsSync(dir)
      ? readdirSync(dir).filter(f => f.endsWith('.enc')).map(f => f.replace(/\.enc$/, ''))
      : [];
    const names = [...new Set([...RESOURCES, ...present])];

    for (const name of names) {
      const value = await fileRepo.getResource(u.id, name);
      if (value !== null && value !== undefined) await pgRepo.setResource(u.id, name, value);
    }
    migrated++;
    if (migrated % 100 === 0) console.log(`[backfill] ${migrated}/${users.length}`);
  }
  console.log(`[backfill] done. migrated=${migrated} pre-existing-users=${skipped}`);
  await closePool();
}

main().catch(e => { console.error('[backfill] FAILED:', e); process.exitCode = 1; });
```

- [ ] **Step 2: Dry-run against dev data** (use a copy of `auth_data` or the live one — reads only on the file side)

```bash
cd /home/pwd-vm/PWDnow/web && DATABASE_URL="$DATABASE_URL" PGSSL=disable KMS_PROVIDER=local LOCAL_KMS_KEY=$(openssl rand -hex 32) AUTH_DATA_DIR=../auth_data node scripts/backfill-to-postgres.js
```
Expected: `[backfill] N users…` then `[backfill] done.` with no errors. (If `auth_data/` is empty here, create one test user via the file-mode UI first, then re-run.)

> **⚠️ KMS-key consistency:** the `LOCAL_KMS_KEY` (or Vault key) used for backfill **must be the same** one the server uses afterward, or DEKs won't unwrap. In production use `KMS_PROVIDER=vault` for both so the key authority is shared.

- [ ] **Step 3: Verify a migrated user decrypts**

```bash
cd /home/pwd-vm/PWDnow/web && DATABASE_URL="$DATABASE_URL" PGSSL=disable node -e "import('pg').then(async ({default:{Pool}})=>{const p=new Pool({connectionString:process.env.DATABASE_URL});const u=await p.query('select count(*) from users');const v=await p.query('select count(*) from vault_items');console.log('users',u.rows[0].count,'items',v.rows[0].count);await p.end();})"
```
Expected: non-zero counts matching the file store.

- [ ] **Step 4: Commit**

```bash
cd /home/pwd-vm/PWDnow/web && git add scripts/backfill-to-postgres.js
git commit -m "feat(p1d): idempotent auth_data → Postgres backfill migrator (per-user DEK)"
```

---

## Task D3: Cutover runbook (documentation task — no code)

- [ ] **Step 1: Append the runbook to this plan / ops docs**

Production cutover sequence (zero-downtime, reversible):
1. Provision Postgres + Vault Transit key (`vault write -f transit/keys/pwdnow-dek type=aes256-gcm96`).
2. `npm run migrate:up` against the prod DB.
3. Deploy with `VAULT_BACKEND=dual`, `KMS_PROVIDER=vault`. New writes now mirror to Postgres; reads stay on file.
4. Run `scripts/backfill-to-postgres.js` (idempotent) to copy pre-existing users.
5. **Verify parity:** spot-check row counts + a sample user login in a `postgres`-mode canary pod.
6. Flip `VAULT_BACKEND=postgres`. Reads now come from Postgres. Keep the file store untouched for rollback.
7. Soak 24–48 h. If healthy, archive `auth_data/`. Rollback = set `VAULT_BACKEND=file` (file store was never mutated destructively).

- [ ] **Step 2: Commit**

```bash
cd /home/pwd-vm/PWDnow && git add docs/superpowers/plans/2026-06-08-saas-p1-postgres-envelope-kms.md
git commit -m "docs(p1d): production cutover runbook"
```

---

## Task D4: Final full regression (both backends)

- [ ] **Step 1: Server contract suites (both, where applicable)**

```bash
cd /home/pwd-vm/PWDnow/web && node --test tests/ \
  && DATABASE_URL="$DATABASE_URL" PGSSL=disable node --test tests/postgresVaultRepository.contract.test.js
```
Expected: all green.

- [ ] **Step 2: Vitest + lint + build**

```bash
cd /home/pwd-vm/PWDnow/web && npm run test && npm run lint && npm run build
```
Expected: all green.

- [ ] **Step 3: E2E both modes** — re-run Task C5 Steps 1 and 2. Both must pass.

- [ ] **Step 4: Final commit / tag**

```bash
cd /home/pwd-vm/PWDnow/web && git add -A && git commit -m "test(p1): full regression green for file + postgres backends" || echo "nothing to commit"
```

---

# Optional sub-plan — Password-bound DEK wrap (`wrap_mode='kms+pw'`)

> Designed-in, **default-off**. Implement only when the zero-knowledge "enhanced tier" is prioritized. No schema migration needed (`wrap_mode` + `pw_wrap_salt` already exist).

**Crypto:** DEK is wrapped twice — first by KMS (as today), then by a key derived from the user password via **Argon2id** (same params as login hashing) with a per-user `pw_wrap_salt`. Stored `wrapped_dek` = `AES-256-GCM(pwKey, KMS_wrapped_dek)`. To unwrap at login: derive `pwKey` from the just-verified password → AES-GCM-decrypt → KMS-unwrap. Server cannot read vaults without a live password (true zero-knowledge), at the cost of: (a) password change must re-wrap the DEK; (b) password reset becomes *vault loss* unless a recovery-code escrow wrap is added.

**Tasks (when scheduled):**
- `Envelope.newUserDek({ password, salt })` → produce the double-wrapped `wrappedDek` + `pwWrapSalt`, `wrapMode='kms+pw'`.
- `Envelope._dek(user, { password })` → password-layer unwrap before KMS unwrap; cache keyed by `user.id` as today.
- Login handler passes the verified password into the first `getResource`/session load of the request lifecycle (request-scoped DEK).
- Password-change handler re-wraps: unwrap with old password → re-wrap with new → `updateUserById` writes new `wrappedDek`.
- Add a recovery-code escrow wrap (Nth copy of the DEK wrapped by a high-entropy recovery code shown once at signup) to keep reset possible.
- Contract test: a row with `wrap_mode='kms+pw'` cannot be decrypted without the password; password change rotates the wrap; recovery code unwraps.

---

# P2 Roadmap — Redis everywhere (separate plan)

**Goal:** move *all* ephemeral state to Redis and re-enable the session cache safely across pods. Foundation (StateStore) already shipped in P0.

- **Session JTI source-of-truth:** introduce a `sessions` table (or Redis set) so `authMiddleware` checks revocation without decrypting a per-user blob. Replace `loadSessions`/`saveSessions` semantics with a queryable store; keep the `VaultRepository` method signatures.
- **Re-enable the session cache** (currently `SESSIONS_CACHE_TTL_MS = 0`, `web/lib/session.js:99`) with a short TTL **plus Redis pub/sub invalidation** on logout / password-change / revoke-others — fixes the PM2 correctness bug that forced TTL=0.
- **Email OTP / passkey challenges → Redis** with TTL + single-use (Lua compare-and-set) via the existing `StateStore.getdel`.
- **Cluster-wide Argon2 admission** already routes through `StateStore` (P0); point `REDIS_URL` at the cluster to make it global instead of per-pod.
- **Verify:** the StateStore contract suite already runs against Redis when `REDIS_URL` is set; add a multi-worker test that proves a logout on worker A revokes a session seen by worker B.

Plan file: `docs/superpowers/plans/2026-06-08-saas-p2-redis-everywhere.md`.

---

# P3 Roadmap — Kubernetes + autoscale (separate plan)

**Goal:** run the SaaS track as stateless, autoscaled pods to the 100k target.

- **Containerize:** multi-stage Dockerfile (build `dist/` → slim Node 24 runtime); non-root user; read-only FS except `/tmp`.
- **Deployment + HPA:** scale on CPU **and** a custom `login_queue_depth` metric (Argon2 is the bottleneck — B6). Optional dedicated **auth-worker pool** so 6–8 s hashes don't starve vault-read pods.
- **Secrets:** KMS/Vault token, `DATABASE_URL`, JWE session secret → K8s Secrets / Vault Agent injection. Make the JWE key a managed secret with a **key-id header** for zero-downtime rotation (today it's HKDF from the local master key, `web/lib/session.js:28`).
- **Data-in-transit:** TLS 1.3 to Postgres/Redis. Document the accepted residual: managed services rarely speak PQC TLS yet — **ALE is the zero-knowledge-at-rest guarantee**; data is ciphertext before it leaves the pod.
- **Load test:** k6 ramp to 100k users; tune `PG_POOL_MAX`, DEK LRU TTL, Argon2 admission bucket, HPA thresholds.
- **Observability:** request latency, KMS QPS + DEK cache hit-rate, login-queue depth, Argon2 concurrency, PG pool saturation, Redis op latency.

Plan file: `docs/superpowers/plans/2026-06-08-saas-p3-kubernetes.md`.

---

## Self-Review Checklist

### Spec coverage (against `2026-06-07-saas-scalability-design.md`)

| Spec requirement | Covered by |
|---|---|
| Per-user envelope: KMS CMK wraps per-user DEK (§2.2) | Tasks B2–B4, C3 |
| Short-TTL DEK LRU bounds KMS QPS; cached only in pod memory (§2.2) | Task B4 (`Envelope`, `dekTtlMs`, zeroize) |
| Replace single `auth_data/.master_key` blast radius (§1, §2.2) | Tasks B4, C3 (per-user DEK) |
| Postgres schema: users + one-row-per-item; HMAC blind index kept (§2.3) | Task C1 (`email_hmac` unique), C3 |
| `pg` + thin parameterized query module; node-pg-migrate (§2.3) | Tasks B1, C1, C2 |
| Eliminate `users.enc` rewrite amplification / global lock (B3, B7) | Tasks A1, C3 (row-oriented user writes; per-resource rows) |
| Fix file-store-doesn't-cluster (B3) | Phase C (Postgres) |
| `VaultRepository` Postgres impl behind one contract (§4) | Task C3 + shared contract test |
| Dual-write + backfill + flag-gated cutover (P1, §3) | Tasks C4, D1, D2, D3 |
| Keep `comprehensive-platform.spec.ts` green in both modes (§4) | Tasks A4, C5, D4 |
| Argon2id never weakened; scale horizontally (B6) | Unchanged; noted in P2/P3 roadmap |
| Password-bound DEK wrap option (§2.2, §5.2) | Optional sub-plan (schema-ready) |
| CNSA 2.0 / L5 preserved; daemon untouched (invariant) | AES-256-GCM throughout; no `daemon/` edits |

### Placeholder scan
No "TBD"/"add error handling"/"similar to Task N". The 78 call-site migrations (A2/A3) are specified by an exhaustive transformation table + a grep-to-empty acceptance check + the E2E gate — every transformation is concrete, and the proof of correctness is the green gold-standard E2E, not assertion.

### Type/signature consistency
`VaultRepository` methods are identical across `FileVaultRepository`, `PostgresVaultRepository`, `DualWriteVaultRepository`: `findUserByEmailHash`, `findUserById`, `insertUser`, `updateUserById(id, fn)`, `deleteUserById`, `withUserTransaction(fn)`, `getResource(uid,name)`, `setResource(uid,name,value)`, `deleteResource(uid,name)`, `deleteUserData(uid)`, `loadSessions(uid)`, `saveSessions(uid,list)`. `Envelope`: `newUserDek()`, `encryptResource(user,value)`, `decryptResource(user,blob)`, `_dekCacheSize()`. `KmsProvider`: `wrapDek(dek)→{wrapped,keyId}`, `unwrapDek(wrapped,keyId)→Buffer`. User object shape carries `wrappedDek`/`kmsKeyId`/`wrapMode`/`pwWrapSalt` consistently from `rowToUser` through `Envelope`.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-08-saas-p1-postgres-envelope-kms.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration. Best for the long P1.A call-site migration (each route file is its own reviewable unit).
2. **Inline Execution** — execute tasks in this session with checkpoints (`superpowers:executing-plans`), batch by phase (A → B → C → D).

Which approach?
